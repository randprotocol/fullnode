//! The Fiat-Shamir transcript, as a DSL sequence: `DuplexChallenger<Val, Perm, 8, 4>` over the same
//! Poseidon2 the inner machine hashes with (`p3-challenger-0.7.0/src/duplex_challenger.rs`).
//!
//! Every challenge the verifier program draws has to be the *same element* the prover drew, so this
//! is the one place where "close enough" is indistinguishable from "accepts forged proofs".
//! `tests/transcript.rs` pins it against the real crate on random observations. The four details that
//! make or break that:
//!
//! 1. **The input buffer is compile-time.** `observe` in the reference pushes onto a buffer and
//!    duplexes only when it reaches the rate; the DSL knows at build time how many elements have been
//!    buffered, so the buffer lives in the builder, not in rVM memory, and only the duplexing is
//!    emitted. An `observe` also *invalidates* any buffered output.
//! 2. **A duplex is prefix-free.** It overwrites `state[0..k]` with the buffered elements, zeroes
//!    `state[k..RATE]`, **adds `k` into `state[RATE]`** — the length tag, which is why an absorb of
//!    three elements and an absorb of three elements followed by a zero are different transcripts —
//!    and permutes. A *squeeze* (`k = 0`) permutes and touches nothing else.
//! 3. **`sample` pops from the back.** The first element sampled after a permutation is `state[3]`,
//!    then `state[2]`, `state[1]`, `state[0]`. An extension draw is two samples, `c0` first.
//! 4. **`sample_bits` is the low bits of the *canonical* representative.** Goldilocks is
//!    `p = 2^64 - 2^32 + 1`, so a 64-bit decomposition of a field element is not unique: the
//!    non-canonical ones are exactly those whose high 32 bits are all one and whose low 32 bits are
//!    non-zero. Without that check a prover chooses which FRI query indices to answer, so it is a
//!    constraint here and not a comment (see [`DslChallenger::sample_bits`]).

use p3_field::{Field, PrimeCharacteristicRing};

use super::{Builder, Digest, Ext, Felt, Ptr};
use crate::dsl::hash::{RATE, WIDTH};
use crate::isa::F;

/// The rVM-side twin of `DuplexChallenger<Val, Perm, 8, 4>`.
///
/// The sponge state is eight rVM cells; the input and output buffers are compile-time `Vec`s of
/// handles, because their *lengths* are compile-time in any program whose transcript shape is fixed —
/// which is every program this DSL builds (the shape is specialised, spec §4.2). That is what keeps a
/// `observe` free and a `sample` down to one `LOAD`.
pub struct DslChallenger {
    /// `WIDTH` cells. Allocated and zeroed by [`DslChallenger::new`]; never aliased by the hash
    /// layer, which works through its own region.
    state: Ptr,
    /// The absorbed-but-not-yet-permuted elements, `len < RATE`.
    buffered: Vec<Felt>,
    /// The squeezed elements not yet handed out, popped from the **back**.
    output: Vec<Felt>,
}

impl DslChallenger {
    /// A fresh transcript: the all-zero state, matching `DuplexChallenger::new`. Nine rows.
    pub fn new(b: &mut Builder) -> Self {
        let state = b.alloc(WIDTH as u64);
        b.zero_cells(state, 0, WIDTH);
        DslChallenger { state, buffered: Vec::new(), output: Vec::new() }
    }

    /// Absorb one base element (`CanObserve<F>::observe`): buffered at build time, and a duplex only
    /// when the buffer fills the rate. Any buffered output is invalidated, exactly as in the
    /// reference — a sample after an observe must reflect the observe.
    pub fn observe(&mut self, b: &mut Builder, v: Felt) {
        self.output.clear();
        self.buffered.push(v);
        if self.buffered.len() == RATE {
            self.duplex(b);
        }
    }

    pub fn observe_slice(&mut self, b: &mut Builder, vs: &[Felt]) {
        for v in vs {
            self.observe(b, *v);
        }
    }

    /// `observe_algebra_element`: the two coefficients, `c0` first.
    pub fn observe_ext(&mut self, b: &mut Builder, v: Ext) {
        let (c0, c1) = b.ext_parts(v);
        self.observe(b, c0);
        self.observe(b, c1);
    }

    /// Four absorbs — `CanObserve<[F; 4]>` on a digest, which is what a commitment's cap entries are
    /// made of.
    pub fn observe_digest(&mut self, b: &mut Builder, d: Digest) {
        for k in 0..super::DIGEST_ELEMS as i64 {
            let v = b.load(d.0, k);
            self.observe(b, v);
        }
    }

    /// A whole `MerkleCap` of four digests, in `roots()` order: sixteen absorbs, which is what
    /// observing one commitment of this machine costs (`cap_height = 2`).
    pub fn observe_cap(&mut self, b: &mut Builder, cap: &[Digest; 4]) {
        for d in cap {
            self.observe_digest(b, *d);
        }
    }

    /// `observe_base_as_algebra_element::<Challenge>`: the value, then a zero.
    ///
    /// Every metadata word in the batch transcript goes through here — instance counts, degree bits,
    /// widths, chunk counts — so each of them is **two** absorbs, not one
    /// (`p3-batch-stark-0.7.0/src/transcript.rs`, `p3-challenger-0.7.0/src/lib.rs:141`). A verifier
    /// that absorbed one would diverge from the prover on the very first word.
    pub fn observe_usize(&mut self, b: &mut Builder, v: usize) {
        let h = b.constant(F::from_u64(v as u64));
        self.observe(b, h);
        let z = b.zero();
        self.observe(b, z);
    }

    /// One base-field challenge. Duplexes if anything is buffered or the output is spent, then pops
    /// from the back of the squeezed rate.
    pub fn sample(&mut self, b: &mut Builder) -> Felt {
        if !self.buffered.is_empty() || self.output.is_empty() {
            self.duplex(b);
        }
        self.output.pop().expect("a duplex refills the output buffer")
    }

    /// One extension challenge: two samples in coefficient order (`from_basis_coefficients_fn`,
    /// `p3-challenger-0.7.0/src/lib.rs:124`).
    pub fn sample_ext(&mut self, b: &mut Builder) -> Ext {
        let c0 = self.sample(b);
        let c1 = self.sample(b);
        b.ext_from_parts(c0, c1)
    }

    /// The low `bits` bits of the canonical representative of one sampled element, as little-endian
    /// bit handles — `sample::<Val>().as_canonical_u64() as usize & ((1 << bits) - 1)`
    /// (`duplex_challenger.rs:285-290`).
    ///
    /// The prover hints all sixty-four bits and the program constrains them:
    ///
    /// - each bit is boolean (`b·(b-1) = 0`);
    /// - the **canonicality** of the claimed decomposition, because `p = 2^64 - 2^32 + 1` and so the
    ///   values with a second 64-bit decomposition are exactly those with `hi = b_32..b_63` all one
    ///   and `lo = b_0..b_31` non-zero. `lo`'s non-zeroness is decided by an inverse-or-zero hint
    ///   `t`: `lo·t·lo = lo` forces `t = lo⁻¹` when `lo ≠ 0` and leaves `t` free when `lo = 0`, so
    ///   `lo·t` is exactly the indicator "`lo ≠ 0`", and `all_hi · lo · t = 0` is the check. Without
    ///   it a prover picks between two decompositions of the same challenge and so picks which FRI
    ///   query indices to answer;
    /// - and only then that the decomposition is the sampled element at all.
    ///
    /// **That order is deliberate and is pinned by a test**: a tape whose bits are non-canonical
    /// traps under the canonicality checkpoint whatever the sampled value happens to be, rather than
    /// under the decomposition one. Both canonicality assertions carry the same name, because either
    /// failing means the same thing: the hinted bits are not the canonical representative.
    ///
    /// Consumes sixty-five witness words — the sixty-four bits, then `t` — which is what
    /// [`canonicality_hint`] and the tape builder have to supply, in that order. `bits = 0` still
    /// samples and still reads them, because the reference samples too.
    ///
    /// **Measured: 1 173 rows and one permutation per sampled index**, of which 584 are the
    /// allocator's spill and reload traffic (333 spills, 251 reloads): the sixty-four bits are
    /// sixty-four live-forever handles, each of whose three uses — booleanity, the decomposition sum,
    /// the high-bit product — creates two more, and nothing here is alive for more than a row. The
    /// plan's ruling budgeted ~140 rows for this; the real number is eight times that, and at 80
    /// queries it is ~95 000 rows of a 524 288-row budget. Moving the bits into memory instead does
    /// not help (measured: 1 178) — the cost tracks *handles created*, not registers held — so the
    /// fix is liveness in the allocator, not a rewrite here. Task 6's measurement and Task 7's
    /// precompile decision both need to know this.
    pub fn sample_bits(&mut self, b: &mut Builder, bits: usize) -> Vec<Felt> {
        assert!(bits <= 32, "sample_bits({bits}): p3 requires 2^bits < |F|, and a query index space \
                             wider than 2^32 does not exist on this machine");
        let x = self.sample(b);
        let zero = b.zero();

        // The sixty-four bits first, so the tape's segment is one contiguous run.
        let bit: Vec<Felt> = (0..64).map(|_| b.hint()).collect();
        for (k, &bk) in bit.iter().enumerate() {
            let less_one = b.add_const(bk, F::NEG_ONE);
            let p = b.mul(bk, less_one);
            b.assert_eq(p, zero, &format!("sample_bits bit {k}"));
        }

        let lo = horner(b, &bit[..32]);
        let hi = horner(b, &bit[32..]);
        let mut all_hi = bit[32];
        for &bk in &bit[33..] {
            all_hi = b.mul(all_hi, bk);
        }

        // Canonicality, before the decomposition is tied to `x` — see the note above.
        let t = b.hint();
        let lo_t = b.mul(lo, t);
        let back = b.mul(lo, lo_t);
        b.assert_eq(back, lo, "sample_bits canonicality");
        let non_canonical = b.mul(all_hi, lo_t);
        b.assert_eq(non_canonical, zero, "sample_bits canonicality");

        let shifted = b.mul_const(hi, F::from_u64(1 << 32));
        let sum = b.add(lo, shifted);
        b.assert_eq(sum, x, "sample_bits decomposition");

        bit[..bits].to_vec()
    }

    /// `GrindingChallenger::check_witness`: observe the witness, then assert the low `bits` bits of
    /// the next challenge are zero (`grinding_challenger.rs:44-49`).
    ///
    /// At `bits == 0` this is a no-op that does **not** even observe the witness, and that is not an
    /// optimisation — it is what the reference does, so a config with zero proof-of-work bits (this
    /// machine's commit phase) has a witness element in the proof that the transcript never sees. A
    /// verifier that observed it anyway would diverge from the prover from that point on.
    pub fn check_witness(&mut self, b: &mut Builder, bits: usize, w: Felt, what: &str) {
        if bits == 0 {
            return;
        }
        self.observe(b, w);
        let sampled = self.sample_bits(b, bits);
        let zero = b.zero();
        for (k, &bk) in sampled.iter().enumerate() {
            b.assert_eq(bk, zero, &format!("{what} bit {k}"));
        }
    }

    /// One permutation of the sponge (`duplex_challenger.rs:88-114`).
    fn duplex(&mut self, b: &mut Builder) {
        let buf: Vec<Felt> = std::mem::take(&mut self.buffered);
        let k = buf.len();
        for (i, v) in buf.into_iter().enumerate() {
            b.store(self.state, i as i64, v);
        }
        if k > 0 {
            // An absorb: clear the rest of the rate and bind the absorbed length into the first
            // capacity lane. A squeeze does neither — it permutes the state as it stands.
            b.zero_cells(self.state, k as i64, RATE - k);
            let cap = b.load(self.state, RATE as i64);
            let tagged = b.add_const(cap, F::from_u64(k as u64));
            b.store(self.state, RATE as i64, tagged);
        }
        b.poseidon2(self.state);
        self.output = (0..RATE as i64).map(|i| b.load(self.state, i)).collect();
    }
}

/// `Σ_k bits[k]·2^k` for little-endian `bits`, by Horner from the top: two rows per bit after the
/// first.
fn horner(b: &mut Builder, bits: &[Felt]) -> Felt {
    let mut acc = *bits.last().expect("a decomposition has at least one bit");
    for &bk in bits.iter().rev().skip(1) {
        let doubled = b.mul_const(acc, F::TWO);
        acc = b.add(doubled, bk);
    }
    acc
}

/// The host-side twin of [`DslChallenger::sample_bits`]' non-zero hint: `0` when the low 32 bits of
/// `v` are zero, else their inverse.
///
/// `v` is `x.as_canonical_u64()` for the sampled element `x`. The witness-tape builder and every test
/// that drives `sample_bits` needs this, immediately after that element's sixty-four bits.
pub fn canonicality_hint(v: u64) -> F {
    let lo = v & 0xFFFF_FFFF;
    if lo == 0 {
        F::ZERO
    } else {
        F::from_u64(lo).inverse()
    }
}
