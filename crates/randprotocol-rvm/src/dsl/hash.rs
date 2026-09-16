//! The three hashes the inner proof system is built out of, as DSL sequences: the padding-free leaf
//! sponge, the truncated-permutation compressor, and the Merkle authentication walk.
//!
//! Each one is *bit-exact* with the Plonky3 code the native verifier calls —
//! `PaddingFreeSponge<Perm, 8, 4, 4>`, `TruncatedPermutation<Perm, 2, 4, 8>` and
//! `MerkleTreeMmcs::verify_batch`'s loop at arity 2 — and `tests/transcript.rs` checks that against
//! those very crates on random input rather than against a second implementation of the same idea.
//! The three rules that are easy to get wrong, and that the tests exist to catch:
//!
//! 1. **The sponge is padding-free.** A trailing partial block overwrites only its own rate lanes
//!    and permutes once; it does **not** zero the rest of the rate. Zero-filling it would agree with
//!    the reference on every message whose length is a multiple of four and disagree on every other
//!    one (`p3-symmetric-0.7.0/src/sponge.rs:176-214`).
//! 2. **A digest is four elements, the state is eight.** The sponge squeezes lanes `0..4` and the
//!    compressor keeps lanes `0..4` of `[left ‖ right]` (spec §12 erratum 1).
//! 3. **The walk ends below the root.** `cap_height = 2`, so it runs `log2(padded height) - 2`
//!    levels and the caller compares the surviving digest with the cap entry at the index that is
//!    left (`p3-merkle-tree-0.7.0/src/mmcs/batch.rs:267`).
//!
//! **Aliasing.** Every primitive here works through the one sixteen-cell region
//! `Builder::hash_scratch` hands out — eight permutation lanes and two scratch digests — so that a
//! program that hashes tens of thousands of times pays for it once. No argument to any function in
//! this module may point into that region.

use super::builder::RRef;
use super::{Builder, Digest, Felt, Ptr};
use crate::isa::{Op, F};
use p3_field::PrimeCharacteristicRing;

/// A digest is four field elements on this machine (re-exported so `hash::DIGEST_ELEMS` reads as one
/// idea with [`super::DIGEST_ELEMS`] rather than two constants that happen to agree).
pub use super::DIGEST_ELEMS;

/// The salt elements the hiding MMCS appends to every committed row before the leaf hash
/// (`MerkleTreeHidingMmcs<.., 2, 4, 4>`'s third parameter, `p3-merkle-tree-0.7.0/src/
/// hiding_mmcs.rs:232-275`). A leaf sponge's message is `row ‖ salt`, so it is `width + 4` long.
pub const SALT_ELEMS: usize = 4;
/// The permutation's rate: how many lanes an absorbed block overwrites.
pub const RATE: usize = 4;
/// The permutation's width, and so the number of cells `POSEIDON2` permutes.
pub const WIDTH: usize = 8;

/// The scratch digest the Merkle walk parks its running digest in while an injected group is hashed.
const TMP_A: i64 = WIDTH as i64;
/// The scratch digest an injected group's sponge writes into.
const TMP_B: i64 = WIDTH as i64 + DIGEST_ELEMS as i64;

/// One `PaddingFreeSponge<Perm, 8, 4, 4>` over `n` cells starting at `src`, digest written to `out`.
///
/// Absorbs in blocks of four with the overwrite rule and permutes after every full block; a trailing
/// partial block overwrites only its own lanes and permutes once
/// (`p3-symmetric-0.7.0/src/sponge.rs:176-214`). The state starts all-zero, which is why the lanes
/// the *first* block does not reach are zeroed and none after it are.
///
/// Measured: `2n + (WIDTH - min(n, RATE)) + ceil(n/4) + 8` rows and `ceil(n / 4)` permutations —
/// 18 rows for one word, 285 for the 121 a wide committed row comes to. Two of those rows per cell
/// are the message copy into the rate, which is why the message is moved with `Builder::copy_cells`
/// rather than through handles: handles would add a third. `src` and `out` must not point into
/// `Builder::hash_scratch`; `out` may overlap `src`.
pub fn sponge(b: &mut Builder, src: Ptr, n: usize, out: Digest) {
    match b.precompiles() {
        crate::dsl::Precompiles::Off => sponge_compiled(b, src, n, out),
        crate::dsl::Precompiles::On => {
            assert!(n >= 1, "a padding-free sponge over an empty message is not a hash; p3's own hash_iter \
                             would return the zero state's first four lanes, and no call site does it");
            let st = b.hash_scratch();
            let first = n.min(RATE);
            // The first block's unreached lanes start zero and stay whatever the previous
            // permutation leaves them after that — the padding-free rule, exactly as compiled.
            b.zero_cells(st, first as i64, WIDTH - first);
            let mut done = 0;
            while done + RATE <= n {
                let block = b.offset(src, done as i64);
                b.sponge_absorb(st, block);
                done += RATE;
            }
            // The trailing partial block stays compiled: one copy of the tail into the rate,
            // then one in-place permutation (`SPONGE` absorbs exactly four lanes).
            if done < n {
                b.copy_cells(st, 0, src, done as i64, n - done);
                b.poseidon2(st);
            }
            b.copy_cells(out.0, 0, st, 0, DIGEST_ELEMS);
        }
    }
}

/// [`sponge`] with the absorb loop compiled as plain instructions (`copy_cells` + `POSEIDON2`
/// per block) — the precompile's differential reference, kept in the tree
/// (`tests/transcript.rs` and `tests/precompiles.rs` pin the two to each other).
pub fn sponge_compiled(b: &mut Builder, src: Ptr, n: usize, out: Digest) {
    assert!(n >= 1, "a padding-free sponge over an empty message is not a hash; p3's own hash_iter \
                     would return the zero state's first four lanes, and no call site does it");
    let st = b.hash_scratch();
    let first = n.min(RATE);
    // Lanes the first block overwrites need no zeroing; every other lane must start at zero, and
    // *stay* whatever the previous permutation left it after that — the padding-free rule.
    b.zero_cells(st, first as i64, WIDTH - first);
    let mut done = 0;
    while done < n {
        let k = (n - done).min(RATE);
        b.copy_cells(st, 0, src, done as i64, k);
        b.poseidon2(st);
        done += k;
    }
    b.copy_cells(out.0, 0, st, 0, DIGEST_ELEMS);
}

/// The capacity-seeded sponge (plan R5): the `Program::digest` construction generalized to a
/// word slice — the state starts as `[0, 0, 0, 0, domain, n, 0, 0]` (the domain tag and the word
/// count in the *capacity* lanes, so two different lengths are different digests by
/// construction), then the absorb loop is [`sponge`]'s own, overwrite rule included. The host
/// twin is `public_values::public_digest`; `tests/verifier.rs` pins the two to each other on
/// every fixture, and `tests/tables.rs` pins the construction itself.
///
/// Measured against `sponge`: the same `ceil(n / 4)` permutations plus the four header rows.
pub fn sponge_seeded(b: &mut Builder, domain: u64, src: Ptr, n: usize, out: Digest) {
    assert!(n >= 1, "a padding-free sponge over an empty message is not a hash");
    let st = b.hash_scratch();
    // Lanes 0..4 start zero (a short first block's unreached lanes stay zero, the padding-free
    // rule); lanes 4..6 are the header; lane 7 starts zero.
    b.zero_cells(st, 0, 4);
    let d = b.constant(F::from_u64(domain));
    b.store(st, 4, d);
    let l = b.constant(F::from_u64(n as u64));
    b.store(st, 5, l);
    b.zero_cells(st, 6, 2);
    let mut done = 0;
    match b.precompiles() {
        crate::dsl::Precompiles::On => {
            while done + RATE <= n {
                let block = b.offset(src, done as i64);
                b.sponge_absorb(st, block);
                done += RATE;
            }
            if done < n {
                b.copy_cells(st, 0, src, done as i64, n - done);
                b.poseidon2(st);
            }
        }
        crate::dsl::Precompiles::Off => {
            while done < n {
                let k = (n - done).min(RATE);
                b.copy_cells(st, 0, src, done as i64, k);
                b.poseidon2(st);
                done += k;
            }
        }
    }
    b.copy_cells(out.0, 0, st, 0, DIGEST_ELEMS);
}

/// `TruncatedPermutation<Perm, 2, 4, 8>`: the eight cells `[left(4) ‖ right(4)]` permuted, the first
/// four lanes kept (`p3-symmetric-0.7.0/src/compression.rs:40-47`).
///
/// Measured: 25 rows and one permutation. Neither input may point into `Builder::hash_scratch`;
/// `out` may alias either input.
pub fn compress(b: &mut Builder, left: Digest, right: Digest, out: Digest) {
    compress_into_state(b, left, right);
    let st = b.hash_scratch();
    b.copy_cells(out.0, 0, st, 0, DIGEST_ELEMS);
}

/// One word into a *running* sponge whose state is the eight cells at `st` and whose next rate
/// lane is the absolute address in the cell at `cursor` — the runtime-length sponge's absorb
/// step (M5.3's aggregate program, where the interface list's length is a tape value, not a
/// build-time constant): store at `*cursor`, bump, and when the cursor reaches `st + RATE` the
/// rate is full — permute and rewind.
///
/// The overwrite rule is the padding-free one, one word at a time: lanes the cursor has not
/// reached keep their values, so a trailing partial block is exactly "overwrite only its own
/// lanes, permute once" — the caller permutes once more after the last word rather than here.
/// `st` must be a *dedicated* region, never `Builder::hash_scratch`: the whole point is that the
/// state survives unrelated hashing between absorbs.
///
/// Measured: six rows per word plus, on the word that fills the rate, one permutation and the
/// rewind (four more).
pub fn absorb_staged(b: &mut Builder, st: Ptr, cursor: Ptr, v: Felt) {
    let at = b.load(cursor, 0);
    b.store_indirect(at, v);
    let bumped = b.add_const(at, F::ONE);
    b.store(cursor, 0, bumped);
    let full = b.constant(F::from_u64(b.addr_of(st) + RATE as u64));
    b.if_eq(bumped, full, |b| {
        b.poseidon2(st);
        let base = b.constant(F::from_u64(b.addr_of(st)));
        b.store(cursor, 0, base);
    });
}

/// One Merkle authentication path, exactly `MerkleTreeMmcs::verify_batch`'s loop at arity 2 with
/// `cap_height = 2`: `pos = index_bit`, `compress([digest, sibling])` or `compress([sibling,
/// digest])`.
///
/// `index_bits` are the little-endian bits of the leaf index, already bit-constrained (this function
/// trusts them: a bit that is not 0 or 1 gives a digest that is neither child order, which is why
/// `DslChallenger::sample_bits` constrains them where they are born). `siblings` points at
/// `4·levels` cells, level 0 first. `out` receives the digest reached after `levels` compressions,
/// which the caller compares with the cap entry at the remaining index — the walk itself never
/// touches the commitment.
///
/// Measured: `33·levels + 16` rows and `levels` permutations — 33 rows per level (32 for the child
/// select, one for the permutation) and sixteen for copying the leaf digest in and the result out.
/// The running digest lives in the permutation's own lanes for the whole walk, so a level costs no
/// copy of its own.
pub fn merkle_walk(b: &mut Builder, leaf: Digest, index_bits: &[Felt], siblings: Ptr, levels: usize,
                   out: Digest) {
    merkle_walk_with_injections(b, leaf, index_bits, siblings, levels, &[], out);
}

/// A shorter-height matrix group injected into the walk after `after_level`: the `n_cells` at `rows`
/// are sponged and compressed into the running digest.
///
/// **One `Injection` per level, covering every matrix at that height.** `rows` is *all* the group's
/// opened rows at that height, concatenated in tallest-first order and each salted, because the
/// reference does one `hash_iter_slices` over every such matrix and then one compression
/// (`p3-merkle-tree-0.7.0/src/mmcs/batch.rs:245-262`). Two injections sharing a level would sponge
/// and compress twice and diverge from that on the second matrix; [`merkle_walk_with_injections`]
/// rejects it at build time rather than letting it become a wrong digest.
#[derive(Clone, Copy, Debug)]
pub struct Injection {
    /// The zero-based level *after* which the injection happens: the group's height is the height
    /// the walk has climbed to by then (`p3-merkle-tree-0.7.0/src/mmcs/batch.rs:240-262`).
    pub after_level: usize,
    pub rows: Ptr,
    pub n_cells: usize,
}

/// [`merkle_walk`] with shorter-height matrix groups injected after given levels, which is what a
/// real round needs: `digest = compress([digest, sponge(rows at that height)])`
/// (`p3-merkle-tree-0.7.0/src/mmcs/batch.rs:240-262`).
///
/// Injections may be given in any order, but their levels must be **pairwise distinct** — one
/// compression per height is what the reference does, so one `Injection` per height is what this
/// takes; see [`Injection`].
///
/// Measured: an injection of `m` cells adds `sponge(m) + 25` rows and `ceil(m/4) + 1` permutations —
/// 58 rows and four permutations for the nine-cell group a five-column salted matrix comes to.
pub fn merkle_walk_with_injections(b: &mut Builder, leaf: Digest, index_bits: &[Felt],
                                   siblings: Ptr, levels: usize, injections: &[Injection],
                                   out: Digest) {
    assert!(index_bits.len() >= levels,
            "a {levels}-level walk needs {levels} index bits, got {}", index_bits.len());
    assert!(injections.iter().all(|i| i.after_level < levels),
            "an injection after a level the walk never reaches would be silently dropped");
    for (i, inj) in injections.iter().enumerate() {
        assert!(
            injections[..i].iter().all(|other| other.after_level != inj.after_level),
            "two injections after level {}: the reference sponges every matrix at one height into \
             one digest and compresses once (p3-merkle-tree-0.7.0/src/mmcs/batch.rs:245-262), so a \
             height gets one Injection whose `rows` are all of its salted rows concatenated — two \
             would compress twice and compute a different root",
            inj.after_level
        );
    }
    let st = b.hash_scratch();
    // The running digest lives in the permutation's own first four lanes for the whole walk: every
    // level reads it from there and writes the next level's `left` back over it, so a level costs no
    // copy at all.
    b.copy_cells(st, 0, leaf.0, 0, DIGEST_ELEMS);
    for (l, &bit) in index_bits.iter().enumerate().take(levels) {
        select_children(b, st, siblings, (l * DIGEST_ELEMS) as i64, bit);
        b.poseidon2(st);
        for inj in injections.iter().filter(|i| i.after_level == l) {
            // `sponge` needs the eight lanes, so the running digest steps aside into the first
            // scratch digest and comes back as the compression's left input.
            b.copy_cells(st, TMP_A, st, 0, DIGEST_ELEMS);
            let (a, tmp_b) = (b.offset(st, TMP_A), b.offset(st, TMP_B));
            sponge(b, inj.rows, inj.n_cells, Digest(tmp_b));
            compress_into_state(b, Digest(a), Digest(tmp_b));
        }
    }
    b.copy_cells(out.0, 0, st, 0, DIGEST_ELEMS);
}

/// `[left ‖ right]` into the eight lanes, permuted; the result is lanes `0..4`.
fn compress_into_state(b: &mut Builder, left: Digest, right: Digest) {
    let st = b.hash_scratch();
    b.copy_cells(st, 0, left.0, 0, DIGEST_ELEMS);
    b.copy_cells(st, DIGEST_ELEMS as i64, right.0, 0, DIGEST_ELEMS);
    b.poseidon2(st);
}

/// The running digest in lanes `0..4` and the sibling at `sib + off`, written into lanes `0..8` in
/// the order the index bit `t` selects: `left = d + t·(s − d)`, `right = s − t·(s − d)`.
///
/// Arithmetic, not a branch — the row sequence is the same whichever way the bit falls, which is
/// what spec §4.1 means by the walk being one compiled sequence. Eight rows per lane through four
/// scratch registers and **no handles**: every intermediate here is dead one row after it is born,
/// and a handle would instead live to the end of the program and spill a cell for the privilege.
fn select_children(b: &mut Builder, st: Ptr, sib: Ptr, off: i64, t: Felt) {
    b.raw_group();
    // Operands first: a spilled `t` or base address reloads into scratch, so the working registers
    // have to be taken after them.
    let rt = b.raw_reg(t);
    let (rst, dst) = b.raw_ptr(st);
    let (rsib, dsib) = b.raw_ptr(sib);
    let w = b.raw_scratch(3);
    let (d, s, m) = (w, w + 1, w + 2);
    for k in 0..DIGEST_ELEMS as i64 {
        b.raw_emit(Op::Load, RRef::scratch(d), rst, Builder::raw_imm(dst + k));
        b.raw_emit(Op::Load, RRef::scratch(s), rsib, Builder::raw_imm(dsib + off + k));
        b.raw_emit(Op::Fsub, RRef::scratch(m), RRef::scratch(s), Builder::raw_scratch_b(d));
        b.raw_emit(Op::Fmul, RRef::scratch(m), rt, Builder::raw_scratch_b(m));
        // `right` first: it consumes `s`, which `left` does not need.
        b.raw_emit(Op::Fsub, RRef::scratch(s), RRef::scratch(s), Builder::raw_scratch_b(m));
        b.raw_emit(Op::Fadd, RRef::scratch(d), RRef::scratch(d), Builder::raw_scratch_b(m));
        b.raw_emit(Op::Store, RRef::scratch(d), rst, Builder::raw_imm(dst + k));
        b.raw_emit(Op::Store, RRef::scratch(s), rst, Builder::raw_imm(dst + DIGEST_ELEMS as i64 + k));
    }
}
