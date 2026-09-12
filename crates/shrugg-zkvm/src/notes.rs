//! Notes, commitments, nullifiers, and the key hierarchy the `transfer` guest and the
//! viewing-key layer share. Everything here is a pure function of `notes::hash` (the
//! Poseidon2 sponge, `hash::sponge_hash`, under a domain tag), and every function the guest
//! recomputes in-circuit has its reference here.
//!
//! ```text
//!   sk  ──H_NK──▶  nk (= the viewing key)  ──H_PK──▶  pk (the address)
//!                    │
//!                    ├──H_NF(nk, cm)──▶  nf    (nullifier of the note with commitment cm)
//!                    ├──H_OVK───────▶  ovk    (wraps outgoing envelopes, `viewing.rs`)
//!                    └──H_KEM_SEED───▶  ML-KEM keypair (receives envelopes, `viewing.rs`)
//! ```
//!
//! The one-way arrows are what make "view without spend" true: `nk` is derived *from* `sk`,
//! so a holder of `nk` can compute every address, nullifier and decryption key of the party
//! but cannot satisfy the `transfer` guest, which takes `sk` as a private input and derives
//! `nk` itself (`guests::transfer`).
//!
//! Widths (M3.3): keys, commitments and nullifiers are `Word8` — four canonical Goldilocks
//! field elements, each split lo/hi into two 32-bit machine words, exactly what
//! `hash::sponge_hash`/`hash::split_digest` produce. `SpendKey` is eight words too, like every
//! other key: `pk = H_PK(H_NK(sk))` is known to every counterparty (the `from` field of a
//! received note), so anything narrower would be a brute-force target for recovering spend
//! authority from a public address.

use crate::hash::sponge_hash;
use rand::Rng;

/// A 256-bit value as eight machine words: four canonical Goldilocks field elements, each
/// split lo/hi (`hash::split_digest`'s layout). Every key, commitment and nullifier is one.
pub type Word8 = [u32; 8];

/// Depth of the commitment Merkle tree `MERKLE_VERIFY`/`ledger::CommitmentTree` use.
pub const DEPTH: usize = 32;

/// Fixed domain tags. Every use of the hash has its own tag as the *first* absorbed word, so
/// a note commitment can never collide with a nullifier, a key, a tree node or the output
/// commitment even on identical remaining inputs.
pub mod domain {
    /// `nk = H(NK, sk)` — a fixed 9-word message, the tag plus `SpendKey`'s eight words
    /// (one fixed message length per domain; see `research/AGENTS.md`).
    pub const NK: u32 = 1;
    pub const PK: u32 = 2;
    pub const NF: u32 = 3;
    pub const CM: u32 = 4;
    pub const OVK: u32 = 5;
    pub const KEM_SEED: u32 = 6;
    /// A commitment tree node: `H(NODE, left(8), right(8))`.
    pub const NODE: u32 = 7;
    /// The in-circuit program commitment (M3.4): `hash::program_digest`'s capacity-lane
    /// header, `[HC, base_pc, len]`, seeded into the very first digest-row permutation
    /// before any program word is absorbed.
    pub const HC: u32 = 8;
    /// The `transfer` guest's output commitment: `H(OUT, anchor(8), nf(8), cm_out(8), time)`
    /// — see `output_digest` and `docs/06-viewing-keys.md`'s "Public outputs" section.
    pub const OUT: u32 = 9;
    /// M4.1: the input commitment (`hash::input_digest`), sealing the private-input vector
    /// `READ_INPUT` draws from — the capacity-lane header `[IN, n_in, 0]` seeded into the very
    /// first input-digest-row permutation, mirroring `HC`'s `[HC, base_pc, len]` exactly.
    pub const IN: u32 = 10;
    /// The `bundle` guest's output digest (`docs/superpowers/plans/2026-09-11-shielded-pool-z.md`
    /// Task 3): `H(BUNDLE, anchor(8) nf1(8) nf2(8) cm1(8) cm2(8) fee(2) burn(2) asset(1) time(1)
    /// bad(1))` — 47 words. `bad` is an explicit last word, the guest's own taint accumulator
    /// (0 for an honest run), never folded into `time` or any other plaintext-published field —
    /// XORing it into a published word would let a cheating sender simply publish the corrupted
    /// value and have the ledger's independent recomputation agree. The host reference
    /// (`bundle_digest`/`expected_bundle_outputs`) always computes with `bad = 0`; only the
    /// guest ever writes a nonzero `bad` word, which is exactly what makes a dishonest witness's
    /// digest fail to match any plaintext the ledger could reconstruct.
    pub const BUNDLE: u32 = 11;
    pub const TEST: u32 = 0xff;
}

/// The domain-tagged Poseidon2 sponge every key, commitment, nullifier and tree node is
/// built from: `H(domain, msg) = sponge_hash([domain, msg...])`. Exactly what the `POSEIDON2`
/// syscall computes over the same words (`hash::sponge_hash`), so the guest and this
/// function agree bit for bit.
pub fn hash(domain: u32, msg: &[u32]) -> Word8 {
    let mut full = Vec::with_capacity(1 + msg.len());
    full.push(domain);
    full.extend_from_slice(msg);
    sponge_hash(&full)
}

/// A host-only wide hash (never computed in-circuit): squeezes `out_words` words by hashing
/// `[domain, msg..., counter]` for `counter = 0, 1, ...` and concatenating 8-word chunks.
/// Used for `ovk`/`kem_seed`, which need more output than one `Word8`.
fn wide_hash(domain: u32, msg: &[u32], out_words: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_words);
    let mut counter = 0u32;
    while out.len() < out_words {
        let mut full = Vec::with_capacity(2 + msg.len());
        full.push(domain);
        full.extend_from_slice(msg);
        full.push(counter);
        let chunk = sponge_hash(&full);
        let take = (out_words - out.len()).min(chunk.len());
        out.extend_from_slice(&chunk[..take]);
        counter += 1;
    }
    out
}

/// The spend authority. Never leaves the wallet; the guest reads it through `READ_INPUT`.
/// Eight words (256 bits), like every other key: `pk = H_PK(H_NK(sk))` is known to every
/// counterparty (the `from` field of a received note), so a shorter `sk` would be a
/// brute-force target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendKey(pub Word8);

impl SpendKey {
    pub fn random() -> Self {
        let mut rng = rand::rng();
        SpendKey(std::array::from_fn(|_| rng.next_u32()))
    }
    /// The full viewing key: everything the party can see, nothing it can spend.
    pub fn viewing_key(&self) -> ViewingKey { ViewingKey { nk: hash(domain::NK, &self.0) } }
}

/// A party's full viewing key. Holding it means seeing the party's whole history — every
/// note received and every note spent — and being able to check each row of that history
/// against the chain. It cannot produce a proof: see `SpendKey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ViewingKey { pub nk: Word8 }

impl ViewingKey {
    /// The public address, the field a note names its owner and its creator by.
    pub fn pk(&self) -> Word8 { hash(domain::PK, &self.nk) }
    /// The nullifier of the party's note with commitment `cm`: `H_NF(nk, cm)`. Binding the
    /// nullifier to the commitment — rather than to a sender-chosen nonce — means two notes
    /// minted for the same owner can never collide to one nullifier (the ledger already
    /// rejects duplicate commitments, so distinct notes have distinct nullifiers). Only `nk`
    /// can compute it, which is why an auditor holding the sender's viewing key can check a
    /// spend row's nullifier against the chain while a receiver, holding only the note,
    /// cannot.
    pub fn nullifier(&self, cm: &Word8) -> Word8 {
        let mut msg = [0u32; 16];
        msg[..8].copy_from_slice(&self.nk);
        msg[8..].copy_from_slice(cm);
        hash(domain::NF, &msg)
    }
    /// Outgoing viewing key: the symmetric key under which every envelope this party sends
    /// carries a copy of its transaction key.
    pub fn ovk(&self) -> [u8; 32] {
        let w = wide_hash(domain::OVK, &self.nk, 8);
        words_to_bytes(&w).try_into().unwrap()
    }
    /// Seed for the ML-KEM decapsulation key (64 bytes, per FIPS 203's `d || z`).
    pub fn kem_seed(&self) -> [u8; 64] {
        let w = wide_hash(domain::KEM_SEED, &self.nk, 16);
        words_to_bytes(&w).try_into().unwrap()
    }
}

/// What a note records. `from` is the address of the party that created it — the sender of
/// the transfer, or the minter — so the commitment authenticates the sender to whoever can
/// open the note, with no extra disclosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Note {
    /// Owner.
    pub pk: Word8,
    /// Creator.
    pub from: Word8,
    /// SHRUGG units. Two machine words on the wire (lo, hi) — see `words()`. `u64`, not
    /// `u32`: SHRUGG units are `1e9` per coin, so `u32` cannot hold a single coin
    /// (`docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §13's ruling).
    pub amount: u64,
    pub asset: u32,
    /// Creation time, as the transaction that created the note published it.
    pub time: u32,
    /// Commitment randomness.
    pub r: Word8,
}

impl Note {
    /// `pk(8) from(8) amount_lo amount_hi asset(1) time(1) r(8)`.
    pub const WORDS: usize = 8 + 8 + 2 + 1 + 1 + 8;
    pub const BYTES: usize = 4 * Self::WORDS;

    /// The word layout the guest hashes: `pk, from, amount_lo, amount_hi, asset, time, r`.
    pub fn words(&self) -> [u32; Self::WORDS] {
        let mut w = [0u32; Self::WORDS];
        w[0..8].copy_from_slice(&self.pk);
        w[8..16].copy_from_slice(&self.from);
        w[16] = self.amount as u32;
        w[17] = (self.amount >> 32) as u32;
        w[18] = self.asset;
        w[19] = self.time;
        w[20..28].copy_from_slice(&self.r);
        w
    }
    pub fn from_words(w: [u32; Self::WORDS]) -> Note {
        Note {
            pk: w[0..8].try_into().unwrap(),
            from: w[8..16].try_into().unwrap(),
            amount: (w[16] as u64) | ((w[17] as u64) << 32),
            asset: w[18],
            time: w[19],
            r: w[20..28].try_into().unwrap(),
        }
    }
    pub fn commitment(&self) -> Word8 { hash(domain::CM, &self.words()) }
    pub fn to_bytes(&self) -> Vec<u8> { words_to_bytes(&self.words()) }
    pub fn from_bytes(b: &[u8]) -> Option<Note> {
        if b.len() != Self::BYTES { return None; }
        let mut w = [0u32; Self::WORDS];
        for (i, c) in b.chunks(4).enumerate() { w[i] = u32::from_le_bytes(c.try_into().unwrap()); }
        Some(Note::from_words(w))
    }
    /// A fresh note for `owner`, created by `from`, with random `r`.
    pub fn new(owner: Word8, from: Word8, amount: u64, asset: u32, time: u32) -> Note {
        let mut rng = rand::rng();
        let r = std::array::from_fn(|_| rng.next_u32());
        Note { pk: owner, from, amount, asset, time, r }
    }
}

pub fn words_to_bytes(w: &[u32]) -> Vec<u8> { w.iter().flat_map(|x| x.to_le_bytes()).collect() }

/// `H(OUT_DOMAIN, anchor, nf, cm_out, time)` — the single 8-word digest `guests::transfer`
/// publishes in place of four separate public outputs (`docs/06-viewing-keys.md`'s "Public
/// outputs" section explains why: at `Word8` widths, `anchor`/`nf`/`cm_out`/`time` no longer
/// fit in the CPU table's 8 output slots, and growing `NUM_OUTPUTS` would widen the CPU table
/// and reopen its pinned constraint-degree budget). `Ledger::apply` is handed the four
/// plaintext values alongside the proof (the same way it is already handed `time`/`cm_out` as
/// plain `Tx` fields, never hidden) and recomputes this digest to check the proof attests to
/// exactly those values.
pub fn output_digest(anchor: &Word8, nf: &Word8, cm_out: &Word8, time: u32) -> Word8 {
    let mut msg = [0u32; 25];
    msg[0..8].copy_from_slice(anchor);
    msg[8..16].copy_from_slice(nf);
    msg[16..24].copy_from_slice(cm_out);
    msg[24] = time;
    hash(domain::OUT, &msg)
}

/// The private-input vector of `guests::transfer`: the spend key, the note being spent, the
/// fields of the note being created that the guest does not derive itself, and the Merkle
/// witness (path and index) proving the spent note's commitment is in the tree. Index
/// constants are the `READ_INPUT` indices the guest uses.
pub mod input {
    use super::DEPTH;
    pub const SK: usize = 0;          // 8 words
    pub const IN_FROM: usize = 8;     // 8 words
    pub const IN_AMOUNT_LO: usize = 16;
    pub const IN_AMOUNT_HI: usize = 17;
    pub const IN_ASSET: usize = 18;
    pub const IN_TIME: usize = 19;
    pub const IN_R: usize = 20;       // 8 words
    pub const OUT_PK: usize = 28;     // 8 words
    pub const OUT_TIME: usize = 36;
    pub const OUT_R: usize = 37;      // 8 words
    /// `DEPTH` sibling `Word8`s, leaf to root (private: the Merkle witness).
    pub const PATH: usize = 45;       // DEPTH * 8 words
    /// The spent note's leaf index; bit `level` selects which side it's on at that level.
    pub const INDEX: usize = PATH + DEPTH * 8;   // 301
    pub const COUNT: usize = INDEX + 1;          // 302
}

/// Output-slot layout of `guests::transfer`: the public values a ledger reads. `NUM_OUTPUTS`
/// stays 8 (`isa.rs`) — the whole slot range is the single output-commitment digest
/// (`output_digest`), not four separate `Word8`s.
pub mod output {
    pub const DIGEST: usize = 0; // 8 words
}

/// Builds the guest's private inputs for spending `spent` (which must be owned by `sk` and
/// whose commitment is the tree leaf at `index`, with sibling path `path`, leaf to root) into
/// `created` (whose `from` must be `sk`'s address and whose amount and asset must match).
pub fn transfer_inputs(sk: &SpendKey, spent: &Note, created: &Note, path: &[Word8; DEPTH], index: u32) -> [u32; input::COUNT] {
    let mut v = [0u32; input::COUNT];
    v[input::SK..input::SK + 8].copy_from_slice(&sk.0);
    v[input::IN_FROM..input::IN_FROM + 8].copy_from_slice(&spent.from);
    v[input::IN_AMOUNT_LO] = spent.amount as u32;
    v[input::IN_AMOUNT_HI] = (spent.amount >> 32) as u32;
    v[input::IN_ASSET] = spent.asset;
    v[input::IN_TIME] = spent.time;
    v[input::IN_R..input::IN_R + 8].copy_from_slice(&spent.r);
    v[input::OUT_PK..input::OUT_PK + 8].copy_from_slice(&created.pk);
    v[input::OUT_TIME] = created.time;
    v[input::OUT_R..input::OUT_R + 8].copy_from_slice(&created.r);
    for (level, sib) in path.iter().enumerate() { v[input::PATH + 8 * level..input::PATH + 8 * level + 8].copy_from_slice(sib); }
    v[input::INDEX] = index;
    v
}

/// What the guest's eight output words should be for an honest run — the reference the
/// emulator and the proof are checked against. `anchor` is the tree root the Merkle witness
/// (`path`/`index` inside `inputs`, not taken here) proves membership against; callers get it
/// from `ledger::CommitmentTree::root` (or `Ledger::path_for`, which returns both).
pub fn expected_outputs(sk: &SpendKey, spent: &Note, created: &Note, anchor: Word8) -> [u32; crate::isa::NUM_OUTPUTS] {
    let vk = sk.viewing_key();
    let cm_in = spent.commitment();
    let nf = vk.nullifier(&cm_in);
    let cm_out = created.commitment();
    output_digest(&anchor, &nf, &cm_out, created.time)
}

/// The private-input vector of `guests::bundle`: spend key, two input notes (each `from`,
/// `amount_lo`, `amount_hi`, `asset`, `time`, `r`, a depth-32 Merkle witness), the tree root
/// every real input is checked against, two output notes (`pk`, `amount_lo`, `amount_hi`, `r`
/// — `from`/`time`/`asset` are not separately supplied, since the guest always sets an
/// output's `from` to the derived `pk_self` and its `time`/`asset` to the bundle's own public
/// `time`/`asset`, design spec §4 items 4/6/7), and the four bundle-level values (`fee`,
/// `burn` as u64 pairs, `asset`, `time`) that get folded into the digest. Flat, like `input` —
/// no stride abstraction, so a value's offset is a single named constant exactly as `input`'s
/// are.
pub mod bundle_input {
    use super::DEPTH;
    pub const SK: usize = 0;                                // 8
    pub const IN1_FROM: usize = 8;                          // 8
    pub const IN1_AMOUNT_LO: usize = 16;
    pub const IN1_AMOUNT_HI: usize = 17;
    pub const IN1_ASSET: usize = 18;
    pub const IN1_TIME: usize = 19;
    pub const IN1_R: usize = 20;                            // 8
    pub const IN1_PATH: usize = 28;                         // DEPTH * 8 = 256
    pub const IN1_INDEX: usize = IN1_PATH + DEPTH * 8;      // 284
    pub const IN2_FROM: usize = IN1_INDEX + 1;              // 285
    pub const IN2_AMOUNT_LO: usize = IN2_FROM + 8;          // 293
    pub const IN2_AMOUNT_HI: usize = IN2_AMOUNT_LO + 1;
    pub const IN2_ASSET: usize = IN2_AMOUNT_HI + 1;
    pub const IN2_TIME: usize = IN2_ASSET + 1;
    pub const IN2_R: usize = IN2_TIME + 1;                  // 8
    pub const IN2_PATH: usize = IN2_R + 8;                  // DEPTH * 8
    pub const IN2_INDEX: usize = IN2_PATH + DEPTH * 8;      // 561
    /// The tree root every real input's `MERKLE_VERIFY` is checked against (§4 item 2), and
    /// the value the guest publishes as `anchor` (an honest wallet passes `ledger.root()`).
    pub const ANCHOR: usize = IN2_INDEX + 1;                // 562, 8 words
    pub const OUT1_PK: usize = ANCHOR + 8;                  // 8
    pub const OUT1_AMOUNT_LO: usize = OUT1_PK + 8;
    pub const OUT1_AMOUNT_HI: usize = OUT1_AMOUNT_LO + 1;
    pub const OUT1_R: usize = OUT1_AMOUNT_HI + 1;           // 8
    pub const OUT2_PK: usize = OUT1_R + 8;                  // 8
    pub const OUT2_AMOUNT_LO: usize = OUT2_PK + 8;
    pub const OUT2_AMOUNT_HI: usize = OUT2_AMOUNT_LO + 1;
    pub const OUT2_R: usize = OUT2_AMOUNT_HI + 1;           // 8
    pub const FEE_LO: usize = OUT2_R + 8;
    pub const FEE_HI: usize = FEE_LO + 1;
    pub const BURN_LO: usize = FEE_HI + 1;
    pub const BURN_HI: usize = BURN_LO + 1;
    pub const ASSET: usize = BURN_HI + 1;
    pub const TIME: usize = ASSET + 1;
    pub const COUNT: usize = TIME + 1;                      // 612
}

/// `bundle`'s single public output: `H(BUNDLE, anchor, nf1, nf2, cm1, cm2, fee_lo, fee_hi,
/// burn_lo, burn_hi, asset, time, bad)` — 47 words after the domain tag. `bad` is always `0`
/// here: this is the host-side reference for an *honest* digest (what the ledger independently
/// recomputes from the plaintext a bundle publishes); only the guest itself ever writes a
/// nonzero `bad` word (see `domain::BUNDLE`'s doc comment).
#[allow(clippy::too_many_arguments)]
pub fn bundle_digest(anchor: &Word8, nf1: &Word8, nf2: &Word8, cm1: &Word8, cm2: &Word8, fee: u64, burn: u64, asset: u32, time: u32) -> Word8 {
    let mut msg = [0u32; 47];
    msg[0..8].copy_from_slice(anchor);
    msg[8..16].copy_from_slice(nf1);
    msg[16..24].copy_from_slice(nf2);
    msg[24..32].copy_from_slice(cm1);
    msg[32..40].copy_from_slice(cm2);
    msg[40] = fee as u32; msg[41] = (fee >> 32) as u32;
    msg[42] = burn as u32; msg[43] = (burn >> 32) as u32;
    msg[44] = asset;
    msg[45] = time;
    msg[46] = 0; // bad: always 0 for the honest host-side reference digest
    hash(domain::BUNDLE, &msg)
}

/// The reference `guests::bundle`'s output is checked against for an HONEST witness
/// (`tests/bundle.rs`), and what a wallet recomputes before submitting a bundle. Computes
/// nf1/nf2/cm1/cm2 from `sk`/`inputs`/`outputs` the same way the guest does (owner forced to
/// `pk_self`) and folds them with `anchor`/`fee`/`burn`/`asset`/`time` into `bundle_digest`.
/// `inputs[i].0` with `.amount == 0` is a dummy (its path/index are never dereferenced against
/// the real tree by this function — membership is a guest-side, not host-side, check — so any
/// value is fine there for a dummy).
///
/// Dummy notes are not so forgiving about `r`, on *either* side: a dummy still needs a freshly
/// random `r` like any other note (`Note::new`), because its commitment is a plain hash of its
/// words. An all-zero `r` makes every such dummy commit to the same value, which repeats across
/// bundles and, within one bundle, collides with the other slot's dummy:
///
/// - two zero-`r` dummy *outputs* give `cm_out1 == cm_out2`, which `guests::bundle`'s
///   duplicate-output check taints in-circuit and `Ledger::apply_bundle` rejects as
///   `DuplicateCommitmentInBundle`; one at a time, a zero-`r` dummy output still collides with
///   an earlier bundle's dummy leaf (`LedgerError::Duplicate`);
/// - two zero-`r` dummy *inputs* give the same `cm_in`, hence `nf1 == nf2` (a nullifier is a
///   deterministic function of the commitment), which the duplicate-input check taints and
///   `apply_bundle` rejects as `DuplicateNullifierInBundle`; one at a time, it is a nullifier
///   an earlier bundle already published (`LedgerError::Spent`).
///
/// So a wallet building a bundle must use `Note::new` for its dummies, not a hand-written
/// `Note { .., r: [0; 8] }`.
///
/// Deliberately does **not** re-derive `outputs[i]`'s `from`/`time`/`asset` from
/// `pk_self`/the bundle's fields the way the guest structurally does — it trusts the caller's
/// `outputs: &[Note; 2]` already has `from = pk_self`, `time`/`asset` matching the bundle's,
/// because this function is the *host* reference for an *honest* run (a wallet building its
/// own bundle), and the guest's structural enforcement is exactly what makes a *dishonest*
/// caller's mismatched `outputs` produce a different, non-matching digest.
#[allow(clippy::too_many_arguments)]
pub fn expected_bundle_outputs(
    sk: &SpendKey,
    inputs: &[(Note, [Word8; DEPTH], u32); 2],
    outputs: &[Note; 2],
    anchor: Word8, fee: u64, burn: u64, asset: u32, time: u32,
) -> [u32; crate::isa::NUM_OUTPUTS] {
    let vk = sk.viewing_key();
    let pk_self = vk.pk();
    let cm_in = |note: &Note| Note { pk: pk_self, ..*note }.commitment();
    let cm1 = cm_in(&inputs[0].0);
    let cm2 = cm_in(&inputs[1].0);
    let nf1 = vk.nullifier(&cm1);
    let nf2 = vk.nullifier(&cm2);
    let cm_out1 = outputs[0].commitment();
    let cm_out2 = outputs[1].commitment();
    bundle_digest(&anchor, &nf1, &nf2, &cm_out1, &cm_out2, fee, burn, asset, time)
}

/// Builds `guests::bundle`'s private-input vector.
#[allow(clippy::too_many_arguments)]
pub fn bundle_inputs(
    sk: &SpendKey,
    inputs: &[(Note, [Word8; DEPTH], u32); 2],
    outputs: &[Note; 2],
    anchor: Word8, fee: u64, burn: u64, asset: u32, time: u32,
) -> Vec<u32> {
    use bundle_input::*;
    let mut v = vec![0u32; COUNT];
    v[SK..SK + 8].copy_from_slice(&sk.0);
    #[allow(clippy::too_many_arguments)]
    fn put_in(v: &mut [u32], from_off: usize, amt_lo: usize, amt_hi: usize, asset_off: usize, time_off: usize, r_off: usize, path_off: usize, index_off: usize, note: &Note, path: &[Word8; DEPTH], index: u32) {
        v[from_off..from_off + 8].copy_from_slice(&note.from);
        v[amt_lo] = note.amount as u32;
        v[amt_hi] = (note.amount >> 32) as u32;
        v[asset_off] = note.asset;
        v[time_off] = note.time;
        v[r_off..r_off + 8].copy_from_slice(&note.r);
        for (level, sib) in path.iter().enumerate() { v[path_off + 8 * level..path_off + 8 * level + 8].copy_from_slice(sib); }
        v[index_off] = index;
    }
    put_in(&mut v, IN1_FROM, IN1_AMOUNT_LO, IN1_AMOUNT_HI, IN1_ASSET, IN1_TIME, IN1_R, IN1_PATH, IN1_INDEX, &inputs[0].0, &inputs[0].1, inputs[0].2);
    put_in(&mut v, IN2_FROM, IN2_AMOUNT_LO, IN2_AMOUNT_HI, IN2_ASSET, IN2_TIME, IN2_R, IN2_PATH, IN2_INDEX, &inputs[1].0, &inputs[1].1, inputs[1].2);
    v[ANCHOR..ANCHOR + 8].copy_from_slice(&anchor);
    v[OUT1_PK..OUT1_PK + 8].copy_from_slice(&outputs[0].pk);
    v[OUT1_AMOUNT_LO] = outputs[0].amount as u32; v[OUT1_AMOUNT_HI] = (outputs[0].amount >> 32) as u32;
    v[OUT1_R..OUT1_R + 8].copy_from_slice(&outputs[0].r);
    v[OUT2_PK..OUT2_PK + 8].copy_from_slice(&outputs[1].pk);
    v[OUT2_AMOUNT_LO] = outputs[1].amount as u32; v[OUT2_AMOUNT_HI] = (outputs[1].amount >> 32) as u32;
    v[OUT2_R..OUT2_R + 8].copy_from_slice(&outputs[1].r);
    v[FEE_LO] = fee as u32; v[FEE_HI] = (fee >> 32) as u32;
    v[BURN_LO] = burn as u32; v[BURN_HI] = (burn >> 32) as u32;
    v[ASSET] = asset; v[TIME] = time;
    v
}
