//! A simulated chain for the shielded transfer: an append-only commitment Merkle tree, the
//! nullifier set, a clock, and one envelope per transaction. `apply` is what a node would
//! run: check the proof's output-commitment digest against the plaintext values it is handed
//! (`docs/06-viewing-keys.md`'s "Public outputs"), check the claimed anchor is a recent root,
//! verify the proof under the transfer guest's `hc`, then apply the effects.
//!
//! M3.3: `cm_in` (the spent note's commitment) is no longer public anywhere — `MERKLE_VERIFY`
//! proves it in-circuit against `anchor`, a tree root, so the chain no longer shows which
//! commitment a transfer spent. `anchor` alone is public (as part of the output-commitment
//! digest), and only as one of a bounded window of recent roots, not a single fixed point.
//!
//! Shielded pool phase Z: the chain carries a second, independently numbered sequence of
//! transactions, `bundles`. A [`Bundle`] is the design spec §3 shape — one anchor, two
//! nullifiers, two commitments, `fee`, `burn`, `asset`, `time`, two envelopes — and
//! [`Ledger::apply_bundle`] is its consensus check (`docs/06-viewing-keys.md`'s "Ledger
//! admission for bundles"). It runs the same *kind* of checks as `apply` — every free
//! structural one before the single expensive STARK verification — but in the spec's own
//! cheapest-first order, which is not `apply`'s; see its doc comment. Both sequences share
//! one tree, one nullifier set and one recent-roots window.

use crate::isa::Program;
use crate::machine::{Machine, Proof, VerifyError};
use crate::notes::{output_digest, Note, Word8, DEPTH};
use crate::viewing::Envelope;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug)]
pub struct Tx {
    /// `None` for a mint (created from nothing, no note spent).
    pub anchor: Option<Word8>,
    pub nf: Option<Word8>,
    pub cm_out: Word8,
    pub time: u32,
    pub envelope: Envelope,
}

#[derive(Debug)]
pub enum LedgerError {
    Proof(VerifyError),
    /// The proof's published digest does not match `output_digest(anchor, nf, cm_out, time)`
    /// for the plaintext values `apply` was handed.
    BadDigest,
    /// `anchor` is not one of the ledger's recently recorded tree roots.
    UnknownAnchor(Word8),
    /// `nf` has already been published.
    Spent(Word8),
    /// `cm_out` already exists.
    Duplicate(Word8),
    /// The created note's time is not the chain's current time (`apply`/`mint`), or a
    /// bundle's `time` is outside `Ledger::TIME_WINDOW` seconds before `now` (`apply_bundle`).
    Time { claimed: u32, now: u32 },
    /// A `Bundle`'s two nullifiers are equal (design spec §7's admission order, "the two
    /// differ"). Distinct from `Spent`, which is the cross-bundle case: this one is about the
    /// two slots *of the same bundle*, which the nullifier set alone cannot catch, since
    /// neither has been inserted yet. `guests::bundle` also taints such a witness in-circuit;
    /// this check is defence in depth, and is what catches it without paying for a
    /// verification.
    DuplicateNullifierInBundle,
    /// A `Bundle`'s two output commitments are equal — the mirror of
    /// `DuplicateNullifierInBundle` on the output side, and likewise both tainted in-circuit
    /// and checked here. Distinct from `Duplicate`, the cross-bundle case.
    DuplicateCommitmentInBundle,
    /// A `Bundle` declares a non-zero `asset` but charges a non-zero `fee` (design spec §4
    /// item 6: "`fee` is charged in asset 0, so a bundle with `asset != 0` must have
    /// `fee = 0`").
    ///
    /// Enforced by the ledger and *not* by `guests::bundle`, deliberately: `fee` and `asset`
    /// are both public chain data, and the ledger recomputes the bundle digest over both of
    /// them (step 7 of `apply_bundle`'s order), so it already knows the exact values the proof
    /// is bound to. An in-circuit comparison of two public words would add nothing that this
    /// free integer compare does not already give, and would cost a witness the guest would
    /// have to carry. Nor is this a soundness rule: the fee is subtracted from the bundle's
    /// inputs in whatever asset they are denominated in, so a fee in a foreign asset creates
    /// no value. What it would corrupt is `Ledger::fees_collected`, which is SHRUGG (asset 0)
    /// accounting; this check is what keeps that total denominated in one asset.
    FeeInForeignAsset { asset: u32, fee: u64 },
    /// A minted note's `amount` is `>= 2^63`, outside the range the design spec makes a global
    /// invariant and `guests::bundle` enforces with six `emit_range_check_u63` checks. Such a
    /// note would be a real, spendable-looking leaf that no bundle could ever spend — the
    /// range check would taint the proof and the ledger would refuse it as `BadDigest` — i.e.
    /// permanently stuck value, so the one entry point that creates notes from nothing refuses
    /// it up front. (`apply`'s transfer path preserves amounts rather than creating them, so
    /// it needs no check of its own.)
    AmountOutOfRange(u64),
}

/// An append-only, depth-`DEPTH` commitment Merkle tree, using exactly the hash the guest's
/// `MERKLE_VERIFY` uses (`notes::hash(domain::NODE, ..)`) so a witness built from
/// `path_for`/`root` verifies in-circuit. The standard incremental/sparse-Merkle-tree
/// approach: unfilled subtrees use a fixed "empty" digest per level, precomputed once, so a
/// depth-32 tree never requires materializing `2^32` leaves.
pub struct CommitmentTree {
    leaves: Vec<Word8>,
    index: HashMap<Word8, usize>,
    /// `empty[d]` is the default digest of an empty subtree of depth `d`: `empty[0]` is the
    /// all-zero "no leaf" value, `empty[d] = H(NODE, empty[d-1], empty[d-1])`.
    empty: [Word8; DEPTH + 1],
}

impl CommitmentTree {
    pub fn new() -> CommitmentTree {
        let mut empty = [[0u32; 8]; DEPTH + 1];
        for d in 1..=DEPTH {
            let prev = empty[d - 1];
            let mut msg = [0u32; 16];
            msg[..8].copy_from_slice(&prev);
            msg[8..].copy_from_slice(&prev);
            empty[d] = crate::notes::hash(crate::notes::domain::NODE, &msg);
        }
        CommitmentTree { leaves: Vec::new(), index: HashMap::new(), empty }
    }

    /// Every level's node list, level 0 (the leaves, real values only — no trailing padding)
    /// through `DEPTH` (the root, one node). An odd tail at any level is paired with that
    /// level's `empty` default rather than materialized, which is what keeps this whole
    /// computation `O(leaves)` instead of `O(2^DEPTH)`.
    fn levels(&self) -> Vec<Vec<Word8>> {
        let mut levels = vec![self.leaves.clone()];
        for level in 0..DEPTH {
            let cur = &levels[level];
            let next = if cur.is_empty() {
                vec![self.empty[level + 1]]
            } else {
                let mut out = Vec::with_capacity(cur.len().div_ceil(2));
                let mut i = 0;
                while i < cur.len() {
                    let left = cur[i];
                    let right = if i + 1 < cur.len() { cur[i + 1] } else { self.empty[level] };
                    let mut msg = [0u32; 16];
                    msg[..8].copy_from_slice(&left);
                    msg[8..].copy_from_slice(&right);
                    out.push(crate::notes::hash(crate::notes::domain::NODE, &msg));
                    i += 2;
                }
                out
            };
            levels.push(next);
        }
        levels
    }

    /// MINOR: appends unconditionally, even if `cm` is already a leaf — the new leaf is
    /// pushed regardless, but `self.index.insert` then overwrites the existing index entry to
    /// point at the *new* position, leaving the old leaf still physically in the tree but
    /// unreachable through `index`/`path_for`. This method does not itself guard against that;
    /// `Ledger::mint`/`Ledger::apply` are what actually make duplicate commitments impossible
    /// in practice, by checking `self.tree.index.contains_key(&cm)` and returning
    /// `LedgerError::Duplicate` before ever calling `append`. Rejecting duplicates is therefore
    /// the caller's responsibility, not this method's.
    pub fn append(&mut self, cm: Word8) -> usize {
        let idx = self.leaves.len();
        self.leaves.push(cm);
        self.index.insert(cm, idx);
        idx
    }

    pub fn root(&self) -> Word8 { *self.levels()[DEPTH].first().unwrap_or(&self.empty[DEPTH]) }

    /// The sibling path (leaf to root) and index for the leaf at `index`.
    pub fn path(&self, index: usize) -> [Word8; DEPTH] {
        let levels = self.levels();
        let mut path = [[0u32; 8]; DEPTH];
        let mut idx = index;
        for level in 0..DEPTH {
            let nodes = &levels[level];
            let sib = idx ^ 1;
            path[level] = if sib < nodes.len() { nodes[sib] } else { self.empty[level] };
            idx /= 2;
        }
        path
    }

    /// The path and index for the leaf equal to `cm`, if it has been appended.
    pub fn path_for(&self, cm: &Word8) -> Option<([Word8; DEPTH], u32)> {
        let idx = *self.index.get(cm)?;
        Some((self.path(idx), idx as u32))
    }
}

impl Default for CommitmentTree {
    fn default() -> Self { Self::new() }
}

pub struct Ledger {
    /// The transfer guest; every `apply`/`mint` proof is verified against its `hc`.
    pub program: Program,
    /// The bundle guest (`guests::bundle`); every `apply_bundle` proof is verified against
    /// *its* `hc`, which is a different program digest from `program`'s — a transfer proof
    /// therefore cannot be submitted as a bundle, or the other way round.
    pub bundle_program: Program,
    pub txs: Vec<Tx>,
    /// Admitted bundles, in chain order. A `Bundle`'s index here is what `viewing::Row`'s
    /// `tx` field means when its `source` is `RowSource::Bundle` — the two sequences are
    /// numbered independently.
    pub bundles: Vec<Bundle>,
    tree: CommitmentTree,
    /// Bounded window of the tree's most recent roots, oldest first — what `apply` and
    /// `apply_bundle` accept an `anchor` against. Starts with the genesis (empty-tree) root.
    recent_roots: VecDeque<Word8>,
    nullifiers: HashSet<Word8>,
    /// Block time. A transaction must carry it.
    pub now: u32,
    /// Total `fee` across every admitted bundle — the design spec's "the proposer is paid"
    /// accounting (§3, §8's "every bundle fee in a block is credited to the proposer's rewards
    /// field"). Phase Z only *totals* it: routing a fee to a particular validator needs an
    /// actions layer this crate does not have, and is phase S2's job.
    ///
    /// It is a single-asset total, and legitimately so: §4 item 6 charges every fee in asset 0
    /// (SHRUGG), and `apply_bundle` refuses a bundle that declares another asset with a
    /// non-zero fee (`LedgerError::FeeInForeignAsset`), so nothing but SHRUGG can ever reach
    /// this accumulator.
    pub fees_collected: u64,
    /// Total value that has left the pool through `burn` (the Bond/BridgeBurn mechanism, §3,
    /// §6) — again only totaled here, never routed to a destination (S2/S3).
    ///
    /// Unlike `fees_collected`, this one *is* cross-asset: `burn` is denominated in the
    /// bundle's own `asset`, whatever it is, and no rule confines it to asset 0. So this is a
    /// count of units burned across all assets, useful as a ledger-level "something left the
    /// pool" signal and nothing more. S2/S3, which give the burn a destination, are where it
    /// has to become per-asset; do not read it as SHRUGG until then.
    pub burned: u64,
}

/// A shielded-pool bundle transaction (design spec §3), restricted to what phase Z's zkVM side
/// needs in order to admit one: the fee/burn *destination* accounting the full node's actions
/// layer will need (S2/S3) is out of scope, so this only carries the totals a ledger-level
/// auditor cares about.
///
/// Every field here is public chain data, exactly as `Tx`'s are. Note in particular that a
/// dummy input's nullifier and a dummy output's commitment are, by design (§3), not
/// distinguishable on chain from real ones — the whole point of the fixed 2-in-2-out shape —
/// so `apply_bundle` puts them through the very same nullifier-set/tree path as real ones and
/// never tries to detect "this one is fake".
#[derive(Clone, Debug)]
pub struct Bundle {
    pub anchor: Word8,
    pub nullifiers: [Word8; 2],
    pub commitments: [Word8; 2],
    pub fee: u64,
    pub burn: u64,
    pub asset: u32,
    pub time: u32,
    /// One envelope per output, in the same slot order as `commitments` — `envelopes[i]` is
    /// sealed against `commitments[i]` as its associated data.
    pub envelopes: [Envelope; 2],
}

impl Ledger {
    /// How many of the tree's most recent roots the ledger accepts as an `anchor` — a proof
    /// may be built against a root that is no longer the very latest one (another transaction
    /// can land first), as long as it is recent enough. 64 per the design spec §7 ("a prover
    /// about a minute at 1 s blocks"), up from the M3.3-era 16. Applies to both `transfer` and
    /// `bundle`: `record_root`, `apply` and `apply_bundle` all read the same `recent_roots`
    /// deque.
    pub const ANCHOR_WINDOW: usize = 64;

    /// How far in the past a bundle's `time` may be, in seconds — the design spec §7's "`time`
    /// within 64 of the block height", checked here against `now` since this crate has no
    /// block height (see `apply_bundle`'s doc comment). A `time` in the *future* is never
    /// accepted. `apply`/`mint` (the transfer path) keep their stricter `time == now`.
    pub const TIME_WINDOW: u32 = 64;

    pub fn new(now: u32) -> Ledger {
        let tree = CommitmentTree::new();
        let mut recent_roots = VecDeque::new();
        recent_roots.push_back(tree.root());
        Ledger {
            program: crate::guests::transfer(),
            bundle_program: crate::guests::bundle(),
            txs: Vec::new(),
            bundles: Vec::new(),
            tree,
            recent_roots,
            nullifiers: HashSet::new(),
            now,
            fees_collected: 0,
            burned: 0,
        }
    }
    pub fn advance(&mut self, seconds: u32) { self.now += seconds; }
    pub fn has_commitment(&self, cm: &Word8) -> bool { self.tree.index.contains_key(cm) }
    pub fn has_nullifier(&self, nf: &Word8) -> bool { self.nullifiers.contains(nf) }
    /// The current tree root — the freshest valid `anchor`.
    pub fn root(&self) -> Word8 { self.tree.root() }
    /// The Merkle witness (path, index) for a commitment already in the tree — what
    /// `notes::transfer_inputs` needs to spend the note it belongs to.
    pub fn path_for(&self, cm: &Word8) -> Option<([Word8; DEPTH], u32)> { self.tree.path_for(cm) }

    fn record_root(&mut self) {
        self.recent_roots.push_back(self.tree.root());
        while self.recent_roots.len() > Self::ANCHOR_WINDOW { self.recent_roots.pop_front(); }
    }

    /// A deposit: a note created in the open (the bridge's mint, a public deposit) with its
    /// commitment appended to the tree directly. Its envelope is sealed like any other so the
    /// receiver's viewing key finds it.
    pub fn mint(&mut self, note: &Note, envelope: Envelope) -> Result<usize, LedgerError> {
        // The pool's global amount invariant, enforced at the only place value enters it:
        // `guests::bundle` range-checks every amount it sees `< 2^63`, so a leaf minted above
        // that bound could never be spent by a bundle (see `AmountOutOfRange`).
        if note.amount >= 1u64 << 63 { return Err(LedgerError::AmountOutOfRange(note.amount)); }
        if note.time != self.now { return Err(LedgerError::Time { claimed: note.time, now: self.now }); }
        let cm = note.commitment();
        if self.tree.index.contains_key(&cm) { return Err(LedgerError::Duplicate(cm)); }
        self.tree.append(cm);
        self.record_root();
        self.txs.push(Tx { anchor: None, nf: None, cm_out: cm, time: note.time, envelope });
        Ok(self.txs.len() - 1)
    }

    /// The consensus check for a transfer. `anchor`/`nf`/`cm_out`/`time` are the plaintext
    /// values the guest's output-commitment digest attests to (`docs/06-viewing-keys.md`) —
    /// published the same way `cm_out`/`time` always were, as plain transaction metadata, not
    /// hidden inside the envelope. Cheap structural checks run first so a node never pays for
    /// a STARK verification of a transaction it would reject anyway; the proof is then
    /// verified and the tree/nullifier set updated.
    #[allow(clippy::too_many_arguments)]
    pub fn apply(&mut self, machine: &Machine, proof: &Proof, anchor: Word8, nf: Word8, cm_out: Word8, time: u32, envelope: Envelope) -> Result<usize, LedgerError> {
        use crate::tables::cpu::pv;
        // Same shape check `verify` makes first, so a malformed proof is a proof error and not
        // a misleading digest mismatch. A slot outside 32 bits cannot come from an honest
        // trace (an output is a register word); `verify` rejects it, and until then the digest
        // simply cannot match.
        if proof.public_values.len() != pv::NUM { return Err(LedgerError::Proof(VerifyError::PublicValues)); }
        if proof.public_values[pv::OUT0..pv::OUT0 + 8].iter().any(|v| *v > u32::MAX as u64) { return Err(LedgerError::BadDigest); }
        let published: Word8 = std::array::from_fn(|i| proof.public_values[pv::OUT0 + i] as u32);
        if published != output_digest(&anchor, &nf, &cm_out, time) { return Err(LedgerError::BadDigest); }
        if !self.recent_roots.contains(&anchor) { return Err(LedgerError::UnknownAnchor(anchor)); }
        if self.nullifiers.contains(&nf) { return Err(LedgerError::Spent(nf)); }
        if self.tree.index.contains_key(&cm_out) { return Err(LedgerError::Duplicate(cm_out)); }
        if time != self.now { return Err(LedgerError::Time { claimed: time, now: self.now }); }
        machine.verify(&self.program.digest(), proof).map_err(LedgerError::Proof)?;
        self.nullifiers.insert(nf);
        self.tree.append(cm_out);
        self.record_root();
        self.txs.push(Tx { anchor: Some(anchor), nf: Some(nf), cm_out, time, envelope });
        Ok(self.txs.len() - 1)
    }

    /// The consensus check for a bundle (design spec §7), restricted to what phase Z can check
    /// without an actions/fee-floor/anchor-height layer: this crate has no mempool, no wire
    /// encoding (so §7's size checks are not modeled), no block height beyond `now`, and no
    /// action types. §7's "`time` within 64 of the block height" is therefore checked against
    /// `now` — the same stand-in `apply`/`mint` already make, widened from their exact
    /// `time == now` to the spec's actual window (`Ledger::TIME_WINDOW`), since a bundle prover
    /// legitimately needs the seconds the `ANCHOR_WINDOW` exists to give it. S1 will implement
    /// the rule against a real height.
    ///
    /// Admission order, cheapest first. It is **not** `apply`'s order, and the difference is
    /// deliberate rather than drift: `apply` recomputes its digest second, immediately after
    /// the shape check, while this recomputes seventh, after every window/set/tree lookup. A
    /// bundle digest is a Poseidon2 sponge over 47 words; a `recent_roots` scan, two `HashSet`
    /// probes and two `HashMap` probes together are not close to that. Ordering them
    /// cheapest-first is what the design spec §7 asks for. What the two *do* share, and what
    /// actually matters, is that every free structural check runs before the one expensive
    /// thing, the STARK verification, which is last in both.
    ///
    /// 1. shape — the proof carries `pv::NUM` public values, and its eight digest words are
    ///    canonical field-to-`u32` values (nothing an honest trace can violate; checked so a
    ///    malformed proof is a proof error, not a misleading digest mismatch);
    /// 2. `anchor` is one of the last `ANCHOR_WINDOW` recorded roots;
    /// 3. `time` is within `TIME_WINDOW` seconds before `now`, and not in the future;
    /// 4. a bundle in a foreign asset (`asset != 0`) charges no `fee` (spec §4 item 6 — two
    ///    integer compares over public words, see `LedgerError::FeeInForeignAsset` for why
    ///    the ledger and not the circuit enforces it);
    /// 5. the two nullifiers differ, and neither is already spent;
    /// 6. the two commitments differ, and neither is already a leaf;
    /// 7. the digest recomputed from the published plaintext equals `pv::OUT0..8`;
    /// 8. the proof verifies under `bundle_program`'s `hc` — last, and only then.
    ///
    /// The digest is recomputed with `notes::bundle_digest`, which fixes the preimage's 47th
    /// word (`bad`) at `0`: `bad` is a guest-internal taint flag with no plaintext channel, so
    /// a bundle whose guest set it publishes a digest this recomputation can never match, and
    /// is rejected at step 7 as `BadDigest` (that is how every in-circuit relation failure —
    /// over-spend, a wrong Merkle path, an asset mismatch, a 64-bit wrap — reaches the ledger).
    ///
    /// Effects on success: both nullifiers inserted, both commitments appended in slot order,
    /// the new root recorded, `fee`/`burn` accumulated, the bundle pushed. Returns its index in
    /// `self.bundles`.
    pub fn apply_bundle(&mut self, machine: &Machine, proof: &Proof, b: &Bundle) -> Result<usize, LedgerError> {
        use crate::tables::cpu::pv;
        if proof.public_values.len() != pv::NUM { return Err(LedgerError::Proof(VerifyError::PublicValues)); }
        if proof.public_values[pv::OUT0..pv::OUT0 + 8].iter().any(|v| *v > u32::MAX as u64) { return Err(LedgerError::BadDigest); }
        if !self.recent_roots.contains(&b.anchor) { return Err(LedgerError::UnknownAnchor(b.anchor)); }
        if b.time > self.now || self.now - b.time > Self::TIME_WINDOW { return Err(LedgerError::Time { claimed: b.time, now: self.now }); }
        if b.asset != 0 && b.fee != 0 { return Err(LedgerError::FeeInForeignAsset { asset: b.asset, fee: b.fee }); }
        if b.nullifiers[0] == b.nullifiers[1] { return Err(LedgerError::DuplicateNullifierInBundle); }
        for nf in &b.nullifiers { if self.nullifiers.contains(nf) { return Err(LedgerError::Spent(*nf)); } }
        if b.commitments[0] == b.commitments[1] { return Err(LedgerError::DuplicateCommitmentInBundle); }
        for cm in &b.commitments { if self.tree.index.contains_key(cm) { return Err(LedgerError::Duplicate(*cm)); } }
        let published: Word8 = std::array::from_fn(|i| proof.public_values[pv::OUT0 + i] as u32);
        let expected = crate::notes::bundle_digest(&b.anchor, &b.nullifiers[0], &b.nullifiers[1], &b.commitments[0], &b.commitments[1], b.fee, b.burn, b.asset, b.time);
        if published != expected { return Err(LedgerError::BadDigest); }
        machine.verify(&self.bundle_program.digest(), proof).map_err(LedgerError::Proof)?;
        for nf in &b.nullifiers { self.nullifiers.insert(*nf); }
        for cm in &b.commitments { self.tree.append(*cm); }
        self.record_root();
        // Saturating, not `+=`: these are `u64` totals over an unbounded number of bundles,
        // each contributing a `fee`/`burn` the guest only range-checks `< 2^63`, so the sum
        // can overflow in a way no single bundle can. A saturated total is visibly wrong to an
        // auditor; a wrapped one silently reads as almost nothing.
        self.fees_collected = self.fees_collected.saturating_add(b.fee);
        self.burned = self.burned.saturating_add(b.burn);
        self.bundles.push(b.clone());
        Ok(self.bundles.len() - 1)
    }
}
