//! The chain-side verifier: implements randprotocol-core's executor trait with the zkVM.
//!
//! M3.4: the verifier no longer holds the program at all — `Machine::verify` takes `hc`, the
//! in-circuit Poseidon2 digest of the program (`isa::Program::digest`), never `words`. The
//! verifier key it needs is `(tier, program_log_height)`-keyed and program-*content*-independent
//! (`Machine::verifier_key`'s own doc comment), so `Machine` already caches it end to end; there
//! is no second, program-keyed cache to maintain here any more (see `warm`'s doc comment for
//! what "warm" means now).
//!
//! M4.1: the verifier key grew a third key component, `input_log_height` — the input table's
//! declared height, exactly as `program_log_height` already was (`tables::input::input_log_height`'s
//! doc comment mirrors `tables::program::program_log_height`'s rule). `verify_call`'s degree-bits
//! pre-check and `warm` both bound and thread it through the same way they already did for
//! `program_log_height`.
//!
//! M4.2 (constraint set 5): a proof now declares *four* table heights, not two. The keccak
//! table's `keccak_log_height` joins the key as a fourth component — and is **optional**: `0`
//! means the proof declares no keccak table at all, an eight-instance batch. `mem_log_height`
//! is proof-declared too, but is deliberately *not* part of the verifier key (every valid
//! memory height yields the same `CommonData`; see `Machine::verifier_key`) — it only enters
//! the degree-bit vector. `decode_and_check` therefore delegates every range check on the
//! declared shape to `machine::check_declared_heights`, the exact function `Machine::verify`
//! runs, rather than restating its rules here: the chain's bound on a keccak-bearing proof
//! *is* upstream's (`klh ∈ [5, min(tier + 5, 20)]`), and what keeps an absurd declaration cheap
//! is that the degree-bits pre-check below rejects it before any verifier key is built.
//!
//! Constraint set 6: two more declared heights join the key — M4.4's `sha256_log_height`
//! (optional, on the keccak table's exact terms, `0` = no sha256 table) and the public input
//! segment's `public_log_height` (**mandatory**: every proof commits to a public segment, even
//! an empty one, which declares `tables::public::MIN_LOG_HEIGHT`). The public segment also
//! changes *what* verification means: `H_PUB` (`pv::PUB0..7`) is unsalted, so a verifier that
//! holds the words can recompute it — `Machine::verify_public`. `verify_bundle` runs
//! `verify_public(hc, &binding, proof)`, which pins `H_PUB` to `hash::public_digest(&binding)`:
//! since Task 5b (the transaction binding, a hard fork like constraint set 6) every bundle proof is
//! made over, and verified against, the eight words of `Transaction::binding` of the transaction it
//! rides in — so a proof copied onto a transaction with a changed action, changed envelopes or a
//! different companion bundle no longer verifies. The bundle guest never reads the segment
//! (`SYS_READ_PUBLIC`); it does not need to, because the public table's `PUBLIC_DIGEST` bus binds
//! the committed words into `H_PUB` whether or not the guest reads them. Since the
//! call limits (spec §5) a program may be deployed with a public input, whose digest the ledger
//! records once at deploy (`ProgramRecord::public_digest`); `verify_call` runs `verify` and then
//! compares `pv::PUB0..7` with that digest, or with `public_digest(&[])` for a program without
//! one — the same check as `verify_public`, without re-hashing the words on every call. Plain `verify` would leave `pv::PUB0..7`
//! unchecked against anything outside the proof — a guest reading a prover-chosen public
//! segment the chain never saw — and every honest proof by today's guests (none of which calls
//! `SYS_READ_PUBLIC`) has the empty segment anyway, so the stronger check costs nothing.
//!
//! Verifying a proof costs ~16-20 ms once its `(tier, program_log_height, input_log_height,
//! keccak_log_height, sha256_log_height, public_log_height)` verifier key is known; computing
//! that key (the range/nibble/Poseidon2-round-constant preprocessed commitment, FRI-expanded) is
//! the dominant cost of an uncached verify (`docs/03-privacy.md`).

use crate::isa::{Instr, Program};
use crate::machine::{check_declared_heights, Backend, FriProfile, Machine, Proof, Tier, TIERS};
use crate::tables::cpu::pv;
use crate::tables::{input, program, public};
use randprotocol_core::confidential::{ConfidentialError, ConfidentialExecutor};
use randprotocol_core::notes::{BundleDigestInput, Word8};
use randprotocol_core::program::{CallOutcome, ProgramRecord};
use randprotocol_core::types::TX_BINDING_WORDS;

/// M4.2: the `keccak_log_height` of a proof that declares no keccak table — the batch shape
/// every guest this chain deploys produces, and the only keccak class `warm`/`warm_bundle`
/// precompute a verifier key for. Named rather than inlined as `0` because `0` is a *value* of
/// that key component, not the absence of one (`Machine::verifier_key`'s doc comment).
const NO_KECCAK: u8 = 0;

/// M4.4 (arrived with constraint set 6): the sha256 table's analogue of `NO_KECCAK` — no guest
/// this chain deploys calls `SYS_SHA256`, and `warm`/`warm_bundle` precompute no sha256 class.
const NO_SHA256: u8 = 0;

/// The one tier a bundle proof may declare (zkvm I1). The hidden-asset guest has a single
/// execution shape up to the dummy skip and the Merkle bit branch, so *every* witness a prover
/// can build — the ten input shapes and the adversarial cycle-worst one — lands here, measured by
/// `tests/hidden_bundle.rs`'s `every_shape_lands_at_tier_14_with_identical_table_heights`. It is
/// a function of cycles and permutations alone (`Tier::for_workload`), so it does not vary with
/// the FRI profile: `warm_bundle` precomputes this tier's key and `decode_and_check` refuses any
/// other, which is what keeps a junk header from making a node build one.
const BUNDLE_TIER: usize = 14;

/// The highest tier a *call* proof may declare (deep scan 2026-09-24, zkvm), enforced by
/// `verify_call` before any verifier key is built, so it is a validity rule (admission and block
/// apply both run `verify_call`). It is the highest tier `warm` pre-builds, and that is the
/// point: `Machine::verify` builds the key for whatever tier a header declares, the build grows
/// ~4× per tier step (production profile, `tests/executor.rs`'s
/// `measure_a_call_verifier_key_build_at_the_production_profile`: tier 14 ≈ 3.6 s / 227 MB,
/// tier 16 ≈ 13.7 s / 893 MB, tier 20 ≈ 216 s / 6.5 GB), and the validators are 2–4 GB droplets — so every tier past what is
/// warmed is a header an attacker submits for the price of one fee bundle and a node builds
/// synchronously, and the largest is an out-of-memory kill. `gas::MAX_TIER` (20) stays the
/// prover-side ceiling; a call that needs more than this tier is refused as
/// `ConfidentialError::CallTierTooHigh` with the remedy in the message. Raising it means
/// raising what `warm` covers with it (`TIERS[..N]` below) and re-measuring the worst
/// admissible shape at the new tier on a fleet droplet.
pub const MAX_CALL_TIER: u8 = 14;

/// The highest `keccak_log_height` a call proof may declare — 2^12 rows, 128 permutations
/// (deep scan 2026-09-24, zkvm: the second half of the finding, found by costing the worst
/// header `MAX_CALL_TIER` alone still admits). `check_declared_heights` bounds the keccak table
/// by the tier's honest need, `klh ≤ t + 5`, and the flat `tables::keccak::MAX_LOG_HEIGHT` of
/// 20 was chosen upstream as "unreachable-but-finite" — but the key's cost is the table's 99
/// *preprocessed* columns, FRI-expanded, and at the production profile a tier-14 key with
/// `klh = 19` (the tier's own bound) measures 128 s and 8.7 GB, worse than the tier-20 header
/// the finding started from; with the sha256 table at its 2^20 as well, 209 s and 10 GB
/// (`tests/executor.rs`'s `measure_a_call_verifier_key_build_at_the_production_profile`). The
/// program, input and public heights cost nothing by comparison (2^16/2^16/2^15 is the same
/// 3.9 s / 227 MB as the base), so the two hash tables are the whole of what is capped here.
///
/// 12 is a policy bound, not an honest-shape one: a tier-14 guest could honestly make 16 383
/// keccak calls. What real calls need is far smaller — the translated ERC-20's harness hashes
/// a handful of storage slots and ABI words, the EVM interpreter additionally binds its code
/// (136 bytes a permutation, so 128 covers a 17 KB contract), and the suite's largest is 40
/// permutations (`tests/e2e.rs`). A call past it is refused as `InvalidProof` naming the cap.
///
/// With every pin in place the worst header a call may still declare — tier 14, program and
/// input tables at 2^16, public at 2^15, both hash tables at their caps — builds in 4.7 s at
/// 312 MB peak, and eight such keys retained by `Machine`'s cache together peak at 711 MB
/// (~60 MB retained a key; the same harness, `;`-separated shapes).
pub const MAX_CALL_KECCAK_LOG_HEIGHT: u8 = 12;
/// The sha256 table's twin — 2^13 rows, 128 compressions (8 KB hashed). Its preprocessed trace
/// is ten columns to keccak's 99, so it is the cheaper of the two at equal height (2^16 costs
/// 5.1 s / 366 MB against keccak's 2^15 at 14 s / 702 MB), but 2^20 is still 48.7 s and 3.3 GB.
/// No guest this chain deploys calls `SYS_SHA256`; the sBPF interpreter's PDA derivations are
/// the intended user.
pub const MAX_CALL_SHA256_LOG_HEIGHT: u8 = 13;

/// The largest `input_log_height` a call at `tier` can honestly declare — the input table's
/// analogue of `Tier::max_keccak_log_height` (deep scan 2026-09-24, zkvm). Every private-input
/// word is absorbed by an `IS_INDIGEST` cpu row, four words a row plus the salt row
/// (`hash::input_digest_row_count`), and each of those rows is a cycle inside the tier's
/// `2^t − 1` budget, so `n_in ≤ 4·(2^t − 2)` and `input_log_height(n_in) ≤ t + 2`. The flat
/// 16-bit `HASH_LEFT` cap (65 535 words, `tables::input::MAX_LOG_HEIGHT`'s doc comment) is the
/// other ceiling; the bound is the smaller of the two. `verify_call` refuses a declaration past
/// it before any verifier key is built.
pub fn max_input_log_height(tier: Tier) -> u8 {
    ((tier.0 + 2) as u8).min(input::input_log_height(u16::MAX as usize))
}

pub struct ZkExecutor {
    machine: Machine,
}

impl ZkExecutor {
    pub fn new(profile: FriProfile) -> ZkExecutor {
        ZkExecutor { machine: Machine::new(profile) }
    }

    pub fn profile(&self) -> FriProfile {
        self.machine.profile
    }

    pub fn profile_from_str(s: &str) -> Option<FriProfile> {
        match s {
            "production" => Some(FriProfile::Production),
            "test" => Some(FriProfile::Test),
            _ => None,
        }
    }

    /// Decode the `hc` (`isa::Program::digest`) a `ProgramRecord`'s `code_hash` stores — 8
    /// little-endian `u32` words, 32 bytes total (see `check_program`). Any other length means
    /// the record predates M3.4 or is otherwise corrupt; neither is a program this executor can
    /// verify a call against.
    fn hc_of(record: &ProgramRecord) -> Result<[u32; 8], ConfidentialError> {
        if record.code_hash.len() != 32 {
            return Err(ConfidentialError::WrongProgram);
        }
        let mut hc = [0u32; 8];
        for (i, word) in hc.iter_mut().enumerate() {
            *word = u32::from_le_bytes(record.code_hash[4 * i..4 * i + 4].try_into().unwrap());
        }
        Ok(hc)
    }

    /// Number of `(tier, program_log_height, input_log_height, keccak_log_height,
    /// sha256_log_height, public_log_height)` verifier keys this executor's `Machine` currently
    /// has cached — `Machine`'s own cache, not a second one kept here (see the module doc
    /// comment).
    pub fn cached_keys(&self) -> usize {
        self.machine.cached_keys()
    }

    /// Decode a proof and run every check that must precede `Machine::verify_public` — the
    /// cheap, purely structural ones, none of which touch the constraint system.
    ///
    /// The tier and all six declared table heights (`program_log_height`, `input_log_height`,
    /// `keccak_log_height`, `sha256_log_height`, `public_log_height`, `mem_log_height`) are
    /// attacker-chosen words inside the proof, and both the degree-bits comparison below and
    /// `Machine`'s verifier-key lookup shift by them, so each has to be bounded before it is
    /// used to size anything. That bounding is `machine::check_declared_heights`, called
    /// verbatim rather than restated — it is the same function `Machine::verify` runs, in the
    /// same order (tier, then program, then input, then the keccak table's flat range and
    /// keccak-vs-tier relation, then the sha256 table's pair, then the public table's plain
    /// range — mandatory, so there is no `0` escape — then memory), and the chain has no reason
    /// to want a different rule. `keccak_log_height == 0` and `sha256_log_height == 0` are
    /// legitimate and mean the proof declares no such table at all, which is every proof this
    /// chain has produced so far: neither the deployed guests nor the bundle guest uses either
    /// syscall.
    ///
    /// `exact` is what separates the two callers, and it still applies only to the program and
    /// input heights. A *call* proof's are merely range-checked here; `verify_call` then pins
    /// the program height to the deployed record's word count, bounds the input height by the
    /// tier and caps the tier itself (`MAX_CALL_TIER`), all before `Machine::verify` — which
    /// binds the heights cryptographically via the program and input digests, but only after
    /// building a key for them. A *bundle* proof is against one pinned guest with one fixed input width,
    /// so both heights are known up front and anything else is a proof for a different shape —
    /// rejected here rather than paying for a verifier key that could never match. Since zkvm I1
    /// the exact case also pins `tier` ([`BUNDLE_TIER`]) and both optional hash-table heights
    /// (`NO_KECCAK`/`NO_SHA256`), which are the *only* other prover-chosen words in a proof
    /// header that feed `Machine::verifier_key`; `mem_log_height` stays merely ranged, since it
    /// is the one header word `verifier_key` does not key on.
    ///
    /// Size is no defence here and never was: chain 13 and 14 set `max_proof_bytes` to 8 MiB
    /// (`deploy/genesis-chain13.json`), and a junk header need not carry a large body at all —
    /// the key is built from the header before any proof body is looked at.
    ///
    /// The public height *is* pinned in the exact case since Task 5b: a bundle proof carries the
    /// transaction binding — always [`TX_BINDING_WORDS`] words — so its public table has exactly
    /// one honest height, `public_log_height(TX_BINDING_WORDS)` (`public_log_height`, passed in
    /// here). Any other declared height is a proof over a segment of some other length — the empty
    /// segment of a pre-fork bundle proof among them — which `verify_public` would refuse anyway,
    /// but only after building (and caching, evicting an honest one) a verifier key for the junk
    /// height; refusing it here is deterministic and costs a comparison.
    fn decode_and_check(
        &self,
        proof: &[u8],
        program_log_height: u8,
        input_log_height: u8,
        public_log_height: u8,
        exact: bool,
    ) -> Result<Proof, ConfidentialError> {
        let proof = decode_canonical(proof)?;
        check_declared_heights(
            proof.tier,
            proof.program_log_height,
            proof.input_log_height,
            proof.keccak_log_height,
            proof.sha256_log_height,
            proof.public_log_height,
            proof.mem_log_height,
        )
        .map_err(|e| ConfidentialError::InvalidProof(format!("declared shape: {e:?}")))?;
        if exact && proof.program_log_height != program_log_height {
            return Err(ConfidentialError::InvalidProof("program height not the pinned guest's".into()));
        }
        if exact && proof.input_log_height != input_log_height {
            return Err(ConfidentialError::InvalidProof("input height not the pinned guest's".into()));
        }
        if exact && proof.public_log_height != public_log_height {
            return Err(ConfidentialError::InvalidProof("public height not the transaction binding's".into()));
        }
        // And the last three prover-chosen words of a bundle proof's header (zkvm I1). `tier`,
        // `keccak_log_height` and `sha256_log_height` were merely *ranged* by
        // `check_declared_heights`, so any of a few hundred legal triples reached
        // `Machine::verify` — which builds the verifier key for the declared shape *before*
        // verifying anything. That preprocessing pass is multi-second at the high tiers and the
        // key cache is a 64-entry FIFO, so 65 junk headers (free: no funds, no valid proof, no
        // deployed program — only a digest that matches the plaintext, which `check_bundle_proof`
        // compares cheaply) evict the honest bundle key `warm_bundle` built, and a Byzantine
        // proposer can make every validator rebuild it synchronously inside `on_proposal`.
        //
        // The hidden guest closes it because it has exactly one honest shape: every witness a
        // prover can construct lands at tier 14 — measured over all ten input shapes plus the
        // cycle-worst adversarial one in `tests/hidden_bundle.rs`
        // (`every_shape_lands_at_tier_14_with_identical_table_heights`; the lightest shape needs
        // 1 330 permutations, past tier 12's cap, and the worst fits tier 14 with 2 141 cycles
        // and 238 permutations to spare) — and it issues neither hash syscall, so both optional
        // tables are absent. `Tier::for_workload` reads cycles and permutations only, so this
        // holds at every FRI profile: the test profile's proofs are the same tier 14.
        if exact
            && (proof.tier != Tier(BUNDLE_TIER)
                || proof.keccak_log_height != NO_KECCAK
                || proof.sha256_log_height != NO_SHA256)
        {
            return Err(ConfidentialError::InvalidProof("tier or hash-table height not the pinned guest's".into()));
        }
        // Reproduces `Machine::verify`'s own equality check, which is simultaneously the check
        // that the batch's *instance count* matches what `chips` would build — nine mandatory
        // tables (the public table since constraint set 6), plus one per optional hash table
        // declared — so a header that claims `keccak_log_height = 0` while carrying ten
        // instances dies here, before any verifier key is built.
        if proof.batch.degree_bits
            != self.machine.log_ext_degrees_pub(
                proof.tier,
                proof.program_log_height,
                proof.input_log_height,
                proof.keccak_log_height,
                proof.sha256_log_height,
                proof.public_log_height,
                proof.mem_log_height,
            )
        {
            return Err(ConfidentialError::InvalidProof("degree bits".into()));
        }
        // The eight published output words are read as `u32`s by both callers, and since S3 so
        // are the eight `H_IN` words (`CallOutcome::h_in`, which a call receipt publishes); a
        // slot outside 32 bits cannot come from an honest trace — an output is a register word
        // and `H_IN` is a digest encoded as byte sums. The eight `H_PUB` words need no range
        // check of their own: `verify_call` and `verify_bundle` compare them against an expected
        // digest wholesale, and `Machine::verify` has already insisted every public
        // value is a canonical field element.
        if proof.public_values.len() != pv::NUM {
            return Err(ConfidentialError::MalformedProof);
        }
        if proof.public_values[pv::OUT0..pv::OUT0 + 8].iter().any(|v| *v > u32::MAX as u64) {
            return Err(ConfidentialError::InvalidProof("output not a u32".into()));
        }
        if proof.public_values[pv::IN0..pv::IN0 + 8].iter().any(|v| *v > u32::MAX as u64) {
            return Err(ConfidentialError::InvalidProof("H_IN word not a u32".into()));
        }
        Ok(proof)
    }

    /// The chain's bundle guest: since chain 14 the hidden-asset guest
    /// ([`Self::hidden_bundle_program`], spec
    /// `docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md` §3.10). Every
    /// shielded-pool proof on the chain is against it, and [`Self::hc_bundle`] is what a genesis
    /// pins.
    pub fn bundle_program() -> &'static Program {
        Self::hidden_bundle_program()
    }

    /// Digest of the chain's bundle guest (the hidden-asset guest) — the value a genesis pins as
    /// `hc_bundle`.
    pub fn hc_bundle() -> Word8 {
        Self::hc_hidden_bundle()
    }

    /// The `(program_log_height, input_log_height, public_log_height)` a bundle proof must
    /// declare: the hidden guest's ([`Self::hidden_bundle_heights`]). All three are fixed: the
    /// guest is one pinned program, its private-input vector is always
    /// `hidden::hidden_input::COUNT` words wide (a dummy slot is a zero-amount note, not a shorter
    /// witness — that is the whole point of the fixed 4-in-4-out shape), and its public segment
    /// is always the transaction binding, [`TX_BINDING_WORDS`] words (Task 5b) — whose height,
    /// `public_log_height(8) == 4`, is not the empty segment's `MIN_LOG_HEIGHT == 2`, so a
    /// pre-fork bundle proof is refused on the declared height alone.
    pub fn bundle_heights() -> (u8, u8, u8) {
        Self::hidden_bundle_heights()
    }

    /// The retired 2-in-2-out bundle guest (`guests::bundle`), vendored verbatim from the research
    /// crate. **Off the chain path since the hidden-asset bundle** (chain 14): no executor method
    /// verifies against it. Kept only for the tests that still need it — `tests/shielded.rs` pins
    /// its digest to upstream's (`RESEARCH_HC_BUNDLE_HEX`), and `tests/hidden_bundle.rs` checks a
    /// hidden proof is refused under it. Assembled once per process.
    pub fn legacy_bundle_program() -> &'static Program {
        static BUNDLE: std::sync::OnceLock<Program> = std::sync::OnceLock::new();
        BUNDLE.get_or_init(crate::guests::bundle)
    }

    /// Digest of the retired `bundle` guest ([`Self::legacy_bundle_program`]). No chain pins it.
    pub fn hc_legacy_bundle() -> Word8 {
        Self::legacy_bundle_program().digest()
    }

    /// The hidden-asset bundle guest (`guests::bundle_hidden`, spec
    /// `docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md`): four slots, the asset
    /// private. Node-local — there is no upstream copy to pin it against — and, since chain 14,
    /// the chain's one bundle guest ([`Self::bundle_program`]).
    ///
    /// Assembled once per process: `bundle_heights` calls this on every bundle admission (twice,
    /// in fact — `bundle_proof_digest` then `verify_bundle`), and re-running the assembler on
    /// each gossiped transaction is pure waste. The guest is a compile-time constant, so a
    /// `OnceLock` is the whole of the cache invalidation story.
    pub fn hidden_bundle_program() -> &'static Program {
        static HIDDEN: std::sync::OnceLock<Program> = std::sync::OnceLock::new();
        HIDDEN.get_or_init(crate::guests::bundle_hidden)
    }

    /// Digest of the hidden bundle guest — what a chain-14 genesis pins as `hc_bundle`.
    pub fn hc_hidden_bundle() -> Word8 {
        Self::hidden_bundle_program().digest()
    }

    /// `bundle_heights` for the hidden bundle guest: its program, its fixed
    /// `hidden::hidden_input::COUNT`-word input vector, and the transaction binding.
    pub fn hidden_bundle_heights() -> (u8, u8, u8) {
        pinned_heights(Self::hidden_bundle_program(), crate::hidden::hidden_input::COUNT)
    }

    /// `ConfidentialExecutor::bundle_proof_digest` for a hidden bundle proof: the digest it
    /// publishes, after the same structural checks (exact heights, canonical encoding).
    pub fn hidden_bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.pinned_proof_digest(Self::hidden_bundle_heights(), proof)
    }

    /// `ConfidentialExecutor::verify_bundle` for a hidden bundle proof: verified against `hc`
    /// with the transaction binding as its public segment (Task 5b), exactly as a `bundle` proof
    /// is — the empty segment and any other transaction's words are refused.
    pub fn verify_hidden_bundle(&self, hc: &Word8, proof: &[u8], binding: &[u32; TX_BINDING_WORDS]) -> Result<(), ConfidentialError> {
        self.verify_pinned_bundle(Self::hidden_bundle_heights(), hc, proof, binding)
    }

    /// The published digest of a proof of a pinned bundle guest whose heights are `heights`.
    fn pinned_proof_digest(&self, heights: (u8, u8, u8), proof: &[u8]) -> Result<Word8, ConfidentialError> {
        let (plh, ilh, pubh) = heights;
        let p = self.decode_and_check(proof, plh, ilh, pubh, true)?;
        Ok(std::array::from_fn(|k| p.public_values[pv::OUT0 + k] as u32))
    }

    /// Verifies a proof of a pinned bundle guest (heights `heights`, digest `hc`) against the
    /// transaction binding. `verify_public` against the binding (Task 5b): `H_PUB` must be the
    /// digest of exactly the eight words of `Transaction::binding` for the transaction the bundle
    /// rides in. The empty segment (every pre-fork bundle proof) is refused on its declared
    /// height, and any other transaction's words fail as `PublicValues`.
    fn verify_pinned_bundle(
        &self,
        heights: (u8, u8, u8),
        hc: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError> {
        let (plh, ilh, pubh) = heights;
        let p = self.decode_and_check(proof, plh, ilh, pubh, true)?;
        self.machine
            .verify_public(hc, binding, &p)
            .map_err(|e| ConfidentialError::InvalidBundleProof(format!("{e:?}")))
    }
}

/// The core crate's digest record as the hidden guest's (the two are field-for-field the same;
/// core cannot name a zkvm type, so the copy happens on this side).
pub fn hidden_digest_input(i: &BundleDigestInput) -> crate::hidden::HiddenDigestInput {
    let BundleDigestInput { anchor, nullifiers, commitments, fee, burn_a, burn_r, burn_asset, time } = *i;
    crate::hidden::HiddenDigestInput { anchor, nullifiers, commitments, fee, burn_a, burn_r, burn_asset, time }
}

/// The `(program_log_height, input_log_height, public_log_height)` every proof of a pinned bundle
/// guest must declare: its program's, its fixed `input_words`-wide private input's, and the
/// transaction binding's ([`TX_BINDING_WORDS`] words, Task 5b). Shared by `bundle` and the hidden
/// bundle so the two cannot drift.
fn pinned_heights(program: &Program, input_words: usize) -> (u8, u8, u8) {
    (
        program::program_log_height(program.words.len()),
        input::input_log_height(input_words),
        public::public_log_height(TX_BINDING_WORDS),
    )
}

/// Decode a proof and refuse it unless its bytes are the *canonical* postcard encoding of what
/// they decode to — `decode(bytes).to_bytes() == bytes`. `postcard::from_bytes` alone ignores
/// trailing bytes and accepts overlong varints, so without this a proof could be padded (riding
/// free under a byte-priced fee, since the fee is charged on the bytes the chain stores) or
/// re-encoded into a different transaction id for the same statement. Every proof the chain
/// decodes — fee bundle, burn bundle and call, all through `decode_and_check` — passes here
/// first; a non-canonical one is the same `MalformedProof` as an undecodable one. The re-encode
/// costs a linear pass over bytes that are about to be verified anyway.
///
/// A consensus tightening: a chain-12 block holding a non-canonical proof would be refused by
/// this build, which is one more reason the build is chain-13-only (CHANGELOG, v0.4).
pub fn decode_canonical(bytes: &[u8]) -> Result<Proof, ConfidentialError> {
    let proof: Proof = postcard::from_bytes(bytes).map_err(|_| ConfidentialError::MalformedProof)?;
    if proof.to_bytes() != bytes {
        return Err(ConfidentialError::MalformedProof);
    }
    Ok(proof)
}

impl ConfidentialExecutor for ZkExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        if base_pc % 4 != 0 {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "base_pc not word aligned".into() });
        }
        if words.is_empty() {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "empty program".into() });
        }
        // ZH4 (2026-09-12 zk audit): a program whose `base_pc + 4·len` wraps the u32 address
        // space can never execute past the wrap (`instr_at` refuses `pc < base_pc`, and
        // `Program::pc_of` wraps in release) — reject it at admission rather than let a deployer
        // pay `deploy_fee` for a program no call could ever prove.
        if base_pc as u64 + 4 * words.len() as u64 > 1 << 32 {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "program spans the u32 pc wrap".into() });
        }
        for (index, w) in words.iter().enumerate() {
            Instr::decode(*w).map_err(|e| ConfidentialError::BadInstruction { index, reason: format!("{e:?}") })?;
        }
        // M3.4: the on-chain code commitment *is* `hc` now — the exact in-circuit digest
        // `Machine::verify` checks every call's proof against, not just an informational
        // content id (`program_id`, a separate blake3 hash, already covers that role via
        // `ProgramRecord.id`). Stored as 8 little-endian `u32` words (32 bytes); `hc_of` is the
        // inverse.
        let hc = Program { base_pc, words: words.to_vec() }.digest();
        let mut out = Vec::with_capacity(32);
        for w in hc {
            out.extend_from_slice(&w.to_le_bytes());
        }
        Ok(out)
    }

    /// Precompute the verifier keys a call against `record` is likely to need, off the node
    /// loop (deploy commit / startup). Since M3.4 the key is `(tier, program_log_height)` and
    /// program-content-independent, so this warms one shared key per tier for this program's
    /// declared height. The security review (a44d3f4) found that warming a single tier left the
    /// first honest call at any other tier paying the uncached key cost inline; warming every
    /// tier would build the Poseidon2 chip's preprocessed round-constant table at `2^22` rows on
    /// a 2-vCPU validator, so this warms the tiers real guests land on today (10, 12, 14 — the
    /// transfer guest proves at 14). Since the deep scan of 2026-09-24 those are also the *only*
    /// tiers a call may declare (`MAX_CALL_TIER`, enforced by `verify_call` before any key is
    /// built), so the set warmed here is exactly the set admissible, and the two are written as
    /// one expression so they cannot drift.
    ///
    /// M4.1 (ruling): the key also carries `input_log_height`, but `warm` only knows the
    /// program's word count — it has no visibility into what any future call's private-input
    /// vector will look like, so it cannot warm "the" input height the way it warms the exact
    /// program height. It warms two classes instead: `input::MIN_LOG_HEIGHT` (`input_log_height`
    /// of a 0..3-word call — the smallest class the table shape has) and
    /// `input::input_log_height(4)` (a 4-word call — what every guest this crate deploys today
    /// actually reads: `balance_check`/`private_payment` both read exactly 4 private inputs via
    /// `guests.rs`'s `read_input(0..3)` pattern), when that is a different class from the first
    /// (it is: `input_log_height(0) == MIN_LOG_HEIGHT == 2`, `input_log_height(4) == 3`). A call
    /// with a differently-sized input vector still verifies; like an unwarmed tier, it just pays
    /// the first-verify key-build cost once per (tier, program_log_height, input_log_height).
    ///
    /// M4.2: the key carries `keccak_log_height` too, and this warms exactly one value of it —
    /// `0`, "no keccak table". That is not a guess in the way the input height is: a proof only
    /// declares a keccak table if its guest actually calls `SYS_KECCAK`, no guest this chain
    /// deploys does, and at the production profile a keccak-bearing proof is ~1.91 MB larger
    /// than one without — 3 106 757 bytes at tier 10, which `randprotocol-core`'s 2 MiB
    /// `MAX_PROOF_BYTES` refuses outright. Warming the keccak classes as well would multiply
    /// this by the whole `[5, tier + 5]` range; a call that does declare one (at the `Test`
    /// profile, or once the block-space work makes such a proof admissible) pays the key-build
    /// cost once, like an unwarmed tier.
    ///
    /// Constraint set 6: the key carries `sha256_log_height` and `public_log_height` as well,
    /// and this warms exactly one value of each, on the same grounds as the keccak class —
    /// `NO_SHA256` (no deployed guest calls `SYS_SHA256` either) and
    /// `public::public_log_height(0)` (the empty public segment's declared height,
    /// `tables::public::MIN_LOG_HEIGHT`). A program deployed with a public input (the call
    /// limits, spec §5) proves at `public_log_height(record.public_len)` instead — every call
    /// against it commits to exactly that input, so that one class is warmed in place of the
    /// empty one, and its first call pays no key build.
    fn warm(&self, record: &ProgramRecord) {
        let log_height = program::program_log_height(record.words.len());
        let smallest = input::MIN_LOG_HEIGHT;
        let typical = input::input_log_height(4);
        let input_heights: &[u8] = if typical == smallest { &[smallest] } else { &[smallest, typical] };
        let public_height = public::public_log_height(record.public_len as usize);
        // Every tier a call may declare (`MAX_CALL_TIER` and below) — the cap and this loop
        // move together, so no admissible tier is ever an unwarmed key build at admission.
        for t in TIERS.iter().filter(|t| **t as u8 <= MAX_CALL_TIER) {
            for &in_h in input_heights {
                self.machine.verifier_key(Tier(*t), log_height, in_h, NO_KECCAK, NO_SHA256, public_height);
            }
        }
    }

    fn verify_call(&self, record: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        // `Machine::verify` runs `check_declared_heights` on the proof's tier and six declared
        // table heights before using any of them to size anything — but the degree-bits pre-check
        // inside `decode_and_check` shifts by them too, so it runs that same function in front of
        // it, to avoid panicking on an attacker-chosen out-of-range value before ever reaching
        // `verify`. `decode_and_check` only *ranges* a call's tier, program and input heights;
        // the three checks below pin them against what the chain does know, and every one of
        // them runs before `Machine::verify` builds a verifier key for the declared shape.
        let proof = self.decode_and_check(proof, 0, 0, 0, false)?;
        // The tier cap (deep scan 2026-09-24, zkvm). `check_declared_heights` admits every tier
        // in `TIERS`, and `Machine::verify` builds the verifier key for the declared tier
        // *before* it looks at a byte of STARK data — every pre-check in front of that build is
        // satisfiable from public data alone (a consistent `degree_bits`, the tier's memory
        // floor, the tier public value). The tier-20 key costs 216 s and 6.5 GB at the
        // production profile, on validators that are 2–4 GB droplets, so one legal tier-20
        // header — its transaction never mined, its fee bundle's note never spent, so it can be
        // resubmitted forever — was an out-of-memory kill of the admitting node. Refused as its
        // own verdict, with the remedy in the message, so an honest prover above the cap is
        // told what to do rather than handed a `Batch(…)` failure.
        let tier = proof.tier.0 as u8;
        if tier > MAX_CALL_TIER {
            return Err(ConfidentialError::CallTierTooHigh { tier, max: MAX_CALL_TIER });
        }
        // The two optional hash tables, whose preprocessed columns are the key's real cost
        // (`MAX_CALL_KECCAK_LOG_HEIGHT`'s doc comment has the numbers): `check_declared_heights`
        // bounds them by the tier's honest need, which at tier 14 is still a 2^19-row keccak
        // table — 128 s and 8.7 GB of key. `0` declares no table and is always admitted.
        if proof.keccak_log_height > MAX_CALL_KECCAK_LOG_HEIGHT {
            return Err(ConfidentialError::InvalidProof(format!(
                "keccak height {} past the {} a call may declare",
                proof.keccak_log_height, MAX_CALL_KECCAK_LOG_HEIGHT
            )));
        }
        if proof.sha256_log_height > MAX_CALL_SHA256_LOG_HEIGHT {
            return Err(ConfidentialError::InvalidProof(format!(
                "sha256 height {} past the {} a call may declare",
                proof.sha256_log_height, MAX_CALL_SHA256_LOG_HEIGHT
            )));
        }
        // The program height is not a guess: the record holds the deployed words, and
        // `Machine::prove` declares exactly `program_log_height(program.len())` (`Program::len`
        // is `words.len()`), so any other declared height is a proof over a different program
        // table — one the `hc` compare inside `verify` would refuse, but only after a key was
        // built and cached (evicting a warmed one) for the junk height.
        if proof.program_log_height != program::program_log_height(record.words.len()) {
            return Err(ConfidentialError::InvalidProof("program height not the deployed program's".into()));
        }
        // The input height is unknown but bounded by the tier, exactly as the keccak height is
        // bounded by it inside `check_declared_heights` (`max_input_log_height`).
        if proof.input_log_height > max_input_log_height(proof.tier) {
            return Err(ConfidentialError::InvalidProof("input height past what the tier can read".into()));
        }
        // A deterministic early reject, before `hc_of` and `Machine::verify`: a call against a
        // program deployed with a public input must declare exactly the public-table height the
        // prover derives from that input's length (`Machine::prove` uses
        // `public_log_height(public.len())`, and the record's `public_len` is that length). Any
        // other height is a proof over a different public segment, which the `PUB0..7` compare
        // below would refuse anyway — but only after `verify` had built (and cached, evicting an
        // honest one) a verifier key for the junk height. Same error as that compare.
        if proof.public_log_height != public::public_log_height(record.public_len as usize) {
            return Err(ConfidentialError::InvalidProof(format!("{:?}", crate::machine::VerifyError::PublicValues)));
        }
        let hc = Self::hc_of(record)?;
        // The call limits (spec §5): `verify`, then `pv::PUB0..7` against the public input the
        // program was deployed with — its record's digest, computed once at deploy, so no word is
        // re-hashed here. A program deployed without one takes only `hash::public_digest(&[])`,
        // exactly `verify_public(hc, &[], proof)`, today's rule. Plain `verify` alone would
        // accept any `H_PUB`, bound in-circuit to a public segment the chain never saw (see the
        // module doc comment). A mismatch reports as `verify_public`'s own `PublicValues`.
        self.machine.verify(&hc, &proof).map_err(|e| ConfidentialError::InvalidProof(format!("{e:?}")))?;
        let want = record.public_digest.unwrap_or_else(|| crate::hash::public_digest(&[]));
        if (0..8).any(|i| proof.public_values[pv::PUB0 + i] != want[i] as u64) {
            return Err(ConfidentialError::InvalidProof(format!("{:?}", crate::machine::VerifyError::PublicValues)));
        }
        let outputs = std::array::from_fn(|i| proof.public_values[pv::OUT0 + i] as u32);
        // M4.1/S3: `H_IN` travels to the receipt so a call-input envelope sealed against it can
        // be opened and checked later (spec §6.1). `decode_and_check` has already refused a
        // proof whose `IN0..7` are not `u32`s, so the narrowing below cannot silently truncate.
        let h_in = std::array::from_fn(|i| proof.public_values[pv::IN0 + i] as u32);
        Ok(CallOutcome { tier: proof.tier.0 as u8, outputs, h_in })
    }

    /// `H_PUB` exactly as the circuit publishes it in `pv::PUB0..7`.
    fn public_digest(&self, words: &[u32]) -> Word8 {
        crate::hash::public_digest(words)
    }

    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        let mut msg = [0u32; 16];
        msg[..8].copy_from_slice(left);
        msg[8..].copy_from_slice(right);
        crate::notes::hash(crate::notes::domain::NODE, &msg)
    }

    /// The vendored `Note`'s own commitment, built by fields rather than by `Note::new` (which
    /// draws `r` itself): the ledger is handed `r` on the wire precisely so it can recompute a
    /// deposit note it did not create. `tests/shielded.rs` pins the two against each other.
    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
        crate::notes::Note { pk: *pk, from: *from, amount, asset, time, r: *r }.commitment()
    }

    /// The hidden-asset bundle digest (spec §3.4, `hidden::hidden_bundle_digest`) over the core
    /// record's fields — the same eight fields, the same order, and no asset.
    fn bundle_digest(&self, i: &BundleDigestInput) -> Word8 {
        crate::hidden::hidden_bundle_digest(&hidden_digest_input(i))
    }

    fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.hidden_bundle_proof_digest(proof)
    }

    fn verify_bundle(
        &self,
        hc_bundle: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError> {
        self.verify_hidden_bundle(hc_bundle, proof, binding)
    }

    /// The bundle guest's verifier key. Unlike `warm`, this needs no guessing: the guest is
    /// pinned, so its `(tier, program_log_height, input_log_height, keccak_log_height,
    /// sha256_log_height, public_log_height)` is a single known sextuple — tier 14, which is
    /// where every witness of the hidden guest lands (`tests/hidden_bundle.rs` measures the worst
    /// case), `NO_KECCAK` and `NO_SHA256` since the guest issues neither hash syscall, and the
    /// transaction binding's public height (`bundle_heights`), since every bundle proof commits
    /// to it.
    fn warm_bundle(&self) {
        let (plh, ilh, pubh) = Self::bundle_heights();
        let _ = self.machine.verifier_key(Tier(BUNDLE_TIER), plh, ilh, NO_KECCAK, NO_SHA256, pubh);
    }

    /// The bare zkVM executor cannot build or verify aggregate proofs: the rVM lives in
    /// `randprotocol-rvm`, which depends on this crate, so linking it here would be a crate cycle.
    /// `rand-node` wraps this executor with the rVM-backed aggregating one.
    fn aggregate_program_digest(
        &self,
        _shape: &randprotocol_core::types::DeclaredShape,
    ) -> Result<[u64; 4], ConfidentialError> {
        Err(ConfidentialError::AggregationUnsupported)
    }

    fn verify_aggregate(
        &self,
        _shape: &randprotocol_core::types::DeclaredShape,
        _covered: &[randprotocol_core::types::CoveredBundle],
        _proof: &[u8],
    ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
        Err(ConfidentialError::AggregationUnsupported)
    }
}

/// The zkVM's own commitment to a program: `hc`, the in-circuit Poseidon2 digest
/// `Machine::verify` checks proofs against, as hex. M3.4: no longer `Machine`/tier-dependent —
/// `Program::code_hash` is a pure, deterministic function of `base_pc` and the program's words;
/// kept here (rather than just calling `program.code_hash()` at call sites) for API stability,
/// e.g. explorers that already import it from this module.
pub fn zk_code_hash(program: &Program) -> String {
    program.code_hash()
}

/// Prover entry point for the wallet and tests. Returns (proof bytes, outputs, tier).
///
/// `backend` picks the prover implementation: `Backend::Cpu` always exists, the GPU and
/// reference backends only in builds that enabled their feature. Every backend produces a proof
/// the ordinary CPU verifier accepts, so nothing downstream of here changes with it. There is no
/// fallback: a backend that cannot start (no driver, no PTX) is an error, not a silent CPU run.
///
/// M4.1: every path this delegates to (`Machine::prove_with` → `Machine::prove` on the CPU
/// backend, `Machine::prove_on` for the reference/CUDA backends) draws a fresh per-proof `H_IN`
/// salt from OS entropy internally — never `Machine::prove_salted`, which exists only for tests
/// that need a fixed salt to check against. This entry point must keep it that way: an unsalted
/// or reused `H_IN` is a guessable/linkable commitment to the private inputs, not a hiding one.
///
/// S3: a caller that will publish a call-input envelope needs the salt back and uses
/// [`prove_call`] instead, which draws an equally fresh one on this side of `Machine`. This
/// function stays as it is — it is the path every backend can serve.
///
/// `public` is the program's deploy-time public input (`rand_getProgramPublic`), empty for a
/// program deployed without one. The proof's `H_PUB` commits to it, and the chain checks that
/// against the program's recorded digest (`ZkExecutor::verify_call`), so a proof over any other
/// public input is refused.
pub fn prove(
    profile: FriProfile,
    program: &Program,
    inputs: &[u32],
    public: &[u32],
    tier: Option<u8>,
    backend: Backend,
) -> Result<(Vec<u8>, [u32; 8], u8), String> {
    let m = Machine::new(profile);
    let (proof, exec) = m
        .prove_with(backend, program, inputs, public, tier.map(|t| Tier(t as usize)))
        .map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}

/// `prove` for a caller that will publish a call-input envelope: the same proof, plus the
/// `H_IN` salt that produced it (spec §6.1, S3 Task 1).
///
/// The envelope's body carries `(salt, inputs)` and is sealed against the proof's public
/// `H_IN` (`pv::IN0..7`), so whoever opens it can recompute `hash::input_digest(salt, inputs)`
/// and see that the transcript is the one the guest was actually fed
/// (`call_envelope::call_envelope_is_faithful`). That is only possible if the salt leaves the
/// prover, which `Machine::prove` — drawing it internally and dropping it — does not allow;
/// hence this entry point, which draws the same fresh OS-entropy salt itself and hands it to
/// `Machine::prove_salted`. Freshness is still this function's job: a reused or guessable salt
/// makes `H_IN` a guessable commitment to the private inputs, which is the whole reason M4.1
/// salts it (`Machine::prove_salted`'s doc comment).
///
/// Only `Backend::Cpu` can answer: the GPU and reference paths run inside the vendored
/// `Machine::prove_with`, which draws its own salt and never returns it. A caller proving on
/// one of those backends must prove without an envelope (`prove`) — the chain accepts both.
///
/// `public` is the program's deploy-time public input, as for [`prove`]. `max_input_words` is the
/// envelope's input cap (`call_envelope::CallCaps::max_input_words`, derived from the chain's
/// `max_call_envelope_bytes`).
pub fn prove_call(
    profile: FriProfile,
    program: &Program,
    inputs: &[u32],
    public: &[u32],
    tier: Option<u8>,
    backend: Backend,
    max_input_words: usize,
) -> Result<(Vec<u8>, [u32; 8], u8, [u32; 4]), String> {
    // The envelope this proof is for cannot carry more than the chain's input cap, and proving
    // is minutes: refuse now rather than after the work is done (`call_envelope`'s own check is
    // the same one, reached by a caller that seals without proving).
    if inputs.len() > max_input_words {
        return Err(format!("a call may prove at most {max_input_words} input words, got {}", inputs.len()));
    }
    match backend {
        Backend::Cpu => {
            use rand::RngExt;
            let salt: [u32; 4] = rand::rng().random();
            let m = Machine::new(profile);
            let (proof, exec) = m
                .prove_salted(program, inputs, public, salt, tier.map(|t| Tier(t as usize)))
                .map_err(|e| format!("{e:?}"))?;
            Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8, salt))
        }
        #[allow(unreachable_patterns)]
        other => Err(format!(
            "{other:?} draws its H_IN salt inside the prover and cannot return it; \
             prove a call that publishes an input envelope on the CPU backend"
        )),
    }
}

/// Wallet-side prover for a shielded bundle: proves the chain's bundle guest (the hidden-asset
/// guest, [`ZkExecutor::bundle_program`]) on `inputs` (built by `hidden::hidden_bundle_inputs`)
/// with `binding` as its public input segment, and returns (postcard proof bytes, the published
/// bundle digest, tier). The same as [`prove_hidden_bundle`].
///
/// `binding` is `Transaction::binding` of the transaction this bundle will ride in (Task 5b), so
/// the caller builds that transaction — every field but the proof — *before* proving. The chain
/// verifies against the binding it recomputes (`ZkExecutor::verify_bundle`), so a proof made for
/// any other transaction, or against the empty segment, is refused.
///
/// The tier is not chosen here — `Machine::prove_with` picks the smallest one the trace fits, and
/// the caller asserts what it got rather than pinning it, so a guest that grows past its tier is
/// a visible failure instead of a silent prove error. Like `prove`, every path this delegates to
/// draws a fresh per-proof `H_IN` salt from OS entropy internally; see `prove`'s doc comment for
/// why that must not be weakened.
///
/// A bundle whose witness violates the relation still *proves* — the guest taints its `bad` word
/// instead of failing — so a successful return here says nothing about admissibility. What it
/// yields is a digest the ledger can recompute from the bundle's published plaintext
/// (`ConfidentialExecutor::bundle_digest`); a tainted run's digest matches no such plaintext.
pub fn prove_bundle(
    profile: FriProfile,
    inputs: &[u32],
    binding: &[u32; TX_BINDING_WORDS],
    backend: Backend,
) -> Result<(Vec<u8>, Word8, u8), String> {
    prove_hidden_bundle(profile, inputs, binding, backend)
}

/// `prove_bundle` for the hidden-asset bundle guest (`guests::bundle_hidden`): `inputs` built by
/// `hidden::hidden_bundle_inputs`, proved against the transaction's `binding`, returning (proof
/// bytes, the published digest, tier). Everything `prove_bundle`'s doc comment says holds here
/// too — the binding, the auto-picked tier (14 for every witness, honest or not: the worst case
/// is measured by `tests/hidden_bundle.rs`), the fresh `H_IN` salt, and that a tainted witness
/// still proves to a digest no plaintext matches.
pub fn prove_hidden_bundle(
    profile: FriProfile,
    inputs: &[u32],
    binding: &[u32; TX_BINDING_WORDS],
    backend: Backend,
) -> Result<(Vec<u8>, Word8, u8), String> {
    prove_pinned_bundle(
        profile,
        ZkExecutor::hidden_bundle_program(),
        crate::hidden::hidden_input::COUNT,
        "hidden bundle",
        inputs,
        binding,
        backend,
    )
}

fn prove_pinned_bundle(
    profile: FriProfile,
    program: &Program,
    input_words: usize,
    what: &str,
    inputs: &[u32],
    binding: &[u32; TX_BINDING_WORDS],
    backend: Backend,
) -> Result<(Vec<u8>, Word8, u8), String> {
    // The guest reads a fixed-width private-input vector; a shorter one makes the emulator read
    // past the end and a longer one silently ignores the tail, so neither is a prove request that
    // could ever produce an admissible bundle.
    if inputs.len() != input_words {
        return Err(format!("{what} inputs must be exactly {input_words} words, got {}", inputs.len()));
    }
    let m = Machine::new(profile);
    // The transaction binding as the public segment. The guest never reads it; the public
    // table's `PUBLIC_DIGEST` bus commits it into `H_PUB` regardless.
    let (proof, exec) = m.prove_with(backend, program, inputs, binding, None).map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}

#[cfg(test)]
mod tests {
    /// The ledger mirrors this machine's public-value layout as `randprotocol_core::types::pv` (it
    /// cannot name a zkvm type — the dependency points this way). If a constraint-set change
    /// moves the real layout, this fails here, where both sides are visible, rather than
    /// silently desynchronising block-aggregation's admission checks.
    #[test]
    fn the_ledgers_pv_mirror_matches_the_real_layout() {
        use crate::tables::cpu::pv as real;
        use randprotocol_core::types::pv as mirror;
        assert_eq!(mirror::PC_ENTRY, real::PC_ENTRY);
        assert_eq!(mirror::TIER, real::TIER);
        assert_eq!(mirror::OUT0, real::OUT0);
        assert_eq!(mirror::HC0, real::HC0);
        assert_eq!(mirror::IN0, real::IN0);
        assert_eq!(mirror::PUB0, real::PUB0);
        assert_eq!(mirror::NUM, real::NUM);
    }
}
