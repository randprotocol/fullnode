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
    /// input heights. A *call* proof is against a program the chain only knows the `hc` of, and
    /// whose private-input vector the chain never sees, so the two heights are merely
    /// range-checked (`Machine::verify` then binds them cryptographically via the program and
    /// input digests). A *bundle* proof is against one pinned guest with one fixed input width,
    /// so both heights are known up front and anything else is a proof for a different shape —
    /// rejected here rather than paying for a verifier key that could never match. The sha256,
    /// public and memory heights are *not* pinned even in the exact case: `mem_log_height`
    /// legitimately varies with how much RAM a given witness touches, a hash table the bundle
    /// guest never fills is padding the prover pays for, not something a verifier must forbid —
    /// at the production profile a keccak-bearing proof is ~1.91 MB larger (3 106 757 bytes at
    /// tier 10, upstream `docs/03-privacy.md`), so `randprotocol-core`'s 2 MiB `MAX_PROOF_BYTES`
    /// rejects it long before this would.
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

    /// The bundle guest (`guests::bundle`), the one program every shielded-pool proof on this
    /// chain is against. Vendored verbatim from the research crate — see
    /// `tests/shielded.rs`'s `RESEARCH_HC_BUNDLE_HEX`, which pins its digest to upstream's.
    ///
    /// Assembled once per process: `bundle_heights` below calls this on every bundle admission
    /// (twice, in fact — `bundle_proof_digest` then `verify_bundle`), and re-running the
    /// assembler for a 3811-word guest on each gossiped transaction is pure waste. The guest is
    /// a compile-time constant, so a `OnceLock` is the whole of the cache invalidation story.
    pub fn bundle_program() -> &'static Program {
        static BUNDLE: std::sync::OnceLock<Program> = std::sync::OnceLock::new();
        BUNDLE.get_or_init(crate::guests::bundle)
    }

    /// Digest of the vendored `bundle` guest — the value a genesis pins as `hc_bundle`.
    pub fn hc_bundle() -> Word8 {
        Self::bundle_program().digest()
    }

    /// The `(program_log_height, input_log_height, public_log_height)` a bundle proof must
    /// declare. All three are fixed: the guest is one pinned program, its private-input vector is
    /// always `notes::bundle_input::COUNT` words wide (a dummy input is a zero-amount note, not a
    /// shorter witness — that is the whole point of the fixed 2-in-2-out shape), and its public
    /// segment is always the transaction binding, [`TX_BINDING_WORDS`] words (Task 5b) — whose
    /// height, `public_log_height(8) == 4`, is not the empty segment's `MIN_LOG_HEIGHT == 2`, so a
    /// pre-fork bundle proof is refused on the declared height alone.
    pub fn bundle_heights() -> (u8, u8, u8) {
        (
            program::program_log_height(Self::bundle_program().words.len()),
            input::input_log_height(crate::notes::bundle_input::COUNT),
            public::public_log_height(TX_BINDING_WORDS),
        )
    }
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
    /// transfer guest proves at 14). A call at a larger tier still verifies; it pays the
    /// first-verify cost once per (tier, height).
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
        for t in &TIERS[..3] {
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
        // `verify`. A call's program and input heights are ranged, not exact: the chain knows
        // neither the program's word count (only its `hc`) nor its private-input width. (Its
        // public height is checked just below, against the record.)
        let proof = self.decode_and_check(proof, 0, 0, 0, false)?;
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

    fn bundle_digest(&self, i: &BundleDigestInput) -> Word8 {
        crate::notes::bundle_digest(
            &i.anchor,
            &i.nullifiers[0],
            &i.nullifiers[1],
            &i.commitments[0],
            &i.commitments[1],
            i.fee,
            i.burn,
            i.asset,
            i.time,
        )
    }

    fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        let (plh, ilh, pubh) = Self::bundle_heights();
        let p = self.decode_and_check(proof, plh, ilh, pubh, true)?;
        Ok(std::array::from_fn(|k| p.public_values[pv::OUT0 + k] as u32))
    }

    fn verify_bundle(
        &self,
        hc_bundle: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError> {
        let (plh, ilh, pubh) = Self::bundle_heights();
        let p = self.decode_and_check(proof, plh, ilh, pubh, true)?;
        // `verify_public` against the transaction binding (Task 5b): `H_PUB` must be the digest
        // of exactly the eight words of `Transaction::binding` for the transaction this bundle
        // rides in. The empty segment (every pre-fork bundle proof) and any other transaction's
        // words fail here as `PublicValues`.
        self.machine
            .verify_public(hc_bundle, binding, &p)
            .map_err(|e| ConfidentialError::InvalidBundleProof(format!("{e:?}")))
    }

    /// The bundle guest's verifier key. Unlike `warm`, this needs no guessing: the guest is
    /// pinned, so its `(tier, program_log_height, input_log_height, keccak_log_height,
    /// sha256_log_height, public_log_height)` is a single known sextuple — tier 14, which is
    /// where the 3811-word guest's trace lands (`tests/shielded.rs` asserts it), `NO_KECCAK`
    /// and `NO_SHA256` since the guest issues neither hash syscall, and the transaction
    /// binding's public height (`bundle_heights`), since every bundle proof commits to it.
    fn warm_bundle(&self) {
        let (plh, ilh, pubh) = Self::bundle_heights();
        let _ = self.machine.verifier_key(Tier(14), plh, ilh, NO_KECCAK, NO_SHA256, pubh);
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

/// Wallet-side prover for a shielded bundle: proves `guests::bundle()` on `inputs` (built by
/// `notes::bundle_inputs`) with `binding` as its public input segment, and returns (postcard proof
/// bytes, the published bundle digest, tier).
///
/// `binding` is `Transaction::binding` of the transaction this bundle will ride in (Task 5b), so
/// the caller builds that transaction — every field but the proofs — *before* proving, and
/// proves every bundle of it with the same words. The chain verifies against the binding it
/// recomputes (`ZkExecutor::verify_bundle`), so a proof made for any other transaction, or
/// against the empty segment, is refused.
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
    // The guest reads a fixed-width private-input vector (`notes::bundle_input::COUNT`); a
    // shorter one makes the emulator read past the end and a longer one silently ignores the
    // tail, so neither is a prove request that could ever produce an admissible bundle.
    if inputs.len() != crate::notes::bundle_input::COUNT {
        return Err(format!(
            "bundle inputs must be exactly {} words, got {}",
            crate::notes::bundle_input::COUNT,
            inputs.len()
        ));
    }
    let m = Machine::new(profile);
    let program = ZkExecutor::bundle_program();
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
