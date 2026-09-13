//! The chain-side verifier: implements shrugg-core's executor trait with the zkVM.
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
//! Verifying a proof costs ~16-20 ms once its `(tier, program_log_height, input_log_height,
//! keccak_log_height)` verifier key is known; computing that key (the range/nibble/Poseidon2-
//! round-constant preprocessed commitment, FRI-expanded) is the dominant cost of an uncached
//! verify (`docs/03-privacy.md`).

use crate::isa::{Instr, Program};
use crate::machine::{check_declared_heights, Backend, FriProfile, Machine, Proof, Tier, TIERS};
use crate::tables::cpu::pv;
use crate::tables::{input, program};
use shrugg_core::confidential::{ConfidentialError, ConfidentialExecutor};
use shrugg_core::notes::{BundleDigestInput, Word8};
use shrugg_core::program::{CallOutcome, ProgramRecord};

/// M4.2: the `keccak_log_height` of a proof that declares no keccak table — the eight-instance
/// batch every guest this chain deploys produces, and the only keccak class `warm`/`warm_bundle`
/// precompute a verifier key for. Named rather than inlined as `0` because `0` is a *value* of
/// that key component, not the absence of one (`Machine::verifier_key`'s doc comment).
const NO_KECCAK: u8 = 0;

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

    /// Number of `(tier, program_log_height, input_log_height, keccak_log_height)` verifier keys
    /// this executor's `Machine` currently has cached — `Machine`'s own cache, not a second one
    /// kept here (see the module doc comment).
    pub fn cached_keys(&self) -> usize {
        self.machine.cached_keys()
    }

    /// Decode a proof and run every check that must precede `Machine::verify` — the cheap,
    /// purely structural ones, none of which touch the constraint system.
    ///
    /// The tier and all four declared table heights (`program_log_height`, `input_log_height`,
    /// `keccak_log_height`, `mem_log_height`) are attacker-chosen words inside the proof, and
    /// both the degree-bits comparison below and `Machine`'s verifier-key lookup shift by them,
    /// so each has to be bounded before it is used to size anything. M4.2: that bounding is
    /// `machine::check_declared_heights`, called verbatim rather than restated — it is the same
    /// function `Machine::verify` runs, in the same order (tier, then program, then input, then
    /// the keccak table's flat range, then the keccak-vs-tier relation, then memory), and the
    /// chain has no reason to want a different rule. `keccak_log_height == 0` is legitimate and
    /// means the proof declares no keccak table at all, which is every proof this chain has
    /// produced so far: neither the deployed guests nor the bundle guest uses the syscall.
    ///
    /// `exact` is what separates the two callers, and it still applies only to the program and
    /// input heights. A *call* proof is against a program the chain only knows the `hc` of, and
    /// whose private-input vector the chain never sees, so the two heights are merely
    /// range-checked (`Machine::verify` then binds them cryptographically via the program and
    /// input digests). A *bundle* proof is against one pinned guest with one fixed input width,
    /// so both heights are known up front and anything else is a proof for a different shape —
    /// rejected here rather than paying for a verifier key that could never match. The keccak
    /// and memory heights are *not* pinned even in the exact case: `mem_log_height` legitimately
    /// varies with how much RAM a given witness touches, and a keccak table the bundle guest
    /// never fills is padding the prover pays for, not something a verifier must forbid — at the
    /// production profile a keccak-bearing proof is ~1.91 MB larger (3 106 757 bytes at tier 10,
    /// upstream `docs/03-privacy.md`), so `shrugg-core`'s 2 MiB `MAX_PROOF_BYTES` rejects it long
    /// before this would.
    fn decode_and_check(
        &self,
        proof: &[u8],
        program_log_height: u8,
        input_log_height: u8,
        exact: bool,
    ) -> Result<Proof, ConfidentialError> {
        let proof: Proof = postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        check_declared_heights(
            proof.tier,
            proof.program_log_height,
            proof.input_log_height,
            proof.keccak_log_height,
            proof.mem_log_height,
        )
        .map_err(|e| ConfidentialError::InvalidProof(format!("declared shape: {e:?}")))?;
        if exact && proof.program_log_height != program_log_height {
            return Err(ConfidentialError::InvalidProof("program height not the pinned guest's".into()));
        }
        if exact && proof.input_log_height != input_log_height {
            return Err(ConfidentialError::InvalidProof("input height not the pinned guest's".into()));
        }
        // Reproduces `Machine::verify`'s own equality check, which is simultaneously the check
        // that the batch's *instance count* matches what `chips` would build — eight without a
        // keccak table, nine with one — so a header that claims `keccak_log_height = 0` while
        // carrying nine instances dies here, before any verifier key is built.
        if proof.batch.degree_bits
            != self.machine.log_ext_degrees_pub(
                proof.tier,
                proof.program_log_height,
                proof.input_log_height,
                proof.keccak_log_height,
                proof.mem_log_height,
            )
        {
            return Err(ConfidentialError::InvalidProof("degree bits".into()));
        }
        // The eight published output words are read as `u32`s by both callers, and since S3 so
        // are the eight `H_IN` words (`CallOutcome::h_in`, which a call receipt publishes); a
        // slot outside 32 bits cannot come from an honest trace — an output is a register word
        // and `H_IN` is a digest encoded as byte sums.
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

    /// The `(program_log_height, input_log_height)` a bundle proof must declare. Both are fixed:
    /// the guest is one pinned program and its private-input vector is always
    /// `notes::bundle_input::COUNT` words wide (a dummy input is a zero-amount note, not a
    /// shorter witness — that is the whole point of the fixed 2-in-2-out shape).
    fn bundle_heights() -> (u8, u8) {
        (
            program::program_log_height(Self::bundle_program().words.len()),
            input::input_log_height(crate::notes::bundle_input::COUNT),
        )
    }
}

impl ConfidentialExecutor for ZkExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        if base_pc % 4 != 0 {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "base_pc not word aligned".into() });
        }
        if words.is_empty() {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "empty program".into() });
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
    /// than one without — 3 106 757 bytes at tier 10, which `shrugg-core`'s 2 MiB
    /// `MAX_PROOF_BYTES` refuses outright. Warming the keccak classes as well would multiply
    /// this by the whole `[5, tier + 5]` range; a call that does declare one (at the `Test`
    /// profile, or once the block-space work makes such a proof admissible) pays the key-build
    /// cost once, like an unwarmed tier.
    fn warm(&self, record: &ProgramRecord) {
        let log_height = program::program_log_height(record.words.len());
        let smallest = input::MIN_LOG_HEIGHT;
        let typical = input::input_log_height(4);
        let input_heights: &[u8] = if typical == smallest { &[smallest] } else { &[smallest, typical] };
        for t in &TIERS[..3] {
            for &in_h in input_heights {
                self.machine.verifier_key(Tier(*t), log_height, in_h, NO_KECCAK);
            }
        }
    }

    fn verify_call(&self, record: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        // `Machine::verify` runs `check_declared_heights` on the proof's tier and four declared
        // table heights before using any of them to size anything — but the degree-bits pre-check
        // inside `decode_and_check` shifts by them too, so it runs that same function in front of
        // it, to avoid panicking on an attacker-chosen out-of-range value before ever reaching
        // `verify`. A call's program and input heights are ranged, not exact: the chain knows
        // neither the program's word count (only its `hc`) nor its private-input width.
        let proof = self.decode_and_check(proof, 0, 0, false)?;
        let hc = Self::hc_of(record)?;
        self.machine.verify(&hc, &proof).map_err(|e| ConfidentialError::InvalidProof(format!("{e:?}")))?;
        let outputs = std::array::from_fn(|i| proof.public_values[pv::OUT0 + i] as u32);
        // M4.1/S3: `H_IN` travels to the receipt so a call-input envelope sealed against it can
        // be opened and checked later (spec §6.1). `decode_and_check` has already refused a
        // proof whose `IN0..7` are not `u32`s, so the narrowing below cannot silently truncate.
        let h_in = std::array::from_fn(|i| proof.public_values[pv::IN0 + i] as u32);
        Ok(CallOutcome { tier: proof.tier.0 as u8, outputs, h_in })
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
        let (plh, ilh) = Self::bundle_heights();
        let p = self.decode_and_check(proof, plh, ilh, true)?;
        Ok(std::array::from_fn(|k| p.public_values[pv::OUT0 + k] as u32))
    }

    fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<(), ConfidentialError> {
        let (plh, ilh) = Self::bundle_heights();
        let p = self.decode_and_check(proof, plh, ilh, true)?;
        self.machine
            .verify(hc_bundle, &p)
            .map_err(|e| ConfidentialError::InvalidBundleProof(format!("{e:?}")))
    }

    /// The bundle guest's verifier key. Unlike `warm`, this needs no guessing: the guest is
    /// pinned, so its `(tier, program_log_height, input_log_height, keccak_log_height)` is a
    /// single known quadruple — tier 14, which is where the 3811-word guest's trace lands
    /// (`tests/shielded.rs` asserts it), and `NO_KECCAK`, since the guest issues no `SYS_KECCAK`.
    fn warm_bundle(&self) {
        let (plh, ilh) = Self::bundle_heights();
        let _ = self.machine.verifier_key(Tier(14), plh, ilh, NO_KECCAK);
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
pub fn prove(
    profile: FriProfile,
    program: &Program,
    inputs: &[u32],
    tier: Option<u8>,
    backend: Backend,
) -> Result<(Vec<u8>, [u32; 8], u8), String> {
    let m = Machine::new(profile);
    let (proof, exec) = m
        .prove_with(backend, program, inputs, tier.map(|t| Tier(t as usize)))
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
pub fn prove_call(
    profile: FriProfile,
    program: &Program,
    inputs: &[u32],
    tier: Option<u8>,
    backend: Backend,
) -> Result<(Vec<u8>, [u32; 8], u8, [u32; 4]), String> {
    // The envelope this proof is for cannot carry more than the spec's input cap, and proving
    // is minutes: refuse now rather than after the work is done (`call_envelope`'s own check is
    // the same one, reached by a caller that seals without proving).
    if inputs.len() > crate::call_envelope::MAX_CALL_INPUT_WORDS {
        return Err(format!(
            "a call may prove at most {} input words, got {}",
            crate::call_envelope::MAX_CALL_INPUT_WORDS,
            inputs.len()
        ));
    }
    match backend {
        Backend::Cpu => {
            use rand::RngExt;
            let salt: [u32; 4] = rand::rng().random();
            let m = Machine::new(profile);
            let (proof, exec) = m
                .prove_salted(program, inputs, salt, tier.map(|t| Tier(t as usize)))
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
/// `notes::bundle_inputs`) and returns (postcard proof bytes, the published bundle digest, tier).
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
pub fn prove_bundle(profile: FriProfile, inputs: &[u32], backend: Backend) -> Result<(Vec<u8>, Word8, u8), String> {
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
    let (proof, exec) = m.prove_with(backend, program, inputs, None).map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}
