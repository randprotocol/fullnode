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
//! Verifying a proof costs ~16-20 ms once its `(tier, program_log_height, input_log_height)`
//! verifier key is known; computing that key (the range/nibble/Poseidon2-round-constant
//! preprocessed commitment, FRI-expanded) is the dominant cost of an uncached verify
//! (`docs/03-privacy.md`).

use crate::isa::{Instr, Program};
use crate::machine::{Backend, FriProfile, Machine, Proof, Tier, TIERS};
use crate::tables::cpu::pv;
use crate::tables::{input, program};
use shrugg_core::confidential::{ConfidentialError, ConfidentialExecutor};
use shrugg_core::notes::{BundleDigestInput, Word8};
use shrugg_core::program::{CallOutcome, ProgramRecord};

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

    /// Number of `(tier, program_log_height)` verifier keys this executor's `Machine` currently
    /// has cached — `Machine`'s own cache, not a second one kept here (see the module doc
    /// comment).
    pub fn cached_keys(&self) -> usize {
        self.machine.cached_keys()
    }

    /// Decode a proof and run every check that must precede `Machine::verify` — the cheap,
    /// purely structural ones, none of which touch the constraint system.
    ///
    /// All three declared heights (`tier`, `program_log_height`, `input_log_height`) are
    /// attacker-chosen words inside the proof, and both the degree-bits comparison below and
    /// `Machine`'s verifier-key lookup shift by them, so each has to be bounded before it is used
    /// to size anything.
    ///
    /// `exact` is what separates the two callers. A *call* proof is against a program the chain
    /// only knows the `hc` of, and whose private-input vector the chain never sees, so the two
    /// heights are merely range-checked (`Machine::verify` then binds them cryptographically via
    /// the program and input digests). A *bundle* proof is against one pinned guest with one
    /// fixed input width, so both heights are known up front and anything else is a proof for a
    /// different shape — rejected here rather than paying for a verifier key that could never
    /// match.
    fn decode_and_check(
        &self,
        proof: &[u8],
        program_log_height: u8,
        input_log_height: u8,
        exact: bool,
    ) -> Result<Proof, ConfidentialError> {
        let proof: Proof = postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        if !TIERS.contains(&proof.tier.0) {
            return Err(ConfidentialError::InvalidProof("unknown tier".into()));
        }
        let program_ok = if exact {
            proof.program_log_height == program_log_height
        } else {
            (program::MIN_LOG_HEIGHT..=program::MAX_LOG_HEIGHT).contains(&proof.program_log_height)
        };
        if !program_ok {
            return Err(ConfidentialError::InvalidProof("program height out of range".into()));
        }
        let input_ok = if exact {
            proof.input_log_height == input_log_height
        } else {
            (input::MIN_LOG_HEIGHT..=input::MAX_LOG_HEIGHT).contains(&proof.input_log_height)
        };
        if !input_ok {
            return Err(ConfidentialError::InvalidProof("input height out of range".into()));
        }
        if proof.batch.degree_bits
            != self.machine.log_ext_degrees_pub(proof.tier, proof.program_log_height, proof.input_log_height)
        {
            return Err(ConfidentialError::InvalidProof("degree bits".into()));
        }
        // The eight published output words are read as `u32`s by both callers; a slot outside 32
        // bits cannot come from an honest trace (an output is a register word).
        if proof.public_values.len() != pv::NUM {
            return Err(ConfidentialError::MalformedProof);
        }
        if proof.public_values[pv::OUT0..pv::OUT0 + 8].iter().any(|v| *v > u32::MAX as u64) {
            return Err(ConfidentialError::InvalidProof("output not a u32".into()));
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
    fn warm(&self, record: &ProgramRecord) {
        let log_height = program::program_log_height(record.words.len());
        let smallest = input::MIN_LOG_HEIGHT;
        let typical = input::input_log_height(4);
        let input_heights: &[u8] = if typical == smallest { &[smallest] } else { &[smallest, typical] };
        for t in &TIERS[..3] {
            for &in_h in input_heights {
                self.machine.verifier_key(Tier(*t), log_height, in_h);
            }
        }
    }

    fn verify_call(&self, record: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        // `Machine::verify` bounds `proof.tier`/`proof.program_log_height`/`proof.input_log_height`
        // itself before using any of them to size anything — but the degree-bits pre-check inside
        // `decode_and_check` shifts by all three too, so it needs the same guard in front of it to
        // avoid panicking on an attacker-chosen out-of-range value before ever reaching `verify`.
        // A call's heights are ranged, not exact: the chain knows neither the program's word count
        // (only its `hc`) nor its private-input width.
        let proof = self.decode_and_check(proof, 0, 0, false)?;
        let hc = Self::hc_of(record)?;
        self.machine.verify(&hc, &proof).map_err(|e| ConfidentialError::InvalidProof(format!("{e:?}")))?;
        let outputs = std::array::from_fn(|i| proof.public_values[pv::OUT0 + i] as u32);
        Ok(CallOutcome { tier: proof.tier.0 as u8, outputs })
    }

    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        let mut msg = [0u32; 16];
        msg[..8].copy_from_slice(left);
        msg[8..].copy_from_slice(right);
        crate::notes::hash(crate::notes::domain::NODE, &msg)
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
    /// pinned, so its `(tier, program_log_height, input_log_height)` is a single known triple —
    /// tier 14, which is where the 3811-word guest's trace lands (`tests/shielded.rs` asserts it).
    fn warm_bundle(&self) {
        let (plh, ilh) = Self::bundle_heights();
        let _ = self.machine.verifier_key(Tier(14), plh, ilh);
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
