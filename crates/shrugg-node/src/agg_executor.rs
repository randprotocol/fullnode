//! The node's aggregating executor: every `ConfidentialExecutor` method the zkVM already
//! implements, delegated to [`ZkExecutor`], plus the block-aggregation surface (spec §4 steps
//! 7–8) backed by the vendored rVM (`shrugg-rvm`).
//!
//! This type exists because of the crate graph, not preference: `shrugg-rvm` depends on
//! `shrugg-zkvm` (an rVM verifier program is specialised to the zkVM's own proof format), so
//! the real aggregate methods cannot live on `ZkExecutor` without a crate cycle. `ZkExecutor`'s
//! own aggregate arms therefore return `ConfidentialError::AggregationUnsupported`, and the
//! node builds this wrapper instead — `node::executor_for_profile` never hands out a bare
//! `ZkExecutor`.

use shrugg_core::confidential::{ConfidentialError, ConfidentialExecutor};
use shrugg_core::notes::{BundleDigestInput, Word8};
use shrugg_core::program::{CallOutcome, ProgramRecord};
use shrugg_core::types::{CoveredBundle, DeclaredShape};
use shrugg_rvm::aggregate::{aggregate_program, AggregateProof, InnerVerifierKey};
use shrugg_rvm::shape::{InnerKey, InnerShape};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::machine::FriProfile;

/// The executor the node runs: `ZkExecutor` inside, one rVM `Machine` beside it (its 64-entry
/// verifier-key FIFO is what `warm_aggregation` fills and every `verify_aggregate` then reuses).
pub struct AggExecutor {
    inner: ZkExecutor,
    rvm: shrugg_rvm::machine::Machine,
}

impl AggExecutor {
    pub fn new(profile: FriProfile) -> AggExecutor {
        AggExecutor { inner: ZkExecutor::new(profile), rvm: shrugg_rvm::machine::Machine::new(profile) }
    }

    /// The rVM's own shape types for a registered declared shape: the fallible
    /// `InnerShape::try_of` (a genesis file's heights are numbers this node did not choose —
    /// exactly what `try_of` is for) and the startup-derived preprocessed cap.
    fn inner_key(shape: &DeclaredShape) -> Result<InnerVerifierKey, ConfidentialError> {
        let profile = zkvm_profile(shape.profile);
        let s = InnerShape::try_of(
            profile,
            shrugg_zkvm::machine::Tier(shape.tier as usize),
            shape.program_log_height,
            shape.input_log_height,
            shape.keccak_log_height,
            shape.sha256_log_height,
            shape.public_log_height,
            shape.mem_log_height,
        )
        .map_err(|e| ConfidentialError::BadDeclaredShape(format!("{e:?}")))?;
        Ok(InnerVerifierKey { key: InnerKey::of(profile, &s), shape: s })
    }
}

/// `shrugg-core`'s ledger-side mirror enum to the machine's own (R6: the ledger never names a
/// zkvm type; the two have exactly the same variants).
fn zkvm_profile(profile: shrugg_core::types::FriProfile) -> FriProfile {
    match profile {
        shrugg_core::types::FriProfile::Test => FriProfile::Test,
        shrugg_core::types::FriProfile::Production => FriProfile::Production,
    }
}

impl ConfidentialExecutor for AggExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        self.inner.check_program(base_pc, words)
    }

    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        self.inner.verify_call(program, proof)
    }

    fn warm(&self, program: &ProgramRecord) {
        self.inner.warm(program)
    }

    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        self.inner.node_hash(left, right)
    }

    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
        self.inner.note_commitment(pk, from, amount, asset, time, r)
    }

    fn bundle_digest(&self, input: &BundleDigestInput) -> Word8 {
        self.inner.bundle_digest(input)
    }

    fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.inner.bundle_proof_digest(proof)
    }

    fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<(), ConfidentialError> {
        self.inner.verify_bundle(hc_bundle, proof)
    }

    fn warm_bundle(&self) {
        self.inner.warm_bundle()
    }

    /// spec §2.3's registered artifact: the N-generic aggregate program's digest for the shape,
    /// rebuilt deterministically from `(shape, key)` — seconds of DSL emission, never a proof.
    fn aggregate_program_digest(&self, shape: &DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
        use p3_field::PrimeField64;
        let vk = Self::inner_key(shape)?;
        Ok(shrugg_rvm::programs::aggregate_program_digest(&vk.shape, &vk.key).map(|f| f.as_canonical_u64()))
    }

    /// spec §4 steps 7–8: the §4.4 interface list is recomputed from the covered bundles' public
    /// values (auxiliary data, the `verify_public` pattern — the proof carries only its digest),
    /// then the rVM's own `verify_aggregate` does the digest compare and the `Machine::verify`.
    /// Cheap refusals come first: the empty set and the undecodable proof never reach a program
    /// build.
    fn verify_aggregate(
        &self,
        shape: &DeclaredShape,
        covered: &[CoveredBundle],
        proof: &[u8],
    ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
        if covered.is_empty() {
            return Err(ConfidentialError::InvalidAggregateProof(
                "an aggregate covers at least one bundle".into(),
            ));
        }
        let rvm_proof: shrugg_rvm::machine::Proof =
            postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        let vk = Self::inner_key(shape)?;
        let pvs: Vec<Vec<u64>> = covered.iter().map(|c| c.public_values.to_vec()).collect();
        let public = shrugg_rvm::public_values::interface_words(&vk.shape, &vk.key, &pvs);
        let program = aggregate_program(&vk);
        shrugg_rvm::aggregate::verify_aggregate(&self.rvm, &program, &AggregateProof { proof: rvm_proof, public })
            .map_err(|e| ConfidentialError::InvalidAggregateProof(format!("{e:?}")))
    }

    /// The startup key-build (spec §2.3, `circuits/recursion/docs/02-aggregate.md` "Startup: the
    /// key-build story"): build the N-generic program (seconds) and warm the rVM verifier key at
    /// the N=1 aggregate's landing tier — 2¹⁹ test / 2²¹ production, the measured anchors — so
    /// the first aggregate to arrive does not pay the ~30–70 s (production) build inside
    /// admission. Aggregates covering more bundles land at higher tiers and warm their key on
    /// first verify, once, into the same FIFO. A shape the rVM refuses to build is logged and
    /// skipped, not panicked on: genesis validation is where that refusal belongs.
    fn warm_aggregation(&self, shape: &DeclaredShape) {
        let t0 = std::time::Instant::now();
        let vk = match Self::inner_key(shape) {
            Ok(vk) => vk,
            Err(e) => {
                tracing::warn!("aggregation: admitted shape cannot build an inner key ({e}); skipping the warm");
                return;
            }
        };
        let program = aggregate_program(&vk);
        let tier = match self.rvm.profile {
            FriProfile::Test => 19,
            FriProfile::Production => 21,
        };
        // The reduce flag tracks the program, not a guess: `Precompiles::On` emits a REDUCE
        // instruction per query opening, so the batch carries the reduce instance exactly when
        // the program has such an instruction (`machine::verifier_key`'s third key component).
        let reduce = program.instrs.iter().any(|i| matches!(i.op, shrugg_rvm::isa::Op::Reduce));
        let _ = self.rvm.verifier_key(&program, shrugg_rvm::machine::Tier(tier), reduce);
        tracing::info!(
            "aggregation: aggregate program built and the tier-{tier} verifier key warmed ({:.1?})",
            t0.elapsed()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shrugg_core::types::FriProfile as CoreProfile;

    /// A recursion fixture cache proof (`$RECURSION_FIXTURES/{profile}-{k}.proof`: a 32-byte
    /// `hc` then the postcard `shrugg_zkvm::machine::Proof`). The conformance discipline needs
    /// the *doc's* fixtures — the 107-word interface list rides on their random notes — so a
    /// missing cache is a loud failure, not a skip: set `RECURSION_FIXTURES` to a checkout's
    /// `recursion/target/recursion-fixtures`.
    fn fixture_proof(k: usize) -> shrugg_zkvm::machine::Proof {
        let dir = std::env::var_os("RECURSION_FIXTURES")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/recursion-fixtures"));
        let path = dir.join(format!("Test-{k}.proof"));
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e} — the aggregation tests need a recursion fixture cache; \
                 set RECURSION_FIXTURES (docs/aggregation.md)",
                path.display()
            )
        });
        postcard::from_bytes(&bytes[32..]).expect("a fixture proof decodes")
    }

    /// The covered-bundle record admission would assemble for fixture `k`: its declared shape
    /// read off the proof's stored header, and its 34 public values.
    fn covered(k: usize) -> (DeclaredShape, CoveredBundle) {
        let p = fixture_proof(k);
        let shape = DeclaredShape {
            profile: CoreProfile::Test,
            tier: p.tier.0 as u8,
            program_log_height: p.program_log_height,
            input_log_height: p.input_log_height,
            keccak_log_height: p.keccak_log_height,
            sha256_log_height: p.sha256_log_height,
            public_log_height: p.public_log_height,
            mem_log_height: p.mem_log_height,
        };
        let public_values: [u64; 34] = p.public_values.clone().try_into().expect("cs6 proofs carry 34 public values");
        (shape, CoveredBundle { public_values, shape })
    }

    /// Why the wrapper exists: the bare zkVM executor names its own refusal, so a miswired node
    /// (or a test that forgot the wrapper) gets `AggregationUnsupported`, never a wrong digest.
    #[test]
    fn the_bare_zkvm_executor_refuses_the_aggregate_surface_by_name() {
        let (shape, cov) = covered(0);
        let zk = ZkExecutor::new(FriProfile::Test);
        assert_eq!(
            zk.aggregate_program_digest(&shape),
            Err(ConfidentialError::AggregationUnsupported)
        );
        assert_eq!(
            zk.verify_aggregate(&shape, &[cov], b"proof"),
            Err(ConfidentialError::AggregationUnsupported)
        );
    }

    /// Delegation is real: the hash surface answers exactly what the bare executor answers.
    #[test]
    fn the_wrapper_delegates_the_zkvm_surface() {
        let w = AggExecutor::new(FriProfile::Test);
        let zk = ZkExecutor::new(FriProfile::Test);
        let (a, b) = ([1u32; 8], [2u32; 8]);
        assert_eq!(w.node_hash(&a, &b), zk.node_hash(&a, &b));
        assert_eq!(w.note_commitment(&a, &b, 5, 0, 9, &a), zk.note_commitment(&a, &b, 5, 0, 9, &a));
    }

    /// The registered artifact (spec §2.3): the wrapper's digest is the rVM's own
    /// `aggregate_program_digest` over the same shape, deterministically.
    #[test]
    fn the_aggregate_program_digest_is_the_rvms_own_build() {
        let (shape, _) = covered(0);
        let w = AggExecutor::new(FriProfile::Test);
        let got = w.aggregate_program_digest(&shape).expect("the fixture shape builds");
        let vk = AggExecutor::inner_key(&shape).unwrap();
        use p3_field::PrimeField64;
        let want = shrugg_rvm::programs::aggregate_program_digest(&vk.shape, &vk.key).map(|f| f.as_canonical_u64());
        assert_eq!(got, want);
        assert_eq!(
            got,
            w.aggregate_program_digest(&shape).unwrap(),
            "the build is deterministic — the genesis-pinned value is reproducible"
        );
    }

    /// Cheap refusals, before any program build: the empty cover set and the undecodable proof.
    #[test]
    fn verify_aggregate_refuses_the_empty_set_and_malformed_bytes_cheaply() {
        let (shape, cov) = covered(0);
        let w = AggExecutor::new(FriProfile::Test);
        match w.verify_aggregate(&shape, &[], b"whatever") {
            Err(ConfidentialError::InvalidAggregateProof(_)) => {}
            other => panic!("an empty cover set must be a named refusal, got {other:?}"),
        }
        assert_eq!(
            w.verify_aggregate(&shape, &[cov], b"not a postcard proof"),
            Err(ConfidentialError::MalformedProof)
        );
    }

    /// An RV32 bundle proof's bytes are not an rVM aggregate proof: the answer is a named error,
    /// never a panic — even if the postcard bytes happen to decode across the two proof types.
    #[test]
    fn an_rv32_bundle_proof_is_not_an_aggregate_proof() {
        let (shape, cov) = covered(0);
        let bundle_proof = fixture_proof(0);
        let w = AggExecutor::new(FriProfile::Test);
        match w.verify_aggregate(&shape, &[cov], &bundle_proof.to_bytes()) {
            Err(ConfidentialError::MalformedProof | ConfidentialError::InvalidAggregateProof(_)) => {}
            other => panic!("a bundle proof fed as an aggregate must be a named refusal, got {other:?}"),
        }
    }

    /// The startup obligation (spec §2.3): one call builds the N-generic program and warms the
    /// N=1 landing tier's verifier key into the FIFO. Smoke, not timing: it must simply run.
    #[test]
    fn warm_aggregation_builds_the_program_and_key() {
        let (shape, _) = covered(0);
        let w = AggExecutor::new(FriProfile::Test);
        w.warm_aggregation(&shape);
    }

    /// The real round-trip: one fixture bundle proof aggregated by the rVM, the proof bytes
    /// verified through the wrapper, the covered bundle's `OUT0..7` back. `#[ignore]`d out of
    /// the gates: the tier-19 prove peaks around 30 GB and takes tens of minutes contended —
    /// the runbook's job, run alone:
    /// `RECURSION_FIXTURES=... cargo test --release -p shrugg-node --lib agg_executor -- --ignored --nocapture`
    #[test]
    #[ignore = "a real tier-19 rVM aggregate prove (~30 GB peak, tens of minutes contended); run alone"]
    fn an_aggregate_of_one_fixture_bundle_round_trips_through_the_wrapper() {
        let (shape, cov) = covered(0);
        let inner = fixture_proof(0);
        let vk = AggExecutor::inner_key(&shape).unwrap();
        let m = shrugg_rvm::machine::Machine::new(FriProfile::Test);
        let a = shrugg_rvm::aggregate::aggregate(&m, &vk, std::slice::from_ref(&inner), None)
            .expect("one real bundle proof aggregates");
        let w = AggExecutor::new(FriProfile::Test);
        let outs = w
            .verify_aggregate(&shape, std::slice::from_ref(&cov), &a.proof.to_bytes())
            .expect("the wrapper verifies the aggregate");
        let want: [u32; 8] = std::array::from_fn(|k| {
            u32::try_from(cov.public_values[shrugg_zkvm::tables::cpu::pv::OUT0 + k]).unwrap()
        });
        assert_eq!(outs, vec![want], "the covered bundle's OUT0..7, in cover order");
    }
}
