//! The node's aggregating executor: every `ConfidentialExecutor` method the zkVM already
//! implements, delegated to [`ZkExecutor`], plus the block-aggregation surface (spec §4 steps
//! 7–8) backed by the vendored rVM (`randprotocol-rvm`).
//!
//! This type exists because of the crate graph, not preference: `randprotocol-rvm` depends on
//! `randprotocol-zkvm` (an rVM verifier program is specialised to the zkVM's own proof format), so
//! the real aggregate methods cannot live on `ZkExecutor` without a crate cycle. `ZkExecutor`'s
//! own aggregate arms therefore return `ConfidentialError::AggregationUnsupported`, and the
//! node builds this wrapper instead — `node::executor_for_profile` never hands out a bare
//! `ZkExecutor`.

use randprotocol_core::confidential::{ConfidentialError, ConfidentialExecutor};
use randprotocol_core::notes::{BundleDigestInput, Word8};
use randprotocol_core::program::{CallOutcome, ProgramRecord};
use randprotocol_core::types::{CoveredBundle, DeclaredShape};
use randprotocol_rvm::aggregate::{aggregate_program, AggregateProof, InnerVerifierKey};
use randprotocol_rvm::shape::{InnerKey, InnerShape};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::FriProfile;

/// The counter behind [`AggExecutor::verification_count`] — see its doc comment.
static AGGREGATE_VERIFICATIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The executor the node runs: `ZkExecutor` inside, one rVM `Machine` beside it (its 64-entry
/// verifier-key FIFO is what `warm_aggregation` fills and every `verify_aggregate` then reuses).
pub struct AggExecutor {
    inner: ZkExecutor,
    rvm: randprotocol_rvm::machine::Machine,
}

impl AggExecutor {
    pub fn new(profile: FriProfile) -> AggExecutor {
        AggExecutor { inner: ZkExecutor::new(profile), rvm: randprotocol_rvm::machine::Machine::new(profile) }
    }

    /// Process-wide count of real rVM aggregate verifications this process has run — the
    /// sealed-sync cluster test's instrument for "one rVM verification per sealed window" (it
    /// reads the delta across a fresh node's sync, in the same process). Incremented only on
    /// this real path, never by the stub executor.
    pub fn verification_count() -> usize {
        AGGREGATE_VERIFICATIONS.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The rVM's own shape types for a registered declared shape: the fallible
    /// `InnerShape::try_of` (a genesis file's heights are numbers this node did not choose —
    /// exactly what `try_of` is for) and the startup-derived preprocessed cap.
    fn inner_key(shape: &DeclaredShape) -> Result<InnerVerifierKey, ConfidentialError> {
        let profile = zkvm_profile(shape.profile);
        let s = InnerShape::try_of(
            profile,
            randprotocol_zkvm::machine::Tier(shape.tier as usize),
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

/// `randprotocol-core`'s ledger-side mirror enum to the machine's own (R6: the ledger never names a
/// zkvm type; the two have exactly the same variants).
fn zkvm_profile(profile: randprotocol_core::types::FriProfile) -> FriProfile {
    match profile {
        randprotocol_core::types::FriProfile::Test => FriProfile::Test,
        randprotocol_core::types::FriProfile::Production => FriProfile::Production,
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

    fn public_digest(&self, words: &[u32]) -> Word8 {
        self.inner.public_digest(words)
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
        Ok(randprotocol_rvm::programs::aggregate_program_digest(&vk.shape, &vk.key).map(|f| f.as_canonical_u64()))
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
        let rvm_proof: randprotocol_rvm::machine::Proof =
            postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        // Canonical encoding only, as `randprotocol_zkvm::executor::decode_canonical` insists for
        // every bundle and call proof: postcard ignores trailing bytes and accepts overlong
        // varints, so a padded or re-encoded aggregate would otherwise verify under another txid.
        if rvm_proof.to_bytes() != proof {
            return Err(ConfidentialError::MalformedProof);
        }
        let vk = Self::inner_key(shape)?;
        let pvs: Vec<Vec<u64>> = covered.iter().map(|c| c.public_values.to_vec()).collect();
        let public = randprotocol_rvm::public_values::interface_words(&vk.shape, &vk.key, &pvs);
        let program = aggregate_program(&vk);
        let out =
            randprotocol_rvm::aggregate::verify_aggregate(&self.rvm, &program, &AggregateProof { proof: rvm_proof, public })
                .map_err(|e| ConfidentialError::InvalidAggregateProof(format!("{e:?}")))?;
        AGGREGATE_VERIFICATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(out)
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
        let reduce = program.instrs.iter().any(|i| matches!(i.op, randprotocol_rvm::isa::Op::Reduce));
        let _ = self.rvm.verifier_key(&program, randprotocol_rvm::machine::Tier(tier), reduce);
        tracing::info!(
            "aggregation: aggregate program built and the tier-{tier} verifier key warmed ({:.1?})",
            t0.elapsed()
        );
    }
}

/// A recursion fixture cache proof (`$RECURSION_FIXTURES/{profile}-{k}.proof`: a 32-byte `hc`
/// then the postcard `randprotocol_zkvm::machine::Proof`). The conformance discipline needs the
/// *doc's* fixtures — the 107-word interface list rides on their random notes — so a missing
/// cache is a loud failure, not a skip: set `RECURSION_FIXTURES` to a checkout's
/// `recursion/target/recursion-fixtures`. `pub(crate)` so `node`'s covered-assembly tests can
/// store a bundle carrying a real proof.
#[cfg(test)]
pub(crate) fn fixture_proof(k: usize) -> randprotocol_zkvm::machine::Proof {
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

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::types::FriProfile as CoreProfile;

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
        let want = randprotocol_rvm::programs::aggregate_program_digest(&vk.shape, &vk.key).map(|f| f.as_canonical_u64());
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

    /// The conformance suite (spec §4, and the plan's gate): the admission stub is not trusted
    /// until the fullnode's recompute reproduces `circuits/recursion/docs/02-aggregate.md`'s
    /// pinned vectors byte-for-byte — the `inner_vk_digest` (a constant of the fixture shape),
    /// the 107-word interface list for the 3-proof test-profile fixture set, and its digest.
    /// The list rides on the fixtures' random notes, so this pins against *this* fixture
    /// cache, the same one the doc's worked example measured.
    #[test]
    fn the_admission_recompute_reproduces_the_pinned_vectors_byte_for_byte() {
        use p3_field::PrimeField64;
        let hex_words = |words: &[randprotocol_rvm::isa::F]| -> String {
            words.iter().map(|w| format!("{:016x}", w.as_canonical_u64())).collect::<Vec<_>>().join("")
        };
        let (shape, _) = covered(0);
        for k in 1..3 {
            let (s, _) = covered(k);
            assert_eq!(s, shape, "the fixture set shares one declared shape");
        }
        let vk = AggExecutor::inner_key(&shape).unwrap();
        // The inner vk digest, a data-independent constant of the shape.
        assert_eq!(
            hex_words(&randprotocol_rvm::shape::inner_vk_digest(&vk.shape, &vk.key)),
            "33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8",
            "the pinned inner_vk_digest"
        );
        // The 107-word interface list, built the way admission builds it: from the covered
        // bundles' 34 public values, in cover order.
        let pvs: Vec<Vec<u64>> = (0..3).map(|k| covered(k).1.public_values.to_vec()).collect();
        let list = randprotocol_rvm::public_values::interface_words(&vk.shape, &vk.key, &pvs);
        assert_eq!(list.len(), 4 + 1 + 34 * 3);
        assert_eq!(hex_words(&list), INTERFACE_LIST_HEX, "the pinned 107-word interface list");
        assert_eq!(
            hex_words(&randprotocol_rvm::public_values::public_digest(&list)),
            "9f11f1aeb33546be79efe66a4829dc39c28f49f2ebd0bb055ac8a1a3fe088dcd",
            "the pinned interface digest"
        );
    }

    /// `docs/02-aggregate.md`'s worked example: the 107-word interface list for the 3-proof
    /// test-profile fixture set, each word the canonical `u64` as 16 lowercase hex chars.
    const INTERFACE_LIST_HEX: &str = concat!(
        "33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8",
        "00000000000000030000000000000000000000000000000e000000005d14ecfe",
        "00000000ce79a1da0000000049a7f73400000000272b8ab1000000009e349119",
        "000000007b4352f9000000004895d8b90000000019456d2f000000006f35274a",
        "000000000371953700000000a8a42560000000004b291c6600000000b7c2de0e",
        "00000000d6bf7fcf00000000182b470b00000000fb4abd6c000000001b1c6d71",
        "00000000b3fe016a00000000dbc589840000000064fe382600000000f65a5995",
        "00000000b50cb2db00000000879d19c4000000007f2a281900000000934a2759",
        "00000000d5389ac8000000002e612784000000008639ed090000000085f58a21",
        "000000004448d889000000006bb9c915000000000671dc2c0000000000000000",
        "000000000000000e0000000074f52033000000008800a94e0000000057a33ba9",
        "000000001c26c5e4000000008fe213ef000000001ea2ad220000000019b569a6",
        "00000000937e3135000000006f35274a000000000371953700000000a8a42560",
        "000000004b291c6600000000b7c2de0e00000000d6bf7fcf00000000182b470b",
        "00000000fb4abd6c00000000411a8c0500000000cc72996c000000009e3b3c0c",
        "00000000db272b6300000000003f7555000000000bab78070000000036480e8f",
        "000000003f87a6e000000000934a275900000000d5389ac8000000002e612784",
        "000000008639ed090000000085f58a21000000004448d889000000006bb9c915",
        "000000000671dc2c0000000000000000000000000000000e00000000d8c8a779",
        "000000001ca1010e00000000997e50da00000000288bb2cb00000000a544b803",
        "000000009346ee320000000047fe4bfd000000003e98afc0000000006f35274a",
        "000000000371953700000000a8a42560000000004b291c6600000000b7c2de0e",
        "00000000d6bf7fcf00000000182b470b00000000fb4abd6c00000000ed62b62b",
        "000000008dab0ce0000000001523999000000000b36787f2000000000dc6f8bf",
        "00000000ef9a31bc00000000a19e9ecb00000000bc07b80f00000000934a2759",
        "00000000d5389ac8000000002e612784000000008639ed090000000085f58a21",
        "000000004448d889000000006bb9c915000000000671dc2c",
    );

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
    /// `RECURSION_FIXTURES=... cargo test --release -p randprotocol-node --lib agg_executor -- --ignored --nocapture`
    #[test]
    #[ignore = "a real tier-19 rVM aggregate prove (~30 GB peak, tens of minutes contended); run alone"]
    fn an_aggregate_of_one_fixture_bundle_round_trips_through_the_wrapper() {
        let (shape, cov) = covered(0);
        let inner = fixture_proof(0);
        let vk = AggExecutor::inner_key(&shape).unwrap();
        let m = randprotocol_rvm::machine::Machine::new(FriProfile::Test);
        let a = randprotocol_rvm::aggregate::aggregate(&m, &vk, std::slice::from_ref(&inner), None)
            .expect("one real bundle proof aggregates");
        let w = AggExecutor::new(FriProfile::Test);
        let outs = w
            .verify_aggregate(&shape, std::slice::from_ref(&cov), &a.proof.to_bytes())
            .expect("the wrapper verifies the aggregate");
        let want: [u32; 8] = std::array::from_fn(|k| {
            u32::try_from(cov.public_values[randprotocol_zkvm::tables::cpu::pv::OUT0 + k]).unwrap()
        });
        assert_eq!(outs, vec![want], "the covered bundle's OUT0..7, in cover order");
    }
}
