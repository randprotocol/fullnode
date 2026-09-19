//! Confidential computation: the executor the ledger calls to validate programs, verify call
//! proofs and reach every Poseidon2 hash the shielded pool needs. `randprotocol-zkvm` provides the
//! real implementation (`ZkExecutor`); `StubExecutor` is a crypto-free stand-in for fast tests.

use crate::crypto::Hash;
use crate::notes::{word8_from_bytes, word8_to_bytes, BundleDigestInput, Word8};
use crate::program::{CallOutcome, ProgramRecord};
use crate::types::{Transaction, TX_BINDING_WORDS};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ConfidentialError {
    #[error("program word {index} does not decode: {reason}")]
    BadInstruction { index: usize, reason: String },
    #[error("malformed proof")]
    MalformedProof,
    #[error("proof does not verify: {0}")]
    InvalidProof(String),
    #[error("proof is for another program")]
    WrongProgram,
    #[error("bundle proof: {0}")]
    InvalidBundleProof(String),
    /// Block aggregation: the aggregate proof's interface digest does not match the covered
    /// bundles' recomputed list, or the rVM `Machine::verify` refused it (spec §4 steps 7–8).
    #[error("aggregate proof: {0}")]
    InvalidAggregateProof(String),
    /// Block aggregation: this executor does not build or verify aggregate proofs (the bare
    /// zkVM executor; the node wraps it with the rVM-backed aggregating one). Never a
    /// transaction's fault, so never a permanent admission verdict.
    #[error("this executor does not support aggregate proofs")]
    AggregationUnsupported,
    /// Block aggregation: the registered declared shape is one the rVM refuses to build a
    /// verifier for (`InnerShape::try_of`). A chain-configuration error, never a transaction's
    /// fault — never a permanent admission verdict either.
    #[error("the registered shape is not one a proof can have: {0}")]
    BadDeclaredShape(String),
    #[error("confidential computation is disabled on this chain")]
    Disabled,
}

pub trait ConfidentialExecutor: Send + Sync {
    /// Validate program code at deploy time (must be cheap: it runs inside block application)
    /// and return the code commitment recorded on chain.
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError>;
    /// Verify `proof` against `program`; on success return the tier and the eight outputs.
    ///
    /// The proof's public-input digest (`pv::PUB0..7`) must equal `program.public_digest`, or
    /// `public_digest(&[])` for a program deployed without a public input; a mismatch is
    /// `InvalidProof("PublicValues")`. The public words are never re-hashed here: the digest was
    /// computed once, at deploy.
    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError>;
    /// Precompute whatever makes `verify_call` fast for `program` (the zkVM verifier key,
    /// ~2 s). Called from a background task after a deploy commits and at startup; may be a no-op.
    fn warm(&self, _program: &ProgramRecord) {}
    /// `H_PUB` of a public input (`randprotocol_zkvm::hash::public_digest`): what a call's proof
    /// publishes in `pv::PUB0..7`. The ledger calls it once per deploy with a non-empty public
    /// input and stores the result on the program's record.
    fn public_digest(&self, words: &[u32]) -> Word8;
    /// Poseidon2 tree-node hash `H(NODE, left || right)` — the hash `MERKLE_VERIFY` checks against.
    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8;
    /// The note commitment `H(CM, pk(8) from(8) amount_lo amount_hi asset time r(8))` — the
    /// 28-word note layout of the vendored `randprotocol_zkvm::notes::Note`.
    ///
    /// The ledger needs this for the deposits it creates itself rather than accepts on the
    /// wire: S2's `Withdraw` and S3's `BridgeAttest` publish only the blinding `r` and a public
    /// amount, and the chain computes the commitment, so a validator cannot declare one amount
    /// and mint a note for another.
    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8;
    /// `notes::bundle_digest(..)` (in the vendored research note layer, `randprotocol_zkvm::notes`,
    /// arriving in Task 2) over the public bundle fields with the taint word fixed to 0.
    fn bundle_digest(&self, input: &BundleDigestInput) -> Word8;
    /// Cheap: decode `proof`, check its declared tier/heights/public-value canonicity, and return
    /// the digest it publishes in `OUT0..OUT7`. Verifies nothing cryptographic.
    fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError>;
    /// Expensive: the STARK verification of a bundle proof against the pinned bundle guest, and
    /// against `binding` — the [`crate::types::Transaction::binding`] of the transaction the
    /// bundle rides in, which the proof must carry as its public input segment
    /// (`pv::PUB0..7 == H_PUB(binding)`). A proof made for any other transaction, or against the
    /// empty segment, is refused: that is what keeps a copied proof from riding a changed action,
    /// changed envelopes or a different companion bundle.
    fn verify_bundle(
        &self,
        hc_bundle: &Word8,
        proof: &[u8],
        binding: &[u32; crate::types::TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError>;
    /// Precompute the bundle verifier key. May be a no-op.
    fn warm_bundle(&self) {}

    /// The registered aggregate program's digest for an admitted shape (block aggregation,
    /// spec §2.3): a startup constant, recomputed from the shape alone. Cheap relative to
    /// verification (the DSL program build, not the proving key).
    fn aggregate_program_digest(&self, shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError>;
    /// spec §4 steps 7–8: the interface-list recompute and digest compare against the proof's
    /// batch public values, then the rVM `Machine::verify` of the aggregate proof against the
    /// registered aggregate program. Returns each covered bundle's `OUT0..7` in cover order.
    /// Expensive: the rVM verify (~1–2 s warm at production; the first call at a shape pays the
    /// startup key-build).
    fn verify_aggregate(
        &self,
        shape: &crate::types::DeclaredShape,
        covered: &[crate::types::CoveredBundle],
        proof: &[u8],
    ) -> Result<Vec<[u32; 8]>, ConfidentialError>;
    /// Precompute the aggregate program and the rVM verifier key for an admitted shape (the
    /// startup key-build, ~30–70 s at production). Called once at node startup on a chain whose
    /// genesis has an `aggregation` section; may be a no-op.
    fn warm_aggregation(&self, _shape: &crate::types::DeclaredShape) {}
}

/// Test executor. A "proof" is `STUB` || tier (1 byte) || 8 outputs (LE u32) || `H_IN`
/// (8 LE u32) || `H_PUB` (8 LE u32) || blake3(program id)[..8]. Any code is accepted. Never use
/// on a real chain.
#[derive(Debug, Default, Clone)]
pub struct StubExecutor;

pub const STUB_MARKER: &[u8; 4] = b"STUB";
const STUB_LEN: usize = 4 + 1 + 32 + 32 + 32 + 8;
/// Stub bundle proof: `STUB` || 32-byte digest || blake3("rand-stub-bundle", hc_bundle bytes)[..8]
/// || the 8 binding words (32 bytes, little-endian) — the stand-in for a real proof's public
/// input segment, compared word for word by `verify_bundle` exactly as the zkVM compares `H_PUB`.
const STUB_BUNDLE_LEN: usize = 4 + 32 + 8 + 32;
/// Where the binding words start inside a stub bundle proof.
const STUB_BUNDLE_BINDING: usize = 4 + 32 + 8;

impl StubExecutor {
    /// A stub call proof publishing an all-zero `H_IN` — what a test that is not about the
    /// input commitment wants. [`Self::make_proof_with_h_in`] is the same proof with a chosen one.
    pub fn make_proof(program: &Hash, tier: u8, outputs: [u32; 8]) -> Vec<u8> {
        Self::make_proof_with_h_in(program, tier, outputs, [0; 8])
    }

    /// A stub call proof publishing `h_in` as its private-input commitment (`pv::IN0..7` on a
    /// real proof) — what a call-input envelope is sealed against (spec §6.1).
    pub fn make_proof_with_h_in(program: &Hash, tier: u8, outputs: [u32; 8], h_in: Word8) -> Vec<u8> {
        Self::make_proof_full(program, tier, outputs, h_in, &[])
    }

    /// A stub call proof committed to the public input `public` (`pv::PUB0..7` on a real proof):
    /// what a call against a program deployed with that public input must carry.
    pub fn make_proof_with_public(program: &Hash, tier: u8, outputs: [u32; 8], public: &[u32]) -> Vec<u8> {
        Self::make_proof_full(program, tier, outputs, [0; 8], public)
    }

    fn make_proof_full(program: &Hash, tier: u8, outputs: [u32; 8], h_in: Word8, public: &[u32]) -> Vec<u8> {
        let mut v = STUB_MARKER.to_vec();
        v.push(tier);
        for o in outputs {
            v.extend_from_slice(&o.to_le_bytes());
        }
        v.extend_from_slice(&word8_to_bytes(&h_in));
        v.extend_from_slice(&word8_to_bytes(&StubExecutor.public_digest(public)));
        v.extend_from_slice(&Hash::digest_domain(b"rand-stub-binding", program.as_bytes()).0[..8]);
        v
    }

    /// Build a stub bundle proof publishing `digest`, bound to the guest commitment `hc_bundle`
    /// and to `binding` — the [`Transaction::binding`] of the transaction it will ride in.
    pub fn make_bundle_proof(hc_bundle: &Word8, digest: &Word8, binding: &[u32; TX_BINDING_WORDS]) -> Vec<u8> {
        let mut v = STUB_MARKER.to_vec();
        v.extend_from_slice(&word8_to_bytes(digest));
        v.extend_from_slice(&Hash::digest_domain(b"rand-stub-bundle", &word8_to_bytes(hc_bundle)).0[..8]);
        v.extend_from_slice(&word8_to_bytes(binding));
        v
    }

    /// Re-bind every stub bundle proof `tx` carries — the fee bundle's and an asset bundle's — to
    /// `tx.binding()`, leaving each proof's digest and guest commitment as they were, and leaving
    /// anything that is not a well-formed stub bundle proof (a pruned marker, deliberately broken
    /// bytes) untouched. What a test calls once it has finished assembling a transaction: the
    /// stub's analogue of a wallet proving after it has built everything but the proofs.
    ///
    /// Binding blanks every bundle proof, so the order in which the two proofs are rewritten does not
    /// matter: the binding is the same before and after.
    pub fn bind(tx: &mut Transaction) {
        let binding = word8_to_bytes(&tx.binding());
        let rebind = |b: &mut crate::notes::Bundle| {
            if b.proof.len() == STUB_BUNDLE_LEN && &b.proof[..4] == STUB_MARKER {
                b.proof[STUB_BUNDLE_BINDING..].copy_from_slice(&binding);
            }
        };
        if let Some(b) = tx.bundle.as_mut() {
            rebind(b);
        }
        if let Some(b) = tx.action.asset_bundle_mut() {
            rebind(b);
        }
    }

    /// [`Self::bind`], by value.
    pub fn bound(mut tx: Transaction) -> Transaction {
        Self::bind(&mut tx);
        tx
    }

    fn hash_words(domain: &[u8], parts: &[&[u8]]) -> Word8 {
        let mut buf = Vec::new();
        for p in parts {
            buf.extend_from_slice(p);
        }
        word8_from_bytes(&Hash::digest_domain(domain, &buf).0).unwrap()
    }
}

impl ConfidentialExecutor for StubExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        Ok(crate::program::program_id(base_pc, words).0.to_vec())
    }

    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        if proof.len() != STUB_LEN || &proof[..4] != STUB_MARKER {
            return Err(ConfidentialError::MalformedProof);
        }
        let expected = &Hash::digest_domain(b"rand-stub-binding", program.id.as_bytes()).0[..8];
        if &proof[STUB_LEN - 8..] != expected {
            return Err(ConfidentialError::WrongProgram);
        }
        let tier = proof[4];
        let mut outputs = [0u32; 8];
        for (i, o) in outputs.iter_mut().enumerate() {
            *o = u32::from_le_bytes(proof[5 + 4 * i..9 + 4 * i].try_into().unwrap());
        }
        let h_in = word8_from_bytes(&proof[37..69]).expect("32 bytes");
        let h_pub = word8_from_bytes(&proof[69..101]).expect("32 bytes");
        if h_pub != program.public_digest.unwrap_or_else(|| self.public_digest(&[])) {
            return Err(ConfidentialError::InvalidProof("PublicValues".into()));
        }
        Ok(CallOutcome { tier, outputs, h_in })
    }

    /// A blake3 stand-in for `H_PUB`, length-prefixed like the real one's header, so the empty
    /// input has its own fixed, non-zero digest as it does in the zkVM.
    fn public_digest(&self, words: &[u32]) -> Word8 {
        let mut buf = (words.len() as u32).to_le_bytes().to_vec();
        for w in words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        Self::hash_words(b"rand-stub-public", &[&buf])
    }

    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        Self::hash_words(b"rand-stub-node", &[&word8_to_bytes(left), &word8_to_bytes(right)])
    }

    /// A blake3 stand-in over the same six fields. It is not the real note commitment and no
    /// note sealed against it will ever open on a real chain — but it is injective in exactly
    /// the fields the real one is, which is what the ledger's tests need.
    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
        Self::hash_words(
            b"rand-stub-note",
            &[
                &word8_to_bytes(pk),
                &word8_to_bytes(from),
                &amount.to_le_bytes(),
                &asset.to_le_bytes(),
                &time.to_le_bytes(),
                &word8_to_bytes(r),
            ],
        )
    }

    fn bundle_digest(&self, i: &BundleDigestInput) -> Word8 {
        Self::hash_words(
            b"rand-stub-bundle-digest",
            &[
                &word8_to_bytes(&i.anchor),
                &word8_to_bytes(&i.nullifiers[0]),
                &word8_to_bytes(&i.nullifiers[1]),
                &word8_to_bytes(&i.commitments[0]),
                &word8_to_bytes(&i.commitments[1]),
                &i.fee.to_le_bytes(),
                &i.burn.to_le_bytes(),
                &i.asset.to_le_bytes(),
                &i.time.to_le_bytes(),
            ],
        )
    }

    fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        if proof.len() != STUB_BUNDLE_LEN || &proof[..4] != STUB_MARKER {
            return Err(ConfidentialError::MalformedProof);
        }
        Ok(word8_from_bytes(&proof[4..36]).unwrap())
    }

    fn verify_bundle(
        &self,
        hc_bundle: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError> {
        self.bundle_proof_digest(proof)?;
        let expected = &Hash::digest_domain(b"rand-stub-bundle", &word8_to_bytes(hc_bundle)).0[..8];
        if &proof[36..STUB_BUNDLE_BINDING] != expected {
            return Err(ConfidentialError::WrongProgram);
        }
        // The binding, as the zkVM checks `H_PUB`: a proof made for another transaction is
        // refused with the same words `Machine::verify_public` reports (`PublicValues`).
        if proof[STUB_BUNDLE_BINDING..] != word8_to_bytes(binding) {
            return Err(ConfidentialError::InvalidBundleProof("PublicValues".into()));
        }
        Ok(())
    }

    fn aggregate_program_digest(&self, _shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
        // A stand-in digest, not the real one — distinctive so a test that forgot to stub the
        // right thing notices, and deterministic so the rest can compare.
        Ok([0xa66_e6a7e_u64; 4])
    }

    fn verify_aggregate(
        &self,
        _shape: &crate::types::DeclaredShape,
        covered: &[crate::types::CoveredBundle],
        proof: &[u8],
    ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
        if proof == b"reject" {
            return Err(ConfidentialError::InvalidAggregateProof("stub rejection".into()));
        }
        // The stub answers what the real one would for an honest aggregate: each covered
        // bundle's `OUT0..7` — pv words `pv::OUT0..OUT0+8` in cover order — so ledger tests
        // exercise the real control flow without any proving.
        Ok(covered
            .iter()
            .map(|c| {
                std::array::from_fn(|k| {
                    u32::try_from(c.public_values[crate::types::pv::OUT0 + k]).expect("stub OUT words are u32-range")
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: Hash) -> ProgramRecord {
        ProgramRecord { id, base_pc: 0, words: vec![0x13], code_hash: vec![], deployed_at: 0, public_digest: None, public_len: 0 }
    }

    /// The stub checks the proof's public-input digest against the record's exactly as the zkVM
    /// executor does: the deploy-time digest when there is one, the empty input's otherwise.
    #[test]
    fn stub_checks_the_public_digest_against_the_record() {
        let id = Hash::digest(b"p");
        let public = [7u32, 8, 9];
        let digest = StubExecutor.public_digest(&public);
        assert_ne!(digest, StubExecutor.public_digest(&[]));
        assert_ne!(StubExecutor.public_digest(&[]), [0; 8]);
        let with = ProgramRecord { public_digest: Some(digest), public_len: 3, ..record(id) };
        let proof = StubExecutor::make_proof_with_public(&id, 12, [1; 8], &public);
        assert_eq!(StubExecutor.verify_call(&with, &proof).unwrap().outputs, [1; 8]);
        let bad = ConfidentialError::InvalidProof("PublicValues".into());
        let other = StubExecutor::make_proof_with_public(&id, 12, [1; 8], &[7, 8, 10]);
        assert_eq!(StubExecutor.verify_call(&with, &other), Err(bad.clone()));
        let empty = StubExecutor::make_proof(&id, 12, [1; 8]);
        assert_eq!(StubExecutor.verify_call(&with, &empty), Err(bad.clone()));
        // A program without a public input takes only the empty input's proofs.
        assert!(StubExecutor.verify_call(&record(id), &empty).is_ok());
        assert_eq!(StubExecutor.verify_call(&record(id), &proof), Err(bad));
    }

    #[test]
    fn stub_roundtrips_outputs_and_binds_program() {
        let id = Hash::digest(b"p");
        let proof = StubExecutor::make_proof(&id, 12, [1, 0, 5, 0, 0, 0, 0, 9]);
        let out = StubExecutor.verify_call(&record(id), &proof).unwrap();
        assert_eq!(out, CallOutcome { tier: 12, outputs: [1, 0, 5, 0, 0, 0, 0, 9], h_in: [0; 8] });
        // …and the H_IN a call-input envelope is sealed against travels in the proof, not beside it.
        let sealed = StubExecutor::make_proof_with_h_in(&id, 12, [1, 0, 5, 0, 0, 0, 0, 9], [7; 8]);
        assert_eq!(StubExecutor.verify_call(&record(id), &sealed).unwrap().h_in, [7; 8]);
        assert_eq!(StubExecutor.verify_call(&record(Hash::digest(b"q")), &proof), Err(ConfidentialError::WrongProgram));
        assert_eq!(StubExecutor.verify_call(&record(id), b"junk"), Err(ConfidentialError::MalformedProof));
    }

    #[test]
    fn stub_bundle_proof_carries_its_digest_and_binds_hc() {
        let hc = [3u32; 8];
        let d = [5u32; 8];
        let binding = [6u32; 8];
        let p = StubExecutor::make_bundle_proof(&hc, &d, &binding);
        assert_eq!(StubExecutor.bundle_proof_digest(&p).unwrap(), d);
        assert_eq!(StubExecutor.verify_bundle(&hc, &p, &binding), Ok(()));
        assert_eq!(StubExecutor.verify_bundle(&[4u32; 8], &p, &binding), Err(ConfidentialError::WrongProgram));
        // Task 5b: the stub enforces the binding as the zkVM does — another transaction's words
        // are refused, and so is a proof made against no transaction at all.
        let public_values = Err(ConfidentialError::InvalidBundleProof("PublicValues".into()));
        assert_eq!(StubExecutor.verify_bundle(&hc, &p, &[7u32; 8]), public_values);
        let unbound = StubExecutor::make_bundle_proof(&hc, &d, &[0; 8]);
        assert_eq!(StubExecutor.verify_bundle(&hc, &unbound, &binding), public_values);
        assert_eq!(StubExecutor.bundle_proof_digest(b"junk"), Err(ConfidentialError::MalformedProof));
        assert_ne!(StubExecutor.node_hash(&[1; 8], &[2; 8]), StubExecutor.node_hash(&[2; 8], &[1; 8]));
    }

    /// Every field the real commitment binds, the stand-in binds too — otherwise a ledger test
    /// could pass on a note the real chain would compute differently.
    #[test]
    fn the_stub_note_commitment_binds_every_field() {
        let base = StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 0, 9, &[3; 8]);
        assert_eq!(base, StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 0, 9, &[3; 8]), "deterministic");
        for other in [
            StubExecutor.note_commitment(&[9; 8], &[2; 8], 5, 0, 9, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[9; 8], 5, 0, 9, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[2; 8], 6, 0, 9, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 1, 9, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 0, 10, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 0, 9, &[4; 8]),
        ] {
            assert_ne!(other, base);
        }
        // A different domain from the tree node hash, over the same-shaped input.
        assert_ne!(base, StubExecutor.node_hash(&[1; 8], &[2; 8]));
    }
}
