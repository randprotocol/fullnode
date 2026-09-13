//! Confidential computation: the executor the ledger calls to validate programs, verify call
//! proofs and reach every Poseidon2 hash the shielded pool needs. `shrugg-zkvm` provides the
//! real implementation (`ZkExecutor`); `StubExecutor` is a crypto-free stand-in for fast tests.

use crate::crypto::Hash;
use crate::notes::{word8_from_bytes, word8_to_bytes, BundleDigestInput, Word8};
use crate::program::{CallOutcome, ProgramRecord};

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
    #[error("confidential computation is disabled on this chain")]
    Disabled,
}

pub trait ConfidentialExecutor: Send + Sync {
    /// Validate program code at deploy time (must be cheap: it runs inside block application)
    /// and return the code commitment recorded on chain.
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError>;
    /// Verify `proof` against `program`; on success return the tier and the eight outputs.
    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError>;
    /// Precompute whatever makes `verify_call` fast for `program` (the zkVM verifier key,
    /// ~2 s). Called from a background task after a deploy commits and at startup; may be a no-op.
    fn warm(&self, _program: &ProgramRecord) {}
    /// Poseidon2 tree-node hash `H(NODE, left || right)` — the hash `MERKLE_VERIFY` checks against.
    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8;
    /// The note commitment `H(CM, pk(8) from(8) amount_lo amount_hi asset time r(8))` — the
    /// 28-word note layout of the vendored `shrugg_zkvm::notes::Note`.
    ///
    /// The ledger needs this for the deposits it creates itself rather than accepts on the
    /// wire: S2's `Withdraw` and S3's `BridgeAttest` publish only the blinding `r` and a public
    /// amount, and the chain computes the commitment, so a validator cannot declare one amount
    /// and mint a note for another.
    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8;
    /// `notes::bundle_digest(..)` (in the vendored research note layer, `shrugg_zkvm::notes`,
    /// arriving in Task 2) over the public bundle fields with the taint word fixed to 0.
    fn bundle_digest(&self, input: &BundleDigestInput) -> Word8;
    /// Cheap: decode `proof`, check its declared tier/heights/public-value canonicity, and return
    /// the digest it publishes in `OUT0..OUT7`. Verifies nothing cryptographic.
    fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError>;
    /// Expensive: the STARK verification of a bundle proof against the pinned bundle guest.
    fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<(), ConfidentialError>;
    /// Precompute the bundle verifier key. May be a no-op.
    fn warm_bundle(&self) {}
}

/// Test executor. A "proof" is `STUB` || tier (1 byte) || 8 outputs (LE u32) || `H_IN`
/// (8 LE u32) || blake3(program id)[..8]. Any code is accepted. Never use on a real chain.
#[derive(Debug, Default, Clone)]
pub struct StubExecutor;

pub const STUB_MARKER: &[u8; 4] = b"STUB";
const STUB_LEN: usize = 4 + 1 + 32 + 32 + 8;
/// Stub bundle proof: `STUB` || 32-byte digest || blake3("shrugg-stub-bundle", hc_bundle bytes)[..8].
const STUB_BUNDLE_LEN: usize = 4 + 32 + 8;

impl StubExecutor {
    /// A stub call proof publishing an all-zero `H_IN` — what a test that is not about the
    /// input commitment wants. [`Self::make_proof_with_h_in`] is the same proof with a chosen one.
    pub fn make_proof(program: &Hash, tier: u8, outputs: [u32; 8]) -> Vec<u8> {
        Self::make_proof_with_h_in(program, tier, outputs, [0; 8])
    }

    /// A stub call proof publishing `h_in` as its private-input commitment (`pv::IN0..7` on a
    /// real proof) — what a call-input envelope is sealed against (spec §6.1).
    pub fn make_proof_with_h_in(program: &Hash, tier: u8, outputs: [u32; 8], h_in: Word8) -> Vec<u8> {
        let mut v = STUB_MARKER.to_vec();
        v.push(tier);
        for o in outputs {
            v.extend_from_slice(&o.to_le_bytes());
        }
        v.extend_from_slice(&word8_to_bytes(&h_in));
        v.extend_from_slice(&Hash::digest_domain(b"shrugg-stub-binding", program.as_bytes()).0[..8]);
        v
    }

    /// Build a stub bundle proof publishing `digest` and bound to the guest commitment `hc_bundle`.
    pub fn make_bundle_proof(hc_bundle: &Word8, digest: &Word8) -> Vec<u8> {
        let mut v = STUB_MARKER.to_vec();
        v.extend_from_slice(&word8_to_bytes(digest));
        v.extend_from_slice(&Hash::digest_domain(b"shrugg-stub-bundle", &word8_to_bytes(hc_bundle)).0[..8]);
        v
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
        let expected = &Hash::digest_domain(b"shrugg-stub-binding", program.id.as_bytes()).0[..8];
        if &proof[STUB_LEN - 8..] != expected {
            return Err(ConfidentialError::WrongProgram);
        }
        let tier = proof[4];
        let mut outputs = [0u32; 8];
        for (i, o) in outputs.iter_mut().enumerate() {
            *o = u32::from_le_bytes(proof[5 + 4 * i..9 + 4 * i].try_into().unwrap());
        }
        let h_in = word8_from_bytes(&proof[37..69]).expect("32 bytes");
        Ok(CallOutcome { tier, outputs, h_in })
    }

    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        Self::hash_words(b"shrugg-stub-node", &[&word8_to_bytes(left), &word8_to_bytes(right)])
    }

    /// A blake3 stand-in over the same six fields. It is not the real note commitment and no
    /// note sealed against it will ever open on a real chain — but it is injective in exactly
    /// the fields the real one is, which is what the ledger's tests need.
    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
        Self::hash_words(
            b"shrugg-stub-note",
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
            b"shrugg-stub-bundle-digest",
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

    fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<(), ConfidentialError> {
        self.bundle_proof_digest(proof)?;
        let expected = &Hash::digest_domain(b"shrugg-stub-bundle", &word8_to_bytes(hc_bundle)).0[..8];
        if &proof[36..] != expected {
            return Err(ConfidentialError::WrongProgram);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: Hash) -> ProgramRecord {
        ProgramRecord { id, base_pc: 0, words: vec![0x13], code_hash: vec![], deployed_at: 0 }
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
        let p = StubExecutor::make_bundle_proof(&hc, &d);
        assert_eq!(StubExecutor.bundle_proof_digest(&p).unwrap(), d);
        assert_eq!(StubExecutor.verify_bundle(&hc, &p), Ok(()));
        assert_eq!(StubExecutor.verify_bundle(&[4u32; 8], &p), Err(ConfidentialError::WrongProgram));
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
