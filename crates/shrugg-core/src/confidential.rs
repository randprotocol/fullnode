//! Confidential computation: the executor the ledger calls to validate programs and verify
//! call proofs. `shrugg-zkvm` provides the real implementation (`ZkExecutor`); `StubExecutor`
//! is a crypto-free stand-in for fast tests, and `DisabledExecutor` serves chains started with
//! `confidential: false`.

use crate::crypto::Hash;
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
}

/// Test executor. A "proof" is `STUB` || tier (1 byte) || 8 outputs (LE u32) || blake3(program id)[..8].
/// Any code is accepted. Never use on a real chain.
#[derive(Debug, Default, Clone)]
pub struct StubExecutor;

pub const STUB_MARKER: &[u8; 4] = b"STUB";
const STUB_LEN: usize = 4 + 1 + 32 + 8;

impl StubExecutor {
    pub fn make_proof(program: &Hash, tier: u8, outputs: [u32; 8]) -> Vec<u8> {
        let mut v = STUB_MARKER.to_vec();
        v.push(tier);
        for o in outputs {
            v.extend_from_slice(&o.to_le_bytes());
        }
        v.extend_from_slice(&Hash::digest_domain(b"shrugg-stub-binding", program.as_bytes()).0[..8]);
        v
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
        Ok(CallOutcome { tier, outputs })
    }
}

/// Executor that refuses everything: for chains with `confidential: false`.
#[derive(Debug, Default, Clone)]
pub struct DisabledExecutor;

impl ConfidentialExecutor for DisabledExecutor {
    fn check_program(&self, _: u32, _: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        Err(ConfidentialError::Disabled)
    }
    fn verify_call(&self, _: &ProgramRecord, _: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        Err(ConfidentialError::Disabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn record(id: Hash) -> ProgramRecord {
        ProgramRecord { id, base_pc: 0, words: vec![0x13], code_hash: vec![], deployer: Keypair::from_seed([1; 32]).unwrap().address(), deployed_at: 0 }
    }

    #[test]
    fn stub_roundtrips_outputs_and_binds_program() {
        let id = Hash::digest(b"p");
        let proof = StubExecutor::make_proof(&id, 12, [1, 0, 5, 0, 0, 0, 0, 9]);
        let out = StubExecutor.verify_call(&record(id), &proof).unwrap();
        assert_eq!(out, CallOutcome { tier: 12, outputs: [1, 0, 5, 0, 0, 0, 0, 9] });
        assert_eq!(StubExecutor.verify_call(&record(Hash::digest(b"q")), &proof), Err(ConfidentialError::WrongProgram));
        assert_eq!(StubExecutor.verify_call(&record(id), b"junk"), Err(ConfidentialError::MalformedProof));
    }

    #[test]
    fn disabled_rejects() {
        assert_eq!(DisabledExecutor.check_program(0, &[0x13]), Err(ConfidentialError::Disabled));
    }
}
