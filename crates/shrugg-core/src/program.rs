//! On-chain programs and call receipts.

use crate::crypto::Hash;
use crate::notes::Word8;
use crate::types::CallEnvelope;
use serde::{Deserialize, Serialize};

pub type ProgramId = Hash;

/// Content address of a program: blake3 over base_pc and the code words.
pub fn program_id(base_pc: u32, words: &[u32]) -> ProgramId {
    let mut buf = Vec::with_capacity(4 + 4 * words.len());
    buf.extend_from_slice(&base_pc.to_le_bytes());
    for w in words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    Hash::digest_domain(b"shrugg-program", &buf)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRecord {
    pub id: ProgramId,
    pub base_pc: u32,
    pub words: Vec<u32>,
    /// `hc`: the zkVM's in-circuit Poseidon2 program digest (`shrugg_zkvm::isa::Program::digest`),
    /// as 8 little-endian `u32` words (32 bytes). M3.4: this is no longer merely informational —
    /// `ZkExecutor::verify_call` decodes it back into `hc` and hands it straight to
    /// `Machine::verify(hc, proof)`, which never sees `words` at all (the verifier holds only
    /// the digest, `docs/confidential.md`'s "Constraint set 3" note). `ZkExecutor::check_program`
    /// computes it at deploy time.
    pub code_hash: Vec<u8>,
    pub deployed_at: u64,
}

/// What a verified call proved: its gas tier, the eight public outputs, and the public
/// commitment to its private inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallOutcome {
    pub tier: u8,
    pub outputs: [u32; 8],
    /// `H_IN` (zkVM M4.1, `pv::IN0..7`): the salted in-circuit commitment to every word the
    /// guest read. Public, and taken straight from the proof the verifier just accepted.
    ///
    /// The chain does nothing with it — but it is the associated data a call-input envelope is
    /// sealed against (spec §6.1), so without it on the receipt nobody holding a viewing key, a
    /// per-call key or an auditor key could open the transcript, and nobody could check an
    /// opened one against `hash::input_digest(salt, inputs)`.
    pub h_in: Word8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallReceipt {
    pub tx: Hash,
    pub program: ProgramId,
    pub tier: u8,
    pub outputs: [u32; 8],
    pub height: u64,
    pub index: u32,
    /// `H_IN`, copied from the verified proof: the public commitment to the call's private
    /// inputs, and the key to reading `input_envelope` (see [`CallOutcome::h_in`]).
    pub h_in: Word8,
    /// The call-input envelope the transaction published, if it published one (spec §6.1).
    ///
    /// Chain data the chain never reads: the ledger checks its size and stores it here, and a
    /// node serves it as `shrugg_getCallEnvelope`. It lives on the receipt rather than being
    /// re-read from the block because that is how it is asked for — by transaction hash, by
    /// someone who was handed a viewing key or a per-call key long after the block was made.
    pub input_envelope: Option<CallEnvelope>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_id_depends_on_code_and_base_pc() {
        let a = program_id(0, &[1, 2, 3]);
        assert_eq!(a, program_id(0, &[1, 2, 3]));
        assert_ne!(a, program_id(4, &[1, 2, 3]));
        assert_ne!(a, program_id(0, &[1, 2, 4]));
        assert_ne!(a, program_id(0, &[1, 2]));
    }
}
