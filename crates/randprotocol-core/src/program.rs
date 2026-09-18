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
    Hash::digest_domain(b"rand-program", &buf)
}

/// Content address of a program deployed with a public input (the call limits, spec §5): the same
/// code with a different public input is a different program.
///
/// - `public` empty: exactly [`program_id`], so every id a chain without public inputs issued
///   still holds;
/// - otherwise `blake3("rand-program-2", base_pc ‖ u32_le(len(words)) ‖ words ‖ u32_le(len(public)) ‖ public)`.
///
/// Both lengths are bound. With only the public input's, the boundary between the code and the
/// public input would be ambiguous: `words = [a, 2], public = [d]` and `words = [a], public = [1, d]`
/// would hash the same bytes, and whoever deployed first would own the other's id.
pub fn program_id_with_public(base_pc: u32, words: &[u32], public: &[u32]) -> ProgramId {
    if public.is_empty() {
        return program_id(base_pc, words);
    }
    let mut buf = Vec::with_capacity(12 + 4 * (words.len() + public.len()));
    buf.extend_from_slice(&base_pc.to_le_bytes());
    buf.extend_from_slice(&(words.len() as u32).to_le_bytes());
    for w in words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    buf.extend_from_slice(&(public.len() as u32).to_le_bytes());
    for w in public {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    Hash::digest_domain(b"rand-program-2", &buf)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRecord {
    pub id: ProgramId,
    pub base_pc: u32,
    pub words: Vec<u32>,
    /// `hc`: the zkVM's in-circuit Poseidon2 program digest (`randprotocol_zkvm::isa::Program::digest`),
    /// as 8 little-endian `u32` words (32 bytes). M3.4: this is no longer merely informational —
    /// `ZkExecutor::verify_call` decodes it back into `hc` and hands it straight to
    /// `Machine::verify(hc, proof)`, which never sees `words` at all (the verifier holds only
    /// the digest, `docs/confidential.md`'s "Constraint set 3" note). `ZkExecutor::check_program`
    /// computes it at deploy time.
    pub code_hash: Vec<u8>,
    pub deployed_at: u64,
    /// `H_PUB` of the public input the program was deployed with (`hash::public_digest(public)`
    /// in the zkVM, reached through `ConfidentialExecutor::public_digest`), computed once at
    /// deploy; `None` for a program deployed without one. Every call's proof must publish exactly
    /// this in `pv::PUB0..7` (or `public_digest(&[])` when `None`). The words themselves are not
    /// here — the node keeps them in its `program_public` column, so the record stays small.
    pub public_digest: Option<Word8>,
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
    /// The public-input digest the proof was checked against: the program's
    /// [`ProgramRecord::public_digest`], `None` for a program deployed without a public input.
    pub h_pub: Option<Word8>,
    /// The call-input envelope the transaction published, if it published one (spec §6.1).
    ///
    /// Chain data the chain never reads: the ledger checks its size and stores it here, and a
    /// node serves it as `rand_getCallEnvelope`. It lives on the receipt rather than being
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

    /// The id rule (spec §5): no public input keeps today's id; a public input moves the program
    /// to the `rand-program-2` domain, with the public input's length bound in front of it.
    #[test]
    fn a_public_input_changes_the_id_and_an_empty_one_does_not() {
        assert_eq!(program_id_with_public(0, &[1, 2, 3], &[]), program_id(0, &[1, 2, 3]));
        let with = program_id_with_public(4, &[1, 2, 3], &[7, 8]);
        assert_ne!(with, program_id(4, &[1, 2, 3]));
        assert_ne!(with, program_id_with_public(4, &[1, 2, 3], &[7, 9]));
        assert_ne!(with, program_id_with_public(4, &[1, 2, 3], &[7]));
        assert_ne!(with, program_id_with_public(0, &[1, 2, 3], &[7, 8]));
        let mut buf = Vec::new();
        for w in [4u32, 3, 1, 2, 3, 2, 7, 8] {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        assert_eq!(
            with,
            Hash::digest_domain(b"rand-program-2", &buf),
            "base_pc ‖ u32_le(len(words)) ‖ words ‖ u32_le(len(public)) ‖ public"
        );
    }

    /// The collision the single-length rule had: without the code's length, these two hashed
    /// the same bytes, `pc ‖ a ‖ 2 ‖ 1 ‖ d`.
    #[test]
    fn the_code_and_public_boundary_is_bound() {
        let (a, d) = (0x13u32, 0x99u32);
        assert_ne!(program_id_with_public(0, &[a, 2], &[d]), program_id_with_public(0, &[a], &[1, d]));
    }

    /// Every split of one concatenation into non-empty code and non-empty public input is a
    /// different program.
    #[test]
    fn every_split_of_the_same_words_is_a_different_id() {
        let all = [1u32, 2, 3, 1, 2, 1, 1];
        let ids: std::collections::BTreeSet<ProgramId> =
            (1..all.len()).map(|k| program_id_with_public(0, &all[..k], &all[k..])).collect();
        assert_eq!(ids.len(), all.len() - 1);
    }
}
