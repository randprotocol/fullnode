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
///
/// **Separation from the old rule is by length parity.** [`Hash::digest_domain`] concatenates the
/// domain raw in front of the data, with no length or separator, so the two rules hash:
///
/// - old: `"rand-program"` (12 bytes) ‖ `base_pc` (4) ‖ `4n` bytes of code: `16 + 4n ≡ 0 (mod 4)`;
/// - new: `"rand-program-2"` (14 bytes) ‖ `base_pc` (4) ‖ two lengths (8) ‖ `4(n + m)` bytes:
///   `26 + 4(n + m) ≡ 2 (mod 4)`.
///
/// An old-rule blake3 input is therefore never byte-equal to a new-rule one, whatever the words
/// (the domains' shared prefix `"rand-program"` does not matter), and a new-rule id equals an
/// old-rule id only by a blake3 collision. Changing either domain's length, or the width of any
/// field, must keep the two residues apart; `the_two_id_rules_hash_inputs_of_different_length_parity`
/// pins them.
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

/// The public segment a call proves over under genesis `hardening_v6` (INT-4, and issue #55 for a
/// program with a public input): the program's deploy-time public words, then the eight words of
/// `Transaction::call_binding`. The guest reads its own public words at the indices it always did;
/// the binding after them only moves `H_PUB`, so a proof copied under another fee bundle fails the
/// digest compare. The ledger, the wallet and the prover all build it here, so they cannot drift.
pub fn hardened_call_segment(public: &[u32], binding: &[u32; crate::types::TX_BINDING_WORDS]) -> Vec<u32> {
    [public, binding.as_slice()].concat()
}

/// Rows in the zkVM's program table for a program of `len` words: `max(len + 1, 128)` rounded up
/// to a power of two — `1 << tables::program::program_log_height(len)` in the zkVM (`pad_height(len +
/// 1, MIN_HEIGHT)`, floored at `2^MIN_PRIVATE_TABLE_LOG_HEIGHT` since constraint set 7; through
/// constraint set 6 the floor was `MIN_HEIGHT`'s 16). Core cannot name a zkvm function (the
/// dependency points the other way), so this is a mirror, like `types::pv`;
/// `randprotocol-zkvm/src/executor.rs`'s tests pin it to the real function, so a re-vendor that
/// moves the table's padding fails there.
pub fn program_table_rows(len: usize) -> u64 {
    (len as u64).saturating_add(1).max(1 << MIN_PRIVATE_TABLE_LOG_HEIGHT).next_power_of_two()
}

/// The zkVM's private-table floor, `executor::MIN_PRIVATE_TABLE_LOG_HEIGHT` (2^7 rows): under genesis
/// `hardening_v6` a call's program table is declared at `max(program_log_height(len), 7)`
/// (`executor::hardened_program_log_height`, PROGRAM-TABLE-LEAK), so the rows the pc window has to
/// hold are at least this many. Core cannot name the zkVM's constant (the dependency points the other
/// way), so this is a mirror, like [`program_table_rows`]; `randprotocol-zkvm/src/executor.rs`'s
/// tests pin it equal to the real one, so a re-vendor that moves the floor fails there rather than
/// letting the window drift from the table a hardened proof builds.
pub const MIN_PRIVATE_TABLE_LOG_HEIGHT: u8 = 7;

/// ZKV-11 (pc-wrap, 2026-09-28): does every row of this program's *padded* program table sit below
/// the u32 pc wrap — `base_pc + 4 · max(program_table_rows(len), 2^MIN_PRIVATE_TABLE_LOG_HEIGHT) ≤ 2^32`?
///
/// The circuit does its PC arithmetic in the field — the program table's PC chain, the cpu's
/// fall-through `PC + 4`, the JAL/JALR link — while the emulator wraps mod 2^32, so a program whose
/// padded table crosses 2^32 has rows whose field PCs the emulator never produces, and no honest
/// proof of it verifies (`OodEvaluationMismatch`). ZH4's `check_program` bounds only the program's
/// own words, `base_pc + 4 · len`, not the `2^program_log_height` rows the table pads to: fib (15
/// words) at `base_pc = 0xffffffc4` ends exactly at 2^32 and passes it, but pads to 16 rows, one
/// past the wrap — deployable, paid for, and uncallable for ever. Nothing live is affected (every
/// chain-15 program sits at `base_pc` 0). The verifier- and prover-side halves of the fix are the
/// zkVM's (vendored, upstream); this predicate is what the node refuses such a deploy on — as its
/// admission policy on every chain, and as a validity rule under genesis `hardening_v6` (the v0.6 switch).
///
/// **The rows measured are the floored table's** (PCW-FLOOR, the v0.6 rescan). Under `hardening_v6`
/// every call declares its program table at no fewer than 2^7 rows, and the padding rows carry
/// field PCs `last_pc + 4k` exactly as the unfloored ones do — so fib at `0xffffffc0`, whose 16-row
/// table ends at 2^32, has a 128-row table that crosses it, and the rescan's reproduction showed
/// its floored proof refused (`OodEvaluationMismatch`) while the window had admitted the deploy:
/// the very condition the window exists to prevent. One window for both uses, the floored one:
/// stricter than chain 15's unfloored calls strictly need, which costs the pool policy nothing
/// (every chain-15 program sits at `base_pc` 0, and a start within 512 bytes of the wrap is no
/// honest deployer's choice).
pub fn pc_window_fits(base_pc: u32, len: usize) -> bool {
    let rows = program_table_rows(len).max(1 << MIN_PRIVATE_TABLE_LOG_HEIGHT);
    (base_pc as u64).saturating_add(rows.saturating_mul(4)) <= 1 << 32
}

/// The refusal for a deploy [`pc_window_fits`] refuses, one text for the admission policy and the
/// validity rule, in ZH4's words.
pub fn pc_window_error() -> crate::confidential::ConfidentialError {
    crate::confidential::ConfidentialError::BadInstruction {
        index: 0,
        reason: "padded program table spans the u32 pc wrap".into(),
    }
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
    /// The length of that public input, in words (0 when there is none). A proof's public table
    /// height is a function of it (`tables::public::public_log_height`), so the executor's `warm`
    /// needs it to precompute the verifier key every call against this program uses.
    pub public_len: u32,
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
    /// The proof's declared keccak-table height (`0` = no table): with `tier` and
    /// `sha256_log_height`, what `gas::gas_max` prices a call by (spec 2026-09-28 §4.1).
    pub keccak_log_height: u8,
    /// The declared sha256-table height, `0` = none.
    pub sha256_log_height: u8,
    /// Constraint set 8: the proof's declared gas limit (`pv::GAS`), taken straight from the
    /// proof the verifier just accepted. The circuit holds the run's metered gas to it
    /// (`gas ≤ gas_limit`) and the verifier holds it to the header's ceiling
    /// ([`Self::gas_max`]), so `gas_limit ≤ gas_max()` for every accepted proof. What a gas-priced
    /// chain charges a call for (spec 2026-09-28 §4.3): a caller who declares less pays less.
    pub gas_limit: u64,
}

impl CallOutcome {
    /// The gas ceiling this proof's header implies (`gas::gas_max`).
    pub fn gas_max(&self) -> u64 {
        crate::gas::gas_max(self.tier, self.keccak_log_height, self.sha256_log_height)
    }
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

    /// The separation argument on [`program_id_with_public`]: the old rule's blake3 input is
    /// `≡ 0 (mod 4)` bytes long, the new rule's `≡ 2 (mod 4)`, for any word counts. Rebuilt here
    /// from the two domains and checked against both functions, so a change to either domain or
    /// either layout that closed the gap fails here.
    #[test]
    fn the_two_id_rules_hash_inputs_of_different_length_parity() {
        let old_input = |base_pc: u32, words: &[u32]| {
            let mut v = b"rand-program".to_vec();
            v.extend_from_slice(&base_pc.to_le_bytes());
            words.iter().for_each(|w| v.extend_from_slice(&w.to_le_bytes()));
            v
        };
        let new_input = |base_pc: u32, words: &[u32], public: &[u32]| {
            let mut v = b"rand-program-2".to_vec();
            v.extend_from_slice(&base_pc.to_le_bytes());
            v.extend_from_slice(&(words.len() as u32).to_le_bytes());
            words.iter().for_each(|w| v.extend_from_slice(&w.to_le_bytes()));
            v.extend_from_slice(&(public.len() as u32).to_le_bytes());
            public.iter().for_each(|w| v.extend_from_slice(&w.to_le_bytes()));
            v
        };
        for n in 0..6usize {
            let words: Vec<u32> = (0..n as u32).map(|i| 0x13 + i).collect();
            let old = old_input(4, &words);
            assert_eq!(old.len() % 4, 0, "old rule, {n} words");
            assert_eq!(program_id(4, &words), Hash(*blake3::hash(&old).as_bytes()));
            for m in 1..5usize {
                let public: Vec<u32> = (0..m as u32).collect();
                let new = new_input(4, &words, &public);
                assert_eq!(new.len() % 4, 2, "new rule, {n} words, {m} public");
                assert_eq!(program_id_with_public(4, &words, &public), Hash(*blake3::hash(&new).as_bytes()));
                assert_ne!(program_id_with_public(4, &words, &public), program_id(4, &words));
            }
        }
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

    /// PCW-FLOOR (the v0.6 rescan): the window is taken over the program table a hardened call
    /// declares — at least `2^MIN_PRIVATE_TABLE_LOG_HEIGHT` = 128 rows — not the 16 fib's 15 words
    /// would pad to unfloored. At `0xffffffc0` the 16-row table ends exactly at 2^32 but the
    /// 128-row one does not, and the rescan's reproduction showed its floored proof failing
    /// (`OodEvaluationMismatch`); the highest start that fits is `2^32 − 4·128`. A program past
    /// 127 words is unaffected: its own table is the taller one.
    #[test]
    fn the_window_measures_the_floored_program_table() {
        assert!(!pc_window_fits(0xffff_ffc0, 15), "the rescan's reproduction: 128 rows cross the wrap");
        assert!(pc_window_fits(0xffff_fe00, 15), "2^32 − 512: the 128 rows end exactly at 2^32");
        assert!(!pc_window_fits(0xffff_fe04, 15), "one word higher does not fit");
        assert!(pc_window_fits(0xffff_fe00, 127), "127 words still pad to 128 rows");
        assert!(!pc_window_fits(0xffff_fe00, 128), "128 words pad to 256: the program's own table rules");
        assert!(pc_window_fits(0xffff_fc00, 128));
        assert!(pc_window_fits(0, 15), "every chain-15 program sits at base_pc 0");
    }
}
