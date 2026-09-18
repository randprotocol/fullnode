//! The call-input envelope a `Call` may carry (spec §6.1).
//!
//! This module is the whole chain-side rule, and it is deliberately tiny: the ledger checks the
//! envelope's size and nothing else. The ciphertext is not bound to the call by consensus but
//! by the AEAD — the sealing uses the proof's public input commitment `H_IN` as associated
//! data, so an envelope that does not belong to this call simply fails to open for everyone.
//! Checking more here would cost every node work that buys no security.
//!
//! S3's Task 1 adds the storage half (the envelope travels with the call receipt). The size cap
//! is the ledger's `max_call_envelope_bytes`, a genesis parameter since the call limits.

use super::TxError;
use crate::types::CallEnvelope;

/// Spec §7 step 7, for `Call`: an absent envelope is fine, a present one must fit `max`, the
/// ledger's `max_call_envelope_bytes` (default [`crate::types::MAX_CALL_ENVELOPE_BYTES`]).
pub(super) fn validate(envelope: &Option<CallEnvelope>, max: usize) -> Result<(), TxError> {
    match envelope {
        Some(e) if e.len() > max => Err(TxError::EnvelopeTooLarge),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MAX_CALL_ENVELOPE_BYTES;

    fn envelope(body: usize) -> Option<CallEnvelope> {
        // The real shapes: an ML-KEM-768 ciphertext and two nonce + 32-byte key + tag wraps.
        Some(CallEnvelope { kem_ct: vec![1; 1088], to_sender: vec![2; 60], to_auditor: vec![3; 60], body: vec![4; body] })
    }

    #[test]
    fn the_cap_is_the_only_rule() {
        let max = MAX_CALL_ENVELOPE_BYTES;
        assert_eq!(validate(&None, max), Ok(()));
        assert_eq!(validate(&envelope(0), max), Ok(()));
        let fits = MAX_CALL_ENVELOPE_BYTES - (1088 + 60 + 60);
        assert_eq!(validate(&envelope(fits), max), Ok(()), "exactly at the cap is accepted");
        assert_eq!(validate(&envelope(fits + 1), max), Err(TxError::EnvelopeTooLarge));
    }

    /// The cap is the caller's (the ledger's `max_call_envelope_bytes`), not the constant.
    #[test]
    fn the_cap_is_a_parameter() {
        let fits = MAX_CALL_ENVELOPE_BYTES - (1088 + 60 + 60);
        assert_eq!(validate(&envelope(fits + 1), 65_536), Ok(()));
        assert_eq!(validate(&envelope(65_536 - 1208), 65_536), Ok(()));
        assert_eq!(validate(&envelope(65_536 - 1207), 65_536), Err(TxError::EnvelopeTooLarge));
        assert_eq!(validate(&envelope(0), 1207), Err(TxError::EnvelopeTooLarge), "a lower cap bites too");
        assert_eq!(validate(&None, 0), Ok(()), "an absent envelope is always fine");
    }
}
