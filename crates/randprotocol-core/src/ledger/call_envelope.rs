//! The call-input envelope a `Call` may carry (spec §6.1).
//!
//! This module is the whole chain-side rule, and it is deliberately tiny: the ledger checks the
//! envelope's size and nothing else. The ciphertext is not bound to the call by consensus but
//! by the AEAD — the sealing uses the proof's public input commitment `H_IN` as associated
//! data, so an envelope that does not belong to this call simply fails to open for everyone.
//! Checking more here would cost every node work that buys no security.
//!
//! S3's Task 1 adds the storage half (the envelope travels with the call receipt); the size
//! cap below is final.

use super::TxError;
use crate::types::{CallEnvelope, MAX_CALL_ENVELOPE_BYTES};

/// Spec §7 step 7, for `Call`: an absent envelope is fine, a present one must fit the cap.
pub(super) fn validate(envelope: &Option<CallEnvelope>) -> Result<(), TxError> {
    match envelope {
        Some(e) if e.len() > MAX_CALL_ENVELOPE_BYTES => Err(TxError::EnvelopeTooLarge),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(body: usize) -> Option<CallEnvelope> {
        // The real shapes: an ML-KEM-768 ciphertext and two nonce + 32-byte key + tag wraps.
        Some(CallEnvelope { kem_ct: vec![1; 1088], to_sender: vec![2; 60], to_auditor: vec![3; 60], body: vec![4; body] })
    }

    #[test]
    fn the_cap_is_the_only_rule() {
        assert_eq!(validate(&None), Ok(()));
        assert_eq!(validate(&envelope(0)), Ok(()));
        let fits = MAX_CALL_ENVELOPE_BYTES - (1088 + 60 + 60);
        assert_eq!(validate(&envelope(fits)), Ok(()), "exactly at the cap is accepted");
        assert_eq!(validate(&envelope(fits + 1)), Err(TxError::EnvelopeTooLarge));
    }
}
