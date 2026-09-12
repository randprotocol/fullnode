//! Field structs and signing messages the staking (phase S2) and bridge/call-envelope
//! (phase S3) actions carry.
//!
//! Nothing here is interpreted by the ledger yet: phase S2/S3 Task 0 adds the shapes and the
//! signing messages so both phases can be implemented in parallel against one wire format.
//! The variants that use them are rejected with [`crate::ledger::TxError::UnsupportedAction`]
//! until their phase lands.

use crate::crypto::{Address, Hash, PublicKey, Signature};
use crate::notes::{Envelope, ShieldedAddress, Word8};
use serde::{Deserialize, Serialize};

/// Largest call-input envelope accepted in a `Call` transaction (spec §6.1).
///
/// A call's private input vector is capped at 4096 words, so the sealed body is at most
/// 16 KiB of plaintext plus a 12-byte nonce, a 16-byte salt and a 16-byte Poly1305 tag; the
/// key-wrapping parts (`kem_ct`, `to_sender`, `to_auditor`) add an ML-KEM-768 ciphertext and
/// two 48-byte wraps. 17 000 bytes leaves room for all of it and nothing beyond.
pub const MAX_CALL_ENVELOPE_BYTES: usize = 17_000;

/// A validator's first appearance in the register (spec §8): the Dilithium2 key that signs its
/// later staking actions and the shielded address its rewards are paid to. `signature` is over
/// [`registration_message`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub public_key: PublicKey,
    pub payout: ShieldedAddress,
    pub signature: Signature,
}

/// The encrypted transcript of a confidential call's private inputs (spec §6.1).
///
/// The chain checks nothing about the ciphertext — exactly as with a note [`Envelope`] — only
/// that it is no larger than [`MAX_CALL_ENVELOPE_BYTES`]. Binding to the call comes from the
/// proof's public input commitment `H_IN`, which the sealing uses as AEAD associated data:
/// an envelope that does not belong to this call simply fails to open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallEnvelope {
    /// ML-KEM-768 ciphertext sealing the per-call key to the auditor; empty when there is none.
    pub kem_ct: Vec<u8>,
    /// The per-call key wrapped under the caller's outgoing viewing key.
    pub to_sender: Vec<u8>,
    /// The per-call key wrapped under the auditor's KEM shared secret; empty when there is none.
    pub to_auditor: Vec<u8>,
    /// The inputs themselves, sealed under the per-call key with `H_IN` as associated data.
    pub body: Vec<u8>,
}

impl CallEnvelope {
    /// Total wire size of the four parts.
    pub fn len(&self) -> usize {
        self.kem_ct.len() + self.to_sender.len() + self.to_auditor.len() + self.body.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a validator signs to claim an address in the register: the chain and the payout
/// address. The key itself is not in the message — it is what verifies the signature, so a
/// valid signature already proves possession of `registration.public_key`.
///
/// The message therefore binds chain and payout only; what binds the registration to the
/// address it is claiming is a separate rule the message cannot carry: the enclosing
/// `Action::Bond`'s `validator` field must equal `registration.public_key.address()`, and
/// S2's validation asserts it. Without that check a bond could register one key's payout
/// under another key's address.
pub fn registration_message(chain_id: u64, payout: &ShieldedAddress) -> Hash {
    let bytes = bincode::serialize(&(chain_id, payout)).expect("serializes");
    Hash::digest_domain(b"shrugg-register", &bytes)
}

/// What a validator signs to move stake into unbonding. The register's `nonce` is the replay
/// protection: there are no accounts on this chain to carry one.
pub fn unbond_message(chain_id: u64, validator: &Address, amount: u64, nonce: u64) -> Hash {
    let bytes = bincode::serialize(&(chain_id, validator, amount, nonce)).expect("serializes");
    Hash::digest_domain(b"shrugg-unbond", &bytes)
}

/// What a validator signs to withdraw released stake and rewards into a deposit note. The
/// blinding `r`, the note's `time` and the envelope are in the message so the note the ledger
/// computes is the note the validator asked for — and, since the envelope is sealed against that
/// exact note, the one the payout wallet can open.
#[allow(clippy::too_many_arguments)]
pub fn withdraw_message(
    chain_id: u64,
    validator: &Address,
    amount: u64,
    nonce: u64,
    time: u32,
    r: &Word8,
    envelope: &Envelope,
) -> Hash {
    let bytes = bincode::serialize(&(chain_id, validator, amount, nonce, time, r, envelope)).expect("serializes");
    Hash::digest_domain(b"shrugg-withdraw", &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn addr() -> ShieldedAddress {
        ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] }
    }

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] }
    }

    #[test]
    fn call_envelopes_roundtrip_and_measure_their_four_parts() {
        let e = CallEnvelope { kem_ct: vec![1; 1088], to_sender: vec![2; 48], to_auditor: vec![3; 48], body: vec![4; 100] };
        assert_eq!(e.len(), 1088 + 48 + 48 + 100);
        assert!(!e.is_empty());
        let back: CallEnvelope = bincode::deserialize(&bincode::serialize(&e).unwrap()).unwrap();
        assert_eq!(back, e);
        let empty = CallEnvelope { kem_ct: vec![], to_sender: vec![], to_auditor: vec![], body: vec![] };
        assert!(empty.is_empty());
    }

    #[test]
    fn registrations_roundtrip() {
        let k = Keypair::from_seed([9; 32]).unwrap();
        let payout = addr();
        let r = Registration {
            public_key: k.public_key().clone(),
            payout: payout.clone(),
            signature: k.sign(registration_message(7, &payout).as_bytes()),
        };
        let back: Registration = bincode::deserialize(&bincode::serialize(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        assert!(r.public_key.verify(registration_message(7, &payout).as_bytes(), &r.signature));
        assert!(!r.public_key.verify(registration_message(8, &payout).as_bytes(), &r.signature));
    }

    /// Every field of every staking message is bound, and the three domains never collide.
    #[test]
    fn signing_messages_bind_every_field_under_distinct_domains() {
        let v = Address([1; 32]);
        let w = Address([2; 32]);
        let base = unbond_message(7, &v, 5, 1);
        for other in [unbond_message(8, &v, 5, 1), unbond_message(7, &w, 5, 1), unbond_message(7, &v, 6, 1), unbond_message(7, &v, 5, 2)] {
            assert_ne!(other, base);
        }
        let wbase = withdraw_message(7, &v, 5, 1, 9, &[3; 8], &env());
        for other in [
            withdraw_message(8, &v, 5, 1, 9, &[3; 8], &env()),
            withdraw_message(7, &w, 5, 1, 9, &[3; 8], &env()),
            withdraw_message(7, &v, 6, 1, 9, &[3; 8], &env()),
            withdraw_message(7, &v, 5, 2, 9, &[3; 8], &env()),
            withdraw_message(7, &v, 5, 1, 10, &[3; 8], &env()),
            withdraw_message(7, &v, 5, 1, 9, &[4; 8], &env()),
            withdraw_message(7, &v, 5, 1, 9, &[3; 8], &Envelope { body: vec![9], ..env() }),
        ] {
            assert_ne!(other, wbase);
        }
        let mut other_payout = addr();
        other_payout.pk = [5; 8];
        assert_ne!(registration_message(7, &addr()), registration_message(7, &other_payout));
        assert_ne!(registration_message(7, &addr()), registration_message(8, &addr()));
        // Different domains, so no message of one kind is ever a message of another.
        assert_ne!(base.to_hex(), wbase.to_hex());
    }
}
