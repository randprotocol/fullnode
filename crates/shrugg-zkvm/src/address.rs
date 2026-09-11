//! Bridges the vendored note layer (`notes`, `viewing`) and the node's pure data types.
//!
//! `shrugg-core` deliberately knows no field arithmetic and no AEAD: its `ShieldedAddress`,
//! `Envelope` and `BundleDigestInput` are plain serialisable records with the same shape as the
//! research crate's `viewing::Address`, `viewing::Envelope` and `notes::bundle_digest`'s
//! argument list. This module is the one place the two representations meet, so that the
//! vendored files stay byte-identical to upstream across a `deploy/sync-zkvm.sh` resync and
//! nothing node-specific has to be hand-patched into them.

use crate::notes::{Note, ViewingKey};
use crate::viewing::{self, TxKey};
use shrugg_core::notes::{BundleDigestInput, Envelope, ShieldedAddress, Word8};

/// The address a party publishes: its note-owner field `pk` plus the ML-KEM-768 encapsulation
/// key envelopes are sealed to. Both are derived from the viewing key alone — holding it is
/// enough to compute the address, and never enough to spend (`notes::SpendKey`).
pub fn address_of(vk: &ViewingKey) -> ShieldedAddress {
    let a = vk.address();
    ShieldedAddress { pk: a.pk, kem_ek: a.kem_ek }
}

pub fn to_research(a: &ShieldedAddress) -> viewing::Address {
    viewing::Address { pk: a.pk, kem_ek: a.kem_ek.clone() }
}

pub fn envelope_to_core(e: &viewing::Envelope) -> Envelope {
    Envelope {
        kem_ct: e.kem_ct.clone(),
        to_receiver: e.to_receiver.clone(),
        to_sender: e.to_sender.clone(),
        body: e.body.clone(),
    }
}

pub fn envelope_from_core(e: &Envelope) -> viewing::Envelope {
    viewing::Envelope {
        kem_ct: e.kem_ct.clone(),
        to_receiver: e.to_receiver.clone(),
        to_sender: e.to_sender.clone(),
        body: e.body.clone(),
    }
}

/// Seals `note` to `to`, with a copy of `tx_key` wrapped under `sender`'s outgoing viewing key.
/// `tx_key` must be fresh per envelope — see `viewing::TxKey`'s doc comment for why that
/// obligation is the wallet's and cannot be enforced here.
pub fn seal_note(sender: &ViewingKey, to: &ShieldedAddress, note: &Note, tx_key: &TxKey) -> Envelope {
    envelope_to_core(&viewing::Envelope::seal(sender, &to_research(to), note, tx_key))
}

/// The public preimage of a bundle digest, in spec field order — the argument list
/// `notes::bundle_digest` takes, packaged as the record `shrugg-core` passes around.
#[allow(clippy::too_many_arguments)]
pub fn digest_input_of(
    anchor: Word8,
    nullifiers: [Word8; 2],
    commitments: [Word8; 2],
    fee: u64,
    burn: u64,
    asset: u32,
    time: u32,
) -> BundleDigestInput {
    BundleDigestInput { anchor, nullifiers, commitments, fee, burn, asset, time }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notes::SpendKey;

    #[test]
    fn address_and_envelope_roundtrip_through_the_core_types() {
        let vk = SpendKey::random().viewing_key();
        let a = address_of(&vk);
        assert_eq!(a.pk, vk.pk());
        assert_eq!(a.kem_ek.len(), shrugg_core::notes::KEM_EK_BYTES);
        assert_eq!(to_research(&a), vk.address());
        // The text form parses back to the same address, so a wallet can hand one out as a string.
        assert_eq!(shrugg_core::notes::ShieldedAddress::parse(&a.to_string()).unwrap(), a);

        let note = Note::new(vk.pk(), vk.pk(), 7, 0, 3);
        let key = TxKey::random();
        let sealed = seal_note(&vk, &a, &note, &key);
        let research = envelope_from_core(&sealed);
        assert_eq!(envelope_to_core(&research), sealed);
        assert_eq!(research.open_as_receiver(note.commitment(), &vk).map(|(_, n)| n), Some(note));
        assert_eq!(research.open_with_tx_key(note.commitment(), &key), Some(note));
    }
}
