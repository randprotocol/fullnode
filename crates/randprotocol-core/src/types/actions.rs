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
/// The arithmetic, for the largest envelope the format can produce — a 4096-word input vector
/// (the spec's cap) sealed for both the caller and an auditor:
///
/// | part | bytes |
/// |---|---|
/// | `body` = nonce 12 + salt 16 + inputs 4 × 4096 + Poly1305 tag 16 | 16 428 |
/// | `kem_ct`, an ML-KEM-768 ciphertext | 1 088 |
/// | `to_sender` = nonce 12 + key 32 + tag 16 | 60 |
/// | `to_auditor`, the same shape | 60 |
/// | **total** | **17 636** |
///
/// 18 432 bytes (18 KiB) is the next round number above that: it admits every envelope an
/// honest wallet can build and nothing appreciably beyond. (An earlier 17 000 came from
/// costing the two key wraps at 48 bytes, which forgot their 12-byte nonces and would have
/// refused a fully-loaded audited call.)
pub const MAX_CALL_ENVELOPE_BYTES: usize = 18_432;

/// A validator's first appearance in the register (spec §8): the Dilithium2 key that signs its
/// later staking actions and the shielded address its rewards are paid to. `signature` is over
/// [`registration_message`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub public_key: PublicKey,
    pub payout: ShieldedAddress,
    pub signature: Signature,
}

impl Registration {
    /// The blob a validator hands its bonder: `rand-node register` prints it as hex and
    /// `rand bond --registration` reads it back. Bincode, like [`Transaction::encode`] — a
    /// registration travels inside an `Action`, so nothing hashes this form and the two ends
    /// only have to agree with each other.
    ///
    /// [`Transaction::encode`]: crate::Transaction::encode
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Registration serializes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Registration, bincode::Error> {
        bincode::deserialize(bytes)
    }
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
    #[serde(with = "crate::crypto::wire_bytes")]
    pub kem_ct: Vec<u8>,
    /// The per-call key wrapped under the caller's outgoing viewing key.
    #[serde(with = "crate::crypto::wire_bytes")]
    pub to_sender: Vec<u8>,
    /// The per-call key wrapped under the auditor's KEM shared secret; empty when there is none.
    #[serde(with = "crate::crypto::wire_bytes")]
    pub to_auditor: Vec<u8>,
    /// The inputs themselves, sealed under the per-call key with `H_IN` as associated data.
    #[serde(with = "crate::crypto::wire_bytes")]
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

/// The supply an [`Action::RegisterToken`] creates in the same transaction that registers the
/// token (the RPL token standard, spec §4): a public `amount` of the brand-new asset, as one
/// note the *chain* computes — `note_commitment(recipient.pk, MINT_FROM, amount, index, time, r)`
/// — exactly as a bridge deposit is computed, so the creator cannot mint a note for an amount or
/// an owner the registration does not declare.
///
/// `time` is the note's own `time` word and not the height the registration is applied at, for
/// [`Action::BridgeAttest`]'s reason: the creator seals `envelope` against this note before
/// submitting, and cannot predict which block will take it. Admission holds it to the window a
/// bundle's `time` gets.
///
/// **The whole of this struct is part of the token's [`AssetId`]** (`ledger::tokens::
/// native_asset_id`'s `initial`), not just `amount`: a `RegisterToken` carries no signature, and
/// while the transaction binding keeps the creator's fee bundle from riding a copy, an observer can
/// pay for a copy with a fee bundle of its own — so it could otherwise copy a gossiped registration
/// with `recipient` swapped and take both the identity and the whole initial supply. With all
/// five fields in the id, a redirected copy is a different token (spec §3, amended 2026-09-19).
///
/// [`Action::RegisterToken`]: crate::types::Action::RegisterToken
/// [`Action::BridgeAttest`]: crate::types::Action::BridgeAttest
/// [`AssetId`]: crate::bridge::AssetId
/// [`MINT_FROM`]: crate::ledger::tokens::MINT_FROM
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialMint {
    pub amount: u64,
    pub recipient: ShieldedAddress,
    pub r: Word8,
    pub time: u32,
    pub envelope: Envelope,
}

/// What a `Key` mint authority signs to mint `amount` of its token (the RPL token standard,
/// spec §4): the chain, the token's [`AssetId`], the register's `mint_nonce`, the amount, the
/// commitment of the note the chain is about to append, and the digest of the envelope that
/// opens it.
///
/// The commitment stands in for the note's other four words — the recipient's `pk`, the asset
/// index, the `time` and the blinding `r` — because it *is* their hash: a signature over it is a
/// signature over exactly the leaf the ledger will create, and nothing about that leaf can be
/// changed without changing it. The asset id rather than the index: an index is this chain's
/// dense numbering, while the id is the token's identity, so a mint signed for one token is
/// never a mint for another chain's token that happens to sit at the same index.
///
/// **The envelope is in the message too** (amended 2026-09-19 after Task 4's review), as
/// `blake3(bincode(envelope))`: the commitment binds the note but not the ciphertext that opens
/// it, so without this a third party could lift a gossiped mint, re-wrap it with a garbage
/// envelope and spend the authority's nonce on a note whose recipient would have to rebuild it
/// from the public fields to find it. It is hashed rather than inlined because an envelope is
/// kilobytes and this message is hashed on every admission.
///
/// [`AssetId`]: crate::bridge::AssetId
pub fn token_mint_message(
    chain_id: u64,
    asset_id: &crate::bridge::AssetId,
    nonce: u64,
    amount: u64,
    cm: &Word8,
    envelope: &Envelope,
) -> Hash {
    let bytes = bincode::serialize(&(chain_id, asset_id, nonce, amount, cm, envelope_digest(envelope)))
        .expect("serializes");
    Hash::digest_domain(b"rand-rpl-mint-1", &bytes)
}

/// `blake3(bincode(envelope))` — the envelope as [`token_mint_message`] binds it. Its own
/// function so the signer and the verifier cannot compute it two ways, and public so a wallet
/// can pre-compute what it is about to sign.
pub fn envelope_digest(envelope: &Envelope) -> Hash {
    Hash::digest(&bincode::serialize(envelope).expect("an envelope serializes"))
}

/// What a `Key` mint authority signs to hand its token to another key — or to no key at all,
/// which retires minting for good ([`token_mint_message`]'s twin, one action over).
///
/// `new` is in the message as the `Option` it is, so a rotation to a key and a renunciation are
/// never the same message; the nonce is the same per-token counter a mint spends, so neither
/// can be replayed after the other.
pub fn set_authority_message(
    chain_id: u64,
    asset_id: &crate::bridge::AssetId,
    nonce: u64,
    new: &Option<PublicKey>,
) -> Hash {
    let bytes = bincode::serialize(&(chain_id, asset_id, nonce, new)).expect("serializes");
    Hash::digest_domain(b"rand-rpl-authority-1", &bytes)
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
    Hash::digest_domain(b"rand-register", &bytes)
}

/// The registration message under a `staking` section's `registration_v2` (the v4 re-review's
/// "proof of possession"). The v1 message binds the chain id and the payout; the key's
/// signature already proves possession of the key, but nothing tied that proof to *this* chain
/// rather than any chain sharing its id, nor named the address the bond registers. This one
/// binds the genesis hash (the pattern of the consensus domain's v1 tags, `SigningDomain`) and
/// the validator's address beside them, under its own tag, so a v1 signature never verifies as
/// a v2 one and a v2 one verifies on exactly one chain.
pub fn registration_message_v2(genesis: &Hash, chain_id: u64, validator: &Address, payout: &ShieldedAddress) -> Hash {
    let bytes = bincode::serialize(&(genesis, chain_id, validator, payout)).expect("serializes");
    Hash::digest_domain(b"rand-register-2", &bytes)
}

/// What a validator signs to move stake into unbonding. The register's `nonce` is the replay
/// protection: there are no accounts on this chain to carry one.
pub fn unbond_message(chain_id: u64, validator: &Address, amount: u64, nonce: u64) -> Hash {
    let bytes = bincode::serialize(&(chain_id, validator, amount, nonce)).expect("serializes");
    Hash::digest_domain(b"rand-unbond", &bytes)
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
    Hash::digest_domain(b"rand-withdraw", &bytes)
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
        // The wire form the node prints and a wallet's `--registration` reads back.
        assert_eq!(Registration::decode(&r.encode()).unwrap(), r);
        assert!(Registration::decode(b"not a registration").is_err());
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

    /// The two RPL signing messages (spec §4): each binds the chain, the token's asset id, the
    /// mint nonce and its own body, and the two domains never collide — a mint signature is
    /// never a rotation signature, on this chain or another.
    #[test]
    fn the_token_messages_bind_the_chain_the_asset_the_nonce_and_their_body() {
        let a = Hash([1; 32]);
        let b = Hash([2; 32]);
        let pk = Keypair::from_seed([5; 32]).unwrap().public_key().clone();
        let other = Keypair::from_seed([6; 32]).unwrap().public_key().clone();

        // The envelope is in the message because the commitment is not over it: without this a
        // third party could re-wrap a gossiped mint with a garbage envelope and spend the
        // authority's nonce (spec §4, amended 2026-09-19). Every part of it is bound.
        let m = token_mint_message(7, &a, 1, 500, &[3; 8], &env());
        for x in [
            token_mint_message(8, &a, 1, 500, &[3; 8], &env()),
            token_mint_message(7, &b, 1, 500, &[3; 8], &env()),
            token_mint_message(7, &a, 2, 500, &[3; 8], &env()),
            token_mint_message(7, &a, 1, 501, &[3; 8], &env()),
            token_mint_message(7, &a, 1, 500, &[4; 8], &env()),
            token_mint_message(7, &a, 1, 500, &[3; 8], &Envelope { body: vec![9], ..env() }),
            token_mint_message(7, &a, 1, 500, &[3; 8], &Envelope { kem_ct: vec![9], ..env() }),
            token_mint_message(7, &a, 1, 500, &[3; 8], &Envelope { to_receiver: vec![9], ..env() }),
            token_mint_message(7, &a, 1, 500, &[3; 8], &Envelope { to_sender: vec![9], ..env() }),
        ] {
            assert_ne!(x, m);
        }

        let s = set_authority_message(7, &a, 1, &Some(pk.clone()));
        for x in [
            set_authority_message(8, &a, 1, &Some(pk.clone())),
            set_authority_message(7, &b, 1, &Some(pk.clone())),
            set_authority_message(7, &a, 2, &Some(pk.clone())),
            set_authority_message(7, &a, 1, &Some(other)),
            set_authority_message(7, &a, 1, &None),
        ] {
            assert_ne!(x, s);
        }
        assert_ne!(m, s, "distinct domains");
    }
}

// ── block aggregation: the aggregator register's signed forms (spec §2–§3) ──────────────────

/// An aggregator's first appearance in the register (spec §2.2): the Dilithium2 key that signs
/// its later aggregation actions and the shielded address its subsidy, proving shares and bond
/// are paid to. `signature` is over [`aggregator_register_message`]. The [`Registration`] twin,
/// one role over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorRegistration {
    pub public_key: PublicKey,
    pub payout: ShieldedAddress,
    pub signature: Signature,
}

/// One signed header of a slash's evidence pair (spec §2.2): two of these with the same
/// `(aggregator, nonce)` and different content are the equivocation `Action::SlashAggregator`
/// proves. Carried boxed so a slash transaction's size stays bounded by two headers rather than
/// by any list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAggregateHeader {
    pub aggregator: Address,
    pub nonce: u64,
    pub time: u32,
    pub r: Word8,
    pub covers: Vec<crate::crypto::Hash>,
    pub proof_hash: crate::crypto::Hash,
    pub signature: Signature,
}

/// What an aggregator signs to claim an address in the register: the chain and the payout —
/// [`registration_message`]'s exact construction, one role over. As there, the enclosing
/// action's `aggregator` field must equal `registration.public_key.address()`, so one key's
/// payout cannot be registered under another key's address.
pub fn aggregator_register_message(chain_id: u64, payout: &ShieldedAddress) -> crate::crypto::Hash {
    let bytes = bincode::serialize(&(chain_id, payout)).expect("serializes");
    crate::crypto::Hash::digest_domain(b"rand-aggregator-register", &bytes)
}

/// What an aggregator signs to stop submitting and start the unbonding window: the register's
/// `nonce` is the replay protection — [`unbond_message`]'s, one role over.
pub fn aggregator_unbond_message(chain_id: u64, aggregator: &Address, nonce: u64) -> crate::crypto::Hash {
    let bytes = bincode::serialize(&(chain_id, aggregator, nonce)).expect("serializes");
    crate::crypto::Hash::digest_domain(b"rand-aggregator-unbond", &bytes)
}

/// What an aggregator signs to withdraw its released bond into a deposit note: `r`, the note's
/// `time` and the envelope are in the message so the note the ledger computes is the note the
/// aggregator asked for — [`withdraw_message`]'s, one role over.
pub fn aggregator_withdraw_message(
    chain_id: u64,
    aggregator: &Address,
    nonce: u64,
    time: u32,
    r: &Word8,
    envelope: &Envelope,
) -> crate::crypto::Hash {
    let bytes = bincode::serialize(&(chain_id, aggregator, nonce, time, r, envelope)).expect("serializes");
    crate::crypto::Hash::digest_domain(b"rand-aggregator-withdraw", &bytes)
}

/// The aggregate binding (audit v3, AGG-2): `H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖
/// nonce)` as eight little-endian `u32` words — [`crate::Transaction::binding`]'s word layout. The
/// rVM's aggregate program absorbs these words into its interface digest, so a proof made under
/// one `(chain, aggregator, nonce)` verifies under no other: an aggregate re-signed by another
/// registered aggregator, or replayed at a later nonce, is refused. The prover passes its own
/// triple; admission recomputes it from the transaction, never from the proof.
pub fn aggregate_binding(chain_id: u64, aggregator: &crate::crypto::Address, nonce: u64) -> [u32; 8] {
    let bytes = bincode::serialize(&(chain_id, aggregator, nonce)).expect("serializes");
    let digest = crate::crypto::Hash::digest_domain(b"rand-aggregate-bind-1", &bytes);
    std::array::from_fn(|i| u32::from_le_bytes(digest.0[4 * i..4 * i + 4].try_into().expect("four bytes")))
}

/// What an aggregator signs over an `Aggregate` submission (spec §3.1): the chain, the register
/// nonce, the payout note's `time` and blinding `r`, the cover set, and the proof's hash — the
/// full content an equivocating pair of `SignedAggregateHeader`s is evidence of.
pub fn aggregate_signing_hash(
    chain_id: u64,
    nonce: u64,
    time: u32,
    r: &Word8,
    covers: &[crate::crypto::Hash],
    proof_hash: &crate::crypto::Hash,
) -> crate::crypto::Hash {
    let bytes = bincode::serialize(&(chain_id, nonce, time, r, covers, proof_hash)).expect("serializes");
    crate::crypto::Hash::digest_domain(b"rand-aggregate", &bytes)
}
