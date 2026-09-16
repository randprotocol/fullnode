//! The receiver registry (spec §6.1–§6.3): consensus state, keyed by receiver id.
use super::{Ledger, TxError};
use crate::crypto::{merkle_root, Hash};
use crate::notes::{word8_to_bytes, Word8};
use crate::receiver::{ReceiverId, ReceiverRecord};
use std::collections::BTreeMap;

/// The registry's component of the state root (spec §6.1): a merkle root over one leaf per
/// receiver id, each leaf binding the id, the record's version, its `pk` and its KEM key.
/// `Ledger::state_root` appends this unconditionally — the registry has no genesis gate, so it
/// is empty rather than absent on a chain that has registered none.
pub fn receivers_root(m: &BTreeMap<ReceiverId, ReceiverRecord>) -> Hash {
    let leaves: Vec<Hash> = m
        .iter()
        .map(|(id, r)| {
            let mut buf = Vec::with_capacity(32 + 4 + 32 + r.kem_ek.len());
            buf.extend_from_slice(&id.0);
            buf.extend_from_slice(&r.version.to_be_bytes());
            buf.extend_from_slice(&word8_to_bytes(&r.pk));
            buf.extend_from_slice(&r.kem_ek);
            Hash::digest_domain(b"rand-receiver-leaf-1", &buf)
        })
        .collect();
    merkle_root(&leaves)
}

impl Ledger {
    pub fn receivers(&self) -> &BTreeMap<ReceiverId, ReceiverRecord> {
        &self.receivers
    }
    pub fn set_receivers(&mut self, m: BTreeMap<ReceiverId, ReceiverRecord>) {
        self.receivers = m;
    }
    pub fn resolve_record(&self, id: &ReceiverId) -> Option<&ReceiverRecord> {
        self.receivers.get(id)
    }
    pub fn resolve_pk(&self, id: &ReceiverId) -> Option<Word8> {
        self.receivers.get(id).map(|r| r.pk)
    }

    /// Spec §6.2: the record verifies under the id it names, for this chain; a first
    /// registration is version 1; a later one is exactly `current + 1` with the same `pk`.
    pub(crate) fn validate_register_receiver(&self, record: &ReceiverRecord) -> Result<(), TxError> {
        let id = record.id();
        record.verify(&id, self.chain_id()).map_err(TxError::Receiver)?;
        match self.receivers.get(&id) {
            None if record.version != 1 => {
                Err(TxError::ReceiverVersion { expected: 1, actual: record.version })
            }
            None => Ok(()),
            Some(cur) if record.version != cur.version + 1 => {
                Err(TxError::ReceiverVersion { expected: cur.version + 1, actual: record.version })
            }
            Some(cur) if record.pk != cur.pk => Err(TxError::ReceiverPkChanged),
            Some(_) => Ok(()),
        }
    }
    pub(crate) fn apply_register_receiver(&mut self, record: &ReceiverRecord) {
        self.receivers.insert(record.id(), record.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::notes::KEM_EK_BYTES;
    use crate::receiver::{receiver_signing_keypair, RecordError, ReceiverId, ReceiverRecord};
    use crate::types::{Action, Transaction};

    fn ledger() -> Ledger {
        // The same fixture `ledger/mod.rs`'s tests build: chain 7, two validators, faucet on.
        crate::ledger::test_fixtures::ledger_with_validators(7)
    }
    fn record(seed: u8, version: u32, chain: u64) -> (ReceiverRecord, ReceiverId) {
        let k = receiver_signing_keypair(&[seed; 32]);
        (
            ReceiverRecord::sign(&k, chain, version, [seed as u32; 8], vec![seed; KEM_EK_BYTES]),
            ReceiverId::from(k.public_key()),
        )
    }
    fn tx_with(l: &Ledger, action: Action) -> Transaction {
        crate::ledger::test_fixtures::bundle_tx(l, action) // a valid stub bundle at the base fee
    }

    #[test]
    fn a_first_record_registers_and_the_state_root_moves() {
        let mut l = ledger();
        let before = l.state_root();
        let (rec, id) = record(1, 1, 7);
        let tx = tx_with(&l, Action::RegisterReceiver { record: rec.clone() });
        l.validate(&tx, &StubExecutor).unwrap();
        l.apply_tx(&tx, &crate::ledger::test_fixtures::proposer(&l), &StubExecutor).unwrap();
        assert_eq!(l.receivers().get(&id), Some(&rec));
        assert_eq!(l.resolve_pk(&id), Some(rec.pk));
        assert_ne!(l.state_root(), before, "the registry is in the state root");
    }

    #[test]
    fn versions_must_step_by_one_and_pk_may_not_change() {
        let mut l = ledger();
        let (v1, id) = record(1, 1, 7);
        let p = crate::ledger::test_fixtures::proposer(&l);
        l.apply_tx(&tx_with(&l, Action::RegisterReceiver { record: v1.clone() }), &p, &StubExecutor).unwrap();
        // replay of v1: refused
        match l.validate(&tx_with(&l, Action::RegisterReceiver { record: v1.clone() }), &StubExecutor) {
            Err(TxError::ReceiverVersion { expected: 2, actual: 1 }) => {}
            other => panic!("{other:?}"),
        }
        // v3 skips: refused
        let k = receiver_signing_keypair(&[1; 32]);
        let v3 = ReceiverRecord::sign(&k, 7, 3, v1.pk, vec![2; KEM_EK_BYTES]);
        assert!(matches!(
            l.validate(&tx_with(&l, Action::RegisterReceiver { record: v3 }), &StubExecutor),
            Err(TxError::ReceiverVersion { expected: 2, actual: 3 })
        ));
        // v2 with a changed pk: refused
        let bad = ReceiverRecord::sign(&k, 7, 2, [9; 8], vec![2; KEM_EK_BYTES]);
        assert!(matches!(
            l.validate(&tx_with(&l, Action::RegisterReceiver { record: bad }), &StubExecutor),
            Err(TxError::ReceiverPkChanged)
        ));
        // v2 rotation: applies, and the registry holds the new key
        let v2 = ReceiverRecord::sign(&k, 7, 2, v1.pk, vec![2; KEM_EK_BYTES]);
        l.apply_tx(&tx_with(&l, Action::RegisterReceiver { record: v2.clone() }), &p, &StubExecutor).unwrap();
        assert_eq!(l.receivers()[&id].kem_ek, vec![2; KEM_EK_BYTES]);
        // a first registration must be version 1
        let (v5, _) = record(2, 5, 7);
        assert!(matches!(
            l.validate(&tx_with(&l, Action::RegisterReceiver { record: v5 }), &StubExecutor),
            Err(TxError::ReceiverVersion { expected: 1, actual: 5 })
        ));
    }

    #[test]
    fn a_record_for_another_chain_or_with_a_bad_signature_is_refused_by_name() {
        let l = ledger();
        let (other_chain, _) = record(1, 1, 8);
        assert!(matches!(
            l.validate(&tx_with(&l, Action::RegisterReceiver { record: other_chain }), &StubExecutor),
            Err(TxError::Receiver(RecordError::BadSignature))
        ));
        let (mut rec, _) = record(1, 1, 7);
        rec.kem_ek = vec![1; 10];
        assert!(matches!(
            l.validate(&tx_with(&l, Action::RegisterReceiver { record: rec }), &StubExecutor),
            Err(TxError::Receiver(RecordError::KemLength(10)))
        ));
    }

    #[test]
    fn the_root_is_a_merkle_over_id_version_pk_kem_leaves() {
        let (a, ida) = record(1, 1, 7);
        let (b, idb) = record(2, 1, 7);
        let m: BTreeMap<_, _> = [(ida, a.clone()), (idb, b.clone())].into_iter().collect();
        let leaf = |id: &ReceiverId, r: &ReceiverRecord| {
            let mut buf = id.0.to_vec();
            buf.extend_from_slice(&r.version.to_be_bytes());
            buf.extend_from_slice(&crate::notes::word8_to_bytes(&r.pk));
            buf.extend_from_slice(&r.kem_ek);
            crate::crypto::Hash::digest_domain(b"rand-receiver-leaf-1", &buf)
        };
        // The leaves are in the `BTreeMap`'s own (ascending id) order, not insertion order —
        // `ida` need not sort before `idb` (it does not, for these two seeds), and the root is a
        // merkle tree, so leaf order matters. `m.iter()` is the one source of truth for it.
        let leaves: Vec<_> = m.iter().map(|(id, r)| leaf(id, r)).collect();
        assert_eq!(receivers_root(&m), crate::crypto::merkle_root(&leaves));
        assert_eq!(receivers_root(&BTreeMap::new()), crate::crypto::merkle_root(&[]));
    }
}
