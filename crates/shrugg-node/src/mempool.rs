//! Pending transaction pool: validated against the tip ledger and offered to the proposer by
//! fee.
//!
//! A redacted chain has no senders and no nonces, so there is no per-sender ordering left to
//! do: a bundle is admissible or it is not, and two bundles are only related to each other when
//! they touch the same note. What replaces the old nonce bookkeeping is *conflict* tracking —
//! the pool never holds two transactions that spend the same nullifier, create the same
//! commitment, or consume the same bridge attestation digest, because at most one of them could
//! ever be included and carrying the other only wastes the proposer's block space and a
//! (~20 ms) proof verification per gossip round.

use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::ledger::{bridge_notes, TIME_WINDOW};
use shrugg_core::notes::word8_to_hex;
use shrugg_core::{Action, Hash, Ledger, Transaction, TxError, Word8};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum MempoolError {
    #[error("{0}")]
    Invalid(TxError),
    #[error("already in mempool")]
    Duplicate,
    #[error("conflicts with a pending transaction over {}", word8_to_hex(.0))]
    Conflict(Word8),
    /// Two relayers raced the same bridge attestation. Their transactions share no nullifier
    /// and no commitment, so only the digest tells them apart.
    #[error("conflicts with a pending transaction over bridge attestation {0}")]
    AttestationConflict(Hash),
    #[error("mempool full")]
    Full,
}

pub struct Mempool {
    txs: HashMap<Hash, Transaction>,
    /// Which pooled transaction spends each nullifier — one owner per nullifier, always.
    nullifiers: HashMap<Word8, Hash>,
    /// Which pooled transaction creates each commitment (a bundle's two output slots, or a
    /// mint's single note).
    commitments: HashMap<Word8, Hash>,
    /// Which pooled transaction consumes each bridge attestation digest. A digest is spendable
    /// once, like a nullifier, but it is not a field of the transaction — see
    /// `Transaction::bridge_digests`.
    digests: HashMap<Hash, Hash>,
    max_size: usize,
}

impl Mempool {
    pub fn new(max_size: usize) -> Mempool {
        Mempool {
            txs: HashMap::new(),
            nullifiers: HashMap::new(),
            commitments: HashMap::new(),
            digests: HashMap::new(),
            max_size,
        }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.txs.contains_key(hash)
    }

    pub fn get(&self, hash: &Hash) -> Option<&Transaction> {
        self.txs.get(hash)
    }

    /// Validate against `ledger` (the state the next block will build on) and insert.
    ///
    /// Cheap admission decisions come first: `Ledger::validate` clones nothing but does verify
    /// the bundle's STARK, so a duplicate, a conflict or a full pool has to be answered before
    /// paying that cost for every gossiped transaction.
    pub fn insert(
        &mut self,
        tx: Transaction,
        ledger: &Ledger,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Hash, MempoolError> {
        let hash = tx.hash();
        if self.txs.contains_key(&hash) {
            return Err(MempoolError::Duplicate);
        }
        for nf in tx.nullifiers() {
            if self.nullifiers.contains_key(&nf) {
                return Err(MempoolError::Conflict(nf));
            }
        }
        for cm in tx.commitments() {
            if self.commitments.contains_key(&cm) {
                return Err(MempoolError::Conflict(cm));
            }
        }
        for mu in tx.bridge_digests() {
            if self.digests.contains_key(&mu) {
                return Err(MempoolError::AttestationConflict(mu));
            }
        }
        if self.txs.len() >= self.max_size {
            return Err(MempoolError::Full);
        }
        ledger.validate(&tx, executor).map_err(MempoolError::Invalid)?;

        for nf in tx.nullifiers() {
            self.nullifiers.insert(nf, hash);
        }
        for cm in tx.commitments() {
            self.commitments.insert(cm, hash);
        }
        for mu in tx.bridge_digests() {
            self.digests.insert(mu, hash);
        }
        self.txs.insert(hash, tx);
        Ok(hash)
    }

    /// Transactions ready for inclusion on top of `ledger`, highest fee first and ties broken by
    /// hash so every honest proposer building on the same pool picks the same block.
    pub fn candidates(&self, ledger: &Ledger, max: usize) -> Vec<Transaction> {
        self.candidates_within(ledger, max, usize::MAX)
    }

    /// Like `candidates`, but stops before the encoded size of the selection exceeds `max_bytes`.
    ///
    /// Only pool-level re-checks happen here (the ledger may have moved since insertion): a
    /// transaction whose anchor has scrolled out, whose nullifier was spent, or whose commitment
    /// now exists is skipped rather than offered. The proposer's own `apply_transactions` is
    /// still the authority; this only avoids proposing a block that would fail.
    pub fn candidates_within(&self, ledger: &Ledger, max: usize, max_bytes: usize) -> Vec<Transaction> {
        let mut ready: Vec<(&Hash, &Transaction)> =
            self.txs.iter().filter(|(_, tx)| Self::still_applies(tx, ledger)).collect();
        ready.sort_by(|a, b| b.1.fee().cmp(&a.1.fee()).then_with(|| a.0.cmp(b.0)));
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for (_, tx) in ready.into_iter().take(max) {
            let len = tx.encoded_len();
            if bytes + len > max_bytes {
                break;
            }
            bytes += len;
            out.push(tx.clone());
        }
        out
    }

    /// The cheap half of `Ledger::validate` — everything that can go stale between insertion and
    /// the next block, and nothing that costs a proof verification.
    fn still_applies(tx: &Transaction, ledger: &Ledger) -> bool {
        let in_window = |t: u32| {
            let t = t as u64;
            t <= ledger.height() && ledger.height() - t <= TIME_WINDOW
        };
        if let Some(b) = &tx.bundle {
            if !ledger.is_anchor(&b.anchor) || !in_window(b.time) {
                return false;
            }
        }
        // A `BridgeAttest`'s `time` goes stale by the same rule (`Ledger::check_time`), and it is
        // not the bundle's: a transaction whose attestation has aged out would be admitted here
        // and then kill the block it was offered to.
        if let Action::BridgeAttest { attestation, time, asset, .. } = &tx.action {
            if !in_window(*time) {
                return false;
            }
            // And its `asset` goes stale the same way: a pooled first sighting names the index it
            // sealed an envelope for, and a *competing* first sighting committing in the meantime
            // moves the index the registry would assign — which admission now refuses
            // (`TxError::AttestAssetMismatch`). Decoding the attestation costs no signature work,
            // and a rotation (which decodes to no transfer) binds no index.
            if let Some((id, _)) = bridge_notes::attested_transfer(attestation) {
                if ledger.bridge().and_then(|b| b.deposit_index(&id)) != Some(*asset) {
                    return false;
                }
            }
        }
        !tx.nullifiers().iter().any(|nf| ledger.is_spent(nf))
            && !tx.commitments().iter().any(|cm| ledger.has_commitment(cm))
            && !tx.bridge_digests().iter().any(|mu| ledger.is_digest_spent(mu))
    }

    /// Forget these transactions — called with a committed block's hashes.
    pub fn remove(&mut self, hashes: &[Hash]) {
        for h in hashes {
            self.remove_one(h);
        }
    }

    fn remove_one(&mut self, hash: &Hash) -> Option<Transaction> {
        let tx = self.txs.remove(hash)?;
        for nf in tx.nullifiers() {
            // Only withdraw the index entries this transaction owns: a conflicting one was never
            // admitted, so an entry pointing elsewhere cannot exist, but checking keeps the two
            // maps honest if that ever changes.
            if self.nullifiers.get(&nf) == Some(hash) {
                self.nullifiers.remove(&nf);
            }
        }
        for cm in tx.commitments() {
            if self.commitments.get(&cm) == Some(hash) {
                self.commitments.remove(&cm);
            }
        }
        for mu in tx.bridge_digests() {
            if self.digests.get(&mu) == Some(hash) {
                self.digests.remove(&mu);
            }
        }
        Some(tx)
    }

    /// Drop txs that can no longer apply on `ledger`: a nullifier spent by someone else, a
    /// commitment that now exists, an attestation digest another relayer's transaction already
    /// consumed, an anchor that has scrolled out of the window, or a `time` that has fallen out
    /// of it. Called after every commit.
    pub fn prune(&mut self, ledger: &Ledger) {
        let stale: Vec<Hash> =
            self.txs.iter().filter(|(_, tx)| !Self::still_applies(tx, ledger)).map(|(h, _)| *h).collect();
        for h in stale {
            self.remove_one(&h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fixtures;
    use shrugg_core::bridge::{digest, sign_digest, Attestation, Body, Payload, Transfer, CHAIN_RAND};
    use shrugg_core::confidential::StubExecutor;
    use shrugg_core::ledger::ANCHOR_WINDOW;
    use shrugg_core::notes::ShieldedAddress;
    use shrugg_core::types::Action;

    /// A ledger at the fixtures' genesis, with the faucet on and a height past 0 so bundles can
    /// carry a `time` inside the window.
    fn ledger() -> Ledger {
        let gs = fixtures::genesis(1);
        let mut l = gs.ledger.clone();
        l.set_faucet(true);
        l
    }

    fn nf(n: u8) -> Word8 {
        [n as u32 + 1000; 8]
    }

    fn cm(n: u8) -> Word8 {
        [n as u32 + 2000; 8]
    }

    #[test]
    fn inserts_validates_and_orders_by_fee() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let cheap = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        let dear = fixtures::bundle_tx(&l, [nf(3), nf(4)], [cm(3), cm(4)], fixtures::bundle_fee() * 3);
        m.insert(cheap.clone(), &l, &StubExecutor).unwrap();
        m.insert(dear.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), 2);
        // Highest fee first, regardless of insertion order.
        assert_eq!(m.candidates(&l, 10), vec![dear.clone(), cheap.clone()]);
        assert_eq!(m.candidates(&l, 1), vec![dear.clone()]);
        // The byte budget stops the selection short rather than overflowing a block.
        let one = dear.encoded_len();
        assert_eq!(m.candidates_within(&l, 10, one).len(), 1);
        assert_eq!(m.candidates_within(&l, 10, 1).len(), 0);
        assert_eq!(m.candidates_within(&l, 10, usize::MAX).len(), 2);
    }

    #[test]
    fn a_tie_on_fee_is_broken_by_hash_so_every_proposer_agrees() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let a = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        let b = fixtures::bundle_tx(&l, [nf(3), nf(4)], [cm(3), cm(4)], fixtures::bundle_fee());
        m.insert(a.clone(), &l, &StubExecutor).unwrap();
        m.insert(b.clone(), &l, &StubExecutor).unwrap();
        let mut expected = vec![a, b];
        expected.sort_by_key(|t| t.hash());
        assert_eq!(m.candidates(&l, 10), expected);
    }

    #[test]
    fn rejects_duplicates_and_nullifier_conflicts() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let tx = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        m.insert(tx.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.insert(tx.clone(), &l, &StubExecutor), Err(MempoolError::Duplicate));
        // A different transaction spending one of the same notes is a conflict, named by the
        // nullifier they disagree over.
        let same_nf = fixtures::bundle_tx(&l, [nf(2), nf(9)], [cm(7), cm(8)], fixtures::bundle_fee());
        assert_eq!(m.insert(same_nf, &l, &StubExecutor), Err(MempoolError::Conflict(nf(2))));
        // So is one that would create a commitment another pending transaction already creates.
        let same_cm = fixtures::bundle_tx(&l, [nf(5), nf(6)], [cm(2), cm(9)], fixtures::bundle_fee());
        assert_eq!(m.insert(same_cm, &l, &StubExecutor), Err(MempoolError::Conflict(cm(2))));
        assert_eq!(m.len(), 1);
        // Removing the owner frees both notes again.
        m.remove(&[tx.hash()]);
        assert_eq!(m.len(), 0);
        let now_fine = fixtures::bundle_tx(&l, [nf(2), nf(9)], [cm(7), cm(8)], fixtures::bundle_fee());
        m.insert(now_fine, &l, &StubExecutor).unwrap();
    }

    #[test]
    fn an_invalid_transaction_is_refused_with_the_ledger_s_own_error() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let mut wrong_chain = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        wrong_chain.chain_id = 99;
        assert!(matches!(
            m.insert(wrong_chain, &l, &StubExecutor),
            Err(MempoolError::Invalid(TxError::WrongChain { .. }))
        ));
        let underpaid = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], 1);
        assert!(matches!(m.insert(underpaid, &l, &StubExecutor), Err(MempoolError::Invalid(TxError::FeeTooLow { .. }))));
        // A refused transaction leaves no trace in the conflict indexes.
        assert_eq!(m.len(), 0);
        let good = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        m.insert(good, &l, &StubExecutor).unwrap();
    }

    #[test]
    fn prune_drops_spent_and_stale() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let a = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        // `b` double-spends one of `a`'s notes; the pool never holds both, so it is only
        // reachable after `a` is committed and removed.
        let b = fixtures::bundle_tx(&l, [nf(2), nf(9)], [cm(7), cm(8)], fixtures::bundle_fee());
        let far = fixtures::bundle_tx(&l, [nf(5), nf(6)], [cm(5), cm(6)], fixtures::bundle_fee());
        m.insert(a.clone(), &l, &StubExecutor).unwrap();
        m.insert(far.clone(), &l, &StubExecutor).unwrap();

        // Apply `a` to the ledger the way a commit would, then re-admit `b`.
        let mut after = l.clone();
        after.apply_tx(&a, &fixtures::key(1).address(), &StubExecutor).unwrap();
        m.remove(&[a.hash()]);
        m.insert(b.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), 2);

        // `b`'s nullifier is now spent and its commitments are untouched; `far` still applies.
        m.prune(&after);
        assert!(!m.contains(&b.hash()), "a transaction double-spending a committed nullifier survived");
        assert!(m.contains(&far.hash()));

        // Scroll the anchor window past `far`'s anchor: it is no longer provable against.
        let mut scrolled = after.clone();
        for h in 1..=(ANCHOR_WINDOW as u64 + 2) {
            scrolled.set_height(h);
            scrolled.record_anchor(h);
        }
        assert!(!scrolled.is_anchor(&far.bundle.as_ref().unwrap().anchor));
        m.prune(&scrolled);
        assert_eq!(m.len(), 0, "a transaction anchored outside the window survived");
    }

    #[test]
    fn full_pool_rejects() {
        let l = ledger();
        let mut m = Mempool::new(1);
        let a = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        let b = fixtures::bundle_tx(&l, [nf(3), nf(4)], [cm(3), cm(4)], fixtures::bundle_fee());
        m.insert(a, &l, &StubExecutor).unwrap();
        assert_eq!(m.insert(b, &l, &StubExecutor), Err(MempoolError::Full));
    }

    #[test]
    fn a_mint_takes_its_commitment_slot_like_any_other_note() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let mint = fixtures::mint_tx(l.chain_id(), cm(1), 5, &fixtures::key(1));
        m.insert(mint.clone(), &l, &StubExecutor).unwrap();
        // A bundle that would create the same note is a conflict, not a second copy of it.
        let clash = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        assert_eq!(m.insert(clash, &l, &StubExecutor), Err(MempoolError::Conflict(cm(1))));
        assert_eq!(m.candidates(&l, 10), vec![mint]);
    }

    /// A ledger on a bridged chain, plus the guardian secrets that can attest to it.
    fn bridged_ledger() -> (Ledger, Vec<[u8; 32]>) {
        let (gs, secrets) = fixtures::bridged_genesis(1);
        (gs.ledger.clone(), secrets)
    }

    fn recipient() -> ShieldedAddress {
        ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] }
    }

    /// The one attestation both relayers see: 1,000 of chain 2's token to `recipient()`,
    /// signed by a quorum of five of the six guardians.
    fn attestation(secrets: &[[u8; 32]]) -> Vec<u8> {
        attestation_of(secrets, [0xaa; 32], 0)
    }

    /// [`attestation`] for a chosen `token` and `sequence`, so two attestations can name two
    /// different tokens — each a first sighting racing the other for the registry's next index.
    fn attestation_of(secrets: &[[u8; 32]], token: [u8; 32], sequence: u64) -> Vec<u8> {
        let body = Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: 2,
            emitter_address: [2; 32],
            sequence,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(1_000),
                token_address: token,
                token_chain: 2,
                to: recipient().recipient_hash(),
                to_chain: CHAIN_RAND,
                fee: Transfer::u256_from_u128(0),
            })
            .encode(),
        };
        let d = digest(&body.encode());
        let signatures = (0..5).map(|i| sign_digest(&secrets[i], i as u8, &d)).collect();
        Attestation { guardian_set_index: 0, signatures, body }.encode()
    }

    /// One relayer's submission of `attestation`: its own fee bundle and its own blinding `r`,
    /// so two relayers' transactions have nothing in common but the attestation itself. The
    /// `asset` word is the index `l`'s registry would deposit under, as a wallet would fill it in.
    fn attest_tx(l: &Ledger, attestation: Vec<u8>, seed: u8) -> Transaction {
        let s = seed as u32;
        let b = fixtures::bundle(l, [nf(seed), nf(seed + 1)], [cm(seed), cm(seed + 1)], fixtures::bundle_fee());
        let asset = fixtures::deposit_index(l, &attestation);
        Transaction::shielded(
            l.chain_id(),
            b,
            Action::BridgeAttest {
                attestation,
                recipient: recipient(),
                r: [s; 8],
                time: l.height() as u32,
                asset,
                envelope: fixtures::env(seed),
            },
        )
    }

    /// A bridge is permissionless, so two relayers racing one attestation is the normal case,
    /// not an attack. Their transactions share no nullifier and no commitment — the deposit
    /// note is computed by the ledger and never appears on the wire — so only the attestation
    /// digest says they collide. Without claiming it the pool would hold both, offer both, and
    /// the proposer's block would die on the second with `Bridge(Replay)`.
    #[test]
    fn two_relayers_racing_one_attestation_do_not_both_enter_the_pool() {
        let (l, secrets) = bridged_ledger();
        let a = attestation(&secrets);
        let first = attest_tx(&l, a.clone(), 10);
        let second = attest_tx(&l, a.clone(), 20);
        // Nothing the old indexes track connects them.
        assert_ne!(first.hash(), second.hash());
        assert!(first.nullifiers().iter().all(|x| !second.nullifiers().contains(x)));
        assert!(first.commitments().iter().all(|x| !second.commitments().contains(x)));
        // Both are independently valid: the race is real, not a validation failure.
        assert_eq!(l.validate(&second, &StubExecutor), Ok(()));

        let mut m = Mempool::new(100);
        let mu = first.bridge_digests()[0];
        m.insert(first.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(
            m.insert(second.clone(), &l, &StubExecutor),
            Err(MempoolError::AttestationConflict(mu)),
            "the digest is the only thing that tells them apart"
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m.candidates(&l, 10), vec![first.clone()]);

        // Once the first is mined, the digest is consumed on chain: the second can never apply,
        // and `prune` drops it rather than leaving it to kill a block.
        let mut mined = l.clone();
        mined.apply_tx(&first, &fixtures::key(1).address(), &StubExecutor).unwrap();
        assert!(mined.is_digest_spent(&mu));
        let mut m2 = Mempool::new(100);
        m2.insert(second.clone(), &l, &StubExecutor).unwrap();
        assert!(m2.candidates(&mined, 10).is_empty(), "not offered to the proposer");
        m2.prune(&mined);
        assert_eq!(m2.len(), 0);

        // And removing the first releases its claim, so a genuine retry can take its place.
        m.remove(&[first.hash()]);
        assert!(m.insert(second, &l, &StubExecutor).is_ok());
    }

    /// Two *different* tokens, both seen for the first time, both predicting the registry's next
    /// index for their deposit note. They do not conflict in the pool — different digests,
    /// different notes — but only one of them can have index 1, and the loser's `asset` word no
    /// longer matches what the ledger would assign it. Admission refuses that
    /// (`TxError::AttestAssetMismatch`), so the pool has to stop offering it: the alternative is a
    /// proposer building a block that dies on its own candidate.
    #[test]
    fn a_pooled_first_sighting_is_dropped_once_another_registers_its_index() {
        let (l, secrets) = bridged_ledger();
        let mine = attest_tx(&l, attestation_of(&secrets, [0xaa; 32], 0), 10);
        let theirs = attest_tx(&l, attestation_of(&secrets, [0xbb; 32], 1), 20);
        // Both name index 1 — the registry is empty, so that is what either would be given.
        for tx in [&mine, &theirs] {
            let Action::BridgeAttest { asset, .. } = &tx.action else { panic!("an attest") };
            assert_eq!(*asset, 1);
            assert_eq!(l.validate(tx, &StubExecutor), Ok(()));
        }
        let mut m = Mempool::new(100);
        m.insert(mine.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.candidates(&l, 10), vec![mine.clone()]);

        // The other one commits. Nothing mine spends is spent and its digest is untouched, so
        // only the moved index can drop it.
        let mut after = l.clone();
        after.apply_tx(&theirs, &fixtures::key(1).address(), &StubExecutor).unwrap();
        assert!(!after.is_digest_spent(&mine.bridge_digests()[0]));
        assert!(mine.nullifiers().iter().all(|nf| !after.is_spent(nf)));
        assert!(matches!(
            after.validate(&mine, &StubExecutor),
            Err(TxError::AttestAssetMismatch { expected: 2, actual: 1 })
        ));
        assert!(m.candidates(&after, 10).is_empty(), "still offered to the proposer");
        m.prune(&after);
        assert_eq!(m.len(), 0);

        // Re-sealed and re-proved against the registry as it now stands, the same deposit is
        // admissible again — the wallet pays for a second bundle, not a lost note.
        let again = attest_tx(&after, attestation_of(&secrets, [0xaa; 32], 0), 30);
        let Action::BridgeAttest { asset, .. } = &again.action else { panic!("an attest") };
        assert_eq!(*asset, 2);
        m.insert(again.clone(), &after, &StubExecutor).unwrap();
        assert_eq!(m.candidates(&after, 10), vec![again]);
    }
}
