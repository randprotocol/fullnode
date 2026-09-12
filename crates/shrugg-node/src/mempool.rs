//! Pending transaction pool: validated against the tip ledger and offered to the proposer by
//! fee.
//!
//! A redacted chain has no senders and no nonces, so there is no per-sender ordering left to
//! do: a bundle is admissible or it is not, and two bundles are only related to each other when
//! they touch the same note. What replaces the old nonce bookkeeping is *conflict* tracking —
//! the pool never holds two transactions that spend the same nullifier or create the same
//! commitment, because at most one of them could ever be included and carrying the other only
//! wastes the proposer's block space and a (~20 ms) proof verification per gossip round. One of
//! those commitments is not in the transaction at all: a `Withdraw`'s deposit note, which the
//! ledger derives from the register, and which two withdraws can collide over just as two bundles
//! can collide over an output.

use shrugg_core::confidential::ConfidentialExecutor;
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
    #[error("mempool full")]
    Full,
}

/// A pooled transaction and the commitments it claims.
///
/// The claims are remembered rather than recomputed because one of them is not on the wire: the
/// note a `Withdraw` makes the ledger create comes from the register, via
/// `Ledger::derived_commitment`, so a transaction leaving the pool could not name it again
/// without a ledger to hand.
struct Pooled {
    tx: Transaction,
    commitments: Vec<Word8>,
}

pub struct Mempool {
    txs: HashMap<Hash, Pooled>,
    /// Which pooled transaction spends each nullifier — one owner per nullifier, always.
    nullifiers: HashMap<Word8, Hash>,
    /// Which pooled transaction creates each commitment: a bundle's two output slots, a mint's
    /// single note, or the deposit a `Withdraw` will make the ledger create.
    commitments: HashMap<Word8, Hash>,
    max_size: usize,
}

/// Every commitment `tx` claims: the ones it carries, plus the deposit `ledger` would derive for
/// it. Two transactions claiming one commitment can never both be included, so the pool holds at
/// most one of them — and for a withdraw that is also what makes a second withdraw paying the same
/// note a conflict here rather than a transaction the proposer silently drops.
fn claimed_commitments(tx: &Transaction, ledger: &Ledger, executor: &dyn ConfidentialExecutor) -> Vec<Word8> {
    let mut v = tx.commitments();
    v.extend(ledger.derived_commitment(&tx.action, executor));
    v
}

impl Mempool {
    pub fn new(max_size: usize) -> Mempool {
        Mempool { txs: HashMap::new(), nullifiers: HashMap::new(), commitments: HashMap::new(), max_size }
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
        self.txs.get(hash).map(|p| &p.tx)
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
        let commitments = claimed_commitments(&tx, ledger, executor);
        for cm in &commitments {
            if self.commitments.contains_key(cm) {
                return Err(MempoolError::Conflict(*cm));
            }
        }
        if self.txs.len() >= self.max_size {
            return Err(MempoolError::Full);
        }
        ledger.validate(&tx, executor).map_err(MempoolError::Invalid)?;

        for nf in tx.nullifiers() {
            self.nullifiers.insert(nf, hash);
        }
        for cm in &commitments {
            self.commitments.insert(*cm, hash);
        }
        self.txs.insert(hash, Pooled { tx, commitments });
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
        let mut ready: Vec<(&Hash, &Pooled)> =
            self.txs.iter().filter(|(_, p)| Self::still_applies(p, ledger)).collect();
        ready.sort_by(|a, b| b.1.tx.fee().cmp(&a.1.tx.fee()).then_with(|| a.0.cmp(b.0)));
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for (_, p) in ready.into_iter().take(max) {
            let len = p.tx.encoded_len();
            if bytes + len > max_bytes {
                break;
            }
            bytes += len;
            out.push(p.tx.clone());
        }
        out
    }

    /// The cheap half of `Ledger::validate` — everything that can go stale between insertion and
    /// the next block, and nothing that costs a proof verification.
    fn still_applies(p: &Pooled, ledger: &Ledger) -> bool {
        let tx = &p.tx;
        if let Some(b) = &tx.bundle {
            if !ledger.is_anchor(&b.anchor) || !ledger.time_in_window(b.time) {
                return false;
            }
        }
        // A bundle-less `Withdraw` carries a `time` of its own, under the same window rule — so
        // it goes stale here the same way a bundle does (`Ledger::time_in_window`).
        if let Action::Withdraw { time, .. } = &tx.action {
            if !ledger.time_in_window(*time) {
                return false;
            }
        }
        // The claims include a withdraw's derived deposit, so a note someone else created in the
        // meantime takes that withdraw out of the pool too.
        !tx.nullifiers().iter().any(|nf| ledger.is_spent(nf))
            && !p.commitments.iter().any(|cm| ledger.has_commitment(cm))
    }

    /// Forget these transactions — called with a committed block's hashes.
    pub fn remove(&mut self, hashes: &[Hash]) {
        for h in hashes {
            self.remove_one(h);
        }
    }

    fn remove_one(&mut self, hash: &Hash) -> Option<Transaction> {
        let p = self.txs.remove(hash)?;
        for nf in p.tx.nullifiers() {
            // Only withdraw the index entries this transaction owns: a conflicting one was never
            // admitted, so an entry pointing elsewhere cannot exist, but checking keeps the two
            // maps honest if that ever changes.
            if self.nullifiers.get(&nf) == Some(hash) {
                self.nullifiers.remove(&nf);
            }
        }
        for cm in &p.commitments {
            if self.commitments.get(cm) == Some(hash) {
                self.commitments.remove(cm);
            }
        }
        Some(p.tx)
    }

    /// Drop txs that can no longer apply on `ledger`: a nullifier spent by someone else, a
    /// commitment that now exists, an anchor that has scrolled out of the window, or a `time`
    /// that has fallen out of it. Called after every commit.
    pub fn prune(&mut self, ledger: &Ledger) {
        let stale: Vec<Hash> =
            self.txs.iter().filter(|(_, p)| !Self::still_applies(p, ledger)).map(|(h, _)| *h).collect();
        for h in stale {
            self.remove_one(&h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fixtures;
    use shrugg_core::confidential::StubExecutor;
    use shrugg_core::ledger::ANCHOR_WINDOW;

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

    /// The fixtures' ledger with validator 1 holding more rewards than the bundle base, so it has
    /// something to withdraw: two applied bundles, whose fees are its own as their proposer.
    fn ledger_with_rewards() -> Ledger {
        let mut l = ledger();
        let v = fixtures::key(1);
        for (height, n) in [(1u64, 30u8), (2, 34)] {
            l.set_height(height);
            let t = fixtures::bundle_tx(&l, [nf(n), nf(n + 1)], [cm(n), cm(n + 1)], fixtures::bundle_fee());
            l.apply_tx(&t, &v.address(), &StubExecutor).unwrap();
            l.record_anchor(height);
        }
        assert_eq!(l.released(&v.address()), 2 * fixtures::bundle_fee());
        l
    }

    /// A `Withdraw` claims the note the *ledger* will create for it, which the wire does not
    /// carry: without that claim the pool would hold two withdraws that pay one note, or a
    /// withdraw beside a bundle creating the same note, and only one of each pair could ever be
    /// included.
    #[test]
    fn a_withdraw_claims_the_deposit_the_ledger_will_derive() {
        let l = ledger_with_rewards();
        let mut m = Mempool::new(100);
        let v = fixtures::key(1);
        let amount = 2 * fixtures::bundle_fee();
        let w = |nonce: u64, r: Word8| fixtures::withdraw_tx(l.chain_id(), &v, amount, nonce, l.height() as u32, r);

        let first = w(0, [3; 8]);
        let derived = l.derived_commitment(&first.action, &StubExecutor).expect("a withdraw derives one note");
        assert!(!first.commitments().contains(&derived), "and the transaction itself does not carry it");
        m.insert(first.clone(), &l, &StubExecutor).unwrap();

        // Another withdraw that would pay that same note — a different nonce, the same blinding —
        // is a conflict, named by the note the two disagree over.
        assert_eq!(m.insert(w(1, [3; 8]), &l, &StubExecutor), Err(MempoolError::Conflict(derived)));
        // So is a bundle whose output slot is that note.
        let clash = fixtures::bundle_tx(&l, [nf(1), nf(2)], [derived, cm(2)], fixtures::bundle_fee());
        assert_eq!(m.insert(clash.clone(), &l, &StubExecutor), Err(MempoolError::Conflict(derived)));
        // A withdraw paying a *different* note — the same nonce, a fresh blinding — is no
        // conflict at all.
        m.insert(w(0, [4; 8]), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), 2);

        // And removing the owner frees the note again, claim and all.
        m.remove(&[first.hash()]);
        m.insert(clash, &l, &StubExecutor).unwrap();
    }

    /// A bundle-less validator action is pooled, ordered and offered exactly as a mint is. An
    /// unbond creates no note, so it claims nothing: two of them are not a pool conflict, and the
    /// register's nonce is what makes only one applicable.
    #[test]
    fn a_bundle_less_validator_action_is_pooled_like_a_mint() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let v = fixtures::key(1);
        let unbond = |amount: u64| {
            let signature = v.sign(shrugg_core::unbond_message(l.chain_id(), &v.address(), amount, 0).as_bytes());
            Transaction {
                chain_id: l.chain_id(),
                bundle: None,
                action: Action::Unbond { validator: v.address(), amount, nonce: 0, signature },
            }
        };
        let first = unbond(1000);
        m.insert(first.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.candidates(&l, 10), vec![first.clone()]);
        assert_eq!(m.insert(first.clone(), &l, &StubExecutor), Err(MempoolError::Duplicate));
        m.insert(unbond(2000), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), 2, "a second unbond at the same nonce is not a conflict here");
        // And nothing about it goes stale, so a commit does not drop it.
        m.prune(&l);
        assert_eq!(m.len(), 2);
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
}
