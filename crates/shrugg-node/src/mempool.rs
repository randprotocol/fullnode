//! Pending transaction pool: validated against the tip ledger, ordered per
//! sender by nonce, and offered to the proposer by fee.

use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::{Address, Hash, Ledger, Transaction, TxError};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum MempoolError {
    #[error("{0}")]
    Invalid(TxError),
    #[error("nonce {nonce} too far ahead of account nonce {current}")]
    NonceGap { nonce: u64, current: u64 },
    #[error("already in mempool")]
    Duplicate,
    #[error("replacement fee too low")]
    ReplacementUnderpriced,
    #[error("mempool full")]
    Full,
}

pub struct Mempool {
    txs: HashMap<Hash, Transaction>,
    by_sender: BTreeMap<Address, BTreeMap<u64, Hash>>,
    max_size: usize,
    max_per_sender: u64,
}

impl Mempool {
    pub fn new(max_size: usize, max_per_sender: u64) -> Mempool {
        Mempool { txs: HashMap::new(), by_sender: BTreeMap::new(), max_size, max_per_sender }
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

    pub fn has_nonce(&self, sender: &Address, nonce: u64) -> bool {
        self.by_sender.get(sender).map(|m| m.contains_key(&nonce)).unwrap_or(false)
    }

    /// Validate against `ledger` (the state the next block will build on) and insert.
    /// A tx whose nonce is ahead of the account is kept if the gap is small.
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
        let sender = tx.sender();
        let current = ledger.nonce(&sender);
        if tx.body.nonce < current {
            return Err(MempoolError::Invalid(TxError::BadNonce { expected: current, actual: tx.body.nonce }));
        }
        if tx.body.nonce >= current + self.max_per_sender {
            return Err(MempoolError::NonceGap { nonce: tx.body.nonce, current });
        }
        // Cheap admission decisions first: the probe below clones the whole
        // ledger and validates (signature, possibly a ~20 ms STARK verify), so
        // duplicates/full-pool/underpriced replacements must be rejected here,
        // not after paying that cost for every gossiped transaction.
        let replacing = self.by_sender.get(&sender).and_then(|slot| slot.get(&tx.body.nonce)).copied();
        if let Some(existing) = replacing {
            if tx.body.fee <= self.txs[&existing].body.fee {
                return Err(MempoolError::ReplacementUnderpriced);
            }
        } else if self.txs.len() >= self.max_size {
            return Err(MempoolError::Full);
        }
        // Validate everything except the exact nonce match: probe against a copy of the
        // full state (accounts, programs, flags) with only this sender's nonce adjusted.
        let mut probe = ledger.clone();
        {
            let mut adjusted = probe.account(&sender);
            adjusted.nonce = tx.body.nonce;
            probe.set_account(sender, adjusted);
        }
        probe.validate(&tx, executor).map_err(MempoolError::Invalid)?;

        let slot = self.by_sender.entry(sender).or_default();
        if let Some(existing) = replacing {
            self.txs.remove(&existing);
            slot.remove(&tx.body.nonce);
        }
        slot.insert(tx.body.nonce, hash);
        self.txs.insert(hash, tx);
        Ok(hash)
    }

    /// Transactions ready for inclusion on top of `ledger`: per sender a
    /// contiguous nonce run starting at the account nonce, senders ordered by
    /// their first tx's fee (highest first). Cumulative balance is checked so
    /// the proposer does not waste block space on txs that will fail.
    pub fn candidates(&self, ledger: &Ledger, max: usize) -> Vec<Transaction> {
        self.candidates_within(ledger, max, usize::MAX)
    }

    /// Like `candidates`, but stops before the encoded size of the selection exceeds `max_bytes`.
    pub fn candidates_within(&self, ledger: &Ledger, max: usize, max_bytes: usize) -> Vec<Transaction> {
        let mut runs: Vec<(u128, Vec<&Transaction>)> = Vec::new();
        for (sender, nonces) in &self.by_sender {
            let mut expected = ledger.nonce(sender);
            let mut balance = ledger.balance(sender);
            let mut run = Vec::new();
            for (nonce, hash) in nonces {
                if *nonce != expected {
                    break;
                }
                let tx = &self.txs[hash];
                let Some(cost) = tx.total_cost() else { break };
                if cost > balance {
                    break;
                }
                balance -= cost;
                expected += 1;
                run.push(tx);
            }
            if let Some(first) = run.first() {
                runs.push((first.body.fee, run));
            }
        }
        runs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1[0].sender().cmp(&b.1[0].sender())));
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for tx in runs.into_iter().flat_map(|(_, r)| r).take(max) {
            let len = tx.encoded_len();
            if bytes + len > max_bytes {
                break;
            }
            bytes += len;
            out.push(tx.clone());
        }
        out
    }

    pub fn remove(&mut self, hash: &Hash) -> Option<Transaction> {
        let tx = self.txs.remove(hash)?;
        let sender = tx.sender();
        if let Some(slot) = self.by_sender.get_mut(&sender) {
            slot.remove(&tx.body.nonce);
            if slot.is_empty() {
                self.by_sender.remove(&sender);
            }
        }
        Some(tx)
    }

    /// Drop txs that can no longer apply on `ledger` (nonce already used, or
    /// balance gone). Called after every commit.
    pub fn prune(&mut self, ledger: &Ledger) {
        let stale: Vec<Hash> = self
            .by_sender
            .iter()
            .flat_map(|(sender, nonces)| {
                let current = ledger.nonce(sender);
                nonces.iter().filter(move |(n, _)| **n < current).map(|(_, h)| *h)
            })
            .collect();
        for h in stale {
            self.remove(&h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shrugg_core::confidential::StubExecutor;
    use shrugg_core::Keypair;

    fn key(n: u8) -> Keypair {
        Keypair::from_seed([n; 32]).unwrap()
    }

    fn ledger() -> Ledger {
        let mut l = Ledger::new(1);
        l.credit(key(1).address(), 1_000).unwrap();
        l.credit(key(2).address(), 1_000).unwrap();
        l
    }

    #[test]
    fn insert_orders_by_nonce_and_fee() {
        let l = ledger();
        let mut m = Mempool::new(100, 16);
        let a = key(1);
        let b = key(2);
        let to = key(3).address();
        let a1 = Transaction::transfer(&a, 1, 1, to, 10, 1); // gap: nonce 1 before 0
        let a0 = Transaction::transfer(&a, 1, 0, to, 10, 1);
        let b0 = Transaction::transfer(&b, 1, 0, to, 10, 5);
        m.insert(a1.clone(), &l, &StubExecutor).unwrap();
        // only b0 (a's run doesn't start at nonce 0 yet)
        m.insert(b0.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.candidates(&l, 10), vec![b0.clone()]);
        m.insert(a0.clone(), &l, &StubExecutor).unwrap();
        let c = m.candidates(&l, 10);
        assert_eq!(c, vec![b0.clone(), a0.clone(), a1.clone()]); // b pays more, a in nonce order
        assert_eq!(m.candidates(&l, 2).len(), 2);
    }

    #[test]
    fn rejects_bad_txs() {
        let l = ledger();
        let mut m = Mempool::new(100, 4);
        let a = key(1);
        let to = key(3).address();
        let wrong_chain = Transaction::transfer(&a, 2, 0, to, 1, 0);
        assert!(matches!(m.insert(wrong_chain, &l, &StubExecutor), Err(MempoolError::Invalid(TxError::WrongChain { .. }))));
        let gap = Transaction::transfer(&a, 1, 4, to, 1, 0);
        assert!(matches!(m.insert(gap, &l, &StubExecutor), Err(MempoolError::NonceGap { .. })));
        let broke = Transaction::transfer(&key(9), 1, 0, to, 1, 0);
        assert!(matches!(m.insert(broke, &l, &StubExecutor), Err(MempoolError::Invalid(TxError::InsufficientBalance { .. }))));
        let ok = Transaction::transfer(&a, 1, 0, to, 1, 0);
        m.insert(ok.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.insert(ok.clone(), &l, &StubExecutor), Err(MempoolError::Duplicate));
        let cheaper = Transaction::transfer(&a, 1, 0, to, 2, 0);
        assert_eq!(m.insert(cheaper, &l, &StubExecutor), Err(MempoolError::ReplacementUnderpriced));
        let pricier = Transaction::transfer(&a, 1, 0, to, 2, 3);
        m.insert(pricier.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m.candidates(&l, 10), vec![pricier]);
    }

    #[test]
    fn candidates_respect_cumulative_balance_and_prune_after_commit() {
        let l = ledger();
        let mut m = Mempool::new(100, 16);
        let a = key(1);
        let to = key(3).address();
        let t0 = Transaction::transfer(&a, 1, 0, to, 600, 0);
        let t1 = Transaction::transfer(&a, 1, 1, to, 600, 0); // individually ok, cumulatively not
        m.insert(t0.clone(), &l, &StubExecutor).unwrap();
        m.insert(t1.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.candidates(&l, 10), vec![t0.clone()]);
        // simulate commit of t0
        let mut after = l.clone();
        after.apply_tx(&t0, &key(4).address(), &StubExecutor).unwrap();
        m.prune(&after);
        assert_eq!(m.len(), 1);
        assert!(m.contains(&t1.hash()));
        assert!(m.candidates(&after, 10).is_empty()); // 400 left < 600
    }

    #[test]
    fn mint_accepted_only_with_faucet() {
        let mut l = ledger();
        let mut m = Mempool::new(100, 16);
        let to = key(3).address();
        let mint = Transaction::mint(&key(1), 1, 0, to, 5, 0);
        assert!(matches!(m.insert(mint.clone(), &l, &StubExecutor), Err(MempoolError::Invalid(TxError::FaucetDisabled))));
        l.set_faucet(true);
        m.insert(mint.clone(), &l, &StubExecutor).unwrap();
        assert!(m.has_nonce(&key(1).address(), 0));
        assert_eq!(m.candidates(&l, 10), vec![mint]);
    }

    #[test]
    fn candidates_stop_at_byte_budget() {
        let l = ledger();
        let mut m = Mempool::new(100, 16);
        let a = key(1);
        let to = key(3).address();
        for n in 0..3 {
            m.insert(Transaction::transfer(&a, 1, n, to, 1, 0), &l, &StubExecutor).unwrap();
        }
        let one = Transaction::transfer(&a, 1, 0, to, 1, 0).encoded_len();
        assert_eq!(m.candidates_within(&l, 10, one * 2 + 1).len(), 2);
        assert_eq!(m.candidates_within(&l, 10, usize::MAX).len(), 3);
        assert_eq!(m.candidates_within(&l, 10, 1).len(), 0);
    }

    #[test]
    fn full_pool_rejects() {
        let l = ledger();
        let mut m = Mempool::new(1, 16);
        let a = key(1);
        let to = key(3).address();
        m.insert(Transaction::transfer(&a, 1, 0, to, 1, 0), &l, &StubExecutor).unwrap();
        assert_eq!(m.insert(Transaction::transfer(&a, 1, 1, to, 1, 0), &l, &StubExecutor), Err(MempoolError::Full));
    }
}
