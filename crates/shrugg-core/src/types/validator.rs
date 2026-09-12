//! Validator set and leader schedule.

use crate::crypto::{Address, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    pub public_key: PublicKey,
    pub stake: u128,
}

impl Validator {
    pub fn address(&self) -> Address {
        self.public_key.address()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
}

impl ValidatorSet {
    /// Validators are sorted by address so every node derives the same leader schedule.
    pub fn new(mut validators: Vec<Validator>) -> ValidatorSet {
        validators.sort_by_key(|v| v.address());
        validators.dedup_by_key(|v| v.address());
        ValidatorSet { validators }
    }

    /// Build a set from register entries (`(key, stake)` pairs, phase S2).
    ///
    /// This is the one boundary where the register's `u64` stake becomes the `u128` consensus
    /// weight: amounts on this chain are `u64` units, while quorum and total-stake arithmetic
    /// keeps the headroom so summing a full set can never overflow.
    pub fn from_entries<'a>(entries: impl IntoIterator<Item = (&'a PublicKey, u64)>) -> ValidatorSet {
        ValidatorSet::new(
            entries
                .into_iter()
                .map(|(public_key, stake)| Validator { public_key: public_key.clone(), stake: stake as u128 })
                .collect(),
        )
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Validator> {
        self.validators.iter()
    }

    pub fn get(&self, addr: &Address) -> Option<&Validator> {
        self.validators.iter().find(|v| v.address() == *addr)
    }

    pub fn contains(&self, addr: &Address) -> bool {
        self.get(addr).is_some()
    }

    pub fn total_stake(&self) -> u128 {
        self.validators.iter().map(|v| v.stake).sum()
    }

    /// `stake * 3 > total * 2`, i.e. strictly more than two thirds.
    pub fn has_quorum(&self, stake: u128) -> bool {
        stake.saturating_mul(3) > self.total_stake().saturating_mul(2)
    }

    /// Round-robin leader. Hook for a future sortition beacon.
    ///
    /// An empty set has no leader: phase S2 lets an epoch's register derive one (every validator
    /// below the minimum stake), and such an epoch halts rather than panicking here — no key
    /// addresses to [`Address::ZERO`], so no proposal can pass the leader check.
    pub fn leader(&self, view: u64) -> Address {
        if self.validators.is_empty() {
            return Address::ZERO;
        }
        let idx = (view % self.validators.len() as u64) as usize;
        self.validators[idx].address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn vset(stakes: &[u128]) -> ValidatorSet {
        ValidatorSet::new(
            stakes
                .iter()
                .enumerate()
                .map(|(i, s)| Validator {
                    public_key: Keypair::from_seed([i as u8 + 1; 32]).unwrap().public_key().clone(),
                    stake: *s,
                })
                .collect(),
        )
    }

    #[test]
    fn quorum_is_strictly_more_than_two_thirds() {
        let v = vset(&[1, 1, 1, 1]);
        assert!(!v.has_quorum(2));
        assert!(v.has_quorum(3));
        let two = vset(&[1, 1]);
        assert!(!two.has_quorum(1));
        assert!(two.has_quorum(2));
        let one = vset(&[5]);
        assert!(one.has_quorum(5));
        let weighted = vset(&[10, 1, 1]);
        assert!(weighted.has_quorum(10));
        assert!(!weighted.has_quorum(2));
    }

    #[test]
    fn leader_rotates_and_is_order_independent() {
        let a = vset(&[1, 1, 1]);
        let mut shuffled: Vec<Validator> = a.iter().cloned().collect();
        shuffled.reverse();
        let b = ValidatorSet::new(shuffled);
        for view in 0..9 {
            assert_eq!(a.leader(view), b.leader(view));
        }
        assert_ne!(a.leader(0), a.leader(1));
        assert_eq!(a.leader(0), a.leader(3));
    }
}
