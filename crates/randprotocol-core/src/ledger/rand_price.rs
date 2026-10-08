//! The governance-set RAND/USD price behind the dollar-indexed sealing subsidy (genesis
//! `fees.usd_subsidy`, `docs/fees.md` §1.3, decision of 2026-10-09).
//!
//! The price is **not** a market oracle: it is set by the validator set's vote,
//! `Action::SetRandPrice`, in `AdmitValidator`'s shape — one bundle-less, fee-less action carrying
//! one `(validator key, signature)` per voter in strictly ascending voter order, judged by the
//! same voting set and the same quorum (`staking::check_votes`: strictly more than two thirds of
//! the weight, `ValidatorSet::has_quorum`). Each update carries the next nonce and may move the
//! price by at most a factor of two either way, so no single vote can swing the subsidy further
//! than that, and every update is a fresh signature over `(genesis, price, nonce)`.
//!
//! The ledger keeps `Option<RandPrice>`: seeded from `initial_price_micros` at height 0 / nonce 0
//! when the genesis gives one, `None` otherwise until the first update. It is consensus state
//! **only under the section**: folded into the state root as `H("rand-state-price-1", root ‖
//! price_root)` around everything else, inside `Ledger`'s equality, persisted by the node under
//! `META_RAND_PRICE`. Without the section it is `None`, the root is untouched byte for byte, and
//! the action is refused by name before a byte of it is read.

use super::staking::{check_votes, VoteFault};
use super::{Ledger, TxError};
use crate::crypto::{Address, Hash, PublicKey, Signature};
use crate::types::actions::set_rand_price_message;
use serde::{Deserialize, Serialize};

/// The chain's RAND/USD price as the validator set last voted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandPrice {
    /// Micro-dollars (10⁻⁶ USD) per whole RAND (10⁹ units). Never 0.
    pub price_micros_per_rand: u64,
    /// The height of the block that set it (0 for the genesis price).
    pub set_at_height: u64,
    /// The update's nonce (0 for the genesis price); the next update carries `nonce + 1`.
    pub nonce: u64,
}

impl RandPrice {
    /// Whether the price is usable at `height`: `height − set_at_height ≤ max_age` (saturating,
    /// so a price is fresh at the very height that set it).
    pub fn fresh_at(&self, height: u64, max_age: u64) -> bool {
        height.saturating_sub(self.set_at_height) <= max_age
    }
}

/// The price as one hash for the state root: a presence byte, then the three fields big-endian —
/// so "no price yet" and every price commit distinctly.
pub fn price_root(price: Option<&RandPrice>) -> Hash {
    let mut buf = Vec::with_capacity(25);
    match price {
        None => buf.push(0),
        Some(p) => {
            buf.push(1);
            buf.extend_from_slice(&p.price_micros_per_rand.to_be_bytes());
            buf.extend_from_slice(&p.set_at_height.to_be_bytes());
            buf.extend_from_slice(&p.nonce.to_be_bytes());
        }
    }
    Hash::digest_domain(b"rand-price-1", &buf)
}

/// Why a `SetRandPrice` was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PriceError {
    /// Not the next update: the ledger's nonce plus one is the only one that applies. State.
    #[error("price update nonce {got}, expected {expected}")]
    BadNonce { expected: u64, got: u64 },
    /// A price of 0 converts no dollar. About the bytes alone.
    #[error("a RAND price of 0 micro-dollars is no price")]
    ZeroPrice,
    /// More than a factor of two from the price it replaces. State (the old price moves).
    #[error("price {new} µ$/RAND is outside [{old}/2, {old}×2] of the current price")]
    OutOfBand { old: u64, new: u64 },
    /// No vote, or more votes than the voting set has members.
    #[error("a price update carries {got} votes; the voting set has {max} members")]
    VoteCount { got: usize, max: usize },
    /// Votes not in strictly ascending voter order (a repeated voter is this too). About the bytes.
    #[error("the price update's votes are not in strictly ascending voter order (a voter may appear once)")]
    VoteOrder,
    /// A vote by a key outside the voting set. State.
    #[error("{0} is not in the voting validator set")]
    VoterNotInSet(Address),
    /// The voters' weight is not strictly more than two thirds of the set's. State.
    #[error("the price update's voters hold {weight} of {total}: not more than two thirds")]
    NoQuorum { weight: u128, total: u128 },
    /// A vote whose signature does not verify over this chain's message for this price and nonce.
    #[error("the vote by {0} is not a signature over this chain's price update")]
    BadVote(Address),
}

impl From<VoteFault> for PriceError {
    fn from(fault: VoteFault) -> PriceError {
        match fault {
            VoteFault::Count { got, max } => PriceError::VoteCount { got, max },
            VoteFault::Order => PriceError::VoteOrder,
            VoteFault::NotInSet(v) => PriceError::VoterNotInSet(v),
            VoteFault::NoQuorum { weight, total } => PriceError::NoQuorum { weight, total },
            VoteFault::BadSignature(v) => PriceError::BadVote(v),
        }
    }
}

/// What a `SetRandPrice` gets on a chain whose genesis has no `fees.usd_subsidy`: the gate,
/// before a byte of the action is read, as an old node refuses the unknown wire variant.
pub const NO_USD_SUBSIDY: TxError =
    TxError::UnsupportedAction("the RAND price vote is not enabled on this chain (genesis fees.usd_subsidy)");

/// The nonce the next update must carry: one past the ledger's, or 1 when it holds no price.
pub fn next_nonce(ledger: &Ledger) -> u64 {
    ledger.rand_price().map_or(1, |p| p.nonce.saturating_add(1))
}

/// The state half of an update, with no signature work: the gate and the nonce. What the mempool
/// asks at every tip — once another update has taken this nonce, this one can never apply.
pub fn check_price_open(ledger: &Ledger, nonce: u64) -> Result<(), TxError> {
    if ledger.fees().usd_subsidy().is_none() {
        return Err(NO_USD_SUBSIDY);
    }
    let expected = next_nonce(ledger);
    if nonce != expected {
        return Err(PriceError::BadNonce { expected, got: nonce }.into());
    }
    Ok(())
}

/// `SetRandPrice`'s rules, cheap before expensive: the gate and the nonce
/// ([`check_price_open`]), a positive price, the per-update band — `old/2 ≤ new ≤ 2·old`, exact
/// (`2·new ≥ old`, no rounding), when an old price exists — and then the validator set's vote over
/// [`set_rand_price_message`] exactly as an admission's ([`check_votes`]).
pub fn check_set_price(ledger: &Ledger, price: u64, nonce: u64, votes: &[(PublicKey, Signature)]) -> Result<(), TxError> {
    check_price_open(ledger, nonce)?;
    if price == 0 {
        return Err(PriceError::ZeroPrice.into());
    }
    if let Some(old) = ledger.rand_price() {
        let (old, new) = (u128::from(old.price_micros_per_rand), u128::from(price));
        if new * 2 < old || new > old * 2 {
            return Err(PriceError::OutOfBand { old: old as u64, new: price }.into());
        }
    }
    let message = set_rand_price_message(&ledger.signing_domain().genesis, price, nonce);
    check_votes(ledger, &message, votes).map_err(|f| TxError::from(PriceError::from(f)))
}

/// The apply step, in lockstep with [`check_set_price`]: re-checked against this very state, then
/// the one write — the price, the height of the block applying it, and the nonce.
pub(super) fn apply_set_price(ledger: &mut Ledger, price: u64, nonce: u64, votes: &[(PublicKey, Signature)]) -> Result<(), TxError> {
    check_set_price(ledger, price, nonce, votes)?;
    let height = ledger.height();
    ledger.set_rand_price(Some(RandPrice { price_micros_per_rand: price, set_at_height: height, nonce }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::Keypair;
    use crate::ledger::fees::{FeesConfig, UsdSubsidy};
    use crate::ledger::staking::MIN_STAKE;
    use crate::ledger::ValidatorEntry;
    use crate::notes::{ShieldedAddress, KEM_EK_BYTES};
    use crate::types::{Action, Transaction};
    use std::collections::BTreeMap;

    const CHAIN: u64 = 7;

    fn key(i: u8) -> Keypair {
        Keypair::from_seed([i; 32]).unwrap()
    }

    fn this_chain() -> Hash {
        Hash::digest(b"this chain")
    }

    fn usd() -> UsdSubsidy {
        UsdSubsidy { usd_micros_per_sealed_block: 4_791, max_subsidy_per_block: 300_000_000, price_max_age_blocks: 100, initial_price_micros: Some(150_000) }
    }

    /// Four validators of `MIN_STAKE` at height 5, signing under `this_chain()`, with the
    /// `usd_subsidy` section (and the genesis price 0.15 $/RAND at height 0) or without it.
    fn chain(section: bool) -> (Vec<Keypair>, Ledger) {
        let vals: Vec<Keypair> = (1..=4u8).map(key).collect();
        let register: BTreeMap<Address, ValidatorEntry> = vals
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let e = ValidatorEntry {
                    public_key: k.public_key().clone(),
                    stake: MIN_STAKE,
                    pending: Vec::new(),
                    rewards: 0,
                    payout: ShieldedAddress { pk: [i as u32; 8], kem_ek: vec![i as u8; KEM_EK_BYTES] },
                    nonce: 0,
                    activation_epoch: 0,
                };
                (k.address(), e)
            })
            .collect();
        let mut l = Ledger::new(CHAIN, [11; 8], register, &StubExecutor);
        l.set_height(5);
        l.set_signing_domain(crate::types::SigningDomain::v1(this_chain()));
        if section {
            l.set_fees(FeesConfig { usd_subsidy: Some(usd()), ..FeesConfig::default() });
            l.set_rand_price(Some(RandPrice { price_micros_per_rand: 150_000, set_at_height: 0, nonce: 0 }));
        }
        (vals, l)
    }

    fn signed_votes(genesis: &Hash, price: u64, nonce: u64, voters: &[&Keypair]) -> Vec<(PublicKey, Signature)> {
        let m = set_rand_price_message(genesis, price, nonce);
        let mut v: Vec<(PublicKey, Signature)> = voters.iter().map(|k| (k.public_key().clone(), k.sign(m.as_bytes()))).collect();
        v.sort_by_key(|(k, _)| k.address());
        v
    }

    fn set_tx(price: u64, nonce: u64, voters: &[&Keypair]) -> Transaction {
        Transaction {
            chain_id: CHAIN,
            bundle: None,
            action: Action::SetRandPrice { price_micros_per_rand: price, nonce, votes: signed_votes(&this_chain(), price, nonce, voters) },
        }
    }

    fn price_err(e: TxError) -> PriceError {
        match e {
            TxError::Price(p) => p,
            other => panic!("not a price error: {other:?}"),
        }
    }

    /// A quorum's vote applies: the price, the applying block's height and the nonce are stored,
    /// the state root moves, and the next update needs nonce 2.
    #[test]
    fn a_quorum_sets_the_price_at_the_applying_height() {
        let (vals, mut l) = chain(true);
        let before = l.state_root();
        let supply = l.supply();
        let tx = set_tx(200_000, 1, &[&vals[0], &vals[1], &vals[2]]);
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        l.apply_tx(&tx, &vals[0].address(), &StubExecutor).unwrap();
        assert_eq!(l.rand_price(), Some(&RandPrice { price_micros_per_rand: 200_000, set_at_height: 5, nonce: 1 }));
        assert_ne!(l.state_root(), before, "the price is in the root under the section");
        assert_eq!(next_nonce(&l), 2);
        assert_eq!(price_err(l.validate(&tx, &StubExecutor).unwrap_err()), PriceError::BadNonce { expected: 2, got: 1 }, "never twice");
        assert_eq!(l.supply(), supply, "fee-less: no fee, no mint, no burn");
    }

    /// Below quorum, a non-validator voter, duplicate and unsorted voters, a vote for another
    /// chain, price or nonce: each refused by name, nothing written.
    #[test]
    fn the_vote_must_be_a_quorum_of_the_voting_set_in_canonical_order() {
        let (vals, l) = chain(true);
        let two = set_tx(200_000, 1, &[&vals[0], &vals[1]]);
        assert_eq!(
            price_err(l.validate(&two, &StubExecutor).unwrap_err()),
            PriceError::NoQuorum { weight: 2 * MIN_STAKE as u128, total: 4 * MIN_STAKE as u128 }
        );
        let outsider = key(9);
        let with_outsider = set_tx(200_000, 1, &[&vals[0], &vals[1], &outsider]);
        assert_eq!(price_err(l.validate(&with_outsider, &StubExecutor).unwrap_err()), PriceError::VoterNotInSet(outsider.address()));

        let mut dup = set_tx(200_000, 1, &[&vals[0], &vals[1], &vals[2]]);
        let Action::SetRandPrice { votes, .. } = &mut dup.action else { unreachable!() };
        let first = votes[0].clone();
        votes.insert(0, first);
        assert_eq!(price_err(l.validate(&dup, &StubExecutor).unwrap_err()), PriceError::VoteOrder, "a voter twice");
        let mut unsorted = set_tx(200_000, 1, &[&vals[0], &vals[1], &vals[2]]);
        let Action::SetRandPrice { votes, .. } = &mut unsorted.action else { unreachable!() };
        votes.swap(0, 1);
        assert_eq!(price_err(l.validate(&unsorted, &StubExecutor).unwrap_err()), PriceError::VoteOrder);

        // Signed for another genesis, another price, another nonce: a vote that does not count.
        let quorum = [&vals[0], &vals[1], &vals[2]];
        for (genesis, price, nonce) in [(Hash::digest(b"another chain"), 200_000, 1), (this_chain(), 200_001, 1), (this_chain(), 200_000, 2)] {
            let tx = Transaction {
                chain_id: CHAIN,
                bundle: None,
                action: Action::SetRandPrice { price_micros_per_rand: 200_000, nonce: 1, votes: signed_votes(&genesis, price, nonce, &quorum) },
            };
            assert!(matches!(price_err(l.validate(&tx, &StubExecutor).unwrap_err()), PriceError::BadVote(_)), "{genesis:?} {price} {nonce}");
        }
        let empty = Transaction { chain_id: CHAIN, bundle: None, action: Action::SetRandPrice { price_micros_per_rand: 200_000, nonce: 1, votes: vec![] } };
        assert_eq!(price_err(l.validate(&empty, &StubExecutor).unwrap_err()), PriceError::VoteCount { got: 0, max: 4 });
        let mut scratch = l.clone();
        assert!(scratch.apply_tx(&two, &vals[0].address(), &StubExecutor).is_err());
        assert_eq!(scratch, l, "a refused update writes nothing");
    }

    /// Wrong nonce, zero price, and the band [old/2, old×2] (exact at both edges); with no old
    /// price any positive price is the first.
    #[test]
    fn the_nonce_the_zero_price_and_the_band_are_enforced() {
        let (vals, l) = chain(true);
        let q = [&vals[0], &vals[1], &vals[2]];
        assert_eq!(price_err(l.validate(&set_tx(200_000, 2, &q), &StubExecutor).unwrap_err()), PriceError::BadNonce { expected: 1, got: 2 });
        assert_eq!(price_err(l.validate(&set_tx(200_000, 0, &q), &StubExecutor).unwrap_err()), PriceError::BadNonce { expected: 1, got: 0 });
        assert_eq!(price_err(l.validate(&set_tx(0, 1, &q), &StubExecutor).unwrap_err()), PriceError::ZeroPrice);
        assert_eq!(l.validate(&set_tx(75_000, 1, &q), &StubExecutor), Ok(()), "exactly half");
        assert_eq!(l.validate(&set_tx(300_000, 1, &q), &StubExecutor), Ok(()), "exactly double");
        assert_eq!(price_err(l.validate(&set_tx(74_999, 1, &q), &StubExecutor).unwrap_err()), PriceError::OutOfBand { old: 150_000, new: 74_999 });
        assert_eq!(price_err(l.validate(&set_tx(300_001, 1, &q), &StubExecutor).unwrap_err()), PriceError::OutOfBand { old: 150_000, new: 300_001 });

        // No genesis price: the first update is any positive price, at nonce 1.
        let (vals, mut l) = chain(true);
        l.set_rand_price(None);
        let tx = set_tx(1, 1, &[&vals[0], &vals[1], &vals[2]]);
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        l.apply_tx(&tx, &vals[3].address(), &StubExecutor).unwrap();
        assert_eq!(l.rand_price().unwrap().price_micros_per_rand, 1);
    }

    /// A chain without the section refuses the action by name and keeps its root byte for byte:
    /// the price is not in it, and a price left on such a ledger would change nothing.
    #[test]
    fn without_the_section_the_action_is_refused_and_the_root_is_untouched() {
        let (vals, l) = chain(false);
        let tx = set_tx(200_000, 1, &[&vals[0], &vals[1], &vals[2]]);
        assert_eq!(l.validate(&tx, &StubExecutor), Err(NO_USD_SUBSIDY));
        let mut scratch = l.clone();
        assert_eq!(scratch.apply_tx(&tx, &vals[0].address(), &StubExecutor), Err(NO_USD_SUBSIDY));
        assert_eq!(scratch, l);
        // The root without the section ignores the price field entirely.
        let root = l.state_root();
        let mut stray = l.clone();
        stray.set_rand_price(Some(RandPrice { price_micros_per_rand: 1, set_at_height: 0, nonce: 0 }));
        assert_eq!(stray.state_root(), root, "absent section, byte-identical root");
        // And under the section the wrapper is exactly H("rand-state-price-1", inner ‖ price_root).
        let (_, on) = chain(true);
        let mut inner = on.clone();
        inner.set_fees(FeesConfig::default());
        let mut buf = inner.state_root().as_bytes().to_vec();
        buf.extend_from_slice(price_root(on.rand_price()).as_bytes());
        assert_eq!(on.state_root(), Hash::digest_domain(b"rand-state-price-1", &buf));
        let mut none = on.clone();
        none.set_rand_price(None);
        assert_ne!(none.state_root(), on.state_root(), "no price and a price commit apart");
    }

    #[test]
    fn freshness_is_inclusive_of_the_max_age() {
        let p = RandPrice { price_micros_per_rand: 1, set_at_height: 10, nonce: 1 };
        assert!(p.fresh_at(10, 5) && p.fresh_at(15, 5));
        assert!(!p.fresh_at(16, 5));
        assert!(p.fresh_at(3, 0), "a height below the set height saturates to age 0");
    }
}
