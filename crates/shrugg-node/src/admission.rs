//! Admission control for arriving transactions: what this node has already decided about, and how
//! fast one peer may make it decide.
//!
//! Both pieces exist because verifying a bundle's STARK costs ~20 ms *on the consensus loop*. The
//! [`RefusedCache`] answers a transaction this node has already refused for free, and
//! [`PeerLimiter`] bounds how many verifications a single peer can ask for per second. Neither is
//! consensus: a cached verdict only ever refuses what `Ledger::validate` would refuse anyway, and a
//! throttled peer's transaction is dropped by *this* node, not judged invalid.

use shrugg_core::{Hash, TxError};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// How many refused hashes to remember. The pool itself holds 10 000, so a flood of distinct bad
/// proofs cannot evict the entries that are actually saving work.
pub const REFUSED_CACHE_ENTRIES: usize = 8192;

/// Gossiped transactions one peer may submit back to back.
pub const PEER_TX_BURST: u32 = 16;

/// And the rate it recovers them at. The chain commits about one transaction a second, so 4/s per
/// peer is far above any honest peer's share of it.
pub const PEER_TX_PER_SEC: f64 = 4.0;

/// Transaction hashes whose verification already failed for a reason that is a statement about
/// the transaction's bytes, not about this node's state. Bounded and FIFO: a refused hash is
/// looked up once, on arrival, so recency ordering buys nothing an insertion order does not.
pub struct RefusedCache {
    seen: HashMap<Hash, TxError>,
    order: VecDeque<Hash>,
    cap: usize,
}

impl RefusedCache {
    pub fn new(cap: usize) -> RefusedCache {
        RefusedCache { seen: HashMap::new(), order: VecDeque::new(), cap }
    }

    pub fn get(&self, h: &Hash) -> Option<&TxError> {
        self.seen.get(h)
    }

    /// No-op for a verdict [`is_permanent`] refuses, so a caller cannot poison the cache by
    /// forwarding the wrong error.
    pub fn insert(&mut self, h: Hash, e: TxError) {
        if !is_permanent(&e) || self.cap == 0 {
            return;
        }
        // A hash already held keeps its place in the queue: the entry is not new, only its error
        // is, so re-arriving copies of one bad transaction must not push the queue around.
        if self.seen.insert(h, e).is_some() {
            return;
        }
        self.order.push_back(h);
        while self.order.len() > self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Is this verdict a function of the transaction's bytes alone?
///
/// `UnknownAnchor`, `TimeOutOfWindow`, `Spent`, `CommitmentExists`, `UnknownProgram`,
/// `MinterNotValidator`, `Bridge`, `AttestAssetMismatch`, `Staking` and `UnknownProposer` are
/// all statements about *this node's state at this moment*: a node one block behind would
/// otherwise poison itself against transactions that are about to be valid.
///
/// Two arms are worth spelling out, because neither is literally a property of the bytes on their
/// own — each is a property of the bytes *against a constant that cannot change under this cache*:
///
/// - `WrongChain` compares against `Ledger::chain_id`, which is fixed at genesis and cannot move
///   without a new chain, and
/// - `InvalidBundleProof` (like `InvalidProof`) is a verdict against `hc_bundle` — also a genesis
///   constant — under the executor's constraint set and FRI profile, which are compiled in. A
///   constraint-set change is a hard fork and a new binary.
///
/// A cache entry only ever has to outlive the *process*, and none of those constants changes inside
/// one. Anything genuinely per-node-state is what the paragraph above refuses.
///
/// Everything outside the allowlist is treated as state, so a `TxError` added later is not cached
/// until someone decides it may be. Kept out deliberately, for the record, are the chain's own
/// configuration and this build's reach: `FaucetDisabled` and `ConfidentialDisabled` (genesis flags
/// the node can also toggle at runtime), `FeeTooLow` (a floor a fee market would make dynamic),
/// `UnsupportedAsset`, `UnsupportedBurn` and `UnsupportedAction` (the phase this release has
/// shipped, so a rolling upgrade makes them valid mid-process — an operator restarts the binary, but
/// the transaction was never about *bytes*), and `Overflow` (arithmetic over amounts this node
/// holds). `MintTooLarge` is the closest call: `FAUCET_MAX_UNITS` is a compile-time constant, so it
/// would qualify on the same argument as `WrongChain` — it stays out because a faucet cap is a
/// policy knob, unlike a chain id or a guest commitment, and a mint is cheap to re-refuse; nothing
/// is gained by caching it and the conservative side of this line is the safe one.
pub fn is_permanent(e: &TxError) -> bool {
    matches!(
        e,
        // The proofs and the digest are over the transaction's own fields.
        TxError::InvalidProof(_)
            | TxError::InvalidBundleProof(_)
            | TxError::BadDigest
            | TxError::BadMintSignature
            | TxError::BadProgram(_)
            // The chain id is a per-chain constant, and the shape of an action — bundle or no
            // bundle — is on the wire.
            | TxError::WrongChain { .. }
            | TxError::MissingBundle
            | TxError::ActionCarriesBundle(_)
            // Byte lengths, every one of them.
            | TxError::EnvelopeTooLarge
            | TxError::ProofTooLarge
            | TxError::AttestationTooLarge
            // fix-sync-stall's: the whole transaction is bigger than a block. A byte length is a
            // function of the bytes, and `validate` refuses it at step 1 before anything about
            // this node's state is consulted, so it is as permanent as a size cap gets.
            | TxError::TransactionTooLarge(_)
            | TxError::ProgramTooLarge
            // A transaction colliding with *itself* — no other transaction and no state involved.
            | TxError::DuplicateNullifierInBundle
            | TxError::DuplicateCommitmentInBundle
            // A burn's asset-bundle arithmetic is entirely within the transaction, as is the
            // recipient an attestation names against the one the action carries.
            | TxError::BurnAssetMismatch { .. }
            | TxError::BurnAssetBundleFee(_)
            | TxError::BurnAmountMismatch { .. }
            | TxError::BridgeRecipientMismatch
    )
}

/// One peer's allowance. Lives on `node::Peer`, which the node already keys by `PeerId` and already
/// drops on `PeerDisconnected` — so this type holds no peer id, no map and no lifetime rule of its
/// own. `None` for the tokens means "not yet used": a fresh bucket starts full.
///
/// **It is `Copy`, so spend it in place.** `PeerLimiter::allow` takes `&mut TokenBucket` and writes
/// the remaining tokens back into it: call it on the field the peer table owns
/// (`allow(&mut peer.tx_bucket, now)`), never on a local copy of it (`let mut b = peer.tx_bucket`),
/// or every call sees a full bucket and the limit does nothing. `Copy` is here because a bucket is
/// two words and `node::Peer` is `Clone`; it is not an invitation to move one around.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokenBucket {
    tokens: Option<f64>,
    last: Option<Instant>,
}

/// The policy over those buckets: a token bucket on gossiped transaction submissions, metered
/// against the peer that **forwarded** the message (`GossipId.propagation_source`), never the peer
/// that authored it — `NetworkEvent::Gossip.from` is the author and may be a peer we hold no
/// connection to at all (see `node::Peer`'s doc comment, and `connected_peers` in `shrugg_status`).
/// RPC submissions are not metered: that port is the operator's own and is bounded by
/// `rpc::RPC_MAX_BODY_BYTES`.
pub struct PeerLimiter {
    burst: f64,
    per_sec: f64,
}

impl PeerLimiter {
    pub fn new(burst: u32, per_sec: f64) -> PeerLimiter {
        PeerLimiter { burst: burst as f64, per_sec }
    }

    /// Spend one token from `bucket`, refilling it first. `false` means "over the limit right now".
    ///
    /// The refill is computed from the elapsed time on every call, so there is no timer and no
    /// background task: a bucket nobody touches for an hour is simply full when it is next asked.
    pub fn allow(&self, bucket: &mut TokenBucket, now: Instant) -> bool {
        let available = match (bucket.tokens, bucket.last) {
            (Some(tokens), Some(last)) => {
                let elapsed = now.saturating_duration_since(last).as_secs_f64();
                (tokens + elapsed * self.per_sec).min(self.burst)
            }
            // Never used, so nothing has been spent: full, whenever `now` is.
            _ => self.burst,
        };
        bucket.last = Some(now);
        if available < 1.0 {
            bucket.tokens = Some(available);
            return false;
        }
        bucket.tokens = Some(available - 1.0);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shrugg_core::confidential::ConfidentialError;
    use shrugg_core::Address;
    use std::time::Duration;

    fn h(n: u8) -> Hash {
        Hash::digest(&[n])
    }

    #[test]
    fn the_refused_cache_is_bounded_and_evicts_oldest_first() {
        let mut c = RefusedCache::new(3);
        for n in 0..3 {
            c.insert(h(n), TxError::BadDigest)
        }
        assert_eq!(c.len(), 3);
        assert!(c.get(&h(0)).is_some());
        c.insert(h(3), TxError::BadDigest);
        assert_eq!(c.len(), 3, "the cap holds");
        assert!(c.get(&h(0)).is_none(), "the oldest went first");
        assert!(c.get(&h(3)).is_some());
        // Re-inserting a hash already held does not grow the queue.
        c.insert(h(3), TxError::BadDigest);
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn only_a_verdict_about_the_bytes_is_cached() {
        // A bad proof is a bad proof on every node forever.
        for e in [
            TxError::BadDigest,
            TxError::InvalidProof(ConfidentialError::MalformedProof),
            TxError::InvalidBundleProof(ConfidentialError::MalformedProof),
            TxError::BadMintSignature,
            TxError::ProofTooLarge,
            TxError::EnvelopeTooLarge,
            TxError::TransactionTooLarge(9_000_000),
            TxError::DuplicateNullifierInBundle,
            TxError::WrongChain { expected: 7, actual: 8 },
        ] {
            assert!(is_permanent(&e), "{e} is a statement about the bytes");
        }
        // These are statements about this node's state right now. A node one block behind that
        // cached them would refuse transactions that are about to be valid — for good, since
        // nothing evicts on a state change.
        for e in [
            TxError::UnknownAnchor,
            TxError::TimeOutOfWindow { time: 3, height: 900 },
            TxError::Spent([1; 8]),
            TxError::CommitmentExists([2; 8]),
            TxError::UnknownProgram(Hash::ZERO),
            TxError::MinterNotValidator(Address([3; 32])),
        ] {
            assert!(!is_permanent(&e), "{e} depends on state and must not be cached");
        }
        // And the cache itself refuses one, so a wrong caller cannot poison it.
        let mut c = RefusedCache::new(4);
        c.insert(h(1), TxError::UnknownAnchor);
        assert_eq!(c.len(), 0);
    }

    /// The shipped policy, pinned: 8192 entries against a 10 000-transaction pool, and a burst of 16
    /// refilling at 4/s against a chain that commits about one transaction a second. Changing any of
    /// the three is a decision about how much work an unknown peer may cost this node, so it should
    /// break a test rather than a fleet.
    #[test]
    fn the_shipped_policy_is_the_one_the_plan_sized() {
        assert_eq!(REFUSED_CACHE_ENTRIES, 8192);
        assert_eq!(PEER_TX_BURST, 16);
        assert_eq!(PEER_TX_PER_SEC, 4.0);
        // And the constants are what the node's own limiter is built from: burst first, rate second.
        let l = PeerLimiter::new(PEER_TX_BURST, PEER_TX_PER_SEC);
        let mut b = TokenBucket::default();
        let t0 = Instant::now();
        for i in 0..PEER_TX_BURST {
            assert!(l.allow(&mut b, t0), "burst {i} of {PEER_TX_BURST}");
        }
        assert!(!l.allow(&mut b, t0), "and no more until it refills");
        assert!(l.allow(&mut b, t0 + Duration::from_millis(250)), "a quarter second is one token at 4/s");
    }

    #[test]
    fn the_peer_limiter_allows_a_burst_then_refills() {
        let l = PeerLimiter::new(4, 2.0);
        let mut b = TokenBucket::default();
        let t0 = Instant::now();
        for i in 0..4 {
            assert!(l.allow(&mut b, t0), "burst {i}")
        }
        assert!(!l.allow(&mut b, t0), "the bucket is empty");
        // Half a second at 2/s is one token.
        assert!(l.allow(&mut b, t0 + Duration::from_millis(500)));
        assert!(!l.allow(&mut b, t0 + Duration::from_millis(500)));
        // It never refills past the burst.
        assert!(l.allow(&mut b, t0 + Duration::from_secs(60)));
        for _ in 0..3 {
            assert!(l.allow(&mut b, t0 + Duration::from_secs(60)))
        }
        assert!(!l.allow(&mut b, t0 + Duration::from_secs(60)), "burst is the ceiling");
        // Buckets are per peer because the *peer table* is: a second peer's bucket is a second
        // `TokenBucket` on a second `node::Peer`, and a disconnected peer's goes with the entry.
        let mut other = TokenBucket::default();
        assert!(l.allow(&mut other, t0 + Duration::from_secs(60)), "an untouched bucket starts full");
        assert!(l.allow(&mut TokenBucket::default(), t0), "and so does a fresh one at any time");
    }
}
