//! Admission control for arriving transactions: what this node has already decided about, and how
//! fast one peer may make it decide.
//!
//! Both pieces exist because verifying a bundle's STARK costs ~20 ms *on the consensus loop*. The
//! [`RefusedCache`] answers a transaction this node has already refused for free, and
//! [`PeerLimiter`] bounds how many verifications a single peer can ask for per second. Neither is
//! consensus: a cached verdict only ever refuses what `Ledger::validate` would refuse anyway, and a
//! throttled peer's transaction is dropped by *this* node, not judged invalid.

use crate::mempool::MempoolError;
use crate::network::{GossipId, MessageAcceptance};
use shrugg_core::{Hash, Transaction, TxError};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;
use tokio::sync::oneshot;

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
    // The aggregation register's verdicts, split like `Staking`'s: the byte-verdicts (and the
    // ones against genesis-pinned constants) are cacheable, the register's state is not. A
    // signature is over the transaction's own fields against the entry's key — and an address
    // *is* its key's address, so no re-registration can ever make a bad signature a good one.
    // `UnregisteredShape`/`CoveredShapeMismatch`/`CoveredGuestMismatch` judge the covered
    // bundles against the admitted shapes, which are genesis constants. `CoverNotABundle` is a
    // statement about a *committed* — finalised, immutable — transaction's shape, and
    // `CoverSealed` one about committed history, which only ever accumulates. Everything
    // else (`UnknownAggregator`, `Unbonding`, `BadNonce`, the payout's `CommitmentExists`,
    // `UnknownCover`, `CoverOutsideWindow`, `CoverStoreCorrupt`, the register actions' own
    // verdicts) moves with this node's state and stays out.
    if let TxError::Aggregation(a) = e {
        use shrugg_core::ledger::aggregation::AggregationError as A;
        return matches!(
            a,
            A::BadSignature
                | A::EmptyCoverSet
                | A::TooManyCovers { .. }
                | A::DuplicateCover(_)
                | A::UnregisteredShape(_)
                | A::CoveredShapeMismatch { .. }
                | A::CoveredGuestMismatch(_)
                | A::CoverNotABundle(_)
                | A::CoverSealed(_)
        );
    }
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
            // The aggregate action's wire cap is a byte length, and its proof's verdicts are
            // against genesis-pinned artifacts (the registered shapes and the aggregate
            // program), exactly `InvalidBundleProof`'s argument.
            | TxError::AggregateTooLarge(_)
            | TxError::InvalidAggregateProof(_)
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

/// How many proof verifications may run on blocking workers at once.
///
/// Four, against a machine that also runs the consensus loop, RocksDB and the RPC server: a warm
/// bundle verification is ~20 ms of pure CPU, so four of them saturate four cores and no more. The
/// number is a *concurrency* bound, not a throughput target — the queue below is what absorbs a
/// burst.
pub const MAX_VERIFY_IN_FLIGHT: usize = 4;

/// How many transactions may be waiting for one of those slots.
///
/// Sized against gossipsub's validation window rather than against memory: a message stays in
/// gossipsub's cache for `history_length` heartbeats (5 × 500 ms = 2.5 s), and a verdict later than
/// that reports into nothing. At ~20 ms a verification and four at a time, 64 queued is ~320 ms of
/// work — comfortably inside the window even when every proof is cold. Deeper would only buy
/// verdicts nobody can act on; the 65th transaction is shed with an `Ignore`, which an honest peer
/// re-gossips on its next heartbeat.
pub const MAX_VERIFY_QUEUE: usize = 64;

/// What this node has decided to tell gossipsub about one delivered message.
///
/// libp2p's own [`MessageAcceptance`] derives `Debug` and nothing else — no `Clone`, no `PartialEq`
/// — so it can be neither compared in a test nor carried beside a queued transaction. This is that
/// enum with the three derives the decision path needs; it converts into libp2p's at the single
/// boundary where the verdict leaves this node ([`crate::network::NetworkHandle::report_validation`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acceptance {
    /// Valid as far as this node can tell: deliver it onward.
    Accept,
    /// This message's *bytes* are bad, and the forwarder wears the penalty.
    Reject,
    /// Not forwarded, nobody penalised — the refusal is about this node, not about the message.
    Ignore,
}

impl From<Acceptance> for MessageAcceptance {
    fn from(a: Acceptance) -> MessageAcceptance {
        match a {
            Acceptance::Accept => MessageAcceptance::Accept,
            Acceptance::Reject => MessageAcceptance::Reject,
            Acceptance::Ignore => MessageAcceptance::Ignore,
        }
    }
}

/// Who is waiting on a verification, and what has to happen when it lands.
pub enum VerifySource {
    /// Gossip: the verdict decides the message's acceptance, so the transaction is propagated only
    /// once it has verified here.
    Gossip(GossipId),
    /// RPC: the verdict is the caller's answer, and an accepted transaction is broadcast.
    Rpc(oneshot::Sender<Result<Hash, MempoolError>>),
}

/// One finished verification, on its way back to the node loop.
pub struct Verdict {
    pub tx: Transaction,
    pub result: Result<(), TxError>,
    pub source: VerifySource,
}

/// What to do with one gossip message, decided without touching the pool or a proof.
#[derive(Debug, PartialEq, Eq)]
pub enum GossipOutcome {
    Report(Acceptance),
    Verify,
}

impl GossipOutcome {
    /// A consensus or status message. Neither is validated at the application level — a proposal's
    /// verification stays on the consensus loop, and a status is three fields — so both are
    /// accepted at once, exactly as they were before `validate_messages()` was turned on.
    pub fn for_consensus() -> GossipOutcome {
        GossipOutcome::Report(Acceptance::Accept)
    }

    /// `bucket` is the **forwarding** peer's allowance (`node::Peer::tx_bucket`, looked up by
    /// `GossipId.propagation_source`), and `None` for an RPC submission, which is not metered.
    /// `queued` is the current verification queue depth.
    ///
    /// The order is the point. The refused cache first, because it is a hash lookup and because a
    /// peer flooding one known-bad transaction must not spend an allowance it could have used on a
    /// good one. Then the bucket, so a burst is shed before anything reads the ledger. Then the
    /// queue depth. Everything more expensive than this — `Mempool::precheck`, which hashes a
    /// bridge attestation, and the proof itself — happens only after a `Verify`.
    pub fn for_transaction(
        tx: &Transaction,
        bucket: Option<&mut TokenBucket>,
        refused: &mut RefusedCache,
        limiter: &PeerLimiter,
        queued: usize,
        now: Instant,
    ) -> GossipOutcome {
        if refused.get(&tx.hash()).is_some() {
            return GossipOutcome::Report(Acceptance::Reject);
        }
        if let Some(b) = bucket {
            if !limiter.allow(b, now) {
                return GossipOutcome::Report(Acceptance::Ignore);
            }
        }
        if queued >= MAX_VERIFY_QUEUE {
            return GossipOutcome::Report(Acceptance::Ignore);
        }
        GossipOutcome::Verify
    }
}

/// The acceptance a verdict earns, and the cache entry it leaves behind.
///
/// `Accept` even when the pool then refuses the transaction as a conflict: it verified, so
/// propagating it is right — some other node's pool may have room for it.
pub fn acceptance_for(result: &Result<(), TxError>, hash: Hash, refused: &mut RefusedCache) -> Acceptance {
    match result {
        Ok(()) => Acceptance::Accept,
        Err(e) if is_permanent(e) => {
            refused.insert(hash, e.clone());
            Acceptance::Reject
        }
        Err(_) => Acceptance::Ignore,
    }
}

/// The same rule one level up, for a refusal that came from the pool's pre-screen rather than from
/// a verification: a `Duplicate`, a `Conflict` or a `Full` pool is a statement about *this node*
/// and never about the message, so it is an `Ignore` and is not cached. A `TxError` the pre-screen
/// found — an oversized attestation, a spent nullifier — is judged exactly as a verdict's is.
pub fn acceptance_for_pool(e: &MempoolError, hash: Hash, refused: &mut RefusedCache) -> Acceptance {
    match e {
        MempoolError::Invalid(t) => acceptance_for(&Err(t.clone()), hash, refused),
        MempoolError::Duplicate
        | MempoolError::Conflict(_)
        | MempoolError::AttestationConflict(_)
        | MempoolError::Full => Acceptance::Ignore,
    }
}

/// The error an RPC submitter hears for a decision [`GossipOutcome::for_transaction`] took before
/// any verification ran. Both are errors `Mempool::insert` already produced, because `docs/rpc.md`
/// quotes its messages:
///
/// - `Reject` can only be the refused cache — the RPC path passes no bucket and a full queue is an
///   `Ignore` — so the answer is the verdict the ledger gave this transaction the first time.
/// - `Ignore` is the full verify queue, which is a "not now": `Full` is what that already says to a
///   client, and it is the one refusal here worth retrying.
pub fn rpc_refusal(a: Acceptance, hash: &Hash, refused: &RefusedCache) -> MempoolError {
    match (a, refused.get(hash)) {
        (Acceptance::Reject, Some(e)) => MempoolError::Invalid(e.clone()),
        // Unreachable as long as `for_transaction` only rejects on a cache hit; `Full` rather than
        // a panic, because an RPC caller is owed an answer either way.
        _ => MempoolError::Full,
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

    /// The aggregate verdicts, split: the byte-verdicts and the genesis-constant ones are
    /// cached, the register's and the window's state is not.
    #[test]
    fn aggregate_verdicts_are_cached_only_when_they_are_about_the_bytes() {
        use shrugg_core::ledger::aggregation::AggregationError as A;
        let agg = |a: A| TxError::Aggregation(a);
        for e in [
            agg(A::BadSignature),
            agg(A::EmptyCoverSet),
            agg(A::TooManyCovers { got: 4, max: 3 }),
            agg(A::DuplicateCover(h(1))),
            agg(A::UnregisteredShape(h(2))),
            agg(A::CoveredShapeMismatch { cover: h(3), field: "tier", expected: 14, actual: 15 }),
            agg(A::CoveredGuestMismatch(h(4))),
            agg(A::CoverNotABundle(h(5))),
            agg(A::CoverSealed(h(5))),
            TxError::AggregateTooLarge(9_000_000),
            TxError::InvalidAggregateProof(ConfidentialError::MalformedProof),
        ] {
            assert!(is_permanent(&e), "{e} is a statement about the bytes or genesis constants");
        }
        for e in [
            agg(A::UnknownAggregator(Address([9; 32]))),
            agg(A::Unbonding(Address([9; 32]))),
            agg(A::BadNonce { expected: 1, actual: 0 }),
            agg(A::UnknownCover(h(6))),
            agg(A::CoverOutsideWindow { cover: h(7), block: 1, head: 300 }),
            agg(A::CoverStoreCorrupt(h(8))),
            // The covered-carrying path's signpost is not a verdict on the transaction at all.
            TxError::AggregateNeedsCovered,
        ] {
            assert!(!is_permanent(&e), "{e} depends on state and must not be cached");
        }
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
