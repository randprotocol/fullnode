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
use randprotocol_core::{Hash, Transaction, TxError};
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

/// Faucet mints (`rand_mint`, `NodeCommand::Mint`) this node will hand out back to back, and the
/// rate it recovers them at (node I4).
///
/// A faucet mint is fee-less, unsigned by any payer, and costs one pooled transaction per call —
/// so on chain 14, where the faucet is on and a bridge holds value behind it, an unthrottled
/// `rand_mint` on any reachable validator RPC is free pool pressure (the same audit-v3 faucet
/// exposure, now with something behind it). Eight back to back covers a demo or a test run
/// starting cold; one a second is well past any human's use of a faucet and far below what it
/// would take to crowd a 10 000-entry pool. The limit is **per process**, not per caller: the
/// RPC port has no peer identity to meter, and the resource being protected is this node's pool.
pub const FAUCET_MINT_BURST: u32 = 8;
/// See [`FAUCET_MINT_BURST`].
pub const FAUCET_MINT_PER_SEC: f64 = 1.0;

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

/// How many verified transaction hashes to remember. Same size as the refused cache and for the
/// same reason: the pool holds 10 000, so nothing the pool can still do — flood it with good
/// transactions or bad — evicts the entries that are saving work before their blocks arrive.
/// An entry evicted early costs one re-verification at apply and nothing else (audit v3, B5).
pub const VERIFIED_SET_ENTRIES: usize = 8192;

/// Transaction hashes whose proofs this node already verified, filled by the admission workers
/// when a verification succeeds (audit v3, B5). What the consensus loop reads at propose and at
/// a proposal's apply through [`randprotocol_core::VerifiedProofs`]: on a hit the ledger decodes
/// the proofs instead of re-verifying them.
///
/// Bounded and FIFO like the refused cache, and keyed on the transaction hash for the same
/// reason the whole scheme is sound: the hash binds the proof (`rand-txid-2` takes it by
/// digest, and the transaction binding covers the rest), so a stale entry can only ever say
/// "these exact bytes verified" — never vouch for a different transaction. An entry whose
/// transaction was then refused by the pool for a *state* reason (a lost conflict, a stale
/// anchor) is kept deliberately: the proof did verify, and the stateful half is re-checked at
/// apply either way.
pub struct VerifiedSet {
    seen: std::collections::HashSet<Hash>,
    order: VecDeque<Hash>,
    cap: usize,
}

impl VerifiedSet {
    pub fn new(cap: usize) -> VerifiedSet {
        VerifiedSet { seen: std::collections::HashSet::new(), order: VecDeque::new(), cap }
    }

    pub fn insert(&mut self, h: Hash) {
        if self.cap == 0 {
            return;
        }
        // A hash already held keeps its place in the queue: re-verifying one transaction must
        // not push the queue around (see `RefusedCache::insert`).
        if !self.seen.insert(h) {
            return;
        }
        self.order.push_back(h);
        while self.order.len() > self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }

    pub fn contains(&self, h: &Hash) -> bool {
        self.seen.contains(h)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

impl randprotocol_core::VerifiedProofs for VerifiedSet {
    fn contains(&self, tx: &Hash) -> bool {
        self.contains(tx)
    }
    fn is_empty(&self) -> bool {
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
/// `UnsupportedAction` (which modules a chain's genesis switched on — a statement about the chain,
/// not the transaction), and `Overflow` (arithmetic over amounts this node holds). `MintTooLarge`
/// is the closest call: `FAUCET_MAX_UNITS` is a compile-time constant, so it would qualify on the
/// same argument as `WrongChain` — it stays out because a faucet cap is a policy knob, unlike a
/// chain id or a guest commitment, and a mint is cheap to re-refuse; nothing is gained by caching
/// it and the conservative side of this line is the safe one.
///
/// `UnsupportedAsset` and `UnsupportedBurn` used to sit in that list, when they meant "a later
/// phase than this release". Since the hidden-asset bundle they mean something narrower, and they
/// are in the allowlist below: each is `Ledger::check_burn_shape` (or `check_asset_burn`) comparing
/// the bundle's own `burn_asset`/`burn_a`/`burn_r` against the *kind* of its own action — a token
/// burn field on an action that burns no token, RAND burned on an action that may not burn it, RAND
/// burned alongside a token burn. Both operands are the transaction's bytes and the rule reads
/// nothing else, so no registry, register, height or pool state can ever make the same bytes valid;
/// a node that is behind refuses them exactly as a node at the tip does. The same holds for
/// `Token(UnknownToken(0))`, the one `UnknownToken` that is a byte verdict: index 0 is RAND's, and
/// the registry can never hand it to a token (`TokenRegistry::new` starts at `FIRST_TOKEN_INDEX`
/// and `register` refuses rather than wraps at `u32::MAX`), so a burn, mint or rotation naming
/// token 0 is refused on every state forever. Every *other* index is state — a registration can
/// create it one block later — and stays out.
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
        use randprotocol_core::ledger::aggregation::AggregationError as A;
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
    // The RPL registry's verdicts, split the same way: only the ones a transaction's *own bytes*
    // decide are cacheable — the metadata rules (`BadName`, `BadSymbol`, `TooManyDecimals`), the
    // authority kind a registration may choose, a fixed-supply registration with no initial mint,
    // a zero amount, and a token index of 0 (RAND's, never a token's). Everything else is a
    // statement about this node's registry at this moment: `BadNonce`, `UnknownToken` of any other
    // index, `AlreadyRegistered`, `IndexMismatch`,
    // `SupplyOverflow`, `SupplyUnderflow`, `BridgedToken`, `Disabled`, `RegistrationFeeTooLow` and
    // `NotKeyAuthority` all move as blocks arrive, and a node one block behind would poison itself
    // against transactions that are about to be valid. `BridgedToken` is the subtle one: it reads
    // a token's authority, which a `SetAuthority` can rotate, so it is state like the rest.
    //
    // `BadSignature` is deliberately **not** here, unlike the staking and aggregation registers':
    // there the key is the address, so no state can turn a bad signature good, but a token's mint
    // authority is state — a `SetAuthority` hands it to another key — so the very same bytes are
    // refused before that rotation commits and accepted after it.
    if let TxError::Token(t) = e {
        use randprotocol_core::ledger::tokens::TokenError as T;
        return matches!(
            t,
            // Index 0 is RAND's and no registry state can ever make it a token (see above).
            T::UnknownToken(0)
                | T::BadName
                | T::BadSymbol
                | T::TooManyDecimals(_)
                | T::AuthorityNotAllowed
                | T::InitialMintRequired
                | T::ZeroAmount
                // Two byte lengths, like `TooManyDecimals` above: a `Key` authority's public key
                // and a mint recipient's `kem_ek`, each compared against a compile-time constant
                // and nothing else (core I-1). No state can make a wrong-length key right.
                | T::BadAuthorityKey { .. }
                | T::BadRecipientKey { .. }
        );
    }
    // The Dilithium2 co-signature's verdicts (bridge hardening B3). Every other bridge verdict
    // stays out: a digest's `Replay`, a guardian set's expiry and the registry's listings all move
    // with this node's state. Of the five PQ refusals only the three that are about the list's
    // own bytes are cached:
    //
    // - `PqIndexOrder` — the indices as written, and nothing else;
    // - `PqBadSignatureLength` — a byte length, like every other length above;
    // - `PqIndexOutOfRange` — the index against `n`, the size of the genesis PQ set, which no
    //   action changes (a payload-2 rotation moves the ECDSA set only; a PQ rotation is the
    //   deferred payload 3, and when it lands this arm must be revisited, as `WrongChain` would
    //   be if chain ids could move).
    //
    // `PqNoQuorum` also reads only the list's length and `n`, and `PqBadSignature` only the bytes,
    // the genesis keys and the chain id, so both would qualify on `InvalidBundleProof`'s argument —
    // they stay out on the conservative side of this line, like `MintTooLarge`: the quorum formula
    // is shared with the governance quorums a later PQ-set change would move, and re-refusing
    // either is cheap next to what a wrongly cached refusal costs (a relayer's mint censored on
    // this node until restart). `PqNoQuorum` is decided before any other attest check and
    // `PqBadSignature` only after a valid ECDSA quorum over an unconsumed digest.
    //
    // B1's `BadPauseSignature` is cached: it depends on the transaction's bytes alone. The ledger
    // checks the nonce first (`BadPauseNonce`, state, never cached) and the flag second, and only
    // then verifies the signature over `pause_message(tx.chain_id, nonce)` — built from the
    // transaction's own nonce and chain id — under the genesis `pause_key`, which no action
    // changes. So a signature that fails once fails at every tip. Caching it matters because a
    // `PauseMints` is bundle-less and fee-less: without the cache a peer could replay one bad
    // pause and buy a Dilithium2 verification per delivery for free (the per-peer token bucket
    // bounds the rate; this makes the repeats cost nothing). If a later action ever rotates the
    // pause key, this arm must move out, as `PqIndexOutOfRange` would with a PQ rotation.
    //
    // F1's `WrongDepositBlinding` is cached too: it compares the action's `r` with
    // `blake3("rand-deposit-r-1" ‖ mu)` of the action's own `attestation` bytes — no key, no
    // registry, no height — so the same bytes are refused at every tip.
    if let TxError::Bridge(b) = e {
        use randprotocol_core::bridge::BridgeError as B;
        return matches!(
            b,
            B::PqIndexOrder
                | B::PqIndexOutOfRange { .. }
                | B::PqBadSignatureLength { .. }
                | B::BadPauseSignature
                | B::WrongDepositBlinding
        );
    }
    matches!(
        e,
        // The proofs and the digest are over the transaction's own fields.
        TxError::InvalidProof(_)
            | TxError::InvalidBundleProof(_)
            | TxError::BadDigest
            | TxError::BadMintSignature
            // A mint's commitment is a function of its own bytes (`ledger::mint_commitment`).
            | TxError::MintCommitmentMismatch
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
            | TxError::TransactionTooLarge { .. }
            | TxError::ProgramTooLarge
            // The aggregate action's wire cap is a byte length, and its proof's verdicts are
            // against genesis-pinned artifacts (the registered shapes and the aggregate
            // program), exactly `InvalidBundleProof`'s argument.
            | TxError::AggregateTooLarge { .. }
            | TxError::InvalidAggregateProof(_)
            // A transaction colliding with *itself* — no other transaction and no state involved.
            | TxError::DuplicateNullifierInBundle
            | TxError::DuplicateCommitmentInBundle
            // A bundle's burn fields against its action's are entirely within the transaction
            // (the hidden-asset bundle's burn shape), as is the recipient an attestation names
            // against the one the action carries.
            | TxError::BurnAssetMismatch { .. }
            | TxError::BurnAmountMismatch { .. }
            | TxError::NonCanonicalRandBurn(_)
            // A burn field the action's kind may not carry: the bundle's own fields against its
            // own action's kind, nothing else read (see the doc comment).
            | TxError::UnsupportedAsset(_)
            | TxError::UnsupportedBurn(_)
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
/// connection to at all (see `node::Peer`'s doc comment, and `connected_peers` in `rand_status`).
/// RPC submissions are not metered: that port is the operator's own and is bounded by
/// `rpc::RpcState::max_body_bytes`.
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
    use randprotocol_core::confidential::ConfidentialError;
    use randprotocol_core::Address;
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
    fn the_verified_set_is_bounded_and_evicts_oldest_first() {
        let mut s = VerifiedSet::new(3);
        for n in 0..3 {
            s.insert(h(n));
        }
        assert_eq!(s.len(), 3);
        assert!(s.contains(&h(0)));
        s.insert(h(3));
        assert_eq!(s.len(), 3, "the cap holds");
        assert!(!s.contains(&h(0)), "the oldest went first");
        assert!(s.contains(&h(3)));
        // Re-inserting a hash already held keeps its place and does not grow the queue.
        s.insert(h(3));
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn only_a_verdict_about_the_bytes_is_cached() {
        // A bad proof is a bad proof on every node forever.
        for e in [
            TxError::BadDigest,
            TxError::InvalidProof(ConfidentialError::MalformedProof),
            TxError::InvalidBundleProof(ConfidentialError::MalformedProof),
            TxError::BadMintSignature,
            TxError::MintCommitmentMismatch,
            TxError::ProofTooLarge,
            TxError::EnvelopeTooLarge,
            TxError::TransactionTooLarge { size: 9_000_000, max: 4 << 20 },
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

    /// B3's co-signature verdicts: the list's own bytes (order, lengths) and its indices against
    /// the genesis PQ set's size are cached; the count and a failed verification are not, and no
    /// other bridge verdict is either.
    #[test]
    fn only_the_byte_level_pq_verdicts_are_cached() {
        use randprotocol_core::bridge::BridgeError as B;
        for b in [B::PqIndexOrder, B::PqIndexOutOfRange { index: 6, n: 6 }, B::PqBadSignatureLength { index: 4, len: 2419 }] {
            let e = TxError::Bridge(b);
            assert!(is_permanent(&e), "{e} is a statement about the list's bytes");
        }
        for b in [B::PqNoQuorum { have: 4, need: 5, n: 6 }, B::PqBadSignature { index: 0 }, B::Replay, B::WrongEmitter] {
            let e = TxError::Bridge(b);
            assert!(!is_permanent(&e), "{e} is kept out of the cache");
        }
    }

    /// Bridge hardening B1: every verdict of the cap and the brake but one is state — the day's
    /// counter, the pause flag, the pause nonce. None of those is cached: a deposit over today's
    /// cap is admissible tomorrow, a paused mint after the unpause.
    #[test]
    fn the_cap_and_pause_state_verdicts_are_never_cached() {
        use randprotocol_core::bridge::BridgeError as B;
        use randprotocol_core::ledger::tokens::TokenError as T;
        for b in [
            B::MintsPaused,
            B::Token(T::MintCapExceeded { cap: 10, minted_today: 10, amount: 1 }),
            B::NoPauseKey,
            B::AlreadyPaused,
            B::NotPaused,
            B::BadPauseNonce { expected: 1, got: 0 },
        ] {
            let e = TxError::Bridge(b);
            assert!(!is_permanent(&e), "{e} is state, not bytes");
        }
    }

    /// The one pause verdict that is about the bytes: a `PauseMints` whose signature fails under
    /// the genesis pause key over `pause_message(its own chain id, its own nonce)` fails at every
    /// tip, so it is cached — a replayed bad pause, bundle-less and fee-less, costs no second
    /// Dilithium2 verification. (The ledger reaches it only after the nonce and flag checks,
    /// which stay uncached: `bridge_gov`'s tests pin that order.)
    /// F1's blinding verdict is about the bytes alone — the action's `r` against a hash of its own
    /// `attestation` field, no key, no state — so no tip can ever admit the same transaction and
    /// it is cached like a byte length.
    #[test]
    fn a_wrong_deposit_blinding_is_a_byte_verdict_and_is_cached() {
        use randprotocol_core::bridge::BridgeError as B;
        let e = TxError::Bridge(B::WrongDepositBlinding);
        assert!(is_permanent(&e), "{e} depends on the transaction's bytes alone");
    }

    #[test]
    fn a_bad_pause_signature_is_a_byte_verdict_and_is_cached() {
        use randprotocol_core::bridge::BridgeError as B;
        let e = TxError::Bridge(B::BadPauseSignature);
        assert!(is_permanent(&e), "{e} depends on the transaction's bytes alone");
        let mut c = RefusedCache::new(4);
        c.insert(h(7), e.clone());
        assert_eq!(c.get(&h(7)), Some(&e), "the cache keeps it");
    }

    /// The aggregate verdicts, split: the byte-verdicts and the genesis-constant ones are
    /// cached, the register's and the window's state is not.
    #[test]
    fn aggregate_verdicts_are_cached_only_when_they_are_about_the_bytes() {
        use randprotocol_core::ledger::aggregation::AggregationError as A;
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
            TxError::AggregateTooLarge { size: 9_000_000, max: 2 << 20 },
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

    /// The RPL verdicts, split the same way the aggregate's are: a refusal the transaction's own
    /// bytes decide is cacheable, a refusal about this node's registry is not — and the registry
    /// moves with every block, so caching one would make a node one block behind refuse
    /// transactions that are about to be valid, for good.
    #[test]
    fn token_verdicts_are_cached_only_when_they_are_about_the_bytes() {
        use randprotocol_core::ledger::tokens::TokenError as T;
        let tok = |t: T| TxError::Token(t);
        for e in [
            tok(T::BadName),
            tok(T::BadSymbol),
            tok(T::TooManyDecimals(10)),
            tok(T::AuthorityNotAllowed),
            tok(T::InitialMintRequired),
            tok(T::ZeroAmount),
        ] {
            assert!(is_permanent(&e), "{e} is a statement about the bytes");
        }
        for e in [
            tok(T::Disabled),
            tok(T::UnknownToken(3)),
            tok(T::BridgedToken(3)),
            tok(T::SupplyUnderflow),
            tok(T::SupplyOverflow),
            tok(T::BadNonce { expected: 1, got: 0 }),
            tok(T::IndexMismatch { expected: 4, got: 3 }),
            tok(T::NotKeyAuthority(3)),
            tok(T::RegistrationFeeTooLow { min: 2, fee: 1 }),
            // A token's mint authority is state — `SetAuthority` rotates it — so the very same
            // bytes are refused before that commits and accepted after it.
            tok(T::BadSignature),
            // The release-unit verdicts (bridge-06/audit O-5). `NotReleasable` is the closest
            // call in this whole function: the unit is `10^(8-decimals)` of a backing whose
            // decimals never change once listed, so for a *listed* coin it really is a statement
            // about the bytes. It stays out because a coin is not listed forever-or-never — a
            // governance `AddBacking` lists a new one, and a burn naming a pair that is about to
            // become a backing must not be refused for good by a node that saw it first.
            // `BadBackingDecimals` is a listing's verdict, never a transaction's, and rides
            // along on the same reasoning.
            tok(T::NotReleasable { amount: 199, unit: 100 }),
            tok(T::BadBackingDecimals(19)),
        ] {
            assert!(!is_permanent(&e), "{e} depends on state and must not be cached");
        }
    }

    /// The hidden-asset bundle's burn-shape verdicts are byte verdicts: `UnsupportedAsset`,
    /// `UnsupportedBurn` and `UnknownToken(0)` are cached — and, what makes caching them sound,
    /// the very same bytes are refused the very same way on a bare bridged chain and on one that
    /// has since registered a native token, deposited a bridged one and minted: no state the
    /// registry can reach turns them valid. `UnknownToken` of any *other* index is not cached,
    /// because a registration one block later does make it valid.
    #[test]
    fn the_burn_shape_verdicts_are_byte_verdicts_and_are_cached() {
        use crate::storage::fixtures;
        use randprotocol_core::confidential::{ConfidentialExecutor, StubExecutor};
        use randprotocol_core::ledger::tokens::TokenError as T;
        use randprotocol_core::{Action, Transaction};

        for e in [TxError::UnsupportedAsset(2), TxError::UnsupportedBurn(5), TxError::Token(T::UnknownToken(0))] {
            assert!(is_permanent(&e), "{e} is a statement about the bytes");
        }
        assert!(!is_permanent(&TxError::Token(T::UnknownToken(2))), "a registration can create index 2");

        let (gs, secrets) = fixtures::bridged_genesis(1);
        let bare = gs.ledger.clone();
        let mut grown = gs.ledger.clone();
        let deposit = fixtures::attest_tx(&grown, fixtures::attestation(&secrets, &fixtures::recipient(), 1_000, 0), 200);
        grown.apply_tx(&deposit, &fixtures::key(1).address(), &StubExecutor).unwrap();
        let register = fixtures::register_token_tx(&grown, 5_000, 210);
        grown.apply_tx(&register, &fixtures::key(1).address(), &StubExecutor).unwrap();
        grown.record_anchor(0);
        assert!(grown.tokens().unwrap().get(2).is_some(), "the grown chain holds token 2");

        // A bundle keyed at 10 with its burn fields set, re-proved, on the given action.
        let tx = |l: &randprotocol_core::Ledger, action: Action, burn_asset: u32, burn_a: u64, burn_r: u64| {
            let mut b = fixtures::bundle(l, [[10; 8], [11; 8]], [[12; 8], [13; 8]], randprotocol_core::gas::BUNDLE_BASE);
            (b.burn_asset, b.burn_a, b.burn_r) = (burn_asset, burn_a, burn_r);
            b.proof = StubExecutor::make_bundle_proof(&fixtures::HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
            StubExecutor::bound(Transaction::shielded(l.chain_id(), b, action))
        };
        for l in [&bare, &grown] {
            // A transfer that burns a token, or burns RAND: its action burns nothing.
            let t = tx(l, Action::None, 2, 5, 0);
            assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedAsset(2)));
            let t = tx(l, Action::None, 0, 0, 5);
            assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedBurn(5)));
            // A token burn that also burns RAND — on the grown chain past every registry check
            // (token 2 exists, has supply), on the bare one refused earlier for the missing token:
            // either way refused, and on the grown chain for the byte reason.
            let t = tx(l, Action::TokenBurn { asset: 2, amount: 300 }, 2, 300, 7);
            let got = l.validate(&t, &StubExecutor).unwrap_err();
            if l.tokens().unwrap().get(2).is_some() {
                assert_eq!(got, TxError::UnsupportedBurn(7));
            } else {
                assert_eq!(got, TxError::Token(T::UnknownToken(2)), "state first here, and state is not cached");
                assert!(!is_permanent(&got));
            }
            // A burn of token 0 — RAND — on either chain.
            let t = tx(l, Action::TokenBurn { asset: 0, amount: 300 }, 0, 0, 0);
            assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Token(T::UnknownToken(0))));
        }
    }

    /// The shipped policy, pinned: 8192 entries against a 10 000-transaction pool, and a burst of 16
    /// refilling at 4/s against a chain that commits about one transaction a second. Changing any of
    /// the three is a decision about how much work an unknown peer may cost this node, so it should
    /// break a test rather than a fleet.
    #[test]
    fn the_shipped_policy_is_the_one_the_plan_sized() {
        // The faucet's own allowance rides the same type (node I4).
        assert_eq!((FAUCET_MINT_BURST, FAUCET_MINT_PER_SEC), (8, 1.0));
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

    /// Node I4: the faucet's own allowance, the shipped numbers, over the same type. A mint is
    /// fee-less and costs a pooled transaction, so an unthrottled `rand_mint` is free pool
    /// pressure on a chain with the faucet on behind a live bridge. One bucket, not a map: the
    /// RPC port has no peer identity to meter, and what is being protected is this node's pool.
    #[test]
    fn the_faucet_allows_its_burst_then_one_a_second() {
        let l = PeerLimiter::new(FAUCET_MINT_BURST, FAUCET_MINT_PER_SEC);
        let mut b = TokenBucket::default();
        let t0 = Instant::now();
        for i in 0..FAUCET_MINT_BURST {
            assert!(l.allow(&mut b, t0), "mint {i} of the burst");
        }
        assert!(!l.allow(&mut b, t0), "the ninth in the same instant is refused");
        // The e2e gate's shape — five faucet mints back to back — fits inside the burst with
        // room to spare, which is why 8 was chosen rather than something tighter.
        assert!(FAUCET_MINT_BURST >= 5);
        assert!(l.allow(&mut b, t0 + Duration::from_secs(1)), "one a second");
        assert!(!l.allow(&mut b, t0 + Duration::from_secs(1)));
        // And it never refills past the burst, however long the faucet is left alone.
        for i in 0..FAUCET_MINT_BURST {
            assert!(l.allow(&mut b, t0 + Duration::from_secs(3600)), "refilled {i}");
        }
        assert!(!l.allow(&mut b, t0 + Duration::from_secs(3600)), "the burst is the ceiling");
    }
}
