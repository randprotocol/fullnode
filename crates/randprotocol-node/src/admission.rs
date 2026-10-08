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
use randprotocol_core::notes::Word8;
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
/// reason the whole scheme is sound: the hash binds the proof (`rand-txid-3` takes it, and the
/// split-authorisation auth proof, by digest, and the transaction binding covers the rest), so a stale entry can only ever say
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

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
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
/// `MinterNotValidator`, `MinterNotAllowed`, `Bridge`, `AttestAssetMismatch`, `Staking` and
/// `UnknownProposer` are all statements about *this node's state at this moment*: a node one block behind would
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
    // Genesis vesting: the register's entries, their keys and whether each is revocable are all
    // fixed at genesis — no action rotates a key or adds an entry — so a bad signature, an
    // unknown entry, a revoke of an irrevocable entry and a bond from a revocable one are
    // verdicts on the bytes against constants, as are the byte rules (a recipient's key length,
    // an amount under the base, a zero amount). Everything else — the nonce, what has vested,
    // what is free or bonded, whether the entry was revoked — moves with the chain and time.
    // Audit v6, STAKE-3: an entry's revokers, its threshold and its treasury are genesis terms
    // too, so a revoke to another address, a signature list naming a position the entry does not
    // have or one revoker twice, and one shorter than the threshold are byte verdicts as well.
    if let TxError::Vesting(v) = e {
        use randprotocol_core::ledger::vesting::VestingError as V;
        return matches!(
            v,
            V::BadSignature
                | V::UnknownEntry(_)
                | V::NotRevocable
                | V::BondNeedsIrrevocable
                | V::BadRecipient
                | V::BelowBundleBase { .. }
                | V::ZeroAmount
                | V::NotTheTreasury
                | V::BelowThreshold { .. }
                | V::DuplicateRevoker(_)
                | V::BadRevokerIndex(_)
        );
    }
    // The validator register's verdicts are state, every one (see the doc comment) — with the
    // three an `AdmitValidator` (audit v6, STAKE-2) can earn on its own bytes: a candidate key of
    // the wrong length, votes out of strict voter order (which is what a repeated voter is), and
    // a vote that does not verify under the key the action itself lists beside it, over the
    // genesis hash and the candidate the action itself names. No register, height or pool state
    // enters any of them, so a node one block behind refuses the same bytes. They are worth
    // caching because the action is fee-less: without it each repeat costs a set derivation and
    // a Dilithium2 verification. Membership of the voting set, the quorum, the candidate being
    // registered or admitted, the set being full — and `NotAdmitted` itself — move with the chain.
    // And STAKE-1's evidence: two headers that are not an equivocation (one key, one view, two
    // hashes, the lower first — all read off the action), an encoding over the cap, and a
    // signature that does not verify under the key the header itself names over this chain's
    // signing domain (a genesis constant). The window, the offender's stake and the jail are
    // state and stay out.
    if let TxError::Staking(s) = e {
        use randprotocol_core::ledger::StakingError as S;
        return matches!(
            s,
            S::BadCandidateKey { .. }
                | S::AdmissionVoteOrder
                | S::BadAdmissionVote(_)
                | S::NotEquivocation(_)
                | S::EvidenceTooLarge { .. }
                | S::BadEvidenceSignature(_)
        );
    }
    // The RAND price vote's byte-verdicts (`fees.usd_subsidy`), `Staking`'s three for the same
    // vote shape: a zero price, votes out of strict voter order, and a vote that does not verify
    // under the key the action lists beside it over the genesis hash, price and nonce the action
    // itself names. The nonce, the band against the current price, membership and the quorum
    // move with the chain and stay out.
    if let TxError::Price(p) = e {
        use randprotocol_core::ledger::rand_price::PriceError as P;
        return matches!(p, P::ZeroPrice | P::VoteOrder | P::BadVote(_));
    }
    // The aggregation register's verdicts, split like `Staking`'s: the byte-verdicts (and the
    // ones against genesis-pinned constants) are cacheable, the register's state is not. A
    // signature is over the transaction's own fields against the entry's key — and an address
    // *is* its key's address, so no re-registration can ever make a bad signature a good one.
    // `UnregisteredShape`/`CoveredShapeMismatch`/`CoveredGuestMismatch` judge the covered
    // bundles against the admitted shapes, which are genesis constants. `CoverNotABundle` is a
    // statement about a *committed* — finalised, immutable — transaction's shape, and
    // `CoverSealed` one about committed history, which only ever accumulates. Everything
    // else (`UnknownAggregator`, `Unbonding`, `BadNonce`, `PayoutMismatch` — the schedule moves
    // with a price vote, staleness and halvings, and a re-sealed aggregate is new bytes anyway —
    // the payout's `CommitmentExists`,
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
                // A slash is refused whatever its bytes and whatever the state (INTERFACE-1).
                | A::SlashingRetired
        );
    }
    // Multisig accounts, split the same way. Cacheable are the verdicts on the action's own
    // bytes: a signer set or threshold outside the creation bounds (`BadSigners`, the new set a
    // create or a rotate names), one index listed twice, a payout list that is empty, over the
    // cap or holds a zero amount, and a deposit whose bundle burns nothing. Everything read off
    // the account is state: whether it exists (a create can land), the nonce, the vault, and the
    // signer set and threshold, which a rotation replaces — so `BadSignature`, `BadSignerIndex`
    // (an index against the *current* list's length; bridge v2 made `PqIndexOutOfRange` state
    // for the same reason) and `BelowThreshold` (against the current threshold) may all be valid
    // after one rotation. The set's shape is checked before the nonce, so a pay signed for the
    // nonce after a pending rotation hears one of them until that rotation lands.
    if let TxError::Multisig(m) = e {
        use randprotocol_core::ledger::multisig::MultisigError as M;
        return matches!(
            m,
            M::BadSigners(_) | M::DuplicateSigner(_) | M::NoPayouts | M::TooManyPayouts(_) | M::ZeroPayout | M::EmptyDeposit
        );
    }
    // RPL-2's verdicts, split the same way. Cacheable are the ones `program_state::check_shape`
    // and the segment rule give — the transition's own lists and amounts against compile-time
    // constants, and its inflow word against its own bundle's `burn_a`:
    //
    // - `TooManyReads` / `TooManyWrites` / `TooManyPayouts`, `UnorderedKeys`;
    // - `InflowWithoutBurn` / `InflowMissing` — the action's word against the bundle's field;
    // - `ZeroPayout` / `PayoutTooLarge` — an amount as written against 0 and 2^63;
    // - `ContextTooLong` — the transition's word count against the length of the program's
    //   public input. That length is read off the program's record, but it is no more state
    //   than a chain id: a program id is the hash of its words *and* its public words
    //   (`program_id_with_public`), records are never rewritten, and the verdict is only
    //   answered once the record is found (before that the same bytes are `UnknownProgram`,
    //   which is not cached) — so no later state gives the id the transaction names another
    //   length.
    //
    // Everything else moves with this node's state and stays out: `StaleRead` (the cells — a
    // node one block behind would poison itself against an invoke proved on the tip),
    // `VaultShort` (the vault), `NotProgramToken` (a token's authority is the registry's, and
    // the index may be registered to this program a block later), `Overflow` (arithmetic over
    // amounts this node holds) and `Disabled` (which modules the genesis switched on — a
    // statement about the chain, like `UnsupportedAction`).
    if let TxError::ProgramState(p) = e {
        use randprotocol_core::ledger::program_state::ProgramStateError as P;
        return matches!(
            p,
            P::TooManyReads(_)
                | P::TooManyWrites(_)
                | P::TooManyPayouts(_)
                | P::UnorderedKeys
                | P::InflowWithoutBurn
                | P::InflowMissing { .. }
                | P::ZeroPayout
                | P::PayoutTooLarge(_)
                | P::ContextTooLong { .. }
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
                // A note at or above 2^63 (deep scan 2026-09-24): the amount as written against
                // a constant, and the gate that makes the ledger say it is a genesis constant,
                // like `WrongChain`'s chain id. `SupplyTooLarge` — the token's supply would reach
                // the bound — is state: a burn makes room, so it stays out.
                | T::AmountTooLarge { .. }
        );
    }
    // RPL-3's verdicts, every variant placed by name (no catch-all: a new one must be placed).
    // Cacheable are the ones the bytes decide against genesis constants: the section's presence
    // (`Disabled`, a statement about the chain fixed at genesis), a market id and the tier cap
    // (`UnknownMarket`, `TierTooHigh`), the action's own fields and lists (`BadOrder`,
    // `ZeroAmount`, `BadPrice`, `UnorderedPrices`, `DuplicatePayout`, `TooManyPayouts`,
    // `AmountTooLarge`, `CollateralAssetMismatch` — the bundle's burn asset against the
    // section's), `ReservedAccount` (a key whose id is the insurance fund's, forever),
    // `KeyMismatch` (an account id is its key's hash) and `BadSignature` (over the action's own
    // message, under the account's key or the oracle's — neither rotates; the message's binding
    // domain is a genesis constant). The final fix wave adds two more: `DepositTooSmall` (the
    // bundle's burn against the genesis `min_deposit`) and `PartialPayout` (a payout against its
    // request's amount, which the request id — the request's own hash — fixes: no state makes
    // a partial payout of that request whole). Everything else reads state that moves: the nonce
    // windows, the accounts and their cap, the pending withdrawals and their cap, the validator
    // set, the proved height and its digests — and the proof's verdict, which is over a segment
    // built from them. The block's input caps (`BlockFull`, `AccountBlockFull`) are about the
    // block being built — the next has room; `WithdrawalPending` clears when a proof settles the
    // account's request; `RequestOutsideWindow` reads the height the request was recorded at.
    if let TxError::Perps(p) = e {
        use randprotocol_core::ledger::perps::PerpError as P;
        return match p {
            P::Disabled
            | P::UnknownMarket(_)
            | P::BadOrder(_)
            | P::BadSignature
            | P::TooManyPayouts(_)
            | P::TierTooHigh { .. }
            | P::DuplicatePayout
            | P::BadPrice
            | P::AmountTooLarge(_)
            | P::ReservedAccount
            | P::UnorderedPrices
            | P::CollateralAssetMismatch
            | P::KeyMismatch
            | P::ZeroAmount
            | P::DepositTooSmall(_)
            | P::PartialPayout { .. } => true,
            P::NonceUsed
            | P::WindowMismatch { .. }
            | P::MissingDigest(_)
            | P::UnknownRequest
            | P::UnknownAccount
            | P::TooManyWithdrawals
            | P::TooManyAccounts
            | P::NotValidator
            | P::OracleNonce
            | P::PayoutTooLarge { .. }
            | P::ProofRefused(_)
            // The pending request holding the opening is paid by a later proof, freeing it.
            | P::DuplicateOpening
            | P::Overflow
            | P::BlockFull
            | P::AccountBlockFull
            | P::WithdrawalPending
            | P::RequestOutsideWindow { .. } => false,
        };
    }
    // The Dilithium2 co-signature's verdicts (bridge hardening B3). Every other bridge verdict
    // stays out: a digest's `Replay`, a guardian set's expiry and the registry's listings all move
    // with this node's state. Of the five PQ refusals only the two that are about the list's own
    // bytes are cached:
    //
    // - `PqIndexOrder` — the indices as written, and nothing else;
    // - `PqBadSignatureLength` — a byte length, like every other length above.
    //
    // **Not cached since audit v6 (BRG-18), because bridge rules v2 made them state:**
    //
    // - `PqIndexOutOfRange` — the index against `n`, the size of the PQ set. It was the genesis
    //   set's, "which no action changes"; `RotatePqGuardians` (chains 15–18) changes it, so a
    //   node one block behind a rotation to a larger set refused a valid mint for good.
    // - `BadPauseSignature` — the signature under the chain's pause key, which `RotatePauseKey`
    //   replaces. A node that had not yet applied the rotation cached a refusal of the new
    //   holder's `PauseMints` and kept it until restart — the emergency brake, of all things.
    //   What the cache bought there was free repeats of one bad pause (it is bundle-less and
    //   fee-less); without it each repeat costs a Dilithium2 verify, bounded by the per-peer
    //   token bucket like every other uncached refusal.
    //
    // `PqNoQuorum` and `PqBadSignature` were always out, on the same side of this line.
    //
    // F1's `WrongDepositBlinding` is cached: it compares the action's `r` with
    // `blake3("rand-deposit-r-1" ‖ mu)` of the action's own `attestation` bytes — no key, no
    // registry, no height — so the same bytes are refused at every tip.
    if let TxError::Bridge(b) = e {
        use randprotocol_core::bridge::BridgeError as B;
        return matches!(
            b,
            B::PqIndexOrder
                | B::PqBadSignatureLength { .. }
                | B::WrongDepositBlinding
                // A transfer amount that fits no note — past `u64`, or at or above 2^63 under
                // `tokens.bound_note_value` (deep scan 2026-09-24): the wire bytes against a
                // constant, decided before any signature is looked at.
                | B::AmountTooLarge
                // Bridge rules v2: the gate is a genesis constant, and a key's length or a
                // duplicate inside the action's own key list is about the bytes. The nonce, the
                // set-length rule (the current ECDSA set's size), the membership rules and the
                // caps are state and stay out.
                | B::RulesV2Disabled
                | B::BadPqGuardianKey { .. }
                | B::BadPauseKeyLength { .. }
                | B::DuplicatePqGuardian
                // Audit v6, BRG-14: the rotation group and its possession rule are genesis
                // constants, and a possession list's count and lengths and a cancel's kind byte
                // are the action's own bytes. `BadPossession` (a key's signature: the key list
                // is the action's own, so no state turns it good — but the message it is over
                // carries the nonce), `RotationPending`, `NoPendingRotation`,
                // `BadCancelSignature` (the pause key rotates) and the nonce are state and stay out.
                | B::RotationRulesDisabled
                | B::PossessionRequired
                | B::PossessionNotEnabled
                | B::PossessionCountMismatch { .. }
                | B::BadPossessionLength { .. }
                | B::BadRotationKind(_)
                // C15-1: the body's own `(emitter_chain, sequence)` against the genesis replay
                // floor, which no action moves — like `WrongChain`'s chain id.
                | B::BelowReplayFloor { .. }
        );
    }
    matches!(
        e,
        // The proofs and the digest are over the transaction's own fields.
        TxError::InvalidProof(_)
            | TxError::InvalidBundleProof(_)
            | TxError::BadDigest
            // Split authorisation: the auth fields against the genesis gate, and the auth proof
            // against the pinned auth guest and the transaction's own binding — all the bytes'.
            | TxError::AuthUnexpected
            | TxError::AuthMissing
            | TxError::AuthMismatch
            | TxError::InvalidAuthProof(_)
            | TxError::BadMintSignature
            // A mint's commitment is a function of its own bytes (`ledger::mint_commitment`).
            | TxError::MintCommitmentMismatch
            // A mint's recipient `pk` is its own bytes, against a genesis list (chain 15).
            | TxError::FaucetRecipientNotAllowed
            // A faucet mint at or above 2^63 (deep scan 2026-09-24): the node's own byte verdict
            // for a note no proof could spend (`oversized_note`), against a constant — unlike
            // `MintTooLarge`, which stays out (see the doc comment).
            | TxError::AmountTooLarge { .. }
            | TxError::BadProgram(_)
            // The chain id is a per-chain constant, and the shape of an action — bundle or no
            // bundle — is on the wire.
            | TxError::WrongChain { .. }
            | TxError::MissingBundle
            | TxError::ActionCarriesBundle(_)
            // Byte lengths, every one of them.
            | TxError::EnvelopeTooLarge
            // Spec 2026-09-26 §2.4: an envelope's length against the genesis constant.
            | TxError::EnvelopeSize { .. }
            // Spec 2026-09-28 §4.3: a bundle proof's declared gas limit is its own bytes, against
            // the genesis `bundle_gas_limit`.
            | TxError::BundleGasLimit { .. }
            // And an auth proof's, against the auth guest's fixed ceiling.
            | TxError::AuthGasLimit { .. }
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
        self.allow_n(bucket, 1.0, now)
    }

    /// Spend `cost` tokens at once — a byte budget spends a message's size (CN-4). All or
    /// nothing: over the limit spends none, so a large message refused now is not charged for.
    /// A cost above the burst can never pass; the caller sizes the burst above its largest
    /// honest message.
    pub fn allow_n(&self, bucket: &mut TokenBucket, cost: f64, now: Instant) -> bool {
        let available = match (bucket.tokens, bucket.last) {
            (Some(tokens), Some(last)) => {
                let elapsed = now.saturating_duration_since(last).as_secs_f64();
                (tokens + elapsed * self.per_sec).min(self.burst)
            }
            // Never used, so nothing has been spent: full, whenever `now` is.
            _ => self.burst,
        };
        bucket.last = Some(now);
        if available < cost {
            bucket.tokens = Some(available);
            return false;
        }
        bucket.tokens = Some(available - cost);
        true
    }
}

/// How many proof verifications run on blocking workers at once, and how many wait for a slot
/// (spec 2026-10-05 §6). The floor is today's four: a warm bundle verification is ~20 ms of
/// pure CPU, and a machine that also runs the consensus loop, RocksDB and the RPC server keeps
/// two cores for them. The queue is sixteen per worker (today's 64 for 4): sized against
/// gossipsub's 2.5 s validation window (`history_length` 5 x 500 ms) — at ~20 ms a verification,
/// sixteen deep is ~320 ms of work per worker, inside the window even cold. A transaction past
/// the queue is shed with an `Ignore`, which an honest peer re-gossips on its next heartbeat.
/// The in-flight number is a concurrency bound, not a throughput target; the queue absorbs bursts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyLimits {
    pub in_flight: usize,
    pub queue: usize,
}

impl VerifyLimits {
    pub const FLOOR: usize = 4;
    pub const QUEUE_PER_WORKER: usize = 16;

    /// The cores minus two (consensus loop, RocksDB and RPC keep those), never under the floor.
    pub fn for_cores(cores: usize) -> VerifyLimits {
        let in_flight = cores.saturating_sub(2).max(Self::FLOOR);
        VerifyLimits { in_flight, queue: in_flight * Self::QUEUE_PER_WORKER }
    }

    /// [`VerifyLimits::for_cores`] of this host's available parallelism.
    pub fn for_host() -> VerifyLimits {
        Self::for_cores(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(Self::FLOOR))
    }

    /// `--verify-workers N`: exactly N, `0` refused — never defaulted, as `--threads 0` is not.
    /// A count whose queue (`N × QUEUE_PER_WORKER`) does not fit a `usize` is refused by name
    /// rather than wrapped into a small queue.
    pub fn fixed(workers: usize) -> Result<VerifyLimits, String> {
        if workers == 0 {
            return Err("--verify-workers must be at least 1".into());
        }
        let queue = workers.checked_mul(Self::QUEUE_PER_WORKER).ok_or_else(|| format!("--verify-workers too large: {workers}"))?;
        Ok(VerifyLimits { in_flight: workers, queue })
    }
}

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
    /// For a `PerpStateProof`, the proved root of the snapshot it was verified on and the digest
    /// of the segment it was verified over ([`state_proof_key`]) — what a `ProofRefused` verdict
    /// is keyed by in the [`ProofRefusedCache`]; `None` for every other transaction.
    pub proof_key: Option<StateProofKey>,
}

/// How many refused state proofs to remember (RPL-3 final fix wave, I1). Only proofs against the
/// current proved root are held, and a window's proofs are few; this bounds a flood of distinct
/// junk proofs, which then costs one verification each, as any uncached refusal does.
pub const PROOF_REFUSED_ENTRIES: usize = 256;

/// What a state proof's verdict on one ledger is a function of, beside its own bytes: the proved
/// root the ledger holds and the digest (`blake3` of the little-endian words) of the public
/// segment the ledger builds for it — `R_from` (that root), the window's recorded digests and the
/// transaction's own claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StateProofKey {
    pub proved_root: Word8,
    pub segment: Hash,
}

/// The [`StateProofKey`] of a `PerpStateProof` on `ledger`: `None` for any other transaction, on
/// a chain without the section, and for a proof whose cheap rules `ledger` refuses (which the
/// ledger answers without looking at the STARK, so there is nothing to cache).
pub fn state_proof_key(
    tx: &Transaction,
    ledger: &randprotocol_core::Ledger,
    executor: &dyn randprotocol_core::confidential::ConfidentialExecutor,
) -> Option<StateProofKey> {
    let randprotocol_core::Action::PerpStateProof { .. } = tx.action else { return None };
    let proved_root = ledger.perps()?.proved_root;
    let words = randprotocol_core::ledger::perps::state_proof_segment_on(ledger, tx, executor).ok()?;
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    Some(StateProofKey { proved_root, segment: Hash::digest_domain(b"rand-node-perp-segment-1", &bytes) })
}

/// RPL-3 (final fix wave, I1): state proofs whose STARK this node refused (`ProofRefused`),
/// keyed by the transaction hash and its [`StateProofKey`] — the proved root and the segment.
///
/// `ProofRefused` is not [`is_permanent`] — the segment a proof is verified over is built from
/// the chain's proved root and recorded digests, which move — so the [`RefusedCache`] never holds
/// it, and the same junk proof re-sent was verified afresh each time: a state proof is
/// bundle-less and fee-less, and its STARK is the most expensive verification a node runs. The
/// verdict is a function of the proof's bytes (in the hash), the genesis constants and the
/// segment, so the same hash over the same segment is refused again without verifying. Every
/// entry is dropped the moment the proved root moves, since no segment of the old root can be
/// built again. Bounded and FIFO like the refused cache.
pub struct ProofRefusedCache {
    root: Option<Word8>,
    seen: HashMap<(Hash, Hash), TxError>,
    order: VecDeque<(Hash, Hash)>,
    cap: usize,
}

impl ProofRefusedCache {
    pub fn new(cap: usize) -> ProofRefusedCache {
        ProofRefusedCache { root: None, seen: HashMap::new(), order: VecDeque::new(), cap }
    }

    /// The refusal of `h` over `key`, if this node made one — never one made against an earlier
    /// root or over another segment.
    pub fn get(&self, h: &Hash, key: &StateProofKey) -> Option<&TxError> {
        if self.root != Some(key.proved_root) {
            return None;
        }
        self.seen.get(&(*h, key.segment))
    }

    /// Remember `e` for `h` over `key` — only a `ProofRefused`, so no other verdict (a window or
    /// a digest refusal, which a later block may answer) is held. A new root empties the cache
    /// first.
    pub fn insert(&mut self, h: Hash, key: StateProofKey, e: TxError) {
        use randprotocol_core::ledger::perps::PerpError;
        if !matches!(e, TxError::Perps(PerpError::ProofRefused(_))) || self.cap == 0 {
            return;
        }
        if self.root != Some(key.proved_root) {
            self.seen.clear();
            self.order.clear();
            self.root = Some(key.proved_root);
        }
        let k = (h, key.segment);
        if self.seen.insert(k, e).is_some() {
            return;
        }
        self.order.push_back(k);
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
    /// `queued` is the current verification queue depth and `queue_cap` its limit
    /// ([`VerifyLimits::queue`]): at or past it the transaction is shed with an `Ignore`.
    ///
    /// The order is the point. The bucket first (audit v6, GOSSIP-1): the transaction id hashes
    /// the whole transaction, proofs included — up to a block's worth of bytes — so nothing that
    /// needs it runs until the forwarder is known to be within its allowance. A peer re-sending a
    /// known-bad transaction now spends a token on it, which is the price of not hashing for it
    /// first. Then the hash, once, and the refused cache; then [`oversized_note`] and
    /// [`deploy_outside_pc_window`], byte verdicts cached like a cache hit. Then the queue depth.
    /// Everything more expensive than this — `Mempool::precheck`, which hashes a bridge
    /// attestation, and the proof itself — happens only after a `Verify`.
    pub fn for_transaction(
        tx: &Transaction,
        bucket: Option<&mut TokenBucket>,
        refused: &mut RefusedCache,
        limiter: &PeerLimiter,
        queued: usize,
        queue_cap: usize,
        now: Instant,
    ) -> GossipOutcome {
        Self::for_transaction_hashed(tx, || tx.hash(), bucket, refused, limiter, queued, queue_cap, now)
    }

    /// [`GossipOutcome::for_transaction`] with the transaction id computed by `hash`, called at
    /// most once — the seam a test counts the hashing through.
    #[allow(clippy::too_many_arguments)] // `for_transaction`'s seven plus the hash closure the test counts through.
    pub(crate) fn for_transaction_hashed(
        tx: &Transaction,
        hash: impl FnOnce() -> Hash,
        bucket: Option<&mut TokenBucket>,
        refused: &mut RefusedCache,
        limiter: &PeerLimiter,
        queued: usize,
        queue_cap: usize,
        now: Instant,
    ) -> GossipOutcome {
        if let Some(b) = bucket {
            if !limiter.allow(b, now) {
                return GossipOutcome::Report(Acceptance::Ignore);
            }
        }
        let h = hash();
        if refused.get(&h).is_some() {
            return GossipOutcome::Report(Acceptance::Reject);
        }
        // Then the note-value screen, a field compare (a payload decode for a deposit) and a
        // byte verdict like a cache hit — cached like one too, so the RPC answer names it and a
        // repeat is the lookup above.
        if let Some(e) = oversized_note(tx) {
            refused.insert(h, e);
            return GossipOutcome::Report(Acceptance::Reject);
        }
        // And the pc-window screen (ZKV-11), a comparison on the deploy's own fields, for the
        // same reasons and the same way.
        if let Some(e) = deploy_outside_pc_window(tx) {
            refused.insert(h, e);
            return GossipOutcome::Report(Acceptance::Reject);
        }
        if queued >= queue_cap {
            return GossipOutcome::Report(Acceptance::Ignore);
        }
        GossipOutcome::Verify
    }
}

/// A transaction that would create a note worth `MAX_NOTE_VALUE` (2^63) or more, from its bytes
/// alone — a faucet `Mint`, a `TokenMint`, a `RegisterToken`'s initial mint or a `BridgeAttest`
/// whose transfer amount is at or above it (a decode of the attestation's payload, no signature
/// work). The hidden-asset guest range-checks every value to u63, so such a note could never be
/// spent: its value would sit in a token's `total_supply` or a backing's `locked` for ever, and
/// for zUSD `total_supply == Σ locked` could never be closed by a burn (deep scan 2026-09-24,
/// ledger arithmetic). `None` for everything else, including bytes that do not decode — those
/// are the ledger's to refuse.
///
/// **Unconditional**, on every chain: it is node policy, not a validity rule. On chain 14, whose
/// genesis has no `tokens.bound_note_value`, the ledger admits such a mint and a block carrying
/// one is valid — this node simply never pools or forwards it, and answers the same bytes from
/// the refused cache thereafter. Under the gate the ledger's own verdict is the same variant
/// (`Token(AmountTooLarge)`, `Bridge(AmountTooLarge)`); a faucet `Mint` is refused by
/// `FAUCET_MAX_UNITS` everywhere and gets `TxError::AmountTooLarge` here, since `MintTooLarge`
/// is deliberately never cached.
pub fn oversized_note(tx: &Transaction) -> Option<TxError> {
    use randprotocol_core::bridge::{Attestation, BridgeError, Payload};
    use randprotocol_core::ledger::tokens::TokenError;
    use randprotocol_core::notes::MAX_NOTE_VALUE;
    use randprotocol_core::Action;
    match &tx.action {
        Action::Mint { amount, .. } if *amount >= MAX_NOTE_VALUE => Some(TxError::AmountTooLarge { amount: *amount }),
        Action::TokenMint { amount, .. } if *amount >= MAX_NOTE_VALUE => {
            Some(TxError::Token(TokenError::AmountTooLarge { amount: *amount }))
        }
        Action::RegisterToken { initial: Some(m), .. } if m.amount >= MAX_NOTE_VALUE => {
            Some(TxError::Token(TokenError::AmountTooLarge { amount: m.amount }))
        }
        Action::BridgeAttest { attestation, .. } => {
            // The transfer's amount as the wire carries it (a u256): past `u64` or at or above
            // the bound, the bridge's own verdict for "fits no note" — what `check_attest`
            // answers for the same bytes, under the gate. A rotation moves no value.
            let att = Attestation::decode(attestation).ok()?;
            let Payload::Transfer(t) = Payload::decode(&att.body.payload).ok()? else {
                return None;
            };
            let too_large = match t.amount_u128() {
                Some(amount) => amount >= MAX_NOTE_VALUE as u128,
                None => true,
            };
            too_large.then_some(TxError::Bridge(BridgeError::AmountTooLarge))
        }
        // RPL-2: a payout at or above the bound, the ledger's own verdict for it
        // (`program_state::check_shape` refuses it on every chain that admits an invoke, whatever
        // `tokens.bound_note_value` says). The count is capped first, as the ledger caps it: an
        // unvalidated transition must not buy a walk of any length.
        Action::Invoke { transition, .. } => {
            use randprotocol_core::ledger::program_state::{ProgramStateError, MAX_PAYOUTS};
            if transition.pays.len() + transition.mints.len() > MAX_PAYOUTS {
                return None;
            }
            transition
                .payouts()
                .find(|p| p.amount >= MAX_NOTE_VALUE)
                .map(|p| TxError::ProgramState(ProgramStateError::PayoutTooLarge(p.amount)))
        }
        _ => None,
    }
}

/// A `Deploy` whose padded program table crosses the u32 pc wrap
/// (`randprotocol_core::program::pc_window_fits`, ZKV-11): `TxError::BadProgram` with the ledger's
/// own text. No honest proof of such a program verifies — the circuit does its PC arithmetic in the
/// field, the emulator wraps mod 2^32 — yet ZH4's `check_program` bounds only `base_pc + 4·len`,
/// so a deployer could pay `deploy_fee` for a program no call can ever use. `None` for everything
/// else, and for every program at `base_pc` 0 (all 105 on chain 15).
///
/// **Unconditional**, on every chain, like [`oversized_note`]: node policy, not a validity rule —
/// on a chain whose genesis does not set `hardening_v6` (chain 15) the ledger admits such a
/// deploy and a block carrying one is valid; this node never pools or forwards it. Under the flag
/// the ledger's verdict is the same one. Cached like `oversized_note`'s, and for its reason: a
/// function of the transaction's bytes against a constant (`BadProgram` is already in
/// [`is_permanent`]'s allowlist, as ZH4's and every other deploy-shape refusal is), so a repeat
/// costs a lookup. The row count is `program::program_table_rows`, core's mirror of the zkVM's
/// `program_log_height`, floored at `program::MIN_PRIVATE_TABLE_LOG_HEIGHT` (PCW-FLOOR: the
/// table a hardened call declares), both pinned to the zkVM's own in its executor tests.
pub fn deploy_outside_pc_window(tx: &Transaction) -> Option<TxError> {
    let randprotocol_core::Action::Deploy { base_pc, words, .. } = &tx.action else {
        return None;
    };
    (!randprotocol_core::program::pc_window_fits(*base_pc, words.len()))
        .then(|| TxError::BadProgram(randprotocol_core::program::pc_window_error()))
}

/// A `Deploy` of more program words than any call can hold (CPU-1, the 2026-09-27 zkVM/ISA
/// review): `TxError::ProgramUncallable`, the ledger's own verdict under `hardening_v6`. Every
/// proof pays one Poseidon2 permutation per four program words, plus the empty input's salt row
/// and the public segment's header, before it executes anything, and a call is capped at tier 14's
/// 2 048 — so a program past 8 184 words (fewer beside a public input) deploys, is charged
/// `deploy_fee` and can never be called. The shipped EVM (18 009 words) and sBPF (8 317)
/// interpreters are both past it. The bound is `randprotocol_zkvm::executor::
/// max_callable_program_words`, the prover's own terms. `None` for everything else.
///
/// **Node policy on every chain, never permanent** ([`is_permanent`] leaves it out: the bound is
/// the build's call tier cap, which a later build may raise, and a peer on an older build that
/// forwards the deploy must not be penalised) — an Ignore, never cached. On a chain whose genesis
/// sets `hardening_v6` the ledger refuses the same deploy itself; on chain 15 a block from an older
/// proposer that carries one still applies.
pub fn deploy_uncallable(tx: &Transaction) -> Option<TxError> {
    let randprotocol_core::Action::Deploy { words, public, .. } = &tx.action else {
        return None;
    };
    let max_words = randprotocol_zkvm::executor::max_callable_program_words(public.len());
    (words.len() > max_words).then_some(TxError::ProgramUncallable { words: words.len(), public_words: public.len(), max_words })
}

/// A transaction whose bundle proof or call proof carries a field the honest prover would not
/// write (`randprotocol_zkvm::executor::non_canonical`: the memory height first — INT-5, a bundle
/// declaring 17 verifies today): `TxError::NonCanonicalProof`, the ledger's own verdict under
/// `hardening_v6`. Such a field is accepted by the verifier at more than one value, so whoever
/// relays the transaction can re-encode its proof into a second transaction id, and a bundle shape
/// the aggregate program was not built for can never be covered. Decided on the headers alone,
/// before any verification. `None` for everything else, including bytes that do not decode.
///
/// **Node policy on every chain, never permanent** ([`is_permanent`] leaves it out: what the honest
/// prover writes is this build's knowledge, which a re-vendor may move, and a peer on an older
/// build that forwards the transaction must not be penalised) — an Ignore, never cached. A block
/// from an older proposer carrying one still applies until a genesis sets `hardening_v6`.
pub fn non_canonical_proofs(tx: &Transaction) -> Option<TxError> {
    randprotocol_core::ledger::non_canonical_proofs(tx, &randprotocol_zkvm::executor::non_canonical_proof)
}

/// A `Call` whose proof declares its input table — or a keccak or sha256 table it carries — under
/// `MIN_PRIVATE_TABLE_LOG_HEIGHT` (2^7 rows): `TxError::CallRevealsPrivateInputs`, telling the
/// wallet to upgrade (COV-2). A table that small has fewer random rows than the proof opens of it
/// (80 FRI queries + 2 out-of-domain points), so the proof discloses the call's private inputs;
/// the prover is being fixed upstream to floor the tables at 128 rows. Decided on the header
/// alone (`ZkExecutor::call_private_table_under_floor`), before any verification. Bundles are
/// exempt: their shape is pinned and safe (a 2048-row input table, no hash tables).
///
/// **Node policy, never a ledger validity rule**: a block from a proposer that pooled such a call
/// still applies — refusing it would split the chain on a privacy rule no genesis carries — and
/// the verdict is not permanent ([`is_permanent`] leaves it out: the floor is this build's policy,
/// which can move, and a peer on an older build that forwards the call must not be penalised), so
/// it is an Ignore and is never cached.
pub fn call_reveals_private_inputs(tx: &Transaction) -> Option<TxError> {
    // An RPL-2 `Invoke`'s call proof is a call proof: the same private tables, the same floor.
    let (randprotocol_core::Action::Call { proof, .. } | randprotocol_core::Action::Invoke { proof, .. }) = &tx.action
    else {
        return None;
    };
    let (table, log_height) = randprotocol_zkvm::executor::call_private_table_under_floor(proof)?;
    Some(TxError::CallRevealsPrivateInputs {
        table,
        log_height,
        min: randprotocol_zkvm::executor::MIN_PRIVATE_TABLE_LOG_HEIGHT,
    })
}

/// The keys a faucet `Mint` may be signed by, as this node's admission policy: the genesis's
/// `staking.faucet_minters` where it lists them — the validity rule, which this then only
/// anticipates — and otherwise the genesis validators, the register a chain starts with, every key
/// of it the operator's (RESCAN-LEDGER-1).
///
/// The ledger's rule is a row in the register, which a permissionless `Bond` writes at once, and
/// the bonded key is in the active set `bond_activation_epochs + 1` epochs later; so neither is a
/// bound on who mints, and on chain 15 a bonder holding one allowlisted wallet could drain each
/// epoch's faucet budget to it ahead of the operator and bond the proceeds. A validator bonded
/// after genesis — the operator's own included — cannot mint through this node's pool; the
/// operator mints through a genesis key.
pub fn faucet_minters(gs: &randprotocol_core::genesis::GenesisState) -> std::collections::BTreeSet<randprotocol_core::Address> {
    match gs.staking.as_ref().and_then(|s| s.faucet_minters.as_ref()) {
        Some(list) => list.iter().map(|m| m.0).collect(),
        None => gs.validators.iter().map(|v| v.address()).collect(),
    }
}

/// A faucet `Mint` whose minter has a row in the validator register but is not in `minters`
/// ([`faucet_minters`]): `TxError::MinterNotAllowed`. `None` for everything else — including a
/// minter with no row at all, which is the ledger's own `MinterNotValidator`, left to `validate`
/// to answer in its order.
///
/// Node policy, not a validity rule, so the verdict is an `Ignore` and never cached
/// ([`is_permanent`] leaves it out): a peer on an older build still admits the same bytes, and
/// the peer that forwarded them must not wear a penalty for it. A key that is not a minter
/// proposes no block of this pool's, and a chain whose genesis validators are all the operator's
/// keeps every such mint out of every block once its nodes run this.
pub fn minter_not_allowed(
    tx: &Transaction,
    ledger: &randprotocol_core::Ledger,
    minters: &std::collections::BTreeSet<randprotocol_core::Address>,
) -> Option<TxError> {
    let randprotocol_core::Action::Mint { minter, .. } = &tx.action else {
        return None;
    };
    let addr = minter.address();
    (ledger.validators().contains_key(&addr) && !minters.contains(&addr)).then_some(TxError::MinterNotAllowed(addr))
}

/// Spec 2026-09-28 §4.1 (gas, Phase 0): what `tx` must pay under `policy`. A `Call` pays
/// `GasPolicy::call_floor` of its proof header — `gas_max(tier, keccak, sha256)` and its bytes —
/// read by `decode_call` (`decode_call_hardened` under genesis `hardening_v6`, as the ledger
/// reads it; no verification; the size cap first, so an oversized blob buys no decode).
/// Every other action's floor is the schedule's `fee_floor`. Every floor here adds the ledger's
/// `prove_base_for(tx)` (genesis `fees.prove_base`, 0 on every chain without it). Admission policy above
/// the ledger's `call_fee` validity rule, the LEDGER-1 pattern: the pool and the proposer
/// demand it, a block never does.
///
/// Spec §4.2 (Phase 1): on a chain whose genesis carries the `gas` section, `policy` is not
/// read — the floor is the ledger's own rule (`Ledger::gas_call_floor` over the decoded
/// outcome's declared `gas_limit`, at the ledger's current prices), so the pool demands
/// exactly what a block does.
pub fn call_pricing(
    tx: &Transaction,
    ledger: &randprotocol_core::Ledger,
    executor: &dyn randprotocol_core::confidential::ConfidentialExecutor,
    policy: &randprotocol_core::gas::GasPolicy,
) -> Result<CallPricing, TxError> {
    use randprotocol_core::gas;
    use randprotocol_core::ledger::program_state;
    use randprotocol_core::Action;
    let (Action::Call { program, proof, input_envelope } | Action::Invoke { program, proof, input_envelope, .. }) =
        &tx.action
    else {
        return Ok(CallPricing { floor: gas::fee_floor(&tx.action).saturating_add(ledger.prove_base_for(tx)), gas_limit: None });
    };
    if proof.len() > ledger.max_proof_bytes() {
        return Err(TxError::ProofTooLarge);
    }
    let record = ledger.program(program).ok_or(TxError::UnknownProgram(*program))?;
    // Read the header as the ledger's step 10 does: under genesis `hardening_v6` a program
    // without a public input is proved over the call binding (INT-4), which the plain decoder
    // would refuse as `PublicValues`. The segment is the ledger's own (`hardened_call_segment`:
    // a program's deploy-time public words, then the binding — issue #55), so a program with a
    // public input decodes here too.
    //
    // RPL-2: an `Invoke`'s header is read over its own segment (`Ledger::invoke_segment`:
    // `public ‖ call_binding ‖ context`), by the invoke decoder, whatever the flag — the
    // ledger's step 10 again. Before the decode the transition's counts are held to the
    // ledger's caps, so an unvalidated transition cannot make this build a segment of any
    // length (the context is 16 words a cell).
    let outcome = match &tx.action {
        Action::Invoke { transition, .. } => {
            if transition.reads.len() > program_state::MAX_READS {
                return Err(program_state::ProgramStateError::TooManyReads(transition.reads.len()).into());
            }
            if transition.writes.len() > program_state::MAX_WRITES {
                return Err(program_state::ProgramStateError::TooManyWrites(transition.writes.len()).into());
            }
            let payouts = transition.pays.len() + transition.mints.len();
            if payouts > program_state::MAX_PAYOUTS {
                return Err(program_state::ProgramStateError::TooManyPayouts(payouts).into());
            }
            let segment = ledger.invoke_segment(record, tx).ok_or(TxError::MissingBundle)?;
            executor.decode_invoke(record, proof, &segment)
        }
        _ if ledger.hardening_v6() => {
            executor.decode_call_hardened(record, proof, &ledger.hardened_call_segment(record, &tx.call_binding(ledger.binding_domain())))
        }
        _ => executor.decode_call(record, proof),
    }
    .map_err(TxError::InvalidProof)?;
    // An invoke pays a call's floor plus `cell_fee` per cell it creates on this ledger (zero for
    // a call): the ledger's own post-verify floor, so the pool demands what a block does.
    // And `fees.prove_base` (`docs/compute-optimization.md` §6.3), which the ledger adds to every
    // bundle's floor: a pool that left it out would count it as surplus.
    let cells = program_state::cell_fee_of(ledger, &tx.action).saturating_add(ledger.prove_base_for(tx));
    if let Some(floor) = ledger.gas_call_floor(outcome.gas_limit, gas::call_bytes(proof, input_envelope.as_ref())) {
        return Ok(CallPricing { floor: floor.saturating_add(cells), gas_limit: Some(outcome.gas_limit) });
    }
    let floor = policy.call_floor(outcome.tier, outcome.keccak_log_height, outcome.sha256_log_height, gas::call_bytes(proof, input_envelope.as_ref()));
    Ok(CallPricing { floor: floor.saturating_add(cells), gas_limit: None })
}

/// What [`call_pricing`] read off a transaction: the floor it must pay at the ledger's prices
/// now, and — for a call on a chain with the genesis `gas` section — the `GAS_LIMIT` its proof
/// declares, which with the call's own bytes is all the ledger's rule needs to price it again
/// at another block's prices (audit v6, CH-9: the pool re-prices at selection without decoding
/// the proof a second time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallPricing {
    pub floor: u64,
    pub gas_limit: Option<u64>,
}

/// [`call_pricing`]'s floor alone.
pub fn call_floor(
    tx: &Transaction,
    ledger: &randprotocol_core::Ledger,
    executor: &dyn randprotocol_core::confidential::ConfidentialExecutor,
    policy: &randprotocol_core::gas::GasPolicy,
) -> Result<u64, TxError> {
    call_pricing(tx, ledger, executor, policy).map(|p| p.floor)
}

/// `FeeTooLow` naming `floor` when `tx` pays less; non-permanent (a floor a fee market moves).
pub fn fee_below_floor(tx: &Transaction, floor: u64) -> Option<TxError> {
    (tx.fee() < floor).then(|| TxError::FeeTooLow { min: floor, fee: tx.fee() })
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

    #[test]
    fn verify_limits_follow_the_cores_with_a_floor_of_four() {
        assert_eq!(VerifyLimits::for_cores(1), VerifyLimits { in_flight: 4, queue: 64 }, "a two-core droplet is today's 4/64");
        assert_eq!(VerifyLimits::for_cores(6), VerifyLimits { in_flight: 4, queue: 64 });
        assert_eq!(VerifyLimits::for_cores(8), VerifyLimits { in_flight: 6, queue: 96 });
        assert_eq!(VerifyLimits::for_cores(16), VerifyLimits { in_flight: 14, queue: 224 });
        assert_eq!(VerifyLimits::fixed(3).unwrap(), VerifyLimits { in_flight: 3, queue: 48 });
        assert!(VerifyLimits::fixed(0).unwrap_err().contains("at least 1"));
        // The queue is `workers × QUEUE_PER_WORKER`: a count whose queue overflows is refused,
        // not wrapped (final review M4).
        assert!(VerifyLimits::fixed(usize::MAX).unwrap_err().contains("too large"));
        assert!(VerifyLimits::fixed(usize::MAX / VerifyLimits::QUEUE_PER_WORKER).is_ok());
        assert!(VerifyLimits::for_host().in_flight >= 4);
    }

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

    /// I1: a `ProofRefused` is held per proved root — only that verdict, never past a root change,
    /// and bounded.
    #[test]
    fn the_proof_refused_cache_holds_one_roots_refusals() {
        use randprotocol_core::ledger::perps::PerpError as P;
        let refused = TxError::Perps(P::ProofRefused("outputs".into()));
        let key = |root: u32, seg: u8| StateProofKey { proved_root: [root; 8], segment: h(100 + seg) };
        let mut c = ProofRefusedCache::new(2);
        c.insert(h(1), key(1, 0), refused.clone());
        assert_eq!(c.get(&h(1), &key(1, 0)), Some(&refused));
        assert_eq!(c.get(&h(1), &key(2, 0)), None, "not against another root");
        assert_eq!(c.get(&h(1), &key(1, 1)), None, "not over another segment (another window's digests)");
        // Only `ProofRefused`: a window or digest refusal may be answered by the next block.
        c.insert(h(2), key(1, 0), TxError::Perps(P::MissingDigest(4)));
        c.insert(h(3), key(1, 0), TxError::Perps(P::WindowMismatch { from: 0, to: 1, proved: 1, max: 8 }));
        assert_eq!(c.len(), 1);
        // Bounded, oldest first.
        c.insert(h(4), key(1, 0), refused.clone());
        c.insert(h(5), key(1, 0), refused.clone());
        assert_eq!((c.len(), c.get(&h(1), &key(1, 0))), (2, None));
        // The root moves: every entry goes.
        c.insert(h(6), key(2, 0), refused.clone());
        assert_eq!(c.len(), 1);
        assert_eq!(c.get(&h(4), &key(1, 0)), None);
        assert_eq!(c.get(&h(6), &key(2, 0)), Some(&refused));
    }

    /// RPL-3: a perp refusal is cached only when it is about the bytes against genesis
    /// constants — the section's presence, its markets and tier cap, the action's own lists and
    /// amounts, a signature under a key no action rotates (an account id is its key's hash, an
    /// oracle's key its address). The nonces, the accounts, the pending withdrawals, the proved
    /// height and its digests, the validator set and the proof's verdict on a segment built from
    /// them move with the chain.
    #[test]
    fn a_perp_refusal_is_cached_only_when_it_is_about_the_bytes() {
        use randprotocol_core::ledger::perps::PerpError as P;
        for e in [
            P::Disabled,
            P::UnknownMarket(3),
            P::BadOrder("size"),
            P::BadSignature,
            P::TooManyPayouts(9),
            P::TierTooHigh { tier: 18, max: 16 },
            P::DuplicatePayout,
            P::BadPrice,
            P::AmountTooLarge(1 << 63),
            P::ReservedAccount,
            P::UnorderedPrices,
            P::CollateralAssetMismatch,
            P::KeyMismatch,
            P::ZeroAmount,
            P::DepositTooSmall(5),
            P::PartialPayout { want: 1, have: 2 },
        ] {
            assert!(is_permanent(&TxError::Perps(e.clone())), "{e} is a statement about the bytes");
        }
        for e in [
            P::NonceUsed,
            P::WindowMismatch { from: 0, to: 3, proved: 2, max: 8 },
            P::MissingDigest(4),
            P::UnknownRequest,
            P::UnknownAccount,
            P::TooManyWithdrawals,
            P::TooManyAccounts,
            P::NotValidator,
            P::OracleNonce,
            P::PayoutTooLarge { request: "ab".into(), want: 2, have: 1 },
            P::ProofRefused("outputs".into()),
            P::DuplicateOpening,
            P::Overflow,
            // The final fix wave's: the next block has room, a proof settles the pending
            // request, and a request's recorded height is state.
            P::BlockFull,
            P::AccountBlockFull,
            P::WithdrawalPending,
            P::RequestOutsideWindow { height: 3, from: 0, to: 2 },
        ] {
            assert!(!is_permanent(&TxError::Perps(e.clone())), "{e} moves with the chain");
        }
    }

    #[test]
    fn only_a_verdict_about_the_bytes_is_cached() {
        // A bad proof is a bad proof on every node forever.
        for e in [
            TxError::BadDigest,
            TxError::InvalidProof(ConfidentialError::MalformedProof),
            // The call tier cap reads the proof header alone (deep scan 2026-09-24, zkvm).
            TxError::InvalidProof(ConfidentialError::CallTierTooHigh { tier: 20, max: 14 }),
            TxError::InvalidBundleProof(ConfidentialError::MalformedProof),
            TxError::BadMintSignature,
            TxError::MintCommitmentMismatch,
            TxError::FaucetRecipientNotAllowed,
            TxError::ProofTooLarge,
            TxError::EnvelopeTooLarge,
            // Spec 2026-09-26 §2.4: an envelope's length against the genesis constant.
            TxError::EnvelopeSize { expected: 1860, got: 1348 },
            // Spec 2026-09-28 §4.3: the proof's own declared limit against a genesis constant.
            TxError::BundleGasLimit { want: 20_479, got: Some(20_480) },
            TxError::BundleGasLimit { want: 20_479, got: None },
            TxError::AuthGasLimit { want: 1_279, got: Some(1_280) },
            TxError::AuthGasLimit { want: 1_279, got: None },
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
            TxError::UnknownAnchor { window: 256 },
            TxError::TimeOutOfWindow { time: 3, height: 900, window: 256 },
            TxError::Spent([1; 8]),
            TxError::CommitmentExists([2; 8]),
            TxError::UnknownProgram(Hash::ZERO),
            TxError::MinterNotValidator(Address([3; 32])),
            // Audit v4, STAKE-2: the faucet budget is per epoch, and the next epoch admits the
            // very same bytes again — a cached refusal would censor the faucet for good.
            TxError::FaucetBudgetExhausted { budget: 100, minted: 100 },
        ] {
            assert!(!is_permanent(&e), "{e} depends on state and must not be cached");
        }
        // And the cache itself refuses one, so a wrong caller cannot poison it.
        let mut c = RefusedCache::new(4);
        c.insert(h(1), TxError::UnknownAnchor { window: 256 });
        assert_eq!(c.len(), 0);
    }

    /// B3's co-signature verdicts: the list's own bytes (order, lengths) are cached; the count
    /// and a failed verification are not, and no other bridge verdict is either.
    ///
    /// Audit v6, BRG-18: an index against the PQ set's size was cached too, as "the genesis PQ
    /// set, which no action changes" — and since bridge rules v2 (chains 15–18) `RotatePqGuardians`
    /// changes it. A node one block behind a rotation to a larger set cached `PqIndexOutOfRange`
    /// against the old size and refused the relayer's valid mint until it was restarted.
    #[test]
    fn only_the_byte_level_pq_verdicts_are_cached() {
        use randprotocol_core::bridge::BridgeError as B;
        for b in [B::PqIndexOrder, B::PqBadSignatureLength { index: 4, len: 2419 }] {
            let e = TxError::Bridge(b);
            assert!(is_permanent(&e), "{e} is a statement about the list's bytes");
        }
        for b in [
            B::PqIndexOutOfRange { index: 6, n: 6 },
            B::PqNoQuorum { have: 4, need: 5, n: 6 },
            B::PqBadSignature { index: 0 },
            B::Replay,
            B::WrongEmitter,
        ] {
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

    /// Bridge rules v2 (audit v4): the gate is a genesis constant and three verdicts are byte
    /// lengths or duplicates in the transaction's own key list, so they are cached; the nonce,
    /// the set-length rule (the current ECDSA set's size), the pause-key and guardian membership
    /// rules and the global cap are state and are not.
    #[test]
    fn the_rotation_verdicts_are_cached_only_when_they_are_about_the_bytes_or_the_genesis() {
        use randprotocol_core::bridge::BridgeError as B;
        use randprotocol_core::ledger::tokens::TokenError as T;
        for b in [B::RulesV2Disabled, B::BadPqGuardianKey { index: 1, len: 3 }, B::BadPauseKeyLength { len: 3 }, B::DuplicatePqGuardian] {
            let e = TxError::Bridge(b);
            assert!(is_permanent(&e), "{e} is about the bytes or the genesis");
        }
        for b in [
            B::BadRotationNonce { expected: 1, got: 0 },
            B::PqSetLengthMismatch { expected: 6, got: 5 },
            B::GuardianIsPauseKey,
            B::PauseKeyIsGuardian,
            B::Token(T::GlobalMintCapExceeded { cap: 10, minted: 10, amount: 1 }),
        ] {
            let e = TxError::Bridge(b);
            assert!(!is_permanent(&e), "{e} is state, not bytes");
        }
    }

    /// C15-1: the replay floor compares the attestation body's own `(emitter_chain, sequence)`
    /// with a genesis constant no action moves, so the same bytes are refused at every tip and the
    /// refusal is cached — a relayer replaying an old lock buys one decode, not a quorum's worth
    /// of recoveries per delivery.
    #[test]
    fn a_transfer_below_the_replay_floor_is_a_byte_verdict_and_is_cached() {
        use randprotocol_core::bridge::BridgeError as B;
        let e = TxError::Bridge(B::BelowReplayFloor { chain: 4, sequence: 1, floor: 2 });
        assert!(is_permanent(&e), "{e} is the body's bytes against a genesis constant");
    }

    /// Audit v6, BRG-18: a bad pause signature was cached as a verdict on the bytes against
    /// "the genesis `pause_key`, which no action changes". `RotatePauseKey` (bridge rules v2)
    /// changes it: a node that had not yet applied the rotation refused the new holder's valid
    /// `PauseMints` — the emergency brake — and remembered the refusal until restart.
    #[test]
    fn a_bad_pause_signature_depends_on_the_pause_key_and_is_not_cached() {
        use randprotocol_core::bridge::BridgeError as B;
        let e = TxError::Bridge(B::BadPauseSignature);
        assert!(!is_permanent(&e), "{e} reads the chain's current pause key");
    }

    /// Genesis vesting: a verdict against the entry's genesis terms — its keys, its revokers and
    /// their threshold, its treasury (audit v6, STAKE-3) — is about the bytes; the nonce, the
    /// schedule's position and whether the entry was revoked are state.
    #[test]
    fn vesting_verdicts_are_cached_only_when_they_are_about_the_bytes_or_genesis_terms() {
        use randprotocol_core::ledger::vesting::VestingError as V;
        for v in [
            V::BadSignature,
            V::UnknownEntry("07".repeat(32)),
            V::NotRevocable,
            V::BondNeedsIrrevocable,
            V::BadRecipient,
            V::BelowBundleBase { amount: 1, base: 2 },
            V::ZeroAmount,
            V::NotTheTreasury,
            V::BelowThreshold { have: 1, need: 2 },
            V::DuplicateRevoker(0),
            V::BadRevokerIndex(7),
        ] {
            let e = TxError::Vesting(v);
            assert!(is_permanent(&e), "{e} is a statement about the bytes or the entry's genesis terms");
        }
        for v in [
            V::BadNonce { expected: 1, actual: 0 },
            V::NotYetVested { available: 0, want: 1 },
            V::AlreadyRevoked,
            V::RevokeExceedsUnvested { unvested_now: 0, want: 1 },
            V::BondedElsewhere,
            V::NotFreeToBond { available: 0, want: 1 },
            V::NotBonded { bonded: 0, want: 1 },
            V::Overflow,
        ] {
            let e = TxError::Vesting(v);
            assert!(!is_permanent(&e), "{e} moves with the chain and time");
        }
    }

    /// Multisig accounts: a verdict on the transaction's own bytes — a signer set or threshold out
    /// of the creation bounds, a signer named twice, a payout list empty, over the cap or holding
    /// a zero amount, a deposit that burns nothing — is cached. Everything read off the account
    /// moves: its existence, its nonce, its vault, and its signer set and threshold, which a
    /// rotation replaces — so a signature that does not verify, a signer index past the current
    /// list and a list shorter than the current threshold may all be valid one rotation later.
    #[test]
    fn multisig_verdicts_split_into_bytes_and_state() {
        use randprotocol_core::ledger::multisig::MultisigError as M;
        for m in [
            M::BadSigners("0 signers".into()),
            M::DuplicateSigner(1),
            M::NoPayouts,
            M::TooManyPayouts(5),
            M::ZeroPayout,
            M::EmptyDeposit,
        ] {
            let e = TxError::Multisig(m);
            assert!(is_permanent(&e), "{e} is a statement about the bytes");
        }
        for m in [
            M::BadSignature(0),
            M::BelowThreshold { have: 1, need: 2 },
            M::BadSignerIndex(3),
            M::UnknownAccount("07".repeat(32)),
            M::AccountExists("07".repeat(32)),
            M::BadNonce { expected: 1, actual: 0 },
            M::VaultShort { asset: 0, have: 0, want: 1 },
            M::Overflow,
        ] {
            let e = TxError::Multisig(m);
            assert!(!is_permanent(&e), "{e} moves with the chain");
        }
        // The section's gate is a statement about the chain, like every `UnsupportedAction`.
        assert!(!is_permanent(&TxError::UnsupportedAction("multisig")));
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
            agg(A::SlashingRetired),
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

    /// RPL-2's verdicts, split like the registry's: cached are the ones the transition's own
    /// bytes decide (against compile-time constants, its own bundle's burn field, and the
    /// content-addressed program's public length); every verdict about cells, vaults, the
    /// registry or the chain's gate stays out — and for the two a busy program produces all day,
    /// the very same bytes are shown refused on one state and valid on the next.
    #[test]
    fn program_state_verdicts_are_cached_only_when_they_are_about_the_bytes() {
        use crate::storage::fixtures::{self, rpl2_cell, rpl2_invoke_tx, rpl2_payout, rpl2_transition, RPL2_FEE};
        use randprotocol_core::confidential::StubExecutor;
        use randprotocol_core::ledger::program_state::{ProgramStateError as P, Transition};
        let ps = |p: P| TxError::ProgramState(p);
        for e in [
            ps(P::TooManyReads(9)),
            ps(P::TooManyWrites(9)),
            ps(P::TooManyPayouts(5)),
            ps(P::UnorderedKeys),
            ps(P::InflowWithoutBurn),
            ps(P::InflowMissing { asset: 1, amount: 5 }),
            ps(P::ZeroPayout),
            ps(P::PayoutTooLarge(1 << 63)),
            ps(P::ContextTooLong { context: 139, public: 0, max: 119 }),
        ] {
            assert!(is_permanent(&e), "{e} is a statement about the bytes");
        }
        for e in [
            ps(P::Disabled),
            ps(P::StaleRead { key: "00".repeat(32) }),
            ps(P::VaultShort { asset: 0, have: 400, want: 600 }),
            // A token's authority is the registry's: the index may be this program's a block on.
            ps(P::NotProgramToken(3)),
            ps(P::Overflow),
        ] {
            assert!(!is_permanent(&e), "{e} depends on state and must not be cached");
        }

        // What makes caching the first list sound and the second unsound, on a ledger.
        let (_d, _s, _gs, l, _b1) = fixtures::rpl2_chain(7);
        let proposer = fixtures::key(1).address();
        // A read of cell 1 = 5 while the cell is absent is stale; once another invoke has
        // written 5 there, the same bytes are valid.
        let reader = rpl2_invoke_tx(&l, 10, RPL2_FEE, (0, 0, 0), Transition { reads: vec![rpl2_cell(1, 5)], ..rpl2_transition() });
        assert!(matches!(l.validate(&reader, &StubExecutor), Err(TxError::ProgramState(P::StaleRead { .. }))));
        let mut written = l.clone();
        let writer = rpl2_invoke_tx(&l, 20, RPL2_FEE, (0, 0, 0), Transition { writes: vec![rpl2_cell(1, 5)], ..rpl2_transition() });
        written.apply_tx(&writer, &proposer, &StubExecutor).unwrap();
        assert_eq!(written.validate(&reader, &StubExecutor), Ok(()), "the same bytes, one block later");
        // A payout from an empty vault is short; once another invoke has funded it, valid.
        let payer = rpl2_invoke_tx(&l, 30, RPL2_FEE, (0, 0, 0), Transition { pays: vec![rpl2_payout(0, 600, 1)], ..rpl2_transition() });
        assert_eq!(l.validate(&payer, &StubExecutor), Err(ps(P::VaultShort { asset: 0, have: 0, want: 600 })));
        let mut funded = l.clone();
        funded.apply_tx(&rpl2_invoke_tx(&l, 40, RPL2_FEE, (1_000, 0, 0), rpl2_transition()), &proposer, &StubExecutor).unwrap();
        assert_eq!(funded.validate(&payer, &StubExecutor), Ok(()));
        // A byte verdict is the same on every one of those states.
        let unordered = Transition { writes: vec![rpl2_cell(2, 1), rpl2_cell(1, 1)], ..rpl2_transition() };
        let bad = rpl2_invoke_tx(&l, 50, RPL2_FEE, (0, 0, 0), unordered);
        for state in [&l, &written, &funded] {
            assert_eq!(state.validate(&bad, &StubExecutor), Err(ps(P::UnorderedKeys)));
        }

        // The note-value screen reaches a payout: refused at the door, cached, before the bucket.
        let huge = Transition { pays: vec![rpl2_payout(0, 1 << 63, 1)], ..rpl2_transition() };
        let huge = rpl2_invoke_tx(&l, 60, RPL2_FEE, (0, 0, 0), huge);
        assert_eq!(oversized_note(&huge), Some(ps(P::PayoutTooLarge(1 << 63))));
        assert_eq!(l.validate(&huge, &StubExecutor), Err(ps(P::PayoutTooLarge(1 << 63))), "the ledger's own verdict");
        assert_eq!(oversized_note(&payer), None);
        let mut refused = RefusedCache::new(4);
        assert_eq!(
            GossipOutcome::for_transaction(&huge, None, &mut refused, &PeerLimiter::new(16, 4.0),  0, VerifyLimits::for_cores(1).queue, Instant::now()),
            GossipOutcome::Report(Acceptance::Reject)
        );
        assert!(refused.get(&huge.hash()).is_some());
    }

    /// The two header policies the pool applies to a call's proof — the private-table floor
    /// (COV-2) and the canonical-proof rules (INT-5) — read an `Invoke`'s call proof exactly as
    /// they read a `Call`'s: the same bytes under either action get the same answer.
    #[test]
    fn the_call_proof_policies_read_an_invokes_proof_as_a_calls() {
        use crate::storage::fixtures;
        use randprotocol_core::Action;
        use randprotocol_zkvm::machine::{Backend, FriProfile, Proof};

        let l = fixtures::rpl2_genesis(7).ledger;
        let program = randprotocol_zkvm::guests::private_payment(1000);
        let (bytes, _, _) =
            randprotocol_zkvm::executor::prove(FriProfile::Test, &program, &[400, 250, 300, 75], &[], None, Backend::Cpu, None).unwrap();
        let rewritten = |f: &dyn Fn(&mut Proof)| {
            let mut p: Proof = postcard::from_bytes(&bytes).unwrap();
            f(&mut p);
            p.to_bytes()
        };
        let pid = randprotocol_core::Hash::digest(b"program");
        let as_call = |proof: Vec<u8>| fixtures::v3_tx(&l, 50, fixtures::RPL2_FEE, Action::Call { program: pid, proof, input_envelope: None });
        let as_invoke = |proof: Vec<u8>| {
            let action = Action::Invoke { program: pid, proof, input_envelope: None, transition: fixtures::rpl2_transition() };
            fixtures::v3_tx(&l, 50, fixtures::RPL2_FEE, action)
        };
        assert_eq!(call_reveals_private_inputs(&as_invoke(bytes.clone())), None, "the honest header");
        assert_eq!(non_canonical_proofs(&as_invoke(bytes.clone())), None);
        let small = rewritten(&|p| p.input_log_height = 3);
        assert_eq!(
            call_reveals_private_inputs(&as_invoke(small.clone())),
            Some(TxError::CallRevealsPrivateInputs { table: "input", log_height: 3, min: 7 })
        );
        assert_eq!(call_reveals_private_inputs(&as_invoke(small.clone())), call_reveals_private_inputs(&as_call(small)));
        let taller = rewritten(&|p| p.mem_log_height += 1);
        let got = non_canonical_proofs(&as_invoke(taller.clone())).expect("a taller memory table is not what the honest prover writes");
        assert!(matches!(&got, TxError::NonCanonicalProof(w) if w.starts_with("call proof: memory height")), "{got}");
        assert_eq!(Some(got), non_canonical_proofs(&as_call(taller)));
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

    /// Deep scan 2026-09-24 (ledger arithmetic): a mint or deposit at or above 2^63 creates a
    /// note the hidden-asset guest can never spend. Chain 14's ledger admits one (its genesis has
    /// no `tokens.bound_note_value`), so the door is this node's only refusal there: the screen
    /// names each such transaction from its bytes, `for_transaction` rejects it before the
    /// bucket or the queue, and the verdict is cached as a byte verdict so the RPC answer names
    /// it and a repeat costs a lookup. One below the bound goes on to verify.
    #[test]
    fn a_note_at_or_above_the_bound_is_refused_at_the_door_on_every_chain() {
        use crate::storage::fixtures;
        use randprotocol_core::bridge::BridgeError as B;
        use randprotocol_core::confidential::StubExecutor;
        use randprotocol_core::ledger::tokens::TokenError as T;
        use randprotocol_core::notes::MAX_NOTE_VALUE;
        use randprotocol_core::Transaction;

        let (gs, secrets) = fixtures::bridged_genesis(1);
        let mut l = gs.ledger.clone();
        let register = fixtures::register_token_tx(&l, 5_000, 210);
        l.apply_tx(&register, &fixtures::key(1).address(), &StubExecutor).unwrap();
        l.record_anchor(0);
        let asset = l.tokens().unwrap().next_index() - 1;

        let mint = fixtures::token_mint_tx(&l, asset, MAX_NOTE_VALUE, 0, 220);
        assert_eq!(oversized_note(&mint), Some(TxError::Token(T::AmountTooLarge { amount: MAX_NOTE_VALUE })));
        assert_eq!(l.validate(&mint, &StubExecutor), Ok(()), "chain 14's ledger admits it: the door is the only refusal");
        let fits = fixtures::token_mint_tx(&l, asset, MAX_NOTE_VALUE - 1, 0, 220);
        assert_eq!(oversized_note(&fits), None);
        let initial = fixtures::register_token_tx(&l, MAX_NOTE_VALUE, 230);
        assert_eq!(oversized_note(&initial), Some(TxError::Token(T::AmountTooLarge { amount: MAX_NOTE_VALUE })));
        assert_eq!(oversized_note(&fixtures::register_token_tx(&l, MAX_NOTE_VALUE - 1, 230)), None);
        let deposit = |amount: u128, seq: u64| {
            fixtures::attest_tx(&l, fixtures::attestation(&secrets, &fixtures::recipient(), amount, seq), 240)
        };
        assert_eq!(oversized_note(&deposit(MAX_NOTE_VALUE as u128, 1)), Some(TxError::Bridge(B::AmountTooLarge)));
        assert_eq!(oversized_note(&deposit(u64::MAX as u128 + 1, 2)), Some(TxError::Bridge(B::AmountTooLarge)), "past u64 too");
        assert_eq!(oversized_note(&deposit(MAX_NOTE_VALUE as u128 - 1, 3)), None);
        let faucet = |amount: u64| Transaction::mint(1, [31; 8], 0, [31; 8], fixtures::env(3), amount, &fixtures::key(1), &StubExecutor);
        assert_eq!(oversized_note(&faucet(MAX_NOTE_VALUE)), Some(TxError::AmountTooLarge { amount: MAX_NOTE_VALUE }));
        assert_eq!(oversized_note(&faucet(MAX_NOTE_VALUE - 1)), None);

        // Each verdict is about the bytes and is cached; the supply's is state and is not.
        for e in [
            TxError::AmountTooLarge { amount: MAX_NOTE_VALUE },
            TxError::Token(T::AmountTooLarge { amount: MAX_NOTE_VALUE }),
            TxError::Bridge(B::AmountTooLarge),
        ] {
            assert!(is_permanent(&e), "{e} is a statement about the bytes");
        }
        assert!(!is_permanent(&TxError::Token(T::SupplyTooLarge { supply: 1, amount: 1 })), "a burn can make room");

        // The door: rejected before the bucket, cached, and the RPC answer names the verdict.
        let mut refused = RefusedCache::new(4);
        let limiter = PeerLimiter::new(16, 4.0);
        let now = Instant::now();
        assert_eq!(
            GossipOutcome::for_transaction(&mint, None, &mut refused, &limiter,  0, VerifyLimits::for_cores(1).queue, now),
            GossipOutcome::Report(Acceptance::Reject)
        );
        assert_eq!(
            rpc_refusal(Acceptance::Reject, &mint.hash(), &refused),
            MempoolError::Invalid(TxError::Token(T::AmountTooLarge { amount: MAX_NOTE_VALUE }))
        );
        let mut bucket = TokenBucket::default();
        assert_eq!(
            GossipOutcome::for_transaction(&deposit(MAX_NOTE_VALUE as u128, 4), Some(&mut bucket), &mut refused, &limiter,  0, VerifyLimits::for_cores(1).queue, now),
            GossipOutcome::Report(Acceptance::Reject)
        );
        // A byte verdict needs the hash, which is paid for only within the forwarder's allowance
        // (audit v6, GOSSIP-1): the refusal spent one token.
        assert_eq!(bucket.tokens, Some(15.0), "the refusal was reached within the peer's allowance");
        assert_eq!(GossipOutcome::for_transaction(&fits, None, &mut refused, &limiter,  0, VerifyLimits::for_cores(1).queue, now), GossipOutcome::Verify);
    }

    /// COV-2: a call proof whose input table is 2^3 rows (a four-word call, what every wallet's
    /// prover declares today) reveals its private inputs through the proof's openings; so does a
    /// keccak or sha256 table under 2^7. The pool refuses such a call before any verification, as
    /// a non-permanent policy verdict (Ignore, never cached). A header at the 2^7 floor — what the
    /// upstream prover now declares — pools; a proof that does not decode is the ledger's to
    /// refuse, not this screen's.
    #[test]
    fn a_call_whose_private_tables_are_under_the_floor_is_not_pooled() {
        use crate::mempool::{Mempool, MempoolError};
        use crate::storage::fixtures;
        use randprotocol_core::confidential::StubExecutor;
        use randprotocol_zkvm::machine::{Backend, FriProfile, Proof};

        let (gs, _) = fixtures::bridged_genesis(1);
        let l = gs.ledger.clone();
        let program = randprotocol_zkvm::guests::private_payment(1000);
        let (bytes, _, _) =
            randprotocol_zkvm::executor::prove(FriProfile::Test, &program, &[400, 250, 300, 75], &[], None, Backend::Cpu, None).unwrap();
        let honest: Proof = postcard::from_bytes(&bytes).unwrap();
        // The vendored prover floors the table itself since the COV-2 / INT-6 re-vendor, so a v0.6
        // wallet's four-word call declares 2^7; a wallet from before it declared 2^3 — the header
        // this screen reads, reproduced below by rewriting the height alone.
        assert_eq!(honest.input_log_height, 7, "a four-word call's input table, floored by the prover");
        assert_eq!((honest.keccak_log_height, honest.sha256_log_height), (0, 0));
        let call = |proof: Vec<u8>| {
            let action = randprotocol_core::Action::Call { program: randprotocol_core::Hash::digest(b"program"), proof, input_envelope: None };
            let b = fixtures::bundle(&l, [[50; 8], [51; 8]], [[52; 8], [53; 8]], randprotocol_core::gas::fee_floor(&action));
            StubExecutor::bound(Transaction::shielded(l.chain_id(), b, action))
        };
        let with = |f: &dyn Fn(&mut Proof)| {
            let mut p: Proof = postcard::from_bytes(&bytes).unwrap();
            f(&mut p);
            call(p.to_bytes())
        };
        let pool = Mempool::new(100);
        let refused = |tx: &Transaction| match pool.precheck(tx, &l, &StubExecutor) {
            Err(MempoolError::Invalid(e)) => Some(e),
            Err(other) => panic!("unexpected pool refusal {other}"),
            Ok(_) => None,
        };

        assert_eq!(refused(&call(bytes.clone())), None, "an upgraded wallet's floored call pools");
        let got = refused(&with(&|p| p.input_log_height = 3)).expect("the finding: a 2^3-row input table (an old wallet's) is pooled");
        assert_eq!(got, TxError::CallRevealsPrivateInputs { table: "input", log_height: 3, min: 7 });
        assert!(!is_permanent(&got), "policy, never cached");
        let mut cache = RefusedCache::new(4);
        assert_eq!(acceptance_for(&Err(got.clone()), Hash::digest(b"x"), &mut cache), Acceptance::Ignore);
        assert!(cache.is_empty());
        assert!(got.to_string().contains("upgrade the wallet"), "{got}");

        assert_eq!(refused(&with(&|p| p.input_log_height = 7)), None, "the floored header pools");
        assert_eq!(
            refused(&with(&|p| (p.input_log_height, p.keccak_log_height) = (7, 5))),
            Some(TxError::CallRevealsPrivateInputs { table: "keccak", log_height: 5, min: 7 })
        );
        assert_eq!(
            refused(&with(&|p| (p.input_log_height, p.sha256_log_height) = (7, 6))),
            Some(TxError::CallRevealsPrivateInputs { table: "sha256", log_height: 6, min: 7 })
        );
        // Heights at or above the floor pass this screen. (This header is a rewrite of a real
        // proof, so VERIFIER-2's canonical-shape screen now refuses it as a non-canonical proof —
        // a different verdict; the point here is that the privacy screen does not.)
        assert!(!matches!(
            refused(&with(&|p| (p.input_log_height, p.keccak_log_height, p.sha256_log_height) = (8, 7, 9))),
            Some(TxError::CallRevealsPrivateInputs { .. })
        ));
        assert_eq!(refused(&call(vec![4u8; 64])), None, "undecodable bytes are the ledger's to refuse");
        // The ledger itself never raises it: a block carrying such a call applies (StubExecutor
        // verifies stub proofs only, so the rule's absence is shown on the variant: nothing in
        // `randprotocol-core` constructs it).
    }

    /// ZKV-11 (pc-wrap): a deploy whose padded program table crosses the u32 pc wrap can never be
    /// proven — the circuit does PC arithmetic in the field, the emulator wraps — yet ZH4's
    /// `check_program` bounds only `base_pc + 4·len`, so fib's 15 words at `0xffffffc4` (ending
    /// exactly at 2^32, padding to 16 rows) pass it on every chain. The door refuses it from its
    /// bytes, before the bucket, as the ledger's own `BadProgram` verdict — a byte verdict, cached
    /// like `oversized_note`'s. The window is the floored table's (PCW-FLOOR: a hardened call
    /// declares 128 rows), so one word lower, `0xffffffc0`, is refused as well; `2^32 − 512` fits
    /// and goes on to verify.
    #[test]
    fn a_deploy_whose_padded_program_table_wraps_the_pc_space_is_refused_at_the_door() {
        use crate::storage::fixtures;
        use randprotocol_core::confidential::{ConfidentialExecutor, StubExecutor};
        use randprotocol_core::Transaction;

        let (gs, _) = fixtures::bridged_genesis(1);
        let l = gs.ledger.clone();
        let fib = randprotocol_zkvm::guests::fib(10);
        assert_eq!(fib.words.len(), 15, "the finding's program");
        let zk = randprotocol_zkvm::executor::ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
        assert!(zk.check_program(0xffff_ffc4, &fib.words).is_ok(), "ZH4's bound admits it: the gap");
        let deploy = |base_pc: u32| {
            let action = randprotocol_core::Action::Deploy { base_pc, words: fib.words.clone(), public: vec![] };
            let b = fixtures::bundle(&l, [[40; 8], [41; 8]], [[42; 8], [43; 8]], randprotocol_core::gas::fee_floor(&action));
            StubExecutor::bound(Transaction::shielded(l.chain_id(), b, action))
        };
        let wraps = deploy(0xffff_ffc4);
        let floored_wraps = deploy(0xffff_ffc0);
        let fits = deploy(0xffff_fe00);

        let mut refused = RefusedCache::new(4);
        let limiter = PeerLimiter::new(16, 4.0);
        let now = Instant::now();
        assert_eq!(
            GossipOutcome::for_transaction(&wraps, None, &mut refused, &limiter,  0, VerifyLimits::for_cores(1).queue, now),
            GossipOutcome::Report(Acceptance::Reject),
            "a program no call can prove is refused at the door"
        );
        let verdict = TxError::BadProgram(randprotocol_core::program::pc_window_error());
        assert_eq!(refused.get(&wraps.hash()), Some(&verdict), "cached as the byte verdict it is");
        assert!(is_permanent(&verdict));
        assert_eq!(
            GossipOutcome::for_transaction(&floored_wraps, None, &mut refused, &limiter,  0, VerifyLimits::for_cores(1).queue, now),
            GossipOutcome::Report(Acceptance::Reject),
            "PCW-FLOOR: its 16 rows end at 2^32, the 128 a hardened call declares do not"
        );
        assert_eq!(GossipOutcome::for_transaction(&fits, None, &mut refused, &limiter,  0, VerifyLimits::for_cores(1).queue, now), GossipOutcome::Verify);
        assert_eq!(GossipOutcome::for_transaction(&deploy(0), None, &mut refused, &limiter,  0, VerifyLimits::for_cores(1).queue, now), GossipOutcome::Verify);
    }

    /// CPU-1: a deploy past the most program words a tier-14 call can hold (8 184 with an empty
    /// public segment) is not pooled, on every chain — a non-permanent policy verdict (Ignore,
    /// never cached), the ledger's own `ProgramUncallable` under `hardening_v6`. 8 184 words pool;
    /// so does anything that is not a deploy.
    #[test]
    fn a_deploy_no_call_can_hold_is_not_pooled() {
        use crate::mempool::{Mempool, MempoolError};
        use crate::storage::fixtures;
        use randprotocol_core::confidential::StubExecutor;

        let (gs, _) = fixtures::bridged_genesis(1);
        let mut l = gs.ledger.clone();
        l.set_max_program_words(65_535);
        let deploy = |n: usize| {
            let action = randprotocol_core::Action::Deploy { base_pc: 0, words: vec![0x13; n], public: vec![] };
            let b = fixtures::bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], randprotocol_core::gas::fee_floor(&action));
            StubExecutor::bound(Transaction::shielded(l.chain_id(), b, action))
        };
        let pool = Mempool::new(100);
        let refused = |tx: &Transaction| match pool.precheck(tx, &l, &StubExecutor) {
            Err(MempoolError::Invalid(e)) => Some(e),
            Err(other) => panic!("unexpected pool refusal {other}"),
            Ok(_) => None,
        };
        let got = refused(&deploy(8185)).expect("the finding: a deploy no call can hold is pooled today");
        assert_eq!(got, TxError::ProgramUncallable { words: 8185, public_words: 0, max_words: 8184 });
        assert!(!is_permanent(&got), "policy, never cached");
        let mut cache = RefusedCache::new(4);
        assert_eq!(acceptance_for(&Err(got), Hash::digest(b"x"), &mut cache), Acceptance::Ignore);
        assert!(cache.is_empty());
        assert_eq!(refused(&deploy(8184)), None, "the bound itself pools");
        assert_eq!(deploy_uncallable(&deploy(18_009)).map(|e| e.to_string().contains("split the program")), Some(true));
    }

    /// INT-5 (the canonical-proof rules, first of three): a proof declaring a memory height other
    /// than the honest prover's — `t + 2` for a proof without a hash table, 16 for every bundle —
    /// is not pooled, on every chain, whether it is the call's proof or the bundle's: a
    /// non-permanent policy verdict (Ignore, never cached). The honest proof pools.
    #[test]
    fn a_proof_with_a_non_canonical_header_is_not_pooled() {
        use crate::mempool::{Mempool, MempoolError};
        use crate::storage::fixtures;
        use randprotocol_core::confidential::StubExecutor;
        use randprotocol_zkvm::machine::{Backend, FriProfile, Proof};

        let (gs, _) = fixtures::bridged_genesis(1);
        let l = gs.ledger.clone();
        let program = randprotocol_zkvm::guests::private_payment(1000);
        let (bytes, _, _) =
            randprotocol_zkvm::executor::prove(FriProfile::Test, &program, &[400, 250, 300, 75], &[], None, Backend::Cpu, None).unwrap();
        let honest: Proof = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(honest.mem_log_height, honest.tier.min_mem_log_height(), "the honest prover declares t + 2");
        let mut taller: Proof = postcard::from_bytes(&bytes).unwrap();
        taller.mem_log_height += 1;
        let taller = taller.to_bytes();
        let call = |proof: Vec<u8>| {
            let action = randprotocol_core::Action::Call { program: randprotocol_core::Hash::digest(b"program"), proof, input_envelope: None };
            let b = fixtures::bundle(&l, [[70; 8], [71; 8]], [[72; 8], [73; 8]], randprotocol_core::gas::fee_floor(&action));
            StubExecutor::bound(Transaction::shielded(l.chain_id(), b, action))
        };
        let pool = Mempool::new(100);
        let refused = |tx: &Transaction| match pool.precheck(tx, &l, &StubExecutor) {
            Err(MempoolError::Invalid(e)) => Some(e),
            Err(other) => panic!("unexpected pool refusal {other}"),
            Ok(_) => None,
        };
        assert_eq!(refused(&call(bytes.clone())), None, "the honest header pools");
        let got = refused(&call(taller.clone())).expect("the finding: a taller memory table is pooled today");
        let t = honest.tier.0;
        let want = format!("call proof: memory height {} where the honest prover declares {} (tier {t}, no hash table)", t + 3, t + 2);
        assert_eq!(got, TxError::NonCanonicalProof(want));
        assert!(!is_permanent(&got), "policy, never cached");
        let mut cache = RefusedCache::new(4);
        assert_eq!(acceptance_for(&Err(got), Hash::digest(b"x"), &mut cache), Acceptance::Ignore);
        assert!(cache.is_empty());
        // The bundle's proof is screened the same way (the header rule is the same one; a bundle's
        // honest memory height is its tier's, 16).
        let mut with_bundle = call(bytes);
        with_bundle.bundle.as_mut().unwrap().proof = taller;
        assert!(matches!(non_canonical_proofs(&with_bundle), Some(TxError::NonCanonicalProof(w)) if w.starts_with("bundle proof: memory height")));
    }

    /// RESCAN-LEDGER-1: the ledger's `Mint` arm asks only for a row in the register, which a
    /// permissionless `Bond` writes at once — and two epochs later (chain 15's
    /// `bond_activation_epochs`) the bonded key is in the active set too, so neither is a bound on
    /// who mints. The pool admits a faucet mint only from a genesis validator: the bonder, active
    /// or not, is refused at the pre-screen, at `insert_verified` and at a local insert, with an
    /// `Ignore` and no cache entry; a genesis validator's mint pools, and a key with no row still
    /// hears the ledger's own `MinterNotValidator`.
    #[test]
    fn admission_refuses_a_faucet_mint_by_a_bonded_key_even_once_it_is_in_the_active_set() {
        use crate::mempool::Mempool;
        use crate::storage::fixtures;
        use randprotocol_core::confidential::StubExecutor;
        use randprotocol_core::ledger::staking::MIN_STAKE;
        use randprotocol_core::ledger::{StakingConfig, ValidatorEntry};
        use randprotocol_core::{Keypair, Ledger, Transaction, UNITS_PER_RAND};

        let (operator, bonder, stranger) = (fixtures::key(1), fixtures::key(9), fixtures::key(10));
        let gs = fixtures::genesis_of(1, &[&operator], Vec::new(), 10);
        assert_eq!(faucet_minters(&gs), [operator.address()].into_iter().collect(), "the genesis validators");
        // The register two epochs after the bonder's v2 `Bond`: its row active from epoch 3, and
        // the ledger at epoch 3.
        let row = |k: &Keypair, activation_epoch: u64, i: u8| {
            let e = ValidatorEntry {
                public_key: k.public_key().clone(),
                stake: MIN_STAKE,
                pending: Vec::new(),
                rewards: 0,
                payout: fixtures::payout(i),
                nonce: 0,
                activation_epoch,
            };
            (k.address(), e)
        };
        let register = [row(&operator, 0, 1), row(&bonder, 3, 9)].into_iter().collect();
        let mut l = Ledger::new(1, fixtures::HC, register, &StubExecutor);
        l.set_faucet(true);
        l.set_epoch_blocks(10);
        l.set_height(30);
        l.set_staking(Some(StakingConfig {
            faucet_budget_per_epoch: 10_000 * UNITS_PER_RAND,
            bond_activation_epochs: 2,
            ..Default::default()
        }));
        assert!(l.derive_next_set(l.epoch()).contains(&bonder.address()), "the bonder is an active validator");
        let mint = |k: &Keypair, seed: u32| {
            Transaction::mint(1, [seed; 8], 30, [seed + 1; 8], fixtures::env(3), 100 * UNITS_PER_RAND, k, &StubExecutor)
        };
        let attack = mint(&bonder, 40);
        // The ledger alone admits it on a chain without `staking.faucet_minters` — the finding.
        assert_eq!(l.validate(&attack, &StubExecutor), Ok(()));

        let mut pool = Mempool::new(16);
        pool.set_faucet_minters(faucet_minters(&gs));
        let refusal = TxError::MinterNotAllowed(bonder.address());
        assert_eq!(pool.precheck(&attack, &l, &StubExecutor).err(), Some(MempoolError::Invalid(refusal.clone())));
        assert_eq!(pool.insert_verified(attack.clone(), &l, &StubExecutor), Err(MempoolError::Invalid(refusal.clone())));
        assert_eq!(pool.insert(attack.clone(), &l, &StubExecutor), Err(MempoolError::Invalid(refusal.clone())));
        // Not forwarded, nobody penalised, nothing cached.
        assert!(!is_permanent(&refusal), "{refusal} is this node's policy, not the bytes'");
        let mut refused = RefusedCache::new(4);
        assert_eq!(acceptance_for_pool(&MempoolError::Invalid(refusal), attack.hash(), &mut refused), Acceptance::Ignore);
        assert!(refused.is_empty());
        // A key with no row is the ledger's verdict, in the ledger's order.
        let unknown = mint(&stranger, 50);
        assert_eq!(
            pool.insert(unknown, &l, &StubExecutor),
            Err(MempoolError::Invalid(TxError::MinterNotValidator(stranger.address())))
        );
        // A genesis validator's mint still pools.
        let honest = mint(&operator, 60);
        assert!(pool.precheck(&honest, &l, &StubExecutor).is_ok());
        assert!(pool.insert(honest, &l, &StubExecutor).is_ok());
    }

    /// Where a genesis lists `staking.faucet_minters` the pool's minters are that list, not the
    /// genesis validators: a listed non-genesis key is admitted, an unlisted genesis key is not.
    #[test]
    fn the_pools_faucet_minters_are_the_genesis_list_when_it_names_one() {
        use crate::storage::fixtures;
        use randprotocol_core::genesis::{FaucetMinter, StakingConfig};
        use randprotocol_core::UNITS_PER_RAND;
        let (a, b, later) = (fixtures::key(1), fixtures::key(2), fixtures::key(9));
        let mut g = fixtures::genesis_file_of(1, &[&a, &b], Vec::new(), 10);
        g.staking = Some(StakingConfig { faucet_budget_per_epoch: 100 * UNITS_PER_RAND, bond_activation_epochs: 2, ..Default::default() });
        let gs = g.build(&randprotocol_core::confidential::StubExecutor).unwrap();
        assert_eq!(faucet_minters(&gs), [a.address(), b.address()].into_iter().collect());
        g.staking.as_mut().unwrap().faucet_minters = Some(vec![FaucetMinter(b.address()), FaucetMinter(later.address())]);
        let gs = g.build(&randprotocol_core::confidential::StubExecutor).unwrap();
        assert_eq!(faucet_minters(&gs), [b.address(), later.address()].into_iter().collect());
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
        const { assert!(FAUCET_MINT_BURST >= 5) };
        assert!(l.allow(&mut b, t0 + Duration::from_secs(1)), "one a second");
        assert!(!l.allow(&mut b, t0 + Duration::from_secs(1)));
        // And it never refills past the burst, however long the faucet is left alone.
        for i in 0..FAUCET_MINT_BURST {
            assert!(l.allow(&mut b, t0 + Duration::from_secs(3600)), "refilled {i}");
        }
        assert!(!l.allow(&mut b, t0 + Duration::from_secs(3600)), "the burst is the ceiling");
    }
}
