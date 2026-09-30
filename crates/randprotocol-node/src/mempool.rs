//! Pending transaction pool: validated against the tip ledger and offered to the proposer by
//! fee.
//!
//! A redacted chain has no senders and no nonces, so there is no per-sender ordering left to
//! do: a bundle is admissible or it is not, and two bundles are only related to each other when
//! they touch the same note. What replaces the old nonce bookkeeping is *conflict* tracking —
//! the pool never holds two transactions that spend the same nullifier, create the same
//! commitment, or consume the same bridge attestation digest, because at most one of them could
//! ever be included and carrying the other only wastes the proposer's block space and a
//! (~20 ms) proof verification per gossip round. Some of those commitments are not in the
//! transaction at all: the notes the *ledger* creates — a `Withdraw`'s deposit, whose owner is
//! the payout address in the register, a `BridgeAttest`'s, whose amount and asset come from
//! the attestation and the registry, and an `Aggregate`'s payout (spec §4 step 5), whose amount
//! is the subsidy the block would pay. Two of either can collide over one note just as two
//! bundles can collide over an output, so `Ledger::derived_commitment` answers for all three
//! and the pool claims what it answers.

use randprotocol_core::bridge::BridgeError;
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::ledger::bridge_notes;
use randprotocol_core::ledger::staking::StakingError;
use randprotocol_core::ledger::tokens::TokenError;
use randprotocol_core::notes::{word8_from_bytes, word8_to_hex};
use randprotocol_core::{Action, Address, Hash, Ledger, Transaction, TxError, Word8};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum MempoolError {
    #[error("{0}")]
    Invalid(TxError),
    #[error("already in mempool")]
    Duplicate,
    #[error("conflicts with a pending transaction over {}", word8_to_hex(.0))]
    Conflict(Word8),
    /// Two relayers raced the same bridge attestation. Their transactions share no nullifier and
    /// no commitment *of their own*, so the digest is what tells them apart — unless the two
    /// happened to choose the same blinding for the deposit, in which case the note they both
    /// derive collides first and the conflict is reported over that note instead.
    #[error("conflicts with a pending transaction over bridge attestation {0}")]
    AttestationConflict(Hash),
    #[error("mempool full")]
    Full,
}

/// What a transaction claims of the pool, as [`Mempool::precheck`] worked it out: the commitments
/// it creates — including the note the *ledger* would derive for a `Withdraw`, a `BridgeAttest`
/// or an `Aggregate`'s payout, which is not on the wire — and the register nonce slot it takes,
/// if any.
///
/// Returned rather than recomputed because the derivation costs a note hash and a registry lookup,
/// and because the caller that pools the transaction is not always the one that screened it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    pub commitments: Vec<Word8>,
    /// See [`claimed_nonce`]: `None` for every action but a bundle-less `Unbond` or `Withdraw`,
    /// or an `Aggregate`.
    pub claim: Option<(Address, u64)>,
    /// See [`claimed_token_slot`]: a token's `mint_nonce` for a `TokenMint` or `SetAuthority`,
    /// the registry index for a `RegisterToken`, `None` otherwise.
    pub token: Option<TokenClaim>,
    /// The floor this transaction was admitted against (spec 2026-09-28 §7's ordering key).
    pub floor: u64,
    /// A call's declared `GAS_LIMIT` on a chain with the genesis `gas` section, else `None`
    /// (audit v6, CH-9): what the pool re-prices the call from at selection, when the prices
    /// have moved since it was admitted.
    pub gas_limit: Option<u64>,
    /// Pooled transactions to drop so this one fits under the pool's byte cap (audit v6, CH-7;
    /// [`MAX_POOL_BLOCKS`]): each ranked strictly below it, cheapest per KiB first. Empty while
    /// the pool is under the cap, and always for a governance action.
    pub evict: Vec<Hash>,
    /// For a `BridgeAttest`, the bridge's `rotation_nonce` on the ledger it was screened against
    /// (audit v6, BRG-12); `None` for everything else. The attestation's post-quantum
    /// co-signatures were verified against the PQ guardian set of that moment, and a
    /// `RotatePqGuardians` replaces the set: once the nonce has moved the pooled verdict is no
    /// longer the ledger's, and the transaction leaves ([`Mempool::still_applies`]).
    pub bridge_rotation: Option<u64>,
}

/// A token-registry slot at most one pooled transaction may hold (H4 review minor): the ledger
/// accepts exactly one transaction per slot, so two pooled holders are a block that dies on its
/// own candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenClaim {
    /// Token `asset`'s `mint_nonce` — consumed by a `TokenMint` *and* by a `SetAuthority`,
    /// which share the counter.
    Nonce { asset: u32, nonce: u64 },
    /// The registry index a `RegisterToken` is held to (`TokenError::IndexMismatch`).
    Index(u32),
}

impl TokenClaim {
    /// A display key for the conflict, through the same `Conflict(Word8)` the other maps use:
    /// a tag word (`"tokn"` or `"tidx"`), the index, and the nonce's two halves.
    fn conflict_key(&self) -> Word8 {
        match *self {
            TokenClaim::Nonce { asset, nonce } => {
                [u32::from_le_bytes(*b"tokn"), asset, nonce as u32, (nonce >> 32) as u32, 0, 0, 0, 0]
            }
            TokenClaim::Index(index) => [u32::from_le_bytes(*b"tidx"), index, 0, 0, 0, 0, 0, 0],
        }
    }
}

/// The token-registry slot `action` consumes, if any — see [`TokenClaim`].
fn claimed_token_slot(action: &Action) -> Option<TokenClaim> {
    match action {
        Action::TokenMint { asset, nonce, .. } | Action::SetAuthority { asset, nonce, .. } => {
            Some(TokenClaim::Nonce { asset: *asset, nonce: *nonce })
        }
        Action::RegisterToken { index, .. } => Some(TokenClaim::Index(*index)),
        _ => None,
    }
}

/// A pooled transaction and the commitments it claims.
///
/// The claims are remembered rather than recomputed because one of them is not on the wire: the
/// note a `Withdraw`, a `BridgeAttest` or an `Aggregate` makes the ledger create comes from the
/// register or the asset registry, via `Ledger::derived_commitment`, so a transaction leaving
/// the pool could not name it again without a ledger to hand.
struct Pooled {
    tx: Transaction,
    commitments: Vec<Word8>,
    /// The register nonce this transaction claims, for an `Unbond`, a `Withdraw` or an
    /// `Aggregate` — see [`claimed_nonce`].
    claim: Option<(Address, u64)>,
    /// The token-registry slot it claims — see [`claimed_token_slot`].
    token: Option<TokenClaim>,
    /// When this transaction entered the pool, for `Mempool::info`'s oldest-entry age.
    since: Instant,
    /// `tx.encoded_len()`, taken once at admission: that is a full re-encode (a ~1.2 MB proof
    /// included), and `info` and `candidates_within` would otherwise pay it per entry per call.
    len: usize,
    /// The floor this transaction was admitted against — see [`Claims::floor`].
    floor: u64,
    /// See [`Claims::gas_limit`].
    gas_limit: Option<u64>,
    /// See [`Claims::bridge_rotation`].
    bridge_rotation: Option<u64>,
}

/// The register nonce a bundle-less `Unbond` or `Withdraw` claims — and the aggregator
/// register's nonce-consuming actions, one register over: an `Aggregate`'s (spec §4 step 5)
/// and an `UnbondAggregator`'s or `WithdrawAggregator`'s `(aggregator, nonce)`. `None` for
/// every other action. Two pooled transactions can never both apply at the same nonce — the
/// register accepts only the one matching its current nonce — so this is a pool-level claim
/// exactly like a commitment: at most one pooled transaction may hold it.
fn claimed_nonce(action: &Action) -> Option<(Address, u64)> {
    match action {
        Action::Unbond { validator, nonce, .. } | Action::Withdraw { validator, nonce, .. } => {
            Some((*validator, *nonce))
        }
        Action::Aggregate { aggregator, nonce, .. }
        | Action::UnbondAggregator { aggregator, nonce, .. }
        | Action::WithdrawAggregator { aggregator, nonce, .. } => Some((*aggregator, *nonce)),
        // Bridge hardening B1: the bridge's one `pause_nonce`, which a pause and an unpause share.
        // There is no address to key it on — the bridge is one register of one — so the zero
        // address stands in, and `claim_key`'s role keeps it apart from every validator's.
        Action::PauseMints { nonce, .. } | Action::UnpauseMints { nonce, .. } => Some((Address([0; 32]), *nonce)),
        // B4: the bridge's `list_nonce`, shared the same way by a registration and a listing.
        Action::RegisterBridgedToken { nonce, .. } | Action::ListBacking { nonce, .. } => Some((Address([0; 32]), *nonce)),
        // Bridge rules v2: the bridge's `rotation_nonce`, shared by the two rotations.
        Action::RotatePqGuardians { nonce, .. } | Action::RotatePauseKey { nonce, .. } => Some((Address([0; 32]), *nonce)),
        // Genesis vesting: the entry's nonce, which all four of its actions share — keyed on the
        // entry's 32-byte id, kept apart from every address by `claim_key`'s role.
        Action::ClaimVested { entry, nonce, .. }
        | Action::RevokeVesting { entry, nonce, .. }
        | Action::BondVested { entry, nonce, .. }
        | Action::UnbondVested { entry, nonce, .. } => Some((Address(*entry), *nonce)),
        _ => None,
    }
}

/// A display key for a `(validator, nonce)` conflict: the validator's address bytes, reported
/// through the same `Conflict(Word8)` the commitment and nullifier maps use. The nonce itself is
/// not part of the key — for a given validator, at most one nonce is ever claimed at a time.
fn claim_conflict_key(validator: &Address) -> Word8 {
    word8_from_bytes(validator.as_bytes()).expect("an address is exactly 32 bytes, like a Word8")
}

/// The claims map's key: the register the nonce belongs to, so one keypair's two roles — a
/// validator's `Unbond` and an aggregator's `Aggregate` at the same nonce — never collide over
/// a slot the two registers do not share (chain-9 runs both roles on the same ops keys).
/// The six bridge governance actions (bridge hardening B1/B4, bridge rules v2): the emergency
/// pause, its lifting, the two listings and the two rotations. They are exempt from the pool's
/// capacity refusal and ordered ahead of fee order among a block's candidates (node I4) — a
/// brake that can be crowded out is not a brake, and a key rotation after a compromise is the
/// same kind of thing. All are safe only because [`claimed_nonce`]/[`claim_key`] already bound
/// roles 2, 3 and 4 to one pooled transaction each, which tests assert.
fn is_governance(action: &Action) -> bool {
    matches!(
        action,
        Action::PauseMints { .. }
            | Action::UnpauseMints { .. }
            | Action::RegisterBridgedToken { .. }
            | Action::ListBacking { .. }
            | Action::RotatePqGuardians { .. }
            | Action::RotatePauseKey { .. }
    )
}

/// The pool holds at most this many blocks' worth of transaction bytes (audit v6, CH-7): eight
/// times the ledger's `max_block_bytes` — 160 MiB on a 20 MiB-block chain. The count cap alone
/// (10 000) bounded nothing in bytes when a transaction runs from 1.3 MB to over 12 MB. Eight
/// blocks is more than a proposer can use before the pool is refilled by gossip; past it an
/// entry that pays more per KiB displaces the cheapest (see [`Mempool::make_room`]).
pub const MAX_POOL_BLOCKS: usize = 8;

/// A transaction's fee above its floor, per KiB of its encoding (spec 2026-09-28 §7): the key the
/// proposer ranks candidates by under a price, and the key the byte cap evicts by (audit v6,
/// CH-7) — what a byte of this transaction pays beyond what it must.
fn surplus_per_kib(fee: u64, floor: u64, len: usize) -> u128 {
    (fee.saturating_sub(floor) as u128 * 1024) / len.max(1) as u128
}

fn claim_key(action: &Action, claim: &(Address, u64)) -> (u8, Address, u64) {
    let role = match action {
        Action::Aggregate { .. } | Action::UnbondAggregator { .. } | Action::WithdrawAggregator { .. } => 1u8,
        Action::PauseMints { .. } | Action::UnpauseMints { .. } => 2,
        Action::RegisterBridgedToken { .. } | Action::ListBacking { .. } => 3,
        Action::RotatePqGuardians { .. } | Action::RotatePauseKey { .. } => 4,
        Action::ClaimVested { .. } | Action::RevokeVesting { .. } | Action::BondVested { .. } | Action::UnbondVested { .. } => 5,
        _ => 0,
    };
    (role, claim.0, claim.1)
}

pub struct Mempool {
    txs: HashMap<Hash, Pooled>,
    /// Which pooled transaction spends each nullifier — one owner per nullifier, always.
    nullifiers: HashMap<Word8, Hash>,
    /// Which pooled transaction creates each commitment: a bundle's two output slots, a mint's
    /// single note, or the deposit a `Withdraw` or a `BridgeAttest` will make the ledger create.
    commitments: HashMap<Word8, Hash>,
    /// Which pooled transaction claims each register's next action — an `Unbond` or `Withdraw`'s
    /// `(validator, nonce)`, an `Aggregate`'s `(aggregator, nonce)` — keyed by register and
    /// address the same way `commitments` claims a note (see [`claim_key`]).
    claims: HashMap<(u8, Address, u64), Hash>,
    /// Which pooled transaction holds each token-registry slot: a token's `mint_nonce`, or the
    /// next registration index (see [`TokenClaim`]).
    token_claims: HashMap<TokenClaim, Hash>,
    /// Which pooled transaction consumes each bridge attestation digest. A digest is spendable
    /// once, like a nullifier, but it is not a field of the transaction — see
    /// `Transaction::bridge_digests`.
    digests: HashMap<Hash, Hash>,
    /// The sum of every pooled entry's `len`, kept on insert and on `remove_one` — the only two
    /// places `txs` changes — so `info` reads it rather than summing the pool on the node loop.
    bytes: usize,
    max_size: usize,
    /// The keys whose faucet `Mint`s this pool admits (`admission::faucet_minters`,
    /// RESCAN-LEDGER-1), set once by the node from its genesis. `None` — a pool nobody configured,
    /// every unit test's — is no policy, the ledger's rule alone.
    faucet_minters: Option<BTreeSet<Address>>,
    /// This node's gas policy (spec 2026-09-28 §4.1, Phase 0), set once from its
    /// `--gas-price`/`--byte-price`. `None` — a pool nobody configured, every unit test's — is no
    /// policy, the ledger's own `fee_floor` alone.
    gas_policy: Option<randprotocol_core::gas::GasPolicy>,
}

/// Every commitment `tx` claims: the ones it carries, plus the deposit `ledger` would derive for
/// it. Two transactions claiming one commitment can never both be included, so the pool holds at
/// most one of them — which is what makes a second `Withdraw` paying the same note, or a second
/// relayer's `BridgeAttest` deriving it, a conflict here rather than a transaction the proposer
/// silently drops at its trial apply.
fn claimed_commitments(tx: &Transaction, ledger: &Ledger, executor: &dyn ConfidentialExecutor) -> Vec<Word8> {
    let mut v = tx.commitments();
    v.extend(ledger.derived_commitment(&tx.action, executor));
    v
}

/// A snapshot of the pool's occupancy for `rand_getMempoolInfo`: how many transactions it
/// holds, their combined encoded size, and how long the oldest of them has waited — `None` when
/// the pool is empty, since there is no entry to date it against.
#[derive(Clone, Debug, Serialize)]
pub struct MempoolInfo {
    pub count: usize,
    pub bytes: usize,
    pub oldest_ms: Option<u64>,
    pub max_count: usize,
}

impl Mempool {
    pub fn new(max_size: usize) -> Mempool {
        Mempool {
            txs: HashMap::new(),
            nullifiers: HashMap::new(),
            commitments: HashMap::new(),
            claims: HashMap::new(),
            token_claims: HashMap::new(),
            digests: HashMap::new(),
            bytes: 0,
            max_size,
            faucet_minters: None,
            gas_policy: None,
        }
    }

    /// Admit faucet `Mint`s only from `minters` (`admission::faucet_minters`). The node calls this
    /// once, with what its genesis names; the set never changes while the process runs.
    pub fn set_faucet_minters(&mut self, minters: BTreeSet<Address>) {
        self.faucet_minters = Some(minters);
    }

    /// Price calls by their proof header (spec 2026-09-28 §4.1, Phase 0). The node calls this
    /// once from its `--gas-price`/`--byte-price`; the policy never changes while it runs.
    pub fn set_gas_policy(&mut self, policy: randprotocol_core::gas::GasPolicy) {
        self.gas_policy = Some(policy);
    }

    /// The floor `tx` must pay here: on a chain with the genesis `gas` section, the ledger's own
    /// rule for a call (spec §4.2 — the policy is not read there); else the gas policy's for a
    /// call under one, the schedule's otherwise — refusing below it.
    fn gas_policy_floor(
        &self,
        tx: &Transaction,
        ledger: &Ledger,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<crate::admission::CallPricing, TxError> {
        use crate::admission::{call_pricing, CallPricing};
        let pricing = match (&self.gas_policy, ledger.gas()) {
            (Some(p), _) => call_pricing(tx, ledger, executor, p)?,
            // `call_pricing` answers the ledger rule under the section whatever policy it is handed.
            (None, Some(_)) => call_pricing(tx, ledger, executor, &randprotocol_core::gas::GasPolicy::DEFAULT)?,
            (None, None) => CallPricing { floor: randprotocol_core::gas::fee_floor(&tx.action), gas_limit: None },
        };
        match crate::admission::fee_below_floor(tx, pricing.floor) {
            Some(e) => Err(e),
            None => Ok(pricing),
        }
    }

    /// The floor a pooled transaction must pay on top of `ledger` (audit v6, CH-9). For a call
    /// admitted under the genesis `gas` section that is the ledger's rule at the prices in force
    /// *now* — `BUNDLE_BASE + gas_price·GAS_LIMIT + byte_price·KiB`, from the limit remembered at
    /// admission and the call's own bytes — and for everything else the floor it was admitted
    /// at, which does not move.
    fn current_floor(p: &Pooled, ledger: &Ledger) -> u64 {
        match (&p.tx.action, p.gas_limit) {
            (Action::Call { proof, input_envelope, .. }, Some(limit)) => ledger
                .gas_call_floor(limit, randprotocol_core::gas::call_bytes(proof, input_envelope.as_ref()))
                .unwrap_or(p.floor),
            _ => p.floor,
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

    /// The pool's occupancy as of `now`: count, combined encoded size, and the oldest entry's
    /// age in milliseconds (`None` when the pool is empty).
    pub fn info(&self, now: Instant) -> MempoolInfo {
        MempoolInfo {
            count: self.txs.len(),
            bytes: self.bytes,
            oldest_ms: self.txs.values().map(|p| now.saturating_duration_since(p.since).as_millis() as u64).max(),
            max_count: self.max_size,
        }
    }

    pub fn get(&self, hash: &Hash) -> Option<&Transaction> {
        self.txs.get(hash).map(|p| &p.tx)
    }

    /// Validate against `ledger` (the state the next block will build on) and insert.
    ///
    /// Cheap admission decisions come first: `Ledger::validate` clones nothing but does verify
    /// the bundle's STARK, so a duplicate, a conflict or a full pool has to be answered before
    /// paying that cost for every gossiped transaction. Those are [`Mempool::pool_conflicts`], and
    /// `validate` answers everything else — including the staleness [`Mempool::applies`] screens
    /// pre-pool, so that a transaction refused for two reasons at once is refused with the
    /// *ledger's* first one. A wrong-chain wallet whose anchor has also scrolled out hears
    /// `WrongChain`, which is a statement about its bytes and which it can act on, rather than
    /// `UnknownAnchor`, which is a statement about this node.
    pub fn insert(
        &mut self,
        tx: Transaction,
        ledger: &Ledger,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Hash, MempoolError> {
        let c = self.pool_conflicts(&tx, ledger, executor)?;
        ledger.validate(&tx, executor).map_err(MempoolError::Invalid)?;
        // The pool's policies (the faucet minter rule, COV-2's call screen) after the ledger's own
        // verdict: this path runs no `precheck`, and it is the one a local `rand_mint` takes.
        self.pool_policy(&tx, ledger).map_err(MempoolError::Invalid)?;
        let mut c = c;
        let pricing = self.gas_policy_floor(&tx, ledger, executor).map_err(MempoolError::Invalid)?;
        (c.floor, c.gas_limit) = (pricing.floor, pricing.gas_limit);
        c.evict = self.make_room(&tx, c.floor, ledger)?;
        Ok(self.admit(tx, c))
    }

    /// Room for `tx` under the byte cap (audit v6, CH-7): `MAX_POOL_BLOCKS` × the ledger's
    /// `max_block_bytes`, read from the ledger each time so it follows the chain's genesis. Under
    /// the cap, nothing to drop. Over it, the pooled entries ranked strictly below `tx` — by
    /// [`surplus_per_kib`] over each one's floor on this tip, then fee — are taken cheapest first
    /// until `tx` fits; if they are not enough, `tx` is the one that does not belong: `Full`.
    /// A tie is not "below", so an equal newcomer never churns the pool. Governance actions are
    /// exempt from the cap as from the count cap — admitted past it and never taken to make room
    /// — and their bytes still count, as their entries count towards the count cap.
    fn make_room(&self, tx: &Transaction, floor: u64, ledger: &Ledger) -> Result<Vec<Hash>, MempoolError> {
        if is_governance(&tx.action) {
            return Ok(Vec::new());
        }
        let cap = ledger.max_block_bytes().saturating_mul(MAX_POOL_BLOCKS);
        let len = tx.encoded_len();
        let over = self.bytes.saturating_add(len).saturating_sub(cap);
        if over == 0 {
            return Ok(Vec::new());
        }
        let key = (surplus_per_kib(tx.fee(), floor, len), tx.fee());
        let mut below: Vec<((u128, u64), &Hash, usize)> = self
            .txs
            .iter()
            .filter(|(_, p)| !is_governance(&p.tx.action))
            .map(|(h, p)| ((surplus_per_kib(p.tx.fee(), Self::current_floor(p, ledger), p.len), p.tx.fee()), h, p.len))
            .filter(|(k, _, _)| *k < key)
            .collect();
        // Cheapest first; among equals the higher hash goes first, the mirror of the proposer's
        // lower-hash-first tie break, so every node evicts the same entries.
        below.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(a.1)));
        let (mut freed, mut evict) = (0usize, Vec::new());
        for (_, h, l) in below {
            if freed >= over {
                break;
            }
            freed += l;
            evict.push(*h);
        }
        if freed < over {
            return Err(MempoolError::Full);
        }
        Ok(evict)
    }

    /// The pool's own half of admission: this transaction against the ones already held, and
    /// against the capacity. Nothing here reads the ledger except to derive the commitments the
    /// transaction claims, and nothing here costs a proof verification.
    ///
    /// Returns those commitments — including the note the ledger would derive for a `Withdraw`
    /// **or a `BridgeAttest`**, which is why the executor is a parameter — and the
    /// `(validator, nonce)` it claims, so no caller recomputes either.
    fn pool_conflicts(
        &self,
        tx: &Transaction,
        ledger: &Ledger,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Claims, MempoolError> {
        let hash = tx.hash();
        if self.txs.contains_key(&hash) {
            return Err(MempoolError::Duplicate);
        }
        for nf in tx.nullifiers() {
            if self.nullifiers.contains_key(&nf) {
                return Err(MempoolError::Conflict(nf));
            }
        }
        let commitments = claimed_commitments(tx, ledger, executor);
        for cm in &commitments {
            if self.commitments.contains_key(cm) {
                return Err(MempoolError::Conflict(*cm));
            }
        }
        let claim = claimed_nonce(&tx.action);
        if let Some(claim) = claim {
            if self.claims.contains_key(&claim_key(&tx.action, &claim)) {
                return Err(MempoolError::Conflict(claim_conflict_key(&claim.0)));
            }
        }
        let token = claimed_token_slot(&tx.action);
        if let Some(t) = token {
            if self.token_claims.contains_key(&t) {
                return Err(MempoolError::Conflict(t.conflict_key()));
            }
        }
        for mu in tx.bridge_digests() {
            if self.digests.contains_key(&mu) {
                return Err(MempoolError::AttestationConflict(mu));
            }
        }
        // The capacity check is last, and the four governance actions are outside it (node I4).
        // `PauseMints` is the brake for a guardian-key compromise: bundle-less, fee-less, and
        // the one transaction that must reach a block while an attacker is minting. It used to
        // enter the pool like anything else — refused `Full` at 10 000 entries — and `rand_mint`
        // hands out a free, fee-less pooled transaction per call, so filling every reachable
        // validator's pool and keeping the pause out cost an attacker nothing. Exempting them is
        // safe because their nonce claims, checked above, already bound each of the two roles to
        // **one** pooled transaction at a time: the exemption can add at most two entries past
        // the cap, not an unbounded flood.
        if !is_governance(&tx.action) && self.txs.len() >= self.max_size {
            return Err(MempoolError::Full);
        }
        let bridge_rotation = match &tx.action {
            Action::BridgeAttest { .. } => ledger.bridge().map(|b| b.rotation_nonce),
            _ => None,
        };
        Ok(Claims { commitments, claim, token, floor: randprotocol_core::gas::fee_floor(&tx.action), gas_limit: None, evict: Vec::new(), bridge_rotation })
    }

    /// Everything the pool can decide about a transaction without verifying a proof: the pool
    /// conflicts and the capacity [`Mempool::insert`] also answers, plus the state-dependent half of
    /// `Ledger::validate` (anchor, time, nullifiers, commitments, attestation digests, the register
    /// nonce) — which `insert` leaves to `validate` itself, so that a submitter hears the ledger's
    /// own first refusal. Returns what
    /// [`Mempool::pool_conflicts`] worked out — the claimed commitments and the claimed
    /// `(validator, nonce)` — so the caller that pools the transaction afterwards computes neither
    /// again.
    ///
    /// This is a *pre-screen*, not a verdict: it is for a caller deciding whether to spend ~20 ms
    /// verifying a proof, so it answers with the cheapest refusal it can see and leaves the ledger's
    /// own ordering of the rest to `validate`. Safe to run twice — once before a verification is
    /// scheduled, once against the tip it will actually be pooled on. It takes `&self`, so a caller
    /// may ask before it holds the pool mutably.
    pub fn precheck(
        &self,
        tx: &Transaction,
        ledger: &Ledger,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Claims, MempoolError> {
        let c = self.pool_conflicts(tx, ledger, executor)?;
        Self::applies(tx, &c.commitments, c.claim, ledger).map_err(MempoolError::Invalid)?;
        self.pool_policy(tx, ledger).map_err(MempoolError::Invalid)?;
        let mut c = c;
        let pricing = self.gas_policy_floor(tx, ledger, executor).map_err(MempoolError::Invalid)?;
        (c.floor, c.gas_limit) = (pricing.floor, pricing.gas_limit);
        // Before any proof is verified for it: a transaction the byte cap would refuse costs no
        // verification (audit v6, CH-7).
        c.evict = self.make_room(tx, c.floor, ledger)?;
        Ok(c)
    }

    /// RESCAN-LEDGER-1's admission policy (`admission::minter_not_allowed`) against this pool's
    /// minter set, when the node configured one. Asked here and in [`Mempool::insert`] only, not
    /// at every tip like [`Mempool::applies`]: the set is fixed for the process, so a mint that
    /// passed once passes for as long as it is pooled.
    ///
    /// COV-2's screen rides here too (`admission::call_reveals_private_inputs`), unconditionally:
    /// a call whose proof would disclose its private inputs is not pooled, before any verification
    /// is scheduled for it. Policy like the minter rule — never permanent, never the ledger's.
    ///
    /// CPU-1's (`admission::deploy_uncallable`) too: a deploy no call can hold is not pooled; and
    /// the canonical-proof rules' (`admission::non_canonical_proofs`). Policy on every chain, and
    /// the ledger's own rules only under genesis `hardening_v6`.
    fn pool_policy(&self, tx: &Transaction, ledger: &Ledger) -> Result<(), TxError> {
        if let Some(e) = crate::admission::call_reveals_private_inputs(tx) {
            return Err(e);
        }
        if let Some(e) = crate::admission::deploy_uncallable(tx) {
            return Err(e);
        }
        // And the canonical-proof rules (INT-5, VERIFIER-1/-2): a header the honest prover would
        // not write, on the bundle's proof or the call's. The ledger's own rule under
        // `hardening_v6`; policy here on every chain.
        if let Some(e) = crate::admission::non_canonical_proofs(tx) {
            return Err(e);
        }
        match &self.faucet_minters {
            Some(minters) => crate::admission::minter_not_allowed(tx, ledger, minters).map_or(Ok(()), Err),
            None => Ok(()),
        }
    }

    /// Insert a transaction whose proof has already been verified. Re-runs [`Mempool::precheck`],
    /// because the tip has moved since the verification was scheduled — a nullifier spent, a
    /// commitment created or an anchor scrolled out in the meantime is caught here, on the state
    /// the transaction is actually being pooled on.
    ///
    /// **The caller must have just run `Ledger::validate` on this transaction, against a snapshot of
    /// this same chain**, and must treat a failure of it as a refusal. This method re-checks only
    /// what can go *stale*; it does not re-check, and cannot, what `validate` alone looks at — the
    /// bundle and call proofs, the attestation's guardian quorum, the fee floor, the burn shape,
    /// and a `BridgeAttest`'s derived deposit colliding with its own bundle's outputs. (All four
    /// of a bundle's nullifiers and commitments are claimed, through `Transaction::nullifiers`
    /// /`commitments`.) Pool a transaction here whose proof nobody verified and the pool will
    /// offer the proposer a block that dies on its own candidate.
    pub fn insert_verified(
        &mut self,
        tx: Transaction,
        ledger: &Ledger,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Hash, MempoolError> {
        let c = self.precheck(&tx, ledger, executor)?;
        Ok(self.admit(tx, c))
    }

    /// Take ownership of `tx`'s claims and pool it. Every caller has just run
    /// [`Mempool::pool_conflicts`] for this transaction, so no index entry written here can collide
    /// with one that exists.
    fn admit(&mut self, tx: Transaction, c: Claims) -> Hash {
        let Claims { commitments, claim, token, floor, gas_limit, evict, bridge_rotation } = c;
        // The byte cap's evictions first (audit v6, CH-7), through `remove_one`, which releases
        // every index the entry held; `make_room` chose them on this same pool a moment ago.
        for h in &evict {
            if self.remove_one(h).is_some() {
                tracing::debug!(evicted = %h, "pool at its byte cap: evicted for a transaction paying more per KiB");
            }
        }
        let hash = tx.hash();
        for nf in tx.nullifiers() {
            self.nullifiers.insert(nf, hash);
        }
        for cm in &commitments {
            self.commitments.insert(*cm, hash);
        }
        if let Some(claim) = claim {
            self.claims.insert(claim_key(&tx.action, &claim), hash);
        }
        if let Some(t) = token {
            self.token_claims.insert(t, hash);
        }
        for mu in tx.bridge_digests() {
            self.digests.insert(mu, hash);
        }
        let len = tx.encoded_len();
        self.bytes += len;
        // `pool_conflicts` refuses a hash already pooled, so nothing is replaced here; if that
        // ever changes, the replaced entry's bytes must leave the total with it.
        if let Some(old) = self.txs.insert(hash, Pooled { tx, commitments, claim, token, since: Instant::now(), len, floor, gas_limit, bridge_rotation }) {
            self.bytes -= old.len;
        }
        hash
    }

    /// Transactions ready for inclusion on top of `ledger`, highest surplus per KiB first, then
    /// fee, and ties broken by hash so every honest proposer building on the same pool picks the
    /// same block.
    pub fn candidates(&self, ledger: &Ledger, max: usize) -> Vec<Transaction> {
        self.candidates_within(ledger, max, usize::MAX)
    }

    /// Every pooled aggregate's `(tx hash, cover set)` — the commit path's §3.4 rule (a pooled
    /// aggregate whose cover just sealed leaves the pool) reads nothing else of the pool.
    pub fn pooled_aggregate_covers(&self) -> Vec<(Hash, Vec<Hash>)> {
        self.txs
            .values()
            .filter_map(|p| match &p.tx.action {
                Action::Aggregate { covers, .. } => Some((p.tx.hash(), covers.clone())),
                _ => None,
            })
            .collect()
    }

    /// What a proposer packs on top of `ledger`: at most `gas::MAX_BLOCK_TXS` transactions within
    /// the ledger's `max_block_bytes` — this chain's block cap as its genesis set it, the same cap
    /// `Ledger::apply_block_for_sync` enforces on the block.
    pub fn block_candidates(&self, ledger: &Ledger) -> Vec<Transaction> {
        self.candidates_within(ledger, randprotocol_core::gas::MAX_BLOCK_TXS, ledger.max_block_bytes())
    }

    /// Like `candidates`, but keeps the encoded size of the selection within `max_bytes`, skipping
    /// any transaction that would not fit rather than ending the selection at it.
    ///
    /// Only pool-level re-checks happen here (the ledger may have moved since insertion): a
    /// transaction whose anchor has scrolled out, whose nullifier was spent, or whose commitment
    /// now exists is skipped rather than offered. The proposer's own `apply_transactions` is
    /// still the authority; this only avoids proposing a block that would fail.
    pub fn candidates_within(&self, ledger: &Ledger, max: usize, max_bytes: usize) -> Vec<Transaction> {
        // Each entry with the floor it must pay on this tip (audit v6, CH-9): a call whose floor
        // has risen past its fee would fail `FeeTooLow` in the proposer's trial apply, so it is
        // not offered — it stays pooled, the price falls again — and it takes no candidate slot.
        let mut ready: Vec<(&Hash, &Pooled, u64)> = self
            .txs
            .iter()
            .filter(|(_, p)| Self::still_applies(p, ledger))
            .map(|(h, p)| (h, p, Self::current_floor(p, ledger)))
            .filter(|(_, p, floor)| p.tx.fee() >= *floor)
            .collect();
        // Spec 2026-09-28 §7: governance first, then the fee above the admitted floor per KiB of
        // transaction (bytes are what a block is short of), then total fee, then hash so every
        // honest proposer on the same pool picks the same block. A `PauseMints` pays
        // `fee() == 0` by design — it must work from a wallet holding no RAND at all — so fee
        // order sorted the emergency brake behind every transaction that pays, which is the
        // wrong end of a block while a compromised guardian set is minting.
        //
        // The surplus-per-KiB key applies under a gas policy or on a chain whose genesis carries
        // the `gas` section (calls are priced there by the ledger's own rule, and each pooled
        // floor is that rule's): a node without either orders exactly as before the gas work
        // (governance, total fee, hash), so switching the policy off is a true no-op there.
        let priced = self.gas_policy.is_some() || ledger.gas().is_some();
        // The surplus is over the floor on this tip, not the one the entry was admitted at.
        let surplus_per_kib = |p: &Pooled, floor: u64| if priced { surplus_per_kib(p.tx.fee(), floor, p.len) } else { 0 };
        ready.sort_by(|a, b| {
            is_governance(&b.1.tx.action)
                .cmp(&is_governance(&a.1.tx.action))
                .then_with(|| surplus_per_kib(b.1, b.2).cmp(&surplus_per_kib(a.1, a.2)))
                .then_with(|| b.1.tx.fee().cmp(&a.1.tx.fee()))
                .then_with(|| a.0.cmp(b.0))
        });
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for (_, p, _) in ready.into_iter().take(max) {
            let len = p.len;
            if bytes + len > max_bytes {
                // Skip it, do not end the block. `break` meant one transaction that cannot fit —
                // sorted first because it pays the highest fee — produced *empty* blocks for as
                // long as it stayed pooled. Admission now refuses a transaction larger than a block
                // outright (`TxError::TransactionTooLarge`), so what reaches here is only a
                // transaction too large for the space *left*, and a smaller one behind it should
                // still travel.
                continue;
            }
            bytes += len;
            out.push(p.tx.clone());
        }
        out
    }

    /// The cheap half of `Ledger::validate` — everything that can go stale between insertion and
    /// the next block, and nothing that costs a proof verification.
    ///
    /// Shared by [`Mempool::precheck`], before a transaction is pooled, and
    /// [`Mempool::still_applies`], after: the two ask the same question a block apart. It reports
    /// the `TxError` each check stands for, because the pre-pool caller answers a submitter and the
    /// post-pool one only needs a yes or no.
    fn applies(
        tx: &Transaction,
        commitments: &[Word8],
        claim: Option<(Address, u64)>,
        ledger: &Ledger,
    ) -> Result<(), TxError> {
        // An `Aggregate`'s byte-level checks (spec §4 step 1) come before any register state,
        // here exactly as they do in the worker's `validate_for_pool`: a wrong chain id or an
        // oversized part is a verdict about the bytes — cacheable the moment it is answered
        // (`admission::is_permanent`) — and it must not be pre-empted by the register's
        // state-dependent answers below. The same argument the attestation size cap makes for
        // running in this pre-screen at all.
        if matches!(tx.action, Action::Aggregate { .. }) {
            ledger.preflight_aggregate(tx)?;
        }
        // A pooled attestation whose guardian set the chain has retired can never be admitted
        // again, and nothing else in this function looks at the bridge's sets — so before this it
        // sat in the pool until a restart, taking a slot and being offered to every block
        // (fullnode issue #4). Checked at every tip change through `prune`, which is where a
        // rotation becomes visible. The size cap runs first, as everywhere: an oversized blob must
        // not buy a decode.
        if let Action::BridgeAttest { attestation, .. } = &tx.action {
            if attestation.len() > randprotocol_core::gas::MAX_ATTESTATION_BYTES {
                return Err(TxError::AttestationTooLarge);
            }
            if let Some(bridge) = ledger.bridge() {
                if let Ok(att) = randprotocol_core::bridge::Attestation::decode(attestation) {
                    if !bridge.guardian_sets.contains_key(&att.guardian_set_index) {
                        return Err(TxError::Bridge(randprotocol_core::bridge::BridgeError::Verify(
                            randprotocol_core::bridge::VerifyError::UnknownGuardianSet(att.guardian_set_index),
                        )));
                    }
                }
            }
        }
        if let Some(b) = &tx.bundle {
            if !ledger.is_anchor(&b.anchor) {
                return Err(TxError::UnknownAnchor);
            }
            if !ledger.time_in_window(b.time) {
                return Err(TxError::TimeOutOfWindow { time: b.time, height: ledger.height() });
            }
        }
        // A bundle-less `Withdraw` (S2) carries a `time` of its own, under the same window rule —
        // so it goes stale here the same way a bundle does (`Ledger::time_in_window`). An
        // `Aggregate`'s payout note's `time` (spec §4 step 3) is the same promise, one action
        // over, and a `WithdrawAggregator`'s note time is its `Withdraw` twin's, one register over.
        if let Action::Withdraw { time, .. }
        | Action::Aggregate { time, .. }
        | Action::WithdrawAggregator { time, .. }
        | Action::ClaimVested { time, .. }
        | Action::RevokeVesting { time, .. } = &tx.action
        {
            if !ledger.time_in_window(*time) {
                return Err(TxError::TimeOutOfWindow { time: *time, height: ledger.height() });
            }
        }
        // A `BridgeAttest`'s `time` (S3) goes stale by that same rule, and it is not the bundle's:
        // a transaction whose attestation has aged out would be admitted here and then kill the
        // block it was offered to.
        if let Action::BridgeAttest { attestation, time, asset, .. } = &tx.action {
            // The size cap, before the decode below. `validate` applies it at step 1
            // (`TxError::AttestationTooLarge`), but this runs *before* validation — a pre-pool
            // caller screens a gossiped transaction in order to decide whether to validate it at
            // all — so a multi-megabyte blob would otherwise buy a full attestation decode at no
            // fee. `Ledger::derived_commitment` guards the same decode for the same reason
            // (randprotocol-core `staking.rs`, the `BridgeAttest` arm). Nothing admissible is lost: a
            // transaction over the cap is refused, here and there.
            if attestation.len() > randprotocol_core::gas::MAX_ATTESTATION_BYTES {
                return Err(TxError::AttestationTooLarge);
            }
            if !ledger.time_in_window(*time) {
                return Err(TxError::TimeOutOfWindow { time: *time, height: ledger.height() });
            }
            // And its `asset` is screened against the registry the same way: the action names the
            // index its envelope was sealed for, and admission holds it to the index the token
            // registry gives that asset (`TxError::AttestAssetMismatch`). A listed token's index
            // never moves — listing, not first sighting, is what hands one out — so this is a
            // plain compare now rather than a race the pool had to watch; it stays because a
            // transaction built against another chain's registry, or against a node that had not
            // yet seen a listing, would otherwise sit in the pool until restart. Decoding the
            // attestation costs no signature work, and a rotation (which decodes to no transfer)
            // binds no index.
            if let Some((chain, token, _)) = bridge_notes::attested_transfer(attestation) {
                // No bridge is the bridge's own verdict rather than a mismatch — the error
                // `Ledger::validate` gives it, so a caller that prechecks before validating hears
                // the same thing either way. A pooled attest can only exist on a bridged chain, so
                // this arm is unreachable from `still_applies`.
                let Some(bridge) = ledger.bridge() else {
                    return Err(TxError::Bridge(BridgeError::Disabled));
                };
                // A transfer is refused while mints are paused (audit v6, BRG-12) — the ledger's
                // own first verdict on it (`BridgeState::check_attestation`), asked here so a
                // pooled mint leaves at the tip that paused rather than being offered to, and
                // failing, every block until its `time` expires. Rotations are not transfers
                // and stay open under a pause, as the ledger keeps them.
                if bridge.mint_paused {
                    return Err(TxError::Bridge(BridgeError::MintsPaused));
                }
                // A coin nobody listed as a backing deposits nothing at all, and `validate`'s
                // answer for it is the bridge's `UnlistedToken` rather than a mismatched index —
                // the index the action names is not wrong, there is simply nothing to deposit.
                // `validate`'s own pre-screen is silent in that case for the same reason; this
                // one cannot be, because a `false` from `still_applies` is what takes the
                // transaction out of the pool.
                //
                // The pair is destructured out of the same decode, so there is nothing left to
                // re-derive here and no second decode to be surprised by: `attested_transfer`
                // answered `Some`, so the `(chain, token)` in hand is the one this attestation
                // names. (It used to be re-read with an `expect` on gossip-fed bytes.)
                match ledger.tokens().and_then(|t| t.bridged(chain, &token)).map(|info| info.index) {
                    Some(index) if index == *asset => {}
                    Some(index) => {
                        return Err(TxError::AttestAssetMismatch { expected: index, actual: *asset })
                    }
                    None => return Err(TxError::Bridge(BridgeError::UnlistedToken { chain, token })),
                }
            }
        }
        // An `Unbond` or `Withdraw` carries no anchor, nullifier or commitment of its own — the
        // register's nonce is the only thing that can make it stale. Once the validator's nonce
        // has moved past the one this transaction signed over, it can never apply again (the
        // register does not rewind), so it has to leave here rather than sit in every pool
        // (and every proposal's trial-apply) until the node restarts. An `Aggregate`'s claim is
        // the aggregator register's nonce, so it is read there (spec §4 step 5).
        if let Some((addr, nonce)) = claim {
            if matches!(tx.action, Action::PauseMints { .. } | Action::UnpauseMints { .. }) {
                // B1: the bridge's `pause_nonce`, which only moves forward — a pooled pause or
                // unpause signed for a nonce it has passed can never apply again.
                let bridge = ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled))?;
                if bridge.pause_nonce != nonce {
                    return Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: bridge.pause_nonce, got: nonce }));
                }
            } else if matches!(tx.action, Action::RotatePqGuardians { .. } | Action::RotatePauseKey { .. }) {
                // Bridge rules v2: the bridge's `rotation_nonce`, the same rule a counter over.
                let bridge = ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled))?;
                if bridge.rotation_nonce != nonce {
                    return Err(TxError::Bridge(BridgeError::BadRotationNonce { expected: bridge.rotation_nonce, got: nonce }));
                }
            } else if matches!(tx.action, Action::RegisterBridgedToken { .. } | Action::ListBacking { .. }) {
                // B4: the bridge's `list_nonce`, the same rule one counter over.
                let bridge = ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled))?;
                if bridge.list_nonce != nonce {
                    return Err(TxError::Bridge(BridgeError::BadListNonce { expected: bridge.list_nonce, got: nonce }));
                }
            } else if matches!(
                tx.action,
                Action::ClaimVested { .. } | Action::RevokeVesting { .. } | Action::BondVested { .. } | Action::UnbondVested { .. }
            ) {
                // Genesis vesting: the entry's nonce, which only moves forward. Never the
                // validator lookup below — an entry id is not a validator address.
                use randprotocol_core::ledger::vesting::VestingError;
                let reg = ledger.vesting().ok_or(TxError::UnsupportedAction("vesting"))?;
                match reg.get(&addr.0).map(|e| e.nonce) {
                    Some(current) if current == nonce => {}
                    Some(current) => {
                        return Err(TxError::Vesting(VestingError::BadNonce { expected: current, actual: nonce }))
                    }
                    None => return Err(TxError::Vesting(VestingError::UnknownEntry(hex::encode(addr.0)))),
                }
            } else if matches!(
                tx.action,
                Action::Aggregate { .. } | Action::UnbondAggregator { .. } | Action::WithdrawAggregator { .. }
            ) {
                use randprotocol_core::ledger::aggregation::AggregationError;
                match ledger.aggregators().get(&addr).map(|e| e.nonce) {
                    Some(current) if current == nonce => {}
                    Some(current) => {
                        return Err(TxError::Aggregation(AggregationError::BadNonce { expected: current, actual: nonce }))
                    }
                    None => return Err(TxError::Aggregation(AggregationError::UnknownAggregator(addr))),
                }
            } else {
                match ledger.validators().get(&addr).map(|e| e.nonce) {
                    Some(current) if current == nonce => {}
                    Some(current) => {
                        return Err(TxError::Staking(StakingError::BadNonce { expected: current, actual: nonce }))
                    }
                    None => return Err(TxError::Staking(StakingError::UnknownValidator(addr))),
                }
            }
        }
        // A token slot goes stale the same way a register nonce does: once the token's
        // `mint_nonce` has moved past the one signed over, or the registry has handed out the
        // index a registration is held to, the transaction can never apply again. On a chain
        // without the tokens gate, and for a token the registry does not hold, `validate` gives
        // its own answer; there is nothing to go stale here.
        if let Some(tokens) = ledger.tokens() {
            match claimed_token_slot(&tx.action) {
                Some(TokenClaim::Nonce { asset, nonce }) => {
                    if let Some(info) = tokens.get(asset) {
                        if info.mint_nonce != nonce {
                            return Err(TxError::Token(TokenError::BadNonce { expected: info.mint_nonce, got: nonce }));
                        }
                    }
                }
                Some(TokenClaim::Index(index)) if index != tokens.next_index() => {
                    return Err(TxError::Token(TokenError::IndexMismatch { expected: tokens.next_index(), got: index }));
                }
                _ => {}
            }
        }
        let nullifiers = tx.nullifiers();
        if let Some(nf) = nullifiers.iter().find(|nf| ledger.is_spent(nf)) {
            return Err(TxError::Spent(*nf));
        }
        // The claims include a derived deposit, so a note someone else created in the meantime
        // takes the withdraw or the attest that would have created it out of the pool too.
        if let Some(cm) = commitments.iter().find(|cm| ledger.has_commitment(cm)) {
            return Err(TxError::CommitmentExists(*cm));
        }
        let digests = tx.bridge_digests();
        if digests.iter().any(|mu| ledger.is_digest_spent(mu)) {
            return Err(TxError::Bridge(BridgeError::Replay));
        }
        Ok(())
    }

    fn still_applies(p: &Pooled, ledger: &Ledger) -> bool {
        // A pooled attestation whose PQ co-signatures were checked against a set that has since
        // been rotated (audit v6, BRG-12). Compared by the bridge's rotation nonce rather than by
        // verifying again: six Dilithium2 verifies per pooled attestation per tip change is the
        // cost this avoids, and a pause-key rotation (the same nonce) costs a relayer one resend.
        if p.bridge_rotation.is_some() && p.bridge_rotation != ledger.bridge().map(|b| b.rotation_nonce) {
            return false;
        }
        Self::applies(&p.tx, &p.commitments, p.claim, ledger).is_ok()
    }

    /// Forget these transactions — called with a committed block's hashes.
    pub fn remove(&mut self, hashes: &[Hash]) {
        for h in hashes {
            self.remove_one(h);
        }
    }

    fn remove_one(&mut self, hash: &Hash) -> Option<Transaction> {
        let p = self.txs.remove(hash)?;
        self.bytes -= p.len;
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
        if let Some(claim) = p.claim {
            let key = claim_key(&p.tx.action, &claim);
            if self.claims.get(&key) == Some(hash) {
                self.claims.remove(&key);
            }
        }
        if let Some(t) = p.token {
            if self.token_claims.get(&t) == Some(hash) {
                self.token_claims.remove(&t);
            }
        }
        for mu in p.tx.bridge_digests() {
            if self.digests.get(&mu) == Some(hash) {
                self.digests.remove(&mu);
            }
        }
        Some(p.tx)
    }

    /// Drop txs that can no longer apply on `ledger`: a nullifier spent by someone else, a
    /// commitment that now exists, an attestation digest another relayer's transaction already
    /// consumed, an anchor that has scrolled out of the window, or a `time` that has fallen out
    /// of it. Called after every commit.
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
    use randprotocol_core::bridge::{digest, sign_digest, Attestation, Body, Payload, Transfer, CHAIN_RAND};
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::ledger::ANCHOR_WINDOW;
    use randprotocol_core::notes::ShieldedAddress;
    use randprotocol_core::types::Action;
    use std::time::Duration;

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
        // The byte budget keeps the selection inside a block rather than overflowing it.
        let one = dear.encoded_len();
        assert_eq!(m.candidates_within(&l, 10, one).len(), 1);
        assert_eq!(m.candidates_within(&l, 10, 1).len(), 0);
        assert_eq!(m.candidates_within(&l, 10, usize::MAX).len(), 2);
    }

    /// The proposer's selection (spec §4, proposer packing) is bounded by the ledger's
    /// `max_block_bytes` and `MAX_BLOCK_TXS`, not the default block constant.
    #[test]
    fn block_candidates_pack_to_the_ledgers_block_cap() {
        let mut l = ledger();
        let mut m = Mempool::new(100);
        let cheap = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        let dear = fixtures::bundle_tx(&l, [nf(3), nf(4)], [cm(3), cm(4)], fixtures::bundle_fee() * 3);
        m.insert(cheap.clone(), &l, &StubExecutor).unwrap();
        m.insert(dear.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.block_candidates(&l), vec![dear.clone(), cheap.clone()], "a default block carries both");
        l.set_max_block_bytes(dear.encoded_len() + cheap.encoded_len() - 1);
        assert_eq!(m.block_candidates(&l), vec![dear.clone()], "the ledger's cap, not the constant");
        l.set_max_block_bytes(dear.encoded_len() + cheap.encoded_len());
        assert_eq!(m.block_candidates(&l), vec![dear, cheap]);
    }

    #[test]
    fn info_counts_bytes_and_the_oldest_entry() {
        let l = ledger();
        let mut pool = Mempool::new(100);
        let tx = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        pool.insert(tx.clone(), &l, &StubExecutor).unwrap();
        let t0 = Instant::now();
        let empty = Mempool::new(10).info(t0);
        assert_eq!((empty.count, empty.bytes, empty.oldest_ms, empty.max_count), (0, 0, None, 10));
        let info = pool.info(t0 + Duration::from_millis(1_500));
        assert_eq!(info.count, 1);
        assert_eq!(info.bytes, tx.encoded_len());
        assert!(info.oldest_ms.unwrap() >= 1_500);
    }

    /// The running byte total: two entries sum, the older one dates the pool, and removing
    /// both — one committed, one pruned — brings the total back to zero rather than leaving
    /// either's bytes behind.
    #[test]
    fn info_keeps_a_running_byte_total_across_insert_remove_and_prune() {
        let l = ledger();
        let mut pool = Mempool::new(100);
        let a = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        let b = fixtures::bundle_tx(&l, [nf(3), nf(4)], [cm(3), cm(4)], fixtures::bundle_fee() * 2);
        pool.insert(a.clone(), &l, &StubExecutor).unwrap();
        pool.insert(b.clone(), &l, &StubExecutor).unwrap();
        // `a` has waited ten seconds longer; `since` is only ever set by admission, so move it.
        let older = Instant::now().checked_sub(Duration::from_secs(10)).expect("the clock is past ten seconds");
        pool.txs.get_mut(&a.hash()).unwrap().since = older;
        let now = Instant::now();
        let info = pool.info(now);
        assert_eq!(info.count, 2);
        assert_eq!(info.bytes, a.encoded_len() + b.encoded_len());
        assert_eq!(info.oldest_ms, Some(now.duration_since(older).as_millis() as u64), "the older entry dates the pool");
        assert!(info.oldest_ms.unwrap() >= 10_000);

        // Asked about an instant before either entry arrived, the age saturates at zero.
        let before = older.checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(pool.info(before).oldest_ms, Some(0));

        pool.remove(&[a.hash()]);
        assert_eq!(pool.info(now).bytes, b.encoded_len());
        // `b` lands on the ledger by some other route: its nullifiers are spent, so it is pruned.
        let mut spent = l.clone();
        spent.apply_tx(&b, &fixtures::key(1).address(), &StubExecutor).unwrap();
        pool.prune(&spent);
        let info = pool.info(now);
        assert_eq!((info.count, info.bytes, info.oldest_ms), (0, 0, None));
    }

    /// A transaction larger than a block never enters the pool.
    ///
    /// The RPC body limit admits one — two `MAX_PROOF_BYTES` proofs each pass the per-part caps and
    /// together exceed `MAX_BLOCK_BYTES` — so without this the pool would hold a transaction no
    /// block could ever carry, and `candidates_within` would meet it on every proposal.
    #[test]
    fn a_transaction_larger_than_a_block_is_refused_at_insert() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let mut big = fixtures::bundle(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        // A proof inside its own cap, twice over once the action carries one too.
        big.proof = vec![3u8; randprotocol_core::gas::MAX_PROOF_BYTES];
        let tx = randprotocol_core::confidential::StubExecutor::bound(Transaction::shielded(
            l.chain_id(),
            big,
            Action::Call {
                program: randprotocol_core::Hash::digest(b"program"),
                proof: vec![4u8; randprotocol_core::gas::MAX_PROOF_BYTES],
                input_envelope: None,
            },
        ));
        assert!(
            tx.encoded_len() > randprotocol_core::gas::MAX_BLOCK_BYTES,
            "the fixture must be unminable: {} B",
            tx.encoded_len()
        );

        let err = m.insert(tx, &l, &StubExecutor).unwrap_err();
        match err {
            MempoolError::Invalid(randprotocol_core::ledger::TxError::TransactionTooLarge { size: n, max }) => {
                assert!(n > randprotocol_core::gas::MAX_BLOCK_BYTES, "the error should carry the size: {n}");
                assert_eq!(max, randprotocol_core::gas::MAX_BLOCK_BYTES, "and the ledger's cap");
            }
            other => panic!("expected TransactionTooLarge, got {other}"),
        }
        assert_eq!(m.len(), 0, "nothing should have been pooled");
    }

    /// A transaction that does not fit is skipped, not treated as the end of the block.
    ///
    /// It used to `break`: a transaction too big for the budget, sorted first because it paid the
    /// most, produced *empty* blocks for as long as it stayed pooled — one poisoned entry stalling
    /// throughput for every other sender.
    #[test]
    fn a_candidate_that_does_not_fit_is_skipped_so_a_smaller_one_behind_it_still_travels() {
        let l = ledger();
        let mut m = Mempool::new(100);
        // The dear one pays more, so it sorts first and is met first by the byte budget — and it is
        // bigger, so it is the one that does not fit. The padding goes in the envelopes, which the
        // bundle digest does not cover, so the fixture's stub proof still verifies.
        let cheap = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        let mut big = fixtures::bundle(&l, [nf(3), nf(4)], [cm(3), cm(4)], fixtures::bundle_fee() * 3);
        for e in &mut big.envelopes {
            e.body = vec![7u8; 512];
        }
        let dear = randprotocol_core::confidential::StubExecutor::bound(Transaction::shielded(l.chain_id(), big, Action::None));
        m.insert(cheap.clone(), &l, &StubExecutor).unwrap();
        m.insert(dear.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.candidates(&l, 10), vec![dear.clone(), cheap.clone()], "the dear one sorts first");

        // A budget that fits the cheap one but not the dear one.
        let budget = dear.encoded_len() - 1;
        assert!(cheap.encoded_len() <= budget, "the cheap one has to fit for this test to mean anything");
        assert_eq!(
            m.candidates_within(&l, 10, budget),
            vec![cheap],
            "the block should carry the transaction that fits, not come back empty"
        );
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

    /// The split the off-loop verification needs: `precheck` decides everything that does not cost
    /// a proof verification, and `insert_verified` does the rest without paying for one. Together
    /// they must accept and reject exactly what `insert` does.
    #[test]
    fn precheck_and_insert_verified_agree_with_insert() {
        let gs = fixtures::genesis_with(1, vec![fixtures::alloc_note(20, 5 * randprotocol_core::UNITS_PER_RAND)]);
        let ledger = gs.ledger.clone();
        let tx = fixtures::bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fixtures::bundle_fee());

        let mut a = Mempool::new(10);
        let mut b = Mempool::new(10);
        let claims = a.precheck(&tx, &ledger, &StubExecutor).unwrap();
        assert_eq!(claims.commitments, tx.commitments(), "a bundle claims exactly its own output slots");
        assert_eq!(claims.claim, None, "and no register nonce");
        let via_split = b.insert_verified(tx.clone(), &ledger, &StubExecutor).unwrap();
        let via_insert = a.insert(tx.clone(), &ledger, &StubExecutor).unwrap();
        assert_eq!(via_split, via_insert);
        assert_eq!((a.len(), b.len()), (1, 1));

        // A duplicate is refused by both halves, with the same error.
        assert_eq!(b.precheck(&tx, &ledger, &StubExecutor).unwrap_err(), MempoolError::Duplicate);
        assert_eq!(b.insert_verified(tx.clone(), &ledger, &StubExecutor).unwrap_err(), MempoolError::Duplicate);

        // And a state change between the precheck and the insert is caught at the insert: this is
        // the race the off-loop verification opens, and re-running precheck is what closes it.
        let mut moved = ledger.clone();
        let rival = fixtures::bundle_tx(&ledger, [[1; 8], [9; 8]], [[7; 8], [8; 8]], fixtures::bundle_fee());
        moved.apply_tx(&rival, &fixtures::key(1).address(), &StubExecutor).unwrap();
        assert!(moved.is_spent(&[1; 8]), "the rival spent the note this transaction spends");
        let mut c = Mempool::new(10);
        assert!(c.precheck(&tx, &ledger, &StubExecutor).is_ok(), "fine against the tip it was scheduled on");
        assert!(moved.is_anchor(&tx.bundle.as_ref().unwrap().anchor), "and stale for exactly one reason");
        assert_eq!(
            c.insert_verified(tx, &moved, &StubExecutor).unwrap_err(),
            MempoolError::Invalid(TxError::Spent([1; 8])),
            "and refused against the tip it would be pooled on"
        );
        assert_eq!(c.len(), 0, "and it left no trace in the conflict indexes");
    }

    /// `insert` answers with the *ledger's* first refusal, not the pre-screen's.
    ///
    /// A wallet built against the wrong chain whose anchor has also scrolled out is refused for two
    /// reasons at once. `WrongChain` is the one it can act on — and the one a refused-hash cache may
    /// hold, since it is a statement about the transaction's bytes — while `UnknownAnchor` is a
    /// statement about this node at this moment and is deliberately never cached. So the staleness
    /// screen must not run ahead of `Ledger::validate` inside `insert`.
    #[test]
    fn insert_answers_a_doubly_invalid_transaction_with_the_ledger_s_own_verdict() {
        let l = ledger();
        let mut m = Mempool::new(10);
        let mut tx = fixtures::bundle_tx(&l, [nf(1), nf(2)], [cm(1), cm(2)], fixtures::bundle_fee());
        tx.chain_id = 99;
        tx.bundle.as_mut().unwrap().anchor = [0xdead; 8];
        assert!(matches!(
            m.insert(tx.clone(), &l, &StubExecutor),
            Err(MempoolError::Invalid(TxError::WrongChain { .. })),
        ));
        assert_eq!(m.len(), 0);
        // The cheap pre-screen still refuses it, on the staleness it is there to see.
        assert_eq!(
            m.precheck(&tx, &l, &StubExecutor).unwrap_err(),
            MempoolError::Invalid(TxError::UnknownAnchor)
        );
    }

    /// `precheck` must refuse a stale anchor without ever reaching a proof — that is the whole
    /// point of the split.
    #[test]
    fn precheck_refuses_a_stale_anchor_before_any_proof_work() {
        let gs = fixtures::genesis_with(1, vec![fixtures::alloc_note(20, 5 * randprotocol_core::UNITS_PER_RAND)]);
        let ledger = gs.ledger.clone();
        let mut tx = fixtures::bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fixtures::bundle_fee());
        tx.bundle.as_mut().unwrap().anchor = [0xdead; 8];
        let pool = Mempool::new(10);
        assert_eq!(
            pool.precheck(&tx, &ledger, &StubExecutor).unwrap_err(),
            MempoolError::Invalid(TxError::UnknownAnchor)
        );
    }

    /// Audit v6, CH-7: at the byte cap (eight blocks of the ledger's `max_block_bytes`) a
    /// newcomer paying more per KiB evicts the cheapest entry; one paying less is refused
    /// `Full`; one paying the same churns nothing. Every index follows the eviction: the evicted
    /// transaction's nullifiers are free again, so it can re-enter once there is room, and the
    /// byte total is the entries'.
    #[test]
    fn at_the_byte_cap_the_cheapest_per_kib_is_evicted_for_a_better_payer() {
        let mut l = ledger();
        let tx = |n: u8, mult: u64| fixtures::bundle_tx(&l, [nf(n), nf(n + 100)], [cm(n), cm(n + 100)], fixtures::bundle_fee() * mult);
        let len = tx(1, 2).encoded_len();
        let pooled: Vec<Transaction> = (0..MAX_POOL_BLOCKS as u8).map(|i| tx(i + 1, 2 + i as u64)).collect();
        assert!(pooled.iter().all(|t| t.encoded_len() == len));
        l.set_max_block_bytes(len);
        let mut m = Mempool::new(10_000);
        for t in &pooled {
            m.insert(t.clone(), &l, &StubExecutor).unwrap();
        }
        assert_eq!(m.info(Instant::now()).bytes, MAX_POOL_BLOCKS * len, "exactly at the cap");

        let worse = fixtures::bundle_tx(&l, [nf(50), nf(150)], [cm(50), cm(150)], fixtures::bundle_fee());
        assert_eq!(m.insert(worse.clone(), &l, &StubExecutor), Err(MempoolError::Full), "a newcomer ranked lowest is refused");
        assert_eq!(m.precheck(&worse, &l, &StubExecutor).map(|_| ()), Err(MempoolError::Full), "before any proof is verified");
        let equal = fixtures::bundle_tx(&l, [nf(51), nf(151)], [cm(51), cm(151)], fixtures::bundle_fee() * 2);
        assert_eq!(m.insert(equal, &l, &StubExecutor), Err(MempoolError::Full), "a tie is not below: nothing churns");

        let better = fixtures::bundle_tx(&l, [nf(60), nf(160)], [cm(60), cm(160)], fixtures::bundle_fee() * 50);
        m.insert(better.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), MAX_POOL_BLOCKS);
        assert!(!m.contains(&pooled[0].hash()), "the cheapest per KiB made room");
        assert!(m.contains(&better.hash()));
        assert!(pooled[1..].iter().all(|t| m.contains(&t.hash())), "and nothing else did");
        let sum: usize = m.txs.values().map(|p| p.len).sum();
        assert_eq!(m.info(Instant::now()).bytes, sum, "the byte total is the entries' after the eviction");
        assert_eq!(sum, MAX_POOL_BLOCKS * len);
        // The evicted entry's indices went with it: its nullifiers are claimable again, and with
        // room made it re-enters.
        assert!(pooled[0].nullifiers().iter().all(|nf| !m.nullifiers.contains_key(nf)));
        assert!(pooled[0].commitments().iter().all(|cm| !m.commitments.contains_key(cm)));
        m.remove(&[better.hash()]);
        m.insert(pooled[0].clone(), &l, &StubExecutor).unwrap();
    }

    /// A governance action is admitted at the byte cap, as at the count cap, and never taken to
    /// make room: a better-paying newcomer displaces fee-payers around it.
    #[test]
    fn a_governance_action_passes_the_byte_cap_and_is_never_evicted() {
        let (mut l, _) = bridged_ledger();
        let pause_key = fixtures::key(0x7f);
        let brake = Transaction {
            chain_id: l.chain_id(),
            bundle: None,
            action: Action::PauseMints { nonce: 0, signature: pause_key.sign(&randprotocol_core::bridge::gov::pause_message(l.chain_id(), 0)) },
        };
        // Blocks as large as the brake (a Dilithium2 signature outweighs a stub bundle), and the
        // pool filled with fee-payers to the last one that fits under eight of them.
        l.set_max_block_bytes(brake.encoded_len());
        let cap = MAX_POOL_BLOCKS * brake.encoded_len();
        let tx = |l: &Ledger, n: u8, mult: u64| fixtures::bundle_tx(l, [nf(n), nf(n + 100)], [cm(n), cm(n + 100)], fixtures::bundle_fee() * mult);
        let len = tx(&l, 1, 2).encoded_len();
        let mut m = Mempool::new(10_000);
        let pooled: Vec<Transaction> = (0..(cap / len) as u8).map(|i| tx(&l, i + 1, 2 + i as u64)).collect();
        for t in &pooled {
            m.insert(t.clone(), &l, &StubExecutor).unwrap();
        }
        let worse = tx(&l, 90, 1);
        assert_eq!(m.insert(worse, &l, &StubExecutor), Err(MempoolError::Full), "the pool is at its byte cap");
        m.insert(brake.clone(), &l, &StubExecutor).unwrap();
        assert!(m.info(Instant::now()).bytes > cap, "the brake is admitted past the byte cap");

        let better = tx(&l, 95, 500);
        m.insert(better.clone(), &l, &StubExecutor).unwrap();
        assert!(m.contains(&brake.hash()) && m.contains(&better.hash()), "the brake is never evicted");
        // The fee-payers that made room are the cheapest, in order; the brake's bytes count, so
        // more of them went than the newcomer alone would need.
        let gone = pooled.iter().take_while(|t| !m.contains(&t.hash())).count();
        assert!(gone * len >= len + brake.encoded_len() - (cap - pooled.len() * len), "enough went to fit both");
        assert!(pooled[gone..].iter().all(|t| m.contains(&t.hash())), "only the cheapest went");
        let sum: usize = m.txs.values().map(|p| p.len).sum();
        assert_eq!(m.info(Instant::now()).bytes, sum);
        assert!(sum - brake.encoded_len() <= cap, "the fee-payers are back under the cap");
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
        // A withdraw paying a *different* note — the same nonce, a fresh blinding — is *also* a
        // conflict now: `(validator, nonce)` is a pool-level claim of its own (item 2), and the
        // register can only ever apply one signed action at nonce 0.
        assert_eq!(
            m.insert(w(0, [4; 8]), &l, &StubExecutor),
            Err(MempoolError::Conflict(claim_conflict_key(&v.address())))
        );
        assert_eq!(m.len(), 1);

        // And removing the owner frees the note and the nonce again.
        m.remove(&[first.hash()]);
        m.insert(clash, &l, &StubExecutor).unwrap();
    }

    /// A bundle-less validator action is pooled, ordered and offered exactly as a mint is. An
    /// unbond creates no note and spends no nullifier, but its `(validator, nonce)` is a pool
    /// claim just like a commitment: only one pooled unbond may sit at a given nonce, and it
    /// applies as long as the register's nonce has not moved past it.
    #[test]
    fn a_bundle_less_validator_action_is_pooled_like_a_mint() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let v = fixtures::key(1);
        let unbond = |amount: u64, nonce: u64| {
            let signature =
                v.sign(randprotocol_core::unbond_message(l.chain_id(), &v.address(), amount, nonce).as_bytes());
            Transaction {
                chain_id: l.chain_id(),
                bundle: None,
                action: Action::Unbond { validator: v.address(), amount, nonce, signature },
            }
        };
        let first = unbond(1000, 0);
        m.insert(first.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.candidates(&l, 10), vec![first.clone()]);
        assert_eq!(m.insert(first.clone(), &l, &StubExecutor), Err(MempoolError::Duplicate));
        // A different unbond at the *same* nonce is a conflict: the register can only ever apply
        // one of them.
        assert_eq!(
            m.insert(unbond(2000, 0), &l, &StubExecutor),
            Err(MempoolError::Conflict(claim_conflict_key(&v.address())))
        );
        assert_eq!(m.len(), 1);
        // Nothing else about it goes stale — the register's nonce is still 0, matching what
        // `first` signed over — so a commit that touches nothing else does not drop it.
        m.prune(&l);
        assert_eq!(m.len(), 1);
    }

    /// Once the register's nonce has moved past a pooled unbond, `still_applies` throws it out:
    /// it can never apply again, so it must not sit in the pool (and be trial-applied on every
    /// proposal) until the node restarts.
    #[test]
    fn a_pooled_unbond_dies_with_its_nonce() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let v = fixtures::key(1);
        let signature = v.sign(randprotocol_core::unbond_message(l.chain_id(), &v.address(), 1000, 0).as_bytes());
        let tx = Transaction {
            chain_id: l.chain_id(),
            bundle: None,
            action: Action::Unbond { validator: v.address(), amount: 1000, nonce: 0, signature },
        };
        m.insert(tx.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), 1);

        // Apply it to the ledger the way a commit would: the register's nonce for `v` moves to 1.
        let mut after = l.clone();
        after.apply_tx(&tx, &v.address(), &StubExecutor).unwrap();
        assert_eq!(after.validators().get(&v.address()).unwrap().nonce, 1);

        m.prune(&after);
        assert!(m.is_empty(), "an unbond whose nonce the register has moved past survived prune");
    }

    /// Genesis vesting: a claim holds its entry's nonce in the pool — one pooled action per
    /// entry nonce, whichever of the four — and once the entry's nonce moves past it, it leaves
    /// at prune with the vesting verdict, never falling through to the validator lookup (an
    /// entry id is not an address).
    #[test]
    fn a_vesting_claim_holds_its_entry_nonce_and_dies_with_it() {
        use randprotocol_core::ledger::vesting::{Class, VestingConfig, VestingEntryConfig, VestingError, VestingRegister};
        use randprotocol_core::types::actions::{claim_vested_message, unbond_vested_message};
        let holder = fixtures::key(40);
        let mut l = ledger();
        let entry = |id: u8| VestingEntryConfig {
            id: [id; 32],
            class: Class::Investor,
            beneficiary: holder.public_key().clone(),
            revoker: None,
            amount: 10 * randprotocol_core::UNITS_PER_RAND,
            start_ms: 0,
            cliff_ms: 0,
            linear_ms: 1,
            step_ms: None,
        };
        l.set_vesting(Some(VestingRegister::from_config(&VestingConfig { entries: vec![entry(1), entry(2)] })));
        l.set_timestamp_ms(10);
        let genesis = l.signing_domain().genesis;
        let claim = |id: u8, nonce: u64, r: u32| {
            let to = ShieldedAddress { pk: [r; 8], kem_ek: vec![3; randprotocol_core::notes::KEM_EK_BYTES] };
            let (time, r, envelope) = (l.height() as u32, [r; 8], fixtures::env(1));
            let amount = randprotocol_core::UNITS_PER_RAND;
            let m = claim_vested_message(&genesis, l.chain_id(), &[id; 32], amount, nonce, &to, time, &r, &envelope);
            Transaction {
                chain_id: l.chain_id(),
                bundle: None,
                action: Action::ClaimVested { entry: [id; 32], amount, nonce, to, time, r, envelope, signature: holder.sign(m.as_bytes()) },
            }
        };
        let mut m = Mempool::new(100);
        m.insert(claim(1, 0, 1), &l, &StubExecutor).unwrap();
        // Another entry's nonce 0 is its own slot.
        m.insert(claim(2, 0, 2), &l, &StubExecutor).unwrap();
        // The same entry's nonce 0 is taken, whichever action wants it.
        let unbond_sig = holder.sign(unbond_vested_message(&genesis, l.chain_id(), &[1; 32], 5, 0).as_bytes());
        let unbond = Transaction {
            chain_id: l.chain_id(),
            bundle: None,
            action: Action::UnbondVested { entry: [1; 32], amount: 5, nonce: 0, signature: unbond_sig },
        };
        assert!(matches!(m.insert(unbond, &l, &StubExecutor), Err(MempoolError::Conflict(_))));
        assert_eq!(m.len(), 2);

        // Entry 1's nonce moves on (a claim committed elsewhere): its pooled claim is stale.
        let mut after = l.clone();
        after.apply_tx(&claim(1, 0, 9), &fixtures::key(1).address(), &StubExecutor).unwrap();
        let stale = claim(1, 0, 1);
        assert_eq!(
            Mempool::applies(&stale, &[], claimed_nonce(&stale.action), &after).unwrap_err(),
            TxError::Vesting(VestingError::BadNonce { expected: 1, actual: 0 })
        );
        m.prune(&after);
        assert_eq!(m.len(), 1, "entry 1's claim left, entry 2's stayed");
    }

    /// The same `(validator, nonce)` claimed by an unbond and a withdraw is still one claim: the
    /// register can only ever apply one signed action at a given nonce, whichever shape it is.
    #[test]
    fn a_same_nonce_pair_conflicts_at_insert() {
        let l = ledger_with_rewards();
        let mut m = Mempool::new(100);
        let v = fixtures::key(1);
        let unbond_sig = v.sign(randprotocol_core::unbond_message(l.chain_id(), &v.address(), 1000, 0).as_bytes());
        let unbond = Transaction {
            chain_id: l.chain_id(),
            bundle: None,
            action: Action::Unbond { validator: v.address(), amount: 1000, nonce: 0, signature: unbond_sig },
        };
        let withdraw =
            fixtures::withdraw_tx(l.chain_id(), &v, 3 * fixtures::bundle_fee() / 2, 0, l.height() as u32, [9; 8]);
        m.insert(unbond.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(
            m.insert(withdraw.clone(), &l, &StubExecutor),
            Err(MempoolError::Conflict(claim_conflict_key(&v.address())))
        );
        assert_eq!(m.len(), 1);
        // Removing the owner frees the nonce again.
        m.remove(&[unbond.hash()]);
        m.insert(withdraw, &l, &StubExecutor).unwrap();
    }

    #[test]
    fn a_mint_takes_its_commitment_slot_like_any_other_note() {
        let l = ledger();
        let mut m = Mempool::new(100);
        let mint = fixtures::mint_tx(l.chain_id(), cm(1), 5, &fixtures::key(1));
        let minted = mint.commitments()[0];
        m.insert(mint.clone(), &l, &StubExecutor).unwrap();
        // A bundle that would create the same note is a conflict, not a second copy of it.
        let clash = fixtures::bundle_tx(&l, [nf(1), nf(2)], [minted, cm(2)], fixtures::bundle_fee());
        assert_eq!(m.insert(clash, &l, &StubExecutor), Err(MempoolError::Conflict(minted)));
        assert_eq!(m.candidates(&l, 10), vec![mint]);
    }

    /// Bridge hardening B1: a pause and an unpause are bundle-less and share the bridge's one
    /// `pause_nonce`, so it is a pool claim like a validator's: one pooled governance message per
    /// nonce, and it dies once the bridge's nonce moves past it.
    #[test]
    fn a_pause_is_pooled_bundle_less_and_claims_the_pause_nonce() {
        let (l, _) = bridged_ledger();
        let mut m = Mempool::new(100);
        let pause_key = fixtures::key(0x7f);
        let pause = |nonce: u64| Transaction {
            chain_id: l.chain_id(),
            bundle: None,
            action: Action::PauseMints {
                nonce,
                signature: pause_key.sign(&randprotocol_core::bridge::gov::pause_message(l.chain_id(), nonce)),
            },
        };
        let first = pause(0);
        m.insert(first.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.candidates(&l, 10), vec![first.clone()]);
        // An unpause at the same nonce claims the same slot: only one can ever apply.
        let keys = fixtures::pq_keys();
        let msg = randprotocol_core::bridge::gov::unpause_message(l.chain_id(), 0);
        let unpause = Transaction {
            chain_id: l.chain_id(),
            bundle: None,
            action: Action::UnpauseMints {
                nonce: 0,
                pq_signatures: (0..5u8)
                    .map(|i| randprotocol_core::bridge::PqSignature {
                        index: i,
                        signature: keys[i as usize].sign(&msg).as_bytes().to_vec(),
                    })
                    .collect(),
            },
        };
        assert_eq!(m.precheck(&unpause, &l, &StubExecutor).map(|_| ()), Err(MempoolError::Conflict(claim_conflict_key(&Address([0; 32])))));
        // Once the pause commits, the bridge's nonce is 1 and the pooled pause is dropped.
        let mut after = l.clone();
        after.apply_tx(&first, &fixtures::key(1).address(), &StubExecutor).unwrap();
        assert!(after.bridge().unwrap().mint_paused);
        m.prune(&after);
        assert!(m.is_empty());
    }

    /// Node I4: the emergency brake cannot be crowded out. A `PauseMints` is bundle-less and
    /// `fee() == 0` by design — it must work from a wallet holding no RAND at all — so it used to
    /// be refused `Full` at the pool's cap and sorted *last* among candidates, behind everything
    /// that pays. With `rand_mint` handing out free, fee-less pooled transactions, an attacker
    /// minting with stolen guardian keys could fill every reachable validator's pool and keep the
    /// pause out for nothing.
    ///
    /// The exemption is bounded by the claim the pause already takes: role 2's one nonce, so at
    /// most one pooled pause-or-unpause, and role 3's one, so at most one pooled
    /// register-or-listing. Two entries past the cap, not a flood — asserted here.
    #[test]
    fn a_governance_message_is_exempt_from_a_full_pool_and_ordered_first() {
        let (l, _) = bridged_ledger();
        let pause_key = fixtures::key(0x7f);
        let pause = |nonce: u64| Transaction {
            chain_id: l.chain_id(),
            bundle: None,
            action: Action::PauseMints {
                nonce,
                signature: pause_key.sign(&randprotocol_core::bridge::gov::pause_message(l.chain_id(), nonce)),
            },
        };

        // A pool at its cap, filled with fee-paying bundles.
        let mut m = Mempool::new(2);
        let paid: Vec<Transaction> = [(1u8, 3u64), (3, 2)]
            .iter()
            .map(|&(n, mult)| {
                fixtures::bundle_tx(&l, [nf(n), nf(n + 1)], [cm(n), cm(n + 1)], fixtures::bundle_fee() * mult)
            })
            .collect();
        for t in &paid {
            m.insert(t.clone(), &l, &StubExecutor).unwrap();
        }
        let extra = fixtures::bundle_tx(&l, [nf(9), nf(10)], [cm(9), cm(10)], fixtures::bundle_fee());
        assert_eq!(m.insert(extra, &l, &StubExecutor), Err(MempoolError::Full), "an ordinary transaction is refused");

        // The pause is not.
        let brake = pause(0);
        m.insert(brake.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), 3, "one past the cap, which is what the exemption is worth");
        // And a second one is refused by its nonce claim, not by the cap — so the exemption
        // cannot be turned into a flood.
        // A second pause never lands, whatever nonce it names — the same one is a `Duplicate`,
        // another nonce is the bridge's own (its `pause_nonce` is 0 and nothing else is
        // admissible), and an *unpause* at the live nonce takes role 2's one claim. None of the
        // three is `Full`, which is the point: the exemption is bounded by the claim, not by the
        // cap it steps past.
        assert_eq!(m.precheck(&pause(0), &l, &StubExecutor).map(|_| ()), Err(MempoolError::Duplicate));
        assert_eq!(
            m.precheck(&pause(1), &l, &StubExecutor).map(|_| ()),
            Err(MempoolError::Invalid(TxError::Bridge(randprotocol_core::bridge::BridgeError::BadPauseNonce {
                expected: 0,
                got: 1
            })))
        );
        let msg = randprotocol_core::bridge::gov::unpause_message(l.chain_id(), 0);
        let keys = fixtures::pq_keys();
        let unpause = Transaction {
            chain_id: l.chain_id(),
            bundle: None,
            action: Action::UnpauseMints {
                nonce: 0,
                pq_signatures: (0..5u8)
                    .map(|i| randprotocol_core::bridge::PqSignature {
                        index: i,
                        signature: keys[i as usize].sign(&msg).as_bytes().to_vec(),
                    })
                    .collect(),
            },
        };
        assert_eq!(
            m.precheck(&unpause, &l, &StubExecutor).map(|_| ()),
            Err(MempoolError::Conflict(claim_conflict_key(&Address([0; 32])))),
            "role 2 holds exactly one pooled slot"
        );

        // And it leads the block, ahead of both fee-payers — which are themselves still in fee
        // order behind it.
        let picked = m.candidates(&l, 10);
        assert_eq!(picked[0], brake, "the fee-less brake is first");
        assert_eq!(picked[1..].iter().map(|t| t.fee()).collect::<Vec<_>>(), vec![
            fixtures::bundle_fee() * 3,
            fixtures::bundle_fee() * 2
        ]);
    }

    /// Bridge rules v2 (audit v4): a rotation is pooled bundle-less, is governance (exempt from
    /// the cap, first among the candidates), claims the bridge's one `rotation_nonce` — a PQ
    /// rotation and a pause-key rotation at the same nonce conflict — and is dropped once the
    /// nonce moves past it. On a chain-14-shaped ledger it is refused `RulesV2Disabled`.
    #[test]
    fn a_rotation_is_governance_and_claims_the_rotation_nonce() {
        let (gs, _) = fixtures::bridged_genesis_v2(1);
        let l = gs.ledger.clone();
        let mut m = Mempool::new(1);
        let pay = fixtures::bundle_tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fixtures::bundle_fee() * 2);
        m.insert(pay.clone(), &l, &StubExecutor).unwrap();
        let rotate = fixtures::rotate_pause_tx(&l, &fixtures::key(0x99), 0);
        assert_eq!(rotate.bundle, None);
        m.insert(rotate.clone(), &l, &StubExecutor).unwrap_or_else(|e| panic!("governance is exempt from the cap: {e:?}"));
        assert_eq!(m.candidates(&l, 10), vec![rotate.clone(), pay.clone()], "the rotation leads");
        // A PQ rotation at the same nonce claims the same slot.
        let keys = fixtures::pq_keys();
        let new: Vec<randprotocol_core::PublicKey> = (0..6u8).map(|i| fixtures::key(0xa0 + i).public_key().clone()).collect();
        let msg = randprotocol_core::bridge::gov::rotate_pq_message(l.chain_id(), 0, &new);
        let rotate_pq = Transaction {
            chain_id: l.chain_id(),
            bundle: None,
            action: Action::RotatePqGuardians {
                new_pq_guardians: new,
                nonce: 0,
                pq_signatures: (0..5u8)
                    .map(|i| randprotocol_core::bridge::PqSignature { index: i, signature: keys[i as usize].sign(&msg).as_bytes().to_vec() })
                    .collect(),
            },
        };
        assert_eq!(m.precheck(&rotate_pq, &l, &StubExecutor).map(|_| ()), Err(MempoolError::Conflict(claim_conflict_key(&Address([0; 32])))));
        // A rotation signed for a nonce the bridge has passed is refused on the nonce.
        assert_eq!(
            m.precheck(&fixtures::rotate_pause_tx(&l, &fixtures::key(0x98), 1), &l, &StubExecutor).map(|_| ()),
            Err(MempoolError::Invalid(TxError::Bridge(randprotocol_core::bridge::BridgeError::BadRotationNonce { expected: 0, got: 1 })))
        );
        // Once it commits, the nonce is 1 and the pooled rotation is dropped.
        let mut after = l.clone();
        after.apply_tx(&rotate, &fixtures::key(1).address(), &StubExecutor).unwrap();
        assert_eq!(after.bridge().unwrap().rotation_nonce, 1);
        m.prune(&after);
        assert_eq!(m.candidates(&after, 10), vec![pay]);
        // Chain 14's shape: the ledger's gate refuses it before anything is pooled.
        let (v1, _) = bridged_ledger();
        let mut m1 = Mempool::new(100);
        assert_eq!(
            m1.insert(fixtures::rotate_pause_tx(&v1, &fixtures::key(0x99), 0), &v1, &StubExecutor).map(|_| ()),
            Err(MempoolError::Invalid(TxError::Bridge(randprotocol_core::bridge::BridgeError::RulesV2Disabled)))
        );
        assert!(m1.is_empty());
    }

    /// A ledger on a bridged chain, plus the guardian secrets that can attest to it.
    fn bridged_ledger() -> (Ledger, Vec<[u8; 32]>) {
        let (gs, secrets) = fixtures::bridged_genesis(1);
        (gs.ledger.clone(), secrets)
    }

    /// Full-length `kem_ek`: every mint recipient is held to `KEM_EK_BYTES` (core I-1).
    fn recipient() -> ShieldedAddress {
        ShieldedAddress { pk: [4; 8], kem_ek: vec![6; randprotocol_core::notes::KEM_EK_BYTES] }
    }

    /// The one attestation both relayers see: 1,000 of chain 2's token to `recipient()`,
    /// signed by a quorum of five of the six guardians.
    fn attestation(secrets: &[[u8; 32]]) -> Vec<u8> {
        attestation_of(secrets, [0xaa; 32], 0)
    }

    /// [`attestation`] for a chosen `token` and `sequence`, so an attestation can name a token
    /// the chain has not listed as easily as the one it has.
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
        let r = randprotocol_core::ledger::bridge_notes::deposit_r(&attestation).unwrap_or([seed as u32; 8]);
        attest_tx_with_r(l, attestation, seed, r)
    }

    /// [`attest_tx`] with the blinding spelled out, for the pool's own rules — admission requires
    /// the attestation digest's (F1), so anything else here is a transaction the ledger refuses.
    /// Two submitters of one attestation at one `time` derive the very same note, which is a
    /// collision no field of either transaction shows.
    fn attest_tx_with_r(l: &Ledger, attestation: Vec<u8>, seed: u8, r: Word8) -> Transaction {
        let b = fixtures::bundle(l, [nf(seed), nf(seed + 1)], [cm(seed), cm(seed + 1)], fixtures::bundle_fee());
        let asset = fixtures::deposit_index(l, &attestation);
        let pq_signatures = fixtures::pq_quorum(l.chain_id(), &attestation);
        randprotocol_core::confidential::StubExecutor::bound(Transaction::shielded(
            l.chain_id(),
            b,
            Action::BridgeAttest {
                attestation,
                recipient: recipient(),
                r,
                time: l.height() as u32,
                asset,
                envelope: fixtures::env(seed),
                pq_signatures,
            },
        ))
    }

    /// [`bridged_ledger`] with validator 1 holding more rewards than the bundle base, so it has
    /// something to withdraw beside an attestation: two applied bundles whose fees are its own as
    /// their proposer, exactly as [`ledger_with_rewards`] does it on the unbridged chain.
    fn bridged_ledger_with_rewards() -> (Ledger, Vec<[u8; 32]>) {
        let (mut l, secrets) = bridged_ledger();
        let v = fixtures::key(1);
        for (height, n) in [(1u64, 40u8), (2, 44)] {
            l.set_height(height);
            let t = fixtures::bundle_tx(&l, [nf(n), nf(n + 1)], [cm(n), cm(n + 1)], fixtures::bundle_fee());
            l.apply_tx(&t, &v.address(), &StubExecutor).unwrap();
            l.record_anchor(height);
        }
        assert_eq!(l.released(&v.address()), 2 * fixtures::bundle_fee());
        (l, secrets)
    }

    /// A `SetAuthority` of `asset` at `nonce`, signed by the fixture issuer, handing the token to
    /// `key(new)`; its fee bundle keyed at `seed..seed + 3`.
    fn set_authority_tx(l: &Ledger, asset: u32, nonce: u64, new: u8, seed: u32) -> Transaction {
        let id = l.tokens().and_then(|t| t.get(asset)).map(|i| i.id).unwrap();
        let new = Some(fixtures::key(new).public_key().clone());
        let msg = randprotocol_core::types::actions::set_authority_message(l.chain_id(), &id, nonce, &new);
        let signature = fixtures::issuer().sign(msg.as_bytes());
        StubExecutor::bound(Transaction::shielded(
            l.chain_id(),
            fixtures::bundle(l, [[seed; 8], [seed + 1; 8]], [[seed + 2; 8], [seed + 3; 8]], randprotocol_core::gas::BUNDLE_BASE),
            Action::SetAuthority { asset, new, nonce, signature },
        ))
    }

    /// Two pooled transactions at one token's `mint_nonce` — two `TokenMint`s, or a mint and a
    /// `SetAuthority`, which share the counter — and two `RegisterToken`s at one registry index
    /// can never both apply, so the pool holds one of each pair (H4 review minor). Removing the
    /// owner frees the slot; once the ledger has moved past it, a pooled rival is stale and
    /// pruned, and a new one is refused before any proof is verified.
    #[test]
    fn a_token_nonce_and_a_registration_index_are_claimed_once_in_the_pool() {
        let (gs, _secrets) = fixtures::bridged_genesis(1);
        let mut l = gs.ledger.clone();
        let register = fixtures::register_token_tx(&l, 5_000, 210);
        l.apply_tx(&register, &fixtures::key(1).address(), &StubExecutor).unwrap();
        l.record_anchor(0);

        // Two mints at nonce 0, and a rotation at nonce 0.
        let mint_a = fixtures::token_mint_tx(&l, 2, 700, 0, 300);
        let mint_b = fixtures::token_mint_tx(&l, 2, 800, 0, 320);
        let rotate = set_authority_tx(&l, 2, 0, 22, 340);
        for t in [&mint_a, &mint_b, &rotate] {
            assert_eq!(l.validate(t, &StubExecutor), Ok(()), "each alone is valid: a race, not a bad tx");
        }
        let mut m = Mempool::new(100);
        m.insert(mint_a.clone(), &l, &StubExecutor).unwrap();
        assert!(matches!(m.insert(mint_b.clone(), &l, &StubExecutor), Err(MempoolError::Conflict(_))));
        assert!(matches!(m.precheck(&rotate, &l, &StubExecutor), Err(MempoolError::Conflict(_))));
        m.remove(&[mint_a.hash()]);
        m.insert(rotate.clone(), &l, &StubExecutor).unwrap();
        assert!(matches!(m.insert(mint_b.clone(), &l, &StubExecutor), Err(MempoolError::Conflict(_))));

        // Two registrations at the next index (3), neither with an initial mint, so no commitment
        // is shared: only the index makes them rivals.
        let reg_a = fixtures::register_token_tx(&l, 0, 400);
        let reg_b = fixtures::register_token_tx(&l, 0, 420);
        assert_ne!(reg_a.hash(), reg_b.hash());
        for t in [&reg_a, &reg_b] {
            assert_eq!(l.validate(t, &StubExecutor), Ok(()));
        }
        m.insert(reg_a.clone(), &l, &StubExecutor).unwrap();
        assert!(matches!(m.insert(reg_b.clone(), &l, &StubExecutor), Err(MempoolError::Conflict(_))));
        assert_eq!(m.len(), 2, "the rotation and the first registration");

        // The chain applies a mint at nonce 0 and a registration at index 3 from elsewhere: the
        // pooled rotation and registration can never apply and leave at the next prune.
        l.apply_tx(&mint_b, &fixtures::key(1).address(), &StubExecutor).unwrap();
        l.apply_tx(&reg_b, &fixtures::key(1).address(), &StubExecutor).unwrap();
        m.prune(&l);
        assert_eq!(m.len(), 0, "a spent nonce and a taken index are stale");
        let stale = fixtures::token_mint_tx(&l, 2, 900, 0, 500);
        assert!(matches!(
            m.precheck(&stale, &l, &StubExecutor),
            Err(MempoolError::Invalid(TxError::Token(TokenError::BadNonce { expected: 1, got: 0 })))
        ));
    }

    /// Every bundle-carrying kind the hidden-asset bundle reshaped — a plain transfer (`None`), a
    /// holder's `TokenBurn` and a `BridgeBurn` — claims all four of its nullifiers and all four
    /// of its commitments, no more and no fewer, and each of the eight blocks a rival that shares
    /// only it. The rival is a plain transfer, so the claim is by word and not by kind. Slots 2
    /// and 3 are the fixture's derived words, standing for an honest bundle's dummies: the chain
    /// cannot tell a dummy from a real note (that is the point of the shape), so a dummy's
    /// nullifier and commitment are claimed exactly like a real one's — a dummy commitment
    /// reused by a second transaction would die on `CommitmentExists` in the proposer's block.
    /// Removing the owner frees all eight.
    #[test]
    fn every_bundle_kind_claims_its_four_nullifiers_and_four_commitments() {
        let (gs, secrets) = fixtures::bridged_genesis(1);
        let mut l = gs.ledger.clone();
        // Supply for both burns: 1 000 of the bridged token (index 1), 5 000 of a native one (2).
        let deposit = fixtures::attest_tx(&l, fixtures::attestation(&secrets, &fixtures::recipient(), 1_000, 0), 200);
        l.apply_tx(&deposit, &fixtures::key(1).address(), &StubExecutor).unwrap();
        let register = fixtures::register_token_tx(&l, 5_000, 210);
        l.apply_tx(&register, &fixtures::key(1).address(), &StubExecutor).unwrap();
        l.record_anchor(0);

        let rival = |slot: usize, nf_of: Option<Word8>, cm_of: Option<Word8>, seed: u32| {
            let mut t = fixtures::transfer_tx(&l, seed);
            {
                let b = t.bundle.as_mut().unwrap();
                if let Some(x) = nf_of {
                    b.nullifiers[slot] = x;
                }
                if let Some(x) = cm_of {
                    b.commitments[slot] = x;
                }
                b.proof = StubExecutor::make_bundle_proof(&fixtures::HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
            }
            StubExecutor::bound(t)
        };

        let kinds = [
            ("none", fixtures::transfer_tx(&l, 10)),
            ("token_burn", fixtures::token_burn_tx(&l, 2, 300, 20)),
            ("bridge_burn", fixtures::burn_tx(&l, 1, 400, 100, 30)),
        ];
        for (kind, owner) in kinds {
            assert_eq!(l.validate(&owner, &StubExecutor), Ok(()), "{kind}");
            let (nfs, cms) = (owner.nullifiers(), owner.commitments());
            assert_eq!((nfs.len(), cms.len()), (4, 4), "{kind}: four and four, dummies included");
            let mut m = Mempool::new(100);
            let claims = m.precheck(&owner, &l, &StubExecutor).unwrap();
            assert_eq!(claims.commitments, cms, "{kind}: exactly its four output slots");
            m.insert(owner.clone(), &l, &StubExecutor).unwrap();
            for slot in 0..4 {
                let seed = 1_000 + 16 * slot as u32;
                let by_nf = rival(slot, Some(nfs[slot]), None, seed);
                assert_eq!(l.validate(&by_nf, &StubExecutor), Ok(()), "{kind} slot {slot}: a race, not a bad tx");
                assert_eq!(m.insert(by_nf, &l, &StubExecutor), Err(MempoolError::Conflict(nfs[slot])), "{kind} nf {slot}");
                let by_cm = rival(slot, None, Some(cms[slot]), seed + 8);
                assert_eq!(l.validate(&by_cm, &StubExecutor), Ok(()), "{kind} slot {slot}: a race, not a bad tx");
                assert_eq!(m.insert(by_cm, &l, &StubExecutor), Err(MempoolError::Conflict(cms[slot])), "{kind} cm {slot}");
            }
            assert_eq!(m.len(), 1, "{kind}");
            m.remove(&[owner.hash()]);
            for slot in 0..4 {
                let seed = 2_000 + 16 * slot as u32;
                m.insert(rival(slot, Some(nfs[slot]), None, seed), &l, &StubExecutor).unwrap();
                m.insert(rival(slot, None, Some(cms[slot]), seed + 8), &l, &StubExecutor).unwrap();
            }
            assert_eq!(m.len(), 8, "{kind}: its removal freed all eight words");
        }
    }

    /// A transfer — of RAND or of any token, the same bundle since the hidden-asset bundle —
    /// claims all four of its nullifiers and all four of its commitments in the pool's conflict
    /// index, the dummy slots' included: two transfers sharing any one of them do not both enter
    /// the pool. Without it the pool would offer the proposer a block whose second transfer dies
    /// on `Spent` or `CommitmentExists`.
    #[test]
    fn two_transfers_sharing_any_slot_do_not_both_enter_the_pool() {
        let (l, _) = bridged_ledger();
        let first = fixtures::transfer_tx_with(&l, [nf(10), nf(11)], [cm(10), cm(11)]);
        assert_eq!(first.nullifiers().len(), 4);
        assert_eq!(first.commitments().len(), 4);
        let mut m = Mempool::new(100);
        m.insert(first.clone(), &l, &StubExecutor).unwrap();
        // Sharing slot 0's nullifier, slot 3's (a dummy's) nullifier, slot 0's commitment and
        // slot 3's commitment: each is refused on exactly that word.
        let shared_nf0 = fixtures::transfer_tx_with(&l, [nf(10), nf(12)], [cm(12), cm(13)]);
        assert_eq!(l.validate(&shared_nf0, &StubExecutor), Ok(()), "a race, not a validation failure");
        assert_eq!(m.insert(shared_nf0, &l, &StubExecutor), Err(MempoolError::Conflict(nf(10))));
        let mut shared_nf3 = fixtures::transfer_tx_with(&l, [nf(14), nf(15)], [cm(14), cm(15)]);
        {
            let b = shared_nf3.bundle.as_mut().unwrap();
            b.nullifiers[3] = first.nullifiers()[3];
            b.proof = StubExecutor::make_bundle_proof(&fixtures::HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
        }
        StubExecutor::bind(&mut shared_nf3);
        assert_eq!(m.insert(shared_nf3, &l, &StubExecutor), Err(MempoolError::Conflict(first.nullifiers()[3])));
        let shared_cm0 = fixtures::transfer_tx_with(&l, [nf(16), nf(17)], [cm(10), cm(16)]);
        assert_eq!(m.insert(shared_cm0, &l, &StubExecutor), Err(MempoolError::Conflict(cm(10))));
        let mut shared_cm3 = fixtures::transfer_tx_with(&l, [nf(18), nf(19)], [cm(18), cm(19)]);
        {
            let b = shared_cm3.bundle.as_mut().unwrap();
            b.commitments[3] = first.commitments()[3];
            b.proof = StubExecutor::make_bundle_proof(&fixtures::HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
        }
        StubExecutor::bind(&mut shared_cm3);
        assert_eq!(m.insert(shared_cm3, &l, &StubExecutor), Err(MempoolError::Conflict(first.commitments()[3])));
        assert_eq!(m.len(), 1);
        assert_eq!(m.candidates(&l, 10), vec![first]);
    }

    /// A bridge is permissionless, so two relayers racing one attestation is the normal case,
    /// not an attack. Their transactions share no nullifier and no commitment *on the wire* —
    /// the deposit note is computed by the ledger and never appears there — so what says they
    /// collide is the derived note (at one `time`, since F1 fixes the blinding) or, failing
    /// that, the attestation digest. Without claiming the digest the pool would hold two
    /// submissions at two `time`s, offer both, and the proposer's block would die on the second
    /// with `Bridge(Replay)`.
    #[test]
    fn two_relayers_racing_one_attestation_do_not_both_enter_the_pool() {
        let (mut l, secrets) = bridged_ledger();
        // Two heights in the window, so a submitter has a `time` to differ on: the one word F1
        // leaves it (the derived blinding takes every other).
        l.set_height(5);
        l.record_anchor(5);
        let l = l;
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
        // Two claims collide now, not one: since F1 both submissions derive the *same* deposit
        // note (one attestation, one `time`, one blinding), which is the griefing this rule
        // closes — the copier cannot mint a note of its own. The commitment index is consulted
        // before the digest index, so that is the conflict reported; the digest claim below is
        // still the one that catches two relayers at two different `time`s.
        assert_eq!(
            m.insert(second.clone(), &l, &StubExecutor),
            Err(MempoolError::Conflict(l.derived_commitment(&first.action, &StubExecutor).unwrap())),
            "one attestation at one time is one note"
        );
        let mut later = attest_tx(&l, a.clone(), 20);
        let Action::BridgeAttest { time, .. } = &mut later.action else { panic!("an attest") };
        *time = l.height() as u32 - 1;
        let later = StubExecutor::bound(later);
        assert_ne!(
            l.derived_commitment(&later.action, &StubExecutor),
            l.derived_commitment(&first.action, &StubExecutor),
            "another `time` is another note"
        );
        assert_eq!(
            m.insert(later, &l, &StubExecutor),
            Err(MempoolError::AttestationConflict(mu)),
            "and then the digest is the only thing that tells them apart"
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

    /// The race this test used to describe is gone. Two *different* tokens, both seen for the
    /// first time, used to predict the same next index and one of them had to lose it — so a
    /// pooled attest could go stale on an index that moved under it. Bridged tokens are listed
    /// now (in genesis, or by a governance message), so an index is a fact before any attestation
    /// of it exists and nothing can take it from a transaction being proved.
    ///
    /// What is left is the refusal that replaced the race — an attestation of a token nobody
    /// listed never enters the pool — and the stability: a pooled attest of a listed token is
    /// still a candidate after other transactions commit.
    #[test]
    fn an_attest_of_an_unlisted_token_is_refused_and_a_listed_ones_index_cannot_move() {
        let (l, secrets) = bridged_ledger();
        // The fixture genesis lists chain 2's `[0xaa; 32]` at index 1, and nothing else.
        let unlisted = attest_tx(&l, attestation_of(&secrets, [0xbb; 32], 1), 20);
        assert_eq!(
            l.validate(&unlisted, &StubExecutor),
            Err(TxError::Bridge(BridgeError::UnlistedToken { chain: 2, token: [0xbb; 32] })),
            "no listing, no index, no deposit"
        );
        let mut m = Mempool::new(100);
        assert!(m.insert(unlisted, &l, &StubExecutor).is_err(), "and so it never reaches the pool");
        assert_eq!(m.len(), 0);

        let mine = attest_tx(&l, attestation_of(&secrets, [0xaa; 32], 0), 10);
        let Action::BridgeAttest { asset, .. } = &mine.action else { panic!("an attest") };
        assert_eq!(*asset, 1, "the index the genesis listing gave it");
        assert_eq!(l.validate(&mine, &StubExecutor), Ok(()));
        m.insert(mine.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.candidates(&l, 10), vec![mine.clone()]);

        // Another transaction commits while it waits. Nothing it spends is spent, its digest is
        // untouched — and, unlike the old first sighting, its index cannot have moved, because
        // no transaction of any kind hands one out.
        let mut after = l.clone();
        let other = fixtures::bundle_tx(&after, [nf(60), nf(61)], [cm(60), cm(61)], fixtures::bundle_fee());
        after.apply_tx(&other, &fixtures::key(1).address(), &StubExecutor).unwrap();
        assert_eq!(after.tokens().unwrap().bridged(2, &[0xaa; 32]).unwrap().index, 1);
        assert_eq!(after.validate(&mine, &StubExecutor), Ok(()));
        assert_eq!(m.candidates(&after, 10), vec![mine.clone()], "still offered to the proposer");
        m.prune(&after);
        assert_eq!(m.len(), 1);
    }

    /// Two attestations of one transfer, with two different digests — a different `sequence`, so
    /// nothing the digest index tracks connects them — submitted by relayers that happened to
    /// choose the same blinding and the same `time`. The note the *ledger* derives is then one
    /// note, and only one of the two can ever be included. Before the derivation covered an
    /// attest, both pooled and the second died at the proposer's trial apply with
    /// `CommitmentExists`, costing a block's worth of space and a proof verification per gossip
    /// round; now they collide at insert, over the note itself.
    #[test]
    fn two_attests_deriving_one_note_conflict_at_insert() {
        let (l, secrets) = bridged_ledger();
        let a = attestation_of(&secrets, [0xaa; 32], 0);
        let r = randprotocol_core::ledger::bridge_notes::deposit_r(&a).unwrap();
        let first = attest_tx_with_r(&l, a, 10, r);
        // A *second* attestation of the same transfer (another `sequence`, so another digest)
        // whose submitter reuses the first's blinding: inadmissible since F1 — the ledger takes
        // only the blinding its own digest derives — but the pool screens before it validates, so
        // this is exactly the pair its note claim must still catch.
        let second = attest_tx_with_r(&l, attestation_of(&secrets, [0xaa; 32], 1), 20, r);
        // Nothing the other indexes track connects them, and both are independently admissible:
        // the collision is between the two transactions, not inside either.
        assert_ne!(first.bridge_digests(), second.bridge_digests(), "two digests, so two attestations");
        assert!(first.nullifiers().iter().all(|x| !second.nullifiers().contains(x)));
        assert!(first.commitments().iter().all(|x| !second.commitments().contains(x)));
        assert_eq!(l.validate(&first, &StubExecutor), Ok(()));
        assert_eq!(
            l.validate(&second, &StubExecutor),
            Err(randprotocol_core::ledger::TxError::Bridge(randprotocol_core::bridge::BridgeError::WrongDepositBlinding)),
            "the ledger's own answer to a reused blinding"
        );

        let derived = l.derived_commitment(&first.action, &StubExecutor).expect("an attest derives one note");
        assert_eq!(
            l.derived_commitment(&second.action, &StubExecutor),
            Some(derived),
            "the same recipient, amount, asset, time and blinding is the same note"
        );
        assert!(!first.commitments().contains(&derived), "and neither transaction carries it");

        let mut m = Mempool::new(100);
        m.insert(first.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(
            m.insert(second.clone(), &l, &StubExecutor),
            Err(MempoolError::Conflict(derived)),
            "named by the note the two disagree over"
        );
        // A bundle whose output slot is that same note collides with it too, exactly as it does
        // with a withdraw's derived deposit.
        let clash = fixtures::bundle_tx(&l, [nf(1), nf(2)], [derived, cm(2)], fixtures::bundle_fee());
        assert_eq!(m.insert(clash, &l, &StubExecutor), Err(MempoolError::Conflict(derived)));
        assert_eq!(m.len(), 1);
        assert_eq!(m.candidates(&l, 10), vec![first.clone()]);

        // And removing the owner frees the note, so another submission can take its place: a
        // second relayer's transaction over the *same* attestation, which since F1 derives the
        // very same note (its blinding is that attestation's digest, not the submitter's).
        m.remove(&[first.hash()]);
        let other_relayer = attest_tx(&l, attestation_of(&secrets, [0xaa; 32], 0), 30);
        assert_ne!(other_relayer.hash(), first.hash());
        assert_eq!(l.derived_commitment(&other_relayer.action, &StubExecutor), Some(derived));
        m.insert(other_relayer, &l, &StubExecutor).unwrap();
    }

    /// Fullnode issue #4: a pooled attestation whose guardian set the chain has retired is
    /// dropped at the next tip change. Nothing else in the pool's rules reads the bridge's sets,
    /// so before this the transaction sat there until a restart — holding a slot and being offered
    /// to every block, for a verdict that can now only be a refusal.
    #[test]
    fn a_pooled_attest_leaves_when_its_guardian_set_is_retired() {
        let (mut l, secrets) = bridged_ledger();
        let tx = attest_tx(&l, attestation(&secrets), 10);
        let mut m = Mempool::new(100);
        m.insert(tx.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), 1);
        // A tip where nothing about the bridge changed keeps it.
        m.prune(&l);
        assert_eq!(m.len(), 1, "an attestation on a live set stays pooled");

        // Retire the set it names. (On chain this is a guardian-set rotation past its grace
        // window; here the state is edited directly, which is what the pool sees either way.)
        let index = randprotocol_core::bridge::Attestation::decode(match &tx.action {
            Action::BridgeAttest { attestation, .. } => attestation,
            _ => panic!("an attest"),
        })
        .unwrap()
        .guardian_set_index;
        let mut bridge = l.bridge().expect("a bridged chain").clone();
        bridge.guardian_sets.remove(&index);
        l.set_bridge(Some(bridge));

        m.prune(&l);
        assert_eq!(m.len(), 0, "the attestation outlived the set that signed it");
    }

    /// Audit v6, BRG-12: the two other things that can turn a pooled attestation's verdict and
    /// that the pool did not look at — a pause, and a rotation of the post-quantum guardian set
    /// its co-signatures were verified against (rotation exists since chain 15). It stayed
    /// pooled and was offered to every block until its `time` left the window, failing each
    /// trial apply. A relayer resubmits after an unpause or with the new set's co-signatures.
    #[test]
    fn a_pooled_attest_leaves_on_a_pause_and_on_a_post_quantum_rotation() {
        let pooled = || {
            let (l, secrets) = bridged_ledger();
            let tx = attest_tx(&l, attestation(&secrets), 10);
            let mut m = Mempool::new(100);
            m.insert(tx, &l, &StubExecutor).unwrap();
            m.prune(&l);
            assert_eq!(m.len(), 1, "nothing about the bridge moved: it stays");
            (m, l)
        };
        let (mut m, mut l) = pooled();
        let mut bridge = l.bridge().unwrap().clone();
        bridge.mint_paused = true;
        l.set_bridge(Some(bridge));
        m.prune(&l);
        assert_eq!(m.len(), 0, "a transfer attest does not wait out a pause in the pool");

        let (mut m, mut l) = pooled();
        let mut bridge = l.bridge().unwrap().clone();
        bridge.rotation_nonce += 1;
        l.set_bridge(Some(bridge));
        assert!(m.candidates(&l, 10).is_empty(), "not offered once the set it was verified against has rotated");
        m.prune(&l);
        assert_eq!(m.len(), 0, "and gone at the tip change");

        // While paused a new one is refused at the pre-screen with the ledger's own verdict.
        let (l0, secrets) = bridged_ledger();
        let tx = attest_tx(&l0, attestation(&secrets), 10);
        let mut paused = l0.clone();
        let mut bridge = paused.bridge().unwrap().clone();
        bridge.mint_paused = true;
        paused.set_bridge(Some(bridge));
        assert_eq!(
            Mempool::new(4).precheck(&tx, &paused, &StubExecutor).map(|_| ()),
            Err(MempoolError::Invalid(TxError::Bridge(BridgeError::MintsPaused)))
        );
    }

    /// An oversized attestation must not buy a decode from the pre-screen.
    ///
    /// `precheck` runs on a transaction nobody has validated yet — that is its whole purpose — and
    /// decoding an attestation is work. So the 16 KiB cap has to be applied before the decode,
    /// exactly as `Ledger::validate` applies it at step 1 and `Ledger::derived_commitment` applies
    /// it before deriving a deposit. Without it every gossiped copy of an oversized blob buys a full
    /// parse at a zero fee.
    #[test]
    fn precheck_refuses_an_oversized_attestation_before_decoding_it() {
        let (l, secrets) = bridged_ledger();
        let mut tx = attest_tx(&l, attestation(&secrets), 10);
        let Action::BridgeAttest { attestation: blob, .. } = &mut tx.action else { panic!("an attest") };
        *blob = vec![0u8; randprotocol_core::gas::MAX_ATTESTATION_BYTES + 1];
        let mut m = Mempool::new(100);
        assert_eq!(
            m.precheck(&tx, &l, &StubExecutor).unwrap_err(),
            MempoolError::Invalid(TxError::AttestationTooLarge)
        );
        // And `insert` says the same, because `validate` caps it at step 1: one verdict, from two
        // paths that must not disagree about a transaction this cheap to refuse.
        assert_eq!(
            m.insert(tx, &l, &StubExecutor),
            Err(MempoolError::Invalid(TxError::AttestationTooLarge))
        );
        assert_eq!(m.len(), 0);
    }

    /// The claim is one note, not one *kind* of note: an attest and a withdraw that derive
    /// different notes are unrelated, and the pool has to hold both — a bridged chain whose
    /// validator is also withdrawing is the ordinary case, and dropping either would cost a
    /// transaction that is perfectly includable.
    #[test]
    fn an_attest_and_a_withdraw_deriving_different_notes_both_pool() {
        let (l, secrets) = bridged_ledger_with_rewards();
        let v = fixtures::key(1);
        let attest = attest_tx(&l, attestation(&secrets), 10);
        let withdraw =
            fixtures::withdraw_tx(l.chain_id(), &v, 2 * fixtures::bundle_fee(), 0, l.height() as u32, [3; 8]);
        let deposited = l.derived_commitment(&attest.action, &StubExecutor).expect("the attest derives a note");
        let withdrawn = l.derived_commitment(&withdraw.action, &StubExecutor).expect("the withdraw derives a note");
        assert_ne!(deposited, withdrawn, "different owners, different amounts, different assets");

        let mut m = Mempool::new(100);
        m.insert(attest.clone(), &l, &StubExecutor).unwrap();
        m.insert(withdraw.clone(), &l, &StubExecutor).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m.candidates(&l, 10).len(), 2, "and both are offered to the proposer");
    }

    /// The aggregate's pool claims (spec §4 step 5): the derived payout note is claimed the way
    /// a `BridgeAttest`'s is, and the `(aggregator, nonce)` the way an `Unbond`'s register nonce
    /// is — keyed by register, so one keypair's two roles never collide over a shared slot.
    #[test]
    fn an_aggregate_claims_its_payout_note_and_its_aggregator_nonce() {
        use randprotocol_core::ledger::aggregation::{AdmittedShape, AggregationConfig};
        use randprotocol_core::types::actions::{aggregate_signing_hash, aggregator_register_message, AggregatorRegistration};
        use randprotocol_core::types::{DeclaredShape, FriProfile};

        let kp = fixtures::key(1); // the fixture chain's one validator — and its aggregator.
        let addr = kp.public_key().address();
        let shape = DeclaredShape {
            profile: FriProfile::Test,
            tier: 14,
            program_log_height: 13,
            input_log_height: 12,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 2,
            mem_log_height: 18,
        };
        let bond = 100 * randprotocol_core::UNITS_PER_RAND;
        let mut l = ledger();
        l.set_aggregation(Some(AggregationConfig {
            bond,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![AdmittedShape { shape, hc: Hash::digest(b"guest"), aggregate_program_digest: StubExecutor.aggregate_program_digest(&shape).unwrap() }],
        }));
        // Register the aggregator, through a bond-burning bundle with a stub proof.
        let mut b = randprotocol_core::notes::Bundle {
            anchor: l.root(),
            nullifiers: crate::storage::fixtures::pad4([nf(1), nf(2)]),
            commitments: crate::storage::fixtures::pad4([cm(1), cm(2)]),
            fee: fixtures::bundle_fee(),
            burn_a: 0,
            burn_r: bond,
            burn_asset: 0,
            time: l.height() as u32,
            envelopes: [fixtures::env(1), fixtures::env(2), fixtures::env(1), fixtures::env(2)],
            proof: vec![],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&fixtures::HC, &d, &[0; 8]);
        let payout = ShieldedAddress { pk: [7; 8], kem_ek: vec![8; randprotocol_core::notes::KEM_EK_BYTES] };
        let registration = AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(aggregator_register_message(1, &payout).as_bytes()),
        };
        let register = randprotocol_core::confidential::StubExecutor::bound(Transaction::shielded(1, b, Action::RegisterAggregator { registration }));
        l.apply_tx(&register, &fixtures::key(1).address(), &StubExecutor).unwrap();

        let aggregate = |covers: Vec<Hash>, nonce: u64, r: Word8| {
            let proof = b"ok".to_vec();
            Transaction {
                chain_id: 1,
                bundle: None,
                action: Action::Aggregate {
                    covers: covers.clone(),
                    proof: proof.clone(),
                    aggregator: addr,
                    nonce,
                    time: 0,
                    r,
                    envelope: fixtures::env(3),
                    signature: kp.sign(
                        aggregate_signing_hash(1, nonce, 0, &r, &covers, &Hash::digest(&proof), &randprotocol_core::types::actions::envelope_digest(&fixtures::env(3))).as_bytes(),
                    ),
                },
            }
        };

        // The synthetic covers in the ledger's coverable set (H1's block rule), excess-free.
        l.set_unsealed_fees(
            [Hash::digest(b"cover a"), Hash::digest(b"cover b")]
                .into_iter()
                .map(|c| (c, (0, fixtures::key(1).address(), u64::MAX)))
                .collect(),
        );
        let mut m = Mempool::new(10);
        let tx1 = aggregate(vec![Hash::digest(b"cover a")], 0, [9; 8]);
        let claims = m.precheck(&tx1, &l, &StubExecutor).unwrap();
        assert_eq!(claims.claim, Some((addr, 0)), "the aggregator's nonce slot is claimed");
        let payout_cm = l.derived_commitment(&tx1.action, &StubExecutor).expect("the payout note derives");
        assert_eq!(claims.commitments, vec![payout_cm], "and the payout note is the commitment claim");
        m.insert_verified(tx1.clone(), &l, &StubExecutor).unwrap();

        // The same aggregator at the same nonce, whatever it covers: a conflict over the slot.
        let tx2 = aggregate(vec![Hash::digest(b"cover b")], 0, [10; 8]);
        assert_eq!(
            m.precheck(&tx2, &l, &StubExecutor),
            Err(MempoolError::Conflict(claim_conflict_key(&addr)))
        );
        // The same keypair's *validator* unbond at nonce 0: a different register, no collision.
        let unbond = Transaction {
            chain_id: 1,
            bundle: None,
            action: Action::Unbond {
                validator: addr,
                amount: randprotocol_core::ledger::staking::MIN_STAKE,
                nonce: 0,
                signature: kp.sign(
                    randprotocol_core::types::unbond_message(1, &addr, randprotocol_core::ledger::staking::MIN_STAKE, 0).as_bytes(),
                ),
            },
        };
        assert!(
            m.precheck(&unbond, &l, &StubExecutor).is_ok(),
            "one keypair's two roles must not collide over a shared address and nonce"
        );

        // The register's other nonce consumers claim the same slot: an `UnbondAggregator` at
        // the same nonce conflicts with the pooled aggregate, and so does a
        // `WithdrawAggregator` — one register, one nonce, one claim.
        let agg_unbond = Transaction {
            chain_id: 1,
            bundle: None,
            action: Action::UnbondAggregator {
                aggregator: addr,
                nonce: 0,
                signature: kp.sign(
                    randprotocol_core::types::actions::aggregator_unbond_message(1, &addr, 0).as_bytes(),
                ),
            },
        };
        assert_eq!(
            m.precheck(&agg_unbond, &l, &StubExecutor),
            Err(MempoolError::Conflict(claim_conflict_key(&addr)))
        );
        let agg_withdraw = Transaction {
            chain_id: 1,
            bundle: None,
            action: Action::WithdrawAggregator {
                aggregator: addr,
                nonce: 0,
                time: 0,
                r: [4; 8],
                envelope: fixtures::env(5),
                signature: kp.sign(
                    randprotocol_core::types::actions::aggregator_withdraw_message(1, &addr, 0, 0, &[4; 8], &fixtures::env(5))
                        .as_bytes(),
                ),
            },
        };
        assert_eq!(
            m.precheck(&agg_withdraw, &l, &StubExecutor),
            Err(MempoolError::Conflict(claim_conflict_key(&addr)))
        );
    }

    /// A `WithdrawAggregator`'s note time goes stale by the same rule as a `Withdraw`'s: out of
    /// the window, the pre-screen refuses it before any register work.
    #[test]
    fn a_withdraw_aggregator_whose_time_is_outside_the_window_is_refused() {
        use randprotocol_core::ledger::aggregation::AggregationConfig;
        use randprotocol_core::types::actions::aggregator_withdraw_message;

        let kp = fixtures::key(1);
        let addr = kp.public_key().address();
        let mut l = ledger();
        l.set_aggregation(Some(AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![],
        }));
        // Height 1, so a future time is outside the window.
        l.set_height(1);
        let tx = Transaction {
            chain_id: 1,
            bundle: None,
            action: Action::WithdrawAggregator {
                aggregator: addr,
                nonce: 0,
                time: 2,
                r: [4; 8],
                envelope: fixtures::env(5),
                signature: kp.sign(aggregator_withdraw_message(1, &addr, 0, 2, &[4; 8], &fixtures::env(5)).as_bytes()),
            },
        };
        match l.validate(&tx, &StubExecutor) {
            Err(TxError::TimeOutOfWindow { time: 2, height: 1 }) => {}
            other => panic!("a stale note time must be refused, got {other:?}"),
        }
        // And the pre-screen reports it the same way.
        let m = Mempool::new(10);
        match m.precheck(&tx, &l, &StubExecutor) {
            Err(MempoolError::Invalid(TxError::TimeOutOfWindow { time: 2, height: 1 })) => {}
            other => panic!("the pre-screen must report it too, got {other:?}"),
        }
    }

    /// A ledger with a four-word program deployed, its id, and a call to it at `tier` paying
    /// `fee`, on fresh nullifiers `n..n+4`.
    fn program_and_call(tier: u8, fee: u64, n: u8) -> (Ledger, randprotocol_core::program::ProgramId, Transaction) {
        use randprotocol_core::confidential::StubExecutor;
        let gs = fixtures::genesis(1);
        let mut ledger = gs.ledger.clone();
        let words = vec![0x13u32; 4];
        let pid = randprotocol_core::program::program_id(0, &words);
        let with_bundle = |l: &Ledger, a: u8, fee: u64, action| {
            let a = a as u32;
            let b = fixtures::bundle_tx(l, [[a; 8], [a + 1; 8]], [[a + 2; 8], [a + 3; 8]], fee).bundle.expect("bundle");
            StubExecutor::bound(Transaction::shielded(gs.chain_id, b, action))
        };
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let deploy = with_bundle(&ledger, 40, randprotocol_core::gas::fee_floor(&deploy), deploy);
        ledger.apply_tx(&deploy, &fixtures::key(1).address(), &StubExecutor).unwrap();
        ledger.record_anchor(ledger.height());
        let call = with_bundle(
            &ledger,
            n,
            fee,
            Action::Call { program: pid, proof: StubExecutor::make_proof_with_public(&pid, tier, [7; 8], &[]), input_envelope: None },
        );
        (ledger, pid, call)
    }

    /// Spec 2026-09-28 §4.1: under a policy a call must pay `GasPolicy::call_floor` of its
    /// header; at the ledger's old floor it is refused, naming the policy's minimum, and the
    /// verdict is not permanent.
    #[test]
    fn a_call_under_the_policy_floor_is_refused_at_precheck() {
        use randprotocol_core::gas::{self, GasPolicy};
        // Tier 14, not the brief's 12: at tier 12 (gas_max 5 119, GAS_PRICE_DEFAULT 100) the
        // gas-priced floor is 1 512 700 against the old schedule's 2 100 000 — the ledger's own
        // floor dominates the `max` in `GasPolicy::call_floor` and `want == old`, so the refusal
        // this test exists to demonstrate cannot happen there. Tier 14 (gas_max 20 479) is the
        // first step where the gas price's `100 × gas_max` term overtakes the flat per-tier-step
        // schedule; verified against the built `GasPolicy::DEFAULT` before writing this in.
        let stub_len = StubExecutor::make_proof_with_public(&Hash::ZERO, 14, [0; 8], &[]).len();
        let old = gas::BUNDLE_BASE + gas::call_fee(14, stub_len);
        let want = GasPolicy::DEFAULT.call_floor(14, 0, 0, stub_len);
        assert!(want > old);
        let (ledger, _, call) = program_and_call(14, old, 50);
        let mut m = Mempool::new(64);
        m.set_gas_policy(GasPolicy::DEFAULT);
        assert_eq!(
            m.precheck(&call, &ledger, &StubExecutor).unwrap_err(),
            MempoolError::Invalid(TxError::FeeTooLow { min: want, fee: old })
        );
        assert!(!crate::admission::is_permanent(&TxError::FeeTooLow { min: want, fee: old }));
        // `insert` (the local `rand_sendTransaction` path) applies it too.
        assert_eq!(m.insert(call, &ledger, &StubExecutor).unwrap_err(), MempoolError::Invalid(TxError::FeeTooLow { min: want, fee: old }));
        // At the policy floor it pools, and its claims carry that floor.
        let (ledger, _, paid) = program_and_call(14, want, 60);
        let c = m.precheck(&paid, &ledger, &StubExecutor).unwrap();
        assert_eq!(c.floor, want);
        m.insert(paid, &ledger, &StubExecutor).unwrap();
        // Without a policy the old floor pools, and the claims carry the ledger's floor.
        let (ledger, _, call) = program_and_call(14, old, 70);
        let n = Mempool::new(64);
        assert_eq!(n.precheck(&call, &ledger, &StubExecutor).unwrap().floor, gas::fee_floor(&call.action));
    }

    /// C1 of the final review: under genesis `hardening_v6` a call to a program without a public
    /// input proves over its `call_binding` (INT-4), so the policy's header read must decode it the
    /// hardened way, as the ledger does — the plain decoder compares `H_PUB` against the empty
    /// segment and refused every such call `InvalidProof("PublicValues")`, permanently.
    #[test]
    fn a_hardened_call_paying_the_policy_floor_passes_precheck() {
        use randprotocol_core::gas::GasPolicy;
        let (mut ledger, pid, _) = program_and_call(14, 0, 50);
        ledger.set_hardening_v6(true);
        let stub_len = StubExecutor::make_proof_with_public(&Hash::ZERO, 14, [0; 8], &[]).len();
        let want = GasPolicy::DEFAULT.call_floor(14, 0, 0, stub_len);
        let b = fixtures::bundle_tx(&ledger, [[60; 8], [61; 8]], [[62; 8], [63; 8]], want).bundle.expect("bundle");
        let mut call = Transaction::shielded(ledger.chain_id(), b, Action::Call { program: pid, proof: vec![], input_envelope: None });
        let proof = StubExecutor::make_proof_with_public(&pid, 14, [7; 8], &call.call_binding());
        let Action::Call { proof: p, .. } = &mut call.action else { unreachable!() };
        *p = proof;
        let call = StubExecutor::bound(call);
        assert_eq!(ledger.validate(&call, &StubExecutor), Ok(()), "the ledger accepts the bound call");
        let mut m = Mempool::new(64);
        m.set_gas_policy(GasPolicy::DEFAULT);
        assert_eq!(m.precheck(&call, &ledger, &StubExecutor).unwrap().floor, want);
    }

    /// Chain 16 hotfix: `admission::call_floor` used to read a hardened call's header over just
    /// `tx.call_binding()`, but the ledger's own hardened-call rule (`hardened_call_segment`,
    /// issue #55) proves over the program's deploy-time public words *then* the binding — for a
    /// program deployed with a public input that segment is longer than the binding alone, so
    /// the policy's decode failed `InvalidProof("PublicValues")` (permanent) for every valid call
    /// to it, even though the ledger itself would have accepted the same proof. The fix reads the
    /// segment the same way the ledger does.
    #[test]
    fn a_hardened_call_to_a_public_input_program_is_priced_not_refused_under_a_node_policy() {
        use randprotocol_core::gas::GasPolicy;
        use randprotocol_core::program::{hardened_call_segment, program_id_with_public};

        let gs = fixtures::genesis(1);
        let mut ledger = gs.ledger.clone();
        ledger.set_hardening_v6(true);
        ledger.set_max_program_public_words(8);
        let words = vec![0x13u32; 4];
        let public = vec![1u32, 2, 3];
        let pid = program_id_with_public(0, &words, &public);
        let with_bundle = |l: &Ledger, a: u8, fee: u64, action| {
            let a = a as u32;
            let b = fixtures::bundle_tx(l, [[a; 8], [a + 1; 8]], [[a + 2; 8], [a + 3; 8]], fee).bundle.expect("bundle");
            StubExecutor::bound(Transaction::shielded(gs.chain_id, b, action))
        };
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: public.clone() };
        let deploy = with_bundle(&ledger, 40, randprotocol_core::gas::fee_floor(&deploy), deploy);
        ledger.apply_tx(&deploy, &fixtures::key(1).address(), &StubExecutor).unwrap();
        ledger.record_anchor(ledger.height());

        let stub_len = StubExecutor::make_proof_with_public(&Hash::ZERO, 12, [0; 8], &[]).len();
        let want = GasPolicy::DEFAULT.call_floor(12, 0, 0, stub_len);
        let call = with_bundle(&ledger, 60, want, Action::Call { program: pid, proof: vec![], input_envelope: None });
        let binding = call.call_binding();
        let segment = hardened_call_segment(&public, &binding);
        let proof = StubExecutor::make_proof_with_public(&pid, 12, [7; 8], &segment);
        let mut call = call;
        let Action::Call { proof: p, .. } = &mut call.action else { unreachable!() };
        *p = proof;
        let call = StubExecutor::bound(call);

        assert_eq!(ledger.validate(&call, &StubExecutor), Ok(()), "the ledger accepts the bound call");
        assert_eq!(
            crate::admission::call_floor(&call, &ledger, &StubExecutor, &GasPolicy::DEFAULT),
            Ok(want),
            "the pool prices the call over the ledger's own segment instead of refusing it"
        );
        let mut m = Mempool::new(64);
        m.set_gas_policy(GasPolicy::DEFAULT);
        assert_eq!(m.precheck(&call, &ledger, &StubExecutor).unwrap().floor, want);
    }

    /// Spec 2026-09-28 §4.2: on a chain whose genesis carries the `gas` section the pool's floor
    /// for a call IS the ledger's rule — `BUNDLE_BASE + gas_price·GAS_LIMIT + byte_price·KiB` at
    /// the ledger's current prices over the proof's declared limit — with or without a node
    /// policy, and never the schedule's `fee_floor` (which would refuse a call the chain admits).
    #[test]
    fn under_the_gas_section_the_pools_call_floor_is_the_ledger_rule() {
        use randprotocol_core::gas::{self, GasConfig, GasMetering, GasPolicy, GasPrices};
        let section = GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: GasMetering::Circuit, dynamic: None };
        let stub_len = StubExecutor::make_proof_with_public(&Hash::ZERO, 12, [0; 8], &[]).len();
        // A stub tier-12 proof declares gas_max(12, 0, 0) = 5 119 (4 095 cycles + the 2^10 absorb term).
        let want = gas::circuit_call_floor(100, 800, gas::gas_max(12, 0, 0), stub_len);
        assert!(want < gas::fee_floor(&Action::Call { program: Hash::ZERO, proof: vec![], input_envelope: None }), "cheaper than the schedule's pre-verify floor");
        for policy in [None, Some(GasPolicy::DEFAULT), GasPolicy::from_prices(1_000, 8_000)] {
            let (mut ledger, _, short) = program_and_call(12, want - 1, 50);
            ledger.set_gas(Some(section.clone()));
            let mut m = Mempool::new(64);
            if let Some(p) = policy {
                m.set_gas_policy(p);
            }
            assert_eq!(
                m.precheck(&short, &ledger, &StubExecutor).unwrap_err(),
                MempoolError::Invalid(TxError::FeeTooLow { min: want, fee: want - 1 }),
                "{policy:?}"
            );
            let (mut ledger, _, paid) = program_and_call(12, want, 60);
            ledger.set_gas(Some(section.clone()));
            assert_eq!(ledger.validate(&paid, &StubExecutor), Ok(()), "the ledger admits it at the rule's floor");
            assert_eq!(m.precheck(&paid, &ledger, &StubExecutor).unwrap().floor, want, "{policy:?}");
            m.insert(paid, &ledger, &StubExecutor).unwrap();
            // `call_floor` itself answers the rule, at the ledger's current prices.
            let (mut ledger, _, call) = program_and_call(12, want, 70);
            ledger.set_gas(Some(section.clone()));
            ledger.set_gas_prices(GasPrices { gas_price: 300, byte_price: 900 });
            assert_eq!(
                crate::admission::call_floor(&call, &ledger, &StubExecutor, &GasPolicy::DEFAULT).unwrap(),
                gas::circuit_call_floor(300, 900, gas::gas_max(12, 0, 0), stub_len)
            );
        }
    }

    /// Audit v6, CH-9. Under `gas.dynamic` a call's floor moves every block; the pool stored the
    /// floor once, at admission, ranked by the fee above *that* floor, and never looked at the
    /// fee again. After a price rise a call that no longer pays its floor fails `FeeTooLow` in
    /// the proposer's trial apply — yet it was offered first, on its old surplus, and counted
    /// against the candidate caps until its anchor left the window: thin or empty blocks for
    /// minutes. Selection re-prices each call at the ledger's current prices: below the floor it
    /// is not offered (it stays pooled — prices fall again), and the rank is the surplus now.
    #[test]
    fn a_pooled_call_is_repriced_at_selection_not_ranked_on_the_floor_it_was_admitted_at() {
        use randprotocol_core::gas::{self, GasConfig, GasMetering, GasPrices};
        let section = GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: GasMetering::Circuit, dynamic: None };
        let stub_len = StubExecutor::make_proof_with_public(&Hash::ZERO, 12, [0; 8], &[]).len();
        let limit = gas::gas_max(12, 0, 0);
        let at_start = gas::circuit_call_floor(100, 800, limit, stub_len);
        let at_triple = gas::circuit_call_floor(300, 900, limit, stub_len);
        assert!(at_triple > at_start + 1_000_000);
        // `stale` pays a large surplus at the start prices and less than the floor after the rise;
        // `keeps` still pays its floor after it, by 10; a transfer pays 1 000 over its flat base.
        let (mut ledger, pid, stale) = program_and_call(12, at_start + 1_000_000, 50);
        ledger.set_gas(Some(section));
        let second = |n: u32, fee: u64, action| {
            let b = fixtures::bundle_tx(&ledger, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], fee).bundle.expect("bundle");
            StubExecutor::bound(Transaction::shielded(ledger.chain_id(), b, action))
        };
        let keeps = second(60, at_triple + 10, Action::Call { program: pid, proof: StubExecutor::make_proof_with_public(&pid, 12, [8; 8], &[]), input_envelope: None });
        let transfer = fixtures::bundle_tx(&ledger, [[80; 8], [81; 8]], [[82; 8], [83; 8]], gas::BUNDLE_BASE + 1_000);
        let mut m = Mempool::new(64);
        let stale_hash = m.insert(stale, &ledger, &StubExecutor).unwrap();
        let keeps_hash = m.insert(keeps, &ledger, &StubExecutor).unwrap();
        let transfer_hash = m.insert(transfer, &ledger, &StubExecutor).unwrap();
        let picked = |l: &Ledger| m.candidates(l, 10).iter().map(|t| t.hash()).collect::<Vec<Hash>>();
        assert_eq!(picked(&ledger), vec![keeps_hash, stale_hash, transfer_hash], "at the start prices: by surplus per KiB");

        let mut risen = ledger.clone();
        risen.set_gas_prices(GasPrices { gas_price: 300, byte_price: 900 });
        let now = picked(&risen);
        assert!(!now.contains(&stale_hash), "a call under the current floor is not offered: {now:?}");
        assert_eq!(now, vec![transfer_hash, keeps_hash], "and the rank is the surplus over the current floor (1 000 against 10)");
        assert_eq!(m.len(), 3, "nothing is evicted: the price falls again");
        assert_eq!(picked(&ledger).len(), 3, "and at the old prices all three are offered once more");
    }

    /// Review focus 1 and 2: the policy check never decodes a proof it should not.
    #[test]
    fn an_unknown_programs_call_is_refused_before_its_proof_is_decoded() {
        let (ledger, _, call) = program_and_call(12, u64::MAX / 2, 50);
        let unknown = Hash::digest(b"no such program");
        let Action::Call { proof, .. } = &call.action else { unreachable!() };
        let tx = StubExecutor::bound(Transaction::shielded(
            ledger.chain_id(),
            call.bundle.clone().unwrap(),
            Action::Call { program: unknown, proof: proof.clone(), input_envelope: None },
        ));
        let r = crate::admission::call_floor(&tx, &ledger, &StubExecutor, &randprotocol_core::gas::GasPolicy::DEFAULT);
        assert_eq!(r.unwrap_err(), TxError::UnknownProgram(unknown));
    }

    #[test]
    fn an_oversized_proof_is_refused_before_the_policy_decodes_it() {
        let (ledger, pid, call) = program_and_call(12, u64::MAX / 2, 50);
        let over = vec![0u8; ledger.max_proof_bytes() + 1];
        let tx = StubExecutor::bound(Transaction::shielded(
            ledger.chain_id(),
            call.bundle.clone().unwrap(),
            Action::Call { program: pid, proof: over, input_envelope: None },
        ));
        let r = crate::admission::call_floor(&tx, &ledger, &StubExecutor, &randprotocol_core::gas::GasPolicy::DEFAULT);
        assert_eq!(r.unwrap_err(), TxError::ProofTooLarge);
    }

    /// Review focus 3 (final review I1): no policy is no change. Without a gas policy the pool
    /// orders as it did before the gas work — governance, then total fee, then hash — and only a
    /// node running a policy orders by surplus per KiB. The same two transactions: a call paying
    /// one more than a transfer in total, but less above its floor per KiB.
    #[test]
    fn zero_prices_mean_no_policy() {
        use randprotocol_core::gas::{self, GasPolicy};
        assert!(GasPolicy::from_prices(0, 0).is_none(), "zero prices name no policy");
        let stub_len = StubExecutor::make_proof_with_public(&Hash::ZERO, 12, [0; 8], &[]).len();
        let call_fee = GasPolicy::DEFAULT.call_floor(12, 0, 0, stub_len) + 3_000;
        let (ledger, _, call) = program_and_call(12, call_fee, 50);
        let transfer = fixtures::bundle_tx(&ledger, [[80; 8], [81; 8]], [[82; 8], [83; 8]], call_fee - 1);
        assert!(call.fee() > transfer.fee(), "the call pays more in total");
        assert!(call.encoded_len() > transfer.encoded_len(), "and is the bigger transaction");

        let mut plain = Mempool::new(64);
        let call_hash = plain.insert(call.clone(), &ledger, &StubExecutor).unwrap();
        let transfer_hash = plain.insert(transfer.clone(), &ledger, &StubExecutor).unwrap();
        // Under the schedule's floors the transfer's surplus per KiB is the larger one too, so
        // only the pre-gas key — total fee — puts the call first.
        let per_kib = |t: &Transaction| (t.fee() - gas::fee_floor(&t.action)) as u128 * 1024 / t.encoded_len() as u128;
        assert!(per_kib(&transfer) > per_kib(&call));
        let picked: Vec<Hash> = plain.candidates(&ledger, 10).iter().map(|t| t.hash()).collect();
        assert_eq!(picked, vec![call_hash, transfer_hash], "no policy: total fee first");

        let mut priced = Mempool::new(64);
        priced.set_gas_policy(GasPolicy::DEFAULT);
        priced.insert(call, &ledger, &StubExecutor).unwrap();
        priced.insert(transfer, &ledger, &StubExecutor).unwrap();
        let picked: Vec<Hash> = priced.candidates(&ledger, 10).iter().map(|t| t.hash()).collect();
        assert_eq!(picked, vec![transfer_hash, call_hash], "a policy: surplus per KiB first");
    }

    /// Spec §7: candidates order by fee above the floor per KiB, governance first. A big call
    /// paying a little more in total sorts behind a small transfer paying more per KiB.
    #[test]
    fn candidates_order_by_surplus_per_kib() {
        use randprotocol_core::gas;
        // The stub call proof is ~110 B, so the call is only slightly bigger than the transfer;
        // give it the smaller surplus (3 000 over its floor against the transfer's 5 000) so the
        // per-KiB key, not the total, decides.
        let (ledger, _, call) = program_and_call(12, gas::GasPolicy::DEFAULT.call_floor(12, 0, 0, 200) + 3_000, 50);
        let mut m = Mempool::new(64);
        m.set_gas_policy(gas::GasPolicy::DEFAULT);
        let transfer = fixtures::bundle_tx(&ledger, [[80; 8], [81; 8]], [[82; 8], [83; 8]], gas::BUNDLE_BASE + 5_000);
        let call_hash = m.insert(call.clone(), &ledger, &StubExecutor).unwrap();
        let transfer_hash = m.insert(transfer.clone(), &ledger, &StubExecutor).unwrap();
        assert!(call.encoded_len() > transfer.encoded_len(), "the call is the bigger transaction");
        assert!(call.fee() > transfer.fee(), "and pays more in total");
        let picked: Vec<Hash> = m.candidates(&ledger, 10).iter().map(|t| t.hash()).collect();
        assert_eq!(picked, vec![transfer_hash, call_hash], "more surplus per KiB first");
    }

    /// Final review I3: the key is surplus *per KiB*, not absolute surplus. Here the bigger call
    /// carries MORE surplus above its floor than the transfer, but less per KiB, and the smaller
    /// transfer still sorts first — an absolute-surplus key would have put the call first.
    #[test]
    fn candidates_order_by_surplus_per_kib_not_by_absolute_surplus() {
        use randprotocol_core::gas::{self, GasPolicy};
        let policy = GasPolicy::DEFAULT;
        // Lengths do not depend on the fee (a fixed-width u64), so measure them first.
        let (ledger, _, probe) = program_and_call(12, 0, 50);
        let floor_c = crate::admission::call_floor(&probe, &ledger, &StubExecutor, &policy).unwrap();
        let floor_t = gas::fee_floor(&Action::None);
        let len_t = fixtures::bundle_tx(&ledger, [[80; 8], [81; 8]], [[82; 8], [83; 8]], 0).encoded_len();
        let len_c = probe.encoded_len();
        assert!(len_c > len_t, "the call is the bigger transaction ({len_c} vs {len_t} B)");
        // The transfer's surplus, and a call surplus above it but below it scaled by the size
        // ratio: halfway into that gap.
        let s_t: u64 = 10_000_000;
        let s_c = s_t + (s_t as u128 * (len_c - len_t) as u128 / len_t as u128 / 2) as u64;
        let (ledger, _, call) = program_and_call(12, floor_c + s_c, 50);
        let transfer = fixtures::bundle_tx(&ledger, [[80; 8], [81; 8]], [[82; 8], [83; 8]], floor_t + s_t);
        assert_eq!((call.encoded_len(), transfer.encoded_len()), (len_c, len_t));
        let per_kib = |s: u64, len: usize| s as u128 * 1024 / len as u128;
        assert!(s_c > s_t, "the call has more absolute surplus ({s_c} vs {s_t})");
        assert!(per_kib(s_c, len_c) < per_kib(s_t, len_t), "but less per KiB");
        let mut m = Mempool::new(64);
        m.set_gas_policy(policy);
        let call_hash = m.insert(call, &ledger, &StubExecutor).unwrap();
        let transfer_hash = m.insert(transfer, &ledger, &StubExecutor).unwrap();
        let picked: Vec<Hash> = m.candidates(&ledger, 10).iter().map(|t| t.hash()).collect();
        assert_eq!(picked, vec![transfer_hash, call_hash], "more surplus per KiB first, not more surplus");
    }

    /// Controller ruling (B3 review): under the genesis `gas` section calls are priced, so the
    /// pool orders by surplus per KiB even on a node without a gas policy. The same shape as
    /// `candidates_order_by_surplus_per_kib_not_by_absolute_surplus`, no policy, a fixed section.
    #[test]
    fn under_the_gas_section_candidates_order_by_surplus_per_kib_without_a_policy() {
        use randprotocol_core::gas::{self, GasConfig, GasMetering};
        let section = GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: GasMetering::Circuit, dynamic: None };
        let with_section = |(mut l, pid, tx): (Ledger, randprotocol_core::program::ProgramId, Transaction)| {
            l.set_gas(Some(section.clone()));
            (l, pid, tx)
        };
        let (ledger, _, probe) = with_section(program_and_call(12, 0, 50));
        let floor_c = ledger.gas_call_floor(gas::gas_max(12, 0, 0), {
            let Action::Call { proof, .. } = &probe.action else { unreachable!() };
            proof.len()
        })
        .unwrap();
        let floor_t = gas::fee_floor(&Action::None);
        let len_t = fixtures::bundle_tx(&ledger, [[80; 8], [81; 8]], [[82; 8], [83; 8]], 0).encoded_len();
        let len_c = probe.encoded_len();
        assert!(len_c > len_t, "the call is the bigger transaction ({len_c} vs {len_t} B)");
        let s_t: u64 = 10_000_000;
        let s_c = s_t + (s_t as u128 * (len_c - len_t) as u128 / len_t as u128 / 2) as u64;
        let (ledger, _, call) = with_section(program_and_call(12, floor_c + s_c, 50));
        let transfer = fixtures::bundle_tx(&ledger, [[80; 8], [81; 8]], [[82; 8], [83; 8]], floor_t + s_t);
        assert!(call.fee() > transfer.fee(), "total-fee order would put the call first");
        let per_kib = |s: u64, len: usize| s as u128 * 1024 / len as u128;
        assert!(per_kib(s_c, len_c) < per_kib(s_t, len_t), "but it has less surplus per KiB");
        let mut m = Mempool::new(64);
        let call_hash = m.insert(call, &ledger, &StubExecutor).unwrap();
        let transfer_hash = m.insert(transfer, &ledger, &StubExecutor).unwrap();
        let picked: Vec<Hash> = m.candidates(&ledger, 10).iter().map(|t| t.hash()).collect();
        assert_eq!(picked, vec![transfer_hash, call_hash], "more surplus per KiB first, with no node policy");
    }

    /// B3 review: `call_floor` decodes a hardened call over the ledger's own segment — a
    /// program's deploy-time public words, then the call binding (issue #55) — so a call to a
    /// program WITH a public input is priced at the rule's floor, not refused `InvalidProof`.
    #[test]
    fn a_hardened_call_to_a_public_input_program_is_priced_not_refused() {
        use randprotocol_core::gas::{self, GasConfig, GasMetering, GasPolicy};
        let gs = fixtures::genesis(1);
        let mut ledger = gs.ledger.clone();
        ledger.set_max_program_public_words(64);
        let words = vec![0x13u32; 4];
        let public = vec![0xdead_beefu32; 3];
        let pid = randprotocol_core::program::program_id_with_public(0, &words, &public);
        let deploy = Action::Deploy { base_pc: 0, words, public: public.clone() };
        let b = fixtures::bundle_tx(&ledger, [[40; 8], [41; 8]], [[42; 8], [43; 8]], gas::fee_floor(&deploy)).bundle.expect("bundle");
        let deploy = StubExecutor::bound(Transaction::shielded(gs.chain_id, b, deploy));
        ledger.apply_tx(&deploy, &fixtures::key(1).address(), &StubExecutor).unwrap();
        ledger.record_anchor(ledger.height());
        ledger.set_hardening_v6(true);
        ledger.set_gas(Some(GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: GasMetering::Circuit, dynamic: None }));
        let stub_len = StubExecutor::make_proof_with_public(&pid, 12, [7; 8], &public).len();
        let floor = gas::circuit_call_floor(100, 800, gas::gas_max(12, 0, 0), stub_len);
        let b = fixtures::bundle_tx(&ledger, [[60; 8], [61; 8]], [[62; 8], [63; 8]], floor).bundle.expect("bundle");
        let mut call = Transaction::shielded(ledger.chain_id(), b, Action::Call { program: pid, proof: vec![], input_envelope: None });
        let segment = [public.as_slice(), call.call_binding().as_slice()].concat();
        let proof = StubExecutor::make_proof_with_public(&pid, 12, [7; 8], &segment);
        let Action::Call { proof: p, .. } = &mut call.action else { unreachable!() };
        *p = proof;
        let call = StubExecutor::bound(call);
        assert_eq!(ledger.validate(&call, &StubExecutor), Ok(()), "the ledger accepts the call at the floor");
        assert_eq!(crate::admission::call_floor(&call, &ledger, &StubExecutor, &GasPolicy::DEFAULT), Ok(floor));
        assert_eq!(Mempool::new(64).precheck(&call, &ledger, &StubExecutor).unwrap().floor, floor);
    }
}
