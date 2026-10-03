//! RPL-3: perpetual futures (`docs/superpowers/plans/2026-10-03-rpl3-perps.md`).
//!
//! The chain does not run the exchange. It records what traders and validators send — deposits,
//! orders, cancels, withdrawal requests, oracle prices — as fixed-width words, closes each block
//! with a digest `D_h` of that block's words, and advances the exchange's state root only when a
//! prover submits one STARK that ran the engine over a window of those digests. This module holds
//! the words and the state the ledger keeps for that:
//!
//! - **The words.** [`PerpInput::words`], [`perp_digest`] and [`state_proof_segment`] are the
//!   encodings the engine's guest recomputes bit for bit; `tests/vectors/perps-v1.json` pins them
//!   so the engine's crate, which cannot depend on this one, can check it agrees.
//! - **The ledger's own state.** Trading keys and their nonce windows, the oracle, the proved
//!   root and height, the digests of the blocks not yet proved, and the withdrawals waiting on a
//!   proof to pay them. The state root ([`Perps::root`]) commits every field of it — the oracle
//!   submissions and nonces too, since they decide whether the next oracle transaction is valid —
//!   except the two per-block transient fields, which are emptied before a block's root is taken.
//!   The genesis section itself is fixed for the chain's life and committed by the genesis.
//!
//! The gate is the genesis `perps` section: without it the chain has no [`Perps`] at all.

use super::{Ledger, TxError};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{merkle_root, Address, Hash, PublicKey, Signature};
use crate::notes::{word8_from_bytes, word8_to_bytes, Envelope, ShieldedAddress, Word8, MAX_NOTE_VALUE};
use crate::types::transaction::{Action, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Word 0 of a state proof's public segment. The guest refuses a version it was not written for.
pub const PERP_VERSION: u32 = 1;
/// The most payout notes one state proof may create: [`super::MAX_LEAVES_PER_TX`] (8), since a
/// `PerpStateProof` carries no bundle whose commitments would share that budget.
pub const MAX_PERP_PAYOUTS: usize = 8;
/// A validator's oracle price older than this many blocks no longer counts towards the median.
pub const ORACLE_STALE_BLOCKS: u64 = 30;
/// The most words [`perp_digest`] absorbs per sponge call: with the domain word and the eight
/// words of the running digest, `1 + 8 + 4000` stays under the `POSEIDON2` syscall's 4 096-word
/// cap, so the guest computes the same digest in the same calls.
pub const DIGEST_CHUNK_WORDS: usize = 4000;

/// The Poseidon2 domains of the perp words, mirrored from `randprotocol-zkvm`'s
/// `notes::domain::{PERP_BLOCK, PERP_STATE, PERP_PAYOUTS}` (core cannot name the zkvm crate; a
/// test there pins the two).
pub mod domain {
    /// A block's input digest `D_h`.
    pub const BLOCK: u32 = 21;
    /// The engine's state root `R`.
    pub const STATE: u32 = 22;
    /// A state proof's payouts digest.
    pub const PAYOUTS: u32 = 23;
}

/// The tiers a zkVM proof can be made at (`randprotocol-zkvm`'s `machine::TIERS`), restated
/// because core cannot import it; a test in the zkvm crate pins the two.
pub const TIERS: [u8; 6] = [10, 12, 14, 16, 18, 20];
/// The most blocks `max_window_blocks` may set one state proof to cover.
pub const MAX_WINDOW_BLOCKS: u64 = 64;
/// The widest a nonce window reaches below its highest nonce: the 64 bits of `used`.
const NONCE_WINDOW: u64 = 64;

/// A trader's account on the exchange: the eight words of its trading key's address. Words
/// rather than an [`Address`] because the engine, which only sees words, keys accounts by it.
pub type AccountId = Word8;

/// The account a trading key owns.
pub fn account_id(trading_key: &PublicKey) -> AccountId {
    word8_from_bytes(Address::from_public_key(trading_key).as_bytes()).expect("an address is 32 bytes")
}

/// One market of the genesis section. The engine's own copy of these numbers is in its state, so
/// the root the genesis names already commits to them; the ledger keeps them to refuse an order
/// for a market that does not exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketSpec {
    pub id: u32,
    pub symbol: String,
    /// The size increment, in base atomic units.
    pub lot: u64,
    /// The price increment, in quote atomic units per `BASE_UNIT` of base.
    pub tick: u64,
    pub max_leverage: u32,
    pub maintenance_bps: u32,
    pub taker_fee_bps: u32,
    pub maker_fee_bps: u32,
}

/// The genesis `perps` section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerpsConfig {
    /// The asset deposits are made in and withdrawals paid in: 0 is RAND.
    pub collateral_asset: u32,
    /// The highest tier a state proof may be made at, which bounds what one costs to verify.
    pub max_tier: u8,
    /// The most blocks one state proof may cover.
    pub max_window_blocks: u64,
    /// The engine guest's program commitment: a state proof of any other program is refused.
    #[serde(with = "crate::notes::word8_hex")]
    pub engine_hc: Word8,
    /// The engine's state root at height 0.
    #[serde(with = "crate::notes::word8_hex")]
    pub genesis_root: Word8,
    pub markets: Vec<MarketSpec>,
}

impl PerpsConfig {
    pub fn check(&self) -> Result<(), String> {
        if !TIERS.contains(&self.max_tier) {
            return Err(format!("perps.max_tier {} is not a proof tier ({TIERS:?})", self.max_tier));
        }
        if !(1..=MAX_WINDOW_BLOCKS).contains(&self.max_window_blocks) {
            return Err(format!(
                "perps.max_window_blocks {} is outside 1..={MAX_WINDOW_BLOCKS}",
                self.max_window_blocks
            ));
        }
        if !(1..=16).contains(&self.markets.len()) {
            return Err(format!("perps.markets has {} markets; a chain has 1 to 16", self.markets.len()));
        }
        for (i, m) in self.markets.iter().enumerate() {
            if m.id as usize != i {
                return Err(format!("perps.markets[{i}] has id {}; ids are 0, 1, … in order", m.id));
            }
            if m.lot == 0 || m.tick == 0 {
                return Err(format!("perps market {i}: lot and tick must be positive"));
            }
            if !(1..=100).contains(&m.max_leverage) {
                return Err(format!("perps market {i}: max_leverage {} is outside 1..=100", m.max_leverage));
            }
            for (name, bps) in [
                ("maintenance_bps", m.maintenance_bps),
                ("taker_fee_bps", m.taker_fee_bps),
                ("maker_fee_bps", m.maker_fee_bps),
            ] {
                if bps > 10_000 {
                    return Err(format!("perps market {i}: {name} {bps} exceeds 10000"));
                }
            }
        }
        Ok(())
    }
}

/// An order as its trader signs it. `side`: 0 buy, 1 sell. `kind`: 0 limit, 1 market. `tif`:
/// 0 GTC, 1 IOC, 2 post-only. The engine, not the ledger, decides whether the order is good;
/// the ledger only records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerpOrderBody {
    pub nonce: u64,
    pub market: u32,
    pub side: u8,
    pub kind: u8,
    pub tif: u8,
    pub reduce_only: bool,
    pub price: u64,
    pub size: u64,
}

/// One market's oracle median, as a block's `Close` input carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerpPrice {
    pub market: u32,
    pub price: u64,
}

/// What a state proof pays against one pending withdrawal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerpPayout {
    #[serde(with = "crate::notes::word8_hex")]
    pub request: Word8,
    pub amount: u64,
}

/// One input the engine consumes, in block order. A block's inputs end with exactly one `Close`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PerpInput {
    Deposit { account: AccountId, amount: u64 },
    Order { account: AccountId, body: PerpOrderBody },
    Cancel { account: AccountId, nonce: u64, target: u64 },
    Withdraw { account: AccountId, nonce: u64, amount: u64, request: Word8 },
    Close { height: u64, time_ms: u64, medians: Vec<PerpPrice> },
}

fn push_u64(out: &mut Vec<u32>, v: u64) {
    out.push(v as u32);
    out.push((v >> 32) as u32);
}

impl PerpInput {
    /// Append this input's words: its tag (1–5), then its fields, every `u64` as two words low
    /// first and every `Word8` as its eight words. The layout is the guest's, word for word.
    pub fn words(&self, out: &mut Vec<u32>) {
        match self {
            PerpInput::Deposit { account, amount } => {
                out.push(1);
                out.extend_from_slice(account);
                push_u64(out, *amount);
            }
            PerpInput::Order { account, body } => {
                out.push(2);
                out.extend_from_slice(account);
                push_u64(out, body.nonce);
                out.push(body.market);
                out.push(body.side as u32);
                out.push(body.kind as u32);
                out.push(body.tif as u32);
                out.push(body.reduce_only as u32);
                push_u64(out, body.price);
                push_u64(out, body.size);
            }
            PerpInput::Cancel { account, nonce, target } => {
                out.push(3);
                out.extend_from_slice(account);
                push_u64(out, *nonce);
                push_u64(out, *target);
            }
            PerpInput::Withdraw { account, nonce, amount, request } => {
                out.push(4);
                out.extend_from_slice(account);
                push_u64(out, *nonce);
                push_u64(out, *amount);
                out.extend_from_slice(request);
            }
            PerpInput::Close { height, time_ms, medians } => {
                out.push(5);
                push_u64(out, *height);
                push_u64(out, *time_ms);
                out.push(medians.len() as u32);
                for m in medians {
                    out.push(m.market);
                    push_u64(out, m.price);
                }
            }
        }
    }
}

/// The digest of a variable-length word string under `domain`: the length first, then the words
/// in chunks of [`DIGEST_CHUNK_WORDS`], each absorbed after the running digest. The sponge does
/// not pad, so the length word is what keeps `[a]` and `[a, 0]` apart.
pub fn perp_digest(h: &dyn ConfidentialExecutor, domain: u32, words: &[u32]) -> Word8 {
    let mut acc = h.hash_domain(domain, &[words.len() as u32]);
    let mut msg = Vec::with_capacity(8 + DIGEST_CHUNK_WORDS.min(words.len()));
    for chunk in words.chunks(DIGEST_CHUNK_WORDS) {
        msg.clear();
        msg.extend_from_slice(&acc);
        msg.extend_from_slice(chunk);
        acc = h.hash_domain(domain, &msg);
    }
    acc
}

/// `perp_digest(PAYOUTS, [n, (request(8), amount_lo, amount_hi)*])`: what a state proof's
/// segment says it pays, so the ledger can hold the proof to the payouts the transaction lists.
pub fn payouts_digest(h: &dyn ConfidentialExecutor, payouts: &[PerpPayout]) -> Word8 {
    let mut w = Vec::with_capacity(1 + 10 * payouts.len());
    w.push(payouts.len() as u32);
    for p in payouts {
        w.extend_from_slice(&p.request);
        push_u64(&mut w, p.amount);
    }
    perp_digest(h, domain::PAYOUTS, &w)
}

/// A state proof's public segment, `[PERP_VERSION, from, to, R_from, R_to, payouts, fees,
/// n_blocks, D_{from+1}, …, D_to]`. The ledger builds it from its own recorded digests, so a
/// prover cannot choose which block inputs its proof ran over.
pub fn state_proof_segment(
    from: u64,
    to: u64,
    r_from: &Word8,
    r_to: &Word8,
    payouts: &Word8,
    fees: u64,
    digests: &[Word8],
) -> Vec<u32> {
    let mut w = Vec::with_capacity(32 + 8 * digests.len());
    w.push(PERP_VERSION);
    push_u64(&mut w, from);
    push_u64(&mut w, to);
    w.extend_from_slice(r_from);
    w.extend_from_slice(r_to);
    w.extend_from_slice(payouts);
    push_u64(&mut w, fees);
    w.push(digests.len() as u32);
    for d in digests {
        w.extend_from_slice(d);
    }
    w
}

/// A trading account as the ledger knows it: the key that signs for it and its nonce window.
/// Its collateral and positions are the engine's, not the ledger's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerpAccount {
    pub trading_key: PublicKey,
    /// The highest nonce accepted.
    pub nonce_high: u64,
    /// Bit `i` is set when nonce `nonce_high - i` has been accepted.
    pub used: u64,
}

impl PerpAccount {
    /// Accept nonce `n` once. Nonces need not arrive in order — a trader may have several orders
    /// in flight — but each is good once, and one more than 63 below the highest is refused,
    /// since the window no longer remembers whether it was used.
    pub fn accept_nonce(&mut self, n: u64) -> Result<(), PerpError> {
        if n > self.nonce_high {
            let shift = n - self.nonce_high;
            self.used = if shift >= NONCE_WINDOW { 0 } else { self.used << shift };
            self.used |= 1;
            self.nonce_high = n;
            return Ok(());
        }
        let back = self.nonce_high - n;
        if back >= NONCE_WINDOW || self.used & (1 << back) != 0 {
            return Err(PerpError::NonceUsed);
        }
        self.used |= 1 << back;
        Ok(())
    }
}

/// A withdrawal the engine has been asked for and no proof has paid yet. The note it becomes is
/// the chain's to compute — recipient, blinding and envelope are fixed here, the amount by the
/// proof — exactly as an RPL-2 payout's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWithdrawal {
    pub account: AccountId,
    pub amount: u64,
    pub recipient: ShieldedAddress,
    pub r: Word8,
    pub envelope: Envelope,
    pub time: u32,
    pub height: u64,
}

/// One market's oracle: each validator's latest price and the height it was given at, and the
/// median the last block close computed from the fresh ones.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleState {
    pub submissions: BTreeMap<Address, (u64, u64)>,
    pub median: u64,
}

/// The ledger's perps state under the genesis section.
#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
pub struct Perps {
    pub config: PerpsConfig,
    accounts: BTreeMap<AccountId, PerpAccount>,
    oracle: BTreeMap<u32, OracleState>,
    /// The last oracle nonce each validator used.
    oracle_nonces: BTreeMap<Address, u64>,
    /// The engine state root the last state proof ended at (the genesis root before the first).
    pub proved_root: Word8,
    /// The height that root is at.
    pub proved_height: u64,
    /// `D_h` of every closed block above `proved_height`: what the next state proof must cover.
    digests: BTreeMap<u64, Word8>,
    /// Pending withdrawals by request id.
    withdrawals: BTreeMap<Word8, PendingWithdrawal>,
    /// The current block's inputs so far. Transient: emptied at every block close.
    #[serde(skip)]
    block_inputs: Vec<PerpInput>,
    /// The last closed block's height and input words, for the node to store and serve to
    /// provers. Transient: the node takes them right after the block applies.
    #[serde(skip)]
    last_block_words: Option<(u64, Vec<u32>)>,
}

/// Consensus fields only — exactly what the root commits, plus the genesis section: two ledgers
/// that agree on them are equal whatever their in-flight transient fields hold.
impl PartialEq for Perps {
    fn eq(&self, other: &Perps) -> bool {
        self.config == other.config
            && self.accounts == other.accounts
            && self.oracle == other.oracle
            && self.oracle_nonces == other.oracle_nonces
            && self.proved_root == other.proved_root
            && self.proved_height == other.proved_height
            && self.digests == other.digests
            && self.withdrawals == other.withdrawals
    }
}

impl Perps {
    /// The state at genesis: the section's root at height 0, nothing else.
    pub fn from_config(c: &PerpsConfig) -> Perps {
        Perps {
            config: c.clone(),
            accounts: BTreeMap::new(),
            oracle: BTreeMap::new(),
            oracle_nonces: BTreeMap::new(),
            proved_root: c.genesis_root,
            proved_height: 0,
            digests: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            block_inputs: Vec::new(),
            last_block_words: None,
        }
    }

    /// `blake3("rand-perps-1", proved_root ‖ proved_height ‖ accounts_root ‖ oracle_root ‖
    /// oracle_nonces_root ‖ digests_root ‖ withdrawals_root)`, each a merkle root over its map's
    /// leaves in map order. An oracle leaf is the market's median and every submission behind it
    /// (in validator address order), because the submissions and the nonces decide whether the
    /// next oracle transaction is valid: two nodes that differ in them must differ in root.
    /// Integers are big-endian; a withdrawal's leaf is its bincode, which is length-prefixed
    /// wherever a field is variable. Everything but the two transient per-block fields is here.
    pub fn root(&self) -> Hash {
        let accounts: Vec<Hash> = self
            .accounts
            .iter()
            .map(|(id, a)| {
                let mut buf = Vec::with_capacity(48 + a.trading_key.as_bytes().len());
                buf.extend_from_slice(&word8_to_bytes(id));
                buf.extend_from_slice(&a.nonce_high.to_be_bytes());
                buf.extend_from_slice(&a.used.to_be_bytes());
                buf.extend_from_slice(a.trading_key.as_bytes());
                Hash::digest_domain(b"rand-perp-account-1", &buf)
            })
            .collect();
        let oracle: Vec<Hash> = self
            .oracle
            .iter()
            .map(|(market, o)| {
                let mut buf = Vec::with_capacity(16 + 48 * o.submissions.len());
                buf.extend_from_slice(&market.to_be_bytes());
                buf.extend_from_slice(&o.median.to_be_bytes());
                buf.extend_from_slice(&(o.submissions.len() as u32).to_be_bytes());
                for (validator, (price, height)) in &o.submissions {
                    buf.extend_from_slice(validator.as_bytes());
                    buf.extend_from_slice(&price.to_be_bytes());
                    buf.extend_from_slice(&height.to_be_bytes());
                }
                Hash::digest_domain(b"rand-perp-oracle-1", &buf)
            })
            .collect();
        let oracle_nonces: Vec<Hash> = self
            .oracle_nonces
            .iter()
            .map(|(validator, nonce)| {
                let mut buf = Vec::with_capacity(40);
                buf.extend_from_slice(validator.as_bytes());
                buf.extend_from_slice(&nonce.to_be_bytes());
                Hash::digest_domain(b"rand-perp-oracle-nonce-1", &buf)
            })
            .collect();
        let digests: Vec<Hash> = self
            .digests
            .iter()
            .map(|(height, d)| {
                let mut buf = Vec::with_capacity(40);
                buf.extend_from_slice(&height.to_be_bytes());
                buf.extend_from_slice(&word8_to_bytes(d));
                Hash::digest_domain(b"rand-perp-digest-1", &buf)
            })
            .collect();
        let withdrawals: Vec<Hash> = self
            .withdrawals
            .iter()
            .map(|(request, w)| {
                let buf = bincode::serialize(&(request, w)).expect("a pending withdrawal serializes");
                Hash::digest_domain(b"rand-perp-withdrawal-1", &buf)
            })
            .collect();
        let mut buf = Vec::with_capacity(32 + 8 + 5 * 32);
        buf.extend_from_slice(&word8_to_bytes(&self.proved_root));
        buf.extend_from_slice(&self.proved_height.to_be_bytes());
        buf.extend_from_slice(merkle_root(&accounts).as_bytes());
        buf.extend_from_slice(merkle_root(&oracle).as_bytes());
        buf.extend_from_slice(merkle_root(&oracle_nonces).as_bytes());
        buf.extend_from_slice(merkle_root(&digests).as_bytes());
        buf.extend_from_slice(merkle_root(&withdrawals).as_bytes());
        Hash::digest_domain(b"rand-perps-1", &buf)
    }

    pub fn account(&self, id: &AccountId) -> Option<&PerpAccount> {
        self.accounts.get(id)
    }

    /// A page of accounts in id order, starting after `after`.
    pub fn accounts(&self, after: Option<&AccountId>, limit: usize) -> Vec<(AccountId, PerpAccount)> {
        use std::ops::Bound;
        let start = match after {
            Some(id) => Bound::Excluded(*id),
            None => Bound::Unbounded,
        };
        self.accounts.range((start, Bound::Unbounded)).take(limit).map(|(id, a)| (*id, a.clone())).collect()
    }

    /// `D_h`, while block `height` is above the proved height.
    pub fn digest(&self, height: u64) -> Option<Word8> {
        self.digests.get(&height).copied()
    }

    /// The closed heights no state proof has covered yet, ascending.
    pub fn pending_heights(&self) -> Vec<u64> {
        self.digests.keys().copied().collect()
    }

    /// The market's last median; 0 before any block has closed with a fresh price for it.
    pub fn median(&self, market: u32) -> u64 {
        self.oracle.get(&market).map_or(0, |o| o.median)
    }

    pub fn withdrawal(&self, request: &Word8) -> Option<&PendingWithdrawal> {
        self.withdrawals.get(request)
    }

    /// The last closed block's height and input words, once: the node stores them for provers.
    pub fn take_block_words(&mut self) -> Option<(u64, Vec<u32>)> {
        self.last_block_words.take()
    }
}

/// The most trading accounts the ledger opens: the engine has 16 slots and keeps one for the
/// insurance fund ([`INSURANCE_ACCOUNT`]).
pub const MAX_ACCOUNTS: usize = 15;
/// The engine's insurance fund. No trading key owns it, so no deposit may open it.
pub const INSURANCE_ACCOUNT: AccountId = [0; 8];

/// Whether a deposit may open account `id`: not the insurance fund's, and a slot is free.
fn check_new_account(p: &Perps, id: &AccountId) -> Result<(), PerpError> {
    if *id == INSURANCE_ACCOUNT {
        return Err(PerpError::ReservedAccount);
    }
    if p.accounts.len() >= MAX_ACCOUNTS {
        return Err(PerpError::TooManyAccounts);
    }
    Ok(())
}

/// What a `PerpDeposit`'s bundle brings in: the collateral asset's burn — RAND through `burn_r`
/// with nothing through `burn_a` and `burn_asset`, or the collateral token through `burn_a`
/// with nothing through `burn_r` — and nothing else.
fn deposit_amount(p: &Perps, tx: &Transaction) -> Result<u64, TxError> {
    let b = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?;
    let c = p.config.collateral_asset;
    let amount = match c {
        0 if b.burn_a == 0 && b.burn_asset == 0 => b.burn_r,
        _ if c != 0 && b.burn_asset == c && b.burn_r == 0 => b.burn_a,
        _ => return Err(PerpError::CollateralAssetMismatch.into()),
    };
    if amount == 0 {
        return Err(PerpError::ZeroAmount.into());
    }
    Ok(amount)
}

/// The rules of an order's body the chain holds it to: a known market, the side / kind / tif
/// codes, a size in whole lots, a limit price in whole ticks and a market order without one.
/// Whether the order is any good is the engine's business.
fn check_order(p: &Perps, b: &PerpOrderBody) -> Result<(), PerpError> {
    let m = p.config.markets.get(b.market as usize).ok_or(PerpError::UnknownMarket(b.market))?;
    if b.side > 1 {
        return Err(PerpError::BadOrder("side is 0 (buy) or 1 (sell)"));
    }
    if b.kind > 1 {
        return Err(PerpError::BadOrder("kind is 0 (limit) or 1 (market)"));
    }
    if b.tif > 2 {
        return Err(PerpError::BadOrder("tif is 0, 1 or 2"));
    }
    if b.size == 0 || !b.size.is_multiple_of(m.lot) {
        return Err(PerpError::BadOrder("size is a positive multiple of the market's lot"));
    }
    if b.kind == 0 && (b.price == 0 || !b.price.is_multiple_of(m.tick)) {
        return Err(PerpError::BadOrder("a limit price is a positive multiple of the market's tick"));
    }
    if b.kind == 1 && b.price != 0 {
        return Err(PerpError::BadOrder("a market order carries no price"));
    }
    Ok(())
}

/// The account a signed action names, and that `nonce` is still free in its window (tried on
/// a copy: nothing is written).
fn check_account_nonce<'a>(p: &'a Perps, account: &AccountId, nonce: u64) -> Result<&'a PerpAccount, PerpError> {
    let a = p.accounts.get(account).ok_or(PerpError::UnknownAccount)?;
    a.clone().accept_nonce(nonce)?;
    Ok(a)
}

/// Whether another withdrawal may wait: fewer than [`MAX_PERP_PAYOUTS`] are pending.
fn check_withdrawal_room(p: &Perps) -> Result<(), PerpError> {
    if p.withdrawals.len() >= MAX_PERP_PAYOUTS {
        return Err(PerpError::TooManyWithdrawals);
    }
    Ok(())
}

/// The request id a `PerpWithdraw` is held and paid under: its transaction's hash as words.
fn request_id(tx: &Transaction) -> Word8 {
    word8_from_bytes(tx.hash().as_bytes()).expect("a hash is 32 bytes")
}

/// One of the five perp actions this module's rules cover (34–38), its fields borrowed. The
/// one place an [`Action`] is classified here: every variant is spelled out in [`PerpAction::of`],
/// so a new variant does not compile until it is placed.
enum PerpAction<'a> {
    Deposit {
        trading_key: &'a PublicKey,
    },
    Order {
        account: &'a AccountId,
        body: &'a PerpOrderBody,
        signature: &'a Signature,
    },
    Cancel {
        account: &'a AccountId,
        nonce: u64,
        target: u64,
        signature: &'a Signature,
    },
    Withdraw {
        account: &'a AccountId,
        nonce: u64,
        amount: u64,
        recipient: &'a ShieldedAddress,
        r: &'a Word8,
        time: u32,
        envelope: &'a Envelope,
        signature: &'a Signature,
    },
    Oracle {
        validator: &'a PublicKey,
        prices: &'a [PerpPrice],
        nonce: u64,
        signature: &'a Signature,
    },
}

impl<'a> PerpAction<'a> {
    fn of(action: &'a Action) -> Option<PerpAction<'a>> {
        match action {
            Action::PerpDeposit { trading_key } => Some(PerpAction::Deposit { trading_key }),
            Action::PerpOrder { account, body, signature } => Some(PerpAction::Order { account, body, signature }),
            Action::PerpCancel { account, nonce, target, signature } => {
                Some(PerpAction::Cancel { account, nonce: *nonce, target: *target, signature })
            }
            Action::PerpWithdraw { account, nonce, amount, recipient, r, time, envelope, signature } => {
                Some(PerpAction::Withdraw {
                    account,
                    nonce: *nonce,
                    amount: *amount,
                    recipient,
                    r,
                    time: *time,
                    envelope,
                    signature,
                })
            }
            Action::PerpOracle { validator, prices, nonce, signature } => {
                Some(PerpAction::Oracle { validator, prices, nonce: *nonce, signature })
            }
            Action::None
            | Action::Mint { .. }
            | Action::Deploy { .. }
            | Action::Call { .. }
            | Action::Bond { .. }
            | Action::Unbond { .. }
            | Action::Withdraw { .. }
            | Action::BridgeAttest { .. }
            | Action::BridgeBurn { .. }
            | Action::RegisterAggregator { .. }
            | Action::UnbondAggregator { .. }
            | Action::WithdrawAggregator { .. }
            | Action::SlashAggregator { .. }
            | Action::Aggregate { .. }
            | Action::RegisterToken { .. }
            | Action::TokenMint { .. }
            | Action::SetAuthority { .. }
            | Action::TokenBurn { .. }
            | Action::PauseMints { .. }
            | Action::UnpauseMints { .. }
            | Action::RegisterBridgedToken { .. }
            | Action::ListBacking { .. }
            | Action::RotatePqGuardians { .. }
            | Action::RotatePauseKey { .. }
            | Action::ClaimVested { .. }
            | Action::RevokeVesting { .. }
            | Action::BondVested { .. }
            | Action::UnbondVested { .. }
            | Action::AdmitValidator { .. }
            | Action::SlashEquivocation { .. }
            | Action::RotatePqGuardiansV2 { .. }
            | Action::RotatePauseKeyV2 { .. }
            | Action::CancelRotation { .. }
            | Action::Invoke { .. }
            // Task 4's: its admission is not this module's yet.
            | Action::PerpStateProof { .. } => None,
        }
    }

    /// The signature over [`Transaction::perp_sign_message`]; `None` for a deposit.
    fn signature(&self) -> Option<&'a Signature> {
        match self {
            PerpAction::Deposit { .. } => None,
            PerpAction::Order { signature, .. }
            | PerpAction::Cancel { signature, .. }
            | PerpAction::Withdraw { signature, .. }
            | PerpAction::Oracle { signature, .. } => Some(signature),
        }
    }
}

/// The refusal for an action this module's rules do not cover — unreachable through
/// `validate_inner` and `apply_tx_with`, which route only the five here.
const NOT_PERP: TxError = TxError::UnsupportedAction("not a perp action");

/// Every rule of a perp action but its signature, in `validate`'s order, against this ledger's
/// state: map lookups and compares, no hash but a withdrawal's transaction id. Returns the key
/// the signature must verify under (`None` for a deposit, which the bundle authorises).
fn check<'a>(ledger: &'a Ledger, tx: &Transaction, action: &PerpAction<'a>) -> Result<Option<&'a PublicKey>, TxError> {
    // The gate is absolute: on a chain without the section nothing about a perp action is read.
    let p = ledger.perps().ok_or(PerpError::Disabled)?;
    match *action {
        PerpAction::Deposit { trading_key } => {
            deposit_amount(p, tx)?;
            let id = account_id(trading_key);
            match p.accounts.get(&id) {
                Some(a) if a.trading_key != *trading_key => return Err(PerpError::KeyMismatch.into()),
                Some(_) => {}
                None => check_new_account(p, &id)?,
            }
            Ok(None)
        }
        PerpAction::Order { account, body, .. } => {
            let a = p.accounts.get(account).ok_or(PerpError::UnknownAccount)?;
            check_order(p, body)?;
            a.clone().accept_nonce(body.nonce)?;
            Ok(Some(&a.trading_key))
        }
        PerpAction::Cancel { account, nonce, .. } => Ok(Some(&check_account_nonce(p, account, nonce)?.trading_key)),
        PerpAction::Withdraw { account, nonce, amount, recipient, time, envelope, .. } => {
            let a = p.accounts.get(account).ok_or(PerpError::UnknownAccount)?;
            if amount == 0 {
                return Err(PerpError::ZeroAmount.into());
            }
            // A note at or above 2^63 is unspendable (the bundle guest range-checks every amount),
            // so a request for one could only fail at payout, holding a slot: refused now, as an
            // RPL-2 payout is.
            if amount >= MAX_NOTE_VALUE {
                return Err(PerpError::AmountTooLarge(amount).into());
            }
            // A state proof pays at most `MAX_PERP_PAYOUTS` withdrawals, so no more may wait:
            // past that, one holder could queue requests no proof can ever pay.
            check_withdrawal_room(p)?;
            // The RPL-2 payout checks (the note this becomes is the chain's to append), and the
            // time window a bundle's `time` is held to, by the same function.
            ledger.check_note_envelope(envelope)?;
            super::tokens::check_recipient(recipient)?;
            ledger.check_time(time)?;
            a.clone().accept_nonce(nonce)?;
            if p.withdrawals.contains_key(&request_id(tx)) {
                return Err(PerpError::NonceUsed.into());
            }
            Ok(Some(&a.trading_key))
        }
        PerpAction::Oracle { validator, prices, nonce, .. } => {
            let address = validator.address();
            // In the register and not jailed (STAKE-1): a jailed key's price would not count
            // towards a median, so it is not taken either.
            if !ledger.validators().contains_key(&address) || ledger.jailed_until(&address).is_some() {
                return Err(PerpError::NotValidator.into());
            }
            // At least one price; strictly ascending and known markets, so at most 16; every
            // price positive (the engine reads a median of 0 as "no price").
            if prices.is_empty() {
                return Err(PerpError::BadPrice.into());
            }
            let mut last: Option<u32> = None;
            for price in prices {
                if price.market as usize >= p.config.markets.len() {
                    return Err(PerpError::UnknownMarket(price.market).into());
                }
                if last.is_some_and(|l| price.market <= l) {
                    return Err(PerpError::UnorderedPrices.into());
                }
                if price.price == 0 {
                    return Err(PerpError::BadPrice.into());
                }
                last = Some(price.market);
            }
            if nonce <= p.oracle_nonces.get(&address).copied().unwrap_or(0) {
                return Err(PerpError::OracleNonce.into());
            }
            Ok(Some(validator))
        }
    }
}

/// Whether `tx`, a perp action [`validate`] accepted on an earlier state, can still apply on
/// `ledger`: [`validate`] without the signature, with the verdict [`validate`] would give — the
/// account still exists, the nonce is still free, the request is not already pending, the
/// oracle nonce is still above the validator's last and the validator still in the set, the
/// withdrawal's time still in the window. For a node's pool, which asks after every block.
/// `Ok` for every other action (and, until Task 4, for a state proof).
pub fn still_applies(ledger: &Ledger, tx: &Transaction) -> Result<(), TxError> {
    match PerpAction::of(&tx.action) {
        Some(a) => check(ledger, tx, &a).map(|_| ()),
        None => Ok(()),
    }
}

/// The action step of admission for a perp action (34–38): the section's gate, the action's
/// own rules against the ledger, then — last, the one expensive check — the signature over
/// [`Transaction::perp_sign_message`]. A deposit has no signature: its bundle, whose proof the
/// common path verifies after this, authorises it.
///
/// Nothing is written: every refusal [`apply`] could make is made here.
pub(super) fn validate(ledger: &Ledger, tx: &Transaction, action: &Action) -> Result<(), TxError> {
    let a = PerpAction::of(action).ok_or(NOT_PERP)?;
    let key = check(ledger, tx, &a)?;
    let (Some(key), Some(signature)) = (key, a.signature()) else {
        return Ok(()); // a deposit: the bundle authorises it
    };
    let msg = Transaction::perp_sign_message(tx.chain_id, action).ok_or(PerpError::BadSignature)?;
    if !key.verify(msg.as_bytes(), signature) {
        return Err(PerpError::BadSignature.into());
    }
    Ok(())
}

/// The apply step, in lockstep with [`validate`]: everything fallible is decided before the
/// first write, so a refusal here leaves the ledger as it was. A deposit opens or tops up the
/// account, an order, a cancel and a withdrawal take their nonce, a withdrawal is held under its
/// request id, and each of those four is recorded as the block's next input; an oracle records
/// its prices at this height and its nonce, and is no input of its own — its prices reach the
/// engine through the block's `Close`.
pub(super) fn apply(ledger: &mut Ledger, tx: &Transaction, action: &Action) -> Result<(), TxError> {
    let a = PerpAction::of(action).ok_or(NOT_PERP)?;
    let height = ledger.height();
    let p = ledger.perps().ok_or(PerpError::Disabled)?;
    match a {
        PerpAction::Deposit { trading_key } => {
            let amount = deposit_amount(p, tx)?;
            let id = account_id(trading_key);
            if !p.accounts.contains_key(&id) {
                check_new_account(p, &id)?;
            }
            let p = ledger.perps_mut().ok_or(PerpError::Disabled)?;
            p.accounts.entry(id).or_insert_with(|| PerpAccount {
                trading_key: trading_key.clone(),
                nonce_high: 0,
                used: 0,
            });
            p.block_inputs.push(PerpInput::Deposit { account: id, amount });
        }
        PerpAction::Order { account, body, .. } => {
            let mut a = p.accounts.get(account).ok_or(PerpError::UnknownAccount)?.clone();
            a.accept_nonce(body.nonce)?;
            let p = ledger.perps_mut().ok_or(PerpError::Disabled)?;
            p.accounts.insert(*account, a);
            p.block_inputs.push(PerpInput::Order { account: *account, body: body.clone() });
        }
        PerpAction::Cancel { account, nonce, target, .. } => {
            let mut a = p.accounts.get(account).ok_or(PerpError::UnknownAccount)?.clone();
            a.accept_nonce(nonce)?;
            let p = ledger.perps_mut().ok_or(PerpError::Disabled)?;
            p.accounts.insert(*account, a);
            p.block_inputs.push(PerpInput::Cancel { account: *account, nonce, target });
        }
        PerpAction::Withdraw { account, nonce, amount, recipient, r, time, envelope, .. } => {
            let mut a = p.accounts.get(account).ok_or(PerpError::UnknownAccount)?.clone();
            a.accept_nonce(nonce)?;
            let request = request_id(tx);
            if p.withdrawals.contains_key(&request) {
                return Err(PerpError::NonceUsed.into());
            }
            check_withdrawal_room(p)?;
            let pending = PendingWithdrawal {
                account: *account,
                amount,
                recipient: recipient.clone(),
                r: *r,
                envelope: envelope.clone(),
                time,
                height,
            };
            let p = ledger.perps_mut().ok_or(PerpError::Disabled)?;
            p.accounts.insert(*account, a);
            p.withdrawals.insert(request, pending);
            p.block_inputs.push(PerpInput::Withdraw { account: *account, nonce, amount, request });
        }
        PerpAction::Oracle { validator, prices, nonce, .. } => {
            let address = validator.address();
            let p = ledger.perps_mut().ok_or(PerpError::Disabled)?;
            for price in prices {
                p.oracle.entry(price.market).or_default().submissions.insert(address, (price.price, height));
            }
            p.oracle_nonces.insert(address, nonce);
        }
    }
    Ok(())
}

/// The stake-weighted median of one market's fresh submissions at `height`: the submissions
/// given at `height - ORACLE_STALE_BLOCKS` or later, each weighted by `stake` of its validator
/// now (one that has left the set or is jailed weighs 0 and is dropped), sorted by price; the median is
/// the first price at which the running stake reaches ⌈total / 2⌉. `None` when nothing fresh
/// and staked remains, and the caller keeps the last median.
fn stake_median(o: &OracleState, stake: &dyn Fn(&Address) -> u64, height: u64) -> Option<u64> {
    let mut fresh: Vec<(u64, u128)> = o
        .submissions
        .iter()
        .filter(|(_, (_, at))| at.saturating_add(ORACLE_STALE_BLOCKS) >= height)
        .map(|(address, (price, _))| (*price, stake(address) as u128))
        .filter(|(_, stake)| *stake > 0)
        .collect();
    // Ties in price are interchangeable, so an unstable sort on the price alone is deterministic.
    fresh.sort_unstable_by_key(|(price, _)| *price);
    let total: u128 = fresh.iter().map(|(_, s)| s).sum();
    let half = total.div_ceil(2);
    let mut running = 0u128;
    for (price, stake) in fresh {
        running += stake;
        if running >= half {
            return Some(price);
        }
    }
    None
}

/// The block-end step under the section (`Ledger::close_block`, before the anchor): each
/// market's median is recomputed from the fresh submissions (kept when none is fresh), the
/// block's `Close` input is appended to its inputs, and the digest `D_height` of the whole word
/// string is recorded for the next state proof to cover. The words themselves are left for the
/// node to take ([`Perps::take_block_words`]); the inputs are emptied for the next block. Every
/// step reads only consensus state, the block's height and its timestamp.
pub(super) fn close_block(ledger: &mut Ledger, height: u64, executor: &dyn ConfidentialExecutor) {
    let time_ms = ledger.timestamp_ms();
    // A submission whose validator has left the register is dropped here, so a departed key
    // does not sit in the root for good; a jailed one stays (it may serve again) and weighs 0.
    let departed: Vec<Address> = match ledger.perps() {
        Some(p) => {
            let mut v: Vec<Address> = p
                .oracle
                .values()
                .flat_map(|o| o.submissions.keys())
                .filter(|a| !ledger.validators().contains_key(a))
                .copied()
                .collect();
            v.sort();
            v.dedup();
            v
        }
        None => return,
    };
    if !departed.is_empty() {
        let Some(p) = ledger.perps_mut() else { return };
        for o in p.oracle.values_mut() {
            o.submissions.retain(|a, _| departed.binary_search(a).is_err());
        }
    }
    let stake = |a: &Address| -> u64 {
        if ledger.jailed_until(a).is_some() {
            return 0;
        }
        ledger.validators().get(a).map_or(0, |v| v.stake)
    };
    let Some(p) = ledger.perps() else { return };
    let medians: Vec<PerpPrice> = p
        .config
        .markets
        .iter()
        .map(|m| {
            let fresh = p.oracle.get(&m.id).and_then(|o| stake_median(o, &stake, height));
            PerpPrice { market: m.id, price: fresh.unwrap_or_else(|| p.median(m.id)) }
        })
        .collect();
    let Some(p) = ledger.perps_mut() else { return };
    for m in &medians {
        if let Some(o) = p.oracle.get_mut(&m.market) {
            o.median = m.price;
        }
    }
    let mut words = Vec::new();
    for input in p.block_inputs.drain(..) {
        input.words(&mut words);
    }
    PerpInput::Close { height, time_ms, medians }.words(&mut words);
    p.digests.insert(height, perp_digest(executor, domain::BLOCK, &words));
    p.last_block_words = Some((height, words));
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum PerpError {
    #[error("perps are disabled on this chain")]
    Disabled,
    #[error("no perps account has this id; deposit first")]
    UnknownAccount,
    #[error("the trading key does not own this account")]
    KeyMismatch,
    #[error("the nonce has been used or is below the account's window")]
    NonceUsed,
    #[error("the signature does not verify")]
    BadSignature,
    #[error("market {0} does not exist")]
    UnknownMarket(u32),
    #[error("bad order: {0}")]
    BadOrder(&'static str),
    #[error("the amount is zero")]
    ZeroAmount,
    #[error("the oracle key is not in the validator set")]
    NotValidator,
    #[error("the oracle nonce is not above the validator's last")]
    OracleNonce,
    #[error("a state proof pays at most {MAX_PERP_PAYOUTS} withdrawals, this one pays {0}")]
    TooManyPayouts(usize),
    #[error(
        "the proof covers {from}..={to}; it must start at the proved height {proved} and cover at most {max} blocks"
    )]
    WindowMismatch { from: u64, to: u64, proved: u64, max: u64 },
    #[error("no input digest is recorded for height {0}")]
    MissingDigest(u64),
    #[error("no pending withdrawal has this request id")]
    UnknownRequest,
    #[error("withdrawal {request} asked for {have}; the payout is {want}")]
    PayoutTooLarge { request: String, want: u64, have: u64 },
    #[error("the proof is at tier {tier}; this chain allows at most {max}")]
    TierTooHigh { tier: u8, max: u8 },
    #[error("the state proof is refused: {0}")]
    ProofRefused(String),
    #[error("the bundle burns a different asset from the perps collateral")]
    CollateralAssetMismatch,
    #[error("an amount overflows")]
    Overflow,
    #[error("an oracle's prices must name each market once, in ascending order")]
    UnorderedPrices,
    #[error("the exchange holds at most 15 trading accounts; this deposit would open a 16th")]
    TooManyAccounts,
    #[error("account id 0 is the engine's insurance fund and no key may own it")]
    ReservedAccount,
    #[error("{MAX_PERP_PAYOUTS} withdrawals are already waiting on a proof; a state proof pays at most that many")]
    TooManyWithdrawals,
    #[error("an oracle submission carries at least one price, and every price is positive")]
    BadPrice,
    #[error("a withdrawal of {0} is at or above the note bound 2^63")]
    AmountTooLarge(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;

    fn acct(n: u8) -> AccountId {
        [n as u32; 8]
    }

    #[test]
    fn input_words_follow_the_layout() {
        let mut w = Vec::new();
        PerpInput::Deposit { account: acct(1), amount: (7u64 << 32) | 5 }.words(&mut w);
        assert_eq!(w, [vec![1], vec![1; 8], vec![5, 7]].concat());
        w.clear();
        PerpInput::Order {
            account: acct(2),
            body: PerpOrderBody {
                nonce: 9,
                market: 1,
                side: 1,
                kind: 0,
                tif: 2,
                reduce_only: true,
                price: 10,
                size: 20,
            },
        }
        .words(&mut w);
        assert_eq!(w.len(), 20);
        assert_eq!(&w[..], &[vec![2], vec![2; 8], vec![9, 0, 1, 1, 0, 2, 1, 10, 0, 20, 0]].concat()[..]);
        w.clear();
        PerpInput::Close { height: 3, time_ms: 4, medians: vec![PerpPrice { market: 0, price: 11 }] }.words(&mut w);
        assert_eq!(w, vec![5, 3, 0, 4, 0, 1, 0, 11, 0]);
        w.clear();
        PerpInput::Cancel { account: acct(3), nonce: 9, target: 4 }.words(&mut w);
        assert_eq!(w.len(), 13);
        assert_eq!(w, [vec![3], vec![3; 8], vec![9, 0, 4, 0]].concat());
        w.clear();
        PerpInput::Withdraw { account: acct(4), nonce: 5, amount: (1u64 << 32) | 6, request: [7; 8] }.words(&mut w);
        assert_eq!(w.len(), 21);
        assert_eq!(w, [vec![4], vec![4; 8], vec![5, 0, 6, 1], vec![7; 8]].concat());
    }

    #[test]
    fn digest_chunks_at_4000_words_and_binds_the_length() {
        let h = StubExecutor;
        let a = perp_digest(&h, domain::BLOCK, &[1, 2, 3]);
        let b = perp_digest(&h, domain::BLOCK, &[1, 2, 3, 0]);
        assert_ne!(a, b, "a trailing zero changes the digest");
        let long: Vec<u32> = (0..9000).collect();
        let _ = perp_digest(&h, domain::BLOCK, &long); // three chunks, no panic
    }

    #[test]
    fn nonce_window_accepts_out_of_order_and_refuses_reuse() {
        let mut a =
            PerpAccount { trading_key: crate::Keypair::generate().public_key().clone(), nonce_high: 0, used: 0 };
        a.accept_nonce(10).unwrap();
        a.accept_nonce(8).unwrap();
        assert_eq!(a.accept_nonce(8), Err(PerpError::NonceUsed));
        assert_eq!(a.accept_nonce(10), Err(PerpError::NonceUsed));
        a.accept_nonce(100).unwrap();
        assert_eq!(a.accept_nonce(36), Err(PerpError::NonceUsed), "below the 64-wide window");
        a.accept_nonce(37).unwrap();
    }

    #[test]
    fn segment_layout_is_pinned() {
        let seg = state_proof_segment(5, 7, &[1; 8], &[2; 8], &[3; 8], 99, &[[4; 8], [5; 8]]);
        assert_eq!(seg[0], PERP_VERSION);
        assert_eq!(&seg[1..5], &[5, 0, 7, 0]);
        assert_eq!(&seg[5..13], &[1; 8]);
        assert_eq!(&seg[13..21], &[2; 8]);
        assert_eq!(&seg[21..29], &[3; 8]);
        assert_eq!(&seg[29..32], &[99, 0, 2]);
        assert_eq!(seg.len(), 32 + 16);
    }

    #[test]
    fn root_changes_with_every_component_and_config_check_bounds() {
        let c = sample_config();
        assert!(c.check().is_ok());
        let refused = |f: &dyn Fn(&mut PerpsConfig)| {
            let mut bad = c.clone();
            f(&mut bad);
            bad.check().is_err()
        };
        assert!(refused(&|b| b.max_tier = 11), "not a tier");
        assert!(refused(&|b| b.max_tier = 22), "above the highest tier");
        assert!(refused(&|b| b.max_window_blocks = 0), "an empty window");
        assert!(refused(&|b| b.max_window_blocks = MAX_WINDOW_BLOCKS + 1), "a 65-block window");
        assert!(refused(&|b| b.markets[0].id = 1), "a market id out of order");
        assert!(refused(&|b| b.markets[0].maintenance_bps = 10_001), "more than 100%");
        assert!(refused(&|b| b.markets.clear()), "no market");
        let mut ok = c.clone();
        ok.max_window_blocks = MAX_WINDOW_BLOCKS;
        assert!(ok.check().is_ok(), "the bound itself is allowed");

        // Each consensus field moves the root; each step keeps the earlier ones' changes.
        let mut p = Perps::from_config(&c);
        let mut seen = vec![p.root()];
        let mut moved = |p: &Perps, what: &str| {
            let r = p.root();
            assert!(!seen.contains(&r), "{what} does not change the root");
            seen.push(r);
        };
        p.proved_root = [1; 8];
        moved(&p, "proved_root");
        p.proved_height = 1;
        moved(&p, "proved_height");
        let key = crate::Keypair::from_seed([3; 32]).unwrap().public_key().clone();
        p.accounts.insert(account_id(&key), PerpAccount { trading_key: key.clone(), nonce_high: 0, used: 0 });
        moved(&p, "a new account");
        p.accounts.get_mut(&account_id(&key)).unwrap().accept_nonce(4).unwrap();
        moved(&p, "an account's nonce window");
        let validator = Address([5; 32]);
        p.oracle.entry(0).or_default().submissions.insert(validator, (100, 1));
        moved(&p, "an oracle submission");
        p.oracle.get_mut(&0).unwrap().submissions.insert(validator, (101, 1));
        moved(&p, "an oracle submission's price");
        p.oracle.get_mut(&0).unwrap().median = 100;
        moved(&p, "a median");
        p.oracle_nonces.insert(validator, 1);
        moved(&p, "an oracle nonce");
        p.oracle_nonces.insert(validator, 2);
        moved(&p, "an oracle nonce's value");
        p.digests.insert(2, [6; 8]);
        moved(&p, "a digest");
        let pending = PendingWithdrawal {
            account: account_id(&key),
            amount: 5,
            recipient: ShieldedAddress { pk: [8; 8], kem_ek: vec![1; 4] },
            r: [9; 8],
            envelope: Envelope { kem_ct: vec![1], to_receiver: vec![], to_sender: vec![], body: vec![2] },
            time: 7,
            height: 2,
        };
        p.withdrawals.insert([7; 8], pending);
        moved(&p, "a withdrawal");
        p.withdrawals.get_mut(&[7; 8]).unwrap().amount = 6;
        moved(&p, "a withdrawal's amount");

        // The transient fields are outside both the root and equality.
        let before = (p.root(), p.clone());
        p.block_inputs.push(PerpInput::Deposit { account: acct(1), amount: 1 });
        p.last_block_words = Some((3, vec![1]));
        assert_eq!(p.root(), before.0);
        assert_eq!(p, before.1);
    }

    fn sample_config() -> PerpsConfig {
        PerpsConfig {
            collateral_asset: 0,
            max_tier: 16,
            max_window_blocks: 8,
            engine_hc: [9; 8],
            genesis_root: [8; 8],
            markets: vec![MarketSpec {
                id: 0,
                symbol: "X-PERP".into(),
                lot: 1_000_000,
                tick: 1_000,
                max_leverage: 10,
                maintenance_bps: 500,
                taker_fee_bps: 5,
                maker_fee_bps: 2,
            }],
        }
    }

    /// Writes the golden vectors perp-core's `tests/vectors.rs` reads; run with
    /// `PERPS_WRITE_VECTORS=1 cargo test -p randprotocol-core perps::tests::golden_vectors`.
    #[test]
    fn golden_vectors() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/perps-v1.json");
        let mut cases = serde_json::Map::new();
        let mut w = Vec::new();
        let inputs = vec![
            PerpInput::Deposit { account: acct(1), amount: 1_000_000_000 },
            PerpInput::Order {
                account: acct(1),
                body: PerpOrderBody {
                    nonce: 1,
                    market: 0,
                    side: 0,
                    kind: 0,
                    tif: 0,
                    reduce_only: false,
                    price: 2_000_000_000,
                    size: 500_000_000,
                },
            },
            PerpInput::Cancel { account: acct(1), nonce: 2, target: 1 },
            PerpInput::Withdraw { account: acct(1), nonce: 3, amount: 5, request: acct(7) },
            PerpInput::Close {
                height: 1,
                time_ms: 1_700_000_000_000,
                medians: vec![PerpPrice { market: 0, price: 2_000_000_000 }],
            },
        ];
        for i in &inputs {
            i.words(&mut w);
        }
        cases.insert("block_words".into(), serde_json::json!(w));
        cases.insert(
            "segment".into(),
            serde_json::json!(state_proof_segment(0, 1, &[1; 8], &[2; 8], &[3; 8], 0, &[[4; 8]])),
        );
        let json = serde_json::to_string_pretty(&serde_json::Value::Object(cases)).unwrap();
        if std::env::var("PERPS_WRITE_VECTORS").is_ok() {
            std::fs::write(path, &json).unwrap();
        }
        let on_disk =
            std::fs::read_to_string(path).expect("vectors file exists; regenerate with PERPS_WRITE_VECTORS=1");
        assert_eq!(on_disk.trim(), json.trim(), "perps-v1.json is stale");
    }

    // ---- Task 3: the ledger rules, the block close and the root ----

    use crate::crypto::{Keypair, Signature};
    use crate::gas;
    use crate::ledger::tokens::{TokenError, TokenRegistry};
    use crate::ledger::{Ledger, TxError, ValidatorEntry};
    use crate::notes::{Bundle, KEM_EK_BYTES};
    use crate::types::transaction::{Action, Transaction};

    const HC: Word8 = [11; 8];
    const CHAIN: u64 = 7;
    const RAND: u64 = 1_000_000_000;
    /// `state_root()` of `ledger_with(false)`, and of it with an RPL-2 `program_state` section,
    /// computed on the parent commit (f942259c) before this task touched the root: a chain
    /// without the `perps` section keeps its root byte for byte.
    const ROOT_BEFORE: &str = "167a98459b148598751726f1a50bb0d096dcbedf879cd8dac71f7422f52c251a";
    const ROOT_BEFORE_PSTATE: &str = "ebe3c658a3678fb43943b5577932ace50f53af66980d1988b3503a88a5060050";

    fn kp(n: u8) -> Keypair {
        Keypair::from_seed([n; 32]).unwrap()
    }

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
    }

    fn recipient() -> ShieldedAddress {
        ShieldedAddress { pk: [4; 8], kem_ek: vec![6; KEM_EK_BYTES] }
    }

    /// Three validators — keys 1, 2 and 3 at stakes 1, 1 and 10 — the token registry, and the
    /// `perps` section (one market, lot 1 000 000, tick 1 000) when `section`.
    fn ledger_with(section: bool) -> Ledger {
        let entry = |n: u8, stake: u64| {
            let k = kp(n);
            let e = ValidatorEntry {
                public_key: k.public_key().clone(),
                stake,
                pending: Vec::new(),
                rewards: 0,
                payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
                nonce: 0,
                activation_epoch: 0,
            };
            (k.address(), e)
        };
        let validators = [entry(1, 1), entry(2, 1), entry(3, 10)].into_iter().collect();
        let mut l = Ledger::new(CHAIN, HC, validators, &StubExecutor);
        l.set_tokens(Some(TokenRegistry::new(1_000_000_000)));
        if section {
            l.set_perps(Some(Perps::from_config(&sample_config())));
        }
        l.set_genesis_supply(1_000_000_000_000, 12);
        l.set_height(1);
        l.set_timestamp_ms(1_700_000_000_000);
        l
    }

    fn bundle(l: &Ledger, seed: u32, fee: u64, burns: (u64, u32, u64)) -> Bundle {
        let mut b = Bundle {
            anchor: l.anchors().back().expect("the genesis anchor").1,
            nullifiers: crate::notes::pad4([[seed; 8], [seed + 1; 8]]),
            commitments: crate::notes::pad4([[seed + 2; 8], [seed + 3; 8]]),
            fee,
            burn_r: burns.0,
            burn_asset: burns.1,
            burn_a: burns.2,
            time: l.height() as u32,
            envelopes: [env(), env(), env(), env()],
            proof: vec![],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
        b
    }

    fn apply(l: &mut Ledger, tx: &Transaction) -> Result<(), TxError> {
        l.apply_tx(tx, &kp(1).address(), &StubExecutor).map(|_| ())
    }

    fn refusal(l: &Ledger, tx: &Transaction) -> TxError {
        l.validate(tx, &StubExecutor).expect_err("refused")
    }

    fn pe(e: PerpError) -> TxError {
        TxError::Perps(e)
    }

    fn close(l: &mut Ledger, height: u64) {
        l.set_height(height);
        l.close_block(height, &kp(1).address(), 0, 0, &StubExecutor);
    }

    /// `a` with its signature made by `k` over `perp_sign_message(chain, a)`.
    fn signed(chain: u64, k: &Keypair, a: Action) -> Action {
        let msg = Transaction::perp_sign_message(chain, &a).expect("a signed perp action");
        let sig = k.sign(msg.as_bytes());
        let mut a = a;
        match &mut a {
            Action::PerpOrder { signature, .. }
            | Action::PerpCancel { signature, .. }
            | Action::PerpWithdraw { signature, .. }
            | Action::PerpOracle { signature, .. } => *signature = sig,
            _ => panic!("not a signed perp action"),
        }
        a
    }

    fn bare(a: Action) -> Transaction {
        Transaction { chain_id: CHAIN, bundle: None, action: a }
    }

    fn deposit_with(l: &Ledger, k: &Keypair, seed: u32, burns: (u64, u32, u64)) -> Transaction {
        let a = Action::PerpDeposit { trading_key: k.public_key().clone() };
        let fee = gas::fee_floor(&a);
        StubExecutor::bound(Transaction::shielded(CHAIN, bundle(l, seed, fee, burns), a))
    }

    fn deposit(l: &Ledger, k: &Keypair, seed: u32, amount: u64) -> Transaction {
        deposit_with(l, k, seed, (amount, 0, 0))
    }

    fn dep_with(l: &mut Ledger, k: &Keypair, seed: u32, burns: (u64, u32, u64)) -> Result<(), TxError> {
        let tx = deposit_with(l, k, seed, burns);
        apply(l, &tx)
    }

    fn dep(l: &mut Ledger, k: &Keypair, seed: u32, amount: u64) -> Result<(), TxError> {
        dep_with(l, k, seed, (amount, 0, 0))
    }

    fn id(k: &Keypair) -> AccountId {
        account_id(k.public_key())
    }

    fn body(nonce: u64) -> PerpOrderBody {
        PerpOrderBody {
            nonce,
            market: 0,
            side: 0,
            kind: 0,
            tif: 0,
            reduce_only: false,
            price: 2_000_000,
            size: 1_000_000,
        }
    }

    fn order_by(signer: &Keypair, account: AccountId, b: PerpOrderBody) -> Transaction {
        bare(signed(CHAIN, signer, Action::PerpOrder { account, body: b, signature: Signature::empty() }))
    }

    fn order(k: &Keypair, b: PerpOrderBody) -> Transaction {
        order_by(k, id(k), b)
    }

    fn withdraw(k: &Keypair, nonce: u64, amount: u64, time: u32) -> Action {
        Action::PerpWithdraw {
            account: id(k),
            nonce,
            amount,
            recipient: recipient(),
            r: [5; 8],
            time,
            envelope: env(),
            signature: Signature::empty(),
        }
    }

    fn oracle(k: &Keypair, prices: &[(u32, u64)], nonce: u64) -> Transaction {
        let prices = prices.iter().map(|&(market, price)| PerpPrice { market, price }).collect();
        bare(signed(
            CHAIN,
            k,
            Action::PerpOracle { validator: k.public_key().clone(), prices, nonce, signature: Signature::empty() },
        ))
    }

    fn close_words(l: &Ledger, height: u64, median: u64) -> Vec<u32> {
        let mut w = Vec::new();
        PerpInput::Close { height, time_ms: l.timestamp_ms(), medians: vec![PerpPrice { market: 0, price: median }] }
            .words(&mut w);
        w
    }

    #[test]
    fn a_deposit_creates_the_account_and_records_an_input() {
        let mut l = ledger_with(true);
        let k = kp(50);
        dep(&mut l, &k, 10, RAND).unwrap();
        let p = l.perps().unwrap();
        assert_eq!(p.account(&id(&k)).map(|a| (&a.trading_key, a.nonce_high, a.used)), Some((k.public_key(), 0, 0)));
        assert_eq!(p.digest(1), None, "nothing is digested before the block closes");
        close(&mut l, 1);
        let d = l.perps().unwrap().digest(1).expect("the block's digest");
        let (h, words) = l.take_perp_block_words().expect("the block's words");
        assert_eq!(h, 1);
        let mut want = vec![1];
        want.extend_from_slice(&id(&k));
        want.extend([RAND as u32, 0]);
        assert_eq!(&words[..11], &want[..], "the deposit's words first");
        assert_eq!(words, [want, close_words(&l, 1, 0)].concat(), "then the Close record, and nothing else");
        assert_eq!(d, perp_digest(&StubExecutor, domain::BLOCK, &words));
        assert_eq!(l.take_perp_block_words(), None, "taken once");
        assert_eq!(l.perps().unwrap().pending_heights(), vec![1]);
        // An empty block still closes with its Close record, and a top-up keeps the account.
        close(&mut l, 2);
        assert_eq!(l.take_perp_block_words(), Some((2, close_words(&l, 2, 0))));
        dep(&mut l, &k, 20, 5).unwrap();
        assert_eq!(l.perps().unwrap().accounts(None, 10).len(), 1);

        // The collateral rule: RAND through `burn_r` only; a zero burn; a token burn on a RAND chain.
        assert_eq!(refusal(&l, &deposit(&l, &k, 30, 0)), pe(PerpError::ZeroAmount));
        assert_eq!(refusal(&l, &deposit_with(&l, &k, 40, (0, 1, 5))), pe(PerpError::CollateralAssetMismatch));
        assert_eq!(refusal(&l, &deposit_with(&l, &k, 50, (5, 1, 5))), pe(PerpError::CollateralAssetMismatch));
        // A chain whose collateral is token 1: `burn_a` of token 1, nothing through `burn_r`.
        let mut tok = ledger_with(false);
        let mut c = sample_config();
        c.collateral_asset = 1;
        tok.set_perps(Some(Perps::from_config(&c)));
        assert_eq!(refusal(&tok, &deposit(&tok, &k, 60, RAND)), pe(PerpError::CollateralAssetMismatch));
        assert_eq!(refusal(&tok, &deposit_with(&tok, &k, 70, (1, 1, 5))), pe(PerpError::CollateralAssetMismatch));
        assert_eq!(refusal(&tok, &deposit_with(&tok, &k, 80, (0, 2, 5))), pe(PerpError::CollateralAssetMismatch));
        dep_with(&mut tok, &k, 90, (0, 1, 5)).unwrap();
        close(&mut tok, 1);
        let (_, words) = tok.take_perp_block_words().unwrap();
        assert_eq!(&words[9..11], &[5, 0], "the amount is the token burn");
    }

    #[test]
    fn deposits_stop_at_fifteen_accounts_and_the_insurance_id_is_reserved() {
        let mut l = ledger_with(true);
        for n in 0..15u8 {
            dep(&mut l, &kp(100 + n), 1000 + 10 * n as u32, RAND).unwrap();
        }
        assert_eq!(refusal(&l, &deposit(&l, &kp(200), 2000, RAND)), pe(PerpError::TooManyAccounts));
        dep(&mut l, &kp(100), 2010, RAND).expect("an existing account still tops up");
        // `[0; 8]` is the engine's insurance fund: no key may own it, and nothing addresses it.
        assert_eq!(check_new_account(l.perps().unwrap(), &[0; 8]), Err(PerpError::ReservedAccount));
        assert_eq!(check_new_account(l.perps().unwrap(), &id(&kp(200))), Err(PerpError::TooManyAccounts));
        assert_eq!(refusal(&l, &order_by(&kp(100), [0; 8], body(1))), pe(PerpError::UnknownAccount));
    }

    #[test]
    fn an_order_from_an_unknown_account_is_refused() {
        let mut l = ledger_with(true);
        let k = kp(50);
        assert_eq!(refusal(&l, &order(&k, body(1))), pe(PerpError::UnknownAccount));
        let cancel = bare(signed(
            CHAIN,
            &k,
            Action::PerpCancel { account: id(&k), nonce: 2, target: 1, signature: Signature::empty() },
        ));
        assert_eq!(refusal(&l, &cancel), pe(PerpError::UnknownAccount));
        assert_eq!(refusal(&l, &bare(signed(CHAIN, &k, withdraw(&k, 1, 5, 1)))), pe(PerpError::UnknownAccount));
        assert_eq!(still_applies(&l, &order(&k, body(1))), Err(pe(PerpError::UnknownAccount)));
        dep(&mut l, &k, 10, RAND).unwrap();
        apply(&mut l, &order(&k, body(1))).unwrap();
        apply(&mut l, &cancel).unwrap();
        assert_eq!(refusal(&l, &order(&k, PerpOrderBody { market: 1, ..body(3) })), pe(PerpError::UnknownMarket(1)));
        close(&mut l, 1);
        let (_, words) = l.take_perp_block_words().unwrap();
        let mut want = Vec::new();
        PerpInput::Deposit { account: id(&k), amount: RAND }.words(&mut want);
        PerpInput::Order { account: id(&k), body: body(1) }.words(&mut want);
        PerpInput::Cancel { account: id(&k), nonce: 2, target: 1 }.words(&mut want);
        assert_eq!(words, [want, close_words(&l, 1, 0)].concat(), "every input in block order");
    }

    #[test]
    fn an_order_with_a_bad_signature_or_reused_nonce_is_refused() {
        let mut l = ledger_with(true);
        let k = kp(50);
        dep(&mut l, &k, 10, RAND).unwrap();
        let forged = order_by(&kp(51), id(&k), body(1));
        assert_eq!(refusal(&l, &forged), pe(PerpError::BadSignature));
        let other_chain = bare(signed(
            CHAIN + 1,
            &k,
            Action::PerpOrder { account: id(&k), body: body(1), signature: Signature::empty() },
        ));
        assert_eq!(refusal(&l, &other_chain), pe(PerpError::BadSignature));
        let mut tampered = order(&k, body(1));
        let Action::PerpOrder { body: b, .. } = &mut tampered.action else { unreachable!() };
        b.size = 2_000_000;
        assert_eq!(refusal(&l, &tampered), pe(PerpError::BadSignature), "the signature covers the body");
        // `still_applies` is `validate` without the signature.
        assert_eq!(still_applies(&l, &forged), Ok(()));
        let first = order(&k, body(5));
        apply(&mut l, &first).unwrap();
        assert_eq!(l.perps().unwrap().account(&id(&k)).map(|a| a.nonce_high), Some(5));
        assert_eq!(refusal(&l, &first), pe(PerpError::NonceUsed), "a replay");
        assert_eq!(refusal(&l, &order(&k, PerpOrderBody { side: 1, ..body(5) })), pe(PerpError::NonceUsed));
        assert_eq!(still_applies(&l, &first), Err(pe(PerpError::NonceUsed)));
        assert_eq!(still_applies(&l, &forged), Ok(()), "nonce 1 is still free");
        apply(&mut l, &order(&k, body(3))).expect("out of order, inside the window");
        // A cancel's nonce shares the window.
        let cancel = |n| {
            bare(signed(
                CHAIN,
                &k,
                Action::PerpCancel { account: id(&k), nonce: n, target: 5, signature: Signature::empty() },
            ))
        };
        assert_eq!(refusal(&l, &cancel(3)), pe(PerpError::NonceUsed));
        apply(&mut l, &cancel(4)).unwrap();
        // A refusal leaves the ledger as it was.
        let before = l.clone();
        assert!(l.apply_transactions(&[order(&k, body(6)), first.clone()], &kp(1).address(), &StubExecutor).is_err());
        assert!(l == before && l.state_root() == before.state_root());
        assert_eq!(still_applies(&l, &deposit(&l, &k, 20, 0)), Err(pe(PerpError::ZeroAmount)));
        // Not a perp action: nothing to ask.
        assert_eq!(still_applies(&l, &bare(Action::None)), Ok(()));
    }

    #[test]
    fn an_order_off_tick_or_off_lot_is_refused() {
        let mut l = ledger_with(true);
        let k = kp(50);
        dep(&mut l, &k, 10, RAND).unwrap();
        let bad = |b: PerpOrderBody| matches!(refusal(&l, &order(&k, b)), TxError::Perps(PerpError::BadOrder(_)));
        assert!(bad(PerpOrderBody { price: 2_000_500, ..body(1) }), "off tick");
        assert!(bad(PerpOrderBody { size: 1_500_000, ..body(1) }), "off lot");
        assert!(bad(PerpOrderBody { size: 0, ..body(1) }), "no size");
        assert!(bad(PerpOrderBody { price: 0, ..body(1) }), "a limit order without a price");
        assert!(bad(PerpOrderBody { kind: 1, ..body(1) }), "a market order with a price");
        assert!(bad(PerpOrderBody { side: 2, ..body(1) }));
        assert!(bad(PerpOrderBody { kind: 2, ..body(1) }));
        assert!(bad(PerpOrderBody { tif: 3, ..body(1) }));
        assert_eq!(
            still_applies(&l, &order(&k, PerpOrderBody { tif: 3, ..body(1) })),
            Err(pe(PerpError::BadOrder("tif is 0, 1 or 2")))
        );
        apply(&mut l, &order(&k, PerpOrderBody { kind: 1, price: 0, tif: 1, ..body(1) })).expect("a market order");
        apply(&mut l, &order(&k, PerpOrderBody { side: 1, tif: 2, reduce_only: true, size: 3_000_000, ..body(2) }))
            .unwrap();
    }

    #[test]
    fn an_oracle_from_a_non_validator_or_old_nonce_is_refused_and_the_median_is_stake_weighted() {
        let mut l = ledger_with(true);
        assert_eq!(refusal(&l, &oracle(&kp(9), &[(0, 100)], 1)), pe(PerpError::NotValidator));
        assert_eq!(refusal(&l, &oracle(&kp(1), &[(0, 100)], 0)), pe(PerpError::OracleNonce), "nonces start above 0");
        assert_eq!(refusal(&l, &oracle(&kp(1), &[(1, 100)], 1)), pe(PerpError::UnknownMarket(1)));
        assert_eq!(refusal(&l, &oracle(&kp(1), &[(0, 100), (0, 101)], 1)), pe(PerpError::UnorderedPrices));
        let mut forged = oracle(&kp(2), &[(0, 100)], 1);
        let Action::PerpOracle { validator, .. } = &mut forged.action else { unreachable!() };
        *validator = kp(1).public_key().clone();
        assert_eq!(refusal(&l, &forged), pe(PerpError::BadSignature));
        assert_eq!(still_applies(&l, &forged), Ok(()));

        // Stakes 1, 1, 10 at prices 100, 200, 300: the heavy validator is the median.
        apply(&mut l, &oracle(&kp(1), &[(0, 100)], 7)).unwrap();
        apply(&mut l, &oracle(&kp(2), &[(0, 200)], 1)).unwrap();
        apply(&mut l, &oracle(&kp(3), &[(0, 300)], 1)).unwrap();
        assert_eq!(refusal(&l, &oracle(&kp(1), &[(0, 100)], 7)), pe(PerpError::OracleNonce), "a replay");
        assert_eq!(refusal(&l, &oracle(&kp(1), &[(0, 100)], 6)), pe(PerpError::OracleNonce));
        assert_eq!(still_applies(&l, &oracle(&kp(1), &[(0, 100)], 7)), Err(pe(PerpError::OracleNonce)));
        assert_eq!(l.perps().unwrap().median(0), 0, "the median moves at the close");
        close(&mut l, 1);
        assert_eq!(l.perps().unwrap().median(0), 300);
        let (_, words) = l.take_perp_block_words().unwrap();
        assert_eq!(words, close_words(&l, 1, 300), "an oracle submission is no input; the Close carries the median");

        // Still fresh 30 blocks on; the two light validators resubmit at 32, and at 32 the heavy
        // one's height-1 price is 31 blocks old and drops: stakes 1 and 1 at 100 and 200.
        close(&mut l, 31);
        assert_eq!(l.perps().unwrap().median(0), 300);
        l.set_height(32);
        apply(&mut l, &oracle(&kp(1), &[(0, 100)], 8)).unwrap();
        apply(&mut l, &oracle(&kp(2), &[(0, 200)], 2)).unwrap();
        close(&mut l, 32);
        assert_eq!(l.perps().unwrap().median(0), 100, "the first price reaching half the fresh stake");
        // Every price stale: the median stays.
        close(&mut l, 63);
        assert_eq!(l.perps().unwrap().median(0), 100);
        assert_eq!(l.take_perp_block_words().map(|(_, w)| w), Some(close_words(&l, 63, 100)));
    }

    fn add(
        o: &mut OracleState,
        vals: &mut BTreeMap<Address, ValidatorEntry>,
        n: u8,
        stake: u64,
        price: u64,
        height: u64,
    ) {
        let k = kp(n);
        let e = ValidatorEntry {
            public_key: k.public_key().clone(),
            stake,
            pending: Vec::new(),
            rewards: 0,
            payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
            nonce: 0,
            activation_epoch: 0,
        };
        vals.insert(k.address(), e);
        o.submissions.insert(k.address(), (price, height));
    }

    #[test]
    fn the_median_is_the_first_price_reaching_half_the_stake() {
        let (mut o, mut vals) = (OracleState::default(), BTreeMap::new());
        add(&mut o, &mut vals, 1, 2, 100, 10);
        add(&mut o, &mut vals, 2, 2, 300, 10);
        add(&mut o, &mut vals, 3, 0, 50, 10);
        // Stake 4: half is 2, which 100 already reaches; the stake-0 validator counts for nothing.
        assert_eq!(stake_median(&o, &|a| vals.get(a).map_or(0, |v| v.stake), 10), Some(100));
        add(&mut o, &mut vals, 4, 1, 200, 10);
        // Stake 5: ⌈5/2⌉ = 3, reached at 200.
        assert_eq!(stake_median(&o, &|a| vals.get(a).map_or(0, |v| v.stake), 10), Some(200));
        // A submitter that has left the set is dropped.
        o.submissions.insert(Address([0xee; 32]), (1, 10));
        assert_eq!(stake_median(&o, &|a| vals.get(a).map_or(0, |v| v.stake), 10), Some(200));
        assert_eq!(stake_median(&o, &|a| vals.get(a).map_or(0, |v| v.stake), 40), Some(200), "30 blocks on, still fresh");
        assert_eq!(stake_median(&o, &|a| vals.get(a).map_or(0, |v| v.stake), 41), None, "everything is stale");
        assert_eq!(stake_median(&OracleState::default(), &|a| vals.get(a).map_or(0, |v| v.stake), 10), None);
    }

    #[test]
    fn a_withdraw_request_is_held_until_a_proof() {
        let mut l = ledger_with(true);
        let k = kp(50);
        dep(&mut l, &k, 10, RAND).unwrap();
        l.set_height(5);
        let tx = bare(signed(CHAIN, &k, withdraw(&k, 1, 400, 4)));
        apply(&mut l, &tx).unwrap();
        let request = word8_from_bytes(tx.hash().as_bytes()).unwrap();
        let w = l.perps().unwrap().withdrawal(&request).expect("pending").clone();
        assert_eq!(
            w,
            PendingWithdrawal {
                account: id(&k),
                amount: 400,
                recipient: recipient(),
                r: [5; 8],
                envelope: env(),
                time: 4,
                height: 5
            },
            "the note's opening as the request fixed it, and its own time"
        );
        assert_eq!(refusal(&l, &tx), pe(PerpError::NonceUsed), "a replay");
        close(&mut l, 5);
        let (_, words) = l.take_perp_block_words().unwrap();
        let mut want = Vec::new();
        PerpInput::Deposit { account: id(&k), amount: RAND }.words(&mut want);
        PerpInput::Withdraw { account: id(&k), nonce: 1, amount: 400, request }.words(&mut want);
        assert_eq!(words, [want, close_words(&l, 5, 0)].concat());
        assert!(l.perps().unwrap().withdrawal(&request).is_some(), "a close pays nothing");

        // Its own rules: an amount, a note envelope, a recipient key, a time in the window.
        let w = |a: Action| bare(signed(CHAIN, &k, a));
        assert_eq!(refusal(&l, &w(withdraw(&k, 2, 0, 5))), pe(PerpError::ZeroAmount));
        let mut long = withdraw(&k, 2, 1, 5);
        let Action::PerpWithdraw { envelope, .. } = &mut long else { unreachable!() };
        envelope.body = vec![0; crate::notes::MAX_ENVELOPE_BYTES + 1];
        assert_eq!(refusal(&l, &w(long)), TxError::EnvelopeTooLarge);
        let mut short_key = withdraw(&k, 2, 1, 5);
        let Action::PerpWithdraw { recipient, .. } = &mut short_key else { unreachable!() };
        recipient.kem_ek.pop();
        assert_eq!(
            refusal(&l, &w(short_key)),
            TxError::Token(TokenError::BadRecipientKey { expected: KEM_EK_BYTES, got: KEM_EK_BYTES - 1 })
        );
        // The bundle's window, exactly: `height - window ..= height`.
        let window = l.proof_window();
        assert_eq!(refusal(&l, &w(withdraw(&k, 2, 1, 6))), TxError::TimeOutOfWindow { time: 6, height: 5, window });
        l.set_height(window + 10);
        let oldest = 10u32;
        assert_eq!(
            refusal(&l, &w(withdraw(&k, 2, 1, oldest - 1))),
            TxError::TimeOutOfWindow { time: oldest - 1, height: window + 10, window }
        );
        assert_eq!(
            still_applies(&l, &w(withdraw(&k, 2, 1, oldest - 1))),
            Err(TxError::TimeOutOfWindow { time: oldest - 1, height: window + 10, window })
        );
        apply(&mut l, &w(withdraw(&k, 2, 1, oldest))).expect("the window's oldest time");
    }

    #[test]
    fn without_the_section_every_perp_action_is_unsupported_and_the_root_is_unchanged() {
        let mut l = ledger_with(false);
        let k = kp(1);
        let txs = [
            deposit(&l, &k, 10, RAND),
            order(&k, body(1)),
            bare(signed(
                CHAIN,
                &k,
                Action::PerpCancel { account: id(&k), nonce: 1, target: 0, signature: Signature::empty() },
            )),
            bare(signed(CHAIN, &k, withdraw(&k, 1, 5, 1))),
            oracle(&k, &[(0, 100)], 1),
        ];
        for tx in &txs {
            assert_eq!(refusal(&l, tx), pe(PerpError::Disabled));
            assert_eq!(still_applies(&l, tx), Err(pe(PerpError::Disabled)));
        }
        let proof = bare(Action::PerpStateProof {
            from_height: 0,
            to_height: 1,
            new_root: [0; 8],
            payouts: vec![],
            fees: 0,
            proof: vec![],
        });
        assert_eq!(refusal(&l, &proof), TxError::UnsupportedAction("perp"), "Task 4's");
        // The root is the parent commit's, byte for byte, with and without RPL-2's section.
        assert_eq!(hex::encode(l.state_root().as_bytes()), ROOT_BEFORE);
        close(&mut l, 1);
        assert_eq!(l.take_perp_block_words(), None);
        let mut ps = ledger_with(false);
        ps.set_program_state(Some(crate::ledger::program_state::ProgramState::from_config(
            &crate::ledger::program_state::ProgramStateConfig { cell_fee: 10_000_000 },
        )));
        assert_eq!(hex::encode(ps.state_root().as_bytes()), ROOT_BEFORE_PSTATE);
    }

    #[test]
    fn the_root_carries_rand_state_9_only_with_the_section() {
        let bare_l = ledger_with(false);
        let with = ledger_with(true);
        let p = with.perps().unwrap();
        // The section wraps exactly the bytes the chain without it commits, under `rand-state-9`.
        let (d0, b0) = bare_l.state_root_preimage();
        let (d1, b1) = with.state_root_preimage();
        assert_eq!(d0, b"rand-state-4".as_slice(), "tokens on, nothing later");
        assert_eq!(d1, b"rand-state-9".as_slice());
        assert_eq!(b1, [b0.clone(), p.root().as_bytes().to_vec()].concat());
        assert_eq!(with.state_root(), Hash::digest_domain(b"rand-state-9", &b1));
        // And beside RPL-2's: the program-state root, then the perps root.
        let pstate = || {
            Some(crate::ledger::program_state::ProgramState::from_config(
                &crate::ledger::program_state::ProgramStateConfig { cell_fee: 1 },
            ))
        };
        let (mut bare_ps, mut with_ps) = (bare_l.clone(), with.clone());
        bare_ps.set_program_state(pstate());
        with_ps.set_program_state(pstate());
        let (d0, b0) = bare_ps.state_root_preimage();
        let (d1, b1) = with_ps.state_root_preimage();
        assert_eq!((d0, d1), (b"rand-state-8".as_slice(), b"rand-state-9".as_slice()));
        assert_eq!(b1, [b0, p.root().as_bytes().to_vec()].concat());
        // The perps state moves the root; a refused-and-cleared section is the old chain again.
        let mut moved = with.clone();
        dep(&mut moved, &kp(50), 10, RAND).unwrap();
        assert_ne!(moved.perps().unwrap().root(), p.root());
        let mut cleared = with.clone();
        cleared.set_perps(None);
        assert_eq!(cleared.state_root(), bare_l.state_root());
        assert_eq!(hex::encode(cleared.state_root().as_bytes()), ROOT_BEFORE);
        assert!(cleared != with, "the section is inside the ledger's equality");
    }

    // ---- Task 3 review, fix round 1 ----

    #[test]
    fn a_ninth_pending_withdrawal_is_refused_until_one_is_paid() {
        let mut l = ledger_with(true);
        let k = kp(50);
        dep(&mut l, &k, 10, RAND).unwrap();
        let w = |n: u64| bare(signed(CHAIN, &k, withdraw(&k, n, 1, 1)));
        for n in 1..=MAX_PERP_PAYOUTS as u64 {
            apply(&mut l, &w(n)).unwrap();
        }
        assert_eq!(refusal(&l, &w(9)), pe(PerpError::TooManyWithdrawals));
        assert_eq!(still_applies(&l, &w(9)), Err(pe(PerpError::TooManyWithdrawals)));
        // `apply` holds the cap too, before any write.
        let before = l.clone();
        assert_eq!(l.apply_tx(&w(9), &kp(1).address(), &StubExecutor).map(|_| ()), Err(pe(PerpError::TooManyWithdrawals)));
        assert!(l == before);
        // A proof pays one (simulated): a slot is free again.
        let paid = *l.perps().unwrap().withdrawals.keys().next().unwrap();
        l.perps_mut().unwrap().withdrawals.remove(&paid);
        apply(&mut l, &w(9)).expect("a slot is free");
    }

    #[test]
    fn an_oracle_needs_a_price_and_every_price_positive() {
        let l = ledger_with(true);
        assert_eq!(refusal(&l, &oracle(&kp(1), &[], 1)), pe(PerpError::BadPrice));
        assert_eq!(refusal(&l, &oracle(&kp(1), &[(0, 0)], 1)), pe(PerpError::BadPrice));
        assert_eq!(still_applies(&l, &oracle(&kp(1), &[(0, 0)], 1)), Err(pe(PerpError::BadPrice)));
        assert_eq!(l.validate(&oracle(&kp(1), &[(0, 1)], 1), &StubExecutor), Ok(()));
    }

    #[test]
    fn a_withdrawal_at_or_above_the_note_bound_is_refused() {
        let mut l = ledger_with(true);
        let k = kp(50);
        dep(&mut l, &k, 10, RAND).unwrap();
        let max = crate::notes::MAX_NOTE_VALUE;
        assert_eq!(refusal(&l, &bare(signed(CHAIN, &k, withdraw(&k, 1, max, 1)))), pe(PerpError::AmountTooLarge(max)));
        assert_eq!(refusal(&l, &bare(signed(CHAIN, &k, withdraw(&k, 1, u64::MAX, 1)))), pe(PerpError::AmountTooLarge(u64::MAX)));
        apply(&mut l, &bare(signed(CHAIN, &k, withdraw(&k, 1, max - 1, 1)))).expect("just under the bound");
    }

    #[test]
    fn a_departed_validators_price_is_pruned_and_a_jailed_one_is_ignored() {
        let mut l = ledger_with(true);
        apply(&mut l, &oracle(&kp(1), &[(0, 100)], 1)).unwrap();
        apply(&mut l, &oracle(&kp(2), &[(0, 200)], 1)).unwrap();
        apply(&mut l, &oracle(&kp(3), &[(0, 300)], 1)).unwrap();
        // Key 3 (stake 10) is jailed: refused as an oracle, and its price does not count.
        l.set_jailed([(kp(3).address(), u64::MAX)].into_iter().collect());
        assert_eq!(refusal(&l, &oracle(&kp(3), &[(0, 300)], 2)), pe(PerpError::NotValidator));
        assert_eq!(still_applies(&l, &oracle(&kp(3), &[(0, 300)], 2)), Err(pe(PerpError::NotValidator)));
        close(&mut l, 1);
        assert_eq!(l.perps().unwrap().median(0), 100, "stakes 1 and 1 at 100 and 200");
        assert!(l.perps().unwrap().oracle[&0].submissions.contains_key(&kp(3).address()), "jailed, not gone");
        // Key 1 leaves the register: its submission is dropped at the next close.
        l.validators.remove(&kp(1).address());
        let root = l.perps().unwrap().root();
        close(&mut l, 2);
        let o = &l.perps().unwrap().oracle[&0];
        assert!(!o.submissions.contains_key(&kp(1).address()));
        assert_eq!(o.submissions.len(), 2);
        assert_eq!(o.median, 200);
        assert_ne!(l.perps().unwrap().root(), root);
    }
}
