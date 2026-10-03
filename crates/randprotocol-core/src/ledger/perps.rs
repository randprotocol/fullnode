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

use crate::confidential::ConfidentialExecutor;
use crate::crypto::{merkle_root, Address, Hash, PublicKey};
use crate::notes::{word8_from_bytes, word8_to_bytes, Envelope, ShieldedAddress, Word8};
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
    #[allow(dead_code)] // filled by the action rules and drained at block close
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
}
