//! The RPL token registry: dense indices for every fungible asset on this chain, bridged ones
//! included — the bridge (`crate::bridge::state::BridgeState`) is a reader of this registry and
//! no longer keeps one of its own.
//!
//! A note's `asset` word is one `u32`, so every asset — bridged or native — needs a dense index
//! rather than its 32-byte [`AssetId`]. A bridged token earns its index by being *listed* (in
//! genesis, or by a governance message), never by an attestation naming it; an RPL token earns
//! its the moment someone pays to register it (a later task's
//! `Action::RegisterToken`). This module is only the registry's shape and its bookkeeping rules:
//! what a name/symbol/decimals triple must look like, how supply is tracked and checked both
//! ways, and the root that folds the registry into the state root. Nothing here decides which
//! actions can call it — that is the ledger module beside this one, wired up in a later task.
//!
//! Index 0 is RAND, the native coin, and is never handed out: [`TokenRegistry::new`] starts
//! `next_index` at [`FIRST_TOKEN_INDEX`], never at zero, and there is deliberately no `Default`
//! impl that could start it there by accident.
//!
//! A bridged asset registers here too, under an [`AssetId`] over its own registration fields
//! ([`bridged_asset_id`]), so a note's `asset` word means one thing everywhere: an index into
//! this one registry, whether the value behind it came from a bridge attestation or a native
//! mint. A bridged token is backed by one *or several* source-chain coins (spec §12: zUSD is
//! USDT and USDC on four chains at once), and [`TokenRegistry::bridged`] resolves any of those
//! `(chain, token)` pairs to it — many to one. Each backing carries its own locked amount, and
//! their sum is the token's supply ([`TokenRegistry::backing_invariant_holds`]).

use super::{Ledger, TxError};
use crate::bridge::AssetId;
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{merkle_root, Hash, PublicKey};
use crate::gas;
use crate::notes::{ShieldedAddress, Word8};
use crate::program::ProgramId;
use crate::types::actions::{set_authority_message, token_mint_message, InitialMint};
use crate::types::{Action, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The first index [`TokenRegistry::new`] hands out. 0 is RAND and is never registered here,
/// the same reservation the bridge's own registry used to make before this one replaced it.
pub const FIRST_TOKEN_INDEX: u32 = 1;
/// Longest a token's display name may be, in bytes.
pub const MAX_NAME_BYTES: usize = 32;
/// Longest a token's ticker symbol may be, in bytes.
pub const MAX_SYMBOL_BYTES: usize = 12;
/// Most decimal places a token may declare.
pub const MAX_DECIMALS: u8 = 9;
/// Decimals a bridged token is normalized to on this chain, whatever its home chain declares.
pub const BRIDGE_DECIMALS: u8 = 8;
/// Most source-chain coins one bridged token may be backed by (spec §12).
pub const MAX_BACKINGS: usize = 32;
/// The bridge attestation wire's own decimal precision (bridge-06/audit O-5): every amount
/// crossing the wire, in either direction, is expressed at this many decimal places, whatever the
/// source token declares. The same figure as [`BRIDGE_DECIMALS`] — normalizing a deposit to it and
/// expressing a burn's release unit against it are the same fact — so this is that constant under
/// the name the wire format's own rule is stated in.
pub const WIRE_DECIMALS: u8 = BRIDGE_DECIMALS;
/// Largest decimal count a backing's source token may declare. Chosen generously above every real
/// ERC-20/SPL token in use (18 covers every EVM coin; Solana coins are typically 6-9): a listing
/// past it is refused ([`TokenError::BadBackingDecimals`]) rather than accepted and silently
/// unreleasable.
pub const MAX_BACKING_DECIMALS: u8 = 18;

/// One source-chain coin behind a bridged token, and how much of it that chain's contract is
/// holding locked for this one (spec §12).
///
/// zUSD is one Rand-side token backed by USDT and USDC on several chains at once, so a bridged
/// token names a *list* of these. `locked` is per backing rather than per token because a burn
/// releases one specific coin on one specific chain: a redemption the token's whole supply could
/// cover but that coin's own contract could not would succeed here and fail there, stranding the
/// note's value. The sum of every `locked` of a token is exactly its
/// [`TokenInfo::total_supply`] — [`TokenRegistry::backing_invariant_holds`].
///
/// `decimals` is the **source** token's own decimal count (bridge-06/audit O-5), 0..=
/// [`MAX_BACKING_DECIMALS`] — not [`BRIDGE_DECIMALS`], which is what a bridged *token* is
/// normalized to on this chain. The attestation wire always carries amounts at [`WIRE_DECIMALS`],
/// so a source coin with fewer decimals releases in units of [`Backing::release_unit`] native
/// tokens: USDT at 6 decimals releases `amount / 10^2`, and a burn that is not a whole number of
/// those units would either strand value in custody (rounded down) or fail to release at all
/// (below one unit) — [`TokenRegistry::check_release`] refuses both before any note is destroyed.
///
/// `minted_today` and `mint_day` are bridge hardening B1's per-backing daily mint cap: how much
/// this coin's deposits have minted on UTC day `mint_day` (of the block timestamp,
/// `crate::bridge::mint_day`). A deposit on a later day counts from zero again. They are consensus
/// state — the token leaf hashes them — because the cap decides which attestations are admissible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backing {
    pub chain: u16,
    pub token: [u8; 32],
    pub decimals: u8,
    pub locked: u64,
    pub minted_today: u64,
    pub mint_day: u32,
}

impl Backing {
    /// A fresh backing of `(chain, token)` at `decimals` source decimals: nothing locked, nothing
    /// minted — what a listing (genesis, `add_backing`, a registration) starts every coin at.
    pub fn new(chain: u16, token: [u8; 32], decimals: u8) -> Backing {
        Backing { chain, token, decimals, locked: 0, minted_today: 0, mint_day: 0 }
    }

    /// What this backing has minted on `day`: `minted_today` if its counter is for that day, zero
    /// if the counter is for an earlier one (the reset a new day brings, read without a write).
    pub fn minted_on(&self, day: u32) -> u64 {
        if self.mint_day == day {
            self.minted_today
        } else {
            0
        }
    }
}

impl Backing {
    /// How many wire (8-decimal) units the source contract releases per native unit of this coin:
    /// `10^(8 - decimals)` for a coin with fewer decimals than the wire, or `1` when it has 8 or
    /// more (nothing to round — `decimals > 8` still releases one wire unit per native unit,
    /// since the wire is never asked to express a fraction finer than its own precision).
    ///
    /// A burn must destroy a multiple of this ([`TokenRegistry::check_release`]): custody equals
    /// `locked` exactly, at all times, only when nothing is ever asked to release a fraction of a
    /// native unit.
    pub fn release_unit(&self) -> u64 {
        release_unit(self.decimals)
    }
}

/// [`Backing::release_unit`] as a function of the decimals alone, for a caller that has a coin's
/// declared precision but no [`Backing`] to hand — the wallet reads `decimals` off an
/// `rand_getAssets` row and must derive the very same unit the ledger will, rather than write a
/// second `10^(8-d)` that could drift from this one.
///
/// Never wraps: the exponent is at most [`WIRE_DECIMALS`], so the largest value is `10^8`.
pub fn release_unit(decimals: u8) -> u64 {
    if decimals < WIRE_DECIMALS {
        10u64.pow((WIRE_DECIMALS - decimals) as u32)
    } else {
        1
    }
}

/// Who may move a token's [`TokenInfo::total_supply`] and [`TokenInfo::mint_nonce`], in the
/// later task that wires up `Mint`/`Burn`.
///
/// `None` is a fixed-supply token: whatever [`native_asset_id`] committed to at registration is
/// all there will ever be. `Key` and `Program` are the two things that can sign or prove a
/// further mint. `Bridge` is not a minter at all in the sense the other three are — a bridged
/// token's supply moves only through [`TokenRegistry::lock`] and [`TokenRegistry::release`],
/// which move a backing in the same step, and [`TokenRegistry::add_supply`]/
/// [`TokenRegistry::sub_supply`] refuse it outright ([`TokenError::BridgedToken`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintAuthority {
    None,
    Key(PublicKey),
    Bridge { backings: Vec<Backing> },
    Program(ProgramId),
}

/// One registered token: its identity, its declared metadata, who may mint it, and the two
/// counters a mint/burn task will move.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo {
    pub id: AssetId,
    pub index: u32,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub authority: MintAuthority,
    /// Replay protection for a `Key` authority's signed mints, one task over. Unused by the
    /// other three authority kinds, but kept on every row so the leaf shape does not depend on
    /// which kind a token has.
    pub mint_nonce: u64,
    pub total_supply: u64,
    pub registered_at: u64,
}

/// The dense-index registry (spec's RPL token standard): every token by its assigned index and
/// by its [`AssetId`], plus the next index to hand out.
///
/// No `Default`: a defaulted `next_index` of 0 would be RAND's index. [`TokenRegistry::new`] is
/// the only constructor, and it starts at [`FIRST_TOKEN_INDEX`] — the reservation the bridge's
/// own retired registry made for the same reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRegistry {
    pub registration_fee: u64,
    by_index: BTreeMap<u32, TokenInfo>,
    index_of: BTreeMap<AssetId, u32>,
    /// `(chain, token)` -> the index of the bridged token that pair backs. Many-to-one: zUSD's
    /// seven coins all point at one index, and a pair backs at most one token in the whole
    /// registry ([`TokenError::BackingTaken`]).
    ///
    /// Derivable from `by_index` alone — `the_backing_index_is_the_map_the_tokens_describe`
    /// pins that it is exactly the rebuilt map — and persisted with the registry anyway, so a
    /// reloading node's `load` stays a single `bincode::deserialize` and cannot forget to
    /// rebuild it. Maintained only by [`TokenRegistry::register`] and
    /// [`TokenRegistry::add_backing`], the two places a backing comes into existence.
    backing_of: BTreeMap<(u16, [u8; 32]), u32>,
    next_index: u32,
    /// Bridge hardening B1: the most one backing of any bridged token may mint in one UTC day, in
    /// the token's own (8-decimal) units — the genesis `tokens.mint_cap_per_day`, applied **per
    /// backing** ([`TokenError::MintCapExceeded`]). [`TokenRegistry::new`] starts it uncapped
    /// (`u64::MAX`); genesis sets it with [`TokenRegistry::with_mint_cap`].
    mint_cap_per_day: u64,
}

/// Why a registry operation was refused. A later task's `validate`/`apply` for the RPL actions
/// carries this inside its own `TxError` variant, the same way [`super::StakingError`] rides
/// inside `TxError::Staking`, and the bridge carries the backing ones inside
/// [`crate::bridge::BridgeError::Token`]; the metadata, identity, capacity, supply and backing
/// variants are reachable from this module today, the rest are for that task's
/// mint/burn/rotate rules.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum TokenError {
    #[error("RPL tokens are disabled on this chain")]
    Disabled,
    #[error("token name must be 1 to {MAX_NAME_BYTES} bytes")]
    BadName,
    #[error("token symbol must be 1 to {MAX_SYMBOL_BYTES} ASCII graphic bytes")]
    BadSymbol,
    #[error("decimals {0} exceeds the maximum {MAX_DECIMALS}")]
    TooManyDecimals(u8),
    #[error("asset {0} is already registered")]
    AlreadyRegistered(AssetId),
    #[error("the token registry has no indices left")]
    RegistryFull,
    #[error("no token at index {0}")]
    UnknownToken(u32),
    #[error("this action is not allowed by the token's mint authority")]
    AuthorityNotAllowed,
    #[error("a fixed-supply token must mint its initial supply at registration")]
    InitialMintRequired,
    #[error("token {0}'s mint authority is not a key")]
    NotKeyAuthority(u32),
    #[error("wrong mint nonce: expected {expected}, got {got}")]
    BadNonce { expected: u64, got: u64 },
    #[error("bad mint authority signature")]
    BadSignature,
    #[error("token supply overflow")]
    SupplyOverflow,
    #[error("token supply underflow")]
    SupplyUnderflow,
    #[error("amount must not be zero")]
    ZeroAmount,
    #[error("token {0} is bridged and cannot be minted directly")]
    BridgedToken(u32),
    #[error("registration fee {fee} is below the minimum {min}")]
    RegistrationFeeTooLow { min: u64, fee: u64 },
    #[error("wrong token index: expected {expected}, got {got}")]
    IndexMismatch { expected: u32, got: u32 },
    /// The `(chain, token)` pair asked about is not one of token `index`'s backings — it backs
    /// nothing, or it backs some *other* registered token. The token address is deliberately
    /// not in the message: the chain alone names the side of the trade a user got wrong, and
    /// the pair is in the transaction the refusal is about.
    #[error("chain {chain}'s coin does not back token {index}")]
    NotABacking { index: u32, chain: u16 },
    /// A release (a burn) of more of one coin than that coin's own contract is holding. The
    /// token's whole supply may well cover it; this backing does not.
    #[error("only {locked} is locked in that backing, not the {amount} asked for")]
    InsufficientBacking { locked: u64, amount: u64 },
    /// A `(chain, token)` pair backs at most one token in the whole registry, so a second
    /// listing (or [`TokenRegistry::add_backing`]) naming a taken pair is refused.
    #[error("a coin of chain {chain} already backs a registered token")]
    BackingTaken { chain: u16 },
    #[error("a bridged token may have at most {MAX_BACKINGS} backings")]
    TooManyBackings,
    #[error("a bridged token needs at least one backing")]
    NoBackings,
    /// A backing's declared source-chain decimals is over [`MAX_BACKING_DECIMALS`] — not a
    /// meaningful precision for any real coin, and unbounded decimals would make
    /// [`Backing::release_unit`]'s `10^(8-d)` overflow for `d` deep enough below the wire's eight.
    #[error("backing decimals {0} exceeds the maximum {MAX_BACKING_DECIMALS}")]
    BadBackingDecimals(u8),
    /// A burn (or the relayer fee carved out of it) is not a whole number of the backing's
    /// [`Backing::release_unit`] — the source contract cannot release a fraction of a native
    /// unit, so `amount` would either strand the remainder in custody or, below one unit, release
    /// nothing at all (bridge-06/audit O-5). `amount` here is whichever of the burn's amount or
    /// its relayer fee failed the check.
    #[error("{amount} is not a multiple of the release unit {unit}")]
    NotReleasable { amount: u64, unit: u64 },
    /// Bridge hardening B1: a deposit that would take its backing's `minted_today` past the
    /// registry's `mint_cap_per_day`. Not a verdict on the attestation — it becomes admissible on
    /// the next UTC day of the block timestamp.
    #[error("mint cap {cap} per backing per day: {minted_today} minted today, {amount} more would pass it")]
    MintCapExceeded { cap: u64, minted_today: u64, amount: u64 },
}

impl TokenRegistry {
    /// An empty registry charging `registration_fee` per registration, its next index at
    /// [`FIRST_TOKEN_INDEX`] — never 0, which is RAND's.
    pub fn new(registration_fee: u64) -> TokenRegistry {
        TokenRegistry {
            registration_fee,
            by_index: BTreeMap::new(),
            index_of: BTreeMap::new(),
            backing_of: BTreeMap::new(),
            next_index: FIRST_TOKEN_INDEX,
            mint_cap_per_day: u64::MAX,
        }
    }

    /// This registry with its per-backing daily mint cap set (B1) — what genesis builds from
    /// `tokens.mint_cap_per_day`.
    pub fn with_mint_cap(mut self, mint_cap_per_day: u64) -> TokenRegistry {
        self.mint_cap_per_day = mint_cap_per_day;
        self
    }

    /// B1's per-backing daily mint cap, in the token's own units.
    pub fn mint_cap_per_day(&self) -> u64 {
        self.mint_cap_per_day
    }

    pub fn get(&self, index: u32) -> Option<&TokenInfo> {
        self.by_index.get(&index)
    }

    pub fn get_by_id(&self, id: &AssetId) -> Option<&TokenInfo> {
        let index = self.index_of.get(id)?;
        self.by_index.get(index)
    }

    /// The index the next [`Self::register`] will hand out — [`FIRST_TOKEN_INDEX`] on an empty
    /// registry, never 0.
    ///
    /// Public because a creator has to *name* it: an [`Action::RegisterToken`]'s initial note is
    /// sealed against a commitment carrying this index, so the wallet reads it (through
    /// `rand_getTokens`) and the chain holds the transaction to it
    /// ([`TokenError::IndexMismatch`]).
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// The bridged token that `(chain, token)` backs — the one whose index a deposit of that
    /// coin carries. `None` for a pair nobody listed.
    ///
    /// Many-to-one (spec §12): USDT on Ethereum and USDC on Solana both answer zUSD. Only a
    /// [`MintAuthority::Bridge`] token can ever be reached through here, because only a
    /// registration with that authority puts anything into `backing_of` — which is what makes
    /// an attestation's resolution and a burn's resolution agree about what "bridged" means.
    pub fn bridged(&self, chain: u16, token: &[u8; 32]) -> Option<&TokenInfo> {
        let index = self.backing_of.get(&(chain, *token))?;
        self.by_index.get(index)
    }

    /// Token `index`'s backing for `(chain, token)`, with its locked amount. `None` when that
    /// index holds no such backing — including when the pair backs a *different* token, and when
    /// the token is not bridged at all.
    pub fn backing(&self, index: u32, chain: u16, token: &[u8; 32]) -> Option<&Backing> {
        match &self.by_index.get(&index)?.authority {
            MintAuthority::Bridge { backings } => backings.iter().find(|b| b.chain == chain && &b.token == token),
            _ => None,
        }
    }

    /// Every registered token, ascending by index.
    pub fn iter(&self) -> impl Iterator<Item = &TokenInfo> {
        self.by_index.values()
    }

    pub fn len(&self) -> usize {
        self.by_index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_index.is_empty()
    }

    /// Registers `id` at the next dense index, checking metadata first, then that `id` is not
    /// already registered, then that an index is still available. Starts at zero supply and
    /// zero mint nonce; a later task's registration action is what mints the initial supply, in
    /// the same transaction (`TokenError::InitialMintRequired` refuses one that does not).
    /// A `Bridge` authority's backings are additionally checked — one to [`MAX_BACKINGS`] of
    /// them, each `(chain, token)` pair free across the whole registry — and normalized to zero
    /// `locked`, because a registration starts at zero supply and the invariant
    /// `total_supply == Σ locked` has to be true from the first block.
    ///
    /// Refused whole: nothing is written until every check has passed, so a listing that names
    /// one taken pair leaves not even its free pairs behind.
    pub fn register(
        &mut self,
        id: AssetId,
        name: String,
        symbol: String,
        decimals: u8,
        authority: MintAuthority,
        height: u64,
    ) -> Result<u32, TokenError> {
        check_metadata(&name, &symbol, decimals)?;
        if self.index_of.contains_key(&id) {
            return Err(TokenError::AlreadyRegistered(id));
        }
        let authority = match authority {
            MintAuthority::Bridge { backings } => {
                if backings.is_empty() {
                    return Err(TokenError::NoBackings);
                }
                if backings.len() > MAX_BACKINGS {
                    return Err(TokenError::TooManyBackings);
                }
                let mut fresh: BTreeSet<(u16, [u8; 32])> = BTreeSet::new();
                for b in &backings {
                    if b.decimals > MAX_BACKING_DECIMALS {
                        return Err(TokenError::BadBackingDecimals(b.decimals));
                    }
                    let pair = (b.chain, b.token);
                    // Taken by another token, or named twice inside this one listing: the same
                    // collision either way, and the same refusal.
                    if self.backing_of.contains_key(&pair) || !fresh.insert(pair) {
                        return Err(TokenError::BackingTaken { chain: b.chain });
                    }
                }
                MintAuthority::Bridge {
                    backings: backings.into_iter().map(|b| Backing::new(b.chain, b.token, b.decimals)).collect(),
                }
            }
            other => other,
        };
        if self.next_index == u32::MAX {
            return Err(TokenError::RegistryFull);
        }
        let index = self.next_index;
        self.next_index += 1;
        if let MintAuthority::Bridge { backings } = &authority {
            for b in backings {
                self.backing_of.insert((b.chain, b.token), index);
            }
        }
        self.by_index.insert(
            index,
            TokenInfo {
                id,
                index,
                name,
                symbol,
                decimals,
                authority,
                mint_nonce: 0,
                total_supply: 0,
                registered_at: height,
            },
        );
        self.index_of.insert(id, index);
        Ok(index)
    }

    /// Adds a `(chain, token)` pair to a listed bridged token, unlocked (spec §12; Task 10's
    /// `AddBacking` governance message). The pair must be free across the whole registry, the
    /// token must be bridged, it must be under [`MAX_BACKINGS`], and `decimals` — the *source*
    /// token's own decimal count — must be at most [`MAX_BACKING_DECIMALS`]
    /// ([`TokenError::BadBackingDecimals`]).
    ///
    /// Nothing else can grow a backing set: a registration lists its own, and this adds one.
    pub fn add_backing(&mut self, index: u32, chain: u16, token: [u8; 32], decimals: u8) -> Result<(), TokenError> {
        if decimals > MAX_BACKING_DECIMALS {
            return Err(TokenError::BadBackingDecimals(decimals));
        }
        if self.backing_of.contains_key(&(chain, token)) {
            return Err(TokenError::BackingTaken { chain });
        }
        let info = self.by_index.get_mut(&index).ok_or(TokenError::UnknownToken(index))?;
        let MintAuthority::Bridge { backings } = &mut info.authority else {
            return Err(TokenError::AuthorityNotAllowed);
        };
        if backings.len() >= MAX_BACKINGS {
            return Err(TokenError::TooManyBackings);
        }
        backings.push(Backing::new(chain, token, decimals));
        self.backing_of.insert((chain, token), index);
        Ok(())
    }

    /// A deposit on UTC day `day`: `locked += amount` on the named backing and `total_supply +=
    /// amount` on the token, both checked and applied together, so `total_supply == Σ locked`
    /// survives every refusal as well as every success — and the backing's daily mint counter
    /// (B1) moves by the same `amount`, reset first if its day is over.
    ///
    /// [`TokenError::NotABacking`] when `(chain, token)` is not one of `index`'s backings — a
    /// non-bridged token has none at all, so this is also what it answers.
    pub fn lock(&mut self, index: u32, chain: u16, token: &[u8; 32], amount: u64, day: u32) -> Result<(), TokenError> {
        // Every refusal first, in one place a validate step can call on its own
        // (`check_lock`), so what admission pre-checks is by construction what this would
        // refuse — and so the writes below cannot half-apply.
        self.check_lock(index, chain, token, amount, day)?;
        self.move_backing(index, chain, token, amount, true);
        let backing = self.backing_mut(index, chain, token).expect("the checked half resolved the backing");
        // `check_lock` bounded `minted_on(day) + amount` by the cap, so this cannot wrap.
        backing.minted_today = backing.minted_on(day) + amount;
        backing.mint_day = day;
        Ok(())
    }

    fn backing_mut(&mut self, index: u32, chain: u16, token: &[u8; 32]) -> Option<&mut Backing> {
        match &mut self.by_index.get_mut(&index)?.authority {
            MintAuthority::Bridge { backings } => backings.iter_mut().find(|b| b.chain == chain && &b.token == token),
            _ => None,
        }
    }

    /// The write half [`Self::lock`] and [`Self::release`] share: the token's `total_supply` and
    /// the named backing's `locked` move by the same `amount`, up or down together, which is what
    /// keeps `total_supply == Σ locked` true through every call (spec §12).
    ///
    /// Private and infallible: each caller has just run its own `check_*` against this same state,
    /// so every `expect` below is that check's guarantee and the arithmetic cannot wrap. It is one
    /// function rather than two so the two directions cannot drift — they differed only in a sign.
    fn move_backing(&mut self, index: u32, chain: u16, token: &[u8; 32], amount: u64, up: bool) {
        let info = self.by_index.get_mut(&index).expect("the checked half resolved the index");
        info.total_supply = if up { info.total_supply + amount } else { info.total_supply - amount };
        let MintAuthority::Bridge { backings } = &mut info.authority else {
            unreachable!("the checked half resolved a backing")
        };
        let backing = backings
            .iter_mut()
            .find(|b| b.chain == chain && &b.token == token)
            .expect("the checked half resolved the backing");
        backing.locked = if up { backing.locked + amount } else { backing.locked - amount };
    }

    /// Exactly what [`Self::lock`] would refuse, without touching anything: the pair being a
    /// backing of this token at all, the backing's own overflow and the supply's, then B1's daily
    /// mint cap for that backing on `day`. The validate step of a `BridgeAttest` calls this so its
    /// apply step cannot fail.
    ///
    /// The cap is per backing: `minted_on(day) + amount <= mint_cap_per_day`, where a counter left
    /// from an earlier day reads as zero. Exactly the cap is accepted, one unit over is
    /// [`TokenError::MintCapExceeded`].
    pub fn check_lock(&self, index: u32, chain: u16, token: &[u8; 32], amount: u64, day: u32) -> Result<(), TokenError> {
        let info = self.by_index.get(&index).ok_or(TokenError::UnknownToken(index))?;
        // The coin before the arithmetic: a pair that does not back this token is a different
        // mistake from an amount that does not fit, and naming the coin is the more useful of
        // the two answers whenever both are true.
        let backing = self.backing(index, chain, token).ok_or(TokenError::NotABacking { index, chain })?;
        backing.locked.checked_add(amount).ok_or(TokenError::SupplyOverflow)?;
        info.total_supply.checked_add(amount).ok_or(TokenError::SupplyOverflow)?;
        // B1, after the arithmetic that could not hold the deposit at all: today's counter plus
        // this deposit against the cap. A sum past `u64::MAX` is past any cap too.
        let minted_today = backing.minted_on(day);
        if minted_today.checked_add(amount).is_none_or(|total| total > self.mint_cap_per_day) {
            return Err(TokenError::MintCapExceeded { cap: self.mint_cap_per_day, minted_today, amount });
        }
        Ok(())
    }

    /// A redemption: `locked -= amount` on the named backing and `total_supply -= amount` on the
    /// token. Refuses `amount > locked` with [`TokenError::InsufficientBacking`] — the token's
    /// whole supply is not what bounds a burn, the coin being released is — and refuses an
    /// `amount`/`relayer_fee` that is not a whole number of the backing's release unit
    /// ([`TokenError::NotReleasable`], bridge-06/audit O-5): see [`Self::check_release`].
    pub fn release(
        &mut self,
        index: u32,
        chain: u16,
        token: &[u8; 32],
        amount: u64,
        relayer_fee: u64,
    ) -> Result<(), TokenError> {
        self.check_release(index, chain, token, amount, relayer_fee)?;
        self.move_backing(index, chain, token, amount, false);
        Ok(())
    }

    /// Exactly what [`Self::release`] would refuse, without touching anything — the **one** place
    /// that decides every refusal of a burn, so `validate` (through
    /// [`crate::bridge::BridgeState::check_burn`]) and `apply` (through [`Self::release`]) read
    /// the very same verdict and cannot drift:
    ///
    /// 1. the pair being a backing of this token at all ([`TokenError::NotABacking`]);
    /// 2. byte-cheap and state-independent past that point — `amount` and `relayer_fee` must both
    ///    be a whole number of the backing's [`Backing::release_unit`]
    ///    ([`TokenError::NotReleasable`]): the source contract releases in units of
    ///    `10^(8 - decimals)` wire amounts, so anything else would either strand a remainder in
    ///    custody forever or, below one unit, release nothing at all — the amendment this method
    ///    exists for (bridge-06/audit O-5, "custody equals `locked`, exactly, at all times");
    /// 3. `amount > locked` ([`TokenError::InsufficientBacking`]), the state-dependent check, run
    ///    last;
    /// 4. the supply's underflow (unreachable while the backing invariant holds, checked anyway).
    ///
    /// `relayer_fee` is checked here rather than ignored because the wire format releases it in
    /// native units too — it is paid out of `amount` on the destination chain, not on top of it —
    /// so a fee that is not a whole unit is exactly as unreleasable as an amount that is not one.
    pub fn check_release(
        &self,
        index: u32,
        chain: u16,
        token: &[u8; 32],
        amount: u64,
        relayer_fee: u64,
    ) -> Result<(), TokenError> {
        let info = self.by_index.get(&index).ok_or(TokenError::UnknownToken(index))?;
        // The coin first, as in `check_lock`: a pair that does not back this token is a different
        // mistake from an amount that does not fit, and naming the coin is the more useful of the
        // two answers whenever both are true.
        let backing = self.backing(index, chain, token).ok_or(TokenError::NotABacking { index, chain })?;
        let unit = backing.release_unit();
        // Byte-cheap (a modulus against a decimals-derived constant that never changes for this
        // backing) and ahead of the locked comparison, which is the state-dependent half.
        if amount % unit != 0 {
            return Err(TokenError::NotReleasable { amount, unit });
        }
        if relayer_fee % unit != 0 {
            return Err(TokenError::NotReleasable { amount: relayer_fee, unit });
        }
        // The token's supply last: while the backing invariant holds, `amount <= locked` implies
        // `amount <= total_supply`, so the underflow below is unreachable — it is the defensive
        // half of the pair, not the verdict a burn should ever read.
        backing
            .locked
            .checked_sub(amount)
            .ok_or(TokenError::InsufficientBacking { locked: backing.locked, amount })?;
        info.total_supply.checked_sub(amount).ok_or(TokenError::SupplyUnderflow)?;
        Ok(())
    }

    /// `total_supply == Σ backings.locked` for every bridged token (spec §12's invariant, in the
    /// user's words: the USDT and USDC locked on every source chain equals the zUSD on this one).
    ///
    /// Cheap — one pass over the registry — and asserted at every block close in a debug build
    /// ([`super::Ledger::close_block`]) as well as explicitly in tests. It holds by construction:
    /// [`Self::lock`] and [`Self::release`] move both sides together and are the only writers of
    /// a bridged token's supply, since [`Self::add_supply`] and [`Self::sub_supply`] refuse one.
    pub fn backing_invariant_holds(&self) -> bool {
        self.by_index.values().all(|info| match &info.authority {
            MintAuthority::Bridge { backings } => {
                let sum: u128 = backings.iter().map(|b| b.locked as u128).sum();
                sum == info.total_supply as u128
            }
            _ => true,
        })
    }

    /// Credits `amount` to `index`'s supply, refusing to wrap past `u64::MAX`.
    ///
    /// Refuses a bridged token outright ([`TokenError::BridgedToken`]): its supply moves only
    /// through [`Self::lock`], which moves a backing in the same step. Anything else could raise
    /// the supply without any source chain having locked a coin for it, which is exactly the
    /// invariant `backing_invariant_holds` exists to make impossible to break by accident.
    pub fn add_supply(&mut self, index: u32, amount: u64) -> Result<(), TokenError> {
        let info = self.by_index.get_mut(&index).ok_or(TokenError::UnknownToken(index))?;
        if matches!(info.authority, MintAuthority::Bridge { .. }) {
            return Err(TokenError::BridgedToken(index));
        }
        info.total_supply = info.total_supply.checked_add(amount).ok_or(TokenError::SupplyOverflow)?;
        Ok(())
    }

    /// Debits `amount` from `index`'s supply, refusing to underflow below zero — and refusing a
    /// bridged token, for [`Self::add_supply`]'s reason: a burn is a [`Self::release`].
    pub fn sub_supply(&mut self, index: u32, amount: u64) -> Result<(), TokenError> {
        let info = self.by_index.get_mut(&index).ok_or(TokenError::UnknownToken(index))?;
        if matches!(info.authority, MintAuthority::Bridge { .. }) {
            return Err(TokenError::BridgedToken(index));
        }
        info.total_supply = info.total_supply.checked_sub(amount).ok_or(TokenError::SupplyUnderflow)?;
        Ok(())
    }

    /// Advances `index`'s mint nonce, the replay protection a `Key` authority's signed mints
    /// check against. A no-op on an unknown index: like `bump_nonce` on `ValidatorEntry`, the
    /// caller that owns replay protection is expected to have already resolved the index it is
    /// bumping, so there is nothing for an infallible method to report here.
    pub fn bump_nonce(&mut self, index: u32) {
        if let Some(info) = self.by_index.get_mut(&index) {
            info.mint_nonce += 1;
        }
    }

    /// Rotates `index`'s mint authority to `Key(new)`, or to [`MintAuthority::None`] when `new`
    /// is absent — which retires minting for good (spec §4: a key holder may hand the token on or
    /// revoke itself, and nothing else).
    ///
    /// **Only a `Key` authority rotates**, and anything else is *reported*, never ignored:
    ///
    /// - an unknown index is [`TokenError::UnknownToken`];
    /// - a `Bridge` token is [`TokenError::NotKeyAuthority`] — its authority holds its backings,
    ///   so rotating it away would orphan every pair `backing_of` points at this index and break
    ///   the backing invariant in one call;
    /// - a `None` token is the same refusal, and it is what makes a renunciation final: there is
    ///   no key left to sign the rotation back;
    /// - a `Program` token likewise, until RPL-2 gives it a rule of its own.
    ///
    /// The refusals matter because [`Action::SetAuthority`] charges a fee: a silent no-op here
    /// would take that fee and change nothing, which is exactly the shape of bug a caller cannot
    /// see. `Action::SetAuthority`'s own `validate` refuses the same cases first, so this is the
    /// second of two locks on one door rather than the only one.
    pub fn set_key(&mut self, index: u32, new: Option<PublicKey>) -> Result<(), TokenError> {
        let info = self.by_index.get_mut(&index).ok_or(TokenError::UnknownToken(index))?;
        if !matches!(info.authority, MintAuthority::Key(_)) {
            return Err(TokenError::NotKeyAuthority(index));
        }
        info.authority = match new {
            Some(pk) => MintAuthority::Key(pk),
            None => MintAuthority::None,
        };
        Ok(())
    }

    /// Folds the registry into one hash for the state root: a merkle root over every
    /// [`TokenInfo`] leaf in index order, then domain-separated together with `next_index` and
    /// `registration_fee` so a fee change or a still-empty next index also moves the root.
    pub fn root(&self) -> Hash {
        let leaves: Vec<Hash> = self
            .by_index
            .values()
            .map(|info| {
                let bytes = bincode::serialize(info).expect("TokenInfo serializes");
                Hash::digest_domain(b"rand-token-leaf-1", &bytes)
            })
            .collect();
        let leaves_root = merkle_root(&leaves);
        let mut buf = Vec::with_capacity(32 + 4 + 8 + 8);
        buf.extend_from_slice(leaves_root.as_bytes());
        buf.extend_from_slice(&self.next_index.to_be_bytes());
        buf.extend_from_slice(&self.registration_fee.to_be_bytes());
        // B1: the cap decides which deposits are admissible, so it is committed like the fee.
        // (Each backing's own counters are in its token's leaf, above.)
        buf.extend_from_slice(&self.mint_cap_per_day.to_be_bytes());
        Hash::digest_domain(b"rand-token-registry-2", &buf)
    }
}

/// The metadata rules every registration checks, in field order: `name` is 1 to
/// [`MAX_NAME_BYTES`] bytes (spaces allowed — "Tether USD" is a fine name), `symbol` is 1 to
/// [`MAX_SYMBOL_BYTES`] bytes of **ASCII graphic characters** (`0x21..=0x7e` — printable, no
/// space, no control byte, no DEL, nothing outside ASCII), `decimals` is at most
/// [`MAX_DECIMALS`].
///
/// The symbol rule is a byte range, not "no whitespace": a note's `asset` word and every
/// display surface downstream (the explorer, a wallet, an RPC response) treat `symbol` as a
/// short trusted label, so nothing that could be a control sequence, a zero-width character or
/// a multi-byte encoding surprise belongs in it.
pub fn check_metadata(name: &str, symbol: &str, decimals: u8) -> Result<(), TokenError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(TokenError::BadName);
    }
    const ASCII_GRAPHIC: std::ops::RangeInclusive<u8> = 0x21..=0x7e;
    if symbol.is_empty()
        || symbol.len() > MAX_SYMBOL_BYTES
        || symbol.bytes().any(|b| !ASCII_GRAPHIC.contains(&b))
    {
        return Err(TokenError::BadSymbol);
    }
    if decimals > MAX_DECIMALS {
        return Err(TokenError::TooManyDecimals(decimals));
    }
    Ok(())
}

/// The [`AssetId`] a native (non-bridged) token registers under: domain-separated over every
/// field a registration commits to, plus a caller-chosen `salt` so the same declaration can still
/// be made twice as two distinct assets. Built the same way `crate::bridge::asset_id` builds a
/// bridged one — a plain `Hash::digest_domain` call, since [`AssetId`] and [`Hash`] are the same
/// type.
///
/// **The whole `initial` is in the id — amount, recipient, blinding, time and envelope — not just
/// the amount** (spec §3, amended 2026-09-19 after Task 4's review). An
/// [`Action::RegisterToken`] carries no signature, so an observer can lift a pending registration
/// off gossip, attach a fee bundle of its own and race it. (Since the transaction binding the
/// creator's *own* fee bundle cannot ride the copy — its proof is bound to the original
/// transaction, `Transaction::binding` — but the observer's fee bundle is honestly proved for the
/// copy, because those are the observer's notes.) Were only the amount bound, the copy would land under the
/// *same* id: whichever won took the identity and the entire initial supply — permanently, for a
/// fixed-supply token — and the loser died at [`TokenError::AlreadyRegistered`]. With the whole
/// mint in the id a redirected copy is simply a *different* token, which is all a non-unique
/// symbol ever promised; the original then costs one re-issue at the next index
/// ([`TokenError::IndexMismatch`]) and nothing more.
///
/// `initial` is `None` for a `Key` token that registers empty, and that is a different id from
/// any registration that mints.
///
/// [`Action::RegisterToken`]: crate::types::Action::RegisterToken
pub fn native_asset_id(
    name: &str,
    symbol: &str,
    decimals: u8,
    authority: &MintAuthority,
    initial: &Option<InitialMint>,
    salt: &[u8; 32],
) -> AssetId {
    let bytes = bincode::serialize(&(name, symbol, decimals, authority, initial, salt))
        .expect("native asset id fields serialize");
    Hash::digest_domain(b"rand-rpl-asset", &bytes)
}

/// The [`AssetId`] a **bridged** token registers under: its registration fields — name, symbol,
/// the [`BRIDGE_DECIMALS`] every bridged token is normalized to, and a salt — under the same
/// `rand-rpl-asset` domain a native registration uses.
///
/// Deliberately *not* `crate::bridge::asset_id(chain, token)`, which is what a bridged token's id
/// was before one token could have many backings: an id over a `(chain, token)` pair could only
/// ever name one coin, and zUSD names seven. The backings are not in the id either — they grow
/// (`add_backing`), and an identity that moved when a coin was added would be no identity at all.
/// `bridge::asset_id` stays exactly what it was, as the per-backing *wire* id `rand_bridgeAssetId`
/// computes and `rand_getAssets` prints per row.
///
/// It cannot collide with a [`native_asset_id`]: this hashes a four-field tuple and that a
/// six-field one, and bincode's encoding of the shorter can never be the encoding of the longer
/// (the tail past `decimals` is exactly 32 bytes here — the salt — and at least 37 there: four
/// for the authority's variant tag at its shortest, one for the `Option`'s, and the same 32).
pub fn bridged_asset_id(name: &str, symbol: &str, salt: &[u8; 32]) -> AssetId {
    let bytes =
        bincode::serialize(&(name, symbol, BRIDGE_DECIMALS, salt)).expect("bridged asset id fields serialize");
    Hash::digest_domain(b"rand-rpl-asset", &bytes)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The four RPL actions: RegisterToken, TokenMint, SetAuthority, TokenBurn (§4). A transfer of a
// token is a plain `Action::None` bundle since the hidden-asset bundle: the asset is private.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The `from` word of a minted note: an RPL mint has no sender inside the pool, exactly as a
/// bridge deposit has none, so the note records a constant instead of an address that does not
/// exist.
///
/// It is deliberately **not** [`super::bridge_notes`]'s zero word: a deposit and a mint are two
/// different ways value enters the pool, and two notes agreeing on owner, amount, asset, time and
/// blinding must still be two different leaves — otherwise a bridged deposit could collide with
/// an RPL mint and one of the two would be unappendable. The value is the ASCII tag `rpl-mint`,
/// little-endian in the first two words and zero-padded, so it is readable in a hex dump and
/// fixed for the life of the chain.
pub const MINT_FROM: Word8 =
    [u32::from_le_bytes(*b"rpl-"), u32::from_le_bytes(*b"mint"), 0, 0, 0, 0, 0, 0];

/// The commitment of a note an RPL mint creates — a registration's initial supply
/// ([`InitialMint`]) or an [`Action::TokenMint`] — computed identically by [`validate`] and
/// [`apply`], one function so the two cannot drift.
///
/// `index` is the token's registry index, the note's `asset` word; `time` is the action's own
/// `time` and never the applying height, because the minter seals the recipient's envelope
/// against this commitment before the transaction has a block.
///
/// Public because all five inputs are public on the wire: a recipient can rebuild the leaf the
/// chain appended without opening any envelope, which is what the node's note index and
/// `tx_json` do, and what recovers a note whose envelope was published as garbage
/// (`docs/bridge.md` §8's argument, one action over).
pub fn mint_commitment(
    recipient: &ShieldedAddress,
    amount: u64,
    index: u32,
    time: u32,
    r: &Word8,
    executor: &dyn ConfidentialExecutor,
) -> Word8 {
    executor.note_commitment(&recipient.pk, &MINT_FROM, amount, index, time, r)
}

/// What an action reaching this module that it does not own gets. Only a routing mistake in
/// [`super::Ledger::validate_inner`] can produce one, and refusing it is the safe answer: `Ok`
/// would let a mis-routed action skip the rules of the module that does own it.
const NOT_TOKENS: TxError = TxError::UnsupportedAction("tokens");

/// The burn rule of the two token-burning actions, `TokenBurn` and `BridgeBurn`, on the
/// transaction's one bundle (the hidden-asset bundle, spec §3.7). In order, and every one a
/// comparison:
///
/// 1. `asset != 0` — RAND is never a token, and a RAND burn goes through `burn_r`
///    ([`TokenError::UnknownToken`]`(0)`, the registry's own answer for index 0);
/// 2. `burn_asset == asset` ([`TxError::BurnAssetMismatch`]): the guest publishes the asset of
///    its private slots 0–1 here exactly when `burn_a != 0`;
/// 3. `burn_a == amount` ([`TxError::BurnAmountMismatch`]);
/// 4. `burn_r == 0` ([`TxError::UnsupportedBurn`]): a token burn burns no RAND.
///
/// Whether `asset` is a registered token (and its supply or backing covers `amount`) is each
/// caller's own rule, against its own registry. The bundle's proof is verified after every cheap
/// check, by `Ledger::validate_inner`'s steps 8-9, so a transaction that gets any of this wrong
/// costs no verification (spec §7).
pub(super) fn check_asset_burn(tx: &Transaction, asset: u32, amount: u64) -> Result<(), TxError> {
    let b = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?;
    if asset == 0 {
        return Err(TokenError::UnknownToken(0).into());
    }
    if b.burn_asset != asset {
        return Err(TxError::BurnAssetMismatch { expected: asset, actual: b.burn_asset });
    }
    if b.burn_a != amount {
        return Err(TxError::BurnAmountMismatch { expected: amount, actual: b.burn_a });
    }
    if b.burn_r != 0 {
        return Err(TxError::UnsupportedBurn(b.burn_r));
    }
    Ok(())
}

/// The action step of admission (spec §7 step 7) for the four RPL actions.
///
/// Cheap before expensive throughout, and in one order for all four: **the gate** (a chain with
/// no `tokens` section has no RPL at all, and says so before any other token check), then the
/// action's own byte-level rules, then the state lookups, then the fee, then the time window and
/// the tree, and the Dilithium2 signature **last** — it is by far the most expensive thing here,
/// and everything above it can refuse a transaction without buying one. The fee bundle's proof is
/// verified after all of this by the common path (`validate_inner` step 9), as for every other
/// bundle-carrying action.
///
/// Nothing is written: every refusal [`apply`] could make is made here, so `apply` cannot fail on
/// a transaction that was admitted.
pub(super) fn validate(
    ledger: &Ledger,
    tx: &Transaction,
    action: &Action,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    // Fail closed before anything else, so that this half and [`apply`] answer a mis-routed
    // action alike whether or not the chain has a registry. A discriminant compare, and not a
    // *token* check: the gate below is still the first thing any RPL action meets.
    if !matches!(
        action,
        Action::RegisterToken { .. }
            | Action::TokenMint { .. }
            | Action::SetAuthority { .. }
            | Action::TokenBurn { .. }
    ) {
        return Err(NOT_TOKENS);
    }
    // The gate is absolute (spec §4, and the `aggregation` section's rule before it): on a chain
    // whose genesis has no `tokens` section, every RPL action is inadmissible — before its
    // metadata, its authority, its nonce or its signature is looked at, so nothing about a
    // token action can be observed on a chain that has none.
    let registry = ledger.tokens().ok_or(TxError::Token(TokenError::Disabled))?;
    match action {
        Action::RegisterToken { name, symbol, decimals, authority, initial, salt, index } => {
            // The bytes first: name, symbol and decimals are the registry's own rules, and a
            // registration that could never be listed is refused before a single map lookup.
            check_metadata(name, symbol, *decimals)?;
            // Only the two authorities a creator may choose. A bridged token is *listed* (by
            // genesis or by a guardian governance message) so that no attestation can invent one,
            // and `Program` is reserved for RPL-2; both would otherwise let anyone mint an asset
            // the bridge or a program is supposed to own.
            match authority {
                MintAuthority::None | MintAuthority::Key(_) => {}
                MintAuthority::Bridge { .. } | MintAuthority::Program(_) => {
                    return Err(TokenError::AuthorityNotAllowed.into())
                }
            }
            // A fixed-supply token mints once or never: without an initial mint its supply is
            // zero for ever and the registration is a row nobody can use.
            if matches!(authority, MintAuthority::None) && initial.is_none() {
                return Err(TokenError::InitialMintRequired.into());
            }
            if let Some(m) = initial {
                // A zero note is worth nothing and would still occupy a leaf.
                if m.amount == 0 {
                    return Err(TokenError::ZeroAmount.into());
                }
            }
            // The state lookups. The id binds every declared field and the *whole* initial mint,
            // so the identical declaration twice is the same asset — and the second is refused
            // rather than handed a second index — while a copy of this registration with the
            // recipient swapped is a different asset that can take nothing from it.
            let id = native_asset_id(name, symbol, *decimals, authority, initial, salt);
            if registry.get_by_id(&id).is_some() {
                return Err(TokenError::AlreadyRegistered(id).into());
            }
            if registry.next_index() == u32::MAX {
                return Err(TokenError::RegistryFull.into());
            }
            // The index the creator sealed its initial note for. Checked with or without an
            // `initial`: a wallet that read a stale `next_index` built the whole transaction
            // against the wrong row, and refusing it costs a re-proof where accepting it would
            // hand the creator a token at an index it never asked for (and, with an `initial`, a
            // note under an `asset` word its envelope was not sealed against).
            if *index != registry.next_index() {
                return Err(TokenError::IndexMismatch { expected: registry.next_index(), got: *index }.into());
            }
            // The registration fee, on top of the bundle base `gas::fee_floor` already took at
            // step 3. It lives here because it is a *ledger* fact — the registry's own
            // `registration_fee`, which genesis sets — and `fee_floor` has no ledger to read.
            // Saturating: a registry whose fee is near `u64::MAX` makes registration unpayable
            // rather than wrapping to something cheap.
            let min = gas::BUNDLE_BASE.saturating_add(registry.registration_fee);
            if tx.fee() < min {
                return Err(TokenError::RegistrationFeeTooLow { min, fee: tx.fee() }.into());
            }
            if let Some(m) = initial {
                // The note's `time` is the creator's, so it gets the window every note-stamping
                // `time` gets (spec §7 item 5).
                ledger.check_time(m.time)?;
                // And the leaf itself must be new — against the tree and against this
                // transaction's own fee bundle, which `apply` appends first. Deciding it here
                // keeps admission's answer and application's answer the same one.
                let cm = mint_commitment(&m.recipient, m.amount, *index, m.time, &m.r, executor);
                check_new_note(ledger, tx, &cm)?;
            }
        }
        Action::TokenMint { asset, amount, recipient, r, time, envelope, nonce, signature } => {
            // A byte-level rule, so it comes before the registry is consulted at all: a zero mint
            // would spend the authority's nonce to append a leaf worth nothing.
            if *amount == 0 {
                return Err(TokenError::ZeroAmount.into());
            }
            // Registered, `Key`-authorised, at the nonce its row expects — the triple
            // `SetAuthority` shares (see [`key_authority`]).
            let (info, pk) = key_authority(registry, *asset, *nonce)?;
            ledger.check_time(*time)?;
            // A checked add, decided here so `apply`'s `add_supply` cannot fail: a supply that
            // wrapped would stop counting what exists.
            info.total_supply.checked_add(*amount).ok_or(TokenError::SupplyOverflow)?;
            let cm = mint_commitment(recipient, *amount, *asset, *time, r, executor);
            check_new_note(ledger, tx, &cm)?;
            // Last, and the most expensive check in this module by a wide margin. The message
            // carries the commitment, so it binds the recipient, the amount, the asset, the time
            // and the blinding all at once — and the envelope digest beside it, because the
            // commitment does *not* cover the ciphertext that opens the note: without it a third
            // party could re-wrap a gossiped mint with garbage and spend the authority's nonce
            // (spec §4, amended 2026-09-19). So the leaf the ledger appends is the leaf the
            // authority signed for, and the envelope that travels with it is the one it sealed.
            if !pk.verify(token_mint_message(tx.chain_id, &info.id, *nonce, *amount, &cm, envelope).as_bytes(), signature)
            {
                return Err(TokenError::BadSignature.into());
            }
        }
        Action::SetAuthority { asset, new, nonce, signature } => {
            // Explicitly, and before anything is charged: only a registered, `Key`-authorised
            // token at the right nonce rotates — [`key_authority`] again, so a rotation and a
            // mint can never read the same row differently.
            let (info, pk) = key_authority(registry, *asset, *nonce)?;
            // By the **current** key: handing the token on is the holder's decision, never the
            // heir's. Last, as in the mint arm.
            if !pk.verify(set_authority_message(tx.chain_id, &info.id, *nonce, new).as_bytes(), signature) {
                return Err(TokenError::BadSignature.into());
            }
        }
        Action::TokenBurn { asset, amount } => {
            let info = registry.get(*asset).ok_or(TokenError::UnknownToken(*asset))?;
            // A bridged token's supply moves only with one of its backings
            // (`TokenRegistry::release`), so it leaves this chain through a `BridgeBurn`, which
            // names the coin being released. Burning one here would drop the supply while every
            // source contract kept holding its coins — `total_supply == Σ locked` broken on the
            // spot — and `sub_supply` refuses it too, which makes this the first of two locks on
            // one door rather than the only one.
            if matches!(info.authority, MintAuthority::Bridge { .. }) {
                return Err(TokenError::BridgedToken(*asset).into());
            }
            if *amount == 0 {
                return Err(TokenError::ZeroAmount.into());
            }
            // A checked sub, decided here so `apply`'s `sub_supply` cannot fail: a supply that
            // wrapped would stop counting what exists. Two burns in one block are safe for the
            // same reason two mints at one nonce are — block application re-validates each
            // transaction against the ledger the ones before it left, so the second of two burns
            // that do not both fit is refused where it sits.
            info.total_supply.checked_sub(*amount).ok_or(TokenError::SupplyUnderflow)?;
            // The bundle's burn fields, against what the action declares.
            check_asset_burn(tx, *asset, *amount)?;
        }
        _ => return Err(NOT_TOKENS),
    }
    Ok(())
}

/// The apply step, in lockstep with [`validate`]: every refusal below was decided there against
/// this same state, so a transaction that was admitted cannot fail here. (Two RPL actions in one
/// block are safe for the same reason the bridge's two burns are: block application re-validates
/// each transaction against the ledger the ones before it left, so the second of two mints at one
/// nonce — or two registrations at one index — is refused where it sits.)
///
/// The errors are kept rather than unwrapped: `apply_tx`'s caller discards the ledger on any
/// error, so reporting one is strictly safer than a panic on a state that was not what validate
/// saw.
///
/// `_tx` is unused: everything these three actions take from the transaction — its `chain_id` in
/// a signed message, its fee, its fee bundle's own notes — was consumed by [`validate`], and the
/// parameter is kept only so this half reads as [`super::bridge_notes::apply`]'s and
/// [`super::staking::apply`]'s twin.
pub(super) fn apply(
    ledger: &mut Ledger,
    _tx: &Transaction,
    action: &Action,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    // The same two guards `validate` opens with, in the same order and for the same reasons: fail
    // closed on an action this module does not own (only a routing mistake in `validate_inner`
    // produces one, and `Ok(())` would let it skip the rules of the module that does), then the
    // gate — **before any write**. `apply` is only ever reached through `validate`, which has
    // already refused both cases, so this is the second of two locks on one door; it matters
    // because several arms below append a note or spend a nullifier before they first touch the
    // registry, and a direct caller on a gated-off chain would otherwise leave those writes behind.
    if !matches!(
        action,
        Action::RegisterToken { .. }
            | Action::TokenMint { .. }
            | Action::SetAuthority { .. }
            | Action::TokenBurn { .. }
    ) {
        return Err(NOT_TOKENS);
    }
    gate(ledger)?;
    match action {
        Action::RegisterToken { name, symbol, decimals, authority, initial, salt, index: _ } => {
            // The same id `validate` resolved, from the same fields — the whole initial mint
            // included, so `apply` cannot land under an identity `validate` did not check.
            let id = native_asset_id(name, symbol, *decimals, authority, initial, salt);
            let height = ledger.height();
            let registry = ledger.tokens_mut().ok_or(TxError::Token(TokenError::Disabled))?;
            // The index `validate` held the action's `index` to, and the only place it is handed
            // out. `register` re-checks the metadata, the id and the capacity: the same three
            // `validate` decided, against the same state.
            let index =
                registry.register(id, name.clone(), symbol.clone(), *decimals, authority.clone(), height)?;
            if let Some(m) = initial {
                // The note first, then the supply — the bridge deposit's order, for its reason:
                // the leaf is what the recipient's envelope was sealed against, and the supply is
                // the public count of what now exists. Both were pre-decided above.
                let cm = mint_commitment(&m.recipient, m.amount, index, m.time, &m.r, executor);
                ledger.deposit(cm, executor)?;
                ledger.tokens_mut().ok_or(TxError::Token(TokenError::Disabled))?.add_supply(index, m.amount)?;
            }
        }
        Action::TokenMint { asset, amount, recipient, r, time, .. } => {
            let cm = mint_commitment(recipient, *amount, *asset, *time, r, executor);
            ledger.deposit(cm, executor)?;
            let registry = ledger.tokens_mut().ok_or(TxError::Token(TokenError::Disabled))?;
            registry.add_supply(*asset, *amount)?;
            // The nonce the authority signed under is spent, so this exact mint can never be
            // replayed — on this chain or, since the message binds the chain id, on another.
            registry.bump_nonce(*asset);
        }
        Action::SetAuthority { asset, new, .. } => {
            let registry = ledger.tokens_mut().ok_or(TxError::Token(TokenError::Disabled))?;
            registry.set_key(*asset, new.clone())?;
            // A rotation spends the same counter a mint does, so neither can be replayed after
            // the other.
            registry.bump_nonce(*asset);
        }
        // The bundle's notes were written by `apply_tx`'s common path, like every bundle's.
        Action::TokenBurn { asset, amount } => {
            // What the bundle's `burn_a` destroyed leaves the token's public count, so `total_supply`
            // keeps saying what exists. `validate` ruled out every refusal `sub_supply` has — the
            // index, the bridged authority and the underflow — so this cannot fail on a
            // transaction that was admitted.
            ledger.tokens_mut().ok_or(TxError::Token(TokenError::Disabled))?.sub_supply(*asset, *amount)?;
        }
        _ => return Err(NOT_TOKENS),
    }
    Ok(())
}

/// The three checks a `Key`-authorised action shares, in one place and in this order: the token
/// is registered, its authority really is a `Key`, and the nonce is the one that key's register
/// row expects. Returns the row and the key that has to have signed.
///
/// One function because [`Action::TokenMint`] and [`Action::SetAuthority`] must not drift apart
/// on it: they spend the same counter, and a mint that read the nonce differently from a rotation
/// would let one be replayed after the other.
fn key_authority(
    registry: &TokenRegistry,
    asset: u32,
    nonce: u64,
) -> Result<(&TokenInfo, &PublicKey), TokenError> {
    let info = registry.get(asset).ok_or(TokenError::UnknownToken(asset))?;
    // A `Bridge` token's supply moves through its backings alone (`TokenRegistry::lock`), a
    // `None` token's never moves again — which is what makes a renunciation final — and
    // `Program` is reserved. One refusal for all three, naming the index.
    let MintAuthority::Key(pk) = &info.authority else {
        return Err(TokenError::NotKeyAuthority(asset));
    };
    // The token's own counter is the whole of the replay protection: there are no accounts here,
    // and one authority key may hold many tokens at once.
    if nonce != info.mint_nonce {
        return Err(TokenError::BadNonce { expected: info.mint_nonce, got: nonce });
    }
    Ok((info, pk))
}

/// The gate, as a refusal rather than a registry: a chain whose genesis has no `tokens` section
/// has no RPL at all. [`apply`] reads it once, before any write, because several of its arms
/// append a note or spend a nullifier before they first touch the registry; [`validate`] takes
/// the registry itself at the same point, which is the same read.
fn gate(ledger: &Ledger) -> Result<(), TxError> {
    match ledger.tokens() {
        Some(_) => Ok(()),
        None => Err(TxError::Token(TokenError::Disabled)),
    }
}

/// A note the chain is about to create must be one nobody has created yet — in the tree, and in
/// this transaction's own bundle, whose four notes `apply_tx` appends before the action runs.
/// The bridge deposit's check, one action over.
fn check_new_note(ledger: &Ledger, tx: &Transaction, cm: &Word8) -> Result<(), TxError> {
    let in_fee_bundle = tx.bundle.as_ref().is_some_and(|b| b.commitments.contains(cm));
    if ledger.has_commitment(cm) || in_fee_bundle {
        return Err(TxError::CommitmentExists(*cm));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> TokenRegistry {
        TokenRegistry::new(1_000_000_000)
    }

    // `AssetId` is a type alias (`crate::bridge::AssetId = Hash`), and a type alias cannot be
    // used as a tuple constructor (`AssetId([n; 32])` does not compile: E0423, "not a function,
    // tuple struct or tuple variant") — only the aliased item's own name can. `Hash([n; 32])`
    // is the same value; adapted from the brief's `AssetId([n; 32])` for that reason.
    fn id(n: u8) -> AssetId {
        Hash([n; 32])
    }

    #[test]
    fn indices_are_dense_from_one_and_zero_is_never_registered() {
        let mut r = reg();
        assert_eq!(r.register(id(1), "A".into(), "A".into(), 9, MintAuthority::None, 5).unwrap(), 1);
        assert_eq!(r.register(id(2), "B".into(), "A".into(), 0, MintAuthority::None, 6).unwrap(), 2);
        assert!(r.get(0).is_none());
        assert_eq!(r.get(2).unwrap().registered_at, 6);
        assert_eq!(r.get_by_id(&id(1)).unwrap().index, 1);
    }

    #[test]
    fn the_same_symbol_registers_twice_but_the_same_id_does_not() {
        let mut r = reg();
        r.register(id(1), "X".into(), "zUSDC".into(), 8, MintAuthority::None, 0).unwrap();
        r.register(id(2), "Y".into(), "zUSDC".into(), 8, MintAuthority::None, 0).unwrap();
        assert_eq!(
            r.register(id(1), "Z".into(), "Q".into(), 8, MintAuthority::None, 0),
            Err(TokenError::AlreadyRegistered(id(1)))
        );
    }

    #[test]
    fn metadata_rules() {
        assert_eq!(check_metadata("", "A", 0), Err(TokenError::BadName));
        assert_eq!(check_metadata(&"n".repeat(33), "A", 0), Err(TokenError::BadName));
        assert_eq!(check_metadata("n", "", 0), Err(TokenError::BadSymbol));
        assert_eq!(check_metadata("n", "has space", 0), Err(TokenError::BadSymbol));
        assert_eq!(check_metadata("n", &"S".repeat(13), 0), Err(TokenError::BadSymbol));
        assert_eq!(check_metadata("n", "S", 10), Err(TokenError::TooManyDecimals(10)));
        assert!(check_metadata("Tether USD", "zUSDT", 8).is_ok());
    }

    /// The symbol rule is byte-range, not just "no whitespace": every byte must be ASCII
    /// graphic (`0x21..=0x7e`). Non-ASCII (`"λ"`) and non-whitespace control bytes (`"\x01"`,
    /// the DEL byte `0x7f`) are refused just as a literal space is; exactly [`MAX_SYMBOL_BYTES`]
    /// bytes of graphic ASCII is still the boundary that passes.
    #[test]
    fn symbol_bytes_must_be_ascii_graphic() {
        assert_eq!(check_metadata("n", "λ", 0), Err(TokenError::BadSymbol), "non-ASCII");
        assert_eq!(check_metadata("n", "\x01", 0), Err(TokenError::BadSymbol), "a control byte");
        assert_eq!(check_metadata("n", "A\x7f", 0), Err(TokenError::BadSymbol), "the DEL byte");
        assert!(check_metadata("n", &"A".repeat(MAX_SYMBOL_BYTES), 0).is_ok(), "exactly at the length cap");
    }

    #[test]
    fn registering_past_the_last_index_is_refused() {
        let mut r = reg();
        // `next_index` is private to this module; the tests submodule can still reach it
        // directly to drive the registry to its last possible index without registering
        // four billion tokens.
        r.next_index = u32::MAX;
        assert_eq!(
            r.register(id(1), "A".into(), "A".into(), 0, MintAuthority::None, 0),
            Err(TokenError::RegistryFull)
        );
        assert!(r.get_by_id(&id(1)).is_none(), "a refused registration leaves nothing behind");
    }

    /// `bump_nonce` is a no-op on an unknown index (its caller has already resolved the row);
    /// `set_key` is not — it *reports* the miss, because a rotation that quietly changed nothing
    /// would have taken a fee and left the authority where it was.
    #[test]
    fn bump_nonce_is_a_no_op_and_set_key_reports_an_unknown_index() {
        let mut r = reg();
        let pk = crate::crypto::Keypair::from_seed([1; 32]).unwrap().public_key().clone();
        r.bump_nonce(7);
        assert_eq!(r.set_key(7, Some(pk)), Err(TokenError::UnknownToken(7)));
        assert_eq!(r.set_key(7, None), Err(TokenError::UnknownToken(7)));
        assert!(r.get(7).is_none(), "nothing was created for an index that was never registered");
    }

    #[test]
    fn is_empty_reflects_len() {
        let mut r = reg();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        r.register(id(1), "A".into(), "A".into(), 0, MintAuthority::None, 0).unwrap();
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn supply_is_checked_both_ways() {
        let mut r = reg();
        r.register(id(1), "A".into(), "A".into(), 9, MintAuthority::None, 0).unwrap();
        r.add_supply(1, u64::MAX).unwrap();
        assert_eq!(r.add_supply(1, 1), Err(TokenError::SupplyOverflow));
        r.sub_supply(1, u64::MAX).unwrap();
        assert_eq!(r.sub_supply(1, 1), Err(TokenError::SupplyUnderflow));
        assert_eq!(r.add_supply(7, 1), Err(TokenError::UnknownToken(7)));
    }

    #[test]
    fn the_root_moves_with_every_field_and_a_bridged_id_is_the_bridge_id() {
        let mut r = reg();
        let empty = r.root();
        r.register(id(1), "A".into(), "A".into(), 9, MintAuthority::None, 0).unwrap();
        let one = r.root();
        assert_ne!(empty, one);
        r.add_supply(1, 5).unwrap();
        assert_ne!(one, r.root());
        let (chain, token) = (2u16, [0xaa; 32]);
        let bid = bridged_asset_id("USD Coin", "zUSDC", &[7; 32]);
        r.register(bid, "USD Coin".into(), "zUSDC".into(), 8, bridge(&[(chain, token)]), 0).unwrap();
        assert_eq!(r.bridged(chain, &token).unwrap().index, 2);
        // A backing's `locked` is state, and the leaf commits to it.
        let listed = r.root();
        r.lock(2, chain, &token, 5, 0).unwrap();
        assert_ne!(r.root(), listed, "the state root moves when a backing's locked moves");
    }

    /// A native id binds every field a registration declares — and the **whole** of its initial
    /// mint, not just the amount (spec §3, amended 2026-09-19): a `RegisterToken` carries no
    /// signature and an observer may pay for a copy with a fee bundle of its own (the transaction
    /// binding stops only the creator's), so an observer that could swap the
    /// recipient, the blinding or the envelope of a gossiped registration and keep its id would
    /// take the initial supply outright. With all five in the id, a redirected copy is a
    /// *different* token — which is all a non-unique symbol ever promised.
    #[test]
    fn a_native_id_binds_every_registration_field() {
        let mint = |amount: u64, pk: Word8, r: Word8, time: u32, body: u8| {
            Some(InitialMint {
                amount,
                recipient: ShieldedAddress { pk, kem_ek: vec![6; 32] },
                r,
                time,
                envelope: crate::notes::Envelope {
                    kem_ct: vec![1; 8],
                    to_receiver: vec![],
                    to_sender: vec![],
                    body: vec![body; 8],
                },
            })
        };
        let base = mint(10, [4; 8], [7; 8], 9, 2);
        let a = native_asset_id("A", "A", 9, &MintAuthority::None, &base, &[0; 32]);
        assert_eq!(a, native_asset_id("A", "A", 9, &MintAuthority::None, &base, &[0; 32]), "and it is a function");
        for (other, what) in [
            (native_asset_id("A", "A", 9, &MintAuthority::None, &base, &[1; 32]), "the salt"),
            (native_asset_id("B", "A", 9, &MintAuthority::None, &base, &[0; 32]), "the name"),
            (native_asset_id("A", "B", 9, &MintAuthority::None, &base, &[0; 32]), "the symbol"),
            (native_asset_id("A", "A", 8, &MintAuthority::None, &base, &[0; 32]), "the decimals"),
            (
                native_asset_id(
                    "A",
                    "A",
                    9,
                    &MintAuthority::Key(crate::crypto::Keypair::from_seed([1; 32]).unwrap().public_key().clone()),
                    &base,
                    &[0; 32],
                ),
                "the authority",
            ),
            (native_asset_id("A", "A", 9, &MintAuthority::None, &mint(11, [4; 8], [7; 8], 9, 2), &[0; 32]), "the amount"),
            (native_asset_id("A", "A", 9, &MintAuthority::None, &mint(10, [5; 8], [7; 8], 9, 2), &[0; 32]), "the recipient"),
            (native_asset_id("A", "A", 9, &MintAuthority::None, &mint(10, [4; 8], [8; 8], 9, 2), &[0; 32]), "the blinding"),
            (native_asset_id("A", "A", 9, &MintAuthority::None, &mint(10, [4; 8], [7; 8], 10, 2), &[0; 32]), "the time"),
            (native_asset_id("A", "A", 9, &MintAuthority::None, &mint(10, [4; 8], [7; 8], 9, 3), &[0; 32]), "the envelope"),
            (native_asset_id("A", "A", 9, &MintAuthority::None, &None, &[0; 32]), "no initial mint at all"),
        ] {
            assert_ne!(a, other, "{what}");
        }
    }

    // -----------------------------------------------------------------------
    // One bridged token, many backings (spec §12)
    // -----------------------------------------------------------------------

    /// USDT and USDC on chain 2, the two backings most of the tests below use.
    const USDT2: (u16, [u8; 32]) = (2, [0xaa; 32]);
    const USDC2: (u16, [u8; 32]) = (2, [0xbb; 32]);

    /// A `Bridge` authority over `pairs`, every backing starting unlocked.
    fn bridge(pairs: &[(u16, [u8; 32])]) -> MintAuthority {
        MintAuthority::Bridge {
            backings: pairs
                .iter()
                .map(|&(chain, token)| Backing { chain, token, decimals: BRIDGE_DECIMALS, locked: 0, minted_today: 0, mint_day: 0 })
                .collect(),
        }
    }

    /// [`bridge`], with each pair's own source decimals instead of the wire's eight — for the
    /// release-unit tests, where the whole point is that a coin's decimals differ from
    /// [`BRIDGE_DECIMALS`].
    fn bridge_decimals(pairs: &[(u16, [u8; 32], u8)]) -> MintAuthority {
        MintAuthority::Bridge {
            backings: pairs.iter().map(|&(chain, token, decimals)| Backing { chain, token, decimals, locked: 0, minted_today: 0, mint_day: 0 }).collect(),
        }
    }

    /// zUSD listed over `pairs`, at the index it is given (1 in a fresh registry).
    fn list_zusd(r: &mut TokenRegistry, pairs: &[(u16, [u8; 32])]) -> u32 {
        r.register(
            bridged_asset_id("Rand USD", "zUSD", &[9; 32]),
            "Rand USD".into(),
            "zUSD".into(),
            BRIDGE_DECIMALS,
            bridge(pairs),
            0,
        )
        .expect("a fresh listing")
    }

    /// The whole point of the amendment: two source coins, one Rand-side token. A deposit of
    /// either backing mints the same index and raises the same supply, and each backing's
    /// `locked` records which source contract is holding what.
    #[test]
    fn a_deposit_of_either_backing_mints_the_same_index_and_raises_supply() {
        let mut r = reg();
        let i = list_zusd(&mut r, &[USDT2, USDC2]);
        assert_eq!(i, 1);
        assert_eq!(r.bridged(USDT2.0, &USDT2.1).unwrap().index, i);
        assert_eq!(r.bridged(USDC2.0, &USDC2.1).unwrap().index, i, "one token, two coins");
        r.lock(i, USDT2.0, &USDT2.1, 1_000, 0).unwrap();
        r.lock(i, USDC2.0, &USDC2.1, 400, 0).unwrap();
        assert_eq!(r.get(i).unwrap().total_supply, 1_400, "both deposits are the same zUSD");
        assert_eq!(r.backing(i, USDT2.0, &USDT2.1).unwrap().locked, 1_000);
        assert_eq!(r.backing(i, USDC2.0, &USDC2.1).unwrap().locked, 400);
        assert!(r.backing_invariant_holds());
    }

    /// `total_supply == Σ locked` for every bridged token, through a mixed sequence — and it is
    /// the assertion a debug build makes at every block close.
    #[test]
    fn the_backing_invariant_holds_through_deposits_and_burns() {
        let mut r = reg();
        let i = list_zusd(&mut r, &[USDT2, USDC2, (3, [0xcc; 32])]);
        for (chain, token, amount) in [(2u16, [0xaa; 32], 900u64), (3, [0xcc; 32], 250), (2, [0xbb; 32], 75)] {
            r.lock(i, chain, &token, amount, 0).unwrap();
            assert!(r.backing_invariant_holds());
        }
        r.release(i, 2, &[0xaa; 32], 400, 0).unwrap();
        assert!(r.backing_invariant_holds());
        r.release(i, 3, &[0xcc; 32], 250, 0).unwrap();
        assert!(r.backing_invariant_holds());
        assert_eq!(r.get(i).unwrap().total_supply, 900 - 400 + 75);
        assert_eq!(r.backing(i, 3, &[0xcc; 32]).unwrap().locked, 0, "drained, still a backing");
        // A registry whose supply has been tampered with does not hold it — which is what makes
        // the assertion worth making.
        let mut broken = r.clone();
        broken.by_index.get_mut(&i).unwrap().total_supply += 1;
        assert!(!broken.backing_invariant_holds());
    }

    /// A burn is a release of one *coin*, so it is bounded by that coin's own locked amount even
    /// when the token's whole supply would cover it. The same amount against the backing that
    /// does hold it succeeds.
    #[test]
    fn a_release_past_one_backing_is_refused_though_the_supply_covers_it() {
        let mut r = reg();
        let i = list_zusd(&mut r, &[USDT2, USDC2]);
        r.lock(i, USDT2.0, &USDT2.1, 1_000, 0).unwrap();
        r.lock(i, USDC2.0, &USDC2.1, 100, 0).unwrap();
        assert_eq!(
            r.release(i, USDC2.0, &USDC2.1, 400, 0),
            Err(TokenError::InsufficientBacking { locked: 100, amount: 400 }),
            "1 100 of supply, but only 100 USDC is locked"
        );
        assert_eq!(r.get(i).unwrap().total_supply, 1_100, "and a refused release moved nothing");
        r.release(i, USDT2.0, &USDT2.1, 400, 0).unwrap();
        assert_eq!(r.get(i).unwrap().total_supply, 700);
        assert!(r.backing_invariant_holds());
    }

    /// Two burns into one backing that each fit alone but not together: the second is refused,
    /// which is what makes block application (validate against the evolving ledger, then apply)
    /// safe for two burns in one block.
    #[test]
    fn two_releases_that_each_fit_alone_do_not_both_fit() {
        let mut r = reg();
        let i = list_zusd(&mut r, &[USDT2, USDC2]);
        r.lock(i, USDT2.0, &USDT2.1, 100, 0).unwrap();
        r.lock(i, USDC2.0, &USDC2.1, 900, 0).unwrap();
        r.release(i, USDT2.0, &USDT2.1, 60, 0).unwrap();
        assert_eq!(
            r.release(i, USDT2.0, &USDT2.1, 60, 0),
            Err(TokenError::InsufficientBacking { locked: 40, amount: 60 })
        );
        assert_eq!(r.get(i).unwrap().total_supply, 940);
        assert!(r.backing_invariant_holds());
    }

    // ── The release unit (bridge-06/audit O-5): a burn must be a whole number of it ───────────

    /// A 6-decimal backing (USDT/USDC's real decimals on most chains) releases in units of 100
    /// wire amounts (`10^(8-6)`): 199 leaves a remainder that would strand 99 in custody forever,
    /// and 200 — exactly two units — is fine.
    #[test]
    fn a_burn_of_199_into_a_6_decimal_backing_is_not_releasable_and_200_succeeds() {
        let mut r = reg();
        let usdt6 = (2u16, [0xaa; 32], 6u8);
        r.register(
            bridged_asset_id("Rand USD", "zUSD", &[0x5a; 32]),
            "Rand USD".into(),
            "zUSD".into(),
            BRIDGE_DECIMALS,
            bridge_decimals(&[usdt6]),
            0,
        )
        .unwrap();
        r.lock(1, usdt6.0, &usdt6.1, 1_000, 0).unwrap();
        assert_eq!(r.backing(1, usdt6.0, &usdt6.1).unwrap().release_unit(), 100);
        assert_eq!(
            r.release(1, usdt6.0, &usdt6.1, 199, 0),
            Err(TokenError::NotReleasable { amount: 199, unit: 100 })
        );
        assert_eq!(r.get(1).unwrap().total_supply, 1_000, "a refused release moved nothing");
        r.release(1, usdt6.0, &usdt6.1, 200, 0).unwrap();
        assert_eq!(r.get(1).unwrap().total_supply, 800);
        assert!(r.backing_invariant_holds());
    }

    /// The relayer fee is released in native units too (it is carved out of `amount` on the
    /// destination chain, not paid on top of it), so it is checked against the same unit: a fee
    /// of 150 against a 100-unit backing is refused even though the amount itself (1 000) is a
    /// clean multiple.
    #[test]
    fn a_relayer_fee_that_is_not_a_whole_unit_is_refused() {
        let mut r = reg();
        let usdt6 = (2u16, [0xaa; 32], 6u8);
        r.register(
            bridged_asset_id("Rand USD", "zUSD", &[0x5a; 32]),
            "Rand USD".into(),
            "zUSD".into(),
            BRIDGE_DECIMALS,
            bridge_decimals(&[usdt6]),
            0,
        )
        .unwrap();
        r.lock(1, usdt6.0, &usdt6.1, 10_000, 0).unwrap();
        assert_eq!(
            r.release(1, usdt6.0, &usdt6.1, 1_000, 150),
            Err(TokenError::NotReleasable { amount: 150, unit: 100 })
        );
        assert_eq!(r.get(1).unwrap().total_supply, 10_000, "still refused: nothing moved");
        r.release(1, usdt6.0, &usdt6.1, 1_000, 100).unwrap();
        assert_eq!(r.get(1).unwrap().total_supply, 9_000);
    }

    /// A backing at 18 decimals — at or above the wire's eight — has a release unit of 1: every
    /// amount, however oddly shaped, is already a whole number of it.
    #[test]
    fn any_amount_into_an_18_decimal_backing_passes_the_unit_rule() {
        let mut r = reg();
        let dai18 = (3u16, [0xbb; 32], 18u8);
        r.register(
            bridged_asset_id("Rand USD", "zUSD", &[0x5a; 32]),
            "Rand USD".into(),
            "zUSD".into(),
            BRIDGE_DECIMALS,
            bridge_decimals(&[dai18]),
            0,
        )
        .unwrap();
        assert_eq!(r.backing(1, dai18.0, &dai18.1).unwrap().release_unit(), 1);
        r.lock(1, dai18.0, &dai18.1, 12_345_678, 0).unwrap();
        r.release(1, dai18.0, &dai18.1, 7, 3).unwrap();
        assert_eq!(r.get(1).unwrap().total_supply, 12_345_671);
    }

    /// The unit itself, across the whole declarable range: `10^(8-d)` strictly below the wire's
    /// eight decimals, and 1 at eight and above — where the wire is already at least as precise
    /// as the coin and has no fraction to express. The largest value is `10^8`, so nothing here
    /// can wrap a `u64`.
    #[test]
    fn the_release_unit_is_ten_to_the_shortfall_and_one_at_or_above_the_wire() {
        for (decimals, unit) in
            [(0u8, 100_000_000u64), (2, 1_000_000), (6, 100), (7, 10), (8, 1), (9, 1), (18, 1)]
        {
            assert_eq!(release_unit(decimals), unit, "{decimals} decimals");
            assert_eq!(Backing { chain: 2, token: [0; 32], decimals, locked: 0, minted_today: 0, mint_day: 0 }.release_unit(), unit);
        }
        assert_eq!(release_unit(WIRE_DECIMALS), 1, "the wire's own precision needs no rounding");
        assert_eq!(WIRE_DECIMALS, BRIDGE_DECIMALS, "one figure under two names");
    }

    /// Decimals over 18 are refused at the two places a backing is ever declared: a fresh
    /// listing's [`TokenRegistry::register`] and a later [`TokenRegistry::add_backing`] — never
    /// silently accepted and left unreleasable.
    #[test]
    fn decimals_over_18_are_refused_at_register_and_add_backing() {
        let mut r = reg();
        assert_eq!(
            r.register(
                bridged_asset_id("Rand USD", "zUSD", &[0x5a; 32]),
                "Rand USD".into(),
                "zUSD".into(),
                BRIDGE_DECIMALS,
                bridge_decimals(&[(2, [0xaa; 32], 19)]),
                0,
            ),
            Err(TokenError::BadBackingDecimals(19))
        );
        assert!(r.is_empty(), "the whole listing is refused, not just the bad backing");
        let i = list_zusd(&mut r, &[USDT2]);
        assert_eq!(r.add_backing(i, 3, [0xcc; 32], 19), Err(TokenError::BadBackingDecimals(19)));
        assert!(r.backing(i, 3, &[0xcc; 32]).is_none(), "nothing was added");
        r.add_backing(i, 3, [0xcc; 32], 18).unwrap();
        assert_eq!(r.backing(i, 3, &[0xcc; 32]).unwrap().decimals, 18);
    }

    /// A pair that backs nothing, and a pair that backs a *different* token, are both
    /// `NotABacking` of the index asked about — the refusal a burn naming the wrong coin gets.
    #[test]
    fn a_pair_that_backs_nothing_or_another_token_is_not_a_backing() {
        let mut r = reg();
        let zusd = list_zusd(&mut r, &[USDT2]);
        let other = r
            .register(bridged_asset_id("Rand EUR", "zEUR", &[1; 32]), "Rand EUR".into(), "zEUR".into(), 8, bridge(&[USDC2]), 0)
            .unwrap();
        assert_eq!(
            r.lock(zusd, USDC2.0, &USDC2.1, 1, 0),
            Err(TokenError::NotABacking { index: zusd, chain: 2 }),
            "USDC backs zEUR, not zUSD"
        );
        assert_eq!(r.release(zusd, 9, &[0xff; 32], 1, 0), Err(TokenError::NotABacking { index: zusd, chain: 9 }));
        assert!(r.backing(zusd, USDC2.0, &USDC2.1).is_none());
        assert_eq!(r.backing(other, USDC2.0, &USDC2.1).unwrap().locked, 0);
        // And the many-to-one map answers each pair with its own token.
        assert_eq!(r.bridged(USDT2.0, &USDT2.1).unwrap().index, zusd);
        assert_eq!(r.bridged(USDC2.0, &USDC2.1).unwrap().index, other);
        assert!(r.bridged(9, &[0xff; 32]).is_none());
    }

    /// A `(chain, token)` pair backs at most one token in the whole registry: a second listing
    /// naming a taken pair is refused, and refused whole — nothing of it is left behind.
    #[test]
    fn a_pair_backs_at_most_one_token() {
        let mut r = reg();
        list_zusd(&mut r, &[USDT2, USDC2]);
        let again = r.register(
            bridged_asset_id("Copy USD", "cUSD", &[2; 32]),
            "Copy USD".into(),
            "cUSD".into(),
            8,
            bridge(&[(3, [0xdd; 32]), USDC2]),
            0,
        );
        assert_eq!(again, Err(TokenError::BackingTaken { chain: 2 }));
        assert_eq!(r.len(), 1, "a refused registration leaves nothing behind");
        assert!(r.bridged(3, &[0xdd; 32]).is_none(), "not even the pairs that were free");
        // The same pair twice inside one listing is the same collision.
        let twice = r.register(
            bridged_asset_id("Copy USD", "cUSD", &[2; 32]),
            "Copy USD".into(),
            "cUSD".into(),
            8,
            bridge(&[(4, [0xee; 32]), (4, [0xee; 32])]),
            0,
        );
        assert_eq!(twice, Err(TokenError::BackingTaken { chain: 4 }));
    }

    /// One to [`MAX_BACKINGS`] backings, both edges refused.
    #[test]
    fn a_bridged_token_needs_one_backing_and_takes_at_most_thirty_two() {
        let mut r = reg();
        assert_eq!(list_zusd_result(&mut r, &[]), Err(TokenError::NoBackings));
        let many: Vec<(u16, [u8; 32])> = (0..MAX_BACKINGS as u16 + 1).map(|i| (i, [i as u8; 32])).collect();
        assert_eq!(list_zusd_result(&mut r, &many), Err(TokenError::TooManyBackings));
        assert_eq!(list_zusd_result(&mut r, &many[..MAX_BACKINGS]), Ok(1), "exactly the cap is fine");
        assert_eq!(
            r.add_backing(1, 99, [99; 32], BRIDGE_DECIMALS),
            Err(TokenError::TooManyBackings),
            "and a token at the cap takes no more"
        );
    }

    fn list_zusd_result(r: &mut TokenRegistry, pairs: &[(u16, [u8; 32])]) -> Result<u32, TokenError> {
        r.register(
            bridged_asset_id("Rand USD", "zUSD", &[9; 32]),
            "Rand USD".into(),
            "zUSD".into(),
            BRIDGE_DECIMALS,
            bridge(pairs),
            0,
        )
    }

    /// `lock`/`release` are the only way a bridged token's supply moves: a direct `add_supply`
    /// or `sub_supply` is refused, because it would move supply without moving a backing and
    /// break `total_supply == Σ locked` on the spot.
    #[test]
    fn a_bridged_tokens_supply_moves_only_through_its_backings() {
        let mut r = reg();
        let i = list_zusd(&mut r, &[USDT2]);
        assert_eq!(r.add_supply(i, 1), Err(TokenError::BridgedToken(i)));
        assert_eq!(r.sub_supply(i, 1), Err(TokenError::BridgedToken(i)));
        assert_eq!(r.get(i).unwrap().total_supply, 0);
        // A native token is unaffected: its supply is exactly `add_supply`/`sub_supply`'s to move.
        let n = r.register(id(5), "Native".into(), "NTV".into(), 9, MintAuthority::None, 0).unwrap();
        r.add_supply(n, 10).unwrap();
        assert_eq!(r.get(n).unwrap().total_supply, 10);
        assert!(r.backing_invariant_holds());
    }

    /// `backing_of` is persisted with the registry rather than rebuilt on load, so it has to be
    /// exactly the map the tokens themselves describe.
    #[test]
    fn the_backing_index_is_the_map_the_tokens_describe() {
        let mut r = reg();
        list_zusd(&mut r, &[USDT2, USDC2, (5, [0xcc; 32])]);
        r.register(bridged_asset_id("Rand EUR", "zEUR", &[1; 32]), "Rand EUR".into(), "zEUR".into(), 8, bridge(&[(3, [1; 32])]), 0)
            .unwrap();
        r.register(id(5), "Native".into(), "NTV".into(), 9, MintAuthority::None, 0).unwrap();
        r.add_backing(1, 4, [0xdd; 32], BRIDGE_DECIMALS).unwrap();
        let rebuilt: BTreeMap<(u16, [u8; 32]), u32> = r
            .iter()
            .flat_map(|info| match &info.authority {
                MintAuthority::Bridge { backings } => {
                    backings.iter().map(|b| ((b.chain, b.token), info.index)).collect::<Vec<_>>()
                }
                _ => Vec::new(),
            })
            .collect();
        assert_eq!(r.backing_of, rebuilt);
        assert_eq!(rebuilt.len(), 5);
        // And it survives the bincode round trip storage keeps the registry in.
        let back: TokenRegistry = bincode::deserialize(&bincode::serialize(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.bridged(4, &[0xdd; 32]).unwrap().index, 1);
    }

    /// `add_backing` extends a listed token (Task 10's governance message, and the only way a
    /// pair joins a token after genesis). It refuses a taken pair, an unknown index and a token
    /// that is not bridged, and the new backing starts unlocked.
    #[test]
    fn add_backing_extends_a_listed_token() {
        let mut r = reg();
        let i = list_zusd(&mut r, &[USDT2]);
        let n = r.register(id(5), "Native".into(), "NTV".into(), 9, MintAuthority::None, 0).unwrap();
        r.add_backing(i, 4, [0xdd; 32], BRIDGE_DECIMALS).unwrap();
        assert_eq!(r.backing(i, 4, &[0xdd; 32]).unwrap().locked, 0);
        assert_eq!(r.bridged(4, &[0xdd; 32]).unwrap().index, i);
        assert_eq!(r.add_backing(i, USDT2.0, USDT2.1, BRIDGE_DECIMALS), Err(TokenError::BackingTaken { chain: 2 }));
        assert_eq!(r.add_backing(9, 6, [6; 32], BRIDGE_DECIMALS), Err(TokenError::UnknownToken(9)));
        assert_eq!(r.add_backing(n, 6, [6; 32], BRIDGE_DECIMALS), Err(TokenError::AuthorityNotAllowed));
        assert!(r.backing_invariant_holds());
    }

    /// A bridged token's id is over its *registration* fields — name, symbol, the eight decimals
    /// every bridged token has, and a salt — and never over its backings, which grow. The
    /// per-backing `crate::bridge::asset_id` stays what it was, as the wire id.
    #[test]
    fn a_bridged_id_binds_its_registration_fields_and_not_its_backings() {
        let a = bridged_asset_id("Rand USD", "zUSD", &[9; 32]);
        assert_eq!(a, bridged_asset_id("Rand USD", "zUSD", &[9; 32]));
        assert_ne!(a, bridged_asset_id("Rand USD", "zUSD", &[8; 32]), "the salt");
        assert_ne!(a, bridged_asset_id("Rand USD", "zUSDx", &[9; 32]), "the symbol");
        assert_ne!(a, bridged_asset_id("Rand Dollar", "zUSD", &[9; 32]), "the name");
        assert_ne!(a, crate::bridge::asset_id(2, &[0xaa; 32]), "not the per-backing wire id");
        // Two tokens differing only in salt are two registrations, and both list.
        let mut r = reg();
        r.register(a, "Rand USD".into(), "zUSD".into(), 8, bridge(&[USDT2]), 0).unwrap();
        r.register(bridged_asset_id("Rand USD", "zUSD", &[8; 32]), "Rand USD".into(), "zUSD".into(), 8, bridge(&[USDC2]), 0)
            .unwrap();
        assert_eq!(r.get_by_id(&a).unwrap().index, 1);
        assert_eq!(r.len(), 2);
    }

    /// Both directions are checked, and a refused move leaves the registry exactly as it was —
    /// which is what lets validate pre-check and apply stay infallible.
    #[test]
    fn lock_and_release_are_checked_both_ways() {
        let mut r = reg();
        let i = list_zusd(&mut r, &[USDT2, USDC2]);
        r.lock(i, USDT2.0, &USDT2.1, u64::MAX, 0).unwrap();
        assert_eq!(r.lock(i, USDT2.0, &USDT2.1, 1, 0), Err(TokenError::SupplyOverflow), "the backing");
        assert_eq!(r.lock(i, USDC2.0, &USDC2.1, 1, 0), Err(TokenError::SupplyOverflow), "and the supply");
        assert_eq!(r.get(i).unwrap().total_supply, u64::MAX);
        assert_eq!(r.backing(i, USDC2.0, &USDC2.1).unwrap().locked, 0, "a refused lock moved nothing");
        assert_eq!(r.lock(7, 2, &[0; 32], 1, 0), Err(TokenError::UnknownToken(7)));
        assert_eq!(r.release(7, 2, &[0; 32], 1, 0), Err(TokenError::UnknownToken(7)));
        r.release(i, USDT2.0, &USDT2.1, u64::MAX, 0).unwrap();
        assert_eq!(r.release(i, USDT2.0, &USDT2.1, 1, 0), Err(TokenError::InsufficientBacking { locked: 0, amount: 1 }));
        assert!(r.backing_invariant_holds());
    }

    /// A registration starts at zero supply, so the backings it is listed with start unlocked
    /// whatever the caller passed — the invariant is true from the first block by construction.
    #[test]
    fn a_listing_starts_every_backing_unlocked() {
        let mut r = reg();
        r.register(
            bridged_asset_id("Rand USD", "zUSD", &[9; 32]),
            "Rand USD".into(),
            "zUSD".into(),
            8,
            MintAuthority::Bridge { backings: vec![Backing { chain: 2, token: [0xaa; 32], decimals: BRIDGE_DECIMALS, locked: 7, minted_today: 0, mint_day: 0 }] },
            0,
        )
        .unwrap();
        assert_eq!(r.backing(1, 2, &[0xaa; 32]).unwrap().locked, 0);
        assert_eq!(r.get(1).unwrap().total_supply, 0);
        assert!(r.backing_invariant_holds());
    }

    /// Only a `Bridge` registration writes into the backing map, so [`TokenRegistry::bridged`] —
    /// the one lookup an attestation resolves through — can never reach a token of another
    /// authority, whatever id that token happens to be registered under.
    ///
    /// This is the asymmetry the pre-amendment registry had: `bridged` was
    /// `get_by_id(bridge::asset_id(chain, token))`, so a token registered under *that* id with a
    /// `Key` authority would have answered an attestation while a burn of it was refused
    /// (`check_burn` demanded a `Bridge`). Here the collision is constructed on purpose.
    #[test]
    fn only_a_bridge_registration_can_be_reached_by_a_coin() {
        let mut r = reg();
        let pk = crate::crypto::Keypair::from_seed([3; 32]).unwrap().public_key().clone();
        // Registered under exactly the id the bridge computes for `(2, [0xaa; 32])`, and with a
        // key authority: the pair the old lookup would have hashed to it.
        let colliding = crate::bridge::asset_id(2, &[0xaa; 32]);
        let n = r.register(colliding, "Native".into(), "NTV".into(), 9, MintAuthority::Key(pk), 0).unwrap();
        assert_eq!(r.get_by_id(&colliding).unwrap().index, n, "it is in the registry by id");
        assert!(r.bridged(2, &[0xaa; 32]).is_none(), "and unreachable by the coin");
        assert!(r.backing(n, 2, &[0xaa; 32]).is_none());
        assert_eq!(r.lock(n, 2, &[0xaa; 32], 1, 0), Err(TokenError::NotABacking { index: n, chain: 2 }));
        assert_eq!(r.check_lock(n, 2, &[0xaa; 32], 1, 0), Err(TokenError::NotABacking { index: n, chain: 2 }));
        // And once the coin really does back a bridged token, it resolves to that one.
        let zusd = list_zusd(&mut r, &[(2, [0xaa; 32])]);
        assert_eq!(r.bridged(2, &[0xaa; 32]).unwrap().index, zusd);
        assert_ne!(zusd, n);
    }

    /// A bridged token's authority is not re-keyable: rotating it to a key would orphan its
    /// backings and leave `backing_of` pointing at a token that no longer has any. Nor is a
    /// renounced (`None`) one: there is no key left to sign the rotation. Both are *refused*
    /// rather than ignored — a silent no-op here would let a `SetAuthority` take a fee and
    /// change nothing.
    #[test]
    fn only_a_key_authority_can_be_rotated() {
        let mut r = reg();
        let i = list_zusd(&mut r, &[USDT2]);
        let pk = crate::crypto::Keypair::from_seed([1; 32]).unwrap().public_key().clone();
        assert_eq!(r.set_key(i, Some(pk.clone())), Err(TokenError::NotKeyAuthority(i)));
        assert!(matches!(r.get(i).unwrap().authority, MintAuthority::Bridge { .. }));
        assert_eq!(r.set_key(i, None), Err(TokenError::NotKeyAuthority(i)));
        assert!(matches!(r.get(i).unwrap().authority, MintAuthority::Bridge { .. }));
        assert_eq!(r.bridged(USDT2.0, &USDT2.1).unwrap().index, i);

        // A fixed-supply token has no key either, so it stays fixed forever.
        let fixed = r.register(id(9), "Fixed".into(), "FIX".into(), 0, MintAuthority::None, 0).unwrap();
        assert_eq!(r.set_key(fixed, Some(pk.clone())), Err(TokenError::NotKeyAuthority(fixed)));
        assert!(matches!(r.get(fixed).unwrap().authority, MintAuthority::None));

        // And a `Key` token rotates both ways: to another key, and to `None` for good.
        let keyed = r.register(id(8), "Keyed".into(), "KEY".into(), 0, MintAuthority::Key(pk.clone()), 0).unwrap();
        let other = crate::crypto::Keypair::from_seed([2; 32]).unwrap().public_key().clone();
        r.set_key(keyed, Some(other.clone())).unwrap();
        assert_eq!(r.get(keyed).unwrap().authority, MintAuthority::Key(other));
        r.set_key(keyed, None).unwrap();
        assert!(matches!(r.get(keyed).unwrap().authority, MintAuthority::None));
        assert_eq!(r.set_key(keyed, Some(pk)), Err(TokenError::NotKeyAuthority(keyed)), "renouncing is final");
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The five RPL actions through the ledger (spec §4)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod action_tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::{Keypair, Signature};
    use crate::gas;
    use crate::ledger::{Ledger, TxError, ValidatorEntry, TIME_WINDOW};
    use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8};
    use crate::types::actions::{set_authority_message, token_mint_message, InitialMint};
    use crate::types::{Action, Transaction};

    const HC: Word8 = [11; 8];
    const CHAIN: u64 = 7;
    /// The registration fee the test chain charges, on top of the bundle base.
    const REG_FEE: u64 = 1_000_000_000;

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
    }

    fn proposer() -> Keypair {
        Keypair::from_seed([1; 32]).unwrap()
    }

    /// The token issuer's key: the `Key` mint authority every test below registers under.
    fn issuer() -> Keypair {
        Keypair::from_seed([21; 32]).unwrap()
    }

    fn recipient() -> ShieldedAddress {
        ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] }
    }

    /// A ledger at height 1 with the `tokens` gate on and an empty registry.
    fn ledger() -> Ledger {
        let k = proposer();
        let entry = ValidatorEntry {
            public_key: k.public_key().clone(),
            stake: 10,
            pending: Vec::new(),
            rewards: 0,
            payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
            nonce: 0,
        };
        let mut l = Ledger::new(CHAIN, HC, [(k.address(), entry)].into_iter().collect(), &StubExecutor);
        l.set_tokens(Some(TokenRegistry::new(REG_FEE)));
        l.set_height(1);
        l.set_timestamp_ms(1_000_000);
        l
    }

    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes, with its
    /// first two nullifiers and commitments at `seed..seed + 3` (the other two slots derived from
    /// them, `notes::pad4`), burning `burn_a` of `burn_asset` (`0, 0` for no burn).
    fn bundle(l: &Ledger, seed: u32, fee: u64, burn_asset: u32, burn_a: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.anchors().back().expect("the genesis anchor").1,
            nullifiers: crate::notes::pad4([[seed; 8], [seed + 1; 8]]),
            commitments: crate::notes::pad4([[seed + 2; 8], [seed + 3; 8]]),
            fee,
            burn_a,
            burn_r: 0,
            burn_asset,
            time: l.height() as u32,
            envelopes: [env(), env(), env(), env()],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
        b
    }

    /// A bundle burning nothing, paying `fee`, keyed at `seed`.
    fn fee_bundle(l: &Ledger, seed: u32, fee: u64) -> Bundle {
        bundle(l, seed, fee, 0, 0)
    }

    /// The initial mint a registration carries: `amount` to [`recipient`], stamped at the
    /// ledger's height.
    fn initial(l: &Ledger, amount: u64) -> InitialMint {
        InitialMint { amount, recipient: recipient(), r: [7; 8], time: l.height() as u32, envelope: env() }
    }

    /// A `RegisterToken` transaction for "Test Coin"/"TST", paying the base plus the registration
    /// fee, naming the registry's own next index.
    fn register_tx(l: &Ledger, authority: MintAuthority, initial: Option<InitialMint>, seed: u32) -> Transaction {
        register_tx_at(l, authority, initial, seed, l.tokens().unwrap().next_index(), gas::BUNDLE_BASE + REG_FEE)
    }

    /// [`register_tx`] with the claimed `index` and the fee chosen.
    fn register_tx_at(
        l: &Ledger,
        authority: MintAuthority,
        initial: Option<InitialMint>,
        seed: u32,
        index: u32,
        fee: u64,
    ) -> Transaction {
        StubExecutor::bound(Transaction::shielded(
            CHAIN,
            fee_bundle(l, seed, fee),
            Action::RegisterToken {
                name: "Test Coin".into(),
                symbol: "TST".into(),
                decimals: 6,
                authority,
                initial,
                salt: [3; 32],
                index,
            },
        ))
    }

    /// The asset id `register_tx`'s registration lands under, with the whole initial mint in it.
    fn tst_id(authority: &MintAuthority, initial: &Option<InitialMint>) -> AssetId {
        native_asset_id("Test Coin", "TST", 6, authority, initial, &[3; 32])
    }

    /// The id a `RegisterToken` transaction registers under, read off the action itself — which
    /// is what makes the redirect test able to compare two transactions rather than two
    /// hand-built field lists.
    fn id_of(tx: &Transaction) -> AssetId {
        let Action::RegisterToken { name, symbol, decimals, authority, initial, salt, .. } = &tx.action else {
            panic!("a registration")
        };
        native_asset_id(name, symbol, *decimals, authority, initial, salt)
    }

    /// Registers "Test Coin" under `issuer()`'s key with no initial mint, returning its index.
    fn register_keyed(l: &mut Ledger, seed: u32) -> u32 {
        let authority = MintAuthority::Key(issuer().public_key().clone());
        let tx = register_tx(l, authority, Some(initial(l, 1_000)), seed);
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).expect("a fresh registration");
        l.tokens().unwrap().next_index() - 1
    }

    /// A `TokenMint` of `amount` of `asset`, signed by `signer` over chain `chain_id` at `nonce`.
    #[allow(clippy::too_many_arguments)]
    fn mint_tx_signed(
        l: &Ledger,
        asset: u32,
        amount: u64,
        nonce: u64,
        seed: u32,
        signer: &Keypair,
        chain_id: u64,
        r: Word8,
    ) -> Transaction {
        let time = l.height() as u32;
        let cm = mint_commitment(&recipient(), amount, asset, time, &r, &StubExecutor);
        let id = l.tokens().unwrap().get(asset).map(|i| i.id).unwrap_or(crate::crypto::Hash::ZERO);
        let signature = signer.sign(token_mint_message(chain_id, &id, nonce, amount, &cm, &env()).as_bytes());
        StubExecutor::bound(Transaction::shielded(
            CHAIN,
            fee_bundle(l, seed, gas::BUNDLE_BASE),
            Action::TokenMint {
                asset,
                amount,
                recipient: recipient(),
                r,
                time,
                envelope: env(),
                nonce,
                signature,
            },
        ))
    }

    /// The honest mint: this chain, the issuer's key, the register's nonce.
    fn mint_tx(l: &Ledger, asset: u32, amount: u64, nonce: u64, seed: u32) -> Transaction {
        mint_tx_signed(l, asset, amount, nonce, seed, &issuer(), CHAIN, [9; 8])
    }

    /// A `SetAuthority` on `asset`, signed by `signer`.
    fn rotate_tx(
        l: &Ledger,
        asset: u32,
        new: Option<crate::crypto::PublicKey>,
        nonce: u64,
        seed: u32,
        signer: &Keypair,
    ) -> Transaction {
        let id = l.tokens().unwrap().get(asset).map(|i| i.id).unwrap_or(crate::crypto::Hash::ZERO);
        let signature = signer.sign(set_authority_message(CHAIN, &id, nonce, &new).as_bytes());
        StubExecutor::bound(Transaction::shielded(
            CHAIN,
            fee_bundle(l, seed, gas::BUNDLE_BASE),
            Action::SetAuthority { asset, new, nonce, signature },
        ))
    }

    fn tok(e: TokenError) -> TxError {
        TxError::Token(e)
    }

    /// What a `TokenBurn` pays: one bundle's base (the hidden-asset bundle, spec §3.7 — no
    /// longer two).
    const BURN_FEE: u64 = gas::BUNDLE_BASE;

    /// A token transfer as the chain sees it since the hidden-asset bundle: a plain
    /// `Action::None` bundle, burning nothing, the token's index nowhere in it.
    fn transfer_tx(l: &Ledger, seed: u32) -> Transaction {
        StubExecutor::bound(Transaction::shielded(CHAIN, fee_bundle(l, seed, gas::BUNDLE_BASE), Action::None))
    }

    /// A `TokenBurn` of `amount` of `asset` on one bundle keyed at `seed`, publishing
    /// `burn_asset == asset` and `burn_a == amount`. `mutate` edits the bundle after its proof
    /// was made, which is what makes "refused before any proof work" observable.
    fn burn_tx(l: &Ledger, asset: u32, amount: u64, seed: u32, mutate: impl FnOnce(&mut Bundle)) -> Transaction {
        let mut b = bundle(l, seed, BURN_FEE, asset, amount);
        mutate(&mut b);
        StubExecutor::bound(Transaction::shielded(CHAIN, b, Action::TokenBurn { asset, amount }))
    }

    /// USDT on chain 2, the one coin behind the bridged token the tests below list.
    const USDT: [u8; 32] = [0xd7; 32];

    /// Lists a `Bridge`-authority token backed by [`USDT`] and locks `supply` of it, returning its
    /// index — the shape a bridged chain's genesis leaves behind, built directly because no RPL
    /// action may create one.
    fn list_bridged(l: &mut Ledger, supply: u64) -> u32 {
        let registry = l.tokens_mut().expect("the gate is on");
        let index = registry
            .register(
                bridged_asset_id("Rand USD", "zUSD", &[0x5a; 32]),
                "Rand USD".into(),
                "zUSD".into(),
                BRIDGE_DECIMALS,
                MintAuthority::Bridge { backings: vec![Backing { chain: 2, token: USDT, decimals: BRIDGE_DECIMALS, locked: 0, minted_today: 0, mint_day: 0 }] },
                1,
            )
            .expect("a fresh listing");
        registry.lock(index, 2, &USDT, supply, 0).expect("a deposit of the listed coin");
        index
    }

    // ── RegisterToken ────────────────────────────────────────────────────────────────────────

    /// The whole registration path: the next index is handed out, the metadata is what the action
    /// declared, the initial mint is one chain-computed note in the tree beside the fee bundle's
    /// two, the supply is the amount minted, and the state root moved.
    #[test]
    fn a_registration_takes_the_next_index_and_mints_its_initial_note() {
        let mut l = ledger();
        let before = l.state_root();
        let authority = MintAuthority::Key(issuer().public_key().clone());
        let tx = register_tx(&l, authority.clone(), Some(initial(&l, 1_000)), 20);
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();

        let info = l.tokens().unwrap().get(1).expect("index 1, the first one handed out");
        assert_eq!((info.name.as_str(), info.symbol.as_str(), info.decimals), ("Test Coin", "TST", 6));
        assert_eq!(info.id, tst_id(&authority, &Some(initial(&l, 1_000))), "the id binds every registration field");
        assert_eq!(info.authority, authority);
        assert_eq!((info.total_supply, info.mint_nonce, info.registered_at), (1_000, 0, 1));
        assert_eq!(l.tokens().unwrap().next_index(), 2, "and the index is spent");

        // The bundle's four notes plus exactly one mint note.
        assert_eq!(l.next_index(), 5);
        let cm = mint_commitment(&recipient(), 1_000, 1, 1, &[7; 8], &StubExecutor);
        assert!(l.has_commitment(&cm), "the note the creator sealed its envelope against");
        assert_ne!(l.state_root(), before);
    }

    /// A fixed-supply token: no key, so everything it will ever be worth is minted at
    /// registration — and a registration without that mint is refused.
    #[test]
    fn a_fixed_supply_token_must_mint_at_registration() {
        let mut l = ledger();
        let bare = register_tx(&l, MintAuthority::None, None, 20);
        assert_eq!(l.validate(&bare, &StubExecutor), Err(tok(TokenError::InitialMintRequired)));
        let tx = register_tx(&l, MintAuthority::None, Some(initial(&l, 500)), 30);
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 500);
        // And a `Key` token may register with no initial supply at all.
        let keyed = register_tx(&l, MintAuthority::Key(issuer().public_key().clone()), None, 40);
        assert_eq!(l.validate(&keyed, &StubExecutor), Ok(()));
    }

    /// Only `None` and `Key` may be chosen by a registration: a bridged token is *listed* by
    /// genesis or governance, and `Program` is reserved.
    #[test]
    fn a_registration_may_not_choose_a_bridge_or_program_authority() {
        let l = ledger();
        let bridge = MintAuthority::Bridge { backings: vec![Backing { chain: 2, token: [0xaa; 32], decimals: BRIDGE_DECIMALS, locked: 0, minted_today: 0, mint_day: 0 }] };
        for authority in [bridge, MintAuthority::Program(crate::crypto::Hash([5; 32]))] {
            let tx = register_tx(&l, authority.clone(), Some(initial(&l, 5)), 20);
            assert_eq!(l.validate(&tx, &StubExecutor), Err(tok(TokenError::AuthorityNotAllowed)), "{authority:?}");
        }
    }

    /// The metadata rules are the registry's own, reported through the action.
    #[test]
    fn a_registration_checks_its_metadata() {
        let l = ledger();
        let bad = |name: &str, symbol: &str, decimals: u8| {
            let mut tx = register_tx(&l, MintAuthority::None, Some(initial(&l, 5)), 20);
            let Action::RegisterToken { name: n, symbol: s, decimals: d, .. } = &mut tx.action else {
                panic!("a registration")
            };
            (*n, *s, *d) = (name.into(), symbol.into(), decimals);
            l.validate(&tx, &StubExecutor)
        };
        assert_eq!(bad("", "TST", 6), Err(tok(TokenError::BadName)));
        assert_eq!(bad("Test Coin", "has space", 6), Err(tok(TokenError::BadSymbol)));
        assert_eq!(bad("Test Coin", "TST", 10), Err(tok(TokenError::TooManyDecimals(10))));
    }

    /// A zero initial mint would append a note worth nothing and put a zero-supply token's id on
    /// a supply it never had.
    #[test]
    fn a_zero_initial_mint_is_refused() {
        let l = ledger();
        let tx = register_tx(&l, MintAuthority::None, Some(initial(&l, 0)), 20);
        assert_eq!(l.validate(&tx, &StubExecutor), Err(tok(TokenError::ZeroAmount)));
    }

    /// The asset id is content-addressed, so the identical registration twice is the same asset —
    /// and the second is refused rather than handed a second index.
    #[test]
    fn the_same_registration_twice_is_already_registered() {
        let mut l = ledger();
        let tx = register_tx(&l, MintAuthority::None, Some(initial(&l, 5)), 20);
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        let again = register_tx_at(&l, MintAuthority::None, Some(initial(&l, 5)), 30, 2, gas::BUNDLE_BASE + REG_FEE);
        assert_eq!(
            l.validate(&again, &StubExecutor),
            Err(tok(TokenError::AlreadyRegistered(tst_id(&MintAuthority::None, &Some(initial(&l, 5))))))
        );
    }

    /// `index` is the index the creator sealed its initial note for, and the chain holds it to
    /// the index it is actually about to hand out — `BridgeAttest.asset`'s rule: a lost race
    /// costs a re-proof, never a note nobody can open. Checked with and without an initial mint.
    #[test]
    fn a_registration_naming_the_wrong_index_is_refused() {
        let mut l = ledger();
        for (claimed, has_initial) in [(2u32, true), (0, true), (7, false)] {
            let init = has_initial.then(|| initial(&l, 5));
            let tx = register_tx_at(&l, MintAuthority::Key(issuer().public_key().clone()), init, 20, claimed, gas::BUNDLE_BASE + REG_FEE);
            assert_eq!(
                l.validate(&tx, &StubExecutor),
                Err(tok(TokenError::IndexMismatch { expected: 1, got: claimed })),
                "claimed {claimed}"
            );
        }
        // The index the registry names is the one that is accepted, and it moves with each
        // registration: the same transaction that was right at index 1 is wrong at index 2.
        let first = register_tx(&l, MintAuthority::None, Some(initial(&l, 5)), 30);
        l.apply_tx(&first, &proposer().address(), &StubExecutor).unwrap();
        let stale = register_tx_at(&l, MintAuthority::Key(issuer().public_key().clone()), Some(initial(&l, 6)), 40, 1, gas::BUNDLE_BASE + REG_FEE);
        assert_eq!(l.validate(&stale, &StubExecutor), Err(tok(TokenError::IndexMismatch { expected: 2, got: 1 })));
    }

    /// The registration fee is a ledger fact — the registry's `registration_fee` — so it is
    /// checked here rather than by `gas::fee_floor`, which has no ledger to read.
    #[test]
    fn a_registration_pays_the_bundle_base_plus_the_registry_fee() {
        let l = ledger();
        let min = gas::BUNDLE_BASE + REG_FEE;
        let short = register_tx_at(&l, MintAuthority::None, Some(initial(&l, 5)), 20, 1, min - 1);
        assert_eq!(
            l.validate(&short, &StubExecutor),
            Err(tok(TokenError::RegistrationFeeTooLow { min, fee: min - 1 }))
        );
        let exact = register_tx_at(&l, MintAuthority::None, Some(initial(&l, 5)), 30, 1, min);
        assert_eq!(l.validate(&exact, &StubExecutor), Ok(()), "exactly the floor is enough");
        // The bundle base alone is still the floor `gas::fee_floor` reports, so a fee under *it*
        // is refused before this action is reached at all.
        let under_base = register_tx_at(&l, MintAuthority::None, Some(initial(&l, 5)), 40, 1, gas::BUNDLE_BASE - 1);
        assert_eq!(
            l.validate(&under_base, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::BUNDLE_BASE, fee: gas::BUNDLE_BASE - 1 })
        );
    }

    /// The initial note's `time` is the creator's, sealed against before the transaction was
    /// submitted, so it gets the window every note-stamping `time` gets.
    #[test]
    fn an_initial_mint_outside_the_time_window_is_refused() {
        let mut l = ledger();
        let height = TIME_WINDOW + 20;
        l.set_height(height);
        l.record_anchor(height);
        let at = |time: u32| {
            let mut m = initial(&l, 5);
            m.time = time;
            let tx = register_tx(&l, MintAuthority::None, Some(m), 20);
            l.validate(&tx, &StubExecutor)
        };
        let oldest = (height - TIME_WINDOW) as u32;
        assert_eq!(at(height as u32 + 1), Err(TxError::TimeOutOfWindow { time: height as u32 + 1, height }));
        assert_eq!(at(oldest - 1), Err(TxError::TimeOutOfWindow { time: oldest - 1, height }));
        assert_eq!(at(oldest), Ok(()));
    }

    /// The attack the amended id formula closes (spec §3, amended 2026-09-19): a `RegisterToken`
    /// carries no signature, so an observer can lift a pending registration off gossip, swap one
    /// field of its initial mint, attach a fee bundle of its own (the transaction binding keeps the
    /// creator's from riding the copy, not the observer's own) and race it. With the **whole** `InitialMint` in the asset
    /// id, the redirected copy is a *different* token: it cannot take the original's id, the
    /// original is never `AlreadyRegistered`, and only the index it claimed is gone — which costs
    /// a re-issue at the next index and nothing else. The original's supply still lands on the
    /// original's recipient.
    ///
    /// Run for each of the three fields that are outside the note's `amount`: the recipient (the
    /// theft), the blinding and the envelope (which would strand or grief the note).
    #[test]
    fn a_redirected_registration_is_a_different_token_and_cannot_take_the_originals_id() {
        let attacker = ShieldedAddress { pk: [66; 8], kem_ek: vec![6; 32] };
        for field in ["recipient", "r", "envelope"] {
            let mut l = ledger();
            // What the creator built and gossiped: a fixed-supply token, where a stolen initial
            // mint would be the entire supply for ever.
            let honest = register_tx(&l, MintAuthority::None, Some(initial(&l, 1_000)), 20);
            let mut stolen = register_tx(&l, MintAuthority::None, Some(initial(&l, 1_000)), 30);
            let Action::RegisterToken { initial: Some(m), .. } = &mut stolen.action else { panic!("a registration") };
            match field {
                "recipient" => m.recipient = attacker.clone(),
                "r" => m.r = [0x5a; 8],
                _ => {
                    m.envelope =
                        Envelope { kem_ct: vec![9; 8], to_receiver: vec![], to_sender: vec![], body: vec![9; 8] }
                }
            }
            assert_ne!(id_of(&honest), id_of(&stolen), "{field}: a redirected copy is a different token");
            // Since the transaction binding (Task 5b) the creator's own fee bundle cannot ride the
            // copy — its proof is bound to the original — so the attacker proves a fee bundle of
            // its own for the copy, which it can: those are its notes. The id formula is what is
            // left standing between that copy and the original's identity.
            StubExecutor::bind(&mut stolen);

            // The copy wins the race and takes index 1 — under *its own* id.
            l.apply_tx(&stolen, &proposer().address(), &StubExecutor).expect("the copy is a valid registration");
            assert_eq!(l.tokens().unwrap().get(1).unwrap().id, id_of(&stolen), "{field}");
            assert_ne!(l.tokens().unwrap().get(1).unwrap().id, id_of(&honest), "{field}: not the original's id");

            // The original is not dead: the only thing stopping it is the index it named, which
            // is what `IndexMismatch` exists to say. `AlreadyRegistered` would be the theft.
            assert_eq!(
                l.validate(&honest, &StubExecutor),
                Err(tok(TokenError::IndexMismatch { expected: 2, got: 1 })),
                "{field}"
            );

            // Re-issued at the index that is now next, it registers under its own id and the
            // supply lands on the *original* recipient.
            let reissued = register_tx(&l, MintAuthority::None, Some(initial(&l, 1_000)), 40);
            assert_eq!(id_of(&reissued), id_of(&honest), "{field}: the index is not part of the id");
            assert_eq!(l.validate(&reissued, &StubExecutor), Ok(()), "{field}");
            l.apply_tx(&reissued, &proposer().address(), &StubExecutor).unwrap();
            assert_eq!(l.tokens().unwrap().get(2).unwrap().id, id_of(&honest), "{field}");
            assert_eq!(l.tokens().unwrap().get(2).unwrap().total_supply, 1_000);
            assert!(
                l.has_commitment(&mint_commitment(&recipient(), 1_000, 2, 1, &[7; 8], &StubExecutor)),
                "{field}: the original recipient holds the original's supply"
            );
            // And what the attacker took is its own token's supply, at its own index — never the
            // original's.
            if field == "recipient" {
                assert!(l.has_commitment(&mint_commitment(&attacker, 1_000, 1, 1, &[7; 8], &StubExecutor)));
                assert!(!l.has_commitment(&mint_commitment(&attacker, 1_000, 2, 1, &[7; 8], &StubExecutor)));
            }
        }
    }

    /// The registry's last index, through the action: `RegistryFull` before the index compare,
    /// so a chain that has handed out four billion indices says what is actually wrong.
    #[test]
    fn a_registration_is_refused_when_the_registry_is_full() {
        let mut l = ledger();
        // `next_index` is private to this module; `action_tests` is a child of it and can drive
        // the registry to its last index without registering four billion tokens.
        l.tokens_mut().unwrap().next_index = u32::MAX;
        let tx = register_tx(&l, MintAuthority::None, Some(initial(&l, 5)), 20);
        assert_eq!(l.validate(&tx, &StubExecutor), Err(tok(TokenError::RegistryFull)));
        assert_eq!(l.tokens().unwrap().len(), 0, "and nothing was registered");
    }

    /// The initial note is a leaf like any other: one that is already in the tree cannot be
    /// appended again.
    #[test]
    fn an_initial_mint_of_a_note_already_in_the_tree_is_refused() {
        let mut l = ledger();
        let cm = mint_commitment(&recipient(), 5, 1, 1, &[7; 8], &StubExecutor);
        l.deposit(cm, &StubExecutor).unwrap();
        let tx = register_tx(&l, MintAuthority::None, Some(initial(&l, 5)), 20);
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::CommitmentExists(cm)));
    }

    // ── TokenMint ────────────────────────────────────────────────────────────────────────────

    /// A key-authorised mint: one chain-computed note, the supply up by the amount, the nonce
    /// spent, and the state root moved.
    #[test]
    fn a_key_authority_mints_one_note_and_raises_the_supply() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let leaves = l.next_index();
        let before = l.state_root();
        let tx = mint_tx(&l, asset, 250, 0, 30);
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        let cm = mint_commitment(&recipient(), 250, asset, 1, &[9; 8], &StubExecutor);
        assert!(l.has_commitment(&cm));
        assert_eq!(l.next_index(), leaves + 5, "the bundle's four notes and exactly one mint");
        let info = l.tokens().unwrap().get(asset).unwrap();
        assert_eq!((info.total_supply, info.mint_nonce), (1_250, 1));
        assert_ne!(l.state_root(), before);
    }

    /// A mint is only ever a `Key` authority's: a fixed-supply token, a bridged one and an
    /// unregistered index each answer for themselves.
    #[test]
    fn only_a_key_authority_can_mint() {
        let mut l = ledger();
        let fixed = {
            let tx = register_tx(&l, MintAuthority::None, Some(initial(&l, 5)), 20);
            l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
            // The index the registry actually handed out, not a literal that would keep agreeing
            // with itself if the registration had landed somewhere else.
            let index = l.tokens().unwrap().next_index() - 1;
            assert!(matches!(l.tokens().unwrap().get(index).unwrap().authority, MintAuthority::None));
            index
        };
        assert_eq!(
            l.validate(&mint_tx(&l, fixed, 1, 0, 30), &StubExecutor),
            Err(tok(TokenError::NotKeyAuthority(fixed)))
        );
        // A bridged token's supply moves only through its backings.
        let bridged = l
            .tokens_mut()
            .unwrap()
            .register(
                bridged_asset_id("Rand USD", "zUSD", &[9; 32]),
                "Rand USD".into(),
                "zUSD".into(),
                BRIDGE_DECIMALS,
                MintAuthority::Bridge { backings: vec![Backing { chain: 2, token: [0xaa; 32], decimals: BRIDGE_DECIMALS, locked: 0, minted_today: 0, mint_day: 0 }] },
                1,
            )
            .unwrap();
        assert_eq!(
            l.validate(&mint_tx(&l, bridged, 1, 0, 40), &StubExecutor),
            Err(tok(TokenError::NotKeyAuthority(bridged)))
        );
        assert_eq!(l.validate(&mint_tx(&l, 99, 1, 0, 50), &StubExecutor), Err(tok(TokenError::UnknownToken(99))));
    }

    /// The rules a mint's own fields have to pass: a non-zero amount, the register's nonce, the
    /// window, a supply that still fits, and a note nobody has already created.
    #[test]
    fn a_mints_amount_nonce_window_and_note_are_all_checked() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        assert_eq!(l.validate(&mint_tx(&l, asset, 0, 0, 30), &StubExecutor), Err(tok(TokenError::ZeroAmount)));
        assert_eq!(
            l.validate(&mint_tx(&l, asset, 5, 3, 40), &StubExecutor),
            Err(tok(TokenError::BadNonce { expected: 0, got: 3 }))
        );
        // The supply is `u64`, and a mint that would wrap it is refused rather than truncated.
        assert_eq!(
            l.validate(&mint_tx(&l, asset, u64::MAX, 0, 50), &StubExecutor),
            Err(tok(TokenError::SupplyOverflow))
        );
        // A note already in the tree.
        let cm = mint_commitment(&recipient(), 250, asset, 1, &[9; 8], &StubExecutor);
        let mut scratch = l.clone();
        scratch.deposit(cm, &StubExecutor).unwrap();
        assert_eq!(scratch.validate(&mint_tx(&scratch, asset, 250, 0, 60), &StubExecutor), Err(TxError::CommitmentExists(cm)));
        // And the window, on the mint's own `time` — a note stamped in a block that has not
        // happened yet, refused before the signature the stamp invalidated is even looked at.
        let mut tx = mint_tx(&l, asset, 250, 0, 70);
        let Action::TokenMint { time, .. } = &mut tx.action else { panic!("a mint") };
        *time = l.height() as u32 + 1;
        assert_eq!(
            l.validate(&tx, &StubExecutor),
            Err(TxError::TimeOutOfWindow { time: l.height() as u32 + 1, height: l.height() })
        );
    }

    /// The signature is the authority's, over this chain: another key's is refused, and so is
    /// the right key's signature over another chain's message.
    #[test]
    fn a_mint_signature_from_another_key_or_chain_id_is_refused() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let thief = Keypair::from_seed([99; 32]).unwrap();
        assert_eq!(
            l.validate(&mint_tx_signed(&l, asset, 5, 0, 30, &thief, CHAIN, [9; 8]), &StubExecutor),
            Err(tok(TokenError::BadSignature))
        );
        assert_eq!(
            l.validate(&mint_tx_signed(&l, asset, 5, 0, 40, &issuer(), CHAIN + 1, [9; 8]), &StubExecutor),
            Err(tok(TokenError::BadSignature)),
            "the signed message binds the chain"
        );
    }

    /// The envelope is inside the signed message (spec §4, amended 2026-09-19): the commitment
    /// binds the note's six words but not the ciphertext that opens it, so without the envelope
    /// digest a third party could lift a gossiped mint, re-wrap it with a garbage envelope and
    /// spend the authority's nonce on a note its recipient can only recover the hard way. Every
    /// part of the envelope is bound, not just the body.
    #[test]
    fn a_mint_whose_envelope_was_altered_after_signing_is_refused() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let signed = mint_tx(&l, asset, 250, 0, 30);
        assert_eq!(l.validate(&signed, &StubExecutor), Ok(()), "as signed");
        let swapped = [
            Envelope { body: vec![0xff; 8], ..env() },
            Envelope { kem_ct: vec![0xff; 8], ..env() },
            Envelope { to_receiver: vec![0xff; 4], ..env() },
            Envelope { to_sender: vec![0xff; 4], ..env() },
        ];
        for e in swapped {
            let mut tx = signed.clone();
            let Action::TokenMint { envelope, .. } = &mut tx.action else { panic!("a mint") };
            *envelope = e.clone();
            assert_eq!(l.validate(&tx, &StubExecutor), Err(tok(TokenError::BadSignature)), "{e:?}");
        }
    }

    /// The per-token nonce is the whole of a mint's replay protection: the same transaction
    /// resubmitted is refused by it, at whatever fee bundle.
    #[test]
    fn a_replayed_mint_is_refused_by_its_nonce() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let tx = mint_tx(&l, asset, 250, 0, 30);
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::Spent([30; 8])), "its own bundle is spent");
        // A fresh bundle and a fresh blinding, the same nonce: the register says no.
        let again = mint_tx_signed(&l, asset, 250, 0, 40, &issuer(), CHAIN, [11; 8]);
        assert_eq!(l.validate(&again, &StubExecutor), Err(tok(TokenError::BadNonce { expected: 1, got: 0 })));
        assert_eq!(l.validate(&mint_tx_signed(&l, asset, 250, 1, 50, &issuer(), CHAIN, [11; 8]), &StubExecutor), Ok(()));
    }

    // ── SetAuthority ─────────────────────────────────────────────────────────────────────────

    /// The rotation path: the new key mints and the old one cannot, and the nonce is spent.
    #[test]
    fn set_authority_hands_the_token_to_the_new_key() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let heir = Keypair::from_seed([77; 32]).unwrap();
        let before = l.state_root();
        let tx = rotate_tx(&l, asset, Some(heir.public_key().clone()), 0, 30, &issuer());
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        let info = l.tokens().unwrap().get(asset).unwrap();
        assert_eq!(info.authority, MintAuthority::Key(heir.public_key().clone()));
        assert_eq!(info.mint_nonce, 1, "a rotation spends the nonce too");
        assert_ne!(l.state_root(), before);
        // The heir mints; the old key no longer can.
        assert_eq!(l.validate(&mint_tx_signed(&l, asset, 5, 1, 40, &heir, CHAIN, [9; 8]), &StubExecutor), Ok(()));
        assert_eq!(
            l.validate(&mint_tx_signed(&l, asset, 5, 1, 50, &issuer(), CHAIN, [9; 8]), &StubExecutor),
            Err(tok(TokenError::BadSignature))
        );
    }

    /// Renouncing is final: `new: None` leaves a token nobody can ever mint again, and no second
    /// rotation can undo it.
    #[test]
    fn a_renounced_token_can_never_mint_again() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let tx = rotate_tx(&l, asset, None, 0, 30, &issuer());
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(l.tokens().unwrap().get(asset).unwrap().authority, MintAuthority::None);
        assert_eq!(
            l.validate(&mint_tx_signed(&l, asset, 5, 1, 40, &issuer(), CHAIN, [9; 8]), &StubExecutor),
            Err(tok(TokenError::NotKeyAuthority(asset)))
        );
        let back = rotate_tx(&l, asset, Some(issuer().public_key().clone()), 1, 50, &issuer());
        assert_eq!(l.validate(&back, &StubExecutor), Err(tok(TokenError::NotKeyAuthority(asset))));
        // And the supply it already has is untouched by any of it.
        assert_eq!(l.tokens().unwrap().get(asset).unwrap().total_supply, 1_000);
    }

    /// The same three refusals a mint has, one action over: an unknown index, an authority that
    /// is not a key, a stale nonce, and a signature that is not the *current* key's.
    #[test]
    fn set_authority_refuses_an_unknown_token_a_stale_nonce_and_a_foreign_signature() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let heir = Keypair::from_seed([77; 32]).unwrap();
        let some = || Some(heir.public_key().clone());
        assert_eq!(l.validate(&rotate_tx(&l, 99, some(), 0, 30, &issuer()), &StubExecutor), Err(tok(TokenError::UnknownToken(99))));
        assert_eq!(
            l.validate(&rotate_tx(&l, asset, some(), 4, 40, &issuer()), &StubExecutor),
            Err(tok(TokenError::BadNonce { expected: 0, got: 4 }))
        );
        assert_eq!(
            l.validate(&rotate_tx(&l, asset, some(), 0, 50, &heir), &StubExecutor),
            Err(tok(TokenError::BadSignature)),
            "signed by the key it would hand the token to, not the one that holds it"
        );
    }

    // ── Transfers and TokenBurn on the hidden-asset bundle (spec §3.7) ───────────────────────

    /// A transfer of any token — keyed or bridged — is a plain `Action::None` bundle: four
    /// nullifiers spent, four commitments appended, and nothing public moved. Neither a token's
    /// `total_supply` nor a backing's `locked` is involved, and the chain never learns which
    /// token it was.
    #[test]
    fn a_token_transfer_is_a_plain_bundle_and_touches_no_supply() {
        let mut l = ledger();
        let keyed = register_keyed(&mut l, 20);
        let bridged = list_bridged(&mut l, 1_000);
        let supply = |l: &Ledger| {
            let t = l.tokens().unwrap();
            (t.get(keyed).unwrap().total_supply, t.get(bridged).unwrap().total_supply)
        };
        let before = supply(&l);
        let leaves = l.next_index();
        let tx = transfer_tx(&l, 40);
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        assert!(tx.nullifiers().iter().all(|nf| l.is_spent(nf)));
        assert!(tx.commitments().iter().all(|cm| l.has_commitment(cm)));
        assert_eq!(l.next_index(), leaves + 4, "one bundle, four leaves");
        assert_eq!(supply(&l), before, "a transfer mints nothing and burns nothing");
        let t = l.tokens().unwrap();
        assert_eq!(t.backing(bridged, 2, &USDT).unwrap().locked, 1_000);
        assert!(t.backing_invariant_holds());
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::Spent([40; 8])));
    }

    /// A burn must name a registered token: an index nobody registered is `UnknownToken`, and
    /// "burning" RAND (asset 0) through the token slots is the non-canonical RAND burn, refused at
    /// step 3 before the token module is reached.
    #[test]
    fn a_burn_of_an_unregistered_index_or_of_rand_is_refused() {
        let mut l = ledger();
        register_keyed(&mut l, 20);
        let burn = burn_tx(&l, 9, 100, 50, |_| {});
        assert_eq!(l.validate(&burn, &StubExecutor), Err(tok(TokenError::UnknownToken(9))));
        let rand = burn_tx(&l, 0, 100, 60, |_| {});
        assert_eq!(l.validate(&rand, &StubExecutor), Err(TxError::NonCanonicalRandBurn(100)));
    }

    /// A `TokenBurn`'s bundle must burn the asset the action itself declares
    /// ([`TxError::BurnAssetMismatch`]). Refused on a comparison, before any proof work: the
    /// bundle carries an unverifiable proof, so reaching verification would be visible.
    #[test]
    fn a_token_burns_burn_asset_must_match_the_actions_own_asset() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let other = list_bridged(&mut l, 1_000);
        assert_ne!(asset, other);
        let tx = burn_tx(&l, asset, 100, 50, |b| {
            b.burn_asset = other;
            b.proof = vec![0xff; 16];
        });
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::BurnAssetMismatch { expected: asset, actual: other }));
    }

    /// A token burn burns no RAND (`burn_r == 0`), and it burns exactly the declared amount of
    /// the token (`burn_a == amount`), neither more nor less. Refused on comparisons, before any
    /// proof work — each case hands the bundle a proof that could never verify.
    #[test]
    fn a_token_burn_burns_exactly_its_amount_and_no_rand() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let break_proof = |b: &mut Bundle| b.proof = vec![0xff; 16];
        let burn = burn_tx(&l, asset, 100, 50, |b| {
            b.burn_r = 7;
            break_proof(b);
        });
        assert_eq!(l.validate(&burn, &StubExecutor), Err(TxError::UnsupportedBurn(7)));
        for burn_a in [99, 101] {
            let burn = burn_tx(&l, asset, 100, 50, |b| {
                b.burn_a = burn_a;
                break_proof(b);
            });
            assert_eq!(l.validate(&burn, &StubExecutor), Err(TxError::BurnAmountMismatch { expected: 100, actual: burn_a }));
        }
        // With nothing else wrong, the broken proof is what is left to refuse the burn — which
        // is what makes the answers above an ordering statement.
        let last = burn_tx(&l, asset, 100, 60, break_proof);
        assert!(matches!(l.validate(&last, &StubExecutor), Err(TxError::InvalidBundleProof(_))));
    }

    /// A transfer destroys nothing: value leaves a token's supply through `TokenBurn`, which says
    /// so publicly, or through `BridgeBurn`, which names a backing. A plain bundle that burned a
    /// token would take supply out of the count without either.
    #[test]
    fn a_plain_bundle_that_burns_a_token_is_refused() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let mut tx = transfer_tx(&l, 40);
        {
            let b = tx.bundle.as_mut().unwrap();
            b.burn_a = 5;
            b.burn_asset = asset;
            b.proof = vec![0xff; 16];
        }
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::UnsupportedAsset(asset)));
    }

    /// The holder burn: the bundle's `burn_a` destroys `amount`, the token's public supply falls
    /// by exactly that, and the bundle's four nullifiers and four commitments are spent and
    /// appended as in a transfer. The RAND audit's `burned` does not move: a token is not RAND.
    #[test]
    fn a_token_burn_lowers_supply_by_exactly_the_burn() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        assert_eq!(l.tokens().unwrap().get(asset).unwrap().total_supply, 1_000);
        let tx = burn_tx(&l, asset, 400, 40, |_| {});
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(l.tokens().unwrap().get(asset).unwrap().total_supply, 600);
        assert_eq!(tx.nullifiers().len(), 4);
        assert!(tx.nullifiers().iter().all(|nf| l.is_spent(nf)));
        assert!(tx.commitments().iter().all(|cm| l.has_commitment(cm)));
        assert_eq!(l.supply().burned, 0, "a token burn is not a RAND burn");
        // A zero burn would spend notes to destroy nothing, and a burn past the supply would
        // leave a count no longer describing what exists — both refused before any proof work.
        let zero = burn_tx(&l, asset, 0, 60, |b| b.proof = vec![0xff; 16]);
        assert_eq!(l.validate(&zero, &StubExecutor), Err(tok(TokenError::ZeroAmount)));
        let past = burn_tx(&l, asset, 601, 70, |b| b.proof = vec![0xff; 16]);
        assert_eq!(l.validate(&past, &StubExecutor), Err(tok(TokenError::SupplyUnderflow)));
        // Exactly the supply is fine, and leaves the token at zero.
        let all = burn_tx(&l, asset, 600, 80, |_| {});
        assert_eq!(l.validate(&all, &StubExecutor), Ok(()));
        l.apply_tx(&all, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(l.tokens().unwrap().get(asset).unwrap().total_supply, 0);
    }

    /// A bridged token leaves this chain through `BridgeBurn`, which names the coin it redeems and
    /// moves that backing's `locked` in the same step. A holder burn of one would drop the supply
    /// while every source contract kept holding its coins — `total_supply == Σ locked` broken on
    /// the spot — so it is refused outright.
    #[test]
    fn a_token_burn_of_a_bridged_token_is_refused() {
        let mut l = ledger();
        let asset = list_bridged(&mut l, 1_000);
        let tx = burn_tx(&l, asset, 400, 40, |_| {});
        assert_eq!(l.validate(&tx, &StubExecutor), Err(tok(TokenError::BridgedToken(asset))));
        let t = l.tokens().unwrap();
        assert_eq!(t.get(asset).unwrap().total_supply, 1_000);
        assert!(t.backing_invariant_holds());
    }

    /// Two burns of one token that each fit alone but not together: block application re-validates
    /// every transaction against the ledger the ones before it left, so the second is refused where
    /// it sits rather than driving the supply below zero — which is what lets `apply`'s
    /// `sub_supply` be infallible on anything that was admitted.
    #[test]
    fn two_token_burns_in_one_block_that_each_fit_alone_do_not_both_fit() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let first = burn_tx(&l, asset, 600, 40, |_| {});
        let second = burn_tx(&l, asset, 600, 50, |_| {});
        assert_eq!(l.validate(&first, &StubExecutor), Ok(()), "each fits against the tip");
        assert_eq!(l.validate(&second, &StubExecutor), Ok(()));
        let mut block = l.clone();
        block.apply_tx(&first, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(block.tokens().unwrap().get(asset).unwrap().total_supply, 400);
        assert_eq!(
            block.apply_tx(&second, &proposer().address(), &StubExecutor).map(|_| ()),
            Err(tok(TokenError::SupplyUnderflow)),
            "1 000 - 600 - 600 would be -200"
        );
    }

    /// A burn's bundle gets the size caps every bundle gets — at step 1, before the chain id,
    /// the fee floor or anything the action itself owns, and long before the proof is verified.
    #[test]
    fn an_oversized_burn_proof_or_envelope_is_refused_before_verification() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let fat = l.max_proof_bytes() + 1;
        let tx = burn_tx(&l, asset, 400, 50, |b| b.proof = vec![0; fat]);
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::ProofTooLarge));
        let fat_env = burn_tx(&l, asset, 400, 60, |b| b.envelopes[3].body = vec![0; crate::notes::MAX_ENVELOPE_BYTES + 1]);
        assert_eq!(l.validate(&fat_env, &StubExecutor), Err(TxError::EnvelopeTooLarge));
    }

    /// A token burn is single-bundle and pays one bundle base (spec §3.7), checked at step 3 —
    /// before the burn fields or any proof.
    #[test]
    fn a_token_burn_pays_one_bundle_base() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let tx = burn_tx(&l, asset, 400, 50, |_| {});
        let mut short = tx.clone();
        {
            let b = short.bundle.as_mut().unwrap();
            b.fee = BURN_FEE - 1;
            b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
        }
        StubExecutor::bind(&mut short);
        assert_eq!(l.validate(&short, &StubExecutor), Err(TxError::FeeTooLow { min: BURN_FEE, fee: BURN_FEE - 1 }));
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()), "exactly the floor is admitted");
    }

    // ── the gate, the block, and fail-closed routing ─────────────────────────────────────────

    /// The gate is absolute: with no `tokens` section every one of the four is refused before
    /// any other check of its own, whatever else is wrong with it.
    #[test]
    fn every_token_action_is_disabled_without_the_gate() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let txs = [
            // A registration with unusable metadata and a wrong index, so an answer other than
            // `Disabled` would name the check that ran first.
            register_tx_at(&l, MintAuthority::Program(crate::crypto::Hash([5; 32])), None, 30, 9, gas::BUNDLE_BASE + REG_FEE),
            mint_tx_signed(&l, 99, 0, 7, 40, &Keypair::from_seed([98; 32]).unwrap(), CHAIN + 1, [9; 8]),
            // A rotation of a token that really is registered, so its verdict with the gate on
            // comes from the token's own rules rather than from the index being unknown.
            rotate_tx(&l, asset, None, 7, 50, &Keypair::from_seed([98; 32]).unwrap()),
            // A burn with a defect of its own (an unregistered index) so that `Disabled` below
            // is the gate speaking and not that.
            burn_tx(&l, 99, 400, 70, |_| {}),
        ];
        // With the gate on, each of the three is refused for a reason of its own and *never*
        // `Disabled` — which is what makes the answer below the gate speaking rather than some
        // check that would have refused either way.
        for tx in &txs {
            let with_gate = l.validate(tx, &StubExecutor);
            assert!(with_gate.is_err(), "{:?} -> {with_gate:?}", tx.action);
            assert_ne!(with_gate, Err(tok(TokenError::Disabled)), "{:?}", tx.action);
        }
        l.set_tokens(None);
        for tx in &txs {
            assert_eq!(l.validate(tx, &StubExecutor), Err(tok(TokenError::Disabled)), "{:?}", tx.action);
            let mut scratch = l.clone();
            assert_eq!(
                scratch.apply_tx(tx, &proposer().address(), &StubExecutor).map(|_| ()),
                Err(tok(TokenError::Disabled))
            );
            // And the apply half on its own, which only a routing mistake reaches: it reads the
            // gate before any write and leaves the tree exactly as it found it.
            let mut scratch = l.clone();
            let leaves = scratch.next_index();
            assert_eq!(apply(&mut scratch, tx, &tx.action, &StubExecutor), Err(tok(TokenError::Disabled)));
            assert_eq!(scratch.next_index(), leaves, "nothing was appended: {:?}", tx.action);
        }
    }

    /// Block application re-validates every transaction against the ledger the ones before it
    /// left, so two mints at one nonce and two registrations at one index cannot both land —
    /// which is what lets `apply` stay infallible on everything `validate` decided.
    #[test]
    fn two_token_actions_in_one_block_are_each_validated_against_the_last() {
        let mut l = ledger();
        let asset = register_keyed(&mut l, 20);
        let first = mint_tx(&l, asset, 250, 0, 30);
        let second = mint_tx_signed(&l, asset, 250, 0, 40, &issuer(), CHAIN, [11; 8]);
        assert_eq!(l.validate(&first, &StubExecutor), Ok(()), "each fits against the tip");
        assert_eq!(l.validate(&second, &StubExecutor), Ok(()));
        let mut block = l.clone();
        block.apply_tx(&first, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(
            block.apply_tx(&second, &proposer().address(), &StubExecutor).map(|_| ()),
            Err(tok(TokenError::BadNonce { expected: 1, got: 0 })),
            "the nonce the first spent"
        );

        // Two registrations naming the same next index: the second is `IndexMismatch`, not a
        // token quietly registered under an index its creator never sealed for.
        let a = register_tx(&l, MintAuthority::None, Some(initial(&l, 5)), 50);
        let b = register_tx_at(&l, MintAuthority::Key(issuer().public_key().clone()), Some(initial(&l, 6)), 60, 2, gas::BUNDLE_BASE + REG_FEE);
        assert_eq!(l.validate(&a, &StubExecutor), Ok(()));
        let mut block = l.clone();
        block.apply_tx(&a, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(
            block.apply_tx(&b, &proposer().address(), &StubExecutor).map(|_| ()),
            Err(tok(TokenError::IndexMismatch { expected: 3, got: 2 })),
            "index 2 went to the registration before it"
        );
    }

    /// Fail closed: an action this module does not own is refused rather than waved through, by
    /// both halves — and by both alike on a chain with no registry at all, where the gate would
    /// otherwise answer for an action the gate has nothing to do with. Only a routing mistake in
    /// `validate_inner` can produce one.
    #[test]
    fn a_non_token_action_routed_here_is_refused() {
        let mut l = ledger();
        let tx = Transaction { chain_id: CHAIN, bundle: None, action: Action::None };
        let strays =
            [Action::None, Action::Unbond { validator: proposer().address(), amount: 1, nonce: 0, signature: Signature::empty() }];
        for gated in [true, false] {
            if !gated {
                l.set_tokens(None);
            }
            for a in &strays {
                assert_eq!(validate(&l, &tx, a, &StubExecutor), Err(TxError::UnsupportedAction("tokens")), "{a:?}");
                assert_eq!(apply(&mut l, &tx, a, &StubExecutor), Err(TxError::UnsupportedAction("tokens")), "{a:?}");
            }
        }
    }

    /// The mint note's `from` word is its own, never a bridge deposit's: two notes that agree on
    /// every other field are still different leaves, so a bridged deposit and an RPL mint can
    /// never be mistaken for one another.
    #[test]
    fn a_mint_note_is_not_a_deposit_note() {
        assert_ne!(MINT_FROM, [0u32; 8], "DEPOSIT_FROM is the zero word");
        let cm = mint_commitment(&recipient(), 5, 1, 9, &[7; 8], &StubExecutor);
        let deposit = crate::ledger::bridge_notes::deposit_commitment(&recipient(), 5, 1, 9, &[7; 8], &StubExecutor);
        assert_ne!(cm, deposit);
        // And every field of the mint note is bound.
        for other in [
            mint_commitment(&ShieldedAddress { pk: [5; 8], kem_ek: vec![6; 32] }, 5, 1, 9, &[7; 8], &StubExecutor),
            mint_commitment(&recipient(), 6, 1, 9, &[7; 8], &StubExecutor),
            mint_commitment(&recipient(), 5, 2, 9, &[7; 8], &StubExecutor),
            mint_commitment(&recipient(), 5, 1, 10, &[7; 8], &StubExecutor),
            mint_commitment(&recipient(), 5, 1, 9, &[8; 8], &StubExecutor),
        ] {
            assert_ne!(cm, other);
        }
    }

    /// Task 5b on the burn fields themselves: a copy of an honest `TokenBurn` that names another
    /// token — `asset` *and* the bundle's `burn_asset` changed together, so the burn rule holds —
    /// or another amount (`amount` and `burn_a`), with the proof re-issued for the new digest
    /// but still bound to the original transaction, is refused on the binding. And the burn's
    /// bundle lifted whole onto a new burn of another token is refused. The original validates.
    #[test]
    fn a_burns_proof_cannot_ride_a_changed_burn_asset_or_burn_a() {
        let mut l = ledger();
        let keyed = register_keyed(&mut l, 20);
        let fixed = {
            let tx = register_tx(&l, MintAuthority::None, Some(initial(&l, 500)), 30);
            l.apply_tx(&tx, &proposer().address(), &StubExecutor).expect("a second token");
            l.tokens().unwrap().next_index() - 1
        };
        l.record_anchor(l.height());
        let original = burn_tx(&l, keyed, 100, 60, |_| {});
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
        let binding = original.binding();
        let rewired = |asset: u32, amount: u64| {
            let mut t = original.clone();
            t.action = Action::TokenBurn { asset, amount };
            let b = t.bundle.as_mut().unwrap();
            b.burn_asset = asset;
            b.burn_a = amount;
            b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()), &binding);
            t
        };
        let public_values = Err(TxError::InvalidBundleProof(crate::confidential::ConfidentialError::InvalidBundleProof("PublicValues".into())));
        assert_eq!(l.validate(&rewired(fixed, 100), &StubExecutor), public_values, "burn_asset rewired");
        assert_eq!(l.validate(&rewired(keyed, 50), &StubExecutor), public_values, "burn_a rewired");
        // Lifted whole — proof untouched — under a burn of the other token: the burn rule sees
        // `burn_asset != asset` first; either way it is refused.
        let lifted = Transaction::shielded(CHAIN, original.bundle.clone().unwrap(), Action::TokenBurn { asset: fixed, amount: 100 });
        assert!(l.validate(&lifted, &StubExecutor).is_err());
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
    }

}
