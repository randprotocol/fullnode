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

use crate::bridge::AssetId;
use crate::crypto::{merkle_root, Hash, PublicKey};
use crate::program::ProgramId;
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

/// One source-chain coin behind a bridged token, and how much of it that chain's contract is
/// holding locked for this one (spec §12).
///
/// zUSD is one Rand-side token backed by USDT and USDC on several chains at once, so a bridged
/// token names a *list* of these. `locked` is per backing rather than per token because a burn
/// releases one specific coin on one specific chain: a redemption the token's whole supply could
/// cover but that coin's own contract could not would succeed here and fail there, stranding the
/// note's value. The sum of every `locked` of a token is exactly its
/// [`TokenInfo::total_supply`] — [`TokenRegistry::backing_invariant_holds`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backing {
    pub chain: u16,
    pub token: [u8; 32],
    pub locked: u64,
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
    #[error("memo of {0} bytes is too large")]
    MemoTooLarge(usize),
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
        }
    }

    pub fn get(&self, index: u32) -> Option<&TokenInfo> {
        self.by_index.get(&index)
    }

    pub fn get_by_id(&self, id: &AssetId) -> Option<&TokenInfo> {
        let index = self.index_of.get(id)?;
        self.by_index.get(index)
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
                    let pair = (b.chain, b.token);
                    // Taken by another token, or named twice inside this one listing: the same
                    // collision either way, and the same refusal.
                    if self.backing_of.contains_key(&pair) || !fresh.insert(pair) {
                        return Err(TokenError::BackingTaken { chain: b.chain });
                    }
                }
                MintAuthority::Bridge {
                    backings: backings
                        .into_iter()
                        .map(|b| Backing { chain: b.chain, token: b.token, locked: 0 })
                        .collect(),
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
    /// token must be bridged, and it must be under [`MAX_BACKINGS`].
    ///
    /// Nothing else can grow a backing set: a registration lists its own, and this adds one.
    pub fn add_backing(&mut self, index: u32, chain: u16, token: [u8; 32]) -> Result<(), TokenError> {
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
        backings.push(Backing { chain, token, locked: 0 });
        self.backing_of.insert((chain, token), index);
        Ok(())
    }

    /// A deposit: `locked += amount` on the named backing and `total_supply += amount` on the
    /// token, both checked and applied together, so `total_supply == Σ locked` survives every
    /// refusal as well as every success.
    ///
    /// [`TokenError::NotABacking`] when `(chain, token)` is not one of `index`'s backings — a
    /// non-bridged token has none at all, so this is also what it answers.
    pub fn lock(&mut self, index: u32, chain: u16, token: &[u8; 32], amount: u64) -> Result<(), TokenError> {
        // Every refusal first, in one place a validate step can call on its own
        // (`check_lock`), so what admission pre-checks is by construction what this would
        // refuse — and so the writes below cannot half-apply.
        self.check_lock(index, chain, token, amount)?;
        let info = self.by_index.get_mut(&index).expect("check_lock resolved the index");
        info.total_supply += amount;
        let MintAuthority::Bridge { backings } = &mut info.authority else {
            unreachable!("check_lock resolved a backing")
        };
        let backing = backings
            .iter_mut()
            .find(|b| b.chain == chain && &b.token == token)
            .expect("check_lock resolved the backing");
        backing.locked += amount;
        Ok(())
    }

    /// Exactly what [`Self::lock`] would refuse, without touching anything: the supply's
    /// overflow, the pair being a backing of this token at all, and the backing's own overflow.
    /// The validate step of a `BridgeAttest` calls this so its apply step cannot fail.
    pub fn check_lock(&self, index: u32, chain: u16, token: &[u8; 32], amount: u64) -> Result<(), TokenError> {
        let info = self.by_index.get(&index).ok_or(TokenError::UnknownToken(index))?;
        // The coin before the arithmetic: a pair that does not back this token is a different
        // mistake from an amount that does not fit, and naming the coin is the more useful of
        // the two answers whenever both are true.
        let backing = self.backing(index, chain, token).ok_or(TokenError::NotABacking { index, chain })?;
        backing.locked.checked_add(amount).ok_or(TokenError::SupplyOverflow)?;
        info.total_supply.checked_add(amount).ok_or(TokenError::SupplyOverflow)?;
        Ok(())
    }

    /// A redemption: `locked -= amount` on the named backing and `total_supply -= amount` on the
    /// token. Refuses `amount > locked` with [`TokenError::InsufficientBacking`] — the token's
    /// whole supply is not what bounds a burn, the coin being released is.
    pub fn release(&mut self, index: u32, chain: u16, token: &[u8; 32], amount: u64) -> Result<(), TokenError> {
        self.check_release(index, chain, token, amount)?;
        let info = self.by_index.get_mut(&index).expect("check_release resolved the index");
        info.total_supply -= amount;
        let MintAuthority::Bridge { backings } = &mut info.authority else {
            unreachable!("check_release resolved a backing")
        };
        let backing = backings
            .iter_mut()
            .find(|b| b.chain == chain && &b.token == token)
            .expect("check_release resolved the backing");
        backing.locked -= amount;
        Ok(())
    }

    /// Exactly what [`Self::release`] would refuse, without touching anything: the supply's
    /// underflow (unreachable while the backing invariant holds, checked anyway), the pair being
    /// a backing of this token, and `amount > locked`. The validate step of a `BridgeBurn` calls
    /// this — through [`crate::bridge::BridgeState::check_burn`] — so its apply step cannot fail.
    pub fn check_release(&self, index: u32, chain: u16, token: &[u8; 32], amount: u64) -> Result<(), TokenError> {
        let info = self.by_index.get(&index).ok_or(TokenError::UnknownToken(index))?;
        // The coin first, as in `check_lock`, and the token's supply last: while the backing
        // invariant holds, `amount <= locked` implies `amount <= total_supply`, so the underflow
        // below is unreachable — it is the defensive half of the pair, not the verdict a burn
        // should ever read.
        let backing = self.backing(index, chain, token).ok_or(TokenError::NotABacking { index, chain })?;
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

    /// Rotates `index`'s mint authority to `Key(new)`, or to `MintAuthority::None` when `new` is
    /// absent — the same way a `None` authority permanently retires further minting (spec: a
    /// key holder may revoke itself, never re-key a `None` or `Bridge` token). A no-op on an
    /// unknown index, for the same reason as [`Self::bump_nonce`] — and a no-op on a **bridged**
    /// token, whose authority holds its backings: rotating it away would orphan every pair
    /// `backing_of` points at this index and break the backing invariant in one call.
    pub fn set_key(&mut self, index: u32, new: Option<PublicKey>) {
        if let Some(info) = self.by_index.get_mut(&index) {
            if matches!(info.authority, MintAuthority::Bridge { .. }) {
                return;
            }
            info.authority = match new {
                Some(pk) => MintAuthority::Key(pk),
                None => MintAuthority::None,
            };
        }
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
        let mut buf = Vec::with_capacity(32 + 4 + 8);
        buf.extend_from_slice(leaves_root.as_bytes());
        buf.extend_from_slice(&self.next_index.to_be_bytes());
        buf.extend_from_slice(&self.registration_fee.to_be_bytes());
        Hash::digest_domain(b"rand-token-registry-1", &buf)
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
/// field a registration commits to, plus a caller-chosen `salt` so the same name/symbol/
/// decimals/authority/supply combination can still be registered more than once as a distinct
/// asset. Built the same way `crate::bridge::asset_id` builds a bridged one — a plain
/// `Hash::digest_domain` call, since [`AssetId`] and [`Hash`] are the same type.
pub fn native_asset_id(
    name: &str,
    symbol: &str,
    decimals: u8,
    authority: &MintAuthority,
    initial_supply: u64,
    salt: &[u8; 32],
) -> AssetId {
    let bytes = bincode::serialize(&(name, symbol, decimals, authority, initial_supply, salt))
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
/// (the tail past `decimals` is 32 bytes here and at least 44 there, whatever the authority).
pub fn bridged_asset_id(name: &str, symbol: &str, salt: &[u8; 32]) -> AssetId {
    let bytes =
        bincode::serialize(&(name, symbol, BRIDGE_DECIMALS, salt)).expect("bridged asset id fields serialize");
    Hash::digest_domain(b"rand-rpl-asset", &bytes)
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

    #[test]
    fn bump_nonce_and_set_key_are_no_ops_on_an_unknown_index() {
        let mut r = reg();
        let pk = crate::crypto::Keypair::from_seed([1; 32]).unwrap().public_key().clone();
        r.bump_nonce(7);
        r.set_key(7, Some(pk));
        r.set_key(7, None);
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
        r.lock(2, chain, &token, 5).unwrap();
        assert_ne!(r.root(), listed, "the state root moves when a backing's locked moves");
    }

    #[test]
    fn a_native_id_binds_every_registration_field() {
        let a = native_asset_id("A", "A", 9, &MintAuthority::None, 10, &[0; 32]);
        assert_ne!(a, native_asset_id("A", "A", 9, &MintAuthority::None, 10, &[1; 32]));
        assert_ne!(a, native_asset_id("A", "A", 9, &MintAuthority::None, 11, &[0; 32]));
        assert_ne!(a, native_asset_id("B", "A", 9, &MintAuthority::None, 10, &[0; 32]));
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
            backings: pairs.iter().map(|&(chain, token)| Backing { chain, token, locked: 0 }).collect(),
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
        r.lock(i, USDT2.0, &USDT2.1, 1_000).unwrap();
        r.lock(i, USDC2.0, &USDC2.1, 400).unwrap();
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
            r.lock(i, chain, &token, amount).unwrap();
            assert!(r.backing_invariant_holds());
        }
        r.release(i, 2, &[0xaa; 32], 400).unwrap();
        assert!(r.backing_invariant_holds());
        r.release(i, 3, &[0xcc; 32], 250).unwrap();
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
        r.lock(i, USDT2.0, &USDT2.1, 1_000).unwrap();
        r.lock(i, USDC2.0, &USDC2.1, 100).unwrap();
        assert_eq!(
            r.release(i, USDC2.0, &USDC2.1, 400),
            Err(TokenError::InsufficientBacking { locked: 100, amount: 400 }),
            "1 100 of supply, but only 100 USDC is locked"
        );
        assert_eq!(r.get(i).unwrap().total_supply, 1_100, "and a refused release moved nothing");
        r.release(i, USDT2.0, &USDT2.1, 400).unwrap();
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
        r.lock(i, USDT2.0, &USDT2.1, 100).unwrap();
        r.lock(i, USDC2.0, &USDC2.1, 900).unwrap();
        r.release(i, USDT2.0, &USDT2.1, 60).unwrap();
        assert_eq!(
            r.release(i, USDT2.0, &USDT2.1, 60),
            Err(TokenError::InsufficientBacking { locked: 40, amount: 60 })
        );
        assert_eq!(r.get(i).unwrap().total_supply, 940);
        assert!(r.backing_invariant_holds());
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
            r.lock(zusd, USDC2.0, &USDC2.1, 1),
            Err(TokenError::NotABacking { index: zusd, chain: 2 }),
            "USDC backs zEUR, not zUSD"
        );
        assert_eq!(r.release(zusd, 9, &[0xff; 32], 1), Err(TokenError::NotABacking { index: zusd, chain: 9 }));
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
            r.add_backing(1, 99, [99; 32]),
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
        r.add_backing(1, 4, [0xdd; 32]).unwrap();
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
        r.add_backing(i, 4, [0xdd; 32]).unwrap();
        assert_eq!(r.backing(i, 4, &[0xdd; 32]).unwrap().locked, 0);
        assert_eq!(r.bridged(4, &[0xdd; 32]).unwrap().index, i);
        assert_eq!(r.add_backing(i, USDT2.0, USDT2.1), Err(TokenError::BackingTaken { chain: 2 }));
        assert_eq!(r.add_backing(9, 6, [6; 32]), Err(TokenError::UnknownToken(9)));
        assert_eq!(r.add_backing(n, 6, [6; 32]), Err(TokenError::AuthorityNotAllowed));
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
        r.lock(i, USDT2.0, &USDT2.1, u64::MAX).unwrap();
        assert_eq!(r.lock(i, USDT2.0, &USDT2.1, 1), Err(TokenError::SupplyOverflow), "the backing");
        assert_eq!(r.lock(i, USDC2.0, &USDC2.1, 1), Err(TokenError::SupplyOverflow), "and the supply");
        assert_eq!(r.get(i).unwrap().total_supply, u64::MAX);
        assert_eq!(r.backing(i, USDC2.0, &USDC2.1).unwrap().locked, 0, "a refused lock moved nothing");
        assert_eq!(r.lock(7, 2, &[0; 32], 1), Err(TokenError::UnknownToken(7)));
        assert_eq!(r.release(7, 2, &[0; 32], 1), Err(TokenError::UnknownToken(7)));
        r.release(i, USDT2.0, &USDT2.1, u64::MAX).unwrap();
        assert_eq!(r.release(i, USDT2.0, &USDT2.1, 1), Err(TokenError::InsufficientBacking { locked: 0, amount: 1 }));
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
            MintAuthority::Bridge { backings: vec![Backing { chain: 2, token: [0xaa; 32], locked: 7 }] },
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
        assert_eq!(r.lock(n, 2, &[0xaa; 32], 1), Err(TokenError::NotABacking { index: n, chain: 2 }));
        assert_eq!(r.check_lock(n, 2, &[0xaa; 32], 1), Err(TokenError::NotABacking { index: n, chain: 2 }));
        // And once the coin really does back a bridged token, it resolves to that one.
        let zusd = list_zusd(&mut r, &[(2, [0xaa; 32])]);
        assert_eq!(r.bridged(2, &[0xaa; 32]).unwrap().index, zusd);
        assert_ne!(zusd, n);
    }

    /// A bridged token's authority is not re-keyable: rotating it to a key would orphan its
    /// backings and leave `backing_of` pointing at a token that no longer has any.
    #[test]
    fn a_bridged_tokens_authority_cannot_be_rotated_away() {
        let mut r = reg();
        let i = list_zusd(&mut r, &[USDT2]);
        let pk = crate::crypto::Keypair::from_seed([1; 32]).unwrap().public_key().clone();
        r.set_key(i, Some(pk));
        assert!(matches!(r.get(i).unwrap().authority, MintAuthority::Bridge { .. }));
        r.set_key(i, None);
        assert!(matches!(r.get(i).unwrap().authority, MintAuthority::Bridge { .. }));
        assert_eq!(r.bridged(USDT2.0, &USDT2.1).unwrap().index, i);
    }
}
