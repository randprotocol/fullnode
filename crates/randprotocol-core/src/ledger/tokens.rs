//! The RPL token registry: dense indices for fungible assets minted on this chain, alongside
//! the ones the bridge already indexes (`crate::bridge::state::AssetInfo`).
//!
//! A note's `asset` word is one `u32`, so every asset — bridged or native — needs a dense index
//! rather than its 32-byte [`AssetId`]. The bridge earns its index the moment an attestation
//! first names it; an RPL token earns its the moment someone pays to register it (a later task's
//! `Action::RegisterToken`). This module is only the registry's shape and its bookkeeping rules:
//! what a name/symbol/decimals triple must look like, how supply is tracked and checked both
//! ways, and the root that folds the registry into the state root. Nothing here decides which
//! actions can call it — that is the ledger module beside this one, wired up in a later task.
//!
//! Index 0 is RAND, the native coin, and is never handed out: [`TokenRegistry::new`] starts
//! `next_index` at [`FIRST_TOKEN_INDEX`], never at zero, and there is deliberately no `Default`
//! impl that could start it there by accident.
//!
//! A bridged asset registers here too, under the *same* [`AssetId`] the bridge computes
//! (`crate::bridge::asset_id`) — [`TokenRegistry::bridged`] looks it up that way — so a note's
//! `asset` word means one thing everywhere: an index into this one registry, whether the value
//! behind it came from a bridge attestation or a native mint.

use crate::bridge::{asset_id, AssetId};
use crate::crypto::{merkle_root, Hash, PublicKey};
use crate::program::ProgramId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The first index [`TokenRegistry::new`] hands out. 0 is RAND and is never registered here,
/// same reasoning as the bridge's own `FIRST_ASSET_INDEX`.
pub const FIRST_TOKEN_INDEX: u32 = 1;
/// Longest a token's display name may be, in bytes.
pub const MAX_NAME_BYTES: usize = 32;
/// Longest a token's ticker symbol may be, in bytes.
pub const MAX_SYMBOL_BYTES: usize = 12;
/// Most decimal places a token may declare.
pub const MAX_DECIMALS: u8 = 9;
/// Decimals a bridged token is normalized to on this chain, whatever its home chain declares.
pub const BRIDGE_DECIMALS: u8 = 8;

/// Who may move a token's [`TokenInfo::total_supply`] and [`TokenInfo::mint_nonce`], in the
/// later task that wires up `Mint`/`Burn`.
///
/// `None` is a fixed-supply token: whatever [`native_asset_id`] committed to at registration is
/// all there will ever be. `Key` and `Program` are the two things that can sign or prove a
/// further mint. `Bridge` is not a minter at all in the sense the other three are — a bridged
/// token's supply moves only through the bridge's own attestations — but it still has to name
/// *something* here so [`TokenRegistry::bridged`] and a mint attempt both see a bridged token's
/// authority as neither a usable key nor a usable program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintAuthority {
    None,
    Key(PublicKey),
    Bridge { chain: u16, token: [u8; 32] },
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
/// the only constructor, and it starts at [`FIRST_TOKEN_INDEX`] the same way
/// `BridgeState::default()` is written out by hand for its own `next_index` (`bridge/state.rs`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRegistry {
    pub registration_fee: u64,
    by_index: BTreeMap<u32, TokenInfo>,
    index_of: BTreeMap<AssetId, u32>,
    next_index: u32,
}

/// Why a registry operation was refused. A later task's `validate`/`apply` for the RPL actions
/// carries this inside its own `TxError` variant, the same way [`super::StakingError`] rides
/// inside `TxError::Staking`; only the four checked here (metadata, identity, capacity, supply)
/// are reachable from this module today, the rest are for that task's mint/burn/rotate rules.
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
}

impl TokenRegistry {
    /// An empty registry charging `registration_fee` per registration, its next index at
    /// [`FIRST_TOKEN_INDEX`] — never 0, which is RAND's.
    pub fn new(registration_fee: u64) -> TokenRegistry {
        TokenRegistry {
            registration_fee,
            by_index: BTreeMap::new(),
            index_of: BTreeMap::new(),
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

    /// The token registered under the bridge's own id for `(chain, token)` — the same id
    /// [`crate::bridge::state::BridgeState`] would compute for the same pair, so a bridged
    /// token's index means one thing on both sides.
    pub fn bridged(&self, chain: u16, token: &[u8; 32]) -> Option<&TokenInfo> {
        self.get_by_id(&asset_id(chain, token))
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
        if self.next_index == u32::MAX {
            return Err(TokenError::RegistryFull);
        }
        let index = self.next_index;
        self.next_index += 1;
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

    /// Credits `amount` to `index`'s supply, refusing to wrap past `u64::MAX`.
    pub fn add_supply(&mut self, index: u32, amount: u64) -> Result<(), TokenError> {
        let info = self.by_index.get_mut(&index).ok_or(TokenError::UnknownToken(index))?;
        info.total_supply = info.total_supply.checked_add(amount).ok_or(TokenError::SupplyOverflow)?;
        Ok(())
    }

    /// Debits `amount` from `index`'s supply, refusing to underflow below zero.
    pub fn sub_supply(&mut self, index: u32, amount: u64) -> Result<(), TokenError> {
        let info = self.by_index.get_mut(&index).ok_or(TokenError::UnknownToken(index))?;
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
    /// unknown index, for the same reason as [`Self::bump_nonce`].
    pub fn set_key(&mut self, index: u32, new: Option<PublicKey>) {
        if let Some(info) = self.by_index.get_mut(&index) {
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
        let bid = crate::bridge::asset_id(chain, &token);
        r.register(bid, "USD Coin".into(), "zUSDC".into(), 8, MintAuthority::Bridge { chain, token }, 0)
            .unwrap();
        assert_eq!(r.bridged(chain, &token).unwrap().index, 2);
    }

    #[test]
    fn a_native_id_binds_every_registration_field() {
        let a = native_asset_id("A", "A", 9, &MintAuthority::None, 10, &[0; 32]);
        assert_ne!(a, native_asset_id("A", "A", 9, &MintAuthority::None, 10, &[1; 32]));
        assert_ne!(a, native_asset_id("A", "A", 9, &MintAuthority::None, 11, &[0; 32]));
        assert_ne!(a, native_asset_id("B", "A", 9, &MintAuthority::None, 10, &[0; 32]));
    }
}
