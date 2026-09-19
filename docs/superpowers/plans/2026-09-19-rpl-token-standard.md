# RPL Token Standard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give RandProtocol a token standard (RPL): a ledger-level registry of shielded native assets with permissionless creation, mint authorities, transferable tokens, allowance accounts, and the bridge's asset registry rebased onto it.

**Architecture:** A `TokenRegistry` on `Ledger`, gated by `Genesis::tokens`, replaces `BridgeState.assets`/`next_index` and adds a `tokens_root` to the state root (`rand-state-4`). Five new `Action`s; the three that move token notes reuse `BridgeBurn`'s two-bundle shape (RAND fee bundle + asset bundle), so no circuit changes. Allowances are a client convention over `TokenTransfer.memo`.

**Tech Stack:** Rust workspace (`randprotocol-core`, `-node`, `-client`, `bridge-codec`), bincode, blake3 (`Hash::digest_domain`), Dilithium2 (`crypto::PublicKey`/`Signature`), RocksDB, `ml-kem =0.3.2`, `chacha20poly1305 =0.11.0`.

**Spec:** `docs/superpowers/specs/2026-09-19-rpl-token-standard-design.md` — read it first; this plan argues from it.

## Global Constraints

- Work only in the worktree `/tmp/fullnode-rpl` (branch `rpl`). The main checkout is shared with other sessions and has uncommitted work: never touch it. `/tmp/circuits` must be a symlink to the real `circuits` checkout (it is) or `cargo metadata` fails.
- **Never hand-edit `crates/randprotocol-zkvm/` or `crates/randprotocol-rvm/`** — vendored.
- **The gate is absolute:** a genesis without `tokens` must hash, root, accept and refuse byte-for-byte as chain 13. Every token action is refused with `TokenError::Disabled` before any other token check.
- Optional state-root components are **appended, never zero-placed**.
- Cheap checks before expensive ones: every proof verification is the last step of its validation.
- Every persisted ledger field is restored by both `Storage::load_ledger` and `node::reload_ledger`.
- Exact values: name 1..=32 bytes UTF-8; symbol 1..=12 bytes ASCII graphic (`0x21..=0x7e`); decimals 0..=9; bridged tokens decimals = 8; memo ≤ 2 048 bytes; `registration_fee` bounds `1_000_000_000 ..= 10_000_000_000_000` (1..=10 000 RAND at nine decimals); index 0 is RAND and never registered; `FIRST_TOKEN_INDEX = 1`.
- Hash domains, verbatim: `rand-rpl-asset`, `rand-bridge-asset` (unchanged), `rand-token-leaf-1`, `rand-rpl-mint-1`, `rand-rpl-authority-1`, `rand-rpl-allowance-1`, `rand-state-4`, `rand-bridge-state-2`.
- Match the surrounding code's comment density and voice (doc comments explain *why*). Commit messages follow the repo style (`area: what — detail`) and end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Gates: after touching `Action`, `Genesis` or `Ledger`, run `cargo check --workspace --tests` — `cargo test -p … --lib` compiles neither `main.rs` nor `tests/`. Proving tests take the proving slot (`tests/proving_slot/`); run one proving suite at a time.
- Finish by rebase + fast-forward; no merge commits. `bridge-burn-fee` (142e1f7) may land on main first and changes `fee_floor`'s `BridgeBurn` arm: rebase over it, keep its value.

## File Structure

| file | responsibility |
|---|---|
| `crates/randprotocol-core/src/ledger/tokens.rs` (new) | `TokenInfo`, `MintAuthority`, `TokenRegistry`, `TokenError`, ids, metadata rules, root, `validate`/`apply` for the five actions, the shared two-bundle check |
| `crates/randprotocol-core/src/types/transaction.rs` | five `Action` variants, `InitialMint` |
| `crates/randprotocol-core/src/types/actions.rs` | `token_mint_message`, `set_authority_message` |
| `crates/randprotocol-core/src/gas.rs` | fee floors |
| `crates/randprotocol-core/src/genesis.rs` | `TokensConfig`, `GenesisToken`, gate, commitment |
| `crates/randprotocol-core/src/ledger/mod.rs` | `tokens` field, routing, `rand-state-4` |
| `crates/randprotocol-core/src/bridge/state.rs`, `ledger/bridge_notes.rs` | registry removed; resolve through `TokenRegistry`; `UnlistedToken`; supply |
| `crates/bridge-codec/src/payload.rs` | governance payload id 3 |
| `crates/randprotocol-node/src/{storage,node,mempool,admission,rpc,main}.rs` | persistence, note indexing, RPC, genesis CLI |
| `crates/randprotocol-client/src/{lib,wallet,main}.rs`, `src/allowance.rs` (new) | RPC client rows, token submissions, CLI, allowances |
| `docs/tokens.md` (new), `docs/{bridge,rpc,cli,confidential}.md`, `README.md`, `AGENTS.md` | docs |

---

### Task 1: The registry types

**Files:**
- Create: `crates/randprotocol-core/src/ledger/tokens.rs`
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (add `pub mod tokens;`)

**Interfaces:**
- Consumes: `crate::bridge::{AssetId, asset_id}`, `crate::crypto::{Hash, PublicKey}`, `crate::program::ProgramId`, `super::merkle_root`.
- Produces:

```rust
pub const FIRST_TOKEN_INDEX: u32 = 1;
pub const MAX_NAME_BYTES: usize = 32;
pub const MAX_SYMBOL_BYTES: usize = 12;
pub const MAX_DECIMALS: u8 = 9;
pub const BRIDGE_DECIMALS: u8 = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintAuthority { None, Key(PublicKey), Bridge { chain: u16, token: [u8; 32] }, Program(ProgramId) }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo { pub id: AssetId, pub index: u32, pub name: String, pub symbol: String,
    pub decimals: u8, pub authority: MintAuthority, pub mint_nonce: u64, pub total_supply: u64,
    pub registered_at: u64 }

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRegistry { pub registration_fee: u64, by_index: BTreeMap<u32, TokenInfo>,
    index_of: BTreeMap<AssetId, u32>, next_index: u32 }

impl TokenRegistry {
    pub fn new(registration_fee: u64) -> TokenRegistry;          // next_index = FIRST_TOKEN_INDEX
    pub fn get(&self, index: u32) -> Option<&TokenInfo>;
    pub fn get_by_id(&self, id: &AssetId) -> Option<&TokenInfo>;
    pub fn bridged(&self, chain: u16, token: &[u8; 32]) -> Option<&TokenInfo>; // via asset_id
    pub fn iter(&self) -> impl Iterator<Item = &TokenInfo>;       // ascending index
    pub fn len(&self) -> usize;
    pub fn register(&mut self, id: AssetId, name: String, symbol: String, decimals: u8,
        authority: MintAuthority, height: u64) -> Result<u32, TokenError>;
    pub fn add_supply(&mut self, index: u32, amount: u64) -> Result<(), TokenError>;
    pub fn sub_supply(&mut self, index: u32, amount: u64) -> Result<(), TokenError>;
    pub fn bump_nonce(&mut self, index: u32);
    pub fn set_key(&mut self, index: u32, new: Option<PublicKey>);
    pub fn root(&self) -> Hash;
}
pub fn check_metadata(name: &str, symbol: &str, decimals: u8) -> Result<(), TokenError>;
pub fn native_asset_id(name: &str, symbol: &str, decimals: u8, authority: &MintAuthority,
    initial_supply: u64, salt: &[u8; 32]) -> AssetId;
```

`TokenError` (thiserror, `Clone, Debug, PartialEq, Eq`): `Disabled`, `BadName`, `BadSymbol`, `TooManyDecimals(u8)`, `AlreadyRegistered(AssetId)`, `RegistryFull`, `UnknownToken(u32)`, `AuthorityNotAllowed`, `InitialMintRequired`, `NotKeyAuthority(u32)`, `BadNonce { expected: u64, got: u64 }`, `BadSignature`, `SupplyOverflow`, `SupplyUnderflow`, `ZeroAmount`, `BridgedToken(u32)`, `MemoTooLarge(usize)`, `RegistrationFeeTooLow { min: u64, fee: u64 }`, `IndexMismatch { expected: u32, got: u32 }`.

- [ ] **Step 1: Write the failing tests** in `tokens.rs`'s `#[cfg(test)] mod tests`:

```rust
fn reg() -> TokenRegistry { TokenRegistry::new(1_000_000_000) }
fn id(n: u8) -> AssetId { AssetId([n; 32]) }

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
    assert_eq!(r.register(id(1), "Z".into(), "Q".into(), 8, MintAuthority::None, 0),
        Err(TokenError::AlreadyRegistered(id(1))));
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
    r.register(bid, "USD Coin".into(), "zUSDC".into(), 8, MintAuthority::Bridge { chain, token }, 0).unwrap();
    assert_eq!(r.bridged(chain, &token).unwrap().index, 2);
}
#[test]
fn a_native_id_binds_every_registration_field() {
    let a = native_asset_id("A", "A", 9, &MintAuthority::None, 10, &[0; 32]);
    assert_ne!(a, native_asset_id("A", "A", 9, &MintAuthority::None, 10, &[1; 32]));
    assert_ne!(a, native_asset_id("A", "A", 9, &MintAuthority::None, 11, &[0; 32]));
    assert_ne!(a, native_asset_id("B", "A", 9, &MintAuthority::None, 10, &[0; 32]));
}
```

- [ ] **Step 2: Run** `cargo test -p randprotocol-core --lib ledger::tokens` — FAIL (module does not exist).
- [ ] **Step 3: Implement.** `register` calls `check_metadata`, refuses a known id, refuses `next_index == u32::MAX` with `RegistryFull`, inserts with `mint_nonce: 0, total_supply: 0`. `root()` is `merkle_root` over `Hash::digest_domain(b"rand-token-leaf-1", &bincode::serialize(info))` in index order, then `Hash::digest_domain(b"rand-token-registry-1", root ‖ next_index.to_be_bytes() ‖ registration_fee.to_be_bytes())`. `native_asset_id` is `AssetId(*Hash::digest_domain(b"rand-rpl-asset", &bincode::serialize(&(name, symbol, decimals, authority, initial_supply, salt))).as_bytes())` — check how `bridge::asset_id` builds an `AssetId` from a `Hash` and do the same.
- [ ] **Step 4: Run** the same command — PASS.
- [ ] **Step 5: Commit** `tokens: the RPL registry — TokenInfo, MintAuthority, dense indices, checked supply, the registry root`.

---

### Task 2: The genesis gate and the state root

**Files:**
- Modify: `crates/randprotocol-core/src/genesis.rs` (the `bridge` field at :88-93 is the pattern; `check_bridge` :468; commitment :405-410; build :347)
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (`Ledger` struct :256; `set_bridge` :579; `state_root` :1422; `debug_state_root_components`)
- Modify: `crates/randprotocol-node/src/main.rs` (genesis command: `--tokens <TOKENS.JSON>`)

**Interfaces:**
- Consumes: Task 1.
- Produces:

```rust
// genesis.rs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisToken { pub name: String, pub symbol: String,
    pub chain: u16, #[serde(with = "hex_bytes32")] pub token: [u8; 32] }   // Bridge authority, decimals 8
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokensConfig { pub registration_fee: u64, #[serde(default)] pub tokens: Vec<GenesisToken> }
pub struct Genesis { /* … */ #[serde(default, skip_serializing_if = "Option::is_none")] pub tokens: Option<TokensConfig> }
// GenesisError::{BadTokens(String), BridgeNeedsTokens}
// ledger/mod.rs
impl Ledger { pub fn set_tokens(&mut self, t: Option<TokenRegistry>); pub fn tokens(&self) -> Option<&TokenRegistry>;
              pub(crate) fn tokens_mut(&mut self) -> Option<&mut TokenRegistry>; }
```

Genesis tokens are `Bridge`-authority only (a native token at genesis has no note to mint into; creators register after launch).

- [ ] **Step 1: Failing tests** (genesis.rs tests, beside `a_bridge_section_is_accepted_and_only_a_bridged_chain_changes`):

```rust
#[test]
fn a_tokens_section_is_the_only_thing_that_changes_a_chain() {
    let plain = base_genesis();                       // the helper the bridge test uses
    let s = build(&plain);
    assert!(s.ledger.tokens().is_none());
    assert!(!plain.to_json().contains("tokens"));
    let mut tok = plain.clone();
    tok.tokens = Some(TokensConfig { registration_fee: 1_000_000_000, tokens: vec![] });
    let st = build(&tok);
    assert_ne!(st.ledger.state_root(), s.ledger.state_root());
    assert_ne!(tok.hash(), plain.hash());
}
#[test]
fn a_bridge_needs_tokens_and_listed_tokens_need_a_bridge_entry() {
    let mut g = base_genesis();
    g.bridge = Some(bridge_cfg());
    assert!(matches!(g.validate(), Err(GenesisError::BridgeNeedsTokens)));
    g.tokens = Some(TokensConfig { registration_fee: 1_000_000_000, tokens: vec![
        GenesisToken { name: "Tether USD".into(), symbol: "zUSDT".into(), chain: 2, token: [0x11; 32] },
        GenesisToken { name: "USD Coin".into(), symbol: "zUSDC".into(), chain: 2, token: [0x22; 32] }] });
    let s = build(&g);
    let t = s.ledger.tokens().unwrap();
    assert_eq!((t.get(1).unwrap().symbol.as_str(), t.get(2).unwrap().symbol.as_str()), ("zUSDT", "zUSDC"));
    assert_eq!(t.get(1).unwrap().decimals, 8);
}
#[test]
fn registration_fee_bounds_and_duplicate_listings_are_refused() {
    let mut g = base_genesis();
    g.tokens = Some(TokensConfig { registration_fee: 999_999_999, tokens: vec![] });
    assert!(matches!(g.validate(), Err(GenesisError::BadTokens(_))));
    let dup = GenesisToken { name: "A".into(), symbol: "A".into(), chain: 2, token: [1; 32] };
    g.tokens = Some(TokensConfig { registration_fee: 1_000_000_000, tokens: vec![dup.clone(), dup] });
    assert!(matches!(g.validate(), Err(GenesisError::BadTokens(_))));
}
```

Also add to the **pinned chain-13 vector test**: load `deploy/genesis-chain13.json`, assert its hash is still `8123ccac1883a45750e4df6964fb7cd3f0b321798cde4c0ef406a0293939ece3` (use the existing pin test's helper if one exists; otherwise `Genesis::from_json(include_str!("../../../deploy/genesis-chain13.json"))`).

- [ ] **Step 2: Run** `cargo test -p randprotocol-core --lib genesis` — FAIL.
- [ ] **Step 3: Implement.** Commitment: after the bridge bytes, `if let Some(t) = &self.tokens { commit.extend_from_slice(&bincode::serialize(t)...) }`. State root: append `tokens.root()` **after the bridge root, before the aggregators root**; when `self.tokens.is_some()` the domain is `rand-state-4` whether or not aggregation is on (the aggregators root is still appended when it is); otherwise today's code path unchanged. `debug_state_root_components` names `tokens`. Genesis tokens listed without a `bridge` section are `BadTokens`. `main.rs` genesis command: `--tokens <FILE>` reads a `TokensConfig` JSON (the trap from aggregation: the command must actually set `genesis.tokens`).
- [ ] **Step 4: Run** `cargo test -p randprotocol-core --lib` and `cargo check --workspace --tests` — PASS.
- [ ] **Step 5: Commit** `genesis: the tokens section — the RPL gate, listed bridged tokens, tokens_root under rand-state-4; a chain without it is byte-for-byte chain 13`.

---

### Task 3: The bridge resolves assets through the registry

The largest task: `BridgeState.assets` and `next_index` go away.

**Files:**
- Modify: `crates/randprotocol-core/src/bridge/state.rs` (`AssetInfo` :98, `BridgeState` :108, `BridgeMeta` :157, `asset_index`/`asset_by_index`/`deposit_index`/`asset_entry` :373-412, `check_attest` ~:430-515, `apply_attest` :529, `check_burn`/`apply_burn` ~:565-640, `root` :673)
- Modify: `crates/randprotocol-core/src/ledger/bridge_notes.rs` (validate/apply :60-195, `deposit_note`, `attested_transfer`)
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (`TxError::AttestAssetMismatch` doc)
- Modify callers: `crates/randprotocol-node/src/{storage.rs (:285, :330, :2162, load_bridge, BridgeMeta blob), mempool.rs (:458), rpc.rs (:657, :672 assets_json, :1591, :1613)}`, `crates/randprotocol-client/src/wallet.rs` (`burn_is_possible` :1092, `deposit_index` :1430)

**Interfaces:**
- Consumes: `TokenRegistry::{bridged, get, add_supply, sub_supply}`.
- Produces:

```rust
impl BridgeState {
    pub fn check_attest(&self, tokens: &TokenRegistry, bytes: &[u8], now: u64) -> Result<CheckedAttestation, BridgeError>;
    pub fn apply_attest(&mut self, checked: CheckedAttestation) -> AttestOutcome;   // no longer registers
    pub fn check_burn(&self, tokens: &TokenRegistry, asset_index: u32, amount: u64, to_chain: u16, to: &[u8; 32], relayer_fee: u64) -> Result<(), BridgeError>;
}
pub struct BridgeTransfer { pub asset: AssetId, pub index: u32, pub amount: u64, pub to_hash: [u8; 32], pub relayer_fee: u64 }
// BridgeError::UnlistedToken { chain: u16, token: [u8; 32] } replaces AssetRegistryFull
```

Keep each existing signature's other parameters as they are today — read them before editing.

- [ ] **Step 1: Failing tests.** In `state.rs` tests, rewrite the registry tests (`:912`, `:933`, `:1103`, `:1311`) to the new rule, and add:

```rust
#[test]
fn an_unlisted_token_is_refused_and_a_listed_one_deposits_under_its_index() {
    let (st, mut tokens) = (fixture_state(), TokenRegistry::new(1_000_000_000));
    let att = fixture_transfer_attestation();          // the existing fixture: chain 2, TOKEN
    assert!(matches!(st.check_attest(&tokens, &att, NOW), Err(BridgeError::UnlistedToken { chain: 2, .. })));
    let id = asset_id(2, &fixtures::TOKEN);
    tokens.register(id, "Tether USD".into(), "zUSDT".into(), 8,
        MintAuthority::Bridge { chain: 2, token: fixtures::TOKEN }, 0).unwrap();
    let checked = st.check_attest(&tokens, &att, NOW).unwrap();
    assert!(matches!(checked.plan, AttestPlan::Transfer(BridgeTransfer { index: 1, .. })));
}
#[test]
fn the_bridge_root_no_longer_moves_with_the_token_registry() { /* root equal before/after a registration */ }
```

In `bridge_notes.rs` tests: a deposit raises `total_supply` by the gross amount; a burn lowers it; a burn of more than the supply is `TokenError::SupplyUnderflow`; a `Key`-authority token index passed to `BridgeBurn` is refused (`BridgeError::UnlistedToken` — `check_burn` requires `MintAuthority::Bridge`).

- [ ] **Step 2: Run** `cargo test -p randprotocol-core --lib bridge` — FAIL (compile).
- [ ] **Step 3: Implement.** `check_attest` resolves `tokens.bridged(t.token_chain, &t.token_address)` → `UnlistedToken` on a miss. `root()` drops the registry leaves and `next_index`; domain `rand-bridge-state-2`. `bridge_notes::validate/apply` fetch `ledger.tokens()` (`TxError::Token(TokenError::Disabled)` if absent — add `Token(#[from] TokenError)` to `TxError`); apply calls `add_supply`/`sub_supply`. `AttestAssetMismatch` stays (a wrong index is still refused). `deposit_note(tx, bridge, executor)` gains a `tokens` parameter. Node: `BridgeMeta` loses two fields — the stored blob format changes, acceptable because chain 14 is a new datadir; `mempool::still_applies`'s first-sighting drop becomes a plain index check. Client: `burn_is_possible` reads `rand_getTokens` rows with `authority.kind == "bridge"` (Task 7 adds the RPC; until then keep reading `bridge_state["assets"]`, which Task 7 keeps as an alias); `wallet::deposit_index`'s "prediction for a new one" branch becomes an error: *"this token is not listed on this chain"*.
- [ ] **Step 4: Run** `cargo test -p randprotocol-core --lib && cargo test -p bridge-codec && cargo check --workspace --tests` — PASS. Then `cargo test -p randprotocol-node --lib -- bridge storage::tests mempool` (set `RECURSION_FIXTURES` if available; aggregation tests that need it are known to fail without it — not this task's).
- [ ] **Step 5: Commit** `bridge: assets resolve through the RPL registry — listed tokens only (UnlistedToken), no first-sighting race, total_supply follows deposits and burns, rand-bridge-state-2`.

---

### Task 3b: one bridged token, many backings (zUSD)

Spec amendment (user, 2026-09-19): spec §12 — read it first.

**Files:**
- Modify: `crates/randprotocol-core/src/ledger/tokens.rs` (`MintAuthority::Bridge`, `TokenRegistry`)
- Modify: `crates/randprotocol-core/src/genesis.rs` (`GenesisToken`, the commitment twin, validation)
- Modify: `crates/randprotocol-core/src/bridge/state.rs`, `ledger/bridge_notes.rs`, `types/transaction.rs` (`BridgeBurn.token`)
- Modify callers: `crates/randprotocol-node/src/{rpc,storage,mempool}.rs`, `crates/randprotocol-client/src/{wallet,main}.rs`

**Interfaces — produces:**

```rust
pub const MAX_BACKINGS: usize = 32;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backing { pub chain: u16, pub token: [u8; 32], pub locked: u64 }
pub enum MintAuthority { None, Key(PublicKey), Bridge { backings: Vec<Backing> }, Program(ProgramId) }

impl TokenRegistry {
    /// (chain, token) → index; many-to-one; a pair backs at most one token in the whole registry.
    pub fn bridged(&self, chain: u16, token: &[u8; 32]) -> Option<&TokenInfo>;
    pub fn backing(&self, index: u32, chain: u16, token: &[u8; 32]) -> Option<&Backing>;
    pub fn add_backing(&mut self, index: u32, chain: u16, token: [u8; 32]) -> Result<(), TokenError>;
    /// Deposit: locked += amount and total_supply += amount, both checked, atomically.
    pub fn lock(&mut self, index: u32, chain: u16, token: &[u8; 32], amount: u64) -> Result<(), TokenError>;
    /// Redemption: refuses amount > locked (InsufficientBacking); locked -= amount, total_supply -= amount.
    pub fn release(&mut self, index: u32, chain: u16, token: &[u8; 32], amount: u64) -> Result<(), TokenError>;
    /// total_supply == Σ locked for every Bridge token. Cheap; asserted in tests and debug builds at block close.
    pub fn backing_invariant_holds(&self) -> bool;
}
// TokenError += NotABacking { index: u32, chain: u16 }, InsufficientBacking { locked: u64, amount: u64 },
//               BackingTaken { chain: u16 }, TooManyBackings, NoBackings
// Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain, token: [u8; 32], to }
// genesis: GenesisToken { name, symbol, salt: [u8;32] (hex), backings: Vec<GenesisBacking { chain, token (hex) }> }
```

A bridged token's asset id is `native_asset_id`-style over its registration fields (name, symbol, 8, salt) under domain `rand-rpl-asset` — NOT `bridge::asset_id(chain, token)`, which stays as the per-backing wire id `rand_bridgeAssetId` computes. Backings are not part of the id (they grow).

Rules: 1..=32 backings; a `(chain, token)` pair unique across the registry (`BackingTaken`); `chain` must have a registered emitter in the genesis bridge section (genesis validation: `BadTokens`); `check_attest` resolves the attested `(token_chain, token_address)` through `bridged()` → `UnlistedToken` on a miss, and validates `lock` would not overflow; `check_burn` requires `(to_chain, token)` be a backing of `asset` (`NotABacking`), `amount <= locked` (`InsufficientBacking`), and builds the outbound burn message from that backing's chain/token. Refusals happen in validate so apply stays infallible. The token leaf (`rand-token-leaf-1`, bincode of `TokenInfo`) now commits every `locked`.

RPC shapes kept: `rand_getAssets` / `rand_getBridgeState.assets` = one row per backing `{asset: per-backing id, chain, token, index, locked}`. `tx_json`'s `bridge_burn` gains `token`.
Client: `rand bridge-burn` gains `--token <hex>`; `submit_burn` pre-checks the backing's `locked` from `rand_getAssets` before any proving: *"only {locked} is locked in that coin on chain {to_chain}; choose another backing or a smaller amount"*.

**Tests (write first):** a deposit of backing A and of backing B mint the same index and both raise supply; `backing_invariant_holds` after a mixed sequence of deposits and burns; a burn into B greater than B's locked is `InsufficientBacking` even though total supply covers it, and the same amount into A succeeds; a burn naming a pair that backs nothing, or another token, is `NotABacking`; a second token listing an already-taken pair is `BackingTaken`; 0 and 33 backings refused; genesis with one zUSD and seven backings (USDT, USDC × chains 2, 3, 5; USDT on chain 4) builds, `get(1).symbol == "zUSD"`, decimals 8; the genesis commitment moves when one backing byte changes; the state root moves when `locked` moves; a chain without `tokens` is untouched (chain-13 pin test stays green); the outbound burn record carries the chosen backing's chain and token; wallet pre-check error text.

**Gates:** `cargo test -p randprotocol-core --lib`, `cargo test -p bridge-codec`, `cargo check --workspace --tests`, `cargo test -p randprotocol-node --lib`, `cargo test -p randprotocol-client --lib` (known unrelated failures: ~21 node aggregation tests needing RECURSION_FIXTURES; `the_genesis_hash_is_pinned`). No proving suites.

**Commit:** `tokens: one bridged token, many backings — zUSD's backing set, per-backing locked, a burn names its coin, InsufficientBacking`.

---

### Task 4: `RegisterToken`, `TokenMint`, `SetAuthority`

**Files:**
- Modify: `types/transaction.rs` (after `BridgeBurn`), `types/actions.rs`, `gas.rs` :132, `ledger/mod.rs` (routing :1015, apply :1151), `ledger/tokens.rs`

**Interfaces:**
- Produces:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialMint { pub amount: u64, pub recipient: ShieldedAddress, pub r: Word8, pub time: u32, pub envelope: Envelope }
// Action:
RegisterToken { name: String, symbol: String, decimals: u8, authority: MintAuthority, initial: Option<InitialMint>, salt: [u8; 32], index: u32 },
TokenMint { asset: u32, amount: u64, recipient: ShieldedAddress, r: Word8, time: u32, envelope: Envelope, nonce: u64, signature: Signature },
SetAuthority { asset: u32, new: Option<PublicKey>, nonce: u64, signature: Signature },
// types/actions.rs
pub fn token_mint_message(chain_id: u64, asset_id: &AssetId, nonce: u64, amount: u64, cm: &Word8) -> Hash;       // domain rand-rpl-mint-1
pub fn set_authority_message(chain_id: u64, asset_id: &AssetId, nonce: u64, new: &Option<PublicKey>) -> Hash;   // domain rand-rpl-authority-1
// ledger/tokens.rs
pub const MINT_FROM: Word8 = /* distinct from bridge_notes::DEPOSIT_FROM; same construction, tag "rpl-mint" */;
pub fn mint_commitment(recipient: &ShieldedAddress, amount: u64, index: u32, time: u32, r: &Word8, ex: &dyn ConfidentialExecutor) -> Word8;
pub(super) fn validate(ledger: &Ledger, tx: &Transaction, action: &Action, ex: &dyn ConfidentialExecutor) -> Result<(), TxError>;
pub(super) fn apply(ledger: &mut Ledger, tx: &Transaction, action: &Action, ex: &dyn ConfidentialExecutor) -> Result<(), TxError>;
```

All three ride a RAND fee bundle. `fee_floor`: `RegisterToken | TokenMint | SetAuthority => BUNDLE_BASE`; the registration fee is a ledger fact, so `tokens::validate` checks `tx.fee() >= BUNDLE_BASE + registry.registration_fee` → `RegistrationFeeTooLow`.

Validation order, `RegisterToken`: gate → `check_metadata` → authority is `None` or `Key` (`AuthorityNotAllowed`) → `None` requires `initial` (`InitialMintRequired`); `initial.amount != 0` → id not registered, registry not full → fee → `check_time(initial.time)` → the mint commitment not already in the tree (`TxError::CommitmentExists`). `index` is the registry index the creator sealed `initial`'s envelope for (`rand_getTokens`' `next_index`): the mint commitment contains the index, and another registration can commit while this one is being proved. A mismatch with `next_index` is `TokenError::IndexMismatch` — `BridgeAttest.asset`'s rule, for its reason: a lost race costs a re-proof, never a note nobody can open. The field is checked even without `initial`, and it is not part of the asset id.

`TokenMint`: gate → token exists → authority is `Key(pk)` (`NotKeyAuthority`) → `amount != 0` → `nonce == mint_nonce` → `check_time` → supply would not overflow → commitment not in tree → signature over `token_mint_message` last. Apply: `ledger.deposit(cm, ex)`, `add_supply`, `bump_nonce`.

`SetAuthority`: gate → `Key` → nonce → signature over `set_authority_message` by the **current** key. Apply: `set_key`, `bump_nonce`.

- [ ] **Step 1: Failing tests** in `tokens.rs` (use the ledger test helpers `bridge_notes.rs`'s tests use to build a gated ledger and a fee-bundle transaction with `StubExecutor`): one accept test per action asserting registry state, tree growth by exactly one note per mint, and the state root changing; one test per refusal listed above, each asserting the exact `TokenError`; `a_mint_signature_from_another_chain_id_is_refused`; `a_replayed_mint_is_refused_by_its_nonce`; `a_renounced_token_can_never_mint_again` (`SetAuthority { new: None }` then `TokenMint` → `NotKeyAuthority`); `every_token_action_is_disabled_without_the_gate`. In `gas.rs` tests: the three floors.
- [ ] **Step 2: Run** `cargo test -p randprotocol-core --lib ledger::tokens` — FAIL.
- [ ] **Step 3: Implement**; route in `validate_inner` step 7 with `a @ (Action::RegisterToken { .. } | Action::TokenMint { .. } | Action::SetAuthority { .. } | …) => tokens::validate(self, tx, a, executor)?` and in `apply_tx` beside `bridge_notes::apply`. `Action::bundle_less` is unchanged (all carry bundles).
- [ ] **Step 4: Run** `cargo test -p randprotocol-core --lib && cargo check --workspace --tests` (the node's and client's exhaustive `match`es on `Action` — `tx_json`, `created_notes`, `estimateFee` — will fail to compile: add arms that render `"kind"` only and `todo`-free minimal bodies; Tasks 6–7 fill them) — PASS.
- [ ] **Step 5: Commit** `tokens: RegisterToken, TokenMint, SetAuthority — permissionless creation, Key-signed mints with a per-token nonce, chain-computed mint notes`.

---

### Task 5: `TokenTransfer` and `TokenBurn`

**Files:** `types/transaction.rs`, `gas.rs`, `ledger/tokens.rs`, `ledger/bridge_notes.rs` (factor), `ledger/mod.rs`

**Interfaces:**
- Produces:

```rust
pub const MAX_MEMO_BYTES: usize = 2048;
TokenTransfer { asset_bundle: Bundle, #[serde(with = "crate::crypto::wire_bytes_opt")] memo: Option<Vec<u8>> },
TokenBurn { asset_bundle: Bundle, asset: u32, amount: u64 },
// ledger/tokens.rs — the one two-bundle rule, used by TokenTransfer, TokenBurn and BridgeBurn
pub(super) fn check_asset_bundle(ledger: &Ledger, tx: &Transaction, asset_bundle: &Bundle, asset: u32, burn: u64) -> Result<(), TxError>;
```

(If `crypto::wire_bytes` has no `Option` flavour, add `wire_bytes_opt` beside it, same encoding for `Some`.)

`check_asset_bundle`: `asset_bundle.asset == asset` (`BurnAssetMismatch` today — reuse the variants) → `fee == 0` → `burn == burn` → no nullifier/commitment shared with `tx.bundle` → `ledger.check_bundle(asset_bundle)`. The caller runs `check_bundle_proof` **last**. Move the body out of `bridge_notes::validate`'s `BridgeBurn` arm (:100-140) verbatim and call it from there.

`TokenTransfer`: gate → `asset_bundle.asset != 0` and registered (`UnknownToken`) → memo ≤ 2 048 (`MemoTooLarge`) → `check_asset_bundle(.., asset_bundle.asset, 0)` → proof. Apply: `ledger.apply_bundle_notes(asset_bundle, ex)`.
`TokenBurn`: gate → registered → authority is **not** `Bridge` (`BridgedToken`) → `amount != 0` → supply covers it → `check_asset_bundle(.., asset, amount)` → proof. Apply: notes, `sub_supply`.
`fee_floor`: both `2 * BUNDLE_BASE`. The size caps at `ledger/mod.rs:959-968` (`BridgeBurn`'s asset-bundle proof against `max_proof_bytes`) must cover the two new actions' `asset_bundle` — extend those match arms.

- [ ] **Step 1: Failing tests:** `a_token_transfer_moves_notes_and_touches_no_supply`; `a_transfer_of_asset_zero_is_refused`; `a_transfer_of_an_unregistered_index_is_refused`; `an_asset_bundle_paying_a_fee_is_refused`; `an_asset_bundle_that_burns_inside_a_transfer_is_refused`; `a_nullifier_shared_between_the_two_bundles_is_refused`; `a_memo_over_2048_bytes_is_refused_and_one_at_the_cap_is_not`; `a_token_burn_lowers_supply_by_exactly_the_burn`; `a_token_burn_of_a_bridged_token_is_refused`; `an_oversized_asset_bundle_proof_is_refused_before_verification`; and keep every existing `BridgeBurn` test green (the factor must not change behaviour).
- [ ] **Step 2–4:** as Task 4 (`cargo test -p randprotocol-core --lib`, `cargo check --workspace --tests`).
- [ ] **Step 5: Commit** `tokens: TokenTransfer and TokenBurn — the burn's two-bundle shape factored into one rule, an opaque 2 KiB memo`.

---

### Task 6: Node — persistence, note indexing, mempool, admission

**Files:** `crates/randprotocol-node/src/storage.rs` (:143-177 meta keys, `created_notes` :270-335, `load_ledger` :1187-1240, the commit batch that writes `META_SUPPLY`), `node.rs` (`reload_ledger` :137), `mempool.rs` (`still_applies` :440-470, the nullifier/commitment claim keys for a second bundle — find how `BridgeBurn`'s asset bundle is claimed and extend the same arms), `admission.rs` (`is_permanent` :104)

**Interfaces:**
- Produces: `const META_TOKENS: &str = "tokens";` `Storage::load_tokens(&self) -> Result<Option<TokenRegistry>>`.

- [ ] **Step 1: Failing tests** (storage.rs tests, beside the aggregation restart tests ~:3850):

```rust
#[test]
fn the_token_registry_survives_a_restart_with_the_same_state_root() { /* gated genesis → register + mint in a block → commit → drop Storage → reopen → load_ledger → roots equal, tokens().unwrap().get(1).total_supply equal */ }
#[test]
fn reload_ledger_restores_the_tokens_gate() { /* node::reload_ledger on the same datadir → tokens().is_some() */ }
#[test]
fn minted_and_transferred_token_notes_are_indexed_like_any_note() { /* created_notes(tx) for TokenMint = 1 note at the mint commitment; RegisterToken with initial = fee bundle's 2 + 1; TokenTransfer/TokenBurn = 4 commitments */ }
```

mempool: `a_pooled_mint_with_a_stale_nonce_is_dropped`; `two_transfers_spending_the_same_asset_note_conflict`. admission: `is_permanent` is true for `BadName`, `BadSymbol`, `TooManyDecimals`, `AuthorityNotAllowed`, `InitialMintRequired`, `MemoTooLarge`, `ZeroAmount`, `BadSignature`; false for `BadNonce`, `UnknownToken`, `AlreadyRegistered`, `IndexMismatch`, `SupplyOverflow`, `SupplyUnderflow`, `Disabled`, `RegistrationFeeTooLow`.

- [ ] **Step 2: Run** `cargo test -p randprotocol-node --lib -- tokens token_` — FAIL.
- [ ] **Step 3: Implement.** Write `META_TOKENS` in the same atomic batch as `META_SUPPLY`; restore in `load_ledger` next to `set_bridge` and in `reload_ledger` next to `set_aggregation`; `truncate_to` gets it for free if it replays from genesis — verify by reading it, and if it restores from blobs, restore this one. Sync: confirm `apply_block_for_sync` and `propose` both go through `Ledger::close_block`/`apply_tx` so no separate path exists.
- [ ] **Step 4: Run** `cargo test -p randprotocol-node --lib` — PASS (modulo the known `RECURSION_FIXTURES` aggregation tests).
- [ ] **Step 5: Commit** `node: the token registry persists and restarts to the same root; token notes are indexed; pool and refusal rules for the five actions`.

---

### Task 7: RPC

**Files:** `crates/randprotocol-node/src/rpc.rs` (`assets_json` :672, `tx_json` :853, methods :1591-1630, `rand_estimateFee`), `docs/rpc.md`

**Interfaces — JSON shapes (the client and randscan rely on them):**

```json
// rand_getToken [index | "id-hex"]  and each row of rand_getTokens [from_index?, limit? ≤ 256]
{ "index": 1, "id": "…64 hex…", "name": "Tether USD", "symbol": "zUSDT", "decimals": 8,
  "authority": { "kind": "bridge", "chain": 2, "token": "…64 hex…" },
  "mint_nonce": 0, "total_supply": "100000000", "registered_at": 0 }
// authority kinds: {"kind":"none"} | {"kind":"key","key":"hex"} | {"kind":"bridge",…} | {"kind":"program","program":"hex"}
// rand_getTokenSupply [index] → "100000000"          (amounts are decimal strings)
// rand_getTokens on a chain without the gate → { "enabled": false, "tokens": [] }; with it → { "enabled": true, "registration_fee": "…", "next_index": 3, "tokens": [...] }
```

`rand_getAssets` keeps its old row shape (`asset`, `chain`, `token`, `index`), built from the registry's `Bridge` tokens. `rand_getBridgeState`'s `assets` array likewise. `tx_json` kinds: `register_token`, `token_mint` (with the computed `commitment`), `token_transfer` (`asset`, the asset bundle's nullifiers/commitments, `memo_bytes`), `token_burn`, `set_authority`. `rand_estimateFee` accepts those five `kind`s (`register_token` adds the registration fee).

- [ ] **Step 1: Failing tests** beside `tx_json_renders_every_new_action_kind` (:3110) and the `rand_getAssets` test (:3253): one per method and kind, asserting the exact JSON above.
- [ ] **Step 2–4:** `cargo test -p randprotocol-node --lib rpc`.
- [ ] **Step 5:** update `docs/rpc.md` (methods, wire kinds, changelog entry "RPL") and commit `rpc: rand_getTokens, rand_getToken, rand_getTokenSupply; the five token kinds in tx_json and estimateFee; rand_getAssets served from the registry`.

---

### Task 8: Client — wallet submissions and `rand token`

**Files:** `crates/randprotocol-client/src/lib.rs` (`RpcClient`, `AssetRow` → add `TokenRow`), `wallet.rs` (beside `submit_burn` :1119), `main.rs` (`Cmd`), `docs/cli.md`

**Interfaces:**

```rust
pub struct TokenRow { pub index: u32, pub id: String, pub name: String, pub symbol: String, pub decimals: u8,
    pub authority: serde_json::Value, pub mint_nonce: u64, pub total_supply: u64 }
impl RpcClient { pub async fn tokens(&self) -> Result<(bool, u64, u32, Vec<TokenRow>)>;  // enabled, registration_fee, next_index, rows
                 pub async fn token(&self, index: u32) -> Result<TokenRow>; }
// wallet.rs — each mirrors submit_burn's shape, arguments and Submission
pub async fn send_token(rpc, w, store, asset: u32, to: &ShieldedAddress, amount: u64, memo: Option<Vec<u8>>, fee, profile, backend, chain_id, wait) -> Result<Submission>;
pub async fn burn_token(rpc, w, store, asset: u32, amount: u64, fee, …) -> Result<Submission>;
pub async fn create_token(rpc, w, store, name, symbol, decimals, authority: MintAuthority, initial: Option<u64>, fee, …) -> Result<(Submission, u32)>;
pub async fn mint_token(rpc, w, store, authority_key: &Keypair, asset: u32, to: &ShieldedAddress, amount: u64, fee, …) -> Result<Submission>;
pub async fn set_authority(rpc, w, store, authority_key: &Keypair, asset: u32, new: Option<PublicKey>, fee, …) -> Result<Submission>;
```

`send_token` plans: `[Plan::select(store, asset, to, amount, 0, 0), Plan::select(store, 0, &w.address, 0, fee, 0)]` → `prove_bundles` → `Action::TokenTransfer` — `submit_burn` line for line. Pre-checks before any proving (two proofs ≈ 200 s): asset ≠ 0; the token exists (`rpc.token`); amount ≠ 0; the wallet holds ≥ `fee` RAND — else *"a token transfer pays its fee in RAND, and this wallet holds none: send it some RAND first"*; memo ≤ 2 048. `create_token` reads `next_index` and seals `initial` against it; on `IndexMismatch` it reports *"another token was registered first; re-run"*. The mint authority key is a Dilithium2 key file written by `rand token create --authority-key-out <FILE>` (0600, the validator key file's format and permission code).

CLI: `rand token create --name --symbol --decimals [--fixed-supply N --to ADDR | --authority-key-out FILE]`, `mint --asset --to --amount --authority-key`, `send --asset --to --amount`, `burn --asset --amount`, `info <index|id>`, `list`, `set-authority --asset --authority-key [--new-key FILE | --renounce]`. Amount arguments parse with the token's `decimals` (reuse the RAND amount parser, parameterised on decimals). `asset-balance` prints `symbol` beside each index.

- [ ] **Step 1: Failing unit tests** in `wallet.rs` tests (no proving): plan shapes for `send_token` (`asset_plan.fee == 0`, `fee_plan.asset == 0`); each pre-check's exact error text; amount parsing at 8 and 0 decimals; `TokenRow` deserialises Task 7's JSON.
- [ ] **Step 2–4:** `cargo test -p randprotocol-client --lib`.
- [ ] **Step 5:** `docs/cli.md` section "Tokens (RPL)"; commit `client: rand token — create, mint, send, burn, info, list, set-authority; two-bundle submissions with RAND pre-checks`.

---

### Task 9: Allowances

**Files:** Create `crates/randprotocol-client/src/allowance.rs`; modify `wallet.rs` (`KeyFile` → version 3 with `#[serde(default)] allowances`, scan), `main.rs`, `Cargo.toml` (`ml-kem = "=0.3.2"`, `chacha20poly1305 = "=0.11.0"` — the zkvm crate's exact pins)

**Interfaces:**

```rust
pub const GRANT_VERSION: u8 = 1;
pub struct AllowanceGrant { pub allowance_sk: SpendKey, pub asset: u32 }
pub fn allowance_sk(owner: &SpendKey, delegate_pk: &Word8, asset: u32, n: u32) -> SpendKey;   // hash domain rand-rpl-allowance-1
pub fn seal_grant(grant: &AllowanceGrant, delegate: &ShieldedAddress) -> Vec<u8>;             // 1 ‖ kem_ct(1088) ‖ chacha20poly1305(ss, nonce 0, aad b"rand-rpl-grant-1", sk_bytes ‖ asset_be)
pub fn open_grant(memo: &[u8], vk: &ViewingKey) -> Option<AllowanceGrant>;                    // vk.kem_keys().0 decapsulates; None on any failure
// KeyFile v3
pub struct AllowanceRecord { pub role: Role /* Owner | Delegate */, pub asset: u32, pub counterparty_pk: String, pub n: u32, pub spend_key: Option<String> /* Delegate only */ }
```

Derive `allowance_sk` with the hash the zkvm crate exposes for `SpendKey`-sized outputs (`randprotocol_zkvm::notes::hash`-family over a client-side domain constant; if no public hash fits, use `blake3` keyed derivation reduced into the field the way `SpendKey` generation does — read `SpendKey`'s constructor and reuse it). An Owner record stores only `n` (the key re-derives); a Delegate record stores the key.

CLI: `rand token approve --asset --delegate ADDR --amount` (= `send_token` to `Wallet::from(allowance_sk).address` with `memo = seal_grant`), `allowance [--asset] [--delegate]` (scans each allowance wallet, prints balances), `transfer-from --asset --owner-pk --to --amount` (proves the asset bundle with the allowance wallet's notes and change back to the allowance address, the fee bundle with the delegate's own wallet — `prove_bundles` takes one wallet today: add a per-plan wallet argument), `revoke --asset --delegate` (spends every allowance note back to the owner). Scan: for each `TokenTransfer` with a memo in scanned blocks, `open_grant` → add a Delegate record (idempotent).

- [ ] **Step 1: Failing tests** (`allowance.rs`): `a_grant_round_trips_to_the_delegate_and_to_nobody_else`; `a_grant_is_at_most_2048_bytes` (assert the exact length `1 + 1088 + 36 + 16`); `a_truncated_or_foreign_memo_opens_to_none`; `the_allowance_key_is_deterministic_and_distinct_per_delegate_asset_and_counter`; `a_v2_key_file_still_loads` (wallet.rs).
- [ ] **Step 2–4:** `cargo test -p randprotocol-client --lib`.
- [ ] **Step 5:** commit `client: RPL allowances — approve, allowance, transfer-from, revoke over a shared sub-key delivered in a TokenTransfer memo`.

---

### Task 10: Listing a bridged token, or adding a backing, after genesis

> Amended by spec §12: payload 3 is `AddBacking { asset_index, chain, token }` for an existing bridged token, and `RegisterToken` carries the new token's first backing. Apply the rules below to both.

**Files:** `crates/bridge-codec/src/payload.rs` (:138 `Payload`), `bridge/state.rs` (`check_attest`'s governance arm, `AttestPlan`, `AttestOutcome`), `ledger/bridge_notes.rs` (apply), `docs/bridge.md`. **Check first** whether main's bridge-codec has moved (another session had uncommitted edits there): `git log main -- crates/bridge-codec` and rebase if so.

**Interfaces:**

```rust
pub struct RegisterToken { pub chain: u16, pub token: [u8; 32], pub name: String, pub symbol: String }
// wire: id (1) = 3 ‖ chain (2 BE) ‖ token (32) ‖ name_len (1) ‖ name ‖ symbol_len (1) ‖ symbol ; any trailing byte is CodecError::BadPayloadLength
Payload::RegisterToken(RegisterToken)
AttestPlan::RegisterToken(RegisterToken)  /  AttestOutcome::TokenListed(u32)
```

Rules: governance emitter and **current** set only (the `GuardianSetUpgrade` arm's two checks, verbatim); `check_metadata(name, symbol, 8)`; not already listed (`TokenError::AlreadyRegistered`). Apply registers with `MintAuthority::Bridge`, decimals 8. The carrying `BridgeAttest`'s `recipient/r/time/asset/envelope` are ignored exactly as a rotation ignores them.

- [ ] **Step 1: Failing tests:** codec round-trip and every malformed length; a listing signed by a superseded set is `SetExpired`; from a non-governance emitter `WrongEmitter`; a listed token then accepts a deposit; a second listing is refused. Add the vector to the pinned attestation vectors the crate tests read.
- [ ] **Step 2–4:** `cargo test -p bridge-codec && cargo test -p randprotocol-core --lib bridge`.
- [ ] **Step 5:** commit `bridge: governance payload 3 lists a bridged token — guardians, current set only, decimals 8`. Note in the commit body that `../bridge`'s contracts must learn to ignore payload 3 (the chain-14 spec owns that).

---

### Task 11: End-to-end tests, docs, full suite

**Files:** `crates/randprotocol-client/tests/` (the wallet flow), `crates/randprotocol-node/tests/cluster.rs`, `docs/tokens.md` (new), `docs/bridge.md`, `docs/confidential.md` (fee table), `README.md`, `AGENTS.md`

- [ ] **Step 1: Wallet-flow stage** `tokens` on a gated genesis (`registration_fee` 1 RAND), every proving call inside the proving slot: create (`Key`) → mint 1 000 to A → A sends 400 to B → A approves 300 to B → B `transfer-from` 100 to C → A revokes (200 back) → A burns 50. Assert after each step: `rand_getTokenSupply` (1 000 → 950 at the end), each wallet's `balance_of(1)` (A 450, B 400, C 100), and that B's scan imported the grant.
- [ ] **Step 2: Cluster test** `a_token_transfer_commits_on_every_node_with_one_state_root`: three nodes, gated genesis, register + mint + one transfer; every node's `rand_getToken(1)` and state root agree; a restarted node agrees.
- [ ] **Step 3: Run the two suites one at a time** (`cargo test --release -p randprotocol-client --test <wallet flow>`; `cargo test --release -p randprotocol-node --test cluster a_token_transfer`) — PASS.
- [ ] **Step 4: Docs.** `docs/tokens.md`: the standard (spec §§3–5, 7), the ERC-20/SPL difference table (spec §8), the allowance properties verbatim from spec §7, the privacy limits (action kind and asset index are visible). `docs/bridge.md`: listed tokens, 8 decimals (correct the "own units" line at ~:591), no first-sighting race. `docs/confidential.md`: five rows in the fee table. `README.md`: one section. `AGENTS.md`: a project-memory entry (decisions, the gate invariant, `META_TOKENS` restore trap, the memo/vendored-envelope reason, measured suite times).
- [ ] **Step 5: Full suite,** detached: `RECURSION_FIXTURES=<cache if present> cargo test --workspace --release -- --skip round_trips --skip two_test_profile`. Record the wall times in `AGENTS.md`. Report failures with output; the known pre-existing one is `the_genesis_hash_is_pinned` in `main.rs`.
- [ ] **Step 6: Commit** `docs: RPL — docs/tokens.md, the bridge on listed tokens, fee table, AGENTS.md record`, then finish with superpowers:finishing-a-development-branch (rebase on main, fast-forward, no merge commit).
