# RPL: the RandProtocol token standard

Status: approved by the user 2026-09-19 (design section by section, then this document). Target: chain 14
and v0.5 (the bridge). First two registrations: zUSDT and zUSDC.

## 1. Problem

The shielded pool already carries an asset word in every note (`(pk, from, amount, asset, time,
r)`), and the bridge keeps a registry that maps a bridged token to a dense `u32` index
(`bridge/state.rs`, `AssetInfo { chain, token, index }`). Three things are missing:

| gap | today |
|---|---|
| a token cannot be transferred | `Ledger::validate_inner` refuses any transaction bundle with `asset != 0` (`TxError::UnsupportedAsset`); the bundle guest enforces `asset ≠ 0 ⇒ fee = 0`, and the only two-bundle transaction is `BridgeBurn`. A bridged asset can be deposited and burned, never sent |
| a token has no identity beyond the bridge | no name, symbol, decimals, supply or issuer; the registry lives inside `BridgeState` and does not exist on a chain without a bridge; nobody but the guardians can create an asset |
| any attested token is auto-registered | a first sighting registers whatever `(chain, token)` the attestation names, so a worthless ERC-20 called "USDC" would become a bridged asset like the real one |

Programs cannot fill the gap: a `Call` is stateless (its only effect is a receipt of eight output
words; the state root commits program ids, never storage), so an ERC-20-style contract has nowhere
to keep balances, and public balances would make tokens the one transparent asset on a shielded
chain.

## 2. Decisions (user, 2026-09-19)

1. The standard is named **RPL**. It is specified and built first; the bridge registry is rebased
   onto it; zUSDT and zUSDC are its first two registrations; chain 14, the testnet contracts and
   the guardian and relayer follow as their own specs.
2. A token is a **shielded native asset**: an entry in one ledger registry (SPL's structure), with
   balances held as notes. It is not a contract.
3. **Creating a token is permissionless.** Units of an existing token are issued only under the
   mint authority fixed at its registration.
4. **Symbols are not unique**, as with ERC-20 and SPL. A token's identity is its asset id.
5. **Fees are paid in RAND** and the sender must hold RAND, as an ERC-20 transfer needs ETH. A
   token transfer reuses the burn's two-bundle shape, so no circuit changes.
6. **Allowances** (`approve` / `transferFrom` / delegate) are in v1 as allowance accounts: a shared
   sub-key, no consensus change (§7). Program-owned notes are RPL-2; an attributable in-circuit
   ticket is recorded as a later variant (§11).
7. **Freeze, blacklist and pause are out of scope.**

## 3. The registry

A ledger-level `TokenRegistry` (`randprotocol-core/src/ledger/tokens.rs`) replaces
`BridgeState.assets` and `BridgeState.next_index`. `BridgeState` keeps guardians, emitters, spent
digests and burns, and resolves assets through the registry.

```rust
pub struct TokenInfo {
    pub id: AssetId,            // 32 bytes, the canonical identity
    pub index: u32,             // the note's asset word; dense, 1, 2, …; 0 is RAND, never registered
    pub name: String,           // 1..=32 bytes, UTF-8, immutable
    pub symbol: String,         // 1..=12 bytes, ASCII graphic, immutable
    pub decimals: u8,           // 0..=9, immutable
    pub authority: MintAuthority,
    pub mint_nonce: u64,        // Key authority's replay counter
    pub total_supply: u64,      // checked arithmetic; overflow refuses the mint
    pub registered_at: u64,     // height
}

pub enum MintAuthority {
    None,                                   // fixed supply, minted at registration
    Key(PublicKey),                         // Dilithium2, crypto.rs's PublicKey
    Bridge { chain: u16, token: [u8; 32] }, // guardian attestations
    Program(ProgramId),                     // reserved: encodes, refused at registration in v1
}
```

**Decimals are capped at 9.** Amounts are `u64`; at 18 decimals a `u64` holds 18.4 whole tokens.
9 is RAND's own precision. Bridged tokens register with **8** decimals: the attestation wire format
already normalises every amount to `d_max = 8` (`bridge/spec/ATTESTATION.md` §3.7), so 1 USDT (6
decimals on Ethereum) arrives as `100_000_000`. `docs/bridge.md`'s "the bridged asset's own units"
line is corrected to say so.

**Asset id.**
- `Bridge`: `blake3("rand-bridge-asset", chain ‖ token)`, unchanged, so the whitepaper's
  `asset_z` and the contracts stay valid.
- Everything else: `blake3("rand-rpl-asset", bincode(name, symbol, decimals, authority,
  initial_supply, salt))` with a 32-byte creator-chosen `salt`. Content-addressed like a program
  id; registering an id that exists is refused (`TokenError::AlreadyRegistered`).

**The gate.** `Genesis::tokens: Option<TokensConfig>`, omitted from the file and the genesis
commitment when absent, exactly as `bridge` and `aggregation` are. Without it every token action
is refused before any other check (`TokenError::Disabled`) and the chain is byte-for-byte chain
13. A genesis with a `bridge` section must also have a `tokens` section (`GenesisError`).

```rust
pub struct TokensConfig {
    pub registration_fee: u64,          // RAND base units; bounds 1 RAND ..= 10 000 RAND
    pub tokens: Vec<GenesisToken>,      // registered in order, indices 1, 2, …
}
```

**State root.** A `tokens_root` component: the merkle root over `blake3("rand-token-leaf-1",
bincode(TokenInfo))` leaves in index order, appended when the gate is on, under domain
`rand-state-4`. The bridge root stops committing assets and its leaf domain is bumped.

**Persistence.** `META_TOKENS`, one bincode blob beside `META_SUPPLY`, written in the block's
atomic commit. `load_ledger` and `reload_ledger` restore the registry and the gate — the
fork-at-first-restart trap aggregation hit. `truncate_to` rebuilds it by replay.

## 4. Actions

Every token action rides on a transaction whose `tx.bundle` is a RAND fee bundle (asset 0).

| action | fields | fee floor | effect |
|---|---|---|---|
| `RegisterToken` | `name, symbol, decimals, authority, initial: Option<InitialMint>, salt, index` | `BUNDLE_BASE + registration_fee` | assigns `next_index`; mints `initial` if present |
| `TokenMint` | `asset, amount, recipient, r, time, envelope, nonce, signature` | `BUNDLE_BASE` | `Key` authority only; appends one note; `total_supply += amount` |
| `TokenTransfer` | `asset_bundle, memo: Option<Vec<u8>>` | `2 * BUNDLE_BASE` | shielded; `asset_bundle.fee == 0`, `.burn == 0`, `.asset` registered; `memo` is opaque, at most 2 048 bytes, and the chain checks only its size (SPL's memo) |
| `TokenBurn` | `asset_bundle, asset, amount` | `2 * BUNDLE_BASE` | `asset_bundle.burn == amount`; `total_supply -= amount`; refused for a `Bridge` token (use `BridgeBurn`) |
| `SetAuthority` | `asset, new: Option<PublicKey>, nonce, signature` | `BUNDLE_BASE` | `Key → Key` or `Key → None`; nothing else |
| `BridgeAttest` | unchanged | unchanged | now also `total_supply += amount`; refuses an unlisted token (§5) |
| `BridgeBurn` | unchanged | unchanged | now also `total_supply -= amount` |

`InitialMint { amount, recipient, r, time, envelope }`. `index` names the registry index the
creator sealed the initial note for; a mismatch with `next_index` is refused (`IndexMismatch`), as
`BridgeAttest.asset` is, so a lost registration race costs a re-proof and never strands a note. `authority: None` requires `initial`;
`Bridge` and `Program` are refused in a `RegisterToken` (`TokenError::AuthorityNotAllowed`).

**Minted notes** are chain-computed exactly as a deposit is:
`note_commitment(recipient.pk, MINT_FROM, amount, index, time, r)` with a new constant `MINT_FROM`
distinct from `DEPOSIT_FROM`. The amount and the recipient's `pk` are public on the wire; the
recipient can then move the note with a shielded transfer.

**Signatures.** `Key` mints and `SetAuthority` sign
`blake3("rand-rpl-mint-1" | "rand-rpl-authority-1", chain_id ‖ asset_id ‖ nonce ‖ body)`, where
`body` is `(amount, commitment)` or the new key. `nonce` must equal the token's `mint_nonce`, which
then increments: no replay on this chain or another.

**Two-bundle rules** are `BridgeBurn`'s, factored into one function the three actions share: the
asset bundle's asset matches, its fee is zero, its burn matches, no nullifier or commitment is
shared with the fee bundle, `check_bundle`, then `check_bundle_proof` last (cheap before
expensive). The `UnsupportedAsset` refusal on `tx.bundle` stays: the fee bundle is always RAND.
Admission's permanent-verdict allowlist (`is_permanent`) gains the byte-level token refusals only.

**What is public.** Registration, every mint and every burn, with amounts: `total_supply` is
auditable by anyone, which is the supply auditability the whitepaper promises. Transfers reveal
nothing, including which token moved — except that a `TokenTransfer` is distinguishable from a
RAND transfer by its action kind, and the asset bundle names its `asset` index. (Hiding the index
needs the multi-asset bundle of §11.)

## 5. The bridge on RPL

- Bridged tokens are **listed, never auto-registered**. `GenesisToken` entries with a `Bridge`
  authority register zUSDT and zUSDC at indices 1 and 2 with their metadata. After genesis, a new
  guardian governance payload `RegisterToken { chain, token, name, symbol }` (bridge-codec payload
  id 3, decimals fixed at 8) adds one. An attestation naming an unlisted `(chain, token)` is
  `BridgeError::UnlistedToken`.
- This removes the first-sighting index race: `BridgeAttest.asset` always names a registered
  index, and `TxError::AssetIndexMismatch` can only mean a wrong index.
- One bridged token is one `(chain, token)` pair. USDT on Ethereum and USDT on Tron are two
  tokens with two indices; chain 14 lists the Ethereum testnet pair only. Unifying them is out of
  scope.
- `../bridge`'s contracts and `vectors/attestations.json` are unchanged except for the new
  governance payload's vector.

## 6. Surface

- **RPC**: `rand_getTokens` (paged), `rand_getToken` (by index or id), `rand_getTokenSupply`;
  `rand_getAssets` stays as an alias returning the old shape; `tx_json` gains the five kinds.
- **CLI** (`rand token …`): `create`, `mint`, `send`, `burn`, `info`, `list`, `set-authority`,
  and §7's `approve`, `allowance`, `transfer-from`, `revoke`. `asset-balance` stays. The wallet
  pre-checks everything cheap before proving: two proofs are ~200 s.
- **Wallet**: `send_token` builds the fee bundle and the asset bundle under one proving-slot
  permit. It refuses up front when the wallet holds no RAND.
- **Explorer** (randscan) token pages follow in their own change.

## 7. Allowances

An allowance is a note under a key both parties hold. No consensus rule knows about it.

- **Key.** `allowance_sk = hash("rand-rpl-allowance-1", owner_sk ‖ delegate_pk ‖ asset ‖ n)`,
  `n` a counter the owner's key file stores per `(delegate, asset)`. Re-derivable from the owner's
  spend key, so a lost key file loses nothing.
- **`approve(delegate, asset, N)`**: a `TokenTransfer` of `N` to `allowance_sk`'s address whose
  `memo` carries the grant: `version (1) ‖ kem_ct (1088) ‖ chacha20poly1305(ss, AllowanceGrant {
  allowance_sk, asset })`, encapsulated to the delegate's ML-KEM key. The delegate's wallet
  trial-opens every `TokenTransfer` memo on scan and imports a grant as an allowance account. The
  owner's main spend key is never shared. (The note envelope cannot carry it: its plaintext is the
  fixed note layout of the vendored `viewing.rs`, which is never hand-edited.) A memo's presence
  is visible; a wallet may attach a random memo of the same length to an ordinary transfer.
- **`transfer-from`**: the delegate spends from the allowance account to any recipient, change
  back to the allowance address, and pays the RAND fee from its own wallet.
- **`allowance`**: the unspent balance under `allowance_sk`. **Increase**: another transfer in.
  **`revoke`**: the owner spends the notes back to its own address.
- **Properties, stated in `docs/tokens.md`**: loss is bounded by `N`; funds are earmarked (no
  unlimited approvals); on chain an approval is indistinguishable from any token transfer; inside
  the account both parties see each other's activity; a spend is not attributable to either party
  and a revoke races a spend, first nullifier wins; expiry is a wallet-side auto-revoke, not a
  chain rule.

## 8. Differences from ERC-20 and SPL (recorded for `docs/tokens.md`)

No public balances or transfer events; no per-token code (tax, rebase, hooks); no freeze; tokens
cannot be held by programs; `u64` amounts and at most 9 decimals; receiving needs no account
setup; a transfer is two STARK proofs; metadata is on chain and immutable; allowances are
earmarked accounts rather than a counter.

## 9. Testing

- Unit, per action: the accept path and every refusal; supply overflow; nonce replay; a signature
  from another chain id; `Bridge`/`Program` refused in `RegisterToken`; `TokenBurn` on a bridged
  token; an unlisted attestation.
- The gate: a genesis without `tokens` hashes, roots and refuses exactly as chain 13 (pinned
  vector); a `bridge` section without `tokens` is a genesis error.
- State root and persistence: register, mint, restart, same root; `truncate_to` replay.
- Sync: `apply_block_for_sync` and `propose` agree (one `close_block` path).
- Wallet flow, one new stage under the proving slot: create → mint → send → approve → partial
  transfer-from → revoke → burn. Cluster: one test, a token transfer across three nodes.
- `cargo check --tests` before trusting a `--lib` gate (new `Action` variants and a `Genesis`
  field touch `main.rs` and `tests/`).

## 10. Rollout

Hard fork: new actions, a new genesis section, `rand-state-4`, a moved bridge registry. Ships as
chain 14 (its own spec: bridge section, guardian set, zUSDT/zUSDC listings, registration fee).
Branch `rpl`, worktree `/tmp/fullnode-rpl`, merged by rebase and fast-forward.

## 11. Future work

- **Multi-asset bundle**: one proof balances a token and the RAND fee, and hides the asset index.
  A circuits change (`research` first, vendored here).
- **RPL-2, program-owned notes**: a note spendable only with a `Call` proof of a named program —
  what lets a DEX or an escrow hold tokens. Needs a program-state design.
- **`Program` mint authority**: a mint authorised by a call receipt whose outputs commit to
  `(asset, amount, commitment, supply_before)`.
- **Attributable allowances**: an owner-signed ticket checked in the circuit, with an on-chain
  spend counter; enforceable expiry, at the cost of linkable spends.
- Fees payable in a token; freeze and compliance controls for natively issued regulated tokens.
