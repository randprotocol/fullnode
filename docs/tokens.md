# RPL: the RandProtocol token standard

RPL is RandProtocol's own token standard, built for chain 14 (v0.5) — reviewed and merged on the
integration branch, not yet cut as a chain (see `AGENTS.md`'s v0.5 entry for the current state).
A token is a **shielded native asset** — an entry in one ledger registry, with balances held as ordinary notes in the same
commitment tree RAND uses — not a contract. Programs (`docs/confidential.md`) are stateless: a
`Call` writes only a receipt, so an ERC-20-style contract would have nowhere to keep a balance, and
a public balance would make tokens the one transparent asset on an otherwise shielded chain. RPL
sidesteps both problems by making a token a first-class ledger object instead.

This page is the user's and integrator's guide: what a token is, how one is created, how a transfer
looks on chain, the CLI and RPC surface, and how RPL compares with ERC-20 and SPL. The design spec
is `docs/superpowers/specs/2026-09-19-rpl-token-standard-design.md`; the wire-level reference is
`docs/rpc.md`; the bridge's use of RPL (one bridged token, many backings; mint caps; a PQ
co-signature) is `docs/bridge.md` §§13–20; the shielded pool this all sits on is `docs/shielded.md`.

## 1. A token is a registry entry

`TokenRegistry` (`crates/randprotocol-core/src/ledger/tokens.rs`) is a ledger-level table shared by
every token, native or bridged — the same registry the bridge resolves an asset's index through
(`docs/bridge.md` §13). Each entry:

```rust
pub struct TokenInfo {
    pub id: AssetId,            // 32 bytes, content-addressed
    pub index: u32,             // the note's asset word; dense, 1, 2, …; 0 is RAND, never registered
    pub name: String,           // 1..=32 bytes, UTF-8, immutable
    pub symbol: String,         // 1..=12 ASCII graphic bytes, immutable
    pub decimals: u8,           // 0..=9, immutable
    pub authority: MintAuthority,
    pub mint_nonce: u64,        // Key authority's replay counter
    pub total_supply: u64,      // checked arithmetic; overflow refuses the mint
    pub registered_at: u64,     // height
}
```

**Decimals are capped at 9** (`MAX_DECIMALS`): amounts are `u64`, and at 18 decimals a `u64` holds
only 18.4 whole tokens — 9 is RAND's own precision and enough for any real currency. A bridged
token always registers at 8 decimals (`BRIDGE_DECIMALS`), whatever its source coins' own decimal
counts are (`docs/bridge.md` §13).

**The gate.** `Genesis::tokens: Option<TokensConfig>` is omitted from the file and the genesis hash
when absent, exactly as `bridge` and `aggregation` are: without it, every token action is refused
before any other check (`TokenError::Disabled`) and the chain hashes, roots and behaves
byte-for-byte as one without RPL. A genesis with a `bridge` section must also have a `tokens`
section.

**Genesis alloc notes, chain 14 rule.** When a `tokens` section is present, every genesis `alloc`
note must carry its opening — `pk`, `time` and `r`, beside its `cm` and `amount` — and the node
recomputes `note_commitment(pk, [0; 8], amount, 0, time, r)` at asset 0 and refuses a genesis file
whose `cm` does not match. An opaque, unopened `cm` is otherwise how a genesis states a note today,
and once RPL gives a note an `asset` word to name, an opaque alloc `cm` is the one way a genesis
author could put an unbacked note of any asset into the pool without anyone able to check it —
this closes that for the alloc set the same way the faucet mint was already closed (audit v3,
POOL-1).

**State root.** A `tokens_root` component — the merkle root of `blake3("rand-token-leaf-1",
bincode(TokenInfo))` leaves in index order — folds into the state root under domain `rand-state-4`
when the gate is on. `TokenRegistry::root()` itself uses domain `rand-token-registry-2`.
Persistence is `META_TOKENS`, one bincode blob beside `META_SUPPLY`, restored by `load_ledger` and
`reload_ledger` and rebuilt by replay in `truncate_to`.

## 2. Identity: asset id, index, and `rpl1…`

A token has two names and the RPC gives both:

- **The asset id** (`AssetId`, 32 bytes) is content-addressed, like a program id.
  - A **native** token's id is `blake3("rand-rpl-asset", bincode(name, symbol, decimals,
    authority, initial: Option<InitialMint>, salt))`, where `salt` is a creator-chosen 32 bytes.
  - A **bridged** token's id is `blake3("rand-rpl-asset", bincode(name, symbol, BRIDGE_DECIMALS,
    salt))` — no longer over a `(chain, token)` pair, because one bridged token (zUSD) now spans
    seven of them (`docs/bridge.md` §13). The old per-`(chain, token)` value is still what
    `rand_bridgeAssetId` computes and what `rand_getAssets` prints per backing row — a different,
    narrower identifier for the wire, not the token's own id.
  - Registering an id that already exists is refused (`TokenError::AlreadyRegistered`).
- **The index** (`u32`) is what a note's `asset` word actually carries — a 32-byte id does not fit
  in one word. Indices are dense and assigned in registration order, `FIRST_TOKEN_INDEX = 1`; index
  0 is RAND and is never registered.
- **The text form, `rpl1…`** (bridge hardening spec §8): bech32m (BIP-350) with human-readable
  part `rpl` over the 32 id bytes — 52 data characters plus a 6-character checksum, **62
  characters** in all (`crates/randprotocol-core/src/token_id.rs`). Shown beside the 64-hex id
  everywhere a token is named, and accepted anywhere one is looked up (hex stays accepted too).
  Parsing is strict — a bad checksum, the wrong human-readable part, a payload that is not exactly
  32 clean bytes, or mixed upper/lower case are each refused outright, so a typo can never resolve
  to a different real token.

## 3. Mint authorities

```rust
pub enum MintAuthority {
    None,                                   // fixed supply, minted once at registration
    Key(PublicKey),                         // Dilithium2; further mints need this key's signature
    Bridge { backings: Vec<Backing> },      // guardian attestations; docs/bridge.md §13
    Program(ProgramId),                     // reserved: refused at registration in v1
}
```

`None` is a fixed-supply token — whatever `initial` mints at registration is all there will ever
be, and `initial` is then required. `Key` can mint again later, signed, and can hand itself to
another key or renounce (`SetAuthority`, §4 below). `Bridge` is not a minter in the sense the other
two are: its supply moves only through a lock (`BridgeAttest`) or a release (`BridgeBurn`), never a
direct mint. A `RegisterToken` naming `Bridge` or `Program` is refused (`TokenError::
AuthorityNotAllowed`) — a `Bridge`-authority token exists only through the bridge governance
actions of `docs/bridge.md` §18 — and `TokenMint`/`SetAuthority` on any token whose authority is
not `Key` is refused separately (`TokenError::NotKeyAuthority`). `Program` is reserved: a mint
authorised by a call receipt is future work (spec §11).

**A `Key` authority is exactly one Dilithium2 public key, never longer.** `RegisterToken` and
`SetAuthority` both refuse a `Key`/`new` whose byte length is not `PUBLIC_KEY_LEN`
(`TokenError::BadAuthorityKey`) — otherwise a flat-fee, faucet-funded registration could carry an
arbitrarily large "key" into permanent, per-block-rehashed registry state. `InitialMint` and
`TokenMint`'s `recipient.kem_ek` are held to the ML-KEM key length the same way, for the same
reason: both are consensus state or block space bought at a fee that does not scale with size.

## 4. Creating a token

**Creation is permissionless**, and **symbols are not unique** — as with ERC-20 and SPL, a token's
identity is its asset id, not its name or ticker. `Action::RegisterToken { name, symbol, decimals,
authority, initial: Option<InitialMint>, salt, index }` rides on an ordinary RAND fee bundle
(`asset` 0), paying `BUNDLE_BASE + registration_fee`: `registration_fee` is a genesis parameter
(`TokensConfig`), bounded `1 RAND ..= 10 000 RAND` (`MIN_REGISTRATION_FEE`/`MAX_REGISTRATION_FEE`),
so creating a spam token always costs something real. `index` names the registry index the creator
sealed `initial`'s note for; a mismatch with the registry's actual next index is refused
(`TokenError::IndexMismatch { expected, got }`) rather than stranding the note — a lost race just
costs a re-proof at the corrected index.

`name` is 1 to 32 UTF-8 bytes (spaces allowed: "Tether USD" is fine); `symbol` is 1 to 12 bytes of
ASCII graphic characters (`0x21..=0x7e`, no whitespace); `decimals` is 0 to 9. `authority: None`
requires `initial`; `Bridge` and `Program` are refused in a `RegisterToken`.

**Minted notes are chain-computed, not chosen by the submitter**: `note_commitment(recipient.pk,
MINT_FROM, amount, index, time, r)`, with `MINT_FROM` a fixed constant distinct from the bridge
deposit's `DEPOSIT_FROM`. The amount and the recipient's `pk` are public on the wire, so the
recipient can rebuild the note from the transaction's own fields even if the sealed envelope is
garbage — the same defence a bridge deposit has (`docs/bridge.md` §8).

### Why the asset id binds the *whole* initial mint

A `RegisterToken` is unsigned, and its fee bundle is not bound to the action by anything but the
transaction binding (`docs/confidential.md`, "Transaction binding") — which stops a *proved* copy
from being altered, but says nothing about what a fresh, unproved copy is free to name. Had the
asset id bound only `initial.amount`, an observer who saw a pending registration in gossip could
build its own copy naming the same amount but a different `recipient` and `r`, register it under
the *same* id, and win the whole initial supply if it committed first — permanent theft for a
fixed-supply token. Binding the **whole** `InitialMint` (amount, recipient, `r`, `time` and
envelope) closes this: a redirected copy hashes to a *different* asset id, which is exactly what a
non-unique symbol already permits — the original registration still lands, at the next index, for
the cost of one re-proof (`IndexMismatch`).

### Mint and authority signatures

`Key` mints and `SetAuthority` (`TokenMint { asset, amount, recipient, r, time, envelope, nonce,
signature }`, `SetAuthority { asset, new: Option<PublicKey>, nonce, signature }`) sign
`blake3("rand-rpl-mint-1" | "rand-rpl-authority-1", chain_id ‖ asset_id ‖ nonce ‖ body)`, where a
mint's `body` includes `blake3(bincode(envelope))` — the commitment alone does not cover the
envelope, so without the digest a third party could re-wrap a gossiped mint with a garbage envelope
and spend the nonce, leaving the recipient to rebuild the note from the public fields exactly as
above. `nonce` must equal the token's `mint_nonce`, which then increments — no replay, on this
chain or another (the `chain_id` is in the signed body too). Both ride an ordinary RAND fee bundle
paying `BUNDLE_BASE`.

## 5. Transfers are hidden-asset bundles

Since chain 14, every value-moving transaction carries exactly one bundle: the fixed 4-in/4-out
hidden-asset shape (`docs/confidential.md`, "The hidden-asset bundle guest"). Slots 0–1 carry a
**private** asset — RAND or any RPL token, the guest never learns which — and slots 2–3 always
carry RAND. **A transfer of any asset is `Action::None`**, the same action a plain RAND payment
uses; there is no `TokenTransfer` action and no public field naming which token moved. What an
observer of a token transfer sees is *exactly* what a RAND payment publishes:

- an anchor, four nullifiers, four commitments, the RAND `fee`, `burn_a = burn_r = burn_asset = 0`,
  a `time`, four envelope ciphertexts and the bundle proof.

What it does **not** see: who sent it, who received it, the amount, which asset moved, which of
the four slots were dummies, or the change. The wallet spends up to two notes of the token in
slots 0–1 and up to two RAND notes in slots 2–3 for the fee (`docs/shielded.md` §3) — a
token-holder with no RAND is refused before proving, since the fee is always RAND.

## 6. Fees, in RAND

Every RPL action pays its fee in RAND, exactly as an ERC-20 transfer needs ETH: a token-only holder
must still hold RAND to move it.

| action | fee floor |
|---|---|
| a transfer of any asset (`Action::None`) | 0.001 RAND (`BUNDLE_BASE`) |
| `RegisterToken` | `BUNDLE_BASE` + the registry's `registration_fee` |
| `TokenMint` | `BUNDLE_BASE` |
| `SetAuthority` | `BUNDLE_BASE` |
| `TokenBurn` | `BUNDLE_BASE` |

## 7. Burning

`Action::TokenBurn { asset, amount }` rides the same single hidden-asset bundle: the bundle's
`burn_asset` must equal `asset` and `burn_a` must equal `amount`, with `burn_r = 0` — the token
leaves the pool through the asset slots, the RAND fee through slots 2–3 of the same proof.
`total_supply` decreases by exactly `amount`, and a burn is public by design, the same audit
trail a bridge burn or a mint gives (§9 below): the chain can always show that `total_supply` is
what registration and every mint added, less every burn. A `Bridge`-authority token is refused
here (`TokenError::BridgedToken`) — it leaves through `bridge-burn` instead, which also checks a
named backing's `locked` amount and release unit (`docs/bridge.md` §13).

## 8. What is public and what is hidden

| | public | hidden |
|---|---|---|
| **registration** | name, symbol, decimals, authority, the initial mint's amount and recipient, the asset id | — (all of it is meant to be public: this is how a token gets its supply audited from day one) |
| **a further mint** (`TokenMint`) | the amount, the recipient's shielded address, the new note's fields | who paid the RAND fee |
| **a transfer** (`Action::None`) | nothing that says a token moved at all — see §5 | sender, recipient, amount, which asset |
| **a burn** (`TokenBurn`) | the asset and the amount | who held the burned notes |
| **an authority change** (`SetAuthority`) | the new key, or that it was renounced | — |

`total_supply` is therefore always auditable — registration, every mint and every burn are public —
while a transfer between two token holders reveals nothing at all, including the fact that a token
(rather than RAND) changed hands.

## 9. Differences from ERC-20 and SPL

(RPL spec §8, updated for v0.5: one proof per transfer, no `approve`/`transferFrom` yet.)

| | ERC-20 / SPL | RPL |
|---|---|---|
| balances | a public mapping or account | shielded notes; only a key holder can see one |
| transfer events | public, with sender/recipient/amount | none — a transfer publishes nothing distinguishing |
| per-token code | possible (tax, rebase, hooks, freeze) | none — every token follows the same fixed rules |
| holding by a program | yes (a contract can own tokens) | not in v1 — programs are stateless (RPL-2 is future work, spec §11) |
| amounts | up to 256-bit (ERC-20) / 64-bit (SPL) | `u64`, at most 9 decimals |
| receiving | an ERC-20 needs no setup; SPL needs an associated token account | no account setup — a shielded address receives anything |
| proving cost of a transfer | none (plain EVM/SVM execution) | one STARK proof (the shared hidden-asset bundle) |
| approvals | `approve`/`transferFrom`, an unbounded allowance by default | not yet — RPL spec §7 designs earmarked allowance accounts; not on the v0.5 path |
| metadata | mutable in some implementations | on chain and immutable once registered |
| freeze / blacklist | possible on some tokens | out of scope by design (spec §2) |

## 10. The CLI

Full flag detail is `docs/cli.md`'s `rand` (wallet) table; this is the token-specific subset.

| command | what it does |
|---|---|
| `rand token create --name … --symbol … --decimals <0..=9> --salt <hex32>` then either `--fixed-supply <N> --to <ADDR>` or `--authority-key-out <FILE> [--initial <N> --to <ADDR>]` | register a token at the registry's next index: fixed supply (mints once, authority `none`) or `Key`-authorised (writes a fresh Dilithium2 key file), with or without an initial mint. Reads `next_index` and `registration_fee` off `rand_getTokens` before proving; prints the index and the id, hex and `rpl1…`, on success, or "another token took index N first — re-run to register at N+1" on `IndexMismatch` |
| `rand token mint --asset <A> --to <ADDR> --amount <N> --authority-key <FILE>` | mint more of a `Key`-authorised token, signed by its authority; refused up front if `--asset` is not `Key`-authorised or `--authority-key` is the wrong key |
| `rand token set-authority --asset <A> --authority-key <FILE> (--new-key <FILE> \| --renounce)` | hand a `Key`-authorised token to another key, or renounce minting for good |
| `rand token info <A>` | one token's full row: name, symbol, decimals, authority, `mint_nonce`, total supply, `registered_at`, id (hex and `rpl1…`), and — if bridged — every backing |
| `rand token list [--from <index>] [--limit <N>]` | one page of the whole registry |
| `rand token burn <ASSET> <AMOUNT>` | destroy `AMOUNT` of a token this wallet holds; refused before proving for a `Bridge`-authority token |
| `rand send <TO> <AMOUNT> --asset <INDEX\|rpl1…\|hex>` | send RAND (default, `--asset 0`) or any RPL token in one proof; `AMOUNT` is whole units of the token, not a decimal amount |
| `rand asset-balance [INDEX]` | what this wallet holds of one asset, or a row per asset |

`--asset` (on `send`, `token mint`, `token set-authority`, `token burn`, `token info`) accepts an
index, the `rpl1…` text form or 64 hex, and is always resolved from the node's **whole**
`rand_getTokens` listing, never a per-token lookup — a wallet about to move a token should not tell
the node which one it cares about (§11). Amounts are in the token's own smallest unit: a token with
6 decimals moves in millionths, exactly as its source chain would show it.

## 11. The RPC

Full parameter detail is `docs/rpc.md`.

| method | params | result |
|---|---|---|
| `rand_getTokens` | `[from_index, limit]` (optional, default `0`/`1000`, clamped to 1000) | `{ enabled, registration_fee, next_index, tokens: [...] }`, every token ascending by index |
| `rand_getToken` | `[token]` (index, decimal string, 64-hex id, or `rpl1…`) | one token's row, or `null`; a malformed id is `-32602` |
| `rand_getTokenSupply` | `[token]`, same forms | `{ total_supply, backings }`, decimal strings; `backings` empty for a native token |

**Privacy note.** `rand_getTokens` costs the same to read whichever token a caller has in mind, so
a wallet resolves an id **through the whole listing**. `rand_getToken` and `rand_getTokenSupply`
are a *per-token* lookup and tell the node which token the caller cares about — fine for an
explorer or a one-off read, wrong for a wallet about to send. `rand_getAssets` stays as the
bridge's own per-backing view (`docs/bridge.md` §6).

A token row's `authority` is `{"kind":"none"}`, `{"kind":"key","key":<hex>,"address":<base58>}`,
`{"kind":"bridge","backings":[{"chain","token","decimals","locked","mint_cap_per_day",
"minted_today","mint_day"}]}` (each backing's *source* decimals, its locked amount, and bridge
hardening B1's per-backing daily mint cap: the genesis cap, what it has minted on `mint_day` — the
UTC day of the head block — and that day number itself) or `{"kind":"program","program":<hex>}`.
Every amount here — `locked`, `mint_cap_per_day`, `minted_today`, a token's `total_supply`, and
`rand_getTokens`'/`rand_getBridgeState`'s `registration_fee` — is a decimal string, because a
JSON number is not exact past 2^53; `mint_day`, like `index` and `next_index`, is a plain integer.

## 12. Key disclosure: a tx key, a viewing key, and randscan

A token transfer discloses exactly the way a RAND transfer does (`docs/shielded.md` §6): the note
plaintext `(pk, from, amount, asset, time, r)` carries the asset, so a per-transaction key
(`rand tx-key <hash>`) or a viewing key opens a token note exactly as it opens a RAND one —
`rand_checkTransaction(hash, key)` and `rand_importViewingKey`/`rand_getViewingNotes` both return
`asset` in the note they disclose. Given a transaction key or a viewing key, randscan resolves that
`asset` index against `rand_getTokens` and shows the transfer as the named token (zUSD, 8 decimals,
rather than "1000000000 units of asset 1") with its amount, parties and spent state — the public
page for the same transaction shows none of it, exactly as §5 describes. A minted or bridged
note's registration and mint history is public regardless of any key, since those are the chain's
own audit trail (§8).

## 13. Bridged tokens

A `Bridge`-authority token is still an RPL token — the same registry entry shape, the same hidden
transfer, the same burn mechanics — with its supply moved only by the bridge's lock and release
instead of a signed mint. `docs/bridge.md` §§13–20 covers the bridge-specific parts: one token with
many backings (zUSD's seven), the `total_supply == Σ locked` invariant, the release-unit rule, the
per-backing daily mint cap and pause, the post-quantum co-signature every mint needs, and listing a
new bridged token or backing after genesis under a PQ guardian quorum.

## 14. The registry cap (v0.5.4, audit v4 TOK-1)

The registry root is a merkle root over every token's leaf, recomputed at every state root, and
`rand_getTokens` used to walk the whole registry to serve a page. Both are O(tokens), and nothing
bounded the count but the registration fee. A genesis may now say how many tokens the chain will
ever hold:

```json
"tokens": { "registration_fee": 1000000000, "mint_cap_per_day": 10000000000000, "max_tokens": 4096 }
```

`max_tokens` is optional and **absent on chain 14**, where the bound stays `u32::MAX` and nothing
about the genesis hash, the token root or the stored registry changes. When present it is
committed to the genesis hash (`b"max_tokens"` ‖ value, tagged, only then), folded into the token
root (the registry then hashes under `rand-token-registry-3`, with the cap in its extension), and
held to at least one and at least the number of tokens the section lists. At the cap a
`RegisterToken` and a `RegisterBridgedToken` are refused `RegistryFull` — the same verdict the
last index has always given — after the identity check and before any index is spent; a
`ListBacking` adds no token and is unaffected. `rand_getTokens` serves the cap as `max_tokens`
(`null` without one) and pages **by range** (`BTreeMap::range(from..)`), so a page from a high
index no longer reads the rows below it. The O(tokens) root stays: under a cap of a few thousand
it is bounded work per block, and an incremental root would move the token root domain for every
chain — deferred to the cut that needs it.

## 15. The burned registration fee (v0.5.5, audit v5 TOK-2)

The registration fee is paid on the registering bundle, on top of `BUNDLE_BASE` (§3), and the
whole bundle fee goes to the block's proposer — so a validator registering its own token pays the
fee to itself. A genesis may say the fee is burned instead:

```json
"tokens": { "registration_fee": 1000000000, "mint_cap_per_day": 10000000000000, "burn_registration_fee": true }
```

`burn_registration_fee` is optional and **absent on chain 14**, where the proposer keeps the whole
fee and nothing about the genesis hash, the token root, the stored registry or any block reward
changes; `false` is the same rule spelled out and commits nothing either. When `true` it is
committed to the genesis hash (`b"burn_registration_fee"` ‖ `1`, tagged, only then), folded into
the token root beside the registry cap (`rand-token-registry-3`), and served by `rand_getTokens`
as `burn_registration_fee`. Under it a `RegisterToken` or `RegisterBridgedToken` leaves the
proposer `fee − registration_fee` and destroys `registration_fee`: no note is created for it, and
`rand_getSupply` counts it in `burned` and, separately, in `registration_fees_burned`, which the
supply identity subtracts on its right (`total_supply == issued − slashed −
registration_fees_burned`) — the fee left the pool into no register entry, like a slashed bond. On
an aggregating chain the proposer keeps the floor as before and the proving-share bucket gets
`fee − registration_fee − BUNDLE_BASE`. A `ListBacking` registers no token and is unaffected, and
the floor a registration must pay (§3) is unchanged: the gate decides where the fee goes, not how
much it is.
