# The guardian bridge — architecture

> The bridge code lands on main with the `feat/bridge` merge (`543d72b`) and the hardening
> commits that follow it; this page describes it as of `273e13d` (`4585368` plus the attestation check reordering).

This page assumes `docs/architecture.md`. It covers the wire format, the guardian-attestation
model, the on-chain `BridgeState`, the two bridge transaction kinds, and the storage/RPC/wallet
surface built on them.

## 1. Purpose and trust model

The bridge moves value between Rand and four other chains, by a bridge-local chain id
(`crates/bridge-codec/src/lib.rs`):

| Chain    | Id |
|----------|----|
| Rand     | 1  |
| Ethereum | 2  |
| BSC      | 3  |
| Tron     | 4  |
| Solana   | 5  |

Three of the four are EVM-family; Solana is not. The design is Wormhole-shaped: the same
guardian-signed attestation format is shared by Solidity contracts, a Solana program, and this
fullnode. It is a guardian-attestation bridge, not a light-client or on-chain proof bridge — no
source-chain header or state proof is ever verified on Rand.

An **attestation** is a guardian-signed envelope: a body (metadata plus an opaque payload) and a
threshold of ECDSA signatures over the body's digest. **Guardians** are a fixed committee of
secp256k1 keys; a guardian's on-chain identity is the last 20 bytes of
`keccak256(uncompressed_pubkey[1..])` (`crates/shrugg-core/src/bridge/mod.rs`) — Ethereum's
address derivation, reused so the same key/address works across the EVM contracts, the Solana
program, and Rand.

Quorum for a set of size `n` is `n*2/3 + 1` (`quorum`, `crates/bridge-codec/src/lib.rs`). Each
signature carries `r`, `s`, and recovery id `v`, and must be **low-s**: `s <= n/2` for the
secp256k1 curve order, pinned as `SECP256K1_HALF_N` — a high-s signature is rejected outright,
foreclosing signature malleability. The digest guardians sign is `mu =
keccak256(keccak256(body_bytes))`, a double keccak (`crates/shrugg-core/src/bridge/mod.rs`).

A **governance emitter** is a fixed, non-guardian address Rand treats as the sole authorized
source of guardian-set rotations: `keccak256("rand-bridge-governance")`, pinned as a literal
(`GOVERNANCE_EMITTER`, `bridge-codec/src/lib.rs`) and cross-checked by a test
(`governance_emitter_matches_string`). It is a slot in the `(emitter_chain, emitter_address)` pair
that only a `GuardianSetUpgrade` payload may claim, and only as `(CHAIN_RAND, GOVERNANCE_EMITTER)`.

**What this does not protect against.** The trust model is entirely the guardian committee's
signatures — no fallback or dispute mechanism, no independent light client. If `n*2/3 + 1`
guardians collude they can mint arbitrary value or authorize an illegitimate rotation; nothing
here detects or resists that. The one deliberate hardening against a *partially* compromised
committee is the rotation rule in §3.

## 2. Wire format (`bridge-codec`)

`crates/bridge-codec` is `#![no_std]` + `alloc`, **zero dependencies** — the single source of
truth for the byte layout shared by the Solidity contracts, the Solana program, and this
fullnode. Its own doc comment: "hashing and ECDSA are deliberately NOT performed here; callers
inject a keccak256 and a secp256k1 verifier" — kept out of the codec so it stays portable to
whatever verifies it on the other chains; `shrugg-core` supplies both (`sha3`, `k256`).

Every integer is big-endian. Wire version is `VERSION = 1` (`bridge-codec/src/lib.rs`);
`Attestation::decode` rejects any other value as `CodecError::BadVersion`.

**Signature — 66 bytes** (`crates/bridge-codec/src/envelope.rs`)

| Offset | Len | Field |
|--------|-----|-------|
| 0 | 1 | `index` |
| 1 | 32 | `r` |
| 33 | 32 | `s` |
| 65 | 1 | `v` (recovery id) |

**Body header — 51 bytes, then the payload** (`envelope.rs`)

| Offset | Len | Field |
|--------|-----|-------|
| 0 | 4 | `timestamp` |
| 4 | 4 | `nonce` |
| 8 | 2 | `emitter_chain` |
| 10 | 32 | `emitter_address` |
| 42 | 8 | `sequence` |
| 50 | 1 | `consistency_level` |
| 51 | .. | `payload` |

`Attestation::body_bytes` returns this slice straight out of the original wire bytes, unre-encoded
— "exactly what gets hashed to produce `mu`" — so the digest never depends on a future re-encoder
matching today's byte-for-byte.

**Attestation envelope** (`envelope.rs`)

| Offset | Len | Field |
|--------|-----|-------|
| 0 | 1 | `version` (= `VERSION`) |
| 1 | 4 | `guardian_set_index` |
| 5 | 1 | `n_sigs` |
| 6 | `66*n_sigs` | `signatures[]` |
| `6+66*n_sigs` | .. | `body` |

**`Transfer` payload — id `1`, fixed 133 bytes** (`crates/bridge-codec/src/payload.rs`)

| Offset | Len | Field |
|--------|-----|-------|
| 0 | 1 | `id` = 1 |
| 1 | 32 | `amount` (u256 BE) |
| 33 | 32 | `token_address` |
| 65 | 2 | `token_chain` |
| 67 | 32 | `to` |
| 99 | 2 | `to_chain` |
| 101 | 32 | `fee` (u256 BE) |

`TRANSFER_PAYLOAD_LEN = 133`; any other length is `CodecError::BadPayloadLength`. `amount`/`fee`
are full u256 but Rand only unpacks the low 128 bits (`amount_u128`/`fee_u128`); a non-zero top 16
bytes yields `None`, mapped upstream to `BridgeError::AmountOverflow`.

**`GuardianSetUpgrade` payload — id `2`, variable length** (`payload.rs`)

| Offset | Len | Field |
|--------|-----|-------|
| 0 | 1 | `id` = 2 |
| 1 | 4 | `new_index` |
| 5 | 1 | `n` (guardian count) |
| 6 | `20*n` | `keys[]` |

Decode rejects `n == 0` (`ZeroGuardians`), too few bytes (`Truncated`), or too many
(`TrailingBytes`). The codec does not check `new_index == current + 1`, uniqueness, or non-zero
keys — that is `shrugg-core`'s job; the codec has no notion of "current guardian set."

**Left-padding.** `to`, `token_address`, and `emitter_address` are fixed 32-byte slots, so the wire
format is one chain-agnostic shape regardless of native address width. Ethereum/BSC/Tron addresses
are 20 bytes, left-padded with 12 zero bytes. `bridge-codec` doesn't enforce this — it's chain-shape
policy, not wire law — but `BridgeState::check_burn` does on the way out
(`crates/shrugg-core/src/bridge/state.rs`): non-zero `to[..12]` is `BadRecipient` on chains 2/3/4,
and an all-zero `to` is `BadRecipient` everywhere. The wallet (`check_burn_recipient`,
`crates/shrugg-client/src/lib.rs`) applies the same checks before signing.

## 3. Guardian sets

`BridgeConfig` (`crates/shrugg-core/src/bridge/state.rs`) carries the genesis emitter address,
initial guardian keys, and per-source-chain emitter table, as human-readable hex JSON.
`BridgeState::from_config` installs those keys as guardian set index 0, `current_set = 0`,
`expires_at: 0` — "never expires."

**Rotation** is a `GuardianSetUpgrade` attestation whose emitter must be `(CHAIN_RAND,
GOVERNANCE_EMITTER)` exactly, else `WrongEmitter`. `BridgeState::check_attest` then enforces:

- `new_index == current_set + 1` — no skipping — else `BadUpgradeIndex { expected, got }`.
- New keys non-empty (codec `ZeroGuardians`), unique, non-zero — else `DuplicateGuardian`.
- **The attestation's `guardian_set_index` must equal `current_set`**, not merely some
  still-unexpired set (`c84c9f0`). Without this, a set just rotated away from — e.g. because it
  was considered compromised — could use its own grace window to sign *another* rotation and
  re-seize the bridge for up to a day. This brings Rand to parity with the existing Solana program
  and EVM contracts.

Applying an upgrade (`apply_attest`) sets the old current set's `expires_at = now +
GUARDIAN_GRACE_SECS` (`= 86_400` seconds, `bridge-codec/src/lib.rs`) so in-flight *transfers*
signed by the outgoing set stay valid for a day, installs the new set with `expires_at: 0`, and
advances `current_set`.

Expiry is evaluated against `now`, block time (`timestamp_ms / 1000`), not wall clock — checked
only on a bridge-configured chain. Commit `f6e5639`: `apply_block` rejects a bridged chain's block
whose timestamp precedes its parent's (`BlockError::TimestampRewind`, gated on
`self.bridge.is_some()`), and `HotStuff::propose` emits `max(now_ms, parent.timestamp_ms)` so a
lagging leader never proposes a block its peers must reject. Every ledger built from a head block
carries that block's timestamp (`apply_block`, `HotStuff::resume`/`propose`, storage replay), so
expiry is never evaluated at `now = 0`.

Test coverage: `guardian_upgrade_must_be_signed_by_the_current_set`,
`guardian_upgrade_rotates_with_grace_and_rejects_skips`,
`upgrade_rejects_duplicate_and_zero_guardian_keys` (`crates/shrugg-core/src/bridge/state.rs`).

## 4. On-chain state: `BridgeState`

`crates/shrugg-core/src/bridge/state.rs`:

| Field | Type | Meaning |
|-------|------|---------|
| `emitter` | `[u8; 32]` | Rand's outbound emitter address, stamped into burn messages |
| `emitters` | `BTreeMap<u16, [u8; 32]>` | registered emitter per source chain |
| `guardian_sets` | `BTreeMap<u32, GuardianSet>` | every set ever seen, by index |
| `current_set` | `u32` | index of the authoritative set |
| `balances` | `BTreeMap<(AssetId, Address), u128>` | bridged-asset balances |
| `assets` | `BTreeMap<AssetId, (u16, [u8; 32])>` | registry: id -> (home chain, token address) |
| `spent` | `BTreeSet<Hash>` | consumed attestation digests (inbound replay guard) |
| `burn_sequence` | `u64` | next outbound sequence number |
| `burns` | `BTreeMap<u64, BridgeBurnRecord>` | every outbound message, held whole in memory |

`AssetId = blake3("shrugg-bridge-asset" || token_chain BE u16 || token_address)` — a pure,
domain-separated function of `(chain, address)`, computable even without a bridge (§6).

`BridgeMeta` is the "whole-state half": everything above except `balances`, `spent`, `burns`,
which storage keeps one row per key. `meta()`/`from_parts()` destructure the struct field-by-field
on purpose, so a new field must be classified as meta or column family or the build breaks.

### `root()` and what it commits

Spec 6.3:

```
blake3("shrugg-bridge-state"
    || bincode(emitter, emitters, current_set, guardian_sets)
    || merkle(blake3("shrugg-asset-balance" || asset || addr || balance BE))   // zero balances pruned
    || merkle(blake3("shrugg-asset-registry" || asset || chain BE || token))
    || merkle(sorted spent digests)
    || burn_sequence BE)
```

`emitter`/`emitters` are included because they are consensus-relevant genesis configuration, not
incidental metadata (`4b6f661`). Zero balances are pruned so a never-credited and a fully-drained
holder commit identically. `burns` is **excluded** — derivable from transaction history; test
`root_changes_with_balances_spent_and_sequence_but_not_burn_records` clears `burns` on a clone and
confirms the root is unchanged.

The root is pinned by `root_is_pinned_for_a_fixed_state`: a fixed state (two guardians, one asset,
one balance, one spent digest, `burn_sequence = 7`) must hash to
`c757e13d25a59234ca3c642f38fd53970051055a73a1db9bc63f2c0b3058b043`. The test's comment: "Changing
this hash changes consensus ... treat a failure here as a hard fork, never as a test to
re-baseline." Any change to the fields, encoding, or domain tags in `root()` is consensus-breaking
for every bridged chain.

The bridge root folds in only when a bridge exists: `state_root() = blake3(accounts_root ||
programs_root)`, or `blake3(accounts_root || programs_root || bridge_root)` with a `bridge`
genesis section (`crates/shrugg-core/src/ledger.rs`). A bridge-less chain commits exactly the
64 bytes a pre-bridge node did — byte-identical, no third word — verified by
`state_root_unchanged_without_bridge_and_covers_bridge_with`. The genesis hash follows the same
rule: it appends `bincode(BridgeCommit)` only when `Genesis.bridge` is `Some`. `BridgeCommit` is a
plain-bytes twin of `BridgeConfig` — the config's serde is human-readable hex, and hashing that
would commit to hex *strings*, not the real bytes the chain runs on.

`Genesis::build` validates a configured bridge (`check_bridge`,
`crates/shrugg-core/src/genesis.rs`): rejects an empty guardian set, a duplicate or zero-value
guardian key, a zero emitter, an emitter equal to the governance emitter, `CHAIN_RAND` as a source
emitter, a source emitter equal to the governance emitter, and a zero-value source emitter.

## 5. Transactions

Two `TxKind` variants (`crates/shrugg-core/src/types/transaction.rs`), appended after `Call`
(tag 3) so earlier tags keep their bincode encoding:

| Tag | Variant | Fields |
|-----|---------|--------|
| 4 | `BridgeAttest` | `attestation: Vec<u8>` |
| 5 | `BridgeBurn` | `asset: AssetId, amount: u128, to_chain: u16, to: [u8; 32], fee: u128` |

Both cost only the flat SHRUGG fee — no separate gas metering, since the value moved is a bridged
asset, not SHRUGG.

**Admission order — cheap before expensive.** `Ledger::validate_inner`:

1. Size cap first: `attestation.len() > MAX_ATTESTATION_BYTES` (16 KiB = 16,384 bytes,
   `crates/shrugg-core/src/gas.rs`), checked before a byte is parsed or a signature recovered. A
   guardian set is at most 255 keys by wire format, so anything past the cap is malformed by
   construction and "must not be allowed to buy verification work with a zero fee" — the
   repo-wide cheap-before-expensive rule (`d5143a6`) applied to the bridge.
2. Only then is a bridge's presence checked (`BridgeError::Disabled` if none); `check_attest`
   decodes the envelope once and, as of `273e13d`, runs every cheap check before any signature
   work: the replay check against `spent` (by digest `mu`), the payload decode
   (`BridgeError::BadPayload`), the emitter check against the registered emitter for the
   emitter chain, and the payload's own field checks (token chain, asset, recipient shape).
   Only an attestation that passes all of those reaches guardian-set resolution and
   quorum/index/low-s/signature-recovery (`verify_decoded`). Before `273e13d` recovery ran
   first; accepted attestations are unchanged by the reordering.
3. `BridgeBurn`: bridge presence, then `check_burn` — registered asset -> `to_chain` matches home
   chain -> recipient shape -> `fee <= amount` -> `amount != 0` -> sufficient balance.

`apply_tx_with_receipt` debits only the SHRUGG fee up front; the asset movement happens through
`apply_attest`/`apply_burn`, guarded by an `.expect(...)` documented safe because `validate_inner`
already rejected bridge transactions on a bridge-less chain.

**Replay protection** differs by direction:

- **Inbound** (`BridgeAttest`): digest-based. Every consumed `mu` goes into `BridgeState.spent:
  BTreeSet<Hash>` before payload effects apply; a repeat is `BridgeError::Replay`. No sequence
  number here — the digest is the dedup key, since the same attestation can arrive via any relayer.
- **Outbound** (`BridgeBurn`): a strictly increasing `burn_sequence: u64` (`saturating_add`), on
  each `BridgeBurnRecord.sequence`.

**Emitter binding**: a `Transfer` must come from the chain's *registered* emitter
(`self.emitters.get(&emitter_chain) == Some(&emitter_address)`, else `WrongEmitter`), and
`token_chain` must equal the emitting chain (`WrongTokenChain`, `4b6f661`). A
`GuardianSetUpgrade` must be `(CHAIN_RAND, GOVERNANCE_EMITTER)` exactly, else `WrongEmitter`.

**Undecodable payload is a hard error** (`39df27b`). Storage's commit path used to do
`if let Ok(Payload::Transfer(t))` around the decode, so a bad payload fell through silently — "no
balance rows written, commit reported success, disk quietly disagreeing with memory." It is now a
`match` whose `Err` arm returns storage's `Corrupt` error; at the ledger level, decode failure maps
to `BridgeError::BadPayload`. Regression tests: `undecodable_payload_is_treated_as_a_torn_block`
(`crates/shrugg-node/src/storage.rs`), `undecodable_payloads_are_rejected` (`state.rs`).

**Asset registry and fees.** An asset registers the first time a `Transfer` mints it in:
`BridgeState.assets` maps `AssetId -> (token_chain, token_address)`, populated lazily by
`apply_attest`; `check_burn` requires the outbound `to_chain` to match that home chain. All bridge
transactions pay their fee in SHRUGG, like everything else. A `Transfer` payload additionally
carries its own `fee`, in the bridged asset: on mint, `amount - fee` goes to the recipient and
`fee` to the submitter. Bridged balances are a **separate, per-asset ledger**
(`BridgeState.balances`) — plain integer state distinct from `Ledger.accounts`' SHRUGG balances;
moving a bridged asset never touches an account's SHRUGG balance.

## 6. Storage, RPC, wallet

**Storage** (`crates/shrugg-node/src/storage.rs`) — three RocksDB column families plus one `meta`
key:

| Column family | Key | Value |
|----------------|-----|-------|
| `bridge_balances` | `asset \|\| address` | `bincode(u128)`; row deleted at zero |
| `bridge_spent` | digest bytes | empty (a set) |
| `bridge_burns` | big-endian `sequence` | `bincode(BridgeBurnRecord)` |

`meta["bridge_state"]` holds `bincode(BridgeMeta)`; its presence is what makes a chain "bridged" on
disk. `put_bridge`/`clear_bridge` write or erase a whole bridge in one batch; a per-block commit
touches only the rows a block's bridge transactions moved. `load_bridge` rebuilds a full
`BridgeState` from the meta blob plus the three CFs; `truncate_to` (reorg replay) does the same.
The startup integrity check separately compares `stored.bridge() != ledger.bridge()`, since the
root "covers most of the bridge but not the outbound [burn log]." A database predating `--bridge`
recovers by initializing state fresh from genesis if the replayed ledger has none
(`crates/shrugg-node/src/node.rs`).

**RPC** (`crates/shrugg-node/src/rpc.rs`, `docs/rpc.md`) — five methods:

| Method | Params | Result |
|--------|--------|--------|
| `shrugg_getAssetBalance` | `[address, asset]` | one balance, decimal string (8-decimal units); `"0"` if unknown/no bridge |
| `shrugg_getAssets` | `[address]` | every non-zero bridged asset held |
| `shrugg_getBridgeState` | `[]` | emitter, emitter table, guardian set, assets, `burn_sequence`; `{"enabled": false}` with no bridge |
| `shrugg_getBridgeBurn` | `[sequence]` | one outbound message, or `null` |
| `shrugg_bridgeAssetId` | `[token_chain, token_address]` | the asset id; pure function, answers on any chain |

**Wallet** (`crates/shrugg-client`, `docs/cli.md`) — four CLI commands:

| Command | Purpose |
|---------|---------|
| `bridge-mint <ATTESTATION>` | submit a guardian-signed attestation (hex or `@path`); its fee pays the submitter |
| `bridge-burn <ASSET> <AMOUNT> <TO_CHAIN> <TO> [--bridge-fee]` | burn bridged units, emit the outbound message |
| `asset-balance [ADDRESS] <ASSET>` | one bridged balance, plain integer |
| `bridge-status` | this chain's emitter, emitter table, guardian set, burn sequence, assets |

`RpcClient` (`shrugg-client/src/lib.rs`) wraps the RPC methods plus attest/burn submission;
`check_burn_recipient` pre-screens a burn's recipient with the same rule `check_burn` applies
on-chain.

**Cluster test**: `bridge_mint_reaches_every_node` (`crates/shrugg-node/tests/cluster.rs`) builds a
genesis from the shared `vectors.json` guardians/emitters, mints `transfer_eth_usdt_6dp_ok` through
RPC on one node, and confirms every node converges on the same balance and registry, a replay is
rejected, and a restarted node's balance is read back from RocksDB rather than recomputed — the
end-to-end proof the storage round trip above actually works.

## 7. Test vectors

`crates/shrugg-core/src/bridge/vectors.json` is generated externally by a `tools/vectors`
generator in a separate "bridge repo" and copied in verbatim: top-level keys `guardians`,
`governance_emitter`, `rand_emitter`, `emitters`, `now`, `vectors`, and **39 vectors** — named
cases like `transfer_eth_usdt_6dp_ok`, `upgrade_signed_by_superseded_set`, `quorum_four`,
`high_s`, `replay_eth`, `stale_governance_set`.

Two tests pin these against two layers, each asserting an **exact** count — not a lower bound —
so a vector that stops matching fails the build instead of quietly being skipped:

- **Signature level** — `shared_vectors_match_verify` (`crates/shrugg-core/src/bridge/mod.rs`):
  re-verifies every vector whose `expect` is one of `ok, no_quorum, index_order,
  index_out_of_range, bad_signature, high_s, wrong_guardian, set_expired, bad_version` against
  `bridge::verify`, checking the pinned digest (`ok`) or exact `VerifyError`. `checked == 23`.
- **Ledger level** — `vectors_ledger_level` (`crates/shrugg-core/src/ledger.rs`): drives the rest
  (`wrong_emitter`, `wrong_to_chain`, `wrong_token_chain`, `fee_exceeds_amount`,
  `amount_overflow`, `bad_payload`, `replay`, `unknown_set`, `set_expired`,
  `stale_governance_set`) through a real `BridgeAttest` against a live `Ledger`, mapping each to a
  `TxError::Bridge(...)` variant. `checked == 21`, chain 1 only.

`unknown_set` is deliberately *not* checked at the signature level: `verify` takes an
already-resolved `GuardianSet`, not an index, so "no set at this index" is a set-*resolution*
concern only `check_attest` can raise; an earlier version asserted it against the vector's own
`sets` array, tautologically true by construction — `73680a3` fixed that.

What the vectors pin: exact digest values for every `ok` case, so the keccak+quorum math cannot
silently drift, and the exact error taxonomy for every malformed or edge-case attestation the
generator knows about.

## 8. Known gaps

Stated directly in the code's own comments and commit messages:

- **Equal-to-parent block timestamps are allowed.** The bridged-chain check in `apply_block` is
  `<`, not `<=` — it forbids a rewind but not a repeat. The comment names the residual: "a
  colluding 2/3 of leaders can hold `timestamp_ms` constant, which freezes outbound burn
  timestamps and keeps a superseded guardian set inside its grace window indefinitely" — a
  liveness-grade quorum failure this comparison cannot rule out.
- **`BridgeState.burns` is unbounded and kept whole in memory.** Its own doc comment: "known
  linear growth, to be drained into storage per block before ~100k burns (spec 6.3)." Storage
  persists new burn rows incrementally, but the in-memory map is never pruned or paged, and is
  cloned on every speculative block execution the consensus layer performs.
- No light-client or on-chain verification of source-chain state exists or is planned; the
  guardian committee's signatures are the entire trust model (§1).
- No bridge-specific rate limiting beyond the flat SHRUGG fee and the 16 KiB
  `MAX_ATTESTATION_BYTES` cap.
- `AGENTS.md`'s "open follow-ups" lists no bridge-specific items — its outstanding work (validator
  key rotation, proof verification off the consensus event loop, lock-promise durability, wallet
  nonce races) doesn't touch the bridge.

## 9. Relationship to the confidential layer

None, today. `BridgeAttest`/`BridgeBurn` sit alongside `Transfer`/`Mint`/`Deploy`/`Call` in
`TxKind`, but neither touches `ConfidentialExecutor` or the zkVM proof-verification path — only
the `Call` arm of `validate_inner` invokes the executor, and neither `bridge-codec` nor
`shrugg-core::bridge` imports anything confidential- or zkVM-related. The two areas share only the
same `Ledger`/state-root machinery and gas-limits module (`MAX_ATTESTATION_BYTES` sits next to
`MAX_PROOF_BYTES`/`MAX_PROGRAM_WORDS` in `crates/shrugg-core/src/gas.rs`). Bridged balances are
plain, visible state in `BridgeState.balances` — no confidentiality or zero-knowledge property of
their own. A future fully shielded design would have to shield bridged balances too; nothing here
does that today.
