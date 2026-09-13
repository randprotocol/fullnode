# The guardian bridge — architecture

> **Live on the shielded chain since phase S3.** A bridged holding is a **note**, not a balance.
> `BridgeState` has no per-account balances at all — the S1 pool deleted the accounts they were
> keyed by — so what a wallet "has" in a bridged asset is the notes of that asset its viewing key
> opens, exactly as for SHRUGG. A note's `asset` word is the registry's dense `u32` index for the
> asset; index 0 is SHRUGG. There is no `shrugg_getAssetBalance` and there never will be again.
>
> §§1–3 (the trust model, the wire format, guardian sets) are unchanged by any of that and are the
> reference the shielded half is built on. §§4–9 describe the bridge as it stands now. §10 is what
> changed when the pool replaced the accounts, for anyone holding an account-era integration
> against it.

This page assumes `docs/architecture.md` and `docs/shielded.md`. It covers the wire format, the
guardian-attestation model, the on-chain `BridgeState`, the two bridge actions, and the
storage/RPC/wallet surface built on them.

## 0. The bridge at a glance

```
   source chain (Ethereum / BSC / Tron / Solana)                    Rand (SHRUGG)
   ┌──────────────────────────────┐                                 ┌──────────────────────────────┐
   │ token contract / program     │  lock + emit Transfer           │ BridgeAttest transaction     │
   │   locks tokens, emits        │ ───────────────────────────────►│   admission: size cap → time │
   │   (amount, token, to, fee)   │        guardians observe,       │   → decode → replay →        │
   └──────────────────────────────┘        sign mu = keccak²(body)  │   emitter → payload → sigs   │
                  ▲                        threshold n·2/3 + 1      │   effect: one deposit note,  │
                  │                                                 │   computed by the chain      │
   release        │        ┌──────────────────┐   attestation      │                              │
   after guardian │        │ guardian committee│ ◄──────────────────┤                              │
   signatures on  │        │ secp256k1 keys,   │                    │ BridgeBurn transaction       │
   the burn       │        │ rotated by the    │   guardians read   │   two bundles: one burns the │
   message        │        │ governance emitter│   the burn log     │   asset, one pays the SHRUGG │
                  └────────┤ (Rand, sole)      │ ◄──────────────────┤   fee. Appends a             │
                           └──────────────────┘   sequence          │   BridgeBurnRecord           │
                                                                    └──────────────────────────────┘
```

Inbound: value is locked on the source chain, guardians attest, anyone submits the attestation to
Rand, and the ledger appends one deposit note for the recipient. Outbound: a Rand transaction burns
notes and emits a message, guardians attest that message, the source-chain contract releases. Rand
never verifies a source-chain header or state proof; the guardian committee's signatures are the
entire trust model.

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
and an all-zero `to` is `BadRecipient` everywhere. The wallet no longer restates those rules (the
account era's `check_burn_recipient` went with the accounts): `wallet::submit_burn` pre-checks only
the two things it would otherwise throw two bundle proofs away on — a zero amount and a relayer fee
larger than the amount — and leaves the rest to admission (§8).

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
expiry is never evaluated at `now = 0`. Every path that accepts a block goes through `apply_block`
— `HotStuff::on_proposal` (where the refusal surfaces as `ConsensusError::Execution`, like any
other block rule), the node's catch-up sync, and `--verify-chain`'s replay — so none of them can
drift from the rule. Regression test:
`a_bridged_chain_refuses_a_block_whose_timestamp_rewinds_its_parents`
(`crates/shrugg-core/src/ledger/mod.rs`), which also pins that an unbridged chain accepts the very
same rewind.

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
| `assets` | `BTreeMap<AssetId, AssetInfo>` | registry: id -> `{ chain, token, index }` |
| `next_index` | `u32` | the note index the next newly registered asset will get |
| `spent` | `BTreeSet<Hash>` | consumed attestation digests (inbound replay guard) |
| `burn_sequence` | `u64` | next outbound sequence number |
| `burns` | `BTreeMap<u64, BridgeBurnRecord>` | every outbound message, held whole in memory |

**There are no balances.** Phase S3 deleted `balances: BTreeMap<(AssetId, Address), u128>` outright:
a bridged holding is a note in the ledger's own commitment tree, and the tree is what commits to it.
What is left here is the *public* half of the bridge — who may attest, which assets exist and under
which index, which digests are consumed, and what has been burned outbound.

`AssetId = blake3("shrugg-bridge-asset" || token_chain BE u16 || token_address)` — a pure,
domain-separated function of `(chain, address)`, computable even without a bridge (§6).

**Asset indices.** A note's `asset` field is one word (`u32`), and a 32-byte `AssetId` does not fit
in it, so the registry hands out dense indices in registration order: `FIRST_ASSET_INDEX = 1`, and
0 is SHRUGG, which is never in the registry. The index is assigned at an asset's **first sighting**
— the first accepted attestation naming it — and never changes afterwards. `next_index` is
consensus state, not a cache: two nodes disagreeing about it would mint notes with different `asset`
words from the same attestation. Bridged amounts must also fit a note's `u64`; a transfer above that
is `BridgeError::AmountTooLarge` rather than a truncated note.

### `root()` and what it commits

```
blake3("shrugg-bridge-state"
    || bincode(emitter, emitters, current_set, guardian_sets)
    || merkle(blake3("shrugg-asset-registry" || asset || chain BE || token || index BE))
    || merkle(sorted spent digests)
    || burn_sequence BE || next_index BE)
```

`emitter`/`emitters` are included because they are consensus-relevant genesis configuration, not
incidental metadata. So are the note indices and the counter that assigns the next one. `burns` is
**excluded** — derivable from transaction history; test
`root_changes_with_the_registry_spent_and_sequence_but_not_burn_records` clears `burns` on a clone
and confirms the root is unchanged.

The root is pinned by `root_is_pinned_for_a_fixed_state`: a fixed state (two guardians, one asset at
index 1, `next_index = 2`, one spent digest, `burn_sequence = 7`) must hash to
`ee50b48c82eacf7aca2a1bdb33b32b7c98b1a255e645c9ba12dde9d060c43dc8`. The test's comment: "Changing
this hash changes consensus ... treat a failure here as a hard fork, never as a test to
re-baseline." It has been re-pinned exactly once, in S3, when the balance leaves left the
commitment and the registry leaf gained an index — that re-pin *is* the hard fork this phase ships
(the account-era value was `c757e13d…b043`).

The bridge root folds into the chain's state root only when a bridge exists:

```
state_root = blake3("shrugg-state-2" || tree_root || nullifier_root || validators_root || programs_root)
           = blake3("shrugg-state-2" || … || programs_root || bridge_root)   with a `bridge` section
```

A bridge-less chain commits exactly the 128 bytes phase S1 committed — byte-identical, no fifth
word — verified by `the_bridge_root_is_appended_only_on_a_bridged_chain`. The genesis hash
follows the same rule: it appends `bincode(BridgeCommit)` only when `Genesis.bridge` is `Some`.
`BridgeCommit` is a plain-bytes twin of `BridgeConfig` — the config's serde is human-readable hex,
and hashing that would commit to hex *strings*, not the bytes the chain runs on.

`BridgeMeta` is the "whole-state half": everything in the table except `spent` and `burns`, which
storage keeps one row per key. `meta()`/`from_parts()` destructure the struct field by field on
purpose, so a new field must be classified as meta or column family or the build breaks.

`Genesis::build` accepts a `bridge` section again (S1 rejected one outright) and validates it
(`check_bridge`, `crates/shrugg-core/src/genesis.rs`): it rejects an empty guardian set, a duplicate
or zero-value guardian key, a zero emitter, an emitter equal to the governance emitter, `CHAIN_RAND`
as a source emitter, a source emitter equal to the governance emitter, and a zero-value source
emitter. A genesis registers *no assets*: a registry starts empty and the first attestation to name
a token is what puts it in, under index 1.

## 5. Transactions

Two `Action` variants (`crates/shrugg-core/src/types/transaction.rs`), bincode tags 7 and 8, after
the three staking actions:

```
Action::BridgeAttest { attestation: Vec<u8>, recipient: ShieldedAddress, r: Word8, time: u32,
                       asset: u32, envelope: Envelope }

Action::BridgeBurn { asset_bundle: Bundle, asset: u32, amount: u64, relayer_fee: u64,
                     to_chain: u16, to: [u8; 32] }
```

Both are carried by an ordinary shielded transaction, and both pay their fee in SHRUGG: an attest
pays `BUNDLE_BASE` (one bundle), a burn pays `2 * BUNDLE_BASE` (two), out of the one bundle allowed
a non-zero fee. See `docs/confidential.md`'s fee table.

### Inbound: an attestation deposits a note

- **The recipient is a hash on the wire.** The 32-byte `to` field of the `Transfer` payload is
  `blake3("shrugg-shielded-recipient", pk || kem_ek)` of the recipient's shielded address
  (`ShieldedAddress::recipient_hash`): a shielded address is about 1.2 KB and the wire format has
  room for a hash. The source-chain depositor names the hash, the guardians sign it, the submitter
  puts the full address in the action, and the ledger recomputes the hash and rejects a mismatch
  (`TxError::BridgeRecipientMismatch`). Without that equality the submitter would choose who
  receives someone else's deposit.
- **The chain computes the note, not the submitter.** The deposit note is
  `{ pk: recipient.pk, from: 0, amount, asset: <registry index>, time, r }` and its commitment is
  `bridge_notes::deposit_commitment` — from the amount the guardians signed, so a relayer cannot
  inflate a mint or redirect it. It is the one commitment a transaction does **not** carry on the
  wire (`Transaction::commitments` omits it), which is why a node indexing notes for wallets
  recomputes it through `bridge_notes::deposit_note`.
- **`time` and `asset` are the depositor's two predictions.** The envelope that lets the recipient
  open the note is sealed against that commitment *before* submitting, so the depositor has to be
  able to compute it — and it can predict neither the height the transaction lands at nor, for a new
  token, the index the registry will assign. So both are fields of the action: `time` is held to the
  window a bundle's `time` gets (`t <= height`, `height - t <= TIME_WINDOW`, checked before the
  attestation is even decoded), and `asset` must equal the index the registry resolves — the entry
  the asset has, or the one this transaction's own registration would assign — else
  `TxError::AttestAssetMismatch { expected, actual }`. Only a first sighting can hit that, and only
  by losing a race to another first sighting; the cost is a fee bundle and a re-proof instead of a
  note whose `asset` word no key of the recipient's opens. The mempool drops a pooled attest the
  same way once a competing first sighting has moved the number.
- **The relayer fee is not deducted.** The `Transfer` payload's own `fee`, in the bridged asset, is
  carried for the record and paid to nobody: on a shielded chain the submitter has no identity to
  pay, so the deposit note carries the **gross** amount the guardians signed. Netting it would burn
  the difference forever and what the pool holds would stop matching what the source chain locked.
- **A guardian-set rotation deposits nothing**, consumes its digest, and binds neither `asset` nor
  the recipient.

### Outbound: a burn is one transaction with two bundles

```
Transaction {
  chain_id,
  bundle: <SHRUGG bundle: asset 0, burn 0, fee = 2 * BUNDLE_BASE>,   // pays for both bundles
  action: BridgeBurn {
    asset_bundle: <bundle: asset = index, fee 0, burn = amount>,
    asset, amount, relayer_fee, to_chain, to }
}
```

A bundle balances one asset and the fee is always SHRUGG — the bundle guest's own rule is that a
non-SHRUGG bundle's `fee` is zero — so a burn is the chain's only two-bundle transaction. The asset
bundle proves in the zkVM that the burner owned notes of that asset summing to at least `amount`,
with `burn` the value leaving the pool — exactly `amount`, because the wire format's `relayer_fee`
is a *portion* of the amount (`fee <= amount`), carved out on the destination chain by the release
contract, which pays `amount - fee` to `to` and `fee` to the relayer and so releases `amount` in
total. A pool that burned `amount + relayer_fee` would destroy more than the far side ever releases
and strand the difference in the source-chain contract forever. Both bundles go through the *same*
admission: four distinct unspent nullifiers, four new commitments (checked across the pair, not just
within each), both digests recomputed, both STARK proofs verified. `apply_burn` records the outbound
message with the **transaction hash** in the sender slot — a burn is funded by notes, so there is no
sender identity — and the next `burn_sequence`; guardians read the burn log exactly as before.

### Admission order — cheap before expensive

`Ledger::validate_inner` (`docs/shielded.md` §5, spec §7). What is bridge-specific:

1. Size caps first, before a byte is parsed: `attestation.len() <= MAX_ATTESTATION_BYTES`
   (16 KiB, `crates/shrugg-core/src/gas.rs`), each envelope ≤ 2048 bytes, and a burn's asset bundle
   gets the caps every bundle gets (`tx.bundle` is only the fee bundle). A guardian set is at most
   255 keys by wire format, so anything past the cap is malformed by construction and must not buy
   verification work.
2. The fee floor at step 3 already knows a burn has two bundles, so an underpaying burn is refused
   on a comparison.
3. At step 7 (the action step, **before** either bundle's proof at step 9):
   - `BridgeAttest`: `time` window → bridge present → `check_attest` (itself ordered cheap-first:
     decode, guardian-set resolution, the replay check against `spent` by digest `mu`, the payload
     decode, the emitter binding, the payload's field checks, and only then set expiry,
     index/quorum, low-s and one recovery per signature) → the `asset` comparison → the recipient
     hash → the deposit commitment against the tree and the fee bundle.
   - `BridgeBurn`: `asset_bundle.asset == action.asset` → its `fee == 0` →
     `burn == amount` → no nullifier or commitment shared with the fee bundle → the
     asset bundle's own bundle checks → `check_burn` (registered asset, `to_chain` is the asset's
     home chain, recipient shape, `relayer_fee <= amount`, `amount != 0`) → the asset bundle's
     proof.

`apply_tx` writes the fee bundle's notes and then runs the action, so `bridge_notes::apply` consumes
the `CheckedAttestation` that `validate` produced rather than verifying the guardian quorum a second
time. A transaction that fails at either step leaves no state behind, because the caller applies to
a scratch clone and keeps it only if the whole block succeeded.

**Replay protection** differs by direction:

- **Inbound** (`BridgeAttest`): digest-based. Every consumed `mu` goes into `BridgeState.spent`
  before payload effects apply; a repeat is `BridgeError::Replay`. No sequence number — the digest
  is the dedup key, since the same attestation can arrive via any relayer. The mempool indexes
  pending digests too (`MempoolError::AttestationConflict`), so two relayers racing one attestation
  never both make it into a block.
- **Outbound** (`BridgeBurn`): a strictly increasing `burn_sequence: u64`, on each
  `BridgeBurnRecord.sequence`.

**Emitter binding**: a `Transfer` must come from the chain's *registered* emitter
(`self.emitters.get(&emitter_chain) == Some(&emitter_address)`, else `WrongEmitter`), and
`token_chain` must equal the emitting chain (`WrongTokenChain`). A `GuardianSetUpgrade` must be
`(CHAIN_RAND, GOVERNANCE_EMITTER)` exactly, else `WrongEmitter`. An undecodable payload is a hard
error (`BridgeError::BadPayload`), never a silent fall-through.

## 6. Storage, RPC, wallet

**Storage** (`crates/shrugg-node/src/storage.rs`) — two RocksDB column families plus one `meta` key:

| Column family | Key | Value |
|----------------|-----|-------|
| `bridge_spent` | digest bytes | empty (a set) |
| `bridge_burns` | big-endian `sequence` | `bincode(BridgeBurnRecord)` |

`meta["bridge_state"]` holds `bincode(BridgeMeta)`; its presence is what makes a chain "bridged" on
disk. The account era's `bridge_balances` family is gone. A per-block commit writes only the rows a
block's bridge transactions touched; `load_bridge` rebuilds a full `BridgeState` from the meta blob
plus the two families, and `truncate_to` (reorg replay) rebuilds them wholesale from the replayed
ledger — a consumed digest does not record which block consumed it, so there is nothing to prune by
height. Startup verification replays the chain and then compares the whole stored `Ledger` against
the replayed one, which covers the bridge including the burn log the root deliberately leaves out
(`verify_chain`; `verify_chain_replays_a_bridged_chain`).

**RPC** (`crates/shrugg-node/src/rpc.rs`, `docs/rpc.md`) — four methods, none of them per-address:

| Method | Params | Result |
|--------|--------|--------|
| `shrugg_getBridgeState` | `[]` | emitter, emitter table, current guardian set, the registry, `next_index`, `burn_sequence`; `{"enabled": false}` with no bridge |
| `shrugg_getAssets` | `[]` | the registry, ascending by index: `{ index, chain, token, asset_id }` |
| `shrugg_bridgeAssetId` | `[token_chain, token_address]` | the asset id; pure arithmetic, answers on any chain |
| `shrugg_getBridgeBurn` | `[sequence]` | one outbound message (`body_hex`, `digest`, `tx`, `height`), or `null` |

`shrugg_getTransaction` renders a `bridge_attest` with the recipient, the action's `asset`, the
`asset_index` and `amount` it decodes against the registry, the note's `time` and blinding `r`, and
the `commitment` the chain computed from those fields — every word of the deposit note, which is
what makes the recovery path below possible; a `bridge_burn` with its asset, amount, relayer fee,
destination and the asset bundle's public fields. Balances are not among them — there are none.

**Wallet** (`crates/shrugg-client`, `docs/cli.md`) — five commands:

| Command | Purpose |
|---------|---------|
| `bridge-mint <ATTESTATION>` | deposit an attestation (hex or `@path`): seal the recipient's envelope, pay with a bundle of this wallet's SHRUGG |
| `bridge-burn <ASSET> <AMOUNT> <TO_CHAIN> <TO>` | burn a bridged asset outbound; checks the bridge and the registry first, then proves **two** bundles |
| `asset-balance [INDEX]` | what this wallet's own notes hold in one bridged asset, or a row per asset |
| `bridge` | the bridge's public state |
| `bridge-message <SEQUENCE>` | one outbound message, verbatim, for a guardian to sign |

A wallet needs `--to` only when depositing to an address other than its own, and it checks the
recipient hash, the asset id and the index against the node before paying for a proof.
`wallet::attested_deposit` reads the deposit out of the attestation bytes with no state and no
signature work, because the envelope has to be sealed before the transaction exists.

**Tests.** `bridge_mint_deposits_a_note_and_a_burn_spends_it`
(`crates/shrugg-node/tests/cluster.rs`) runs the whole path across two validators on a bridged
genesis: an attestation deposits a note only its recipient's viewing key opens (the relayer who paid
for it holds nothing), both nodes register the token under index 1, the same attestation resubmitted
is refused as already consumed, and a two-bundle burn leaves the change as a note and an identical
outbound message on both nodes. The unit level is `bridge/state.rs` (the bridge's own rules),
`ledger/bridge_notes.rs` (the deposit note, the two-bundle burn, the `asset` and `time` bindings),
`mempool.rs` (racing relayers, stale indices) and `storage.rs` (the round trip).

## 7. Test vectors

`crates/shrugg-core/src/bridge/vectors.json` is generated externally by a `tools/vectors` generator
in a separate "bridge repo" and copied in verbatim: top-level keys `guardians`,
`governance_emitter`, `rand_emitter`, `emitters`, `now`, `vectors`, and **39 vectors** — named cases
like `transfer_eth_usdt_6dp_ok`, `upgrade_signed_by_superseded_set`, `quorum_four`, `high_s`,
`replay_eth`, `stale_governance_set`.

One test pins them, at the signature level: `shared_vectors_match_verify`
(`crates/shrugg-core/src/bridge/mod.rs`) re-verifies every vector whose `expect` is one of `ok,
no_quorum, index_order, index_out_of_range, bad_signature, high_s, wrong_guardian, set_expired,
bad_version` against `bridge::verify`, checking the pinned digest (`ok`) or the exact `VerifyError`.
`checked == 23` — an **exact** count, not a lower bound, so a vector that stops matching fails the
build instead of quietly being skipped.

`unknown_set` is deliberately *not* checked there: `verify` takes an already-resolved `GuardianSet`,
not an index, so "no set at this index" is a set-*resolution* concern only `check_attest` can raise.

The account era had a second, ledger-level pass (`vectors_ledger_level`) that drove the remaining
`expect` values — `wrong_emitter`, `wrong_to_chain`, `wrong_token_chain`, `fee_exceeds_amount`,
`amount_overflow`, `bad_payload`, `replay`, `unknown_set`, `set_expired`, `stale_governance_set` —
through a real `BridgeAttest` against a live `Ledger`. It went with the account ledger in S1 and has
not been rebuilt on the note pool (§8). Every one of those refusals is covered by hand-written unit
tests in `bridge/state.rs` and `ledger/bridge_notes.rs`; what is missing is the cross-chain
agreement that the shared vectors give, so a generator change that alters ledger-level behaviour
would no longer be caught here.

## 8. Known gaps

- **No relayer is paid.** The `Transfer` payload carries a `fee` for whoever relays the attestation,
  and on this chain nobody collects it: the deposit is minted gross and the submitter pays a SHRUGG
  bundle fee out of its own notes for the privilege. Relaying is therefore altruistic (or paid out
  of band) until there is a way to pay an identity-less submitter.
- **A deposit's envelope is bound to nothing, so the wallet does not depend on it.** Anyone may
  submit an attestation (the guardians' signatures are the whole authorisation) and admission checks
  nothing about the `envelope` the submitter publishes beyond its size — so a hostile relayer can
  seal garbage, consume the attestation's digest, and leave a note the honest relayer can no longer
  resubmit. It locks nothing: *every* field of a deposit note is public in that one transaction
  (`recipient`, `amount`, `asset`, `time`, `r`), so `wallet::scan` walks committed blocks, rebuilds
  the note of every `bridge_attest` addressed to it with `rebuilt_deposit`, and records it against
  the leaf whose commitment matches — with no envelope opened. The cost of the attack is therefore
  one `BUNDLE_BASE` to the attacker and one extra block walk to the recipient. `scanned_attest_height`
  is the cursor for that walk, so blocks are read once and a store written before this path existed
  re-reads from zero the first time. In-circuit envelope validity (spec §14) is not needed for
  deposits for the same reason: nothing about a deposit note is secret.
- **The ledger-level vector pass has not been rebuilt** on the note pool (§7).
- **`bridge-burn` still learns about *some* bad arguments from the node, after paying for two
  proofs.** The wallet now pre-checks four things before any proving: a zero amount, a relayer fee
  above the amount, a chain with no bridge at all, and an asset index the registry does not hold —
  the last two off one `shrugg_getBridgeState` read (`wallet::burn_is_possible`). What is left is
  the bridge's own policy, which the wallet deliberately does not restate: a destination that is not
  that asset's home chain, and a recipient of the wrong shape, both still come back as a rejection
  once both bundles have been proved (three minutes).
- **Equal-to-parent block timestamps are allowed.** The bridged-chain check in `apply_block` is `<`,
  not `<=` — it forbids a rewind but not a repeat. The residual, in the code's own words: "a
  colluding 2/3 of leaders can hold `timestamp_ms` constant, which freezes outbound burn timestamps
  and keeps a superseded guardian set inside its grace window indefinitely."
- **`BridgeState.burns` is unbounded and kept whole in memory** — "known linear growth, to be
  drained into storage per block before ~100k burns (spec 6.3)". Storage persists new rows
  incrementally, but the in-memory map is never pruned and is cloned on every speculative block
  execution.
- **A burn costs two proofs**, about three minutes on a laptop, and roughly 600 KB of the 4 MiB
  block limit. Nothing amortizes that yet.
- No light-client or on-chain verification of source-chain state exists or is planned; the guardian
  committee's signatures are the entire trust model (§1).
- No bridge-specific rate limiting beyond the fee floors and the 16 KiB `MAX_ATTESTATION_BYTES` cap.

## 9. Relationship to the shielded pool and the confidential layer

Unlike the account era, where the two areas shared only the `Ledger` and the gas module, the bridge
now rides on the pool's machinery:

- Both bridge actions are carried by a transaction whose bundle is proved by the pinned `bundle`
  zkVM guest, so every bridge transaction pays for at least one STARK verification, and a burn for
  two. The guest is what enforces `asset ≠ 0 ⇒ fee = 0` and that a bundle balances one asset —
  which is *why* a burn needs a second bundle at all.
- Deposit notes are appended to the same commitment tree as every other note and are
  indistinguishable from them once appended; they are committed by the tree, not by `bridge_root`.
- The bridge's own work is still plain CPU cryptography: keccak256, secp256k1 recovery, and set
  lookups. `bridge-codec` and `shrugg-core::bridge` import nothing confidential or zkVM-related.
- The privacy of a bridged holding is the privacy of a note (§11), which is a strictly stronger
  claim than the account era could make, where a bridged balance was plain visible state.

## 10. What changed from the account era

For anyone holding an integration written against the pre-S1 bridge:

| then | now |
|---|---|
| `balances: (AssetId, Address) -> u128` | nothing; a holding is a note with `asset = <index>` |
| a recipient was a Dilithium2 address | a recipient is `blake3` of a shielded address; the action carries the address |
| `amount: u128` | `amount: u64` (a note's field); anything larger is refused at attestation time |
| the registry mapped `AssetId -> (chain, token)` | it maps `AssetId -> { chain, token, index }`, and the note carries the index |
| the relayer fee was paid to the submitter | inbound it is carried and paid to nobody (the deposit is gross); outbound it is still a portion of `amount`, paid on the destination chain, and a burn destroys exactly `amount` |
| `BridgeBurn` was one account-debiting transaction | it is two bundles in one transaction |
| `shrugg_getAssetBalance`, `bridge-status` | gone; `shrugg_getAssets` + a wallet-local `asset-balance` |
| the bridge root committed balance leaves | it commits registry leaves with indices, plus `next_index` |

The last row is a consensus change: `BridgeState::root` was re-pinned in S3, so a bridged chain
cannot be carried across that boundary (§4).

## 11. Privacy and trust on the shielded bridge

| what | who sees it |
|---|---|
| a deposit's amount, asset index, recipient address | everyone, in that one transaction |
| which note a recipient later spends | nobody (the nullifier is a one-way function of `nk`) |
| a burn's amount, asset, destination, relayer fee | everyone (guardians need it) |
| which notes funded a burn | nobody |
| bridged asset balances | only the holder (or a viewing-key holder) |
| guardian set, emitters, registry, burn log | everyone |

The trust model is unchanged: `n·2/3 + 1` colluding guardians can mint arbitrary value. The shielded
design adds one obligation on Rand's side that the account-era bridge did not have: the ledger, not
the submitter, derives the deposit note from the attested amount, so a relayer cannot inflate a
mint.

## 12. What integrators need to know

- Recipients on Rand are identified by a 32-byte hash of a shielded address, not a Dilithium2
  address. Wallets print it and source-chain front ends must accept it.
- Amounts are `u64` in the bridged asset's own units after decimals; anything above `2⁶⁴ − 1` is
  rejected at attestation time. Only index 0 (SHRUGG) has this chain's nine decimals — what a
  bridged token's smallest unit means belongs to its source chain.
- The asset **index**, not the asset id, is what a note and a wallet carry; `shrugg_getAssets` maps
  between them, and `shrugg_bridgeAssetId` computes an id for a token the registry has never seen.
- A deposit of a token this chain has never seen is a first sighting, and the transaction has to
  name the index it will be given. Submit one at a time, or be ready to re-prove the loser.
- A burn costs one SHRUGG fee bundle plus two proofs (~100 s each on a laptop today).
