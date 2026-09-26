# The guardian bridge — architecture

> **Live on the shielded chain since phase S3.** A bridged holding is a **note**, not a balance.
> `BridgeState` has no per-account balances at all — the S1 pool deleted the accounts they were
> keyed by — so what a wallet "has" in a bridged asset is the notes of that asset its viewing key
> opens, exactly as for RAND. A note's `asset` word is the registry's dense `u32` index for the
> asset; index 0 is RAND. There is no `rand_getAssetBalance` and there never will be again.
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
   source chain (Ethereum / BSC / Tron / Solana)                    Rand (RAND)
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
   the burn       │        │ rotated by the    │   guardians read   │   one bundle: slots 0–1 burn │
   message        │        │ governance emitter│   the burn log     │   the asset, 2–3 pay the RAND│
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
`keccak256(uncompressed_pubkey[1..])` (`crates/randprotocol-core/src/bridge/mod.rs`) — Ethereum's
address derivation, reused so the same key/address works across the EVM contracts, the Solana
program, and Rand.

Quorum for a set of size `n` is `n*2/3 + 1` (`quorum`, `crates/bridge-codec/src/lib.rs`). Each
signature carries `r`, `s`, and recovery id `v`, and must be **low-s**: `s <= n/2` for the
secp256k1 curve order, pinned as `SECP256K1_HALF_N` — a high-s signature is rejected outright,
foreclosing signature malleability. The digest guardians sign is `mu =
keccak256(keccak256(body_bytes))`, a double keccak (`crates/randprotocol-core/src/bridge/mod.rs`).

A **governance emitter** is a fixed, non-guardian address Rand treats as the sole authorized
source of guardian-set rotations: `keccak256("rand-bridge-governance")`, pinned as a literal
(`GOVERNANCE_EMITTER`, `bridge-codec/src/lib.rs`) and cross-checked by a test
(`governance_emitter_matches_string`). It is a slot in the `(emitter_chain, emitter_address)` pair
that only a `GuardianSetUpgrade` payload may claim, and only as `(CHAIN_RAND, GOVERNANCE_EMITTER)`.

**The redirect attack, and why it is closed (2026-09-19, Task 5b, chain 14).** A Rand transaction
carries no signature: a burn is authorised by the STARK proof of its bundle (two bundles before
chain 14's hidden-asset bundle), which shows the burner held the notes. Until the transaction
binding, a proof committed only to its bundle's own digest (anchor, nullifiers, commitments, fee,
burn fields, time) — nothing tied them to the
`BridgeBurn` action around them. Anyone who saw a pending burn in gossip (a peer, a proposer) could
copy it, keep both proofs byte for byte, swap `to` for their own address (or raise `relayer_fee`
and relay it themselves, or name another backing's `(to_chain, token)`), and race it; whichever
copy committed first spent the notes, and the source-chain release contract would then pay the
attacker — theft, with nothing on Rand to show it was not the burner's intent. An attest could be
copied the same way with its deposit `r`, `time` or envelope changed (stranding the recipient's
note), or its fee bundle lifted onto another transaction. Now every bundle proof is made over, and
verified against, the eight words of `Transaction::binding` — a hash of the whole transaction
(chain id, the one bundle including its four envelopes, the action) with only the bundle proof
bytes blanked —
as its public input segment, so any copy that changes any field fails the proof
(`TxError::InvalidBundleProof`, `PublicValues`); the ledger tests named in `docs/confidential.md`
admitted each of these copies before the fix and refuse them after. **Every wallet and relayer
must run the new binary at the fork**: an old `rand` makes empty-segment proofs, which the chain
now refuses.

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
whatever verifies it on the other chains; `randprotocol-core` supplies both (`sha3`, `k256`).

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
keys — that is `randprotocol-core`'s job; the codec has no notion of "current guardian set."

**Left-padding.** `to`, `token_address`, and `emitter_address` are fixed 32-byte slots, so the wire
format is one chain-agnostic shape regardless of native address width. Ethereum/BSC/Tron addresses
are 20 bytes, left-padded with 12 zero bytes. `bridge-codec` doesn't enforce this — it's chain-shape
policy, not wire law — but `BridgeState::check_burn` does on the way out
(`crates/randprotocol-core/src/bridge/state.rs`): non-zero `to[..12]` is `BadRecipient` on chains 2/3/4,
and an all-zero `to` is `BadRecipient` everywhere. The wallet no longer restates those rules (the
account era's `check_burn_recipient` went with the accounts): `wallet::submit_burn` pre-checks only
the two things it would otherwise throw two bundle proofs away on — a zero amount and a relayer fee
larger than the amount — and leaves the rest to admission (§8).

## 3. Guardian sets

`BridgeConfig` (`crates/randprotocol-core/src/bridge/state.rs`) carries the genesis emitter address,
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
(`crates/randprotocol-core/src/ledger/mod.rs`), which also pins that an unbridged chain accepts the very
same rewind.

Test coverage: `guardian_upgrade_must_be_signed_by_the_current_set`,
`guardian_upgrade_rotates_with_grace_and_rejects_skips`,
`upgrade_rejects_duplicate_and_zero_guardian_keys` (`crates/randprotocol-core/src/bridge/state.rs`).

## 4. On-chain state: `BridgeState`

`crates/randprotocol-core/src/bridge/state.rs`:

| Field | Type | Meaning |
|-------|------|---------|
| `emitter` | `[u8; 32]` | Rand's outbound emitter address, stamped into burn messages |
| `emitters` | `BTreeMap<u16, [u8; 32]>` | registered emitter per source chain |
| `guardian_sets` | `BTreeMap<u32, GuardianSet>` | every set ever seen, by index |
| `current_set` | `u32` | index of the authoritative ECDSA set |
| `spent` | `BTreeSet<Hash>` | consumed attestation digests (inbound replay guard) |
| `burn_sequence` | `u64` | next outbound sequence number |
| `burns` | `BTreeMap<u64, BridgeBurnRecord>` | every outbound message, held whole in memory |
| `pq_guardians` | `Vec<PublicKey>` | B3: the genesis Dilithium2 set, index-aligned with the ECDSA `guardian_sets[0]`; fixed for the chain's life |
| `pause_key` | `Option<PublicKey>` | B1: the one Dilithium2 key that may `PauseMints` |
| `mint_paused` | `bool` | B1: while true, every transfer `BridgeAttest` is refused |
| `pause_nonce` | `u64` | B1: what the next `PauseMints`/`UnpauseMints` must carry |
| `list_nonce` | `u64` | B4: what the next `ListBacking`/`RegisterBridgedToken` must carry |

**There are no balances.** Phase S3 deleted `balances: BTreeMap<(AssetId, Address), u128>` outright:
a bridged holding is a note in the ledger's own commitment tree, and the tree is what commits to it.
What is left here is the *public* half of the bridge — who may attest, which digests are consumed,
what has been burned outbound, and (since bridge hardening) the pause and listing state.

`AssetId = blake3("rand-bridge-asset" || token_chain BE u16 || token_address)` — a pure,
domain-separated function of `(chain, address)`, computable even without a bridge (§6); it is still
what `rand_bridgeAssetId` computes and what a `Transfer` payload's `(token_chain, token_address)`
resolves to, but it is no longer a *registry key*: see §13.

**Asset indices moved to the RPL token registry (v0.5).** `BridgeState` used to own the map from
`AssetId` to `{ chain, token, index }` and the counter that assigned the next index; the RPL token
standard (`docs/tokens.md`) replaced both with `crate::ledger::tokens::TokenRegistry`, a
ledger-level registry shared by native and bridged tokens alike. `BridgeState::check_attest`/
`check_burn` now *resolve* an asset through the registry instead of owning it; §13 has the details.
A note's `asset` field is still one dense `u32` word (`FIRST_TOKEN_INDEX = 1`, 0 is RAND), and
bridged amounts must still fit a note's `u64` (`BridgeError::AmountOverflow` above that).

### `root()` and what it commits

```
blake3("rand-bridge-state-4"
    || bincode(emitter, emitters, current_set, guardian_sets)
    || merkle(sorted spent digests)
    || burn_sequence BE
    || bincode(pq_guardians)
    || bincode(pause_key, mint_paused, pause_nonce, list_nonce))
```

`emitter`/`emitters` are included because they are consensus-relevant genesis configuration, not
incidental metadata. `burns` is **excluded** — derivable from transaction history; test
`root_changes_with_the_spent_set_and_the_sequence_but_not_burn_records` clears `burns` on a clone
and confirms the root is unchanged. **The asset registry and its `next_index` counter are not here
at all** — both moved to `TokenRegistry`, which the *chain's* state root commits to separately as
`tokens_root` (§13); committing them here too would only give two places for the same fact to
disagree.

The root is pinned by `root_is_pinned_for_a_fixed_state`: a fixed state (two guardians, two PQ
guardians, a pause key, one spent digest, `burn_sequence = 7`) must hash to
`4f2ea1290d513a855ddaaa7aa2ce68a3bd5a54ef3f84819b238a6e9c1da0f712`. The test's comment: "Changing
this hash changes consensus ... treat a failure here as a hard fork, never as a test to
re-baseline." It has been re-pinned four times: in S3 (`rand-bridge-state`, unnamed domain →
implicit; balance leaves left, the registry leaf gained an index — account-era value
`c757e13d…b043`, S3 value `ee50b48c…0c43dc8`), when the RPL token standard moved the registry
and `next_index` out to `TokenRegistry` (domain `rand-bridge-state-2`, value before B3
`89555202…52f9ba642cf5b`), when B3 appended the PQ guardian set (domain `rand-bridge-state-3`,
value before B1/B4 `2504a9da…21b5aceb6366e141`), and when B1/B4 appended the pause key, the pause
flag and the two governance nonces (domain `rand-bridge-state-4`, value before that
`2f1798b1…690499dd6550e63c46`).

The bridge root folds into the chain's state root only when a bridge exists:

```
state_root = blake3("rand-state-2" || tree_root || nullifier_root || validators_root || programs_root)
           = blake3("rand-state-2" || … || programs_root || bridge_root)   with a `bridge` section
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
(`check_bridge`, `crates/randprotocol-core/src/genesis.rs`): it rejects an empty guardian set, a duplicate
or zero-value guardian key, a zero emitter, an emitter equal to the governance emitter, `CHAIN_RAND`
as a source emitter, a source emitter equal to the governance emitter, and a zero-value source
emitter. A genesis registers *no assets*: a registry starts empty and the first attestation to name
a token is what puts it in, under index 1.

## 5. Transactions

Two `Action` variants (`crates/randprotocol-core/src/types/transaction.rs`), bincode tags 7 and 8, after
the three staking actions:

```
Action::BridgeAttest { attestation: Vec<u8>, recipient: ShieldedAddress, r: Word8, time: u32,
                       asset: u32, envelope: Envelope }

Action::BridgeBurn { asset: u32, amount: u64, relayer_fee: u64, to_chain: u16,
                     token: [u8; 32], to: [u8; 32] }
```

Both are carried by an ordinary shielded transaction, and both pay their fee in RAND: an attest
pays `BUNDLE_BASE` (one bundle) and nothing more, because its relayer is paying for a depositor who
holds no RAND yet; a burn pays `BRIDGE_BURN_FEE` (0.01 RAND), the bridge's charge towards the
validators' infrastructure, which also covers the base of its one bundle. On a chain without aggregation the whole fee is the block proposer's. See `docs/confidential.md`'s fee table.

### Inbound: an attestation deposits a note

- **The recipient is a hash on the wire.** The 32-byte `to` field of the `Transfer` payload is
  `blake3("rand-shielded-recipient", pk || kem_ek)` of the recipient's shielded address
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
- **The blinding is derived, not chosen** (F1, chain 14). `r` is
  `blake3("rand-deposit-r-1" || mu)` read as eight little-endian words
  (`bridge_notes::derive_deposit_r`), over `mu = keccak256(keccak256(body))` — the 32 bytes the
  guardian quorum signed. The ledger requires it (`BridgeError::WrongDepositBlinding`) and refuses
  anything else *before* any signature work: two keccaks and a blake3 over the already
  size-capped attestation bytes, ahead of the PQ structure check and the secp256k1 quorum. It is a
  byte verdict, so admission caches it (`admission::is_permanent`). The field stays on the wire —
  the transaction is self-describing and the wallet's public-field rebuild (§8) reads it there —
  it is only constrained. The rule applies to every attest, a rotation's included, so no attest
  carries a field a copier can vary but `time`.

  Why: before it, the deposit note's commitment was not fixed until someone submitted the
  attestation. Anyone who saw a relayer's transaction could submit the same attestation first
  under a blinding of its own — the recipient still got a note (the wallet rebuilds it from the
  public fields), but the relayer's own transaction died on `Bridge(Replay)` or
  `CommitmentExists` after paying for a bundle proof, and the recipient's envelope was replaced.
  With `r` fixed, two submitters of one attestation at one `time` name **one** note, so the pool
  conflicts them on the commitment claim instead of racing them to two different notes.

  `time` is deliberately *not* bound. It must stay the submitter's: the envelope is sealed against
  the commitment before the transaction exists, and no rule can derive a `time` every submitter
  would agree on — the attestation body's own timestamp is the source chain's clock, and clamping
  it into this chain's window is a function of the height the transaction is *judged* at, which
  is exactly what a depositor cannot predict. The residual: a front-runner may still pick another
  `time` inside the window, producing a different note — of the same recipient, amount and asset,
  which its recipient's wallet finds by the same public-field rebuild — and the two submissions
  then collide on the attestation digest claim instead.
- **`time` and `asset` are the depositor's two predictions.** The envelope that lets the recipient
  open the note is sealed against that commitment *before* submitting, so the depositor has to be
  able to compute it — and it cannot predict the height the transaction lands at. So both are fields
  of the action: `time` is held to the window a bundle's `time` gets (`t <= height`, `height - t <=
  TIME_WINDOW`, checked before the attestation is even decoded), and `asset` must equal the index
  the token registry has already given `(chain, token)` — resolved from the wire bytes alone,
  before any guardian signature is verified — else `TxError::AttestAssetMismatch { expected,
  actual }`. **Since v0.5 a token must be listed before its first deposit** (`docs/tokens.md` §5):
  there is no more first-sighting auto-registration, so an attestation naming a `(chain, token)`
  nobody has listed is `BridgeError::UnlistedToken`, not a registration.
- **The relayer fee is not deducted.** The `Transfer` payload's own `fee`, in the bridged asset, is
  carried for the record and paid to nobody: on a shielded chain the submitter has no identity to
  pay, so the deposit note carries the **gross** amount the guardians signed. Netting it would burn
  the difference forever and what the pool holds would stop matching what the source chain locked.
- **A guardian-set rotation deposits nothing**, consumes its digest, and binds neither `asset` nor
  the recipient.

### Outbound: a burn is one transaction with one bundle

```
Transaction {
  chain_id,
  bundle: <hidden-asset bundle: slots 0–1 spend the token, slots 2–3 pay the RAND fee;
           burn_asset = asset, burn_a = amount, burn_r = 0, fee >= BRIDGE_BURN_FEE>,
  action: BridgeBurn { asset, amount, relayer_fee, to_chain, token, to }
}
```

Since the hidden-asset bundle (chain 14) a burn is one bundle: its private slots 0–1 prove in the
zkVM that the burner owned notes of the asset summing to at least `amount`, with `burn_a` the value
leaving the pool, and its RAND slots 2–3 pay the fee. `burn_a` is exactly `amount`, because the wire format's `relayer_fee`
is a *portion* of the amount (`fee <= amount`), carved out on the destination chain by the release
contract, which pays `amount - fee` to `to` and `fee` to the relayer and so releases `amount` in
total. A pool that burned `amount + relayer_fee` would destroy more than the far side ever releases
and strand the difference in the source-chain contract forever. The bundle goes through the
ordinary admission: four distinct unspent nullifiers, four new commitments, the digest recomputed
and the STARK proof verified against the transaction's binding, so it cannot be copied under a
changed `to`, `relayer_fee` or `(to_chain, token)` (§1, "The redirect attack"). `apply_burn` records the outbound
message with the **transaction hash** in the sender slot — a burn is funded by notes, so there is no
sender identity — and the next `burn_sequence`; guardians read the burn log exactly as before.

### Admission order — cheap before expensive

`Ledger::validate_inner` (`docs/shielded.md` §5, spec §7). What is bridge-specific:

1. Size caps first, before a byte is parsed: `attestation.len() <= MAX_ATTESTATION_BYTES`
   (16 KiB, `crates/randprotocol-core/src/gas.rs`), each of the bundle's four envelopes ≤ 2048 bytes,
   and the one bundle a burn carries gets the caps every bundle gets. A guardian set is at most
   255 keys by wire format, so anything past the cap is malformed by construction and must not buy
   verification work.
2. The fee floor at step 3 (`BRIDGE_BURN_FEE`) refuses an underpaying burn on a comparison.
3. At step 7 (the action step, **before** either bundle's proof at step 9):
   - `BridgeAttest`: `time` window → bridge present → `check_attest` (itself ordered cheap-first:
     decode, guardian-set resolution, the replay check against `spent` by digest `mu`, the payload
     decode, the emitter binding, the payload's field checks, and only then set expiry,
     index/quorum, low-s and one recovery per signature) → the `asset` comparison → the recipient
     hash → the deposit commitment against the tree and the fee bundle.
   - `BridgeBurn`: `asset != 0` → `burn_asset == asset` → `burn_a == amount` → `burn_r == 0`
     (`tokens::check_asset_burn`) → `check_burn` (a backing of the asset, recipient shape, release
     unit, `relayer_fee <= amount`, the backing's `locked` covers `amount`).
4. At steps 8–9, the bundle's digest and proof, verified against the transaction binding
   (`Transaction::binding`; `docs/confidential.md`, "Transaction binding").

`apply_tx` writes the bundle's four notes and then runs the action, so `bridge_notes::apply` consumes
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

**Storage** (`crates/randprotocol-node/src/storage.rs`) — two RocksDB column families plus one `meta` key:

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

**RPC** (`crates/randprotocol-node/src/rpc.rs`, `docs/rpc.md`) — none of it per-address:

| Method | Params | Result |
|--------|--------|--------|
| `rand_getBridgeState` | `[]` | emitter, emitter table, guardian set, `pq_guardians`, `mint_paused`, `pause_nonce`, `list_nonce`, `pause_key`, `registration_fee`, `next_index`, `burn_sequence`, `assets` (the `rand_getAssets` rows); `{"enabled": false}` with no bridge |
| `rand_getAssets` | `[]` | the registry's backing rows, ascending by index: `{ index, chain, token, asset_id, decimals, locked, mint_cap_per_day, minted_today, mint_day }` |
| `rand_bridgeAssetId` | `[token_chain, token_address]` | the asset id; pure arithmetic, answers on any chain |
| `rand_getBridgeBurn` | `[sequence]` | one outbound message (`body_hex`, `digest`, `tx`, `height`), or `null` |

The token-level RPC (`rand_getTokens`, `rand_getToken`, `rand_getTokenSupply`) lives in
`docs/tokens.md`: a bridged token's row carries every one of its backings, not one row per backing.

`rand_getTransaction` renders a `bridge_attest` with the recipient, the action's `asset`, the
`asset_index` and `amount` it decodes against the registry, the note's `time` and blinding `r`, and
the `commitment` the chain computed from those fields — every word of the deposit note, which is
what makes the recovery path below possible; a `bridge_burn` with its asset, amount, relayer fee,
destination and the one bundle's public fields (`burn_asset`, `burn_a`). Balances are not among
them — there are none.

**Wallet** (`crates/randprotocol-client`, `docs/cli.md`) — bridge and RPL-registry commands:

| Command | Purpose |
|---------|---------|
| `bridge-mint <ATTESTATION> --pq <QUORUM>` | deposit an attestation (hex or `@path`) with its Dilithium2 co-signature quorum: seal the recipient's envelope, pay with one hidden-asset bundle of this wallet's RAND |
| `bridge-rotate <ROTATION> --pq <QUORUM>` | submit a guardian-set rotation (payload 2) with the current PQ set's co-signature quorum |
| `bridge-pause --sig <SIG>` | pause bridge minting with the genesis pause key's signature; bundle-less, fee-less |
| `bridge-unpause --pq <QUORUM>` | lift a pause with a PQ guardian quorum; bundle-less, fee-less |
| `bridge-burn <ASSET> <AMOUNT> <TO_CHAIN> <TOKEN> <TO>` | burn a bridged asset outbound: checks the bridge, the backing and its locked amount and release unit first, then proves **one** bundle that burns the asset and pays the RAND fee |
| `token register-bridged … --pq <QUORUM>` | register a new bridged token after genesis with its first backing (B4) |
| `token list-backing … --pq <QUORUM>` | add a backing to an existing bridged token (B4) |
| `asset-balance [INDEX]` | what this wallet's own notes hold in one bridged asset, or a row per asset |
| `bridge` | the bridge's public state |
| `bridge-message <SEQUENCE>` | one outbound message, verbatim, for a guardian to sign |

A wallet needs `--to` only when depositing to an address other than its own, and it checks the
recipient hash, the asset id and the index against the node before paying for a proof.
`wallet::attested_deposit` reads the deposit out of the attestation bytes with no state and no
signature work, because the envelope has to be sealed before the transaction exists. Full flag
detail for every command above is `docs/cli.md`'s `rand` (wallet) table.

**Tests.** `bridge_mint_deposits_a_note_and_a_burn_spends_it`
(`crates/randprotocol-node/tests/cluster.rs`) runs the whole path across two validators on a bridged
genesis: an attestation deposits a note only its recipient's viewing key opens (the relayer who paid
for it holds nothing), both nodes register the token under index 1, the same attestation resubmitted
is refused as already consumed, and a burn leaves the change as a note and an identical
outbound message on both nodes. The unit level is `bridge/state.rs` (the bridge's own rules),
`ledger/bridge_notes.rs` (the deposit note, the burn rule, the `asset` and `time` bindings),
`mempool.rs` (racing relayers, stale indices) and `storage.rs` (the round trip).

## 7. Test vectors

`crates/randprotocol-core/src/bridge/vectors.json` is generated externally by a `tools/vectors` generator
in a separate "bridge repo" and copied in verbatim: top-level keys `guardians`,
`governance_emitter`, `rand_emitter`, `emitters`, `now`, `vectors`, and **39 vectors** — named cases
like `transfer_eth_usdt_6dp_ok`, `upgrade_signed_by_superseded_set`, `quorum_four`, `high_s`,
`replay_eth`, `stale_governance_set`.

One test pins them, at the signature level: `shared_vectors_match_verify`
(`crates/randprotocol-core/src/bridge/mod.rs`) re-verifies every vector whose `expect` is one of `ok,
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
  and on this chain nobody collects it: the deposit is minted gross and the submitter pays a RAND
  bundle fee out of its own notes for the privilege. Relaying is therefore altruistic (or paid out
  of band) until there is a way to pay an identity-less submitter.
- **A deposit's envelope is bound to nothing, so the wallet does not depend on it.** Anyone may
  submit an attestation (the guardians' signatures are the whole authorisation) and admission checks
  nothing about the `envelope` the submitter publishes beyond its size — so a hostile relayer can
  seal garbage, consume the attestation's digest, and leave a note the honest relayer can no longer
  resubmit. (Since F1 the *note* is no longer the front-runner's to choose: the blinding is the
  attestation digest's, so at the same `time` both submitters name the same leaf — §5. What is
  left is the envelope, and another `time` in the window.) It locks nothing: *every* field of a deposit note is public in that one transaction
  (`recipient`, `amount`, `asset`, `time`, `r`), so `wallet::scan` walks committed blocks, rebuilds
  the note of every `bridge_attest` addressed to it with `rebuilt_deposit`, and records it against
  the leaf whose commitment matches — with no envelope opened. The cost of the attack is therefore
  one `BUNDLE_BASE` to the attacker and one extra block walk to the recipient. `scanned_attest_height`
  is the cursor for that walk, so blocks are read once and a store written before this path existed
  re-reads from zero the first time. In-circuit envelope validity (spec §14) is not needed for
  deposits for the same reason: nothing about a deposit note is secret.
- **The ledger-level vector pass has not been rebuilt** on the note pool (§7).
- **`bridge-burn` still learns about *some* bad arguments from the node, after paying for a
  proof.** The wallet pre-checks that the chain has a bridge, that it holds `ASSET` in the registry,
  that the named `(TO_CHAIN, TOKEN)` backs it, that the backing has at least `AMOUNT` locked, and
  that `AMOUNT` and the relayer fee are whole release units — all off one `rand_getBridgeState`/
  `rand_getTokens` read, before any proving. What is left is the endpoint's own policy on the
  destination chain, which the wallet cannot see: a rejection there still costs one proof
  (~100 s).
- **Equal-to-parent block timestamps are allowed.** The bridged-chain check in `apply_block` is `<`,
  not `<=` — it forbids a rewind but not a repeat. The residual, in the code's own words: "a
  colluding 2/3 of leaders can hold `timestamp_ms` constant, which freezes outbound burn timestamps
  and keeps a superseded guardian set inside its grace window indefinitely."
- **`BridgeState.burns` is unbounded and kept whole in memory** — "known linear growth, to be
  drained into storage per block before ~100k burns (spec 6.3)". Storage persists new rows
  incrementally, but the in-memory map is never pruned and is cloned on every speculative block
  execution.
- **A burn costs one proof**, about 100 s on a laptop, and roughly 1.43 MB of the 4 MiB default
  block limit (`docs/rpc.md`'s "The transaction on the wire") — two burns fit a block, not more.
- No light-client or on-chain verification of source-chain state exists or is planned; the guardian
  committee's signatures are the entire trust model (§1).
- No bridge-specific rate limiting beyond the fee floors and the 16 KiB `MAX_ATTESTATION_BYTES` cap.

## 9. Relationship to the shielded pool and the confidential layer

Unlike the account era, where the two areas shared only the `Ledger` and the gas module, the bridge
now rides on the pool's machinery:

- Both bridge actions are carried by a transaction whose one bundle is proved by the pinned
  hidden-asset zkVM guest (`docs/confidential.md`, "The hidden-asset bundle guest"), so every
  bridge transaction pays for exactly one STARK verification. The guest is what enforces the burn
  shape — `burn_asset`/`burn_a` for the token, `burn_r` for RAND — and balances both groups in one
  proof, which is why a burn no longer needs a second bundle at all (before chain 14 it did).
- Deposit notes are appended to the same commitment tree as every other note and are
  indistinguishable from them once appended; they are committed by the tree, not by `bridge_root`.
- The bridge's own work is still plain CPU cryptography: keccak256, secp256k1 recovery, and set
  lookups. `bridge-codec` and `randprotocol-core::bridge` import nothing confidential or zkVM-related.
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
| `BridgeBurn` was one account-debiting transaction | it is one hidden-asset bundle (two bundles before chain 14) |
| `rand_getAssetBalance`, `bridge-status` | gone; `rand_getAssets` + a wallet-local `asset-balance` |
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
- **Every amount on the wire is normalised to `BRIDGE_DECIMALS` (8), whatever the source token's
  own decimal count is** (§13): a deposit's `Transfer` payload always names an amount in the
  bridged token's 8-decimal units, and a `BridgeBurn` releases in the same units, converted back to
  the source coin's native units on the destination chain. Only index 0 (RAND) has this chain's
  own nine decimals.
- **A token must be listed before it can be deposited or burned** — v0.5 removed first-sighting
  auto-registration (`docs/tokens.md` §5). An attestation naming an unlisted `(chain, token)` is
  refused `BridgeError::UnlistedToken`, funds safe in the source-chain contract's custody but stuck
  until a PQ guardian quorum lists it (§18) — **list on Rand before `setToken` on the endpoint**, or
  a deposit can land on the endpoint before Rand will accept its attestation.
- The asset **index**, not the asset id, is what a note and a wallet carry; `rand_getAssets` and
  `rand_getTokens` map between them, and `rand_bridgeAssetId` computes an id for a `(chain, token)`
  pair whether or not it backs anything yet.
- A burn costs one RAND fee bundle, one proof (~100 s on a laptop today), and is refused before
  proving if the amount or the relayer fee is not a whole release unit of the backing's source
  decimals (§13), or if the backing does not hold enough locked.

## 13. RPL and the bridge: one token, many backings (v0.5)

Full detail on the RPL token standard is `docs/tokens.md`; this section is what a bridge integrator
needs of it. The asset registry moved from `BridgeState` into a ledger-level
`crate::ledger::tokens::TokenRegistry` (`docs/superpowers/specs/2026-09-19-rpl-token-standard-design.md`
§12), shared by native and bridged tokens, so that a token is a registry entry either way — not a
contract, and not something the bridge owns alone.

**One bridged token, many backings.** A `Bridge`-authority token (`MintAuthority::Bridge {
backings: Vec<Backing> }`) no longer corresponds to a single `(chain, token)` pair. Its first
bridged registration, **zUSD**, is backed by USDT and USDC locked on four chains — Ethereum,
BSC and Solana carry both coins, Tron only USDT (Circle discontinued Tron USDC):

```
chain  token (32-byte wire form)                                                  coin  decimals
2      000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7           USDT  6
2      000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48           USDC  6
3      00000000000000000000000055d398326f99059ff775485246999027b3197955           USDT  18
3      0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d           USDC  18
4      000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c           USDT  6
5      ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264           USDT  6
5      c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61           USDC  6
```

`Backing { chain: u16, token: [u8; 32], decimals: u8, locked: u64, minted_today: u64, mint_day:
u32 }` (`crates/randprotocol-core/src/ledger/tokens.rs`): `(chain, token)` backs at most one token
in the whole registry (`TokenError::BackingTaken`), a token has 1..=32 backings
(`TokenError::TooManyBackings`, `NoBackings`), and `decimals` is the **source** coin's own count,
`0..=MAX_BACKING_DECIMALS` (18) — never the bridged token's own 8 (`TokenError::
BadBackingDecimals`). The user accepted the pooled-backing risk (a depeg on any one coin dilutes
every zUSD holder, and the seven coins are fungible into and out of zUSD at par) in exchange for
one short token id instead of seven, with no Rand-side per-backing share cap: the source endpoints'
own pauser and per-token rate caps are the only limit on how much of one coin's risk zUSD carries.

**The invariant: `total_supply == Σ backings.locked`, by construction.** `lock`/`release`
(`TokenRegistry::lock`, `TokenRegistry::release`) are the only two functions that touch a backing's
`locked` field, and each moves the token's `total_supply` by the same amount in the same call:
`lock` (`BridgeAttest`) does `locked += amount; total_supply += amount`, `release` (`BridgeBurn`)
does `locked -= amount; total_supply -= amount`. Nothing else writes either field, so the identity
holds after every block — several unit tests carry it through a mixed sequence of locks and
releases, and it is checked, not merely argued, at the points that matter: the token leaf commits
every backing's `locked` into `tokens_root`, so two nodes that disagree about one diverge at the
state root, not only in an off-chain audit. On the source-chain side, the deployed endpoints are
fee-free on lock and deduct the whole attested amount on release (the 10 bps and the relayer fee
come out of the release, not the lock), so each backing's `locked` equals that endpoint's on-chain
custody exactly, modulo messages in flight — the bridge session's `rand-bridge-audit` tool
reconciles `rand_getTokenSupply`'s per-backing `locked` against each endpoint's custody.

**Before every unbridge, Rand checks `amount <= locked`.** `TokenRegistry::check_release`
(called from `BridgeState::check_burn`, in `validate_inner`'s step 7, before either the bundle's
digest or its proof) resolves the named `(to_chain, token)` to a backing of the burned asset
(`TokenError::NotABacking` if it backs nothing, or backs a different token) and refuses
`TokenError::InsufficientBacking { locked, amount }` if the backing does not hold enough — the
token's *total* supply may well cover the release; this one backing's custody is what has to.

**The release-unit rule.** The attestation wire always carries an amount at **8** decimals
(`BRIDGE_DECIMALS` = `WIRE_DECIMALS` = 8, `crates/randprotocol-core/src/ledger/tokens.rs`),
whatever the source coin's own `decimals` is — a deposit of 1 USDT (6 decimals on Ethereum) locks
as `100_000_000` wire units. Releasing an amount that is not a whole multiple of the source coin's
own smallest unit — `Backing::release_unit()`, `10^(8-d)` for `d < 8`, else `1` — would strand a
fraction in custody forever (below one unit, the endpoint reverts with nothing released at all).
So `TokenRegistry::check_release` refuses `TokenError::NotReleasable { amount, unit }` unless both
`amount % unit == 0` **and** `relayer_fee % unit == 0` — the relayer fee is carved out of the
amount in native units on the destination chain, so it is exactly as unreleasable — checked before
the `locked` comparison, byte-cheap. `NotReleasable` is deliberately **not** cached as a permanent
admission verdict: a coin refused today may be listed tomorrow. `wallet::submit_burn` pre-checks
the same rule off one `rand_getTokens`/`rand_getBridgeState` read, before any proving:
*"{coin} on chain {c} has {d} decimals: the amount and the relayer fee must be multiples of
{unit}"*.

## 14. Bridge hardening (v0.5): what it closes

Per-backing `locked` and `InsufficientBacking` guarantee the custody invariant for
**redemption** (§13). They do nothing to bound **minting**: a `BridgeAttest` with a valid guardian
quorum mints whatever it says, and — as of 2026-09-19 — all six mainnet guardian keys live on one
laptop, so a single compromise could mint zUSD with no custody behind it and redeem it against real
custody. `docs/superpowers/specs/2026-09-19-bridge-hardening-design.md` is the full spec; three
independent layers close the gap, none of which changes the deployed source-chain endpoints, the
attestation wire format or `bridge-codec`:

- **B1** (§15) bounds *how much* a compromised quorum can mint per day, and gives an operator a
  fast, unilateral brake.
- **B2** (§16) closes a leader's ability to expire a rotated guardian set's grace window, or a
  mint cap's day, by jumping the block clock.
- **B3** (§17) requires a *second*, post-quantum quorum — Dilithium2 — on every mint, so a
  classical compromise of the guardian committee alone cannot mint.
- **B4** (§18) lets zUSD (and any later bridged token) be listed without a chain cut, under the
  same PQ quorum.

## 15. B1 — a per-backing mint cap, and a mint pause

**The cap.** Genesis `tokens.mint_cap_per_day: u64` (8-decimal units) applies **per backing**, not
per token: chain 14 sets it to `100_000 * 10^8` (100 000 zUSD per backing per day; seven backings
→ at most 700 000 zUSD/day across all of them). A day is `timestamp_ms / 86_400_000` of the
**block timestamp**, which B2 (§16) makes trustworthy; each backing's own `minted_today`/`mint_day`
reset on a newer day (`Backing::minted_on`, read without a write). `TokenRegistry::check_lock`
refuses `TokenError::MintCapExceeded { cap, minted_today, amount }` — checked in `validate`, cheap,
before the guardian signature work — and it is **not** cached as a permanent verdict: a deposit
refused today mints fine tomorrow. Two attestations in one block that together exceed the cap: the
second is refused, and applying is otherwise infallible on it.

**The pause.** Genesis `bridge.pause_key`: one Dilithium2 public key, distinct from every
`pq_guardians` entry. Two bundle-less, fee-less actions, routed through `ledger/bridge_gov.rs`:

- `PauseMints { nonce, signature }` — signed by the pause key alone over `M_pause` (§19). It can
  only pause: `BridgeError::NoPauseKey` if genesis set none, `AlreadyPaused` on a repeat,
  `BadPauseNonce` on the wrong `pause_nonce`, `BadPauseSignature` on a bad signature — the last **is**
  cached as a permanent refusal (it is judged after the nonce, over the transaction's own nonce
  and chain id under the fixed genesis key, so it depends on the bytes alone — a bundle-less,
  fee-less pause should not buy a free Dilithium2 verification per replay).
- `UnpauseMints { nonce, pq_signatures }` — needs a **PQ guardian quorum** (§17's rules), never the
  pause key alone: `NotPaused` if nothing is paused, then the same PQ structural and signature
  checks as a mint's co-signatures.

Both bump one ledger counter, `pause_nonce`, so neither message replays. **While paused, every
transfer `BridgeAttest` is refused `BridgeError::MintsPaused`** (not permanent — admissible the
moment it is lifted). **Burns and guardian-set rotations stay open** — a pause must never trap
redemption or an in-progress rotation. `rand_getBridgeState` serves `mint_paused`, `pause_nonce`
and `pause_key`; `rand_getAssets` rows serve `mint_cap_per_day`, `minted_today` and `mint_day`.
**The pause key must be held on a different machine from the one holding the guardian keys** — the
whole point is a fast brake that survives a guardian-key compromise.

**What the pause does and does not cover.** The pause key can only pause; the PQ guardian quorum
alone can `UnpauseMints`, and that same quorum can `ListBacking` up to `MAX_BACKINGS = 32` coins
onto one bridged token, each with its own fresh `mint_cap_per_day` — so the effective Rand-side
bound after a pause is lifted is up to 32× one backing's daily cap, not the smaller number a
single-backing token's cap might suggest. The pause is fully effective against the threat it was
built for — guardian *daemons* tricked or compromised into co-signing a forged mint while the
humans holding the PQ quorum have not — because the pause key needs no guardian cooperation at
all. It is not a defence against theft of the PQ quorum itself: a party that holds the quorum can
unpause in the same block as the next forged attest, or list new backings and mint against their
caps directly, and — in that threat model — could reach the same coins by draining their
source-chain contracts without ever touching Rand. Treat the pause as a brake on a tricked or
compromised bridge operator, not as a lock the PQ quorum cannot open.

## 16. B2 — a forward bound on block timestamps

A bridged chain's block timestamp decides guardian-set expiry (§3) and, since B1, the mint-cap
day — so a leader who can jump the clock forward can expire a rotated set's 86 400 s grace window
early, or skip past a day's cap. Two rules, both gated on `self.bridge.is_some()` exactly as the
existing rewind rule is:

- **A validity rule, checked on replay too**: `block.header.timestamp_ms <= parent.timestamp_ms +
  MAX_TIMESTAMP_STEP_MS` (`MAX_TIMESTAMP_STEP_MS = 60_000`, `crates/randprotocol-core/src/ledger/mod.rs`),
  else `BlockError::TimestampLeap { parent, block, max_step }`. Together with the existing
  `TimestampRewind` rule (`<` on the way down, §8), a bridged chain's block time can only move
  forward, and by at most a minute a block.
- **A vote rule, never a replay rule**: a validator refuses to vote for a block more than
  `MAX_CLOCK_DRIFT_MS` (`= 15_000`, `crates/randprotocol-core/src/consensus/mod.rs`) ahead of its own
  clock (`HotStuff::on_proposal`). The block stays in the speculative tree — it is valid, and a
  quorum whose clocks agree with it can still certify it — so replaying committed history never
  applies this rule; only the step bound above does.

**Operational consequence: every validator on a bridged chain needs NTP.** A validator whose clock
is more than 15 seconds off real time is a **faulty leader** (its own proposals may drift past
`local_now_ms + MAX_CLOCK_DRIFT_MS` and get no votes) and a **faulty voter** (it may refuse to vote
for an honest, on-time leader's block because its own clock reads far enough behind). Neither
failure halts the chain by itself — the honest majority's clocks still agree — but an
un-synchronised fleet loses liveness margin for nothing. **`genesis.timestamp_ms` must be set close
to the actual launch time**: block 1 is measured against it, and a stale genesis time makes block
time visibly lag behind wall clock until B2's step bound lets it catch up, roughly `MAX_TIMESTAMP_
STEP_MS` per block. A `genesis.timestamp_ms` set **more than 15 s in the future** has the opposite
problem: `MAX_CLOCK_DRIFT_MS` withholds every vote, the leader's own included, until wall time
reaches it, so block 1 simply does not commit until then — set it at or just before launch, never
ahead of it.

**Catch-up and the mint-cap day.** After any halt long enough for the chain clock to fall behind
wall time, B2's step bound lets block time close the gap at up to `MAX_TIMESTAMP_STEP_MS` (60 s)
per block — which, at 3 s blocks, can advance the chain clock by a full UTC day in about 76
minutes of real time. B1's cap keys `minted_today`/`mint_day` on that same block timestamp, so a
mint-cap day can roll over faster than once per real day while a chain is catching up; bounded to
at most one extra day's cap per full day of accumulated lag, and never during ordinary operation
where block time already tracks wall time.

## 17. B3 — a Dilithium2 co-signature on every mint

Full spec: `docs/superpowers/specs/2026-09-19-pq-cosignature-bridge.md` (a verbatim copy of the
bridge repo's `spec/PQ-COSIGNATURE.md`). Every `BridgeAttest` — a deposit and a guardian-set
rotation alike — must carry, beside its ECDSA quorum, a quorum of Dilithium2 signatures by the
**same guardians**, over the **same digest**: `M = b"rand-bridge-pq-cosign-1" ‖ rand_chain_id (u64
BE) ‖ mu` (63 bytes, deterministic signing), where `mu` is the same `keccak256(keccak256(body))`
the ECDSA quorum signs. Naming the Rand chain id in `M` means a testnet co-signature never verifies
on a mainnet Rand chain, even if guardian keys were reused; the guardian-set index is not in `M`,
so a co-signature survives an ECDSA-set rotation without re-signing.

`Action::BridgeAttest` gains a last field, `pq_signatures: Vec<PqSignature { index: u8, signature:
Vec<u8> }>` (inside the transaction binding, so it cannot be stripped or swapped on a copy).
`crate::bridge::pq::check_pq_structure` enforces, in this exact order, cheap before expensive:

1. `quorum(n) <= pq_signatures.len() <= n` (`n = pq_guardians.len()`), else `PqNoQuorum`;
2. indices strictly increasing, else `PqIndexOrder`;
3. every index `< n`, else `PqIndexOutOfRange`;
4. every signature exactly 2 420 bytes, else `PqBadSignatureLength`;
5. every signature verifies `M` under `pq_guardians[index]`, else `PqBadSignature` — checked last,
   in `check_pq_quorum_message`.

The PQ signers need not be the same indices as the ECDSA signers — each quorum is counted on its
own. Genesis `bridge.pq_guardians`, index-aligned with `guardian_sets[0]`, is fixed for the
chain's life: a payload-2 rotation moves the ECDSA set only, never the PQ set (a PQ rotation would
be its own governance message, not specified for v0.5). Only `PqIndexOrder`,
`PqIndexOutOfRange` and `PqBadSignatureLength` are cached as permanent admission verdicts — they
are statements about the list's bytes; `PqNoQuorum` and `PqBadSignature` are not, since a short or
wrong quorum today says nothing about a resubmission with a different one. `rand_getBridgeState`
serves `pq_guardians`; `rand bridge-mint @attestation.hex --pq @pq.json --to <rand1…>` is the CLI
(`docs/cli.md`). Conformance: the bridge repo's `vectors/pq-cosignatures.json` (rand_chain_id 99,
quorum 5 of 6 test guardians).

## 18. B4 — listing a bridged token after genesis

Chain 14's genesis lists **no** bridged token: zUSD is registered by transaction, after the cut, by
a faucet-funded deployer wallet that pays the RAND fee, under a PQ guardian quorum's authorisation
— an ordinary address alone can never create a `Bridge`-authority token. Two new actions
(`ledger/bridge_gov.rs`), each on an ordinary RAND fee bundle and each requiring the same PQ quorum
rules as B3's mints:

- `RegisterBridgedToken { name, symbol, salt, chain, token, decimals, nonce, pq_signatures }` —
  registers a new `Bridge`-authority token at the next index, at 8 decimals on Rand, under the
  genesis `mint_cap_per_day`, with its first backing. Its fee owes the bundle base plus the
  registry's `registration_fee`.
- `ListBacking { token_index, chain, token, decimals, nonce, pq_signatures }` — adds a further
  backing to an already-registered bridged token. Its fee owes the bundle base alone.

Both share one ledger counter, `list_nonce` (a message's nonce must equal it; both bump it on
acceptance), and both run the same checks a genesis listing gets: the named chain has a registered
emitter (`BridgeError::NoEmitter`), `(chain, token)` backs nothing yet (`BackingTaken`), the token
has fewer than `MAX_BACKINGS` (32) backings already, and `decimals <= MAX_BACKING_DECIMALS` (18). A
wrong `list_nonce` is `BadListNonce { expected, got }`. A new backing starts at `locked = 0`.

**The index front-run, and why the operational order matters.** `ListBacking` signs a
`token_index`, and registering a *native* token is permissionless — so if a native token happened
to register at the index a pre-signed `ListBacking` names, the pre-signed message would be
invalidated (a refusal, not a fund-loss risk). The procedure: **the PQ guardians sign the
`RegisterBridgedToken` message first, wait for it to commit, read back the index chain assigned,
and only then sign the six `ListBacking` messages** naming that index — never sign a listing ahead
of the registration it depends on.

**Operational order, and why: list on Rand before `setToken` on the source endpoint.** If a coin
were enabled on the endpoint first, a deposit could lock there before Rand has a backing to credit
it against, and the attestation would be refused `UnlistedToken` — funds safe in the endpoint's
custody, but stuck until Rand is caught up. Listing on Rand first costs nothing (a backing with
`locked = 0` accepts no deposits until the endpoint also enables it), so there is no symmetric
failure the other way.

No codec, wire or endpoint change: this is what replaces the RPL spec's originally deferred
guardian governance payload id 3, kept off the wire because `bridge-codec` is compiled into the
live Solana program and must stay byte-stable through launch and its external audit.

## 19. Governance message layouts

Fixed bytes, never bincode — what an auditor or a hardware signer reproduces by hand, all integers
big-endian, no length prefixes except where a variable-length field needs one
(`crates/randprotocol-core/src/bridge/gov.rs`):

```
M_pause    = b"rand-bridge-pause-1"         ‖ chain_id u64 ‖ nonce u64
M_unpause  = b"rand-bridge-pq-unpause-1"    ‖ chain_id u64 ‖ nonce u64
M_list     = b"rand-bridge-pq-list-1"       ‖ chain_id u64 ‖ nonce u64 ‖ token_index u32 ‖ chain u16 ‖ token [32] ‖ decimals u8
M_register = b"rand-bridge-pq-register-1"   ‖ chain_id u64 ‖ nonce u64 ‖ u8 len ‖ name ‖ u8 len ‖ symbol ‖ salt [32] ‖ chain u16 ‖ token [32] ‖ decimals u8
M_rotate_pq    = b"rand-bridge-pq-rotate-pq-1"    ‖ chain_id u64 ‖ nonce u64 ‖ u32 count ‖ key [1312] … (v0.5.4, §21)
M_rotate_pause = b"rand-bridge-pq-rotate-pause-1" ‖ chain_id u64 ‖ nonce u64 ‖ key [1312]           (v0.5.4, §21)
```

`M_pause`/`M_unpause` carry `pause_nonce`; `M_list`/`M_register` carry `list_nonce`;
`M_rotate_pq`/`M_rotate_pause` carry `rotation_nonce` (§21). Each is what `bridge/gov.rs`'s
`pause_message`/`unpause_message`/`list_message`/`register_message`/`rotate_pq_message`/
`rotate_pause_message` builds and what the corresponding validate function re-derives to check a
signature against — never bincode, so the bytes an operator's hardware signer sees are exactly
what gets verified.

## 20. Chain-14 launch order

Steps 1–5 and round 1 of step 7 are **done**, on mainnet, 2026-09-20. Round 2 of step 7 is **in
progress**; step 6 (the guardian-set rotation) is **on hold by the user's decision**, not merely
pending — the bridge stays on guardian set 0 until the user says otherwise, independent of the
genesis or the cut. Full evidence table: `AGENTS.md`'s v0.5 entry.

1. **Done.** Chain 14 was cut with the fixed `bridge` genesis section (§6 of the handoff,
   `pq_guardians` and `pause_key` added) and a `tokens` section with `registration_fee` (1 RAND) and
   `mint_cap_per_day` (100 000 × 10⁸ per backing per day) set, listing no token. Genesis
   `1cff3b7da248d93ab547aef5c05bb7d0d22da510b592dab9cf7374807de7c7ff`, build `b3c594c`.
2. **Done.** The chain-14 faucet is on; the deployer wallet obtained RAND with no prior balance.
3. **Done.** The deployer registered zUSD (`RegisterBridgedToken`, first backing Ethereum USDT)
   under the PQ guardian quorum's signature over `M_register` at `list_nonce = 0`: transaction
   `7fa28fe6277a82401dcc440ff32da13c5e5763f79826fb17cc508f4c15abdd13`, block 256, index 1, id
   `rpl1xtj6k2x8strx8c2d5fjs50ltztck5ykms4ve7nmzmstf6fhn0v0spelqtx`.
4. **Done.** The guardians read back index 1 and signed the six remaining `ListBacking` messages
   naming it, submitted one at a time as `list_nonce` advanced 1→7; all seven backings are live.
5. **Done**, for all seven backings: listed on Rand (steps 3–4) before `setToken` on each source
   endpoint (§18); the endpoints were enabled with small caps first (100/transfer, 1000/day).
6. **On hold, by the user's decision (2026-09-20).** The guardian-set rotation (set 0 → set 1,
   payload 2, signed 5-of-6 by the *current* set) on the four source endpoints, then the same
   attestation submitted to Rand, whose genesis starts at set 0 (§3), is deliberately not run: the
   bridge stays on guardian set 0 until the user says otherwise. The set-1 ECDSA and PQ keys are
   already generated (`~/.rand-bridge/mainnet-guardian-set1/`, `~/.rand-bridge/mainnet-pq-set1/`)
   but unused; `bridge.pq_guardians` in the genesis is index-aligned with set 1 while every mint so
   far verifies under set 0's ECDSA signatures (Open Questions §1 of the cut runbook). bridge-06
   starts the rotation only on a go the user types in its own session.
7. **Round 1 done** (2026-09-20, 1 USDT/coin per source chain): bridge in, mint zUSD, transfer
   between two wallets, burn back, release. `rand-bridge-audit` on mainnet: custody 0 everywhere,
   fees accrued in-contract at exactly 10 bps per release, admin-only `withdrawFees`, Rand supply 0
   == Σ locked 0. **Round 2 confirmed by the user and in progress** (2026-09-20): 9 USDT per chain
   (36 total), mints only, left locked — expected end state 36.00000000 zUSD against 36 USDT in
   custody, no round-2 burns. Locks (endpoint sequence 1): ETH
   https://etherscan.io/tx/0xf9bb33bdc89fec2ee82b4dd02226ec9d0b63d27ae50fb341af6e8b95ec937d0a, BSC
   https://bscscan.com/tx/0xc329ea06440bf4a84383da39b9c67e2484ac96e168558b1a86905242c165c1ff, TRX
   https://tronscan.org/#/transaction/b0fc155a2264b9dbf5b7cbeac899ae918b3a976aa7af21e003f37435eb9f3269,
   SOL
   https://solscan.io/tx/2iAUL44wjhE7pcYeznAwGix5RMb28eTgXVwSRy7qixGASUcwqXx7EhVsrZATyNAjzAKXw2sRNXhQiaLF6ps6w6K3
   — **all four mints committed** (`BridgeAttest`, 9.00000000 zUSD each; relayer order BSC, SOL, TRX, ETH): BSC block 4686 `f74d8ba08c1621337e58b57fe94bba93f893fec674e37c199553728cde5e8376`, SOL block 4798 `1c7cc5b4dcf50639ad7fd041f6064793287091709f320945d558f4db6c55b6e3`, TRX block 4907 `c2a26eec92756946241b5e6c59c46a3a6645e5c92472f3e221e06d9d9fc74aaa`, ETH block 5432 `329cce2a1818a3cc3f4b60b5e2f13c52bb077fce7ffb34c5a6317b01db095fcd`. End state, audited on mainnet by `rand-bridge-audit`: `total_supply` 3600000000 == Σ `locked` (900000000 on each of chains 2/3/4/5 USDT), custody − locked = 0.

## 21. Rules v2 (v0.5.4, audit v4 BRG-14 / BR-4)

Everything in this section is switched on by one optional group inside the genesis `bridge`
section and is **absent from chain 14**: without it a node behaves byte-for-byte as before — the
genesis hash, the bridge root (`rand-bridge-state-4`), the token root (`rand-token-registry-2`),
the storage blobs and every admission verdict are unchanged. Chain 15's genesis carries it:

```json
"bridge": { …, "rules_v2": { "global_mint_cap_per_window": 50000000000000, "cap_window_secs": 86400 } }
```

`cap_window_secs` must be in `3600..=604800` (an hour to a week); `global_mint_cap_per_window` is in
eight-decimal token units, a plain number like `tokens.mint_cap_per_day`, and must be above zero.
The group is committed to the genesis hash as `b"bridge_rules_v2" ‖ global_mint_cap_per_window
u64 BE ‖ cap_window_secs u32 BE`, appended right after the `BridgeCommit` bytes and only when the
group is present (`crates/randprotocol-core/src/genesis.rs`). What it turns on:

### 21.1 Two rotations under the PQ quorum

`Action::RotatePqGuardians { new_pq_guardians, nonce, pq_signatures }` (wire variant 22) replaces
the whole PQ guardian set; `Action::RotatePauseKey { new_pause_key, nonce, pq_signatures }`
(variant 23) replaces the pause key. Both are bundle-less and fee-less like `PauseMints`, both are
governance in the pool (exempt from `MempoolFull`, ordered first, one pooled per nonce), and both
carry the bridge's new **`rotation_nonce`** (`rand_getBridgeState.rotation_nonce`), which each
accepted rotation bumps — so a quorum signed for one nonce authorises exactly one rotation of
either kind. The quorum is the co-signature's five rules (§17) by the **current** PQ set over one
of these two messages, all integers big-endian, no terminators, never bincode:

```
M_rotate_pq    = b"rand-bridge-pq-rotate-pq-1"    ‖ chain_id u64 ‖ rotation_nonce u64 ‖ count u32 ‖ key₀ [1312] ‖ key₁ [1312] ‖ …
                 26 bytes                            8              8                    4            1312 each, in index order
M_rotate_pause = b"rand-bridge-pq-rotate-pause-1" ‖ chain_id u64 ‖ rotation_nonce u64 ‖ key [1312]
                 29 bytes                            8              8                    1312
```

- `chain_id` is this Rand chain's id (14 on chain 14, whatever the next cut names); a rotation
  signed for another chain never verifies.
- `count` is the **number of keys**, not a byte length; every key is a Dilithium2 public key's
  raw 1 312 bytes (`PublicKey::as_bytes`, the same bytes `rand_getBridgeState.pq_guardians` shows
  in hex), concatenated in the order the new set will have — index `i` of the new set is the PQ
  key of the operator of guardian `i` of the current ECDSA set.
- `M_rotate_pq` is `46 + 1312 × count` bytes long; `M_rotate_pause` is `45 + 1312 = 1357` bytes.
  `rand-bridge-gov pq-rotate-pq` / `pq-rotate-pause` (bridge repo) build exactly these from the
  chain id, the nonce read off `rand_getBridgeState` and the key file(s); the node rebuilds them
  in `bridge/gov.rs`'s `rotate_pq_message`/`rotate_pause_message` and verifies with the same
  `verify_pq_message` every other governance quorum goes through.

Admission order for `RotatePqGuardians`, cheapest first: the `bridge` gate (`Disabled`), the
`rules_v2` gate (`RulesV2Disabled` — a genesis constant, cached as permanent), the quorum's
structure (rules 1–3), the nonce (`BadRotationNonce { expected, got }`), then the new set's shape
— exactly the genesis rules: its length equals the **current ECDSA set's** (`PqSetLengthMismatch`),
every key is exactly 1 312 bytes (`BadPqGuardianKey { index, len }`, permanent), no key repeats
(`DuplicatePqGuardian`, permanent), and none is the pause key (`GuardianIsPauseKey`) — and the
Dilithium2 verifications last. Apply replaces `pq_guardians` whole and bumps `rotation_nonce`;
the superseded set signs nothing further (its quorum over the next nonce fails at the signature).
`RotatePauseKey`: the same gates, structure and nonce, then the key's length
(`BadPauseKeyLength { len }`, permanent) and that it is no PQ guardian's (`PauseKeyIsGuardian`),
then the quorum. Apply replaces `pause_key` and bumps the nonce; the old pause key's `M_pause`
signature no longer pauses. There is no grace window on either: the rotation is what a compromise
response needs to be immediate.

`tx_json` renders them as `rotate_pq_guardians` (`new_pq_guardians` hex, `nonce`, `pq_signers`)
and `rotate_pause_key` (`new_pause_key` hex, `nonce`, `pq_signers`) — `docs/rpc.md`.

### 21.2 Rolling-window mint caps

B1's per-backing cap (`tokens.mint_cap_per_day`) is measured over a **rolling window of
`cap_window_secs`** of the block timestamp instead of the UTC calendar day, and a second,
registry-wide cap — `global_mint_cap_per_window` over every backing of every token together — is
judged after it (`TokenError::GlobalMintCapExceeded { cap, minted, amount }`). Under the day
rule, the cap at 23:59:59 and the cap again at 00:00:01 was 2× the cap in two seconds; under the
window the second is refused and admitted again exactly `cap_window_secs` after the first.

The accounting (`ledger/tokens.rs`'s `MintWindow`): a window is a ring of slots of
`⌈cap_window_secs / 24⌉` seconds (an hour for a day's window, seven hours for a week's), keyed by
`block_secs / slot_secs`; a deposit adds to its slot; **a slot counts while its last second is
less than `cap_window_secs` before the block time** (strictly), so the count is never below the
exact rolling sum — it is counted too strictly by up to one slot, never twice — and a deposit
made in the last second of its slot leaves the window exactly `cap_window_secs` later. Slots that
have left the window are dropped on the next deposit, so a window holds at most 26 slots. There
is one window per backing (keyed by token index, chain and token address) and one global window;
all of them are consensus state, folded into the token root, which becomes
`rand-token-registry-3 ‖ … ‖ bincode(RegistryExt)`. The day counters (`minted_today`,
`mint_day`) keep moving under rules v2 and `rand_getAssets` keeps showing them, but nothing reads
them for admission any more. The refusal shape is unchanged — `MintCapExceeded { cap,
minted_today, amount }`, where `minted_today` now reads the window's count.

### 21.3 No listing while paused

`RegisterBridgedToken` and `ListBacking` are refused `MintsPaused` while `mint_paused` — judged
after the `list_nonce`, before the quorum — under rules v2 only: chain 14's ledger keeps accepting
what it accepts today. Burns and both rotations stay open while paused, as before.

### 21.4 State, storage, RPC

`BridgeState` gains `rotation_nonce` and `rules_v2`; with the group present the bridge root is
`rand-bridge-state-5` over the v4 bytes followed by `bincode(rotation_nonce, rules_v2)`. Storage
keeps the v1 `BridgeMeta` blob exactly as it was under `bridge_state` and writes the v2 half
(`BridgeMetaV2 { rotation_nonce, rules }`) under a second key, `bridge_state_v2`, only on a chain
that has the group; the registry's v2 half (`RegistryExt`: TOK-1's `max_tokens` and the windows)
likewise rides `tokens_v2` beside the unchanged `tokens` blob. A chain-14 database therefore never
gains a key and keeps its strict v1 decode; a v0.5.4 node rolls onto chain 14 like any node-only
build. `rand_getBridgeState` gains `rotation_nonce` (0 on chain 14) and `rules_v2`
(`{ "global_mint_cap_per_window": "<decimal string>", "cap_window_secs": 86400 }`, or `null`).

## 22. Genesis custody — a chain cut from another one's bridge state (chain 15)

A chain cut from a running bridged chain inherits custody the source contracts still hold: coins
locked on the far side against notes somebody on the old chain still owns. Chain 15 is cut from
chain 14 with ten zUSD in a third party's wallet, backed by 9 USDT on Tron and 1 USDT on Solana.
Genesis can now start a listed token holding exactly that, so `custody − locked = 0` and
`total_supply == Σ backings.locked` from block 0:

- **`tokens.tokens[].backings[].locked`** (optional, eight-decimal token units, a plain number
  like `mint_cap_per_day`): what the backing starts with. `Genesis::build` applies it through
  `TokenRegistry::lock` itself at the genesis block's time — the one writer that moves `locked`
  and `total_supply` together — so a genesis lock is judged like a deposit in the chain's first
  second (the note bound, the per-backing daily cap, the rules-v2 windows) and counts toward that
  first day's cap. Absent, nothing changes; it is bound to the genesis hash through the state
  root (a backing's `locked` is in its token's leaf).
- **`alloc[].opening.asset`** (optional, default 0 = RAND and then absent from the file): the
  registry index of a token the same genesis lists (the first listed token is 1). The commitment
  is recomputed at that index with `from` the zero word — the deposit commitment a `BridgeAttest`
  would append — and the note never counts toward the RAND supply (`genesis_deposited`).
- **The rule** (`Genesis::validate`): per listed token, Σ its notes == Σ its backings' `locked`
  (`TokenSupplyMismatch`); a note naming an index no listed token holds is `BadNoteAsset`.

`rand-node alloc-note --to <rand1…> --amount <whole units, e.g. 10> --asset <index>` prints one such `alloc`
entry — `--amount` scaled by the asset's decimals (nine for RAND, eight for a bridged token: `10`
at asset 1 is 10 zUSD, 10^9 units) — sealed to the owner's KEM key like a `genesis --alloc` note, so the owner's wallet finds it
on its first scan. The token keeps its id across the cut when it is listed with the old chain's
name, symbol and salt (zUSD: `"Shielded USD"`, `"zUSD"`, salt `27e77272…1d60` → `32e5ab28…7b1f`).

The `bridge` section carries the rest of the old chain's bridge position, each field optional and
committed to the genesis hash under its own tag only when present (`b"bridge_guardian_set_index"`
‖ u32 BE, then `b"bridge_burn_sequence"` ‖ u64 BE, after the rules-v2 bytes), and in the bridge
root either way:

- **`guardian_set_index`**: the index the listed `guardians` start as. The genesis bridge holds
  that one set as `current_set` — an attestation under any other index is `UnknownGuardianSet`,
  and the next rotation must carry `index + 1` (`BadUpgradeIndex` otherwise). `u32::MAX` is
  refused. Chain 15 starts at 1, where the source endpoints already are.
- **`burn_sequence`**: the sequence the first outbound burn carries. Chain 14's burns ended at 6,
  so chain 15 starts at 7 and no endpoint or daemon keyed by sequence sees one twice.

`rand_getBridgeState` serves both as it always has (`guardian_set_index`, `burn_sequence`);
`rand_getTokens`/`rand_getAssets` serve the genesis `locked` and `total_supply`, and
`rand_getSupply`'s `genesis_deposited` stays RAND-only.
