# Short addresses: dual-format text and a self-certifying receiver registry (S3)

- **Status:** draft for review. Not approved. Nothing in it is implemented.
- **Baseline:** fullnode `main` at `a941774` (v0.4, chain 13), rebased to `cba5fef`. File
  references name the function; line numbers are left out because they move.
- **Implementation:** branch `feat/harm-addresses`; §20 records where the code differs from this
  text.
- **Source:** *The S3 address scheme (slimmed HARM), design specification draft 0.1* (Anish
  Mohammed, Dendi Suhubdy, 18 September 2026), written against chain 12 (`c0ffc74`), and the
  *HARM evaluation* it implements. This document restates that design against the current tree
  and folds in the corrections found when it was checked against the code (§17).
- **Supersedes:** the reverted chain-11 design, `2026-09-17-short-shielded-address.md`.
- **Forks:** Phase A is a software release. Phase B is a hard fork at one planned chain cut.
  Phase B+ is a software release. Phase C is reserved.
- **Open decision:** OQ-6 (§16) — S3 as written, or S5 (S3 plus an inline X25519 key). This
  document specifies S3; S5 is a reserved type value that adds to it without changing it.

MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are as in RFC 2119. `||` is concatenation. Integers
in hashes are big-endian unless stated.

## 1. Summary

A wallet has one pair of public values, `pk` (32 bytes) and `kem_ek` (the 1,184-byte ML-KEM-768
encapsulation key), exactly as today (`ShieldedAddress`, `crates/randprotocol-core/src/notes.rs`).
This design gives that pair two text forms and one on-chain registry:

- **Direct address** (`rnd1q…`, 1,963 characters): encodes the pair itself. Anyone holding it
  pays it with no lookup, no registration and no interaction. It is today's address with a
  checksum, a network tag and a type field.
- **Short address** (`rnd1s…`, 63 characters): encodes a 32-byte receiver id, the BLAKE3 hash of
  the pair. It is payable once the pair is published in the receiver registry.
- **Receiver registry**: an append-only set of `(pk, kem_ek)` records in chain state. The id is a
  hash of the record, so a record proves itself. Nobody can register a false record for an id,
  anybody may register any record, and a sender checks what it resolved by hashing it. No
  signatures, no relayers, no expiry, no trust in the resolver.
- **Resolution is private by construction.** A wallet that already streams the chain streams the
  registry with it and resolves locally. A thin wallet downloads a bucket of at least 256 records.
  A wallet never asks a remote endpoint for one id.

Today's address, for comparison: `rand1` + base58(`pk || kem_ek`), 1,216 bytes, about 1,666
characters, with no checksum, no version and no network tag.

## 2. Requirements

These are the properties the long address has always had, plus the reasons chain 11 was
reverted, stated as requirements. Every later section traces to one of them.

| ID | Requirement | Met by |
|----|-------------|--------|
| R1 | A sender holding a wallet's address string can always pay it with no lookup and no prior action by the recipient | The direct form (§4.3). The short form is an addition, never a replacement |
| R2 | No server, registry or relay learns which recipient a sender is about to pay | Streaming and bucket resolution (§9); the prohibition W-7 |
| R3 | Nothing about the payee reaches the chain at payment time | Payments are unchanged; registration is a separate transaction (W-11, W-12) |
| R4 | An empty wallet can obtain a working address | The direct form needs nothing; registration is paid later by the wallet or by anyone (§8) |
| R5 | A resolver that lies is detected by the wallet | Self-certifying id and the MUST-verify rule W-5 |
| R6 | Block validity depends only on the block, the parent state, and data the parent state root commits to | Registry root in the ledger; store-supplied proofs verified against it (§6.4). The AGG-4 lesson |
| R7 | The proposer and every replica compute the post-state through the same code | One apply function (C-9). The AGG-5 lesson |
| R8 | A mistyped or wrong-network address is rejected before funds move | Bech32m, the inner check, network-specific prefix (§4) |
| R9 | Post-quantum confidentiality of note plaintexts from the first payment | ML-KEM-768 stays the only encapsulation; no classical fallback (but see OQ-6) |

### Non-goals

- Key rotation without a change of address. A new ML-KEM key is a new address, as today (§15.1).
- Diversified or per-payer addresses (needs a note-relation change and a new constraint set).
- A classical X25519 fallback (violates R9; reserved as type S5, OQ-6).
- Private information retrieval. Its hooks are reserved (§14); nothing is built.
- Changing how validators, aggregators or the bridge name a payout. They keep carrying a full
  `ShieldedAddress`.
- Human-readable names.

## 3. Terminology

| Term | Meaning |
|------|---------|
| Record | The 1,216 bytes `pk || kem_ek`. `pk` is eight u32 words, little-endian, four canonical Goldilocks elements |
| Receiver id (`id`) | `BLAKE3("rand-shielded-recipient" || pk || kem_ek)`, 32 bytes. Byte-identical to `ShieldedAddress::recipient_hash` (`notes.rs`, via `Hash::digest_domain`, `crypto.rs`) |
| Direct address | The type-`q` text form carrying the record |
| Short address | The type-`s` text form carrying the id |
| Legacy address | Today's `rand1` + base58(`pk || kem_ek`) |
| Registry | The set of registered records, committed to by `receivers_root` |
| `seq` | Zero-based position of a record in registration order |
| Full-sync / thin wallet | A wallet that streams every registration, or one that does not |
| Bucket | All records whose id begins with a given bit prefix |
| Pending set | The ids registered by uncommitted blocks on one branch of the consensus tree (§6.5) |

## 4. Address text formats

### 4.1 Common structure

Both forms are Bech32m strings (BIP-350, constant `0x2bc830a3`) with the BIP-173 90-character
limit removed, as ZIP-316 does. The data part is one type character, then the payload converted
from 8-bit to 5-bit groups with zero padding, then the six-character checksum.

```
address = hrp "1" type payload32 checksum6
hrp     = "rnd" (main network) / "trnd" (test networks) / "drnd" (local development)
type    = "q" (value 0, direct) / "s" (value 16, short); all other values reserved
          (S5, if adopted, takes a new value — OQ-6)
```

- **F-1** An encoder MUST emit lower case. A decoder MUST accept all-lower or all-upper and MUST
  reject mixed case. Wallets SHOULD render QR codes from the upper-case form (QR alphanumeric
  mode, 5.5 bits per character).
- **F-2** A decoder MUST reject an address whose hrp is not the one configured for its network,
  with an error naming both networks.
- **F-3** A decoder MUST reject a reserved type value, non-zero padding bits, and a payload whose
  length is not exactly the one defined for its type.
- **F-4** A decoder MUST check the input length before any decoding: at most 2,000 characters,
  matching `MAX_ADDRESS_CHARS` (`crates/randprotocol-node/src/rpc.rs`).
- **F-4a** The direct form is longer than Bech32m's 1,023-character code length. The
  implementation MUST use a checksum definition that accepts it (a custom checksum type with a
  2,000-character bound, as ZIP-316 implementations do). Whether the `bech32` crate's stock
  `Bech32m` type enforces the 1,023 bound MUST be confirmed at implementation time; the tests of
  §18 include a full-length direct address round trip, so a decoder that refuses it fails CI.

The hrp names a network class, not a chain id: test chains are re-cut often, and what matters is
that a test-network string cannot be paid on the main network. The prefix is deliberately not
`rand`: legacy addresses start `rand1`, and `q` and `s` are valid base58 characters, so a shared
prefix would make the two forms ambiguous (OQ-1).

### 4.2 Short address (type `s`)

```
payload = id                              ; 32 bytes -> 52 characters
length  = len(hrp) + 1 + 1 + 52 + 6       ; 63 for rnd, 64 for trnd
```

At 63 characters the string is under the 89-character bound up to which Bech32's BCH code
guarantees detection of any error affecting at most four characters. (The draft attributed that
guarantee to the 1,023-character design length; past 89 characters the guaranteed distance is
lower. The conclusion for the short form is unchanged.)

### 4.3 Direct address (type `q`)

```
check4  = BLAKE3("rand-addr-check-1" || hrp || 0x00 || pk || kem_ek)[0..4]
payload = pk || kem_ek || check4          ; 1,220 bytes -> 1,952 characters
length  = len(hrp) + 1 + 1 + 1952 + 6     ; 1,963 for rnd, 1,964 for trnd
```

- **F-5** A decoder MUST verify `check4` after the Bech32m checksum and reject on mismatch.
- **F-6** A decoder MUST reject a non-canonical `pk`: each of the four 64-bit limbs (low word,
  high word) MUST be less than the Goldilocks modulus 2^64 − 2^32 + 1.
- **F-7** Before first use for encapsulation, a wallet MUST apply the FIPS 203 encapsulation-key
  check (type and modulus check, FIPS 203 §7.2). The ledger does not (C-4).

At 1,963 characters the direct form is past the length where Bech32m gives guarantees; the
random-error miss rate is about 2^-30. The inner 32-bit check is independent of the BCH code and
costs seven characters. It binds hrp and type, so a string re-encoded under another network's
prefix fails even with a recomputed outer checksum. The direct form is 17% longer than the legacy
form as text (5 bits per character against 5.86) and smaller as a QR code (about 1.35 KB
alphanumeric against 1.67 KB byte mode).

### 4.4 Legacy addresses

- **F-8** From Phase A every parser (node RPC, CLI, wallets, explorer) MUST accept both the
  legacy form and the direct form, trying Bech32m first. A string containing both an upper- and
  a lower-case letter, or any of `1 b i o` after the separator, cannot be Bech32m and is parsed as
  legacy.
- **F-9** From Phase A no component emits the legacy form except behind an explicit `--legacy`
  flag. Legacy parsing SHOULD be removed two chain cuts after Phase B.

### 4.5 Worked vector (encoding only)

`pk` is the eight words 1..8; `kem_ek` is the 1,184 bytes `i mod 251` (not a valid ML-KEM key —
the vector pins encoding and hashes only). Computed by the draft's authors with BLAKE3 1.8 and a
BIP-350 encoder; the Rust implementation MUST reproduce them before they are relied on.

| Value | Hex or text |
|-------|-------------|
| `pk` | `0100000002000000030000000400000005000000060000000700000008000000` |
| `id` | `2c3bb9f942d0d66b095dd7491db1153de6d8f08dc411c89def38717863ecf0d4` |
| short, `rnd` (63) | `rnd1s9samn72z6rtxkz2a6ay3mvg48hnd3uydcsgu38008pchsclv7r2qhkzy0z` |
| short, `trnd` (64) | `trnd1s9samn72z6rtxkz2a6ay3mvg48hnd3uydcsgu38008pchsclv7r2quex6sh` |
| `check4`, `rnd` / `trnd` | `a153ea56` / `0e07e80e` |
| direct, `rnd` (1,963) | `rnd1qqyqqqqqzqqqqqqcqqqqqgqqqqqzsqqqqqcq…9d46hmpvdjkws486jkspq06c` |
| registry leaf at `seq` 0 | `9a28860060f9a80b9c0b72e50a084e8c894184b4c89f134a17a81e63dd333cf2` |

## 5. The receiver id

```
id = BLAKE3( "rand-shielded-recipient" || pk_bytes || kem_ek )
```

The existing `Hash::digest_domain` construction and domain string, so a wallet's id is the 32
bytes its bridge deposits already name (`BridgeAttest`'s `to` field, checked at
`ledger/bridge_notes.rs`). One identifier serves the short address, the registry key and the
bridge recipient.

| Property | Strength | Why it is enough |
|----------|----------|------------------|
| Second preimage | 2^256 classical, ~2^128 Grover | What an attacker needs to make a victim's short address resolve to the attacker's keys. The scheme rests on this |
| Multi-target second preimage | 2^256 / N | At N = 2^30 still 2^226 |
| Collision | 2^128 classical, ~2^85 quantum (BHT) | Lets a party make two of its own records with one id. Harms nobody: an id registers once (C-5), and the colliding party owns either record |

## 6. The registry

### 6.1 Data model

```
ReceiverRecord { pk: Word8, kem_ek: [u8; 1184] }    ; no signature, no version, no expiry
registry : id -> (seq: u64, height: u64, record)     ; append-only, never updated or removed
```

### 6.2 Commitment

A sparse Merkle tree of depth 256 keyed by the bits of `id`, most significant first.

```
leaf(id, seq)  = BLAKE3( "rand-receiver-leaf-2" || id || seq_be8 )
empty[0]       = 32 zero bytes
empty[h]       = node(empty[h-1], empty[h-1])
node(l, r)     = BLAKE3( "rand-receiver-node-1" || l || r )
receivers_root = the root at height 256
```

A non-membership proof for `id` is the sibling list from the root to the empty leaf at `id`, with
siblings equal to `empty[h]` elided and marked in a 256-bit bitmap. At a million records a proof
carries about twenty 32-byte siblings. The tree is written in `randprotocol-core` (about 300
lines, BLAKE3 only) so the consensus-critical layout is pinned in this repository (OQ-7).

### 6.3 What lives where

| Location | Holds | Size |
|----------|-------|------|
| `Ledger` (cloned per candidate block, `hotstuff.rs`) | `receivers_root: Hash`, `receivers_count: u64`, and the branch's pending set (§6.5) | 40 bytes plus 32 bytes per uncommitted registration |
| Node store (RocksDB, never cloned) | `receivers: id -> (seq, height, pk, kem_ek)`; `receivers_by_seq: seq -> id`; `receivers_smt`: tree nodes | ~1.3 KB per record plus tree nodes |
| State root | `receivers_root` as an appended component (§6.6) | — |

Chain 11 kept the registry as a `BTreeMap` inside the `Ledger`, which HotStuff clones per
candidate block, up to 512 deep: at 100,000 records that is 116 MiB per clone. The registry MUST
NOT repeat that pattern.

### 6.4 The proof source and why the store is not trusted

The ledger stays pure. It obtains proofs through a callback in the pattern of `CoveredSource`
(`hotstuff.rs`):

```rust
pub trait ReceiverSource: Send + Sync {
    /// A non-membership proof for `id` against `root`, given the ids registered on this branch
    /// since the last commit (in order), or None if the store cannot produce one.
    fn non_membership(&self, root: &Hash, pending: &[(Hash, u64)], id: &Hash) -> Option<SmtProof>;
}
```

The difference from `CoveredSource` is the point of R6. `CoveredSource` answers are trusted — no
root is checked (the AGG-4 lesson). Here the ledger verifies every proof against the
`receivers_root` it holds and computes the new root from the proof alone. A torn, stale or
malicious store cannot make the ledger accept or reject a registration wrongly; it can only fail
to produce a valid proof, in which case that node refuses the block and recovers by resyncing.

- **C-1** For a block with k `RegisterReceiver` actions, the node MUST supply k proofs, the i-th
  valid against the root after applying the first i−1. The store computes them on an in-memory
  overlay; nothing is written until the block commits.
- **C-2** A block's store writes (records, index, tree nodes) MUST be in the same atomic RocksDB
  batch as the block itself.

### 6.5 Uncommitted ancestors (the pending set)

*Not in draft 0.1; added after checking it against `hotstuff.rs`.*

`HotStuff::on_proposal` applies every block to its parent's `ledger_after` (`hotstuff.rs`),
and a block commits only after three consecutive-view QCs, so two or three uncommitted ancestors
are normally in flight. The store holds committed state only. If block N registers an id and
block N+1 registers another, N+1's proof must be valid against the root after N — a root the
store has never written. Without this section, any two registrations in consecutive blocks would
leave every node unable to produce the proof, and the chain would stall.

- **C-13** The `Ledger` carries `receivers_pending: Vec<(Hash, u64)>` — the `(id, seq)` pairs
  registered by blocks on this branch that are not yet committed, in order. It is cloned with the
  ledger (32 + 8 bytes per entry; bounded by `max_per_block × max_tree_blocks`, in practice by
  the three-block commit depth).
- **C-14** Applying a registration appends to `receivers_pending`. Committing a block removes its
  entries from the front, in the same step that writes them to the store (C-2). The committed
  ledger's pending set is empty after `load_ledger`.
- **C-15** `ReceiverSource::non_membership` answers against *committed tree + `pending`*: it
  builds the overlay by inserting the pending leaves over the committed tree, then produces the
  proof against the resulting root. The ledger passes its own `receivers_pending`; it still
  verifies the proof against its own `receivers_root` (R6), so a store that builds the overlay
  wrong produces a proof that fails, never a wrong acceptance.
- **C-16** A candidate id that is in `pending` is `ReceiverExists` without asking the store.
- **C-17** Every replica construction MUST register the receiver source: startup, `HotStuff::
  resume` (`hotstuff.rs`), `resume_consensus` (`node.rs`) and `apply_synced`
  (`node.rs`). This is the trap `CoveredSource` fell into (a synced node failed every
  aggregate block because `resume` built a replica without it); a replica with no source MUST
  refuse a registration-carrying block with a named error, not panic.
- **C-18** `receivers_pending` does not enter the state root. It is derivable from the blocks
  above the last commit, which every replica holding the branch has.

### 6.6 State root

Today the state root is BLAKE3 under `rand-state-2` over four components with the bridge root
appended when present, and under `rand-state-3` with the aggregators root appended when that
section is present (`ledger/mod.rs`). Presence is inferred from length, which does not
extend to a third optional component. From Phase B:

```
state_root = BLAKE3( "rand-state-5" || flags || tree_root || nullifier_root || validators_root
                     || programs_root [ || bridge_root ] [ || aggregators_root ] [ || receivers_root ] )
flags      = one byte: bit 0 bridge, bit 1 aggregation, bit 2 receivers
```

- **C-3** A chain whose genesis has no receivers section MUST compute its state root exactly as
  chain 13 does. `rand-state-4` is not reused: chain 11 gave it a different meaning.

## 7. Consensus rules

### 7.1 The action

```
Action::RegisterReceiver { pk: Word8, kem_ek: Vec<u8> }   ; next free bincode tag
```

It rides a bundle, like `Deploy` and `Bond`; the bundle pays the fee.

### 7.2 Validation, cheap before expensive

In `validate_inner`'s existing order (`ledger/mod.rs`). The same checks run at mempool
admission, at propose and at apply.

| Step | Check | Error |
|------|-------|-------|
| 1 | The receivers section is present in genesis | `ReceiversDisabled` |
| 2 | `kem_ek.len() == 1184`, before anything else touches it | `BadRecordLength` |
| 3 | `pk` is canonical (F-6) | `NonCanonicalPk` |
| 4 | `bundle.fee >= fee_floor` (§7.3) | `FeeBelowFloor` |
| 5 | At most the `max_per_block`-th registration in the block | `BlockError::TooManyRegistrations` |
| 6 | `id` computed; not in `receivers_pending` (C-16); the supplied proof verifies non-membership against `receivers_root` | `ReceiverExists` / `BadReceiverProof` |
| 7 | The bundle proof verifies (the one expensive step, last, as today) | `InvalidBundleProof` |

- **C-4** The ledger MUST NOT validate `kem_ek` beyond its length. `randprotocol-core` has no
  ML-KEM dependency by design; a malformed key harms only an id nobody will hand out. Wallets
  validate on use (F-7).
- **C-5** An id registers at most once. A second registration is invalid as a transaction and
  makes a block containing it invalid.
- **C-6** On success: `receivers_root` becomes the root with `leaf(id, receivers_count)`
  inserted, `receivers_count` increases by one, `(id, seq)` is appended to `receivers_pending`,
  and the fee is credited as any bundle fee is.
- **C-7** Records are never modified or removed. There is no unregister action.
- **C-8** Steps 1–6 are block-validity rules. A block containing a `RegisterReceiver` that fails
  any of them MUST be rejected by every replica. The mempool applies them only as a pre-filter.
- **C-9** `propose` and `apply_block_with_covered` MUST reach the post-state through one
  function, in the manner of `Ledger::close_block` (`ledger/mod.rs`). There MUST NOT be a
  second implementation of any registry step.

C-8 and C-9 are the two defects of the first aggregation release stated as rules: a coverage rule
enforced only in the mempool (AGG-1), and a block-end step present in apply but not in propose
(AGG-5).

### 7.3 Fee

```
fee_floor(RegisterReceiver) = BUNDLE_BASE + register_per_byte × 1216
register_per_byte           = 25,000 units (= DEPLOY_PER_WORD / 4, the existing price of permanent state)
                            = 1,000,000 + 30,400,000 = 31,400,000 units = 0.0314 RAND
```

`BUNDLE_BASE` and `DEPLOY_PER_WORD` are `crates/randprotocol-core/src/gas.rs`. The registry
is permanent state on every validator, so growth must cost something. `register_per_byte` is a
genesis parameter.

### 7.4 Limits

| Parameter | Value | Basis |
|-----------|-------|-------|
| `max_per_block` | 64 (genesis parameter) | Bounds proof work to 64 path verifications per block; 64 records are 78 KB, under 0.4% of chain 13's 20 MiB block |
| Record size | exactly 1,216 bytes | — |
| Proof size bound | 32 + 256 × 32 bytes | Worst case; about 700 bytes at a million records |

### 7.5 Genesis

```
Genesis.receivers: Option<ReceiverConfig>
ReceiverConfig { register_per_byte: u64, max_per_block: u32, records: Vec<ReceiverRecordHex> }
```

- **C-10** Genesis records are inserted in list order with `seq` from 0, under steps 2, 3 and 6.
  A genesis with a duplicate or malformed record is refused at build time.
- **C-11** Every field of the section enters the genesis hash, as the bridge and aggregation
  sections do.
- **C-12** A chain without the section refuses `RegisterReceiver` by name and is otherwise
  byte-for-byte chain 13.
- **C-19** `main.rs`'s genesis command MUST set `genesis.receivers`, and `reload_ledger` /
  `load_ledger` MUST restore the gate, `receivers_root` and `receivers_count` on restart (the two
  traps the aggregation section fell into).

### 7.6 Mempool

- **M-1** The mempool claims the id of a pooled registration, so two pending registrations of one
  id do not both pool.
- **M-2** `Mempool::applies` drops a pooled registration once its id is registered.
- **M-3** Admission runs steps 1–5 before requesting a proof and never verifies the bundle proof
  on the consensus loop (the existing admission workers apply).

### 7.7 Sync and replay

- **S-1** A syncing node rebuilds the registry from the blocks it applies. No registry data moves
  out of band.
- **S-2** The record is part of the action and is never pruned. Sealed-form sync is unaffected: a
  pruned transaction still carries its action, and its hash binds it (`rand-txid-2`).
- **S-3** `verify_chain` recomputes `receivers_root` and `receivers_count` by replay and reports
  any stored value that disagrees, as it does for the supply counters.

## 8. Registration

A record proves itself, so registration needs no consent from the recipient and cannot be forged
or squatted.

| Path | Who pays | When |
|------|----------|------|
| Self-registration (default) | The wallet, from its own notes | After it has received something. Until then it hands out its direct address |
| Payer-paid | Anyone holding the direct address | A payer who wants the recipient to have a short address; an exchange or merchant on a customer's behalf |
| Genesis | Nobody | Validator payout wallets and allocation owners, at the operator's choice |

- **W-11** The bundle carrying a `RegisterReceiver` MUST be a self-transfer of the registrant's
  own notes. A wallet MUST NOT place a registration in a transaction that also pays the registered
  recipient. The chain cannot enforce this (outputs are hidden); it is a wallet rule, because such
  a transaction would publish "this transaction pays X" (R3).
- **W-12** A wallet registering itself SHOULD wait a random number of blocks, uniform in 16–256,
  after the receipt that funded it. A payer registering someone else SHOULD do so at a time
  unrelated to any payment to them.
- **W-13** A wallet learns that it is registered by finding its own id in the registration
  stream, not by asking.

A registration publishes that a record exists from a given height and nothing else: the paying
bundle is shielded, so the chain does not learn whose notes paid. The only signal is timing,
which W-12 blurs. There is no relayer network: a wallet announcing its keys to a relayer from its
own network address would disclose more than anything in this scheme.

## 9. Resolution

### 9.1 Wallet rules

- **W-1** A direct address is used as given after F-5 to F-7. No network access.
- **W-2** For a short address the wallet consults, in order: its cache; its local registry (full
  sync); a bucket fetch (thin).
- **W-3** A full-sync wallet obtains registrations from the same cursor it scans with (§10.1)
  and resolves locally.
- **W-4** A thin wallet computes `bits = clamp(floor(log2(receivers_count / K_MIN)), 0, 24)`
  with `K_MIN = 256`, using `rand_getReceiverInfo`'s count, and fetches the bucket named by the
  id's first `bits` bits. `bits` MUST be this function of the count and nothing else, so all thin
  wallets ask for buckets of the same shape.
- **W-5** Whatever the source, the wallet MUST recompute `BLAKE3(domain || pk || kem_ek)` and
  compare it with the id, and MUST apply F-6 and F-7. On mismatch it MUST NOT pay, MUST treat the
  endpoint as hostile for the session, and SHOULD retry another endpoint.
- **W-6** A verified record MAY be cached indefinitely; records are immutable.
- **W-7** A wallet MUST NOT request a single id, or any set smaller than `K_MIN` while the registry
  holds at least `K_MIN` records, from an endpoint not on the loopback interface. This includes
  block explorers and any naming or payment-link service.
- **W-8** A wallet SHOULD resolve a short address when it is entered or scanned, not at the moment
  of sending, so the fetch is not adjacent in time to the payment.
- **W-9** If the id is absent after syncing the registration stream to the head (full sync), or
  absent from its bucket (thin), the wallet MUST report: *"This short address is not registered
  yet. Ask the recipient for their full address (rnd1q...)."*
- **W-10** While `receivers_count < K_MIN` a thin wallet fetches the whole registry.

Bucket resolution is Phase B+. At the Phase B cut only full-sync resolution exists (§16).

### 9.2 What each path discloses

| Path | The endpoint learns | Cost at a million records |
|------|---------------------|---------------------------|
| Direct address | Nothing | None |
| Full sync | That the wallet is syncing, which it already learns from scanning | 1.16 GiB once, then 1.2 KB per new wallet on the network |
| Bucket | That the payee is one of at least 256 (about 1,000 at 12 bits) | About 1.2 MB per new payee, cached forever |
| Exact lookup (prohibited remotely) | The payee | — |

Repeated bucket queries for one payee return the same bucket and disclose nothing new. As the
registry grows, buckets nest, so a later query refines an earlier one only to a set that is itself
at least `K_MIN`. An endpoint that withholds a record causes W-9, a liveness failure the user sees,
never a misdirected payment.

## 10. Node interfaces

### 10.1 Streaming (Phase B)

```
rand_getReceivers [from_seq, limit?]            limit default and cap 512
  -> { "records": [ { "seq", "id", "height", "pk", "kem_ek" } ], "next_seq": u64, "count": u64 }
```

`rand_getCompactBlocks` gains, per registering transaction:
`"receiver": { "seq", "id", "pk", "kem_ek" }`.

### 10.2 Buckets and information (Phase B+)

```
rand_getReceiverInfo []
  -> { "count": u64, "root": hex32, "k_min": 256, "bits": u8 }      ; bits as W-4 computes it
rand_getReceiverBucket [prefix_hex, bits]    0 <= bits <= 24; prefix_hex is ceil(bits/8) bytes,
                                             unused low bits zero
  -> { "bits", "prefix", "records": [ { "seq", "id", "pk", "kem_ek" } ] }
  errors: -32602 if the bucket would exceed MAX_BUCKET_RECORDS = 4096 ("increase bits")
```

- **N-1** The store serves a bucket by a range scan over `receivers` (keyed by id) in a blocking
  task, never on the node loop.
- **N-2** Bucket responses are a pure function of `(prefix, bits, registry state)` and carry no
  caller data; operators SHOULD serve them through a cache or CDN.
- **N-3** The node MUST NOT offer an exact lookup by id unless started with
  `--rpc-receiver-lookup`, and then only on a loopback listener, checked in code. It exists for
  an operator's own wallet and for tests.
- **N-4** All methods are subject to the RPC server's concurrency cap and per-peer budget
  (decision D13). None does work proportional to the registry except a `bits = 0` bucket, which
  `MAX_BUCKET_RECORDS` bounds.

### 10.3 CLI

```
rand address [--direct | --short]      default: short if this wallet is registered, else direct
rand register                          self-registration (W-11, W-12)
rand register --for <rnd1q...>         payer-paid registration, as a separate self-transfer
rand send <rnd1q... | rnd1s...>        resolves per §9
rand receivers sync | info             maintain and inspect the local registry
```

## 11. Wallet behaviour

- **W-14** The receive screen shows the short address when the wallet is registered and the
  direct address otherwise, and always offers the other form with one line on what it is for:
  "Works with every wallet, no setup" (direct), "Short; works once you are registered" (short).
- **W-15** A wallet that is not registered and holds funds SHOULD offer to register, stating the
  fee.
- **W-16** A pasted short address that does not resolve shows the W-9 text and no pay action.
- **W-17** `wallet-core` carries the parser, the id function, the W-5 verification and the W-4
  bits function, so the clients cannot diverge. Its fullnode pin MUST be at or after the Phase B
  tag.
- **W-18** Thin wallets persist resolved records and the last `receivers_count`; full-sync wallets
  persist the registry or an id-to-seq index.

## 12. Interaction with existing components

| Component | Change | Note |
|-----------|--------|------|
| Bridge | None to consensus. `BridgeAttest` keeps carrying the full `ShieldedAddress`, and the ledger keeps checking its hash against the 32-byte `to` | The attested recipient is, by construction, the wallet's receiver id. A relayer *of a registered wallet* can resolve it from the registry instead of being handed the long address; `rand bridge-mint --to` accepts either form |
| Staking, aggregator registers | None. `payout` stays a full `ShieldedAddress` | Chain 11 made payouts depend on the registry (its R3). This design does not |
| Genesis allocations | None | Operators MAY list owners under `receivers.records` |
| Viewing keys | None | A viewing key still determines the address |
| Explorer | MAY list registrations and show count and growth. MUST NOT be used by wallets to resolve (W-7) | A public explorer's search box is an exact lookup by a human; the page SHOULD say so |
| Aggregation, sealed sync | None | S-2 |
| RPL tokens (in flight on `feat/rpl`) | None expected | Token notes are sealed to the same `(pk, kem_ek)`; whichever lands second rebases its address parsing onto §4 |

## 13. Security and privacy

### 13.1 Adversaries

| Adversary | Wants | Outcome |
|-----------|-------|---------|
| RPC operator | To learn who a sender pays | Learns nothing (direct, full sync) or a set of at least 256 (bucket). Still sees the sender's network address and later the submitted transaction, as today |
| Lying resolver | To redirect a payment to its own keys | Needs a BLAKE3 second preimage. Detected by W-5 |
| Withholding resolver | To make a payee unpayable | W-9 on that endpoint only; the direct address and other endpoints are unaffected |
| Chain observer | To link a payment to a payee | Payments are unchanged. Sees that a record was registered at a height; W-11 and W-12 separate that from any payment |
| Registry spammer | To bloat state | Pays 0.0314 RAND per 1.2 KB, at most 64 per block |
| Squatter | To register a victim's id first | Can only register the victim's own record, which helps the victim |
| Byzantine leader | To include an invalid or duplicate registration | Rejected by every replica (C-5, C-8). Can delay a registration, as any transaction |
| Malicious or torn store | To make a node accept a bad block | Cannot: proofs verify against the committed root, and the pending overlay against the ledger's own root (§6.4, C-15) |
| Quantum adversary recording | To open envelopes or redirect payments later | ML-KEM-768 unchanged; id second preimage ~2^128. Bucket queries are unencrypted but reveal only the bucket |
| Clipboard or display malware | To swap an address | Unchanged. Short addresses make visual comparison practical for the first time |

### 13.2 The assumption this design widens

ML-KEM ciphertexts must not reveal the key they were encapsulated to. With a registry, an
observer holds every registered `kem_ek` and every on-chain `kem_ct`, so receiver-unlinkability of
each envelope rests on ML-KEM's anonymity under chosen-ciphertext attack — proved for the Kyber
construction in the QROM (Grubbs, Maram and Paterson, EUROCRYPT 2022; Xagawa, EUROCRYPT 2022).

This assumption is already load-bearing today for some wallets: validator payout `kem_ek`s are
public chain state (the validator leaf, `ledger/mod.rs`). The registry widens it to every
registered wallet. The whitepaper's privacy section SHOULD state it and cite it, and the
implementation MUST keep using the FIPS 203 variant those results cover (implicit rejection).

### 13.3 What is not improved

- A recipient still has one static address. Payers who compare notes off chain learn they paid
  the same party.
- Witness requests still tell the RPC operator which notes a wallet is about to spend (PRIV-1),
  a larger leak than anything this scheme touches.
- The RPC server has no rate limiting (RPC-1, decision D13).

## 14. Reserved for a private-lookup tier (not built)

- **Snapshots:** `receivers_root` and `receivers_count` at each epoch boundary identify an
  immutable prefix of the registration log; a PIR database is built over a snapshot and the rest
  streamed.
- **Keyword layer:** the bucket layout of §10.2 is the natural one (one row per fixed-width bucket).
- **Integrity:** W-5 already covers any private-lookup server.
- **Trigger:** build only when thin wallets are a measured majority and bucket bandwidth is a
  measured problem.

## 15. Rationale and rejected alternatives

### 15.1 No rotation

Rotation needs an identifier that outlives the keys: a signing key, a signature scheme in a
wallet that has none, ~5 KB records (Dilithium2 key and signature, as chain 11 had), a version
rule in consensus, and senders tracking the latest version. It buys replacing a compromised
ML-KEM key without telling payers — but a compromised ML-KEM key exposes past plaintexts anyway,
and the viewing key it derives from is the real secret; losing that needs a new spend key and so
a new address regardless.

### 15.2 Rejected

| Alternative | Why not |
|-------------|---------|
| Signed records (chain 11) | §15.1 |
| Registry inside the `Ledger` | Cloned per candidate block (§6.3) |
| Sorted id set with a recomputed Merkle root | Linear hashing per block and 32 bytes per wallet in every ledger clone |
| Registration proofs carried in the block | ~700 bytes per registration on the wire forever, for store independence §6.4 already gives. (It would not remove §6.5: the proposer still needs the pending overlay to build them) |
| Relayers and a subsidised faucet | New network surface, a link between a wallet's IP and its keys, free state growth |
| Expiring registrations | Breaks printed invoices and published payout addresses; protects nothing with self-certifying ids |
| Inline X25519 key (S5) | Violates R9. Reserved as a type value — OQ-6 |
| PIR now | A million-record registry is 1.16 GiB, less than the note stream wallets already download |
| `hrp = rand` | Ambiguous with the legacy prefix (OQ-1) |

## 16. Rollout and open questions

| Phase | Delivers | Gate |
|-------|----------|------|
| A (release, no fork) | §4 in node RPC, CLI, `wallet-core`, the clients and the explorer; legacy parse retained. The ledger stores addresses as structures and the bridge hash is over raw bytes, so no consensus change | Encoding vectors reproduced by two independent implementations; clients released before the CLI stops emitting legacy |
| B (one planned chain cut) | §§5–8, §9.1 full sync, §10.1, §10.3, §§11–12, with the receivers section in genesis | This spec approved; threat model read by someone who did not write the code; §18 green in CI; wallets and explorer ready at the cut. Chain 11 is the precedent for what happens otherwise |
| B+ (release) | §9.1 thin, §10.2 | Registry above `K_MIN`; D13 decided |
| C (reserved) | §14 | Measurements |

| # | Question | Default in this draft |
|---|----------|-----------------------|
| OQ-1 | `rnd`, or `rand` with disambiguation by character set and length? | `rnd` |
| OQ-2 | Is `check4` worth seven characters? | Keep it: an address error is an unrecoverable loss |
| OQ-3 | Is 0.0314 RAND right for 1.2 KB of permanent state? | Yes on a test network; revisit with a fee market |
| OQ-4 | Register validator payout wallets at genesis? | Operator's choice; no consensus dependence |
| OQ-5 | Explorer search by short address? | Yes, with a plain statement that the explorer then knows what was searched |
| **OQ-6** | **Does "always payable from a short string" outrank R9?** | **No — S3 as written. If the authors decide yes, S5 adds a type value carrying `id || x25519_pk` (~116 characters): senders use the registered ML-KEM key when it resolves and X25519 alone otherwise, so the first payment to an unregistered wallet is classically confidential only. The rest of this spec stands unchanged** |
| OQ-7 | Write the sparse Merkle tree or adopt a crate? | Write it in `randprotocol-core` |
| OQ-8 | Bound on `receivers_pending` beyond the commit depth (C-13)? | None beyond `max_per_block × max_tree_blocks`; revisit if the tree cap changes |

## 17. Changes from draft 0.1

1. **§6.5 added (the pending set, C-13–C-18).** Draft 0.1's C-1 overlay covered earlier
   registrations in the same block only. Blocks apply on uncommitted parents
   (`hotstuff.rs`), and the store holds committed state, so without the pending set any two
   registrations in consecutive blocks stall the chain.
2. **C-17, C-19 added**: register the source on every replica construction, and set and restore
   the genesis gate — the `CoveredSource` and aggregation-section traps, stated as rules.
3. **§4.2**: the four-error guarantee comes from the 89-character bound, not the 1,023-character
   design length.
4. **F-4a added**: the direct form exceeds Bech32m's 1,023 code length; the implementation must
   use a checksum type that accepts it.
5. **§13.2**: the ML-KEM anonymity assumption is already load-bearing for validator payout keys.
6. **Rebased from chain 12 (`c0ffc74`) to chain 13 (`a941774`)**: line references updated; the
   per-block registration bound restated against chain 13's 20 MiB block.
7. **§12**: the in-flight RPL work noted.

## 18. Test plan

| Area | Cases |
|------|-------|
| Encoding | Round trip for both types and all three prefixes; the §4.5 vector; every single-character substitution of a short address rejected; wrong network; mixed case; reserved type; non-zero padding; wrong length; non-canonical `pk`; bad `check4` with a recomputed outer checksum; legacy strings still parse; a full 1,963/1,964-character direct address round-trips (F-4a); a 3,000-character input refused before decoding |
| Identifier | `id` equals `ShieldedAddress::recipient_hash` for random addresses |
| Sparse Merkle tree | Empty root; 1, 2 and 1,000 insertions against a reference implementation; non-membership verifies before insertion and fails after; a proof for one root fails against another; sequential proofs within a block |
| Pending set | Registrations in three consecutive uncommitted blocks all apply on every replica; an id pending on the branch is `ReceiverExists` (C-16); two forks registering different ids each apply against their own pending set; commit drains `pending` into the store atomically; a restart mid-branch resumes with an empty pending set and re-applies the uncommitted blocks |
| Consensus | Each §7.2 error; duplicate in one block and across blocks; the 65th registration; fee one unit below the floor; section absent; genesis with a duplicate |
| Byzantine leader | A proposed block with a duplicate registration, a bad-length record, a non-canonical `pk`, or 65 registrations is rejected by replicas although the leader's mempool would never have pooled it (C-8) |
| Propose equals apply | For random blocks with registrations, the proposer's header root equals the replica's recomputed root (C-9) |
| Source registration | A replica built by `resume` and by `apply_synced` applies a registration-carrying block (C-17); a replica with no source refuses it by name |
| Store faults | A store missing a record, holding a wrong record, returning a stale proof, or building the pending overlay wrong makes the node refuse the block and never accept a wrong one (R6) |
| Sync | A fresh node syncing a chain with registrations, raw and sealed, reaches the same `receivers_root`; `verify_chain` detects a tampered stored root; a restart restores the gate, root and count (C-19) |
| Wallet | A tampered record is refused (W-5); no exact lookup to a non-loopback endpoint (W-7), asserted by a test double that fails on such a call; `bits` per W-4 at counts 0, 255, 256, 1,000,000; the W-9 text; cache survives restart |
| Privacy | A wallet-built registration transaction has every output to self (W-11) |

## 19. Parameters

| Name | Value | Scope |
|------|-------|-------|
| hrp | `rnd` / `trnd` / `drnd` | Wallet and node configuration |
| Type values | `q` = 0 direct, `s` = 16 short | Text format |
| Address check domain | `rand-addr-check-1` | Text format |
| Id domain | `rand-shielded-recipient` (existing) | Consensus |
| Leaf / node domains | `rand-receiver-leaf-2` / `rand-receiver-node-1` | Consensus |
| State root domain | `rand-state-5` with a flags byte | Consensus |
| `register_per_byte` | 25,000 units (`gas::REGISTER_PER_BYTE`; §20 item 3) | Consensus |
| `max_per_block` | 64 (genesis) | Consensus |
| `K_MIN` | 256 | Wallet |
| Maximum `bits` | 24 | Wallet and node |
| `MAX_BUCKET_RECORDS` | 4,096 | Node |
| `rand_getReceivers` page cap | 512 | Node |
| `MAX_ADDRESS_CHARS` | 2,000 (existing) | Node |
| Self-registration delay | uniform in 16–256 blocks | Wallet |

## 20. Implementation notes (`feat/harm-addresses`)

What the code does where this text left room, or where it differs:

1. **The source is asked by count, not by root.** `ReceiverSource::lookup(count, pending, id)`
   answers over *the records with seq below `count`*: the store's committed records cut at
   `count`, plus the `pending` entries at or above what the store holds. So one committed store
   answers for the tip, a speculative block above it, and an old ledger being replayed by
   `verify_chain`, without keeping per-branch state. It returns `Absent(proof)` or
   `Present { seq, proof }`, and the ledger verifies either against its own root — a store that
   falsely claims "present" is a refusal, not a false `ReceiverExists`.
2. **The per-block cap is a transaction-level check** (`TxError::Receiver(TooManyInBlock)`), counted
   on the ledger and reset by `close_block`. Because it lives in `apply_tx`, the proposer's
   trial apply skips the 65th registration and a replica refuses a block carrying one at its
   index — C-8 and C-9 by construction, with no `BlockError` variant.
3. **`register_per_byte` is `gas::REGISTER_PER_BYTE`, not a genesis field**: `gas::fee_floor`
   takes only the action. The genesis section carries `max_per_block` and the records.
4. **Genesis records** are `{ "pk": hex32, "kem_ek": hex1184 }`; `rand-node genesis --receiver
   <address>` takes addresses and turns the section on, as does `--receivers`.
5. **Proofs are recomputed from the index** (`receivers::prove`, O(records × 256) hashes at worst),
   with no stored interior nodes. The proof format does not change when a node store is added.
6. **The network** is `address::Network::current()`: `trnd` unless `RAND_NETWORK=main|dev`.
7. **W-4 at a million records is 11 bits** (`floor(log2(1e6 / 256))`), about 490 records per bucket;
   §9.2's "about 1,000 at 12 bits" is off by one bit.
8. **Not implemented yet:** M-1 (a mempool claim on the id — a second pooled registration of one id
   is refused at propose and apply through the pending set, but stays pooled until the pool drops
   it); `rand_getCompactBlocks`' `receiver` field (full-sync wallets stream `rand_getReceivers`);
   W-12's random delay (the CLI warns instead); `--rpc-receiver-lookup` (no exact lookup exists at
   all, which N-3 allows); the explorer, website and `wallet-core` changes of Phase A, which live
   in other repositories.

## Appendix A. Pseudocode

```rust
fn apply_register_receiver(ledger, pk, kem_ek, source) -> Result<()> {
    let cfg = ledger.receivers_cfg().ok_or(ReceiversDisabled)?;
    if kem_ek.len() != 1184 { return Err(BadRecordLength) }
    if !is_canonical(pk) { return Err(NonCanonicalPk) }
    let id = blake3_domain(b"rand-shielded-recipient", [pk_bytes(pk), kem_ek]);
    if ledger.receivers_pending.iter().any(|(p, _)| *p == id) { return Err(ReceiverExists) }
    let proof = source.non_membership(&ledger.receivers_root, &ledger.receivers_pending, &id)
        .ok_or(BadReceiverProof)?;
    let seq = ledger.receivers_count;
    let root = smt::insert_with_non_membership(&ledger.receivers_root, &id, &leaf(&id, seq), &proof)
        .map_err(|e| match e { Occupied => ReceiverExists, _ => BadReceiverProof })?;
    ledger.receivers_root = root;
    ledger.receivers_count = seq + 1;
    ledger.receivers_pending.push((id, seq));
    Ok(())
}

fn resolve(addr) -> Result<(Pk, KemEk)> {
    match parse(addr, network_hrp)? {
        Direct(pk, ek) => { check_ek(&ek)?; Ok((pk, ek)) }
        Short(id) => {
            let rec = cache.get(&id)
                .or_else(|| local_registry.get(&id))
                .or_else(|| {
                    let n = rpc.receiver_info().count;
                    let bits = clamp(floor_log2(n / 256), 0, 24);
                    rpc.receiver_bucket(prefix(&id, bits), bits).find(&id)
                })
                .ok_or(NotRegistered)?;                                          // W-9
            if blake3_domain(DOMAIN, [rec.pk, rec.ek]) != id { return Err(HostileEndpoint) } // W-5
            check_canonical(&rec.pk)?; check_ek(&rec.ek)?;
            cache.put(id, rec.clone());
            Ok((rec.pk, rec.ek))
        }
    }
}
```
