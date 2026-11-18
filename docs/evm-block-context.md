# Block context for programs: the reference block

Issue #168 (ZKVM-203). Status: **the node side is built and gated off; on no chain.** Chain 21 does
not carry the genesis field, so nothing here changes its genesis hash, wire bytes, storage or
behaviour. The guest side (the EVM opcodes that read these words) is circuits work on constraint
set 10 and waits for the chain-22 cut — see §10.

## 1. The problem

Eleven EVM opcodes read the block a transaction runs in: `TIMESTAMP`, `NUMBER`, `BASEFEE`,
`GASPRICE`, `COINBASE`, `GASLIMIT`, `PREVRANDAO`, `BLOCKHASH`, `SELFBALANCE`, `BLOBHASH`,
`BLOBBASEFEE` (and `CHAINID` / `ORIGIN` in the interpreter). On Rand a call is **proved before it
is included**: the prover does not know which block will carry the transaction, and a private
input word cannot carry a block fact (it is bound only to the salted `H_IN`, which no verifier
opens). So all of them trap today (`docs/translators.md` §6.1), and a contract with a permit
deadline cannot run.

## 2. The decision

**Reference block.** A transaction that wants block context names a recent closed block, height
`h`. Its program sees the chain's facts *for block `h`*. The chain admits it only while `h` is
inside a window of the block that includes it.

- **Gated.** Genesis `program_state.reference_block_window` (a block count). `0` or absent is off.
- **Opt-in per transaction.** Only a transaction of the new form names `h` and gets the words. An
  ordinary `Invoke` is unchanged: context version 1, no reference block.
- **The validator fills the words.** The transaction carries `h` and nothing else. The ledger
  keeps the facts of the last `window` closed blocks and builds the block words itself, so a proof
  made against any other facts fails `verify_invoke`.
- **Staleness.** A program sees a block at most `window` blocks behind the one that includes it:
  in wall time about `window × block time` (256 blocks at ~2 s ≈ 8.5 minutes; 4096 ≈ 2.3 hours).
  After a stall the chain's clock catches up at most 60 s a block (`MAX_TIMESTAMP_STEP_MS`), so
  block time can lag wall time further while it does. A contract must treat `TIMESTAMP` as "a
  recent block's time", not "now": a deadline check passes for up to the window after the
  deadline. That is the price of proving before inclusion.

## 3. The carrier: `Action::InvokeAt`, tag 45

```rust
InvokeAt { program, proof, input_envelope, transition, ref_height: u64 }
```

A new variant appended at the end of `Action` (wire tag 45). Its encoding is an `Invoke`'s fields
followed by `ref_height` (8 bytes, little-endian).

Why a variant and not a field: bincode is positional. A field on `Invoke`, on `Transition` or on
`Transaction` changes every such value's bytes, txid, binding and call binding — a wire change
for chain 21. An appended variant changes no existing encoding: tags 0–44 and everything under
them are byte for byte what they were. `crates/randprotocol-core/tests/invoke_wire_pin.rs` pins
an `Invoke`'s encoding digest, txid, both bindings under both binding domains and its version-1
context words, at values taken on the commit before the variant existed.

`ref_height` is inside both bindings (`Action::blanked` keeps it; `call_binding` leaves out only
the proof), so the call proof and the bundle proof both commit to the block named.

On a chain with the window off an `InvokeAt` is refused `ReferenceBlockDisabled` at validation and
at apply, before its transition is read. Without the `program_state` section it is refused
`Disabled`, as an `Invoke` is. It cannot be taken for an `Invoke`: the tag differs, and when the
ledger has no record of block `h` there is **no segment at all** (`Ledger::invoke_segment` returns
the error) — it never falls back to a call's segment.

In every other respect it is an invoke: the same gate, fee floor, cell fee, transition rules,
payout notes, receipt, panic rule and pool handling. `Action::invoke()` gives both forms' fields
to the code that treats them alike.

## 4. Context version 2

An invoke's public segment is `public ‖ call_binding ‖ context` (`docs/program-state.md`). For an
`InvokeAt` the context is version 2: version 1's header, then **17 block words at fixed offsets**,
then version 1's cells and payouts. The block words sit before the variable part, so no offset
depends on how many cells or payouts there are. Offsets are from the start of the context (add
the length of `public` and the 8 binding words for the offset in the segment).

| words | name | value |
|---|---|---|
| 0 | version | **2** (`CONTEXT_VERSION_BLOCK`) |
| 1–10 | | version 1's words 1–10, unchanged: the four counts, `burn_r` (2), inflow, `burn_asset`, `burn_a` (2) |
| 11–12 | `ref_height` | `h`, low word then high |
| 13–14 | `timestamp` | block `h`'s header `timestamp_ms / 1000`, **seconds**, rounded down; low, high |
| 15–16 | `chain_id` | the genesis `chain_id`; low, high |
| 17–18 | `basefee` | §5; low, high |
| 19 | `has_randomness` | 1 if words 20–27 hold a beacon value: 1 on a chain with the genesis `beacon` section (§11), 0 on every other |
| 20–27 | `randomness` | the beacon's value after block `h`'s reveal: 32 bytes as eight little-endian words (a `Word8`, as a cell value is); all zero when word 19 is 0 |
| 28… | | version 1's words 11…: reads, writes (16 words a cell), then payouts (3 words each) |

A u64 is two words, low first — how the header already encodes `burn_r` and `burn_a`. Constants:
`ledger::program_state::{CTX_REF_HEIGHT, CTX_TIMESTAMP, CTX_CHAIN_ID, CTX_BASEFEE,
CTX_HAS_RANDOMNESS, CTX_RANDOMNESS, BLOCK_CONTEXT_WORDS, CONTEXT_HEADER_WORDS_BLOCK}`; the layout
is pinned word for word in `the_block_context_words_are_pinned`.

The segment rule (`segment_fits`) counts the 17 words: a transition that exactly fills version 1's
context does not fit version 2's (`ContextTooLong`).

A program must refuse a version it was not written for. A version-1 program run under an
`InvokeAt` reads `2` in word 0 and must stop.

## 5. `basefee`

`basefee` is **the price of one unit of gas, in RAND base units, that block `h`'s own calls were
charged**: the ledger's live `gas_price` at the start of block `h`, before the block-end controller
moves it.

This is a single consensus-defined value per block. Under `gas.dynamic` the live prices are
consensus state (in the state root under `rand-state-7`), moved once per block by
`close_block`; a call in block `h` pays `BUNDLE_BASE + gas_price·gas_limit + byte_price·⌈bytes/1024⌉`
at the prices the block opened with (`docs/fees.md`). Without `gas.dynamic` it is the genesis
`gas.gas_price`, constant. The `program_state` section requires a `gas` section, so the value is
always defined where an `InvokeAt` can exist. It is recorded per block (not read from the tip),
because the controller moves it.

It is not Ethereum's base fee in two ways, both to be stated in the contract-facing docs: the unit
is RAND base units per Rand gas (a zkVM cycle-based unit), not wei per EVM gas; and none of it is
burned by this rule (`fees.burn_base` burns the bundle base, a different thing). The byte price,
`fees.prove_base` and the USD price vote (`SetRandPrice`) are not part of it: they are not a
price per unit of gas. There are no tips, so `GASPRICE = BASEFEE`.

## 6. The opcodes

What each opcode is defined to return under an `InvokeAt` once the guest side lands (§10). Under an
ordinary `Invoke` or a `Call` every one of them keeps trapping.

| opcode | behaviour | source |
|---|---|---|
| `NUMBER` | `h` | words 11–12 |
| `TIMESTAMP` | block `h`'s time in seconds | words 13–14 |
| `CHAINID` | the chain id | words 15–16 (today a constant baked into the image; unchanged outside an `InvokeAt`) |
| `BASEFEE` | §5 | words 17–18 |
| `GASPRICE` | `= BASEFEE` (no tips) | words 17–18 |
| `PREVRANDAO` | **traps while word 19 is 0** (a chain without the `beacon` section); the beacon value of block `h` when it is 1 — read §11.4 before using it | words 19–27 |
| `COINBASE` | 0 | none: fees go to the proposer's register entry, which has no EVM address |
| `GASLIMIT` | a protocol constant, fixed in the guest by the circuits change | none |
| `BLOCKHASH` | traps | none: no header hash is in the context |
| `BLOBHASH`, `BLOBBASEFEE` | trap | none: the chain has no blobs |
| `SELFBALANCE` | traps; **not block context** — a contract's balance is its vault, a separate matter (a transition would have to declare it as a read) | none |
| `ORIGIN` | `= CALLER`, as today | none |

## 7. The ledger's record and the rules

**The ring.** `Ledger::block_facts`: `(height, timestamp_ms, basefee, randomness)` for the last `window` closed
blocks, oldest first. Recorded in `close_block` beside the anchor (`record_block_facts`), by the
proposer and every replica from the same values. Block 0 is never recorded. Like the anchors it
is derived from the chain, outside the state root, inside `Ledger`'s equality. Each speculative
ledger carries its own, so a proof is checked against the facts of the branch it is included on.
With the window off the ring is always empty.

**Rules.** `Ledger::block_facts_at(h)` is the one check, used by validation, apply and the pool:

| where | accepted when |
|---|---|
| validation on the head (RPC, gossip, the pool) | `h ≤ tip` and `tip − h < window` |
| apply in block `n` (proposer's trial apply, every replica) | `h < n` and `n − h ≤ window` |

The two are the same rule: the head's ledger holds blocks `tip−window+1 ..= tip`, and the next
block is `n = tip + 1`. Refusals, each its own error:

- `ReferenceBlockDisabled` — the window is off.
- `FutureReferenceBlock { ref_height, newest }` — `h` is the including block or later (or above
  the tip; or no block has closed).
- `StaleReferenceBlock { ref_height, oldest, window }` — `h` has left the window.

None is cached as a permanent verdict (`admission::is_permanent`): each is a statement about this
node's tip. A wrong fact is not a separate error: the ledger builds the words, so a proof over
other words is `InvalidProof`.

**Pool.** `program_state::still_applies` refuses a pooled `InvokeAt` whose `h` has left the window,
so it is dropped at the tip that made it stale rather than offered to every block.

**Storage.** One row per block, `block-facts/` ‖ height (big-endian) → `bincode(BlockFacts)`, in the
existing `meta` family (no new column family). Written at a commit for the heights it covers;
rows below the ring's oldest entry deleted in the same batch; rewritten wholesale by
`truncate_to`; read by `Storage::restore_reference_block_window`, which `reload_ledger` and the
replay audit (`verify_chain`) both call next to `restore_proof_window`. The replay rebuilds the
ring from the blocks and compares, so a wrong row is a snapshot mismatch that `--repair` rewrites.
On a chain without the window no row is written or read.

**Genesis.** `program_state.reference_block_window`: `#[serde(default)]`, written only when
nonzero; in the genesis hash as `"program_state_reference_block_window"` ‖ be64, appended last and
only when nonzero. When set it must be in `[256, 4096]` (the proof window's bounds) and the
genesis must bound block time — a `bridge` or a `perps` section (`Ledger::bounds_block_time`), so
timestamps cannot rewind and cannot leap more than 60 s a block. Otherwise `BadProgramState`.
CLI: `rand-node genesis --program-state-reference-block-window <BLOCKS>`.

## 8. RPC

`rand_getBlockContext([height?])` — public. `height` omitted or `null` is the newest closed block.

```json
{ "enabled": true, "height": 4210, "timestamp": 1794960123, "timestamp_ms": 1794960123456,
  "chain_id": 22, "basefee": "100", "has_randomness": false, "randomness": "00…00",  // true and the value under §11
  "window": 256, "oldest": 3955, "newest": 4210,
  "context_version": 2, "offset": 11, "words": [4210, 0, 1794960123, 0, 22, 0, 100, 0, 0, …] }
```

`words` are the 17 block words exactly as the ledger puts them at context words 11..28. On a
chain without the window: `{"enabled": false}` (the shape of every other gated read). A height
outside the window: error `-32602` with the ledger's wording (`… is too old …`, `… is not closed
yet …`). Before any block has closed: `-32001` (not found). Served from the stored ring as of
the committed head. `rand_getLimits.program_state.reference_block_window` is present only when
set. `tx_json` renders the action as `"kind": "invoke_at"` with `ref_height`.

## 9. Privacy

Naming `h` says when a transaction was built, to the block: an observer learns it was proved
after block `h` closed, and how long it waited. An ordinary bundle already reveals a `time` and an
anchor inside the proof window, so this narrows a known interval rather than opening a new one —
but it does narrow it, and a wallet that always names the tip gives an exact build time. That is
why the form is opt-in: an `Invoke` that needs no block context reveals nothing new. A wallet
may name an older `h` inside the window to blur it, at the cost of an older timestamp.

## 10. Not in this slice

All of it waits on the constraint-set-10 re-vendor at the chain-22 cut (this repository cannot
vendor set 10 before it; `AGENTS.md`, "The constraint-set guard").

- **Circuits.** Replace the traps with `READ_PUBLIC` reads of the words above in `evm-core`,
  `evm-rt` and `evm2rv` (version check on word 0, `PREVRANDAO` gated on word 19, the `GASLIMIT`
  constant); re-pin the images.
- **Wallet / CLI.** Build an `InvokeAt`: read `rand_getBlockContext`, feed the words to the
  guest, set `ref_height`, and re-prove on `StaleReferenceBlock`. The wallet's public-note scan
  keys on `"invoke"` and must learn `"invoke_at"` to see such a transaction's payout notes.
- **A real-prover test** of a permit-with-deadline contract end to end.
- **The cut.** `deploy/cut-chain22-genesis.sh` carrying the field; the value is the owner's.

Tested here with `StubExecutor` only: no proof was made.

## 11. Randomness (PREVRANDAO): the beacon

Status: **built in the node and gated off; on no chain.** Genesis `beacon`. Chain 21 has no such
section: its genesis hash, header and block bytes, state root, wire tags 0–45 and store rows are
unchanged (pinned on the commit before the beacon, `crates/randprotocol-core/tests/
beacon_gate_off_pin.rs` and `node::tests::chain_21_is_byte_for_byte_what_it_was_before_the_beacon`).
The guest's `PREVRANDAO` read of words 19–27 is circuits work and waits for the constraint-set-10
re-vendor (§10); nothing was proved here.

### 11.1 What it is

Validator signatures cannot be a beacon: Dilithium signatures are not unique, so a proposer could
grind them. The beacon is a hash-chain commit–reveal ("RANDAO over hash onions"), post-quantum
because it uses only BLAKE3.

- **Link.** `L(x) = blake3("rand-beacon-link-1" ‖ be64(chain_id) ‖ validator address ‖ x)`. The
  address is inside the link, so a commitment copied from another validator opens to nothing.
- **Commitment.** A validator picks a secret 32-byte seed and registers `c = L^N(seed)`. `N` is
  not consensus — the chain checks one link per block and never counts them. The tools default to
  2^20, about 1.7 years at 26 validators and 2 s blocks.
- **Reveal.** Block `n`'s proposer reveals `r` with `L(r) = c`, its current commitment. The
  ledger then sets the proposer's commitment to `r` and
  `beacon(n) = blake3("rand-beacon-1" ‖ beacon(n−1) ‖ r ‖ be64(n))`.
- **Genesis value.** `beacon(0) = blake3("rand-beacon-genesis-1" ‖ be64(chain_id) ‖ (address ‖
  c)*)` over the genesis commitments in address order. (Not the genesis hash: the genesis header
  carries the state root, which commits to this value.)

A reveal is determined by the commitment, so it cannot be ground.

### 11.2 Carrier, rules and state

The reveal is **not a header field**. The header is embedded positionally in `Block`, in the
compact proposal and in a `SlashEquivocation`'s signed headers; a gated trailing field could not
be decoded without context, and any field would move chain 21's header bytes. It is a
transaction:

| action | tag | shape |
|---|---|---|
| `BeaconReveal { reveal: [u8; 32] }` | 46 | bundle-less, fee-less; 45 bytes on the wire |
| `BeaconCommit { validator, commitment, nonce, signature }` | 47 | bundle-less, fee-less; signed by the validator's key over `blake3("rand-beacon-commit-1" ‖ genesis hash ‖ commitment ‖ be64(nonce))` |

Both are appended after `InvokeAt` (45), so tags 0–45 encode as before. Both sit under the
transaction root, so the proposer's signature covers the reveal.

**Block rule** (`Ledger::apply_block_reveal`, run by every replica in
`apply_transactions_for_sync` and by the proposer in `HotStuff::propose` — the same function).
On a chain with the section, block `n` by proposer `P`:

1. `transactions[0]` is a `BeaconReveal`, bundle-less, on this chain's id — else
   `BlockError::MissingBeaconReveal` (or `InvalidTx { index: 0, WrongChain | ActionCarriesBundle }`).
2. `P` has a commitment in force at `n`: its pending commitment if `n ≥` the pending one's
   activation height, otherwise its current one — else `NoBeaconCommitment`.
3. `L(reveal) ==` that commitment — else `BadBeaconReveal`. A replayed old reveal fails here: the
   commitment has moved past it.
4. A pending commitment that was due is promoted; the commitment becomes `reveal`; the value
   moves.
5. No other transaction of the block is a `BeaconReveal` — else
   `BlockError::MisplacedBeaconReveal { index }`.

Everywhere else — the pool, `rand_sendTransaction`, gossip, a proposer's candidate list — a
`BeaconReveal` is refused (`RevealOutsideBlockHead`, cached as a permanent verdict), so it is
never a pooled transaction.

**`BeaconCommit`** (join after genesis, a spent chain, a lost seed): the gate; `validator` is in
the validator register; `nonce` is the validator's last commit nonce plus one (1 for the first);
the signature verifies under the register's key. It writes `pending = (height +
commit_delay_blocks, commitment)` and the nonce; a second commit before promotion replaces the
pending one and restarts the delay. The pool holds one commit per validator and nonce and orders
it with governance (it is fee-less).

**The commit delay** is a rule the original proposal did not have. Without it, two colluding
consecutive leaders — who know `beacon(h−1)` before anyone else — could register a fresh seed
chosen against it: far more than one bit. With it, a commitment registered at height `h` cannot
be opened before `h + commit_delay_blocks`. Default 256; bounds 1..=2^20.

**A validator that cannot reveal** — no commitment in force, or a node that holds no seed opening
it — cannot build a valid block. `propose` returns `NotReady`, the view times out, the next
leader proposes. The validator stays in the set and keeps voting; **nothing is slashed**. It
costs the chain one view timeout per missed slot, and the validator its block fees.

**State.** `Ledger::beacon: Option<BeaconState { commit_delay_blocks, value, entries: address →
{ commitment, nonce, pending } }>`. `None` without the section. With it, consensus state: the
outermost state-root wrapper, `blake3("rand-state-beacon-1" ‖ root ‖ beacon_root)`; inside
`Ledger`'s equality; one row, `beacon`, in the `meta` family, written with genesis, at every
commit and by `truncate_to`, restored by `Storage::restore_beacon` (which `reload_ledger` and the
replay audit call) and named by the audit. Without the section the row is never written, deleted
or read, and both actions are refused `UnsupportedAction` before a byte of them is read.
`BlockFacts.randomness` records `beacon(n)` for each closed block in the reference-block ring.

**Genesis.** `"beacon": { "commit_delay_blocks": 256, "commitments": [{ "validator": "<address,
base58>", "commitment": "<64 hex>" }, …] }` — `#[serde(default)]`, written only when present; in
the genesis hash last, as `"beacon" ‖ be64(delay) ‖ (address ‖ commitment)*` in file order, only
when present. It must list **every** genesis validator exactly once and nobody else, with distinct
commitments, and it **requires `program_state.reference_block_window`** (a program reads the
value only through a reference block) — otherwise `BadBeacon`. CLI: `rand-node genesis
--beacon-commitment <ADDRESS>=<HEX>` (repeatable) and `--beacon-commit-delay-blocks`.

**Gossip.** A beacon block's first transaction is one no peer's pool can hold, so a plain compact
proposal would cost every validator a body fetch per block. On a beacon chain the leader sends
`GossipMessage::CompactProposalPrefilled { compact, prefilled: [reveal] }` (appended as the sixth
gossip variant; never sent on another chain). A receiver keeps the body only after the
pre-screen, only if it is a reveal and the first hash of the signed list; the fetch-by-hash path
is unchanged underneath.

### 11.3 Exposure

`BlockFacts::context_words` sets word 19 to 1 and words 20–27 to `beacon(h)`.
`rand_getBlockContext` renders them (`has_randomness`, `randomness`). `rand_getBeacon` serves the
value and every validator's commitment (`docs/rpc.md`).

### 11.4 What it is worth — read before using `PREVRANDAO`

The beacon is at **Ethereum's `PREVRANDAO` trust level, not better**, and the reference-block
design adds one trap of its own.

- **Withholding: one bit per slot.** A proposer cannot choose its reveal, but it can decline to
  propose. It sees `beacon(n)` before anyone, and if it dislikes it, it skips the block — the
  next leader's reveal gives another value. The price is that block's fees. A run of `k`
  colluding consecutive leaders gets `k` bits.
- **Parent choice: about one more bit.** A leader holding two certified parents the vote rule
  both allows may choose which to extend; the two give different values.
- **Foreknowledge.** The proposer knows `beacon(n)` first, and every validator knows it when the
  proposal arrives, before the block commits. A reveal that leaked in a block that was abandoned
  is public before the block that finally carries it — and the same reveal is used again.
- **Window re-rolls.** The *prover* picks the reference block `h`. A contract that simply reads
  `PREVRANDAO` lets the caller try every block in the window — `window` re-rolls (256 to 4096)
  — and submit the one it likes. **This breaks naive use completely.**

**The contract-side rule.** The guest enforces nothing beyond trapping when word 19 is 0. A
contract must pin the block itself:

1. at bet time, store `target = NUMBER + k` with `k ≥ 2` — a block that does not exist yet;
2. at settlement, `require(NUMBER == target)` and only then read `PREVRANDAO`.

Settlement must then name block `target` as its reference block, which is possible only while
`target` is inside the window: **within `window` blocks after `target`**. A contract therefore
needs a refund path for a bet nobody settled in time. And because of withholding, the beacon is
**unsuitable for a prize worth more than a block's fees to a single proposer** without a further
delay construction (a VDF, or many blocks' values combined).

### 11.5 Operating a validator

- **The seed file.** `<datadir>/beacon.seed.json`, mode 0600, beside `node.key.json`: the chain
  id, the validator's address, and the 32-byte seed, length and commitment of each of its
  chains, newest last. `rand-node beacon init --datadir D --key K --chain-id N` creates it
  (refusing to overwrite) and prints the commitment the genesis lists.
- **It is secret, and it is this host's alone.** Whoever holds a seed knows every reveal that
  validator will make from that chain. The file is bound to one chain id and one address.
  **Never copy `beacon.seed.json` between hosts**, and do not restore it onto a second machine.
  Losing it is recoverable (below); leaking it is not, short of a recommit.
- **No position is stored.** The node finds its reveal by walking from the seed to the preimage
  of the commitment the chain holds. Nothing is written before a proposal leaves, so a crash
  cannot desynchronise it, and after an abandoned block the same reveal is given again.
- **Recommit.** `rand-node beacon recommit --datadir D --key K [--rpc URL]` appends a fresh
  chain to the file (flushed before anything is sent), signs a `BeaconCommit` and submits it. It
  is in force `commit_delay_blocks` after its block, at the validator's next block. The file
  keeps the old seed, so a validator that recommits **before** its chain runs out misses no
  slot; one that lost its seed misses its slots for the delay and keeps voting. A running node
  picks the changed file up by itself.
- **Starting without a seed.** A validator node on a beacon chain with no file, or one that
  opens nothing, **starts and votes** and logs at error level that it will miss its slots. (It is
  not refused: a refused node could not vote, which would cost the chain more than its slots.)
- **Monitoring.** `rand-node beacon status --datadir D [--rpc URL]` prints the commitment in
  force, any pending one, whether the file opens each and the reveals left, and **exits non-zero
  when no seed opens the commitment in force**. Alert on: that exit; remaining reveals under
  about 20 000 (≈ 12 days at 26 validators and 2 s blocks) — recommit then; `rand_getBeacon`
  showing a validator with `commitment: null` and no `pending`; and a rising view-timeout rate at
  one leader's slots, which is what a seedless validator looks like from outside.

### 11.6 Not done

- **Circuits**: the guest's `PREVRANDAO` read of words 19–27 (trap on word 19 = 0), with the rest
  of §10, at the constraint-set-10 re-vendor; and a real-prover test.
- **`deploy/cut-chain22-genesis.sh`** does not carry the section: it does not yet carry
  `reference_block_window` either (§10), which the beacon requires. `deploy/fleet-watch.sh` has
  no beacon alert; the commands to build one on are above.
- **Entries are never removed**: a validator that left the register keeps its row in the beacon
  state (bounded by the register's own growth).
- **Wallet / explorer**: nothing renders `beacon_reveal` / `beacon_commit` beyond `tx_json`.
