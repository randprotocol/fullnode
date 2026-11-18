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
| 19 | `has_randomness` | 1 if words 20–27 hold a beacon value; **always 0 today** |
| 20–27 | `randomness` | 256 bits as eight words (a `Word8`, as a cell value is); **all zero today** |
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
| `PREVRANDAO` | **traps while word 19 is 0** (always, today); the beacon value when it is 1 | words 19–27 |
| `COINBASE` | 0 | none: fees go to the proposer's register entry, which has no EVM address |
| `GASLIMIT` | a protocol constant, fixed in the guest by the circuits change | none |
| `BLOCKHASH` | traps | none: no header hash is in the context |
| `BLOBHASH`, `BLOBBASEFEE` | trap | none: the chain has no blobs |
| `SELFBALANCE` | traps; **not block context** — a contract's balance is its vault, a separate matter (a transition would have to declare it as a read) | none |
| `ORIGIN` | `= CALLER`, as today | none |

## 7. The ledger's record and the rules

**The ring.** `Ledger::block_facts`: `(height, timestamp_ms, basefee)` for the last `window` closed
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
  "chain_id": 22, "basefee": "100", "has_randomness": false, "randomness": "00…00",
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

## 11. Randomness (PREVRANDAO) — proposed, not built

> **Randomness (PREVRANDAO).** The chain has no beacon today, and validator signatures cannot serve as one: Dilithium signatures are not unique, so a proposer could grind them. Proposed: a hash-chain commit–reveal beacon ("RANDAO over hash onions"), post-quantum because it uses only the hash. Each validator registers a commitment `c = H^N(seed)`; each block's proposer reveals the preimage of its last commitment in the header; `beacon(h) = H(beacon(h−1) ‖ reveal)`. A reveal is deterministic, so it cannot be ground; the only influence is withholding (skipping one's own block, forfeiting its reward), which is one bit per leader slot — the same trust level as Ethereum's PREVRANDAO, and it must be documented as unsuitable for high-value lotteries without a delay. It needs a header field, validator registration and slashing-free skip handling, so it is its own consensus change at a chain cut; the `randomness`/`has_randomness` words are reserved here so the public layout does not move when it lands.
