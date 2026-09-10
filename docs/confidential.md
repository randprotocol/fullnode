# Confidential computation

SHRUGG pays for confidential calls: a program runs off-chain inside the Rand zkVM on private inputs,
and only a STARK proof plus eight public output words go on chain. Every node verifies the proof,
charges gas, stores a receipt, and applies the transfer the outputs request.

## The zkVM

`crates/shrugg-zkvm` (vendored from `circuits/research`, upstream `rand_zkvm`): an RV32I subset
(`lui auipc jal jalr branches lw sw alu ecall`) proven by a Plonky3 batch STARK over Goldilocks
with Poseidon2 hashing and ZK-hiding FRI. Five tables (program, cpu, memory, alu, byte) connected by
LogUp buses. Three syscalls: `read_input(i)` (private input word), `write_output(slot, word)` (one
of eight public outputs), `halt`.

Gas tiers pad the execution trace: tier `t` (10, 12, ..., 20) proves up to `2^t - 1` cycles and the
proof reveals only the tier, never the real cycle count. Production FRI profile: blowup 8, 80
queries, 20 PoW bits.

Measured on Apple Silicon at tier 10: prove 22 s, proof 878 KB, verify 19 ms with a cached verifier
key (the key itself costs 2.2 s once per program and is computed in the background).

**Constraint set 2 (2026-09-10, upstream fix wave through `e6dbf38`).** The vendored zkVM now
carries four soundness fixes: ALU padding rows can no longer provide a bus tuple with arbitrary
multiplicity (previously `fib(10) = 999` was provable), never-written output slots are pinned to zero
by `WRITTEN` accumulators, `verify` rejects non-canonical public values, and load/store word
alignment is a stated constraint (the cpu table grew from 40 to 52 columns). Proofs made under the
old constraints do not verify under the new ones, so a node built from this commit will fail the
startup ledger replay of chain 4 at the first block with a confidential call (block 19) and truncate
its chain. Treat this as a hard fork: start a new chain id, or run `--verify-chain off` on nodes that
must keep serving the old chain.

## On-chain model

**Programs** are content addressed: `program_id = blake3("shrugg-program" || base_pc || words)`.
A `Deploy` transaction stores `{ base_pc, words }` (at most 4096 words); every word must decode as an
instruction. Programs are immutable and part of the state root.

**Calls** carry `{ program, proof, recipients }`. The proof is `postcard(rand_zkvm::Proof)` (tier,
public values, batch STARK proof); `recipients` is a public list (at most 8) the program may pay.

**Effects.** The eight output words are the program's instruction to the chain:

| word | meaning |
|---|---|
| `out0` | effect kind: `0` none, `1` transfer |
| `out1` | recipient index into `recipients` |
| `out2`, `out3` | amount in units as a little-endian u64 (low, high) |
| `out4..out7` | free data, recorded in the receipt |

Kind 1 moves `amount` from the caller to `recipients[out1]` inside the same transaction; the caller
must hold `amount + fee`. Kind 0 pays gas and records the outputs. The assembler helper
`emit_transfer(index, lo_reg, hi_reg)` writes the four effect words.

**Receipts** `{ tx, program, tier, outputs, effect, height, index }` are stored per call and served by
`shrugg_getReceipt`; they are recomputed and checked when a node syncs or verifies its chain.

## Validity rules

- Deploy: `words.len() <= 4096`, `base_pc % 4 == 0`, every word decodes, `fee >= 100_000 * words`.
- Call: program exists; `proof.len() <= 1 MiB`; `recipients.len() <= 8`; the proof verifies against
  the stored program for the tier it declares; `fee >= call_fee(tier)`; the effect decodes (known kind,
  index in range); for a transfer the caller's balance covers `amount + fee`.
- A block with an invalid call is invalid, like any other invalid transaction.

## Gas (v0)

| operation | minimum fee |
|---|---|
| Deploy | 100,000 units per word (0.0256 SHRUGG for 256 words) |
| Call | 0.001 SHRUGG + 0.0001 SHRUGG per two tiers above 10 |
| Transfer, Mint | free (fee is a tip) |

Anything above the minimum is a tip; all of it goes to the block proposer. Blocks hold at most
4 MiB of transactions, so about four calls per block. Constants live in `shrugg_core::gas`.

## Privacy

Public: program id, tier, the eight outputs, caller, fee, recipient list, and (for kind 1) the
transfer. Private: inputs, registers, memory, branches taken, cycle count (padded to the tier). Two
proofs of the same run are different bytes (hiding commitments), so proofs do not fingerprint inputs.

## Chains without confidential computation

Genesis `"confidential": false` makes Deploy and Call invalid; `"fri_profile"` selects
`production` (default) or `test` (16 queries, insecure, for the test suite). Both are part of the
genesis hash, so nodes with different settings cannot join the same chain.

## Guest programs

`shrugg program build --guest <name> --arg ...` assembles the built-in guests: `fib n`, `memcpy n`,
`bubble_sort v...`, `balance_check threshold`, `private_payment threshold`. Any RV32I program in the
supported subset can be deployed from a `.json` (`{ "base_pc", "words" }`) or `.bin` (raw
little-endian words) file.
