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

**Constraint set 2 (2026-09-10, upstream fix wave through `f44d58f`).** The vendored zkVM now
carries five soundness fixes: ALU padding rows can no longer provide a bus tuple with arbitrary
multiplicity (previously `fib(10) = 999` was provable), never-written output slots are pinned to zero
by `WRITTEN` accumulators, `verify` rejects non-canonical public values, load/store word
alignment is a stated constraint (the cpu table grew from 40 to 52 columns), and a store's `mem_val`
is pinned to the `rs2` value it writes — left unstated, a cheating witness could store a value that
was never in any register and read it back through a later load as genuine memory contents. The
prover also runs the emulator up to the largest tier's cycle budget rather than a hardcoded `1 << 20`,
so `OutOfCycles` and `TooManyCycles` agree on one limit. Proofs made under the
old constraints do not verify under the new ones, so a node built from this commit will fail the
startup ledger replay of chain 4 at the first block with a confidential call (block 19) and truncate
its chain. Treat this as a hard fork: start a new chain id, or run `--verify-chain off` on nodes that
must keep serving the old chain.

The `balance_check` guest also became carry-aware (a four-balance sum that wraps mod 2^32 now counts
as over any 32-bit threshold), which changes its program id; `private_payment` is unchanged and keeps
the id chain 4 has deployed.

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

## GPU proving (--cuda)

Proving is the only expensive half of a confidential call, and it happens in the wallet, never on
the chain. `shrugg call --cuda` runs the batch STARK's NTTs and Poseidon2 Merkle commitments on an
attached NVIDIA GPU instead of the CPU. The proof is the same object either way — same public
values, same tier, verified by the same CPU verifier — so nothing on the node changes and a chain
cannot tell which backend produced a proof.

The backend lives in the sibling repository, `circuits/rand-zkvm-cuda`, and is referenced by path
(`../../../circuits/rand-zkvm-cuda`); it is not vendored into this repo. `circuits/` must therefore
be checked out beside `fullnode/` to build any of the features below. `deploy/sync-zkvm.sh` prints
the same reminder.

**Building.** On a machine with a CUDA 13 toolkit, an NVIDIA driver, and the compiled PTX:

```
cargo build --release -p shrugg-client --features cuda
shrugg call <program-id> --input 400 --input 250 --cuda
```

The flag is always accepted by the parser, so `--cuda` on a stock build fails with a message rather
than being silently ignored. There is deliberately **no fallback**: if the GPU path cannot start,
the call errors out and nothing is submitted, so a proof is never quietly produced somewhere other
than where it was asked for.

Two other feature flags exist for testing without hardware, neither of which needs a CUDA toolkit:
`--features mock-cuda` runs the same `Backend::Cuda` path with the kernel bodies executing on the
host, and `--features reference-backend` runs the backend's CPU-twin NTT and Merkle engines.
`mock-cuda` is a sibling of `cuda`, not a superset — enabling `cuda` is what pulls in `cuda-core`
and its toolkit requirement.

**Failure modes.** Each exits non-zero and submits nothing:

| Situation | Message |
| --- | --- |
| Built without the feature | `built without CUDA support; rebuild shrugg with --features cuda` |
| No driver or no device | `Backend("CUDA driver: ...")` |
| Built, driver present, PTX missing | `Backend("no PTX for the GPU kernels at <dir>/ptx/kernels.sm_80.ptx (see rand-zkvm-cuda/ptx/PTX_BUILD.md)")` |
| Tier too large for device memory | `Backend("device allocation of N bytes failed (M bytes free); use a lower tier")` |

The PTX path can be overridden with `$RAND_ZKVM_PTX`; it otherwise defaults to
`rand-zkvm-cuda/ptx/kernels.sm_80.ptx`. A deployed binary must set `RAND_ZKVM_PTX`, because that
default is an absolute path into the *build* machine's crate directory and will not exist on the
node.

**Status as of 2026-09-10.** The kernels have not been executed on real hardware, and no PTX is
committed — `rand-zkvm-cuda/ptx/` holds only `PTX_BUILD.md`. Everything above is exercised on the
mock driver and the CPU twins; the first run on a GPU is still ahead, so treat the `cuda` feature as
untested on-device and expect the "no PTX" error until the kernels are compiled and committed.
