# Confidential computation

SHRUGG pays for confidential calls: a program runs off-chain inside the Rand zkVM on private inputs,
and only a STARK proof plus eight public output words go on chain. Every node verifies the proof,
charges gas, stores a receipt, and applies the transfer the outputs request.

## The zkVM

`crates/shrugg-zkvm` (vendored from `circuits/research`, upstream `rand_zkvm`): an RV32I subset,
plus the RV32M extension and sub-word loads/stores (constraint set 3, below), proven by a
Plonky3 batch STARK over Goldilocks with Poseidon2 hashing and ZK-hiding FRI. Seven tables
(program, cpu, memory, alu, range, nibble, poseidon2) connected by LogUp/permutation buses. Four
syscalls: `read_input(i)` (private input word), `write_output(slot, word)` (one of eight public
outputs), `poseidon2(ptr, n)` (in-place hash of `n` words), `halt`.

Gas tiers pad the execution trace: tier `t` (10, 12, ..., 20) proves up to `2^t - 1` cycles and the
proof reveals only the tier, never the real cycle count. Production FRI profile: blowup 8, 27
queries, 20 PoW bits (constraint set 3 below; see `docs/03-privacy.md` in the upstream `research`
crate for the retune history).

Measured upstream on `guests::fib` at tier 10, constraint set 3: prove 3.1 s, proof 268 KB, first
(uncached) verify 16 ms — the verifier key itself is what a cached verify amortizes away; see
"Constraint set 3" below for the full before/after.

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

**Constraint set 3 (2026-09-11, upstream 35fceab: milestones 2+3).** The vendored zkVM was
re-synced past constraint set 2 to `research`'s milestones 2 (finished) and 3 (Poseidon2). The
headline changes:

- **Proofs shrank roughly 3x, verify got faster.** FRI retuned to arity 8 (`max_log_arity: 3`)
  and 27 queries (down from 80), still meeting the ethSTARK conjectured-soundness target
  (`3·27+20 = 101` bits); splitting the old 2^16-row byte table into two 256-row tables (`range`,
  `nibble`) cut the preprocessed commitment the prover rebuilds every proof and the verifier
  rebuilds on every *uncached* verify by two orders of magnitude. Net effect measured upstream at
  tier 10: proof size 892 KB → 268 KB, prove 21.6 s → 3.1 s, first (uncached) verify 2.17 s → 16 ms.
- **Sub-word memory.** Loads and stores can now address a byte or halfword within a word
  (`Instr::Load`/`Store { width, .. }` replace the old word-only `Lw`/`Sw`), sign-extended for
  `lb`/`lh`. Memory itself stays word-addressed.
- **The RV32M extension.** `mul mulh mulhu mulhsu div divu rem remu` (`AluOp` grew from 11 to 19
  variants), register-register only, reached the same way upstream RISC-V reaches it (`OP_ALU`,
  `funct7 = 1`).
- **A Poseidon2 syscall.** `SYS_POSEIDON2 = 3`: `a0 = ptr` (word address), `a1 = n` (≤ 4096
  words); hashes the `n` words in place with a padding-free Poseidon2 sponge and overwrites
  `ptr..ptr+8` with the 8-word digest. Proved by a dedicated `poseidon2` chip (a seventh table)
  the cpu table's new hash rows call into over a `POSEIDON2` bus; `src/hash.rs` is the host-side
  reference sponge (also used for the in-circuit program digest below) and is vendored, unlike
  the note/viewing-key layer built on top of it (`notes.rs`/`viewing.rs`/`ledger.rs`, still not
  vendored — see `deploy/sync-zkvm.sh`'s header comment).
- **The program table is a witness now, and `hc` moved in-circuit.** Through constraint set 2,
  `hc` was the preprocessed program table's Merkle root and the verifier held the whole program
  in the clear to recompute it. The program table is proved as an ordinary witness trace now
  (an in-circuit decoder reproduces `Instr::decode`), and a digest-row prefix at the front of the
  cpu table absorbs every program word through the same Poseidon2 chip, publishing an 8-word
  digest `hc` the verifier checks directly — **`Machine::verify(hc, proof)` replaces
  `verify(program, proof)`**; the verifier never sees a single instruction word. `hc` is still
  binding, not hiding (no salt of its own — the upstream `research` crate's `docs/03-privacy.md`,
  "What that does and doesn't change about what `hc` leaks", has the full argument), and it is
  still guessable by anyone
  who can enumerate candidate programs, but it closes a much larger leak: the program itself.
  `Proof` gained a `program_log_height: u8` field (the program table's height, declared by the
  prover per proof, not derived from the tier — a program can need far more table rows than
  cycles, since a digest row absorbs up to 4 words each); `verifier_key(tier, program_log_height)`
  is program-*content*-independent (cached by `Machine` itself, keyed on that pair).
- **On-chain effect: `ProgramRecord.code_hash` is now `hc`, and it is load-bearing.** Before this
  sync, `code_hash` was blake3(`program_id`) again — informational, since `verify_call`
  reconstructed the program from `record.words` and passed it to `Machine::verify` directly. Now
  that the verifier no longer takes a program at all, `ZkExecutor::check_program` computes and
  stores `hc` (`isa::Program::digest()`, 8 little-endian `u32` words) as `code_hash` at deploy
  time, and `ZkExecutor::verify_call` decodes it back out and hands it to `Machine::verify` —
  `code_hash` is now the actual verification key material, not just an explorer-facing label.
  `shrugg-core`'s `programs` RPC already serves `code_hash` as hex; nothing there changed.
- **Tiers are unchanged** (10, 12, 14, 16, 18, 20; `cpu`/`alu`/`memory` height formulas
  unchanged); `Tier::poseidon2_height()` (`2^(t+2)`) and the proof-declared `program_log_height`
  are new, both sized independently of `cpu_height`.

Proofs made under constraint set 2 (or earlier) do not verify under constraint set 3 — different
FRI parameters, a different table set, and a completely different `hc` construction (a Merkle
root of a preprocessed table vs. an in-circuit Poseidon2 digest). This is the same hard-fork
situation constraint set 2 already documented: a node built from this commit will fail startup
ledger replay of any chain with a confidential call proved under an older constraint set and
truncate its chain. Start a new chain id, or run `--verify-chain off` on nodes that must keep
serving an old chain.

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
