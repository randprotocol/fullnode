# The Rand zkVM — ISA and execution model

This page explains the machine every confidential operation on SHRUGG runs on: what a proof
states, the instruction set, how memory and syscalls work, how a run becomes a trace and a
trace becomes a STARK, what is public, and what it costs. `docs/confidential.md` covers the
on-chain call model, `docs/shielded.md` the note pool built on the `bundle` guest, and
`docs/zkvm-milestones.md` the history. The upstream crate is `circuits/research` (`rand_zkvm`),
vendored here as `crates/shrugg-zkvm`; its own documents (`research/docs/01`–`06`) are the
authoritative reference and are cited by name below.

## 1. What a proof states

One relation, for every program:

> *This RV32IM program, started at `base_pc`, run on a private input vector committed to by
> `H_IN`, halted within `2ᵗ − 1` cycles and published these eight output words.*

The program is identified by its in-circuit digest `hc` (public values `HC0..7`), the inputs by
the salted digest `H_IN` (`IN0..7`), the outputs by `OUT0..7`, and the gas tier by `TIER`. That
is the whole public interface: 26 field elements (`pv::NUM = 26`). Everything else — registers,
memory, branches taken, the exact cycle count, the inputs — is witness and stays private.

A contract is therefore a program: the node stores its words at deploy time, computes `hc`, and
verifies every call with `Machine::verify(hc, proof)` without ever re-reading the program. The
shielded pool's transfer is the `bundle` guest, whose `hc` is pinned in genesis. The EVM and sBPF
targets (milestone M4) are interpreters compiled to this ISA with the foreign bytecode as
private input.

## 2. The machine

**Word size and field.** Words are 32 bits. The proof field is Goldilocks,
`p = 2⁶⁴ − 2³² + 1`, chosen so a 32×32 product never overflows it
(`(2³² − 1)·2³¹ < 2⁶³ < p`) and a word is exactly four byte limbs. RV64 would double the limb
columns of the ALU and memory tables (`research/docs/01-isa.md`, "Why RV32, not RV64").

**Registers.** 32 registers, `x0` hard-wired to zero: the decoder's `writes_rd` is `rd ≠ 0`, so
a write to `x0` never reaches the register file, and the emulator forces `regs[0] = 0` every
cycle to match.

**Memory.** One table holds both the register file (`space = 0`) and RAM (`space = 1`), sorted by
`(space, addr, ts)` with `ts = 4·clk + slot`. Every cycle has four access slots: two register
reads, one memory read or the syscall's second argument, and one write (a register or a store).
A read must return the last written value at that address; the ordering key lets the table prove
that with one range-checked delta per row. RAM is word-addressed; byte and halfword loads and
stores pick a byte offset inside the word, and alignment is a constraint (a word access on a
word boundary, a halfword on a 2-byte boundary), not just an emulator error. A store is a
read-modify-write of the whole word. RAM starts entirely zero; there is no data-section loading
yet, so a compiled guest builds any initialised array itself.

**Addresses cannot wrap the table.** Every address that reaches the memory bus from an
instruction or a syscall pointer is decomposed into range-checked byte limbs and bounded below
`2³⁰`, because the memory key `space·2³⁰ + addr` is a field element and an unbounded pointer
could alias another cell (`research/docs/02-tables-and-buses.md`, the `HASH_PTR` note).

## 3. The instruction set

A staged subset of RV32I plus the M extension (`research/docs/01-isa.md`):

| group | instructions |
|---|---|
| upper / jumps | `LUI AUIPC JAL JALR` |
| branches | `BEQ BNE BLT BGE BLTU BGEU` |
| loads / stores | `LW SW` (M1), `LB LH LBU LHU SB SH` (M2.5) |
| immediate ALU | `ADDI SLTI SLTIU XORI ORI ANDI SLLI SRLI SRAI` |
| register ALU | `ADD SUB SLL SLT SLTU XOR SRL SRA OR AND` |
| RV32M (M2.6) | `MUL MULH MULHU MULHSU DIV DIVU REM REMU` |
| system | `ECALL` |
| never | `FENCE`, CSR instructions, `EBREAK`, the A and C extensions |

Encodings are the standard RV32 layouts (R, I, S, B, U, J). A word that does not decode is
rejected at deploy (`Deploy` fails) or at load (`LoadError::Decode`), never at run time.
`JALR` uses `rs1 + imm` exactly; an odd target cannot be fetched and the run cannot be proved.

Multiplication is proved as an exact integer identity over 16-bit halves of the operands with a
bounded carry, because the naive `hi·2³² + lo` product can exceed the field modulus and let a
prover claim a wrong high word. Division proves `|a| = q·|b| + r` with `r < |b|` on magnitudes
and then fixes the sign, matching the RISC-V edge cases (`x / 0`, `MIN / −1`) exactly.

**Decoding is a table, not logic.** The program table holds each instruction's 23 pre-decoded
fields (`rd`, `rs1`, `rs2`, `imm`, the one-hot load/store widths, `is_branch`, `br_op`,
`writes_rd`, …). The cpu table looks each fetch up on the `PROGRAM` bus and never inspects an
opcode bit itself. Since M3.4 the program table is a witness with an in-circuit decoder, so the
verifier holds only `hc` and never sees a program word.

## 4. Syscalls

`ECALL` reads the syscall number from `a7` and the first argument from `a0`; a second argument
comes from `a1` through the row's memory slot; a value-returning syscall writes `a0`.

| # | name | effect | cpu rows |
|---|---|---|---|
| 0 | `HALT` | ends the run; every later row is padding | 1 |
| 1 | `WRITE_OUTPUT slot word` | pins public output `slot < 8`; each slot at most once; unwritten slots are pinned to zero | 1 |
| 2 | `READ_INPUT idx` | returns private input word `idx`, looked up in the committed input table; two reads of one index agree; `idx ≥ n_in` is unsatisfiable | 1 |
| 3 | `POSEIDON2 ptr n` | hashes `n ≤ 4096` words at word address `ptr` with the Poseidon2 sponge (width 8, rate 4, overwrite mode) and writes the 8-word digest in place | 1 + ⌈n/4⌉ + 2 |
| 4 | `KECCAK ptr` (M4.2) | one Keccak-f[1600] permutation of the 50-word state at word address `ptr`, in place; the keccak table reads and writes the words itself | 1 |

Note commitments, nullifiers and Merkle verification are **not** syscalls: they are assembler
library routines that stage a domain-tagged message in RAM and call `POSEIDON2`
(`asm::emit_note_commit`, `emit_nullify`, `emit_merkle_verify`). The Merkle walk is a counted
loop over the path, so program size does not scale with tree depth.

## 5. Execution model: from a run to a proof

**The emulator is the reference.** `emulator::run(program, inputs, max_cycles)` executes the
program and records one `CycleEvent` per cpu row: the instruction, its operands, the ALU result,
the memory accesses with their slots, the syscall, and any hash-row or keccak-row data. If the
AIR and the emulator ever disagree, the AIR is wrong (`research/AGENTS.md`).

**Cycles and tiers.** A cycle is one cpu row. Gas is a tier `t ∈ {10, 12, 14, 16, 18, 20}`: the
cpu table is padded to `2ᵗ` rows, the ALU table to `2ᵗ⁺¹`, the memory table to `2ᵗ⁺²` (four
accesses per cycle, plus room for Keccak traffic since M4.2), the Poseidon2 table to
`32·2ᵗ⁻³` permutation blocks. Only `t` is public. The prover picks the smallest tier whose
budget covers `cycles + program digest rows + input digest rows`; a run that does not fit fails
before proving.

**The trace.** A run becomes nine tables proved together as one Plonky3 batch STARK, connected
by LogUp buses instead of direct calls:

| table | rows | provides / consumes |
|---|---|---|
| `program` | one per instruction word (witness, in-circuit decoder) | provides `PROGRAM` (pc → decode) and `PROGRAM_WORD` (the words the digest absorbs) |
| `cpu` | one per cycle, plus digest rows | consumes everything; sends `MEMORY`, `ALU`, `RANGE8`, `POW2`, `AND4/OR4/XOR4`, `POSEIDON2`, `INPUT_READ`, `KECCAK` |
| `memory` | one per access, sorted | receives `MEMORY` (multiset equality) |
| `alu` | one per ALU operation | provides `ALU` `(op, a, b, c)` |
| `range`, `nibble` | 256 rows each, preprocessed | provide byte range checks, powers of two, 4-bit AND/OR/XOR |
| `poseidon2` | 32-row blocks, one row per round | provides `POSEIDON2` `[in0..7, out0..7]` |
| `input` | one per private input word | provides `INPUT_DIGEST` and `INPUT_READ` |
| `keccak` (M4.2) | 32-row blocks, 24 rounds + 8 idle rows | provides `KECCAK` `(clk, ptr)`, sends its own `MEMORY` traffic |

The cpu trace begins with **digest rows**: they absorb the program words (through `PROGRAM_WORD`)
and then the salted private inputs (through `INPUT_DIGEST`) into the Poseidon2 chip and publish
`hc` and `H_IN`. A constraint forces the digest multiplicity of every valid program row to be
exactly one, which turns the bus balance into a set equality: no reachable instruction can be
left out of `hc`.

**Two invariants** every table obeys, each named for a bug that once existed: every bus message
column is constrained on every row kind that sends it; and a bus count is forced to zero
wherever its message columns are unconstrained. Every constraint has a cheating test that
tampers a trace and expects a rejection from the constraint checker or the verifier, never from
a trace-builder assertion (`tests/cheating.rs::rejects`).

**The STARK.** Plonky3 0.7 batch STARK, hiding FRI (the low-degree extension and the FRI batch
polynomial are randomized, so two proofs of one run differ; statistical zero knowledge), folding
arity 8, 27 queries plus 20 proof-of-work bits for a conjectured 101-bit soundness target. Every
table's maximum constraint degree is pinned by a test under the cap of 8 that `log_blowup = 3`
allows.

**Verification.** `Machine::verify(hc, proof)` checks the 26 public values are canonical, `HC`
equals `hc`, the tier is valid, the proof-declared heights (`program_log_height`,
`input_log_height`, and `keccak_log_height` since M4.2) are in range and match the proof's degree
bits, then runs the batch verifier. The verifier key depends only on `(tier, heights)`, never on
program content, and is cached; a warm verify is about 16 ms.

## 6. Programs

**Hand-assembled.** `asm.rs` provides mnemonic helpers and routines; the crate's guests
(`fib`, `balance_check`, `private_payment`, `transfer`, `bundle`, `keccak_demo`, …) are built
this way. `Program { base_pc, words }`.

**Compiled.** `#![no_std]` Rust for `riscv32im-unknown-none-elf`, linked with
`guest-sdk/guest.ld` at `0x1000` with a 64 KiB stack, converted with `llvm-objcopy -O binary`,
and loaded by `Program::from_flat_binary(base_pc, bytes)`, which checks the length, alignment,
size and that every word decodes. `_start` sets `sp` to `__stack_top`, calls `main`, then halts.
`guest-sdk` wraps the syscalls (`read_input`, `write_output`, `poseidon2`, `keccak`,
`keccak256`, `halt`); pointers passed to `poseidon2`/`keccak` are converted to word addresses by
the SDK. Compiled guests are committed as `.bin` files with a `Makefile`.

**Identity.** `hc = Poseidon2(HC domain, base_pc, len; words)` with the domain, base address and
length folded into the sponge capacity, computed in circuit. `hc` is binding but not hiding:
anyone who can guess a program can confirm it.

## 7. Inputs and outputs

Private inputs are a vector of words. `H_IN = Poseidon2(IN domain, n_in; salt, inputs)` with a
128-bit per-proof salt, so it is hiding as well as binding. `READ_INPUT` is a lookup against the
committed input table; a program that wants an input to be public absorbs it into an output.

Outputs are eight public words. The shielded `bundle` guest uses them for one digest of its 47
public plaintext words (anchor, nullifiers, commitments, fee, burn, asset, time, and the taint
word the ledger fixes to zero); a confidential call uses them as the call's result.

## 8. Cost

Measured, at the test profile on the development laptop (`research/docs/06-viewing-keys.md`,
`docs/confidential.md`):

| guest | program words | cycles | tier | proof | prove |
|---|---|---|---|---|---|
| `private_payment` (call) | small | < 1 000 | 10 | ~435 KB (production profile) | 7.4 s |
| `bundle`, 2-in-2-out | 3 811 | ≈ 9 160 incl. digest rows | 14 | ~300 KB | ≈ 100 s |
| `bundle`, 1-in-1-out with dummies | 3 811 | ≈ 6 920 | 14 | ~300 KB | ≈ 100 s |

Proving is a wallet-side cost paid once; verification is the consensus cost paid by every node.

## 9. Soundness notes worth knowing

- Every load/store address, hash pointer and keccak pointer is range-bounded below `2³⁰`.
- Never-written output slots are pinned to zero; a slot cannot be written twice.
- The program digest covers every valid program row (set equality), so a computed jump into
  undigested code is impossible.
- Two reads of one input index return one word; the input digest and the reads use two separate
  buses so a prover cannot shrink the digested set while still answering reads.
- The `bundle` guest has no in-circuit assert: violated relations taint a word the ledger fixes
  to zero, which makes the proof's digest irreproducible rather than the proof invalid.

## 10. Where to read more

`research/docs/01-isa.md` (encodings, selectors, loader), `02-tables-and-buses.md` (every column
and bus), `03-privacy.md` (what a proof leaks, the FRI profile), `04-guests.md` (the M4 plan),
`05-roadmap.md` (milestones and deviations), `06-viewing-keys.md` (the note layer and the
`bundle` relation); this repository's `docs/confidential.md` and `docs/shielded.md`.
