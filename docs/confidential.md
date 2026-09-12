# Confidential computation

SHRUGG pays for confidential calls: a program runs off-chain inside the Rand zkVM on private inputs,
and only a STARK proof plus eight public output words go on chain. Every node verifies the proof,
charges gas, and stores a receipt.

Since phase S1 a call **pays through a shielded bundle**, not from an account. `Deploy` and `Call`
are actions on an ordinary shielded transaction whose bundle is a self-transfer of zero: it exists
to pay the action's fee floor out of the caller's own notes, and the chain never learns whose they
were. The call proof and the bundle proof are separate objects and both are verified
(`docs/shielded.md`, `docs/architecture.md` §9). The consequence for programs: **effect kind 1 —
the program-driven transfer to a recipient — is deleted**, along with the recipient list a call
used to carry, because there are no accounts to pay. A program that paid `recipients[i]` must be
rewritten to publish what it decided and let the caller move the value in the bundle.

## The zkVM

`crates/shrugg-zkvm` (vendored from `circuits/research`, upstream `rand_zkvm`): an RV32I subset,
plus the RV32M extension and sub-word loads/stores (constraint set 3, below), proven by a
Plonky3 batch STARK over Goldilocks with Poseidon2 hashing and ZK-hiding FRI. Eight tables
(program, cpu, memory, alu, range, nibble, poseidon2, input — the last added in constraint set 4,
below), plus a ninth, `keccak`, that a proof carries only when its guest called the `KECCAK`
syscall (constraint set 5, below), connected by LogUp/permutation buses. Five syscalls:
`read_input(i)` (private input word, bound since constraint set 4 to a salted commitment `H_IN`),
`write_output(slot, word)` (one of eight public outputs), `poseidon2(ptr, n)` (in-place hash of
`n` words), `keccak(ptr)` (one in-place Keccak-f[1600] permutation, constraint set 5), `halt`.

Gas tiers pad the execution trace: tier `t` (10, 12, ..., 20) proves up to `2^t - 1` cycles and the
proof reveals only the tier, never the real cycle count. Production FRI profile: blowup 8, **80
queries, 20 PoW bits** — the whitepaper's own Part III parameters, restored in constraint set 5
after the 2026-09-12 zk audit; constraint sets 3 and 4 ran at 27 queries (see `docs/03-privacy.md`
in the upstream `research` crate for the full retune-and-revert history).

Measured upstream on `guests::fib` at tier 10: at constraint set 3, prove 3.1 s, proof 268 KB,
first (uncached) verify 16 ms. At constraint set 5 the proof is ~1 202 416 bytes and the first
verify ~233 ms, with prove time unchanged within noise — the query count moves bytes, not work.
The verifier key itself is what a cached verify amortizes away; see "Constraint set 3" and
"Constraint set 5" below for the full before/after.

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

**Constraint set 4 (2026-09-11, upstream 8667928: milestone 4.1).** The vendored zkVM was
re-synced past constraint set 3 to `research`'s milestone 4.1 (compiled guests, `docs/superpowers/
plans/2026-09-11-zkvm-m4-1.md`). The headline changes:

- **`READ_INPUT` is bound to a salted commitment, `H_IN`.** Through constraint set 3, a guest's
  `read_input(idx)` syscall returned whatever word the prover chose to supply, unconstrained —
  nothing tied two reads of the same index together, and nothing stopped a cheating prover from
  answering the same index differently on different cycles. An eighth table, `input` (one row per
  committed private-input word), fixes this: every `READ_INPUT` and the digest's own mandatory
  absorption draw `(idx, word)` from that table over two separate LogUp buses, `INPUT_DIGEST`
  (count `IS_REAL`, the digest's sole and unconditional source) and `INPUT_READ` (count
  `IS_REAL * MULT_READ`, `SYS_READ`'s sole source) — split, rather than shared, so the two
  consumer classes cannot trade budget with each other (an earlier single-bus design let a
  prover under-supply the digest's mandatory copy while a genuine read still succeeded). The cpu
  table's `IS_INDIGEST` rows absorb the committed vector into `H_IN` the same way the existing
  `IS_DIGEST` rows absorb the program into `hc`, published as `pv::IN0..7`. `H_IN` is **salted**
  (four witness words, drawn fresh per proof from OS entropy, absorbed ahead of the real input
  words) — unlike `hc`, which has no salt of its own — precisely so it is hiding as well as
  binding: a verifier who can enumerate candidate input vectors gets nowhere testing them against
  a published `H_IN`, since the salt never leaves the prover. `H_IN` alone makes no input word
  public; it only makes repeated reads of the same index consistent and an out-of-range read
  (`idx >= n_in`) unsatisfiable — a guest that wants an input word public still has to
  `write_output` it itself. The prover must draw a fresh salt every proof (`Machine::prove`, never
  `Machine::prove_salted` outside tests that deliberately need a fixed one to check against, or
  hiding is lost) — `ZkExecutor`'s prover entry point (`executor::prove`) does this already, since
  every backend it can select routes through `Machine::prove`/`Machine::prove_on`, both of which
  draw fresh entropy internally.
- **`pv::NUM` grew from 18 to 26**, and `Proof` gained a new field, `input_log_height: u8` — the
  `input` table's declared height, exactly analogous to `program_log_height` (proof-declared, not
  tier-derived; `tables::input::input_log_height`'s doc comment mirrors `tables::program::
  program_log_height`'s rule). `Machine::verifier_key` and `log_ext_degrees` grew from a
  `(tier, program_log_height)` 2-tuple key to a `(tier, program_log_height, input_log_height)`
  3-tuple; the injected `log_ext_degrees_pub` wrapper and every verifier-key lookup in
  `ZkExecutor` (`verify_call`'s degree-bits pre-check, `warm`) grew the same third argument.
  `pv::HC0..HC7`'s offsets (10..17) are unaffected — `pv::IN0..7` (18..25) was appended after
  them, not inserted before.
- **A flat-binary loader, `Program::from_flat_binary`,** and real compiled guests. Through
  constraint set 3, every guest was hand-assembled against `asm.rs`'s mnemonic helpers; M4.1 adds
  a `riscv32im-unknown-none-elf`-targeted toolchain (upstream's `guest-sdk`/`guests-compiled/`,
  not vendored into this crate — this crate has no use for compiling new guests at runtime, only
  for loading an already-compiled one) and a loader that turns a flat little-endian instruction
  image plus a base `pc` into a `Program`, rejecting anything that doesn't decode
  (`isa::LoadError`). `guests::compiled::fib()` (mirroring upstream's module, with its
  `include_bytes!` path adjusted for this crate's shallower layout) loads the vendored
  `guests-compiled/bin/fib.bin` this way; `tests/e2e.rs`'s `compiled_fib_matches_the_hand_written_
  guest` and `compiled_fib_proves_and_verifies` (vendored wholesale) exercise it end to end.
  Measured upstream (`fib(20)`, compiled, `Tier(10)`, 136 cycles): proof size 271,600–275,889
  bytes over three proofs (varies per proof with the hiding salt).
- **Tiers, FRI parameters and every other table are unchanged** from constraint set 3 — this is
  purely an input-commitment and loader addition, not a re-tune.

Proofs made under constraint set 3 (or earlier) do not verify under constraint set 4 — `pv::NUM`
grew, the batch grew from seven AIRs to eight, and `Proof` gained a field (`input_log_height`), so
neither the public-values shape nor the wire encoding round-trips against the old one. This is the
same hard-fork situation constraint sets 2 and 3 already documented: a node built from this commit
will fail startup ledger replay of any chain with a confidential call proved under an older
constraint set and truncate its chain. Start a new chain id, or run `--verify-chain off` on nodes
that must keep serving an old chain.

**Disclosure implication.** `H_IN` is a commitment, not encryption: it is binding and (thanks to
the salt) hiding against a verifier who only ever sees the published `pv::IN0..7`, but it is not
hiding against a party the caller chooses to show the salt and the input vector to — the same
"binding, revocably hideable" shape as any Pedersen/Poseidon2 commitment. A caller who retains the
salt (and the inputs) can, at any later time, open `H_IN` to a third party by handing over both —
proving after the fact exactly which private inputs a given call used, without any further
proving. This is a capability, not a flaw (auditability on demand, without a second proof), but it
means "private" here means "not disclosed unless the salt-holder chooses to disclose it," not
"provably undiscoverable" — see the shielded pool spec §6.1 for how the shielded-pool design
budgets for this when a bundle's own note commitments and nullifiers (which have their own,
separately-managed disclosure story) sit downstream of a call whose `H_IN` the caller could later
open.

**Constraint set 5 (2026-09-12, upstream ffd9e1e: milestone 4.2 + audit port + FRI 80).** The
vendored zkVM was re-synced past constraint set 4 to `research`'s milestone 4.2, which also
carries the 2026-09-12 zk audit's findings back into the crate they were vendored from. The
headline changes:

- **A ninth table, `keccak` (Keccak-f[1600]), and a fifth syscall, `KECCAK` (number 4).** A guest
  calls `call_keccak(ptr_words)` and the chip permutes the 50-word state at that word address in
  place, reading and writing the words itself over the `MEMORY` bus and answering the cpu row over
  a new `KECCAK` bus. The table is 32-row blocks (24 rounds plus 8 idle rows) and **2 612 columns
  wide**. The host reference is `keccak.rs` (`keccak256`, `keccak_f`), checked against `p3_keccak`
  on 1 000 random states; a compiled guest, `guests::compiled::keccak256()`, hashes a message
  through the syscall end to end. The sponge itself stays in guest code — the chip proves the
  permutation only.
- **The keccak table is optional per proof.** `Proof` gained `keccak_log_height: u8`, where `0`
  means the proof declares *no* keccak table at all: `machine::chips` then returns eight chips,
  not nine, and the degree-bit vector is eight entries long, so `verify`'s existing degree-bits
  equality check also pins the batch's instance count. This matters because a 2 612-column table
  costs about **1.91 MB** of a production proof's FRI leaf openings *regardless of how few rows it
  holds* — every query opens a full-width main-trace leaf, so the table's width, not its height,
  is what a proof pays for. With the table in every proof a keccak-free tier-10 proof measured
  1 142 262 bytes (at 27 queries); optional, it is back to 439 816 bytes, within half a percent of
  its pre-M4.2 size. No guest this chain deploys calls `KECCAK`, so every proof on this chain
  declares `keccak_log_height = 0`.
- **`mem_log_height` is proof-declared too**, and both new heights are untrusted words checked
  before anything is sized from them. `machine::check_declared_heights` is the single place that
  does it — tier in `TIERS`, then `program_log_height`, then `input_log_height`, then the keccak
  table's flat range `[5, 20]`, then the keccak-vs-tier relation `klh ≤ tier + 5` (a permutation
  costs a cycle), then `mem_log_height ∈ [tier + 2, 24]`. `ZkExecutor::decode_and_check` calls
  that same function rather than restating its rules, so the chain's admission bound on a proof's
  declared shape *is* the verifier's.
- **`Machine::verifier_key` is four-keyed**, `(tier, program_log_height, input_log_height,
  keccak_log_height)`; `log_ext_degrees` takes a fifth argument, the declared `mem_log_height`.
  The memory height is deliberately absent from the key: the memory table declares no preprocessed
  and no periodic columns, so every valid declared height yields the same `CommonData`. The
  injected `log_ext_degrees_pub` wrapper and every verifier-key lookup in `ZkExecutor`
  (`decode_and_check`'s degree-bits pre-check, `warm`, `warm_bundle`) follow.
- **The 2026-09-12 zk audit, ported upstream and re-vendored.** Two Critical soundness fixes in
  the cpu table: hash row-groups now have *entry* gates (an absorb row may only follow the ecall
  row or another absorb row; a write-back row only the ecall row, an absorb row, or the first
  write-back row; nothing follows the second) — without them a free-standing `IS_HASH` row spliced
  after any ordinary row gave arbitrary RAM writes at an unbounded `HASH_PTR` — and `HASH_FIN` is
  pinned to write-back rows (`HASH_FIN·(1 − IS_HASH_OUT) = 0`), closing the same hole one row
  later. Then: the memory table's sort key is computed by *addition* (`SPACE·2^30 + ADDR`, not
  `|`), so an honest run whose Poseidon2-derived addresses cross `2^30` can actually be proved;
  `Instr::encode` asserts every immediate's range instead of silently truncating it into wrong
  code; the emulator rejects a Poseidon2 pointer at or above `2^30`, matching the AIR's own bound;
  the auto-tier pick fits the Poseidon2 *permutation* budget as well as the cycle budget; and a
  program or private-input vector longer than 65 535 words is rejected at prove time (the digest
  rows' `HASH_LEFT` is a 16-bit value, so a longer one is unprovable at any tier) as is an
  explicit tier outside `TIERS`.
- **The production FRI profile is back to the whitepaper's: 80 queries, blowup 8, 20 PoW bits.**
  The 27-query retune constraint sets 3 and 4 ran on met the ethSTARK *conjectured* 100-bit target
  (`3·27 + 20 = 101`) but left only ~42 *proven* proximity-gaps bits; 80/8/20 gives ~86 proven and
  260 conjectured, and the whitepaper's Part III reconciliation had already weighed exactly that
  trade. Measured on `guests::fib` immediately before and after the revert, same machine
  (`research/docs/03-privacy.md`):

  | | tier 10 | tier 12 |
  |---|---|---|
  | proof size, 27 queries | 435 529 bytes | 460 441 bytes |
  | proof size, 80 queries | **1 202 416 / 1 195 120 bytes** | **1 252 338 / 1 263 921 bytes** |
  | prove time (27 → 80) | 5.96 s → 6.05 s, 5.81 s | 22.91 s → 22.78 s, 22.74 s |
  | first (uncached) verify (27 → 80) | 213.2 ms → 232.7 ms | 809.2 ms → 837.5 ms |

  Two 80-query numbers are given per cell because the hiding PCS draws fresh entropy per proof, so
  the postcard encoding moves about a percent run to run. Proof size grows ~2.75x, a little under
  the 80/27 = 2.96 the query count alone suggests; prove and first-verify time barely move, since
  both are dominated by trace commitment and the uncached verifier-key recomputation, costs the
  query count does not touch. A keccak-*carrying* tier-10 proof measures 3 106 757 bytes.

**`MAX_PROOF_BYTES` is 2 MiB** (`crates/shrugg-core/src/gas.rs`), raised from 1 MiB in the same
change: at 80 queries the 1 MiB cap rejected *every* production proof. 2 MiB is the smallest
power-of-two cap above the measured sizes with room for the per-proof variation, and it sits
deliberately below the ~3.11 MB a keccak-bearing proof costs. **`MAX_BLOCK_BYTES` stays 4 MiB** —
`docs/block-space.md` §5 records that decision: at ~1.3 MB per shielded transfer that is three
transfers per block, and block-level aggregation rather than a bigger block is the queued remedy.

Proofs made under constraint set 4 (or earlier) do not verify under constraint set 5, in either
direction — the FRI profile differs (a 27-query proof and an 80-query verifier reject each other),
`Proof` gained two fields (`keccak_log_height`, `mem_log_height`) so the wire encoding does not
round-trip, and the verifier key is keyed on four components instead of three. This is the same
hard-fork situation constraint sets 2, 3 and 4 already documented: a node built from this commit
will fail startup ledger replay of any chain with a confidential call proved under an older
constraint set and truncate its chain. Start a new chain id, or run `--verify-chain off` on nodes
that must keep serving an old chain. A fleet must run one build.

## On-chain model

**Programs** are content addressed: `program_id = blake3("shrugg-program" || base_pc || words)`.
A `Deploy` transaction stores `{ base_pc, words }` (at most 4096 words); every word must decode as an
instruction. Programs are immutable and part of the state root.

**Calls** carry `{ program, proof }`. The proof is `postcard(rand_zkvm::Proof)` (tier, public
values, batch STARK proof). There is no recipient list: it existed only for effect kind 1.

**Outputs.** The eight output words are published data, not an instruction to the chain. They are
recorded in the receipt verbatim and nothing follows from them; `out0..out7` mean whatever the
program and its caller agree they mean. The old layout (`out0` effect kind, `out1` recipient index,
`out2|out3` a little-endian u64 amount) survives only as a convention inside guests like
`private_payment`, which still writes `[1, 0, amount_lo, amount_hi, …]`; on this chain that is a
statement, not a payment.

**Receipts** `{ tx, program, tier, outputs, height, index }` are stored per call and served by
`shrugg_getReceipt`; they are recomputed and checked when a node syncs or verifies its chain. There
is no `effect` field.

## Validity rules

- Both: the transaction carries a bundle, and that bundle passes the shielded admission order
  (`docs/shielded.md` §5) — anchor in the 256-block window, neither note already spent, the
  recomputed digest equal to what the bundle proof published, and the bundle proof valid against
  the genesis-pinned `hc_bundle`.
- Deploy: `words.len() <= 4096`, `base_pc % 4 == 0`, every word decodes,
  `fee >= BUNDLE_BASE + 100_000 * words`.
- Call: program exists; `proof.len() <= 2 MiB` (`gas::MAX_PROOF_BYTES`, raised for constraint
  set 5's proof sizes); the proof verifies against the stored program's
  `hc` for the tier it declares; `fee >= BUNDLE_BASE + call_fee(tier)`, checked last, once a
  verified proof has revealed the tier.
- A block with an invalid call is invalid, like any other invalid transaction.

## Gas (v0)

| operation | minimum fee |
|---|---|
| any bundle (`BUNDLE_BASE`) | 0.001 SHRUGG |
| shielded transfer | 0.001 SHRUGG (the base alone) |
| Deploy | 0.001 SHRUGG + 100,000 units per word (0.0266 SHRUGG for 256 words) |
| Call | 0.002 SHRUGG at tier 10, plus 0.0001 SHRUGG per two tiers above it (0.0025 at tier 20) |
| Mint (faucet) | free, and carries no bundle |

Every floor above the mint's includes `BUNDLE_BASE`, because every one of those transactions
carries a bundle. Anything above the minimum is a tip; all of it is credited to the block
proposer's `rewards` in the validator register, which phase S2's `Withdraw` turns back into a note.
Blocks hold at most 4 MiB of transactions, and a bundle proof is ~300 KB, so roughly a dozen
shielded transactions per block. Constants live in `shrugg_core::gas`; `shrugg fee bundle|deploy
<words>|call <tier>` asks the node.

## Privacy

Public: program id, tier, the eight outputs, the bundle's fee, and — since constraint set 4 — the
salted input commitment `H_IN` (`proof.public_values[
IN0..IN7]`). `H_IN` being public does not make any input word public: without the salt (never
published, never leaves the prover) it cannot be opened, so on its own it only pins two reads of
the same input index to agree and makes an out-of-range read unsatisfiable — see "Disclosure
implication" above for what happens if a caller later reveals the salt. Private: inputs, registers,
memory, branches taken, cycle count (padded to the tier), the `H_IN` salt itself — and, since S1,
*who called it and what they paid with*: the bundle publishes two nullifiers and two commitments
and names nobody. Two proofs of the same run are different bytes (hiding commitments), so proofs do
not fingerprint inputs.

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
