# Confidential computation

RAND pays for confidential calls: a program runs off-chain inside the Rand zkVM on private inputs,
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

`crates/randprotocol-zkvm` (vendored from `circuits/research`, upstream `rand_zkvm`): an RV32I subset,
plus the RV32M extension and sub-word loads/stores (constraint set 3, below), proven by a
Plonky3 batch STARK over Goldilocks with Poseidon2 hashing and ZK-hiding FRI. Nine mandatory
tables (program, cpu, memory, alu, range, nibble, poseidon2, input, public — `input` added in
constraint set 4, `public` in constraint set 6, below), plus a `keccak` and a `sha256` table a
proof carries only when its guest called the matching syscall (sets 5 and 6), connected by
LogUp/permutation buses. Seven syscalls: `read_input(i)` (private input word, bound since
constraint set 4 to a salted commitment `H_IN`), `write_output(slot, word)` (one of eight
public outputs), `poseidon2(ptr, n)` (in-place hash of `n` words), `keccak(ptr)` (one in-place
Keccak-f[1600] permutation, constraint set 5), `sha256(ptr)` (one in-place SHA-256 compression,
arrived with constraint set 6's re-vendor), `read_public(i)` (public input word, bound to the
unsalted `H_PUB`, constraint set 6), `halt`.

Gas tiers pad the execution trace: tier `t` (10, 12, ..., 20) proves up to `2^t - 1` cycles and the
proof reveals only the tier, never the real cycle count. Production FRI profile: blowup 8, **80
queries, 20 PoW bits** — the whitepaper's own Part III parameters, restored in constraint set 5
after the 2026-09-12 zk audit; constraint sets 3 and 4 ran at 27 queries (see `docs/03-privacy.md`
in the upstream `research` crate for the full retune-and-revert history).

Measured upstream on `guests::fib` at tier 10: at constraint set 3, prove 3.1 s, proof 268 KB,
first (uncached) verify 16 ms. At constraint set 5 the proof is ~1 202 416 bytes and the first
verify ~233 ms, with prove time unchanged within noise — the query count moves bytes, not work.
Constraint set 6's mandatory public table and wider cpu table add a few percent to those bytes
(see "Constraint set 6" below for the measured deltas); prove and verify are unchanged in kind.
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
  `randprotocol-core`'s `programs` RPC already serves `code_hash` as hex; nothing there changed.
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

**The call-input envelope** (spec §6.1, phase S3) is that opening, made durable: a caller who keeps
the salt in its own head has a capability it loses with the next laptop, so `rand call` publishes
the `(salt, inputs)` transcript on chain by default, sealed so that the caller, a per-call key or a
named auditor can open it later. See "Call input envelopes" below for the format and the rules.

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

**`MAX_PROOF_BYTES` is 2 MiB** (`crates/randprotocol-core/src/gas.rs`), raised from 1 MiB in the same
change: at 80 queries the 1 MiB cap rejected *every* production proof. 2 MiB is the smallest
power-of-two cap above the measured sizes with room for the per-proof variation, and it sits
deliberately below the ~3.11 MB a keccak-bearing proof costs. **`MAX_BLOCK_BYTES` stays 4 MiB** —
`docs/block-space.md` §5 records that decision: at ~1.3 MB per shielded transfer that is three
transfers per block, and block-level aggregation rather than a bigger block is the queued remedy.
(Both are now genesis parameters with these values as defaults; chain 13 raises them to 8 MiB and
20 MiB: [Call limits and a program's public input](#call-limits-and-a-programs-public-input).)

Proofs made under constraint set 4 (or earlier) do not verify under constraint set 5, in either
direction — the FRI profile differs (a 27-query proof and an 80-query verifier reject each other),
`Proof` gained two fields (`keccak_log_height`, `mem_log_height`) so the wire encoding does not
round-trip, and the verifier key is keyed on four components instead of three. This is the same
hard-fork situation constraint sets 2, 3 and 4 already documented: a node built from this commit
will fail startup ledger replay of any chain with a confidential call proved under an older
constraint set and truncate its chain. Start a new chain id, or run `--verify-chain off` on nodes
that must keep serving an old chain. A fleet must run one build.

**Constraint set 6 (2026-09-14, upstream 0200877: the public input segment, carrying milestones
4.3 + 4.4).** The vendored zkVM was re-synced past constraint set 5 to `research`'s
constraint-set-6 merge, which also brings milestones 4.3 (the EVM interpreter guest) and 4.4
(the SHA-256 table and the sBPF interpreter guest) into the crate. The headline changes:

- **A ninth *mandatory* table, `public` — the public input segment — and a seventh syscall,
  `SYS_READ_PUBLIC` (number 6).** A second, independently indexed input vector the guest reads
  with `read_public(idx)`, committed to `H_PUB` (`pv::PUB0..7`): a Poseidon2 digest of the
  segment with capacity header `[PUB(15), n_pub, 0]`, computed by the cpu table's new
  `IS_PUBDIGEST` row prefix exactly the way `IS_INDIGEST` computes `H_IN`. The buses mirror the
  input table's pair — `PUBLIC_DIGEST` (the digest's sole source) and `PUBLIC_READ` (the
  syscall's sole source, count `MULT_READ`) — sixteen buses in all. Unlike `H_IN`, **`H_PUB` is
  unsalted**: the words are meant to be published with the transaction, so a verifier holding
  them recomputes the digest natively and compares — `Machine::verify_public(hc, public_words,
  proof)`. The table is mandatory, not a third optional hash chip: every proof commits to a
  public segment even when it is empty (four rows, `public_log_height = 2`, the fixed
  header-only digest), because the segment is where a guest reads data the chain itself
  publishes — upstream's sBPF guest reads its whole ELF from it, dropping M4.4's in-circuit hash
  of a hiding commitment (1 753 945 → 694 498 cycles).
- **`pv::NUM` is 34 and the cpu table is 275 columns** (was 26 and 224): the eight `PUB0..7`
  public values and the pubdigest region's columns. The existing `pv` slots (`OUT0`, `HC0`,
  `IN0`) do not move, and `H_PUB` binds `SYS_READ_PUBLIC` exactly the way `H_IN` binds
  `SYS_READ_INPUT` — 17 new cheating tests upstream pin the table and its digest region.
- **`Machine::verifier_key` is a 6-tuple**, `(tier, program_log_height, input_log_height,
  keccak_log_height, sha256_log_height, public_log_height)`; `log_ext_degrees` takes a seventh
  argument, the declared `mem_log_height` (still deliberately absent from the key). The injected
  `log_ext_degrees_pub` wrapper and every verifier-key lookup in `ZkExecutor` follow, and
  `check_declared_heights` gained the sha256 pair (flat range, then the sha256-vs-tier relation
  — the keccak table's exact terms) plus a plain range check on the public height (mandatory,
  so there is no `0` escape). `ZkExecutor::decode_and_check` still delegates to that same
  function, so the chain's admission bound on a proof's declared shape *is* the verifier's.
- **M4.4's `sha256` table and `SHA256` syscall (number 5) ride along, optional per proof on the
  keccak table's exact and independent terms**: `sha256_log_height == 0` means no sha256 table
  (the batch is then nine instances; ten with one hash chip, eleven with both). The chip is
  466 + 10 columns, 64-row blocks, one compression in place over 24 words; a proof carrying it
  measures +92 307 bytes at `FriProfile::Test` and +400 563 at the production profile (upstream,
  same guest, instance in versus out). No guest this chain deploys calls either hash syscall, so
  every proof here declares both heights `0`.
- **M4.3/M4.4's interpreter guests arrive as libraries and test fixtures, not as deployed
  guests.** `src/evm.rs` (the EVM host side: `HostRef`, the Poseidon2 sparse storage tree,
  `EvmCall`) and `src/sbpf.rs` (the sBPF host side and the committed SPL Token ELF) are vendored
  with `evm-core`/`sbpf-core` as *path* dependencies (beside the repo, like `rand-zkvm-cuda`,
  but not optional — `circuits/` must sit beside `fullnode/` for any build of the crate), and
  the compiled `evm.bin`/`sbpf.bin` beside `fib.bin`/`keccak256.bin`. Their test suites
  (`tests/evm_*.rs`, `tests/sbpf_*.rs`, `tests/sha256.rs`, the grown `tests/e2e.rs`) are vendored
  wholesale as always, because they are the upstream authority on the machine's behaviour; the
  EVM tier-16 call proof in `e2e.rs` is part of this suite now.
- **The chain admits only the empty public segment.** No transaction on this chain publishes
  public words, so `ZkExecutor::verify_call` and `verify_bundle` both run
  `Machine::verify_public(hc, &[], proof)`, pinning `H_PUB` to `hash::public_digest(&[])`. Plain
  `verify` would leave `pv::PUB0..7` unchecked against anything outside the proof — bound
  in-circuit to a public segment the chain never saw — and every honest proof by today's guests
  (none of which calls `SYS_READ_PUBLIC`) has the empty segment anyway, so the stronger check
  costs nothing. A future action type that publishes words (a public-ELF program in the upstream
  sBPF shape is the obvious one) would pass them in place of `&[]`. (That is now the deploy's
  public input: a call is checked against the digest recorded at deploy, and a program deployed
  without one still against the empty segment's. See [Call limits and a program's public input](#call-limits-and-a-programs-public-input).)
- **`MAX_PROOF_BYTES` stays 2 MiB.** Measured on this tree
  (`cargo test -p randprotocol-zkvm --release --test e2e
  measure_production_profile_at_tier_10_and_12 -- --ignored --nocapture`): a keccak-free
  production proof is 1 298 729 bytes at tier 10 and 1 359 978 at tier 12 (constraint set 5 measured
  1 202 416 / 1 252 338 — the delta is the mandatory public table, the 51 new cpu columns and
  the eight new public values), and a keccak-carrying tier-10 proof is 3 198 430 (set 5:
  3 106 757). The cap keeps both of its constraint-set-5 properties: every hash-table-free proof
  the deployed guests can produce fits, with room for the hiding PCS's ~1% per-proof variation,
  and a keccak-bearing proof is still refused outright.

Proofs made under constraint set 5 (or earlier) do not verify under constraint set 6, in either
direction: `pv::NUM` 26 → 34 changes the public-values vector every proof carries, `Proof`
gained two fields (`sha256_log_height`, `public_log_height`) so the wire encoding does not
round-trip, the verifier key is six-keyed instead of four, and the AIR itself changed (the
pubdigest row region, the public table, its two buses). This is the same hard-fork situation
constraint sets 2–5 already documented: a node built from this commit will fail startup ledger
replay of any chain with a confidential call proved under an older constraint set and truncate
its chain. Start a new chain id, or run `--verify-chain off` on nodes that must keep serving an
old chain. A fleet must run one build.

## On-chain model

**Programs** are content addressed: `program_id = blake3("rand-program" || base_pc || words)`,
or, for a program deployed with a public input,
`blake3("rand-program-2" || base_pc || u32_le(len(words)) || words || u32_le(len(public)) || public)`.
A `Deploy` transaction stores `{ base_pc, words, public }` (at most the chain's program cap: 4096 words, or
the genesis file's `max_program_words`, at most 65 535, when it sets one; `public` at most
`max_program_public_words`, 0 unless the genesis sets it); every word must decode as an
instruction. Programs are immutable and part of the state root. The record keeps `public_len`
and `public_digest` (`H_PUB` of the public words); the node keeps the words themselves and serves
them with `rand_getProgramPublic`.

**Calls** carry `{ program, proof }`. The proof is `postcard(rand_zkvm::Proof)` (tier, public
values, batch STARK proof). There is no recipient list: it existed only for effect kind 1.

**Outputs.** The eight output words are published data, not an instruction to the chain. They are
recorded in the receipt verbatim and nothing follows from them; `out0..out7` mean whatever the
program and its caller agree they mean. The old layout (`out0` effect kind, `out1` recipient index,
`out2|out3` a little-endian u64 amount) survives only as a convention inside guests like
`private_payment`, which still writes `[1, 0, amount_lo, amount_hi, …]`; on this chain that is a
statement, not a payment.

**Receipts** `{ tx, program, tier, outputs, height, index, h_pub }` are stored per call and served by
`rand_getReceipt` (`h_pub` is the program's public digest, `null` for a program without a public
input); they are recomputed and checked when a node syncs or verifies its chain. There
is no `effect` field.

## Validity rules

- Both: the transaction carries a bundle, and that bundle passes the shielded admission order
  (`docs/shielded.md` §5) — anchor in the 256-block window, neither note already spent, the
  recomputed digest equal to what the bundle proof published, and the bundle proof valid against
  the genesis-pinned `hc_bundle`.
- Deploy: `words.len() <= max_program_words` (genesis; 4096 when the file does not set it, and never
  above 65 535, the word count the zkVM can prove), `base_pc % 4 == 0`, every word decodes,
  `public.len() <= max_program_public_words` (checked first, before any fee or code work),
  `fee >= BUNDLE_BASE + 100_000 * (words + public)`.
- Call: program exists; `proof.len() <= max_proof_bytes` (genesis; 2 MiB, `gas::MAX_PROOF_BYTES`,
  when the file does not set it: raised for constraint set 5's proof sizes, re-measured and kept at
  constraint set 6's); the input envelope within `max_call_envelope_bytes` (18 432 by default); the
  proof verifies against the stored program's `hc` for the tier it declares, and its `H_PUB`
  equals the program's recorded public digest (the empty input's for a program without one), or
  the call fails with `PublicValues`; `fee >= BUNDLE_BASE + call_fee(tier, bytes)`, checked last,
  once a verified proof has revealed the tier.
- Any transaction: its encoding at most `max_block_bytes` (4 MiB by default), and a block's
  transactions within the same cap.
- A block with an invalid call is invalid, like any other invalid transaction.

## Gas (v0)

| operation | minimum fee |
|---|---|
| any bundle (`BUNDLE_BASE`) | 0.001 RAND |
| shielded transfer | 0.001 RAND (the base alone) |
| Deploy | 0.001 RAND + 100,000 units per word (0.0266 RAND for 256 words) |
| Deploy with a public input | as Deploy, counting the public words with the code words |
| Call | 0.002 RAND at tier 10, plus 0.0001 RAND per two tiers above it (0.0025 at tier 20), plus 0.000001 RAND per KiB (or part) of call proof and input envelope past 2 097 152 + 18 432 bytes |
| BridgeAttest | 0.001 RAND (the base alone) |
| BridgeBurn | 0.01 RAND (`BRIDGE_BURN_FEE`) — the bridge fee; it covers the base for both of its bundles. A deposit (`BridgeAttest`) pays only the base: the depositor has no RAND yet |
| Mint (faucet) | free, and carries no bundle |

Every floor above the mint's includes `BUNDLE_BASE`, because every one of those transactions
carries a bundle. A `BridgeBurn` includes it *twice*: spec §7 item 3 charges the base per
bundle, and a burn is the one transaction that carries two — the RAND fee bundle and the
asset bundle inside the action — both of which every node verifies. The asset bundle's own
`fee` must be zero, so the RAND bundle pays for both.

Anything above the minimum is a tip; all of it is credited to the block proposer's `rewards` in
the validator register, which phase S2's `Withdraw` turns back into a note. Blocks hold at most
4 MiB of transactions on a chain without `max_block_bytes` (20 MiB on chain 13), and at constraint set 5's 80 queries a bundle proof is ~1.3 MB, so **three**
shielded transactions per block (it was roughly a dozen at 27 queries; `docs/block-space.md`). Constants live in `randprotocol_core::gas`; `rand fee bundle|deploy <words> [--public-words M]|call <tier> [--bytes B]`
asks the node.

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

## Call input envelopes

A call's private inputs are private because nothing published them — but the caller may want to be
able to *show* them later: to an auditor, to a counterparty, to itself on another machine. `H_IN`
makes that possible — it is a binding commitment to every word the guest read, and the salt is what
keeps anyone else from opening it — so the capability lives exactly as long as the caller keeps the
salt, which is to say not past the next laptop. The call-input envelope (spec §6.1) is that
disclosure written to the chain instead.

```
Action::Call { program, proof, input_envelope: Option<CallEnvelope> }

CallEnvelope { kem_ct: Vec<u8>, to_sender: Vec<u8>, to_auditor: Vec<u8>, body: Vec<u8> }
```

| part | bytes | what it is |
|---|---|---|
| `body` | 12 + 16 + 4·n + 16 | `salt \|\| inputs`, each word little-endian, sealed under a fresh per-call key `K_call` |
| `to_sender` | 60 | `K_call` wrapped to the caller's outgoing viewing key (`ovk`) |
| `kem_ct` | 1088 or 0 | an ML-KEM-768 encapsulation to the auditor's address, empty with no auditor |
| `to_auditor` | 60 or 0 | `K_call` wrapped under that encapsulation's shared secret |

Everything is ChaCha20-Poly1305 with a random 12-byte nonce prepended, and the domain tags
(`rand-call-sender`, `rand-call-auditor`) are distinct from the note layer's, so no wrap of one
kind is ever a wrap of another. `K_call` is drawn from OS entropy per envelope and is *not* derived
from any other key: handing one over says nothing about any other call.

**Three keys open it, and no more:**

| key handed over | who holds it | what it opens |
|---|---|---|
| the caller's viewing key (through `ovk`) | the caller's wallet | every call that wallet made |
| the per-call key `K_call` | the caller, and whoever it gave it to | that one call |
| the auditor's viewing key | the auditor named when sealing | that one call |

**What the chain does and does not do.** It checks the envelope's *size* and nothing else:
`max_call_envelope_bytes` from the genesis, 18,432 (`MAX_CALL_ENVELOPE_BYTES`) when the file does not
set it (`call_envelope::validate`, step 7 of admission). The wallet derives its input-word cap from
it: `(max_call_envelope_bytes − 1 252) / 4`, where 1 252 bytes is an envelope with an auditor and no
inputs — 4 295 words by default, 16 071 on chain 13's 65 536. It holds no key that opens any of it, never looks
inside, and serves it verbatim to anyone who asks (`rand_getCallEnvelope`, alongside the receipt's
`h_in`). (A viewing key imported for note scanning — `rand_importViewingKey`, `docs/shielded.md` —
opens *note* envelopes only; a caller's viewing key would open its own calls' sender wraps, but
nothing on the node tries: the scan runs over the commitment tree's leaves, and call envelopes are
not part of it.) The envelope is part of the transaction, so it is part of the transaction hash.

**What binds an envelope to its call** is the AEAD: the body's associated data is the 32 bytes of
`H_IN` as the receipt publishes them, so an envelope lifted onto another call authenticates for
nobody. **What makes an opened transcript faithful** is the holder's own recomputation —
`input_digest(salt, inputs) == H_IN` — because `H_IN` commits in-circuit to every word the guest
read. A caller who seals a transcript that is not the preimage is not stopped by the chain; they are
caught by whoever decrypts, who can show that decryption to anyone. `rand open-call` checks
exactly this, then re-runs the program on the recovered inputs through the emulator and compares the
outputs with the receipt's. Both checks are the command's **exit status**, not just a printed line:
an unfaithful transcript, or one whose words do not reproduce the receipt's outputs, exits non-zero,
so a script that opens a disclosure to check a claim cannot read a warning beside a zero exit as a
yes.

```bash
rand call <id> --input 400 --input 250 --auditor rand1q9f…   # seals for the caller and the auditor
rand call <id> --input 400 --print-call-key                    # also prints K_call
rand call <id> --input 400 --no-envelope                       # publishes nothing
rand open-call <txhash>                  # as the caller
rand open-call <txhash> --as-auditor     # as the auditor
rand open-call <txhash> --call-key <hex> # with the per-call key alone
```

`--no-envelope` is the deliberate opposite: nothing is published, and once the salt is gone nobody
— the caller included — can ever open that call. `--cuda` cannot seal one either: every backend but
the CPU draws the `H_IN` salt inside the prover and never returns it, so `rand call --cuda` fails
unless `--no-envelope` is passed with it. The forfeit is always asked for explicitly; a call is never
quietly downgraded to one.

Covered end to end by `a_call_envelope_is_opened_by_the_caller_and_the_auditor_only`
(`crates/randprotocol-node/tests/cluster.rs`), which opens the bytes a *node* served as the caller and as
the auditor, fails to open them as a third wallet that is neither, and catches both a tampered
transcript (the faithfulness check) and a tampered ciphertext (the AEAD).

## Call limits and a program's public input

Chain 13 (spec `docs/superpowers/specs/2026-09-19-call-limits-design.md`) makes four call limits
genesis parameters and lets a deploy fix a program's public input. A genesis without the fields
hashes, and behaves, exactly as before.

| field | absent | bounds | chain 13 |
|---|---:|---|---:|
| `max_proof_bytes` | 2 097 152 | 1 MiB ..= 32 MiB | 8 388 608 |
| `max_block_bytes` | 4 194 304 | 4 MiB ..= 64 MiB, ≥ 2 × `max_proof_bytes` + 1 MiB | 20 971 520 |
| `max_call_envelope_bytes` | 18 432 | 18 432 ..= 1 MiB | 65 536 |
| `max_program_public_words` | 0 | 0 ..= 65 535 | 32 768 |

- **Every proof cap follows `max_proof_bytes`**: the call's, each bundle's, the bridge burn's and
  the aggregate's. A keccak-carrying call proof (3 198 430 bytes at tier 10, production) fits
  under 8 MiB.
- **The node's transport limits follow the block cap**: the sync budget is `max_block_bytes + 2 MiB`,
  the sync reader limit twice that plus 256 KiB, and the gossip transmit size
  `max(16 MiB, max_block_bytes + 1 MiB)`. A default chain keeps 6 MiB, 12.25 MiB and 16 MiB.
- **A public input is fixed at deploy, never per call.** A proof's public input is visible to
  every verifier, so the chain accepts it once, with the program: every call to the program shows
  the same public words, already on chain since the deploy, and everything that varies per call
  goes through the private tape and the sealed envelope. The ledger records `H_PUB` at deploy and
  `verify_call` compares the proof's `pv::PUB0..7` with it after `verify`.
- **The wallet**: `rand program deploy <image> --public <words file | ELF>`; `rand call` fetches
  the public input, checks it against the program id, and proves over it; `--expect-public <FILE>`
  refuses before proving on a mismatch; a proof over `max_proof_bytes` is refused before the
  paying bundle is proved ([`cli.md`](cli.md#rand-wallet)).

The translated SPL Token (`docs/translators.md`) is the program this was built for: its image reads
the 27 151-word ELF from the public tape and 10 458 private words, so it needs all three raised
limits.

## Chains without confidential computation

Genesis `"confidential": false` makes Deploy and Call invalid; `"fri_profile"` selects
`production` (default) or `test` (16 queries, insecure, for the test suite). Both are part of the
genesis hash, so nodes with different settings cannot join the same chain.

## Guest programs

`rand program build --guest <name> --arg ...` assembles the built-in guests: `fib n`, `memcpy n`,
`bubble_sort v...`, `balance_check threshold`, `private_payment threshold`. Any RV32I program in the
supported subset can be deployed from a `.json` (`{ "base_pc", "words" }`), a raw `.bin`
(little-endian words, loaded from base 0), or a `.bin` produced by the sibling `circuits` repo's
`rand-guest build` — a real `riscv32im-unknown-none-elf` toolchain build, as opposed to a guest
assembled by hand against `randprotocol-zkvm::asm`.

`rand-guest build` emits the M4.3 **image container**: six little-endian header words
(`[0x444e4152, 1, text_base, n_text, data_base, n_data]`), then the guest's text, then its data
segment. `rand program deploy` recognises the container by its first word — `0x444e4152`
(`IMAGE_MAGIC`, `b"RAND"` read little-endian) never decodes as an RV32 instruction, so a raw
`.bin` can never be confused for one — and loads it the same way the prover does,
`isa::Program::from_flat_image`, which synthesises a prologue below the text that writes the data
segment into RAM before the guest's own code runs. That is what makes a compiled guest with a
`.rodata` (jump tables, panic locations, any constant LLVM did not rematerialise) deployable at
all: the M4.1 flat-binary loader populated instruction space only, so a guest with real data read
zeros. A file that starts with `IMAGE_MAGIC` but is not a well-formed container is a deploy error,
not a silent fallback to raw words.

Before proving anything, `program deploy` prints the program id, the word count, and `hc` — the
in-circuit `Program::digest`, hex-encoded the one way the chain ever shows it: the eight digest
words each in little-endian byte order, concatenated, the same form `rand_getProgram` and
`rand program show` print as `code_hash` (*not* `Program::code_hash()`'s own string, which hex-encodes
the same words big-endian and reads different for the same program). Then it calls
`rand_estimateFee` for a `deploy` of that word count. That RPC applies this chain's own
`max_program_words` admission (the cap above), so a program over the cap is refused there — for
the cost of one RPC round trip — rather than after the minutes it takes to prove a bundle the
ledger would then throw away.

Writing, building and deploying a guest step by step (Rust, C, or a hand-built image) is in
[`guests.md`](guests.md). Deploying translated Solana and Ethereum programs is in
[`translators.md`](translators.md).

## GPU proving (--cuda)

Proving is the only expensive half of a confidential call, and it happens in the wallet, never on
the chain. `rand call --cuda` runs the batch STARK's NTTs and Poseidon2 Merkle commitments on an
attached NVIDIA GPU instead of the CPU. The proof is the same object either way — same public
values, same tier, verified by the same CPU verifier — so nothing on the node changes and a chain
cannot tell which backend produced a proof.

The backend lives in the sibling repository, `circuits/rand-zkvm-cuda`, and is referenced by path
(`../../../circuits/rand-zkvm-cuda`); it is not vendored into this repo. `circuits/` must therefore
be checked out beside `fullnode/` to build any of the features below. `deploy/sync-zkvm.sh` prints
the same reminder.

**Building.** On a machine with a CUDA 13 toolkit, an NVIDIA driver, and the compiled PTX:

```
cargo build --release -p randprotocol-client --features cuda
rand call <program-id> --input 400 --input 250 --cuda
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
| Built without the feature | `built without CUDA support; rebuild rand with --features cuda` |
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
