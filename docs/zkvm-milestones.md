# The Rand zkVM, milestone by milestone — what was built and why

This is the history behind `crates/shrugg-zkvm` (vendored from the upstream `research` crate,
`rand_zkvm`, in `randprotocol/circuits`). `docs/architecture.md` covers how the node is put
together; `docs/confidential.md` covers what a confidential call looks like on this chain today.
This document is the part in between: what each zkVM milestone actually built, why it was built
that way, and what changed on the node's side of the fence when it landed. It does not repeat
the on-chain model (`docs/confidential.md` has that) except where a milestone changed it.

Every number below is measured, and the doc it was measured in is named next to it. Where a fact
could not be sourced, it is left out rather than guessed — see the end of this document's commit
message for the short list.

## 1. Why a zkVM at all

The confidential-computation model is simple to state: a program runs off-chain, on private
inputs, inside the Rand zkVM; the chain never sees the inputs, the registers, the branches taken,
or the exact number of cycles it ran; it verifies one STARK proof and applies the eight public
output words the program chose to publish (`docs/confidential.md`'s "On-chain model", "Effects"
table). Everything downstream of that model — deploys, calls, receipts, gas — is bookkeeping
around one verifier call.

**Why a general RISC-V machine instead of a circuit per contract.** The alternative — a bespoke
AIR for every confidential contract — means a new soundness review for every contract. Instead,
`rand_zkvm` proves *one* relation, "this RV32I(+M) program, run on these private inputs, produced
these public outputs," and a contract is just a program: bytes committed to at deploy time,
verified by the same `Machine::verify` call regardless of what the program does. The EVM and SVM
targets follow the same idea one level up: an EVM or sBPF interpreter is itself an RV32IM guest,
the target bytecode is its private input, and "deploying a confidential contract" means registering
the interpreter's program digest plus a commitment to the bytecode — never generating a new
circuit per contract (`research/docs/04-guests.md`, opening paragraph). One verifier, programs as
data, interpreters layered on top later. This is the same choice the whitepaper makes for its own
zkVM comparison, per that same document.

**Why Plonky3, Goldilocks, Poseidon2, hiding FRI.** The machine's words are 32 bits, and Goldilocks
(`p = 2^64 − 2^32 + 1`) is chosen because a 32×32 product never overflows it:
`(2^32−1)·2^31 < 2^63 < p` (`research/docs/01-isa.md`, "Why RV32, not RV64"). That same fact is why
the ISA is RV32 rather than RV64 — RV64 would roughly double the limb columns in the ALU and
memory tables for a target (sBPF) whose 64-bit ops can instead be interpreted at a cost of about
two RV32 operations each. Poseidon2 is the in-circuit hash because Plonky3 ships it natively and
because recursion — a later milestone — will need an arithmetization-friendly hash regardless; the
whitepaper's own production transcript calls for SHA3-384/BLAKE3-384, and using Poseidon2 instead
is listed as one of the roadmap's stated deviations, closable later as a config change
(`research/docs/05-roadmap.md`, "Known deviations", #4). `HidingFriPcs` randomizes the low-degree
extension of every trace and the FRI batch polynomial before committing, so two proofs of the same
run are different bytes and both verify — zero-knowledge, but only statistical, not perfect, a gap
Plonky3 0.7 states about itself (`p3-batch-stark-0.7.0/src/prover.rs:469`, quoted in
`research/docs/03-privacy.md` and `research/docs/05-roadmap.md`'s deviation #3).

**The prove/verify split.** `Machine::verify` is consensus code: every full node runs the same
verifier against the same recomputed verifier key, on every transaction. `Machine::prove` is not
consensus code at all — anyone holding the witness can produce a proof, off the consensus path,
once. That asymmetry is why this whole history optimizes verify's cost (a full preprocessed-
commitment recomputation, the dominant cost of an *uncached* verify) more aggressively than
prove's, and why the CUDA backend (§5) targets the wallet, not the node
(`research/docs/05-roadmap.md`, "Relationship to `../../fullnode`").

## 2. M1 — the machine (done)

M1 is the machine as it exists structurally today, minus the Poseidon2 chip and the RV32M
extension, both added later. Five AIR tables at M1 — `program`, `cpu`, `memory`, `alu`, and one
`byte` table (later split into `range` and `nibble`, §3; the seventh table, `poseidon2`, arrives in
§4) — proved as one Plonky3 batch STARK, exchanging facts over
named LogUp buses rather than calling each other directly (`research/docs/02-tables-and-buses.md`).
`program` held every instruction's decode pre-worked; `cpu` never inspects an opcode bit itself,
only trusts what the `PROGRAM` bus lookup returned. `memory` is one table for both the register
file (`space = 0`) and RAM (`space = 1`), sorted by `(space, addr, ts)` with `ts = 4·clk + slot` —
one of four memory-access slots per cycle. `alu` proves each op as a lookup keyed on
`(op, a, b, c)`. `byte` (at M1, a single 2^16-row preprocessed table) backed every range check and
bitwise operation.

The ISA is a staged RV32I subset: `LUI AUIPC JAL JALR`, the six branches, `LW SW` (word-only at
M1), the twelve immediate/register ALU ops, and `ECALL`. `FENCE`, CSR instructions, and `EBREAK`
never run. Three syscalls existed at M1: `HALT` (0), `WRITE_OUTPUT slot word` (1, pins one of eight
public output slots), `READ_INPUT idx` (2, returns a prover-chosen witness word — nothing ties two
reads of the same index together, and nothing outside the shielded transfer guest binds a private
input to anything on chain at all — `research/docs/03-privacy.md`, "Private inputs are witness, not
yet bound to anything"). Gas tiers pad the trace: tier `t ∈ {10,12,14,16,18,20}` proves up to
`2^t − 1` cycles, `cpu` pads to `2^t` rows, `alu` to `2^{t+1}`, `memory` to `2^{t+2}` (four accesses
per cycle, worst case) — and only the tier itself is public, never the real cycle count
(`research/docs/03-privacy.md`, "Tiers: what padding hides"). Proving uses `HidingFriPcs`, seeded
from fresh OS entropy per proof (statistical ZK, §1).

There is no RISC-V cross toolchain on the development machine, so every guest is written directly
against `src/asm.rs`'s mnemonic helpers; the emulator (`src/emulator.rs`) is the reference
semantics — "if the AIR and the emulator disagree, the AIR is wrong" (`research/AGENTS.md`). Every
new row or bus kind is checked against two invariants that have actually been violated in this
crate's history and are now load-bearing discipline:

1. Every bus message column must be constrained on every row kind that sends it.
2. A bus count must be forced to zero wherever its message columns are unconstrained.

Both are named for the bug that motivated them: M1 shipped with a store's memory value unpinned (a
witness could store a value no register ever held and read it back later as genuine memory
contents), and an ALU padding row could supply an arbitrary `(op, a, b, c)` tuple with arbitrary
multiplicity if its bus count was not forced to zero (`research/AGENTS.md`, "Invariants that have
actually been broken here"). Cheating tests (`tests/cheating.rs`'s `rejects()`) only count a
per-instance constraint-checker panic, a global lookup-balance panic, or a verify error as a
rejection — a trace-builder `assert!` tripping first means the test failed for the wrong reason.
M1 shipped 44 tests, and the exit criterion ran a little wider than originally scoped: four guests
(`fib`, `memcpy`, `bubble_sort`, `alu_mix`, plus `balance_check` as the crate's canonical
confidential-computation example), not three, all proving and verifying with ZK at their tiers,
every cheating test rejecting (`research/docs/05-roadmap.md`).

**The constraint-set-2 soundness fix wave.** After M1 shipped, a review found five gaps and fixed
all five in one wave (upstream commit `f44d58f` and the store-value fix that preceded it,
`2c8a39d`; landed on the node side in fullnode commit `0c3c0a6` plus the earlier vendoring of
`2c8a39d`): ALU padding rows could provide a bus tuple with arbitrary multiplicity (previously
`fib(10) = 999` was provable); never-written output slots were not pinned to zero, so a slot no
`WRITE_OUTPUT` ever touched was a free public value instead of zero (fixed with eight cumulative
`written_i` accumulator columns); `verify` did not reject non-canonical public values (a value `v`
and `v + p` are the same field element but different u64s, and only one should be a valid public
value); load/store word alignment was an emulator-only check, not a stated AIR constraint (fixed by
decomposing `mem_addr` into range-checked byte limbs, growing the `cpu` table from 40 to 52
columns); and a store's memory value was not pinned to the register value it claims to write
(the M1 gap named above). `docs/confidential.md`'s "Constraint set 2" section has the full account.
Proofs made under the old constraints do not verify under the new ones — a node that starts up
under constraint set 2 and tries to replay a chain with a confidential call proved under the old
constraints fails ledger replay and truncates its chain. This is why constraint set 2 forced a hard
fork of chain 4: a node built from this commit could not simply resync against the existing chain;
it needed a new chain id, or `--verify-chain off` for nodes that had to keep serving the old chain.
`balance_check` also became carry-aware in the same wave (a four-balance sum that wraps mod 2^32
now counts as over any 32-bit threshold), which changed its program id; `private_payment` was
unaffected and keeps the id chain 4 has deployed.

### M1.5 — the viewing-key layer (done, not vendored)

Between M1 and M2, the crate built a one-in-one-out shielded transfer guest end to end: in-circuit
note commitments and a nullifier (using a development hash, `Arx8`, later retired at M3.3), note
envelopes sealed with ML-KEM-768 (a post-quantum KEM, FIPS 203) plus ChaCha20-Poly1305, and
party- and transaction-scoped disclosure (`Disclosure::Party(ViewingKey)` sees a party's whole
history, sent and received; `Disclosure::Transaction { tx, key }` sees exactly one transaction). It
shipped as the milestone directly after the base machine — before M2's ISA-completeness work and
M3's native hash — because it is the fastest way to validate the note model end to end: a transfer
proves at tier 12 and a simulated ledger accepts it, every disclosure scope opens exactly its own
rows and nothing else, every row verifies against on-chain commitments and nullifiers, and a
viewing key cannot produce a proof (it is a one-way image of the spend key, and the guest reads the
spend key itself as private input) — six tests, all passing (`research/docs/05-roadmap.md`'s M1.5
row). A note was, and still is, 27 machine words: `pk(8) from(8) amount(1) asset(1) time(1) r(8)`.

M1.5 is **not vendored into the node**. `deploy/sync-zkvm.sh`'s header comment excludes
`notes.rs`, `viewing.rs`, `ledger.rs`, and `arx.rs` (the last no longer exists upstream since M3.3
anyway) because the node has no use for the note layer yet and vendoring it would drag in the
`ml-kem`/`chacha20poly1305` dependencies for no on-chain benefit — this chain's confidential calls
today publish plain output words, not shielded notes.

## 3. M2 — cheaper proofs and a complete ISA (done)

M2's exit criterion, as originally scoped, was broader than what actually shipped: "a guest
compiled with an external RISC-V toolchain runs and proves." What landed instead was a six-task
plan (M2.1–M2.6, in this order) that made proving and verifying cheaper and finished the ISA that
matters for a compiled guest, while leaving the toolchain-facing pieces open
(`research/docs/05-roadmap.md`'s M2 row, "M2's exit criterion as actually delivered is narrower
than the original wording").

**M2.1 — verifier-key cache.** `Machine` gained a cache keyed by `(program digest, tier)` (64
entries, FIFO-evicted at M2; later collapsed further, §4); a second `verify` of the same program
runs the cached hit in under 10% of the first, uncached recomputation
(`docs/superpowers/plans/2026-09-10-zkvm-m2.md`'s Task 1 test).

**M2.2 — FRI retune, 100-bit conjectured target.** Before this task, the `Production` FRI profile
ran 80 queries at 20 proof-of-work bits — conjectured soundness `3·80+20 = 260` bits, far past the
100-bit target the ethSTARK bound calls for, at a proportional cost in proof size. M2.2 retuned it
to 27 queries at 20 PoW bits (`3·27+20 = 101` bits) with folding arity 8 (`max_log_arity: 3`);
`Test` stayed at 16 queries, 4 PoW bits (`3·16+4 = 52` bits — explicitly not a production target,
only fast enough for `cargo test`). "Conjectured" here means the bound is the standard heuristic
argument FRI-based STARKs use for soundness against known attacks, not a formally proven bound —
the crate treats it the way the rest of the field does, as the working security target, and says so
plainly (`research/docs/03-privacy.md`).

> **Erratum (2026-09-12, superseded).** The 27-query retune was reverted in the 2026-09 audit wave
> (constraint set 5, `docs/confidential.md`): it met the ethSTARK *conjectured* 100-bit target but
> dropped the *proven* proximity-gaps floor the whitepaper's 80-query choice exists to keep (~86
> proven bits at q=80/g=20 vs ~42 at q=27 — the paper's Part III reconciliation weighs exactly this
> trade and keeps q=80/g=20). `Production` is once again 80 queries / 20 PoW bits / blowup 8. The
> M2.2 paragraph above is kept as the historical record of the retune and its rationale.

**M2.3 — byte table split.** The single 2^16-row preprocessed byte table was replaced by two
256-row tables: `range` (range checks plus a powers-of-two lookup) and `nibble` (4-bit AND/OR/XOR,
where a successful lookup is itself a range check on both operands). The byte table's fixed
preprocessed commitment dominated proving and, more sharply, *first*-verify cost: every `prove`
rebuilds that commitment's Merkle tree from scratch, and every first `verify` on a fresh `Machine`
does too. Shrinking it by two orders of magnitude cut prove time roughly 3–7x and first-verify time
roughly 100–130x, independent of the FRI profile (`research/docs/03-privacy.md`).

**M2.4 — ALU lookup collapse.** Before this task, `alu`'s three operand limbs (`a0..3`, `b0..3`,
`c0..3`) were always range-checked (12 lookups) on top of whatever op-specific lookups a row
already paid — pure redundancy on bitwise rows, where the nibble lookups already bind every limb.
The range-check gates (`g_ab`, `g_c`) now drop to zero wherever a stronger constraint already binds
the limb: zero on bitwise rows (nibble-bound instead), and `g_c` additionally zero on
compare/equality rows (where the boolean-result constraint already forces the limb into `{0,1}`).
Bitwise rows dropped from 20 lookups to 8; add/sub/eq/sltu land at or under 12.

**M2.5 — sub-word loads and stores.** `LB LH LBU LHU SB SH` join `LW`/`SW`. Memory stays
word-addressed; a load or store computes the byte offset within its word from the ALU-computed
address, decomposed into range-checked byte limbs so the offset cannot be forged over the field (a
naive `mem_addr·4 + off = alu_out` identity alone would let a cheating witness pick any `off` it
likes). Width imposes alignment directly in the AIR, not just in the emulator: a word load/store
must land on a word boundary, a halfword on a 2-byte boundary. A store is a read-modify-write of
the whole word, with the merged bytes traced back to a value that was genuinely in a register.

**M2.6 — the RV32M extension.** `MUL MULH MULHU MULHSU DIV DIVU REM REMU`, decoded only from
register-register `OP_ALU` with `funct7 = 1` (no immediate form exists in RV32M). Multiplication is
proved as an exact integer identity over 16-bit halves of the two 32-bit operands, specifically
*because* the naive `hi·2^32 + lo` product can exceed the Goldilocks modulus, letting a prover claim
`hi = 2^32 − 1` for a small product; splitting into halves and bounding the one free witness
(`carry`) to three range-checked bytes closes that (`research/docs/01-isa.md`, `docs/02-tables-and-
buses.md`'s `alu` section). Division proves the unsigned-magnitude identity `|a| = q·|b| + r`,
`r < |b|`, then fixes up the sign, matching the RISC-V spec's own edge cases exactly (division by
zero, `MIN / −1`).

**Measured before/after** (fib guest, upstream `docs/03-privacy.md`; "M2.1→M2.2→M2.3" tracks the
three steps that actually moved these numbers — M2.4–M2.6 don't touch proof size or timing):

| | tier 10 | tier 12 |
|---|---|---|
| proof size | 892 578 → 290 403 → 268 288 bytes | 886 246 → 291 366 → 289 779 bytes |
| prove time | 21.61 s → 20.88 s → 3.11 s | 29.69 s → 29.45 s → 11.44 s |
| verify time (first, uncached) | 2.166 s → 2.148 s → 16.0 ms | 2.178 s → 2.141 s → 18.0 ms |

A cached verify of the same proof runs under 40% of the first, uncached time
(`tests/e2e.rs::verifier_key_is_cached_after_first_verify`). Note that M2.1 (the cache) and M2.2
(the FRI retune) barely move these two numbers by themselves — they were dominated by trace and
preprocessed-commitment costs the query count and cache don't touch; M2.3 (the byte-table split) is
what actually moves them.

**Constraint degree cap 8.** The FRI config's `log_blowup = 3` plus this machine's ZK hiding
(`is_zk = 1`) caps the maximum AIR constraint degree at 9 (`constraint_degree = max_degree + 1 ≤
2^log_blowup + 1`); raising any table's degree past that would require raising `log_blowup`, and
with it the soundness/proof-size tradeoff FRI's query count depends on. A test
(`tests/tables.rs::alu_max_constraint_degree_is_pinned`) pins each table's measured degree so a
future change can't silently cross that ceiling: `program` 2, `cpu` 8, `memory` 4, `alu` 8, `range`
2, `nibble` 2. `alu`'s 8 comes from the M2.6 division sign-fix identity; `cpu`'s comes from its
packed lookup-fraction terms, not its own row logic (whose costliest single constraint is only
degree 6). Both tables are already at the edge of the budget.

**What remained open.** M2's original, aspirational wording included a flat-binary loader (to run
a program compiled by an external RISC-V toolchain rather than assembled by hand against `asm.rs`)
and a firmer binding for `READ_INPUT` than "a prover-chosen witness value, unconstrained across
repeated reads of the same index." Neither was part of the six-task plan that was actually built.
Both later shipped as **M4.1** (2026-09-11, constraint set 4 — the loader, `guests::compiled::fib`,
and the salted `H_IN` commitment with the `input` table; see `docs/confidential.md`). M2 shipped
81 tests total (`research/docs/05-roadmap.md`).

## 4. M3 — a native hash and the program out of the verifier's hands (done)

M3 is four tasks, M3.1 through M3.4, each depending on the last.

**M3.1 — the Poseidon2 chip.** A new AIR table, one row per permutation round, in fixed 32-row
blocks: 4 initial full rounds, 22 partial rounds, 4 terminal full rounds, then 2 idle rows —
`Poseidon2Goldilocks<8>`'s own round structure, reproduced exactly (the same round constants, drawn
from the crate's existing development seed, `PERM_SEED`, in the same order Plonky3's own
constructor draws them; checked against `Poseidon2Goldilocks::<8>::permute` on 10 000 random
states, `research/docs/02-tables-and-buses.md`). Each round's S-box (`x^7`) is split into two
degree-3 intermediates (`x3 = (s+rc)^3`, `x7 = x3·x3·(s+rc)`) to keep every constraint at or below
degree 4, measured and pinned at exactly 4. The chip provides a `POSEIDON2` lookup bus keyed on
`[input state, output state]`, so any consumer proving "I ran a genuine Poseidon2 permutation" does
so by looking up its claimed input/output pair here.

**M3.2 — the `POSEIDON2` syscall.** `SYS_POSEIDON2 = 3`: `a7 = 3`, `a0 = ptr` (a word address),
`a1 = n` (word count, `0 ≤ n ≤ 4096`). It hashes the `n` words at `ptr` in place with a
padding-free sponge (rate 4, capacity 4, width 8, overwrite mode — exactly `hash::sponge_hash`'s
semantics) and overwrites `ptr..ptr+8` with the 8-word digest. On the `cpu` table this is a
row-group, not a single row: the ecall row, one absorb row per 4-word block, and exactly two
digest write-back rows, all counting as ordinary cycles. `NOTE_COMMIT`, `NULLIFY`, and
`MERKLE_VERIFY` are **not** new syscalls — they are guest-level library routines
(`src/asm.rs::emit_note_commit`/`emit_nullify`/`emit_merkle_verify`) that stage a domain-tagged
message into RAM and call `POSEIDON2` over it. `MERKLE_VERIFY` is unrolled at assembly time (the
tree depth, 32, is a compile-time constant), one `POSEIDON2` call per level, not a runtime loop —
this matters for M3.3's cost, below.

**M3.3 — the note-layer primitives on the chip, and `cm_in` off the public output.** `Arx8`, the
development hash M1.5 used, is retired; `notes.rs`/`viewing.rs` move to the Poseidon2-backed sponge
with a domain tag as the first absorbed word. Widths grow from `Word2` (64-bit, M1.5) to `Word8`
(four canonical Goldilocks elements, 256-bit): every key, commitment, nullifier and tree node is
now a `Word8`. The transfer guest proves, entirely in-circuit:

```
nk      = H_NK(sk)
pk      = H_PK(nk)
cm_in   = NOTE_COMMIT(pk, from_in, amount, asset, time_in, r_in)
anchor  = MERKLE_VERIFY(cm_in, path, index)     -- depth 32, against a commitment tree
nf      = NULLIFY(nk, cm_in)                     -- H(NF_DOMAIN, nk, cm_in), no separate nonce
cm_out  = NOTE_COMMIT(pk_out, pk, amount, asset, time_out, r_out)
```

and publishes a single 8-word digest, `H(OUT_DOMAIN, anchor, nf, cm_out, time)`, instead of the
four plaintext values themselves — at `Word8` widths, `anchor(8)+nf(8)+cm_out(8)+time(1)` is 34
words, which no longer fits the CPU table's 8 output slots, and widening those slots would blow the
CPU table's already-pinned constraint-degree budget (§3). The ledger is handed the plaintext
`anchor`/`nf`/`cm_out`/`time` alongside the proof and recomputes the digest to check the proof
attests to exactly those values before doing anything else. The commitment tree itself is
append-only, depth 32, using the same Poseidon2-based node hash `MERKLE_VERIFY` checks against; the
ledger accepts any of its last 16 roots as a valid anchor (`recent_roots`, bounded to 16), because
proving takes real wall-clock time and another transaction may land first — an anchor that has
scrolled out of that 16-root window is rejected even though the underlying Merkle proof is "true
forever" (`research/docs/06-viewing-keys.md`).

The point of moving `cm_in` off the public output and onto the Merkle witness: before M3.3, the
spent commitment was public, so anyone watching the chain could link a note's creation to its
later spend by matching commitments. After M3.3, only `anchor` (one of the ledger's last 16 roots)
and `nf` (a one-way function of `cm_in`) are public — the transaction-graph link that `cm_in`
disclosure would have created is closed.

**M3.4 — the program table as witness, and `hc` in-circuit.** Through M3.3, the program table was
*preprocessed*: Plonky3 committed it once, independent of any witness, and the verifier held the
whole program in the clear to recompute `hc` (then literally the preprocessed table's Merkle root).
M3.4 makes `program` a **main** (witness) trace with an in-circuit decoder: each row carries a raw
32-bit instruction word, its bit decomposition, and the same 23 `Decoded` fields the old
preprocessed table carried, each pinned by an opcode/funct3/funct7-match constraint against the
word's own bits. The `cpu` trace now begins with `⌈program length / 4⌉` digest rows, which absorb
the whole program through a new `PROGRAM_WORD` bus and the same Poseidon2 chip, publishing an
8-word digest to new public values `pv::HC0..HC7`. `Machine::verify(hc, proof)` replaces
`verify(program, proof)` — the verifier checks `hc` directly and never sees a program word. The
verifier key becomes program-*content*-independent, keyed only by `(tier, program_log_height)` —
`program_log_height` being a value the *prover* declares per proof from the program's own length
(not derived from the tier, since a digest row absorbs up to 4 words per cycle, so a program can
need far more program-table rows than the tier's cycle budget would suggest).

**Soundness arguments, in brief.** The digest is not a plain message-prefixed sponge: the domain
tag `HC_DOMAIN`, `base_pc`, and the program's length are folded into the sponge's *capacity* lanes
(`hs4..6`) of the very first permutation, rather than spending a rate slot (and hence a whole extra
row) on a header block — this is what makes `hc` bound to the program's base address and length
without extra cost. Binding the *whole* program, not just a declared prefix, needed one more fix: a
first cut of M3.4 only zeroed a row's `PROGRAM_WORD` multiplicity when the row was invalid
(`mult_word · (1 − valid) = 0`), which left a valid, executable row free to opt out of the digest —
reachable, say, by a computed jump past the digested window — so `hc` would bind only a declared
prefix. The fix constrains `mult_word = valid` exactly, turning the bus balance into a
set-equality argument: the digest's demanded message set and the valid rows' supplied message set
are forced equal, so a valid row can never be excluded (`tests/cheating.rs`'s
`an_undigested_reachable_program_tail_is_rejected` is the regression for the narrower gap).
Digest rows and ordinary hash rows (from a guest's own `POSEIDON2` calls) are kept mutually
exclusive on every row, so a witness cannot claim to be both at once. And `hash_ptr` (the address a
`POSEIDON2` call reads/writes) is range-and-nibble-bounded below `2^30`, the same technique the
memory-address alignment check uses, so an unbounded pointer cannot be chosen to wrap the memory
table's sort key and redirect a hash call's reads or writes to the wrong address.

**Cost.** The `transfer` guest, measured (`research/docs/06-viewing-keys.md`,
`tests/viewing.rs::transfer_guest_permutation_and_row_counts_are_measured`):

| | |
|---|---|
| program size | 4 554 instructions |
| execution cycles | 3 764 |
| digest rows (⌈4554/4⌉) | 1 139 — count as cycles too |
| **total cycles** | **4 903** — forces tier 14 (exceeds tier 12's 4 095-cycle budget) |
| execution `POSEIDON2` permutations | 190 (nk 1, pk 3, `cm_in` 7, `nf` 5, `cm_out` 7, Merkle 32×5=160, output digest 7) |
| digest-row permutations | 1 139 |
| **total permutations** | **1 329** |
| envelope size | ≈ 1.3 KB (ML-KEM ciphertext plus three AEAD envelopes) |

Tier 14 is forced by the cycle count alone, regardless of the Poseidon2 permutation budget — but at
tier 14, even the unmodified `poseidon2_height(t) = 2^(t+1)` formula (1 024 slots) falls short of
1 329 permutations, so M3.4 bumped it once more, to `2^(t+2)` (2 048 slots at tier 14) — cheaper in
proof size than jumping to tier 16 just to clear the same number.

**The noted follow-up.** The bulk of the program's size, and hence most of the 1 139 digest
permutations, comes from `MERKLE_VERIFY`'s unrolled 32-level loop (§3's M3.2 note): each level is
straight-line code, not a runtime-indexed loop over the path array. The upstream docs do not
commit anywhere to a specific replacement, only imply — through the size of the program and the
open `flat-binary loader`/`READ_INPUT` binding items already carried forward from M2 — that a real,
runtime-looped Merkle routine is the natural way to shrink this. No design or code exists for it
yet.

**What `hc` leaks and does not.** `hc` is binding but not hiding, both before and after M3.4, for
the same underlying reason: it has no salt of its own, in-circuit or out, so anyone who can guess a
candidate program can recompute `hc` and confirm the guess, and two deployments of the same program
are still trivially linkable. What changed is the size of the leak sitting *next to* that fact:
before M3.4, the verifier held the entire program in the clear to check `hc` at all — a far larger
leak than the digest alone. After M3.4, the verifier holds only the 8-word digest and never sees an
instruction word, which is a real privacy gain, but `hc` itself is exactly as guessable as it always
was (`research/docs/03-privacy.md`, "`hc` is now an in-circuit digest").

**What changed on the node side.** `ZkExecutor::check_program` (`crates/shrugg-zkvm/src/
executor.rs`) computes `Program::digest()` and stores it as `ProgramRecord.code_hash` — `code_hash`
is now the actual verification key material, 8 little-endian `u32` words, not an informational
label (before this sync it was `blake3(program_id)` again, since the verifier used to take the
whole program directly). `warm()` at this sync warmed only the smallest tier's verifier key,
because the key is program-content-independent — warming every tier for every deployed program
would mean building the Poseidon2 round-constant table at the largest tiers too, which is not the
cheap end of the preprocessed-commitment cost any more. (It has since grown: the hardening review
widened it to tiers 10/12/14, and M4.1 added the two input-height classes — see
`docs/architecture.md` §9a.) `hash.rs` (the host-side Poseidon2 sponge reference, used
both for `hc` and the `POSEIDON2` syscall) is vendored into the node for the first time at this
sync — it is core machinery, not viewing-key-specific — with its one dependency on the excluded
`notes.rs` (the `HC` domain tag) patched to a local `hash::HC_DOMAIN` constant instead of pulling
`notes.rs` in for one `u32` (`deploy/sync-zkvm.sh`'s header comment).

## 5. The CUDA prover backend (done, unverified on hardware)

**Why.** Proving, not verifying, is the user-facing cost of a confidential call: it happens once,
in the wallet, before a call is ever submitted, while every node just verifies. Moving the two
dominant proving costs — the low-degree-extension NTTs and the Poseidon2 Merkle commitments — onto
a GPU is a wallet-side optimization with no effect on what a node checks
(`docs/superpowers/specs/2026-09-10-cuda-prover-design.md`'s Goal).

**What.** Two new crates alongside `research`: `rand-zkvm-cuda` (stable Rust, the host-side
backend — `GpuDft` implementing Plonky3's `TwoAdicSubgroupDft` trait, `GpuHidingMmcs` implementing
its `Mmcs` trait, both over `cuda-core` 0.3.1 loading a *committed* PTX file at runtime rather than
compiling CUDA at build time) and `gpu-kernels` (a `cuda-oxide` crate, pinned to
`nightly-2026-08-28`, containing only the actual kernel code — NTT stages, Poseidon2 permutation
and compression, byte transposes). `research` gains an optional `cuda` feature exposing
`Backend::{Cpu, Cuda, Reference}` and `Machine::prove_with(backend, ...)`; the fullnode's
`crates/shrugg-zkvm` mirrors that feature, and `shrugg call --cuda` is the client-facing flag,
gated behind `cargo build --features cuda`. Every backend produces the exact same `Proof` type — the
CPU verifier neither knows nor cares which backend produced a given proof.

Because no GPU was available to the author (an Apple M4 Max laptop and 2-vCPU droplets), every
device-side routine has a pure-Rust reference twin with an identical layout — `ntt_forward`/
`ntt_inverse`, `poseidon2_permute`, `merkle_commit`/`open` — each checked bit-for-bit against
Plonky3's own CPU implementation, plus a mock CUDA driver that runs the "device" code path on the
host. `Machine::prove_with(Backend::Reference)` proves and verifies every guest end to end this way,
and that is the contract the real GPU path inherits once it exists. There is deliberately **no
silent fallback**: `shrugg call --cuda` on a build without the `cuda` feature errors with "built
without CUDA support; rebuild shrugg with --features cuda" rather than quietly running on the CPU,
and a build with the feature but no usable device surfaces the underlying `CudaError` and exits
non-zero (`docs/confidential.md`'s "GPU proving" section has the full failure-mode table).

**Honest status.** As of 2026-09-10/11, the kernels have never run on real GPU hardware, and no PTX
is committed — `rand-zkvm-cuda/ptx/` holds only `PTX_BUILD.md`, the runbook for building and
committing it on a machine with the CUDA 13 toolkit and a matching driver. Everything described
above is exercised on the mock driver and the CPU reference twins only. The design spec's own
performance section is explicit that its numbers are "to be measured, not promised"; the one real
measurement on record is the CPU baseline it hopes to beat — 21 s to prove `private_payment` at
tier 10 under the production FRI profile, on the author's laptop
(`docs/superpowers/specs/2026-09-10-cuda-prover-design.md`).

## 6. M4 — compatibility (M4.1 shipped 2026-09-11; the EVM/sBPF interpreters are still open)

M4's overall exit criterion is an ERC-20 `transfer` and an SPL `Transfer` each proving under the
same relation the rest of this document describes (`research/docs/05-roadmap.md`'s M4 row).
**M4.1 landed the first slice on 2026-09-11** (constraint set 4, `docs/confidential.md`): the
flat-binary loader (`Program::from_flat_binary`), the first compiled guest
(`guests::compiled::fib`), and — as part of the same sync — the salted `H_IN` input commitment and
the eighth (`input`) table. What remains open is the interpreters themselves: neither the EVM nor
sBPF ever executes natively — each
becomes an interpreter compiled to RV32IM, with the target bytecode passed in as a private input,
exactly the same "programs as data" idea §1 describes. Cheap opcodes map onto a handful of native
RV32IM instructions each; expensive ones (`KECCAK256`, 256-bit modular arithmetic, `ECRECOVER`,
`sol_sha256`, `sol_ed25519` verification) need dedicated coprocessor AIR tables, the same way the
Poseidon2 chip was hand-built for M3, rather than being simulated bit by bit inside the general ALU.

**What is actually available to build this on, checked directly against the vendored Plonky3 0.7
crate set:** `p3-keccak-0.7.0` exists, but it is the plain Keccak-f[1600] permutation function, not
an AIR/chip. There is no `p3-keccak-air`, no `p3-poseidon2-air`, and no `p3-sha256` of any kind at
0.7.0. This is a direct correction to `research/docs/04-guests.md`'s own text, which says
"`p3-keccak-air` already exists upstream and can be added as a sixth chip" and names it as the
reason M4 builds the EVM interpreter first — that crate is not in the vendored dependency set, so
a Keccak coprocessor chip will have to be hand-written the same way `tables/poseidon2.rs` was, not
imported. Two other facts bear on M4 without a design existing yet: `solana-sbpf` 0.11.1 is
available as a dependency, and Rust 1.98.1 ships a `riscv32im-unknown-none-elf` target — the
M4.1 flat-binary loader (`Program::from_flat_binary`, constraint set 4) is exactly what a program
built by that target plugs into, and `guests::compiled::fib` already exercises the path.

**Rough, unmeasured cycle estimates** (`research/docs/04-guests.md` is explicit that these are
estimates, not measurements, since no interpreter exists yet): a native RV32IM instruction costs 1
cycle by definition; an interpreted EVM opcode costs on the order of 5–20 cycles (mostly dispatch
overhead for cheap opcodes); an interpreted sBPF instruction costs on the order of 2–5 cycles for
arithmetic (the tax of treating each 64-bit sBPF register as two 32-bit RV32 words) but as little as
1 for anything already word-sized. `KECCAK256`/`SHA-256`/`ECRECOVER`/`sol_ed25519` are each
estimated at thousands of native cycles if simulated bit by bit — the stated reason each needs its
own coprocessor table rather than running through the general ALU.

## 7. What each milestone changed for a node operator

| Milestone | Constraint set | Hard fork? | Proof size / verify cost (fib, tier 10) | What a wallet must do differently |
|---|---|---|---|---|
| M1 (base machine) | baseline (unnamed in the vendored docs — "constraint set 2" is the first numbered set) | — | not recorded before the fix wave | build calls against `postcard(Proof)`; nothing else |
| Constraint-set-2 fix wave | constraint set 2 | **Yes** — chain 4 truncates at its first confidential call under the old rules | not recorded in the sources reviewed | none — call format unchanged; node operators need a new chain id or `--verify-chain off` |
| M2 + M3 (FRI retune, byte-table split, sub-word memory, RV32M, Poseidon2, in-circuit `hc`) | constraint set 3 | **Yes** — same failure mode as constraint set 2 | 892 KB → 268 KB proof; 21.6 s → 3.1 s prove; 2.17 s → 16 ms first verify | `Proof` gains a `program_log_height` field (still `postcard`-encoded, still opaque to a caller); a deployed program's `code_hash` is now `hc`, not `blake3(program_id)` — this only matters to code that reads `code_hash` directly, not to a caller submitting a call |
| CUDA backend | unchanged — same proof format, same constraint set | No | unchanged (same `Proof` type; performance only) | opt in with `--cuda` on a build compiled with `--features cuda`, and expect a hard error, never a silent CPU run, if no device is available |
| M4.1 (salted `H_IN` + `input` table, flat-binary loader, compiled guests) | constraint set 4 | **Yes** — `pv::NUM` 18 → 26, eighth AIR, `Proof` gains `input_log_height` | same order as constraint set 3 | private inputs are now committed (salted `H_IN` in the public values); compiled flat binaries can be deployed, not just hand-assembled programs |
| 2026-09-12 audit fixes (hash row-group gates, FRI back to 80/20, prove-time guards) | constraint set 5 | **Yes** — FRI query count 27 → 80 and new AIR constraints; old proofs fail the new verifier and vice versa | larger proofs again (~3x the FRI query work of sets 3–4); the whitepaper's 80/8/20 table is the price of the ~86-bit *proven* floor | none — call format unchanged; provers just produce 80-query proofs |

## 8. Reading order

Upstream (`randprotocol/circuits/research/docs`), in the order they were written to be read:

1. `01-isa.md` — the instruction set, encoding, and syscall ABI.
2. `02-tables-and-buses.md` — the eight tables, their columns, and the buses that connect them.
3. `03-privacy.md` — what zero-knowledge covers here, what a proof leaks, and what `verify` checks.
4. `04-guests.md` — the M4 plan for EVM/sBPF interpreters and coprocessor chips.
5. `05-roadmap.md` — the milestone table, exit criteria, and the whitepaper deviation list.
6. `06-viewing-keys.md` — the M1.5 note/envelope/disclosure design in full.

Design specs and plans (`randprotocol/circuits/docs/superpowers/`):

- `specs/2026-09-10-zkvm-m2-m3-design.md` — the M2/M3 design, approved before implementation.
- `plans/2026-09-10-zkvm-m2.md`, `plans/2026-09-10-zkvm-m3.md` — the task-by-task TDD plans.
- `specs/2026-09-10-cuda-prover-design.md` — the CUDA backend design.

This repository: `docs/architecture.md` (how the node fits together), `docs/confidential.md` (the
on-chain model, gas, and the constraint-set history from the node's point of view — the primary
source for everything in §7), `crates/shrugg-zkvm/src/executor.rs` (the verifier glue), and
`deploy/sync-zkvm.sh` (what is and is not vendored, and why).
