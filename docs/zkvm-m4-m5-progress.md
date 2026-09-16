# zkVM milestones M4 and M5 — progress record (2026-09-16)

What each of the M4.x and M5.x milestones delivered, with the measured numbers, the audits and
hard forks along the way, and what is deferred to which hardware. Upstream work lives in
`circuits/` (`research/` is the RV32 machine, `recursion/` the recursion VM); this repo vendors
both (`crates/shrugg-zkvm`, `crates/shrugg-rvm`) via `deploy/sync-zkvm.sh`. Deeper detail:
`docs/zkvm-milestones.md` (M1–M4 design history), `circuits/recursion/docs/00–03` (the M5
measured records), `circuits/docs/superpowers/` (specs and plans), `docs/confidential.md`
(the constraint-set history from the chain's side).

## M4 — EVM/sBPF guests and the input segments (constraint sets 4–6)

- **M4.1 (constraint set 4)** — salted input commitment `H_IN` with the `input` table; the
  flat-binary loader and compiled guests. `pv::NUM` 18 → 26, an eighth AIR. Vendored here at
  `f06446a`.
- **M4.2 (constraint set 5)** — the `keccak` table and `KECCAK` syscall, **optional per proof**
  (`keccak_log_height = 0` removes the instance); proof-declared `mem_log_height`; a four-keyed
  verifier key; **FRI reverted to the whitepaper's 80/8/20** (the M2.2 27-query retune met the
  conjectured target but dropped the proven proximity-gaps floor to ~42 bits). The 2026-09-12
  zk audit (`../concerns/fullnode-zk-audit-2026-09-12.md`) found two **critical** soundness
  holes in `tables/cpu.rs`'s hash row-group routing (ungated `IS_HASH`/`IS_HASH_OUT` rows → 4
  arbitrary RAM writes per row; `HASH_FIN` unpinned) — both have attack-witness regression tests
  that verify pre-fix and reject post-fix. Every fix was ported upstream and arrived by the cs5
  re-vendor (`bcbf70a`), which also set `MAX_PROOF_BYTES = 2 MiB` (the 80-query proofs no longer
  fit 1 MiB).
- **M4.3** — the EVM interpreter guest (`evm-core`, host-tested against revm 43.0.2 and
  num-bigint before anything is proven). The in-suite proof is a tier-16 EVM call; the ERC-20
  transfer exit proof needs ≥ 28.5 GB and is deferred to a ≥ 64 GB machine.
- **M4.4** — the `sha256` table + `SYS_SHA256` (optional per proof, the keccak table's exact
  terms), the sBPF interpreter guest (`sbpf-core`, checked against solana-sbpf 0.11.1, the SPL
  Token ELF loaded and a real Transfer run natively). Its review found a declared `program_hash`
  unsound under a hiding `H_IN` — the finding that produced constraint set 6.
- **Constraint set 6 (2026-09-14, upstream `0200877`)** — the **public input segment**: a ninth
  **mandatory** table `public` (`PUBLIC_DIGEST`/`PUBLIC_READ` buses, sixteen buses total),
  `SYS_READ_PUBLIC = 6`, and `H_PUB` in `pv::PUB0..7` — **unsalted**, so
  `Machine::verify_public(hc, public_words, proof)` recomputes it natively and compares.
  `pv::NUM` 26 → 34, cpu `col::WIDTH` 224 → 275, the verifier key a 6-tuple `(tier, program,
  input, keccak, sha256, public)`. The sBPF guest reads its ELF from the public segment:
  **1 753 945 → 694 498 cycles (Tier 20)**. Re-vendored here (`3090fb8`, `3f38fd9`, merge
  `b555c99`): the chain admits only the **empty** public segment (`verify_public(hc, &[], _)` —
  plain `verify` would leave `H_PUB` bound only in-circuit); `MAX_PROOF_BYTES` **stays 2 MiB**
  (measured: keccak-free production proof 1 298 729 B at tier 10 / 1 359 978 B at tier 12;
  keccak-carrying 3 198 430 B — both cap properties unchanged). Suite: **678 passed, 0 failed**.

  Open M4 items: the ERC-20 and SPL exit proofs (≥ 64 GB runbook rows 1–2); chain-side EVM
  caller authorisation (design); a deeper storage index before an EVM contract holds real value.

## M5 — the recursion VM (2026-09-13 → 2026-09-16, all merged to `circuits` main)

Design spec approved by the user 2026-09-14. The spike that justified it: running the RV32
verifier as an RV32 guest costs 1.34e9 cycles (88.9% software Poseidon2) — impossible; a second,
field-native machine makes it a few hundred thousand rows.

- **M5.1 (`aadbf47`)** — the 24-instruction Goldilocks-native ISA, the emulator (reference
  semantics), the DSL (typed handles, spilling linear register allocator), and the verifier
  program for RV32 proofs. Exit: **50 real production bundle proofs accepted, 50 tampered
  refused at the named step**. Measured per inner proof (cs6): **5 682 847 cpu rows, 51 595
  permutations, 6 354 037 memory accesses, 199 760 witness words**. The plan's Task-7 precompiles
  (FRIFOLD/EXPBITS) were analysed and **rejected with arithmetic**: their combined share is ~3%,
  so the 2^19 decision point was unreachable through them — the dominant terms were the
  batch-opening reduction (~50%) and allocator spills (~50%).
- **M5.2 (`37b07a5`)** — the machine: eight instances (preprocessed program table, register/RAM
  memory split, public table with the `H_PUB`-pattern 4-element interface digest,
  permutation-per-row Poseidon2 chip with constants in the AIR, cpu at 66 columns, the optional
  reduce chip, the range provider), eight buses, `TIERS` recut [8..22] at the measurement. The
  verifier key is `(FriProfile, Program, Tier)` (an in-circuit program digest is impossible at
  5.69 M instructions). Three measurement-gated row cuts: **liveness** 5 683 021 → 4 052 455,
  **REDUCE** → 2 240 988, **SPONGE** → **1 968 619 rows** (tier 21, 6.1% headroom). Cheating
  suite 26/26 across every spec §7 vector. Exit: the test-profile twin — an rVM proof of the
  verifier program over one real bundle proof, natively verified (proof **327 321 B**, verify
  18.3 s). The production exit is written and `#[ignore]`d with its derived requirement
  (**48.6 GB oracle → ≥ 64 GB**, runbook row 3).
- **M5.3 (`32946a2`)** — the aggregate program and the chain-facing API: **one N-generic
  program per inner shape** (a counted loop over the tape's N, a fresh challenger per proof, the
  interface digest a runtime-length staged sponge over `[inner_vk_digest ‖ N ‖ 34·N]` — one
  registered digest covers every window size). `aggregate` / `verify_aggregate` /
  `aggregate_program_digest` with shape and digest guards; refusal suite green; the N=1 tier-19
  round-trip completes (proof 328 121 B). Per-N measured (test profile): N=1 441 782, N=2
  883 240, N=3 1 324 694 rows; production N=1 1 968 758. Machine classes: **N=1 ≥ 64 GB, N=2
  ≥ 128 GB, N=3 ≥ 160 GB host** — production N≥2 belongs to the GPU backend. The N=2/N=3
  test-profile twins jetsam'd at this laptop's ~33 GB per-process ceiling (written,
  emulation-proven, runbook rows 4–5). The fullnode admission stub's 5-step algorithm + pinned
  hex vectors delivered (now the conformance suite in `crates/shrugg-node`).
- **M5.4 (`271679d`)** — the proving-backend split: `Backend::{Reference, Cuda}`,
  `prove_with`/`prove_on`, the mock-driven equivalence suite — **zero new kernels** (the RV32
  CUDA crate's ten kernels cover the rVM's eight instances as-is). Measured device model: an
  **80 GB card (H100/A100-80G) runs every tier through 23 unchunked**; a 40 GiB card passes the
  tier-23 upload guard. `TIERS` gains 23 with its `for_cycles` pin. The **self-verifier**
  (`rv32r`, via the `VerifierShape` generalisation — the byte-for-byte Off-replay pin intact)
  verifies an rVM proof in-circuit, M5.1's tamper table refused verbatim (6/6). Its end-to-end
  at the M5.2-exit shape is est. 2.9–3.9 M rows (tier 22, ≥ 128 GB) — **written and deferred
  with the measured requirement, as spec §7 allows** (runbook row 11). Still open: the PTX
  first build + hardware bring-up and the production N re-measurement — **blocked on
  provisioning the fleet GPU node** (Linux, R580+, CUDA 13, LLVM 21, sm_80+, 80 GB device,
  ≥ 160 GB host; `circuits` `PTX_BUILD.md`).

## What M5 unlocked here

Chain-side block aggregation — the whole reason for the rVM — is **merged on this repo's main
(`275d1ce`, genesis-gated dark)**: the aggregator register, the `Aggregate` action, the
nine-step admission with the pinned conformance vectors, the subsidy and fee split, sealing and
pruning, sealed-form sync (coverage-closed serving), the RPC surface and the `aggregate --watch`
daemon, and the chain-9 genesis cut. Chain 8 is unaffected (a chain without
`genesis.aggregation` behaves byte-for-byte as today). Activation is gated on the user-owned
≥ 64 GB batch (runbook rows 1–6 — its measurements fill `admitted_shapes[0]`), recorded in
`docs/deploy.md` ("Deferred proof runs and hardware tasks" and "Chain 9 activation").

## The deferred-proof runbook (one session clears rows 1–6 on a ≥ 64 GB machine)

| # | run | class |
|---|---|---|
| 1 | ERC-20 transfer proof (M4.3 exit) | ≥ 64 GB |
| 2 | SPL token transfer proof (M4.4 exit, tier 20) | ≥ 64 GB |
| 3 | M5.2 rVM tier-21 production exit | ≥ 64 GB (48.6 GB oracle) |
| 4–5 | M5.3 N=2 / N=3 test-profile aggregate twins | ≥ 64 GB |
| 6 | production N=1 aggregate | ≥ 64 GB |
| 7–8 | production N=2 / N=3 aggregates | ≥ 128 / ≥ 160 GB host (+ 80 GB device for the GPU path) |
| 9–10 | PTX first build + bring-up; production N re-measurement | the fleet GPU node |
| 11 | self-verifier end-to-end | est. tier 22 / ≥ 128 GB |

Exact commands and per-run estimates: `circuits/recursion/docs/03-gpu-and-self-recursion.md`
Appendix A. The consolidated ops checklist: `docs/deploy.md`.
