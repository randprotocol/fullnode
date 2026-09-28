# AGENTS.md

Guidance for agents working in this repository. The README is the user-facing
overview; this file is the durable project memory: review state, load-bearing
invariants, and known traps.

## Project memory (state as of 2026-09-28)

### v0.6.3 — delegated proving, Phase 2: split authorisation (2026-09-29; chain 17 only)

The bundle proof no longer takes the spend key. Spec `docs/superpowers/specs/2026-09-28-delegated-proving-design.md`
§4–§5, plan `docs/superpowers/plans/2026-09-28-delegated-proving-phase2.md` (10 tasks, every task
reviewed, a whole-branch review, then one fix wave), user guide `docs/prover.md`; branch
`feat/delegated-proving-2` + the chain-17 scripts of `feat/chain17-cut`. **A hard fork: `Bundle` gains
`auth_commit` and `auth_proof` on the wire and the transaction id domain is `rand-txid-3`, so this
build decodes none of chain 16's bundles and refuses chains 14, 15 and 16 at startup
(`node::CHAINS_THIS_BUILD_CANNOT_RUN`, each hash with its reason). It runs chain 17 only — never roll
it onto the chain-16 fleet; it lands with the chain-17 cut.** Phase 1's v0.6.2 stays the chain-16 build.
**What it is:**

- **Two guests, both fullnode-local** (`crates/randprotocol-zkvm/src/{auth.rs,guests.rs,hidden.rs}`,
  excluded from `deploy/sync-zkvm.sh` — no circuits change): the **auth guest** (`hc_auth
  1e4e347f…39c1`, domain `AUTH = 65`, inputs `sk ‖ salt`, publishes `c = H(AUTH, nk, salt)`; tier 10,
  production proof 1.36 MB in ~7 s) and **bundle guest v3** (`hc_bundle 60af094a…3fce`, the v2 guest
  reading `nk` at word 0 and the salt at 1204 — 1 212 words — deriving `pk`/nullifiers from `nk` and
  folding `c` into its digest, preimage 89 words; tier 14 with 4 024 cycles / 273 permutations of
  headroom; v1/v2 byte-identical). Pinned in `tests/guest_provenance.rs`; the §4.4 cheating suite
  (`tests/hidden_cheating.rs`, six cases with real proofs) and `tests/auth_cheating.rs`.
- **Consensus rule** (`Ledger::check_bundle_proof`, gated on genesis `hc_auth` — `Genesis.hc_auth`,
  hashed after `hardening_v6`, paired with `hc_bundle` v3 both-or-neither at `genesis` and at
  startup): on a v3 chain `auth_commit` must equal what the auth proof publishes (cheap, before any
  STARK), the bundle digest is `hidden_bundle_digest_v3` with `c` in the preimage, and both proofs
  verify against the transaction binding (`verify_bundle`, `verify_auth`); a pre-v3 chain requires
  zero `auth_commit` and an empty `auth_proof`. `TxError::{AuthUnexpected, AuthMissing,
  AuthMismatch, InvalidAuthProof}` are permanent. `warm_auth` beside `warm_bundle`.
- **Node**: `rand-node genesis --bundle-guest v3 --auth-guest`; `rand_status` and `rand_getLimits`
  serve `hc_auth`; `tx_json` shows `auth_commit` and `auth_proof_bytes` (randscan reads them there);
  `--prover-fee`/`--prover-fee-address` on the hosted prover. `tests/split_auth.rs`: a real v3
  transaction commits on a v3 genesis; a foreign-binding and a re-salted auth proof are refused.
- **Prover**: `viewing_key` jobs for the v3 guest (exactly 1 212 words) from ANY pairing, own or not
  (`prover_info.witness_kinds`); the **fee**: `run --fee <RAND> --fee-address <rand1…>` (both or
  neither), quoted in `prover_info.fee {amount (base units, decimal string), address}`, checked in
  the opened witness as one RAND output to the prover's `pk` of at least the quote (`-32006`;
  ≥ 2^63 refused cheaply). The prover checks the fee OUTPUT, not its envelope — a wallet can seal
  junk to it (griefing only; the RAND is lost to both).
- **Wallet**: on a v3 chain `rand send` (and every bundle-paying command) makes a fresh 32-byte
  salt, the auth proof locally (always — `sk` never leaves the wallet), and the bundle proof locally
  or through `--prover` as a viewing-key job to whichever prover is paired; a non-own pairing prints
  "this prover can read this wallet's whole history; it cannot spend" before y/N. The fee is one slot
  (spec §5: token transfer/burn → slot 2 fee, slot 3 change; RAND transfer → slot 0 fee, slot 1 its
  change, payment 2, change 3; a bundle paying nobody → slot 2; a single RAND note must be split
  first), bounded by the global **`--max-prover-fee` (default 1 RAND; `0` refuses any)** at the one
  read point of the quote — a hostile prover can otherwise quote anything and `--yes` pays it.
  Prover-supplied strings are sanitised like memos. Refused before proving: a v3 `hc_bundle` whose
  `hc_auth` is null or foreign, and the reverse. Pre-v3 chains send exactly as v0.6.2.
- **Measured** (laptop, test profile): v3 bundle 102 s local / 108–111 s via a paired prover, auth
  6.4–7.4 s; the 2026-09-29 end-to-end run (`docs/prover.md`): a non-own viewing-key-only
  `rand-prover` proved a 5 RAND send, committed, payee credited. A transfer is ~2.85 MB of proofs
  (1.49 + 1.36 MB) — one per 4 MiB block, ~7 per 20 MiB block; aggregation is the remedy.
- **Trap — the wallet's remote path on a pre-v3 chain is unchanged** (a spend-key job to an own
  prover); the same binary speaks both, decided by `rand_status.hc_bundle`.
- **Open (v0.6.4+)**: the wallet does not remember the fee seen at pairing (a prover can raise its
  price up to the cap); the spec §5 "prover assembles and broadcasts" paragraph is deferred (the
  client submits); the prover keeping the fee note's opening; `docs/cli.md`'s genesis table lacks
  the newer flags; `docs/architecture.md` still shows the 2-slot `Bundle`; the node-lib
  `rpc::tests::a_pruned_height_answers_32010…` is a second load flake beside the recorded one
  (passes alone). Clients Phase 2 re-vendors at this tag.

### v0.6.2 — delegated proving, Phase 1 (2026-09-28; tagged `98d1ff6`, released; rolled to all 26 nodes 2026-09-29 by fullnode-cb)

A wallet's bundle proof made on a machine its owner runs (a desktop proving for a phone, a home
server for a laptop). Spec `docs/superpowers/specs/2026-09-28-delegated-proving-design.md`, plan
`docs/superpowers/plans/2026-09-28-delegated-proving-phase1.md`, user guide `docs/prover.md`;
branch `feat/delegated-proving`, rebased onto main at `e1572cd` (v0.6.1 + two test fixes) and
bumped to workspace version 0.6.2; the tag itself waits on chain 16 going live. **Trust model, in
the spec's words: "delegating a proof is handing over custody"** — today's
guest takes `sk` as a private input, so a Phase 1 prover can spend for every wallet it proves for.
**Released 2026-09-28 ~17:20 UTC** (chain 16 live since 16:39 UTC): tag `v0.6.2` = `98d1ff6` on `main`, GitHub release with `rand-node` sha256 `fcd2ff69…1620b`, `rand` `3008cc0f…8520f`, `rand-prover` `85037c5d…492e2b` + `SHA256SUMS`, built on E in `/root/build062` (fullnode = git archive of the tag, circuits = archive of `b9ffc39` beside it, shipped from the laptop by scp — E's `/root/fullnode` is a stale rsync tree; E's clang 18 is fine, clang 23 is only for rand-guest). Smoke on E from the published binary: `keygen`, `pair --own`, `run`, `prover_info` lists v1 + v2 `hc_bundles`, a hostile-origin preflight gets 403. **No fleet roll** — node-only, opt-in; the roll is the user's separate go. Companion: clients `v0.6.5` (pin `e6d1327`) + the re-pin to this tag.

**What it is:**

- **Crate `randprotocol-prover`**: the sealed wire (`wire.rs`, ML-KEM-768 + ChaCha20-Poly1305, the reply under a one-time key, the
  pairing token inside the seal), the prover key and pairing store (`key.rs`, `pairing.rs`,
  `randprover:` links, `own=1` only with `pair --own`), the queue (`service.rs`: per-pairing cap 2,
  `max_queue` 8, `max_parallel` 1, witnesses zeroized; `Service::shutdown` drops the queue, lets a
  proof in flight finish and discards its reply), the `prover_*` JSON-RPC listener (`http.rs`,
  CORS by origin allow-list — default extensions + loopback pages, echoed with `Vary: Origin`; any
  other `Origin` = 403 preflight and `-32007` to every method, so no website can read `kem_ek` as a
  cross-site identifier of a desktop wallet; `--allow-origin`/`--prover-allow-origin`, `*` opt-in —
  `serve_on` a pre-bound listener), a free-memory gate.
  `prover_info` is unauthenticated; a Phase 1 prover's `fee` is `null`.
- **Binary `rand-prover`** (`keygen`, `pair`, `unpair`, `pairings`, `run`; plain HTTP on `127.0.0.1:8600`, TLS by a
  fronting proxy). `run` refuses every `SpendKey` job without `--accept-spend-key`, which prints its
  sentence on stderr, not only in the log.
- **`rand-node run --prover <ADDR>`** (`--prover-home`, `--prover-accept-spend-key`,
  `--prover-max-parallel`, `--prover-max-queue`, `--prover-cuda`, `--prover-skip-memory-check`):
  hosted by `hosted_prover` on **its own listener, never a method of the RPC** (an address equal
  to `--rpc`, or a wildcard on its port, is refused); every check and the bind happen **before the
  node key is read or the database opened**; a prover listener that exits stops the node. On the
  way out: `Service::shutdown`, then the node, then the listener aborted (the order is
  load-bearing — the other way admits jobs while stopping).
- The listener's CORS is an origin allow-list (default: `chrome-extension://*`,
  `moz-extension://*`, `safari-web-extension://*`, `http://localhost:*`, `http://127.0.0.1:*`,
  `http://[::1]:*`; `--allow-origin` / `--prover-allow-origin` replace it; `*` only explicitly) so
  no website can read the desktop wallet's prover key as a cross-site identifier — found by the
  clients repo's final review.
- **Wallet**: `Proving::Remote`, `rand prover pair|show|forget` (`<key>.prover.json`, 0600, one
  pairing; `pair` checks the prover answers with the link's fingerprint), the global `--prover`
  on every bundle-proving command (`call`: only the paying bundle moves; `--prover --cuda` refused
  except `call`'s call proof). Checks: fingerprint, guest in `hc_bundles`, profile, `spend_key` in
  `witness_kinds`, **`own=1` for a spend-key witness**; on the reply the size cap
  (`max_proof_bytes`), **the digest read FROM THE PROOF's public values** (never the reply's field
  — a tainted witness still proves), the field agrees, then a local `verify_bundle` by default
  (`RAND_PROVER_NO_VERIFY=1` skips only that). URL rule: `https://` anywhere, `http://` only to
  `localhost`/`127.0.0.1`/`[::1]`, userinfo refused, the parsed host is the one checked. Polls
  retry through outages, give up (and cancel) after 20 min.
- **NOT in it:** Phase 2 (split authorisation, `ViewingKey` jobs — the prover gets `nk`, can read but
  not spend; needs a guest change and a genesis), fees (`fee: null`), any market or discovery.
- **Roll: node-only and optional** — no consensus, wire or genesis change; `--prover` is off by
  default. **One behaviour change every `rand-node` gets: SIGTERM is handled like ctrl-c** (graceful
  `systemctl stop`, where it used to be killed outright); a unit with `--prover` wants
  `TimeoutStopSec=180` (a proof in flight finishes, ~100 s).
- **Traps found while building:** the chacha20poly1305 `zeroize` feature must be on or copies of
  the cipher key survive; a hygiene test must not scan sealed ciphertext with short needles (random
  hex matches — false positives); `Vec::zeroize` truncates, so assert `is_empty`, not all-zero; a
  wallet must never trust the prover's claimed digest — read it off the proof; URL userinfo
  (`http://localhost:80@evil.com/`) bypasses a host check unless the URL is parsed; tracing-only
  warnings are silenceable by `RUST_LOG` — misconfiguration and the spend-key sentence go through
  `eprintln!` too; the zkvm/mock-cuda tests do not build on the laptop because the sibling
  `circuits` symlink points at `main` while the vendored code is constraint set 7
  (`/private/tmp/circuits-cs7` is the matching checkout); a wrong Co-Authored-By trailer is fixed
  with `git filter-branch` / `--amend`, not a new commit; the v0.6.1 tag's own test suite had two
  stale assertions (the 0.6.0 version pin; the aggregation shape's public height 4 vs the 2^7
  floor's 7) — fixed on main at `e1572cd`, test-only; a branch rebased onto a tag inherits the
  tag's red tests until main is taken instead.
- **Suite on the laptop**, measured on `feat/delegated-proving` rebased onto main `e1572cd`
  (v0.6.1 + two test fixes): core 521+3; prover unit 6, bin 1, http 11, hygiene 2 (108–119 s, one
  real proof), pairing 6, service 10, wire 11; client lib 135; node lib 374 with the 26
  RECURSION_FIXTURES failures only; wallet_flow 7 (1733 s; one send proved through a paired prover
  on a v2-guest chain); cluster 26 (1361 s); zusd_e2e 2 (1839 s); ws 9; genesis_cli 4; prover_flag
  3; prover_hosted 4; submit 2; node bins 22; bridge-codec 4. The zkvm/rvm tests still do not build
  on the laptop (the sibling `circuits` symlink points at `main` while the vendored code is
  constraint set 7).
- **Companions:** clients repo `feat/delegated-proving` — core `prepare_*`/`finish_proof`, the
  engine's prover group with resume, Settings pairing, desktop "Prove for my other devices",
  extension boot resume, a Node e2e wasm → `rand-prover` → node in 126 s; the clients also found
  and fixed a hard-coded `production` FRI profile and a local path that always proved the v1 guest.
- **Open (v0.6.3 / Phase 2):** `docs/superpowers/plans/2026-09-28-delegated-proving-phase2.md`.

### Chain 16 — LIVE 2026-09-28 16:39 UTC (genesis `20925ae6…3005`, build v0.6.1 `2c75e08`)

Genesis `20925ae63cfa6e6c96f3ff369486ead8ea04821fec026a55df9e2893f3d53005`, chain id **16**, file
`deploy/genesis-chain16.json` (sha256 `98036c41…d624`), cut by `deploy/cut-chain16-genesis.sh` with the
macOS build of the tag (its v2 `hc_bundle` `651043e2…839b` checked equal to the Linux release
binary's), rolled all-stop/all-start by `deploy/cutover-fleet-chain16.sh` over all 26 hosts. Chain 15
stopped at ~157 370; its data dirs stay on every host for rollback (retire with
`deploy/retire-chain-dirs.sh` after a day). `--hardening-v6 --bundle-guest v2`, `consensus_domain 1`,
26 validators × 1000 RAND (quorum 18), `faucet_minters` = the 18 operator keys, the chain-15 faucet
allowlist, no aggregation. Bridge: guardian set 1, burn sequence 7, `min_inbound_sequence`
`{2:2,3:2,4:2,5:2}`, the CURRENT endpoints (the 2026-09-29 contract redeploy needs a later genesis to
be usable); zUSD carried: 10 zUSD to Anish, locked Tron USDT 9 + Solana USDT 1, audited
custody == locked == supply after launch. Relayer `rand_cli` → `~/rand-node-a/bin-v061/rand`
(macOS v0.6.1), funded by 3 × 100 RAND faucet mints (blocks 593/600/608); all 8 guardians
co-signing for chain 16. GitHub release v0.6.1: `rand-node` sha256 `aed1a3be…58ad6`, `rand`
`1a6a0419…67ec5` (built on the testbox, Ubuntu 24.04). **Trap from the cut:** chaining
`push … | tail && switch … | tail && start` let `start` run after `push` failed (`LOCAL_NODE`
unset — `push` needs a local rand-node to re-derive the hash) — the pipe's exit status is `tail`'s;
the fleet came back up on chain 15/v0.6 for a minute and was stopped again. Run each phase alone
and read its rc.

### v0.6.1 — constraint set 7 (2026-09-28; tagged `2c75e08`, released, chain 16's build)

circuits `feat/cs7` at **`b9ffc39`** re-vendored by `deploy/sync-zkvm.sh` (CI `CIRCUITS_PIN` =
PROVENANCE.md = `b9ffc39`). **A hard fork: v0.6.1 runs ONLY on a new genesis — chain 16.** Every
verifier key, the AIR and the rVM's programs changed, so no chain-14/15 proof verifies on it; the
node refuses both genesis hashes at `run` and `verify` (`PRE_CONSTRAINT_SET_7_CHAINS` in v0.6.1;
`CHAINS_THIS_BUILD_CANNOT_RUN` since v0.6.3), chains
≤ 13 by their retired `hc_bundle`. **Keep chain 15 on v0.6** until the chain-16 cut
(`deploy/cut-chain16-genesis.sh`, `--bundle-guest v2 --hardening-v6`).

- **What cs7 is:** every LogUp terminal blinded (`BLIND` bus, five appended columns, `F_{p²}` blinds)
  and **every declared table floored at 2^7** (program/input/public `MIN_LOG_HEIGHT` 7, keccak/sha256
  ≥ 7) — INT-2 / GV-1; verifier keys salted from `key_derivation_v2` (HCS-1); 32-bit range checks on
  input/public words and salt lanes (ZKM-1/ZKH-2); `POSEIDON2_LEN` syscall 7 (HCS-4); JALR bit 0
  cleared + funct3 = 0 (ISA-4); guest-sdk arrays / unsafe poseidon2 (R4-b); the pc window on the
  prover and in `Machine::verify` (#53); LRU single-flight key cache (#54); rVM in-circuit VERIFIER-1
  and every chip's writes bound (#58).
- **Pins (all measured on the testbox, 2026-09-28):** `hc_bundle` **unchanged** — v1 `83d3a370…0ef8`,
  v2 `651043e2…839b` (`POSEIDON2` and the program digest did not move). `BUNDLE_PUBLIC_LOG_HEIGHT`
  4 → **7** (the binding and the empty segment now declare the same height; a pre-binding bundle proof
  is refused at `verify_bundle`, `PublicValues`, not on its header). `program_table_rows` floors at 128.
  Admission stub vectors: inner vk digest `ee072b7a…fbe`, interface digest `6059c52a…a6ee` (on the cs7
  fixture cache `/root/recursion-fixtures-cs7`). Production proofs: bundle v1 **1 498 821 B**, v2
  **1 497 156 B** (tier 14); fib tier 10 1 367 688 / tier 12 1 424 299; keccak tier 10 3 283 898 —
  **`MAX_PROOF_BYTES` stays 2 MiB**. `MAX_CALL_TIER` 14 and the DS-3 hash-table caps (12/13) unchanged:
  the worst admissible call header's key (tier 14, 16/16/12/13/15) builds in 11.6 s / 295 MB peak against a
  base tier-14 shape's 8.6 s / 220 MB on the loaded testbox — cs6's ratio (4.7 s vs 3.9 s, laptop), memory flat.
- **Trap — proving got slower:** a Test-profile bundle proof took ~230 s on the testbox (shared with the
  circuits suite). Three tests read the head height *before* waiting for the proving slot and outran
  the bundle window (`wallet_flow`'s token mint, both `bridge_mint` helpers); take the slot first.
- **Vendoring:** `tests/{evm,sbpf}_rt.rs` are now excluded by the script (they test circuits' sibling
  `evm-rt`/`sbpf-rt` crates by `research/`-relative paths); `evm-core` is a dev-dependency again with
  its `ffi` feature for `tests/evm_abi.rs`. `ledger.rs`'s RAND comments are restored after each rsync.

### v0.6 — the zkVM / rVM / aggregation fixes and the v0.6 hardening (2026-09-28; roll status below)

**TAGGED v0.6 = 12a56d1 and ROLLED 2026-09-28 23:36–23:46 UTC, all-stop / all-start** (`rand-node` sha256
`2be892da…e793`, `rand` `d7d9f8b9…3071`, GitHub release v0.6, built on E in `/root/build06`): all 26 hosts staged the
release binaries (sha-checked) with nodes running, stopped together at head 105 435, started together; committing again
~23:39, all 26 healthy on 12a56d1 by 23:46 (block 105 818); public RPC 0.6.0; guardian daemons active. Before it, chain
15's full history (104 850 blocks) was re-verified with the v0.6 binary (`rand-node verify --mode quick` on a copy of
rand-archive-2) — no proof carries a non-zero commit-phase PoW word. Rollback: `/root/rand-node.pre-v06` and
`/root/rand.pre-v06` on every host (= v0.5.10 0c0f4db), all-stop/all-start again. circuits main = 27732e9.
Final checks on 12a56d1: the full suite on 06e688d (only the recursion-fixture tests, the OOM-bound rVM aggregate
binary and the since-fixed TEST-1 failed), then core 518, zkvm lib 21, executor 19, verifier_key 2+1, node lib 351
(21 fixture), genesis_cli 3, client 116, and guest v2's 21 real-proof cheats (HIDDEN_BUNDLE_GUEST=v2) — all green.
Issues #16–#42, #47 closed with commits; open: #43–#46, #48–#52. Reports: ~/Downloads/Rand_zkVM_Bug_Fixes_Report_2026-09-28.pdf
and the four updated scans (Rand_Recursion_VM_Security_2026-09-28_v3, Rand_zkVM_ISA_Security_Review_2026-09-28_v2,
RandProtocol_Automated_Security_Scan_v3_2026-09-28, RandProtocol_Unified_Security_Scan_2026-09-28_v2).

The fixes from the 27–28 September zk reviews (the internal *Recursion VM security* report and its
v2, the *zkVM and ISA security review*, the automated/unified scans, and this session's seven-part
zk scan), each red-first with the red quoted in its commit and re-confirmed by reverting the fix
alone. Report: `~/Downloads/Rand_zkVM_Bug_Fixes_Report_2026-09-28.pdf`; issues #16–#41, #47.
circuits: main `c6cdef4` + `feat/v0.5.11-zk` + `feat/v06-hcs` → pin `4bb4d9a` (CI's `CIRCUITS_PIN`).

- **rVM (dormant; aggregation off everywhere):** RVM-1 (STOREE high lane), OPCODES-1 (reduce clock),
  V-OPCODES-1 (reduce flags on padding), ZKR-4 (reduce run end), OPCODES-4, ZKQ-3, ZKQ-6. The
  registered aggregate program's digest does NOT change; the rVM verifier and self-verifier pins do.
- **zkVM privacy (COV-2 / INT-6, live):** the prover floors the input/keccak/sha256 tables at 2^7
  (80 queries + 2 OOD < 128 random rows); nodes refuse to pool a call proof below it. Bundles were
  never exposed that way. **INT-2 / GV-1** (LogUp totals: which bundle slots are real, leaf
  popcounts): the branch-free guest v2 (`hc_bundle 651043e2…`), selected by a genesis
  (`rand-node genesis --bundle-guest v2`); chain 15 stays on v1 — its docs now say what leaks.
- **One next-cut switch, `hardening_v6`** (`rand-node genesis --hardening-v6`; hashed only when true, so
  chain 15's hash is unchanged): pc window (ZKV-11), uncallable deploys (CPU-1, 8 184 words at tier
  14), canonical proof shapes (INT-5, VERIFIER-2) and commit-phase PoW words (VERIFIER-1), the call
  binding (INT-4), the program-table floor. Each except INT-4 and the floor is ALSO a pool policy now.
- **Node-only:** CPUV-1 (bundle key in its own Machine, one warm-up at a time), HB-1, HB-3, admission
  `catch_unwind`, ZKG-1/2, open-files limit raised at startup (#41), the ssh -A scripts retired (#47).
- **Aggregation interface (dormant):** INTERFACE-1 (slashing retired), -2, -3, -4, -5, -6, -7,
  IFACE-6/7/8/9, V-INTERFACE-2 (signing domain `rand-aggregate-2`), ZKQ-1/2/4.
- **circuits hardening:** HCS-1 interim (rand `=0.10.2`, rand_core `=0.10.1`, verifier-key pins in
  `tests/verifier_key.rs`), HCS-2/3, VERIFIER-1 in `Machine::verify`, ISA-5, AIR invariant tests.
- **Deferred to chain 16 (they change verifier keys):** generic LogUp blinding, ZKM-1/ZKH-2 range
  checks, HCS-4 padding, HCS-1's key_derivation_v2, the rVM's in-circuit VERIFIER-1; INTERFACE-9;
  the end-to-end forged-aggregate exercise (#45, ≥64 GB).
- **ROLL: all-stop, all-start** (the v0.5.6 procedure), NOT one at a time: `Machine::verify` now
  refuses a non-zero commit-phase PoW word unconditionally (circuits VERIFIER-1), so a v0.5.x node
  and a v0.6 node would disagree on a rewritten proof. Honest proofs carry zeros. Wallets ship with
  the node: a v0.6 node refuses call proofs whose private tables are under 2^7 rows.
- **Trap:** every executor trait method with a default must be forwarded by `AggExecutor`, the
  executor every node runs (`the_wrapper_delegates_the_zkvm_surface`).

### v0.5.10 — address sharing and the encrypted memo (2026-09-28)

The launch address stays the ~1,667-char ML-KEM-768 `rand1…` (the user's decision, 2026-09-26: no
standardized PQ KEM has a key under ~700 bytes; a registry, an auto-published key, an X25519 hybrid
and a CTIDH address were each rejected — spec §1). It is made shareable instead. Spec
`docs/superpowers/specs/2026-09-26-address-sharing-and-memo-design.md`, plan
`docs/superpowers/plans/2026-09-26-address-sharing-and-memo.md` (17 tasks across circuits,
fullnode, randscan, randprotocol.org and clients; every task reviewed, then two whole-branch reviews).
**What it is:**

- **Fingerprint** (`randprotocol_core::fingerprint`): 80 bits of `blake3("rand-address-fingerprint-1"
  ‖ pk ‖ kem_ek)`, 16 Crockford chars; seed vector `crates/randprotocol-core/tests/vectors/
  address-sharing.json` → `1WCV-YC8F-47BY-5RZY`. Display only.
- **`randpay:` links** (`randprotocol_core::payment_uri`): address + optional amount (display units),
  asset, memo (≤ 510 B). Every QR encodes one, at level M.
- **The memo**: body plaintext `note (112) ‖ memo field (512)` = `len u16 LE ‖ UTF-8 ‖ zero pad`, sealed
  in the research note layer (`viewing::seal_with_memo`/`memo`, vendored); a malformed field opens as
  no memo, never costing the note. **Genesis `envelope_bytes: 1860`** (only 1860; bound into the hash
  LAST, only when present — chain 14 `1cff3b7d…` and chain 15 `cc30e085…` unchanged) makes every note
  envelope exactly 1,860 B, genesis allocs included (`TxError::EnvelopeSize`, permanent). It turns on
  at the v1.0 genesis (~chain 20, `rand-node genesis --envelope-bytes 1860`); wallets seal the memo
  form only where `rand_getLimits.envelope_bytes == 1860`, legacy 1,348 B elsewhere.
- **Trap — a memo is hostile text on every chain today.** A 1,860-B envelope is ≤ 2,048 so chains 14/15
  accept it, and the opener reads a 624-B body anywhere: anyone can pay a dust note carrying any memo,
  and a link can carry one. Every surface (CLI `memo_display`, UI `ui/lib/memo.js`, iOS/Android
  `Memo.display`, the website) sanitises it and shows it as one non-wrapping line; the CLI bounds the
  line at 1 column per ASCII / 2 per other code point, table-free, after four review rounds found
  wrap forgeries through U+3000, U+2800, skin-tone modifiers and U+3164. Never print a memo raw.
- `WithdrawAggregator`'s envelope now gets the cap every note envelope has (a ruling; refused anyway
  on chains without aggregation).
- **CLI changes:** token amounts (`send --asset`, `token mint`, `token burn`) are display units;
  `rand address` prints only the address on stdout (fingerprint → stderr); `rand send` confirms first
  and refuses a non-terminal stdin without `--yes` (deploy scripts pass `--yes`).
- **Companions:** circuits `research` (the memo seal), randscan `randscan-viewing` (opens the memo body;
  rebuild `frontend/public/viewing/*` before any memo genesis), randprotocol.org (`/address`
  fingerprint + QR + link builder + contacts, `/account` memo column), clients (core re-vendored;
  shared UI, desktop deep link + single-instance, web wallet `web+randpay`, iOS, Android). Apps and
  website ship before any genesis sets `envelope_bytes`; the bridge relayer needs only a `rand` rebuilt
  from this release (it shells out to `rand bridge-mint`).
- **Open (v0.5.11):** a node-supplied token symbol is not length-bounded in the wallet; the
  `RPC_BLOCKING` process-wide semaphore (v0.5.8) makes `rpc::tests::a_token_transfer_reveals…` flaky
  under parallel load (passes alone).

### 2026-09-28 — v0.6 hardening (`feat/v06-hardening`; merged into v0.6)

The 2026-09-27 zkVM/ISA and recursion-VM reviews' remaining fullnode items. **One activation
switch** (the ISA review's R4): top-level genesis `hardening_v6: true`, hashed (tag
`hardening_v6`, appended last) only when true — chain 15 `cc30e085…` stays pinned by
`chain_15s_genesis_file_still_builds_chain_15`. Each rule is every node's **pool policy now**
(non-permanent Ignore) where old wallets allow it, and a **ledger/executor validity rule under the
flag**; `Ledger::hardening_v6`'s doc comment lists them and `docs/deploy.md` "The next cut:
`hardening_v6`" is the operator checklist. **Trap:** every defaulted `ConfidentialExecutor`
method a rule adds must be forwarded by `AggExecutor` (the executor every node runs) — a default
there switches the rule off; `the_wrapper_delegates_the_zkvm_surface` pins them.

- **CPU-1** (medium): a deploy past `executor::max_callable_program_words` — tier 14's 2 048
  Poseidon2 slots less the salt row and the public header, ×4 = 8 184 words (8 180 under the flag,
  whose calls carry the 8-word binding) — is `ProgramUncallable`.
- **INT-5, VERIFIER-2/V-VERIFIER-1, VERIFIER-1**: `executor::non_canonical` pins the memory height
  (`t + 2` without hash tables, 16 for bundles), the FRI folding schedule (`honest_fri_arities`,
  re-derived from `degree_bits`), the random-codeword counts and the commit-phase PoW words (zero)
  — `NonCanonicalProof`. The query PoW word is ground and left alone.
- **INT-4** (flag only — every field wallet proves the empty segment): a call against a program
  without a public input carries `Transaction::call_binding` (`rand-call-bind-1`, both proofs
  blanked) as its public segment; `rand_getLimits.hardening_v6` tells the wallet, which proves the
  call inside `submit_bound_call` (notes, then call, then bundle). Residual: programs *with* a public
  input stay unbound (the ledger holds only their digest).
- **PROGRAM-TABLE-LEAK** (flag only): a call's program table is `max(record height, 7)`
  (`hardened_program_log_height`), emitted by `prove_call_hardened` and pinned by
  `verify_call_hardened`.
- Node-only / dormant: HB-1 (`address::to_research` runs the ML-KEM key decode — a bad key no
  longer panics the faucet), INTERFACE-6 (a pruned record must name its tx and carry its binding's
  `H_PUB`), INTERFACE-7 (duplicate side-table proof hashes refused), V-INTERFACE-2 (the aggregator
  signs the payout envelope's digest; domain `rand-aggregate-2`), HB-3 (`CommitmentTreeFull`, no
  assert in apply), the admission worker's `guard_verify` (a verifier panic is a verdict, not a
  lost worker slot), SAFETY comments. Docs (R1): shielded.md/confidential.md state what the proofs
  leak today. Deferred: INTERFACE-9 (pruning rewrites only the CF_TXS copy of a sealed bundle).

### 2026-09-28 — zk node-side fixes (`feat/zk-node-fixes`; merged into v0.6)

Node-local halves of the zk rescan; the vendored halves are other branches' (`feat/rvm-fixes`,
`feat/zk-privacy-floor`). **Rolls one node at a time; nothing changes chain 15's rules** — its
genesis hash `cc30e085…` stays pinned by `chain_15s_genesis_file_still_builds_chain_15`.

- **CPUV-1 / ZKV-10 (medium, live)**: the bundle key has its own `Machine`
  (`ZkExecutor::bundle_machine`) — eleven deploys of new program shapes no longer evict it from
  the 64-entry FIFO — and `warm`/`warm_bundle` run under one lock (at most one key build a time).
- **ZKG-1**: a bundle proof's published digest is read with `u32::try_from`. **ZKG-2**: the
  `hc_bundle` pin is checked for every `deploy/genesis-chain*.json`.
- **ZKV-11 (pc-wrap)**: a `Deploy` whose padded program table crosses 2^32 is refused at the pool
  on every chain (`admission::deploy_outside_pc_window`, permanent `BadProgram`) and, under the
  top-level genesis flag (next cut), by the ledger. The flag was `program_pc_window`; it is now
  `hardening_v6` (below), renamed before any genesis carried it.
- **COV-2 stopgap**: a call proof whose input/keccak/sha256 table is under 2^7 rows is not pooled
  (`CallRevealsPrivateInputs`, non-permanent, never a ledger rule). **Trap:** until the prover floor
  is vendored no wallet builds a compliant call, so a node on this build pools no call and the call
  stages of `wallet_flow`/`cluster` are refused — merge with or after that re-vendor.
- **The live proof cap is 8 MiB, not 2 MiB**: chains 13–15 set genesis `max_proof_bytes` to
  8 388 608; `gas::MAX_PROOF_BYTES` (2 MiB) is only the default. Older entries below that say
  "2 MiB" describe the default and carry a dated note.

### v0.5.9 — the 2026-09-27 rescan fixes (tagged 2026-09-27; roll status below)

**ROLLED 2026-09-27 08:46–10:11 UTC, one node at a time, no pause.** GitHub release `v0.5.9`
(`rand-node` sha256 `28a0130c…fcce5`, `rand` `14b41094…c6d6`, built on E in `/root/build059`).
Each host downloaded both binaries from the release itself and checked the pinned sha256s before
anything stopped: relaying 47 MB from the laptop stalled at ~170 KB/s upload, so
`update-droplet.sh`'s laptop relay is not the path for a whole-fleet roll. Canary MEM1, then B, F,
the eleven regional, D, C, A, rand-archive-2, E (with `--prune-history 24h` back — the public RPC
now ends at obs1), obs1 last (~3 min public-RPC gap); each back at the head in 25–190 s; then the
six guardian hosts (their own key, `~/.ssh/rand_guardian_ed25519`; guardian daemons stayed
active). Rollback: `/root/rand-node.pre-v059` and `/root/rand.pre-v059` on every host
(= `dd2ccbe`), stop → install → start.

A four-reviewer rescan of `8e64781` (chain 15 live, the chain-15 genesis work never scanned) plus
`cargo audit` (0 vulnerabilities; bincode, derivative, paste, atomic-polyfill unmaintained). Every
fix red-first, each half reverted separately to confirm, the red quoted in its commit. **Node and
wallet only for chain 15 — no wire break, no consensus-rule change on a genesis without the new
fields — so it rolls one node at a time.** Address-sharing (fullnode-8b) is NOT in it: v0.5.10.

- **LEDGER-1 (high, was live)**: a faucet `Mint` was accepted from any key in the validator
  *register*, and a permissionless v2 `Bond` enters the register at once (active 2 epochs later) —
  anyone holding an allowlisted wallet + 1000 RAND could drain `faucet_budget_per_epoch` every
  epoch and bond it toward a third, then two thirds, of the stake. "In the active set" is NOT a
  fix (reachable in ~46 min). Node policy: the pool admits a faucet Mint only from a genesis
  validator (`admission::faucet_minters`, `TxError::MinterNotAllowed`, non-permanent → Ignore).
  Validity rule for the next cut: genesis `staking.faucet_minters` (hashed only when present).
  Validators bonded after genesis can validate but not mint — mint through C.
- **CN-1 (high)**: a failed/abandoned sync batch never backed its peer off, so two silent peers
  claiming the top height alternated for ever. Back-off on failure + the picker ranks misses
  before claimed height (back-off alone loses: the 30 s wire timeout outlasts the 5 s back-off).
- **CN-2**: per-peer meters and the CN-1 back-off survive a reconnect (`PEER_MEMORY_ENTRIES`
  4096); a node-wide `Blocks` budget (burst 32, 8/s); `Blocks` serving runs on `spawn_blocking`
  under `MAX_SYNC_SERVES_IN_FLIGHT` 4 (by-hash stays on the loop — NotHeld liveness).
- **CN-4**: consensus gossip is prechecked (`HotStuff::precheck_gossip`: key/sig lengths, known
  set, one signature verify, size caps, justify-certifies-parent) before it is forwarded, and
  metered by bytes (`consensus_byte_limiter`). A signer we don't know is Ignore (handed to the
  replica, not forwarded), never Reject — we may be behind an epoch.
- **CN-3**: `NotHeld` signs the signer's view (`rand-not-held-2`) and counts only when newer than
  the locked QC and within `NOT_HELD_VIEW_WINDOW` 256; no not-held for a block kept as an orphan.
  The sync wire is CBOR with named fields, so a mixed fleet decodes both ways and neither side
  counts the other's — lock release by NotHeld needs >2/3 on the new build (D15's corner).
- **C15-1 (genesis-gated)**: `bridge.min_inbound_sequence` per source chain refuses an old
  chain's already-minted locks (`BelowReplayFloor`); chain 15 has none — until a cut carries one,
  a guardian brought up with an empty store must start its source cursors past chain 14's last
  lock, never the config's start block (`docs/bridge.md` §23).
- **RS-1 (high, ops + client)**: the public RPC ended at a pruning node; a fresh wallet's first
  `rand_getBlocks(0, …)` got `-32010`. The wallet now resumes at the floor with one warning; the
  public upstream moved to obs1 (archive) through `rpc-tunnel-obs1.service` (`deploy/caddy/README.md`).
- **RS-2 refuted** (below). Still open: CN-5 (orphan leaders from retired epoch sets), RS-4
  (`ssh -A` in the two old cutover scripts), B3, pruning-L1.
- Suite on the laptop: core 476, client 96, node lib 314 (+13 recursion-fixture gap), cluster 26
  (1241 s), wallet_flow 5 (1324 s), zusd_e2e 2 (1719 s), ws 9, genesis_cli 2; rvm/zkvm unchanged
  since v0.5.8.

### 2026-09-27 — RS-2 refuted: the public RPC does not go through F

Suspected: F's Caddy re-enters Cloudflare, so every `rpc.randprotocol.org` caller shares F's
rate-limit bucket. **F's Caddy is `disabled`/dead (never started since boot), F listens on neither
80 nor 443**; DNS goes to the web droplet's own `rpc.randprotocol.org` vhost (installed 2026-09-20
03:04 UTC, website `66a6be9`), which resolves each caller from `CF-Connecting-IP` over Cloudflare's
ranges — the access log shows separate clients metered separately (one curl 429'd while another
client in the same hour was not), none from F. Every note below that says "Caddy on droplet F"
describes a hop that never carried traffic past 2026-09-20; `deploy/caddy/README.md` has the real
chain and the operator housekeeping (dead `set_real_ip_from 159.89.185.254` on the main vhost,
`.bak` files loaded from `sites-enabled/`). **Trap:** a committed config file is not a running
service — check `systemctl is-active` and `ss -ltn` before reasoning from one.

### v0.5.11 — genesis vesting: timelocked RAND for team / investors / partners (2026-09-28, PR #6, genesis-gated: active on no chain)

**Tagged `v0.5.11`** on `main` (PR #6 fast-forwarded). Node-safe on chain 15: without a `vesting`
genesis section the four new actions are refused `UnsupportedAction("vesting")` at admission, so a
v0.5.11 node behaves as v0.5.10 for honest traffic; it only matters at the next cut. Release suite on
the laptop: core 503, node lib 327 (+13 recursion-fixture gap), node bins 18, genesis_cli/submit/ws
green, client lib 114; cluster and wallet_flow **not run**. The zkVM/rVM fixes planned as v0.5.11
become **v0.6** (user, 2026-09-28).

Spec `docs/superpowers/specs/2026-09-28-genesis-vesting-design.md`, guide `docs/vesting.md`, plan
`docs/superpowers/plans/2026-09-28-genesis-vesting.md`. A shielded note cannot be held back, so a
locked allocation lives in a **public vesting register** seeded by a genesis `vesting` section
(absent = every chain to date, byte-for-byte) and enters the pool only when claimed.

- **Schedule = the SAFT's:** nothing until `start + cliff`, then `linear_ms` *after* the cliff,
  continuous or in whole `step_ms` tranches at each step's end (12-month cliff + 18 monthly = months
  13…30). Block timestamp, not height.
- **Actions 24–27**, bundle-less, signed over the genesis hash, nonce per entry (mempool role 5):
  `ClaimVested` (beneficiary; a note to the signed `to`, base to the proposer, like `Withdraw`),
  `RevokeVesting` (revoker; an exact `unvested` amount to the treasury, entry frozen),
  `BondVested`/`UnbondVested` (irrevocable entries only; locked RAND as a validator's stake, back to
  the lock after `UNBONDING_EPOCHS`; the validator's own `Unbond` cannot reach it).
- **State:** `Ledger::vesting`, root appended under **`rand-state-6`**, JSON under `META_VESTING`;
  `reload_ledger` refuses a genesis/database mismatch. Supply counters are kept **off `Supply`**
  (positional blob) via `Audit::with_vesting`. RPC `rand_getVesting [id, at_ms?]`,
  `rand_getVestingSummary`, `rand_getVestingSchedule` (the owner-free lockup table), `rand_getSupply`
  `vesting_*`. CLI `rand-node genesis --vesting`, `rand-node vesting status|claim|revoke|bond|unbond`.
- **Trap found while building it:** the SAFT draft (`../termsheets/`) and the tokenomics paper
  promise *bondable, non-revocable, in-circuit* time-locked notes; the first design (not bondable, all
  revocable, accrual from `start`) would have broken SAFT §5.3/Schedule 2 §4 and §8. The user kept
  the register and took the SAFT fixes; Schedule 2 needs its §8 amendment notice (per-entry amounts
  public under a key) before any investor signs. Read the termsheets before changing lockup rules.
- **Custody:** holders generate their own `rand-node keygen` key; the revoker key offline, never in a
  shell profile. Recommended genesis choice: team revocable, investors/partners irrevocable.

### Chain 15 — LIVE 2026-09-26 13:05 UTC (genesis `cc30e085…`, build `dd2ccbe` = v0.5.8 + the chain-15 genesis work)

Cut on the user's go after the registry-v8 remediation (CS6-1 guest provenance, ZKV-2 Poseidon2
constants as a table, STAKE-2 gated gaps, D1 in the papers). Genesis
`cc30e0854fb25b3abcee96bb7bc206dcd6e37862f6dfe80a05b3e474c2d1b6b8`, chain id **15**, file
`deploy/genesis-chain15.json` (sha256 `bde329aa…3409`), cut by `deploy/cut-chain15-genesis.sh`,
rolled all-stop/all-start by `deploy/cutover-fleet-chain15.sh` (stage → stop 13:04:20 → switch →
start 13:05:24; C, D first). Chain 14 stopped at ~380 620; its data dirs and binaries
(`/root/rand-node.c14`, unit backup `/root/rand-node.service.1cff3b7d.bak`) are kept on every host
for rollback — retire them with `deploy/retire-chain-dirs.sh` once chain 15 has run a day.

- **Same validator keys** as chain 14 (`~/.rand-chain14`), so peer ids and `deploy/nodes.env` are
  unchanged; `consensus_domain: 1` binds every signature to this genesis.
- **Faucet allowlisted** (`staking.faucet_recipients`, 16 wallets: Anish, demo-v05, tester,
  zusd-deployer, relayer, randscan activity w1, and ten new demo wallets whose keys live in
  `~/.rand-chain15/wallets/`); a mint to anyone else is refused. Faucet budget 10 000 RAND per
  1000-block epoch; weight cap 3333 bps; entry budget 10 000 RAND/epoch; 2-epoch bond delay;
  v2 registrations (`rand-node register --v2`). Testnet — mainnet is v1.0; validators prune 24 h,
  obs1 and node A keep everything.
- **Bridge**: guardian set 1 at index 1 (next rotation must carry 2), eight successor Dilithium2
  keys (droplet-held seeds for positions 0–5), chain 14's pause key, `burn_sequence` 7,
  `rules_v2` (global cap 4 000 zUSD / 24 h). Replay of a chain-14 mint is refused: the PQ
  co-signature binds chain id 15.
- **zUSD carried over at genesis**: before the cut the tester wallet burned 26 zUSD (seq 4 ETH 9,
  5 BSC 9, 6 SOL 8; released by the relayer, audited custody == locked). The 10 zUSD left — all
  Anish's — are listed at genesis: same asset id `32e5ab28…`, backings locked Tron USDT 9 /
  Solana USDT 1, one genesis note to his address. `total_supply == Σ locked == custody` at block 0.
- Relayer funded by 3 × 100 RAND faucet mints (blocks 32/36/40).
- **2026-09-27, off the laptop and 26 validators.** Validator A moved to droplet `rand-node-a`
  (139.59.238.151, sgp1; same key, `--prune-history 24h`); the laptop's launchd job is retired and
  `deploy/run-a.sh` refuses to start (two signers on one key = equivocation); the laptop keeps
  only an SSH tunnel on 127.0.0.1:8545 → A's RPC for the bridge daemons still there. New second
  archive `rand-archive-2` (206.81.29.236, fra1, 250 GiB volume `/mnt/rand_archive_2`, full
  history). Both droplets and the six guardian hosts live in DigitalOcean team "My Team"
  (dendi@systematictrading.group); the 17 original validator droplets are in another team whose
  token is not on this machine. Eight nodes were bonded as new validators (1 000 RAND each,
  registration v2, payout wallets `~/.rand-chain15/payout/`, registrations
  `~/.rand-chain15/registrations/`): obs1, rand-archive-2, and guardian hosts 1–6 (their node key
  `/var/lib/randnode/node.key.json`; `--validator --prune-history 24h` in the `chain15.conf`
  drop-in) — the user chose the guardian hosts against the BRG-14 custody advice. Register = 26;
  the eight activate at epoch 43. Funding: genesis alloc wallets shielded-1..5 + a 100-RAND
  top-up each, and 9 merges each in demo-01/05/08 (a bundle spends at most two notes). The bridge session owns the
  relayer, guardians and the six guardian observer droplets.
- **Trap from the cut:** `rand-node alloc-note --amount` scaled zUSD by RAND's 10^9 (100 zUSD for
  "10"); fixed in `d6f6425`, caught by the cut script's Σ notes == Σ locked check. Also:
  `git merge --ff-only X && … ; git push` pushes the unchanged local ref when the merge fails —
  never chain a push after a merge with `;`.

### v0.5.8 — the pre-release scan fixes (2026-09-26)

A ten-reviewer scan of `d56a97a` (v0.5.7 + AGG-2) plus `cargo audit`, every candidate re-traced and
refuted where possible; the report is `~/Downloads/RandProtocol_PreRelease_Security_Scan_2026-09-26.pdf`
(read it before re-reporting). Fixed on `feat/fix-{consensus,node-net,rpc-prune,wallet,deploy}`,
stacked linear as `feat/v0.5.8`, every fix red-first with the red quoted in its commit. **Node-only:
no genesis, wire-format or consensus-rule change for honest traffic — rolls one validator at a
time**; a relayed Status is now ignored (one hop), which an older node's forwarding does not break.

- **SW-1 (critical)** `hotstuff.rs::check_orphan`: an unknown-parent proposal is kept only if its
  proposer leads its view in a set this replica knows, its height is within `max_tree_blocks` of the
  committed head and its view above it, and its tx count, byte size and tx root hold; the pool is
  capped at `max_orphan_bytes` (64 MiB) and evicts its highest blocks for a lower one. Before, any
  self-made key pinned ~4 GiB on every node. `node.rs::on_consensus_gossip` meters consensus gossip
  per forwarder (burst 256, 64/s; over budget = Ignore, not forwarded).
- **SYNC-1 (high)** `on_status_gossip`: a Status is read only when `from == propagation_source`
  (Permissive gossipsub lets an unsigned message claim any author); `floor > height` is Rejected.
  `ValidationMode` deliberately unchanged (Strict needs a canary).
- **CONS-1 (high)** `on_vote`: votes beyond `view + PROPOSAL_VIEW_WINDOW` are ignored and one vote
  counts per (view, voter) (`vote_of`; a second is logged as equivocation) — one validator key could
  fill the 4096-key vote map and stop every QC. A replica >8 views behind builds no QC from votes;
  it catches up through proposals, NewViews and sync.
- **WAL-1/WAL-2 (high)**, client: a token id never resolves to index 0 and must match the row it
  resolves to; `send`'s unit follows what was typed; a node-reported registration fee above 10 RAND
  needs `--fee`. **WAL-3**: `rand sync --rescan`; replies capped at 64 MiB. Residual: a lying node
  can still map a real id to another token with index ≥ 1.
- **Medium/low:** RPC blocking reads capped at 16 (`MAX_CONCURRENT_RPC_BLOCKING`, busy after 2 s) so
  the awaited prune pass cannot starve; inbound sync requests metered per peer (burst 8, 2/s) and
  signed not-helds cached (`NotHeldCache`); a peer answering a live batch with nothing is backed off
  5 s → 120 s; prune cutoff `min(head, now) − keep`; the compaction flag cleared by a drop guard.
  The scan's OPS-4 (`--prune-history` refused on a faucet-off genesis) was written and **reverted
  before the tag**: chain 15 is a testnet with its faucet off (STAKE-2) and must prune; mainnet is
  v1.0, and the archive rule stays a docs rule until a genesis carries an explicit network marker.
- **Deploy:** `deploy/lib/clean-tree.sh` (rebuild/push ship `git archive HEAD`, never `wallets/`);
  `WANT_SHA_WALLET` beside `WANT_SHA` (the `rand` binary is checked too); `deploy/lib/relay-
  binaries.sh` replaces `ssh -A`; `deploy/install-launchd.sh` (launchd runs copies under
  `~/rand-node-a`); `deploy/caddy/README.md`; rustls 0.23.45 (RUSTSEC-2026-0285).
- **Deliberately NOT done:** a pruned node answering `Block(None)` instead of a signed NotHeld
  (pruning L1) — every chain-14 validator prunes, so only node A could still attest and the
  CON-4 lock release would lose its quorum (the 2026-09-24 ghost-lock stall). Needs a design.
- **Operator, open:** delete old `wallets/` and log copies from E's `/root/fullnode`; commit F's live
  Caddyfile under `deploy/caddy/`; turn the faucet off on F; the two chain 7–13 cutover scripts still
  use `ssh -A` (do not reuse). Clean in the scan: AGG-2, pruning storage, bridge (123 tests +
  probes), shielded pool/tokens, git history.


### AGG-2 — the aggregate proof binds its aggregator (2026-09-25, on `main`, in no tag yet)

Audit v3's AGG-2 (plan task C4). The rVM interface is now `[vk ‖ N ‖ B(8) ‖ 34·N]` with
`B = aggregate_binding(chain_id, aggregator, nonce)` (`types/actions.rs`), vendored from circuits
`573ef2e`. `ConfidentialExecutor::verify_aggregate` takes the binding. Admission step 8
recomputes it from the transaction, and the `aggregate --watch` daemon reads its nonce before
proving. A re-signed aggregate is refused (`a_resigned_aggregate_is_refused`; the stub checks
the binding of proofs made with `StubExecutor::make_aggregate_proof`). The aggregate program
digest changed, so **the production proof batch must use this program**, and any chain's
`aggregate_program_digest` is measured on a build that carries it. No live chain carries an
`aggregation` section, so nothing live moves. The capstone (`tests/cluster.rs`) is still
`#[ignore]`d for the unrelated b053a76 shape re-measurement, so the end-to-end prove of this
change is the rVM's own tier-19 round trip (circuits, 1897 s).

### v0.5.7 — history pruning (2026-09-25)

**Released and ROLLED 2026-09-25.** Tag `v0.5.7` = `089bdd6`, GitHub release with the E-built binaries
(`rand-node` sha256 `c8b3539b…2bbe`). Suite on the laptop: core 437, client 90 + wallet_flow 5,
node lib 301 (+21 recursion-fixture gap), node bin 10, cluster 25 (1261 s), genesis_cli 2, submit 2,
ws 9, zusd_e2e 2 (1683 s), bridge-codec 4; CI green; rvm suites not completed on the laptop
(aggregate.rs OOM-killed; no rvm file changed since v0.5.6).
**Roll: all-stop, all-start, NOT one at a time** — found while planning it: a v0.5.7 node cannot
decode a v0.5.6 `Status`, so among v0.5.6 peers `best_peer_height()` is 0 and a restarted node never
batch-syncs (it would sit ~700 blocks behind fetching parents one by one). Staged sha-checked
binaries as `/root/rand-node.new` on 17 droplets + obs1; stop all 04:23:27, install, start all
04:23:40 UTC; node A on `bin-089bdd6` (run-a.sh default). The chain paused at 287 354 and committed
again ~04:55 (13 back); all 17 at head by 04:58. obs1's data moved during the stop onto the
DigitalOcean volume `randbridge-archive` (250 GiB, sgp1, mounted `/mnt/archive`, the datadir is a
symlink to it); obs1 went v0.5.1 → v0.5.7 (the at-open QC prune dropped 287 354 certificates in
6 min, then a full verify of 287 356 blocks, done 05:03). obs1 = the archive, no flag.
**Pruning switched on after the roll, per node:** `--prune-history 24h` appended to each unit's
ExecStart, restarted once through a drop-in adding `--verify-chain off` (the same binary had
verified that data 35 min earlier; the drop-in is removed right after, so the next restart
verifies normally). Canary MEM1 04:58: passes of 512 blocks take 0.55–0.70 s (1-vCPU 48 GB
droplets 0.3–0.6 s), the node stays within two blocks of the head, so waves of four followed
(05:01 SYD1 NYC1 SFO2 BLR1; 05:10 F LON1 AMS3 ATL1; 05:11 C NYC2 SFO3 TOR1; 05:12 B D E MKC1).
The chain kept committing throughout. A full drain is ~2.5 h (≈220k blocks at 512 per 16 blocks).
Node A keeps full history (laptop disk is ample): a second archive beside obs1. Verified: obs1
answers `rand_getBlockByHeight(1000)`, a validator answers `-32010` naming its floor.
**Drained by 07:33 UTC:** every validator keeps ≤ 65.5k blocks (one day), block tables 3.3–4.4 GB (were 19 GB), disks 18–37% used; obs1 19 GB of tables, full history.
Rollback: re-pin `a2d4021` only on an unpruned datadir (obs1, A); a pruned one needs
`--verify-chain off` or a re-sync from obs1.


The 2026-09-24 disk incident's fix (five of twelve droplets crash-looping on ENOSPC, the fleet
lost quorum at height 248 953): a testnet-only node keeps one day of blocks and prunes the rest
(design `docs/superpowers/specs/2026-09-24-history-pruning-design.md`). Branch
`feat/history-pruning`, node-only, no genesis or consensus change.
**What it is:**

- **The flag.** `rand-node run --prune-history <n>m|<n>h|<n>d` (`24h`, `36h`, `2d`); refused
  below `1h` at startup. Absent means never prune — an archive node.
- **The pass.** Every 16th committed block, `Storage::prune_history` deletes `blocks`, `qcs`,
  `block_index`, `txs`, `receipts`/`receipts_by_program` and `seals` for everything below
  `head_timestamp - prune_history`, up to `PRUNE_PASS_MAX = 512` blocks per pass in one synced
  `WriteBatch`. It never touches the ledger (`notes`, `nullifiers`, `anchors`, `validators`,
  `programs`, …), never deletes genesis, the head, the head's parent, or anything inside an
  aggregation window. The floor (`META_PRUNE_FLOOR`) only rises; disk comes back after
  compaction, every 64th pass.
- **The archive rule.** Exactly one node, obs1 (`ARCHIVE` in `deploy/nodes.env`, data dir on a
  volume), runs without the flag and keeps every block forever. **Mainnet units never pass the
  flag** — `docs/deploy.md` says so in the unit template.
- **`Status.floor` is a wire-coordinated change, rolled in one pass, not gradually.** bincode is
  not self-describing, and the incompatibility is one-directional (pinned by a decode test,
  `network::wire`): a v0.5.7 node cannot decode a v0.5.6 peer's `Status` at all (eight bytes
  short — refused, never misread), so that peer is invisible to `pick_sync_peer`. A v0.5.6 node
  still decodes a v0.5.7 peer's `Status` fine, reading only its own known prefix and never
  seeing the floor — so an old node can still pick a peer that has in fact pruned the height it
  needs, and that batch just comes back empty. Either way there is no reliable batch sync
  between mixed versions for the roll window; consensus (votes, new-views, proposals) is
  untouched and blocks keep committing throughout.
- **Startup verification on a pruned node is structural, not a replay**: block 0 and the head
  range's blocks, QCs, parent links and leaders are checked; `load_ledger`'s snapshot is
  trusted. **A structural failure there is fatal** — the node holds one ledger and truncating
  would pair the remaining blocks with state they didn't produce — `check_and_repair_chain` and
  `verify --repair` both exit rather than truncate: re-sync from the archive.
- **RPC.** Error `-32010` (`data.floor`) answers a height-addressed lookup below the floor
  (`rand_getBlockByHeight`, `rand_getFinality` by height, `rand_getBlocks`/`rand_getCompactBlocks`
  reaching a pruned height, `rand_getTransaction`/`rand_checkTransaction` naming one). Hash-only
  lookups (`rand_getReceipt`, `rand_getCallEnvelope`, `rand_getAggregate`,
  `rand_getRawTransaction`, `rand_getBlockByHash`) keep answering `null` for a hash this node
  doesn't hold — only an archive can say "pruned" from "never existed". `rand_status` gains
  `prune_floor` (u64) and `prune_history_secs` (`null` when unset).
- **Rollback:** a pruned data directory opened by a build ≤ v0.5.6 with the default
  `--verify-chain quick` replays from genesis, finds block 1 missing and truncates the whole
  ledger to genesis; run an older build on a pruned data directory only with `--verify-chain
  off`, or re-sync from the archive.

**Roll (operator, not yet run), in order:**

1. **Archive first.** Move obs1's (randbridge-web) datadir onto a volume, no flag, before
   anything else touches the flag; confirm `rand_status.prune_floor == 0` and the head still
   follows the fleet. `rpc.randprotocol.org` is served by droplet F, which will prune: repoint
   the public RPC at obs1 before the roll, or accept `-32010` for heights older than a day there
   — the operator's choice.
2. **Wait until the chain is committing again.** Never roll a wire change onto a halted chain.
3. **The seventeen droplets, one at a time**, built on E from the tagged commit:
   `PRUNE_ARGS="--prune-history 24h" deploy/update-droplet.sh <ip>`, waiting for
   `rand_status.height` to reach the head and one more block to commit before the next. **Measure
   the first rolled validator's pass duration in its log before continuing**: a first pass over a
   backlog is awaited synchronously in the node's post-commit loop up to
   `PRUNE_PASS_MAX = 512` blocks, so a validator holding much more than a day of history could
   stall its own commits for the pass's duration on that first activation. **Gate each step**:
   roll the next droplet only after the previous one's `rand_status.prune_floor` is within a day
   of the head (its drain finished, ~2–3 h at 512 blocks a pass); never have more than one
   validator draining at once.
4. **Node A last**, separately: `BINDIR`/`PRUNE_ARGS="--prune-history 24h"` in `run-a.sh`'s
   environment, then `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a`.
5. **Verify:** every validator's `prune_floor` rising, `du -ch db/*.sst` falling and flat, obs1
   answers `rand_getBlockByHeight(1000)` while a validator answers `-32010`, a fresh observer
   synced from obs1 reaches the head.

### v0.5.6 — the deep security-and-math scan (2026-09-25)

The scan the user ordered after the audit fixes ("issue another scan for deep security and math
issues and fix them too"): nine reviewer dimensions, every candidate re-traced by an adversarial
verifier with a reproduction (design `docs/superpowers/specs/2026-09-24-deep-scan-design.md`,
findings `../security/fullnode-deep-scan-2026-09-24.md` — read it before re-reporting). Branch
`feat/deep-scan`, every fix red-first with the red quoted in its commit. Node-only, same chain.
**What it is (DS-1 … DS-9):**

- **DS-1 (critical)** `6f4e50e`: a sealed-form side table's pruned record is length-checked
  before any block applies (`BlockError::MalformedPrunedRecord`, `PrunedBundle::
  public_values_array`); the digest check reads with `get` → `BadDigest`; `apply_synced` never
  unwraps a peer's list. Was a panic on a 33-word record (unreachable on chain 14: no
  aggregation section).
- **DS-2 (critical)** `a76bc8f`: `connection_limits` on the swarm — 256 established inbound,
  64 pending, 2 per peer (`WireLimits`, inbound only); `Node::peers` held to the same bound for
  disconnected entries. **DS-5** `8fa0a75`: a gossiped `Status` updates only an existing entry
  and is metered per forwarder (a never-connected author bypassed DS-2 through `or_default`).
- **DS-3 (high)** `1588be9`: `ZkExecutor::verify_call` pins a call proof's header before
  `Machine::verify` builds a key — `MAX_CALL_TIER` 14 (a tier-20 header measured 216 s / 6.5 GB,
  an OOM kill of a 2–4 GB validator), keccak ≤ 2^12 and sha256 ≤ 2^13 (the hash tables'
  preprocessed columns dominate: both at the tier's honest bound = 209 s / 10 GB), program
  height = the deployed record's, input height ≤ the tier's. `warm` and the cap share one list;
  worst admissible header 4.7 s / 312 MB. **A validity rule at apply too** — every chain-14 call
  is tier 10, chain 13's tier-16 ERC-20 `approve` would now be refused. Residual: the vendored
  64-entry key cache retains every key it builds (~60 MB each at the cap) — upstream.
- **DS-4 (medium)** `65f7361`: the equivocation record (`proposed`) outlives the tree's eviction
  and a dead branch's pruning, bounded by `MAX_PROPOSED_KEYS` 4096 (oldest views first) — 600
  siblings evicted the first ~90 and re-opened their views to a second block.
- **DS-6 (medium)** `5a5a026` + `61eb5f8`: `notes::MAX_NOTE_VALUE = 2^63` — the guest's u63
  range check made a larger mint or deposit unspendable for ever while counted in the supply.
  Admission refuses it on every chain (`admission::oversized_note`, permanent); under the genesis
  flag `tokens.bound_note_value` it is a validity rule on `TokenMint`, the initial mint, a
  deposit and the running supply (`AmountTooLarge`/`SupplyTooLarge`; `RegistryExtDisk` carries
  the flag; `rand_getTokens` serves it, `b4dcde7`). The saturation audit found no site that
  creates or destroys value.
- **DS-7 (low)** `59e43a9`: one `consecutive_views` helper (checked arithmetic) for the live
  commit rule and the sync path. **DS-8** `a18f9f1`: "more than a third" → quorum in three
  comments, a log line and deploy.md. **DS-9 (ops)** `944163a` + live: `deploy/fleet-watch.sh`
  + LaunchAgent (5 min), `update-droplet.sh WANT_SHA`, F's Caddy attribution, the web droplet's
  backup plist path.
- **Rejected, recorded:** a justify-certifies-parent check in `execute_and_insert` (the proposer
  signature covers the justify; the test could not go red) and key/signature length at
  deserialize (`33b048c` reverts it: the four downstream length checks and their tests became
  unreachable). Bridge and consensus-liveness dimensions: no new finding (B3 stays v0.6).

**Released 2026-09-25: tag `v0.5.6` = `a2d4021` (main), GitHub release published with the E-built
binaries, `rand-node` sha256 `8edb8dbb…`; suite on the laptop: core 437, client 90, executor 17,
node lib 282 (+21 fixture-gap), cluster 24 (1268 s), submit 2, ws 9, zusd_e2e 2 (2392 s),
genesis_cli 2; whitepapers `360dbb3` pushed; the fixes PDF in `~/Downloads` regenerated.**
**ROLLED 2026-09-25 18:36–19:14 UTC** with `deploy/roll-all.sh` (install with sha check on all 17 at
18:36, stop all 18:43:37, start all 18:43:42, node A via launchd): the chain paused at 258 973 and
committed again once 13 were back at ~19:09; every node `ok` on `a2d4021` at 19:14 (the 48 GB
droplets' startup verify took up to 30 min at 259k blocks — plan the pause for that, not 15 min).
**Roll: all-stop, all-start** (`deploy/roll-all.sh`, the v0.5.5 procedure) — DS-3 is a validity
rule and the public RPC admits anyone's submissions, so a mixed fleet is a fork window; the
independent review's one finding, `docs/deploy.md` "Roll note for v0.5.6". Rollback = re-pin
`0154fe2`. **Open for the operator:**
guardian keys in the shell profile (BRG-14), the 48 GB resize vs D19, the TronGrid key, node A
on a laptop, all 18 validator keys one party's; remove any `wallets/` (spend keys) and log copies
earlier `rebuild-vps.sh`/`push-to-vps.sh` runs synced into E's `/root/fullnode` (OPS-1: they rsynced
the working tree; they now ship `git archive HEAD` only, and the next run's `--delete` drops them —
check backups and other hosts too). The whitepaper's fifth reconciliation pass
(`rem:bridgeimpl`, the table, a taint proposition) lands in `../whitepapers`.

### v0.5.5 — the audit-v5 fixes and the chain-14 recovery (2026-09-24)

Audit v5 (`Rand_Final_Audit_v5_Key_Findings.pdf`, closed against `919a7a4`, i.e. before
v0.5.4) — spec `docs/superpowers/specs/2026-09-24-audit-v5-v0.5.5-design.md` (§1 maps each
finding), plan `docs/superpowers/plans/2026-09-24-audit-v5-v0.5.5.md`. Everything node-only or
genesis-gated; chain 14's rules unchanged. **What it is:**

- **OPS-4 (high): a committed block's QC is stored once.** `CF_QCS` keeps genesis' row and the
  head's; every other height's QC is its child's `header.justify` (`qc_by_height`); a v0.5.4
  database is pruned once at open (`prune_committed_qcs`, marker `META_QCS_PRUNED`, then a
  compaction — ~12 GB back per validator). **A node rolled back below v0.5.5 needs a resync.**
  Slope after: ~60 KB a block (the justify inside the header) ≈ 3.6 GB/day at 1.4 s blocks.
- **CON-4 per v5:** the lock releases only on a not-held **quorum** (`has_quorum`, strictly more
  than two thirds; v0.5.4's third was the v4 wording); **durable pending blocks** — every certified
  block above the head is persisted (`META_PENDING_BLOCKS`, replaced whole, emptied on commit) and
  restored by `resume` through `execute_and_insert`; `META_LOCKED_BLOCK` is read once and retired.
- **The three recovery rules, from the stall:** `resume` drops a persisted high QC whose block is
  not among the restored pending blocks (a ghost by construction); `fallback_high_qc` and that
  drop land on the highest QC certifying a block the replica holds (`highest_held_qc`, not blindly
  `head_qc` — F and lon1 had fallen back to their committed 248947 and proposed useless siblings);
  by-hash fetches expire after `sync_request_timeout` (an inflight request libp2p never answered
  nor timed out blocked every later attempt, so no leader reached the eight failures the fallback
  needs — node A managed two attempts per leader turn).
- **TOK-2 (gated):** `tokens.burn_registration_fee` — the registration fee is burned, the proposer
  keeps `fee − registration_fee`; `Ledger::registration_fees_burned` is derived state beside
  `META_SUPPLY`, audited in replay, served by `rand_getSupply`, subtracted in the supply identity.
- `tokens_v2` is JSON through a storage-side mirror (`RegistryExtDisk`; the windows' tuple keys
  as a list) so an appended `RegistryExt` field reads as its default; a v0.5.4 positional blob is
  still read. The WAL-cap test polls (the v0.5.4 tag's CI failure was a mid-flush read).
- `deploy/retire-chain-dirs.sh <ip> [--dry-run]`: the 2026-09-21 cleanup as a guarded script.
- **Website (separate repo, deployed):** WEB-2/3 — the balance page takes a viewing key only, both
  WASM modules are hashed against a pinned digest before they run (`public/*/SHA256`, `BUILT_FROM`);
  WEB-5 — a sale deposit is credited only when two independent sources report it (EVM: two RPCs;
  Tron: TronGrid plus a second operator's receipts). **TronGrid answers 429 without
  `SALE_TRONGRID_KEY`** — Tron deposits were not being scanned before either; a free key fixes it.

**The chain-14 stall, second half (afternoon):** v0.5.4 did not unstick it. The ghost QC (view
261719, block `c82058995dbb9526…` at height 248954, lost from every tree) was restored from every
node's persisted safety state at each restart and re-announced by every NewView; the only path
that discarded it was a leader's eight failed by-hash fetches, and that chain died at the first
request libp2p never answered (see the recovery rules above). Restarting the twelve tip nodes
together at 12:44 UTC only reset their attempt counters; d reached the fallback at 13:13 on its
own. **v0.5.5 is rolled to all 18 at once (stop all, start all)** — with the resume rule, no node
comes back believing the ghost. Six nodes (A, F, lon1, sfo2, nyc1, syd1) sit at 248947 holding
248948–248953 pending; they commit those the moment a QC forms on a child of 248953.

**Not in v0.5.5** (spec §1 and the v0.5.4 §12 list): B3 pacemaker, AGG-2/C4, TOK-3/D17, ZKV-2,
BR-4/BRG-14 custody (the set-1 guardian private keys are still in the laptop's shell profile),
BR-3 multisig/timelock, DOC-4/PA-7, D19 (idle interval — the numbers are above). **Next:** the
deep security-and-math scan, `docs/superpowers/specs/2026-09-24-deep-scan-design.md`.


### v0.5.4 — the audit-v4 fixes (2026-09-24), on `main`; roll status in the tag and the memory

Audit v4 (`Rand_Audit_v4_Summary_for_Dendi.pdf`, 2026-09-21, six slides against v0.5.1; the
67-page report is not in this repo) — spec `docs/superpowers/specs/2026-09-24-audit-v4-v0.5.4-design.md`
(the finding → fix table is §1), plan `docs/superpowers/plans/2026-09-24-audit-v4-v0.5.4.md`. Built
as `main` + the 18 `feat/security-concerns-2` commits (VK-1/2/3, RPC-2 metering, issue #4, RPC-1
tree-once-per-change, PRIV-1 wallet-side witnesses, B5, CS6-3, AGG-3/4/6, CHAIN9-1, CI, the
`69010a43…` genesis re-pin) + three parallel waves, each reviewed clean by an independent pass.
**Three classes of change, and the class decides how it ships:**

- **Node-only** (same-chain, rolls like v0.5.1): OPS-3 disk guard (`--min-free-disk-mb`, default
  1024; `rand_getHealth` says `disk_low` under 4×); CON-3 sibling bound (one block per (view,
  leader), `PROPOSAL_VIEW_WINDOW` = 8 views, off-branch eviction when the tree is full — the
  2026-09-24 stall's "propose failed: too many speculative blocks in memory" can no longer
  happen); the **ghost-QC memory** (`HotStuff::unobtainable`: a QC on a block every fetch failed
  for is not raised again until the block arrives — the livelock that held chain 14 for hours
  after a whole-fleet restart, found and fixed during this release); the 256 MB WAL cap
  (`d187df4`); PROC-3's comment and the release rule (`docs/deploy.md`).
- **Wire-coordinated**: CON-4 — the lock is lowered ONLY on signed `NotHeld` attestations from
  strictly more than a third of the current set's stake (`SyncResponse::NotHeld`, domain
  `rand-not-held-1 ‖ genesis ‖ hash`); `fallback_high_qc` no longer touches `locked_qc`; the locked
  block is persisted beside the lock (`META_LOCKED_BLOCK`) and restored by `resume` when it sits
  on the head. Old peers never answer `NotHeld`, so in a mixed fleet a lock on a lost block holds
  until every validator runs v0.5.4 (D15: accepted).
- **Genesis-gated** (chain 14 byte-for-byte unchanged; the next cut switches them on, see
  `docs/deploy.md` "The next cut"): STAKE-2 `staking` section (faucet ⊕ bridge refused at
  `validate`; `faucet_budget_per_epoch` as state under `rand-state-5`; `bond_activation_epochs`
  with `activation_epoch = e+1+N` on the entry, leaf `rand-validator-leaf-4`); `consensus_domain: 1`
  (every vote/new-view/proposal signs the genesis hash under the `-2` tags); bridge `rules_v2`
  (`RotatePqGuardians` = `Action` 22, `RotatePauseKey` = 23, messages in `docs/bridge.md` §21;
  rolling per-backing and global mint caps in a `RegistryExt` side table under `tokens_v2`;
  listing refused while paused; `rotation_nonce` under `bridge_state_v2`, root
  `rand-bridge-state-5`); `tokens.max_tokens` (+ `rand_getTokens` by range).

**Not in v0.5.4** (spec §12, each with an owner): B3 pacemaker redesign; AGG-2/C4 (circuits,
before the proof batch); TOK-3/D17 (paper); ZKV-2 (research repo); BRG-14 key custody (ops: the
laptop's shell profile holds the set-1 guardian private keys in plain text — move them; never
quote them); `CF_TXS` pruning and the QC-per-block disk slope. **Website** (separate repo, all
deployed 2026-09-24): WEB-1 (bulk `rand_getNullifiers`, intersect in the browser), WEB-4 (nginx
strips `CF-Connecting-IP`; `client_ip` reads `X-Real-IP` only), a CSP on `/account` and
`/address` generated from the built pages (`server/csp-keypages.sh`; deploy with
`server/deploy-site.sh`, not the old `randdeploy` alias).

**Traps from this release:** three parallel waves each re-fixed the same rebase seam (the PRIV-1
`NoteStore` deserializer lacking `main`'s `genesis` field) — when a base branch does not build,
fix it on the base BEFORE forking waves. `git rebase --skip` on a conflict skips the commit
being applied, not a dropped duplicate; check `rebase-merge/message` first. Astro's
`security.csp` cannot serve a site with Shiki-rendered docs (its style hashes make
`'unsafe-inline'` dead). The recursion-fixture tests (`agg_executor::`, `seal_tests`, 21 in the
node lib) cannot run on this laptop; the release suite skips them by name.


### 2026-09-24 — chain 14 stalled on full disks: 13 GB of unpurged RocksDB WAL per validator, ~110 KB of Dilithium2 QC per 1 s block

Found while verifying a CLI fix against the public RPC. **Every chain-14 validator's data dir was
~40 GB after four days: 27 GB of SST plus 13 GB of write-ahead log (`db/*.log`, 216 × 133 MB)
that RocksDB never purged.** A log file lives while *any* column family still holds unflushed
rows from it; the per-block families that get a few bytes a block (`anchors`, `epoch_sets`,
`notes` on a quiet chain) never fill a 64 MB memtable on their own, so under the default
`max_total_wal_size` (zero = four times every family's write buffers, gigabytes across seventeen
families) they pinned every log since their last flush. The twelve 48 GB droplets were at
93–100 %; f, lon1, sfo2, nyc1, syd1 crash-looped (F: restart counter 7 828, each attempt dying at
the recovery flush with ENOSPC), blr1 and c sat at 100 % still running; **quorum was lost and
the chain stalled at height 248 953 from ~02:00 UTC** (views kept advancing, E's mempool held 140
transactions with the oldest 75 h old). Node A had died at 02:04 UTC too and the laptop rebooted
at 06:06 UTC.

- **Growth model** (F's RocksDB LOG, flushed bytes per family): `blocks` 14.9 GB and `qcs`
  12.1 GB over ~249k blocks — ~60 KB + ~49 KB a block, i.e. an 18-signature Dilithium2 QC
  (18 × 2 420 B) stored twice, in the block's `justify` and in the `qcs` row. The fleet runs the
  default `--block-interval-ms 1000` (measured ~1.4 s a block), so an **idle chain grows
  ~6.6 GB/day of SST** before WAL retention. A 48 GB droplet lasts ~3 days from a cut. Only a
  storage redesign changes the slope (store the QC once; prune or aggregate committed QCs; slower
  idle blocks) — the previous entries' "chain 13 grew ~16 GB/day" was this same cost.
- **Recovery that worked:** `journalctl --vacuum-size=50M` and `apt-get clean` freed ~600 MB on
  each of the twelve; that let a crash-looping node complete RocksDB recovery, whose flush makes
  every old log obsolete and deletes it (f, lon1, sfo2, nyc1, syd1 went from 0 to 12–15 GB free).
  **Never delete `.log` files by hand** — they hold the unflushed rows of the pinning families.
  A node still running with its 13 GB of live WAL (blr1, c, ams3, nyc2, tor1, atl1, sfo3 at the
  time of writing) gives it back on a controlled restart, ~15 min of startup verify each.
- **Code fix:** `Storage::open` sets `max_total_wal_size` to 256 MB (`MAX_TOTAL_WAL_BYTES`,
  `d187df4` on `feat/cli-scan-fixes`; test
  `the_write_ahead_log_is_capped_not_pinned_by_a_quiet_family`, 268 MB of log under the old
  options, 22 MB under an 8 MB cap). Node-only, same chain, rolls like v0.5.1. The floor is one
  write buffer above the cap (the live log rolls only when a memtable flushes).
- **Ops facts:** `doctl` is configured on the laptop (account active, 30-droplet limit); a disk
  resize needs a power-off and is permanent. `du -sh <datadir>` hides the split — read
  `du -ch db/*.sst` and `du -ch db/*.log` separately, and `df` on the 48 GB droplets first
  whenever anything "cannot start".
- **Node A is a LaunchAgent now** (`deploy/launchd/org.randprotocol.node-a.plist`, installed
  under `~/Library/LaunchAgents`, `KeepAlive`, `RunAtLoad`): before it, every laptop reboot took
  A down until someone noticed (two days on 2026-09-21). launchd's default of 256 file
  descriptors kills RocksDB at open ("Too many open files") — the plist raises `NumberOfFiles`
  to 65536. Restart A with `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a`, never by
  running `run-a.sh` in a shell beside it.

### 2026-09-24 — the CLI scan fixes from the non-receipt investigation (`feat/cli-scan-fixes`, `74c9dd8`)

The 2026-09-23 investigation of a "nothing received" report proved the payment sound and left
three CLI weaknesses; all three are fixed with red-first tests: **the note store is bound to the
chain it was scanned against** (`NoteStore.genesis`, hex in `<key>.notes.json`; `scan` calls
`rand_getGenesisHash` first and `bind` empties a foreign or pre-binding store with a warning
naming both chains — the reproduced failure was a chain-13-sized `scanned_index` against chain 14
reporting `0 RAND, 0 notes` in 1.9 s); **the wallet speaks TLS** (workspace `reqwest` gains
`rustls-tls`; it refused every `https://` URL before, so `https://rpc.randprotocol.org` was
unusable from the CLI); **`rand_getBlocks` pages 1024 headers** (`rpc::MAX_BLOCK_HEADERS`, was
`MAX_COMPACT_BLOCKS`'s 128; older nodes clamp and the walk advances from the last header it got).
Trap kept: the first sync still reads every block header (a warm 128-page is ~0.4 s on F, ~1 900
round trips over 245k blocks; the server reads the whole block to render a header) — a header
index on the node is the real fix, not a bigger page.


### v0.5 — RPL tokens, zUSD and the hardened bridge — LIVE on chain 14 (2026-09-20), pinned build `b3c594c`

RPL (RandProtocol's own token standard) and zUSD (one bridged token, seven backings) are live.
Spec `docs/superpowers/specs/2026-09-19-rpl-token-standard-design.md` (§12 = one zUSD, §13 =
per-backing source decimals), `.../2026-09-19-hidden-asset-bundle-design.md` (the 4-slot guest),
`.../2026-09-19-bridge-hardening-design.md` (B1–B4), `.../2026-09-19-pq-cosignature-bridge.md`
(B3, verbatim from the bridge repo); plan `docs/superpowers/plans/2026-09-19-rpl-token-standard.md`;
live task-by-task ledger (git-ignored) `.superpowers/sdd/2026-09-19-rpl-token-standard/progress.md`
in the `feat/rpl` worktree (`/tmp/fullnode-rpl`); cut runbook
`docs/superpowers/handoffs/2026-09-20-chain14-cut-runbook.md`; take-over handoff
`docs/superpowers/handoffs/2026-09-19-zusd-v0.5.md` (its closing "State 2026-09-20" section is
current). `feat/rpl` + `feat/bridge-hardening` merged linearly (98 commits, 0 merge commits) onto
`main` at `a2c9896`, then three deploy-only commits — `66cd6b1` (untrack the 24 chain-13 validator
+ payout key files, OPS-1), `971ca75` (the cut/gen/cutover scripts), `b3c594c` (this runbook) —
**`b3c594c` is the pinned fleet build**; `main` now sits at `ed88241` (adds the committed genesis
file, the regenerated `nodes.env`, `run-a.sh`). `docs/tokens.md` is the RPL user guide;
`docs/bridge.md` §§13–20 is the bridge-hardening + launch reference; `docs/confidential.md`'s
soundness table and `docs/shielded.md` cover the hidden-asset bundle. The RPL deploy tutorial is
live at `randprotocol.org/docs/deploy-rpl-token` (concept page `.../docs/concepts/tokens`, website
commit `d79855a`), synced to chain 14.

**What v0.5 is:**

- **RPL**: a ledger-level registry of shielded native tokens (`ledger/tokens.rs`, genesis-gated by
  a `tokens` section, `rand-state-4`), permissionless creation, fees in RAND, symbols not unique, a
  checksummed `rpl1…` text form (bech32m, 62 characters).
- **One hidden-asset bundle for every transfer.** The two-bundle `TokenTransfer` is gone (H3):
  a single fixed 4-in/4-out proof (`guests::bundle_hidden`, tier 14, ~100 s) moves RAND, a bridged
  coin or an RPL token identically — nobody without a key can tell which asset moved at all.
- **Transaction binding.** Every bundle proof is now made over, and verified against,
  `H("rand-tx-bind-1", chain_id ‖ tx with proofs blanked)` via the public input segment, closing a
  redirect attack that let a copied, unmodified proof be resubmitted under a changed destination,
  validator or memo.
- **zUSD**: ONE token, seven backings (USDT+USDC on chains 2, 3, 5; USDT only on chain 4, Tron —
  Circle discontinued Tron USDC), `total_supply == Σ backings.locked` held by construction (`lock`/
  `release` are the only writers); a `BridgeBurn` is refused `NotABacking` / `InsufficientBacking` /
  `NotReleasable` before its digest or proof are even touched.
- **B1** — a per-backing daily mint cap (`mint_cap_per_day`, genesis, applies per backing not per
  token) and a Dilithium2 pause key that can only pause (`PauseMints`, bundle-less, fee-less);
  unpausing needs the PQ guardian quorum (`UnpauseMints`); burns and rotations stay open while paused.
- **B2** — a forward bound on block timestamps: `BlockError::TimestampLeap` (`MAX_TIMESTAMP_STEP_MS`
  = 60 000, a validity rule replayed too) and a 15 s clock-drift vote rule (`MAX_CLOCK_DRIFT_MS`,
  vote-only) — every validator on a bridged chain now needs NTP.
- **B3** — a second, post-quantum (Dilithium2) co-signature quorum, independent of the ECDSA one,
  required on every mint and every guardian-set rotation (`Action::BridgeAttest`'s last field,
  `pq_signatures`, inside the transaction binding).
- **B4** — `RegisterBridgedToken` / `ListBacking`: list a new bridged token or a further backing
  after genesis under the same PQ quorum, no chain cut, no wire or `bridge-codec` change.
- **F1** — a `BridgeAttest`'s deposit blinding `r` is derived, not submitter-chosen:
  `blake3("rand-deposit-r-1" ‖ mu)` over the guardians' own signed digest
  (`BridgeError::WrongDepositBlinding`, permanent), closing issue #3's deposit-commitment
  front-running.
- **Genesis alloc openings** (core review I-2): a `GenesisNote` gains optional `{pk, time, r}`; when
  a genesis carries a `tokens` section every alloc note must carry one, and `rand-node init`
  recomputes its commitment at asset 0 — closes the "opaque alloc note could hide an unbacked
  asset-1 note" hole.
- **Key-length bounds** (core review I-1): `RegisterToken`/`SetAuthority`'s `MintAuthority::Key` and
  `InitialMint`/`TokenMint`'s recipient `kem_ek` are now length-checked (`== PUBLIC_KEY_LEN` /
  `== KEM_EK_BYTES`, permanent verdicts) — closes an unbounded-length state-bloat-at-flat-fee hole.
- **Bundle proofs pinned to tier 14** (zkvm review I1): `decode_and_check`'s bundle branch now
  requires `tier == 14, keccak_log_height == 0, sha256_log_height == 0` instead of trusting the
  prover's declared header — an unpinned header could grow the verifier-key cache and FIFO-evict it
  (a DoS), since every real hidden-asset bundle shape is measured at tier 14 anyway.
- **Every `u64` RPC amount is a decimal string, no exception (breaking).** The pre-chain-14
  exception — a bundle's `fee`, `burn_a`/`burn_r`, a mint's/staking action's/`bridge_attest`'s/
  `bridge_burn`'s `amount` (and `bridge_burn`'s `relayer_fee`), `rand_getAssets`'s and
  `rand_getBridgeState.assets[]`'s `locked` — is gone; only `rand_getStatus.aggregation.
  subsidy_base` moved the other way, to a number, for consistency. `docs/rpc.md`'s conventions
  section and changelog carry the exact field list.
- **Governance actions bypass a full mempool** (node review I4): `PauseMints`/`UnpauseMints`/
  `RegisterBridgedToken`/`ListBacking` are exempt from `MempoolFull` and ordered first, so a
  congested pool can never crowd out a pause; `rand_mint` (the faucet) is now rate-limited too.
- **Faucet rate limit**: burst 8, 1 request/s per node (was unthrottled).

**Chain 14 facts:** genesis
`1cff3b7da248d93ab547aef5c05bb7d0d22da510b592dab9cf7374807de7c7ff`, chain id **14**, pinned build
**`b3c594c`** (`main` at `ed88241`), `hc_bundle 83d3a370…` (chain 13's was `4a27356f…` — the
hidden-asset guest replaced the bundle guest). Eighteen validators, **fresh keys generated off-repo
into `~/.rand-chain14`** (backed up by the user off the laptop) — new peer ids, `deploy/nodes.env`
regenerated as `$KEYDIR/public/nodes-chain14.env`; on a droplet the key lives at
`/root/keys/node-<name>.key.json`, outside `/root/fullnode` so `rebuild-vps.sh`'s `rsync --delete`
can never remove it. Node A runs from `~/rand-node-a` via `deploy/run-a.sh`; the fleet was rolled
with `deploy/cutover-droplet-chain14.sh` (C and D first as bootstraps, then the rest one at a time
waited to `rand_getHealth: ok`, A last). The 24 chain-13 validator+payout key files are untracked
from the repository (OPS-1; working copies remain on disk, still serving chains 8–13). Genesis
names guardian **set 0**, with `pq_guardians` ordered for **set 1** — the relayer files PQ
co-signatures by PQ-list position, not by ECDSA signer index, until the rotation. `registration_fee`
1 RAND, `mint_cap_per_day` 100 000 × 10⁸ per backing per day, **no aggregation section** (`node::
check_build_runs_genesis` refuses to start any genesis carrying one — the hidden-asset bundle's
declared shape needs re-measurement first).

**zUSD facts:** index **1**, asset id
`32e5ab28c782c663e14da2650a3feb12f16a12db85599f4f62dc169d26f37b1f`, id
`rpl1xtj6k2x8strx8c2d5fjs50ltztck5ykms4ve7nmzmstf6fhn0v0spelqtx`. Registered by transaction
`7fa28fe6277a82401dcc440ff32da13c5e5763f79826fb17cc508f4c15abdd13` at block **256** (first backing:
Ethereum USDT), by the faucet-funded deployer wallet, under the PQ guardian quorum's signature. The
six remaining `ListBacking` transactions (`e52eba8d…`, `360e136b…`, `5a800fd6…`, `f3bf7f72…`,
`101bc09b…`, `a73a626f…`) brought `list_nonce` to 7 and all seven backings live. Deployer, relayer,
tester and demo wallets live under `~/.rand-chain14/wallets/` (paths only — never a key file's
contents in this repository).

**The mainnet round trip, round 1 (2026-09-20, 1 USDT per chain), one table:**

| chain | lock (source explorer) | mint (`BridgeAttest`, randscan) | burn (`BridgeBurn`, randscan) | release (source explorer) |
|---|---|---|---|---|
| Ethereum | https://etherscan.io/tx/0xd3a28422a53f455d2c5b9bfeb490aae4cfc1c7386fbfec567e462d3c5b6ceb76 | https://randscan.org/transactions/8ac6c497f8af870982936d29588121a1c0f2be0996af2d394781a1be26a31ec9 (block 3430) | https://randscan.org/transactions/7da01f410cf2726b79c7626cb6d9f2a3fa1cd9362487de216f266764c3f88840 (seq 3) | https://etherscan.io/tx/0x88f9d430f933aa2fe1ea708e40ba9890e04889b5c4b08a8960fe250ee83e7429 |
| BNB Chain | https://bscscan.com/tx/0xd1706d0f752374ccb5ce64b6d246897a0018101cf043a5b3835c651ac9e3f945 | https://randscan.org/transactions/f2f24d75bc0e7d84dff1f4e4518a9d4bef115392492a39befca1528a2404851d (block 2572) | https://randscan.org/transactions/f9f365ca170a5fb51ff9381d7b5cc39538c1a621e5f6e8c1bd74d8751c7bbc49 (seq 0) | https://bscscan.com/tx/0xbe38fd0592def630d4f7fecdd6a354530307a6296b0b8d96ca9729afeef22fc8 |
| Tron | https://tronscan.org/#/transaction/4bba90b365bd6c3ae64557f4774640075066cc3d06afcff88f39f1269fdeaa12 | https://randscan.org/transactions/16ea7cbdacb5261829b43b223f3d486ab0fc43cc7b8d85755de6987ddaeecd90 (block 2793) | https://randscan.org/transactions/013ac7b74c02842ea9516c81570fbc9e0edac4c201a560baedb3d70c7020a038 (seq 1) | https://tronscan.org/#/transaction/9c07d3f2626046316cc52a1678eec3f701cb1cefb5f43bad71bf5c3fbd2b6262 |
| Solana | https://solscan.io/tx/63mjiakBorqYg6oMBwtSJn3KGdh6AhLLxMMvwKKWmg7EWL3A3qYctB9VmbhdkVxMxBKcSBBE8Bt1Lhk9ftZmhRbu | https://randscan.org/transactions/1bb5a046f2faf1cff48830c4ea8e51c6e36db05c5c8ee38d4dbc5cd1cba6c85e (block 2684) | https://randscan.org/transactions/7548f330e0f26dbb0011e66096ae9e1859930103b91259883c7e757612a19285 (seq 2) | https://solscan.io/tx/5Fy65G7KiZZzadqRV8sdNissR2th8Yr1hyBXw8PhKe4ADGTZnmi6sbWrxyaJkFTvbJQKGrc34jv68a6wBSnZyUTz |

The zUSD transfer (tester → a FRESH demo wallet, 1.00000000 zUSD): randscan
https://randscan.org/transactions/e6ddaca3c852e6c861524a55d00a0fbdcaff6867544b9f19b9bf60ce263c32ed,
transaction key `7f68f57c4f33a3f0fe419f4d1a5df2875461339dbc454af8ced50cbd7f40e4ef` (discloses amount
100000000, asset 1), demo wallet viewing key
`a93c673ffeff7204447161347828d8e549b7070460813ae1b7e664694e1dcd5d`.

`rand-bridge-audit` on mainnet after round 1: **custody 0 everywhere**, fees accrue in-contract at
**exactly 10 bps per release** (`accruedFees`, admin-only `withdrawFees(token, to, amount)`, no
fixed treasury), endpoint balance == custody + fees, **Rand supply 0 == Σ locked 0**.

**Round 2 (2026-09-20), confirmed by the user: 9 USDT per chain (36 total), mints only, left
locked** — no round-2 burns; expected end state **36.00000000 zUSD against 36 USDT in custody**.
Locks (endpoint sequence 1): ETH
https://etherscan.io/tx/0xf9bb33bdc89fec2ee82b4dd02226ec9d0b63d27ae50fb341af6e8b95ec937d0a ; BSC
https://bscscan.com/tx/0xc329ea06440bf4a84383da39b9c67e2484ac96e168558b1a86905242c165c1ff ; TRX
https://tronscan.org/#/transaction/b0fc155a2264b9dbf5b7cbeac899ae918b3a976aa7af21e003f37435eb9f3269 ;
SOL
https://solscan.io/tx/2iAUL44wjhE7pcYeznAwGix5RMb28eTgXVwSRy7qixGASUcwqXx7EhVsrZATyNAjzAKXw2sRNXhQiaLF6ps6w6K3
— **all four mints committed** (`BridgeAttest`, 9.00000000 zUSD each; relayer order BSC, SOL, TRX, ETH): BSC block 4686 `f74d8ba08c1621337e58b57fe94bba93f893fec674e37c199553728cde5e8376`, SOL block 4798 `1c7cc5b4dcf50639ad7fd041f6064793287091709f320945d558f4db6c55b6e3`, TRX block 4907 `c2a26eec92756946241b5e6c59c46a3a6645e5c92472f3e221e06d9d9fc74aaa`, ETH block 5432 `329cce2a1818a3cc3f4b60b5e2f13c52bb077fce7ffb34c5a6317b01db095fcd`. End state, audited on mainnet by `rand-bridge-audit`: `total_supply` 3600000000 == Σ `locked` (900000000 on each of chains 2/3/4/5 USDT), custody − locked = 0.

**The guardian-set rotation is on hold by the user's decision (2026-09-20): the bridge stays on
guardian set 0 until the user says otherwise.** The set-1 ECDSA keys already generated
(`~/.rand-bridge/mainnet-guardian-set1/`) exist but are unused; the PQ keys of
`~/.rand-bridge/mainnet-pq-set1/` ARE in use — they are chain 14's `pq_guardians` and co-sign every mint;
`bridge.pq_guardians` in the chain-14 genesis remains index-aligned with set 1 while the chain runs
on set 0's signatures, per the ordering note in the cut runbook's Open Questions §1.

A public RPC endpoint now exists: **`https://rpc.randprotocol.org`** — Cloudflare, proxied to Caddy
on droplet F, forwarding to `127.0.0.1:8545`. Not bound on E (E's node holds randscan's 64
viewing-key import slots; a public RPC there would let anyone else's `rand_importViewingKey` calls
evict them).

**Traps learned:**
- **The fleet's disks filled because retired chains' data dirs were never deleted.** Chain 13
  stalled at ENOSPC on 7 droplets (c, f, lon1, sfo3, blr1, ams3, tor1) whose chain-11 (`79123fa7`,
  7 GB) and chain-12 (`605eb783`, 21 GB) data dirs were still on disk from earlier cuts; chain 13
  itself grew **~16 GB/day**. Delete every retired chain's data dir at each cut (guarded: only when
  the unit's own datadir suffix is current), and watch disk on the 48 GB droplets specifically —
  they fill first. **E hit the same wall on chain 14 (2026-09-21):** chains 11+12 were still on its
  77 GB disk, rand-node crash-looped on ENOSPC ~50×/hour with the RPC never opening (randscan
  degraded, the sale service's upstream down), fixed by deleting the two retired dirs — and tor1,
  nyc1, atl1, nyc2, sfo2, syd1 were all ≥85 % at the same moment. **Later the same day the user
  authorised dropping every retired dir fleet-wide: chains 11–13 (and 12 on mkc1/mem1) deleted on
  all 17 droplets + A, guarded per host by `ExecStart` datadir = `*1cff3b7d` + `rand_getHealth:
  ok`; every droplet ended at 28–59 % used. The chain-13 rollback path (runbook §8) no longer
  exists anywhere — chain 14 is the only chain on any disk.**
- **(Until 2026-09-27; since then the upstream is obs1, the archive, through an SSH tunnel — `deploy/caddy/README.md`.) The sale service's RPC upstream is a Caddy route on E, and it lives in randscan's repo.**
  `SALE_RPC_UPSTREAM = https://randscan.org/rpc` (web droplet `/etc/randprotocol/sale.env`) is a
  route in randscan's `deploy/Caddyfile` (since randscan `412a55d`) that `remote_ip`-allowlists the
  web droplet `159.65.138.161` to E's `127.0.0.1:8545` and 403s the rest. It was first hand-added
  on E and wiped hours later by a randscan redeploy (`vps-setup.sh` re-renders
  `/etc/caddy/Caddyfile` from the template) — randprotocol.org's `/account` then showed zUSD as
  "asset #1" ("the node could not name every token") until the route was restored. This is safe for
  E's viewing-key slots: the sale service's method allowlist (`server/sale/src/rpc.rs`,
  `RPC_ALLOWED`) never forwards `rand_importViewingKey`/`rand_getViewingNotes`, so the only client
  the route admits cannot touch them.
- **randscan migration numbering can silently skip a version.** Version 8 was burned on the live DB
  by the reverted chain-11 receivers migration, so the new migration numbered `008` was silently
  skipped and the indexer stuck at the first 4-nullifier transaction (height 255). Fixed by
  renumbering to `009` (randscan `adfe129`). Check a migration's number against what a chain has
  already *tried*, not just what is in the tree today.
- **`rand-node genesis` writes `bridge: None`**; the cut script splices the `bridge` section in
  afterward, so the genesis hash that matters is what `rand-node init` prints on the *finished*
  file, never the hash `rand-node genesis` printed on the unbridged one.
- **Peer ids derive from the validator key**, so fresh keys mean new bootstrap multiaddrs —
  `deploy/nodes.env` has to be regenerated with the fleet, not hand-edited.
- **`rebuild-vps.sh`'s `rsync --delete` removes E's in-tree keys.** Keys live in `/root/keys` now,
  outside `/root/fullnode`, specifically so a rebuild can never delete them.
- A `BridgeAttest`'s `tx_json` does not render its source chain (follow-up, not fixed); no CLI
  prints a wallet's `recipient_hash` (follow-up — a scratch crate had to compute one for the round
  trip's burn destinations).
- **Rebase-map lesson**: a local `main` ref goes stale inside a worktree; compare a branch's rebase
  target against `origin/main`, not a cached local ref (a rebase onto a stale local `main` can be a
  silent no-op).
- **A detached long run needs `nohup`**; a tool-level timeout kills a bare backgrounded process when
  the invoking call itself times out.

**The audit-v3 consensus work — LANDED on `main` as v0.5.1 (`9c142c1`), rolled to all 18
validators on 2026-09-20; re-reviewed clean 2026-09-22.** fullnode-df's fixes (CON-1b lock
durability, the safety-stop fix, CON-1a/SYNC-1, plus C1/C2/I3/I4 from the liveness-focused
review) were held from the chain-14 cut itself (405217a on C1 unverified-tail evidence and C2 a
sync hot-loop; 9c4be1c on I1 a weak quorum and I2 a pacemaker stall), re-worked through three
review rounds, and landed as the same-chain update the ruling ordered. The independent re-review
(`../security/fullnode-review-auditv3-consensus-rereview-2026-09-22.md`) verified every held item
against the running build: the sync path commits only through `committed_prefix` over a
whole-batch-verified run (the plan's `CommitProof` serving was deliberately superseded — the
tail commits via the live path instead), the lock survives restart/sync/fallback, conflicting
finality stops the node as `FatalSafety`, and B5's verified-proof cache skips only the STARK
verify. **B3 — the timeout-certificate pacemaker — is the one open consensus item**: CH-1's
f+1-NewViews rule was dropped (`has_weak_quorum` is not in the tree), so `on_new_view` still
advances on one signed NewView bounded by `MAX_VIEW_AHEAD`; that needs a validator key (all 18
are the operator's) and buys no safety break, only view inflation. Do not patch it
incrementally; the redesign needs the `av3review/pm.py` model (currently lost — rewrite it) and
18-validator tests. Residual note: `PersistSafety` is persist-on-vote (`hotstuff.rs`'s
`try_vote`), so a lock never voted under before a crash is lost — bounded, standard, recorded
in the re-review.

**Deferred minors** (from the final whole-branch review, none blocking the cut): node M1 (whether
`META_TOKENS` should be a whole rewrite/read or a diff, like the validator register), M3 and M8
(unspecified beyond "parked" in the ledger); core M-6/M-7 (likewise unspecified beyond "parked");
zkvm M2 (two more weakened-guest mutation-fuzz variants for the hidden-asset bundle's cheating
suite); client N-6 (a pre-send failure leaves a token's `.pending` authority-key file with a "fate
unknown" wording that could be clearer). Already documented rather than fixed: core M-1 (the PQ
guardian quorum alone can `UnpauseMints`; the effective post-pause bound is up to 32× one backing's
cap once new backings are listed — `docs/bridge.md` §15) and M-2 (a catch-up day is ≈76 minutes of
real time at 3 s blocks; `genesis.timestamp_ms` must never be set more than 15 s ahead of launch —
`docs/deploy.md`, `docs/bridge.md` §16). Out of scope for v0.5 entirely: RPL spec §7's allowance
accounts (`approve`/`transferFrom` — redesigned whenever picked back up, since `TokenTransfer`'s
memo field that would have carried the grant no longer exists); the Rand-only governance payload
for adding a backing (plan Task 10, replaced for launch by B4); short shielded addresses
(`feat/harm-addresses` stays a separate PR for discussion, not in chain 14).

**randscan issues found post-launch** (explorer repo, not this one — recorded here for whoever picks
them up): `/bridge/assets` keys deposited/burned/outstanding per token **index**, so all seven zUSD
backing rows repeat the token's total instead of showing their own backing's numbers; `/tokens/1`
renders `deploy_tx` as `null`; `/bridge` serves `registration_fee` as a JSON number where this node's
RPC sends a decimal string (the v0.5 amount-encoding rule, above).

### Final audit v3 (2026-09-19): POOL-1 and RPC-1 fixed in code; OPS-1 rotation rides chain 14

The external audit (`../security/Rand_Final_Audit_v3_Key_Findings.pdf`, nine passes 10–18 Sep,
closed out at v0.3 `c0ffc74`; 79 findings, 33 open critical/high — read its findings table
before re-reporting) confirmed the v0.1 fixes (AGG-1, AGG-5, SYNC-2) and named two exposures
live on chain 12, **both also live on chain 13** (faucet on, chain 12's validator keys):

- **POOL-1 (critical) — fixed in code, a hard fork for chain 14.** `Action::Mint` carried a
  `cm` the ledger never related to `amount`, so a validator could mint a note worth anything
  while the supply counted the declared amount. The mint now carries the opening (`pk`, `time`,
  `r`); admission recomputes `ledger::mint_commitment` (no sender, native asset) and refuses a
  mismatch (`TxError::MintCommitmentMismatch`, permanent), `time` is held to the bundle window,
  and the minter signs `rand-mint-2` over every field. `Transaction::mint` takes the executor
  and derives `cm` itself. Regression test:
  `a_mint_whose_commitment_opens_to_more_than_its_amount_is_refused`. **Chain 13 cannot take
  this as a same-chain update** — the wire format changed, so its committed mints no longer
  decode; it ships with the chain-14 cut.
- **OPS-1 (critical) — not fixable in code alone.** `deploy/node-a..f.key.json` are committed
  to a public repository and chains 8–13 all run on them. `deploy/lib/key-guard.sh`
  (`refuse_in_tree_key`) is for the chain-14 cut script: fresh keys from a `KEYS_DIR` outside
  the tree, refused otherwise. The old files stay tracked until the cut, because untracking
  them would delete the working copies node A's scripts read when a checkout fast-forwards.
  Drop the `!deploy/*.key.json` exception from `.gitignore` at the cut.
- **RPC-1 (medium) — fixed.** `rand_getWitness(es)` rebuilds the whole tree per call on the
  blocking pool; at most `MAX_CONCURRENT_WITNESS_BUILDS` (2) run at once per process, and a
  request that waits more than 10 s is refused `-32000` busy. PRIV-1 (the operator learns which
  leaves a wallet spends) is **fixed on `feat/security-concerns-2` (task A4)**: the wallet keeps
  its own commitment tree in the note store (built during `scan` from the
  `rand_getCommitments` pages it already reads, `crates/randprotocol-client/src/tree.rs`) and
  computes its own witnesses; a send never calls `rand_getWitness`, which stays on the node for
  older wallets. A store written before the tree existed is detected on load and rescanned from
  leaf 0 once.
**Re-verified against code 2026-09-20; the remediation plan is
`docs/superpowers/plans/2026-09-20-audit-v3-v0.6.md` (branch `feat/audit-v3-fixes`, tag v0.6
after the full suite).** It adds one finding the audit does not list: AGG-6, the genesis
`aggregate_program_digest` pin is only checked non-zero and never compared with the build. VK-1
is worse than reported: the scan holds the viewing registry's write lock while `publish_status`
takes a blocking read on the node loop, so a long scan stalls consensus.
Still open from the audit's work order (as of the audit): AGG-2 (bind the aggregator before the production batch
pins the digest — **fixed 2026-09-25**, see "AGG-2" under the state as of 2026-09-25), AGG-4/AGG-3, CON-1a/1b + SYNC-1 (the commit rule on the sync path), VK-1/2/3,
BRG-7's forward timestamp bound, and decisions D1–D13.

### v0.3 — the RPC release — LIVE on chain 12 (2026-09-18), pinned build `4504a03`

Eleven JSON-RPC methods (`rand_getVersion`, `rand_getGenesisHash`, `rand_getHealth`,
`rand_getTransactionStatus`, `rand_getReceipts`, `rand_getWitnesses`, `rand_getBlocks`,
`rand_getFinality`, `rand_getProposer`, `rand_getMempoolInfo`, `rand_getEmission`) and two
WebSocket topics (`receipts`, `transaction`), from the Ethereum/Solana comparison
(`docs/rpc-comparison.md`). Spec `docs/superpowers/specs/2026-09-18-rpc-v0.3-design.md` (§9 lists
every decision changed in implementation), plan `…/plans/2026-09-18-rpc-v0.3.md`; built on branch
`rpc-v0.4` (the release was renamed v0.3 mid-run; **v0.4 is now the rand-guest toolchain and the
sBPF/EVM → RV32 transpilers**). Node-only: no consensus, wire or genesis change; rolled to 16
droplets + A as a same-chain update (`deploy/README.md`, "The v0.3 same-chain update").
**Traps learned:**
- **The database is forward-only.** v0.3 adds the `receipts_by_program` column family; RocksDB in
  a pre-v0.3 binary refuses to open it. Roll back with `rand-node db drop-receipts-index --datadir
  <dir>` (v0.3 binary, node stopped) *before* re-pinning — rehearsed on A's real database.
- **Node startup is ~4 min** (quick chain verify before the RPC opens, 239 s at 59k blocks). A
  rolling update waits on `rand_getHealth` = `ok` per node, not a sleep.
- **`rand_getVersion`'s sha**: `rebuild-vps.sh` passes `RAND_BUILD_SHA` because E's
  `/root/fullnode/.git` is stale (rsync `--exclude .git` protects it from `--delete`). The
  `version` field still reads the crate's `0.1.0` — the workspace version was never bumped.
- **`rejected` in `rand_getTransactionStatus` / the `transaction` topic is byte-level refusals
  only** (`admission::is_permanent`); a spent nullifier or expired anchor is not remembered and
  reads `unknown` once out of the pool.
- `main.rs`'s `the_genesis_hash_is_pinned` fails on main before and after v0.3 (left `78390828…`,
  right `fb5881c8…`) — pre-existing, not investigated.
Follow-ups (deferred Minors, all non-blocking): `CommitSummary` cloned per WebSocket receiver
(`Arc` it); `select!` not biased commit-before-refusal; `rand_getUnsealed` still `load_ledger`s
on the async thread; the client's `-32601` fallback is sticky per process; untested: cap across
WS topics, lag close on commits/refusals, `receipts` topic end to end.

### Chain 12 (RAND, the long shielded address again) is LIVE — the short address is reverted (2026-09-17)

Main at the chain-12 record commit (pinned build **`17db41d`** = the revert commit): the twelve
code and docs commits of the short-address feature (`42a4b5b..ee716d7`, tag `v0.2`) are reverted
in one commit; the address is `rand1` + base58(pk ‖ kem_ek) again, payouts and alloc owners are
bare addresses, there is no receiver record, registry, `rand_getReceiver` or versioned KEM key.
**Why:** a receiver id is a hash and a sender cannot seal a note to a hash — the first payment to
a wallet that never registered needed a payment request or a hand-carried record, registration
was a paid self-transfer an empty wallet cannot make, both delivery paths told the registry who
was about to be paid, and a claimable pay-to-id note would have put amount and recipient on
chain. **The design that keeps a short address, unconditional sendability and cryptographic
privacy is a hybrid address** (a 32-byte X25519 key inline, ~93 chars; the ML-KEM key by lookup;
the first payment to an unregistered wallet confidential against classical adversaries, every
later one fully post-quantum) — to be specified next; the chain-11 spec and plan stay under
`docs/superpowers/` for the parts it reuses (the derived signing key, the signed record and its
verifier, the registry as chain state). Chain 12 genesis `605eb783…` (chain 10's shape, cut by
`deploy/cut-chain12-genesis.sh`, no aggregation section), rolled out to 16 droplets + A with
`deploy/cutover-droplet.sh <ip> 79123fa7 605eb783 deploy/genesis-chain12.json` (peer ids
unchanged); explorer redeployed at randscan `ba6fee6` (its receivers commit `d580e5b` reverted);
the activity loop's two wallets on E rewritten back to version-2 key files (same spend keys);
the website's `docs-site` branch repointed to chain 12 (`7f4cafe`). The chain-11 genesis, record
files and cut script stay under `deploy/` as history. **B still needs `bin-17db41d/` and
`.update-pin` = `17db41d`.** The guardian-set attestation bound (`544926c`) survived the revert.

### Chain 11 (RAND, short shielded addresses) — LIVE 2026-09-17 for one day, tag v0.2, reverted the same day (see above)

Main at `255618f` (pinned build `ee716d7`, tag **`v0.2`**): the short-address feature merged
linear (ff) from `short-address`. Chain 11 genesis `79123fa7…` (23 receiver records), rolled
out to 16 droplets + A with `deploy/cutover-droplet.sh` (service `rand-node`, peer ids
unchanged); explorer redeployed with `/api/v1/receivers` (randscan main `d580e5b`); the
activity wallets registered. **B still needs `bin-ee716d7/` and `.update-pin` = `ee716d7`.**
Deferred after merge (the final review's list, in `docs/superpowers/plans/…` history and the
review): a dedicated explorer `TxKind::RegisterReceiver`; `docs/architecture.md`'s stale txid /
action-count / state-domain lines; `--chain-id` for `rand address --record` so the next cut
needs no bootstrap node; a mempool claim key for first registrations; the explorer's address
length pre-check and `receiver_history` limit; `PaymentRequest.record` accessor; http registry
warning; the research repo's own RAND rename.

### Short shielded addresses (2026-09-17): implemented on branch `short-address`, chain 11

Spec approved 2026-09-17 (`docs/superpowers/specs/2026-09-17-short-shielded-address.md`, design
Anish Mohammad); the plan (`docs/superpowers/plans/2026-09-17-short-shielded-address.md`) refined
it with four rulings, R1–R4, all implemented as ruled, not as the spec first drafted:

- **R1** — retired ML-KEM secrets are **re-derived by version, not stored**: `ViewingKey::
  kem_seed_at(v)` (`crates/randprotocol-zkvm/src/notes.rs`) is `kem_seed()` itself at `v = 0`
  (domain `KEM_SEED`, unchanged, so every pre-chain-11 wallet and envelope keeps its meaning) and
  a fresh `domain::KEM_SEED_VERSION` hash of `(nk, v)` for every `v ≥ 1` — never layered on top of
  `kem_seed()`'s output. The key file (`KeyFile` v3, `randprotocol-client/src/wallet.rs`) stores
  only the highest `kem_version` reached; opening an envelope tries every version down to 0,
  newest first.
- **R2** — sender-paid registration **needs no note-to-pk tie**: `Action::RegisterReceiver`'s
  validity is `record.verify(id, chain_id)` plus the version-step rule alone
  (`ledger/receivers.rs`); nothing checks that the paying bundle also creates a note for the
  record's `pk` (the spec §6.3 draft's proposed tie — see the note at the end of this entry).
- **R3** — registrations (validator and aggregator) **must name a registered id**:
  `StakingError::UnknownReceiver` / `AggregationError::UnknownReceiver` refuse a `Bond`/
  `RegisterAggregator` whose payout id has no record in the registry at check time — no same-
  transaction carry-in exists in the implemented code.
- **R4** — `ShieldedAddress` (`crates/randprotocol-core/src/notes.rs`) **stays the in-memory
  pk/kem_ek pair**; only its text form (`Display`/`parse`/`recipient_hash`/`ADDRESS_PREFIX`) was
  removed. `impl From<&ReceiverRecord> for ShieldedAddress` is the bridge from a resolved record
  to what sealing an envelope needs.

Per crate:

- **core** (`crates/randprotocol-core/src/receiver.rs`): `ReceiverId` (32 bytes, `rand1…` text,
  53–55 chars, checksummed) and `ReceiverRecord` (`version`, `pk`, `kem_ek`, `signing_key`,
  `signature`, `MAX_RECORD_BYTES = 8192`), one `verify()` used by core, client and the explorer
  (`randprotocol_core::ReceiverRecord::verify`, confirmed in randscan's own `docs/api.md`). New
  hash domains: `rand-receiver-sign-1` (the signing key seed), `rand-receiver-
  addr-1` (the address checksum), `rand-receiver-record-1` (the signing hash). `ledger/
  receivers.rs`: the registry `BTreeMap<ReceiverId, ReceiverRecord>`, `rand-receiver-leaf-1`
  merkle leaves, folded into the state root as `rand-state-4` (bumped from `rand-state-3`).
  `ledger/staking.rs` / `ledger/aggregation.rs`: `payout: ReceiverId` throughout, resolved via
  `resolve_pk`/`resolve_record`, `UnknownReceiver` on a miss; leaf domains bumped to
  `rand-validator-leaf-3` and `rand-aggregator-leaf-2`. `ledger/bridge_notes.rs`:
  `BridgeAttest.recipient: ReceiverId`, the wire's 32-byte `to` field *is* the id (no more
  `blake3` hash of a long address), `BridgeError::UnknownReceiver` on an unregistered recipient.
  `genesis.rs`: `Genesis::receivers: Vec<ReceiverRecordHex>`, registered before any validator
  payout or alloc owner is resolved.
- **zkVM** (`crates/randprotocol-zkvm/src/viewing.rs`, `notes.rs`): `kem_seed_at`/`address_at`/
  `open_as_receiver_at`, versioned KEM keys (R1 above); nothing about the receiver id enters a
  proof.
- **node** (`crates/randprotocol-node/src/rpc.rs`): `rand_getReceiver`/`rand_getReceivers`,
  `rand_mint`'s optional third `record` param, `record_json`/`tx_json`'s `register_receiver`
  kind. `main.rs`: `genesis --receiver <RECORD.JSON>` (repeatable, registered first), the
  withdraw/aggregate commands resolve records through `resolve_receiver`.
- **client** (`crates/randprotocol-client`): `receiver.rs` (the payment-request URI, the registry
  lookup, the §4 error text verbatim: *"no receiver record for {id}: ask the receiver for a
  payment request, or for them to register"*), `wallet.rs` (`KeyFile` v3 with `kem_version`,
  `Wallet::rotate`/`record`/`record_at`, record version = KEM version + 1), `main.rs` (`address
  [--record]`, `request`, `register [--rotate]`, `send [--record|--registry|--register]`,
  `bridge-deposit-address` refusing until registered, `call --auditor-record/--registry`).
- **explorer** (`randprotocol/randscan`, branch `receivers`): `GET /api/v1/receivers/:address`
  and `/history`, re-verifying every record with the same `verify()` before indexing
  (`../randscan/docs/api.md` "Receivers").

**Chain 11 is not yet cut.** This is a hard fork (address text form, register/registry state,
bridge wire format, state root domain) and ships alongside the next chain cut, not before it —
`deploy/cut-chain11-genesis.sh` does not exist yet. Docs updated to match this branch's code:
`docs/shielded.md` (new §2), `docs/staking.md`, `docs/bridge.md` (§§5, 6, 10–12), `docs/rpc.md`
(new methods, wire format, changelog), `docs/cli.md`, `README.md`.

Note for anyone reading the spec document itself: its §6.3 draft proposed that a sender-paid
`RegisterReceiver` "must sit on a bundle that also creates a note for the record's `pk`" — the
plan's ruling R2 dropped that tie, and `validate_register_receiver` (`ledger/receivers.rs`)
implements exactly that: `verify()` plus the version-step rule, nothing about the bundle's
commitments. `docs/shielded.md` §6 and `docs/bridge.md` describe the code as it is (no tie), per
R2, not the spec's original §6.3 text.

### Session close 2026-09-16: M5 complete, aggregation merged, papers synced — all three repos at their final commits

Everything below is merged and pushed; nothing is pending in any working tree.

- **circuits** `main` at **271679d** (origin): the recursion VM complete — M5.1 (ISA,
  emulator, DSL, verifier program; 50/50 real proofs accepted/refused; 5 682 847 rows per
  inner proof measured), M5.2 (the machine: 8 instances, three gated cuts to **1 968 619
  rows**, tier 21; 26/26 cheating; test-profile exit passed), M5.3 (the N-generic aggregate
  program + chain API + admission stub vectors; machine classes N=1/2/3 → ≥64/128/160 GB),
  M5.4 (CUDA backend split with **zero new kernels**, tier-23 rung, measured device model,
  self-verifier written with its measured requirement). Open only: the PTX first build and
  the production N re-measurement — **blocked on the user provisioning a fleet GPU node**
  (Linux, R580+, CUDA 13, LLVM 21, sm_80+, 80 GB device, ≥160 GB host; `PTX_BUILD.md`).
- **fullnode** `main` at **faef139** (origin): RPC hardening, constraint set 6, viewing-key
  import + `rand_checkTransaction`, and the full block-aggregation pipeline (see the merged
  entry below). `docs/zkvm-m4-m5-progress.md` is the consolidated M4+M5 record with every
  measured number and the 11-row deferred-proof runbook.
- **whitepapers** `main` at **f31277c** (origin): both papers synced to `faef139` —
  `randprotocol.tex` (third pass: abstract + changes list, reconciliation at cs6/M5/aggregation,
  remarks updated) and `randprotocol_implementation.tex` (Implementation Draft 3, new
  `sec:aggregation`); all three PDFs regenerated and committed. Both compile clean, zero
  undefined refs.
- **Outstanding, user-owned**: ① the ≥64 GB proof batch (runbook rows 1–6; fills chain-9's
  `admitted_shapes[0]` — the zero-digest placeholder refuses to init, so this activates
  aggregation) and ② the GPU node above. Full checklists: `docs/deploy.md` ("Deferred proof
  runs and hardware tasks", "Chain 9 activation") and the README's "Open ops tasks".

### Block aggregation: MERGED to main (856887a, 2026-09-16, linear rebase) — user-owned hardware tasks gate activation

The chain-side block aggregation spec is **approved by the user (2026-09-15)** —
`docs/superpowers/specs/2026-09-15-block-aggregation.md` — and all ten plan tasks landed on main
(15 commits, rebased linear off 5748642; the full workspace suite green, the cluster capstone
included). Everything is genesis-gated on `genesis.aggregation`: a chain without the section
behaves byte-for-byte as today, so **chain 8 is unaffected and chain 9 activates only after the
hardware batch below** (its measurements fill `admitted_shapes[0]`; the zero-digest placeholder
refuses to init). What landed: the five actions and the genesis-gated `aggregators_root`
(`rand-state-3`); the register actions mirrored on S2; `crates/randprotocol-rvm` vendored from
`circuits/recursion` `271679d` via `deploy/sync-zkvm.sh`'s two-step rename (a **path dep would
fork `rand_zkvm` into two distinct crates — never do it**); the nine-step admission with the
pinned hex conformance vectors reproduced byte-for-byte; the crate-cycle rule (randprotocol-rvm →
randprotocol-zkvm, so the real `AggExecutor` lives in rand-node); subsidy + the four audit counters;
sealing and pruning (CF_SEALS, pruned = full tx + 34 pv + 7 shape bytes); sealed-form sync with
coverage-closed serving and the robust sync picker; the RPC surface and the `aggregate --watch`
daemon; the chain-9 cut script. Traps already caught and pinned: `main.rs`'s genesis command must
set `genesis.aggregation`; `reload_ledger` must restore the gate on restart (fork-at-first-restart
otherwise); a resumed replica must re-register its `CoveredSource`; the replay path gets the
record-only flavor of the window check, admission keeps the policy flavor; the aggregation tests
need `RECURSION_FIXTURES` set (`docs/aggregation.md`).

**User-owned hardware tasks (accepted 2026-09-15, scheduled 2026-09-16 — see `docs/deploy.md`
"Deferred proof runs and hardware tasks" and README's "Open ops tasks"):** ① the ≥ 64 GB batch
(runbook rows 1–6 in `circuits/recursion/docs/03-gpu-and-self-recursion.md` Appendix A) — its
measurements fill chain-9's `admitted_shapes[0]`, which is what activates chain 9 (the zero-digest
placeholder refuses to init); production proofs run *after* chain-side aggregation lands, per the
user's 2026-09-15 ruling. ② A fleet GPU node (Linux, R580+, CUDA 13, LLVM 21, sm_80+, 80 GB
device, ≥ 160 GB host) for the rVM CUDA backend's PTX build and the production N re-measurement
(M5.4's only open tasks, T3/T4).

### Block aggregation, Tasks 1–10 (2026-09-15, `aggregation-spec` branch): the full pipeline landed

(The fuller picture: `docs/superpowers/plans/2026-09-15-block-aggregation.md`, ten commits on
the branch. What a later session needs beyond the T1–T4 entry below, which stays as the
vendoring/workflow record.)

- **Load-bearing invariants this plan added**: a chain without `genesis.aggregation` is
  byte-for-byte chain 8 (the gate is absolute — `NOT_AGGREGATION` before any register check);
  the nine-step admission is cheap-before-expensive with the rVM verify last, and the covered
  bundles' records are always node-assembled (`Storage::covered_record`, one read for the Raw
  and Pruned forms); `total_supply == issued − slashed` holds with exactly the four new
  counters — `fees_paid` counts the proposer-kept floor at inclusion and an expired excess at
  its sweep, the bucket is not `register_total`, and the payout note's excess part touches no
  counter; a pruned bundle's ledger effect is bound to its aggregate-verified public values by
  the digest of its public fields (`check_bundle_proof`'s pruned branch) — never trust a
  marker form without it.
- **The proving share's bucket is `Ledger::unsealed_fees`, persisted beside `META_SUPPLY` and
  replay-audited** — a restarted node that lost it would mis-pay the next aggregate and fork
  at the state root. The aggregator register (`META_AGGREGATORS`) and the genesis section
  (`META_AGGREGATION`) are persisted the same way; `load_ledger` restores all three.
- **Sealed-form sync is batch-atomic**: a pruned bundle is accepted only when a covering
  aggregate is applied (a local mark) or in the same batch (whose commit is atomic); anything
  else is the raw-form fallback to another peer, never a ban (`node.rs`'s `RawFallback`).
- **Serving is coverage-closed** (`node.rs`'s `close_batch_coverage`). The acceptance above
  makes a batch that ends between a pruned block and its cover unservable — the fallback
  re-asks a peer that pruned the same record and serves the same split form, forever (the
  sealed-sync stall, shown by the capstone inside the full suite: the client's batch count
  halves on wire failures under load; the byte budget cuts where it cuts). So a `Blocks`
  response extends past the count asked and past the soft byte budget until every served
  pruned entry's seal mark resolves inside the batch, capped only by the reader's wire limit
  — beyond that is the genuine archive case the fallback exists for. Do not reintroduce a
  serve path that can cut coverage (regression tests:
  `a_batch_cut_short_of_its_cover_extends_until_the_coverage_closes`,
  `a_batch_cut_by_bytes_short_of_its_cover_extends_within_the_reader_limit`,
  `the_extension_stops_at_the_reader_limit_and_serves_what_it_can`).
- **The sync picker never silently gives up** (`node.rs`'s `pick_sync_peer`): the freshest
  connected-and-ahead peer wins, but with the chain known ahead and no such pair, any
  connected peer is worth one round trip; a send that cannot go out warns, counts, and tries
  the next candidate (regression test:
  `pick_sync_peer_prefers_fresh_and_falls_back_to_any_connected`).
- **Every replica construction re-registers the covered source.** `HotStuff::resume` builds a
  fresh replica, and `apply_synced` forgot to re-set it: a synced node then failed every
  aggregate block at the sidecar (peer-side `AggregateNeedsCovered`; a stable state-root
  mismatch on its own proposals). The resume re-sets `StoreCovered` exactly as startup does.
  And the source answers the **record-only** flavor — existence, bundle-ness, pv and shape —
  never the admission-policy one: before that fix, replaying an aggregate block whose window
  had passed was refused with `AggregateNeedsCovered`, a deterministic consensus break for any
  slow syncer. Coverability policy (window, seal) lives in the admission worker's
  `assemble_covered`, nowhere else.
- **A pruned bundle's identity is its *raw* transaction hash** (the marker form hashes
  differently — the proof bytes differ). The fee bucket keys on it (`0498a3b`), the sealed
  form's side table attests it, and `rand_getUnsealed` resolves marker forms through the
  proof-hash index. Get any of these wrong and the sealed replay diverges at the state root.
- **The proposer's root is computed in list order**: the §3.4 selection trial-applies the
  chosen aggregate *after* the ordinary transactions, where its place in the block is — the
  validators recompute in the same order (the ordering fix, also `0498a3b`).
- The capstone (`tests/cluster.rs`'s `a_fresh_node_syncs_pruned_history_with_one_rvm_verify_per_sealed_window`)
  is the end-to-end proof: register → prove (tier 19, ~26 min on the loaded box) → seal →
  prune → a fresh node resyncs with **one rVM verification per sealed window**. Its wall time
  (~31 min) and the measured numbers live in `docs/aggregation.md` §6.
- The chain-9 admitted shape is the fleet's own measured classes for a 2-in/2-out bundle
  (`program 12, input 10, keccak 0, sha256 0, public 2, mem 16`) — NOT the recursion
  fixtures' (they over-declare at 13/12/18). Cutting a genesis with the wrong shape means no
  aggregate can ever cover a fleet bundle; the cut script's `hc_bundle` keyword substitutes
  the build's pinned guest digest.
- **The measured numbers live in `docs/aggregation.md`** (the cluster capstone's walls, the
  startup key-build, the warm verify).

### Block aggregation, Tasks 1–4 (2026-09-15, `aggregation-spec` branch): the rVM vendored, admission live

The block-aggregation plan (`docs/superpowers/plans/2026-09-15-block-aggregation.md`, ten
tasks) is landing task-by-task on `aggregation-spec`. State and traps a later session needs:

- `crates/randprotocol-rvm/` is **vendored** from `circuits/recursion` (pin `271679d`) by
  `deploy/sync-zkvm.sh`'s recursion section (`RVM_SRC` env override) — never hand-edit it; the
  same two-step `rand_zkvm → randprotocol_zkvm` rename as the research section makes the two
  vendored crates' `Proof` types one type. Re-running the script re-vendors both sections.
- **The crate cycle decides where executor code lives**: `randprotocol-rvm → randprotocol-zkvm`, so
  `ZkExecutor` cannot touch the rVM. Its three aggregate arms return
  `ConfidentialError::AggregationUnsupported`; the real implementation is
  `randprotocol_node::agg_executor::AggExecutor`, which `node::executor_for_profile` always wraps.
  `AggregationUnsupported`/`BadDeclaredShape` are never permanent admission verdicts.
- `randprotocol_core::types::pv` **mirrors** the zkVM's `pv` layout (core cannot name zkvm types);
  `randprotocol-zkvm/src/executor.rs`'s test pins mirror == real.
- Interims by design until the later tasks land: `validate_inner`/`apply_tx` refuse
  `Action::Aggregate` with `TxError::AggregateNeedsCovered` (a proposer's trial-apply skips
  pooled aggregates; no block can carry one until T6's covered pre-pass); admission runs
  through `Ledger::validate_aggregate`/`apply_aggregate` with the covered records assembled
  node-side (`node::assemble_covered`, from CF_TXS); the payout amount is `subsidy(0)` (no
  excess buckets, `sealed_blocks` unincremented) until T5.
- **Gate gap this branch already fell into once**: `cargo test -p randprotocol-node --lib` compiles
  neither `src/main.rs` nor `tests/`, so T1's new `Genesis` field silently broke both. Fixed
  in T3/T4; run `cargo check --tests` (or the T10 full suite) before trusting a `--lib`-only
  gate after touching shared types.
- Recursion-heavy tests stay out of gates: `cargo test --release -p randprotocol-rvm -- --skip
  round_trips --skip two_test_profile` with `RECURSION_FIXTURES` pointing at a recursion
  fixture cache (the conformance vectors ride on the fixtures' random notes — the cache that
  produced `circuits/recursion/docs/02-aggregate.md`'s pins reproduces them byte-for-byte).

### Constraint set 6 re-vendor (2026-09-14, upstream 0200877): the public input segment, carrying M4.3 + M4.4

`crates/randprotocol-zkvm/` is re-vendored to `research`'s constraint-set-6 merge (the public input
segment), which also carries milestones 4.3 (the EVM interpreter guest) and 4.4 (the `sha256`
table, `SYS_SHA256 = 5`, and the sBPF interpreter guest) into this crate. A hard fork like every
set before it; fleets must run the same build (`docs/confidential.md`, "Constraint set 6").

- The zk side: a ninth **mandatory** table, `public` (the `PUBLIC_DIGEST`/`PUBLIC_READ` bus pair,
  sixteen buses in all), `SYS_READ_PUBLIC = 6`, and `H_PUB` in `pv::PUB0..7` — **unsalted**,
  unlike `H_IN`, so `Machine::verify_public(hc, public_words, proof)` recomputes
  `hash::public_digest(words)` natively and compares. `pv::NUM` 26 → 34, cpu `col::WIDTH`
  224 → 275, `Machine::verifier_key` a 6-tuple `(tier, program, input, keccak, sha256, public)`,
  and `Proof` gains `sha256_log_height` (optional, `0` = no table, the keccak table's exact
  terms) and `public_log_height` (mandatory; an empty segment is four rows, height 2).
- **The chain admits only the empty public segment**: `ZkExecutor::verify_call`/`verify_bundle`
  both call `verify_public(hc, &[], proof)`. Plain `verify` would leave `pv::PUB0..7` bound only
  in-circuit — to a segment the chain never saw — and today's guests read no public words
  anyway. A future action type that publishes words passes them in place of `&[]`.
- `MAX_PROOF_BYTES` **stays 2 MiB**, re-measured on this tree (see the commit message and
  `docs/confidential.md`): the mandatory public table + 51 new cpu columns grow a keccak-free
  production proof by a few percent over set 5's 1 202 416 bytes (tier 10), still far under the
  cap, and a keccak-carrying proof is still far over it. *(Note 2026-09-28: that is the default
  cap. Chains 13, 14 and 15 set genesis `max_proof_bytes` to 8 388 608 (8 MiB), so on the live
  chain a keccak-carrying proof fits.)*
- Vendoring mechanics worth knowing before the next resync (all in `deploy/sync-zkvm.sh`'s
  header): the `log_ext_degrees_pub` patch is re-anchored on the six-parameter `verifier_key`
  line and forwards all seven `log_ext_degrees` arguments; the domain-tag inlining gained a
  third tag (`PUB_DOMAIN = 15`, in `hash.rs` and `tables/cpu.rs`); `call_envelope.rs` (src and
  tests) had to be **added to the rsync exclude list** — it is node-local S3 code that did not
  exist when the list was written, and `--delete` would have removed it; three vendored files
  (`src/evm.rs`, `src/sbpf.rs`, `tests/isa.rs`) `include!` assets at upstream's two-levels-up
  `guests-compiled/` layout and get a sed to this crate's shallower one; the guest copy step is
  four bins (`fib`, `keccak256`, `evm`, `sbpf`) plus two assets (`erc20.runtime.hex`,
  `spl_token.so`).
- **New build requirement**: `evm-core` and `sbpf-core` are *path* dependencies of
  `randprotocol-zkvm` (`../../../circuits/guests-compiled/{evm-core,sbpf-core}`) and, unlike
  `rand-zkvm-cuda`, they are NOT optional — `circuits/` must sit beside `fullnode/` for any
  build of the crate. In a `/tmp/fullnode-*` worktree that means `ln -s
  <real circuits checkout> /tmp/circuits` first, or `cargo metadata` fails on the (already
  pre-existing) optional cuda path dep too. Dev-oracles at upstream's exact pins: `revm
  =43.0.2`, `solana-sbpf =0.11.1`, `sha2 =0.10.9`, `num-bigint 0.4`.
- The vendored suite grows by the EVM/sBPF/sha256 test files (`tests/evm_*.rs`, `tests/sbpf_*.rs`,
  `tests/sha256.rs`, a much bigger `tests/e2e.rs` including a tier-16 EVM call proof).
  `cargo test --workspace --release` at the re-vendor: **678 passed, 0 failed, 6 ignored**
  (upstream's three production measurements, the sBPF cycle breakdown, and the two
  memory-bound interpreter exit proofs), ~43½ min wall from a cold release target on a loaded
  machine — wallet flow 9m37s, cluster 22m44s (18 tests), zkvm e2e 7m25s.

### RAND rename and chain 10 (2026-09-16): the coin is RAND; every SHRUGG/SESH name is gone

Commits `a00c88c` (the rename: crates `randprotocol-core/-zkvm/-rvm/-client/-node` — a crate
cannot be `rand-core`, that is crates.io's `rand_core` — binaries `rand-node` and `rand`, RPC
`rand_*`, addresses `rand1…`, hash domains `rand-*`, p2p identity `rand-p2p-identity`, service
`rand-node`; the two root pins moved) and `a7b69d7` (the pin). **Chain 10** = genesis
`4d757f11…`, cut without the aggregation section like chain 9; `deploy/nodes.env` regenerated
(every peer id changed); rolled out with `deploy/cutover-droplet-rand.sh` C, D (the bootstraps)
first, then E, F, the twelve regional; hostnames are `rand-node-<name>`; old binaries and
retired chains' data dirs removed from every droplet. 16 droplets + A live; **B (MacBook Air)
still unreachable — it needs `bin-a00c88c/` and `.update-pin` = `a00c88c`.** The randscan
explorer got the same rename (randscan `286f399`) and was redeployed to E in the same minute.
Chain 9 (`dbb7498b…`, build `5f8c6f9`) lived for about an hour between the two.

### Pre-v0.1 security review (2026-09-16): two findings, both gated behind chain 9 — FIXED the same day

**Fixes merged to `main` (branch `security-fixes-v0.1`):** L1 `151af5b` (`Ledger::close_block`,
called by both `propose` and `apply_block_for_sync`); H1 `248a0f7` + `e03f8bd` (the fee bucket
records every bundle and is the ledger's coverable set — `CoverNotCoverable` at step 4, a
missing entry is a refusal not a zero share — and `BlockError::SecondAggregate` refuses a
second aggregate per block; spec §3.4/§4/§6.1 rewritten); M1 `32ec1b8` (`Transaction::hash`
takes the bundle proof by digest, domain `rand-txid-2`, so the marker form hashes to the
raw hash and the certified tx root binds a sealed block whole — **every transaction id
changes**, a hard fork like constraint set 6); dependencies `4a07d85` (libp2p 0.54 → 0.57,
all ten Dependabot alerts cleared). Each fix has a regression test that failed on `v0.1`.
The report's "Fixes" section records what was deliberately not done (binding the aggregate
proof to `(aggregator, nonce)` — a circuits change, defence in depth only now).


Tag `v0.1` sits on `0b98580`. A four-reviewer pass over `6f112e3..0b98580` (RPC hardening,
constraint set 6, M5 `randprotocol-rvm`, chain-side aggregation, S2/S3 follow-ups), each candidate
re-traced by an adversarial verifier. Findings:
`../security/fullnode-security-review-pre-v0.1-2026-09-16.md` (severity-ordered, "verified
OK" per crate — read it before re-reporting suspected issues). **Nothing found is reachable
on chains 5–8 (`aggregation: null`); all three items must be fixed before chain 9 is cut:**

- **H1** subsidy minting is bounded only by node policy: the replica applies every
  `Aggregate` in a block and `StoreCovered::covered` is seal-blind, so a leader holding an
  aggregator key re-signs a committed proof under fresh nonces and mints `subsidy(n)` per
  copy. Fix: one-per-block and unsealed-and-in-window as consensus rules, proof bound to
  `(aggregator, nonce)`.
- **M1** sealed-form sync binds a pruned bundle's digest fields and the state root, not its
  `envelopes` (nor a stateless `Call`); a sync peer can substitute them and the victim
  persists and re-serves them. Fix: a proof-less tx hash in the pruned record, bound by the
  aggregate interface or the tx-root leaf.
- **L1** (liveness, not security) `propose` never runs `sweep_expired_excesses`, which
  `apply_block_for_sync` runs before the root; the first expired fee bucket halts the chain.
  Fix: sweep in `propose` (factor the block-end steps into one function).

`randprotocol-zkvm` (constraint set 6) and `randprotocol-rvm` had no findings.

### Security review: done, fixes merged

A full review of the four crates against the Draft 3 whitepaper was done on
2026-09-10. Findings: `../concerns/fullnode-review-2026-09-10.md` (severity-
ordered, each verified against code, with a "verified OK" section — read it
before re-reporting suspected issues). Fixes merged into `main`:

- `1d24bf9` consensus: three-consecutive-view commit rule, local QC assembly, view/state bounds
- `d5143a6` hardening: cheap-before-expensive checks, block size as a consensus rule
- `a44d3f4` robustness: key file permissions, RPC limits, storage receipts, genesis validation

### Zk-side audit: fixes ported upstream, vendored back as constraint set 5 (2026-09-12)

A zk-focused audit (every AIR, the emulator, the host prover glue, chain
integration, and the cheating-test suite) found two **critical soundness holes**
in `tables/cpu.rs`'s hash row-group routing, plus a batch of completeness bugs.
Findings: `../concerns/fullnode-zk-audit-2026-09-12.md` (severity-ordered, each
verified against code, the two Critical items confirmed with attack witnesses
that verify pre-fix — read it before re-reporting suspected issues).

Every zk-side fix below was **ported into `research` upstream** and arrives here
through the constraint-set-5 re-vendor, not as a local patch — so read
`crates/randprotocol-zkvm/` as vendored code and take a fix back to `research` first.

- Free-standing `IS_HASH`/`IS_HASH_OUT` rows had **no entry gate** — a cheating
  prover could splice write-back rows anywhere, giving 4 arbitrary RAM writes per
  row at a free, unbounded `HASH_PTR` with no permutation consumed (a total break
  of execution integrity). Fixed with three transition gates (absorb/write-back
  predecessors, and nothing after the second write-back row).
- `HASH_FIN` was never pinned to write-back rows — setting it on the ecall row
  detached the group's `HASH_PTR` from its range-checked source (the same hole,
  one row later) and shifted the PC chain by one instruction. Fixed with
  `HASH_FIN·(1 − IS_HASH_OUT) = 0`.
- Both have full attack-witness regression tests in `tests/cheating.rs` that
  **verify against the pre-fix constraints** and are rejected after (confirmed by
  running them with the gates removed).
- **The M2.2 FRI retune (27 queries) is reverted to the whitepaper's 80/8/20**:
  it met the ethSTARK conjectured 100-bit target but dropped the proven
  proximity-gaps floor to ~42 bits (vs ~86 at q=80). The paper's reconciliation
  keeps q=80 for exactly this reason. `MAX_PROOF_BYTES` is 2 MiB because of it —
  at 80 queries the old 1 MiB cap rejected every production proof. *(Note 2026-09-28: 2 MiB is
  the default; chain 15's genesis, like 13's and 14's, sets `max_proof_bytes` to 8 MiB.)*
- Completeness/robustness: memory-table sort key now matches the AIR's key
  arithmetic (honest ≥2^30 hash addresses were unprovable); the emulator rejects
  `ptr ≥ 2^30`; the poseidon2 permutation budget is a `ProveError`, not a panic
  (auto-tier fits both budgets); the 16-bit `HASH_LEFT` cap (65 535 words) is
  enforced host-side; prove-side tier and immediate-truncation guards.
- **ZH4 is the one fix that is ours, not `research`'s**, because the function is:
  `ZkExecutor::check_program` (`crates/randprotocol-zkvm/src/executor.rs`) rejects a
  program whose `base_pc + 4·len` wraps the u32 pc space — deployable, provable
  by nothing, and paid for per word.
- The re-vendor that carried these also carried **milestone 4.2** (the `keccak`
  table and `KECCAK` syscall, optional per proof; proof-declared `mem_log_height`;
  a four-keyed verifier key), so constraint set 5 is both at once. A hard fork
  like every set before it; fleets must run the same build
  (`docs/confidential.md`, "Constraint set 5").

### RPC hardening: admission verification off the consensus loop (2026-09-14)

S1's review item I2, shipped on `rpc-hardening`. A gossiped or RPC-submitted
transaction's proofs now verify on `spawn_blocking` against a lazily refreshed
`Arc<Ledger>` snapshot — four workers behind a 64-deep queue — while the
consensus loop keeps turning; `Mempool` is split into a cheap `precheck` and an
`insert_verified` that re-runs the state-dependent half against the tip the
transaction is actually pooled on. Gossipsub uses application-level validation
(`validate_messages`), so a transaction is forwarded only once it has verified
here — **`ValidationMode` deliberately stays `Permissive`: a Strict/Permissive
mix across a fleet drops messages, and application validation is local to one
node**. The cost of that switch: every delivered message must be reported back
to gossipsub **exactly once** (accept / reject / ignore) or this node silently
stops forwarding it — consensus and status messages are accepted immediately,
and every transaction path, error paths included, ends in exactly one report. A
bounded refused-hash cache (8192 entries, FIFO, permanent verdicts only — the
`is_permanent` allowlist) answers a repeat refusal for free, and a per-peer
token bucket (burst 16, refill 4/s, keyed on the forwarding peer's
`propagation_source`, held on `node::Peer`) meters gossiped submissions. The RPC
grew `rand_getCompactBlocks`, batch requests (cap 20, notifications refused
`-32600`) and a WebSocket `newHeads` subscription on the same port;
`docs/rpc.md`'s changelog is the client-facing list.

Same day, the key property narrowed: a node may hold **viewing keys** — never
spend keys; the RPC layer has no type for those — for explorer-side scanning
(`rand_importViewingKey` / `rand_getViewingNotes`, in memory, 64 keys, 10 000
leaves a call, cleared at restart) and answer one-call payment proofs
(`rand_checkTransaction`, stateless). An imported key can disclose notes but
never move them.

### Load-bearing consensus invariants (do not regress)

- **The commit rule needs three consecutive-view QCs.** Any relaxation
  re-opens the conflicting-finality bug (regression test:
  `commit_rule_requires_three_consecutive_views`).
- **Every validator assembles QCs locally.** Votes already flood the gossip
  topic; the old `on_vote` gate that dropped them at non-leaders is what
  stalled finality whenever a collector was down (regression test:
  `one_validator_down_keeps_committing`). Do not reintroduce collector-only
  QC assembly. This likely root-causes the "views advance but nothing
  commits" stall worked around in `f5b8dfd`; fleets must run the same build
  (old collectors still eat QCs).
- **Views are bounded** (`MAX_VIEW_AHEAD = 1e6`) and all `view + 1` math is
  saturating. A signed NewView for `u64::MAX` used to halt every node.
- **Sync commits only through the three-chain rule.** `apply_synced` verifies
  the whole batch (every QC, epoch set, leader, execution) and commits only
  `commit_rule::committed_prefix` of it; the tail enters through the live
  path (`offer_pending`), never on a peer's word (regression test:
  `a_synced_certified_but_uncommitted_chain_is_not_committed`).
- **The lock is durable.** `resume` restores a persisted `locked_qc` ahead of
  the head's QC and never lowers one below it; `fallback_high_qc` is the only
  place the lock is lowered, and only after every fetch for the block failed
  (regression tests: `a_resumed_validator_keeps_its_lock`,
  `a_stale_safety_state_never_lowers_the_lock`).
- **Conflicting finality is fatal, not a log line.** A three-chain whose
  commit path does not reach the committed head stops the node
  (`Action::SafetyViolation` → `FatalSafety`); startup's `verify_chain`
  decides what the restart makes of the store.
- **Speculative state is capped**: `max_tree_blocks` (512), vote map (4096
  keys), NewView map (2048 views), orphans (256). Each tree entry clones the
  full ledger — revisit the clone-per-block design when state grows.

### Open follow-ups (not fixed, see concerns doc)

- `deploy/*.key.json` holds the live testnet validator seeds, whitelisted in
  `.gitignore`. Decide: rotate + scrub, or document as throwaway-public.
  **Resolved for chain 14 (2026-09-20, OPS-1)**: the 24 chain-13 validator and
  payout key files are untracked and the `.gitignore` exceptions are dropped;
  chain 14 runs on 18 fresh validator + payout keys generated off-repo into
  `$KEYDIR` (default `~/.rand-chain14`) by `deploy/gen-chain14-keys.sh`. The
  working copies of the old chain-13 keys are still on disk and still
  published seeds — this bullet stands for any chain that still runs on them.
- Block-application proof verification (`Ledger::apply_block`, synchronous
  inside `on_proposal`) still runs on the consensus event loop; moving it
  changes when a vote is emitted, so it needs a consensus decision. Admission
  verification left the loop on 2026-09-14 — see the RPC-hardening note above.
  **Softened on `feat/security-concerns-2` (B5)**: a proof verified at admission
  is not re-verified at propose/apply (the cache key binds the proof via
  `rand-txid-2`); the loop still pays it for blocks full of never-admitted
  transactions.
- Lock promises **are durable across restarts as of v0.5.1** (`resume` restores
  a persisted `locked_qc` ahead of the head's, `extends_locked` withholds the
  vote and fetches an unknown locked block, only `fallback_high_qc` lowers the
  lock and only after every fetch failed). Residual, recorded in the 2026-09-22
  re-review: `PersistSafety` is persist-on-vote, so a lock never voted under
  before a crash is lost — bounded by quorum intersection.
- No CLI prints a wallet's `recipient_hash` (a `rand address --recipient-hash`
  would have saved a scratch crate during the v0.5 round trip's burn-destination
  setup). A `BridgeAttest`'s `tx_json` does not render its source chain, token
  or sequence — both v0.5 follow-ups, not fixed.
- randscan (explorer repo) issues found against the live chain-14 fleet, not
  fixed here: `/bridge/assets` keys deposited/burned/outstanding per token
  **index**, so zUSD's seven backing rows all repeat the token's total instead
  of their own backing's numbers; `/tokens/1` renders `deploy_tx` as `null`;
  `/bridge` serves `registration_fee` as a JSON number where this node's RPC
  sends a decimal string.
- Nonces: **re-checked 2026-09-20 and narrower than this line said.** The shielded wallet carries
  no nonces at all — the only `nonce` fields in `wallet.rs` are bridge test fixtures. The race is
  in `rand-node`'s operator commands (`unbond`, `withdraw`, `unbond-aggregator`,
  `withdraw-aggregator`, `aggregate`), which read the *committed* nonce from the register. Both
  submit paths already wait for the commit before returning (`submit_staking`, and the aggregate
  arm), so back-to-back commands are safe; `--no-wait` opts out of that and re-introduces the
  race by choice. What is still open is a programmatic RPC client: a mempool-aware `next_nonce`
  would need admission to accept `current ≤ nonce ≤ current + pooled_run` as well, because the
  ledger requires the nonce to equal the current one exactly (`staking.rs`, `aggregation.rs`).
  Returning N+1 alone would be refused at the tip.
- **The lock is released in exactly one place** (`fallback_high_qc`), after every fetch for that
  block has failed. To be sound against a Byzantine peer that answers "I do not have it", that
  should require f+1 failed fetches; it does not yet (audit v3 review, I5 — strictly narrower
  than the behaviour before the CON-1b fix, not a regression).

### Repo workflow traps

- **This repo is worked on by multiple agents/sessions in parallel**, in the
  same checkout. Branches and the worktree HEAD move mid-task. Before
  committing, re-check `git worktree list` and `git log main`; for anything
  non-trivial, do your work in a separate worktree
  (`git worktree add /tmp/fullnode-<name> <branch>`).
- History alternates squashed mega-commits with small linear ones; branches
  get merged and deleted quickly. `main` is the only durable line.
- Full test suite: `cargo test --workspace --release` — 466 tests across 27
  binaries, **22 min measured 2026-09-13** on a machine also running another
  session's build, and measured *before* the proving slot below. Cargo runs the
  test binaries one after another and the two that prove real bundles dominate:
  the wallet flow 9m19s (six bundle proofs plus a call proof, after S2's bond
  stage and S3's call-envelope stage were merged into it) and the TCP cluster
  suite 6m28s (16 tests, proofs overlapping).
- **Proving concurrency is capped, and that cap — not block spacing — is what
  keeps a proof inside its window.** `crates/randprotocol-node/tests/proving_slot/`
  and `crates/randprotocol-client/tests/proving_slot/` (one module, two copies: both
  test binaries need it and they are different crates) hand out one permit at a
  time through a file lock in `<target-dir>/tmp`, so no two *unrelated* bundle
  proofs run at once anywhere in the workspace — across test binaries, and
  across two sessions' concurrent `cargo test` runs. Every proving test takes it
  around the whole `wallet::send`/`submit`/`submit_burn` call; the one test whose
  subject is a race takes it once for its pair, so the bound the windows have to
  outlive is a *two-way* contended proof (~190–255 s against 768 s at 3 s
  blocks), not a lone one — `PROVING`'s doc comment states it. With it the
  cluster suite measures **19m59s, 17 tests, 2026-09-13** — slower in wall time, because
  the proofs no longer overlap, and each proof correspondingly faster. That is
  where the 20 minutes go: the suite's ten holds carry **12 bundle proofs and 2
  program proofs**, and a bundle now measures 94.6–97.9 s alone (against ~255 s
  contended), with the double-spend race's two concurrent bundles at 114 s each
  and the burn's two sequential ones 190 s together — ~19 min of proving, plus
  the structural tests. The **wallet flow** measures **9m40s** with the slot
  (579.84 s, five bundles at 99.6–107.7 s plus a call proof) against 9m19s
  without it: that suite was already one test proving in sequence, so the slot
  costs it nothing and it never waited once. `PROVING` stays at **3 s blocks**
  (S2 had raised it to 2, S3 to 3) and its doc comment now says why rather than what;
  read it before making that chain faster again.
- Doctest flakiness ("extern location ... does not exist") means a concurrent
  cargo run raced the cache; rerun.
- **Short-shielded-address feature, full release suite, 2026-09-17** (chain-11 cut, `short-address`
  branch, task 10): `RECURSION_FIXTURES=… cargo test --workspace --release -- --skip round_trips
  --skip two_test_profile` — **0 failed across every one of the ~50 test binaries**, run detached,
  **~87 min wall time**. The three long poles named in the task brief matched: **wallet flow**
  3 tests, **760.24 s** (12m40s); **cluster** 20 tests, **3467.25 s** (57m47s, the aggregation
  capstone included); **zkvm e2e** (`crates/randprotocol-zkvm/tests/e2e.rs`) 24 passed + 6 ignored,
  **412.20 s** (6m52s). Everything else in the workspace (`randprotocol-core`, `-node`, `-client`,
  `-rvm`, `-zkvm`'s ~40 other test files, `bridge-codec`, doctests) finished in seconds each. No
  code changes were needed — the branch's Tasks 1–9 were already green.
- The whitepaper is `../whitepapers/randprotocol.tex` (Draft 3) — its
  AGENTS.md has the parameter table (FRI 80/8/20, Poseidon2 width 8,
  384-bit soundness-bearing hashes) that this repo's docs should stay
  consistent with.
