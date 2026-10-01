# Changelog

Every tagged release of the RAND full node, newest first. The client-facing RPC changes are also
logged, method by method, in [`docs/rpc.md`](docs/rpc.md#changelog).

From v0.5 on, each entry is a short summary: the date is the tag's, in UTC; "hard fork" means the
release runs only on a new chain, "node-only" that it rolled onto the live chain. The full record
of each release (the measured suite, the roll, the traps) is its entry in `AGENTS.md`. This file
stopped at v0.4 until 2026-09-30, when the entries v0.5 to v0.6.7 were written from `AGENTS.md`,
`git tag` and the GitHub release list (audit v6, DOC-6). There is no tag v0.5.2, v0.5.3 or v0.6.5.
"Assets" says what the GitHub release carries, as read on 2026-09-30.

## v0.7.0 — 2026-10-01 (chain 20, node-only)

Tag `TAG_SHA`. Node-only: no consensus rule, wire format, verifier key or genesis change; rolled
onto chain 20 one node at a time, from the first release built by `.github/workflows/release.yml`
(CI-gated, `--locked`, attested) and signed by the release key (`SHA256SUMS.sig`; the fleet's roll
scripts verify it, PROC-4/5, #110). What it carries beyond v0.6.9:

- **The audit v7 addendum, every row but the aggregation one** — Medium: SYNC-5/CON-6 (#120, a
  peer's unsigned claimed height holds a by-hash fetch back for at most 10 s), RPC-5 (#121, header
  pages capped at 16 MiB of reply, carried public-note transactions proof-stripped, the wallet
  halves a page answered too large or too slowly), VK-12 (#122, a proving timeout in
  `rand-prover`); Low: SYNC-6 (#127, the by-hash gate measures the pending tip), PROC-11 (#128,
  the gate pinned through `fetch_block`), CLI-18/CLI-19 (#129, #130, the wallet's first sync keeps
  a page's notes across a rising floor and drops a planted note no leaf matches), VK-13/VK-10
  (#125, #126, the pool's unit confined to loopback and a syscall filter; flood limits), VK-9/OPS-9
  (#123, #124, a key per pool member, the pool installed only from a signed release).
- **The last audit v6 rows**: PROC-2 (#109, the workspace builds from a clean clone: `evm-core`/`sbpf-core` vendored, the cuda backend a git dependency, CI's `clean-clone` job required),
  CS6-2 (#97, the reference ledger verifies with `verify_public`, fixed upstream and re-vendored at circuits 6d2015d), TOK-1 (#86, genesis `tokens.incremental_root`: an incremental registry commitment and per-token storage rows, dormant until a genesis sets it; the legacy root cached on every chain), ZKV-5 (#95, the digest-prefix rows' gas under-count pinned numerically; the circuit fix is constraint set 9's, zkp-circuits#2), OPS-6 (#112, the
  key-separation schedule — by 2026-11-01, before any mainnet genesis — enforced by
  `require_key_separation_or_testnet`).
- A fresh wallet's first sync on chain 20 no longer times out on a 29 MB header page (04092f28).

Open after this release: #119 (aggregation's memory and a targeted rVM forgery, before any genesis
enables aggregation). Assets: `rand-node`, `rand`, `rand-prover`, `SHA256SUMS`, `SHA256SUMS.sig`.

## v0.6.9 — 2026-10-01 (chain 20, node-only)

Tag `3f43101b`. Node-only, rolled onto chain 20 one node at a time: a `rand_getBlocks` header
carries its block's invokes in `public_notes` with their proofs stripped, so a wallet rebuilds an
RPL-2 payout from public fields rather than the invoker's envelope (`d0bb73fb`). Assets:
`rand-node`, `rand`, `rand-prover`, `SHA256SUMS`.

## v0.6.8 — 2026-10-01 (chain 20)

Tag `c9c9bd3c`. Hard fork for chain 20 (genesis `6210cf071a390d7ac61d8cbea5dd9d139d1a493a862b54a45a498f36af2d5135`), rolled all-stop/all-start with
the cut; it computes and runs chain 19's genesis too, but its consensus changes must never roll
node by node. Two lines of work:

- **The zUSD bridge fees** — genesis `bridge.fees`: 10 bps of each mint and each burn kept on Rand as a treasury zUSD note, the release attesting `amount − fee`.
- **RPL-2** — program state, program vaults and the `Invoke` action (`Action` 33), behind a
  `program_state` genesis section (`docs/program-state.md`).
- **The final audit v6 fixes** (issues #67–#118, one commit each): consensus — CON-4 (no
  automatic lock release; `rand-node safety release-lock`) and CH-1 (a timeout-certificate
  pacemaker); node-only hardening (a second `--public-rpc` listener, read timeouts, reserved
  validator peers, sync and gossip budgets, the pool's byte cap, a startup refusal when the
  reloaded state is not the head's, wallet key-file permissions, and more); and genesis-gated
  rules, dormant on any chain whose genesis does not set them: `testnet`, `binding_domain`
  (proofs and signed messages bound to the genesis hash), `proof_window_blocks`, the gas price
  ceilings and paying byte load, staking admission by vote and slashing, vesting revokes by a
  threshold to a fixed treasury, and bridge rotations that need possession and wait out a delay.
  Wallets need this build to send on a chain with `binding_domain`.

Assets: `rand-node`, `rand`, `rand-prover`, `SHA256SUMS`.

## v0.6.7 — 2026-09-29 (chain 18)

Tag `86941a1`. Node-only: fixes on the chain-18 build that change no consensus rule, wire format,
verifier key or shipped program digest; rolled onto chain 18 one node at a time. The sealed-proof
pruning pass keeps a height index of seal marks (#51, dormant: no chain aggregates); a wallet takes
the note-envelope format from the chain id, not from a node's claim (#64); the viewing-key
registry is keyed by a one-way id (#65); circuits `aeacf31` (#49 GPU kernels without aliasing
`&mut`, #63 the rVM DSL allocator, #66 ALU test coverage). **Tagged before its full workspace suite
finished**, on the operator's instruction; no result of that full suite is recorded. Assets:
`rand-node`, `rand`, `rand-prover`, `SHA256SUMS`.

## v0.6.7-rc1 — 2026-09-29 (chain 18's cut build)

Tag `0017de7`, a pre-release. Hard fork: v0.6.6's content (gas, constraint set 8) rebased onto
v0.6.4 (split authorisation). The build chain 18 was cut with: genesis
`a7cb020cc99a33c83fc38cfa0ec1db357f67fbf8b6dab13ab1d9812280b4da76`, live 2026-09-29 04:56 UTC, the
first gas-metered chain and the first with the encrypted memo on (`envelope_bytes: 1860`). Refuses
chains 14 to 17. Assets: `rand-node`, `rand`, `rand-prover`, `SHA256SUMS`.

## v0.6.6 — 2026-09-29 (no chain)

Tag `d742a9b`. Hard fork, never cut as tagged: the gas model (Phase 0's header-priced call floor as
node policy; Phase 1's in-circuit meter, `pv::GAS`, the genesis `gas` section and the pinned
bundle gas limit 20 479; Phase 2's dynamic gas and byte prices) on constraint set 8, and the
chain-18 cut scripts. Its content reached a chain as v0.6.7-rc1. The tag has no GitHub release.

## v0.6.4 — 2026-09-29 (chain 17)

Tag `b388540`. The launch record of chain 17 (genesis
`d1afefc3dd68f73e3799aa0803b692d0e6a5c7c27d228bdeb3d06cdf4027e7ff`, live 2026-09-29 03:03 UTC,
replaced by chain 18 at 04:56 UTC): the committed genesis file, its pin test and the `AGENTS.md`
entry. The code is v0.6.3's. Assets: `rand-node`, `rand`, `rand-prover`, `SHA256SUMS`.

## v0.6.3 — 2026-09-29 (chain 17)

Tag `d4fd0a3`. Hard fork: delegated proving, phase 2 — split authorisation. A `Bundle` gains
`auth_commit` and `auth_proof` on the wire and the transaction id domain becomes `rand-txid-3`; the
bundle proof no longer takes the spend key (bundle guest v3 plus the auth guest, genesis `hc_auth`),
so a paired prover holding only a viewing key can prove; an optional prover fee. Refuses chains 14
to 16. Assets: `rand-node`, `rand`, `rand-prover`, `SHA256SUMS`.

## v0.6.2 — 2026-09-28 (chain 16)

Tag `98d1ff6`. Node-only and opt-in: delegated proving, phase 1 — the `randprotocol-prover` crate,
the `rand-prover` binary, `rand-node run --prover`, and the wallet's `--prover`. A phase-1 prover
receives the spend key, so delegating is handing over custody. One change every node gets: SIGTERM
is handled like ctrl-c. Assets: `rand-node`, `rand`, `rand-prover`, `SHA256SUMS`.

## v0.6.1 — 2026-09-28 (chain 16)

Tag `2c75e08`. Hard fork: constraint set 7 (circuits `b9ffc39`) — every LogUp terminal blinded,
every declared table floored at 2^7 rows, 32-bit range checks on input, public and salt words, the
`POSEIDON2_LEN` syscall, the JALR fix, verifier keys salted from `key_derivation_v2`. Every
verifier key changed. Chain 16 (genesis
`20925ae63cfa6e6c96f3ff369486ead8ea04821fec026a55df9e2893f3d53005`, live 2026-09-28 16:39 UTC) was
cut with `--hardening-v6 --bundle-guest v2`. Refuses chains 14 and 15. Assets: `rand-node`, `rand`,
`SHA256SUMS`.

## v0.6 — 2026-09-27 (chain 15)

Tag `12a56d1`. Same chain, but rolled all-stop/all-start, not one node at a time: `Machine::verify`
refuses a non-zero commit-phase proof-of-work word unconditionally, so a mixed fleet could
disagree on a rewritten proof. The zkVM, rVM and aggregation fixes of the 27–28 September reviews:
the prover floors private tables at 2^7 rows and nodes refuse to pool a call proof below it; the
branch-free bundle guest v2 and the `hardening_v6` switch, both for the next cut; the bundle key in
its own `Machine`; the dormant rVM and aggregation-interface fixes. Assets: `rand-node`, `rand`,
`SHA256SUMS`.

## v0.5.11 — 2026-09-27 (no chain)

Tag `cc65c5e`. Genesis-gated, active on no chain: timelocked genesis vesting for team, investor
and partner allocations (a public vesting register, actions 24 to 27, state root domain
`rand-state-6`). Without a `vesting` genesis section the four actions are refused at admission.
The cluster and wallet-flow suites were not run for this tag. Assets: none.

## v0.5.10 — 2026-09-27 (chain 15)

Tag `0c0f4db`. Node-only on chain 15: address sharing — the 80-bit address fingerprint, `randpay:`
links and QR codes — and the encrypted memo (genesis `envelope_bytes: 1860`, first set by chain
18). CLI changes: token amounts are display units, `rand address` prints only the address on
stdout, `rand send` confirms first. Assets: `rand-node`, `rand`, `SHA256SUMS`.

## v0.5.9 — 2026-09-27 (chain 15)

Tag `8abf85e`. Node-only, rolled one node at a time: the fixes of the 2026-09-27 rescan. A faucet
mint is admitted only from a genesis validator (LEDGER-1; the validity rule is genesis
`staking.faucet_minters`, set from chain 16); sync back-off and peer ranking (CN-1); meters that
survive a reconnect and a node-wide `Blocks` budget (CN-2); consensus gossip prechecked before it
is forwarded (CN-4); a signed `NotHeld` view (CN-3); `bridge.min_inbound_sequence` (C15-1); the
wallet resumes at a pruning node's floor (RS-1). Assets: `rand-node`, `rand`, `SHA256SUMS`.

## v0.5.8 — 2026-09-26 (chain 15)

Tag `b933724`. Node-only: the fixes of the ten-reviewer pre-release scan — the orphan pool bounded
(SW-1), a `Status` read only from its propagation source (SYNC-1), one vote per (view, voter)
within a view window (CONS-1), wallet defences against a lying node (WAL-1, WAL-2, WAL-3), RPC
blocking reads capped, deploy scripts that ship `git archive HEAD` only. The fleet took it through
the chain-15 cut (genesis `cc30e0854fb25b3abcee96bb7bc206dcd6e37862f6dfe80a05b3e474c2d1b6b8`, live
2026-09-26 13:05 UTC, build `dd2ccbe`). Assets: `rand-node`, `rand`, `SHA256SUMS`.

## v0.5.7 — 2026-09-25 (chain 14)

Tag `089bdd6`. Same chain, rolled all-stop/all-start: `Status` gains `floor`, and a v0.5.7 node
cannot decode a v0.5.6 `Status`. History pruning: `rand-node run --prune-history <n>m|h|d` keeps
that much history and prunes the rest; a node without the flag is an archive; RPC error `-32010`
answers a height below the floor. The database is forward-only for a pruned data directory.
Assets: `rand-node`, `rand` (no `SHA256SUMS`).

## v0.5.6 — 2026-09-24 (chain 14)

Tag `a2d4021`. Same chain, rolled all-stop/all-start: DS-3 is a validity rule (a call proof's
header is pinned before a key is built: tier at most 14, keccak at most 2^12, sha256 at most
2^13). The rest of the deep security-and-math scan (DS-1 to DS-9): a pruned record is
length-checked, connection limits on the swarm, the equivocation record outlives eviction, the
2^63 note bound. Assets: `rand-node-v056`, `rand-v056` (no `SHA256SUMS`).

## v0.5.5 — 2026-09-24 (chain 14)

Tag `0154fe2`. Same chain, rolled to all 18 validators at once. The audit-v5 fixes and the recovery
from the chain-14 stall: a committed block's QC is stored once (a node rolled back below v0.5.5
needs a resync); the lock is released only on a not-held quorum; certified blocks above the head
are durable; three recovery rules for a QC on a block no replica holds; `tokens.burn_registration_fee`
(genesis-gated). Assets: none.

## v0.5.4 — 2026-09-24 (chain 14)

Tag `d0778d8`. The audit-v4 fixes, in three classes. Node-only: a disk guard, a bound on sibling
proposals, the ghost-QC memory, the 256 MB write-ahead-log cap. Wire-coordinated: signed `NotHeld`
attestations. Genesis-gated, for the next cut: the `staking` section, `consensus_domain: 1`, bridge
`rules_v2` with rolling mint caps, `tokens.max_tokens`. Assets: none.

## v0.5.1 — 2026-09-20 (chain 14)

Tag `9c142c1`. Node-to-node only, rolled one validator at a time: the audit-v3 consensus fixes —
sync commits only through the three-chain rule, the lock survives a restart and a sync,
conflicting finality stops the node. Assets: none.

## v0.5 — 2026-09-20 (chain 14)

Tag `b143cb9` (fleet build `b3c594c`). Hard fork: chain 14, genesis
`1cff3b7da248d93ab547aef5c05bb7d0d22da510b592dab9cf7374807de7c7ff`, on eighteen fresh validator
keys generated off-repo. RPL tokens (a ledger-level registry of shielded native assets), one
4-in/4-out hidden-asset bundle for every transfer, every bundle proof bound to its transaction,
a mint's commitment opening checked (POOL-1), and the hardened bridge for zUSD: per-backing mint
caps, a pause key, a forward bound on block timestamps, a post-quantum co-signature quorum.
Every `u64` RPC amount became a decimal string. Assets: none.

## v0.4 — 2026-09-19 (chain 13)

| | |
|---|---|
| release date | 2026-09-19 |
| chain | 13, genesis `8123ccac1883a45750e4df6964fb7cd3f0b321798cde4c0ef406a0293939ece3` (`deploy/genesis-chain13.json`) |
| pinned build | fullnode `86af6eb` (Linux `rand-node` sha256 `cc20bf84…`; laptop binaries in `bin-86af6eb/`) |
| circuits | main `7ef3220` (tag `v0.4`) |
| aggregation | off (no `aggregation` section, as chains 9–12) |

Chain 13's limits:

| limit | value |
|---|---|
| `max_program_words` | 65 535 |
| `max_proof_bytes` | 8 388 608 (8 MiB) |
| `max_block_bytes` | 20 971 520 (20 MiB) |
| `max_call_envelope_bytes` | 65 536 |
| `max_program_public_words` | 32 768 |

v0.4 is the RISC-V developer release: the `rand-guest` toolchain and the two bytecode
translators, `sbpf2rv` (Solana) and `evm2rv` (Ethereum). They live in the circuits repo (main
`7ef3220`). Fullnode's side is the program cap as a genesis parameter and the deploy of a
`rand-guest` image. Those commits are already listed under v0.3's
[Also included: the program cap as a genesis parameter](#-also-included-the-program-cap-as-a-genesis-parameter)
and are not repeated here. They take effect on the first chain whose genesis sets
`max_program_words`.

New in v0.4 on the fullnode side (branch `feat/call-limits`, spec
`docs/superpowers/specs/2026-09-19-call-limits-design.md`):

- **The call limits are genesis parameters**: `max_proof_bytes`, `max_block_bytes`,
  `max_call_envelope_bytes` and `max_program_public_words`, threaded like `max_program_words`
  (optional, bound into the hash only when present). Every proof cap, the whole-transaction and
  block caps, the envelope cap, the node's sync and gossip limits and the RPC's body limit and
  pre-check follow them. A call's fee gains a byte term past today's allowance.
- **A program's public input is fixed at deploy**: `rand program deploy --public <words | ELF>`,
  a new program id rule (`rand-program-2`), `H_PUB` checked on every call against the digest
  recorded at deploy, `h_pub` in receipts, and `rand_getLimits` / `rand_getProgramPublic`.
  There are no per-call public words.
- `deploy/cut-chain13-genesis.sh` cuts chain 13 with 65 535 / 8 MiB / 20 MiB / 65 536 /
  32 768. Chain 13 was cut with it on 2026-09-19 and runs on the 16 droplets and node A
  (`deploy/README.md`, "What the chain-13 rollout actually did").

### Headline evidence: live on chain 13

Both translated programs were deployed from the genesis wallet `shielded-1` on the live chain
(production FRI profile), and the ERC-20 was called.

| action | wallet output | on chain |
|---|---|---|
| deploy the translated ERC-20 (`evm2rv` stage 2, `hc a0feae92…` in `rand-guest`'s spelling) | `program id: f074c4eb834cf01886a8241b6a2e0caf6e1cee5327fee6cb1a1a37436607280d (11686 words, hc 92aefea0951c31a717574962aeb70e10a37012a7d035d48e8713c36df68feae0)`; bundle proved in 92.2 s (tier 14, 1 419 655 bytes) | deploy tx `c7a66dc4…53acd0`, committed at height 381 |
| call it: `approve(BOB, 5)`, 649 private words | `proved in 388.7s: tier 16, 3412405 bytes, outputs [1, 942495465, 790002515, 1351749335, 1059083501, 2923046783, 2814575942, 696258848]`; bundle proved in 96.0 s (tier 14, 1 420 423 bytes) | call tx `279e1f62…c4bfa7`, anchored at 802, committed at height 919; fee 0.00357 RAND; envelope 2 700 bytes; receipt `h_pub` null |
| deploy the translated SPL Token (`sbpf2rv`, `hc 8ca905ae…` in `rand-guest`'s spelling) with its ELF as the public input | `program id: 740236918310f8e52bb0c1ef49b2b0e0c018762e289666660685b0694c8dd00a (65096 words, hc ae05a98c…b516ad, public input 27151 words, digest ec57b10e…d67e)`; bundle proved in 94.3 s (tier 14, 1 418 406 bytes) | deploy tx `626fc938…927530`, anchored at height 400; fee 9.2257 RAND |

What the call shows:

| claim | measurement |
|---|---|
| the production call proof needs chain 13's proof cap | 3 412 405 bytes, over chain 12's 2 MiB cap: a call chain 12 could not accept |
| the fee's byte term applies | 0.00357 RAND: the 3.41 MB proof is above the 2 MiB + 18 432 B free allowance |
| the call is faithful | the receipt's eight outputs equal the interpreter's for the same vector |
| a laptop can make it | 622.8 s wall time, 22.9 GB peak RSS, on a 48 GB M-series laptop |

Method: `rand program deploy <image.bin>` (with `--public spl_token.so` for SPL Token) and
`rand call f074c4eb… --input …` against chain 13, 2026-09-19. Full hashes and transcripts:
`docs/translators.md` §4.6, §4.6.1 and §5.4.

### Claims, measurements and methods

| claim | measurement | method |
|---|---|---|
| `rand-guest` builds a Rust or C guest into an image the chain accepts | a Rust and a C guest built, checked, run and deployed; the call's receipt outputs equal `rand-guest run`'s | a local one-validator chain, test FRI profile, 2026-09-19 (`docs/guests.md`) |
| the build is reproducible | the Rust `fib` guest rebuilt at a different checkout path gives the committed `hc ed475c16…b99e` | rebuild and compare; `rand-guest/tests/build.rs` gates the four committed guests |
| the raised cap admits large images | the 11 686-word ERC-20 image deployed on a chain cut with `--max-program-words 65535` (fee 1.1696 RAND); the same deploy on a 4096-word chain is refused before any proving | the same local chain setup |
| `evm2rv` output equals the interpreter's | identical eight words for `transfer`, `approve` and `transferFrom`; 66 235 / 48 119 / 88 824 cycles against 121 638 / 85 645 / 161 434 on `evm.bin` (54.5–56.2 %) | `rand-guest run` on both images and `diff`, re-run 2026-09-19; `evm2rv/tests/parity.rs` (8 vectors, both stages) and `tests/fuzz.rs` (10 000 random programs) |
| `sbpf2rv` output equals the interpreter's | identical eight words for SPL Token `Transfer` 250; 765 851 cycles against 694 498 on `sbpf.bin`; all 8 vectors in tier 20; image 65 096 words | `sbpf2rv/tests/parity.rs`, 2026-09-18 |
| SPL Token translation does not pay off today | about 98 % of each run is the fixed sBPF ABI harness; the translated image is 69–75 k cycles dearer per vector | per-stage cycle attribution (`sbpf2rv/README.md`) |
| the call limits are genesis parameters, and a genesis without them is chain 12 byte for byte | each field bounded, refused out of range (including block ≥ 2 × proof + 1 MiB) and bound into the hash only when present; the chain-12 file still hashes to `605eb783…`; all five restored after a restart and replay | `the_call_limits_are_optional_and_bound_into_the_hash_only_when_present`, `the_call_limits_are_refused_out_of_bounds`, `chain_12s_genesis_file_still_builds_chain_12`, `the_call_limits_hold_through_replay_and_restart` |
| the ledger enforces the chain's limits, not constants | a 2 MiB + 1 B proof refused by default and admitted at 8 MiB (call, fee bundle, burn); a 5 MiB call block refused by default and applied on a raised chain; the envelope cap is the genesis value | `every_proof_cap_is_the_ledgers_max_proof_bytes`, `the_whole_transaction_cap_is_the_ledgers_max_block_bytes`, `apply_block_for_sync_uses_the_ledgers_block_cap`, `the_call_envelope_cap_is_the_ledgers` |
| a call costs what it cost before up to the free allowance | `call_fee` unchanged at ≤ 2 097 152 + 18 432 bytes, +1 000 units per KiB (or part) past it; the node answers `rand fee call 16 --bytes 2115584` with 0.0023 RAND and `--bytes 2115585` with 0.002301 RAND | `the_call_fee_charges_only_bytes_past_todays_allowance`; `rand fee` against the local chain below |
| the node's transport follows the block cap | a ~14 MiB block syncs between two libp2p nodes on 20 MiB limits and is refused between two on the defaults; a default chain keeps 6 MiB / 12.25 MiB / 16 MiB | `two_nodes_on_a_20_mib_chain_sync_a_block_over_the_default_reader_limit`, `the_wire_limits_follow_the_ledgers_block_cap` |
| a public input is fixed at deploy and binds every call | the id with a public input is injective over the code/public split; the deploy pays for its public words and stores the digest; a call proved over the right words verifies and its receipt carries `h_pub`, one over other words or `&[]` fails with `PublicValues` (stub and real zkVM proofs) | `a_public_input_changes_the_id_and_an_empty_one_does_not`, `the_code_and_public_boundary_is_bound`, `a_deploy_with_public_words_gets_the_new_id_pays_for_them_and_stores_the_digest`, `a_call_is_checked_against_the_programs_public_digest_and_the_receipt_carries_it`, zkvm `a_call_is_checked_against_the_records_public_digest`, `a_program_with_a_public_input_is_warmed` |
| the RPC and the wallet expose both | `rand_getLimits` returns the five limits; `rand_getProgramPublic` serves the words; end to end on a test-profile chain: deploy `public_echo` with `--public`, call it, receipt `h_pub` equals the digest, `--expect-public` refuses before proving, a proof over other words is refused by the chain (354 s) | `get_limits_reports_the_chains_five_limits`, `a_programs_public_input_is_served_with_its_digest_and_the_receipts_h_pub`, `wallet_flow::a_program_with_a_public_input_is_deployed_and_called_over_it` |
| the translated ERC-20 is called on chain 13's limits | `approve` (649 private words, tier 16) through `rand call`: receipt outputs `[1, 942495465, 790002515, 1351749335, 1059083501, 2923046783, 2814575942, 696258848]`, equal to `rand-guest run`'s and the native interpreter's; call proof 796 019 bytes, transcript 2 700 bytes, fee 0.0023 RAND; 505.6 s end to end (call proof 392.6 s, fee bundle 95.8 s), 19.8 GB max RSS, 22.9 GB peak footprint; `rand open-call` re-opened the words: faithful | a local one-validator chain with chain 13's five limits, test FRI profile, 48 GB laptop, `/usr/bin/time -l`, 2026-09-19 (`docs/translators.md` §4.6.1) |
| the translated SPL Token deploys with its ELF as the public input | program id `74023691…d00a` (the bare image's is `65d234ce…`), 65 096 code + 27 151 public words, `public_digest ec57b10e…d67e`, fee 9.2257 RAND, 97.3 s (bundle 93.2 s); `rand call --expect-public` with a one-byte-changed ELF or a 4-word file refused in ≤ 0.01 s at 11 MB RSS, nothing proved. The call proof (tier 20, about 330 GB) was not run | the same local chain (`docs/translators.md` §5.4–5.5) |
| ERC-20 is proven; SPL Token is not | tier 18 (ERC-20 `transfer`): OOM-killed at 24.7 GB on a 48 GB laptop, above 47 GB at 25 min on a 64 GB droplet; proved on a 128 GB droplet (m-16vcpu-128gb) at 85.0 GB (translated) / 85.5 GB (interpreted) peak RSS, 3 230.5 s / 3 143.3 s, 811 600 / 805 108-byte proofs. Tier 16 (ERC-20 `approve`, translated): 21.7 GB, 786.7 s (13.1 min), 798 930-byte proof. Tier 20 (SPL Token): OOM-killed at 65.1 GB on a 64 GB droplet after 10 m 41 s; not yet proven — extrapolated at about 330 GB and about 3.6 h, more than DigitalOcean's largest memory droplet (m-32vcpu-256gb, 256 GB) | `/usr/bin/time`, watchdogs; the prover is single-threaded (99 % of one core on 16 vCPUs) |

### Docs

- `docs/guests.md`: the Rand ISA, the syscall ABI, the image container, step-by-step Rust, C and
  hand-built deploys, `hc` versus program id (and `hc`'s two spellings), the hermetic build, the
  cap.
- `docs/translators.md`: the trust model, the parity guarantee and its accepted divergences, the
  ERC-20 and SPL Token walkthroughs, measured tables, limits.
- `docs/node-hardware.md`: what each role proves or verifies, measured RAM and disk, DigitalOcean
  sizes, prover memory per tier, setup.
- The call limits and the public input: `docs/cli.md` (the four `rand-node genesis` flags,
  `deploy --public`, `call --expect-public`, `fee --public-words` / `--bytes`), `docs/rpc.md`
  (`rand_getLimits`, `rand_getProgramPublic`, `h_pub`), `docs/guests.md` §8.1,
  `docs/confidential.md` (Call limits and a program's public input), and `docs/translators.md`
  (calling the ERC-20; the SPL deploy with `--public spl_token.so`).

### Known limits

- **This build is chain-13-only. It must not be same-chain-updated onto chain 12.** The
  encodings of `Action::Deploy` (it carries the public words), `ProgramRecord` (`public_digest`,
  `public_len`) and `CallReceipt` (`h_pub`) changed, so a chain-12 database and chain-12 blocks do
  not decode under it. A proof whose bytes are not the canonical postcard encoding is now
  refused, which is a consensus tightening. The sync wire carries proofs and envelopes as CBOR
  byte strings, which an older node cannot read. A chain-12 genesis file still hashes to
  `605eb783…`, but that says only that the genesis is unchanged, not that the build can run on
  the chain. Roll it out as a chain cut (`deploy/cut-chain13-genesis.sh`).
- The chain side of both translated programs needs chain 13's limits. On chain 12 (no limit
  fields) the images are over the program cap, SPL Token's public input is refused, its 10 458
  private words are over the default 4 295-word input cap, and a keccak-carrying ERC-20 call
  proof (3 198 430 bytes at tier 10, production) is over the 2 MiB proof cap.
- **SPL Token calls are unproven.** No SPL call proof exists: tier 20 needs about 330 GB, more
  than any DigitalOcean droplet (256 GB max). Its deploy (live on chain 13), public input and
  refusal paths are run; its call proof is not. The ERC-20 `transfer` and `transferFrom` calls
  are tier 18 and need about 85 GB; only `approve` (tier 16) was called on chain 13, from a 48 GB
  laptop.
- `rand call --no-envelope` applies no input-word cap, since nothing is sealed.
- EVM: the nine block-context opcodes trap; a `CALL` with nonzero value traps; ecrecover,
  bn256 mul and pairing, large modexp and long blake2f exceed the 2^20-cycle tier cap.
- sBPF: CPI and unknown syscalls trap at run time; Ed25519 and secp256k1 exist in software but are
  unlinked.
- Fixed: `deploy/vps-setup.sh` deleted the `rand-node` unit it had just written (a leftover of the
  rename). It still inits from chain 5's `deploy/genesis.json`; `docs/node-hardware.md` gives the
  manual steps.

---

## 🚀 RAND fullnode v0.3 — the RPC catches up with Ethereum and Solana

**Released 2026-09-18 · chain 12 (genesis `605eb783…`) · same-chain update, no fork**

The fleet runs `4504a03`. The tag also carries two later groups of commits, neither deployed yet:

- `3ee3913`, `c36d690`: the `rand viewing-key` and `rand tx-key` wallet commands and one node-side fix. See [Keys you can hand out](#-keys-you-can-hand-out).
- `3cfc0a2..10422b6`: the program cap as an optional genesis parameter, and deploys of `rand-guest` images. See [Also included](#-also-included-the-program-cap-as-a-genesis-parameter).

v0.3 is an RPC release. We lined the node's JSON-RPC up against Ethereum's execution API and
Solana's RPC, method by method. Then we added the methods a wallet or explorer author reaches for
first and could not find here:

- post-submit status that tells *pending* apart from *dropped*
- per-program receipt queries
- multi-gets
- finality
- health and build identity
- two new WebSocket push topics

Everything is node-side. Blocks, transactions, gossip, sync and genesis are byte-for-byte
unchanged, so v0.3 nodes and chain-12 nodes run side by side. The whole fleet was upgraded in
place with no chain cut.

---

### ✨ Eleven new JSON-RPC methods

| Method | What it answers | Ethereum twin | Solana twin |
|---|---|---|---|
| `rand_getVersion` | crate version, full git sha, chain id, `hc_bundle`, FRI profile | `web3_clientVersion` | `getVersion` |
| `rand_getGenesisHash` | the genesis hash this node was initialised with | — | `getGenesisHash` |
| `rand_getHealth` | `ok` / `syncing` / `behind` + the lag in blocks | `eth_syncing` | `getHealth` |
| `rand_getTransactionStatus` | up to 64 hashes → `committed` / `pending` / `rejected` (with reason) / `unknown` | `eth_getTransactionReceipt` | `getSignatureStatuses` |
| `rand_getReceipts` | a program's receipts over a height range, paged | `eth_getLogs` | `getSignaturesForAddress` |
| `rand_getWitnesses` | up to 32 Merkle witnesses from **one** tree build | `eth_getProof` × N | `getMultipleAccounts` |
| `rand_getBlocks` | up to 128 block headers in one call | batch only | `getBlocks` |
| `rand_getFinality` | `committed` / `certified` / `proposed` / `unknown` from the replica's own QCs | `eth_getBlockByNumber("finalized")` | `getBlockCommitment` |
| `rand_getProposer` | the leader per view (≤ 64) under the current validator set | — | `getLeaderSchedule` |
| `rand_getMempoolInfo` | pooled count, bytes, oldest age, cap | `txpool_status` | — |
| `rand_getEmission` | inflation (a fixed `"0"`), the aggregation subsidy schedule, faucet flag | — | `getInflationRate` |

Full parameters, result shapes, caps and error codes are in [`docs/rpc.md`](docs/rpc.md). The
method-by-method comparison is in [`docs/rpc-comparison.md`](docs/rpc-comparison.md).

#### A closer look

- **Know when a transaction is dead.**
  - What it covers: `rand_getTransactionStatus` checks the chain first, then the mempool, then the
    node's refused-transaction cache. A transaction refused for its own bytes reads `rejected`,
    with the exact reason the node gave. Those reasons include:
    - a bad proof, digest or mint signature
    - the wrong chain
    - an oversize part
  - What it does not cover: a refusal about *state* is not remembered. Examples are a spent
    nullifier or an expired anchor. Such a transaction reads `unknown` once it leaves the pool.
- **Receipts by program**, paged with a *soft-floor* limit (default and cap 256).
  - A page never splits a block, so `next_height` is always the first height not yet served.
  - A client never sees a receipt twice and never loops.
- **Witnesses in bulk.**
  - `rand_getWitness` rebuilds the whole commitment tree for every call.
  - `rand_getWitnesses` pays that cost once for up to 32 leaves.
  - A wallet spending several notes needs one round trip.
- **Finality you can show a user.**
  - `certified` means a quorum certificate exists but the block has not committed yet.
  - `committed` is final.
  - A block that commits while you are asking still reads `committed`, never `unknown`.
- **Emission.** There is no inflation on RAND, and the method says so explicitly. Clients
  porting from Solana's `getInflationRate` get a number instead of a missing method.

---

### 📡 Two new WebSocket topics

Same port and path as before (`ws://host:8545/`). `newHeads` is unchanged.

| Topic | Subscribe with | You get |
|---|---|---|
| `receipts` | `["receipts"]` or `["receipts", "<program_id>"]` | one message per block that carries matching receipts |
| `transaction` | `["transaction", "<hash>"]` | **exactly one** message when the hash commits or is refused, then the subscription removes itself |

- **No race on submit-then-subscribe.** If the transaction already committed or was refused
  before you subscribed, the answer arrives on the next block. Clients have one code path.
- **A slow topic can't disconnect you from another one.** A lag closes a connection only when
  it is subscribed to a stream that fell behind. A `newHeads`-only client is never dropped
  because of receipt or refusal traffic.
- The three streams are independent. A client subscribed to several may see block N's
  receipts before block N's head.

---

### 🔑 Keys you can hand out

Two new wallet commands export the keys a holder may choose to share. Neither can spend.

- **`rand viewing-key`** prints the wallet's viewing key: 64 hex, the exact parameter
  `rand_importViewingKey` takes. It reveals every note the wallet has sent or received.
- **`rand tx-key <hash>`** prints one row per output of that transaction the wallet sent, received
  or kept as change, with the per-transaction key the output was sealed under.
  - A `sent` row's key is a payment proof. `rand_checkTransaction <hash> <key>` discloses that one
    output to whoever holds the pair, and nothing else.
  - Nothing is stored at send time. Every envelope carries its key twice, under the sender's
    outgoing viewing key and under the recipient's KEM secret. So the sender and the recipient
    both recover the same key, for any past transaction.

```
$ rand tx-key bee116bf…
output          role                      amount  tx key
bundle:0        sent                   1000 RAND  5f60738f…ae46
bundle:1        change               99.979 RAND  b5624451…9654
```

**Node change:** `rand_checkTransaction` now also discloses a faucet mint's note (`mint:0`).
Its recipient recovers the key through the envelope's KEM half. The chain-12 fleet runs
`4504a03`, so this check applies once nodes are rebuilt at or after `c36d690`.

---

### 🧩 Also included: the program cap as a genesis parameter

These ten commits were written for the v0.4 chain and change nothing on chain 12.

- A genesis file may set `max_program_words` (`1..=65535`). Absent, the cap stays 4096 words and
  the genesis hash is unchanged, so running chains see no difference. The ledger, admission,
  reload and `rand_estimateFee` all read it.
- `rand_estimateFee` for a deploy refuses past the chain's cap, with the cap in the message. No
  method, parameter or result shape changed.
- `rand program deploy` accepts the image container `rand-guest build` emits, prints `hc` in
  `rand_getProgram`'s spelling, and refuses an over-cap program before any proving.
- It takes effect on the chain cut that sets the field. Details are in `docs/rpc.md`, entry
  "for the v0.4 chain".

---

### 🗄️ Storage

- **New `receipts_by_program` index**, a RocksDB column family written in the same atomic
  batch as each receipt and dropped with it on a truncate.
- **One-time backfill on first start.** Chain 12's explorer node indexed its 117 receipts
  instantly. A later restart finds the marker and skips the backfill. A node killed mid-backfill
  finishes on its next start.
- **The database is forward-only.** A pre-v0.3 binary refuses to open a database that has the
  new column family. To roll back, run the new subcommand with the v0.3 binary while the node is
  stopped:

  ```bash
  rand-node db drop-receipts-index --datadir <dir>
  ```

  Then re-pin the old build. The full procedure is in `deploy/README.md`, section "Rolling back
  v0.3". Tests cover both directions: a pre-v0.3 database migrates, and a dropped database opens
  with the old column-family list.

---

### 👛 Client library (`randprotocol-client`)

- `wait_for_transaction` now fails fast on `rejected`, with the node's reason in the error,
  instead of waiting out the full timeout.
- **Old nodes still work.** Against a node older than v0.3, the client detects the missing
  method once and falls back to its old polling loop.
- New `transaction_status(&[Hash])`.

---

### 🔒 Bounds and hardening

The RPC is unauthenticated, so every new surface is bounded. Code review during the release found
and fixed the following before release.

- `rand_getProposer` refuses a range wider than 64 views **before** allocating anything. It
  used to build the whole range first, so one call with `[0, u64::MAX]` could exhaust a node's
  memory.
- `rand_getTransactionStatus` reads only a transaction's *location* (height and index). It
  no longer decodes the full record, which on chain 12 includes a ~1.2 MB proof. That was up to
  64 decodes per call on the threads consensus shares. The lookup now also runs off the async
  runtime.
- `rand_getMempoolInfo` keeps a running byte total. It no longer re-serializes every pooled
  transaction on the consensus loop for each call. Block building reuses the stored lengths too.
- `rand_getEmission` reads two metadata keys. It no longer rebuilds the whole ledger and
  commitment tree for each call.
- `rand_getReceipts` cursors always advance. The earlier design could loop forever on a
  height with more receipts than the page size.
- `rand_getFinality` by hash no longer reads `unknown` for a block that commits while you ask.
- Every new method checks its caps on the input before doing any work: 64 hashes, 32
  indices, 128 headers, 64 views, 256 receipts, 8 subscriptions per socket.

---

### 🧰 Operators

- **`rand_getVersion` reports the exact commit a node was built from.**
  - `deploy/rebuild-vps.sh` writes it into the tree before the rsync and passes it to the build
    as `RAND_BUILD_SHA`, so a stale `.git` on the build host can't mislead it.
  - `build.rs` now notices new commits on a branch.
  - It marks a build `-dirty` only for modified tracked files.
- **`rand-node db drop-receipts-index`** is the rollback step described above.
- **Startup takes minutes, not seconds.** A node's RPC opens after its quick chain
  verification, about 4 minutes at chain 12's ~59 000 blocks. This is unchanged behaviour, but
  worth knowing when you watch a rolling update.

---

### 📚 Docs

- [`docs/rpc.md`](docs/rpc.md): a section per new method and topic, plus the v0.3 changelog
  entry.
- [`docs/rpc-comparison.md`](docs/rpc-comparison.md): the Ethereum / Solana / RAND table,
  refreshed, and a new section "What v0.3 closed".
- [`docs/superpowers/specs/2026-09-18-rpc-v0.3-design.md`](docs/superpowers/specs/2026-09-18-rpc-v0.3-design.md):
  the design and a record of every decision changed during implementation.
- `deploy/README.md`: "Rolling back v0.3".

---

### ⚠️ Known issues

- `rand_getVersion`'s `version` field reports the workspace crate version, which still reads
  `0.1.0`. Use `git_sha` to identify a build. The crate version will be bumped with the next
  binary change.
- `main.rs`'s `the_genesis_hash_is_pinned` test fails on this commit and on the commit before
  it. The failure predates this release and does not touch chain 12's genesis.

---

### 🙅 Deliberately not in v0.3

These gaps are by design, because RAND's state is shielded. They are not planned.

- `eth_call` / `simulateTransaction`: execution and proving happen in the wallet.
- `eth_getBalance` / `getAccountInfo` / `getProgramAccounts`: there are no readable accounts.
- `debug_traceTransaction`: the node never sees a call's private inputs.
- `rand_feeHistory`: it arrives with the fee-ordered mempool.

---

### 🛫 Upgrading

It is a drop-in binary swap on chain 12. There is no genesis change and no resync.

```bash
deploy/rebuild-vps.sh <build-host>        # build once
deploy/update-droplet.sh <ip>             # per node, one at a time; idempotent
```

The testnet fleet (16 DigitalOcean droplets plus the laptop validator) was rolled one node at a
time with the chain producing blocks throughout.

---

### 📊 By the numbers

| | |
|---|---|
| Commits | 28 |
| Files changed | 20 (+3 904 / −178 lines) |
| New tests | 30 |
| New RPC methods | 11 |
| New WebSocket topics | 2 |
| Review fix rounds before release | 6 (5 per-task + 1 whole-branch) |

**What's next:** v0.4 is the guest toolchain (`rand-guest`, Rust and C to RV32IM) and the
sBPF → RV32 and EVM → RV32 transpilers.
---

## v0.2 — 2026-09-17 (chain 11, reverted the same day)

Short shielded addresses: a receiver id plus a verifiable receiver record. Reverted at
`17db41d` because a sender cannot seal a note to a hash and an empty wallet cannot register;
chain 12 returned to the long ML-KEM address. See `AGENTS.md`.

## v0.1 — 2026-09-16

The first tagged full node: HotStuff BFT, the shielded pool, staking, the bridge, confidential
programs on the zkVM, block aggregation, and the pre-v0.1 security review's fixes.

