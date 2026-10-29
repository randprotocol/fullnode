#!/usr/bin/env bash
# Cut the chain-22 genesis: chain 21's shape and value, cut from a snapshot of chain 21, on a build
# that knows audit v10/v11's genesis-gated rules (v0.8.2, 299378d0, or later: the audit/v10-node
# and audit/v10-perps merges d7358e90 / 81b9a2c0), with those rules switched on — the fields that
# close randprotocol/monorepo#12 (PERP-101), #13 (PERP-6) and #15 (PST-1) at the cut
# (CHANGELOG.md v0.8.2; docs/deploy.md, "The next cut: chain 22 (audit v11 gated fields)"):
#   - `program_state.refuse_panics: true` (PST-1, docs/program-state.md:136): an Invoke whose call
#     proof publishes guest-sdk's panic sentinel (0xdeadbeef in output 7) is invalid;
#   - `perps.bound_payouts: true` (PERP-6, docs/perps.md:62): a state proof may not pay out more
#     collateral than `initial_collateral + collateral_in − collateral_out`; `initial_collateral`
#     ABSENT (0, docs/perps.md:63) — the engine starts from `perp-prover genesis-state`, a fresh
#     state holding nothing (see OPEN 4: chain 21's exchange is NOT carried);
#   - `perps.sparse_windows: true` + `perps.max_window_heights` (PERP-101, docs/perps.md:64,66):
#     input-less blocks record no digest, a window spans at most max_window_heights heights —
#     max_window_heights is an OPERATOR INPUT (OPEN 1);
#   - `perps.engine_program_log_height` (CON-60, docs/perps.md:65): the pinned engine's program
#     height, DERIVED like engine_hc (`rand perp image-hc` prints it on stderr) and pinned here as
#     EXPECT_ENGINE_PROGRAM_LOG_HEIGHT 14 (the pinned image f286a611…, read 2026-10-29 with v0.8.2);
#   - `multisig.max_accounts` (MSA-4, docs/multisig.md:60) — an OPERATOR INPUT (OPEN 2);
#   - `tokens.incremental_root: true` (audit v6 TOK-1, docs/deploy.md "The next cut:
#     `tokens.incremental_root`": "Recommended: on, for the next cut"; chain 21 did not carry it and
#     no record says why — the user's standing rule takes the recommended value; striking it is one
#     constant, TOKENS_INCREMENTAL_ROOT, here and in docs/deploy.md together).
#
#   deploy/cut-chain22-genesis.sh snapshot <dir>     # chain 21 still up, bridge daemons stopped
#   WALLET=<chain 21's rand, v0.8.2> deploy/cut-chain22-genesis.sh balances <dir>
#                                                    # read-only toward the chain: the RAND carry list
#   CUT_RECORD=<record> CHAIN21_SNAPSHOT=<dir> NODE=<the cut build's rand-node> WALLET=<its rand> \
#     EXPECT_NODE_VERSION=<that release> PERP_PROVER=<durian's perp-prover> \
#     PERPS_MAX_WINDOW_HEIGHTS=<64..4096> MULTISIG_MAX_ACCOUNTS=<n ≥ 1> \
#     [PERP_IMAGE=<perp-engine.image.bin>] [TREASURY=<treasury.txt>] \
#     [MULTISIG_NOT_CARRIED_OK=1] [PERPS_STATE_NOT_CARRIED_OK=1] [PROGRAM_VAULTS_DROPPED_OK=1] \
#     deploy/cut-chain22-genesis.sh                  # the cut
#   NODE=<the cut build's rand-node> deploy/cut-chain22-genesis.sh check-limits <rpc url> <genesis file>
#                                                    # after launch: what the first node serves
#                                                    # (base_fees_burned "0" — BASE_FEES_BURNED_ANY=1
#                                                    # after the first bundle — and perps proved_height
#                                                    # 0, no accounts, collateral counters "0": run it
#                                                    # before the first deposit and state proof)
#   SELFTEST=1 deploy/cut-chain22-genesis.sh         # no network, no binaries: the assembly on fixtures
#   DRY_RUN=1 NODE=… WALLET=… PERP_PROVER=… RAND_MSAUTH_VK=<msauth-vk-production.bin> \
#     MULTISIG_NOT_CARRIED_OK=1 deploy/cut-chain22-genesis.sh
#                                                    # no network: the REAL cut path (rand-node genesis,
#                                                    # alloc-note, perp-prover genesis-state, init, a
#                                                    # loopback probe node) on inputs synthesised from
#                                                    # the committed chain-21 genesis — its treasury
#                                                    # holding its genesis balance, so the dry run, like
#                                                    # the cut, refuses without MULTISIG_NOT_CARRIED_OK=1;
#                                                    # without a TREASURY file it uses chain 21's genesis
#                                                    # signers (public keys) at chain 21's 100 000 RAND;
#                                                    # without PERPS_MAX_WINDOW_HEIGHTS /
#                                                    # MULTISIG_MAX_ACCOUNTS it uses each field's lower
#                                                    # bound (64; 1), LOUDLY, as PLACEHOLDERS
#
# OPEN — owner decision before the cut (the real cut refuses until each is given; nothing below is
# a recommendation — the docs give none):
#   1. perps.max_window_heights (PERP-101). No documented value. The range is max_window_blocks
#      (64) ..= MAX_WINDOW_HEIGHTS (4096) (docs/perps.md:66, PerpsConfig::check); the documented
#      default, 0, is refused beside sparse_windows. It is the most heights one state proof spans
#      AND the heartbeat interval (an input-less close is recorded every max_window_heights
#      heights, so funding, marks and liquidations run at least that often), and back-pressure
#      holds new orders at 4 × it past the proved height (docs/perps.md "Sparse windows"). The
#      v11 perps report leaves it to the owner ("choose max_window_heights for chain 22").
#      Input: PERPS_MAX_WINDOW_HEIGHTS, no default.
#   2. multisig.max_accounts (MSA-4). No documented value; the documented default is ABSENT
#      (unbounded — chain 21's rule, which would not close MSA-4). It counts the seeded treasury,
#      so it is ≥ 1; `CreateMultisig` past it is refused for good (docs/multisig.md:60).
#      Input: MULTISIG_MAX_ACCOUNTS, no default.
#   3. The treasury (chain 21's 2-of-3 multisig account d5fd1883…1958, seeded with 100 000 RAND
#      NEW ISSUANCE at chain 21's cut). No document says how a multisig account crosses a cut: the
#      register is genesis state, the treasury's vault is not a note, so `balances` never sees it
#      and nothing re-creates it. This script does what chain 21's did — seeds ONE treasury from
#      TREASURY (default ~/.rand-chain22/treasury.txt) as NEW ISSUANCE, signers asserted equal to
#      chain 21's (in order; TREASURY_ROTATED=1 carries a live rotation, TREASURY_SIGNERS_CHANGED=1
#      knowingly other keys), threshold 2, a fresh salt (so a new id) — and REFUSES while chain 21's
#      register holds any RAND (rand_getSupply.multisig_rand_held > 0: the treasury's vault, and
#      any account created on chain 21) unless MULTISIG_NOT_CARRIED_OK=1, which drops it (the cut
#      record's `drops:` must then name the treasury/multisig). The chain-22 BALANCE (re-issue
#      chain 21's 100 000, the vault's live balance, or another amount) is the owner's: TREASURY's
#      `balance` line, printed beside chain 21's issued and live figures.
#   4. Chain 21's perps exchange (accounts, positions, collateral, pending withdrawals). No carry
#      rule exists: the engine state is proved off chain and chain 22's engine starts from
#      `perp-prover genesis-state` over the market list (the same root as chain 21's genesis,
#      da0e3a53…). The cut REFUSES while chain 21's exchange is not empty (rand_getPerps.accounts,
#      pending_withdrawals, or the collateral counters — which count only since each node's
#      v0.8.2 roll, so `accounts` is the reliable one) unless PERPS_STATE_NOT_CARRIED_OK=1 (the
#      cut record's `drops:` must then name perps). `initial_collateral` stays absent (0): it is
#      only for a seeded engine, and no seeding is designed.
#   5. zUSD inside the exchange (and in any multisig vault). A token's total supply does not move
#      on a perp deposit (docs/perps.md "The supply audit"), so chain 21's zUSD supply still equals
#      Σ locked, and the carry rule still demands Σ ZUSD_CARRY == Σ locked == custody: zUSD held by
#      the exchange is in no wallet, and the operator must say, line by line in ZUSD_CARRY, whose
#      note re-issues it (the depositors at their engine balances, or another holder). `balances`
#      prints the operator wallets' zUSD beside Σ ZUSD_CARRY; the cut refuses any other total.
#   6. NOT carried, documented default off, no recommendation: `incremental_nullifier_root` (the
#      hot path's nullifier MMR; docs/compute-optimization.md §3.1 says such changes "ride the next
#      genesis-gated cut" but no page recommends it for one), `staking.slashing` (recommended only
#      once stake is held by more than one operator, docs/deploy.md D8 — still one), and the
#      aggregation-only fields (`aggregation`, `fees.subsidy_net_of_fees`, `proposer_share_bps`,
#      `prove_base`, `usd_subsidy`: deferred until aggregation is admitted). Each is refused here as
#      chain 21 refused it.
#   7. EXPECT_NODE_VERSION has no default: v0.8.2 is the first release with every field above;
#      v0.8.3 (rc1 9443de63, main 97bcf4b1) is untagged. Set it to the release the cut runs.
#
# Known gap (not a decision): no RPC serves `program_state.refuse_panics` (rand_getLimits'
# program_state object is cell_fee/max_reads/max_writes/max_payouts). `check-limits` therefore
# reads it back through the genesis hash alone — the node must serve the hash `init` derives from
# the file, and the field probe proved that hash moves without the field. Serving it is a node
# follow-up.
#
# DERIVED from deploy/cut-chain21-genesis.sh (chain 21 — v0.8.0, live since 2026-10-12 10:31 UTC,
# genesis ca76c276…ca9a, running v0.8.2 since 2026-10-28): the same snapshot / balances / carry-over
# rule / splice, with chain 21 as the source. Read it first. What this script does that chain 21's
# did not:
#
#   * THE NEW FIELDS above, each written by the build (a flag) or the cut (a section file),
#     asserted on the finished file, proved part of the genesis hash by this rand-node (the cut
#     re-derives the hash without each and refuses if it does not move: 7 variants —
#     program_state.refuse_panics, perps.bound_payouts, perps.sparse_windows (with
#     max_window_heights, which is refused alone), perps.max_window_heights at another value,
#     perps.engine_program_log_height, multisig.max_accounts, tokens.incremental_root), and read
#     back from the first node after launch (`check-limits`: rand_getPerps' bound_payouts,
#     initial_collateral, sparse_windows, max_window_heights, engine_program_log_height and the
#     collateral counters; rand_getLimits.multisig.max_accounts; rand_getTokens.incremental_root;
#     refuse_panics through the hash, above).
#       - refuse_panics: `rand-node genesis --program-state-refuse-panics` (v0.8.2, d3a1eb46).
#       - max_accounts: a field of the `--multisig` file this script writes.
#       - the perps fields: in the perps section file this script splices (as chain 21's).
#       - incremental_root: `rand-node genesis --tokens-incremental-root` (v0.6.9 on).
#       - Every one of them ships in v0.8.2, and a build before it refuses each section that
#         carries one (`deny_unknown_fields` on PerpsConfig, MultisigConfig, ProgramStateConfig),
#         so ONE gate decides them: `rand-node genesis --help` lists --program-state-refuse-panics
#         and `rand perp image-hc` prints `engine_program_log_height`. The real cut REFUSES a build
#         without them; DRY_RUN skips all of them, LOUDLY (AUDIT_V10_SKIPPED), as chain 21's did
#         its sections.
#   * CHAIN 21'S STATE THAT CHAIN 21'S SCRIPT NEVER HAD TO CARRY, read by `snapshot` and refused
#     at the cut unless the operator says otherwise (OPEN 3–5): the multisig register's RAND
#     (MULTISIG_NOT_CARRIED_OK), the perps exchange (PERPS_STATE_NOT_CARRIED_OK), and RPL-2 program
#     vaults' RAND (rand_getSupply.program_rand_held — chain 21's record dropped "the programs'
#     state", but its script never counted it; PROGRAM_VAULTS_DROPPED_OK). Each, when set, must be
#     named on the cut record's `drops:` line.
#   * EVERYTHING ELSE IS CHAIN 21'S, ASSERTED EQUAL: what chain 21's script switched on — `fees`
#     {burn_base, burn_floor}; `perps` (BTC-PERP on zUSD, the pinned engine f286a611…, tier 18, 24
#     inputs, 64 blocks, min deposit 1 zUSD — and its genesis_root, re-derived by perp-prover, must
#     equal chain 21's da0e3a53…); `multisig` create_fee 1 RAND and one treasury, 2 of 3;
#     hc_auth_multisig 9705f8e2… (the file's last field) with 6 MiB proofs and 19 MiB blocks (still
#     pending the measured production msauth proof, MSA-1/2); and chain 20's shape before it
#     (testnet, binding_domain 1, proof_window_blocks 1024, the gas section with ceilings and the
#     paying byte load, bridge.rotation, bridge.fees 10/10 bps to the fingerprinted recipient,
#     staking's 2500-bps budget and admission by vote, program_state cell_fee 10000000) — each still
#     asserted at its value, and the finished file compared field by field with
#     deploy/genesis-chain21.json (the new fields excused, each asserted on its own).
#   * THE BRIDGE IS CHAIN 21'S, NOT RE-DEPLOYED: EMITTER_2..5 default to chain 21's genesis
#     `bridge.emitters` (the 2026-09-30 endpoints chain 20 also trusted), checked against
#     deploy/genesis-chain21.json, refused otherwise unless EMITTERS_CHANGED=1; the 2026-09-19
#     endpoints are refused outright. Floors as chain 21's: `auto` = each endpoint's next sequence
#     at the snapshot, never below chain 21's own (2:3 3:5 4:3 5:7); burn sequence chain 21's live.
#   * OPS-7 as chain 21's: `refuse_reused_chain_id`, `require_cut_record`, and the record must name
#     the treasury and each issue the cut closes (PST-1, PERP-6, PERP-101 on `reason:` or
#     `carries:`). No deploy/cutover-fleet-chain22.sh exists yet: derive it from chain 21's.
#   * NODE must report rand-node $EXPECT_NODE_VERSION (no default, OPEN 7). `balances` runs with
#     chain 21's own build, v0.8.2 (WALLET).
#
# The inputs outside the repository (chain 21's, re-pointed at ~/.rand-chain22 where the cut writes):
#   PERP_IMAGE / EXPECT_ENGINE_HC / PERP_PROVER   as chain 21's (f286a611…; durian.market's perp-prover,
#                     built from the commit that pinned the image or later: state layout version 2).
#   TREASURY          default ~/.rand-chain22/treasury.txt, chain 21's format: `signer <name> <2624
#                     hex>` × 3 in order, `threshold 2`, `balance <RAND>` (OPEN 3). Public keys only.
#   FEE_RECIPIENT_FILE  default ~/.rand-chain20/fee-recipient-address.txt — chain 20's and chain
#                     21's recipient, fingerprint 89DS-4Q4X-HXSX-MBYW (it never moved).
#
# Operations (not checked here; the cut record's `clients:` and the launch checklist): as chain
# 21's (NTP, msauth-vk-production.bin beside every rand-node, a perp-view service and a prover
# host) plus: durian.market's perp-prover must build SPARSE jobs on chain 22 (durian 28cebfb walks
# pending_heights within max_window_heights) and `rand perp prove` proves at the canonical shape by
# default once the engine pin is set (tier = max_tier 18: the prover host must fit a tier-18 proof);
# a validator with less than 8 GB should not run a max_tier-18 perps chain (docs/perps.md, CON-60).
#
# Traps carried from the chain-17 to 21 cuts (AGENTS.md):
#   - `balances` scans CURATED directories of wallet key files, `$WALLETS_DIRS` =
#     ~/.rand-chain17/alloc-wallets (symlinks: shielded-1..5 and the relayer →
#     ~/.rand-chain14/wallets/relayer.key.json; that link went missing once and the scan then listed
#     its alloc as "uncovered"), ~/.rand-chain18/wallets, ~/.rand-chain19/wallets,
#     ~/.rand-chain20/wallets and ~/.rand-chain21/wallets. Never a checkout's `wallets/`. CHECK
#     BEFORE THE SCAN that every wallet holding RAND on chain 21 has its key file (or a symlink) in
#     one of them; the scan also lists chain 21's genesis allocs that no scanned wallet covers, and
#     the cut refuses while that list is non-empty.
#   - `balances` refuses to overwrite <dir>/balances.json and $ALLOC_ADDRESSES: move a first scan
#     aside to re-scan.
#   - The public RPC (Cloudflare) answers Python's urllib with 403: point CHAIN21_RPC at an SSH
#     tunnel to an archive's RPC (`prune_floor` 0), e.g.
#     `ssh -N -L 8545:127.0.0.1:8545 root@203.0.113.29` → CHAIN21_RPC=http://127.0.0.1:8545.
#     The tunnel died twice in the hour of the chain-18 cut (once silently); this script refuses
#     to start `snapshot` or `balances` on a dead one — re-open it and re-run.
#   - Take the snapshot with the SAME EMITTER_* the cut uses (the defaults): custody and sequences
#     are read at those addresses, and the cut refuses a snapshot read anywhere else.
#   - `rand-node genesis` writes no bridge section: the hash that matters is the one `rand-node
#     init` prints on the FINISHED file (this script's last lines), never the base file's.
#
# The carry-over rule (chain 21's, unchanged): zUSD per-backing `locked` = chain 21's at the
# snapshot with one fresh genesis note per $ZUSD_CARRY line (Σ notes == Σ locked == source custody);
# RAND = one genesis note per operator wallet the `balances` scan found holding RAND, at its
# chain-21 balance (Σ alloc == Σ scanned); a validator's unwithdrawn rewards are refused unless
# REWARDS_DROPPED_OK=1 (never carried); pending notes refused unless PENDING_OK=1; uncovered
# chain-21 genesis allocs refused unless UNCOVERED_ALLOCS_OK=1; tokens other than zUSD refused
# unless ALLOW_DROPPED_TOKENS=1. SHIELDED NOTES OF WALLETS THE OPERATOR DOES NOT HOLD ARE NOT
# CARRIED — the cut record's `drops:` line must say so. The treasury is new issuance beside the
# carry, never inside it (OPEN 3).
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash (fresh note randomness, a
# fresh treasury salt and a fresh timestamp). Cut once, distribute the file byte-identically,
# launch within minutes.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091  # sourced from the repo root (the cd above); run shellcheck -x to follow
. deploy/lib/key-guard.sh
# shellcheck disable=SC1091
. deploy/lib/cut-policy.sh

NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
CHAIN_ID=${CHAIN_ID:-22}
OUT=${OUT:-deploy/genesis-chain22.json}
CUT_RECORD=${CUT_RECORD:-$HOME/.rand-chain22/cut-record.txt}   # deploy/cut-record.template, filled in and published before the cut
EXPECT_NODE_VERSION=${EXPECT_NODE_VERSION:-}                  # no default (OPEN 7): v0.8.2 is the first release with the audit-v10 fields; v0.8.3 is untagged
CHAIN21_GENESIS=${CHAIN21_GENESIS:-deploy/genesis-chain21.json}
CHAIN21_HASH=${CHAIN21_HASH:-ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a}
CHAIN21_GENESIS_SHA256=${CHAIN21_GENESIS_SHA256:-88d42b38b76338e6d47d9486e8afd25eb651ec9f69f474aa80bc0aceee028ca1}
# chain 21's treasury, deploy/cut-records/chain21.record `treasury-id:` (re-derived from the committed
# genesis by NODE at the cut, and read live by `snapshot`)
CHAIN21_TREASURY_ID=${CHAIN21_TREASURY_ID:-d5fd188308af5322b234b199ae6193fa686ae1453e6af39720638b1f441b1958}
CHAIN21_RPC=${CHAIN21_RPC:-http://127.0.0.1:8545}          # snapshot/balances: an SSH tunnel to an archive's RPC (Cloudflare 403s urllib)
CHAIN21_SNAPSHOT=${CHAIN21_SNAPSHOT:-}                       # the cut: the snapshot directory

# ── public inputs, all outside the repository ─────────────────────────────────────────────────
VALIDATORS_TSV=${VALIDATORS_TSV:-$HOME/.rand-chain14/public/validators.tsv}   # name addr pk peer payout (18)
REGISTRATIONS=${REGISTRATIONS:-$HOME/.rand-chain15/registrations}              # <name>.txt, one per bonded validator (8)
BONDED=${BONDED:-obs1 archive2 g1 g2 g3 g4 g5 g6}
GENESIS_NAMES=${GENESIS_NAMES:-a b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1}
FAUCET_MINTERS=${FAUCET_MINTERS:-$GENESIS_NAMES}   # chain 21's list; another one needs FAUCET_MINTERS_CHANGED=1
FAUCET_RECIPIENTS=${FAUCET_RECIPIENTS:-}           # unset: chain 21's genesis allowlist; a file ("<name> rand1…") changes it
STAKE_RAND=${STAKE_RAND:-1000}
ALLOC_ADDRESSES=${ALLOC_ADDRESSES:-$HOME/.rand-chain22/alloc-rand.txt}   # "<label> rand1… <RAND>" per line (`balances` writes it)
ZUSD_CARRY=${ZUSD_CARRY:-$HOME/.rand-chain22/zusd-carry.txt}             # "<label> rand1… <zUSD>" per line
WALLETS_DIRS=${WALLETS_DIRS:-$HOME/.rand-chain17/alloc-wallets $HOME/.rand-chain18/wallets $HOME/.rand-chain19/wallets $HOME/.rand-chain20/wallets $HOME/.rand-chain21/wallets}   # `balances`: dirs of *.key.json (a missing dir is skipped, printed); never a checkout's wallets/
REQUIRED_WALLETS=${REQUIRED_WALLETS:-relayer}      # `balances`: <name>.key.json that must be under WALLETS_DIRS before the scan (the relayer's link went missing once)
BALANCES_RESCAN=${BALANCES_RESCAN:-1}              # `balances`: `rand sync --rescan` (from leaf 0) — never trust a laptop note store
RELAYER_DONE_DIR=${RELAYER_DONE_DIR:-}             # optional: a copy of the relayer's done/ (done/<chain>/<seq>; the relayer runs on rand-relayer-1), a floor cross-check
EXPECT_HC_BUNDLE=${EXPECT_HC_BUNDLE:-60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce}   # bundle guest v3, chain 21's
EXPECT_HC_AUTH=${EXPECT_HC_AUTH:-1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1}     # the auth guest, chain 21's
# private multisig's auth guest (MSAUTH_HC), chain 21's hc_auth_multisig: `rand-node genesis
# --auth-multisig-guest` writes the build's own; any other expected value is refused below.
HC_AUTH_MULTISIG_DECIDED=9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247
EXPECT_HC_AUTH_MULTISIG=${EXPECT_HC_AUTH_MULTISIG:-$HC_AUTH_MULTISIG_DECIDED}

# ── the limits: chain 21's, asserted equal to its genesis unless LIMITS_CHANGED=1: 6 MiB proofs and
# 19 MiB blocks (3 · 6 MiB + 1 MiB, the three-proof Call rule), chosen at chain 21 for private
# multisig and still PENDING the measured production msauth proof size (MSA-1/2: no tier-18 auth
# proof has been completed); a measurement re-decides them, here and in docs/deploy.md together.
# GAS_DYNAMIC's byte target is half the block, 9961472, chain 21's.
MAX_PROGRAM_WORDS=${MAX_PROGRAM_WORDS:-65535}
MAX_PROOF_BYTES=${MAX_PROOF_BYTES:-6291456}
MAX_BLOCK_BYTES=${MAX_BLOCK_BYTES:-19922944}
MAX_CALL_ENVELOPE_BYTES=${MAX_CALL_ENVELOPE_BYTES:-65536}
MAX_PROGRAM_PUBLIC_WORDS=${MAX_PROGRAM_PUBLIC_WORDS:-32768}
EPOCH_BLOCKS=${EPOCH_BLOCKS:-1000}

# ── the source endpoints chain 21 trusts (its genesis `bridge.emitters`): chain 22 keeps them ───
C21_EMITTER_2=0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa   # Ethereum  0x7aF6b17047C1db6cB54347FdEa45cF9179075bfA (2026-09-30)
C21_EMITTER_3=0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa   # BNB Chain 0x7aF6b17047C1db6cB54347FdEa45cF9179075bfA (2026-09-30)
C21_EMITTER_4=0000000000000000000000006410797df959987a5baf65b5fab97edeb34d5163   # Tron      TK6JJv55CCkFjNHq7WwoU91GKaZEiC93me (2026-09-30)
C21_EMITTER_5=d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a   # Solana, never redeployed
# The 2026-09-19 endpoints chains 14–18 trusted: never again (their old locks would replay).
OLD_EMITTERS="000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892 0000000000000000000000000992df85dcce77ded2c0387f1fa9cf98ac859700"
EMITTER_2=${EMITTER_2:-$C21_EMITTER_2}
EMITTER_3=${EMITTER_3:-$C21_EMITTER_3}
EMITTER_4=${EMITTER_4:-$C21_EMITTER_4}
EMITTER_5=${EMITTER_5:-$C21_EMITTER_5}
for c in 2 3 4 5; do
  e=EMITTER_$c; o=C21_EMITTER_$c
  case " $OLD_EMITTERS " in *" ${!e} "*)
    echo "cut-chain22: EMITTER_$c=${!e} is a 2026-09-19 endpoint chains 14–18 trusted — never again (EMITTERS_CHANGED does not override this)" >&2; exit 1;; esac
  [ "${!e}" = "${!o}" ] || [ "${EMITTERS_CHANGED:-}" = 1 ] || {
    echo "cut-chain22: EMITTER_$c=${!e} is not chain 21's endpoint ${!o} — set EMITTERS_CHANGED=1 only for a knowingly new endpoint" >&2; exit 1; }
done
# Replay floors: MIN_INBOUND_<c> (env) or MIN_INBOUND_FILE ("<chain> <floor>" per line), else `auto`.
if [ -n "${MIN_INBOUND_FILE:-}" ]; then
  [ -f "$MIN_INBOUND_FILE" ] || { echo "cut-chain22: MIN_INBOUND_FILE=$MIN_INBOUND_FILE is not a file" >&2; exit 1; }
  while read -r fc fv rest; do
    case "$fc" in ''|'#'*) continue;; 2|3|4|5) ;; *) echo "cut-chain22: $MIN_INBOUND_FILE: '$fc $fv' — the chain must be 2, 3, 4 or 5" >&2; exit 1;; esac
    [ -z "$rest" ] && [[ "$fv" =~ ^[0-9]+$ ]] || { echo "cut-chain22: $MIN_INBOUND_FILE: '$fc $fv $rest' is not \"<chain> <floor>\"" >&2; exit 1; }
    v=MIN_INBOUND_$fc
    [ -z "${!v:-}" ] || { echo "cut-chain22: chain $fc's floor is given twice (MIN_INBOUND_$fc=${!v} and $MIN_INBOUND_FILE) — one source per chain" >&2; exit 1; }
    printf -v "$v" '%s' "$fv"
  done < "$MIN_INBOUND_FILE"
fi
for c in 2 3 4 5; do
  v=MIN_INBOUND_$c
  [ -n "${!v:-}" ] || printf -v "$v" auto
  case "${!v}" in
    auto) ;;
    none) echo "cut-chain22: MIN_INBOUND_$c=none — every chain-22 endpoint was minted from on chain 21; its old locks would replay" >&2; exit 1;;
    *) [[ "${!v}" =~ ^[0-9]+$ ]] || { echo "cut-chain22: MIN_INBOUND_$c=${!v}: a sequence or \`auto\`" >&2; exit 1; }
       if [ "$c" != 5 ] && [ "${!v}" -lt 1 ]; then
         echo "cut-chain22: MIN_INBOUND_$c=${!v} is below 1 — sequence 0 of the redeployed chain-$c endpoint is the operator's consume-step lock and must never mint" >&2; exit 1; fi
       [ "${!v}" -ge 1 ] || { echo "cut-chain22: MIN_INBOUND_$c=0 is no floor" >&2; exit 1; };;
  esac
done
# What the cut is expected to derive: chain 21's genesis floors and burn sequence, if nothing moved
# on chain 21 (a live bridge legitimately moves them — compared and warned about, never refused).
EXPECT_FLOORS=${EXPECT_FLOORS:-2:3 3:5 4:3 5:7}
EXPECT_BURN_SEQUENCE=${EXPECT_BURN_SEQUENCE:-14}
ETH_RPC=${ETH_RPC:-https://ethereum-rpc.publicnode.com}
BSC_RPC=${BSC_RPC:-https://bsc-rpc.publicnode.com}
TRON_API=${TRON_API:-https://api.trongrid.io}
SOL_RPC=${SOL_RPC:-https://api.mainnet-beta.solana.com}
SOL_PROGRAM=${SOL_PROGRAM:-FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu}

# ── gas: chain 21's section (its POOL-2 ceilings and paying byte load included), asserted equal ─
GAS_PRICE=${GAS_PRICE:-100}
BYTE_PRICE=${BYTE_PRICE:-800}
BUNDLE_GAS_LIMIT=${BUNDLE_GAS_LIMIT:-20479}                  # gas_max(14, 0, 0), every bundle proof's declared limit
GAS_DYNAMIC=${GAS_DYNAMIC:-$((MAX_BLOCK_BYTES / 2)),262144,1250}
MAX_GAS_PRICE=${MAX_GAS_PRICE:-10000}                        # 100× the start (docs/deploy.md, POOL-2)
MAX_BYTE_PRICE=${MAX_BYTE_PRICE:-80000}                      # 100× the start
GAS_BYTE_LOAD=${GAS_BYTE_LOAD:-paying}
ENVELOPE_BYTES=${ENVELOPE_BYTES:-1860}
# ── chain 21's audit-v6 / RPL-2 genesis fields, carried at chain 21's values and asserted equal ──
BINDING_DOMAIN=${BINDING_DOMAIN:-1}
PROOF_WINDOW_BLOCKS=${PROOF_WINDOW_BLOCKS:-1024}
STAKE_ENTRY_BPS=${STAKE_ENTRY_BPS:-2500}
ROTATION_DELAY_SECS=${ROTATION_DELAY_SECS:-86400}
ROTATION_NEEDS_POSSESSION=${ROTATION_NEEDS_POSSESSION:-true}
PROGRAM_STATE_CELL_FEE=${PROGRAM_STATE_CELL_FEE:-10000000}   # 0.01 RAND a created cell: docs/program-state.md, chain 21's
BRIDGE_MINT_BPS=${BRIDGE_MINT_BPS:-10}                       # chain 21's: 0.1 % each way (docs/bridge.md §25)
BRIDGE_BURN_BPS=${BRIDGE_BURN_BPS:-10}
FEE_RECIPIENT_FILE=${FEE_RECIPIENT_FILE:-$HOME/.rand-chain20/fee-recipient-address.txt}   # chain 20's and chain 21's recipient, the user's own wallet (one rand1… line)
FEE_RECIPIENT_FINGERPRINT=${FEE_RECIPIENT_FINGERPRINT:-89DS-4Q4X-HXSX-MBYW}
FEE_RECIPIENT=${FEE_RECIPIENT:-}                             # set by load_fee_recipient (the selftest sets a fixture)
# ── chain 21's `fees` section (docs/fees.md §1.3), carried and asserted equal. Not overridable. NOT
# subsidy_net_of_fees (needs aggregation, refused until it is re-measured).
# shellcheck disable=SC2089  # JSON text in a string, exported whole, never word-split
FEES_JSON='{"burn_base": true, "burn_floor": true}'
# ── chain 21's `perps` section (RPL-3; docs/perps.md "The genesis section"), carried and asserted
# equal — BTC-PERP on zUSD (asset 1, eight decimals: tick and min_deposit 10^8 are $1 and 1 zUSD),
# 20x / 250 bps, max_tier 18 with 24 inputs (durian.market's gated `block-24-14liq`), 64 blocks a
# window. engine_hc and genesis_root are not in it: the cut derives both (genesis_root must come out
# equal to chain 21's, the same markets on the same engine).
# shellcheck disable=SC2089  # JSON text in a string, exported whole, never word-split
PERPS_JSON='{"collateral_asset": 1, "max_tier": 18, "max_window_blocks": 64, "max_block_inputs": 24, "min_deposit": 100000000,
 "markets": [{"id": 0, "symbol": "BTC-PERP", "lot": 100000, "tick": 100000000, "max_leverage": 20, "maintenance_bps": 250, "taker_fee_bps": 5, "maker_fee_bps": 2}]}'
ENGINE_HC_DECIDED=f286a61171e274278ec8d18d7853e5f36799ed8dc5a3e31e0077ad89ef1d1573   # durian.market artifacts/perp-engine.image.bin.hc (afe4d31), chain 21's
EXPECT_ENGINE_HC=${EXPECT_ENGINE_HC:-$ENGINE_HC_DECIDED}   # any other value is refused below (the decision names this image)
DURIAN=${DURIAN:-$HOME/Github/randprotocol/durian.market}   # read only: the engine image
PERP_IMAGE=${PERP_IMAGE:-$DURIAN/artifacts/perp-engine.image.bin}
PERP_PROVER=${PERP_PROVER:-}                                 # durian's perp-prover: no default, the real cut refuses without it
PERP_GENESIS_ROOT=${PERP_GENESIS_ROOT:-}                     # set by the cut (perp-prover genesis-state → rand perp genesis-root); the selftest sets a fixture
# ── the NEW perps fields (audit v10/v11; docs/perps.md:62–66). Not overridable but for the one
# operator input: another rule edits this script and docs/deploy.md together.
#   - bound_payouts true (PERP-6, monorepo#13): a proof may pay out no more than the exchange holds.
#   - initial_collateral ABSENT (0): chain 22's engine starts from `perp-prover genesis-state`, which
#     holds no collateral; the field is for a seeded engine, and no seeding is designed (OPEN 4).
#   - sparse_windows true (PERP-101, monorepo#12) with max_window_heights = PERPS_MAX_WINDOW_HEIGHTS,
#     the OPERATOR'S (OPEN 1): no default; 64 (max_window_blocks) ..= 4096 (MAX_WINDOW_HEIGHTS).
#   - engine_program_log_height (CON-60): the pinned image's program height, which `rand perp image-hc`
#     prints on stderr — derived at the cut and refused unless it is EXPECT_ENGINE_PROGRAM_LOG_HEIGHT.
#     14 is what v0.8.2's `rand perp image-hc` prints for f286a611… (read 2026-10-29).
# shellcheck disable=SC2089  # JSON text in a string, exported whole, never word-split
PERPS_V10_JSON='{"bound_payouts": true, "sparse_windows": true}'
PERPS_MAX_WINDOW_HEIGHTS=${PERPS_MAX_WINDOW_HEIGHTS:-}       # OPEN 1: the operator's, no default (DRY_RUN/SELFTEST: 64, a PLACEHOLDER)
ENGINE_PROGRAM_LOG_HEIGHT_DECIDED=14
EXPECT_ENGINE_PROGRAM_LOG_HEIGHT=${EXPECT_ENGINE_PROGRAM_LOG_HEIGHT:-$ENGINE_PROGRAM_LOG_HEIGHT_DECIDED}
ENGINE_PROGRAM_LOG_HEIGHT=                                   # set by the cut (`rand perp image-hc` stderr), never the environment; the selftest sets a fixture
# ── chain 21's `multisig` section (docs/multisig.md): create_fee 1 RAND, ONE account — the treasury, 2
# of 3, signers equal to chain 21's (in order), a fresh salt, its balance NEW ISSUANCE from TREASURY
# (OPEN 3) — plus the NEW max_accounts (MSA-4) = MULTISIG_MAX_ACCOUNTS, the OPERATOR'S (OPEN 2): no
# default; ≥ 1, the seeded treasury included.
MULTISIG_CREATE_FEE=1000000000
TREASURY_THRESHOLD=2
TREASURY_SIGNERS=3
TREASURY=${TREASURY:-$HOME/.rand-chain22/treasury.txt}
MULTISIG_MAX_ACCOUNTS=${MULTISIG_MAX_ACCOUNTS:-}             # OPEN 2: the operator's, no default (DRY_RUN/SELFTEST: 1, a PLACEHOLDER)
# ── chain 21's `program_state` (cell_fee 10000000) plus the NEW refuse_panics (PST-1, monorepo#15),
# written by `rand-node genesis --program-state-refuse-panics`. Not overridable.
PROGRAM_STATE_REFUSE_PANICS=true
# ── the NEW tokens switch: incremental_root (audit v6 TOK-1; docs/deploy.md "Recommended: on, for the
# next cut"), written by `rand-node genesis --tokens-incremental-root`. Not overridable.
TOKENS_INCREMENTAL_ROOT=true
# PERPS_SKIPPED (DRY_RUN without PERP_PROVER) and AUDIT_V10_SKIPPED (DRY_RUN on a build without the
# audit-v10 fields): the script's own words, never the operator's — whatever the environment says
# is captured and cleared here; the real cut refuses it, DRY_RUN ignores it, loudly. check-limits
# reads skipped-ness from the genesis file.
# shellcheck disable=SC2034  # read through ${!v} (the *_SKIPPED_FROM_ENV loop at the cut)
PERPS_SKIPPED_FROM_ENV=${PERPS_SKIPPED:-}
PERPS_SKIPPED=
# shellcheck disable=SC2034  # likewise
AUDIT_V10_SKIPPED_FROM_ENV=${AUDIT_V10_SKIPPED:-}
AUDIT_V10_SKIPPED=
[ "$EXPECT_HC_AUTH_MULTISIG" = "$HC_AUTH_MULTISIG_DECIDED" ] || {
  echo "cut-chain22: EXPECT_HC_AUTH_MULTISIG=$EXPECT_HC_AUTH_MULTISIG is not chain 21's multisig auth guest ($HC_AUTH_MULTISIG_DECIDED, MSAUTH_HC) — another guest edits this script and docs/deploy.md together" >&2; exit 1; }
[ "$EXPECT_ENGINE_HC" = "$ENGINE_HC_DECIDED" ] || {
  echo "cut-chain22: EXPECT_ENGINE_HC=$EXPECT_ENGINE_HC is not the decided engine ($ENGINE_HC_DECIDED, durian.market's pinned image) — another engine edits this script and docs/deploy.md together" >&2; exit 1; }
[ "$EXPECT_ENGINE_PROGRAM_LOG_HEIGHT" = "$ENGINE_PROGRAM_LOG_HEIGHT_DECIDED" ] || {
  echo "cut-chain22: EXPECT_ENGINE_PROGRAM_LOG_HEIGHT=$EXPECT_ENGINE_PROGRAM_LOG_HEIGHT is not the pinned engine's program height ($ENGINE_PROGRAM_LOG_HEIGHT_DECIDED) — another engine edits this script and docs/deploy.md together" >&2; exit 1; }
# The two operator inputs, when given, are checked here (absent, the real cut refuses later, at the gates).
if [ -n "$PERPS_MAX_WINDOW_HEIGHTS" ]; then
  [[ $PERPS_MAX_WINDOW_HEIGHTS =~ ^[0-9]+$ ]] && [ "$PERPS_MAX_WINDOW_HEIGHTS" -ge 64 ] && [ "$PERPS_MAX_WINDOW_HEIGHTS" -le 4096 ] || {
    echo "cut-chain22: PERPS_MAX_WINDOW_HEIGHTS=$PERPS_MAX_WINDOW_HEIGHTS is outside max_window_blocks..=MAX_WINDOW_HEIGHTS (64..=4096)" >&2; exit 1; }
fi
if [ -n "$MULTISIG_MAX_ACCOUNTS" ]; then
  [[ $MULTISIG_MAX_ACCOUNTS =~ ^[0-9]+$ ]] && [ "$MULTISIG_MAX_ACCOUNTS" -ge 1 ] && [ "${#MULTISIG_MAX_ACCOUNTS}" -le 18 ] || {
    echo "cut-chain22: MULTISIG_MAX_ACCOUNTS=$MULTISIG_MAX_ACCOUNTS is not a count ≥ 1 (the seeded treasury counts)" >&2; exit 1; }
fi

# shellcheck disable=SC2090
export CHAIN_ID CHAIN21_GENESIS CHAIN21_HASH CHAIN21_GENESIS_SHA256 CHAIN21_TREASURY_ID CHAIN21_RPC VALIDATORS_TSV REGISTRATIONS BONDED GENESIS_NAMES \
  FAUCET_MINTERS FAUCET_RECIPIENTS STAKE_RAND ALLOC_ADDRESSES ZUSD_CARRY WALLETS_DIRS RELAYER_DONE_DIR EXPECT_HC_BUNDLE \
  EXPECT_HC_AUTH MAX_PROGRAM_WORDS MAX_PROOF_BYTES MAX_BLOCK_BYTES MAX_CALL_ENVELOPE_BYTES \
  MAX_PROGRAM_PUBLIC_WORDS EPOCH_BLOCKS EMITTER_2 EMITTER_3 EMITTER_4 EMITTER_5 C21_EMITTER_2 C21_EMITTER_3 \
  C21_EMITTER_4 C21_EMITTER_5 OLD_EMITTERS EXPECT_FLOORS EXPECT_BURN_SEQUENCE MIN_INBOUND_2 MIN_INBOUND_3 MIN_INBOUND_4 MIN_INBOUND_5 \
  ETH_RPC BSC_RPC TRON_API SOL_RPC SOL_PROGRAM GAS_PRICE BYTE_PRICE BUNDLE_GAS_LIMIT GAS_DYNAMIC MAX_GAS_PRICE MAX_BYTE_PRICE \
  GAS_BYTE_LOAD ENVELOPE_BYTES BINDING_DOMAIN PROOF_WINDOW_BLOCKS STAKE_ENTRY_BPS ROTATION_DELAY_SECS ROTATION_NEEDS_POSSESSION \
  PROGRAM_STATE_CELL_FEE BALANCES_RESCAN BRIDGE_MINT_BPS BRIDGE_BURN_BPS FEE_RECIPIENT \
  FEE_RECIPIENT_FINGERPRINT FEES_JSON PERPS_JSON ENGINE_HC_DECIDED EXPECT_ENGINE_HC PERP_GENESIS_ROOT \
  PERPS_SKIPPED PERPS_V10_JSON PERPS_MAX_WINDOW_HEIGHTS EXPECT_ENGINE_PROGRAM_LOG_HEIGHT ENGINE_PROGRAM_LOG_HEIGHT \
  MULTISIG_CREATE_FEE TREASURY_THRESHOLD TREASURY_SIGNERS TREASURY MULTISIG_MAX_ACCOUNTS \
  PROGRAM_STATE_REFUSE_PANICS TOKENS_INCREMENTAL_ROOT AUDIT_V10_SKIPPED EXPECT_HC_AUTH_MULTISIG

# Decimal RAND/zUSD text → base units, the exact rule of `parse_amount` (no float anywhere).
# shellcheck disable=SC2089,SC2090  # python source in a string, exported whole, never word-split
UNITS_PY='
def units(s, decimals=9):
    s = s.strip()
    whole, _, frac = s.partition(".")
    if len(frac) > decimals or not (whole or frac) or not (whole or "0").isdigit() or not (frac or "0").isdigit():
        raise SystemExit(f"cut-chain22: {s!r} is not an amount with at most {decimals} decimals")
    return int(whole or 0) * 10**decimals + int((frac or "").ljust(decimals, "0") or 0)
def fmt(u, decimals=9):
    w, f = divmod(u, 10**decimals)
    return f"{w}" if not f else f"{w}.{f:0{decimals}d}".rstrip("0")
def alloc_lines(path):
    rows = []
    for line in open(path):
        f = line.split()
        if not f or f[0].startswith("#"):
            continue
        if len(f) != 3 or not f[1].startswith("rand1"):
            raise SystemExit(f"cut-chain22: {path}: {line.rstrip()!r} is not \"<label> rand1… <amount>\"")
        rows.append((f[0], f[1], f[2]))
    return rows
'
# shellcheck disable=SC2090
export UNITS_PY

# The tunnel trap (chain 18, twice in one hour): before a step that reads chain 21, it answers, and
# it is chain 21 — not a dead port, not some other node.
need_chain21_rpc() {
  local got
  got=$(curl -s -m 10 -X POST "$CHAIN21_RPC" -H 'content-type: application/json' \
          -d '{"jsonrpc":"2.0","id":1,"method":"rand_getGenesisHash","params":[]}' 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("result",""))' 2>/dev/null || true)
  [ -n "$got" ] || { echo "cut-chain22: $CHAIN21_RPC is not answering — the SSH tunnel to obs1 is down? Re-open it (ssh -N -L 8545:127.0.0.1:8545 root@<obs1>) and re-run; nothing was read" >&2; exit 1; }
  [ "$got" = "$CHAIN21_HASH" ] || { echo "cut-chain22: $CHAIN21_RPC serves genesis $got, not chain 21 ($CHAIN21_HASH)" >&2; exit 1; }
  echo "cut-chain22: $CHAIN21_RPC answers as chain 21 ($(date -u +%T))"
}

# The fee recipient: one rand1… address from FEE_RECIPIENT_FILE whose fingerprint, as the WALLET
# binary computes it, is FEE_RECIPIENT_FINGERPRINT. `rand contacts add` prints an address's
# fingerprint; it runs under a throwaway --key in a temp dir (it writes only <key>.contacts.json).
load_fee_recipient() {
  local d got
  [ -f "$FEE_RECIPIENT_FILE" ] || { echo "cut-chain22: no fee recipient file $FEE_RECIPIENT_FILE (the user's wallet address, one rand1… line)" >&2; exit 1; }
  FEE_RECIPIENT=$(tr -d ' \t\r\n' < "$FEE_RECIPIENT_FILE")
  case "$FEE_RECIPIENT" in rand1*) ;; *) echo "cut-chain22: $FEE_RECIPIENT_FILE does not hold a rand1… address" >&2; exit 1;; esac
  [ "$(wc -l < "$FEE_RECIPIENT_FILE" | tr -d ' ')" -le 1 ] || { echo "cut-chain22: $FEE_RECIPIENT_FILE holds more than one line" >&2; exit 1; }
  [ -x "$WALLET" ] || { echo "cut-chain22: WALLET=$WALLET is not executable — it computes the fee recipient's fingerprint" >&2; exit 1; }
  d=$(mktemp -d)
  got=$("$WALLET" --key "$d/fingerprint-only.key.json" contacts add fee-recipient "$FEE_RECIPIENT" --yes 2>&1 | sed -n 's/^fingerprint \([0-9A-Z-]*\)$/\1/p' | head -1 || true)
  rm -rf "$d"
  [ -n "$got" ] || { echo "cut-chain22: $WALLET printed no fingerprint for the fee recipient in $FEE_RECIPIENT_FILE (not a shielded address?)" >&2; exit 1; }
  [ "$got" = "$FEE_RECIPIENT_FINGERPRINT" ] || { echo "cut-chain22: the fee recipient in $FEE_RECIPIENT_FILE has fingerprint $got, not FEE_RECIPIENT_FINGERPRINT $FEE_RECIPIENT_FINGERPRINT — refusing (the wrong wallet would collect every bridge fee for the chain's life)" >&2; exit 1; }
  export FEE_RECIPIENT
  echo "cut-chain22: bridge fee recipient: ${#FEE_RECIPIENT}-char address from $FEE_RECIPIENT_FILE, fingerprint $got (= FEE_RECIPIENT_FINGERPRINT)"
}

# ══ snapshot: read-only reads of chain 21 and of the source endpoints ═════════════════════════
py_snapshot() {
  python3 - <<'PY'
import base64, hashlib, json, os, struct, sys, time, urllib.request, urllib.error
E = os.environ
sha = hashlib.sha256(open(E["CHAIN21_GENESIS"], "rb").read()).hexdigest()
if sha != E["CHAIN21_GENESIS_SHA256"]:
    sys.exit(f"cut-chain22: {E['CHAIN21_GENESIS']} is not chain 21's committed genesis file "
             f"(sha256 {sha[:8]}…, expected {E['CHAIN21_GENESIS_SHA256'][:8]}…)")
g21 = json.load(open(E["CHAIN21_GENESIS"]))
if g21.get("vesting"):
    sys.exit("cut-chain22: chain 21's genesis has a vesting section — this script carries none; extend it first")
BACKINGS = g21["tokens"]["tokens"][0]["backings"]

def post(url, body, headers=None):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json", "user-agent": "rand-cut-chain22/1", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def rand(method, params=None):
    r = post(E["CHAIN21_RPC"], {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
    if "error" in r:
        sys.exit(f"cut-chain22: {method}: {r['error']}")
    return r["result"]

def eth_call(url, to, data):
    r = post(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": to, "data": data}, "latest"]})
    if "error" in r:
        sys.exit(f"cut-chain22: eth_call {to} on {url}: {r['error']}")
    return int(r["result"], 16)

def tron(contract41, selector, param=""):
    r = post(E["TRON_API"] + "/wallet/triggerconstantcontract",
             {"owner_address": E["TRON_ENDPOINT41"], "contract_address": contract41,
              "function_selector": selector, "parameter": param})
    if not r.get("constant_result"):
        sys.exit(f"cut-chain22: Tron {selector} on {contract41}: {r}")
    return int(r["constant_result"][0], 16)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(b):
    n = int.from_bytes(b, "big"); s = ""
    while n:
        n, r = divmod(n, 58); s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s

def sol_accounts(disc_b58):
    r = post(E["SOL_RPC"], {"jsonrpc": "2.0", "id": 1, "method": "getProgramAccounts",
                            "params": [E["SOL_PROGRAM"], {"encoding": "base64", "filters": [{"memcmp": {"offset": 0, "bytes": disc_b58}}]}]})
    if "error" in r:
        sys.exit(f"cut-chain22: Solana getProgramAccounts: {r['error']}")
    return [base64.b64decode(a["account"]["data"][0]) for a in r["result"]]

snap = {"taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
snap["genesis_hash"] = rand("rand_getGenesisHash")
if snap["genesis_hash"] != E["CHAIN21_HASH"]:
    sys.exit(f"cut-chain22: {E['CHAIN21_RPC']} serves {snap['genesis_hash']}, not chain 21")
snap["status_height"] = rand("rand_status")["height"]
snap["validators"] = rand("rand_getValidators")
snap["bridge"] = rand("rand_getBridgeState")
snap["tokens"] = rand("rand_getTokens")
snap["supply"] = rand("rand_getSupply")
# Chain 21's state its own cut never had to carry (the header's OPEN 3–5), read for the cut's
# refusals and the record: the exchange, its accounts, the treasury as it stands.
snap["perps"] = rand("rand_getPerps")
snap["perp_accounts"] = rand("rand_getPerpAccounts", [{"limit": 1000}])
snap["treasury"] = rand("rand_getMultisig", [E["CHAIN21_TREASURY_ID"]])

# ── the source endpoints: next outbound sequence and custody per backing ─────────────────────
seq, custody = {}, {}
sel_seq, sel_bal, sel_fee = "0x529d15cc", "0x70a08231", "0x07311283"   # sequence(), balanceOf(address), accruedFees(address)
for chain, url in (("2", E["ETH_RPC"]), ("3", E["BSC_RPC"])):
    ep = "0x" + E[f"EMITTER_{chain}"][-40:]
    seq[chain] = eth_call(url, ep, sel_seq)
    for b in BACKINGS:
        if str(b["chain"]) != chain:
            continue
        tok = "0x" + b["token"][-40:]
        bal = eth_call(url, tok, sel_bal + "00" * 12 + ep[2:])
        fees = eth_call(url, ep, sel_fee + "00" * 12 + tok[2:])
        custody[f"{chain}:{b['token']}"] = {"balance": bal, "fees": fees, "custody": bal - fees}
tron_ep41 = "41" + E["EMITTER_4"][-40:]
os.environ["TRON_ENDPOINT41"] = tron_ep41; E = os.environ
seq["4"] = tron(tron_ep41, "sequence()")
for b in BACKINGS:
    if b["chain"] == 4:
        tok41 = "41" + b["token"][-40:]
        bal = tron(tok41, "balanceOf(address)", "00" * 12 + E["EMITTER_4"][-40:])
        fees = tron(tron_ep41, "accruedFees(address)", "00" * 12 + b["token"][-40:])
        custody[f"4:{b['token']}"] = {"balance": bal, "fees": fees, "custody": bal - fees}
# Solana: Config (discriminator 1) carries `sequence`; each TokenRegistry (3) its `custody`.
cfgs = sol_accounts("2")
if len(cfgs) != 1:
    sys.exit(f"cut-chain22: {len(cfgs)} Solana config accounts, expected 1")
off = 1 + 32 * 3 + 1 + 32 + 4
seq["5"] = struct.unpack_from("<Q", cfgs[0], off)[0]
for acc in sol_accounts("4"):
    mint = acc[1:33].hex()
    cu, fe = struct.unpack_from("<QQ", acc, 1 + 32 + 2 + 8 * 4)
    custody[f"5:{mint}"] = {"custody": cu, "fees": fe, "mint": b58(acc[1:33])}
snap["source"] = {"emitters": {c: E[f"EMITTER_{c}"] for c in "2345"}, "next_sequence": seq, "custody": custody}
json.dump(snap, open(os.path.join(E["SNAP"], "chain21-state.json"), "w"), indent=1)
print(f"cut-chain22: snapshot of chain 21 at height {snap['status_height']} → {E['SNAP']}/chain21-state.json")
print(f"cut-chain22: source next sequences {seq}; burn_sequence {snap['bridge']['burn_sequence']}; "
      f"zUSD supply {snap['tokens']['tokens'][0]['total_supply']}")
for k, v in custody.items():
    if v["custody"]:
        print(f"cut-chain22: custody {k[:2]}…{k[-8:]} = {v['custody']}")
P, S, T = snap["perps"] or {}, snap["supply"] or {}, snap["treasury"] or {}
print(f"cut-chain22: perps: {P.get('accounts')} account(s), {P.get('pending_withdrawals')} pending withdrawal(s), proved height "
      f"{P.get('proved_height')} of {P.get('head_height')}, collateral held {P.get('collateral_held')} (counted since the v0.8.2 roll)")
print(f"cut-chain22: multisig: issued {S.get('multisig_issued')}, held {S.get('multisig_rand_held')} RAND units; the treasury "
      f"{E['CHAIN21_TREASURY_ID'][:12]}… threshold {T.get('threshold')}, nonce {T.get('nonce')}, vault {T.get('vault')}; "
      f"program vaults hold {S.get('program_rand_held')} RAND units")
PY
}

# ══ balances: every wallet the operator holds, scanned on chain 21 → the RAND carry list ══════
# Read-only toward the chain; it does write each wallet's note store (<key>.notes.json) as any
# `rand sync` does. The key files are opened by `rand` only — this script never reads them.
py_balances() {
  python3 - <<'PY'
import glob, json, os, re, subprocess, sys, time, urllib.request
E = os.environ
exec(E["UNITS_PY"])
def rpc(method):
    req = urllib.request.Request(E["CHAIN21_RPC"], json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode(),
                                 {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["result"]
if rpc("rand_getGenesisHash") != E["CHAIN21_HASH"]:
    sys.exit(f"cut-chain22: {E['CHAIN21_RPC']} is not chain 21")
status0 = rpc("rand_status")
if int(status0.get("prune_floor", 0) or 0) > 0:
    sys.exit(f"cut-chain22: {E['CHAIN21_RPC']} is pruned (prune_floor {status0['prune_floor']}) — "
             f"`balances` needs a full scan; point CHAIN21_RPC at an archive (obs1, rand-archive-2)")
def rand(key, *args):
    p = subprocess.run([E["WALLET"], "--rpc", E["CHAIN21_RPC"], "--key", key, *args], capture_output=True, text=True)
    if p.stderr.strip():
        print(p.stderr.strip(), file=sys.stderr)   # RS-1's pruned-node warning, the rescan notice: never swallowed
    if p.returncode != 0:
        sys.exit(f"cut-chain22: rand {' '.join(args)} for {key}: {p.stderr.strip()}")
    return p.stdout
files = []
for d in E["WALLETS_DIRS"].split():
    if os.path.isdir(d):
        files += sorted(glob.glob(os.path.join(d, "*.key.json")))
    else:
        print(f"cut-chain22: {d} does not exist — skipped")
if not files:
    sys.exit("cut-chain22: no *.key.json under WALLETS_DIRS")
height0 = status0["height"]
by_addr, pending_by_wallet = {}, []
sync = ["sync", "--rescan"] if E.get("BALANCES_RESCAN", "1") == "1" else ["sync"]
for f in files:
    label = os.path.basename(f)[: -len(".key.json")]
    addr = rand(f, "address").splitlines()[0].strip()
    rand(f, *sync)
    out = rand(f, "balance")
    line = next((l for l in out.splitlines() if l.startswith("balance: ") and l.endswith(" RAND")), None)
    if line is None:
        sys.exit(f"cut-chain22: could not read a balance for {f}: {out!r}")
    ru = units(line[len("balance: "):-len(" RAND")])
    zo = rand(f, "asset-balance", "1").strip()
    zu = int(zo.split()[2]) if zo.startswith("asset 1: ") else 0
    pend = []
    for nline in rand(f, "notes").splitlines():
        cols = re.split(r"  +", nline.strip())
        if len(cols) < 6 or cols[0] == "index":
            continue
        if cols[5] != "-":
            pend.append((cols[1], cols[2], cols[5]))
    if pend:
        pending_by_wallet.append((label, pend))
    row = {"label": label, "address": addr, "rand_units": ru, "zusd_units": zu, "file": f}
    prev = by_addr.get(addr)
    if prev and (prev["rand_units"], prev["zusd_units"]) != (ru, zu):
        sys.exit(f"cut-chain22: {prev['file']} and {f} are one address with different balances — reconcile the note stores")
    if not prev:
        by_addr[addr] = row
    print(f"cut-chain22:   {label:<24} {fmt(ru):>18} RAND  {zu:>12} zUSD units{'  (duplicate key file)' if prev else ''}")
height1 = rpc("rand_status")["height"]
if pending_by_wallet and not E.get("PENDING_OK"):
    detail = "; ".join(f"{label}: " + ", ".join(f"asset {a} amount {amt} ({since})" for a, amt, since in rows) for label, rows in pending_by_wallet)
    sys.exit(f"cut-chain22: pending note(s) would be dropped from the carry silently: {detail} — wait for them to "
             f"clear (or fail) and re-run, or set PENDING_OK=1 to drop them")
elif pending_by_wallet:
    detail = "; ".join(f"{label}: " + ", ".join(f"asset {a} amount {amt}" for a, amt, _ in rows) for label, rows in pending_by_wallet)
    print(f"cut-chain22: ⚠ dropping pending note(s) (PENDING_OK=1): {detail}")
rows = sorted(by_addr.values(), key=lambda r: r["label"])
carry = [r for r in rows if r["rand_units"] > 0]
labels = [r["label"] for r in carry]
if len(set(labels)) != len(labels):
    sys.exit("cut-chain22: two wallets with one label — rename a key file")
total = sum(r["rand_units"] for r in carry)

# ── chain 21's own genesis alloc notes this scan does not cover ────────────────────────────────
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            sys.exit(f"cut-chain22: {s!r} is not base58")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body
scanned_pks = set()
for addr in by_addr:
    if addr.startswith("rand1"):
        raw = b58decode(addr[len("rand1"):])
        if len(raw) >= 32:
            scanned_pks.add(raw[:32].hex())
g21 = json.load(open(E["CHAIN21_GENESIS"]))
alloc_pks = {n["opening"]["pk"]: n["amount"] for n in g21["alloc"] if n.get("opening", {}).get("asset", 0) == 0}
uncovered = [{"pk": pk, "amount": amt} for pk, amt in alloc_pks.items() if pk not in scanned_pks]
if uncovered:
    print("cut-chain22: uncovered genesis allocs (no scanned wallet's pk matches — the cut refuses "
          "unless UNCOVERED_ALLOCS_OK=1): " + ", ".join(f"{u['pk'][:12]}… ({u['amount']})" for u in uncovered))

json.dump({"chain21_hash": E["CHAIN21_HASH"], "taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "height_from": height0, "height_to": height1, "wallets": rows, "carried_rand_units": total,
           "uncovered_genesis_allocs": uncovered, "rescanned": sync == ["sync", "--rescan"]},
          open(os.path.join(E["SNAP"], "balances.json"), "w"), indent=1)
os.makedirs(os.path.dirname(E["ALLOC_ADDRESSES"]) or ".", exist_ok=True)
with open(E["ALLOC_ADDRESSES"], "w") as out:
    out.write(f"# chain-22 RAND carry: chain-21 balances at heights {height0}..{height1}, `balances` step\n")
    for r in carry:
        out.write(f"{r['label']} {r['address']} {fmt(r['rand_units'])}\n")
print(f"cut-chain22: {len(carry)} wallet(s) with RAND, Σ {fmt(total)} RAND → {E['ALLOC_ADDRESSES']} (+ {E['SNAP']}/balances.json)")
z = [r for r in rows if r["zusd_units"]]
if z:
    op_total = sum(r["zusd_units"] for r in z)
    print(f"cut-chain22: zUSD held by operator wallets: " + ", ".join(f"{r['label']} {r['zusd_units']}" for r in z) + f" (Σ {op_total})")
    if os.path.isfile(E["ZUSD_CARRY"]):
        carry_total = sum(units(a, 8) for _, _, a in alloc_lines(E["ZUSD_CARRY"]))
        if carry_total != op_total:
            print(f"cut-chain22: ⚠ Σ operator-wallet zUSD ({op_total}) != Σ ZUSD_CARRY ({carry_total}) — "
                  f"a non-operator holder (e.g. Anish's wallet) legitimately differs; verify by hand")
PY
}

# ══ the cut, step 1: the validators, from the chain-21 register ═══════════════════════════════
py_validators() {
  python3 - <<'PY'
import json, os, sys
E = os.environ
need = lambda c, m: c or sys.exit(f"cut-chain22: {m}")
snap = json.load(open(E["SNAPSHOT_FILE"]))
g21 = json.load(open(E["CHAIN21_GENESIS"]))
register = {v["address"]: v for v in snap["validators"]}
tsv = {}
for line in open(E["VALIDATORS_TSV"]):
    if line.startswith("#") or not line.strip():
        continue
    name, addr, pk, _peer, payout = line.rstrip("\n").split("\t")
    tsv[name] = (addr, pk, payout)
rows = []
for name in E["GENESIS_NAMES"].split():
    need(name in tsv, f"{name} is not in {E['VALIDATORS_TSV']}")
    addr, pk, payout = tsv[name]
    rows.append({"name": name, "address": addr, "public_key": pk, "payout": payout})
for name in E["BONDED"].split():
    lines = open(os.path.join(E["REGISTRATIONS"], f"{name}.txt")).read().split("\n")
    head, reg = lines[0].split(), lines[1].split()
    need(head[0] == "validator" and head[2:] == ["on", "chain", "15"] and reg[0] == "registration:", f"{name}.txt is not a chain-15 registration")
    raw = bytes.fromhex(reg[1])
    n = int.from_bytes(raw[:8], "little")
    need(n == 1312, f"{name}.txt: a {n}-byte public key, expected Dilithium2's 1312")
    addr = head[1]
    need(addr in register, f"{name} ({addr}) is not in chain 21's register")
    rows.append({"name": name, "address": addr, "public_key": raw[8:8 + n].hex(), "payout": register[addr]["payout"]})
stake = int(E["STAKE_RAND"]) * 10**9
need(len(rows) == len(register) == 26, f"{len(rows)} validators assembled, chain 21's register holds {len(register)}")
for r in rows:
    live = register.get(r["address"])
    need(live is not None, f"{r['name']} ({r['address']}) is not in chain 21's register")
    need(live["payout"] == r["payout"], f"{r['name']}: payout differs from chain 21's register")
    need(int(live["stake"]) == stake and not live["pending"], f"{r['name']}: chain 21 stake {live['stake']} / pending {live['pending']}, not a plain {stake}")
    need(live["active"], f"{r['name']} is not active on chain 21")
    need(int(live.get("rewards", "0")) == 0 or E.get("REWARDS_DROPPED_OK"),
         f"{r['name']}: chain 21 shows {live['rewards']} unwithdrawn reward units — withdraw them before the cut "
         f"(rewards are not carried), or set REWARDS_DROPPED_OK=1 to drop them")
need(len({r["public_key"] for r in rows}) == 26 and len({r["address"] for r in rows}) == 26, "a validator twice")
total_rewards = sum(int(register[r["address"]].get("rewards", "0")) for r in rows)
if total_rewards:
    print(f"cut-chain22: ⚠ dropping {total_rewards} unwithdrawn reward unit(s) across the register (REWARDS_DROPPED_OK=1)")
need([(v["public_key"], v["payout"]) for v in g21["validators"]] == [(r["public_key"], r["payout"]) for r in rows],
     "the 26 are not chain 21's genesis validators (keys, payouts or order)")
json.dump(rows, open(os.path.join(E["TMP"], "validators.json"), "w"))
with open(os.path.join(E["TMP"], "validator-args"), "w") as f:
    for r in rows:
        f.write(f"--validator\n{r['public_key']},{E['STAKE_RAND']},{r['payout']}\n")
t = g21["tokens"]
json.dump({"registration_fee": t["registration_fee"], "mint_cap_per_day": t["mint_cap_per_day"], "tokens": []},
          open(os.path.join(E["TMP"], "tokens.json"), "w"))
print(f"cut-chain22: 26 validators × {E['STAKE_RAND']} RAND, equal to chain 21's register at height {snap['status_height']}")
PY
}

# ══ the cut, step 1b: the treasury — TREASURY → $TMP/multisig.json (the `--multisig` file) ═════
# Exactly 3 signers in the file's order, `threshold 2`, a positive `balance` in RAND (the exact
# units() rule; NEW ISSUANCE, the owner's amount — OPEN 3). The signers must be chain 21's treasury
# signers in chain 21's order (its genesis; the live account's after a rotation, TREASURY_ROTATED=1)
# unless TREASURY_SIGNERS_CHANGED=1. A key that is a validator's (chain 21's register, which is
# chain 22's), a bridge guardian's or the pause key is refused — a treasury signer is a person's own
# key — and so is a key listed twice. The salt is 32 fresh random bytes, every run (TREASURY_SALT
# only for the selftest's reproducibility), so the chain-22 id differs from chain 21's anyway (the
# id binds the chain id). `max_accounts` (MSA-4) is MULTISIG_MAX_ACCOUNTS, written unless
# AUDIT_V10_SKIPPED.
py_treasury() {
  python3 - <<'PY'
import json, os, re, secrets, sys
E = os.environ
exec(E["UNITS_PY"])
def need(cond, msg):
    if not cond:
        sys.exit(f"cut-chain22: {E['TREASURY']}: {msg}")
signers, thresholds, balances = [], [], []
for n, line in enumerate(open(E["TREASURY"]), 1):
    f = line.split()
    if not f or f[0].startswith("#"):
        continue
    if f[0] == "signer":
        need(len(f) == 3, f"line {n}: \"signer <name> <public key hex>\", got {len(f) - 1} field(s)")
        need(re.fullmatch(r"[0-9a-f]{2624}", f[2]), f"line {n}: signer {f[1]}'s key is not a Dilithium2 public key (2624 lowercase hex characters)")
        signers.append((f[1], f[2]))
    elif f[0] == "threshold":
        need(len(f) == 2 and f[1].isdigit(), f"line {n}: \"threshold <n>\"")
        thresholds.append(int(f[1]))
    elif f[0] == "balance":
        need(len(f) == 2, f"line {n}: \"balance <RAND>\"")
        balances.append(units(f[1]))
    else:
        need(False, f"line {n}: {f[0]!r} — a line is `signer`, `threshold` or `balance`")
want_n, want_t = int(E["TREASURY_SIGNERS"]), int(E["TREASURY_THRESHOLD"])
need(len(signers) == want_n, f"{len(signers)} signer line(s) — the treasury is exactly {want_n} signers ({want_t} of {want_n})")
need(thresholds == [want_t], f"threshold {thresholds or 'missing'} — the treasury's threshold is {want_t} (one `threshold {want_t}` line)")
need(len(balances) == 1, f"{len(balances)} balance line(s), expected one")
balance = balances[0]
need(balance > 0, "balance 0 — the treasury is seeded with new issuance")
names = [s[0] for s in signers]
pks = [s[1] for s in signers]
need(len(set(names)) == len(names), "a signer name twice")
need(len(set(pks)) == len(pks), "a signer key listed twice — one key for two positions makes 2 of 3 a 1-key account")
known = {}
for v in json.load(open(os.path.join(E["TMP"], "validators.json"))):
    known[v["public_key"]] = f"validator {v['name']}"
g21 = json.load(open(E["CHAIN21_GENESIS"]))
snap = json.load(open(E["SNAPSHOT_FILE"]))
for b in (g21["bridge"], snap["bridge"]):
    for i, k in enumerate(b["pq_guardians"]):
        known[k] = f"bridge PQ guardian {i}"
    known[b["pause_key"]] = "the bridge pause key"
for name, pk in signers:
    need(pk not in known, f"signer {name}'s key is {known.get(pk)}'s — a treasury signer holds a key of its own")
# chain 21's treasury: its genesis signers, or the live ones the snapshot read after a rotation
a21 = g21["multisig"]["accounts"][0]
live = snap.get("treasury") or {}
rotated = E.get("TREASURY_ROTATED") == "1"
if live.get("signers") is not None and (live["signers"], live.get("threshold")) != (a21["signers"], a21["threshold"]):
    need(rotated, "chain 21's treasury signers or threshold moved since its genesis (a rotation) — set TREASURY_ROTATED=1 to "
                  "carry the live signers, or TREASURY_SIGNERS_CHANGED=1 for knowingly other keys")
want_pks = live["signers"] if rotated and live.get("signers") else a21["signers"]
need(pks == want_pks or E.get("TREASURY_SIGNERS_CHANGED") == "1",
     f"the signers are not chain 21's treasury signers in chain 21's order ({'live, rotated' if rotated else 'its genesis'}) — "
     f"TREASURY_SIGNERS_CHANGED=1 only for knowingly other keys")
salt = E.get("TREASURY_SALT") or secrets.token_hex(32)
need(re.fullmatch(r"[0-9a-f]{64}", salt), "TREASURY_SALT is not 64 hex")
need(salt != a21["salt"], "the salt is chain 21's treasury salt — every cut draws a fresh one")
section = {"create_fee": E["MULTISIG_CREATE_FEE"],
           "accounts": [{"salt": salt, "signers": pks, "threshold": want_t, "balance": str(balance)}]}
if not E.get("AUDIT_V10_SKIPPED"):
    cap = E.get("MULTISIG_MAX_ACCOUNTS", "")
    need(cap.isdigit() and int(cap) >= len(section["accounts"]),
         f"MULTISIG_MAX_ACCOUNTS {cap!r} is not a count ≥ {len(section['accounts'])} (the seeded treasury counts) — OPEN 2, the operator's")
    section["max_accounts"] = int(cap)
json.dump(section, open(os.path.join(E["TMP"], "multisig.json"), "w"), indent=1)
with open(os.path.join(E["TMP"], "treasury-args"), "w") as f:
    f.write(f"--salt\n{salt}\n--threshold\n{want_t}\n")
    for pk in pks:
        f.write(f"--signer\n{pk}\n")
open(os.path.join(E["TMP"], "treasury-balance"), "w").write(str(balance))
print(f"cut-chain22: treasury: {want_t} of {want_n} ({', '.join(names)}), balance {fmt(balance)} RAND = {balance} units (NEW ISSUANCE), salt {salt}"
      f"{', max_accounts ' + str(section['max_accounts']) if 'max_accounts' in section else ''}")
print(f"cut-chain22: chain 21's treasury for comparison: issued {fmt(int(a21['balance']))} RAND at its genesis; live vault {live.get('vault')} "
      f"(not carried — OPEN 3; the chain-22 balance is TREASURY's)")
PY
}

# ══ the cut, step 1c: the perps section — markets → genesis words → root; the section file ══════
# PERPS_STEP=markets writes $TMP/perps-markets.json (the bare `{"markets": […]}` perp-prover
# genesis-state reads); PERPS_STEP=section writes $TMP/perps.json from PERPS_JSON, EXPECT_ENGINE_HC
# and PERP_GENESIS_ROOT, in PerpsConfig's field order, then — unless AUDIT_V10_SKIPPED — the new
# fields: bound_payouts, sparse_windows, max_window_heights (PERPS_MAX_WINDOW_HEIGHTS) and
# engine_program_log_height (ENGINE_PROGRAM_LOG_HEIGHT, from `rand perp image-hc`); never
# initial_collateral (OPEN 4). py_splice puts it into the file.
py_perps() {
  python3 - <<'PY'
import json, os, re, sys
E = os.environ
d = json.loads(E["PERPS_JSON"])
if E["PERPS_STEP"] == "markets":
    json.dump({"markets": d["markets"]}, open(os.path.join(E["TMP"], "perps-markets.json"), "w"))
    sys.exit(0)
root = E.get("PERP_GENESIS_ROOT", "")
if not re.fullmatch(r"[0-9a-f]{64}", root):
    sys.exit(f"cut-chain22: PERP_GENESIS_ROOT {root!r} is not 64 hex — the genesis root step did not run")
section = {k: d[k] for k in ("collateral_asset", "max_tier", "max_window_blocks", "max_block_inputs", "min_deposit")}
section.update(engine_hc=E["EXPECT_ENGINE_HC"], genesis_root=root, markets=d["markets"])
if not E.get("AUDIT_V10_SKIPPED"):
    v10 = json.loads(E["PERPS_V10_JSON"])
    mwh, eplh = E.get("PERPS_MAX_WINDOW_HEIGHTS", ""), E.get("ENGINE_PROGRAM_LOG_HEIGHT", "")
    if not (mwh.isdigit() and d["max_window_blocks"] <= int(mwh) <= 4096):
        sys.exit(f"cut-chain22: PERPS_MAX_WINDOW_HEIGHTS {mwh!r} is not in max_window_blocks..=4096 — OPEN 1, the operator's")
    if not (eplh.isdigit() and 1 <= int(eplh) <= 24):
        sys.exit(f"cut-chain22: ENGINE_PROGRAM_LOG_HEIGHT {eplh!r} is not 1..=24 — the `rand perp image-hc` step did not run")
    section.update(bound_payouts=v10["bound_payouts"], sparse_windows=v10["sparse_windows"],
                   max_window_heights=int(mwh), engine_program_log_height=int(eplh))
json.dump(section, open(os.path.join(E["TMP"], "perps.json"), "w"), indent=1)
PY
}

# ══ the cut, step 2: splice bridge, tokens, staking; assert every carried sum and every new field ═
py_splice() {
  python3 - <<'PY'
import copy, json, os, re, sys, time
E = os.environ
exec(E["UNITS_PY"])
out = E["OUT"]
g = json.load(open(out))
g21 = json.load(open(E["CHAIN21_GENESIS"]))
snap = json.load(open(E["SNAPSHOT_FILE"]))
sb = snap["bridge"]
warnings = []

def need(cond, msg):
    if not cond:
        sys.exit(f"cut-chain22: {msg}")

need(snap["genesis_hash"] == E["CHAIN21_HASH"], "the snapshot is not of chain 21")
need(not g21.get("vesting"), "chain 21's genesis has a vesting section — this script carries none")
need(g21.get("chain_id") == 21 and "fees" in g21 and "perps" in g21 and "multisig" in g21 and "hc_auth_multisig" in g21
     and not {"bound_payouts", "initial_collateral", "sparse_windows", "max_window_heights", "engine_program_log_height"} & set(g21["perps"])
     and "max_accounts" not in g21["multisig"] and "refuse_panics" not in g21["program_state"] and "incremental_root" not in g21["tokens"],
     "CHAIN21_GENESIS is not chain 21's (chain id 21 with fees, perps, multisig and hc_auth_multisig; none of the fields chain 22 adds)")
b21 = g21["bridge"]
need({c: E[f"C21_EMITTER_{c}"] for c in "2345"} == b21["emitters"], "C21_EMITTER_* are not deploy/genesis-chain21.json's emitters")

# ── bridge: chain 21's live values, the floors re-derived, rotation and fees chain 21's ─────────
rotated = E.get("BRIDGE_ROTATED")
for k in ("guardians", "guardian_set_index", "pq_guardians", "pause_key"):
    need(sb[k] == b21[k] or rotated, f"chain 21's live {k} differs from its genesis — a rotation; set BRIDGE_ROTATED=1 to carry the live value")
need(sb["emitter"] == b21["emitter"], "the Rand-side emitter differs from chain 21's")
need(not sb["mint_paused"], "chain 21's mints are paused — decide what chain 22 starts with")
need(sb["emitters"] == b21["emitters"], "chain 21's live emitter table differs from its genesis")
need(int(sb["rules_v2"]["global_mint_cap_per_window"]) == int(b21["rules_v2"]["global_mint_cap_per_window"])
     and int(sb["rules_v2"]["cap_window_secs"]) == int(b21["rules_v2"]["cap_window_secs"]), "rules_v2 differs from chain 21's genesis")
need(int(sb["registration_fee"]) == int(g21["tokens"]["registration_fee"]), "registration_fee differs from chain 21's")
need(sb["burn_sequence"] >= b21["burn_sequence"], "chain 21's burn sequence went backwards")
pq_guardians, guardians, pause_key = sb["pq_guardians"], sb["guardians"], sb["pause_key"]
need(len(pq_guardians) == len(guardians) == 8, f"{len(pq_guardians)} pq_guardians against {len(guardians)} guardians, expected 8 and 8")
for i, k in enumerate(pq_guardians + [pause_key]):
    need(re.fullmatch(r"[0-9a-f]{2624}", k), f"PQ key {i} is not 2624 lowercase hex characters")
need(pause_key not in pq_guardians and len(set(pq_guardians)) == 8 and len(set(guardians)) == 8, "duplicate guardian or pause key")
emitters = {c: E[f"EMITTER_{c}"] for c in "2345"}
for c, e in emitters.items():
    need(re.fullmatch(r"[0-9a-f]{64}", e), f"EMITTER_{c} is not 64 lowercase hex characters")
    need(e not in E["OLD_EMITTERS"].split(), f"EMITTER_{c} is a 2026-09-19 endpoint — never again")
need(snap["source"]["emitters"] == emitters, "the snapshot read custody/sequences at other emitters than this cut lists")
need(emitters == b21["emitters"] or E.get("EMITTERS_CHANGED") == "1",
     "the emitter table is not chain 21's (deploy/genesis-chain21.json) — EMITTERS_CHANGED=1 only for a knowingly new endpoint")
changed = [c for c in "2345" if emitters[c] != b21["emitters"][c]]

floor21 = {str(k): int(v) for k, v in (b21.get("min_inbound_sequence") or {}).items()}
allow_unminted = E.get("ALLOW_UNMINTED_LOCKS")
floor, unminted = {}, {}
for c in "2345":
    v = E[f"MIN_INBOUND_{c}"]
    next_seq = int(snap["source"]["next_sequence"][c])
    explicit = v != "auto"
    if not explicit:
        need(c not in changed, f"MIN_INBOUND_{c}=auto on a changed endpoint — give the floor explicitly")
        v = str(next_seq)
    # Sequence 0 of each redeployed endpoint (Ethereum, BNB Chain, Tron) is the operator's
    # consume-step lock: it must never mint, on any chain.
    need(c == "5" or not v.isdigit() or int(v) >= 1, f"chain {c}'s floor {v} is below 1 — the consume-step lock (sequence 0) would mint")
    need(v.isdigit() and int(v) > 0, f"chain {c}'s floor is {v!r}: a positive sequence")
    if int(v) > next_seq:
        need(c in changed and E.get("FLOOR_AHEAD_OK"),
             f"MIN_INBOUND_{c}={v} is above chain {c}'s endpoint next sequence {next_seq}: locks {next_seq}..{int(v) - 1} "
             f"would NEVER mint on chain 22 (refused on an endpoint chain 21 already trusts)")
        warnings.append(f"chain {c}: floor {v} is ahead of the endpoint's next sequence {next_seq} (FLOOR_AHEAD_OK=1)")
    if c not in changed and c in floor21:
        need(int(v) >= floor21[c], f"MIN_INBOUND_{c}={v} is below chain 21's own floor {floor21[c]} — it would re-open minted locks")
    if int(v) < next_seq:
        need(allow_unminted,
             f"chain {c}'s endpoint has emitted up to {next_seq - 1} but the floor is {v}: locks {v}..{next_seq - 1} will mint "
             f"on chain 22 — drain them on chain 21 first, or set ALLOW_UNMINTED_LOCKS=1 if they are user locks chain 21 never minted")
        unminted[c] = (int(v), next_seq - 1)
        warnings.append(f"chain {c}: locks {v}..{next_seq - 1} were emitted and are NOT below the floor — they will mint on chain 22 (ALLOW_UNMINTED_LOCKS=1)")
    if E.get("RELAYER_DONE_DIR") and c not in changed:
        d = os.path.join(E["RELAYER_DONE_DIR"], c)
        done = [int(m.group()) for m in (re.match(r"\d+", x) for x in (os.listdir(d) if os.path.isdir(d) else [])) if m]
        last = max(done) if done else floor21.get(c, 1) - 1
        need(int(v) == last + 1, f"chain {c}: the relayer's done/ says last minted {last}, the floor is {v} (last minted + 1 = {last + 1})")
    floor[c] = int(v)
need(set(floor) == set("2345"), "a replay floor for every endpoint chain 21 trusts")
want_floor = {c: int(v) for c, v in (x.split(":") for x in E["EXPECT_FLOORS"].split())}
if floor != want_floor:
    warnings.append(f"min_inbound_sequence is {floor}, EXPECTED {want_floor} (EXPECT_FLOORS) — confirm every difference against the endpoints before launch")
if int(sb["burn_sequence"]) != int(E["EXPECT_BURN_SEQUENCE"]):
    warnings.append(f"burn_sequence is {sb['burn_sequence']}, EXPECTED {E['EXPECT_BURN_SEQUENCE']} — a burn landed on chain 21 since; confirm its release before launch")

need(E["ROTATION_NEEDS_POSSESSION"] in ("true", "false"), "ROTATION_NEEDS_POSSESSION is true or false")
rotation = {"delay_secs": int(E["ROTATION_DELAY_SECS"]), "needs_possession": E["ROTATION_NEEDS_POSSESSION"] == "true"}
g["bridge"] = {
    "emitter": b21["emitter"],
    "guardians": guardians,
    "emitters": emitters,
    "pq_guardians": pq_guardians,
    "pause_key": pause_key,
    "rules_v2": b21["rules_v2"],
    "guardian_set_index": int(sb["guardian_set_index"]),
    "burn_sequence": int(sb["burn_sequence"]),
    "min_inbound_sequence": floor,
    "rotation": rotation,
    "fees": {"mint_bps": int(E["BRIDGE_MINT_BPS"]), "burn_bps": int(E["BRIDGE_BURN_BPS"]), "recipient": E["FEE_RECIPIENT"]},
}

# ── tokens: zUSD at genesis, locked = chain 21's per backing == custody == supply ───────────────
tok = snap["tokens"]["tokens"]
z = [t for t in tok if t["symbol"] == "zUSD" and t["index"] == 1]
need(len(z) == 1, "chain 21 does not list zUSD at index 1")
others = [t for t in tok if t is not z[0]]
need(not others or E.get("ALLOW_DROPPED_TOKENS"),
     f"chain 21 lists {len(others)} more token(s) ({', '.join(t['symbol'] for t in others)}) the cut cannot carry — set ALLOW_DROPPED_TOKENS=1 to drop them")
if others:
    warnings.append(f"dropped chain-21 tokens: {', '.join(str(t['index']) + ':' + t['symbol'] for t in others)}")
z21 = g21["tokens"]["tokens"][0]
live_backings = z[0]["authority"]["backings"]
need([(b["chain"], b["token"], b["decimals"]) for b in live_backings] == [(b["chain"], b["token"], b["decimals"]) for b in z21["backings"]],
     "chain 21's live backings differ from its genesis list")
backings = []
for lb in live_backings:
    b = {"chain": lb["chain"], "token": lb["token"], "decimals": lb["decimals"]}
    if int(lb["locked"]) > 0:
        b["locked"] = int(lb["locked"])
    backings.append(b)
locked_total = sum(b.get("locked", 0) for b in backings)
need(int(z[0]["total_supply"]) == locked_total, f"chain 21's zUSD supply {z[0]['total_supply']} != Σ locked {locked_total}")
for b in backings:
    key = f"{b['chain']}:{b['token']}"
    have = snap["source"]["custody"].get(key)
    need(have is not None, f"the snapshot has no custody reading for {key}")
    d = b["decimals"]
    if d > 8:
        need(have["custody"] % 10**(d - 8) == 0, f"custody {key} has dust below zUSD's eighth decimal")
    scaled = have["custody"] // 10**(d - 8) if d >= 8 else have["custody"] * 10**(8 - d)
    if scaled != b.get("locked", 0):
        # An unminted user lock (ALLOW_UNMINTED_LOCKS=1, above) is custody chain 21 never locked:
        # custody may exceed locked on that chain only, never fall below it.
        need(str(b["chain"]) in unminted and scaled > b.get("locked", 0),
             f"source custody {key} = {have['custody']} (= {scaled} zUSD units), chain 21 locks {b.get('locked', 0)}")
        warnings.append(f"custody {key} = {scaled} zUSD units, above chain 21's locked {b.get('locked', 0)} — the unminted lock(s) on chain {b['chain']}")

t = g["tokens"]
need(t["registration_fee"] == g21["tokens"]["registration_fee"] and t["mint_cap_per_day"] == g21["tokens"]["mint_cap_per_day"], "tokens header")
t["tokens"] = [{"name": z21["name"], "symbol": z21["symbol"], "salt": z21["salt"], "backings": backings}]
for k in ("max_tokens", "burn_registration_fee", "bound_note_value"):
    t[k] = g21["tokens"][k]
# the new tokens switch (TOK-1, `--tokens-incremental-root`): asserted below; every other switch chain 21's
need({k: v for k, v in t.items() if k not in ("tokens", "incremental_root")} == {k: v for k, v in g21["tokens"].items() if k != "tokens"},
     "the token switches are not chain 21's")

token_notes = [json.loads(l) for l in open(os.path.join(E["TMP"], "token-notes.jsonl")) if l.strip()]
need(token_notes or locked_total == 0, "ZUSD_CARRY carries no note")
notes_total = 0
for i, n in enumerate(token_notes):
    need(n.get("opening", {}).get("asset") == 1, f"token note {i} is not an asset-1 (zUSD) note with an opening")
    notes_total += n["amount"]
need(notes_total == locked_total, f"zUSD genesis notes sum to {notes_total}, backings lock {locked_total} — they must be equal")
carry_total = sum(units(a, 8) for _, _, a in alloc_lines(E["ZUSD_CARRY"]))
need(carry_total == notes_total, f"ZUSD_CARRY lists {carry_total} units, the notes made hold {notes_total}")

# ── RAND: the carry list == the scanned balances; the alloc notes == the carry list ────────────
rand_notes = [n for n in g["alloc"] if n.get("opening", {}).get("asset", 0) == 0]
need(len(rand_notes) == len(g["alloc"]), "the genesis command wrote a non-RAND alloc note")
alloc = alloc_lines(E["ALLOC_ADDRESSES"])
alloc_total = sum(units(a) for _, _, a in alloc)
need(all(units(a) > 0 for _, _, a in alloc), "ALLOC_ADDRESSES lists a zero amount")
need(sum(n["amount"] for n in rand_notes) == alloc_total and len(rand_notes) == len(alloc),
     f"the RAND alloc notes ({len(rand_notes)}, Σ {sum(n['amount'] for n in rand_notes)}) are not ALLOC_ADDRESSES ({len(alloc)}, Σ {alloc_total})")
bal_file = E.get("BALANCES_FILE", "")
if os.path.isfile(bal_file):
    bal = json.load(open(bal_file))
    need(bal["chain21_hash"] == E["CHAIN21_HASH"], "balances.json is not of chain 21")
    scanned = sorted((w["address"], w["rand_units"]) for w in bal["wallets"] if w["rand_units"] > 0)
    listed = sorted((addr, units(a)) for _, addr, a in alloc)
    need(sum(u for _, u in scanned) == alloc_total, f"Σ alloc RAND {alloc_total} != Σ scanned balances {sum(u for _, u in scanned)}")
    need(scanned == listed, "ALLOC_ADDRESSES is not the scanned wallets one-for-one (address, amount) — regenerate it with `balances`")
    uncovered = bal.get("uncovered_genesis_allocs") or []
    need(not uncovered or E.get("UNCOVERED_ALLOCS_OK"),
         "chain 21 genesis alloc(s) match no scanned wallet, so their value would be dropped silently: "
         + ", ".join(f"pk {u['pk'][:12]}… ({u['amount']})" for u in uncovered)
         + " — find the key file(s) and add its directory to WALLETS_DIRS, or set UNCOVERED_ALLOCS_OK=1 to drop them")
    if uncovered:
        warnings.append("dropped uncovered chain-21 genesis alloc(s): " + ", ".join(f"pk {u['pk'][:12]}… ({u['amount']})" for u in uncovered))
    if not bal.get("rescanned"):
        warnings.append("balances.json was NOT taken with `rand sync --rescan` (BALANCES_RESCAN=0) — a stale note store could have read low")
    rand_carry = f"== Σ scanned ({len(scanned)} wallets, heights {bal['height_from']}..{bal['height_to']})"
else:
    need(E.get("NO_BALANCES"), f"no {bal_file or 'balances.json'} — run `balances` (the carry-over rule), or set NO_BALANCES=1 to cut from a hand-made list")
    rand_carry = "NOT checked against a scan (NO_BALANCES=1)"
    warnings.append("RAND allocs were not checked against scanned balances")
g["alloc"] = g["alloc"] + token_notes

# ── chain 21's state its own cut never carried (the header's OPEN 3–5): refused unless the operator
# drops it knowingly, each drop then named on the cut record's `drops:` line (checked in bash) ─────
sup = snap.get("supply") or {}
held = int(sup.get("multisig_rand_held", "0") or 0)
tv = (snap.get("treasury") or {}).get("vault") or []
tv_rand = sum(int(v["amount"]) for v in tv if int(v.get("asset", 0)) == 0)
tv_tokens = [v for v in tv if int(v.get("asset", 0)) != 0 and int(v["amount"])]
if held or tv_tokens:
    need(E.get("MULTISIG_NOT_CARRIED_OK") == "1",
         f"chain 21's multisig register holds {fmt(held)} RAND (the treasury's vault {fmt(tv_rand)}, other accounts {fmt(held - tv_rand)})"
         f"{' and token(s) ' + str(tv_tokens) if tv_tokens else ''} — no document says how a multisig account crosses a cut (OPEN 3): "
         f"set MULTISIG_NOT_CARRIED_OK=1 to drop it (chain 22's treasury is TREASURY's, new issuance) and name it on the record's drops: line")
    warnings.append(f"NOT carried (MULTISIG_NOT_CARRIED_OK=1): chain 21's multisig register, {fmt(held)} RAND (treasury vault {fmt(tv_rand)})"
                    f"{', tokens ' + str(tv_tokens) if tv_tokens else ''}")
pp = snap.get("perps") or {}
pacc = (snap.get("perp_accounts") or {}).get("accounts") or []
p_busy = {"accounts": int(pp.get("accounts", 0) or 0), "listed accounts": len(pacc),
          "pending_withdrawals": int(pp.get("pending_withdrawals", 0) or 0),
          "collateral_held": int(pp.get("collateral_held", "0") or 0), "collateral_in": int(pp.get("collateral_in", "0") or 0)}
if any(p_busy.values()):
    need(E.get("PERPS_STATE_NOT_CARRIED_OK") == "1",
         f"chain 21's perps exchange is not empty ({', '.join(f'{k} {v}' for k, v in p_busy.items() if v)}; the collateral counters count "
         f"only since the v0.8.2 roll) — chain 22's engine starts from genesis-state and no carry is designed (OPEN 4): set "
         f"PERPS_STATE_NOT_CARRIED_OK=1 to drop it, re-issue its zUSD through ZUSD_CARRY (OPEN 5), and name it on the record's drops: line")
    warnings.append(f"NOT carried (PERPS_STATE_NOT_CARRIED_OK=1): chain 21's perps exchange — " + ", ".join(f"{k} {v}" for k, v in p_busy.items() if v)
                    + (f"; account ids {', '.join(str(a.get('account', '?'))[:12] + '…' for a in pacc)} (their collateral and positions are engine state, not served by the ledger)" if pacc else ""))
prog = int(sup.get("program_rand_held", "0") or 0)
if prog:
    need(E.get("PROGRAM_VAULTS_DROPPED_OK") == "1",
         f"chain 21's RPL-2 program vaults hold {fmt(prog)} RAND — program state is not carried (chain 21's record dropped it): set "
         f"PROGRAM_VAULTS_DROPPED_OK=1 to drop it and name it on the record's drops: line")
    warnings.append(f"NOT carried (PROGRAM_VAULTS_DROPPED_OK=1): {fmt(prog)} RAND in chain 21's program vaults")

# ── staking: chain 21's (the entry budget in basis points, admission by vote); no slashing ──────
s21 = g21["staking"]
need("slashing" not in s21, "chain 21's staking has `slashing` — this script carries none")
if E.get("FAUCET_RECIPIENTS"):
    recipients = [l.split()[-1] for l in open(E["FAUCET_RECIPIENTS"]) if l.strip() and not l.startswith("#")]
    need(recipients and all(r.startswith("rand1") for r in recipients) and len(set(recipients)) == len(recipients),
         "FAUCET_RECIPIENTS: rand1… addresses, each once")
    need(recipients == s21["faucet_recipients"] or E.get("FAUCET_RECIPIENTS_CHANGED"),
         f"the faucet allowlist differs from chain 21's ({len(s21['faucet_recipients'])} → {len(recipients)}) "
         f"— set FAUCET_RECIPIENTS_CHANGED=1 if that is the decision")
    if recipients != s21["faucet_recipients"]:
        warnings.append(f"faucet allowlist changed from chain 21's ({len(s21['faucet_recipients'])} → {len(recipients)})")
else:
    recipients = s21["faucet_recipients"]
vals = {v["name"]: v for v in json.load(open(os.path.join(E["TMP"], "validators.json")))}
minters = []
for name in E["FAUCET_MINTERS"].split():
    need(name in vals, f"FAUCET_MINTERS names {name}, not a chain-22 validator")
    minters.append(vals[name]["address"])
need(minters and len(set(minters)) == len(minters), "faucet_minters empty or a key twice")
need(minters == s21["faucet_minters"] or E.get("FAUCET_MINTERS_CHANGED"),
     "faucet_minters differ from chain 21's (set FAUCET_MINTERS_CHANGED=1 if that is the decision)")
need(s21.get("max_stake_entry_bps_per_epoch") == 2500 and s21.get("admission_by_vote") is True
     and "max_stake_entry_per_epoch" not in s21, "chain 21's staking is not the 2500-bps budget with admission by vote")
staking = dict(s21)
staking.update(faucet_recipients=recipients, faucet_minters=minters,
               max_stake_entry_bps_per_epoch=int(E["STAKE_ENTRY_BPS"]), admission_by_vote=True)
g["staking"] = staking
g["consensus_domain"] = 1

# ── the new section: perps, spliced here beside zUSD — `rand-node genesis --perps` cannot write it
# (collateral_asset 1 names a token the base file does not list yet; see the header) ─────────────
need("perps" not in g, "the base file already has a perps section — this script splices it, after zUSD (`rand-node genesis --perps` "
     "refuses collateral_asset 1 on a base file that lists no token)")
perps_file = os.path.join(E["TMP"], "perps.json")
if not E.get("PERPS_SKIPPED"):
    need(os.path.isfile(perps_file), "no perps section to splice ($TMP/perps.json) — the genesis-root step did not run")
    g["perps"] = json.load(open(perps_file))
else:
    need(not os.path.isfile(perps_file), "PERPS_SKIPPED yet a perps section is present ($TMP/perps.json) — the genesis-root step ran")

order = ["chain_id", "timestamp_ms", "validators", "alloc", "faucet", "confidential", "fri_profile",
         "hc_bundle", "bridge", "tokens", "aggregation", "consensus_domain", "staking", "epoch_blocks",
         "max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes",
         "max_program_public_words", "envelope_bytes", "vesting", "hardening_v6", "hc_auth", "gas",
         "testnet", "binding_domain", "proof_window_blocks", "program_state", "fees", "perps", "multisig",
         "hc_auth_multisig"]   # Genesis's last field (712c6336): a file that has it lists it last
unknown = [k for k in g if k not in order]
need(not unknown, f"the genesis command wrote fields this script does not know: {unknown}")
g = {k: g[k] for k in order if k in g}

# ── assertions over the bytes that ship ───────────────────────────────────────────────────────
need(g["chain_id"] == int(E["CHAIN_ID"]) == 22, f"chain_id is {g['chain_id']}")
need(g.get("hardening_v6") is True, "hardening_v6 is not true — --hardening-v6 did not take")
need(g["hc_bundle"] == E["HC_REPORTED"], "hc_bundle is not what this rand-node reports")
need(g["hc_bundle"] == g21["hc_bundle"] == E["EXPECT_HC_BUNDLE"], f"hc_bundle {g['hc_bundle']} is not chain 21's bundle guest v3")
need(g.get("hc_auth") == g21.get("hc_auth") == E["EXPECT_HC_AUTH"], f"hc_auth {g.get('hc_auth')} is not chain 21's auth guest")
need(g["faucet"] is True and g["confidential"] is True and g["fri_profile"] == "production", "faucet/confidential/fri_profile wrong")
need("aggregation" not in g, "an aggregation section is present — none belongs in chain 22")
need("vesting" not in g, "a vesting section is present — none belongs in chain 22")
need(g.get("envelope_bytes") == int(E["ENVELOPE_BYTES"]) == 1860 == g21.get("envelope_bytes"), f"envelope_bytes is {g.get('envelope_bytes')!r}, not 1860")
for i, n in enumerate(g["alloc"]):
    size = sum(len(v) // 2 for v in n["envelope"].values())
    need(size == 1860, f"alloc note {i}'s envelope is {size} B, not 1860 — sealed in the legacy format (alloc-note without --envelope-bytes?)")
# ── chain 21's fees section (docs/fees.md §1.3), burn_base + burn_floor, never the subsidy ─────────
fees_section = g.get("fees")
need(not (fees_section or {}).get("subsidy_net_of_fees"),
     "fees.subsidy_net_of_fees is set — it needs an aggregation section, and this build refuses a genesis with one "
     "at startup until the admitted shape is re-measured against the hidden-asset bundle (b053a76); chain 22 "
     "carries chain 21's burn_base and burn_floor only")
want_fees = json.loads(E["FEES_JSON"])
same_json = lambda a, b: json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)   # 1 is not true
need(same_json(want_fees, {"burn_base": True, "burn_floor": True}), f"FEES_JSON is {want_fees!r}, not chain 21's {{burn_base: true, burn_floor: true}}")
need(same_json(fees_section, want_fees) and same_json(fees_section, g21["fees"]),
     f"fees is {fees_section!r}, not chain 21's {{'burn_base': True, 'burn_floor': True}} — --fees did not take")
# ── perps (docs/perps.md): chain 21's section, plus the new audit-v10 fields ─────────────────────────
PERPS_DECIDED = {"collateral_asset": 1, "max_tier": 18, "max_window_blocks": 64, "max_block_inputs": 24, "min_deposit": 100000000,
                 "markets": [{"id": 0, "symbol": "BTC-PERP", "lot": 100000, "tick": 100000000, "max_leverage": 20,
                              "maintenance_bps": 250, "taker_fee_bps": 5, "maker_fee_bps": 2}]}
ENGINE_HC_DECIDED = "f286a61171e274278ec8d18d7853e5f36799ed8dc5a3e31e0077ad89ef1d1573"
V10_FIELDS = ("bound_payouts", "sparse_windows", "max_window_heights", "engine_program_log_height")
need(same_json(json.loads(E["PERPS_JSON"]), PERPS_DECIDED), "PERPS_JSON is not chain 21's perps section (BTC-PERP on zUSD, 20x / 250 bps, tier 18, 24 inputs)")
need(same_json(json.loads(E["PERPS_V10_JSON"]), {"bound_payouts": True, "sparse_windows": True}),
     "PERPS_V10_JSON is not the decided {bound_payouts: true, sparse_windows: true} (PERP-6, PERP-101)")
need(E["EXPECT_ENGINE_PROGRAM_LOG_HEIGHT"] == "14", f"EXPECT_ENGINE_PROGRAM_LOG_HEIGHT is {E['EXPECT_ENGINE_PROGRAM_LOG_HEIGHT']}, not the pinned engine's 14")
p21 = g21["perps"]
need(same_json({k: v for k, v in p21.items() if k not in ("engine_hc", "genesis_root")}, PERPS_DECIDED) and p21["engine_hc"] == ENGINE_HC_DECIDED,
     "chain 21's genesis perps section is not the decided one (CHAIN21_GENESIS?)")
perps = g.get("perps")
v10_skipped = bool(E.get("AUDIT_V10_SKIPPED"))
if E.get("PERPS_SKIPPED"):
    need(perps is None, "PERPS_SKIPPED yet a perps section is present")
    warnings.append("PERPS SKIPPED — no PERP_PROVER for the engine's genesis root; the real cut refuses that; this file is NOT "
                    "what chain 22 will be")
else:
    need(perps is not None, "no perps section in the finished file — the splice did not take")
    want_keys = set(PERPS_DECIDED) | {"engine_hc", "genesis_root"} | (set() if v10_skipped else set(V10_FIELDS))
    need(set(perps) == want_keys, f"perps carries the fields {sorted(perps)}, not {sorted(want_keys)}"
         + (" — initial_collateral is for a seeded engine; chain 22's starts from genesis-state (OPEN 4)" if "initial_collateral" in perps else ""))
    need(perps["collateral_asset"] == 1, f"perps.collateral_asset is {perps['collateral_asset']!r}, not 1 (zUSD) — chain 21's zUSD collateral")
    toks = g["tokens"]["tokens"]
    need(len(toks) >= 1 and toks[0]["symbol"] == "zUSD", "tokens.tokens[0] is not zUSD — collateral_asset 1 (FIRST_TOKEN_INDEX) would name another token")
    need(len(perps["markets"]) == 1, f"perps lists {len(perps['markets'])} markets — chain 22 has chain 21's one, BTC-PERP")
    for m in perps["markets"]:
        need(m["max_leverage"] >= 1 and m["maintenance_bps"] * m["max_leverage"] < 10000,
             f"market {m['symbol']}: maintenance {m['maintenance_bps']} bps is at or above the initial margin {10000 // max(m['max_leverage'], 1)} bps "
             f"that {m['max_leverage']}x implies (perp-core: ⌈notional / max_leverage⌉) — a max-leverage position would open liquidatable")
    need(perps["max_tier"] == 18, f"perps.max_tier is {perps['max_tier']!r}, not 18 (the production sizing)")
    need(perps["max_block_inputs"] == 24, f"perps.max_block_inputs is {perps['max_block_inputs']!r}, not 24 — the production sizing at tier 18 "
         f"(durian.market's gated case block-24-14liq); nothing measured more")
    need(perps["engine_hc"] == E["EXPECT_ENGINE_HC"] == ENGINE_HC_DECIDED == p21["engine_hc"],
         f"perps.engine_hc {perps['engine_hc']} is not the pinned engine {ENGINE_HC_DECIDED} (durian.market artifacts/perp-engine.image.bin)")
    need(re.fullmatch(r"[0-9a-f]{64}", E.get("PERP_GENESIS_ROOT", "")) and perps["genesis_root"] == E["PERP_GENESIS_ROOT"],
         f"perps.genesis_root {perps['genesis_root']} is not the root this cut derived ({E.get('PERP_GENESIS_ROOT') or 'none'}) from the markets")
    need(perps["genesis_root"] == p21["genesis_root"] or E.get("FIXTURE_ROOT_OK") == "1",
         f"perps.genesis_root {perps['genesis_root']} is not chain 21's {p21['genesis_root']} — the same markets on the same engine must give "
         f"the same root (another perp-prover state layout?)")
    need(same_json({k: v for k, v in perps.items() if k not in ("engine_hc", "genesis_root") + V10_FIELDS}, PERPS_DECIDED),
         f"perps is not chain 21's section: {sorted(k for k in PERPS_DECIDED if not same_json(perps.get(k), PERPS_DECIDED[k]))} differ")
    # the new fields (PERP-6, PERP-101, CON-60), each at its value on the finished file
    if v10_skipped:
        warnings.append("AUDIT_V10 SKIPPED — no bound_payouts / sparse_windows / max_window_heights / engine_program_log_height in perps; "
                        "the real cut refuses such a build; this file is NOT what chain 22 will be")
    else:
        need(perps.get("bound_payouts") is True, f"perps.bound_payouts is {perps.get('bound_payouts')!r}, not true (PERP-6)")
        need("initial_collateral" not in perps, "perps.initial_collateral is set — chain 22's engine is fresh (genesis-state), so it is absent (OPEN 4)")
        need(perps.get("sparse_windows") is True, f"perps.sparse_windows is {perps.get('sparse_windows')!r}, not true (PERP-101)")
        mwh = perps.get("max_window_heights")
        need(type(mwh) is int and str(mwh) == E.get("PERPS_MAX_WINDOW_HEIGHTS") and perps["max_window_blocks"] <= mwh <= 4096,
             f"perps.max_window_heights is {mwh!r}, not PERPS_MAX_WINDOW_HEIGHTS {E.get('PERPS_MAX_WINDOW_HEIGHTS')!r} in "
             f"max_window_blocks..=4096 (OPEN 1)")
        eplh = perps.get("engine_program_log_height")
        need(type(eplh) is int and eplh == int(E["EXPECT_ENGINE_PROGRAM_LOG_HEIGHT"]) and str(eplh) == E.get("ENGINE_PROGRAM_LOG_HEIGHT"),
             f"perps.engine_program_log_height is {eplh!r}, not the pinned engine's {E['EXPECT_ENGINE_PROGRAM_LOG_HEIGHT']} as `rand perp image-hc` "
             f"printed it ({E.get('ENGINE_PROGRAM_LOG_HEIGHT') or 'nothing'}) (CON-60)")
        need(list(perps)[-4:] == list(V10_FIELDS), f"perps lists the new fields out of PerpsConfig's order: {list(perps)}")
    # what Genesis::validate requires of a perps chain (`init` refuses the file without them too);
    # binding_domain 1, which perp signatures bind to, is asserted with chain 21's fields below.
    need(g["confidential"] is True and g.get("tokens") is not None and g.get("gas") is not None and g.get("hardening_v6") is True
         and bool(g.get("hc_auth")), "perps needs confidential, tokens, gas, hardening_v6 and hc_auth")
# ── multisig (docs/multisig.md): chain 21's create fee and one treasury, plus max_accounts ──────────
ms = g.get("multisig")
need(ms is not None, "no multisig section — --multisig did not take")
need(E["MULTISIG_CREATE_FEE"] == "1000000000" == g21["multisig"]["create_fee"], f"MULTISIG_CREATE_FEE is {E['MULTISIG_CREATE_FEE']}, not chain 21's 1000000000 (1 RAND)")
need(ms.get("create_fee") == "1000000000",
     f"multisig.create_fee is {ms.get('create_fee')!r}, not \"1000000000\" (1 RAND, chain 21's; a create_fee of 0 is refused at this cut)")
accts = ms.get("accounts") or []
need(len(accts) == 1, f"multisig seeds {len(accts)} account(s) — chain 22 seeds one, the treasury")
a = accts[0]
a21 = g21["multisig"]["accounts"][0]
need(a.get("threshold") == int(E["TREASURY_THRESHOLD"]) == 2 == a21["threshold"], f"the treasury's threshold is {a.get('threshold')!r}, not 2 (2 of 3)")
need(len(a.get("signers", [])) == int(E["TREASURY_SIGNERS"]) == 3, f"the treasury lists {len(a.get('signers', []))} signer(s), not 3 (2 of 3)")
need(len(set(a["signers"])) == 3, "a treasury signer is listed twice")
need(not set(a["signers"]) & {v["public_key"] for v in g["validators"]}, "a treasury signer is a validator's key")
need(a["signers"] == a21["signers"] or E.get("TREASURY_SIGNERS_CHANGED") == "1" or E.get("TREASURY_ROTATED") == "1",
     "the treasury's signers are not chain 21's, in chain 21's order (TREASURY_SIGNERS_CHANGED=1 / TREASURY_ROTATED=1)")
need(a["salt"] != a21["salt"], "the treasury salt is chain 21's — every cut draws a fresh one")
want_ms = json.load(open(os.path.join(E["TMP"], "multisig.json")))
tb = open(os.path.join(E["TMP"], "treasury-balance")).read().strip()
need(str(a.get("balance")) == tb and int(tb) > 0,
     f"the treasury balance {a.get('balance')!r} units is not TREASURY's {tb} — the units trap (1 RAND = 10^9 units)?")
need(same_json(ms, want_ms), "the multisig section is not the file this cut wrote ($TMP/multisig.json: salt, signers in order, balance, max_accounts)")
treasury_units = int(a["balance"])
if v10_skipped:
    need("max_accounts" not in ms, "AUDIT_V10_SKIPPED yet multisig.max_accounts is present")
else:
    cap = ms.get("max_accounts")
    need(type(cap) is int and str(cap) == E.get("MULTISIG_MAX_ACCOUNTS") and cap >= len(accts),
         f"multisig.max_accounts is {cap!r}, not MULTISIG_MAX_ACCOUNTS {E.get('MULTISIG_MAX_ACCOUNTS')!r} (≥ {len(accts)}, the seeded treasury counts; OPEN 2)")
    need(list(ms) == ["create_fee", "accounts", "max_accounts"], f"the multisig section lists {list(ms)}, not MultisigConfig's order")
# ── chain 21's hc_auth_multisig (private multisig), on the finished file ──────────────────────────
need(E["EXPECT_HC_AUTH_MULTISIG"] == "9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247" == g21["hc_auth_multisig"],
     f"EXPECT_HC_AUTH_MULTISIG is {E['EXPECT_HC_AUTH_MULTISIG']}, not chain 21's multisig auth guest (MSAUTH_HC)")
need("hc_auth_multisig" in g, "no hc_auth_multisig — --auth-multisig-guest did not take")
need(bool(g.get("hc_auth")), "hc_auth_multisig needs hc_auth (the multisig auth guest authorises bundle guest v3's spends)")
need(g["hc_auth_multisig"].lower() != str(g.get("hc_auth")).lower(), "hc_auth_multisig must differ from hc_auth")
need(g["hc_auth_multisig"] == E["EXPECT_HC_AUTH_MULTISIG"], f"hc_auth_multisig {g['hc_auth_multisig']} is not this build's multisig auth guest "
     f"({E['EXPECT_HC_AUTH_MULTISIG']})")
need(E.get("HC_AUTH_MULTISIG_REPORTED", g["hc_auth_multisig"]) == g["hc_auth_multisig"],
     f"hc_auth_multisig {g['hc_auth_multisig']} is not what this rand-node wrote ({E.get('HC_AUTH_MULTISIG_REPORTED')})")
need(g["max_proof_bytes"] >= 4194304, f"max_proof_bytes {g['max_proof_bytes']} cannot hold a multisig auth proof (≥ 4194304, "
     f"the node's MSAUTH_MIN_PROOF_BYTES at production)")
# chain 21's top-level fields, each still asserted at its value
need(g.get("testnet") is True, f"testnet is {g.get('testnet')!r}, not true — --testnet did not take (a faucet beside a bridge on chain 22 needs it)")
need(g.get("binding_domain") == int(E["BINDING_DOMAIN"]) == 1, f"binding_domain is {g.get('binding_domain')!r}, not 1 — --binding-domain 1 did not take")
need(g.get("proof_window_blocks") == int(E["PROOF_WINDOW_BLOCKS"]) == 1024, f"proof_window_blocks is {g.get('proof_window_blocks')!r}, not 1024")
# program_state: chain 21's cell fee, plus the new refuse_panics (PST-1) unless AUDIT_V10_SKIPPED
need(E["PROGRAM_STATE_REFUSE_PANICS"] == "true", f"PROGRAM_STATE_REFUSE_PANICS is {E['PROGRAM_STATE_REFUSE_PANICS']!r}, not the decided true (PST-1)")
want_ps = {"cell_fee": int(E["PROGRAM_STATE_CELL_FEE"])} if v10_skipped else {"cell_fee": int(E["PROGRAM_STATE_CELL_FEE"]), "refuse_panics": True}
need(same_json(g.get("program_state"), want_ps),
     f"program_state is {g.get('program_state')!r}, not {want_ps!r} — --program-state-cell-fee"
     f"{'' if v10_skipped else ' / --program-state-refuse-panics'} did not take")
if v10_skipped:
    warnings.append("AUDIT_V10 SKIPPED — no program_state.refuse_panics (PST-1) and no multisig.max_accounts (MSA-4); this file is NOT what chain 22 will be")
need(int(E["PROGRAM_STATE_CELL_FEE"]) == 10000000 == g21["program_state"]["cell_fee"], "the program_state cell fee is not docs/program-state.md's 10000000 (0.01 RAND), chain 21's")
# the new tokens switch (TOK-1): incremental_root true, written by --tokens-incremental-root
need(E["TOKENS_INCREMENTAL_ROOT"] == "true", f"TOKENS_INCREMENTAL_ROOT is {E['TOKENS_INCREMENTAL_ROOT']!r}, not the recommended true")
need(g["tokens"].get("incremental_root") is True,
     f"tokens.incremental_root is {g['tokens'].get('incremental_root')!r}, not true — --tokens-incremental-root did not take")
# the gas section: chain 21's, its ceilings and paying byte load included
need(g.get("gas") is not None, "the gas section is missing — --gas-price did not take")
gas = g["gas"]
need(int(gas["gas_price"]) == int(E["GAS_PRICE"]) and int(gas["byte_price"]) == int(E["BYTE_PRICE"]),
     f"gas prices are {gas['gas_price']}/{gas['byte_price']}, expected {E['GAS_PRICE']}/{E['BYTE_PRICE']}")
need(int(gas["bundle_gas_limit"]) == int(E["BUNDLE_GAS_LIMIT"]) == 20479, f"bundle_gas_limit is {gas['bundle_gas_limit']}, not gas_max(14, 0, 0) = 20479")
need(gas.get("metering") == "circuit", f"gas.metering is {gas.get('metering')!r}")
need(gas.get("dynamic") is not None, "gas.dynamic is missing — --gas-dynamic did not take (Phase 2 is off)")
dyn = gas["dynamic"]
want_bytes, want_gas, want_bps = (int(x) for x in E["GAS_DYNAMIC"].split(","))
need(int(dyn["target_block_bytes"]) == want_bytes and int(dyn["target_block_gas"]) == want_gas and int(dyn["adjust_bps"]) == want_bps,
     f"gas.dynamic targets are {dyn}, expected {E['GAS_DYNAMIC']}")
need(int(dyn["target_block_bytes"]) * 2 == int(E["MAX_BLOCK_BYTES"]) == g["max_block_bytes"],
     f"target_block_bytes {dyn['target_block_bytes']} is not half max_block_bytes {g['max_block_bytes']}")
need(int(dyn["min_gas_price"]) == int(E["GAS_PRICE"]) and int(dyn["min_byte_price"]) == int(E["BYTE_PRICE"]),
     "gas.dynamic's floors are not the section's own starting prices")
need(str(dyn.get("max_gas_price")) == E["MAX_GAS_PRICE"] == "10000", f"gas.dynamic.max_gas_price is {dyn.get('max_gas_price')!r}, not \"10000\" — --max-gas-price did not take")
need(str(dyn.get("max_byte_price")) == E["MAX_BYTE_PRICE"] == "80000", f"gas.dynamic.max_byte_price is {dyn.get('max_byte_price')!r}, not \"80000\" — --max-byte-price did not take")
need(dyn.get("byte_load") == E["GAS_BYTE_LOAD"] == "paying", f"gas.dynamic.byte_load is {dyn.get('byte_load')!r}, not \"paying\" — --gas-byte-load paying did not take")
# chain 21's section but for the byte target, which follows chain 22's max_block_bytes (half of it,
# asserted above): 9961472 at the 19 MiB both chains decide.
want_gas_section = copy.deepcopy(g21["gas"])
want_gas_section["dynamic"]["target_block_bytes"] = g["max_block_bytes"] // 2
need(gas == want_gas_section or E.get("GAS_CHANGED"), f"the gas section {gas} is not chain 21's {want_gas_section} (GAS_CHANGED=1 if intended)")
# the staking section
st = g["staking"]
need(st.get("admission_by_vote") is True, "staking.admission_by_vote is not true")
need(st.get("max_stake_entry_bps_per_epoch") == int(E["STAKE_ENTRY_BPS"]) == 2500, f"staking.max_stake_entry_bps_per_epoch is {st.get('max_stake_entry_bps_per_epoch')!r}, not 2500")
need("max_stake_entry_per_epoch" not in st, "staking still carries the fixed max_stake_entry_per_epoch (refused beside the bps budget)")
need("slashing" not in st, "staking.slashing is present — recommended only once stake is held by more than one operator (docs/deploy.md, D8)")
# the bridge rotation rules (chain 21's)
need(g["bridge"].get("rotation") == {"delay_secs": 86400, "needs_possession": True} == b21.get("rotation"), f"bridge.rotation is {g['bridge'].get('rotation')!r}, not chain 21's {{delay_secs: 86400, needs_possession: true}}")
# the zUSD bridge fees (docs/bridge.md §25), chain 21's, recipient included
fees = g["bridge"].get("fees") or {}
need(E.get("FEE_RECIPIENT", "").startswith("rand1"), "FEE_RECIPIENT is unset — load_fee_recipient did not run")
need(fees == {"mint_bps": 10, "burn_bps": 10, "recipient": E["FEE_RECIPIENT"]},
     f"bridge.fees is {({k: (v if k != 'recipient' else v[:12] + '…') for k, v in fees.items()})!r}, not {{mint_bps: 10, burn_bps: 10, recipient: <FEE_RECIPIENT>}}")
payouts = {v["payout"] for v in g["validators"]}
need(fees["recipient"] not in payouts or E.get("FEE_RECIPIENT_IS_PAYOUT_OK"),
     "bridge.fees.recipient is a validator's payout address — docs/deploy.md: a dedicated key, never a validator's (FEE_RECIPIENT_IS_PAYOUT_OK=1 to accept)")
need(fees == b21.get("fees") or E.get("FEE_RECIPIENT_CHANGED"),
     "bridge.fees is not chain 21's (deploy/genesis-chain21.json) — FEE_RECIPIENT_CHANGED=1 only for a knowingly new recipient")
if fees["recipient"] in {a for _, a, _ in alloc}:
    warnings.append("the bridge fee recipient is also a carried RAND wallet (an alloc) — its viewing key sees every fee note")
need(g["epoch_blocks"] == int(E["EPOCH_BLOCKS"]) == g21["epoch_blocks"], "epoch_blocks is not chain 21's")
need(len(g["validators"]) == 26 and all(v["stake"] == int(E["STAKE_RAND"]) * 10**9 for v in g["validators"]), "validators wrong")
need([v["public_key"] for v in g["validators"]] == [vals[n]["public_key"] for n in vals], "validator order/keys wrong")
for i, n in enumerate(g["alloc"]):
    need(n.get("opening") is not None, f"alloc note {i} has no opening (core I-2)")
need(sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 1) == locked_total, "Σ zUSD notes != Σ locked")
need(sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 0) == alloc_total, "Σ RAND notes != Σ alloc list")
# The treasury is new issuance beside the carry, never inside it: the carry rule above compares the
# notes alone; the supply bound counts notes, stakes and the register (Genesis::build's SupplyOverflow).
staked_total = sum(v["stake"] for v in g["validators"])
issued_total = alloc_total + staked_total + treasury_units
need(issued_total < 2**64, f"Σ RAND notes {alloc_total} + Σ stakes {staked_total} + treasury {treasury_units} = {issued_total} overflows a u64")
# chain 21's limits (6 MiB proofs — PENDING the measured production msauth proof — and 19 MiB blocks)
for k, want in (("max_program_words", "MAX_PROGRAM_WORDS"), ("max_proof_bytes", "MAX_PROOF_BYTES"),
                ("max_block_bytes", "MAX_BLOCK_BYTES"), ("max_call_envelope_bytes", "MAX_CALL_ENVELOPE_BYTES"),
                ("max_program_public_words", "MAX_PROGRAM_PUBLIC_WORDS")):
    need(g[k] == int(E[want]), f"{k} is {g[k]}")
    need(g[k] == g21[k] or E.get("LIMITS_CHANGED"), f"{k} {g[k]} differs from chain 21's {g21[k]} (LIMITS_CHANGED=1 if intended)")
need(g["max_block_bytes"] >= 3 * g["max_proof_bytes"] + 1048576,
     f"max_block_bytes {g['max_block_bytes']} < 3*max_proof_bytes + 1 MiB: a v3 Call carries three proofs")
# Outside the chain id, the clock, the carried notes, the bridge's burn sequence / floors, the zUSD
# backings' `locked`, the faucet lists, the treasury (salt, balance) and the new fields (asserted at
# their values above), every byte is chain 21's: gas, staking, bridge, tokens, perps, multisig and
# program_state are compared on their own lines below, the new fields taken out.
excused = {"chain_id", "timestamp_ms", "alloc", "bridge", "tokens", "staking", "gas", "perps", "multisig", "program_state"}
if E.get("LIMITS_CHANGED"):
    excused |= {"max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes", "max_program_public_words"}
moved = sorted(k for k in set(g) | set(g21) if k not in excused and g.get(k) != g21.get(k))
need(not moved, f"not chain 21's shape: {moved} differ from chain 21's genesis")
want_staking = s21
if not (E.get("FAUCET_RECIPIENTS_CHANGED") or E.get("FAUCET_MINTERS_CHANGED")):
    need(st == want_staking, f"staking is not chain 21's: "
         f"{sorted(k for k in set(st) | set(want_staking) if st.get(k) != want_staking.get(k))} differ")
bridge_moved = sorted(k for k in set(g["bridge"]) | set(b21)
                      if k not in ("burn_sequence", "min_inbound_sequence") and g["bridge"].get(k) != b21.get(k))
need(not bridge_moved or rotated or (bridge_moved == ["emitters"] and E.get("EMITTERS_CHANGED"))
     or (bridge_moved == ["fees"] and E.get("FEE_RECIPIENT_CHANGED")),
     f"bridge fields {bridge_moved} differ from chain 21's genesis (BRIDGE_ROTATED=1 carries a live rotation)")
strip_locked = lambda toks: [{**t, "backings": [{k: v for k, v in b.items() if k != "locked"} for b in t["backings"]]} for t in toks]
need({**{k: v for k, v in g["tokens"].items() if k != "incremental_root"}, "tokens": strip_locked(g["tokens"]["tokens"])}
     == {**g21["tokens"], "tokens": strip_locked(g21["tokens"]["tokens"])},
     "the tokens section differs from chain 21's in more than the backings' locked amounts and incremental_root")
# the sections that gain a field: chain 21's once the new field is taken out
if perps is not None:
    # genesis_root: asserted equal to chain 21's above (FIXTURE_ROOT_OK only for the selftest's fixture root)
    skip = V10_FIELDS + ("genesis_root",)
    need(same_json({k: v for k, v in perps.items() if k not in skip}, {k: v for k, v in p21.items() if k not in skip}),
         f"perps differs from chain 21's in more than the new fields: {sorted(k for k in set(perps) | set(p21) if k not in skip and not same_json(perps.get(k), p21.get(k)))}")
need(same_json({k: v for k, v in g["program_state"].items() if k != "refuse_panics"}, g21["program_state"]),
     "program_state differs from chain 21's in more than refuse_panics")
need(ms["create_fee"] == g21["multisig"]["create_fee"] and set(ms) - {"max_accounts"} == set(g21["multisig"])
     and set(a) == set(a21) and a["threshold"] == a21["threshold"],
     "multisig differs from chain 21's in more than max_accounts and the treasury's salt, balance (and, knowingly, signers)")
now_ms = int(time.time() * 1000)
need(g["timestamp_ms"] <= now_ms + 15_000, "timestamp_ms is in the future beyond the 15 s vote drift bound")

json.dump(g, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(f"cut-chain22: spliced bridge (set {g['bridge']['guardian_set_index']}, burn seq {g['bridge']['burn_sequence']}, floor {floor}, "
      f"emitters = chain 21's{' (CHANGED: ' + ','.join(changed) + ')' if changed else ''}, rotation {rotation}); "
      f"zUSD locked {locked_total} == notes {notes_total} == chain 21 supply == custody ({len(token_notes)} note(s)); "
      f"RAND allocs Σ {alloc_total} {rand_carry}; staking ({len(recipients)} recipients, {len(minters)} minters, entry 2500 bps, admission by vote, no slashing); "
      f"bridge fees {fees['mint_bps']}/{fees['burn_bps']} bps to {fees['recipient'][:10]}…; "
      f"testnet, binding_domain 1, proof_window_blocks 1024; gas {gas['gas_price']}/{gas['byte_price']} ceilings {dyn['max_gas_price']}/{dyn['max_byte_price']}, byte load {dyn['byte_load']}; "
      f"program_state {g['program_state']}; tokens.incremental_root {g['tokens'].get('incremental_root')}; fees {g.get('fees')}; hc_auth_multisig {g.get('hc_auth_multisig')}, "
      f"max_proof_bytes {g['max_proof_bytes']}, max_block_bytes {g['max_block_bytes']}; every other field equal to chain 21's genesis")
if perps:
    m = perps["markets"][0]
    print(f"cut-chain22: perps: {m['symbol']} on zUSD (asset 1), lot {m['lot']}, tick {m['tick']}, {m['max_leverage']}x, maintenance {m['maintenance_bps']} bps, "
          f"fees {m['taker_fee_bps']}/{m['maker_fee_bps']} bps; max_tier {perps['max_tier']}, {perps['max_block_inputs']} inputs a block, "
          f"{perps['max_window_blocks']} blocks a proof, min deposit {perps['min_deposit']}; engine {perps['engine_hc'][:12]}…, genesis root {perps['genesis_root']} "
          f"({'= chain 21' + chr(39) + 's' if perps['genesis_root'] == p21['genesis_root'] else 'FIXTURE_ROOT_OK: NOT chain 21' + chr(39) + 's'}); NEW: bound_payouts {perps.get('bound_payouts', 'SKIPPED')}, sparse_windows {perps.get('sparse_windows', 'SKIPPED')}, "
          f"max_window_heights {perps.get('max_window_heights', 'SKIPPED')}, engine_program_log_height {perps.get('engine_program_log_height', 'SKIPPED')}, "
          f"initial_collateral absent (0)")
if ms:
    print(f"cut-chain22: multisig: create fee {fmt(int(ms['create_fee']))} RAND, max_accounts {ms.get('max_accounts', 'SKIPPED')}; the treasury 2 of 3 "
          f"(chain 21's signers{'' if a['signers'] == a21['signers'] else ' — CHANGED'}), {fmt(treasury_units)} RAND NEW ISSUANCE "
          f"(not carried: Σ RAND notes {fmt(alloc_total)} == Σ scanned is the carry); issued at genesis: notes + stakes + treasury = {fmt(issued_total)} RAND")
print("cut-chain22: zUSD locked per backing: " + (", ".join(f"{b['chain']}:{b['token'][-8:]}={b['locked']}" for b in backings if b.get("locked")) or "none"))
for w in warnings:
    print(f"cut-chain22: ⚠ {w}")
PY
}

# ══ the field probe: the new fields are part of this rand-node's genesis hash ═══════════════════
# Copies of the finished file each without one new thing, every one still a valid genesis (each
# field is optional, with chain 21's meaning when absent): without `program_state.refuse_panics`,
# without `multisig.max_accounts`, without `perps.bound_payouts`, without `perps.sparse_windows`
# and `perps.max_window_heights` together (the second is refused without the first), with
# `perps.max_window_heights` at another value in range (it cannot be dropped alone), without
# `perps.engine_program_log_height`, and without `tokens.incremental_root`. Each must hash
# differently. A build that parses a field but leaves it out of the hash would launch a chain
# without that rule. Chain 21's fields are compared equal to deploy/genesis-chain21.json, whose hash
# this same rand-node re-derives (ca76c276…) — chain 21's own cut probed its sections. A field the
# dry run skipped (PERPS_SKIPPED, AUDIT_V10_SKIPPED) has no variant, and says so.
py_variants() {
  python3 - <<'PY'
import copy, json, os
E = os.environ
g = json.load(open(E["OUT"]))
d = os.path.join(E["TMP"], "variants"); os.makedirs(d)
n = 0
def variant(name, *paths, set_to=None):
    global n
    v = copy.deepcopy(g)
    for path in paths:
        cur = v
        for k in path[:-1]:
            cur = cur[k]
        if set_to is None:
            del cur[path[-1]]
        else:
            cur[path[-1]] = set_to
    json.dump(v, open(os.path.join(d, name + ".json"), "w"))
    n += 1
if "refuse_panics" in g["program_state"]:
    variant("program_state.refuse_panics", ["program_state", "refuse_panics"])
if "max_accounts" in g["multisig"]:
    variant("multisig.max_accounts", ["multisig", "max_accounts"])
p = g.get("perps") or {}
if "bound_payouts" in p:
    variant("perps.bound_payouts", ["perps", "bound_payouts"])
if "sparse_windows" in p:
    variant("perps.sparse_windows+max_window_heights", ["perps", "sparse_windows"], ["perps", "max_window_heights"])
    mwh = p["max_window_heights"]
    variant("perps.max_window_heights=" + str(mwh + 1 if mwh < 4096 else mwh - 1), ["perps", "max_window_heights"],
            set_to=mwh + 1 if mwh < 4096 else mwh - 1)
if "engine_program_log_height" in p:
    variant("perps.engine_program_log_height", ["perps", "engine_program_log_height"])
if "incremental_root" in g["tokens"]:
    variant("tokens.incremental_root", ["tokens", "incremental_root"])
open(os.path.join(d, "count"), "w").write(str(n))
PY
}

probe_fields() {   # <finished genesis> <its hash>
  local f name h ok=0 want
  [ -z "${PERPS_SKIPPED:-}" ] || echo "cut-chain22: ⚠ field probe of the perps fields SKIPPED — PERPS SKIPPED, the file has no perps section (DRY_RUN)" >&2
  [ -z "${AUDIT_V10_SKIPPED:-}" ] || echo "cut-chain22: ⚠ field probe of refuse_panics, max_accounts and the perps fields SKIPPED — AUDIT_V10 SKIPPED (DRY_RUN)" >&2
  py_variants
  want=$(cat "$TMP/variants/count")
  for f in "$TMP"/variants/*.json; do
    [ -e "$f" ] || continue
    name=$(basename "$f" .json)
    rm -rf "$TMP/vprobe"
    # Every variant is a valid genesis file, so init must accept each and derive another hash — a
    # refusal proves nothing about the hash and is refused here.
    h=$("$NODE" init --datadir "$TMP/vprobe" --genesis "$f" 2>"$TMP/vprobe.err" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p' || true)
    [ -n "$h" ] || { echo "cut-chain22: variant $name: init refused the file or printed no hash ($(tail -1 "$TMP/vprobe.err" | cut -c1-90)) — the probe needs a hash" >&2; exit 1; }
    [ "$h" != "$2" ] || { echo "cut-chain22: variant $name: this rand-node derives the SAME genesis hash — it does not hash that field (a build that predates it?)" >&2; exit 1; }
    echo "cut-chain22:   field probe: $name → genesis ${h:0:12}… (≠ ${2:0:12}…)"
    ok=$((ok + 1))
  done
  [ "$ok" -eq "$want" ] || { echo "cut-chain22: the field probe ran $ok variant(s), expected $want" >&2; exit 1; }
  [ -n "${PERPS_SKIPPED:-}${AUDIT_V10_SKIPPED:-}" ] || [ "$ok" -eq 7 ] \
    || { echo "cut-chain22: the field probe ran $ok variant(s), expected 7 (program_state.refuse_panics, multisig.max_accounts, perps.bound_payouts, perps.sparse_windows+max_window_heights, perps.max_window_heights at another value, perps.engine_program_log_height, tokens.incremental_root)" >&2; exit 1; }
  echo "cut-chain22: the new fields ($ok variants probed) are part of this rand-node's genesis hash"
}

# ══ check-limits: what a chain-22 node serves (after launch; DRY_RUN runs it on a loopback node) ═
py_check_limits() {
  python3 - <<'PY'
import json, os, sys, urllib.request
E = os.environ
url, gen = E["CHECK_RPC"], json.load(open(E["CHECK_GENESIS"]))
def rpc(method, params=None):
    req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(),
                                 {"content-type": "application/json", "user-agent": "rand-cut-chain22/1"})
    with urllib.request.urlopen(req, timeout=20) as r:
        out = json.load(r)
    if "error" in out:
        sys.exit(f"check-limits: {method}: {out['error']}")
    return out["result"]
bad = []
def want(what, got, exp):
    # JSON-typed comparison: Python's == would take 1 for true and 1.0 for 1
    same = json.dumps(got, sort_keys=True) == json.dumps(exp, sort_keys=True)
    print(f"check-limits:   {what:<34} {json.dumps(got)}{'' if same else '   ✗ expected ' + json.dumps(exp)}")
    if not same:
        bad.append(what)
want("rand_getGenesisHash", rpc("rand_getGenesisHash"), E["EXPECT_GENESIS_HASH"])
L = rpc("rand_getLimits")
S = rpc("rand_getSupply")
# the fees section, carried from chain 21: the fee rules, and nothing burned yet
# (BASE_FEES_BURNED_ANY=1 once bundles landed). The cut build serves every FeeRules field: the split
# and the dollar subsidy are unset on chain 22 (each needs an `aggregation` section), so each is null.
want("fee_rules", L.get("fee_rules"), {"burn_base": True, "subsidy_net_of_fees": False, "burn_floor": True,
                                       "proposer_share_bps": None, "prove_base": None, "usd_subsidy": None})
bfb = S.get("base_fees_burned")
if E.get("BASE_FEES_BURNED_ANY") == "1":
    want("base_fees_burned (a decimal string)", isinstance(bfb, str) and bfb.isdigit(), True)
    print(f"check-limits:   base_fees_burned is {bfb!r} (BASE_FEES_BURNED_ANY=1: any decimal accepted)")
else:
    want("base_fees_burned (at launch)", bfb, "0")
want("supply invariant_holds", S.get("invariant_holds"), True)
# perps — chain 21's bounds and market on the pinned engine, nothing proved yet (proved_height 0,
# proved_root == the genesis root: run it before the first state proof lands), plus the audit-v10
# fields (PERP-6 bound_payouts, PERP-101 sparse windows, CON-60 the program-height pin) and the
# collateral counters bound_payouts reads, all zero at launch (no initial_collateral: OPEN 4) — run
# it before the first deposit lands.
# Skipped only when the genesis file itself lacks them (a DRY_RUN that skipped) — never on the
# environment's word.
gp = gen.get("perps")
P = rpc("rand_getPerps")
if gp is None:
    want("perps limits (SKIPPED: absent)", L.get("perps"), None)
    want("rand_getPerps (SKIPPED: absent)", P, {"enabled": False})
    print("check-limits:   ⚠ PERPS SKIPPED — a real chain-22 node must serve perps (BTC-PERP on zUSD, tier 18, 24 inputs, bound_payouts, sparse windows)")
else:
    want("perps limits", L.get("perps"), {"collateral_asset": 1, "max_tier": 18, "max_window_blocks": 64, "max_payouts": 8,
                                          "max_block_inputs": 24, "min_deposit": "100000000"})
    want("perps enabled", P.get("enabled"), True)
    want("perps collateral_asset", P.get("collateral_asset"), 1)
    want("perps markets", P.get("markets"), [{"id": 0, "symbol": "BTC-PERP", "lot": 100000, "tick": 100000000, "max_leverage": 20,
                                              "maintenance_bps": 250, "taker_fee_bps": 5, "maker_fee_bps": 2}])
    want("perps engine_hc", P.get("engine_hc"), "f286a61171e274278ec8d18d7853e5f36799ed8dc5a3e31e0077ad89ef1d1573")
    want("perps genesis_root", P.get("genesis_root"), gp["genesis_root"])
    want("perps proved_root (at launch)", P.get("proved_root"), gp["genesis_root"])
    want("perps proved_height (at launch)", P.get("proved_height"), 0)
    want("perps accounts (at launch)", P.get("accounts"), 0)
    want("perps pending_withdrawals (at launch)", P.get("pending_withdrawals"), 0)
    if "bound_payouts" not in gp:
        print("check-limits:   ⚠ AUDIT_V10 SKIPPED — a real chain-22 node must serve bound_payouts true, sparse_windows true, "
              "max_window_heights (OPEN 1) and engine_program_log_height 14")
    want("perps bound_payouts (PERP-6)", P.get("bound_payouts"), gp.get("bound_payouts", False))
    want("perps initial_collateral", P.get("initial_collateral"), str(gp.get("initial_collateral", 0)))
    for k in ("collateral_in", "collateral_out", "collateral_held"):
        want(f"perps {k} (at launch)", P.get(k), "0")
    want("perps sparse_windows (PERP-101)", P.get("sparse_windows"), gp.get("sparse_windows", False))
    want("perps max_window_heights (PERP-101)", P.get("max_window_heights"), gp.get("max_window_heights", 0))
    want("perps engine_program_log_height (CON-60)", P.get("engine_program_log_height"), gp.get("engine_program_log_height", 0))
# multisig — the create fee, the treasury issued at genesis, and the account cap (MSA-4; absent from
# the served limits when the genesis has none, i.e. a DRY_RUN that skipped audit v10)
gm = gen["multisig"]
acct = gm["accounts"][0]
ml = {"create_fee": "1000000000", "max_signers": 10, "max_payouts": 4}
if "max_accounts" in gm:
    ml["max_accounts"] = gm["max_accounts"]
want("multisig limits (max_accounts MSA-4)", L.get("multisig"), ml)
want("multisig_issued (the treasury)", S.get("multisig_issued"), str(acct["balance"]))
M = rpc("rand_getMultisig", [E["TREASURY_ID"]]) or {}
want("treasury signers (file order)", M.get("signers"), acct["signers"])
want("treasury threshold", M.get("threshold"), 2)
# chain 21's fields, carried
want("proof_window_blocks", L.get("proof_window_blocks"), 1024)
want("binding_domain", L.get("binding_domain"), 1)
want("testnet", L.get("testnet"), True)
want("admission_by_vote", L.get("admission_by_vote"), True)
want("slashing", L.get("slashing"), None)
want("max_gas_price", L.get("max_gas_price"), "10000")
want("max_byte_price", L.get("max_byte_price"), "80000")
want("byte_load", L.get("byte_load"), "paying")
want("gas_metering", L.get("gas_metering"), "circuit")
want("bundle_gas_limit", L.get("bundle_gas_limit"), 20479)
want("adjust_bps", L.get("adjust_bps"), 1250)
want("envelope_bytes", L.get("envelope_bytes"), 1860)
want("hardening_v6", L.get("hardening_v6"), True)
want("max_proof_bytes", L.get("max_proof_bytes"), gen["max_proof_bytes"])
want("max_block_bytes", L.get("max_block_bytes"), gen["max_block_bytes"])
want("hc_auth", L.get("hc_auth"), gen["hc_auth"])
want("hc_auth_multisig", L.get("hc_auth_multisig"), gen["hc_auth_multisig"])
want("status hc_auth_multisig", (rpc("rand_status") or {}).get("hc_auth_multisig"), gen["hc_auth_multisig"])
ps = L.get("program_state") or {}
want("program_state.cell_fee", ps.get("cell_fee"), str(gen["program_state"]["cell_fee"]))
# PST-1's refuse_panics is served by no RPC (rand_getLimits.program_state is cell_fee and the three
# bounds): the genesis hash above, re-derived from a file that holds it and field-probed at the cut,
# is the only read-back.
if gen["program_state"].get("refuse_panics") is True:
    print("check-limits:   program_state.refuse_panics (PST-1)    not served — held by the genesis hash above (field-probed at the cut)")
else:
    print("check-limits:   ⚠ program_state.refuse_panics ABSENT from the genesis file (AUDIT_V10 SKIPPED) — a real chain-22 genesis has it")
T = rpc("rand_getTokens", [0, 1])
want("tokens incremental_root (TOK-1)", T.get("incremental_root"), gen["tokens"].get("incremental_root", False))
want("tokens bound_note_value", T.get("bound_note_value"), gen["tokens"].get("bound_note_value", False))
B = rpc("rand_getBridgeState")
want("bridge emitters", B.get("emitters"), gen["bridge"]["emitters"])
want("bridge min_inbound_sequence", {str(k): v for k, v in (B.get("min_inbound_sequence") or {}).items()}, gen["bridge"]["min_inbound_sequence"])
want("bridge burn_sequence", B.get("burn_sequence"), gen["bridge"]["burn_sequence"])
want("bridge rotation_rules", B.get("rotation_rules"), {"delay_secs": 86400, "needs_possession": True})
want("bridge fees", B.get("fees"), {"mint_bps": 10, "burn_bps": 10, "recipient": gen["bridge"]["fees"]["recipient"]})
if bad:
    sys.exit(f"check-limits: {url} does NOT serve chain 22 as cut: {', '.join(bad)}")
print(f"check-limits: {url} serves chain 22 as cut ({len(L)} limits read)")
PY
}

# The treasury's id, derived offline by NODE (`rand-node multisig id`) from a genesis file's
# `multisig.accounts[0]` and chain id; empty when the file has no multisig section.
treasury_id_of() {   # <genesis file>
  local a=()
  while IFS= read -r l; do a+=("$l"); done < <(python3 -c '
import json, sys
g = json.load(open(sys.argv[1])); m = g.get("multisig")
if m:
    a = m["accounts"][0]
    print("--chain-id"); print(g["chain_id"]); print("--salt"); print(a["salt"]); print("--threshold"); print(a["threshold"])
    for k in a["signers"]:
        print("--signer"); print(k)' "$1")
  [ "${#a[@]}" -gt 0 ] || return 0
  "$NODE" multisig id "${a[@]}"
}

check_limits() {   # <rpc url> <genesis file>
  local h d tid
  [ -f "$2" ] || { echo "check-limits: $2 is not a file" >&2; exit 1; }
  [ -x "$NODE" ] || { echo "check-limits: NODE=$NODE is not executable (it re-derives the genesis hash)" >&2; exit 1; }
  d=$(mktemp -d); h=$("$NODE" init --datadir "$d/p" --genesis "$2" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p' || true); rm -rf "$d"
  [ -n "$h" ] || { echo "check-limits: $NODE derived no genesis hash from $2" >&2; exit 1; }
  tid=$(treasury_id_of "$2")
  echo "check-limits: treasury id ${tid:-none (no multisig section)}"
  CHECK_RPC=$1 CHECK_GENESIS=$2 EXPECT_GENESIS_HASH=$h TREASURY_ID=$tid py_check_limits
}

if [ "${1:-}" = check-limits ]; then
  check_limits "${2:?check-limits <rpc url> <genesis file>}" "${3:?check-limits <rpc url> <genesis file>}"
  exit 0
fi

# ══ fixtures: synthetic inputs derived from the committed chain-21 genesis ═════════════════════
# FIXTURE_MODE=selftest (SELFTEST=1): the python steps alone; fake wallet addresses; the base file
# `rand-node genesis` would write faked too (with every flag's field, `fees` included).
# FIXTURE_MODE=dryrun (DRY_RUN=1): inputs the REAL binaries accept — the committed chain-21 genesis
# unchanged (its sha256 check passes), wallet lines at real addresses (chain 21's validator
# payouts), no base file. BOTH describe chain 21 as the cut expects to find it: its genesis bridge
# state unmoved (burn sequence 14; the four endpoints at their genesis floors 3/5/3/7 as next
# sequences), zUSD locked ETH-USDT 22 / BSC-USDT 23.001999 / Tron-USDT 30 / Sol-USDT 25 == custody,
# the register its 26 validators at 1 000 RAND; its treasury at its genesis signers and 100 000 RAND
# (a live chain 21 holds it — so the happy path sets MULTISIG_NOT_CARRIED_OK=1, as the real cut
# must, OPEN 3), the exchange empty and no RAND in program vaults. treasury.txt (both modes) lists
# chain 21's treasury signers — public keys, read from the committed genesis — at a PLACEHOLDER
# balance of 100 000 RAND (OPEN 3: the owner's).
py_fixtures() {
  python3 - <<'PY'
import copy, json, os, time
E = os.environ; st = E["ST"]; dry = E.get("FIXTURE_MODE") == "dryrun"
exec(E["UNITS_PY"])
g21 = json.load(open(E["CHAIN21_GENESIS"]))
os.makedirs(f"{st}/snap"); os.makedirs(f"{st}/reg"); os.makedirs(f"{st}/tmp")
gnames, bnames = E["GENESIS_NAMES"].split(), E["BONDED"].split()
names = gnames + bnames
assert len(names) == len(g21["validators"]) == 26
minters = g21["staking"]["faucet_minters"]
assert len(minters) == len(gnames)
addr = {n: (minters[i] if i < len(gnames) else f"FIXTUREaddr{i:02d}") for i, n in enumerate(names)}
with open(f"{st}/validators.tsv", "w") as f:
    for n, v in zip(names, g21["validators"]):
        if n in gnames:
            f.write(f"{n}\t{addr[n]}\t{v['public_key']}\tpeer\t{v['payout']}\n")
for n, v in zip(names, g21["validators"]):
    if n in bnames:
        pk = bytes.fromhex(v["public_key"])
        open(f"{st}/reg/{n}.txt", "w").write(f"validator {addr[n]} on chain 15\nregistration: {(len(pk).to_bytes(8, 'little') + pk + b'sig').hex()}\n")
if not dry:
    json.dump(g21, open(f"{st}/genesis-chain21.json", "w"))
b = g21["bridge"]; z = g21["tokens"]["tokens"][0]
total = sum(x.get("locked", 0) for x in z["backings"])
live = [{**{k: x[k] for k in ("chain", "token", "decimals")}, "locked": x.get("locked", 0)} for x in z["backings"]]
assert total == 10000199900, "chain 21's zUSD supply is 100.001999: ETH-USDT 22, BSC-USDT 23.001999, Tron-USDT 30, Sol-USDT 25"
a21 = g21["multisig"]["accounts"][0]
snap = {"taken_at": "dryrun" if dry else "selftest", "genesis_hash": E["CHAIN21_HASH"], "status_height": 50000,
        "validators": [{"address": addr[n], "stake": str(v["stake"]), "pending": [], "rewards": "0", "payout": v["payout"],
                        "nonce": 0, "active": True} for n, v in zip(names, g21["validators"])],
        "bridge": {**{k: b[k] for k in ("emitter", "emitters", "guardian_set_index", "guardians", "pq_guardians", "pause_key")},
                   "burn_sequence": b["burn_sequence"], "mint_paused": False, "registration_fee": str(g21["tokens"]["registration_fee"]),
                   "rules_v2": {"global_mint_cap_per_window": str(b["rules_v2"]["global_mint_cap_per_window"]), "cap_window_secs": b["rules_v2"]["cap_window_secs"]},
                   "min_inbound_sequence": b["min_inbound_sequence"]},
        "tokens": {"tokens": [{"index": 1, "symbol": "zUSD", "total_supply": str(total),
                               "authority": {"kind": "bridged", "backings": [{**x, "locked": str(x["locked"])} for x in live]}}]},
        "supply": {"multisig_issued": a21["balance"], "multisig_rand_held": a21["balance"], "program_rand_held": "0",
                   "perps_collateral_in": "0", "perps_collateral_out": "0", "perps_collateral_held": "0"},
        "perps": {"enabled": True, "accounts": 0, "pending_withdrawals": 0, "proved_height": 0,
                  "collateral_in": "0", "collateral_out": "0", "collateral_held": "0"},
        "perp_accounts": {"accounts": [], "next": None},
        "treasury": {"signers": a21["signers"], "threshold": a21["threshold"], "nonce": 0,
                     "vault": [{"asset": 0, "amount": a21["balance"]}]},
        "source": {"emitters": {c: E[f"EMITTER_{c}"] for c in "2345"},
                   "next_sequence": {c: int(b["min_inbound_sequence"][c]) for c in "2345"},
                   "custody": {f"{x['chain']}:{x['token']}": {"custody": x["locked"] * 10**x["decimals"] // 10**8 if x["decimals"] <= 8 else x["locked"] * 10**(x["decimals"] - 8), "fees": 0} for x in live}}}
json.dump(snap, open(f"{st}/snap/chain21-state.json", "w"))
rand_notes = [n for n in g21["alloc"] if n["opening"].get("asset", 0) == 0]
zusd_notes = [n for n in g21["alloc"] if n["opening"].get("asset", 0) == 1]
payouts = list(dict.fromkeys(v["payout"] for v in g21["validators"]))
assert len(payouts) >= len(rand_notes) + 1, "not enough distinct payout addresses for the dry-run carry"
wallets = [{"label": f"w{i}", "address": payouts[i] if dry else f"rand1SELFTEST{i}", "rand_units": n["amount"], "zusd_units": 0, "file": "-"}
           for i, n in enumerate(rand_notes)]
wallets.append({"label": "empty", "address": "rand1FIXTUREempty", "rand_units": 0, "zusd_units": 0, "file": "-"})
json.dump({"chain21_hash": E["CHAIN21_HASH"], "height_from": 50000, "height_to": 50000, "wallets": wallets,
           "uncovered_genesis_allocs": [], "rescanned": True}, open(f"{st}/snap/balances.json", "w"))
with open(f"{st}/alloc-rand.txt", "w") as f:
    f.write(f"# {'dry run' if dry else 'selftest'}\n")
    for w in wallets[:-1]:
        f.write(f"{w['label']} {w['address']} {fmt(w['rand_units'])}\n")
holder = payouts[len(rand_notes)] if dry else "rand1SELFTESTz"
open(f"{st}/zusd-carry.txt", "w").write("".join(f"holder {holder} {fmt(n['amount'], 8)}\n" for n in zusd_notes))
# A filled cut record (the fixture's — the real one is the operator's, published before the cut).
open(f"{st}/cut-record.txt", "w").write(
    "chain-id: 22\nreason: audit v11 gated fields — PST-1 refuse_panics, PERP-6 bound_payouts, PERP-101 sparse windows, CON-60, MSA-4 max_accounts\n"
    "carries: fixture register, bridge state, balances and the treasury signers (new issuance)\n"
    "drops: fixture: chain 21's multisig register (the treasury vault)\nclients: fixture: none\n"
    "second-operator: fixture\nrollback: fixture: keep chain 21 dirs and *.pre-c22 binaries a day\n")
# The treasury: chain 21's signers in chain 21's order, 2 of 3, a PLACEHOLDER balance (OPEN 3).
open(f"{st}/treasury.txt", "w").write(f"# {'dry run' if dry else 'selftest'} treasury: chain 21's signers, PLACEHOLDER balance (OPEN 3)\n"
                                      + "".join(f"signer s{i} {pk}\n" for i, pk in enumerate(a21["signers"], 1))
                                      + "threshold 2\nbalance 100000\n")
if dry:
    raise SystemExit(0)
# The perps section the cut writes after the genesis-root step (a fixture root).
d = json.loads(E["PERPS_JSON"])
v10 = json.loads(E["PERPS_V10_JSON"])
json.dump({**{k: d[k] for k in ("collateral_asset", "max_tier", "max_window_blocks", "max_block_inputs", "min_deposit")},
           "engine_hc": E["EXPECT_ENGINE_HC"], "genesis_root": E["PERP_GENESIS_ROOT"], "markets": d["markets"],
           "bound_payouts": v10["bound_payouts"], "sparse_windows": v10["sparse_windows"],
           "max_window_heights": int(E["PERPS_MAX_WINDOW_HEIGHTS"]), "engine_program_log_height": int(E["ENGINE_PROGRAM_LOG_HEIGHT"])},
          open(f"{st}/tmp/perps.json", "w"))
open(f"{st}/faucet-recipients-changed.txt", "w").write("someone rand1SELFTESTfaucetrecipientchanged\n")
with open(f"{st}/tmp/token-notes.jsonl", "w") as f:
    for n in zusd_notes:
        f.write(json.dumps(n) + "\n")
# what `rand-node genesis --hardening-v6 --bundle-guest v3 --auth-guest --gas-… --testnet
# --binding-domain 1 --proof-window-blocks 1024 --program-state-cell-fee … --program-state-refuse-panics
# --fees … --auth-multisig-guest --tokens-incremental-root` writes, before the splice
# (`--multisig`'s section is added by the selftest once py_treasury has written it)
base = {k: g21[k] for k in ("chain_id", "timestamp_ms", "validators", "faucet", "confidential", "fri_profile", "hc_bundle",
                           "epoch_blocks", "max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes",
                           "max_program_public_words", "envelope_bytes", "hardening_v6", "hc_auth")}
tb, tg, bps = (int(x) for x in E["GAS_DYNAMIC"].split(","))
base.update(chain_id=22, timestamp_ms=int(time.time() * 1000), alloc=rand_notes, hc_bundle=E["EXPECT_HC_BUNDLE"], hc_auth=E["EXPECT_HC_AUTH"],
            max_proof_bytes=int(E["MAX_PROOF_BYTES"]), max_block_bytes=int(E["MAX_BLOCK_BYTES"]),
            hc_auth_multisig=E["EXPECT_HC_AUTH_MULTISIG"],
            tokens={"registration_fee": g21["tokens"]["registration_fee"], "mint_cap_per_day": g21["tokens"]["mint_cap_per_day"],
                    "incremental_root": True, "tokens": []},
            gas={"gas_price": E["GAS_PRICE"], "byte_price": E["BYTE_PRICE"], "bundle_gas_limit": int(E["BUNDLE_GAS_LIMIT"]), "metering": "circuit",
                 "dynamic": {"target_block_bytes": tb, "target_block_gas": tg, "adjust_bps": bps,
                             "min_gas_price": E["GAS_PRICE"], "min_byte_price": E["BYTE_PRICE"],
                             "max_gas_price": E["MAX_GAS_PRICE"], "max_byte_price": E["MAX_BYTE_PRICE"], "byte_load": E["GAS_BYTE_LOAD"]}},
            testnet=True, binding_domain=int(E["BINDING_DOMAIN"]), proof_window_blocks=int(E["PROOF_WINDOW_BLOCKS"]),
            program_state={"cell_fee": int(E["PROGRAM_STATE_CELL_FEE"]), "refuse_panics": True}, fees=json.loads(E["FEES_JSON"]))
json.dump(base, open(f"{st}/base.json", "w"))
PY
}

# A fake chain-22 node for the selftest's check-limits: serves <file>'s {method: result} on loopback.
fake_rpc() {   # <answers.json> <port file>
  python3 - "$1" "$2" <<'PY' &
import json, sys, http.server, socketserver
answers, portfile = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["content-length"])))
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": json.load(open(answers)).get(req["method"])}).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
with socketserver.TCPServer(("127.0.0.1", 0), H) as s:
    open(portfile, "w").write(str(s.server_address[1]))
    s.serve_forever()
PY
  FAKE_RPC_PID=$!
  for _ in $(seq 1 50); do [ -s "$2" ] && return 0; sleep 0.1; done
  echo "selftest: the fake RPC did not start" >&2; return 1
}

# ══ SELFTEST: the python steps on fixtures derived from deploy/genesis-chain21.json ════════════
if [ "${SELFTEST:-}" = 1 ]; then
  ST=$(mktemp -d); FAKE_RPC_PID=; trap 'rm -rf "$ST"; [ -z "$FAKE_RPC_PID" ] || kill "$FAKE_RPC_PID" 2>/dev/null || true' EXIT
  FEE_RECIPIENT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bridge"]["fees"]["recipient"])' "$CHAIN21_GENESIS")   # chain 21's
  PERP_GENESIS_ROOT=$(printf 'ab%.0s' $(seq 32))   # a fixture root (the cut derives the real one with perp-prover)
  # Fixture values for the operator inputs and the derived pin (the cut reads the pin off the image);
  # the fixture root is not chain 21's, so FIXTURE_ROOT_OK; chain 21's treasury holds its genesis
  # balance (as the live one does), so MULTISIG_NOT_CARRIED_OK, as the real cut will need.
  PERPS_MAX_WINDOW_HEIGHTS=256 MULTISIG_MAX_ACCOUNTS=1 ENGINE_PROGRAM_LOG_HEIGHT=14
  TREASURY_SALT=$(printf '5a%.0s' $(seq 32))
  export ST FIXTURE_MODE=selftest FEE_RECIPIENT PERP_GENESIS_ROOT PERPS_MAX_WINDOW_HEIGHTS MULTISIG_MAX_ACCOUNTS ENGINE_PROGRAM_LOG_HEIGHT \
    TREASURY_SALT FIXTURE_ROOT_OK=1 MULTISIG_NOT_CARRIED_OK=1
  py_fixtures
  NEW_EMITTER=$(printf '0%.0s' $(seq 63))1
  export SNAPSHOT_FILE=$ST/snap/chain21-state.json BALANCES_FILE=$ST/snap/balances.json CHAIN21_GENESIS=$ST/genesis-chain21.json \
    VALIDATORS_TSV=$ST/validators.tsv REGISTRATIONS=$ST/reg ALLOC_ADDRESSES=$ST/alloc-rand.txt ZUSD_CARRY=$ST/zusd-carry.txt \
    TMP=$ST/tmp HC_REPORTED=$EXPECT_HC_BUNDLE
  pass=0; fail=0
  ok()  { echo "selftest: ok   — $1"; pass=$((pass+1)); }
  bad() { echo "selftest: FAIL — $1"; fail=$((fail+1)); }
  fresh() { cp "$ST/base.json" "$ST/out.json"; export OUT=$ST/out.json; }

  # The treasury: py_treasury writes the --multisig file; the base gets it as `rand-node genesis
  # --multisig` would write it (the section as given).
  export TREASURY=$ST/treasury.txt
  if py_validators >/dev/null && py_treasury >"$ST/log" 2>&1 && grep -q 'NEW ISSUANCE' "$ST/log" && grep -q 'max_accounts 1' "$ST/log"; then
    ok "the fixture treasury (chain 21's signers) parses: $(grep -o 'treasury: .*' "$ST/log" | head -1 | cut -c1-110)"
  else bad "the fixture treasury: $(tail -2 "$ST/log")"; fi
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); b["multisig"]=json.load(open(sys.argv[2])); json.dump(b, open(sys.argv[1],"w"))' "$ST/base.json" "$ST/tmp/multisig.json"

  fresh
  if py_validators && py_splice; then
    if python3 - <<'PY'
import json, os
E = os.environ
g = json.load(open(E["OUT"]))
g21 = json.load(open(E["CHAIN21_GENESIS"]))
assert g["chain_id"] == 22 and g["hc_auth"] == g21["hc_auth"] and g["hc_bundle"] == g21["hc_bundle"]
assert list(g) == list(g21), "every key chain 21 has, in chain 21's order — and no other"
assert g["fees"] == g21["fees"] == {"burn_base": True, "burn_floor": True}
assert g["hc_auth_multisig"] == g21["hc_auth_multisig"] == "9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247" != g["hc_auth"]
p = g["perps"]
assert list(p) == ["collateral_asset", "max_tier", "max_window_blocks", "max_block_inputs", "min_deposit", "engine_hc", "genesis_root", "markets",
                   "bound_payouts", "sparse_windows", "max_window_heights", "engine_program_log_height"], list(p)
assert {k: v for k, v in p.items() if k not in ("genesis_root", "bound_payouts", "sparse_windows", "max_window_heights", "engine_program_log_height")} \
    == {k: v for k, v in g21["perps"].items() if k != "genesis_root"}
assert p["genesis_root"] == "ab" * 32
assert p["bound_payouts"] is True and p["sparse_windows"] is True and p["max_window_heights"] == 256 and p["engine_program_log_height"] == 14
assert "initial_collateral" not in p
m = g["multisig"]
assert list(m) == ["create_fee", "accounts", "max_accounts"] and m["create_fee"] == g21["multisig"]["create_fee"] == "1000000000" and m["max_accounts"] == 1
a, a21 = m["accounts"][0], g21["multisig"]["accounts"][0]
assert a["threshold"] == 2 and a["signers"] == a21["signers"] and a["balance"] == str(100000 * 10**9) and a["salt"] == "5a" * 32 != a21["salt"]
assert g["program_state"] == {"cell_fee": 10000000, "refuse_panics": True}
assert g["tokens"] == {**g21["tokens"], "incremental_root": True}
assert g["testnet"] is True and g["binding_domain"] == 1 and g["proof_window_blocks"] == 1024
assert (g["max_proof_bytes"], g["max_block_bytes"]) == (g21["max_proof_bytes"], g21["max_block_bytes"]) == (6291456, 19922944)
assert g["gas"] == g21["gas"] and g["gas"]["dynamic"]["target_block_bytes"] == 9961472 and g["gas"]["dynamic"]["byte_load"] == "paying"
assert g["bridge"]["rotation"] == g21["bridge"]["rotation"] == {"delay_secs": 86400, "needs_possession": True}
assert g["bridge"]["fees"] == g21["bridge"]["fees"] and g["bridge"]["fees"]["mint_bps"] == g["bridge"]["fees"]["burn_bps"] == 10
assert list(g["bridge"]) == list(g21["bridge"])
assert g["bridge"]["emitters"] == g21["bridge"]["emitters"] and g["bridge"]["min_inbound_sequence"] == {"2": 3, "3": 5, "4": 3, "5": 7}
assert g["bridge"]["burn_sequence"] == 14 and g["bridge"]["guardian_set_index"] == g21["bridge"]["guardian_set_index"]
assert g["staking"] == g21["staking"] and g["staking"]["max_stake_entry_bps_per_epoch"] == 2500 and g["staking"]["admission_by_vote"] is True
assert "slashing" not in g["staking"] and "vesting" not in g and "aggregation" not in g
assert [(b["chain"], b["locked"]) for b in g["tokens"]["tokens"][0]["backings"] if "locked" in b] == [(2, 2200000000), (3, 2300199900), (4, 3000000000), (5, 2500000000)]
assert g["validators"] == g21["validators"] and g["consensus_domain"] == 1
assert sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 0) == sum(n["amount"] for n in g21["alloc"] if n["opening"].get("asset", 0) == 0)
assert sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 1) == 10000199900
assert all(sum(len(v) // 2 for v in n["envelope"].values()) == 1860 for n in g["alloc"])
PY
    then ok "the chain-21 fixture assembles into a chain-22 genesis: chain 21's keys in chain 21's order and every section chain 21's, plus program_state.refuse_panics true (PST-1), perps bound_payouts true (PERP-6), sparse_windows true + max_window_heights 256 (PERP-101), engine_program_log_height 14 (CON-60), no initial_collateral, multisig.max_accounts 1 (MSA-4), tokens.incremental_root true; the treasury chain 21's signers, fresh salt, 100000 RAND new issuance; floors 3/5/3/7, burn sequence 14, 100.001999 zUSD locked on four backings"; else bad "assembled genesis content"; fi
  else bad "the happy path refused"; fi
  cp "$ST/out.json" "$ST/good.json"

  export -f py_validators py_splice py_treasury py_variants
  # The field probe's variants (the probe itself needs a rand-node: DRY_RUN runs it): seven on the
  # finished file, each a different file, each still with chain 21's other fields.
  rm -rf "$ST/vtmp"; mkdir -p "$ST/vtmp"
  if OUT=$ST/good.json TMP=$ST/vtmp bash -c py_variants && [ "$(cat "$ST/vtmp/variants/count")" = 7 ] \
     && python3 - "$ST/vtmp/variants" "$ST/good.json" <<'PY'
import glob, json, os, sys
d, g = sys.argv[1], json.load(open(sys.argv[2]))
names = sorted(os.path.basename(f)[:-5] for f in glob.glob(d + "/*.json"))
assert names == sorted(["program_state.refuse_panics", "multisig.max_accounts", "perps.bound_payouts", "perps.sparse_windows+max_window_heights",
                        "perps.max_window_heights=257", "perps.engine_program_log_height", "tokens.incremental_root"]), names
v = json.load(open(d + "/perps.sparse_windows+max_window_heights.json"))
assert "sparse_windows" not in v["perps"] and "max_window_heights" not in v["perps"] and v["perps"]["bound_payouts"] is True
assert json.load(open(d + "/perps.max_window_heights=257.json"))["perps"]["max_window_heights"] == 257
for f in glob.glob(d + "/*.json"):
    x = json.load(open(f))
    assert x != g and set(x) == set(g), f
PY
  then ok "the field probe writes its 7 variants (refuse_panics, max_accounts, bound_payouts, sparse_windows+max_window_heights, max_window_heights 257, engine_program_log_height, incremental_root)"
  else bad "field probe variants: $(find "$ST/vtmp/variants" -name '*.json' 2>&1 | sed 's|.*/||' | tr '\n' ' ')"; fi

  # AUDIT_V10_SKIPPED (DRY_RUN's path on a build before v0.8.2): the base and the section files as
  # such a build and this script would write them — none of the new fields but incremental_root —
  # cut, and said; the same inputs without the skip are refused; the skip with the fields refused.
  for f in "$ST/base.json" "$ST/tmp/perps.json" "$ST/tmp/multisig.json"; do cp "$f" "$f.keep"; done
  AUDIT_V10_SKIPPED=1 bash -c 'py_treasury' >/dev/null 2>&1
  python3 - "$ST/base.json" "$ST/tmp/perps.json" "$ST/tmp/multisig.json" <<'PY'
import json, sys
b, p, m = (json.load(open(f)) for f in sys.argv[1:4])
del b["program_state"]["refuse_panics"]; b["multisig"] = m
for k in ("bound_payouts", "sparse_windows", "max_window_heights", "engine_program_log_height"):
    del p[k]
json.dump(b, open(sys.argv[1], "w")); json.dump(p, open(sys.argv[2], "w"))
PY
  fresh
  if AUDIT_V10_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 && grep -q 'AUDIT_V10 SKIPPED' "$ST/log" \
     && python3 -c 'import json,os; g=json.load(open(os.environ["OUT"])); assert "refuse_panics" not in g["program_state"] and "max_accounts" not in g["multisig"] and "bound_payouts" not in g["perps"] and g["tokens"]["incremental_root"] is True'; then
    ok "AUDIT_V10_SKIPPED=1 (DRY_RUN on a build before v0.8.2) cuts without refuse_panics / max_accounts / the perps fields, and says so"
    cp "$ST/out.json" "$ST/good-v10skipped.json"
  else bad "AUDIT_V10_SKIPPED path: $(tail -2 "$ST/log")"; fi
  fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "a file without the audit-v10 fields accepted when not skipped"
  elif grep -q 'perps carries the fields' "$ST/log"; then ok "the same inputs without AUDIT_V10_SKIPPED are refused ($(grep -o 'cut-chain22: .*' "$ST/log" | tail -1 | cut -c1-80))"
  else bad "no-v10 inputs: $(tail -1 "$ST/log")"; fi
  for f in "$ST/base.json" "$ST/tmp/perps.json" "$ST/tmp/multisig.json"; do mv "$f.keep" "$f"; done
  fresh
  if AUDIT_V10_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "AUDIT_V10_SKIPPED with the fields present accepted"
  elif grep -q 'perps carries the fields' "$ST/log"; then ok "AUDIT_V10_SKIPPED with the audit-v10 fields present is refused"
  else bad "AUDIT_V10_SKIPPED with the fields: $(tail -1 "$ST/log")"; fi
  rm -rf "$ST/vtmp"; mkdir -p "$ST/vtmp"
  if [ -f "$ST/good-v10skipped.json" ] && OUT=$ST/good-v10skipped.json TMP=$ST/vtmp bash -c py_variants && [ "$(cat "$ST/vtmp/variants/count")" = 1 ]; then
    ok "the field probe of an AUDIT_V10-skipped file has 1 variant (tokens.incremental_root)"
  else bad "field probe variants of the skipped file: $(cat "$ST/vtmp/variants/count" 2>&1)"; fi
  # PERPS_SKIPPED (DRY_RUN without PERP_PROVER): the section absent, and said; set while present, refused
  mv "$ST/tmp/perps.json" "$ST/tmp/perps.json.away"
  fresh
  if PERPS_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 && grep -q 'PERPS SKIPPED' "$ST/log" \
     && python3 -c 'import json,os; assert "perps" not in json.load(open(os.environ["OUT"]))'; then
    ok "PERPS_SKIPPED=1 (DRY_RUN without PERP_PROVER) cuts without the perps section, and says so"
  else bad "PERPS_SKIPPED path: $(tail -2 "$ST/log")"; fi
  mv "$ST/tmp/perps.json.away" "$ST/tmp/perps.json"
  fresh
  if PERPS_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "PERPS_SKIPPED with a perps section accepted"
  elif grep -q 'PERPS_SKIPPED yet a perps section is present' "$ST/log"; then ok "PERPS_SKIPPED with a perps section present is refused"
  else bad "PERPS_SKIPPED with a section: $(tail -1 "$ST/log")"; fi

  # every refusal the cut must make, one per case: <description> <file> <mutation> <expected reason phrase> [env]
  refuse() {
    local what=$1 file=$2 mutation=$3 phrase=$4; shift 4
    cp "$file" "$file.orig"
    python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); $mutation; json.dump(d, open(p,'w'))" "$file"
    fresh
    if (env "$@" bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1); then
      bad "$what — accepted"
    else
      local msg; msg=$(grep -o 'cut-chain22: .*' "$ST/log" | tail -1 | cut -c1-110)
      if grep -qF -- "$phrase" "$ST/log"; then ok "$what — $msg"; else bad "$what — refused, but not for the expected reason (wanted \"$phrase\"): $msg"; fi
    fi
    mv "$file.orig" "$file"
  }
  mkdir -p "$ST/done-ok/2" "$ST/done-ok/5" "$ST/done-bad/5"; touch "$ST/done-ok/5/5" "$ST/done-ok/5/6" "$ST/done-bad/5/9"
  S=$ST/snap/chain21-state.json; B=$ST/base.json; G=$ST/genesis-chain21.json; PJ=$ST/tmp/perps.json
  # ── the new fields ──
  # PST-1: program_state.refuse_panics (in the base, as --program-state-refuse-panics writes it)
  refuse "no program_state.refuse_panics"          "$B" 'del d["program_state"]["refuse_panics"]' "--program-state-refuse-panics did not take"
  refuse "refuse_panics false"                     "$B" 'd["program_state"]["refuse_panics"] = False' "--program-state-refuse-panics did not take"
  refuse "refuse_panics as 1, not true"            "$B" 'd["program_state"]["refuse_panics"] = 1' "--program-state-refuse-panics did not take"
  refuse "a PROGRAM_STATE_REFUSE_PANICS off the decision" "$S" 'pass' "not the decided true (PST-1)" PROGRAM_STATE_REFUSE_PANICS=false
  # PERP-6 / PERP-101 / CON-60 (the section file the splice inserts)
  refuse "no perps.bound_payouts"                  "$PJ" 'del d["bound_payouts"]' "perps carries the fields"
  refuse "bound_payouts false"                     "$PJ" 'd["bound_payouts"] = False' "not true (PERP-6)"
  refuse "bound_payouts as 1, not true"            "$PJ" 'd["bound_payouts"] = 1' "not true (PERP-6)"
  refuse "an initial_collateral"                   "$PJ" 'd["initial_collateral"] = 5' "initial_collateral is for a seeded engine"
  refuse "sparse_windows false"                    "$PJ" 'd["sparse_windows"] = False' "not true (PERP-101)"
  refuse "no max_window_heights"                   "$PJ" 'del d["max_window_heights"]' "perps carries the fields"
  refuse "max_window_heights not the operator's"   "$PJ" 'd["max_window_heights"] = 128' "not PERPS_MAX_WINDOW_HEIGHTS '256'"
  refuse "max_window_heights below max_window_blocks" "$PJ" 'd["max_window_heights"] = 32' "max_window_blocks..=4096" PERPS_MAX_WINDOW_HEIGHTS=32
  refuse "max_window_heights above 4096"           "$PJ" 'd["max_window_heights"] = 4097' "max_window_blocks..=4096" PERPS_MAX_WINDOW_HEIGHTS=4097
  refuse "max_window_heights as a string"          "$PJ" 'd["max_window_heights"] = "256"' "not PERPS_MAX_WINDOW_HEIGHTS"
  refuse "engine_program_log_height 15"            "$PJ" 'd["engine_program_log_height"] = 15' "(CON-60)"
  refuse "no engine_program_log_height"            "$PJ" 'del d["engine_program_log_height"]' "perps carries the fields"
  refuse "a pin image-hc did not print"            "$S" 'pass' "(CON-60)" ENGINE_PROGRAM_LOG_HEIGHT=15
  refuse "an EXPECT_ENGINE_PROGRAM_LOG_HEIGHT off the decision" "$S" 'pass' "not the pinned engine's 14" EXPECT_ENGINE_PROGRAM_LOG_HEIGHT=15
  refuse "the new perps fields out of order"       "$PJ" 'd = {"bound_payouts": d.pop("bound_payouts"), **d}' "out of PerpsConfig's order"
  refuse "a PERPS_V10_JSON off the decision"       "$S" 'pass' "PERPS_V10_JSON is not the decided" PERPS_V10_JSON='{"bound_payouts": false, "sparse_windows": true}'
  refuse "a genesis root not chain 21's"           "$S" 'pass' "the same markets on the same engine must give" FIXTURE_ROOT_OK=
  # MSA-4: multisig.max_accounts (in the base, as the --multisig file holds it)
  refuse "no multisig.max_accounts"                "$B" 'del d["multisig"]["max_accounts"]' "not the file this cut wrote"
  refuse "max_accounts not the operator's"         "$S" 'pass' "not MULTISIG_MAX_ACCOUNTS '2'" MULTISIG_MAX_ACCOUNTS=2
  refuse "max_accounts first (MultisigConfig order)" "$B" 'd["multisig"] = {"max_accounts": d["multisig"].pop("max_accounts"), **d["multisig"]}' "not MultisigConfig's order"
  # TOK-1: tokens.incremental_root (in the base, as --tokens-incremental-root writes it)
  refuse "no tokens.incremental_root"              "$B" 'del d["tokens"]["incremental_root"]' "--tokens-incremental-root did not take"
  refuse "tokens.incremental_root false"           "$B" 'd["tokens"]["incremental_root"] = False' "--tokens-incremental-root did not take"
  refuse "a TOKENS_INCREMENTAL_ROOT off the decision" "$S" 'pass' "not the recommended true" TOKENS_INCREMENTAL_ROOT=false
  # chain 21's genesis must be chain 21's: none of the new fields, every chain-21 section present
  refuse "refuse_panics in chain 21's genesis"     "$G" 'd["program_state"]["refuse_panics"] = True' "CHAIN21_GENESIS is not chain 21's"
  refuse "max_accounts in chain 21's genesis"      "$G" 'd["multisig"]["max_accounts"] = 5' "CHAIN21_GENESIS is not chain 21's"
  refuse "bound_payouts in chain 21's genesis"     "$G" 'd["perps"]["bound_payouts"] = True' "CHAIN21_GENESIS is not chain 21's"
  refuse "incremental_root in chain 21's genesis"  "$G" 'd["tokens"]["incremental_root"] = True' "CHAIN21_GENESIS is not chain 21's"
  refuse "chain 21's genesis without fees"         "$G" 'del d["fees"]' "CHAIN21_GENESIS is not chain 21's"
  refuse "chain 21's genesis without perps"        "$G" 'del d["perps"]' "CHAIN21_GENESIS is not chain 21's"
  refuse "chain 21's genesis without multisig"     "$G" 'del d["multisig"]' "CHAIN21_GENESIS is not chain 21's"
  refuse "chain 21's genesis without hc_auth_multisig" "$G" 'del d["hc_auth_multisig"]' "CHAIN21_GENESIS is not chain 21's"
  refuse "chain 20's id on the chain-21 file"      "$G" 'd["chain_id"] = 20' "CHAIN21_GENESIS is not chain 21's"
  # ── chain 21's state its cut never carried (OPEN 3–5) ──
  refuse "chain 21's treasury vault, no MULTISIG_NOT_CARRIED_OK" "$S" 'pass' "no document says how a multisig account crosses a cut" MULTISIG_NOT_CARRIED_OK=
  refuse "a zUSD balance in the treasury vault"    "$S" 'd["treasury"]["vault"].append({"asset": 1, "amount": "5"})' "and token(s)" MULTISIG_NOT_CARRIED_OK=
  refuse "perps accounts on chain 21"              "$S" 'd["perps"]["accounts"] = 3' "chain 21's perps exchange is not empty"
  refuse "a listed perp account on chain 21"       "$S" 'd["perp_accounts"]["accounts"] = [{"account": "cd" * 32}]' "chain 21's perps exchange is not empty"
  refuse "a pending perp withdrawal on chain 21"   "$S" 'd["perps"]["pending_withdrawals"] = 1' "chain 21's perps exchange is not empty"
  refuse "perps collateral held on chain 21"       "$S" 'd["perps"]["collateral_held"] = "5"' "chain 21's perps exchange is not empty"
  refuse "RAND in chain 21's program vaults"       "$S" 'd["supply"]["program_rand_held"] = "1000"' "program vaults hold"
  cp "$S" "$S.keep"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["perps"]["accounts"] = 3; d["perp_accounts"]["accounts"] = [{"account": "cd" * 32}]; d["supply"]["program_rand_held"] = "1000"; json.dump(d, open(p,"w"))' "$S"
  fresh
  if PERPS_STATE_NOT_CARRIED_OK=1 PROGRAM_VAULTS_DROPPED_OK=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 \
     && grep -q 'NOT carried (PERPS_STATE_NOT_CARRIED_OK=1)' "$ST/log" && grep -q 'NOT carried (PROGRAM_VAULTS_DROPPED_OK=1)' "$ST/log" \
     && grep -q 'NOT carried (MULTISIG_NOT_CARRIED_OK=1)' "$ST/log"; then
    ok "chain 21's treasury vault, perps exchange and program vaults are dropped only on MULTISIG_NOT_CARRIED_OK / PERPS_STATE_NOT_CARRIED_OK / PROGRAM_VAULTS_DROPPED_OK, each with a warning"
  else bad "the *_NOT_CARRIED_OK drops: $(tail -2 "$ST/log")"; fi
  mv "$S.keep" "$S"
  # ── chain 21's sections, carried and asserted equal ──
  # fees
  refuse "no fees section"                   "$B" 'del d["fees"]' "--fees did not take"
  refuse "fees without burn_floor"           "$B" 'del d["fees"]["burn_floor"]' "--fees did not take"
  refuse "fees.burn_base false"              "$B" 'd["fees"]["burn_base"] = False' "--fees did not take"
  refuse "fees.burn_base as 1, not true"     "$B" 'd["fees"]["burn_base"] = 1' "--fees did not take"
  refuse "fees.subsidy_net_of_fees set"      "$B" 'd["fees"]["subsidy_net_of_fees"] = True' "re-measured against the hidden-asset bundle (b053a76)"
  refuse "a FEES_JSON off chain 21's"        "$S" 'pass' "FEES_JSON is" FEES_JSON='{"burn_base": true}'
  # perps
  mv "$PJ" "$PJ.away"; fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "perps absent — accepted"
  elif grep -qF "no perps section to splice" "$ST/log"; then ok "perps absent — $(grep -o 'cut-chain22: .*' "$ST/log" | tail -1 | cut -c1-110)"
  else bad "perps absent — wrong refusal: $(tail -1 "$ST/log")"; fi
  mv "$PJ.away" "$PJ"
  refuse "perps written into the base (--perps)"   "$B" 'd["perps"] = json.load(open(sys.argv[1].replace("base.json", "tmp/perps.json")))' "the base file already has a perps section"
  refuse "a wrong engine_hc"                       "$PJ" 'd["engine_hc"] = "cd" * 32' "is not the pinned engine"
  refuse "a genesis_root the cut did not derive"   "$PJ" 'd["genesis_root"] = "cd" * 32' "is not the root this cut derived"
  refuse "collateral_asset 0 (RAND)"               "$PJ" 'd["collateral_asset"] = 0' "perps.collateral_asset is 0, not 1 (zUSD)"
  refuse "collateral 1 not zUSD (tokens[0] renamed)" "$G" 'd["tokens"]["tokens"][0]["symbol"] = "zEUR"' "is not zUSD"
  refuse "a second market"                         "$PJ" 'd["markets"].append(dict(d["markets"][0], id=1, symbol="ETH-PERP"))' "perps lists 2 markets"
  refuse "maintenance 500 bps at 20x (= initial)"  "$PJ" 'd["markets"][0]["maintenance_bps"] = 500' "at or above the initial margin 500 bps"
  refuse "max_block_inputs 25"                     "$PJ" 'd["max_block_inputs"] = 25' "max_block_inputs is 25, not 24"
  refuse "max_tier 20"                             "$PJ" 'd["max_tier"] = 20' "max_tier is 20, not 18"
  refuse "a tick at nine decimals (10^9 = \$10)"   "$PJ" 'd["markets"][0]["tick"] = 1000000000' "perps is not chain 21's section: ['markets'] differ"
  refuse "min_deposit at nine decimals (10 zUSD)"  "$PJ" 'd["min_deposit"] = 1000000000' "perps is not chain 21's section: ['min_deposit'] differ"
  refuse "an unknown perps field"                  "$PJ" 'd["extra"] = 1' "perps carries the fields"
  refuse "a PERPS_JSON off chain 21's"             "$S" 'pass' "PERPS_JSON is not chain 21's" PERPS_JSON='{"collateral_asset": 0}'
  # multisig (in the base, as --multisig writes it)
  refuse "multisig absent"                         "$B" 'del d["multisig"]' "--multisig did not take"
  refuse "create_fee 0"                            "$B" 'd["multisig"]["create_fee"] = "0"' "a create_fee of 0 is refused at this cut"
  refuse "a MULTISIG_CREATE_FEE off chain 21's"    "$S" 'pass' "not chain 21's 1000000000" MULTISIG_CREATE_FEE=0
  refuse "threshold 3 (3 of 3)"                    "$B" 'd["multisig"]["accounts"][0]["threshold"] = 3' "threshold is 3, not 2"
  refuse "2 signers"                               "$B" 'd["multisig"]["accounts"][0]["signers"].pop()' "lists 2 signer(s), not 3"
  refuse "a duplicate signer"                      "$B" 's = d["multisig"]["accounts"][0]["signers"]; s[2] = s[0]' "listed twice"
  refuse "a validator key as a signer"             "$B" 'd["multisig"]["accounts"][0]["signers"][1] = d["validators"][0]["public_key"]' "is a validator's key"
  refuse "signers reordered"                       "$B" 's = d["multisig"]["accounts"][0]["signers"]; s[0], s[1] = s[1], s[0]' "are not chain 21's, in chain 21's order"
  refuse "a treasury balance not TREASURY's"       "$B" 'a = d["multisig"]["accounts"][0]; a["balance"] = str(int(a["balance"]) // 10**9)' "is not TREASURY's"
  refuse "a second seeded account"                 "$B" 'd["multisig"]["accounts"].append(dict(d["multisig"]["accounts"][0], salt="00" * 32))' "seeds 2 account(s)"
  refuse "a salt the cut did not write"            "$B" 'd["multisig"]["accounts"][0]["salt"] = "00" * 32' "not the file this cut wrote"
  refuse "chain 21's treasury salt"                "$B" 'd["multisig"]["accounts"][0]["salt"] = json.load(open(sys.argv[1].replace("base.json", "genesis-chain21.json")))["multisig"]["accounts"][0]["salt"]' "the treasury salt is chain 21's"
  # a treasury whose balance, beside the notes and stakes, overflows a u64: the section file, the
  # balance file and the base all say it (as a cut from such a TREASURY would)
  for f in "$B" "$ST/tmp/multisig.json" "$ST/tmp/treasury-balance"; do cp "$f" "$f.keep"; done
  python3 -c 'import json,sys
for p in sys.argv[1:3]:
    d = json.load(open(p)); m = d.get("multisig", d); m["accounts"][0]["balance"] = str(2**64 - 1); json.dump(d, open(p, "w"))
open(sys.argv[3], "w").write(str(2**64 - 1))' "$B" "$ST/tmp/multisig.json" "$ST/tmp/treasury-balance"
  fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "a treasury that overflows the supply — accepted"
  elif grep -qF "overflows a u64" "$ST/log"; then ok "a treasury that overflows the supply — $(grep -o 'cut-chain22: .*' "$ST/log" | tail -1 | cut -c1-110)"
  else bad "a treasury that overflows the supply — wrong refusal: $(tail -1 "$ST/log")"; fi
  for f in "$B" "$ST/tmp/multisig.json" "$ST/tmp/treasury-balance"; do mv "$f.keep" "$f"; done
  # hc_auth_multisig (private multisig)
  refuse "hc_auth_multisig absent"                 "$B" 'del d["hc_auth_multisig"]' "--auth-multisig-guest did not take"
  refuse "hc_auth_multisig not this build's"       "$B" 'd["hc_auth_multisig"] = "cd" * 32' "is not this build's multisig auth guest"
  refuse "hc_auth_multisig equal to hc_auth"       "$B" 'd["hc_auth_multisig"] = d["hc_auth"]' "must differ from hc_auth"
  refuse "hc_auth missing beside hc_auth_multisig" "$B" 'del d["hc_auth"]' "is not chain 21's auth guest"
  refuse "max_proof_bytes under 4 MiB"             "$B" 'd["max_proof_bytes"] = 4194303' "cannot hold a multisig auth proof"
  refuse "hc_auth_multisig not what the node wrote" "$S" 'pass' "is not what this rand-node wrote" HC_AUTH_MULTISIG_REPORTED="$(printf 'cd%.0s' $(seq 32))"
  # the treasury file itself (py_treasury), each refusal before a section is written
  PK=$(sed -n 's/^signer s1 //p' "$ST/treasury.txt"); PK2=$(sed -n 's/^signer s2 //p' "$ST/treasury.txt"); PK3=$(sed -n 's/^signer s3 //p' "$ST/treasury.txt")
  VPK=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validators"][5]["public_key"])' "$ST/genesis-chain21.json")
  GPK=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bridge"]["pq_guardians"][3])' "$ST/genesis-chain21.json")
  XPK=$(printf '1a%.0s' $(seq 1312)); YPK=$(printf '2b%.0s' $(seq 1312)); ZPK=$(printf '3c%.0s' $(seq 1312))
  treasury_refuses() {  # <description> <phrase> <file content> [env…]
    local what=$1 phrase=$2; printf '%s' "$3" > "$ST/treasury-case.txt"; shift 3
    if env TREASURY="$ST/treasury-case.txt" "$@" bash -c 'py_validators >/dev/null && py_treasury' >"$ST/log" 2>&1; then bad "TREASURY: $what — accepted"
    elif grep -qF -- "$phrase" "$ST/log"; then ok "TREASURY: $what — $(grep -o 'cut-chain22: .*' "$ST/log" | tail -1 | cut -c1-110)"
    else bad "TREASURY: $what — wrong refusal (wanted \"$phrase\"): $(tail -1 "$ST/log")"; fi
  }
  T3="signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'
  treasury_refuses "threshold 3"          "the treasury's threshold is 2" "$T3"$'threshold 3\nbalance 1\n'
  treasury_refuses "no threshold line"    "threshold missing"              "$T3"$'balance 1\n'
  treasury_refuses "2 signers"            "2 signer line(s)"               "signer a $PK"$'\n'"signer b $PK2"$'\n'$'threshold 2\nbalance 1\n'
  treasury_refuses "a duplicate signer"   "listed twice"                   "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK"$'\n'$'threshold 2\nbalance 1\n'
  treasury_refuses "a validator's key"    "is validator"                   "signer a $PK"$'\n'"signer b $VPK"$'\n'"signer c $PK3"$'\n'$'threshold 2\nbalance 1\n'
  treasury_refuses "a guardian's key"     "is bridge PQ guardian 3's"      "signer a $PK"$'\n'"signer b $GPK"$'\n'"signer c $PK3"$'\n'$'threshold 2\nbalance 1\n'
  treasury_refuses "a short key"          "not a Dilithium2 public key"    "signer a ${PK:0:64}"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'$'threshold 2\nbalance 1\n'
  treasury_refuses "balance 0"            "balance 0"                      "$T3"$'threshold 2\nbalance 0\n'
  treasury_refuses "a balance of 10 decimals" "at most 9 decimals"         "$T3"$'threshold 2\nbalance 1.0000000001\n'
  treasury_refuses "no balance line"      "0 balance line(s)"              "$T3"$'threshold 2\n'
  treasury_refuses "an unknown line"      "a line is \`signer\`"           "$T3"$'threshold 2\nbalance 1\nsalt 00\n'
  treasury_refuses "signers not chain 21's" "not chain 21's treasury signers" "signer x $XPK"$'\n'"signer y $YPK"$'\n'"signer z $ZPK"$'\n'$'threshold 2\nbalance 1\n'
  treasury_refuses "chain 21's signers reordered" "not chain 21's treasury signers" "signer b $PK2"$'\n'"signer a $PK"$'\n'"signer c $PK3"$'\n'$'threshold 2\nbalance 1\n'
  treasury_refuses "chain 21's treasury salt" "the salt is chain 21's treasury salt" "$T3"$'threshold 2\nbalance 1\n' \
    TREASURY_SALT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["multisig"]["accounts"][0]["salt"])' "$ST/genesis-chain21.json")"
  treasury_refuses "MULTISIG_MAX_ACCOUNTS 0" "is not a count ≥ 1"         "$T3"$'threshold 2\nbalance 1\n' MULTISIG_MAX_ACCOUNTS=0
  cp "$S" "$S.keep"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["treasury"]["signers"].reverse(); json.dump(d, open(p,"w"))' "$S"
  treasury_refuses "a rotation on chain 21, no TREASURY_ROTATED" "a rotation" "$T3"$'threshold 2\nbalance 1\n'
  mv "$S.keep" "$S"
  printf '%s' "signer x $XPK"$'\n'"signer y $YPK"$'\n'"signer z $ZPK"$'\n'$'threshold 2\nbalance 1\n' > "$ST/treasury-case.txt"
  if TREASURY="$ST/treasury-case.txt" TREASURY_SIGNERS_CHANGED=1 TMP="$ST/tmp-other" bash -c 'mkdir -p "$TMP" && cp "$ST/tmp/validators.json" "$TMP/" && py_treasury' >"$ST/log" 2>&1; then
    ok "other treasury signers are accepted with TREASURY_SIGNERS_CHANGED=1 (knowingly)"
  else bad "TREASURY_SIGNERS_CHANGED=1: $(tail -1 "$ST/log")"; fi
  # chain 21's top-level fields, each still at its value
  refuse "no testnet marker"                 "$B" 'del d["testnet"]' "testnet is None, not true"
  refuse "binding_domain 0"                  "$B" 'd["binding_domain"] = 0' "binding_domain is 0, not 1"
  refuse "proof_window_blocks 256"           "$B" 'd["proof_window_blocks"] = 256' "proof_window_blocks is 256, not 1024"
  refuse "no max_gas_price"                  "$B" 'del d["gas"]["dynamic"]["max_gas_price"]' "--max-gas-price did not take"
  refuse "a max_byte_price off the value"    "$B" 'd["gas"]["dynamic"]["max_byte_price"] = "800000"' "--max-byte-price did not take"
  refuse "no paying byte load"               "$B" 'del d["gas"]["dynamic"]["byte_load"]' "--gas-byte-load paying did not take"
  refuse "no program_state"                  "$B" 'del d["program_state"]' "did not take"
  refuse "a program_state cell fee off docs" "$B" 'd["program_state"]["cell_fee"] = 1' "--program-state-cell-fee"
  refuse "a cell fee env off docs"           "$B" 'd["program_state"]["cell_fee"] = 5' "docs/program-state.md's 10000000" PROGRAM_STATE_CELL_FEE=5
  refuse "a rotation delay off 86400"        "$S" 'pass' "bridge.rotation is" ROTATION_DELAY_SECS=3600
  refuse "a mint fee off 10 bps"             "$S" 'pass' "bridge.fees is" BRIDGE_MINT_BPS=30
  refuse "no fee recipient loaded"           "$S" 'pass' "load_fee_recipient did not run" FEE_RECIPIENT=
  refuse "a validator payout as fee recipient" "$S" 'pass' "a validator's payout address" FEE_RECIPIENT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validators"][0]["payout"])' "$ST/genesis-chain21.json")"
  refuse "a fee recipient that is not chain 21's" "$S" 'pass' "FEE_RECIPIENT_CHANGED=1 only" FEE_RECIPIENT=rand1SELFTESTotherrecipient
  refuse "a stake entry budget off 2500 bps" "$S" 'pass' "not 2500" STAKE_ENTRY_BPS=3333
  refuse "slashing in chain 21's staking"    "$G" 'd["staking"]["slashing"] = {"equivocation_bps": 500, "jail_epochs": 2}' "carries none"
  refuse "a vesting section on chain 21"     "$G" 'd["vesting"] = {"entries": []}' "vesting section"
  refuse "an aggregation section"            "$B" 'd["aggregation"] = {}' "aggregation"
  refuse "a field the script does not know"  "$B" 'd["extra_unknown"] = 1' "fields this script does not know"
  refuse "incremental_nullifier_root (OPEN 6)" "$B" 'd["incremental_nullifier_root"] = True' "fields this script does not know"
  refuse "gas prices that are not chain 21's" "$B" 'd["gas"]["gas_price"] = "200"; d["gas"]["dynamic"]["min_gas_price"] = "200"' "is not chain 21's {" GAS_PRICE=200
  refuse "a bundle_gas_limit off the pin"    "$B" 'd["gas"]["bundle_gas_limit"] = 16383' "not gas_max(14, 0, 0)"
  refuse "a byte target not half the block"  "$B" 'd["gas"]["dynamic"]["target_block_bytes"] = 4194304' "gas.dynamic targets are"
  # chain 21's limits (6 MiB proofs, 19 MiB blocks): others refused without LIMITS_CHANGED=1
  refuse "a 4 MiB proof cap, no LIMITS_CHANGED" "$B" 'd["max_proof_bytes"] = 4194304' "max_proof_bytes 4194304 differs from chain 21's 6291456" MAX_PROOF_BYTES=4194304
  refuse "a 20 MiB block, no LIMITS_CHANGED" "$B" 'd["max_block_bytes"] = 20971520; d["gas"]["dynamic"]["target_block_bytes"] = 10485760' \
    "max_block_bytes 20971520 differs from chain 21's 19922944" MAX_BLOCK_BYTES=20971520 GAS_DYNAMIC=10485760,262144,1250
  refuse "a block under 3 proofs + 1 MiB"    "$B" 'd["max_block_bytes"] = 18874368; d["gas"]["dynamic"]["target_block_bytes"] = 9437184' \
    "a v3 Call carries three proofs" MAX_BLOCK_BYTES=18874368 GAS_DYNAMIC=9437184,262144,1250 LIMITS_CHANGED=1
  cp "$B" "$B.orig"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["max_proof_bytes"] = 4194304; json.dump(d, open(p,"w"))' "$B"
  fresh
  if LIMITS_CHANGED=1 MAX_PROOF_BYTES=4194304 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then
    ok "a 4 MiB proof cap is accepted with LIMITS_CHANGED=1"
  else bad "a 4 MiB proof cap with LIMITS_CHANGED=1: $(tail -1 "$ST/log")"; fi
  mv "$B.orig" "$B"
  refuse "a validator payout that is not chain 21's" "$B" 'd["validators"][0]["payout"] = d["validators"][1]["payout"]' "not chain 21's shape: ['validators']"
  refuse "no envelope_bytes"                 "$B" 'del d["envelope_bytes"]' "envelope_bytes is None, not 1860"
  refuse "a legacy (1 348-B) RAND alloc"     "$B" 'd["alloc"][0]["envelope"]["body"] = d["alloc"][0]["envelope"]["body"][:-1024]' "sealed in the legacy format"
  # chain 21 carries three zUSD notes, so token-notes.jsonl has three lines: shorten the first one's envelope
  TN=$ST/tmp/token-notes.jsonl; cp "$TN" "$TN.orig"
  python3 -c 'import json,sys; p=sys.argv[1]; L=open(p).read().splitlines(); d=json.loads(L[0]); d["envelope"]["body"] = d["envelope"]["body"][:-1024]; L[0]=json.dumps(d); open(p,"w").write("\n".join(L) + "\n")' "$TN"
  fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "a legacy (1 348-B) zUSD note — accepted"
  elif grep -qF "sealed in the legacy format" "$ST/log"; then ok "a legacy (1 348-B) zUSD note — $(grep -o 'cut-chain22: .*' "$ST/log" | tail -1 | cut -c1-110)"
  else bad "a legacy (1 348-B) zUSD note — wrong refusal: $(tail -1 "$ST/log")"; fi
  mv "$TN.orig" "$TN"
  refuse "hc_auth not chain 21's"            "$G" 'd["hc_auth"] = "cd" * 32' "is not chain 21's auth guest"
  # the bridge: emitters, floors, custody
  refuse "a snapshot read at other emitters" "$S" 'd["source"]["emitters"]["2"] = "00" * 31 + "01"' "other emitters than this cut lists"
  refuse "a guardian rotation on chain 21"   "$S" 'd["bridge"]["guardian_set_index"] = 2' "BRIDGE_ROTATED=1"
  refuse "custody one unit below locked"     "$S" 'd["source"]["custody"][[k for k in d["source"]["custody"] if k.startswith("5:ce01")][0]]["custody"] -= 1' "source custody"
  refuse "custody at Tron above locked"      "$S" 'd["source"]["custody"][[k for k in d["source"]["custody"] if k.startswith("4:")][0]]["custody"] += 1' "source custody"
  refuse "zUSD supply above Σ locked"        "$S" 'd["tokens"]["tokens"][0]["total_supply"] = "1000000001"' "!= Σ locked"
  refuse "an explicit Ethereum floor of 0 reaching the splice" "$S" 'pass' "below 1" MIN_INBOUND_2=0
  refuse "a Solana floor below chain 21's"   "$S" 'pass' "below chain 21's own floor" MIN_INBOUND_5=3
  refuse "a BSC floor below chain 21's"      "$S" 'pass' "below chain 21's own floor" MIN_INBOUND_3=4
  refuse "a floor above the next sequence"   "$S" 'pass' "would NEVER mint on chain 22" MIN_INBOUND_3=6
  refuse "an unminted BSC lock (next seq 6, explicit floor 5)" "$S" 'd["source"]["next_sequence"]["3"] = 6' "will mint on chain 22" MIN_INBOUND_3=5
  refuse "the relayer's done/ disagreeing"   "$S" 'pass' "the relayer's done/ says" RELAYER_DONE_DIR="$ST/done-bad"
  refuse "a stake that is not 1000 RAND"     "$S" 'd["validators"][3]["stake"] = "2000000000000"' "not a plain"
  refuse "a validator bonded on chain 21"    "$S" 'd["validators"].append(dict(d["validators"][0], address="new"))' "chain 21's register holds"
  refuse "unwithdrawn validator rewards"     "$S" 'd["validators"][0]["rewards"] = "1"' "REWARDS_DROPPED_OK=1 to drop"
  # the RAND carry
  refuse "a scanned balance the list lacks"  "$ST/snap/balances.json" 'd["wallets"][0]["rand_units"] += 1' "!= Σ scanned balances"
  refuse "an uncovered genesis alloc"        "$ST/snap/balances.json" 'd["uncovered_genesis_allocs"] = [{"pk": "ab" * 32, "amount": 1}]' "UNCOVERED_ALLOCS_OK=1 to drop"
  refuse "no balances.json, no NO_BALANCES"  "$S" 'pass' "the carry-over rule" BALANCES_FILE=/nonexistent
  refuse "a changed faucet allowlist"        "$S" 'pass' "FAUCET_RECIPIENTS_CHANGED=1 if that is" FAUCET_RECIPIENTS="$ST/faucet-recipients-changed.txt"

  # floors: the auto path honours a moved endpoint; an explicit unminted-lock floor carries with a warning
  cp "$S" "$S.keep"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["source"]["next_sequence"].update({"2": 5, "5": 9}); json.dump(d, open(p,"w"))' "$S"
  fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 \
     && python3 -c 'import json,os; assert json.load(open(os.environ["OUT"]))["bridge"]["min_inbound_sequence"] == {"2": 5, "3": 5, "4": 3, "5": 9}' \
     && grep -q 'EXPECTED' "$ST/log"; then ok "auto floors follow the endpoints' next sequences (2:5, 5:9), with the expected-floor warning"
  else bad "auto floors: $(tail -2 "$ST/log")"; fi
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["source"]["next_sequence"]["4"] = 4; k=[k for k in d["source"]["custody"] if k.startswith("4:")][0]; d["source"]["custody"][k]["custody"] += 5000000; json.dump(d, open(p,"w"))' "$S"
  fresh
  if MIN_INBOUND_4=3 ALLOW_UNMINTED_LOCKS=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 \
     && python3 -c 'import json,os; assert json.load(open(os.environ["OUT"]))["bridge"]["min_inbound_sequence"]["4"] == 3' \
     && grep -q 'will mint on chain 22 (ALLOW_UNMINTED_LOCKS=1)' "$ST/log" && grep -q 'the unminted lock(s) on chain 4' "$ST/log"; then
    ok "an explicit floor below an unminted user lock carries with ALLOW_UNMINTED_LOCKS=1 (custody above locked on that chain only), with warnings"
  else bad "ALLOW_UNMINTED_LOCKS path: $(tail -2 "$ST/log")"; fi
  mv "$S.keep" "$S"
  fresh
  if RELAYER_DONE_DIR="$ST/done-ok" bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then
    ok "the relayer's done/ agreeing with every floor is accepted (an empty done/<c> = chain 21's floor − 1)"
  else bad "RELAYER_DONE_DIR agreeing: $(tail -2 "$ST/log")"; fi
  fresh
  if MIN_INBOUND_2=3 MIN_INBOUND_FILE='' bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then ok "an explicit floor equal to the next sequence is accepted"; else bad "explicit floor 3: $(tail -1 "$ST/log")"; fi

  # check-limits against a fake chain-22 node serving the assembled file
  write_answers() {  # <genesis> <answers.json>
    python3 - "$1" "$2" <<'PY'
import json, sys
g = json.load(open(sys.argv[1])); d = g["gas"]["dynamic"]; p = g.get("perps") or {}; m = g["multisig"]
ml = {"create_fee": "1000000000", "max_signers": 10, "max_payouts": 4}
if "max_accounts" in m:
    ml["max_accounts"] = m["max_accounts"]
json.dump({"rand_getGenesisHash": "ab" * 32,
           "rand_status": {"chain_id": 22, "hc_bundle": g["hc_bundle"], "hc_auth": g["hc_auth"], "hc_auth_multisig": g["hc_auth_multisig"], "fri_profile": "production"},
           "rand_getLimits": {"proof_window_blocks": 1024, "binding_domain": 1, "testnet": True, "admission_by_vote": True, "slashing": None,
                              "max_gas_price": d["max_gas_price"], "max_byte_price": d["max_byte_price"], "byte_load": "paying",
                              "gas_metering": "circuit", "bundle_gas_limit": 20479, "adjust_bps": 1250, "envelope_bytes": 1860,
                              "hardening_v6": True, "hc_auth": g["hc_auth"], "max_proof_bytes": g["max_proof_bytes"], "max_block_bytes": g["max_block_bytes"],
                              "hc_auth_multisig": g["hc_auth_multisig"],
                              "program_state": {"cell_fee": str(g["program_state"]["cell_fee"]), "max_reads": 8, "max_writes": 8, "max_payouts": 4},
                              "fee_rules": {"burn_base": True, "subsidy_net_of_fees": False, "burn_floor": True,
                                            "proposer_share_bps": None, "prove_base": None, "usd_subsidy": None},
                              "perps": {"collateral_asset": 1, "max_tier": 18, "max_window_blocks": 64, "max_payouts": 8, "max_block_inputs": 24, "min_deposit": "100000000"},
                              "multisig": ml},
           "rand_getSupply": {"base_fees_burned": "0", "burned": "0", "invariant_holds": True, "multisig_issued": m["accounts"][0]["balance"]},
           "rand_getPerps": {"enabled": True, "collateral_asset": 1, "max_tier": 18, "max_window_blocks": 64,
                             "sparse_windows": p.get("sparse_windows", False), "max_window_heights": p.get("max_window_heights", 0),
                             "engine_program_log_height": p.get("engine_program_log_height", 0),
                             "max_block_inputs": 24, "min_deposit": "100000000",
                             "engine_hc": p["engine_hc"], "genesis_root": p["genesis_root"], "markets": p["markets"],
                             "proved_root": p["genesis_root"], "proved_height": 0, "head_height": 0, "pending_heights": [], "medians": [],
                             "accounts": 0, "pending_withdrawals": 0, "bound_payouts": p.get("bound_payouts", False), "initial_collateral": "0",
                             "collateral_in": "0", "collateral_out": "0", "collateral_held": "0"},
           "rand_getMultisig": {"enabled": True, "id": "ef" * 32, "signers": m["accounts"][0]["signers"], "threshold": 2, "nonce": 0,
                                "vault": [{"asset": 0, "amount": m["accounts"][0]["balance"]}]},
           "rand_getTokens": {"enabled": True, "registration_fee": "1000000000", "next_index": 2, "max_tokens": 4096, "burn_registration_fee": True,
                              "bound_note_value": True, "incremental_root": g["tokens"].get("incremental_root", False), "tokens": []},
           "rand_getBridgeState": {"emitters": g["bridge"]["emitters"], "min_inbound_sequence": g["bridge"]["min_inbound_sequence"],
                                   "burn_sequence": g["bridge"]["burn_sequence"], "rotation_rules": {"delay_secs": 86400, "needs_possession": True},
                                   "fees": g["bridge"]["fees"]}},
          open(sys.argv[2], "w"))
PY
  }
  write_answers "$ST/good.json" "$ST/answers.json"
  fake_rpc "$ST/answers.json" "$ST/port"
  RPC=http://127.0.0.1:$(cat "$ST/port")
  check() {  # <genesis> [env…]: py_check_limits against the fake node
    local gen=$1; shift
    env TREASURY_ID="$(printf 'ef%.0s' $(seq 32))" CHECK_RPC="$RPC" CHECK_GENESIS="$gen" EXPECT_GENESIS_HASH="$(printf 'ab%.0s' $(seq 32))" "$@" bash -c py_check_limits >"$ST/log" 2>&1
  }
  export -f py_check_limits
  if check "$ST/good.json" && grep -q 'program_state.refuse_panics (PST-1)    not served' "$ST/log"; then
    ok "check-limits accepts a node serving chain 22 as cut ($(grep -c '^check-limits:   ' "$ST/log") values read; refuse_panics through the hash)"
  else bad "check-limits on a correct node: $(tail -3 "$ST/log")"; fi
  cp "$ST/answers.json" "$ST/answers.keep"
  python3 -c "import json,sys; p=sys.argv[1]; a=json.load(open(p)); a['rand_getSupply']['base_fees_burned'] = '4063900'; json.dump(a, open(p,'w'))" "$ST/answers.json"
  if check "$ST/good.json" BASE_FEES_BURNED_ANY=1; then
    ok "check-limits with BASE_FEES_BURNED_ANY=1 accepts a node that has burned since launch (base_fees_burned \"4063900\")"
  else bad "BASE_FEES_BURNED_ANY=1: $(tail -2 "$ST/log")"; fi
  mv "$ST/answers.keep" "$ST/answers.json"
  for m in 'L["proof_window_blocks"] = 256' 'L["binding_domain"] = 0' 'L["testnet"] = False' 'L["admission_by_vote"] = False' \
           'L["byte_load"] = None' 'L["max_gas_price"] = None' 'L["max_proof_bytes"] = 4194304' 'L["program_state"] = None' 'B["rotation_rules"] = None' 'B["fees"]["burn_bps"] = 20' \
           'L["fee_rules"] = None' 'L["fee_rules"]["burn_floor"] = False' 'L["fee_rules"]["subsidy_net_of_fees"] = True' 'L["proof_window_blocks"] = 1024.0' \
           'S["base_fees_burned"] = "1000000"' 'S["invariant_holds"] = False' \
           'L["perps"] = None' 'L["perps"]["max_block_inputs"] = 120' 'P["engine_hc"] = "cd" * 32' 'P["proved_height"] = 7' 'P["genesis_root"] = "cd" * 32' 'P.clear(); P["enabled"] = False' \
           'P["bound_payouts"] = False' 'del P["bound_payouts"]' 'P["initial_collateral"] = "5"' 'P["collateral_in"] = "1"' 'P["collateral_held"] = "1"' \
           'P["accounts"] = 1' 'P["pending_withdrawals"] = 1' 'P["sparse_windows"] = False' 'P["max_window_heights"] = 0' 'P["max_window_heights"] = 64' \
           'P["engine_program_log_height"] = 0' 'P["engine_program_log_height"] = 15' \
           'L["multisig"] = None' 'L["multisig"]["create_fee"] = "0"' 'del L["multisig"]["max_accounts"]' 'L["multisig"]["max_accounts"] = 2' \
           'S["multisig_issued"] = "0"' 'M["threshold"] = 3' 'M["signers"].reverse()' 'a["rand_getMultisig"] = None' \
           'T["incremental_root"] = False' 'del T["incremental_root"]' 'T["bound_note_value"] = False' \
           'L["hc_auth_multisig"] = None' 'a["rand_status"]["hc_auth_multisig"] = None'; do
    cp "$ST/answers.json" "$ST/answers.keep"
    python3 -c "import json,sys; p=sys.argv[1]; a=json.load(open(p)); L=a['rand_getLimits']; B=a['rand_getBridgeState']; S=a['rand_getSupply']; P=a['rand_getPerps']; M=a['rand_getMultisig']; T=a['rand_getTokens']; $m; json.dump(a, open(p,'w'))" "$ST/answers.json"
    if check "$ST/good.json"; then bad "check-limits accepted a node with $m"
    elif grep -q 'does NOT serve chain 22 as cut' "$ST/log"; then ok "check-limits refuses a node with $m"
    else bad "check-limits, $m: $(tail -1 "$ST/log")"; fi
    mv "$ST/answers.keep" "$ST/answers.json"
  done
  # AUDIT_V10_SKIPPED in the environment cannot loosen check-limits: skipped-ness is the file's
  cp "$ST/answers.json" "$ST/answers.keep"
  python3 -c "import json,sys; p=sys.argv[1]; a=json.load(open(p)); a['rand_getPerps']['bound_payouts'] = False; json.dump(a, open(p,'w'))" "$ST/answers.json"
  if check "$ST/good.json" AUDIT_V10_SKIPPED=1 PERPS_SKIPPED=1; then bad "check-limits with AUDIT_V10_SKIPPED=1 in the env accepted bound_payouts false on a genesis with it"
  elif grep -q 'does NOT serve chain 22 as cut: perps bound_payouts' "$ST/log"; then ok "check-limits with AUDIT_V10_SKIPPED=1 PERPS_SKIPPED=1 in the env still refuses bound_payouts false when the genesis has it"
  else bad "check-limits, env AUDIT_V10_SKIPPED: $(tail -1 "$ST/log")"; fi
  mv "$ST/answers.keep" "$ST/answers.json"
  # a genesis without the audit-v10 fields (a dry run that skipped them) wants each field's default, and says SKIPPED
  if [ -f "$ST/good-v10skipped.json" ]; then
    cp "$ST/answers.json" "$ST/answers.keep"
    write_answers "$ST/good-v10skipped.json" "$ST/answers.json"
    if check "$ST/good-v10skipped.json" && grep -q 'AUDIT_V10 SKIPPED' "$ST/log" && grep -q 'refuse_panics ABSENT' "$ST/log"; then
      ok "check-limits on an AUDIT_V10-skipped genesis wants bound_payouts false, max_window_heights 0, engine_program_log_height 0 and no max_accounts, and says SKIPPED"
    else bad "check-limits, AUDIT_V10-skipped genesis: $(tail -1 "$ST/log")"; fi
    if check "$ST/good.json"; then bad "check-limits accepted a node without the audit-v10 fields for a genesis that has them"
    elif grep -q 'does NOT serve chain 22 as cut: perps bound_payouts (PERP-6)' "$ST/log"; then ok "check-limits refuses a node without the audit-v10 fields (a build before v0.8.2) for a genesis that has them"
    else bad "check-limits, node without the audit-v10 fields: $(tail -1 "$ST/log")"; fi
    mv "$ST/answers.keep" "$ST/answers.json"
  fi
  if check "$ST/good.json" EXPECT_GENESIS_HASH="$(printf 'cd%.0s' $(seq 32))"; then bad "check-limits accepted another genesis hash"
  else ok "check-limits refuses a node serving another genesis hash"; fi
  kill "$FAKE_RPC_PID" 2>/dev/null || true; FAKE_RPC_PID=

  # the bash-level guards, each refusing before anything runs
  bash_refuses() {  # <description> <phrase> <env…> -- <args…>
    local what=$1 phrase=$2; shift 2
    local envs=(); while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
    if env -u MIN_INBOUND_2 -u MIN_INBOUND_3 -u MIN_INBOUND_4 -u MIN_INBOUND_5 -u PERPS_MAX_WINDOW_HEIGHTS -u MULTISIG_MAX_ACCOUNTS \
         -u ENGINE_PROGRAM_LOG_HEIGHT -u TREASURY_SALT -u FIXTURE_ROOT_OK -u MULTISIG_NOT_CARRIED_OK \
         SELFTEST=0 "${envs[@]}" bash "$0" "$@" >"$ST/log" 2>&1; then bad "$what — accepted"
    elif grep -qF -- "$phrase" "$ST/log"; then ok "$what — refused before anything runs"
    else bad "$what — wrong refusal (wanted \"$phrase\"): $(tail -1 "$ST/log")"; fi
  }
  for c in 2 3 4 5; do
    bash_refuses "EMITTER_$c off chain 21's, no EMITTERS_CHANGED" "is not chain 21's endpoint" "EMITTER_$c=$NEW_EMITTER" --
  done
  bash_refuses "chain 18's old Ethereum endpoint, even with EMITTERS_CHANGED=1" "never again" EMITTER_2=000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892 EMITTERS_CHANGED=1 --
  for c in 2 3 4; do bash_refuses "MIN_INBOUND_$c=0 (the consume-step lock)" "is below 1" "MIN_INBOUND_$c=0" --; done
  bash_refuses "MIN_INBOUND_5=0" "is no floor" MIN_INBOUND_5=0 --
  bash_refuses "MIN_INBOUND_2=none" "its old locks would replay" MIN_INBOUND_2=none --
  printf '2 1\n3 0\n' > "$ST/floors-zero"; printf '2 3\n' > "$ST/floors-ok"; printf '6 1\n' > "$ST/floors-chain"
  bash_refuses "a floor file with chain 3 at 0" "is below 1" MIN_INBOUND_FILE="$ST/floors-zero" --
  bash_refuses "a floor given in env and in the file" "given twice" MIN_INBOUND_FILE="$ST/floors-ok" MIN_INBOUND_2=1 --
  bash_refuses "a floor file naming chain 6" "must be 2, 3, 4 or 5" MIN_INBOUND_FILE="$ST/floors-chain" --
  bash_refuses "PERPS_MAX_WINDOW_HEIGHTS=63 (below max_window_blocks)" "outside max_window_blocks..=MAX_WINDOW_HEIGHTS" PERPS_MAX_WINDOW_HEIGHTS=63 --
  bash_refuses "PERPS_MAX_WINDOW_HEIGHTS=4097" "outside max_window_blocks..=MAX_WINDOW_HEIGHTS" PERPS_MAX_WINDOW_HEIGHTS=4097 --
  bash_refuses "PERPS_MAX_WINDOW_HEIGHTS=abc" "outside max_window_blocks..=MAX_WINDOW_HEIGHTS" PERPS_MAX_WINDOW_HEIGHTS=abc --
  bash_refuses "MULTISIG_MAX_ACCOUNTS=0" "is not a count ≥ 1" MULTISIG_MAX_ACCOUNTS=0 --
  bash_refuses "an EXPECT_ENGINE_PROGRAM_LOG_HEIGHT off the pin" "is not the pinned engine's program height" EXPECT_ENGINE_PROGRAM_LOG_HEIGHT=15 --
  bash_refuses "an EXPECT_HC_AUTH_MULTISIG off chain 21's guest" "is not chain 21's multisig auth guest" EXPECT_HC_AUTH_MULTISIG="$(printf 'cd%.0s' $(seq 32))" --
  bash_refuses "an EXPECT_ENGINE_HC off the decided engine" "is not the decided engine" EXPECT_ENGINE_HC="$(printf 'cd%.0s' $(seq 32))" --
  # A genesis dir holding chain 21's committed file and not chain 22's (once chain 22 is cut,
  # deploy/ holds genesis-chain22.json and `refuse_reused_chain_id 22` would fire first).
  mkdir -p "$ST/gendir-21"; cp "$CHAIN21_GENESIS" "$ST/gendir-21/genesis-chain21.json"
  bash_refuses "a valid floor file parses (and the cut then stops at its missing record)" "no cut record" CUT_POLICY_GENESIS_DIR="$ST/gendir-21" MIN_INBOUND_FILE="$ST/floors-ok" CUT_RECORD="$ST/no-such-record" --
  bash_refuses "the cut without a cut record (OPS-7)" "no cut record" CUT_POLICY_GENESIS_DIR="$ST/gendir-21" CUT_RECORD="$ST/no-such-record" CHAIN21_SNAPSHOT="$ST/snap" NODE=/usr/bin/true WALLET=/usr/bin/true --
  mkdir -p "$ST/gendir"; cp "$CHAIN21_GENESIS" "$ST/gendir/genesis-chain21.json"
  python3 -c 'import json,sys; json.dump({"chain_id": 22}, open(sys.argv[1] + "/gendir/genesis-chain22.json", "w"))' "$ST"
  bash_refuses "a chain id a committed genesis already has (OPS-7)" "already used by genesis-chain22.json" CUT_POLICY_GENESIS_DIR="$ST/gendir" CUT_RECORD="$ST/cut-record.txt" CHAIN21_SNAPSHOT="$ST/snap" NODE=/usr/bin/true WALLET=/usr/bin/true --
  bash_refuses "snapshot on a dead tunnel" "is not answering" CHAIN21_RPC=http://127.0.0.1:9 -- snapshot "$ST/snap-new"
  mkdir -p "$ST/wd"; echo '{}' > "$ST/wd/shielded-1.key.json"
  bash_refuses "balances without the relayer's key file" "relayer.key.json is in none of" WALLETS_DIRS="$ST/wd" WALLET=/usr/bin/true ALLOC_ADDRESSES="$ST/none.txt" CHAIN21_RPC=http://127.0.0.1:9 -- balances "$ST/snap-bal"
  echo '{}' > "$ST/wd/relayer.key.json"
  bash_refuses "balances on a dead tunnel (relayer present)" "is not answering" WALLETS_DIRS="$ST/wd" WALLET=/usr/bin/true ALLOC_ADDRESSES="$ST/none.txt" CHAIN21_RPC=http://127.0.0.1:9 -- balances "$ST/snap-bal"
  # A fake `rand`: `perp image-hc` prints FAKE_HC (default the pinned engine's) on stdout and
  # `engine_program_log_height ${FAKE_EPLH}` (default 14; none when FAKE_EPLH is set empty) on
  # stderr, as v0.8.2 does; anything else prints a fingerprint (the fee recipient's check).
  # shellcheck disable=SC2016  # the fake's own source: expanded when it runs, not here
  printf '#!/usr/bin/env bash\ncase "$*" in *"perp image-hc"*) echo "${FAKE_HC:-%s}"; [ -z "${FAKE_EPLH-14}" ] || echo "engine_program_log_height ${FAKE_EPLH-14}" >&2; exit 0;; esac\necho "fingerprint ${FAKE_FP:-89DS-4Q4X-HXSX-MBYW}"\necho saved\n' "$ENGINE_HC_DECIDED" > "$ST/fake-rand"; chmod +x "$ST/fake-rand"
  echo "rand1SELFTESTfeerecipient" > "$ST/fee-ok.txt"; echo "not-an-address" > "$ST/fee-bad.txt"; printf 'rand1a\nrand1b\n' > "$ST/fee-two.txt"
  fp_case() {  # <description> <want ok|refuse> <phrase> <env…>
    local what=$1 want=$2 phrase=$3; shift 3
    # shellcheck disable=SC2016  # expanded by the child bash
    if env "$@" bash -c 'WALLET=$FAKE_WALLET; load_fee_recipient' >"$ST/log" 2>&1; then r=ok; else r=refuse; fi
    if [ "$r" = "$want" ] && grep -qF -- "$phrase" "$ST/log"; then ok "$what — $(grep -o 'cut-chain22: .*' "$ST/log" | tail -1 | cut -c1-110)"
    else bad "$what — got $r: $(tail -1 "$ST/log")"; fi
  }
  export -f load_fee_recipient
  fp_case "the fee recipient with the expected fingerprint is loaded" ok "fingerprint 89DS-4Q4X-HXSX-MBYW (= FEE_RECIPIENT_FINGERPRINT)" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-ok.txt"
  fp_case "a fee recipient whose fingerprint differs is refused" refuse "not FEE_RECIPIENT_FINGERPRINT" FAKE_WALLET="$ST/fake-rand" FAKE_FP=AAAA-BBBB-CCCC-DDDD FEE_RECIPIENT_FILE="$ST/fee-ok.txt"
  fp_case "a missing fee recipient file is refused" refuse "no fee recipient file" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/none.txt"
  fp_case "a fee recipient file of two lines is refused" refuse "more than one line" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-two.txt"
  fp_case "a wallet that prints no fingerprint is refused" refuse "printed no fingerprint" FAKE_WALLET=/usr/bin/true FEE_RECIPIENT_FILE="$ST/fee-ok.txt"
  # A fake rand-node: `genesis --help` lists every flag the cut needs but FAKE_DROP (one flag left
  # out) and --program-state-refuse-panics only unless FAKE_V10_FLAG is set empty; `--version` says
  # 0.8.2; nothing else answers (init prints no hash). A fake perp-prover and engine image.
  # shellcheck disable=SC2016  # the fake's own source
  printf '#!/usr/bin/env bash\ncase "$1" in\n  --version) echo "rand-node 0.8.2";;\n  genesis) echo "--hardening-v6 --bundle-guest --auth-guest --gas-price --gas-dynamic --envelope-bytes --max-gas-price --max-byte-price --gas-byte-load --testnet --binding-domain --proof-window-blocks --program-state-cell-fee --fees --multisig --auth-multisig-guest --tokens-incremental-root ${FAKE_V10_FLAG---program-state-refuse-panics} ${FAKE_EXTRA:-}" | tr " " "\\n" | grep -vxF -- "${FAKE_DROP:-@none@}" | tr "\\n" " ";;\nesac\n' > "$ST/fake-node"; chmod +x "$ST/fake-node"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$ST/fake-prover"; chmod +x "$ST/fake-prover"; echo image > "$ST/fake-image"
  for x in "treasury:the genesis fees section is a genesis-gated validity rule (PST-1, PERP-6, PERP-101)" \
           "pst1:audit v11 — PERP-6 bound_payouts, PERP-101 sparse windows; the treasury re-seeded" \
           "perp6:audit v11 — PST-1 refuse_panics, PERP-101 sparse windows; the treasury re-seeded" \
           "perp101:audit v11 — PST-1 refuse_panics, PERP-6 bound_payouts; the treasury re-seeded"; do
    sed "s/^reason:.*/reason: ${x#*:}/; s/^carries:.*/carries: fixture register, bridge state and balances/" "$ST/cut-record.txt" > "$ST/cut-record-no-${x%%:*}.txt"
  done
  sed 's/^drops:.*/drops: nothing/' "$ST/cut-record.txt" > "$ST/cut-record-drops-nothing.txt"
  printf '%s\n' "$FEE_RECIPIENT" > "$ST/fee-c21.txt"
  real_cut=(CUT_POLICY_GENESIS_DIR="$ST/gendir-21" CUT_RECORD="$ST/cut-record.txt" CHAIN21_SNAPSHOT="$ST/snap" CHAIN21_GENESIS=deploy/genesis-chain21.json
            OUT="$ST/not-yet.json" NODE="$ST/fake-node" WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-c21.txt"
            TREASURY="$ST/treasury.txt" PERP_PROVER="$ST/fake-prover" PERP_IMAGE="$ST/fake-image"
            PERPS_MAX_WINDOW_HEIGHTS=256 MULTISIG_MAX_ACCOUNTS=1)
  for f in --fees --multisig --auth-multisig-guest --tokens-incremental-root --gas-byte-load; do
    bash_refuses "the real cut on a rand-node without $f" "genesis has no $f —" "${real_cut[@]}" FAKE_DROP="$f" --
  done
  bash_refuses "the real cut on a rand-node with only --fees-like flags (--feesless)" "genesis has no --fees —" "${real_cut[@]}" FAKE_DROP=--fees FAKE_EXTRA=--feesless --
  bash_refuses "DRY_RUN on a rand-node without --multisig (no skip: chain 21 runs it)" "genesis has no --multisig —" "${real_cut[@]}" FAKE_DROP=--multisig DRY_RUN=1 --
  bash_refuses "the real cut on a rand-node without --program-state-refuse-panics (before v0.8.2)" "a build before v0.8.2" "${real_cut[@]}" FAKE_V10_FLAG= --
  bash_refuses "the real cut with a rand whose image-hc prints no engine_program_log_height" "a build before v0.8.2" "${real_cut[@]}" FAKE_EPLH= --
  bash_refuses "an engine image whose program height is not 14" "not EXPECT_ENGINE_PROGRAM_LOG_HEIGHT 14" "${real_cut[@]}" FAKE_EPLH=15 --
  bash_refuses "the real cut without PERPS_MAX_WINDOW_HEIGHTS (OPEN 1)" "PERPS_MAX_WINDOW_HEIGHTS is unset — the owner's decision (OPEN 1" "${real_cut[@]}" PERPS_MAX_WINDOW_HEIGHTS= --
  bash_refuses "the real cut without MULTISIG_MAX_ACCOUNTS (OPEN 2)" "MULTISIG_MAX_ACCOUNTS is unset — the owner's decision (OPEN 2" "${real_cut[@]}" MULTISIG_MAX_ACCOUNTS= --
  bash_refuses "PERPS_SKIPPED=1 from the environment on the real cut" "PERPS_SKIPPED=1 is set in the environment — refusing" "${real_cut[@]}" PERPS_SKIPPED=1 --
  bash_refuses "AUDIT_V10_SKIPPED=1 from the environment on the real cut" "AUDIT_V10_SKIPPED=1 is set in the environment — refusing" "${real_cut[@]}" AUDIT_V10_SKIPPED=1 --
  bash_refuses "the real cut with no EXPECT_NODE_VERSION" "EXPECT_NODE_VERSION is unset" "${real_cut[@]}" --
  bash_refuses "the real cut on a version other than EXPECT_NODE_VERSION" "not rand-node 0.8.3" "${real_cut[@]}" EXPECT_NODE_VERSION=0.8.3 --
  bash_refuses "a rand-node that does not re-derive chain 21's hash" "not chain 21's ca76c276" "${real_cut[@]}" NODE_VERSION_OK=1 --
  bash_refuses "the real cut without PERP_PROVER" "PERP_PROVER is unset or not executable" "${real_cut[@]}" PERP_PROVER= --
  bash_refuses "an engine image whose hc is not the pinned engine" "not EXPECT_ENGINE_HC" "${real_cut[@]}" NODE_VERSION_OK=1 FAKE_HC="$(printf 'cd%.0s' $(seq 32))" --
  bash_refuses "no engine image" "missing $ST/no-image" "${real_cut[@]}" PERP_IMAGE="$ST/no-image" --
  bash_refuses "no treasury file" "missing $ST/no-treasury.txt" "${real_cut[@]}" TREASURY="$ST/no-treasury.txt" --
  bash_refuses "a cut record that does not name the treasury" "names no treasury" "${real_cut[@]}" CUT_RECORD="$ST/cut-record-no-treasury.txt" --
  bash_refuses "a cut record that does not name PST-1" "names no PST-1" "${real_cut[@]}" CUT_RECORD="$ST/cut-record-no-pst1.txt" --
  bash_refuses "a cut record that does not name PERP-6" "names no PERP-6" "${real_cut[@]}" CUT_RECORD="$ST/cut-record-no-perp6.txt" --
  bash_refuses "a cut record that does not name PERP-101" "names no PERP-101" "${real_cut[@]}" CUT_RECORD="$ST/cut-record-no-perp101.txt" --
  bash_refuses "MULTISIG_NOT_CARRIED_OK=1, the record's drops: silent" "names no dropped multisig register" "${real_cut[@]}" MULTISIG_NOT_CARRIED_OK=1 CUT_RECORD="$ST/cut-record-drops-nothing.txt" --
  bash_refuses "PERPS_STATE_NOT_CARRIED_OK=1, the record's drops: silent" "names no dropped perps exchange state" "${real_cut[@]}" PERPS_STATE_NOT_CARRIED_OK=1 --
  bash_refuses "PROGRAM_VAULTS_DROPPED_OK=1, the record's drops: silent" "names no dropped program vaults" "${real_cut[@]}" PROGRAM_VAULTS_DROPPED_OK=1 --
  # DRY_RUN on a build before v0.8.2 and without PERP_PROVER: two loud banners, then on (it stops
  # later, at the fake's init)
  dry=(env -u MIN_INBOUND_2 -u MIN_INBOUND_3 -u MIN_INBOUND_4 -u MIN_INBOUND_5 -u PERPS_MAX_WINDOW_HEIGHTS -u MULTISIG_MAX_ACCOUNTS
       -u ENGINE_PROGRAM_LOG_HEIGHT -u TREASURY_SALT -u FIXTURE_ROOT_OK -u MULTISIG_NOT_CARRIED_OK SELFTEST=0 DRY_RUN=1
       CHAIN21_GENESIS=deploy/genesis-chain21.json TREASURY="$ST/no-treasury.txt" NODE="$ST/fake-node" WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-c21.txt")
  if "${dry[@]}" PERP_PROVER= FAKE_V10_FLAG= bash "$0" >"$ST/log" 2>&1; then bad "DRY_RUN on a fake rand-node finished"
  elif grep -q 'AUDIT_V10 SKIPPED ⚠⚠⚠' "$ST/log" && grep -q 'PERPS SKIPPED ⚠⚠⚠' "$ST/log" && grep -q "cutting with rand-node 0.8.2" "$ST/log" \
       && grep -q "chain 21's three treasury signers" "$ST/log" && ! grep -q 'PLACEHOLDER 64' "$ST/log"; then
    ok "DRY_RUN on a build without --program-state-refuse-panics and without PERP_PROVER says AUDIT_V10 and PERPS SKIPPED loudly and goes on past the gates"
  else bad "DRY_RUN without the audit-v10 flag / PERP_PROVER: $(tail -2 "$ST/log")"; fi
  # DRY_RUN with *_SKIPPED=1 in the env on a v0.8.2 build with PERP_PROVER: ignored; the operator
  # inputs unset → each a loud PLACEHOLDER
  if "${dry[@]}" PERPS_SKIPPED=1 AUDIT_V10_SKIPPED=1 PERP_PROVER="$ST/fake-prover" PERP_IMAGE="$ST/fake-image" bash "$0" >"$ST/log" 2>&1; then bad "DRY_RUN on a fake rand-node finished"
  elif grep -q 'PERPS_SKIPPED=1 in the environment is IGNORED' "$ST/log" && grep -q 'AUDIT_V10_SKIPPED=1 in the environment is IGNORED' "$ST/log" \
       && ! grep -q 'SKIPPED ⚠⚠⚠' "$ST/log" && grep -q 'PERPS_MAX_WINDOW_HEIGHTS unset — DRY RUN PLACEHOLDER 64' "$ST/log" \
       && grep -q 'MULTISIG_MAX_ACCOUNTS unset — DRY RUN PLACEHOLDER 1' "$ST/log" && grep -q 'engine program height 14' "$ST/log" \
       && grep -q 'engine image .*(= EXPECT_ENGINE_HC' "$ST/log"; then
    ok "DRY_RUN ignores PERPS/AUDIT_V10_SKIPPED=1 from the environment (loudly), reads the engine height 14, and puts in loud PLACEHOLDERS (64, 1) for the unset operator inputs"
  else bad "DRY_RUN with env *_SKIPPED: $(tail -2 "$ST/log")"; fi
  echo "selftest: $pass passed, $fail failed"
  [ "$fail" = 0 ]; exit
fi

# ══ DRY_RUN: the REAL cut path on synthetic inputs, no network ══════════════════════════════════
# Everything `snapshot` and `balances` would read off chain 21 and the four source chains is
# synthesised from the committed chain-21 genesis (py_fixtures, FIXTURE_MODE=dryrun) as the cut
# expects to find it. Then the cut below runs unchanged — chain 21's hash re-derived, the real
# `rand-node genesis` with every flag (`--fees` included), `alloc-note`, the splice and every
# assertion, two `init`s, the field probe — and then a
# LOOPBACK probe node (127.0.0.1 only, no bootstrap, no mDNS, a throwaway key) runs the file so
# `check-limits` reads what a chain-22 node serves. The output lands in a temp dir (DRY_OUT to
# choose), never at deploy/genesis-chain22.json, and is not chain 22: launch nothing from it.
if [ "${DRY_RUN:-}" = 1 ]; then
  ST=$(mktemp -d)
  export ST FIXTURE_MODE=dryrun
  py_fixtures
  CHAIN21_SNAPSHOT=$ST/snap VALIDATORS_TSV=$ST/validators.tsv REGISTRATIONS=$ST/reg \
    ALLOC_ADDRESSES=$ST/alloc-rand.txt ZUSD_CARRY=$ST/zusd-carry.txt CUT_RECORD=$ST/cut-record.txt
  OUT=${DRY_OUT:-$ST/genesis-chain22.DRY-RUN.json}
  export CHAIN21_SNAPSHOT VALIDATORS_TSV REGISTRATIONS ALLOC_ADDRESSES ZUSD_CARRY
  # OPS-402: once chain 22 is cut and its genesis committed, `refuse_reused_chain_id 22` would
  # stop every dry run (a rehearsal of this script, not a cut). The dry run scans a copy of the
  # committed genesis files without chain 22's own; the real cut still scans deploy/ and refuses.
  if [ -z "${CUT_POLICY_GENESIS_DIR:-}" ]; then
    mkdir -p "$ST/gendir-dry"
    for g in "$(dirname "$0")"/genesis*.json; do
      [ "$(basename "$g")" = genesis-chain22.json ] || cp "$g" "$ST/gendir-dry/"
    done
    CUT_POLICY_GENESIS_DIR=$ST/gendir-dry; export CUT_POLICY_GENESIS_DIR
  fi
  if [ ! -f "$TREASURY" ]; then
    # No treasury file: chain 21's treasury signers (public keys, from the committed genesis), 2 of
    # 3, a PLACEHOLDER 100 000 RAND (py_fixtures). The chain-22 balance is OPEN 3.
    echo "cut-chain22: DRY RUN — no TREASURY file ($TREASURY): chain 21's three treasury signers, 2 of 3, PLACEHOLDER 100000 RAND → $ST/treasury.txt"
    TREASURY=$ST/treasury.txt
  fi
  export TREASURY
  DRY_PLACEHOLDERS=$([ -n "$PERPS_MAX_WINDOW_HEIGHTS" ] || printf 'max_window_heights '; [ -n "$MULTISIG_MAX_ACCOUNTS" ] || printf 'max_accounts')
  echo "cut-chain22: DRY RUN — synthetic chain-21 snapshot, balances and inputs under $ST (from $CHAIN21_GENESIS); no network; $OUT is NOT chain 22"
fi

if [ "${1:-}" = snapshot ]; then
  SNAP=${2:?snapshot <dir>}
  [ ! -e "$SNAP/chain21-state.json" ] || { echo "cut-chain22: $SNAP/chain21-state.json exists — a snapshot is taken once; move it aside" >&2; exit 1; }
  need_chain21_rpc
  mkdir -p "$SNAP"; export SNAP
  py_snapshot
  exit 0
fi

if [ "${1:-}" = balances ]; then
  SNAP=${2:?balances <snapshot dir>}
  [ ! -e "$SNAP/balances.json" ] || { echo "cut-chain22: $SNAP/balances.json exists — move it aside to re-scan" >&2; exit 1; }
  [ ! -e "$ALLOC_ADDRESSES" ] || { echo "cut-chain22: $ALLOC_ADDRESSES exists — move it aside; \`balances\` writes it" >&2; exit 1; }
  [ -x "$WALLET" ] || { echo "cut-chain22: $WALLET is not executable — a rand that decodes chain 21: v0.8.2 (the build chain 21 runs since 2026-10-28)" >&2; exit 1; }
  for w in $REQUIRED_WALLETS; do
    found=; for d in $WALLETS_DIRS; do [ -e "$d/$w.key.json" ] && found=$d/$w.key.json; done
    [ -n "$found" ] || { echo "cut-chain22: $w.key.json is in none of WALLETS_DIRS ($WALLETS_DIRS) — link it there before the scan (the relayer's: ~/.rand-chain17/alloc-wallets/relayer.key.json → ~/.rand-chain14/wallets/relayer.key.json)" >&2; exit 1; }
    [ -s "$found" ] || { echo "cut-chain22: $found is empty or a broken link" >&2; exit 1; }
    echo "cut-chain22: required wallet $w: $found"
  done
  need_chain21_rpc
  [ -f "$SNAP/chain21-state.json" ] || { echo "cut-chain22: take the snapshot first ($0 snapshot $SNAP)" >&2; exit 1; }
  refuse_in_tree_key "$SNAP/chain21-state.json"
  export SNAP WALLET WALLETS_DIRS
  py_balances
  exit 0
fi

# ══ the cut ══════════════════════════════════════════════════════════════════════════════════
# PERPS_SKIPPED and AUDIT_V10_SKIPPED from the environment: refused on the real cut, ignored
# (loudly) by DRY_RUN, which decides each from the inputs and the binary in hand. (Chain 21's
# FEES/MULTISIG/AUTH_MULTISIG skips are gone: chain 21 runs those sections, so every build that can
# cut chain 22 has their flags, and the real cut and the dry run alike refuse one without them.)
for s in PERPS AUDIT_V10; do
  v=${s}_SKIPPED_FROM_ENV
  [ -n "${!v}" ] || continue
  if [ "${DRY_RUN:-}" = 1 ]; then
    echo "cut-chain22: ⚠ ${s}_SKIPPED=${!v} in the environment is IGNORED — the dry run decides it from the inputs in hand" >&2
  else
    echo "cut-chain22: ${s}_SKIPPED=${!v} is set in the environment — refusing: the $(tr '[:upper:]' '[:lower:]' <<<"$s") fields are never skipped on the real cut (only DRY_RUN sets it)" >&2; exit 1
  fi
done
# OPS-7 first: a reused chain id and a missing cut record are refused before anything else.
refuse_reused_chain_id "$CHAIN_ID"
require_cut_record "$CUT_RECORD"
# The treasury is new issuance, not a carry: the record published before the cut says it seeds one.
require_cut_record_mentions "$CUT_RECORD" 'treasury|multisig' "treasury (the multisig section's seeded account, new issuance)" reason carries
# The audit-v11 issues this cut closes: the record names each (monorepo#15, #13, #12).
require_cut_record_mentions "$CUT_RECORD" 'PST-1|refuse_panics' "PST-1 (program_state.refuse_panics, monorepo#15)" reason carries
require_cut_record_mentions "$CUT_RECORD" 'PERP-6|bound_payouts' "PERP-6 (perps.bound_payouts, monorepo#13)" reason carries
require_cut_record_mentions "$CUT_RECORD" 'PERP-101|sparse.windows|max_window_heights' "PERP-101 (perps.sparse_windows + max_window_heights, monorepo#12)" reason carries
# Chain 21's state the cut drops on the operator's word (OPEN 3–5): the record's drops: line names it.
[ "${MULTISIG_NOT_CARRIED_OK:-}" != 1 ] || require_cut_record_mentions "$CUT_RECORD" 'treasury|multisig' "dropped multisig register (MULTISIG_NOT_CARRIED_OK=1)" drops
[ "${PERPS_STATE_NOT_CARRIED_OK:-}" != 1 ] || require_cut_record_mentions "$CUT_RECORD" 'perp' "dropped perps exchange state (PERPS_STATE_NOT_CARRIED_OK=1)" drops
[ "${PROGRAM_VAULTS_DROPPED_OK:-}" != 1 ] || require_cut_record_mentions "$CUT_RECORD" 'program' "dropped program vaults (PROGRAM_VAULTS_DROPPED_OK=1)" drops
[ -n "$CHAIN21_SNAPSHOT" ] || { echo "cut-chain22: CHAIN21_SNAPSHOT is unset — run \`$0 snapshot <dir>\` while chain 21 is up" >&2; exit 1; }
SNAPSHOT_FILE=$CHAIN21_SNAPSHOT/chain21-state.json; BALANCES_FILE=$CHAIN21_SNAPSHOT/balances.json
export SNAPSHOT_FILE BALANCES_FILE
for bin in "$NODE" "$WALLET"; do
  [ -x "$bin" ] || { echo "cut-chain22: $bin is not executable — the binaries of the cut build (v0.8.2, 299378d0, or later)" >&2; exit 1; }
done
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$ALLOC_ADDRESSES" "$ZUSD_CARRY" "$CHAIN21_GENESIS" "$TREASURY" "$PERP_IMAGE" ${FAUCET_RECIPIENTS:+"$FAUCET_RECIPIENTS"}; do
  [ -f "$f" ] || { echo "cut-chain22: missing $f" >&2; exit 1; }
done
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$ALLOC_ADDRESSES" "$ZUSD_CARRY" "$TREASURY" ${FAUCET_RECIPIENTS:+"$FAUCET_RECIPIENTS"}; do
  refuse_in_tree_key "$f"
done
for n in $BONDED; do refuse_in_tree_key "$REGISTRATIONS/$n.txt"; done
[ "$(shasum -a 256 "$CHAIN21_GENESIS" | cut -c1-64)" = "$CHAIN21_GENESIS_SHA256" ] \
  || { echo "cut-chain22: $CHAIN21_GENESIS is not chain 21's committed genesis file (sha256 ${CHAIN21_GENESIS_SHA256:0:8}…)" >&2; exit 1; }
[ ! -e "$OUT" ] || { echo "cut-chain22: $OUT already exists — a genesis is cut once; move it aside deliberately" >&2; exit 1; }
HELP=$("$NODE" genesis --help)
# Every flag chain 21's cut needed (fees 3119a29a-era sections included: chain 21 runs them, so a build
# without one cannot cut chain 22 at all — refused here, DRY_RUN too) plus --tokens-incremental-root.
for flag in --hardening-v6 --bundle-guest --auth-guest --gas-price --gas-dynamic --envelope-bytes \
            --max-gas-price --max-byte-price --gas-byte-load --testnet --binding-domain --proof-window-blocks \
            --program-state-cell-fee --fees --multisig --auth-multisig-guest --tokens-incremental-root; do
  grep -qE -- "(^|[[:space:]])$flag([[:space:]=<,]|\$)" <<<"$HELP" \
    || { echo "cut-chain22: $NODE genesis has no $flag — not a build that can cut chain 21's shape (v0.8.0+; the cut wants v0.8.2+)" >&2; exit 1; }
done
# The perps section: its genesis root comes from durian.market's perp-prover (the engine's own
# encoding of the genesis state) and this build's `rand perp genesis-root`; without them it cannot
# be derived, and a hand-copied root is not accepted.
if [ -z "$PERP_PROVER" ] || [ ! -x "$PERP_PROVER" ]; then
  if [ "${DRY_RUN:-}" = 1 ]; then
    PERPS_SKIPPED=1; export PERPS_SKIPPED
    cat >&2 <<EOF
cut-chain22: ⚠⚠⚠ PERPS SKIPPED ⚠⚠⚠ — PERP_PROVER='${PERP_PROVER}' is not an executable perp-prover: the engine's
cut-chain22:     genesis root cannot be derived. The dry run goes on WITHOUT the perps section and its probe;
cut-chain22:     the REAL cut refuses. Build durian.market's perp-prover (cargo build --release -p perp-prover).
EOF
  else
    echo "cut-chain22: PERP_PROVER is unset or not executable ('${PERP_PROVER}') — durian.market's perp-prover derives the perps genesis root (\`perp-prover genesis-state\`); refusing" >&2; exit 1
  fi
fi
# The audit-v10 fields (v0.8.2): `--program-state-refuse-panics` (PST-1) and `rand perp image-hc`
# printing the engine's program height (CON-60) — the same release ships the perps and multisig
# fields, which an older build refuses inside their sections (deny_unknown_fields). One gate.
EPLH_GOT=$("$WALLET" perp image-hc --image "$PERP_IMAGE" 2>&1 >/dev/null | sed -n 's/^engine_program_log_height \([0-9][0-9]*\)$/\1/p' | tail -1 || true)
if ! grep -qE -- '(^|[[:space:]])--program-state-refuse-panics([[:space:]=<,]|$)' <<<"$HELP" || [ -z "$EPLH_GOT" ]; then
  if [ "${DRY_RUN:-}" = 1 ]; then
    AUDIT_V10_SKIPPED=1; export AUDIT_V10_SKIPPED
    cat >&2 <<EOF
cut-chain22: ⚠⚠⚠ AUDIT_V10 SKIPPED ⚠⚠⚠ — $NODE genesis has no --program-state-refuse-panics, or \`$WALLET perp
cut-chain22:     image-hc\` prints no engine_program_log_height: a build before v0.8.2 (299378d0). The dry run
cut-chain22:     goes on WITHOUT refuse_panics, bound_payouts, sparse_windows, max_window_heights,
cut-chain22:     engine_program_log_height and max_accounts, and without their probes; the REAL cut refuses.
EOF
  else
    echo "cut-chain22: $NODE genesis has no --program-state-refuse-panics, or \`$WALLET perp image-hc\` prints no engine_program_log_height — a build before v0.8.2 (299378d0); the audit-v10 fields (PST-1, PERP-6, PERP-101, CON-60, MSA-4) cannot be written" >&2; exit 1
  fi
else
  # CON-60: the pin is what this build reads off the pinned image, and must be the decided height.
  [ "$EPLH_GOT" = "$EXPECT_ENGINE_PROGRAM_LOG_HEIGHT" ] || { echo "cut-chain22: \`$WALLET perp image-hc --image $PERP_IMAGE\` prints engine_program_log_height $EPLH_GOT, not EXPECT_ENGINE_PROGRAM_LOG_HEIGHT $EXPECT_ENGINE_PROGRAM_LOG_HEIGHT — another engine image" >&2; exit 1; }
  ENGINE_PROGRAM_LOG_HEIGHT=$EPLH_GOT; export ENGINE_PROGRAM_LOG_HEIGHT
  echo "cut-chain22: engine program height $ENGINE_PROGRAM_LOG_HEIGHT (\`rand perp image-hc\`, = EXPECT_ENGINE_PROGRAM_LOG_HEIGHT) → perps.engine_program_log_height"
  # The two operator inputs (OPEN 1, OPEN 2): no default on the real cut; DRY_RUN puts in each
  # field's lower bound, LOUDLY, as a placeholder.
  for v in PERPS_MAX_WINDOW_HEIGHTS:64 MULTISIG_MAX_ACCOUNTS:1; do
    n=${v%%:*}; ph=${v#*:}
    [ -z "${!n}" ] || continue
    if [ "${DRY_RUN:-}" = 1 ]; then
      printf -v "$n" '%s' "$ph"; export "${n?}"
      echo "cut-chain22: ⚠⚠⚠ $n unset — DRY RUN PLACEHOLDER $ph (the lower bound); the owner's value is OPEN (header) and the real cut refuses without it" >&2
    else
      echo "cut-chain22: $n is unset — the owner's decision (OPEN $([ "$n" = PERPS_MAX_WINDOW_HEIGHTS ] && echo 1 || echo 2) in this script's header); no documented value, and the real cut takes no default" >&2; exit 1
    fi
  done
fi
NODE_VERSION=$("$NODE" --version 2>/dev/null || true)
if [ -z "$EXPECT_NODE_VERSION" ]; then
  if [ "${DRY_RUN:-}" = 1 ]; then echo "cut-chain22: ⚠ DRY RUN with '$NODE_VERSION' and no EXPECT_NODE_VERSION — the real cut refuses that unless NODE_VERSION_OK=1" >&2
  else [ "${NODE_VERSION_OK:-}" = 1 ] || { echo "cut-chain22: EXPECT_NODE_VERSION is unset — set it to the tagged release the cut runs (v0.8.2+, OPEN 7; '$NODE_VERSION' is what $NODE reports), or NODE_VERSION_OK=1 to cut with it knowingly" >&2; exit 1; }; fi
else
  case "$NODE_VERSION" in
    "rand-node $EXPECT_NODE_VERSION"*) ;;
    *) if [ "${DRY_RUN:-}" = 1 ]; then echo "cut-chain22: ⚠ DRY RUN with '$NODE_VERSION', not rand-node $EXPECT_NODE_VERSION — the real cut refuses it" >&2
       else [ "${NODE_VERSION_OK:-}" = 1 ] || { echo "cut-chain22: $NODE reports '$NODE_VERSION', not rand-node $EXPECT_NODE_VERSION — NODE_VERSION_OK=1 to cut with it knowingly" >&2; exit 1; }; fi ;;
  esac
fi
echo "cut-chain22: cutting with $NODE_VERSION"
if [ -z "${PERPS_SKIPPED:-}" ]; then
  # The engine: this build's `rand perp image-hc` over the image must be the decided engine.
  ENGINE_HC_GOT=$("$WALLET" perp image-hc --image "$PERP_IMAGE" 2>/dev/null | tail -1 || true)
  [ "$ENGINE_HC_GOT" = "$EXPECT_ENGINE_HC" ] || { echo "cut-chain22: \`$WALLET perp image-hc --image $PERP_IMAGE\` printed '${ENGINE_HC_GOT}', not EXPECT_ENGINE_HC $EXPECT_ENGINE_HC — the wrong engine image (or a rand without \`perp image-hc\`)" >&2; exit 1; }
  echo "cut-chain22: engine image $PERP_IMAGE: hc $ENGINE_HC_GOT (= EXPECT_ENGINE_HC, durian.market's pinned engine)"
fi
load_fee_recipient

TMP=$(mktemp -d); PROBE_PID=; trap 'rm -rf "$TMP"; [ -z "$PROBE_PID" ] || kill "$PROBE_PID" 2>/dev/null || true' EXIT
export TMP

# This rand-node hashes chain 21's fields as chain 21 did: it re-derives chain 21's own genesis hash
# from the committed file (so every field carried from chain 21 is hashed, and the three new
# sections are the only difference the cut makes).
H21=$("$NODE" init --datadir "$TMP/chain21-probe" --genesis "$CHAIN21_GENESIS" 2>"$TMP/chain21-probe.err" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p' || true)
[ "$H21" = "$CHAIN21_HASH" ] || { echo "cut-chain22: $NODE derives '${H21:-nothing}' from $CHAIN21_GENESIS, not chain 21's $CHAIN21_HASH ($(tail -1 "$TMP/chain21-probe.err" | cut -c1-90))" >&2; exit 1; }
echo "cut-chain22: this rand-node re-derives chain 21's genesis ${H21:0:12}… from $CHAIN21_GENESIS"
# ... and chain 21's treasury id, offline, from the same file (the id `snapshot` read the vault at).
T21=$(treasury_id_of "$CHAIN21_GENESIS")
[ "$T21" = "$CHAIN21_TREASURY_ID" ] || { echo "cut-chain22: $NODE derives chain 21's treasury id '${T21:-nothing}', not CHAIN21_TREASURY_ID $CHAIN21_TREASURY_ID" >&2; exit 1; }
echo "cut-chain22: chain 21's treasury id ${T21:0:12}… (rand-node multisig id over its genesis account)"

py_validators

# The treasury: TREASURY → $TMP/multisig.json, its id derived offline by this rand-node.
py_treasury
targs=(); while IFS= read -r l; do targs+=("$l"); done < "$TMP/treasury-args"
TREASURY_ID=$("$NODE" multisig id --chain-id "$CHAIN_ID" "${targs[@]}")
[[ $TREASURY_ID =~ ^[0-9a-f]{64}$ ]] || { echo "cut-chain22: \`rand-node multisig id\` printed '$TREASURY_ID', not an id" >&2; exit 1; }
[ "$TREASURY_ID" != "$CHAIN21_TREASURY_ID" ] || { echo "cut-chain22: the chain-22 treasury id is chain 21's" >&2; exit 1; }
echo "cut-chain22: treasury id (offline, rand-node multisig id): $TREASURY_ID"
export TREASURY_ID

# The perps section: the market list → perp-prover's genesis words → this build's root.
if [ -z "${PERPS_SKIPPED:-}" ]; then
  PERPS_STEP=markets py_perps
  "$PERP_PROVER" genesis-state --markets "$TMP/perps-markets.json" --out "$TMP/perp-state0.json"
  PERP_GENESIS_ROOT=$("$WALLET" perp genesis-root --state "$TMP/perp-state0.json" | tail -1)
  [[ $PERP_GENESIS_ROOT =~ ^[0-9a-f]{64}$ ]] || { echo "cut-chain22: \`rand perp genesis-root\` printed '$PERP_GENESIS_ROOT', not a root" >&2; exit 1; }
  export PERP_GENESIS_ROOT
  PERPS_STEP=section py_perps
  echo "cut-chain22: perps genesis root $PERP_GENESIS_ROOT ($PERP_PROVER genesis-state → $WALLET perp genesis-root); the section is spliced after zUSD"
fi

args=()
while IFS= read -r l; do args+=("$l"); done < "$TMP/validator-args"
while read -r label addr amount; do
  case "$label" in ''|'#'*) continue;; esac
  args+=(--alloc "$addr=$amount")
done < "$ALLOC_ADDRESSES"
# The fees section: chain 21's, written here, checked to be the decided value before it is passed.
printf '%s\n' "$FEES_JSON" > "$TMP/fees.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d == {"burn_base": True, "burn_floor": True} else "cut-chain22: fees.json is %r, not chain 21'"'"'s {burn_base: true, burn_floor: true}" % d)' "$TMP/fees.json"
echo "cut-chain22: fees section: $(cat "$TMP/fees.json") → --fees"
# PST-1: the build writes `program_state.refuse_panics: true` beside the cell fee.
v10_args=()
[ -n "${AUDIT_V10_SKIPPED:-}" ] || v10_args=(--program-state-refuse-panics)

# zUSD genesis notes: fresh openings, sealed to each carried holder (asset 1 = zUSD, 8 decimals).
: > "$TMP/token-notes.jsonl"
while read -r label addr amount; do
  case "$label" in ''|'#'*) continue;; esac
  "$NODE" alloc-note --to "$addr" --amount "$amount" --asset 1 --envelope-bytes "$ENVELOPE_BYTES" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)))' >> "$TMP/token-notes.jsonl"
  echo "cut-chain22: zUSD genesis note, $amount zUSD to $label"
done < "$ZUSD_CARRY"

echo "cut-chain22: writing the base file (its printed hash is NOT chain 22's)"
"$NODE" genesis --chain-id "$CHAIN_ID" "${args[@]}" \
  --max-program-words "$MAX_PROGRAM_WORDS" \
  --max-proof-bytes "$MAX_PROOF_BYTES" \
  --max-block-bytes "$MAX_BLOCK_BYTES" \
  --max-call-envelope-bytes "$MAX_CALL_ENVELOPE_BYTES" \
  --max-program-public-words "$MAX_PROGRAM_PUBLIC_WORDS" \
  --tokens "$TMP/tokens.json" \
  --bundle-guest v3 --auth-guest --auth-multisig-guest --hardening-v6 --tokens-incremental-root \
  --gas-price "$GAS_PRICE" --byte-price "$BYTE_PRICE" --bundle-gas-limit "$BUNDLE_GAS_LIMIT" --gas-dynamic "$GAS_DYNAMIC" \
  --max-gas-price "$MAX_GAS_PRICE" --max-byte-price "$MAX_BYTE_PRICE" --gas-byte-load "$GAS_BYTE_LOAD" \
  --envelope-bytes "$ENVELOPE_BYTES" \
  --testnet --binding-domain "$BINDING_DOMAIN" --proof-window-blocks "$PROOF_WINDOW_BLOCKS" \
  --program-state-cell-fee "$PROGRAM_STATE_CELL_FEE" ${v10_args[@]+"${v10_args[@]}"} \
  --fees "$TMP/fees.json" --multisig "$TMP/multisig.json" \
  --epoch-blocks "$EPOCH_BLOCKS" --faucet --fri-profile production --out "$TMP/genesis.json" | tee "$TMP/genesis.out"

HC_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_bundle',''))" "$TMP/genesis.json")
HC_AUTH_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_auth',''))" "$TMP/genesis.json")
for pair in "hc_bundle:$HC_REPORTED" "hc_auth:$HC_AUTH_REPORTED"; do
  k=${pair%%:*}; v=${pair#*:}
  [ -n "$v" ] || { echo "cut-chain22: the genesis command wrote no $k" >&2; exit 1; }
  said=$(grep -o "$k [0-9a-f]\{64\}" "$TMP/genesis.out" | head -1 | cut -d' ' -f2 || true)
  [ -z "$said" ] || [ "$said" = "$v" ] || { echo "cut-chain22: the genesis command printed $k $said but wrote $v" >&2; exit 1; }
done
HC_AUTH_MULTISIG_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_auth_multisig',''))" "$TMP/genesis.json")
[ -n "$HC_AUTH_MULTISIG_REPORTED" ] || { echo "cut-chain22: the genesis command wrote no hc_auth_multisig — --auth-multisig-guest did not take" >&2; exit 1; }
said=$(grep -o "hc_auth_multisig [0-9a-f]\{64\}" "$TMP/genesis.out" | head -1 | cut -d' ' -f2 || true)
[ "$said" = "$HC_AUTH_MULTISIG_REPORTED" ] || { echo "cut-chain22: the genesis command printed hc_auth_multisig '${said}' but wrote $HC_AUTH_MULTISIG_REPORTED" >&2; exit 1; }
[ "$HC_AUTH_MULTISIG_REPORTED" = "$EXPECT_HC_AUTH_MULTISIG" ] || { echo "cut-chain22: this rand-node's multisig auth guest is $HC_AUTH_MULTISIG_REPORTED, not EXPECT_HC_AUTH_MULTISIG $EXPECT_HC_AUTH_MULTISIG — another build's guest" >&2; exit 1; }
echo "cut-chain22: this rand-node reports hc_bundle $HC_REPORTED, hc_auth $HC_AUTH_REPORTED, hc_auth_multisig $HC_AUTH_MULTISIG_REPORTED (= EXPECT_HC_AUTH_MULTISIG)"
# `genesis --multisig` prints `  multisig <id> <balance> RAND, 2 of 3 signers`: the same id, the same balance.
said=$(sed -n 's/^  multisig \([0-9a-f]\{64\}\) .*/\1/p' "$TMP/genesis.out")
[ "$said" = "$TREASURY_ID" ] || { echo "cut-chain22: rand-node genesis --multisig printed treasury id '${said}', the offline derivation $TREASURY_ID" >&2; exit 1; }
said_bal=$(sed -n 's/^  multisig [0-9a-f]\{64\} \([0-9.]*\) RAND, 2 of 3 signers$/\1/p' "$TMP/genesis.out")
want_bal=$(python3 -c 'import os,sys; exec(os.environ["UNITS_PY"]); print(fmt(int(open(sys.argv[1]).read())))' "$TMP/treasury-balance")
[ -n "$said_bal" ] && [ "$said_bal" = "$want_bal" ] || { echo "cut-chain22: rand-node genesis printed the treasury as '${said_bal:-nothing}' RAND (2 of 3), TREASURY says $want_bal RAND" >&2; exit 1; }
echo "cut-chain22: rand-node genesis --multisig prints the same treasury id and $said_bal RAND, 2 of 3"
export HC_REPORTED HC_AUTH_MULTISIG_REPORTED
# Built in $TMP; lands at $OUT only once it has passed every check, `init` and the field probe.
FINAL_OUT=$OUT; OUT=$TMP/genesis.json; export OUT

py_splice
# OPS-6 (docs/deploy.md, "Cut policy" / "Key separation"): while deploy/key-separation says
# `met: no`, the finished file must carry `"testnet": true` (py_splice asserts it too).
require_key_separation_or_testnet "$OUT"
echo "cut-chain22: key separation: $(sed -n 's/^met:[[:space:]]*//p' deploy/key-separation | head -1) — the finished file carries testnet: true (OPS-6)"

INIT=$("$NODE" init --datadir "$TMP/probe" --genesis "$OUT")
echo "$INIT"
HASH=$(printf '%s\n' "$INIT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ -n "$HASH" ] || { echo "cut-chain22: rand-node init printed no genesis hash" >&2; exit 1; }
[ "$HASH" != "$CHAIN21_HASH" ] || { echo "cut-chain22: init derived chain 21's hash" >&2; exit 1; }
grep -q "(chain id $CHAIN_ID)" <<<"$INIT" || { echo "cut-chain22: init does not say chain id $CHAIN_ID" >&2; exit 1; }
# What `init` prints of chain 21's carried gas fields: its gas line names the ceilings and the byte load.
grep -qF "ceiling $MAX_GAS_PRICE/$MAX_BYTE_PRICE, byte load paying" <<<"$INIT" \
  || { echo "cut-chain22: init's gas line does not say 'ceiling $MAX_GAS_PRICE/$MAX_BYTE_PRICE, byte load paying'" >&2; exit 1; }
HASH2=$("$NODE" init --datadir "$TMP/probe2" --genesis "$OUT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ "$HASH2" = "$HASH" ] || { echo "cut-chain22: init re-derived $HASH2, first $HASH" >&2; exit 1; }
# `init` prints no line for the new fields — but it has run Genesis::validate over them
# (PerpsConfig::check's max_window_heights range and engine height bound, max_accounts ≥ the
# seeded accounts). The field probe proves each is in the hash, and `check-limits` reads them back
# from a running node (rand_getPerps, rand_getLimits.multisig, rand_getTokens; refuse_panics
# through the hash alone).
probe_fields "$OUT" "$HASH"

if [ "${DRY_RUN:-}" = 1 ] && [ "${DRY_RUN_NO_PROBE:-}" != 1 ]; then
  # A loopback probe node: 127.0.0.1 only, no bootstrap, no mDNS, a throwaway key, a temp datadir.
  read -r P2P RPCP < <(python3 -c 'import socket
s=[socket.socket() for _ in range(2)]
[x.bind(("127.0.0.1",0)) for x in s]; print(*[x.getsockname()[1] for x in s])')
  "$NODE" keygen --out "$TMP/probe-node.key.json" >/dev/null
  "$NODE" run --datadir "$TMP/probe" --key "$TMP/probe-node.key.json" --listen "/ip4/127.0.0.1/tcp/$P2P" \
    --rpc "127.0.0.1:$RPCP" --no-mdns > "$TMP/probe-node.log" 2>&1 &
  PROBE_PID=$!
  for _ in $(seq 1 60); do
    curl -s -m 2 -X POST "127.0.0.1:$RPCP" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"rand_getHealth","params":[]}' | grep -q result && break
    kill -0 "$PROBE_PID" 2>/dev/null || { echo "cut-chain22: the loopback probe node exited: $(tail -3 "$TMP/probe-node.log") — a genesis with hc_auth_multisig needs the msauth verifier key: RAND_MSAUTH_VK=<msauth-vk-production.bin> (crates/randprotocol-zkvm/keys/)" >&2; exit 1; }
    sleep 1
  done
  echo "cut-chain22: loopback probe node up on 127.0.0.1:$RPCP — check-limits:"
  CHECK_RPC=http://127.0.0.1:$RPCP CHECK_GENESIS=$OUT EXPECT_GENESIS_HASH=$HASH TREASURY_ID=$TREASURY_ID py_check_limits
  kill "$PROBE_PID" 2>/dev/null || true; wait "$PROBE_PID" 2>/dev/null || true; PROBE_PID=
fi

[ ! -e "$FINAL_OUT" ] || { echo "cut-chain22: $FINAL_OUT appeared during the cut — refusing to overwrite it" >&2; exit 1; }
cp "$OUT" "$FINAL_OUT"; OUT=$FINAL_OUT
TS=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['timestamp_ms'])" "$OUT")
AGE=$(( ( $(date +%s) * 1000 - TS ) / 1000 ))

cat <<EOF

cut-chain22: wrote $OUT (sha256 $(shasum -a 256 "$OUT" | cut -c1-64))
cut-chain22: genesis hash $HASH
cut-chain22: chain id $CHAIN_ID, hc_bundle $HC_REPORTED (guest v3), hc_auth $HC_AUTH_REPORTED, hc_auth_multisig $HC_AUTH_MULTISIG_REPORTED, hardening_v6, consensus_domain 1, no aggregation, no vesting
cut-chain22: limits: max_proof_bytes $MAX_PROOF_BYTES, max_block_bytes $MAX_BLOCK_BYTES (chain 21's; 6 MiB pending the measured msauth proof)
cut-chain22: testnet: true; binding_domain: $BINDING_DOMAIN; proof_window_blocks: $PROOF_WINDOW_BLOCKS
cut-chain22: gas: $GAS_PRICE/gas, $BYTE_PRICE/KiB, bundle limit $BUNDLE_GAS_LIMIT, dynamic $GAS_DYNAMIC, ceilings $MAX_GAS_PRICE/$MAX_BYTE_PRICE, byte load $GAS_BYTE_LOAD
cut-chain22: envelope_bytes $ENVELOPE_BYTES — every genesis note sealed in the 1 860-B form
cut-chain22: bridge.fees: mint $BRIDGE_MINT_BPS bps, burn $BRIDGE_BURN_BPS bps, recipient fingerprint $FEE_RECIPIENT_FINGERPRINT (from $FEE_RECIPIENT_FILE)
cut-chain22: staking: chain 21's (max_stake_entry_bps_per_epoch $STAKE_ENTRY_BPS, admission_by_vote); no slashing
cut-chain22: program_state: cell_fee $PROGRAM_STATE_CELL_FEE$([ -n "${AUDIT_V10_SKIPPED:-}" ] && echo ", refuse_panics SKIPPED — NOT what chain 22 will be" || echo ", refuse_panics true (PST-1)")
cut-chain22: tokens: incremental_root true (TOK-1)
cut-chain22: fees: $FEES_JSON (no subsidy_net_of_fees: aggregation is refused until re-measured)
cut-chain22: perps: $([ -n "${PERPS_SKIPPED:-}" ] && echo "SKIPPED (no PERP_PROVER) — NOT what chain 22 will be" || echo "BTC-PERP on zUSD (asset 1), lot 100000, tick 100000000, 20x, maintenance 250 bps, fees 5/2 bps; max_tier 18, 24 inputs a block, 64 blocks a proof, min deposit 100000000 (1 zUSD)")
cut-chain22: perps audit v10: $([ -n "${PERPS_SKIPPED:-}${AUDIT_V10_SKIPPED:-}" ] && echo "SKIPPED — NOT what chain 22 will be" || echo "bound_payouts true (PERP-6), initial_collateral absent (0), sparse_windows true + max_window_heights $PERPS_MAX_WINDOW_HEIGHTS (PERP-101), engine_program_log_height $ENGINE_PROGRAM_LOG_HEIGHT (CON-60)")
cut-chain22: perps engine_hc: $([ -n "${PERPS_SKIPPED:-}" ] && echo "SKIPPED" || echo "$EXPECT_ENGINE_HC ($PERP_IMAGE)")
cut-chain22: PERPS GENESIS ROOT ${PERP_GENESIS_ROOT:-SKIPPED}
cut-chain22: multisig: create_fee $MULTISIG_CREATE_FEE (1 RAND)$([ -n "${AUDIT_V10_SKIPPED:-}" ] && echo ", max_accounts SKIPPED" || echo ", max_accounts $MULTISIG_MAX_ACCOUNTS (MSA-4)"); the treasury 2 of 3 (chain 21's signers), $(python3 -c 'import os,sys; exec(os.environ["UNITS_PY"]); print(fmt(int(open(sys.argv[1]).read())))' "$TMP/treasury-balance") RAND NEW ISSUANCE (not carried), salt $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["accounts"][0]["salt"])' "$TMP/multisig.json")
cut-chain22: TREASURY ID $TREASURY_ID
cut-chain22: 26 validators × $STAKE_RAND RAND (quorum 18); faucet minters: $FAUCET_MINTERS
cut-chain22: bridge: $(python3 -c "import json,sys;b=json.load(open(sys.argv[1]))['bridge'];print('emitters', json.dumps(b['emitters'], sort_keys=True), '| min_inbound_sequence', json.dumps(b['min_inbound_sequence'], sort_keys=True), '| burn_sequence', b['burn_sequence'], '| guardian set', b['guardian_set_index'], '| rotation', json.dumps(b['rotation']))" "$OUT")
cut-chain22: NOT carried: shielded notes of wallets the operator does not hold, any unwithdrawn validator rewards, chain 21's multisig register (the treasury's vault), perps exchange and program vaults — the cut record's drops: line.
cut-chain22: next: the second operator rebuilds the hash from this file on another machine and writes \`second-hash: $HASH\` into $CUT_RECORD — deploy/cutover-fleet-chain22.sh (to be derived from chain 21's) push refuses without it.
cut-chain22: record in $CUT_RECORD: the genesis hash, the TREASURY ID and the PERPS GENESIS ROOT above (treasury-id: / perps-genesis-root: lines).
cut-chain22: after launch: NODE=… $0 check-limits <first node's RPC> $OUT   (before the first bundle, deposit and state proof)
cut-chain22: operations: msauth-vk-production.bin (sha256 68facb06…cd30) beside rand-node on every chain-22 node; NTP on every validator (perps block time is consensus input); a perp-view service and a prover host (~22 GB a proof) whose perp-prover builds sparse jobs (durian 28cebfb+); token collateral is outside the supply audit (M6).

⚠  Stamped $AGE s ago; the chain's clock starts there. Launch within MINUTES, or delete $OUT and re-cut.
EOF
[ "${DRY_RUN:-}" != 1 ] || echo "cut-chain22: DRY RUN — every step above ran on synthetic inputs; $OUT is NOT chain 22, launch nothing from it. max_window_heights $PERPS_MAX_WINDOW_HEIGHTS and max_accounts $MULTISIG_MAX_ACCOUNTS are $([ -n "$DRY_PLACEHOLDERS" ] && echo "PLACEHOLDERS ($DRY_PLACEHOLDERS)" || echo "the operator's").$([ -n "${PERPS_SKIPPED:-}" ] && echo ' ⚠ PERPS SKIPPED.')$([ -n "${AUDIT_V10_SKIPPED:-}" ] && echo ' ⚠ AUDIT_V10 SKIPPED.')"
