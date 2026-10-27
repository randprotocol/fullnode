#!/usr/bin/env bash
# Cut the chain-21 genesis: chain 20's shape and value, cut from a snapshot of chain 20, on a build
# carrying the genesis `fees`, `perps` and `multisig` sections (main at 6f1cd272 or later) and
# private multisig's `hc_auth_multisig` (feat/private-multisig, 712c6336 or later), with three new
# genesis sections and one new field switched on (docs/deploy.md, "The next cut: the `fees` section
# (chain 21)"; the user's decisions 2026-10-08 and 2026-10-11):
#   - `fees: {burn_base: true, burn_floor: true}` — every bundle's settled floor is burned;
#   - `perps` — RPL-3 perpetual futures: ONE market, BTC-PERP, collateral zUSD (token index 1),
#     the pinned durian.market engine (engine_hc f286a611…), max_tier 18 / max_block_inputs 24;
#   - `multisig` — create_fee 1 RAND and ONE seeded account, the foundation treasury: 2 of 3
#     signers, its balance NEW ISSUANCE (never carried from a chain-20 wallet);
#   - `hc_auth_multisig` — private multisig: this build's multisig auth guest (9705f8e2…), with
#     chain 21's decided limits for it, 6 MiB proofs and 19 MiB blocks.
#
#   deploy/cut-chain21-genesis.sh snapshot <dir>     # chain 20 still up, bridge daemons stopped
#   WALLET=<chain 20's rand, v0.7.0> deploy/cut-chain21-genesis.sh balances <dir>
#                                                    # read-only toward the chain: the RAND carry list
#   CUT_RECORD=<record> CHAIN20_SNAPSHOT=<dir> NODE=<the cut build's rand-node> WALLET=<its rand> \
#     EXPECT_NODE_VERSION=<that release> PERP_PROVER=<durian's perp-prover> \
#     [PERP_IMAGE=<perp-engine.image.bin>] [TREASURY=<treasury.txt>] deploy/cut-chain21-genesis.sh
#                                                    # the cut
#   NODE=<the cut build's rand-node> deploy/cut-chain21-genesis.sh check-limits <rpc url> <genesis file>
#                                                    # after launch: what the first node serves
#                                                    # (base_fees_burned must be "0": run it before the
#                                                    # first bundle lands, or BASE_FEES_BURNED_ANY=1;
#                                                    # perps proved_height must be 0: before the first
#                                                    # state proof)
#   SELFTEST=1 deploy/cut-chain21-genesis.sh         # no network, no binaries: the assembly on fixtures
#   DRY_RUN=1 NODE=… WALLET=… PERP_PROVER=… [TREASURY=…] deploy/cut-chain21-genesis.sh
#                                                    # no network: the REAL cut path (rand-node genesis,
#                                                    # alloc-note, perp-prover genesis-state, init, a
#                                                    # loopback probe node) on inputs synthesised from
#                                                    # the committed chain-20 genesis (no TREASURY file:
#                                                    # three throwaway signer keys are generated)
#
# The new inputs (all outside the repository):
#   PERP_IMAGE        the engine image (default $DURIAN/artifacts/perp-engine.image.bin, DURIAN
#                     default ~/Github/randprotocol/durian.market); `rand perp image-hc --image`
#                     must print EXPECT_ENGINE_HC.
#   EXPECT_ENGINE_HC  f286a61171e274278ec8d18d7853e5f36799ed8dc5a3e31e0077ad89ef1d1573, the pinned
#                     image's (durian.market artifacts/perp-engine.image.bin.hc); any other refused.
#   PERP_PROVER       durian.market's `perp-prover`, built from the commit that pinned the image
#                     (its perp-core encodes the engine's genesis state: state layout version 2). No
#                     default; the real cut refuses without it, DRY_RUN skips perps LOUDLY.
#   TREASURY          default ~/.rand-chain21/treasury.txt, the operator's treasury file:
#                       signer <name> <Dilithium2 public key, 2624 hex>     × exactly 3, in order
#                       threshold 2
#                       balance <RAND, decimal>                             (new issuance, > 0)
#                     `#` lines and blank lines ignored. Public keys only — each signer generates
#                     its key on its own machine (docs/multisig.md); never two keys in one place.
#
# What perps adds to OPERATIONS (not checked by this script — the cut record's `clients:` and the
# launch checklist must say each is in place):
#   - NTP on every validator: a perps chain's block time is consensus input (docs/perps.md, "Block
#     time is bounded"; already true of a bridged chain — chain 20's validators run it).
#   - A perp-view service (`perp-prover serve`, the site's /api/perp-view) and a prover host
#     (`perp-prover run`): a production-FRI proof peaks near 22 GB of RAM; proving is open and
#     unpaid in v0, and a withdrawal is paid only when the proofs reach its block. A 64-block window
#     does not fit tier 18 (≈ 25 k cycles a close with funding running): the prover halves its
#     window until it fits.
#   - The supply audit does NOT cover token collateral (docs/perps.md v0 limit M6): the perps term
#     counts RAND only, so a zUSD deposit/payout imbalance inside the exchange is invisible to
#     `rand_getSupply`'s identity. The user chose zUSD knowing this (2026-10-11).
#
# DERIVED from deploy/cut-chain20-genesis.sh (chain 20 — v0.6.8, live since 2026-10-01 06:17 UTC,
# genesis 6210cf07…5135, running v0.7.0 (806ed349) since 2026-10-02; v0.7.1 was tagged, never
# rolled — is chain 21's predecessor): the same snapshot /
# balances / carry-over rule / splice, with chain 20 as the source. Read it first. What this script
# does that chain 20's did not:
#
#   * THE NEW GENESIS FIELD, the value docs/deploy.md recommends (the user's standing rule: take the
#     recommended value every time; the decision for this cut, 2026-10-08), asserted on the
#     finished file, proved to be part of the genesis hash by this rand-node (the cut re-derives the
#     hash with the section taken out, and with `burn_floor` taken out, and refuses if it does not
#     move — a build that ignores the section would launch a chain without it), and read back from
#     the first node after launch (`check-limits`):
#       - `fees: {burn_base: true, burn_floor: true}` (`--fees <fees.json>`, the file written by this
#         script; docs/fees.md §1.3): every bundle's whole settled floor — the base, a Deploy's
#         per-word term, a Call's tier-exact gas and byte terms — is destroyed instead of paid; the
#         proposer keeps only `fee − floor`. `rand_getLimits.fee_rules` serves it;
#         `rand_getSupply.base_fees_burned` counts the burn ("0" at launch).
#       - NOT `fees.subsidy_net_of_fees`: it needs an `aggregation` section, and this build refuses
#         a genesis with one at startup until the admitted shape is re-measured against the
#         hidden-asset bundle (b053a76). A genesis that sets it is refused, with that reason.
#       - The `--fees` flag exists only on a build at d6cc16f5 or later: the real cut REFUSES a
#         rand-node without it; DRY_RUN skips the section, LOUDLY, when the binary in hand lacks it.
#   * THE NEW `perps` SECTION (docs/perps.md, "The genesis section"; the user's decision
#     2026-10-11), the script's constant PERPS_JSON plus two commitments the cut derives — asserted
#     on the finished file, proved to be part of the hash (without `perps`, and without
#     `perps.min_deposit`), read back after launch (`rand_getLimits.perps`, `rand_getPerps`):
#       - collateral_asset 1 = zUSD (FIRST_TOKEN_INDEX; the finished file's tokens.tokens[0] must
#         be zUSD); ONE market {id 0, BTC-PERP, lot 100000 (0.0001 BTC at BASE_UNIT 10^9), tick
#         100000000 ($1 a BTC), max_leverage 20, maintenance_bps 250, taker 5 / maker 2 bps};
#         max_tier 18, max_block_inputs 24 (the documented production sizing, gated by
#         durian.market's `block-24-14liq`), max_window_blocks 64, min_deposit 100000000 (1 zUSD).
#         zUSD has EIGHT decimals (BRIDGE_DECIMALS): $1 is 10^8 units, not 10^9 — see PERPS_JSON.
#       - engine_hc = `rand perp image-hc --image $PERP_IMAGE` = EXPECT_ENGINE_HC (the pinned image).
#       - genesis_root = `rand perp genesis-root --state` over `$PERP_PROVER genesis-state` of the
#         market list: printed in the cut output for the record.
#       - SPLICED, not passed as `rand-node genesis --perps`: the base file lists no token (zUSD is
#         a bridged token, and `rand-node genesis` writes no bridge section, so it is spliced in
#         with the bridge), and `Genesis::validate` refuses `collateral_asset 1` on a file whose
#         token list is empty ("is not a token this genesis lists"). The section rides the splice
#         beside zUSD and `rand-node init` on the finished file runs the whole of
#         `Genesis::validate` over it (`PerpsConfig::check`, the confidential/tokens/gas/
#         hardening_v6/hc_auth requirements, the collateral index); the field probe proves it is
#         hashed. A rand-node that does not know the section ignores it (no deny_unknown_fields)
#         and the probe refuses it.
#   * THE NEW `multisig` SECTION (docs/multisig.md; docs/deploy.md "The next cut: a `multisig`
#     section (the treasury)"), written by the script from $TREASURY and passed as `rand-node
#     genesis --multisig` — asserted, probed (without `multisig`, without `multisig.create_fee`),
#     read back (`rand_getLimits.multisig`, `rand_getSupply.multisig_issued`, `rand_getMultisig`):
#       - create_fee "1000000000" (1 RAND, docs' recommended value; never 0 at this cut);
#       - ONE account: exactly 3 signers in the file's order, threshold 2, a fresh 32-byte salt per
#         cut (printed), balance = TREASURY's `balance` in units (the exact `units()`, no float).
#         A signer key that is a validator's, a bridge guardian's or the pause key is refused, and
#         so is one listed twice.
#       - The id is derived offline (`rand-node multisig id`) and must equal what `rand-node genesis
#         --multisig` prints; the cut prints `TREASURY ID <id>`, and the cut record must name the
#         treasury (`reason:` or `carries:` mentions treasury/multisig — require_cut_record_mentions).
#       - The carry rule is untouched: Σ RAND notes == Σ scanned balances; the treasury is NOT a
#         note and NOT carried — it is printed as new issuance, and Σ notes + Σ stakes + treasury
#         must fit a u64 (`SupplyOverflow`).
#       - `--multisig` exists from 3119a29a on: the real cut REFUSES a rand-node without it; DRY_RUN
#         skips the section, LOUDLY (MULTISIG_SKIPPED), as it does `fees`.
#   * THE NEW hc_auth_multisig FIELD (private multisig phase 4; feat/private-multisig 712c6336,
#     docs/superpowers/specs/2026-10-11-private-multisig-phase4-design.md §2), written by `rand-node
#     genesis --auth-multisig-guest` (clap: requires --auth-guest) from the build's own
#     ZkExecutor::hc_auth_multisig() — never typed — asserted, probed, read back:
#       - = EXPECT_HC_AUTH_MULTISIG (9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247,
#         circuits' msauth guest; any other value is refused like EXPECT_ENGINE_HC), the binary's
#         own reported value equal to it; hc_auth present and a different guest; the LAST field of
#         the file (and hashed last, a tagged append after aggregation_tree, so chain 20's hash is
#         unchanged); max_proof_bytes ≥ 4 MiB (the node's ProofCapTooSmallForMsauth at production).
#       - excused from the chain-20 comparison (chain 20 has none; chain 20's file carrying one is
#         refused); one more field-probe variant (without hc_auth_multisig: 7 in all); check-limits
#         reads it from rand_getLimits and rand_status (private-multisig Task 5's fields: a build
#         before them serves neither, and check-limits then refuses a chain that has the field).
#       - chain 21's limits move for it: max_proof_bytes 6 MiB, max_block_bytes 19 MiB (see
#         MAX_PROOF_BYTES; 6 MiB pending the measured production proof size).
#       - every chain-21 node needs the msauth verifier key beside rand-node
#         (/usr/local/bin/msauth-vk-production.bin, or RAND_MSAUTH_VK / --msauth-vk) or it refuses
#         to start; DRY_RUN's loopback probe node too (set RAND_MSAUTH_VK to the committed blob).
#       - The cut record must name it (`reason:` or `carries:` mentions hc_auth_multisig / private
#         multisig). `--auth-multisig-guest` exists from 712c6336 on: the real cut REFUSES a
#         rand-node without it; DRY_RUN skips the field, LOUDLY (AUTH_MULTISIG_SKIPPED), as it does
#         `multisig`.
#   * EVERYTHING ELSE IS CHAIN 20'S, ASSERTED EQUAL: what chain 20's script switched on — testnet,
#     binding_domain 1, proof_window_blocks 1024, the gas ceilings 10000/80000 and the paying byte
#     load, bridge.rotation 86400/possession, bridge.fees 10/10 bps to the fingerprinted recipient,
#     staking's 2500-bps entry budget and admission by vote, program_state cell_fee 10000000 — is
#     now part of "chain 20's shape": each still asserted at its value, and the finished file
#     compared field by field with deploy/genesis-chain20.json. No `vesting`, no `aggregation`, no
#     `staking.slashing`, no `tokens.incremental_root`, no `incremental_nullifier_root` (the last
#     two are refused as fields this script does not know or as a token switch chain 20 lacks).
#   * THE BRIDGE IS CHAIN 20'S, NOT RE-DEPLOYED: EMITTER_2..5 default to chain 20's genesis
#     `bridge.emitters` (the 2026-09-30 endpoints; Solana unchanged), checked against
#     deploy/genesis-chain20.json itself, and refused otherwise unless EMITTERS_CHANGED=1. The
#     2026-09-19 endpoints chains 14–18 trusted are refused outright, EMITTERS_CHANGED or not.
#     `bridge.rotation` and `bridge.fees` (recipient included) must equal chain 20's.
#   * THE REPLAY FLOORS, per source chain 2..5: `auto` (default) = that endpoint's next outbound
#     sequence at the snapshot — last minted + 1 when every lock minted on chain 20 (the custody ==
#     locked check fails otherwise) — never below chain 20's own floor. An explicit floor overrides
#     it, from MIN_INBOUND_<c>=<n> or MIN_INBOUND_FILE (lines "<chain> <floor>"; one source per
#     chain — both for one chain is refused). A floor below 1 on chains 2, 3 and 4 is refused
#     outright: sequence 0 on each redeployed endpoint is the operator's consume-step lock, which
#     must never mint. `none` is refused on every chain (each endpoint was minted from).
#   * OPS-7, deploy/lib/cut-policy.sh: the cut refuses a chain id any deploy/genesis*.json already
#     has (`refuse_reused_chain_id`) and a missing or unfilled cut record (`require_cut_record
#     "$CUT_RECORD"`, deploy/cut-record.template); on the finished file it calls OPS-6's
#     `require_key_separation_or_testnet` (chain 20's script predates it). No deploy/cutover-fleet-chain21.sh exists yet:
#     the second operator's rebuild (`require_second_rebuild`) is checked by that script's `push`
#     once it is derived from deploy/cutover-fleet-chain20.sh.
#   * `balances` rescans every wallet from leaf 0 (`rand sync --rescan`; BALANCES_RESCAN=0 to sync
#     incrementally): a key file's note store on the laptop can be stale — the relayer's is (the
#     relayer runs on droplet rand-relayer-1; the laptop holds only its key), and the scan must
#     rest on the chain alone. REQUIRED_WALLETS (default `relayer`) names key files that must be
#     present under WALLETS_DIRS before the scan starts.
#   * The SSH tunnel to obs1 is checked (`rand_getGenesisHash` answers, and is chain 20's) right
#     before `snapshot` and right before `balances`, not only described.
#   * NODE must report rand-node $EXPECT_NODE_VERSION for the cut, and EXPECT_NODE_VERSION has no
#     default: the release that carries the fees section is v0.8.0 (d6cc16f5 reported 0.7.1, a
#     version chain 20 never ran; chain 20 runs 0.7.0, which lacks `--fees`). Set it to 0.8.0, or
#     cut with NODE_VERSION_OK=1 knowingly; `--fees` itself is checked either way. `balances` runs
#     with chain 20's own build, v0.7.0 (WALLET, built from tag v0.7.0 = 806ed349).
#
# Traps carried from the chain-17 to 20 cuts (AGENTS.md):
#   - `balances` scans CURATED directories of wallet key files, `$WALLETS_DIRS` =
#     ~/.rand-chain17/alloc-wallets (symlinks: shielded-1..5 and the relayer →
#     ~/.rand-chain14/wallets/relayer.key.json; that link went missing once and the scan then listed
#     its alloc as "uncovered"), ~/.rand-chain18/wallets, ~/.rand-chain19/wallets and
#     ~/.rand-chain20/wallets. Never a checkout's `wallets/`. CHECK BEFORE THE SCAN that every
#     wallet holding RAND on chain 20 has its key file (or a symlink) in one of them; the scan also
#     lists chain 20's genesis allocs that no scanned wallet covers, and the cut refuses while that
#     list is non-empty.
#   - `balances` refuses to overwrite <dir>/balances.json and $ALLOC_ADDRESSES: move a first scan
#     aside to re-scan.
#   - The public RPC (Cloudflare) answers Python's urllib with 403: point CHAIN20_RPC at an SSH
#     tunnel to obs1's RPC (the archive, `prune_floor` 0), e.g.
#     `ssh -N -L 8545:127.0.0.1:8545 root@203.0.113.29` → CHAIN20_RPC=http://127.0.0.1:8545.
#     The tunnel died twice in the hour of the chain-18 cut (once silently); this script refuses
#     to start `snapshot` or `balances` on a dead one — re-open it and re-run.
#   - Take the snapshot with the SAME EMITTER_* the cut uses (the defaults): custody and sequences
#     are read at those addresses, and the cut refuses a snapshot read anywhere else.
#   - `rand-node genesis` writes no bridge section: the hash that matters is the one `rand-node
#     init` prints on the FINISHED file (this script's last lines), never the base file's.
#   - The fee recipient file (FEE_RECIPIENT_FILE, default ~/.rand-chain20/fee-recipient-address.txt)
#     is chain 20's: the cut refuses a recipient whose fingerprint is not 89DS-4Q4X-HXSX-MBYW, and
#     one that is not chain 20's genesis `bridge.fees.recipient`.
#
# The carry-over rule (chain 20's, unchanged): zUSD per-backing `locked` = chain 20's at the
# snapshot with one fresh genesis note per $ZUSD_CARRY line (Σ notes == Σ locked == source custody);
# RAND = one genesis note per operator wallet the `balances` scan found holding RAND, at its
# chain-20 balance (Σ alloc == Σ scanned); a validator's unwithdrawn rewards are refused unless
# REWARDS_DROPPED_OK=1 (never carried); pending notes refused unless PENDING_OK=1; uncovered
# chain-20 genesis allocs refused unless UNCOVERED_ALLOCS_OK=1. SHIELDED NOTES OF WALLETS THE
# OPERATOR DOES NOT HOLD ARE NOT CARRIED — the cut record's `drops:` line must say so.
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash (fresh note randomness and a
# fresh timestamp). Cut once, distribute the file byte-identically, launch within minutes.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091  # sourced from the repo root (the cd above); run shellcheck -x to follow
. deploy/lib/key-guard.sh
# shellcheck disable=SC1091
. deploy/lib/cut-policy.sh

NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
CHAIN_ID=${CHAIN_ID:-21}
OUT=${OUT:-deploy/genesis-chain21.json}
CUT_RECORD=${CUT_RECORD:-$HOME/.rand-chain21/cut-record.txt}   # deploy/cut-record.template, filled in and published before the cut
EXPECT_NODE_VERSION=${EXPECT_NODE_VERSION:-}                  # no default: the release carrying d6cc16f5's fees section is untagged (see the header)
CHAIN20_GENESIS=${CHAIN20_GENESIS:-deploy/genesis-chain20.json}
CHAIN20_HASH=${CHAIN20_HASH:-6210cf071a390d7ac61d8cbea5dd9d139d1a493a862b54a45a498f36af2d5135}
CHAIN20_GENESIS_SHA256=${CHAIN20_GENESIS_SHA256:-0020247a1b51a2b012e62bdb2d225ed59dbc42d39163a70530c07c60040f3a21}
CHAIN20_RPC=${CHAIN20_RPC:-http://127.0.0.1:8545}          # snapshot/balances: an SSH tunnel to obs1's RPC (the archive; Cloudflare 403s urllib)
CHAIN20_SNAPSHOT=${CHAIN20_SNAPSHOT:-}                       # the cut: the snapshot directory

# ── public inputs, all outside the repository ─────────────────────────────────────────────────
VALIDATORS_TSV=${VALIDATORS_TSV:-$HOME/.rand-chain14/public/validators.tsv}   # name addr pk peer payout (18)
REGISTRATIONS=${REGISTRATIONS:-$HOME/.rand-chain15/registrations}              # <name>.txt, one per bonded validator (8)
BONDED=${BONDED:-obs1 archive2 g1 g2 g3 g4 g5 g6}
GENESIS_NAMES=${GENESIS_NAMES:-a b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1}
FAUCET_MINTERS=${FAUCET_MINTERS:-$GENESIS_NAMES}   # chain 20's list; another one needs FAUCET_MINTERS_CHANGED=1
FAUCET_RECIPIENTS=${FAUCET_RECIPIENTS:-}           # unset: chain 20's genesis allowlist; a file ("<name> rand1…") changes it
STAKE_RAND=${STAKE_RAND:-1000}
ALLOC_ADDRESSES=${ALLOC_ADDRESSES:-$HOME/.rand-chain21/alloc-rand.txt}   # "<label> rand1… <RAND>" per line (`balances` writes it)
ZUSD_CARRY=${ZUSD_CARRY:-$HOME/.rand-chain21/zusd-carry.txt}             # "<label> rand1… <zUSD>" per line
WALLETS_DIRS=${WALLETS_DIRS:-$HOME/.rand-chain17/alloc-wallets $HOME/.rand-chain18/wallets $HOME/.rand-chain19/wallets $HOME/.rand-chain20/wallets}   # `balances`: dirs of *.key.json (a missing dir is skipped, printed); never a checkout's wallets/
REQUIRED_WALLETS=${REQUIRED_WALLETS:-relayer}      # `balances`: <name>.key.json that must be under WALLETS_DIRS before the scan (the relayer's link went missing once)
BALANCES_RESCAN=${BALANCES_RESCAN:-1}              # `balances`: `rand sync --rescan` (from leaf 0) — never trust a laptop note store
RELAYER_DONE_DIR=${RELAYER_DONE_DIR:-}             # optional: a copy of the relayer's done/ (done/<chain>/<seq>; the relayer runs on rand-relayer-1), a floor cross-check
EXPECT_HC_BUNDLE=${EXPECT_HC_BUNDLE:-60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce}   # bundle guest v3, chain 20's
EXPECT_HC_AUTH=${EXPECT_HC_AUTH:-1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1}     # the auth guest, chain 20's
# private multisig's auth guest (MSAUTH_HC, crates/randprotocol-zkvm/tests/guest_provenance.rs on
# feat/private-multisig): `rand-node genesis --auth-multisig-guest` writes the build's own; any other
# expected value is refused below (another guest edits this script and docs/deploy.md together).
HC_AUTH_MULTISIG_DECIDED=9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247
EXPECT_HC_AUTH_MULTISIG=${EXPECT_HC_AUTH_MULTISIG:-$HC_AUTH_MULTISIG_DECIDED}

# ── the limits: chain 20's, asserted equal to its genesis unless LIMITS_CHANGED=1 — except the two
# chain 21 decides for private multisig (hc_auth_multisig), asserted at those values unless
# LIMITS_CHANGED=1: a multisig auth proof plus its bundle is estimated near 4.8 MB at production
# FRI, and the node refuses a cap below 4 MiB beside hc_auth_multisig (gas::MSAUTH_MIN_PROOF_BYTES).
#   - max_proof_bytes 6 MiB (6291456; chain 20's was 4 MiB). PENDING the measured production msauth
#     proof size (private-multisig phase 4, Task 3: prove still to run from the user's terminal); a
#     measurement re-decides it, here and in docs/deploy.md together.
#   - max_block_bytes 19 MiB (19922944; chain 20's was 20 MiB): exactly 3 · 6 MiB + 1 MiB, the
#     three-proof Call rule (a `Call` carries bundle, auth and call proofs). GAS_DYNAMIC's byte target
#     follows as max_block_bytes / 2 (9961472; chain 20's 10485760) — the one gas field that moves.
MAX_PROGRAM_WORDS=${MAX_PROGRAM_WORDS:-65535}
MAX_PROOF_BYTES=${MAX_PROOF_BYTES:-6291456}
MAX_BLOCK_BYTES=${MAX_BLOCK_BYTES:-19922944}
MAX_CALL_ENVELOPE_BYTES=${MAX_CALL_ENVELOPE_BYTES:-65536}
MAX_PROGRAM_PUBLIC_WORDS=${MAX_PROGRAM_PUBLIC_WORDS:-32768}
EPOCH_BLOCKS=${EPOCH_BLOCKS:-1000}

# ── the source endpoints chain 20 trusts (its genesis `bridge.emitters`): chain 21 keeps them ───
C20_EMITTER_2=0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa   # Ethereum  0x7aF6b17047C1db6cB54347FdEa45cF9179075bfA (2026-09-30)
C20_EMITTER_3=0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa   # BNB Chain 0x7aF6b17047C1db6cB54347FdEa45cF9179075bfA (2026-09-30)
C20_EMITTER_4=0000000000000000000000006410797df959987a5baf65b5fab97edeb34d5163   # Tron      TK6JJv55CCkFjNHq7WwoU91GKaZEiC93me (2026-09-30)
C20_EMITTER_5=d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a   # Solana, never redeployed
# The 2026-09-19 endpoints chains 14–18 trusted: never again (their old locks would replay).
OLD_EMITTERS="000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892 0000000000000000000000000992df85dcce77ded2c0387f1fa9cf98ac859700"
EMITTER_2=${EMITTER_2:-$C20_EMITTER_2}
EMITTER_3=${EMITTER_3:-$C20_EMITTER_3}
EMITTER_4=${EMITTER_4:-$C20_EMITTER_4}
EMITTER_5=${EMITTER_5:-$C20_EMITTER_5}
for c in 2 3 4 5; do
  e=EMITTER_$c; o=C20_EMITTER_$c
  case " $OLD_EMITTERS " in *" ${!e} "*)
    echo "cut-chain21: EMITTER_$c=${!e} is a 2026-09-19 endpoint chains 14–18 trusted — never again (EMITTERS_CHANGED does not override this)" >&2; exit 1;; esac
  [ "${!e}" = "${!o}" ] || [ "${EMITTERS_CHANGED:-}" = 1 ] || {
    echo "cut-chain21: EMITTER_$c=${!e} is not chain 20's endpoint ${!o} — set EMITTERS_CHANGED=1 only for a knowingly new endpoint" >&2; exit 1; }
done
# Replay floors: MIN_INBOUND_<c> (env) or MIN_INBOUND_FILE ("<chain> <floor>" per line), else `auto`.
if [ -n "${MIN_INBOUND_FILE:-}" ]; then
  [ -f "$MIN_INBOUND_FILE" ] || { echo "cut-chain21: MIN_INBOUND_FILE=$MIN_INBOUND_FILE is not a file" >&2; exit 1; }
  while read -r fc fv rest; do
    case "$fc" in ''|'#'*) continue;; 2|3|4|5) ;; *) echo "cut-chain21: $MIN_INBOUND_FILE: '$fc $fv' — the chain must be 2, 3, 4 or 5" >&2; exit 1;; esac
    [ -z "$rest" ] && [[ "$fv" =~ ^[0-9]+$ ]] || { echo "cut-chain21: $MIN_INBOUND_FILE: '$fc $fv $rest' is not \"<chain> <floor>\"" >&2; exit 1; }
    v=MIN_INBOUND_$fc
    [ -z "${!v:-}" ] || { echo "cut-chain21: chain $fc's floor is given twice (MIN_INBOUND_$fc=${!v} and $MIN_INBOUND_FILE) — one source per chain" >&2; exit 1; }
    printf -v "$v" '%s' "$fv"
  done < "$MIN_INBOUND_FILE"
fi
for c in 2 3 4 5; do
  v=MIN_INBOUND_$c
  [ -n "${!v:-}" ] || printf -v "$v" auto
  case "${!v}" in
    auto) ;;
    none) echo "cut-chain21: MIN_INBOUND_$c=none — every chain-21 endpoint was minted from on chain 20; its old locks would replay" >&2; exit 1;;
    *) [[ "${!v}" =~ ^[0-9]+$ ]] || { echo "cut-chain21: MIN_INBOUND_$c=${!v}: a sequence or \`auto\`" >&2; exit 1; }
       if [ "$c" != 5 ] && [ "${!v}" -lt 1 ]; then
         echo "cut-chain21: MIN_INBOUND_$c=${!v} is below 1 — sequence 0 of the redeployed chain-$c endpoint is the operator's consume-step lock and must never mint" >&2; exit 1; fi
       [ "${!v}" -ge 1 ] || { echo "cut-chain21: MIN_INBOUND_$c=0 is no floor" >&2; exit 1; };;
  esac
done
# What the cut is expected to derive: chain 20's genesis floors and burn sequence, if nothing moved
# on chain 20 (a live bridge legitimately moves them — compared and warned about, never refused).
EXPECT_FLOORS=${EXPECT_FLOORS:-2:3 3:3 4:3 5:7}
EXPECT_BURN_SEQUENCE=${EXPECT_BURN_SEQUENCE:-13}
ETH_RPC=${ETH_RPC:-https://ethereum-rpc.publicnode.com}
BSC_RPC=${BSC_RPC:-https://bsc-rpc.publicnode.com}
TRON_API=${TRON_API:-https://api.trongrid.io}
SOL_RPC=${SOL_RPC:-https://api.mainnet-beta.solana.com}
SOL_PROGRAM=${SOL_PROGRAM:-FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu}

# ── gas: chain 20's section (its POOL-2 ceilings and paying byte load included), asserted equal ─
GAS_PRICE=${GAS_PRICE:-100}
BYTE_PRICE=${BYTE_PRICE:-800}
BUNDLE_GAS_LIMIT=${BUNDLE_GAS_LIMIT:-20479}                  # gas_max(14, 0, 0), every bundle proof's declared limit
GAS_DYNAMIC=${GAS_DYNAMIC:-$((MAX_BLOCK_BYTES / 2)),262144,1250}
MAX_GAS_PRICE=${MAX_GAS_PRICE:-10000}                        # 100× the start (docs/deploy.md, POOL-2)
MAX_BYTE_PRICE=${MAX_BYTE_PRICE:-80000}                      # 100× the start
GAS_BYTE_LOAD=${GAS_BYTE_LOAD:-paying}
ENVELOPE_BYTES=${ENVELOPE_BYTES:-1860}
# ── chain 20's audit-v6 / RPL-2 genesis fields, carried at chain 20's values and asserted equal ──
BINDING_DOMAIN=${BINDING_DOMAIN:-1}
PROOF_WINDOW_BLOCKS=${PROOF_WINDOW_BLOCKS:-1024}
STAKE_ENTRY_BPS=${STAKE_ENTRY_BPS:-2500}
ROTATION_DELAY_SECS=${ROTATION_DELAY_SECS:-86400}
ROTATION_NEEDS_POSSESSION=${ROTATION_NEEDS_POSSESSION:-true}
PROGRAM_STATE_CELL_FEE=${PROGRAM_STATE_CELL_FEE:-10000000}   # 0.01 RAND a created cell: docs/program-state.md, chain 20's
BRIDGE_MINT_BPS=${BRIDGE_MINT_BPS:-10}                       # chain 20's: 0.1 % each way (docs/bridge.md §25)
BRIDGE_BURN_BPS=${BRIDGE_BURN_BPS:-10}
FEE_RECIPIENT_FILE=${FEE_RECIPIENT_FILE:-$HOME/.rand-chain20/fee-recipient-address.txt}   # chain 20's recipient, the user's own wallet (one rand1… line)
FEE_RECIPIENT_FINGERPRINT=${FEE_RECIPIENT_FINGERPRINT:-89DS-4Q4X-HXSX-MBYW}
FEE_RECIPIENT=${FEE_RECIPIENT:-}                             # set by load_fee_recipient (the selftest sets a fixture)
# ── the new field: the genesis `fees` section (docs/fees.md §1.3; docs/deploy.md "The next cut: the
# `fees` section (chain 21)") — the user's decision 2026-10-08. Not overridable: a cut that wants other
# rules edits this script and docs/deploy.md together. NOT subsidy_net_of_fees (needs aggregation).
# shellcheck disable=SC2089  # JSON text in a string, exported whole, never word-split
FEES_JSON='{"burn_base": true, "burn_floor": true}'
# FEES_SKIPPED is the script's own word, never the operator's: whatever the environment says is
# captured and cleared here; the cut refuses it below (DRY_RUN ignores it, loudly), and only the
# DRY_RUN gate on a binary without --fees sets it. check-limits reads skipped-ness from the file.
FEES_SKIPPED_FROM_ENV=${FEES_SKIPPED:-}
FEES_SKIPPED=
# ── the new section: `perps` (RPL-3; docs/perps.md "The genesis section") — the user's decision
# 2026-10-11. Not overridable, like FEES_JSON: another market or bound edits this script and
# docs/deploy.md together. engine_hc and genesis_root are not in it: the cut derives both (below).
#   - collateral_asset 1: zUSD, FIRST_TOKEN_INDEX — chain 20's genesis lists exactly one token, and
#     py_splice asserts the finished file's tokens.tokens[0] is zUSD.
#   - UNITS: a price is quote (= collateral) atomic units per BASE_UNIT = 10^9 of base, and zUSD is a
#     bridged token, EIGHT decimals (tokens::BRIDGE_DECIMALS). So "$1 a BTC" is tick 10^8 and "1
#     zUSD" is min_deposit 10^8 — not the 10^9 a nine-decimal reading gives (that would be a $10
#     tick and a 10-zUSD floor). lot 100000 is 0.0001 BTC (base atomic units, BASE_UNIT = 1 BTC).
#   - maintenance_bps 250 is below the initial margin 20x implies: perp-core's Req::Initial is
#     ⌈notional / max_leverage⌉ (500 bps at 20x), Req::Maintenance ⌈notional · maintenance_bps /
#     10 000⌉. At maintenance ≥ initial a max-leverage position opens already liquidatable; the
#     engine does NOT refuse such a spec (MarketSpec::is_valid checks ranges only), so py_splice
#     does (maintenance_bps · max_leverage < 10 000).
#   - max_tier 18 with max_block_inputs 24: the documented production sizing (docs/perps.md
#     "Sizing a window"; durian.market's check gates `block-24-14liq`, 212 018 cycles, at tier 18
#     with 15 % headroom). 25 inputs is refused: nothing measured it.
# shellcheck disable=SC2089  # JSON text in a string, exported whole, never word-split
PERPS_JSON='{"collateral_asset": 1, "max_tier": 18, "max_window_blocks": 64, "max_block_inputs": 24, "min_deposit": 100000000,
 "markets": [{"id": 0, "symbol": "BTC-PERP", "lot": 100000, "tick": 100000000, "max_leverage": 20, "maintenance_bps": 250, "taker_fee_bps": 5, "maker_fee_bps": 2}]}'
ENGINE_HC_DECIDED=f286a61171e274278ec8d18d7853e5f36799ed8dc5a3e31e0077ad89ef1d1573   # durian.market artifacts/perp-engine.image.bin.hc (afe4d31)
EXPECT_ENGINE_HC=${EXPECT_ENGINE_HC:-$ENGINE_HC_DECIDED}   # any other value is refused below (the decision names this image)
DURIAN=${DURIAN:-$HOME/Github/randprotocol/durian.market}   # read only: the engine image
PERP_IMAGE=${PERP_IMAGE:-$DURIAN/artifacts/perp-engine.image.bin}
PERP_PROVER=${PERP_PROVER:-}                                 # durian's perp-prover: no default, the real cut refuses without it
PERP_GENESIS_ROOT=${PERP_GENESIS_ROOT:-}                     # set by the cut (perp-prover genesis-state → rand perp genesis-root); the selftest sets a fixture
# ── the new section: `multisig` (docs/multisig.md) — the treasury, the user's decision 2026-10-11.
# create_fee is docs' recommended 1 RAND (a create_fee of 0 is refused at this cut); one account,
# 2 of 3, new issuance. Signers and balance come from TREASURY (public keys only, see the header).
MULTISIG_CREATE_FEE=1000000000
TREASURY_THRESHOLD=2
TREASURY_SIGNERS=3
TREASURY=${TREASURY:-$HOME/.rand-chain21/treasury.txt}
# PERPS_SKIPPED / MULTISIG_SKIPPED, like FEES_SKIPPED: the script's own words, never the operator's.
# shellcheck disable=SC2034  # read through ${!v} (the *_SKIPPED_FROM_ENV loop at the cut)
PERPS_SKIPPED_FROM_ENV=${PERPS_SKIPPED:-}
PERPS_SKIPPED=
# shellcheck disable=SC2034  # likewise
MULTISIG_SKIPPED_FROM_ENV=${MULTISIG_SKIPPED:-}
MULTISIG_SKIPPED=
# AUTH_MULTISIG_SKIPPED (hc_auth_multisig): likewise, set only by DRY_RUN on a binary without
# --auth-multisig-guest.
# shellcheck disable=SC2034  # likewise
AUTH_MULTISIG_SKIPPED_FROM_ENV=${AUTH_MULTISIG_SKIPPED:-}
AUTH_MULTISIG_SKIPPED=
[ "$EXPECT_HC_AUTH_MULTISIG" = "$HC_AUTH_MULTISIG_DECIDED" ] || {
  echo "cut-chain21: EXPECT_HC_AUTH_MULTISIG=$EXPECT_HC_AUTH_MULTISIG is not the decided multisig auth guest ($HC_AUTH_MULTISIG_DECIDED, MSAUTH_HC) — another guest edits this script and docs/deploy.md together" >&2; exit 1; }
[ "$EXPECT_ENGINE_HC" = "$ENGINE_HC_DECIDED" ] || {
  echo "cut-chain21: EXPECT_ENGINE_HC=$EXPECT_ENGINE_HC is not the decided engine ($ENGINE_HC_DECIDED, durian.market's pinned image) — another engine edits this script and docs/deploy.md together" >&2; exit 1; }

# shellcheck disable=SC2090
export CHAIN_ID CHAIN20_GENESIS CHAIN20_HASH CHAIN20_GENESIS_SHA256 CHAIN20_RPC VALIDATORS_TSV REGISTRATIONS BONDED GENESIS_NAMES \
  FAUCET_MINTERS FAUCET_RECIPIENTS STAKE_RAND ALLOC_ADDRESSES ZUSD_CARRY WALLETS_DIRS RELAYER_DONE_DIR EXPECT_HC_BUNDLE \
  EXPECT_HC_AUTH MAX_PROGRAM_WORDS MAX_PROOF_BYTES MAX_BLOCK_BYTES MAX_CALL_ENVELOPE_BYTES \
  MAX_PROGRAM_PUBLIC_WORDS EPOCH_BLOCKS EMITTER_2 EMITTER_3 EMITTER_4 EMITTER_5 C20_EMITTER_2 C20_EMITTER_3 \
  C20_EMITTER_4 C20_EMITTER_5 OLD_EMITTERS EXPECT_FLOORS EXPECT_BURN_SEQUENCE MIN_INBOUND_2 MIN_INBOUND_3 MIN_INBOUND_4 MIN_INBOUND_5 \
  ETH_RPC BSC_RPC TRON_API SOL_RPC SOL_PROGRAM GAS_PRICE BYTE_PRICE BUNDLE_GAS_LIMIT GAS_DYNAMIC MAX_GAS_PRICE MAX_BYTE_PRICE \
  GAS_BYTE_LOAD ENVELOPE_BYTES BINDING_DOMAIN PROOF_WINDOW_BLOCKS STAKE_ENTRY_BPS ROTATION_DELAY_SECS ROTATION_NEEDS_POSSESSION \
  PROGRAM_STATE_CELL_FEE BALANCES_RESCAN BRIDGE_MINT_BPS BRIDGE_BURN_BPS FEE_RECIPIENT \
  FEE_RECIPIENT_FINGERPRINT FEES_JSON FEES_SKIPPED PERPS_JSON ENGINE_HC_DECIDED EXPECT_ENGINE_HC PERP_GENESIS_ROOT \
  PERPS_SKIPPED MULTISIG_CREATE_FEE TREASURY_THRESHOLD TREASURY_SIGNERS TREASURY MULTISIG_SKIPPED \
  EXPECT_HC_AUTH_MULTISIG AUTH_MULTISIG_SKIPPED

# Decimal RAND/zUSD text → base units, the exact rule of `parse_amount` (no float anywhere).
# shellcheck disable=SC2089,SC2090  # python source in a string, exported whole, never word-split
UNITS_PY='
def units(s, decimals=9):
    s = s.strip()
    whole, _, frac = s.partition(".")
    if len(frac) > decimals or not (whole or frac) or not (whole or "0").isdigit() or not (frac or "0").isdigit():
        raise SystemExit(f"cut-chain21: {s!r} is not an amount with at most {decimals} decimals")
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
            raise SystemExit(f"cut-chain21: {path}: {line.rstrip()!r} is not \"<label> rand1… <amount>\"")
        rows.append((f[0], f[1], f[2]))
    return rows
'
# shellcheck disable=SC2090
export UNITS_PY

# The tunnel trap (chain 18, twice in one hour): before a step that reads chain 20, it answers, and
# it is chain 20 — not a dead port, not some other node.
need_chain20_rpc() {
  local got
  got=$(curl -s -m 10 -X POST "$CHAIN20_RPC" -H 'content-type: application/json' \
          -d '{"jsonrpc":"2.0","id":1,"method":"rand_getGenesisHash","params":[]}' 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("result",""))' 2>/dev/null || true)
  [ -n "$got" ] || { echo "cut-chain21: $CHAIN20_RPC is not answering — the SSH tunnel to obs1 is down? Re-open it (ssh -N -L 8545:127.0.0.1:8545 root@<obs1>) and re-run; nothing was read" >&2; exit 1; }
  [ "$got" = "$CHAIN20_HASH" ] || { echo "cut-chain21: $CHAIN20_RPC serves genesis $got, not chain 20 ($CHAIN20_HASH)" >&2; exit 1; }
  echo "cut-chain21: $CHAIN20_RPC answers as chain 20 ($(date -u +%T))"
}

# The fee recipient: one rand1… address from FEE_RECIPIENT_FILE whose fingerprint, as the WALLET
# binary computes it, is FEE_RECIPIENT_FINGERPRINT. `rand contacts add` prints an address's
# fingerprint; it runs under a throwaway --key in a temp dir (it writes only <key>.contacts.json).
load_fee_recipient() {
  local d got
  [ -f "$FEE_RECIPIENT_FILE" ] || { echo "cut-chain21: no fee recipient file $FEE_RECIPIENT_FILE (the user's wallet address, one rand1… line)" >&2; exit 1; }
  FEE_RECIPIENT=$(tr -d ' \t\r\n' < "$FEE_RECIPIENT_FILE")
  case "$FEE_RECIPIENT" in rand1*) ;; *) echo "cut-chain21: $FEE_RECIPIENT_FILE does not hold a rand1… address" >&2; exit 1;; esac
  [ "$(wc -l < "$FEE_RECIPIENT_FILE" | tr -d ' ')" -le 1 ] || { echo "cut-chain21: $FEE_RECIPIENT_FILE holds more than one line" >&2; exit 1; }
  [ -x "$WALLET" ] || { echo "cut-chain21: WALLET=$WALLET is not executable — it computes the fee recipient's fingerprint" >&2; exit 1; }
  d=$(mktemp -d)
  got=$("$WALLET" --key "$d/fingerprint-only.key.json" contacts add fee-recipient "$FEE_RECIPIENT" --yes 2>&1 | sed -n 's/^fingerprint \([0-9A-Z-]*\)$/\1/p' | head -1 || true)
  rm -rf "$d"
  [ -n "$got" ] || { echo "cut-chain21: $WALLET printed no fingerprint for the fee recipient in $FEE_RECIPIENT_FILE (not a shielded address?)" >&2; exit 1; }
  [ "$got" = "$FEE_RECIPIENT_FINGERPRINT" ] || { echo "cut-chain21: the fee recipient in $FEE_RECIPIENT_FILE has fingerprint $got, not FEE_RECIPIENT_FINGERPRINT $FEE_RECIPIENT_FINGERPRINT — refusing (the wrong wallet would collect every bridge fee for the chain's life)" >&2; exit 1; }
  export FEE_RECIPIENT
  echo "cut-chain21: bridge fee recipient: ${#FEE_RECIPIENT}-char address from $FEE_RECIPIENT_FILE, fingerprint $got (= FEE_RECIPIENT_FINGERPRINT)"
}

# ══ snapshot: read-only reads of chain 20 and of the source endpoints ═════════════════════════
py_snapshot() {
  python3 - <<'PY'
import base64, hashlib, json, os, struct, sys, time, urllib.request, urllib.error
E = os.environ
sha = hashlib.sha256(open(E["CHAIN20_GENESIS"], "rb").read()).hexdigest()
if sha != E["CHAIN20_GENESIS_SHA256"]:
    sys.exit(f"cut-chain21: {E['CHAIN20_GENESIS']} is not chain 20's committed genesis file "
             f"(sha256 {sha[:8]}…, expected {E['CHAIN20_GENESIS_SHA256'][:8]}…)")
g20 = json.load(open(E["CHAIN20_GENESIS"]))
if g20.get("vesting"):
    sys.exit("cut-chain21: chain 20's genesis has a vesting section — this script carries none; extend it first")
BACKINGS = g20["tokens"]["tokens"][0]["backings"]

def post(url, body, headers=None):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json", "user-agent": "rand-cut-chain21/1", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def rand(method, params=None):
    r = post(E["CHAIN20_RPC"], {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
    if "error" in r:
        sys.exit(f"cut-chain21: {method}: {r['error']}")
    return r["result"]

def eth_call(url, to, data):
    r = post(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": to, "data": data}, "latest"]})
    if "error" in r:
        sys.exit(f"cut-chain21: eth_call {to} on {url}: {r['error']}")
    return int(r["result"], 16)

def tron(contract41, selector, param=""):
    r = post(E["TRON_API"] + "/wallet/triggerconstantcontract",
             {"owner_address": E["TRON_ENDPOINT41"], "contract_address": contract41,
              "function_selector": selector, "parameter": param})
    if not r.get("constant_result"):
        sys.exit(f"cut-chain21: Tron {selector} on {contract41}: {r}")
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
        sys.exit(f"cut-chain21: Solana getProgramAccounts: {r['error']}")
    return [base64.b64decode(a["account"]["data"][0]) for a in r["result"]]

snap = {"taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
snap["genesis_hash"] = rand("rand_getGenesisHash")
if snap["genesis_hash"] != E["CHAIN20_HASH"]:
    sys.exit(f"cut-chain21: {E['CHAIN20_RPC']} serves {snap['genesis_hash']}, not chain 20")
snap["status_height"] = rand("rand_status")["height"]
snap["validators"] = rand("rand_getValidators")
snap["bridge"] = rand("rand_getBridgeState")
snap["tokens"] = rand("rand_getTokens")
snap["supply"] = rand("rand_getSupply")

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
    sys.exit(f"cut-chain21: {len(cfgs)} Solana config accounts, expected 1")
off = 1 + 32 * 3 + 1 + 32 + 4
seq["5"] = struct.unpack_from("<Q", cfgs[0], off)[0]
for acc in sol_accounts("4"):
    mint = acc[1:33].hex()
    cu, fe = struct.unpack_from("<QQ", acc, 1 + 32 + 2 + 8 * 4)
    custody[f"5:{mint}"] = {"custody": cu, "fees": fe, "mint": b58(acc[1:33])}
snap["source"] = {"emitters": {c: E[f"EMITTER_{c}"] for c in "2345"}, "next_sequence": seq, "custody": custody}
json.dump(snap, open(os.path.join(E["SNAP"], "chain20-state.json"), "w"), indent=1)
print(f"cut-chain21: snapshot of chain 20 at height {snap['status_height']} → {E['SNAP']}/chain20-state.json")
print(f"cut-chain21: source next sequences {seq}; burn_sequence {snap['bridge']['burn_sequence']}; "
      f"zUSD supply {snap['tokens']['tokens'][0]['total_supply']}")
for k, v in custody.items():
    if v["custody"]:
        print(f"cut-chain21: custody {k[:2]}…{k[-8:]} = {v['custody']}")
PY
}

# ══ balances: every wallet the operator holds, scanned on chain 20 → the RAND carry list ══════
# Read-only toward the chain; it does write each wallet's note store (<key>.notes.json) as any
# `rand sync` does. The key files are opened by `rand` only — this script never reads them.
py_balances() {
  python3 - <<'PY'
import glob, json, os, re, subprocess, sys, time, urllib.request
E = os.environ
exec(E["UNITS_PY"])
def rpc(method):
    req = urllib.request.Request(E["CHAIN20_RPC"], json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode(),
                                 {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["result"]
if rpc("rand_getGenesisHash") != E["CHAIN20_HASH"]:
    sys.exit(f"cut-chain21: {E['CHAIN20_RPC']} is not chain 20")
status0 = rpc("rand_status")
if int(status0.get("prune_floor", 0) or 0) > 0:
    sys.exit(f"cut-chain21: {E['CHAIN20_RPC']} is pruned (prune_floor {status0['prune_floor']}) — "
             f"`balances` needs a full scan; point CHAIN20_RPC at an archive (obs1, rand-archive-2)")
def rand(key, *args):
    p = subprocess.run([E["WALLET"], "--rpc", E["CHAIN20_RPC"], "--key", key, *args], capture_output=True, text=True)
    if p.stderr.strip():
        print(p.stderr.strip(), file=sys.stderr)   # RS-1's pruned-node warning, the rescan notice: never swallowed
    if p.returncode != 0:
        sys.exit(f"cut-chain21: rand {' '.join(args)} for {key}: {p.stderr.strip()}")
    return p.stdout
files = []
for d in E["WALLETS_DIRS"].split():
    if os.path.isdir(d):
        files += sorted(glob.glob(os.path.join(d, "*.key.json")))
    else:
        print(f"cut-chain21: {d} does not exist — skipped")
if not files:
    sys.exit("cut-chain21: no *.key.json under WALLETS_DIRS")
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
        sys.exit(f"cut-chain21: could not read a balance for {f}: {out!r}")
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
        sys.exit(f"cut-chain21: {prev['file']} and {f} are one address with different balances — reconcile the note stores")
    if not prev:
        by_addr[addr] = row
    print(f"cut-chain21:   {label:<24} {fmt(ru):>18} RAND  {zu:>12} zUSD units{'  (duplicate key file)' if prev else ''}")
height1 = rpc("rand_status")["height"]
if pending_by_wallet and not E.get("PENDING_OK"):
    detail = "; ".join(f"{label}: " + ", ".join(f"asset {a} amount {amt} ({since})" for a, amt, since in rows) for label, rows in pending_by_wallet)
    sys.exit(f"cut-chain21: pending note(s) would be dropped from the carry silently: {detail} — wait for them to "
             f"clear (or fail) and re-run, or set PENDING_OK=1 to drop them")
elif pending_by_wallet:
    detail = "; ".join(f"{label}: " + ", ".join(f"asset {a} amount {amt}" for a, amt, _ in rows) for label, rows in pending_by_wallet)
    print(f"cut-chain21: ⚠ dropping pending note(s) (PENDING_OK=1): {detail}")
rows = sorted(by_addr.values(), key=lambda r: r["label"])
carry = [r for r in rows if r["rand_units"] > 0]
labels = [r["label"] for r in carry]
if len(set(labels)) != len(labels):
    sys.exit("cut-chain21: two wallets with one label — rename a key file")
total = sum(r["rand_units"] for r in carry)

# ── chain 20's own genesis alloc notes this scan does not cover ────────────────────────────────
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            sys.exit(f"cut-chain21: {s!r} is not base58")
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
g20 = json.load(open(E["CHAIN20_GENESIS"]))
alloc_pks = {n["opening"]["pk"]: n["amount"] for n in g20["alloc"] if n.get("opening", {}).get("asset", 0) == 0}
uncovered = [{"pk": pk, "amount": amt} for pk, amt in alloc_pks.items() if pk not in scanned_pks]
if uncovered:
    print("cut-chain21: uncovered genesis allocs (no scanned wallet's pk matches — the cut refuses "
          "unless UNCOVERED_ALLOCS_OK=1): " + ", ".join(f"{u['pk'][:12]}… ({u['amount']})" for u in uncovered))

json.dump({"chain20_hash": E["CHAIN20_HASH"], "taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "height_from": height0, "height_to": height1, "wallets": rows, "carried_rand_units": total,
           "uncovered_genesis_allocs": uncovered, "rescanned": sync == ["sync", "--rescan"]},
          open(os.path.join(E["SNAP"], "balances.json"), "w"), indent=1)
os.makedirs(os.path.dirname(E["ALLOC_ADDRESSES"]) or ".", exist_ok=True)
with open(E["ALLOC_ADDRESSES"], "w") as out:
    out.write(f"# chain-21 RAND carry: chain-20 balances at heights {height0}..{height1}, `balances` step\n")
    for r in carry:
        out.write(f"{r['label']} {r['address']} {fmt(r['rand_units'])}\n")
print(f"cut-chain21: {len(carry)} wallet(s) with RAND, Σ {fmt(total)} RAND → {E['ALLOC_ADDRESSES']} (+ {E['SNAP']}/balances.json)")
z = [r for r in rows if r["zusd_units"]]
if z:
    op_total = sum(r["zusd_units"] for r in z)
    print(f"cut-chain21: zUSD held by operator wallets: " + ", ".join(f"{r['label']} {r['zusd_units']}" for r in z) + f" (Σ {op_total})")
    if os.path.isfile(E["ZUSD_CARRY"]):
        carry_total = sum(units(a, 8) for _, _, a in alloc_lines(E["ZUSD_CARRY"]))
        if carry_total != op_total:
            print(f"cut-chain21: ⚠ Σ operator-wallet zUSD ({op_total}) != Σ ZUSD_CARRY ({carry_total}) — "
                  f"a non-operator holder (e.g. Anish's wallet) legitimately differs; verify by hand")
PY
}

# ══ the cut, step 1: the validators, from the chain-20 register ═══════════════════════════════
py_validators() {
  python3 - <<'PY'
import json, os, sys
E = os.environ
need = lambda c, m: c or sys.exit(f"cut-chain21: {m}")
snap = json.load(open(E["SNAPSHOT_FILE"]))
g20 = json.load(open(E["CHAIN20_GENESIS"]))
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
    need(addr in register, f"{name} ({addr}) is not in chain 20's register")
    rows.append({"name": name, "address": addr, "public_key": raw[8:8 + n].hex(), "payout": register[addr]["payout"]})
stake = int(E["STAKE_RAND"]) * 10**9
need(len(rows) == len(register) == 26, f"{len(rows)} validators assembled, chain 20's register holds {len(register)}")
for r in rows:
    live = register.get(r["address"])
    need(live is not None, f"{r['name']} ({r['address']}) is not in chain 20's register")
    need(live["payout"] == r["payout"], f"{r['name']}: payout differs from chain 20's register")
    need(int(live["stake"]) == stake and not live["pending"], f"{r['name']}: chain 20 stake {live['stake']} / pending {live['pending']}, not a plain {stake}")
    need(live["active"], f"{r['name']} is not active on chain 20")
    need(int(live.get("rewards", "0")) == 0 or E.get("REWARDS_DROPPED_OK"),
         f"{r['name']}: chain 20 shows {live['rewards']} unwithdrawn reward units — withdraw them before the cut "
         f"(rewards are not carried), or set REWARDS_DROPPED_OK=1 to drop them")
need(len({r["public_key"] for r in rows}) == 26 and len({r["address"] for r in rows}) == 26, "a validator twice")
total_rewards = sum(int(register[r["address"]].get("rewards", "0")) for r in rows)
if total_rewards:
    print(f"cut-chain21: ⚠ dropping {total_rewards} unwithdrawn reward unit(s) across the register (REWARDS_DROPPED_OK=1)")
need([(v["public_key"], v["payout"]) for v in g20["validators"]] == [(r["public_key"], r["payout"]) for r in rows],
     "the 26 are not chain 20's genesis validators (keys, payouts or order)")
json.dump(rows, open(os.path.join(E["TMP"], "validators.json"), "w"))
with open(os.path.join(E["TMP"], "validator-args"), "w") as f:
    for r in rows:
        f.write(f"--validator\n{r['public_key']},{E['STAKE_RAND']},{r['payout']}\n")
t = g20["tokens"]
json.dump({"registration_fee": t["registration_fee"], "mint_cap_per_day": t["mint_cap_per_day"], "tokens": []},
          open(os.path.join(E["TMP"], "tokens.json"), "w"))
print(f"cut-chain21: 26 validators × {E['STAKE_RAND']} RAND, equal to chain 20's register at height {snap['status_height']}")
PY
}

# ══ the cut, step 1b: the treasury — TREASURY → $TMP/multisig.json (the `--multisig` file) ═════
# Exactly 3 signers in the file's order, `threshold 2`, a positive `balance` in RAND (the exact
# units() rule). A key that is a validator's (chain 20's register, which is chain 21's), a bridge
# guardian's or the pause key is refused — a treasury signer is a person's own key, never an
# operator key that already signs something else — and so is a key listed twice. The salt is 32
# fresh random bytes, every run (TREASURY_SALT only for the selftest's reproducibility).
py_treasury() {
  python3 - <<'PY'
import json, os, re, secrets, sys
E = os.environ
exec(E["UNITS_PY"])
def need(cond, msg):
    if not cond:
        sys.exit(f"cut-chain21: {E['TREASURY']}: {msg}")
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
g20 = json.load(open(E["CHAIN20_GENESIS"]))
snap = json.load(open(E["SNAPSHOT_FILE"]))
for b in (g20["bridge"], snap["bridge"]):
    for i, k in enumerate(b["pq_guardians"]):
        known[k] = f"bridge PQ guardian {i}"
    known[b["pause_key"]] = "the bridge pause key"
for name, pk in signers:
    need(pk not in known, f"signer {name}'s key is {known.get(pk)}'s — a treasury signer holds a key of its own")
salt = E.get("TREASURY_SALT") or secrets.token_hex(32)
need(re.fullmatch(r"[0-9a-f]{64}", salt), "TREASURY_SALT is not 64 hex")
section = {"create_fee": E["MULTISIG_CREATE_FEE"],
           "accounts": [{"salt": salt, "signers": pks, "threshold": want_t, "balance": str(balance)}]}
json.dump(section, open(os.path.join(E["TMP"], "multisig.json"), "w"), indent=1)
with open(os.path.join(E["TMP"], "treasury-args"), "w") as f:
    f.write(f"--salt\n{salt}\n--threshold\n{want_t}\n")
    for pk in pks:
        f.write(f"--signer\n{pk}\n")
open(os.path.join(E["TMP"], "treasury-balance"), "w").write(str(balance))
print(f"cut-chain21: treasury: {want_t} of {want_n} ({', '.join(names)}), balance {fmt(balance)} RAND = {balance} units (NEW ISSUANCE), salt {salt}")
PY
}

# ══ the cut, step 1c: the perps section — markets → genesis words → root; the section file ══════
# PERPS_STEP=markets writes $TMP/perps-markets.json (the bare `{"markets": […]}` perp-prover
# genesis-state reads); PERPS_STEP=section writes $TMP/perps.json from PERPS_JSON, EXPECT_ENGINE_HC
# and PERP_GENESIS_ROOT, in PerpsConfig's field order. py_splice puts it into the file.
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
    sys.exit(f"cut-chain21: PERP_GENESIS_ROOT {root!r} is not 64 hex — the genesis root step did not run")
section = {k: d[k] for k in ("collateral_asset", "max_tier", "max_window_blocks", "max_block_inputs", "min_deposit")}
section.update(engine_hc=E["EXPECT_ENGINE_HC"], genesis_root=root, markets=d["markets"])
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
g20 = json.load(open(E["CHAIN20_GENESIS"]))
snap = json.load(open(E["SNAPSHOT_FILE"]))
sb = snap["bridge"]
warnings = []

def need(cond, msg):
    if not cond:
        sys.exit(f"cut-chain21: {msg}")

need(snap["genesis_hash"] == E["CHAIN20_HASH"], "the snapshot is not of chain 20")
need(not g20.get("vesting"), "chain 20's genesis has a vesting section — this script carries none")
need(g20.get("chain_id") == 20 and "fees" not in g20 and "perps" not in g20 and "multisig" not in g20 and "hc_auth_multisig" not in g20,
     "CHAIN20_GENESIS is not chain 20's (chain id 20, no fees, perps, multisig or hc_auth_multisig section)")
b20 = g20["bridge"]
need({c: E[f"C20_EMITTER_{c}"] for c in "2345"} == b20["emitters"], "C20_EMITTER_* are not deploy/genesis-chain20.json's emitters")

# ── bridge: chain 20's live values, the floors re-derived, rotation and fees chain 20's ─────────
rotated = E.get("BRIDGE_ROTATED")
for k in ("guardians", "guardian_set_index", "pq_guardians", "pause_key"):
    need(sb[k] == b20[k] or rotated, f"chain 20's live {k} differs from its genesis — a rotation; set BRIDGE_ROTATED=1 to carry the live value")
need(sb["emitter"] == b20["emitter"], "the Rand-side emitter differs from chain 20's")
need(not sb["mint_paused"], "chain 20's mints are paused — decide what chain 21 starts with")
need(sb["emitters"] == b20["emitters"], "chain 20's live emitter table differs from its genesis")
need(int(sb["rules_v2"]["global_mint_cap_per_window"]) == int(b20["rules_v2"]["global_mint_cap_per_window"])
     and int(sb["rules_v2"]["cap_window_secs"]) == int(b20["rules_v2"]["cap_window_secs"]), "rules_v2 differs from chain 20's genesis")
need(int(sb["registration_fee"]) == int(g20["tokens"]["registration_fee"]), "registration_fee differs from chain 20's")
need(sb["burn_sequence"] >= b20["burn_sequence"], "chain 20's burn sequence went backwards")
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
need(emitters == b20["emitters"] or E.get("EMITTERS_CHANGED") == "1",
     "the emitter table is not chain 20's (deploy/genesis-chain20.json) — EMITTERS_CHANGED=1 only for a knowingly new endpoint")
changed = [c for c in "2345" if emitters[c] != b20["emitters"][c]]

floor20 = {str(k): int(v) for k, v in (b20.get("min_inbound_sequence") or {}).items()}
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
             f"would NEVER mint on chain 21 (refused on an endpoint chain 20 already trusts)")
        warnings.append(f"chain {c}: floor {v} is ahead of the endpoint's next sequence {next_seq} (FLOOR_AHEAD_OK=1)")
    if c not in changed and c in floor20:
        need(int(v) >= floor20[c], f"MIN_INBOUND_{c}={v} is below chain 20's own floor {floor20[c]} — it would re-open minted locks")
    if int(v) < next_seq:
        need(allow_unminted,
             f"chain {c}'s endpoint has emitted up to {next_seq - 1} but the floor is {v}: locks {v}..{next_seq - 1} will mint "
             f"on chain 21 — drain them on chain 20 first, or set ALLOW_UNMINTED_LOCKS=1 if they are user locks chain 20 never minted")
        unminted[c] = (int(v), next_seq - 1)
        warnings.append(f"chain {c}: locks {v}..{next_seq - 1} were emitted and are NOT below the floor — they will mint on chain 21 (ALLOW_UNMINTED_LOCKS=1)")
    if E.get("RELAYER_DONE_DIR") and c not in changed:
        d = os.path.join(E["RELAYER_DONE_DIR"], c)
        done = [int(m.group()) for m in (re.match(r"\d+", x) for x in (os.listdir(d) if os.path.isdir(d) else [])) if m]
        last = max(done) if done else floor20.get(c, 1) - 1
        need(int(v) == last + 1, f"chain {c}: the relayer's done/ says last minted {last}, the floor is {v} (last minted + 1 = {last + 1})")
    floor[c] = int(v)
need(set(floor) == set("2345"), "a replay floor for every endpoint chain 20 trusts")
want_floor = {c: int(v) for c, v in (x.split(":") for x in E["EXPECT_FLOORS"].split())}
if floor != want_floor:
    warnings.append(f"min_inbound_sequence is {floor}, EXPECTED {want_floor} (EXPECT_FLOORS) — confirm every difference against the endpoints before launch")
if int(sb["burn_sequence"]) != int(E["EXPECT_BURN_SEQUENCE"]):
    warnings.append(f"burn_sequence is {sb['burn_sequence']}, EXPECTED {E['EXPECT_BURN_SEQUENCE']} — a burn landed on chain 20 since; confirm its release before launch")

need(E["ROTATION_NEEDS_POSSESSION"] in ("true", "false"), "ROTATION_NEEDS_POSSESSION is true or false")
rotation = {"delay_secs": int(E["ROTATION_DELAY_SECS"]), "needs_possession": E["ROTATION_NEEDS_POSSESSION"] == "true"}
g["bridge"] = {
    "emitter": b20["emitter"],
    "guardians": guardians,
    "emitters": emitters,
    "pq_guardians": pq_guardians,
    "pause_key": pause_key,
    "rules_v2": b20["rules_v2"],
    "guardian_set_index": int(sb["guardian_set_index"]),
    "burn_sequence": int(sb["burn_sequence"]),
    "min_inbound_sequence": floor,
    "rotation": rotation,
    "fees": {"mint_bps": int(E["BRIDGE_MINT_BPS"]), "burn_bps": int(E["BRIDGE_BURN_BPS"]), "recipient": E["FEE_RECIPIENT"]},
}

# ── tokens: zUSD at genesis, locked = chain 20's per backing == custody == supply ───────────────
tok = snap["tokens"]["tokens"]
z = [t for t in tok if t["symbol"] == "zUSD" and t["index"] == 1]
need(len(z) == 1, "chain 20 does not list zUSD at index 1")
others = [t for t in tok if t is not z[0]]
need(not others or E.get("ALLOW_DROPPED_TOKENS"),
     f"chain 20 lists {len(others)} more token(s) ({', '.join(t['symbol'] for t in others)}) the cut cannot carry — set ALLOW_DROPPED_TOKENS=1 to drop them")
if others:
    warnings.append(f"dropped chain-20 tokens: {', '.join(str(t['index']) + ':' + t['symbol'] for t in others)}")
z20 = g20["tokens"]["tokens"][0]
live_backings = z[0]["authority"]["backings"]
need([(b["chain"], b["token"], b["decimals"]) for b in live_backings] == [(b["chain"], b["token"], b["decimals"]) for b in z20["backings"]],
     "chain 20's live backings differ from its genesis list")
backings = []
for lb in live_backings:
    b = {"chain": lb["chain"], "token": lb["token"], "decimals": lb["decimals"]}
    if int(lb["locked"]) > 0:
        b["locked"] = int(lb["locked"])
    backings.append(b)
locked_total = sum(b.get("locked", 0) for b in backings)
need(int(z[0]["total_supply"]) == locked_total, f"chain 20's zUSD supply {z[0]['total_supply']} != Σ locked {locked_total}")
for b in backings:
    key = f"{b['chain']}:{b['token']}"
    have = snap["source"]["custody"].get(key)
    need(have is not None, f"the snapshot has no custody reading for {key}")
    d = b["decimals"]
    if d > 8:
        need(have["custody"] % 10**(d - 8) == 0, f"custody {key} has dust below zUSD's eighth decimal")
    scaled = have["custody"] // 10**(d - 8) if d >= 8 else have["custody"] * 10**(8 - d)
    if scaled != b.get("locked", 0):
        # An unminted user lock (ALLOW_UNMINTED_LOCKS=1, above) is custody chain 20 never locked:
        # custody may exceed locked on that chain only, never fall below it.
        need(str(b["chain"]) in unminted and scaled > b.get("locked", 0),
             f"source custody {key} = {have['custody']} (= {scaled} zUSD units), chain 20 locks {b.get('locked', 0)}")
        warnings.append(f"custody {key} = {scaled} zUSD units, above chain 20's locked {b.get('locked', 0)} — the unminted lock(s) on chain {b['chain']}")

t = g["tokens"]
need(t["registration_fee"] == g20["tokens"]["registration_fee"] and t["mint_cap_per_day"] == g20["tokens"]["mint_cap_per_day"], "tokens header")
t["tokens"] = [{"name": z20["name"], "symbol": z20["symbol"], "salt": z20["salt"], "backings": backings}]
for k in ("max_tokens", "burn_registration_fee", "bound_note_value"):
    t[k] = g20["tokens"][k]
need({k: v for k, v in t.items() if k != "tokens"} == {k: v for k, v in g20["tokens"].items() if k != "tokens"}, "the token switches are not chain 20's")

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
    need(bal["chain20_hash"] == E["CHAIN20_HASH"], "balances.json is not of chain 20")
    scanned = sorted((w["address"], w["rand_units"]) for w in bal["wallets"] if w["rand_units"] > 0)
    listed = sorted((addr, units(a)) for _, addr, a in alloc)
    need(sum(u for _, u in scanned) == alloc_total, f"Σ alloc RAND {alloc_total} != Σ scanned balances {sum(u for _, u in scanned)}")
    need(scanned == listed, "ALLOC_ADDRESSES is not the scanned wallets one-for-one (address, amount) — regenerate it with `balances`")
    uncovered = bal.get("uncovered_genesis_allocs") or []
    need(not uncovered or E.get("UNCOVERED_ALLOCS_OK"),
         "chain 20 genesis alloc(s) match no scanned wallet, so their value would be dropped silently: "
         + ", ".join(f"pk {u['pk'][:12]}… ({u['amount']})" for u in uncovered)
         + " — find the key file(s) and add its directory to WALLETS_DIRS, or set UNCOVERED_ALLOCS_OK=1 to drop them")
    if uncovered:
        warnings.append("dropped uncovered chain-20 genesis alloc(s): " + ", ".join(f"pk {u['pk'][:12]}… ({u['amount']})" for u in uncovered))
    if not bal.get("rescanned"):
        warnings.append("balances.json was NOT taken with `rand sync --rescan` (BALANCES_RESCAN=0) — a stale note store could have read low")
    rand_carry = f"== Σ scanned ({len(scanned)} wallets, heights {bal['height_from']}..{bal['height_to']})"
else:
    need(E.get("NO_BALANCES"), f"no {bal_file or 'balances.json'} — run `balances` (the carry-over rule), or set NO_BALANCES=1 to cut from a hand-made list")
    rand_carry = "NOT checked against a scan (NO_BALANCES=1)"
    warnings.append("RAND allocs were not checked against scanned balances")
g["alloc"] = g["alloc"] + token_notes

# ── staking: chain 20's (the entry budget in basis points, admission by vote); no slashing ──────
s20 = g20["staking"]
need("slashing" not in s20, "chain 20's staking has `slashing` — this script carries none")
if E.get("FAUCET_RECIPIENTS"):
    recipients = [l.split()[-1] for l in open(E["FAUCET_RECIPIENTS"]) if l.strip() and not l.startswith("#")]
    need(recipients and all(r.startswith("rand1") for r in recipients) and len(set(recipients)) == len(recipients),
         "FAUCET_RECIPIENTS: rand1… addresses, each once")
    need(recipients == s20["faucet_recipients"] or E.get("FAUCET_RECIPIENTS_CHANGED"),
         f"the faucet allowlist differs from chain 20's ({len(s20['faucet_recipients'])} → {len(recipients)}) "
         f"— set FAUCET_RECIPIENTS_CHANGED=1 if that is the decision")
    if recipients != s20["faucet_recipients"]:
        warnings.append(f"faucet allowlist changed from chain 20's ({len(s20['faucet_recipients'])} → {len(recipients)})")
else:
    recipients = s20["faucet_recipients"]
vals = {v["name"]: v for v in json.load(open(os.path.join(E["TMP"], "validators.json")))}
minters = []
for name in E["FAUCET_MINTERS"].split():
    need(name in vals, f"FAUCET_MINTERS names {name}, not a chain-21 validator")
    minters.append(vals[name]["address"])
need(minters and len(set(minters)) == len(minters), "faucet_minters empty or a key twice")
need(minters == s20["faucet_minters"] or E.get("FAUCET_MINTERS_CHANGED"),
     "faucet_minters differ from chain 20's (set FAUCET_MINTERS_CHANGED=1 if that is the decision)")
need(s20.get("max_stake_entry_bps_per_epoch") == 2500 and s20.get("admission_by_vote") is True
     and "max_stake_entry_per_epoch" not in s20, "chain 20's staking is not the 2500-bps budget with admission by vote")
staking = dict(s20)
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
need(g["chain_id"] == int(E["CHAIN_ID"]) == 21, f"chain_id is {g['chain_id']}")
need(g.get("hardening_v6") is True, "hardening_v6 is not true — --hardening-v6 did not take")
need(g["hc_bundle"] == E["HC_REPORTED"], "hc_bundle is not what this rand-node reports")
need(g["hc_bundle"] == g20["hc_bundle"] == E["EXPECT_HC_BUNDLE"], f"hc_bundle {g['hc_bundle']} is not chain 20's bundle guest v3")
need(g.get("hc_auth") == g20.get("hc_auth") == E["EXPECT_HC_AUTH"], f"hc_auth {g.get('hc_auth')} is not chain 20's auth guest")
need(g["faucet"] is True and g["confidential"] is True and g["fri_profile"] == "production", "faucet/confidential/fri_profile wrong")
need("aggregation" not in g, "an aggregation section is present — none belongs in chain 21")
need("vesting" not in g, "a vesting section is present — none belongs in chain 21")
need(g.get("envelope_bytes") == int(E["ENVELOPE_BYTES"]) == 1860 == g20.get("envelope_bytes"), f"envelope_bytes is {g.get('envelope_bytes')!r}, not 1860")
for i, n in enumerate(g["alloc"]):
    size = sum(len(v) // 2 for v in n["envelope"].values())
    need(size == 1860, f"alloc note {i}'s envelope is {size} B, not 1860 — sealed in the legacy format (alloc-note without --envelope-bytes?)")
# ── the new field: the fees section (docs/fees.md §1.3), burn_base + burn_floor, never the subsidy ─
fees_section = g.get("fees")
need(not (fees_section or {}).get("subsidy_net_of_fees"),
     "fees.subsidy_net_of_fees is set — it needs an aggregation section, and this build refuses a genesis with one "
     "at startup until the admitted shape is re-measured against the hidden-asset bundle (b053a76); chain 21 "
     "carries burn_base and burn_floor only (docs/deploy.md, \"The next cut: the `fees` section (chain 21)\")")
want_fees = json.loads(E["FEES_JSON"])
same_json = lambda a, b: json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)   # 1 is not true
need(same_json(want_fees, {"burn_base": True, "burn_floor": True}), f"FEES_JSON is {want_fees!r}, not the decided {{burn_base: true, burn_floor: true}}")
if E.get("FEES_SKIPPED"):
    need(fees_section is None, "FEES_SKIPPED yet a fees section is present")
    warnings.append("FEES SKIPPED — this rand-node has no --fees (it predates d6cc16f5); the real cut refuses "
                    "such a binary; this file is NOT what chain 21 will be")
else:
    need(same_json(fees_section, want_fees),
         f"fees is {fees_section!r}, not {{'burn_base': True, 'burn_floor': True}} — --fees did not take")
# ── the new section: perps (docs/perps.md), the decided values, on the finished file ──────────────
PERPS_DECIDED = {"collateral_asset": 1, "max_tier": 18, "max_window_blocks": 64, "max_block_inputs": 24, "min_deposit": 100000000,
                 "markets": [{"id": 0, "symbol": "BTC-PERP", "lot": 100000, "tick": 100000000, "max_leverage": 20,
                              "maintenance_bps": 250, "taker_fee_bps": 5, "maker_fee_bps": 2}]}
ENGINE_HC_DECIDED = "f286a61171e274278ec8d18d7853e5f36799ed8dc5a3e31e0077ad89ef1d1573"
need(same_json(json.loads(E["PERPS_JSON"]), PERPS_DECIDED), "PERPS_JSON is not the decided perps section (BTC-PERP on zUSD, 20x / 250 bps, tier 18, 24 inputs)")
perps = g.get("perps")
if E.get("PERPS_SKIPPED"):
    need(perps is None, "PERPS_SKIPPED yet a perps section is present")
    warnings.append("PERPS SKIPPED — no PERP_PROVER for the engine's genesis root; the real cut refuses that; this file is NOT "
                    "what chain 21 will be")
else:
    need(perps is not None, "no perps section in the finished file — the splice did not take")
    need(set(perps) == set(PERPS_DECIDED) | {"engine_hc", "genesis_root"}, f"perps carries the fields {sorted(perps)}, not PerpsConfig's eight")
    need(perps["collateral_asset"] == 1, f"perps.collateral_asset is {perps['collateral_asset']!r}, not 1 (zUSD) — the decision is zUSD collateral")
    toks = g["tokens"]["tokens"]
    need(len(toks) >= 1 and toks[0]["symbol"] == "zUSD", "tokens.tokens[0] is not zUSD — collateral_asset 1 (FIRST_TOKEN_INDEX) would name another token")
    need(len(perps["markets"]) == 1, f"perps lists {len(perps['markets'])} markets — chain 21 has one, BTC-PERP")
    for m in perps["markets"]:
        need(m["max_leverage"] >= 1 and m["maintenance_bps"] * m["max_leverage"] < 10000,
             f"market {m['symbol']}: maintenance {m['maintenance_bps']} bps is at or above the initial margin {10000 // max(m['max_leverage'], 1)} bps "
             f"that {m['max_leverage']}x implies (perp-core: ⌈notional / max_leverage⌉) — a max-leverage position would open liquidatable")
    need(perps["max_tier"] == 18, f"perps.max_tier is {perps['max_tier']!r}, not 18 (the production sizing)")
    need(perps["max_block_inputs"] == 24, f"perps.max_block_inputs is {perps['max_block_inputs']!r}, not 24 — the production sizing at tier 18 "
         f"(durian.market's gated case block-24-14liq); nothing measured more")
    need(perps["engine_hc"] == E["EXPECT_ENGINE_HC"] == ENGINE_HC_DECIDED,
         f"perps.engine_hc {perps['engine_hc']} is not the pinned engine {ENGINE_HC_DECIDED} (durian.market artifacts/perp-engine.image.bin)")
    need(re.fullmatch(r"[0-9a-f]{64}", E.get("PERP_GENESIS_ROOT", "")) and perps["genesis_root"] == E["PERP_GENESIS_ROOT"],
         f"perps.genesis_root {perps['genesis_root']} is not the root this cut derived ({E.get('PERP_GENESIS_ROOT') or 'none'}) from the markets")
    need(same_json({k: v for k, v in perps.items() if k not in ("engine_hc", "genesis_root")}, PERPS_DECIDED),
         f"perps is not the decided section: {sorted(k for k in PERPS_DECIDED if not same_json(perps.get(k), PERPS_DECIDED[k]))} differ")
    # what Genesis::validate requires of a perps chain (`init` refuses the file without them too);
    # binding_domain 1, which perp signatures bind to, is asserted with chain 20's fields below.
    need(g["confidential"] is True and g.get("tokens") is not None and g.get("gas") is not None and g.get("hardening_v6") is True
         and bool(g.get("hc_auth")), "perps needs confidential, tokens, gas, hardening_v6 and hc_auth")
# ── the new section: multisig (docs/multisig.md), the treasury, on the finished file ─────────────
ms = g.get("multisig")
treasury_units = 0
if E.get("MULTISIG_SKIPPED"):
    need(ms is None, "MULTISIG_SKIPPED yet a multisig section is present")
    warnings.append("MULTISIG SKIPPED — this rand-node has no --multisig (it predates 3119a29a); the real cut refuses such a "
                    "binary; this file is NOT what chain 21 will be (no treasury)")
else:
    need(ms is not None, "no multisig section — --multisig did not take")
    need(E["MULTISIG_CREATE_FEE"] == "1000000000", f"MULTISIG_CREATE_FEE is {E['MULTISIG_CREATE_FEE']}, not the decided 1000000000 (1 RAND)")
    need(ms.get("create_fee") == "1000000000",
         f"multisig.create_fee is {ms.get('create_fee')!r}, not \"1000000000\" (1 RAND, docs' recommended value; a create_fee of 0 is refused at this cut)")
    accts = ms.get("accounts") or []
    need(len(accts) == 1, f"multisig seeds {len(accts)} account(s) — chain 21 seeds one, the treasury")
    a = accts[0]
    need(a.get("threshold") == int(E["TREASURY_THRESHOLD"]) == 2, f"the treasury's threshold is {a.get('threshold')!r}, not 2 (2 of 3)")
    need(len(a.get("signers", [])) == int(E["TREASURY_SIGNERS"]) == 3, f"the treasury lists {len(a.get('signers', []))} signer(s), not 3 (2 of 3)")
    need(len(set(a["signers"])) == 3, "a treasury signer is listed twice")
    need(not set(a["signers"]) & {v["public_key"] for v in g["validators"]}, "a treasury signer is a validator's key")
    want_ms = json.load(open(os.path.join(E["TMP"], "multisig.json")))
    tb = open(os.path.join(E["TMP"], "treasury-balance")).read().strip()
    need(str(a.get("balance")) == tb and int(tb) > 0,
         f"the treasury balance {a.get('balance')!r} units is not TREASURY's {tb} — the units trap (1 RAND = 10^9 units)?")
    need(same_json(ms, want_ms), "the multisig section is not the file this cut wrote ($TMP/multisig.json: salt, signers in order, balance)")
    treasury_units = int(a["balance"])
# ── the new field: hc_auth_multisig (private multisig phase 4), on the finished file ──────────────
need(E["EXPECT_HC_AUTH_MULTISIG"] == "9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247",
     f"EXPECT_HC_AUTH_MULTISIG is {E['EXPECT_HC_AUTH_MULTISIG']}, not the decided multisig auth guest (MSAUTH_HC)")
if E.get("AUTH_MULTISIG_SKIPPED"):
    need("hc_auth_multisig" not in g, "AUTH_MULTISIG_SKIPPED yet hc_auth_multisig is present")
    warnings.append("AUTH_MULTISIG SKIPPED — this rand-node has no --auth-multisig-guest (it predates 712c6336): no private "
                    "multisig on this chain; the real cut refuses such a rand-node; this file is NOT what chain 21 will be")
else:
    need("hc_auth_multisig" in g, "no hc_auth_multisig — --auth-multisig-guest did not take")
    need(bool(g.get("hc_auth")), "hc_auth_multisig needs hc_auth (the multisig auth guest authorises bundle guest v3's spends)")
    need(g["hc_auth_multisig"].lower() != str(g.get("hc_auth")).lower(), "hc_auth_multisig must differ from hc_auth")
    need(g["hc_auth_multisig"] == E["EXPECT_HC_AUTH_MULTISIG"], f"hc_auth_multisig {g['hc_auth_multisig']} is not this build's multisig auth guest "
         f"({E['EXPECT_HC_AUTH_MULTISIG']})")
    need(E.get("HC_AUTH_MULTISIG_REPORTED", g["hc_auth_multisig"]) == g["hc_auth_multisig"],
         f"hc_auth_multisig {g['hc_auth_multisig']} is not what this rand-node wrote ({E.get('HC_AUTH_MULTISIG_REPORTED')})")
    need(g["max_proof_bytes"] >= 4194304, f"max_proof_bytes {g['max_proof_bytes']} cannot hold a multisig auth proof (≥ 4194304, "
         f"the node's MSAUTH_MIN_PROOF_BYTES at production)")
# chain 20's top-level fields, each still asserted at its value
need(g.get("testnet") is True, f"testnet is {g.get('testnet')!r}, not true — --testnet did not take (a faucet beside a bridge on chain 21 needs it)")
need(g.get("binding_domain") == int(E["BINDING_DOMAIN"]) == 1, f"binding_domain is {g.get('binding_domain')!r}, not 1 — --binding-domain 1 did not take")
need(g.get("proof_window_blocks") == int(E["PROOF_WINDOW_BLOCKS"]) == 1024, f"proof_window_blocks is {g.get('proof_window_blocks')!r}, not 1024")
need(g.get("program_state") == {"cell_fee": int(E["PROGRAM_STATE_CELL_FEE"])},
     f"program_state is {g.get('program_state')!r}, not {{'cell_fee': {E['PROGRAM_STATE_CELL_FEE']}}} — --program-state-cell-fee did not take")
need(int(E["PROGRAM_STATE_CELL_FEE"]) == 10000000 == g20["program_state"]["cell_fee"], "the program_state cell fee is not docs/program-state.md's 10000000 (0.01 RAND), chain 20's")
# the gas section: chain 20's, its ceilings and paying byte load included
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
# chain 20's section but for the byte target, which follows chain 21's max_block_bytes (half of it,
# asserted above): 9961472 at the decided 19 MiB, chain 20's 10485760 at its 20 MiB.
want_gas_section = copy.deepcopy(g20["gas"])
want_gas_section["dynamic"]["target_block_bytes"] = g["max_block_bytes"] // 2
need(gas == want_gas_section or E.get("GAS_CHANGED"), f"the gas section {gas} is not chain 20's {want_gas_section} (GAS_CHANGED=1 if intended)")
# the staking section
st = g["staking"]
need(st.get("admission_by_vote") is True, "staking.admission_by_vote is not true")
need(st.get("max_stake_entry_bps_per_epoch") == int(E["STAKE_ENTRY_BPS"]) == 2500, f"staking.max_stake_entry_bps_per_epoch is {st.get('max_stake_entry_bps_per_epoch')!r}, not 2500")
need("max_stake_entry_per_epoch" not in st, "staking still carries the fixed max_stake_entry_per_epoch (refused beside the bps budget)")
need("slashing" not in st, "staking.slashing is present — recommended only once stake is held by more than one operator (docs/deploy.md, D8)")
# the bridge rotation rules (chain 20's)
need(g["bridge"].get("rotation") == {"delay_secs": 86400, "needs_possession": True} == b20.get("rotation"), f"bridge.rotation is {g['bridge'].get('rotation')!r}, not chain 20's {{delay_secs: 86400, needs_possession: true}}")
# the zUSD bridge fees (docs/bridge.md §25), chain 20's, recipient included
fees = g["bridge"].get("fees") or {}
need(E.get("FEE_RECIPIENT", "").startswith("rand1"), "FEE_RECIPIENT is unset — load_fee_recipient did not run")
need(fees == {"mint_bps": 10, "burn_bps": 10, "recipient": E["FEE_RECIPIENT"]},
     f"bridge.fees is {({k: (v if k != 'recipient' else v[:12] + '…') for k, v in fees.items()})!r}, not {{mint_bps: 10, burn_bps: 10, recipient: <FEE_RECIPIENT>}}")
payouts = {v["payout"] for v in g["validators"]}
need(fees["recipient"] not in payouts or E.get("FEE_RECIPIENT_IS_PAYOUT_OK"),
     "bridge.fees.recipient is a validator's payout address — docs/deploy.md: a dedicated key, never a validator's (FEE_RECIPIENT_IS_PAYOUT_OK=1 to accept)")
need(fees == b20.get("fees") or E.get("FEE_RECIPIENT_CHANGED"),
     "bridge.fees is not chain 20's (deploy/genesis-chain20.json) — FEE_RECIPIENT_CHANGED=1 only for a knowingly new recipient")
if fees["recipient"] in {a for _, a, _ in alloc}:
    warnings.append("the bridge fee recipient is also a carried RAND wallet (an alloc) — its viewing key sees every fee note")
need(g["epoch_blocks"] == int(E["EPOCH_BLOCKS"]) == g20["epoch_blocks"], "epoch_blocks is not chain 20's")
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
# chain 21's decided limits (private multisig; see MAX_PROOF_BYTES): 6 MiB proofs — PENDING the
# measured production msauth proof size — and 19 MiB blocks, 3 · 6 MiB + 1 MiB.
LIMITS_DECIDED = {"max_proof_bytes": 6291456, "max_block_bytes": 19922944}
for k, want in (("max_program_words", "MAX_PROGRAM_WORDS"), ("max_proof_bytes", "MAX_PROOF_BYTES"),
                ("max_block_bytes", "MAX_BLOCK_BYTES"), ("max_call_envelope_bytes", "MAX_CALL_ENVELOPE_BYTES"),
                ("max_program_public_words", "MAX_PROGRAM_PUBLIC_WORDS")):
    need(g[k] == int(E[want]), f"{k} is {g[k]}")
    if k in LIMITS_DECIDED:
        need(g[k] == LIMITS_DECIDED[k] or E.get("LIMITS_CHANGED"),
             f"{k} {g[k]} is not chain 21's decided {LIMITS_DECIDED[k]} (chain 20's was {g20[k]}; LIMITS_CHANGED=1 if intended)")
    else:
        need(g[k] == g20[k] or E.get("LIMITS_CHANGED"), f"{k} {g[k]} differs from chain 20's {g20[k]} (LIMITS_CHANGED=1 if intended)")
need(g["max_block_bytes"] >= 3 * g["max_proof_bytes"] + 1048576,
     f"max_block_bytes {g['max_block_bytes']} < 3*max_proof_bytes + 1 MiB: a v3 Call carries three proofs")
# Outside the chain id, the clock, the carried notes, the bridge's burn sequence / floors, the zUSD
# backings' `locked`, the faucet lists, the three new sections and chain 21's two decided limits
# (asserted at their values above), every byte is chain 20's (gas and staking are compared on their
# own lines, with their own override).
excused = {"chain_id", "timestamp_ms", "alloc", "bridge", "tokens", "staking", "gas", "fees", "perps", "multisig",
           "hc_auth_multisig", "max_proof_bytes", "max_block_bytes"}
if E.get("LIMITS_CHANGED"):
    excused |= {"max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes", "max_program_public_words"}
moved = sorted(k for k in set(g) | set(g20) if k not in excused and g.get(k) != g20.get(k))
need(not moved, f"not chain 20's shape: {moved} differ from chain 20's genesis")
want_staking = s20
if not (E.get("FAUCET_RECIPIENTS_CHANGED") or E.get("FAUCET_MINTERS_CHANGED")):
    need(st == want_staking, f"staking is not chain 20's: "
         f"{sorted(k for k in set(st) | set(want_staking) if st.get(k) != want_staking.get(k))} differ")
bridge_moved = sorted(k for k in set(g["bridge"]) | set(b20)
                      if k not in ("burn_sequence", "min_inbound_sequence") and g["bridge"].get(k) != b20.get(k))
need(not bridge_moved or rotated or (bridge_moved == ["emitters"] and E.get("EMITTERS_CHANGED"))
     or (bridge_moved == ["fees"] and E.get("FEE_RECIPIENT_CHANGED")),
     f"bridge fields {bridge_moved} differ from chain 20's genesis (BRIDGE_ROTATED=1 carries a live rotation)")
strip_locked = lambda toks: [{**t, "backings": [{k: v for k, v in b.items() if k != "locked"} for b in t["backings"]]} for t in toks]
need({**g["tokens"], "tokens": strip_locked(g["tokens"]["tokens"])} == {**g20["tokens"], "tokens": strip_locked(g20["tokens"]["tokens"])},
     "the tokens section differs from chain 20's in more than the backings' locked amounts")
now_ms = int(time.time() * 1000)
need(g["timestamp_ms"] <= now_ms + 15_000, "timestamp_ms is in the future beyond the 15 s vote drift bound")

json.dump(g, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(f"cut-chain21: spliced bridge (set {g['bridge']['guardian_set_index']}, burn seq {g['bridge']['burn_sequence']}, floor {floor}, "
      f"emitters = chain 20's{' (CHANGED: ' + ','.join(changed) + ')' if changed else ''}, rotation {rotation}); "
      f"zUSD locked {locked_total} == notes {notes_total} == chain 20 supply == custody ({len(token_notes)} note(s)); "
      f"RAND allocs Σ {alloc_total} {rand_carry}; staking ({len(recipients)} recipients, {len(minters)} minters, entry 2500 bps, admission by vote, no slashing); "
      f"bridge fees {fees['mint_bps']}/{fees['burn_bps']} bps to {fees['recipient'][:10]}…; "
      f"testnet, binding_domain 1, proof_window_blocks 1024; gas {gas['gas_price']}/{gas['byte_price']} ceilings {dyn['max_gas_price']}/{dyn['max_byte_price']}, byte load {dyn['byte_load']}; "
      f"program_state {g['program_state']}; fees {g.get('fees', 'SKIPPED')}; hc_auth_multisig {g.get('hc_auth_multisig', 'SKIPPED')}, "
      f"max_proof_bytes {g['max_proof_bytes']}, max_block_bytes {g['max_block_bytes']}; every other field equal to chain 20's genesis")
if perps:
    m = perps["markets"][0]
    print(f"cut-chain21: perps: {m['symbol']} on zUSD (asset 1), lot {m['lot']}, tick {m['tick']}, {m['max_leverage']}x, maintenance {m['maintenance_bps']} bps, "
          f"fees {m['taker_fee_bps']}/{m['maker_fee_bps']} bps; max_tier {perps['max_tier']}, {perps['max_block_inputs']} inputs a block, "
          f"{perps['max_window_blocks']} blocks a proof, min deposit {perps['min_deposit']}; engine {perps['engine_hc'][:12]}…, genesis root {perps['genesis_root']}")
if ms:
    print(f"cut-chain21: multisig: create fee {fmt(int(ms['create_fee']))} RAND; the treasury 2 of 3, {fmt(treasury_units)} RAND NEW ISSUANCE "
          f"(not carried: Σ RAND notes {fmt(alloc_total)} == Σ scanned is the carry); issued at genesis: notes + stakes + treasury = {fmt(issued_total)} RAND")
print("cut-chain21: zUSD locked per backing: " + (", ".join(f"{b['chain']}:{b['token'][-8:]}={b['locked']}" for b in backings if b.get("locked")) or "none"))
for w in warnings:
    print(f"cut-chain21: ⚠ {w}")
PY
}

# ══ the field probe: the new sections are part of this rand-node's genesis hash ═════════════════
# Copies of the finished file each without one thing, every one still a valid genesis: without the
# `fees` section, without `fees.burn_floor` (the section then burns the base alone), without the
# `perps` section, without `perps.min_deposit` (optional: no floor), without the `multisig` section
# (no treasury: the supply is smaller, still valid), without `multisig.create_fee` (optional: 0) and
# without `hc_auth_multisig` (no private multisig: a single-key chain, still valid).
# Each must hash differently. A build that parses a section but leaves it out of the hash — or does
# not know it and drops it, as every build before d6cc16f5 (fees), feat/rpl3 (perps), 3119a29a
# (multisig) and 712c6336 (hc_auth_multisig) does (`Genesis` has no deny_unknown_fields) — would launch a chain without that rule.
# Chain 20's fields were probed by chain 20's cut; here they are compared equal to
# deploy/genesis-chain20.json, whose hash this same rand-node re-derives (6210cf07…). A section the
# dry run skipped (FEES/PERPS/MULTISIG/AUTH_MULTISIG_SKIPPED) has no variants, and says so.
py_variants() {
  python3 - <<'PY'
import copy, json, os
E = os.environ
g = json.load(open(E["OUT"]))
d = os.path.join(E["TMP"], "variants"); os.makedirs(d)
def drop(name, path):
    v = copy.deepcopy(g); cur = v
    for k in path[:-1]:
        cur = cur[k]
    del cur[path[-1]]
    json.dump(v, open(os.path.join(d, name + ".json"), "w"))
n = 0
for section, field in (("fees", "burn_floor"), ("perps", "min_deposit"), ("multisig", "create_fee")):
    if section in g:
        drop(section, [section])
        drop(f"{section}.{field}", [section, field])
        n += 2
if "hc_auth_multisig" in g:
    drop("hc_auth_multisig", ["hc_auth_multisig"])
    n += 1
open(os.path.join(d, "count"), "w").write(str(n))
PY
}

probe_fields() {   # <finished genesis> <its hash>
  local f name h ok=0 want s v
  for s in FEES PERPS MULTISIG AUTH_MULTISIG; do
    v=${s}_SKIPPED
    [ -z "${!v:-}" ] || echo "cut-chain21: ⚠ field probe of $(tr '[:upper:]' '[:lower:]' <<<"$s") SKIPPED — $s SKIPPED, the file has no such section to probe (DRY_RUN)" >&2
  done
  py_variants
  want=$(cat "$TMP/variants/count")
  for f in "$TMP"/variants/*.json; do
    [ -e "$f" ] || continue
    name=$(basename "$f" .json)
    rm -rf "$TMP/vprobe"
    # Every variant is a valid genesis file, so init must accept each and derive another hash — a
    # refusal proves nothing about the hash and is refused here.
    h=$("$NODE" init --datadir "$TMP/vprobe" --genesis "$f" 2>"$TMP/vprobe.err" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p' || true)
    [ -n "$h" ] || { echo "cut-chain21: without $name init refused the file or printed no hash ($(tail -1 "$TMP/vprobe.err" | cut -c1-90)) — the probe needs a hash" >&2; exit 1; }
    [ "$h" != "$2" ] || { echo "cut-chain21: without $name this rand-node derives the SAME genesis hash — it does not hash that field (a build that predates the section?)" >&2; exit 1; }
    echo "cut-chain21:   field probe: without $name → genesis ${h:0:12}… (≠ ${2:0:12}…)"
    ok=$((ok + 1))
  done
  [ "$ok" -eq "$want" ] || { echo "cut-chain21: the field probe ran $ok variant(s), expected $want" >&2; exit 1; }
  [ -n "${FEES_SKIPPED:-}${PERPS_SKIPPED:-}${MULTISIG_SKIPPED:-}${AUTH_MULTISIG_SKIPPED:-}" ] || [ "$ok" -eq 7 ] \
    || { echo "cut-chain21: the field probe ran $ok variant(s), expected 7 (fees, fees.burn_floor, perps, perps.min_deposit, multisig, multisig.create_fee, hc_auth_multisig)" >&2; exit 1; }
  echo "cut-chain21: the new sections ($ok variants probed) are part of this rand-node's genesis hash"
}

# ══ check-limits: what a chain-21 node serves (after launch; DRY_RUN runs it on a loopback node) ═
py_check_limits() {
  python3 - <<'PY'
import json, os, sys, urllib.request
E = os.environ
url, gen = E["CHECK_RPC"], json.load(open(E["CHECK_GENESIS"]))
def rpc(method, params=None):
    req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(),
                                 {"content-type": "application/json", "user-agent": "rand-cut-chain21/1"})
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
# the new field: the fee rules, and nothing burned yet (BASE_FEES_BURNED_ANY=1 once bundles landed).
# Skipped only when the genesis file itself has no fees section (a DRY_RUN on a binary without
# --fees) — never on the environment's word.
fees_skipped = "fees" not in gen
if fees_skipped:
    want("fee_rules (SKIPPED: absent)", L.get("fee_rules"), None)
    print("check-limits:   ⚠ FEES SKIPPED — a real chain-21 node must serve fee_rules {burn_base: true, subsidy_net_of_fees: false, burn_floor: true}")
else:
    # The cut build (6f1cd272+) serves every FeeRules field: the split and the dollar subsidy are
    # unset on chain 21 (each needs an `aggregation` section), so each is null.
    want("fee_rules", L.get("fee_rules"), {"burn_base": True, "subsidy_net_of_fees": False, "burn_floor": True,
                                           "proposer_share_bps": None, "prove_base": None, "usd_subsidy": None})
bfb = S.get("base_fees_burned")
if fees_skipped and bfb is None:
    print("check-limits:   base_fees_burned (SKIPPED: absent)  null — a build before d6cc16f5 has no such counter")
elif E.get("BASE_FEES_BURNED_ANY") == "1":
    want("base_fees_burned (a decimal string)", isinstance(bfb, str) and bfb.isdigit(), True)
    print(f"check-limits:   base_fees_burned is {bfb!r} (BASE_FEES_BURNED_ANY=1: any decimal accepted)")
else:
    want("base_fees_burned (at launch)", bfb, "0")
want("supply invariant_holds", S.get("invariant_holds"), True)
# the new section: perps — the decided bounds and market, the pinned engine, and nothing proved yet
# (proved_height 0, proved_root == the genesis root: run it before the first state proof lands).
# Skipped only when the genesis file itself has no perps section (a DRY_RUN without PERP_PROVER).
gp = gen.get("perps")
P = rpc("rand_getPerps")
if gp is None:
    want("perps limits (SKIPPED: absent)", L.get("perps"), None)
    want("rand_getPerps (SKIPPED: absent)", P, {"enabled": False})
    print("check-limits:   ⚠ PERPS SKIPPED — a real chain-21 node must serve perps (BTC-PERP on zUSD, tier 18, 24 inputs)")
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
# the new section: multisig — the create fee and the treasury, issued at genesis
gm = gen.get("multisig")
if gm is None:
    want("multisig limits (SKIPPED: absent)", L.get("multisig"), None)
    print("check-limits:   ⚠ MULTISIG SKIPPED — a real chain-21 node must serve multisig {create_fee: \"1000000000\"} and the treasury")
else:
    acct = gm["accounts"][0]
    want("multisig limits", L.get("multisig"), {"create_fee": "1000000000", "max_signers": 10, "max_payouts": 4})
    want("multisig_issued (the treasury)", S.get("multisig_issued"), str(acct["balance"]))
    M = rpc("rand_getMultisig", [E["TREASURY_ID"]]) or {}
    want("treasury signers (file order)", M.get("signers"), acct["signers"])
    want("treasury threshold", M.get("threshold"), 2)
# chain 20's fields, carried
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
# the new field: hc_auth_multisig (private multisig) — null where the genesis has none (a DRY_RUN
# that skipped it); served by rand_getLimits and rand_status from private-multisig Task 5 on.
want("hc_auth_multisig", L.get("hc_auth_multisig"), gen.get("hc_auth_multisig"))
want("status hc_auth_multisig", (rpc("rand_status") or {}).get("hc_auth_multisig"), gen.get("hc_auth_multisig"))
if "hc_auth_multisig" not in gen:
    print("check-limits:   ⚠ AUTH_MULTISIG SKIPPED — a real chain-21 node must serve hc_auth_multisig 9705f8e2… (private multisig)")
ps = L.get("program_state") or {}
want("program_state.cell_fee", ps.get("cell_fee"), str(gen["program_state"]["cell_fee"]))
B = rpc("rand_getBridgeState")
want("bridge emitters", B.get("emitters"), gen["bridge"]["emitters"])
want("bridge min_inbound_sequence", {str(k): v for k, v in (B.get("min_inbound_sequence") or {}).items()}, gen["bridge"]["min_inbound_sequence"])
want("bridge burn_sequence", B.get("burn_sequence"), gen["bridge"]["burn_sequence"])
want("bridge rotation_rules", B.get("rotation_rules"), {"delay_secs": 86400, "needs_possession": True})
want("bridge fees", B.get("fees"), {"mint_bps": 10, "burn_bps": 10, "recipient": gen["bridge"]["fees"]["recipient"]})
if bad:
    sys.exit(f"check-limits: {url} does NOT serve chain 21 as cut: {', '.join(bad)}")
print(f"check-limits: {url} serves chain 21 as cut ({len(L)} limits read)")
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

# ══ fixtures: synthetic inputs derived from the committed chain-20 genesis ═════════════════════
# FIXTURE_MODE=selftest (SELFTEST=1): the python steps alone; fake wallet addresses; the base file
# `rand-node genesis` would write faked too (with every flag's field, `fees` included).
# FIXTURE_MODE=dryrun (DRY_RUN=1): inputs the REAL binaries accept — the committed chain-20 genesis
# unchanged (its sha256 check passes), wallet lines at real addresses (chain 20's validator
# payouts), no base file. BOTH describe chain 20 as the cut expects to find it: its genesis bridge
# state unmoved (burn sequence 13; the four endpoints at their genesis floors 3/3/3/7 as next
# sequences), zUSD locked ETH-USDT 22 / BSC-USDT 22 / Tron-USDT 30 / Sol-USDT 25 == custody, the
# register its 26 validators at 1 000 RAND.
py_fixtures() {
  python3 - <<'PY'
import copy, json, os, time
E = os.environ; st = E["ST"]; dry = E.get("FIXTURE_MODE") == "dryrun"
exec(E["UNITS_PY"])
g20 = json.load(open(E["CHAIN20_GENESIS"]))
os.makedirs(f"{st}/snap"); os.makedirs(f"{st}/reg"); os.makedirs(f"{st}/tmp")
gnames, bnames = E["GENESIS_NAMES"].split(), E["BONDED"].split()
names = gnames + bnames
assert len(names) == len(g20["validators"]) == 26
minters = g20["staking"]["faucet_minters"]
assert len(minters) == len(gnames)
addr = {n: (minters[i] if i < len(gnames) else f"FIXTUREaddr{i:02d}") for i, n in enumerate(names)}
with open(f"{st}/validators.tsv", "w") as f:
    for n, v in zip(names, g20["validators"]):
        if n in gnames:
            f.write(f"{n}\t{addr[n]}\t{v['public_key']}\tpeer\t{v['payout']}\n")
for n, v in zip(names, g20["validators"]):
    if n in bnames:
        pk = bytes.fromhex(v["public_key"])
        open(f"{st}/reg/{n}.txt", "w").write(f"validator {addr[n]} on chain 15\nregistration: {(len(pk).to_bytes(8, 'little') + pk + b'sig').hex()}\n")
if not dry:
    json.dump(g20, open(f"{st}/genesis-chain20.json", "w"))
b = g20["bridge"]; z = g20["tokens"]["tokens"][0]
total = sum(x.get("locked", 0) for x in z["backings"])
live = [{**{k: x[k] for k in ("chain", "token", "decimals")}, "locked": x.get("locked", 0)} for x in z["backings"]]
assert total == 9900000000, "chain 20's zUSD supply is 99: ETH-USDT 22, BSC-USDT 22, Tron-USDT 30, Sol-USDT 25"
snap = {"taken_at": "dryrun" if dry else "selftest", "genesis_hash": E["CHAIN20_HASH"], "status_height": 50000,
        "validators": [{"address": addr[n], "stake": str(v["stake"]), "pending": [], "rewards": "0", "payout": v["payout"],
                        "nonce": 0, "active": True} for n, v in zip(names, g20["validators"])],
        "bridge": {**{k: b[k] for k in ("emitter", "emitters", "guardian_set_index", "guardians", "pq_guardians", "pause_key")},
                   "burn_sequence": b["burn_sequence"], "mint_paused": False, "registration_fee": str(g20["tokens"]["registration_fee"]),
                   "rules_v2": {"global_mint_cap_per_window": str(b["rules_v2"]["global_mint_cap_per_window"]), "cap_window_secs": b["rules_v2"]["cap_window_secs"]},
                   "min_inbound_sequence": b["min_inbound_sequence"]},
        "tokens": {"tokens": [{"index": 1, "symbol": "zUSD", "total_supply": str(total),
                               "authority": {"kind": "bridged", "backings": [{**x, "locked": str(x["locked"])} for x in live]}}]},
        "supply": {},
        "source": {"emitters": {c: E[f"EMITTER_{c}"] for c in "2345"},
                   "next_sequence": {c: int(b["min_inbound_sequence"][c]) for c in "2345"},
                   "custody": {f"{x['chain']}:{x['token']}": {"custody": x["locked"] * 10**x["decimals"] // 10**8 if x["decimals"] <= 8 else x["locked"] * 10**(x["decimals"] - 8), "fees": 0} for x in live}}}
json.dump(snap, open(f"{st}/snap/chain20-state.json", "w"))
rand_notes = [n for n in g20["alloc"] if n["opening"].get("asset", 0) == 0]
zusd_notes = [n for n in g20["alloc"] if n["opening"].get("asset", 0) == 1]
payouts = list(dict.fromkeys(v["payout"] for v in g20["validators"]))
assert len(payouts) >= len(rand_notes) + 1, "not enough distinct payout addresses for the dry-run carry"
wallets = [{"label": f"w{i}", "address": payouts[i] if dry else f"rand1SELFTEST{i}", "rand_units": n["amount"], "zusd_units": 0, "file": "-"}
           for i, n in enumerate(rand_notes)]
wallets.append({"label": "empty", "address": "rand1FIXTUREempty", "rand_units": 0, "zusd_units": 0, "file": "-"})
json.dump({"chain20_hash": E["CHAIN20_HASH"], "height_from": 50000, "height_to": 50000, "wallets": wallets,
           "uncovered_genesis_allocs": [], "rescanned": True}, open(f"{st}/snap/balances.json", "w"))
with open(f"{st}/alloc-rand.txt", "w") as f:
    f.write(f"# {'dry run' if dry else 'selftest'}\n")
    for w in wallets[:-1]:
        f.write(f"{w['label']} {w['address']} {fmt(w['rand_units'])}\n")
holder = payouts[len(rand_notes)] if dry else "rand1SELFTESTz"
open(f"{st}/zusd-carry.txt", "w").write("".join(f"holder {holder} {fmt(n['amount'], 8)}\n" for n in zusd_notes))
# A filled cut record (the fixture's — the real one is the operator's, published before the cut).
open(f"{st}/cut-record.txt", "w").write(
    "chain-id: 21\nreason: the genesis fees, perps and multisig (the treasury) sections and hc_auth_multisig (private multisig) are genesis-gated validity rules\n"
    "carries: fixture register, bridge state and balances\ndrops: fixture: nothing\nclients: fixture: none\n"
    "second-operator: fixture\nrollback: fixture: keep chain 20 dirs and *.pre-c21 binaries a day\n")
if dry:
    raise SystemExit(0)
# The treasury (selftest): three fixture signer keys — 1312 bytes each, none a validator's or a
# guardian's — 2 of 3, 500 000 000 RAND (docs/multisig.md's example).
fixture_pks = [f"{i:02x}" * 1312 for i in (0x1a, 0x2b, 0x3c)]
open(f"{st}/treasury.txt", "w").write("# selftest treasury\n" + "".join(f"signer s{i} {pk}\n" for i, pk in enumerate(fixture_pks, 1))
                                      + "threshold 2\nbalance 500000000\n")
# The perps section the cut writes after the genesis-root step (a fixture root).
d = json.loads(E["PERPS_JSON"])
json.dump({**{k: d[k] for k in ("collateral_asset", "max_tier", "max_window_blocks", "max_block_inputs", "min_deposit")},
           "engine_hc": E["EXPECT_ENGINE_HC"], "genesis_root": E["PERP_GENESIS_ROOT"], "markets": d["markets"]},
          open(f"{st}/tmp/perps.json", "w"))
open(f"{st}/faucet-recipients-changed.txt", "w").write("someone rand1SELFTESTfaucetrecipientchanged\n")
with open(f"{st}/tmp/token-notes.jsonl", "w") as f:
    for n in zusd_notes:
        f.write(json.dumps(n) + "\n")
# what `rand-node genesis --hardening-v6 --bundle-guest v3 --auth-guest --gas-… --testnet
# --binding-domain 1 --proof-window-blocks 1024 --program-state-cell-fee … --fees … --auth-multisig-guest` writes, before the splice
# (`--multisig`'s section is added by the selftest once py_treasury has written it)
base = {k: g20[k] for k in ("chain_id", "timestamp_ms", "validators", "faucet", "confidential", "fri_profile", "hc_bundle",
                           "epoch_blocks", "max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes",
                           "max_program_public_words", "envelope_bytes", "hardening_v6", "hc_auth")}
tb, tg, bps = (int(x) for x in E["GAS_DYNAMIC"].split(","))
base.update(chain_id=21, timestamp_ms=int(time.time() * 1000), alloc=rand_notes, hc_bundle=E["EXPECT_HC_BUNDLE"], hc_auth=E["EXPECT_HC_AUTH"],
            max_proof_bytes=int(E["MAX_PROOF_BYTES"]), max_block_bytes=int(E["MAX_BLOCK_BYTES"]),
            hc_auth_multisig=E["EXPECT_HC_AUTH_MULTISIG"],
            tokens={"registration_fee": g20["tokens"]["registration_fee"], "mint_cap_per_day": g20["tokens"]["mint_cap_per_day"], "tokens": []},
            gas={"gas_price": E["GAS_PRICE"], "byte_price": E["BYTE_PRICE"], "bundle_gas_limit": int(E["BUNDLE_GAS_LIMIT"]), "metering": "circuit",
                 "dynamic": {"target_block_bytes": tb, "target_block_gas": tg, "adjust_bps": bps,
                             "min_gas_price": E["GAS_PRICE"], "min_byte_price": E["BYTE_PRICE"],
                             "max_gas_price": E["MAX_GAS_PRICE"], "max_byte_price": E["MAX_BYTE_PRICE"], "byte_load": E["GAS_BYTE_LOAD"]}},
            testnet=True, binding_domain=int(E["BINDING_DOMAIN"]), proof_window_blocks=int(E["PROOF_WINDOW_BLOCKS"]),
            program_state={"cell_fee": int(E["PROGRAM_STATE_CELL_FEE"])}, fees=json.loads(E["FEES_JSON"]))
json.dump(base, open(f"{st}/base.json", "w"))
PY
}

# A fake chain-21 node for the selftest's check-limits: serves <file>'s {method: result} on loopback.
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

# ══ SELFTEST: the python steps on fixtures derived from deploy/genesis-chain20.json ════════════
if [ "${SELFTEST:-}" = 1 ]; then
  ST=$(mktemp -d); FAKE_RPC_PID=; trap 'rm -rf "$ST"; [ -z "$FAKE_RPC_PID" ] || kill "$FAKE_RPC_PID" 2>/dev/null || true' EXIT
  FEE_RECIPIENT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bridge"]["fees"]["recipient"])' "$CHAIN20_GENESIS")   # chain 20's
  PERP_GENESIS_ROOT=$(printf 'ab%.0s' $(seq 32))   # a fixture root (the cut derives the real one with perp-prover)
  export ST FIXTURE_MODE=selftest FEE_RECIPIENT PERP_GENESIS_ROOT
  py_fixtures
  NEW_EMITTER=$(printf '0%.0s' $(seq 63))1
  export SNAPSHOT_FILE=$ST/snap/chain20-state.json BALANCES_FILE=$ST/snap/balances.json CHAIN20_GENESIS=$ST/genesis-chain20.json \
    VALIDATORS_TSV=$ST/validators.tsv REGISTRATIONS=$ST/reg ALLOC_ADDRESSES=$ST/alloc-rand.txt ZUSD_CARRY=$ST/zusd-carry.txt \
    TMP=$ST/tmp HC_REPORTED=$EXPECT_HC_BUNDLE
  pass=0; fail=0
  ok()  { echo "selftest: ok   — $1"; pass=$((pass+1)); }
  bad() { echo "selftest: FAIL — $1"; fail=$((fail+1)); }
  fresh() { cp "$ST/base.json" "$ST/out.json"; export OUT=$ST/out.json; }

  # The treasury: py_treasury writes the --multisig file; the base gets it as `rand-node genesis
  # --multisig` would write it (the section as given).
  export TREASURY=$ST/treasury.txt
  if py_validators >/dev/null && py_treasury >"$ST/log" 2>&1 && grep -q 'NEW ISSUANCE' "$ST/log"; then
    ok "the fixture treasury parses: $(grep -o 'treasury: .*' "$ST/log" | cut -c1-110)"
  else bad "the fixture treasury: $(tail -2 "$ST/log")"; fi
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); b["multisig"]=json.load(open(sys.argv[2])); json.dump(b, open(sys.argv[1],"w"))' "$ST/base.json" "$ST/tmp/multisig.json"

  fresh
  if py_validators && py_splice; then
    if python3 - <<'PY'
import json, os
E = os.environ
g = json.load(open(E["OUT"]))
g20 = json.load(open(E["CHAIN20_GENESIS"]))
assert g["chain_id"] == 21 and g["hc_auth"] == g20["hc_auth"] and g["hc_bundle"] == g20["hc_bundle"]
assert list(g)[-10:] == ["hc_auth", "gas", "testnet", "binding_domain", "proof_window_blocks", "program_state", "fees", "perps", "multisig", "hc_auth_multisig"], list(g)
assert g["fees"] == {"burn_base": True, "burn_floor": True}
assert list(g)[:-4] == list(g20), "every key chain 20 has, in chain 20's order, then fees, perps, multisig, hc_auth_multisig"
assert g["hc_auth_multisig"] == "9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247" != g["hc_auth"]
p = g["perps"]
assert list(p) == ["collateral_asset", "max_tier", "max_window_blocks", "max_block_inputs", "min_deposit", "engine_hc", "genesis_root", "markets"], list(p)
assert p["collateral_asset"] == 1 and g["tokens"]["tokens"][0]["symbol"] == "zUSD"
assert (p["max_tier"], p["max_window_blocks"], p["max_block_inputs"], p["min_deposit"]) == (18, 64, 24, 100000000)
assert p["engine_hc"] == "f286a61171e274278ec8d18d7853e5f36799ed8dc5a3e31e0077ad89ef1d1573" and p["genesis_root"] == "ab" * 32
assert p["markets"] == [{"id": 0, "symbol": "BTC-PERP", "lot": 100000, "tick": 100000000, "max_leverage": 20, "maintenance_bps": 250, "taker_fee_bps": 5, "maker_fee_bps": 2}]
m = g["multisig"]
assert m["create_fee"] == "1000000000" and len(m["accounts"]) == 1
a = m["accounts"][0]
assert a["threshold"] == 2 and len(a["signers"]) == 3 and a["balance"] == str(500000000 * 10**9) and len(a["salt"]) == 64
assert g["testnet"] is True and g["binding_domain"] == 1 and g["proof_window_blocks"] == 1024
assert g["program_state"] == {"cell_fee": 10000000} == g20["program_state"]
assert (g["max_proof_bytes"], g["max_block_bytes"]) == (6291456, 19922944) == (6 << 20, 3 * (6 << 20) + (1 << 20))
assert {**g["gas"], "dynamic": {**g["gas"]["dynamic"], "target_block_bytes": 10485760}} == g20["gas"] and g["gas"]["dynamic"]["target_block_bytes"] == 9961472
assert g["gas"]["dynamic"]["byte_load"] == "paying"
assert g["bridge"]["rotation"] == g20["bridge"]["rotation"] == {"delay_secs": 86400, "needs_possession": True}
assert g["bridge"]["fees"] == g20["bridge"]["fees"] and g["bridge"]["fees"]["mint_bps"] == g["bridge"]["fees"]["burn_bps"] == 10
assert list(g["bridge"]) == list(g20["bridge"])
assert g["bridge"]["emitters"] == g20["bridge"]["emitters"] and g["bridge"]["min_inbound_sequence"] == {"2": 3, "3": 3, "4": 3, "5": 7}
assert g["bridge"]["burn_sequence"] == 13 and g["bridge"]["guardian_set_index"] == 1
assert g["staking"] == g20["staking"] and g["staking"]["max_stake_entry_bps_per_epoch"] == 2500 and g["staking"]["admission_by_vote"] is True
assert "slashing" not in g["staking"] and "vesting" not in g and "aggregation" not in g
assert [(b["chain"], b["locked"]) for b in g["tokens"]["tokens"][0]["backings"] if "locked" in b] == [(2, 2200000000), (3, 2200000000), (4, 3000000000), (5, 2500000000)]
assert g["tokens"] == g20["tokens"]
assert g["validators"] == g20["validators"] and g["consensus_domain"] == 1
assert sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 0) == sum(n["amount"] for n in g20["alloc"] if n["opening"].get("asset", 0) == 0)
assert sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 1) == 9900000000
assert all(sum(len(v) // 2 for v in n["envelope"].values()) == 1860 for n in g["alloc"])
PY
    then ok "the chain-20 fixture assembles into a chain-21 genesis (hc_auth_multisig 9705f8e2… last; max_proof_bytes 6 MiB, max_block_bytes 19 MiB, byte target 9961472; fees {burn_base, burn_floor}; perps BTC-PERP on zUSD (asset 1), 20x / 250 bps, tier 18, 24 inputs, tick and min deposit 10^8; multisig create fee 1 RAND, the treasury 2 of 3 at 500000000 RAND new issuance; every other key chain 20's in chain 20's order: testnet, binding_domain 1, proof_window_blocks 1024, gas + ceilings + paying, bridge.rotation, bridge.fees 10/10 bps to chain 20's recipient, staking 2500 bps + admission by vote, program_state 10000000; floors 3/3/3/7, burn sequence 13, 99 zUSD locked on four backings, chain 20's validators and allocs)"; else bad "assembled genesis content"; fi
  else bad "the happy path refused"; fi
  cp "$ST/out.json" "$ST/good.json"

  export -f py_validators py_splice
  # FEES_SKIPPED (DRY_RUN's path on a binary without --fees): the section must be absent, and said
  cp "$ST/base.json" "$ST/base.json.keep"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); del d["fees"]; json.dump(d, open(p,"w"))' "$ST/base.json"
  fresh
  if FEES_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 && grep -q 'FEES SKIPPED' "$ST/log"; then
    ok "FEES_SKIPPED=1 (DRY_RUN on a binary without --fees) cuts without the section, and says so"
  else bad "FEES_SKIPPED path: $(tail -2 "$ST/log")"; fi
  fresh
  if FEES_SKIPPED='' bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "a base without fees accepted when not skipped"
  elif grep -q -- "--fees did not take" "$ST/log"; then ok "the same base without FEES_SKIPPED is refused (--fees did not take)"
  else bad "no-fees base: $(tail -1 "$ST/log")"; fi
  mv "$ST/base.json.keep" "$ST/base.json"
  # PERPS_SKIPPED / MULTISIG_SKIPPED (DRY_RUN without PERP_PROVER / on a binary without --multisig):
  # each section absent, and said; set while the section is present, refused
  cp "$ST/base.json" "$ST/base.json.keep"; mv "$ST/tmp/perps.json" "$ST/tmp/perps.json.away"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); del d["multisig"]; json.dump(d, open(p,"w"))' "$ST/base.json"
  fresh
  if PERPS_SKIPPED=1 MULTISIG_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 && grep -q 'PERPS SKIPPED' "$ST/log" && grep -q ' MULTISIG SKIPPED' "$ST/log" \
     && python3 -c 'import json,os; g=json.load(open(os.environ["OUT"])); assert "perps" not in g and "multisig" not in g'; then
    ok "PERPS_SKIPPED=1 MULTISIG_SKIPPED=1 (DRY_RUN without PERP_PROVER / --multisig) cut without either section, and say so"
  else bad "PERPS/MULTISIG_SKIPPED path: $(tail -2 "$ST/log")"; fi
  mv "$ST/base.json.keep" "$ST/base.json"; mv "$ST/tmp/perps.json.away" "$ST/tmp/perps.json"
  fresh
  if MULTISIG_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "MULTISIG_SKIPPED with a multisig section accepted"
  elif grep -q 'MULTISIG_SKIPPED yet a multisig section is present' "$ST/log"; then ok "MULTISIG_SKIPPED with a multisig section present is refused"
  else bad "MULTISIG_SKIPPED with a section: $(tail -1 "$ST/log")"; fi
  # AUTH_MULTISIG_SKIPPED (DRY_RUN on a binary without --auth-multisig-guest): the field absent, and
  # said; the same base without the skip refused; the skip with the field present refused
  cp "$ST/base.json" "$ST/base.json.keep"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); del d["hc_auth_multisig"]; json.dump(d, open(p,"w"))' "$ST/base.json"
  fresh
  if AUTH_MULTISIG_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 && grep -q 'AUTH_MULTISIG SKIPPED' "$ST/log" \
     && python3 -c 'import json,os; assert "hc_auth_multisig" not in json.load(open(os.environ["OUT"]))'; then
    ok "AUTH_MULTISIG_SKIPPED=1 (DRY_RUN on a binary without --auth-multisig-guest) cuts without hc_auth_multisig, and says so"
  else bad "AUTH_MULTISIG_SKIPPED path: $(tail -2 "$ST/log")"; fi
  fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "a base without hc_auth_multisig accepted when not skipped"
  elif grep -q -- "--auth-multisig-guest did not take" "$ST/log"; then ok "the same base without AUTH_MULTISIG_SKIPPED is refused (--auth-multisig-guest did not take)"
  else bad "no-hc_auth_multisig base: $(tail -1 "$ST/log")"; fi
  mv "$ST/base.json.keep" "$ST/base.json"
  fresh
  if AUTH_MULTISIG_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "AUTH_MULTISIG_SKIPPED with hc_auth_multisig present accepted"
  elif grep -q 'AUTH_MULTISIG_SKIPPED yet hc_auth_multisig is present' "$ST/log"; then ok "AUTH_MULTISIG_SKIPPED with hc_auth_multisig present is refused"
  else bad "AUTH_MULTISIG_SKIPPED with the field: $(tail -1 "$ST/log")"; fi

  # every refusal the cut must make, one per case: <description> <file> <mutation> <expected reason phrase> [env]
  refuse() {
    local what=$1 file=$2 mutation=$3 phrase=$4; shift 4
    cp "$file" "$file.orig"
    python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); $mutation; json.dump(d, open(p,'w'))" "$file"
    fresh
    if (env "$@" bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1); then
      bad "$what — accepted"
    else
      local msg; msg=$(grep -o 'cut-chain21: .*' "$ST/log" | tail -1 | cut -c1-110)
      if grep -qF -- "$phrase" "$ST/log"; then ok "$what — $msg"; else bad "$what — refused, but not for the expected reason (wanted \"$phrase\"): $msg"; fi
    fi
    mv "$file.orig" "$file"
  }
  mkdir -p "$ST/done-ok/2" "$ST/done-ok/5" "$ST/done-bad/5"; touch "$ST/done-ok/5/5" "$ST/done-ok/5/6" "$ST/done-bad/5/9"
  S=$ST/snap/chain20-state.json; B=$ST/base.json; G=$ST/genesis-chain20.json
  # the new field: fees
  refuse "no fees section"                   "$B" 'del d["fees"]' "--fees did not take"
  refuse "fees without burn_floor"           "$B" 'del d["fees"]["burn_floor"]' "--fees did not take"
  refuse "fees.burn_base false"              "$B" 'd["fees"]["burn_base"] = False' "--fees did not take"
  refuse "fees.burn_base as 1, not true"     "$B" 'd["fees"]["burn_base"] = 1' "--fees did not take"
  refuse "fees.burn_floor as 1, not true"    "$B" 'd["fees"]["burn_floor"] = 1' "--fees did not take"
  refuse "fees.subsidy_net_of_fees set"      "$B" 'd["fees"]["subsidy_net_of_fees"] = True' "re-measured against the hidden-asset bundle (b053a76)"
  refuse "subsidy_net_of_fees alone"         "$B" 'd["fees"] = {"subsidy_net_of_fees": True}' "b053a76"
  refuse "a FEES_JSON off the decision"      "$S" 'pass' "not the decided" FEES_JSON='{"burn_base": true}'
  refuse "a fees section on chain 20's genesis" "$G" 'd["fees"] = {"burn_base": True}' "no fees, perps, multisig or hc_auth_multisig"
  # the new section: perps (the section file the splice inserts, $ST/tmp/perps.json)
  PJ=$ST/tmp/perps.json
  mv "$PJ" "$PJ.away"; fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "perps absent — accepted"
  elif grep -qF "no perps section to splice" "$ST/log"; then ok "perps absent — $(grep -o 'cut-chain21: .*' "$ST/log" | tail -1 | cut -c1-110)"
  else bad "perps absent — wrong refusal: $(tail -1 "$ST/log")"; fi
  mv "$PJ.away" "$PJ"
  refuse "perps written into the base (--perps)"   "$B" 'd["perps"] = json.load(open(sys.argv[1].replace("base.json", "tmp/perps.json")))' "the base file already has a perps section"
  refuse "a wrong engine_hc"                       "$PJ" 'd["engine_hc"] = "cd" * 32' "is not the pinned engine"
  refuse "an EXPECT_ENGINE_HC off the decision"    "$PJ" 'pass' "is not the pinned engine" EXPECT_ENGINE_HC="$(printf 'cd%.0s' $(seq 32))"
  refuse "a genesis_root the cut did not derive"   "$PJ" 'd["genesis_root"] = "cd" * 32' "is not the root this cut derived"
  refuse "collateral_asset 0 (RAND)"               "$PJ" 'd["collateral_asset"] = 0' "perps.collateral_asset is 0, not 1 (zUSD)"
  refuse "collateral 1 not zUSD (tokens[0] renamed)" "$G" 'd["tokens"]["tokens"][0]["symbol"] = "zEUR"' "is not zUSD"
  refuse "a second market"                         "$PJ" 'd["markets"].append(dict(d["markets"][0], id=1, symbol="ETH-PERP"))' "perps lists 2 markets"
  refuse "maintenance 500 bps at 20x (= initial)"  "$PJ" 'd["markets"][0]["maintenance_bps"] = 500' "at or above the initial margin 500 bps"
  refuse "maintenance 250 bps at 50x (> initial)"  "$PJ" 'd["markets"][0]["max_leverage"] = 50' "at or above the initial margin 200 bps"
  refuse "max_block_inputs 25"                     "$PJ" 'd["max_block_inputs"] = 25' "max_block_inputs is 25, not 24"
  refuse "max_tier 20"                             "$PJ" 'd["max_tier"] = 20' "max_tier is 20, not 18"
  refuse "a tick at nine decimals (10^9 = \$10)"   "$PJ" 'd["markets"][0]["tick"] = 1000000000' "perps is not the decided section: ['markets'] differ"
  refuse "min_deposit at nine decimals (10 zUSD)"  "$PJ" 'd["min_deposit"] = 1000000000' "perps is not the decided section: ['min_deposit'] differ"
  refuse "an unknown perps field"                  "$PJ" 'd["extra"] = 1' "not PerpsConfig's eight"
  refuse "a PERPS_JSON off the decision"           "$S" 'pass' "PERPS_JSON is not the decided" PERPS_JSON='{"collateral_asset": 0}'
  refuse "a perps section on chain 20's genesis"   "$G" 'd["perps"] = {}' "no fees, perps, multisig or hc_auth_multisig"
  # the new section: multisig (in the base, as --multisig writes it)
  refuse "multisig absent"                         "$B" 'del d["multisig"]' "--multisig did not take"
  refuse "create_fee 0"                            "$B" 'd["multisig"]["create_fee"] = "0"' "a create_fee of 0 is refused at this cut"
  refuse "create_fee absent (default 0)"           "$B" 'del d["multisig"]["create_fee"]' "a create_fee of 0 is refused at this cut"
  refuse "a MULTISIG_CREATE_FEE off the decision"  "$S" 'pass' "not the decided 1000000000" MULTISIG_CREATE_FEE=0
  refuse "threshold 3 (3 of 3)"                    "$B" 'd["multisig"]["accounts"][0]["threshold"] = 3' "threshold is 3, not 2"
  refuse "threshold 1 (1 of 3)"                    "$B" 'd["multisig"]["accounts"][0]["threshold"] = 1' "threshold is 1, not 2"
  refuse "2 signers"                               "$B" 'd["multisig"]["accounts"][0]["signers"].pop()' "lists 2 signer(s), not 3"
  refuse "a duplicate signer"                      "$B" 's = d["multisig"]["accounts"][0]["signers"]; s[2] = s[0]' "listed twice"
  refuse "a validator key as a signer"             "$B" 'd["multisig"]["accounts"][0]["signers"][1] = d["validators"][0]["public_key"]' "is a validator's key"
  refuse "a treasury balance not TREASURY's"       "$B" 'a = d["multisig"]["accounts"][0]; a["balance"] = str(int(a["balance"]) // 10**9)' "is not TREASURY's"
  refuse "a second seeded account"                 "$B" 'd["multisig"]["accounts"].append(dict(d["multisig"]["accounts"][0], salt="00" * 32))' "seeds 2 account(s)"
  refuse "a salt the cut did not write"            "$B" 'd["multisig"]["accounts"][0]["salt"] = "00" * 32' "not the file this cut wrote"
  refuse "signers reordered"                       "$B" 's = d["multisig"]["accounts"][0]["signers"]; s[0], s[1] = s[1], s[0]' "not the file this cut wrote"
  # a treasury whose balance, beside the notes and stakes, overflows a u64: the section file, the
  # balance file and the base all say it (as a cut from such a TREASURY would)
  for f in "$B" "$ST/tmp/multisig.json" "$ST/tmp/treasury-balance"; do cp "$f" "$f.keep"; done
  python3 -c 'import json,sys
for p in sys.argv[1:3]:
    d = json.load(open(p)); m = d.get("multisig", d); m["accounts"][0]["balance"] = str(2**64 - 1); json.dump(d, open(p, "w"))
open(sys.argv[3], "w").write(str(2**64 - 1))' "$B" "$ST/tmp/multisig.json" "$ST/tmp/treasury-balance"
  fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "a treasury that overflows the supply — accepted"
  elif grep -qF "overflows a u64" "$ST/log"; then ok "a treasury that overflows the supply — $(grep -o 'cut-chain21: .*' "$ST/log" | tail -1 | cut -c1-110)"
  else bad "a treasury that overflows the supply — wrong refusal: $(tail -1 "$ST/log")"; fi
  for f in "$B" "$ST/tmp/multisig.json" "$ST/tmp/treasury-balance"; do mv "$f.keep" "$f"; done
  refuse "a multisig section on chain 20's genesis" "$G" 'd["multisig"] = {}' "no fees, perps, multisig or hc_auth_multisig"
  # the new field: hc_auth_multisig (private multisig phase 4)
  refuse "hc_auth_multisig absent"                 "$B" 'del d["hc_auth_multisig"]' "--auth-multisig-guest did not take"
  refuse "hc_auth_multisig not this build's"       "$B" 'd["hc_auth_multisig"] = "cd" * 32' "is not this build's multisig auth guest"
  refuse "hc_auth_multisig equal to hc_auth"       "$B" 'd["hc_auth_multisig"] = d["hc_auth"]' "must differ from hc_auth"
  refuse "hc_auth_multisig = hc_auth, upper case"  "$B" 'd["hc_auth_multisig"] = d["hc_auth"].upper()' "must differ from hc_auth"
  refuse "hc_auth missing beside hc_auth_multisig" "$B" 'del d["hc_auth"]' "is not chain 20's auth guest"
  refuse "max_proof_bytes under 4 MiB"             "$B" 'd["max_proof_bytes"] = 4194303' "cannot hold a multisig auth proof"
  refuse "hc_auth_multisig not what the node wrote" "$S" 'pass' "is not what this rand-node wrote" HC_AUTH_MULTISIG_REPORTED="$(printf 'cd%.0s' $(seq 32))"
  refuse "hc_auth_multisig on chain 20's genesis"  "$G" 'd["hc_auth_multisig"] = "cd" * 32' "no fees, perps, multisig or hc_auth_multisig"
  # the treasury file itself (py_treasury), each refusal before a section is written
  PK=$(sed -n 's/^signer s1 //p' "$ST/treasury.txt"); PK2=$(sed -n 's/^signer s2 //p' "$ST/treasury.txt"); PK3=$(sed -n 's/^signer s3 //p' "$ST/treasury.txt")
  VPK=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validators"][5]["public_key"])' "$ST/genesis-chain20.json")
  GPK=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bridge"]["pq_guardians"][3])' "$ST/genesis-chain20.json")
  treasury_refuses() {  # <description> <phrase> <file content>
    printf '%s' "$3" > "$ST/treasury-case.txt"
    if TREASURY=$ST/treasury-case.txt bash -c 'py_validators >/dev/null && py_treasury' >"$ST/log" 2>&1; then bad "TREASURY: $1 — accepted"
    elif grep -qF -- "$2" "$ST/log"; then ok "TREASURY: $1 — $(grep -o 'cut-chain21: .*' "$ST/log" | tail -1 | cut -c1-110)"
    else bad "TREASURY: $1 — wrong refusal (wanted \"$2\"): $(tail -1 "$ST/log")"; fi
  }
  export -f py_treasury
  treasury_refuses "threshold 3"          "the treasury's threshold is 2" "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'"threshold 3"$'\n'"balance 1"$'\n'
  treasury_refuses "threshold 1"          "the treasury's threshold is 2" "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'"threshold 1"$'\n'"balance 1"$'\n'
  treasury_refuses "no threshold line"    "threshold missing"              "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'"balance 1"$'\n'
  treasury_refuses "2 signers"            "2 signer line(s)"               "signer a $PK"$'\n'"signer b $PK2"$'\n'"threshold 2"$'\n'"balance 1"$'\n'
  treasury_refuses "4 signers"            "4 signer line(s)"               "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'"signer d $VPK"$'\n'"threshold 2"$'\n'"balance 1"$'\n'
  treasury_refuses "a duplicate signer"   "listed twice"                   "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK"$'\n'"threshold 2"$'\n'"balance 1"$'\n'
  treasury_refuses "a validator's key"    "is validator"                   "signer a $PK"$'\n'"signer b $VPK"$'\n'"signer c $PK3"$'\n'"threshold 2"$'\n'"balance 1"$'\n'
  treasury_refuses "a guardian's key"     "is bridge PQ guardian 3's"      "signer a $PK"$'\n'"signer b $GPK"$'\n'"signer c $PK3"$'\n'"threshold 2"$'\n'"balance 1"$'\n'
  treasury_refuses "a short key"          "not a Dilithium2 public key"    "signer a ${PK:0:64}"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'"threshold 2"$'\n'"balance 1"$'\n'
  treasury_refuses "balance 0"            "balance 0"                      "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'"threshold 2"$'\n'"balance 0"$'\n'
  treasury_refuses "a balance of 10 decimals" "at most 9 decimals"         "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'"threshold 2"$'\n'"balance 1.0000000001"$'\n'
  treasury_refuses "no balance line"      "0 balance line(s)"              "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'"threshold 2"$'\n'
  treasury_refuses "an unknown line"      "a line is \`signer\`"           "signer a $PK"$'\n'"signer b $PK2"$'\n'"signer c $PK3"$'\n'"threshold 2"$'\n'"balance 1"$'\n'"salt 00"$'\n'
  # chain 20's fields, each still at its value
  refuse "no testnet marker"                 "$B" 'del d["testnet"]' "testnet is None, not true"
  refuse "binding_domain 0"                  "$B" 'd["binding_domain"] = 0' "binding_domain is 0, not 1"
  refuse "no binding_domain"                 "$B" 'del d["binding_domain"]' "--binding-domain 1 did not take"
  refuse "proof_window_blocks 256"           "$B" 'd["proof_window_blocks"] = 256' "proof_window_blocks is 256, not 1024"
  refuse "no proof_window_blocks"            "$B" 'del d["proof_window_blocks"]' "proof_window_blocks is None"
  refuse "no max_gas_price"                  "$B" 'del d["gas"]["dynamic"]["max_gas_price"]' "--max-gas-price did not take"
  refuse "a max_byte_price off the value"    "$B" 'd["gas"]["dynamic"]["max_byte_price"] = "800000"' "--max-byte-price did not take"
  refuse "no paying byte load"               "$B" 'del d["gas"]["dynamic"]["byte_load"]' "--gas-byte-load paying did not take"
  refuse "no program_state"                  "$B" 'del d["program_state"]' "--program-state-cell-fee did not take"
  refuse "a program_state cell fee off docs" "$B" 'd["program_state"]["cell_fee"] = 1' "--program-state-cell-fee did not take"
  refuse "a cell fee env off docs"           "$B" 'd["program_state"]["cell_fee"] = 5' "docs/program-state.md's 10000000" PROGRAM_STATE_CELL_FEE=5
  refuse "a rotation delay off 86400"        "$S" 'pass' "bridge.rotation is" ROTATION_DELAY_SECS=3600
  refuse "rotation without possession"       "$S" 'pass' "bridge.rotation is" ROTATION_NEEDS_POSSESSION=false
  refuse "a mint fee off 10 bps"             "$S" 'pass' "bridge.fees is" BRIDGE_MINT_BPS=30
  refuse "a burn fee off 10 bps"             "$S" 'pass' "bridge.fees is" BRIDGE_BURN_BPS=0
  refuse "no fee recipient loaded"           "$S" 'pass' "load_fee_recipient did not run" FEE_RECIPIENT=
  refuse "a validator payout as fee recipient" "$S" 'pass' "a validator's payout address" FEE_RECIPIENT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validators"][0]["payout"])' "$ST/genesis-chain20.json")"
  refuse "a fee recipient that is not chain 20's" "$S" 'pass' "FEE_RECIPIENT_CHANGED=1 only" FEE_RECIPIENT=rand1SELFTESTotherrecipient
  refuse "a rotation off chain 20's in its genesis" "$G" 'd["bridge"]["rotation"]["delay_secs"] = 3600' "not chain 20's"
  refuse "a stake entry budget off 2500 bps" "$S" 'pass' "not 2500" STAKE_ENTRY_BPS=3333
  refuse "slashing in chain 20's staking"    "$G" 'd["staking"]["slashing"] = {"equivocation_bps": 500, "jail_epochs": 2}' "carries none"
  refuse "a vesting section on chain 20"     "$G" 'd["vesting"] = {"entries": []}' "vesting section"
  refuse "an aggregation section"            "$B" 'd["aggregation"] = {}' "aggregation"
  refuse "a vesting section in the base"     "$B" 'd["vesting"] = {"entries": []}' "vesting section is present"
  refuse "a field the script does not know"  "$B" 'd["extra_unknown"] = 1' "fields this script does not know"
  refuse "incremental_nullifier_root"        "$B" 'd["incremental_nullifier_root"] = True' "fields this script does not know"
  refuse "tokens.incremental_root"           "$B" 'd["tokens"]["incremental_root"] = True' "token switches are not chain 20's"
  # chain 20's shape, carried
  refuse "gas prices that are not chain 20's" "$B" 'd["gas"]["gas_price"] = "200"; d["gas"]["dynamic"]["min_gas_price"] = "200"' "is not chain 20's {" GAS_PRICE=200
  refuse "a bundle_gas_limit off the pin"    "$B" 'd["gas"]["bundle_gas_limit"] = 16383' "not gas_max(14, 0, 0)"
  refuse "a byte target not half the block"  "$B" 'd["gas"]["dynamic"]["target_block_bytes"] = 4194304' "gas.dynamic targets are"
  # chain 21's decided limits (6 MiB proofs, 19 MiB blocks): chain 20's own are refused without LIMITS_CHANGED=1
  refuse "chain 20's 4 MiB proof cap, no LIMITS_CHANGED" "$B" 'd["max_proof_bytes"] = 4194304' "max_proof_bytes 4194304 is not chain 21's decided 6291456" MAX_PROOF_BYTES=4194304
  refuse "chain 20's 20 MiB block, no LIMITS_CHANGED" "$B" 'd["max_block_bytes"] = 20971520; d["gas"]["dynamic"]["target_block_bytes"] = 10485760' \
    "max_block_bytes 20971520 is not chain 21's decided 19922944" MAX_BLOCK_BYTES=20971520 GAS_DYNAMIC=10485760,262144,1250
  refuse "a block under 3 proofs + 1 MiB"    "$B" 'd["max_block_bytes"] = 18874368; d["gas"]["dynamic"]["target_block_bytes"] = 9437184' \
    "a v3 Call carries three proofs" MAX_BLOCK_BYTES=18874368 GAS_DYNAMIC=9437184,262144,1250 LIMITS_CHANGED=1
  cp "$B" "$B.orig"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["max_proof_bytes"] = 4194304; d["max_block_bytes"] = 20971520; d["gas"]["dynamic"]["target_block_bytes"] = 10485760; json.dump(d, open(p,"w"))' "$B"
  fresh
  if LIMITS_CHANGED=1 MAX_PROOF_BYTES=4194304 MAX_BLOCK_BYTES=20971520 GAS_DYNAMIC=10485760,262144,1250 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then
    ok "chain 20's limits (4 MiB / 20 MiB, byte target 10485760) are accepted with LIMITS_CHANGED=1"
  else bad "chain 20's limits with LIMITS_CHANGED=1: $(tail -1 "$ST/log")"; fi
  mv "$B.orig" "$B"
  refuse "a validator payout that is not chain 20's" "$B" 'd["validators"][0]["payout"] = d["validators"][1]["payout"]' "not chain 20's shape: ['validators']"
  refuse "no envelope_bytes"                 "$B" 'del d["envelope_bytes"]' "envelope_bytes is None, not 1860"
  refuse "a legacy (1 348-B) RAND alloc"     "$B" 'd["alloc"][0]["envelope"]["body"] = d["alloc"][0]["envelope"]["body"][:-1024]' "sealed in the legacy format"
  # chain 20 carries two zUSD notes, so token-notes.jsonl has two lines: shorten the first one's envelope
  TN=$ST/tmp/token-notes.jsonl; cp "$TN" "$TN.orig"
  python3 -c 'import json,sys; p=sys.argv[1]; L=open(p).read().splitlines(); d=json.loads(L[0]); d["envelope"]["body"] = d["envelope"]["body"][:-1024]; L[0]=json.dumps(d); open(p,"w").write("\n".join(L) + "\n")' "$TN"
  fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then bad "a legacy (1 348-B) zUSD note — accepted"
  elif grep -qF "sealed in the legacy format" "$ST/log"; then ok "a legacy (1 348-B) zUSD note — $(grep -o 'cut-chain21: .*' "$ST/log" | tail -1 | cut -c1-110)"
  else bad "a legacy (1 348-B) zUSD note — wrong refusal: $(tail -1 "$ST/log")"; fi
  mv "$TN.orig" "$TN"
  refuse "hc_auth not chain 20's"            "$G" 'd["hc_auth"] = "cd" * 32' "is not chain 20's auth guest"
  # the bridge: emitters, floors, custody
  refuse "a snapshot read at other emitters" "$S" 'd["source"]["emitters"]["2"] = "00" * 31 + "01"' "other emitters than this cut lists"
  refuse "a guardian rotation on chain 20"   "$S" 'd["bridge"]["guardian_set_index"] = 2' "BRIDGE_ROTATED=1"
  refuse "custody one unit below locked"     "$S" 'd["source"]["custody"][[k for k in d["source"]["custody"] if k.startswith("5:ce01")][0]]["custody"] -= 1' "source custody"
  refuse "custody at Tron above locked"      "$S" 'd["source"]["custody"][[k for k in d["source"]["custody"] if k.startswith("4:")][0]]["custody"] += 1' "source custody"
  refuse "zUSD supply above Σ locked"        "$S" 'd["tokens"]["tokens"][0]["total_supply"] = "1000000001"' "!= Σ locked"
  refuse "an explicit Ethereum floor of 0 reaching the splice" "$S" 'pass' "below 1" MIN_INBOUND_2=0
  refuse "a Solana floor below chain 20's"   "$S" 'pass' "below chain 20's own floor" MIN_INBOUND_5=3
  refuse "a floor above the next sequence"   "$S" 'pass' "would NEVER mint on chain 21" MIN_INBOUND_3=4
  refuse "an unminted BSC lock (next seq 4, explicit floor 3)" "$S" 'd["source"]["next_sequence"]["3"] = 4' "will mint on chain 21" MIN_INBOUND_3=3
  refuse "the relayer's done/ disagreeing"   "$S" 'pass' "the relayer's done/ says" RELAYER_DONE_DIR="$ST/done-bad"
  refuse "a stake that is not 1000 RAND"     "$S" 'd["validators"][3]["stake"] = "2000000000000"' "not a plain"
  refuse "a validator bonded on chain 20"    "$S" 'd["validators"].append(dict(d["validators"][0], address="new"))' "chain 20's register holds"
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
     && python3 -c 'import json,os; assert json.load(open(os.environ["OUT"]))["bridge"]["min_inbound_sequence"] == {"2": 5, "3": 3, "4": 3, "5": 9}' \
     && grep -q 'EXPECTED' "$ST/log"; then ok "auto floors follow the endpoints' next sequences (2:5, 5:9), with the expected-floor warning"
  else bad "auto floors: $(tail -2 "$ST/log")"; fi
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["source"]["next_sequence"]["4"] = 4; k=[k for k in d["source"]["custody"] if k.startswith("4:")][0]; d["source"]["custody"][k]["custody"] += 5000000; json.dump(d, open(p,"w"))' "$S"
  fresh
  if MIN_INBOUND_4=3 ALLOW_UNMINTED_LOCKS=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 \
     && python3 -c 'import json,os; assert json.load(open(os.environ["OUT"]))["bridge"]["min_inbound_sequence"]["4"] == 3' \
     && grep -q 'will mint on chain 21 (ALLOW_UNMINTED_LOCKS=1)' "$ST/log" && grep -q 'the unminted lock(s) on chain 4' "$ST/log"; then
    ok "an explicit floor below an unminted user lock carries with ALLOW_UNMINTED_LOCKS=1 (custody above locked on that chain only), with warnings"
  else bad "ALLOW_UNMINTED_LOCKS path: $(tail -2 "$ST/log")"; fi
  mv "$S.keep" "$S"
  fresh
  if RELAYER_DONE_DIR="$ST/done-ok" bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then
    ok "the relayer's done/ agreeing with every floor is accepted (an empty done/<c> = chain 20's floor − 1)"
  else bad "RELAYER_DONE_DIR agreeing: $(tail -2 "$ST/log")"; fi

  # check-limits against a fake chain-21 node serving the assembled file
  python3 - "$ST/good.json" "$ST/answers.json" <<'PY'
import json, sys
g = json.load(open(sys.argv[1])); d = g["gas"]["dynamic"]
json.dump({"rand_getGenesisHash": "ab" * 32,
           "rand_status": {"chain_id": 21, "hc_bundle": g["hc_bundle"], "hc_auth": g["hc_auth"], "hc_auth_multisig": g["hc_auth_multisig"], "fri_profile": "production"},
           "rand_getLimits": {"proof_window_blocks": 1024, "binding_domain": 1, "testnet": True, "admission_by_vote": True, "slashing": None,
                              "max_gas_price": d["max_gas_price"], "max_byte_price": d["max_byte_price"], "byte_load": "paying",
                              "gas_metering": "circuit", "bundle_gas_limit": 20479, "adjust_bps": 1250, "envelope_bytes": 1860,
                              "hardening_v6": True, "hc_auth": g["hc_auth"], "max_proof_bytes": g["max_proof_bytes"], "max_block_bytes": g["max_block_bytes"],
                              "hc_auth_multisig": g["hc_auth_multisig"],
                              "program_state": {"cell_fee": str(g["program_state"]["cell_fee"]), "max_reads": 8, "max_writes": 8, "max_payouts": 4},
                              "fee_rules": {"burn_base": True, "subsidy_net_of_fees": False, "burn_floor": True,
                                            "proposer_share_bps": None, "prove_base": None, "usd_subsidy": None},
                              "perps": {"collateral_asset": 1, "max_tier": 18, "max_window_blocks": 64, "max_payouts": 8, "max_block_inputs": 24, "min_deposit": "100000000"},
                              "multisig": {"create_fee": "1000000000", "max_signers": 10, "max_payouts": 4}},
           "rand_getSupply": {"base_fees_burned": "0", "burned": "0", "invariant_holds": True, "multisig_issued": g["multisig"]["accounts"][0]["balance"]},
           "rand_getPerps": {"enabled": True, "collateral_asset": 1, "max_tier": 18, "max_window_blocks": 64, "max_block_inputs": 24, "min_deposit": "100000000",
                             "engine_hc": g["perps"]["engine_hc"], "genesis_root": g["perps"]["genesis_root"], "markets": g["perps"]["markets"],
                             "proved_root": g["perps"]["genesis_root"], "proved_height": 0, "head_height": 0, "pending_heights": [], "accounts": 0},
           "rand_getMultisig": {"enabled": True, "id": "ef" * 32, "signers": g["multisig"]["accounts"][0]["signers"], "threshold": 2, "nonce": 0,
                                "vault": [{"asset": 0, "amount": g["multisig"]["accounts"][0]["balance"]}]},
           "rand_getBridgeState": {"emitters": g["bridge"]["emitters"], "min_inbound_sequence": g["bridge"]["min_inbound_sequence"],
                                   "burn_sequence": g["bridge"]["burn_sequence"], "rotation_rules": {"delay_secs": 86400, "needs_possession": True},
                                   "fees": g["bridge"]["fees"]}},
          open(sys.argv[2], "w"))
PY
  fake_rpc "$ST/answers.json" "$ST/port"
  RPC=http://127.0.0.1:$(cat "$ST/port")
  if TREASURY_ID=$(printf "ef%.0s" $(seq 32)) CHECK_RPC=$RPC CHECK_GENESIS=$ST/good.json EXPECT_GENESIS_HASH=$(printf 'ab%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1; then
    ok "check-limits accepts a node serving chain 21 as cut ($(grep -c '^check-limits:   ' "$ST/log") values read)"
  else bad "check-limits on a correct node: $(tail -3 "$ST/log")"; fi
  cp "$ST/answers.json" "$ST/answers.keep"
  python3 -c "import json,sys; p=sys.argv[1]; a=json.load(open(p)); a['rand_getSupply']['base_fees_burned'] = '4063900'; json.dump(a, open(p,'w'))" "$ST/answers.json"
  if BASE_FEES_BURNED_ANY=1 TREASURY_ID=$(printf "ef%.0s" $(seq 32)) CHECK_RPC=$RPC CHECK_GENESIS=$ST/good.json EXPECT_GENESIS_HASH=$(printf 'ab%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1; then
    ok "check-limits with BASE_FEES_BURNED_ANY=1 accepts a node that has burned since launch (base_fees_burned \"4063900\")"
  else bad "BASE_FEES_BURNED_ANY=1: $(tail -2 "$ST/log")"; fi
  mv "$ST/answers.keep" "$ST/answers.json"
  for m in 'L["proof_window_blocks"] = 256' 'L["binding_domain"] = 0' 'L["testnet"] = False' 'L["admission_by_vote"] = False' \
           'L["byte_load"] = None' 'L["max_gas_price"] = None' 'L["max_proof_bytes"] = 4194304' 'L["max_block_bytes"] = 20971520' 'L["program_state"] = None' 'B["rotation_rules"] = None' 'B["min_inbound_sequence"]["2"] = 0' 'B["fees"] = None' 'B["fees"]["burn_bps"] = 20' \
           'L["fee_rules"] = None' 'L["fee_rules"]["burn_floor"] = False' 'L["fee_rules"]["burn_base"] = False' 'L["fee_rules"]["subsidy_net_of_fees"] = True' \
           'L["fee_rules"]["burn_base"] = 1' 'L["fee_rules"]["burn_floor"] = 1' 'L["fee_rules"]["prove_base"] = "1000"' 'del L["fee_rules"]["usd_subsidy"]' 'L["proof_window_blocks"] = 1024.0' \
           'S["base_fees_burned"] = "1000000"' 'S["base_fees_burned"] = 0' 'del S["base_fees_burned"]' 'S["invariant_holds"] = False' 'S["invariant_holds"] = 1' \
           'L["perps"] = None' 'L["perps"]["collateral_asset"] = 0' 'L["perps"]["max_block_inputs"] = 120' 'L["perps"]["min_deposit"] = "1000000000"' \
           'P["engine_hc"] = "cd" * 32' 'P["markets"][0]["tick"] = 1000000000' 'P["markets"].append(P["markets"][0])' 'P["proved_height"] = 7' \
           'P["proved_root"] = "cd" * 32' 'P["genesis_root"] = "cd" * 32' 'P["collateral_asset"] = 0' 'P.clear(); P["enabled"] = False' \
           'L["multisig"] = None' 'L["multisig"]["create_fee"] = "0"' 'S["multisig_issued"] = "0"' 'del S["multisig_issued"]' \
           'M["threshold"] = 3' 'M["signers"].reverse()' 'a["rand_getMultisig"] = None' \
           'L["hc_auth_multisig"] = None' 'del L["hc_auth_multisig"]' 'L["hc_auth_multisig"] = "cd" * 32' 'a["rand_status"]["hc_auth_multisig"] = None' \
           'del a["rand_status"]["hc_auth_multisig"]'; do
    cp "$ST/answers.json" "$ST/answers.keep"
    python3 -c "import json,sys; p=sys.argv[1]; a=json.load(open(p)); L=a['rand_getLimits']; B=a['rand_getBridgeState']; S=a['rand_getSupply']; P=a['rand_getPerps']; M=a['rand_getMultisig']; $m; json.dump(a, open(p,'w'))" "$ST/answers.json"
    if TREASURY_ID=$(printf "ef%.0s" $(seq 32)) CHECK_RPC=$RPC CHECK_GENESIS=$ST/good.json EXPECT_GENESIS_HASH=$(printf 'ab%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1; then bad "check-limits accepted a node with $m"
    elif grep -q 'does NOT serve chain 21 as cut' "$ST/log"; then ok "check-limits refuses a node with $m"
    else bad "check-limits, $m: $(tail -1 "$ST/log")"; fi
    mv "$ST/answers.keep" "$ST/answers.json"
  done
  # FEES_SKIPPED in the environment cannot loosen check-limits: skipped-ness is the file's
  cp "$ST/answers.json" "$ST/answers.keep"
  python3 -c "import json,sys; p=sys.argv[1]; a=json.load(open(p)); a['rand_getLimits']['fee_rules'] = None; json.dump(a, open(p,'w'))" "$ST/answers.json"
  if FEES_SKIPPED=1 TREASURY_ID=$(printf "ef%.0s" $(seq 32)) CHECK_RPC=$RPC CHECK_GENESIS=$ST/good.json EXPECT_GENESIS_HASH=$(printf 'ab%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1; then bad "check-limits with FEES_SKIPPED=1 in the env accepted fee_rules null on a genesis with fees"
  elif grep -q 'does NOT serve chain 21 as cut: fee_rules' "$ST/log"; then ok "check-limits with FEES_SKIPPED=1 in the env still refuses fee_rules null when the genesis has fees"
  else bad "check-limits, env FEES_SKIPPED: $(tail -1 "$ST/log")"; fi
  mv "$ST/answers.keep" "$ST/answers.json"
  # a genesis without hc_auth_multisig (a dry run that skipped it) wants null from both reads, and says SKIPPED
  cp "$ST/answers.json" "$ST/answers.keep"
  python3 -c 'import json,sys; g=json.load(open(sys.argv[1])); del g["hc_auth_multisig"]; json.dump(g, open(sys.argv[2],"w"))
a=json.load(open(sys.argv[3])); a["rand_getLimits"]["hc_auth_multisig"] = None; a["rand_status"]["hc_auth_multisig"] = None; json.dump(a, open(sys.argv[3],"w"))' "$ST/good.json" "$ST/good-nomsauth.json" "$ST/answers.json"
  if TREASURY_ID=$(printf "ef%.0s" $(seq 32)) CHECK_RPC=$RPC CHECK_GENESIS=$ST/good-nomsauth.json EXPECT_GENESIS_HASH=$(printf 'ab%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1 \
     && grep -q 'AUTH_MULTISIG SKIPPED' "$ST/log"; then ok "check-limits on a genesis without hc_auth_multisig wants null from rand_getLimits and rand_status, and says SKIPPED"
  else bad "check-limits, no hc_auth_multisig: $(tail -1 "$ST/log")"; fi
  if TREASURY_ID=$(printf "ef%.0s" $(seq 32)) CHECK_RPC=$RPC CHECK_GENESIS=$ST/good.json EXPECT_GENESIS_HASH=$(printf 'ab%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1; then bad "check-limits accepted a node serving no hc_auth_multisig for a genesis that has it"
  elif grep -q 'does NOT serve chain 21 as cut: hc_auth_multisig, status hc_auth_multisig' "$ST/log"; then ok "check-limits refuses a node serving no hc_auth_multisig (a build before private-multisig Task 5) for a genesis that has it"
  else bad "check-limits, node without hc_auth_multisig: $(tail -1 "$ST/log")"; fi
  mv "$ST/answers.keep" "$ST/answers.json"
  if TREASURY_ID=$(printf "ef%.0s" $(seq 32)) CHECK_RPC=$RPC CHECK_GENESIS=$ST/good.json EXPECT_GENESIS_HASH=$(printf 'cd%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1; then bad "check-limits accepted another genesis hash"
  else ok "check-limits refuses a node serving another genesis hash"; fi
  kill "$FAKE_RPC_PID" 2>/dev/null || true; FAKE_RPC_PID=

  # the bash-level guards, each refusing before anything runs
  bash_refuses() {  # <description> <phrase> <env…> -- <args…>
    local what=$1 phrase=$2; shift 2
    local envs=(); while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
    if env -u MIN_INBOUND_2 -u MIN_INBOUND_3 -u MIN_INBOUND_4 -u MIN_INBOUND_5 SELFTEST=0 "${envs[@]}" bash "$0" "$@" >"$ST/log" 2>&1; then bad "$what — accepted"
    elif grep -qF -- "$phrase" "$ST/log"; then ok "$what — refused before anything runs"
    else bad "$what — wrong refusal: $(tail -1 "$ST/log")"; fi
  }
  for c in 2 3 4 5; do
    bash_refuses "EMITTER_$c off chain 20's, no EMITTERS_CHANGED" "is not chain 20's endpoint" "EMITTER_$c=$NEW_EMITTER" --
  done
  bash_refuses "chain 18's old Ethereum endpoint, even with EMITTERS_CHANGED=1" "never again" EMITTER_2=000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892 EMITTERS_CHANGED=1 --
  bash_refuses "chain 18's old Tron endpoint" "never again" EMITTER_4=0000000000000000000000000992df85dcce77ded2c0387f1fa9cf98ac859700 --
  for c in 2 3 4; do bash_refuses "MIN_INBOUND_$c=0 (the consume-step lock)" "is below 1" "MIN_INBOUND_$c=0" --; done
  bash_refuses "MIN_INBOUND_5=0" "is no floor" MIN_INBOUND_5=0 --
  bash_refuses "MIN_INBOUND_2=none" "its old locks would replay" MIN_INBOUND_2=none --
  printf '2 1\n3 0\n' > "$ST/floors-zero"; printf '2 1\n' > "$ST/floors-ok"; printf '6 1\n' > "$ST/floors-chain"
  bash_refuses "a floor file with chain 3 at 0" "is below 1" MIN_INBOUND_FILE="$ST/floors-zero" --
  bash_refuses "a floor given in env and in the file" "given twice" MIN_INBOUND_FILE="$ST/floors-ok" MIN_INBOUND_2=1 --
  bash_refuses "a floor file naming chain 6" "must be 2, 3, 4 or 5" MIN_INBOUND_FILE="$ST/floors-chain" --
  # A genesis dir without chain 21's committed file: since the launch record landed, the real
  # deploy/ holds genesis-chain21.json and `refuse_reused_chain_id 21` would fire first.
  mkdir -p "$ST/gendir-20"; cp "$CHAIN20_GENESIS" "$ST/gendir-20/genesis-chain20.json"
  bash_refuses "a valid floor file parses (and the cut then stops at its missing record)" "no cut record" CUT_POLICY_GENESIS_DIR="$ST/gendir-20" MIN_INBOUND_FILE="$ST/floors-ok" CUT_RECORD="$ST/no-such-record" --
  fresh
  if MIN_INBOUND_2=3 MIN_INBOUND_FILE='' bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then ok "an explicit floor equal to the next sequence is accepted"; else bad "explicit floor 3: $(tail -1 "$ST/log")"; fi
  bash_refuses "the cut without a cut record (OPS-7)" "no cut record" CUT_POLICY_GENESIS_DIR="$ST/gendir-20" CUT_RECORD="$ST/no-such-record" CHAIN20_SNAPSHOT="$ST/snap" NODE=/usr/bin/true WALLET=/usr/bin/true --
  python3 -c 'import json,sys; json.dump({"chain_id": 21}, open(sys.argv[1] + "/genesis-chain21.json", "w"))' "$ST" 2>/dev/null
  mkdir -p "$ST/gendir"; cp "$ST/genesis-chain21.json" "$ST/gendir/"; cp "$CHAIN20_GENESIS" "$ST/gendir/genesis-chain20.json"
  bash_refuses "a chain id a committed genesis already has (OPS-7)" "already used by genesis-chain21.json" CUT_POLICY_GENESIS_DIR="$ST/gendir" CUT_RECORD="$ST/cut-record.txt" CHAIN20_SNAPSHOT="$ST/snap" NODE=/usr/bin/true WALLET=/usr/bin/true --
  bash_refuses "snapshot on a dead tunnel" "is not answering" CHAIN20_RPC=http://127.0.0.1:9 -- snapshot "$ST/snap-new"
  mkdir -p "$ST/wd"; echo '{}' > "$ST/wd/shielded-1.key.json"
  bash_refuses "balances without the relayer's key file" "relayer.key.json is in none of" WALLETS_DIRS="$ST/wd" WALLET=/usr/bin/true ALLOC_ADDRESSES="$ST/none.txt" CHAIN20_RPC=http://127.0.0.1:9 -- balances "$ST/snap-bal"
  echo '{}' > "$ST/wd/relayer.key.json"
  bash_refuses "balances on a dead tunnel (relayer present)" "is not answering" WALLETS_DIRS="$ST/wd" WALLET=/usr/bin/true ALLOC_ADDRESSES="$ST/none.txt" CHAIN20_RPC=http://127.0.0.1:9 -- balances "$ST/snap-bal"
  # the fee recipient's fingerprint, computed by WALLET: a fake `rand` that prints one
  # shellcheck disable=SC2016  # the fake's own source: expanded when it runs, not here
  # (`perp image-hc` prints FAKE_HC, by default the pinned engine's)
  printf '#!/usr/bin/env bash\ncase "$*" in *"perp image-hc"*) echo "${FAKE_HC:-%s}"; exit 0;; esac\necho "fingerprint ${FAKE_FP:-89DS-4Q4X-HXSX-MBYW}"\necho saved\n' "$ENGINE_HC_DECIDED" > "$ST/fake-rand"; chmod +x "$ST/fake-rand"
  echo "rand1SELFTESTfeerecipient" > "$ST/fee-ok.txt"; echo "not-an-address" > "$ST/fee-bad.txt"; printf 'rand1a\nrand1b\n' > "$ST/fee-two.txt"
  fp_case() {  # <description> <want ok|refuse> <phrase> <env…>
    local what=$1 want=$2 phrase=$3; shift 3
    # shellcheck disable=SC2016  # expanded by the child bash
    if env "$@" bash -c 'WALLET=$FAKE_WALLET; load_fee_recipient' >"$ST/log" 2>&1; then r=ok; else r=refuse; fi
    if [ "$r" = "$want" ] && grep -qF -- "$phrase" "$ST/log"; then ok "$what — $(grep -o 'cut-chain21: .*' "$ST/log" | tail -1 | cut -c1-110)"
    else bad "$what — got $r: $(tail -1 "$ST/log")"; fi
  }
  export -f load_fee_recipient
  fp_case "the fee recipient with the expected fingerprint is loaded" ok "fingerprint 89DS-4Q4X-HXSX-MBYW (= FEE_RECIPIENT_FINGERPRINT)" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-ok.txt"
  fp_case "a fee recipient whose fingerprint differs is refused" refuse "not FEE_RECIPIENT_FINGERPRINT" FAKE_WALLET="$ST/fake-rand" FAKE_FP=AAAA-BBBB-CCCC-DDDD FEE_RECIPIENT_FILE="$ST/fee-ok.txt"
  fp_case "a missing fee recipient file is refused" refuse "no fee recipient file" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/none.txt"
  fp_case "a fee recipient file without an address is refused" refuse "does not hold a rand1" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-bad.txt"
  fp_case "a fee recipient file of two lines is refused" refuse "more than one line" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-two.txt"
  fp_case "a wallet that prints no fingerprint is refused" refuse "printed no fingerprint" FAKE_WALLET=/usr/bin/true FEE_RECIPIENT_FILE="$ST/fee-ok.txt"
  # the binary gates, on a fake rand-node: `genesis --help` lists every chain-20 flag, `--fees` only
  # when FAKE_FEES_FLAG says so, `--multisig` unless FAKE_MULTISIG_FLAG is set empty,
  # `--auth-multisig-guest` unless FAKE_AUTH_MULTISIG_FLAG is set empty; `--version`
  # says 0.7.1; nothing else answers. A fake perp-prover and engine image (the gates read neither).
  # shellcheck disable=SC2016  # the fake's own source
  printf '#!/usr/bin/env bash\ncase "$1" in\n  --version) echo "rand-node 0.7.1";;\n  genesis) echo "--hardening-v6 --bundle-guest --auth-guest --gas-price --gas-dynamic --envelope-bytes --max-gas-price --max-byte-price --gas-byte-load --testnet --binding-domain --proof-window-blocks --program-state-cell-fee ${FAKE_FEES_FLAG:-} ${FAKE_MULTISIG_FLAG---multisig} ${FAKE_AUTH_MULTISIG_FLAG---auth-multisig-guest}";;\nesac\n' > "$ST/fake-node"; chmod +x "$ST/fake-node"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$ST/fake-prover"; chmod +x "$ST/fake-prover"; echo image > "$ST/fake-image"
  sed 's/^reason:.*/reason: the genesis fees section is a genesis-gated validity rule/' "$ST/cut-record.txt" > "$ST/cut-record-no-treasury.txt"
  sed 's/^reason:.*/reason: the genesis fees, perps and multisig (the treasury) sections are genesis-gated validity rules/' "$ST/cut-record.txt" > "$ST/cut-record-no-msauth.txt"
  printf '%s\n' "$FEE_RECIPIENT" > "$ST/fee-c20.txt"
  real_cut=(CUT_POLICY_GENESIS_DIR="$ST/gendir-20" CUT_RECORD="$ST/cut-record.txt" CHAIN20_SNAPSHOT="$ST/snap" CHAIN20_GENESIS=deploy/genesis-chain20.json
            OUT="$ST/not-yet.json" NODE="$ST/fake-node" WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-c20.txt"
            TREASURY="$ST/treasury.txt" PERP_PROVER="$ST/fake-prover" PERP_IMAGE="$ST/fake-image")
  bash_refuses "the real cut on a rand-node without --fees (before d6cc16f5)" "has no --fees — a build before d6cc16f5" "${real_cut[@]}" --
  bash_refuses "the real cut on a rand-node with only --fees-like flags (--feesless)" "has no --fees — a build before d6cc16f5" "${real_cut[@]}" FAKE_FEES_FLAG=--feesless --
  bash_refuses "FEES_SKIPPED=1 from the environment on the real cut" "is set in the environment — refusing" "${real_cut[@]}" FAKE_FEES_FLAG=--fees FEES_SKIPPED=1 --
  bash_refuses "the real cut with no EXPECT_NODE_VERSION" "EXPECT_NODE_VERSION is unset" "${real_cut[@]}" FAKE_FEES_FLAG=--fees --
  bash_refuses "the real cut on a version other than EXPECT_NODE_VERSION" "not rand-node 0.7.2" "${real_cut[@]}" FAKE_FEES_FLAG=--fees EXPECT_NODE_VERSION=0.7.2 --
  bash_refuses "a rand-node that does not re-derive chain 20's hash" "not chain 20's 6210cf07" "${real_cut[@]}" FAKE_FEES_FLAG=--fees NODE_VERSION_OK=1 --
  # the new sections' gates on the real cut
  bash_refuses "the real cut on a rand-node without --multisig (before 3119a29a)" "has no --multisig — a build before 3119a29a" "${real_cut[@]}" FAKE_FEES_FLAG=--fees FAKE_MULTISIG_FLAG= --
  bash_refuses "the real cut without PERP_PROVER" "PERP_PROVER is unset or not executable" "${real_cut[@]}" FAKE_FEES_FLAG=--fees PERP_PROVER= --
  bash_refuses "the real cut with a PERP_PROVER that is not executable" "PERP_PROVER is unset or not executable" "${real_cut[@]}" FAKE_FEES_FLAG=--fees PERP_PROVER="$ST/fake-image" --
  bash_refuses "PERPS_SKIPPED=1 from the environment on the real cut" "PERPS_SKIPPED=1 is set in the environment — refusing" "${real_cut[@]}" FAKE_FEES_FLAG=--fees PERPS_SKIPPED=1 --
  bash_refuses "MULTISIG_SKIPPED=1 from the environment on the real cut" "cut-chain21: MULTISIG_SKIPPED=1 is set in the environment — refusing" "${real_cut[@]}" FAKE_FEES_FLAG=--fees MULTISIG_SKIPPED=1 --
  bash_refuses "the real cut on a rand-node without --auth-multisig-guest (before 712c6336)" "has no --auth-multisig-guest — a build before 712c6336" "${real_cut[@]}" FAKE_FEES_FLAG=--fees FAKE_AUTH_MULTISIG_FLAG= --
  bash_refuses "AUTH_MULTISIG_SKIPPED=1 from the environment on the real cut" "AUTH_MULTISIG_SKIPPED=1 is set in the environment — refusing" "${real_cut[@]}" FAKE_FEES_FLAG=--fees AUTH_MULTISIG_SKIPPED=1 --
  bash_refuses "an EXPECT_HC_AUTH_MULTISIG off the decided guest" "is not the decided multisig auth guest" "${real_cut[@]}" EXPECT_HC_AUTH_MULTISIG="$(printf 'cd%.0s' $(seq 32))" --
  bash_refuses "a cut record that does not name hc_auth_multisig" "names no hc_auth_multisig" "${real_cut[@]}" FAKE_FEES_FLAG=--fees CUT_RECORD="$ST/cut-record-no-msauth.txt" --
  bash_refuses "an engine image whose hc is not the pinned engine" "not EXPECT_ENGINE_HC" "${real_cut[@]}" FAKE_FEES_FLAG=--fees NODE_VERSION_OK=1 FAKE_HC="$(printf 'cd%.0s' $(seq 32))" --
  bash_refuses "an EXPECT_ENGINE_HC off the decided engine" "is not the decided engine" "${real_cut[@]}" EXPECT_ENGINE_HC="$(printf 'cd%.0s' $(seq 32))" --
  bash_refuses "no engine image" "missing $ST/no-image" "${real_cut[@]}" FAKE_FEES_FLAG=--fees PERP_IMAGE="$ST/no-image" --
  bash_refuses "no treasury file" "missing $ST/no-treasury.txt" "${real_cut[@]}" FAKE_FEES_FLAG=--fees TREASURY="$ST/no-treasury.txt" --
  bash_refuses "a cut record that does not name the treasury" "names no treasury" "${real_cut[@]}" FAKE_FEES_FLAG=--fees CUT_RECORD="$ST/cut-record-no-treasury.txt" --
  # DRY_RUN on the same binary without --fees or --multisig, and no PERP_PROVER: three loud banners,
  # then on (it stops later, at the fake's init)
  if env -u MIN_INBOUND_2 -u MIN_INBOUND_3 -u MIN_INBOUND_4 -u MIN_INBOUND_5 -u PERP_PROVER SELFTEST=0 DRY_RUN=1 CHAIN20_GENESIS=deploy/genesis-chain20.json \
       FAKE_MULTISIG_FLAG= FAKE_AUTH_MULTISIG_FLAG= TREASURY="$ST/treasury.txt" NODE="$ST/fake-node" WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-c20.txt" bash "$0" >"$ST/log" 2>&1; then bad "DRY_RUN on a fake rand-node finished"
  elif grep -q 'FEES SKIPPED ⚠⚠⚠' "$ST/log" && grep -q ' MULTISIG SKIPPED ⚠⚠⚠' "$ST/log" && grep -q 'PERPS SKIPPED ⚠⚠⚠' "$ST/log" && grep -q 'AUTH_MULTISIG SKIPPED ⚠⚠⚠' "$ST/log" && grep -q "cutting with rand-node 0.7.1" "$ST/log"; then
    ok "DRY_RUN on a rand-node without --fees / --multisig / --auth-multisig-guest and without PERP_PROVER says FEES, MULTISIG, AUTH_MULTISIG and PERPS SKIPPED loudly and goes on past the gates"
  else bad "DRY_RUN without --fees / --multisig / --auth-multisig-guest / PERP_PROVER: $(tail -2 "$ST/log")"; fi
  # DRY_RUN with FEES_SKIPPED=1 in the env on a binary that HAS --fees: ignored, the section is cut
  if env -u MIN_INBOUND_2 -u MIN_INBOUND_3 -u MIN_INBOUND_4 -u MIN_INBOUND_5 SELFTEST=0 DRY_RUN=1 FEES_SKIPPED=1 PERPS_SKIPPED=1 MULTISIG_SKIPPED=1 AUTH_MULTISIG_SKIPPED=1 FAKE_FEES_FLAG=--fees \
       PERP_PROVER="$ST/fake-prover" PERP_IMAGE="$ST/fake-image" TREASURY="$ST/treasury.txt" \
       CHAIN20_GENESIS=deploy/genesis-chain20.json NODE="$ST/fake-node" WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-c20.txt" bash "$0" >"$ST/log" 2>&1; then bad "DRY_RUN on a fake rand-node finished"
  elif grep -q 'FEES_SKIPPED=1 in the environment is IGNORED' "$ST/log" && grep -q 'PERPS_SKIPPED=1 in the environment is IGNORED' "$ST/log" \
       && grep -q 'cut-chain21: ⚠ MULTISIG_SKIPPED=1 in the environment is IGNORED' "$ST/log" && grep -q 'AUTH_MULTISIG_SKIPPED=1 in the environment is IGNORED' "$ST/log" \
       && ! grep -q 'SKIPPED ⚠⚠⚠' "$ST/log" \
       && grep -q 'engine image .*(= EXPECT_ENGINE_HC' "$ST/log"; then
    ok "DRY_RUN ignores FEES/PERPS/MULTISIG/AUTH_MULTISIG_SKIPPED=1 from the environment (loudly) when the binary and PERP_PROVER are in hand"
  else bad "DRY_RUN with env *_SKIPPED: $(tail -2 "$ST/log")"; fi
  echo "selftest: $pass passed, $fail failed"
  [ "$fail" = 0 ]; exit
fi

# ══ DRY_RUN: the REAL cut path on synthetic inputs, no network ══════════════════════════════════
# Everything `snapshot` and `balances` would read off chain 20 and the four source chains is
# synthesised from the committed chain-20 genesis (py_fixtures, FIXTURE_MODE=dryrun) as the cut
# expects to find it. Then the cut below runs unchanged — chain 20's hash re-derived, the real
# `rand-node genesis` with every flag (`--fees` included), `alloc-note`, the splice and every
# assertion, two `init`s, the field probe — and then a
# LOOPBACK probe node (127.0.0.1 only, no bootstrap, no mDNS, a throwaway key) runs the file so
# `check-limits` reads what a chain-21 node serves. The output lands in a temp dir (DRY_OUT to
# choose), never at deploy/genesis-chain21.json, and is not chain 21: launch nothing from it.
if [ "${DRY_RUN:-}" = 1 ]; then
  ST=$(mktemp -d)
  export ST FIXTURE_MODE=dryrun
  py_fixtures
  CHAIN20_SNAPSHOT=$ST/snap VALIDATORS_TSV=$ST/validators.tsv REGISTRATIONS=$ST/reg \
    ALLOC_ADDRESSES=$ST/alloc-rand.txt ZUSD_CARRY=$ST/zusd-carry.txt CUT_RECORD=$ST/cut-record.txt
  OUT=${DRY_OUT:-$ST/genesis-chain21.DRY-RUN.json}
  export CHAIN20_SNAPSHOT VALIDATORS_TSV REGISTRATIONS ALLOC_ADDRESSES ZUSD_CARRY
  if [ ! -f "$TREASURY" ]; then
    # No treasury file: three throwaway signer keys (NODE keygen, under $ST, deleted with it), 2 of 3,
    # 500 000 000 RAND (docs/multisig.md's example). Never what chain 21's signers will be.
    [ -x "$NODE" ] || { echo "cut-chain21: DRY RUN without a TREASURY file needs NODE to generate throwaway signer keys" >&2; exit 1; }
    mkdir -p "$ST/treasury-keys"
    { echo "# DRY RUN: three throwaway signer keys under $ST/treasury-keys"
      for i in 1 2 3; do
        "$NODE" keygen --out "$ST/treasury-keys/dry-s$i.key.json" >/dev/null
        echo "signer dry-s$i $("$NODE" address --key "$ST/treasury-keys/dry-s$i.key.json" | sed -n 's/^public_key: //p')"
      done
      echo "threshold 2"; echo "balance 500000000"; } > "$ST/treasury.txt"
    echo "cut-chain21: DRY RUN — no TREASURY file ($TREASURY): three throwaway signer keys, 2 of 3, 500000000 RAND → $ST/treasury.txt"
    TREASURY=$ST/treasury.txt
  fi
  export TREASURY
  echo "cut-chain21: DRY RUN — synthetic chain-20 snapshot, balances and inputs under $ST (from $CHAIN20_GENESIS); no network; $OUT is NOT chain 21"
fi

if [ "${1:-}" = snapshot ]; then
  SNAP=${2:?snapshot <dir>}
  [ ! -e "$SNAP/chain20-state.json" ] || { echo "cut-chain21: $SNAP/chain20-state.json exists — a snapshot is taken once; move it aside" >&2; exit 1; }
  need_chain20_rpc
  mkdir -p "$SNAP"; export SNAP
  py_snapshot
  exit 0
fi

if [ "${1:-}" = balances ]; then
  SNAP=${2:?balances <snapshot dir>}
  [ ! -e "$SNAP/balances.json" ] || { echo "cut-chain21: $SNAP/balances.json exists — move it aside to re-scan" >&2; exit 1; }
  [ ! -e "$ALLOC_ADDRESSES" ] || { echo "cut-chain21: $ALLOC_ADDRESSES exists — move it aside; \`balances\` writes it" >&2; exit 1; }
  [ -x "$WALLET" ] || { echo "cut-chain21: $WALLET is not executable — a rand that decodes chain 20: v0.7.0 (the build chain 20 runs, tag 806ed349)" >&2; exit 1; }
  for w in $REQUIRED_WALLETS; do
    found=; for d in $WALLETS_DIRS; do [ -e "$d/$w.key.json" ] && found=$d/$w.key.json; done
    [ -n "$found" ] || { echo "cut-chain21: $w.key.json is in none of WALLETS_DIRS ($WALLETS_DIRS) — link it there before the scan (the relayer's: ~/.rand-chain17/alloc-wallets/relayer.key.json → ~/.rand-chain14/wallets/relayer.key.json)" >&2; exit 1; }
    [ -s "$found" ] || { echo "cut-chain21: $found is empty or a broken link" >&2; exit 1; }
    echo "cut-chain21: required wallet $w: $found"
  done
  need_chain20_rpc
  [ -f "$SNAP/chain20-state.json" ] || { echo "cut-chain21: take the snapshot first ($0 snapshot $SNAP)" >&2; exit 1; }
  refuse_in_tree_key "$SNAP/chain20-state.json"
  export SNAP WALLET WALLETS_DIRS
  py_balances
  exit 0
fi

# ══ the cut ══════════════════════════════════════════════════════════════════════════════════
# FEES_SKIPPED from the environment: refused on the real cut, ignored (loudly) by DRY_RUN, which
# decides it from the binary in hand.
if [ -n "$FEES_SKIPPED_FROM_ENV" ]; then
  if [ "${DRY_RUN:-}" = 1 ]; then
    echo "cut-chain21: ⚠ FEES_SKIPPED=$FEES_SKIPPED_FROM_ENV in the environment is IGNORED — the dry run decides it from the binary (--fees or not)" >&2
  else
    echo "cut-chain21: FEES_SKIPPED=$FEES_SKIPPED_FROM_ENV is set in the environment — refusing: the fees section is never skipped on the real cut (only DRY_RUN sets it, on a binary without --fees)" >&2; exit 1
  fi
fi
# PERPS_SKIPPED, MULTISIG_SKIPPED and AUTH_MULTISIG_SKIPPED from the environment: the same rule.
for s in PERPS MULTISIG AUTH_MULTISIG; do
  v=${s}_SKIPPED_FROM_ENV
  [ -n "${!v}" ] || continue
  if [ "${DRY_RUN:-}" = 1 ]; then
    echo "cut-chain21: ⚠ ${s}_SKIPPED=${!v} in the environment is IGNORED — the dry run decides it from the inputs in hand" >&2
  else
    echo "cut-chain21: ${s}_SKIPPED=${!v} is set in the environment — refusing: the $(tr '[:upper:]' '[:lower:]' <<<"$s") section/field is never skipped on the real cut (only DRY_RUN sets it)" >&2; exit 1
  fi
done
# OPS-7 first: a reused chain id and a missing cut record are refused before anything else.
refuse_reused_chain_id "$CHAIN_ID"
require_cut_record "$CUT_RECORD"
# The treasury is new issuance, not a carry: the record published before the cut says it seeds one.
require_cut_record_mentions "$CUT_RECORD" 'treasury|multisig' "treasury (the multisig section's seeded account, new issuance)" reason carries
# Private multisig is switched on at this cut: the record says so.
require_cut_record_mentions "$CUT_RECORD" 'hc_auth_multisig|private multisig' "hc_auth_multisig (private multisig, a new auth guest)" reason carries
[ -n "$CHAIN20_SNAPSHOT" ] || { echo "cut-chain21: CHAIN20_SNAPSHOT is unset — run \`$0 snapshot <dir>\` while chain 20 is up" >&2; exit 1; }
SNAPSHOT_FILE=$CHAIN20_SNAPSHOT/chain20-state.json; BALANCES_FILE=$CHAIN20_SNAPSHOT/balances.json
export SNAPSHOT_FILE BALANCES_FILE
for bin in "$NODE" "$WALLET"; do
  [ -x "$bin" ] || { echo "cut-chain21: $bin is not executable — the binaries of the fees build (main at d6cc16f5 or later)" >&2; exit 1; }
done
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$ALLOC_ADDRESSES" "$ZUSD_CARRY" "$CHAIN20_GENESIS" "$TREASURY" "$PERP_IMAGE" ${FAUCET_RECIPIENTS:+"$FAUCET_RECIPIENTS"}; do
  [ -f "$f" ] || { echo "cut-chain21: missing $f" >&2; exit 1; }
done
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$ALLOC_ADDRESSES" "$ZUSD_CARRY" "$TREASURY" ${FAUCET_RECIPIENTS:+"$FAUCET_RECIPIENTS"}; do
  refuse_in_tree_key "$f"
done
for n in $BONDED; do refuse_in_tree_key "$REGISTRATIONS/$n.txt"; done
[ "$(shasum -a 256 "$CHAIN20_GENESIS" | cut -c1-64)" = "$CHAIN20_GENESIS_SHA256" ] \
  || { echo "cut-chain21: $CHAIN20_GENESIS is not chain 20's committed genesis file (sha256 ${CHAIN20_GENESIS_SHA256:0:8}…)" >&2; exit 1; }
[ ! -e "$OUT" ] || { echo "cut-chain21: $OUT already exists — a genesis is cut once; move it aside deliberately" >&2; exit 1; }
HELP=$("$NODE" genesis --help)
for flag in --hardening-v6 --bundle-guest --auth-guest --gas-price --gas-dynamic --envelope-bytes \
            --max-gas-price --max-byte-price --gas-byte-load --testnet --binding-domain --proof-window-blocks \
            --program-state-cell-fee; do
  grep -q -- "$flag" <<<"$HELP" || { echo "cut-chain21: $NODE genesis has no $flag (not a build that can cut chain 20's shape)" >&2; exit 1; }
done
# The fees section: the one flag a build before d6cc16f5 (v0.7.1 and earlier) does not have.
if ! grep -qE -- '(^|[[:space:]])--fees([[:space:]=<]|$)' <<<"$HELP"; then
  if [ "${DRY_RUN:-}" = 1 ]; then
    FEES_SKIPPED=1; export FEES_SKIPPED
    cat >&2 <<EOF
cut-chain21: ⚠⚠⚠ FEES SKIPPED ⚠⚠⚠ — $NODE genesis has no --fees: this binary predates d6cc16f5
cut-chain21:     (the genesis fees section). The dry run goes on WITHOUT the fees section and without
cut-chain21:     the field probe; the REAL cut refuses this binary. Re-run DRY_RUN with a build at d6cc16f5+.
EOF
  else
    echo "cut-chain21: $NODE genesis has no --fees — a build before d6cc16f5; the fees section (burn_base, burn_floor) cannot be written" >&2; exit 1
  fi
fi
# The multisig section: `--multisig` (3119a29a on). Without it the treasury cannot be written.
if ! grep -qE -- '(^|[[:space:]])--multisig([[:space:]=<]|$)' <<<"$HELP"; then
  if [ "${DRY_RUN:-}" = 1 ]; then
    MULTISIG_SKIPPED=1; export MULTISIG_SKIPPED
    cat >&2 <<EOF
cut-chain21: ⚠⚠⚠ MULTISIG SKIPPED ⚠⚠⚠ — $NODE genesis has no --multisig: this binary predates 3119a29a.
cut-chain21:     The dry run goes on WITHOUT the treasury and without its probe; the REAL cut refuses this binary.
EOF
  else
    echo "cut-chain21: $NODE genesis has no --multisig — a build before 3119a29a; the multisig section (the treasury) cannot be written" >&2; exit 1
  fi
fi
# hc_auth_multisig: `--auth-multisig-guest` (712c6336 on, feat/private-multisig).
if ! grep -qE -- '(^|[[:space:]])--auth-multisig-guest([[:space:]=<]|$)' <<<"$HELP"; then
  if [ "${DRY_RUN:-}" = 1 ]; then
    AUTH_MULTISIG_SKIPPED=1; export AUTH_MULTISIG_SKIPPED
    cat >&2 <<EOF
cut-chain21: ⚠⚠⚠ AUTH_MULTISIG SKIPPED ⚠⚠⚠ — $NODE genesis has no --auth-multisig-guest: this binary predates
cut-chain21:     712c6336 (private multisig). The dry run goes on WITHOUT hc_auth_multisig and its probe; the REAL
cut-chain21:     cut refuses this binary.
EOF
  else
    echo "cut-chain21: $NODE genesis has no --auth-multisig-guest — a build before 712c6336 (private multisig phase 4); hc_auth_multisig cannot be written" >&2; exit 1
  fi
fi
# The perps section: its genesis root comes from durian.market's perp-prover (the engine's own
# encoding of the genesis state) and this build's `rand perp genesis-root`; without them it cannot
# be derived, and a hand-copied root is not accepted.
if [ -z "$PERP_PROVER" ] || [ ! -x "$PERP_PROVER" ]; then
  if [ "${DRY_RUN:-}" = 1 ]; then
    PERPS_SKIPPED=1; export PERPS_SKIPPED
    cat >&2 <<EOF
cut-chain21: ⚠⚠⚠ PERPS SKIPPED ⚠⚠⚠ — PERP_PROVER='${PERP_PROVER}' is not an executable perp-prover: the engine's
cut-chain21:     genesis root cannot be derived. The dry run goes on WITHOUT the perps section and its probe;
cut-chain21:     the REAL cut refuses. Build durian.market's perp-prover (cargo build --release -p perp-prover).
EOF
  else
    echo "cut-chain21: PERP_PROVER is unset or not executable ('${PERP_PROVER}') — durian.market's perp-prover derives the perps genesis root (\`perp-prover genesis-state\`); refusing" >&2; exit 1
  fi
fi
NODE_VERSION=$("$NODE" --version 2>/dev/null || true)
if [ -z "$EXPECT_NODE_VERSION" ]; then
  if [ "${DRY_RUN:-}" = 1 ]; then echo "cut-chain21: ⚠ DRY RUN with '$NODE_VERSION' and no EXPECT_NODE_VERSION — the real cut refuses that unless NODE_VERSION_OK=1" >&2
  else [ "${NODE_VERSION_OK:-}" = 1 ] || { echo "cut-chain21: EXPECT_NODE_VERSION is unset — set it to the tagged release that carries the fees section (d6cc16f5+; '$NODE_VERSION' is what $NODE reports), or NODE_VERSION_OK=1 to cut with it knowingly" >&2; exit 1; }; fi
else
  case "$NODE_VERSION" in
    "rand-node $EXPECT_NODE_VERSION"*) ;;
    *) if [ "${DRY_RUN:-}" = 1 ]; then echo "cut-chain21: ⚠ DRY RUN with '$NODE_VERSION', not rand-node $EXPECT_NODE_VERSION — the real cut refuses it" >&2
       else [ "${NODE_VERSION_OK:-}" = 1 ] || { echo "cut-chain21: $NODE reports '$NODE_VERSION', not rand-node $EXPECT_NODE_VERSION — NODE_VERSION_OK=1 to cut with it knowingly" >&2; exit 1; }; fi ;;
  esac
fi
echo "cut-chain21: cutting with $NODE_VERSION"
if [ -z "${PERPS_SKIPPED:-}" ]; then
  # The engine: this build's `rand perp image-hc` over the image must be the decided engine.
  ENGINE_HC_GOT=$("$WALLET" perp image-hc --image "$PERP_IMAGE" 2>&1 | tail -1 || true)
  [ "$ENGINE_HC_GOT" = "$EXPECT_ENGINE_HC" ] || { echo "cut-chain21: \`$WALLET perp image-hc --image $PERP_IMAGE\` printed '${ENGINE_HC_GOT}', not EXPECT_ENGINE_HC $EXPECT_ENGINE_HC — the wrong engine image (or a rand without \`perp image-hc\`)" >&2; exit 1; }
  echo "cut-chain21: engine image $PERP_IMAGE: hc $ENGINE_HC_GOT (= EXPECT_ENGINE_HC, durian.market's pinned engine)"
fi
load_fee_recipient

TMP=$(mktemp -d); PROBE_PID=; trap 'rm -rf "$TMP"; [ -z "$PROBE_PID" ] || kill "$PROBE_PID" 2>/dev/null || true' EXIT
export TMP

# This rand-node hashes chain 20's fields as chain 20 did: it re-derives chain 20's own genesis hash
# from the committed file (so every field carried from chain 20 is hashed, and the three new
# sections are the only difference the cut makes).
H20=$("$NODE" init --datadir "$TMP/chain20-probe" --genesis "$CHAIN20_GENESIS" 2>"$TMP/chain20-probe.err" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p' || true)
[ "$H20" = "$CHAIN20_HASH" ] || { echo "cut-chain21: $NODE derives '${H20:-nothing}' from $CHAIN20_GENESIS, not chain 20's $CHAIN20_HASH ($(tail -1 "$TMP/chain20-probe.err" | cut -c1-90))" >&2; exit 1; }
echo "cut-chain21: this rand-node re-derives chain 20's genesis ${H20:0:12}… from $CHAIN20_GENESIS"

py_validators

# The treasury: TREASURY → $TMP/multisig.json, its id derived offline by this rand-node.
multisig_args=(); TREASURY_ID=
if [ -z "${MULTISIG_SKIPPED:-}" ]; then
  py_treasury
  targs=(); while IFS= read -r l; do targs+=("$l"); done < "$TMP/treasury-args"
  TREASURY_ID=$("$NODE" multisig id --chain-id "$CHAIN_ID" "${targs[@]}")
  [[ $TREASURY_ID =~ ^[0-9a-f]{64}$ ]] || { echo "cut-chain21: \`rand-node multisig id\` printed '$TREASURY_ID', not an id" >&2; exit 1; }
  echo "cut-chain21: treasury id (offline, rand-node multisig id): $TREASURY_ID"
  multisig_args=(--multisig "$TMP/multisig.json")
fi
export TREASURY_ID

# The perps section: the market list → perp-prover's genesis words → this build's root.
if [ -z "${PERPS_SKIPPED:-}" ]; then
  PERPS_STEP=markets py_perps
  "$PERP_PROVER" genesis-state --markets "$TMP/perps-markets.json" --out "$TMP/perp-state0.json"
  PERP_GENESIS_ROOT=$("$WALLET" perp genesis-root --state "$TMP/perp-state0.json" | tail -1)
  [[ $PERP_GENESIS_ROOT =~ ^[0-9a-f]{64}$ ]] || { echo "cut-chain21: \`rand perp genesis-root\` printed '$PERP_GENESIS_ROOT', not a root" >&2; exit 1; }
  export PERP_GENESIS_ROOT
  PERPS_STEP=section py_perps
  echo "cut-chain21: perps genesis root $PERP_GENESIS_ROOT ($PERP_PROVER genesis-state → $WALLET perp genesis-root); the section is spliced after zUSD"
fi

args=()
while IFS= read -r l; do args+=("$l"); done < "$TMP/validator-args"
while read -r label addr amount; do
  case "$label" in ''|'#'*) continue;; esac
  args+=(--alloc "$addr=$amount")
done < "$ALLOC_ADDRESSES"
# The fees section: written here, checked to be the decided value before it is passed.
fees_args=()
if [ -z "${FEES_SKIPPED:-}" ]; then
  printf '%s\n' "$FEES_JSON" > "$TMP/fees.json"
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d == {"burn_base": True, "burn_floor": True} else "cut-chain21: fees.json is %r, not the decided {burn_base: true, burn_floor: true}" % d)' "$TMP/fees.json"
  fees_args=(--fees "$TMP/fees.json")
  echo "cut-chain21: fees section: $(cat "$TMP/fees.json") → --fees"
fi
# hc_auth_multisig: the build writes its own msauth guest; the value is checked after the write.
msauth_args=()
[ -n "${AUTH_MULTISIG_SKIPPED:-}" ] || msauth_args=(--auth-multisig-guest)

# zUSD genesis notes: fresh openings, sealed to each carried holder (asset 1 = zUSD, 8 decimals).
: > "$TMP/token-notes.jsonl"
while read -r label addr amount; do
  case "$label" in ''|'#'*) continue;; esac
  "$NODE" alloc-note --to "$addr" --amount "$amount" --asset 1 --envelope-bytes "$ENVELOPE_BYTES" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)))' >> "$TMP/token-notes.jsonl"
  echo "cut-chain21: zUSD genesis note, $amount zUSD to $label"
done < "$ZUSD_CARRY"

echo "cut-chain21: writing the base file (its printed hash is NOT chain 21's)"
"$NODE" genesis --chain-id "$CHAIN_ID" "${args[@]}" \
  --max-program-words "$MAX_PROGRAM_WORDS" \
  --max-proof-bytes "$MAX_PROOF_BYTES" \
  --max-block-bytes "$MAX_BLOCK_BYTES" \
  --max-call-envelope-bytes "$MAX_CALL_ENVELOPE_BYTES" \
  --max-program-public-words "$MAX_PROGRAM_PUBLIC_WORDS" \
  --tokens "$TMP/tokens.json" \
  --bundle-guest v3 --auth-guest ${msauth_args[@]+"${msauth_args[@]}"} --hardening-v6 \
  --gas-price "$GAS_PRICE" --byte-price "$BYTE_PRICE" --bundle-gas-limit "$BUNDLE_GAS_LIMIT" --gas-dynamic "$GAS_DYNAMIC" \
  --max-gas-price "$MAX_GAS_PRICE" --max-byte-price "$MAX_BYTE_PRICE" --gas-byte-load "$GAS_BYTE_LOAD" \
  --envelope-bytes "$ENVELOPE_BYTES" \
  --testnet --binding-domain "$BINDING_DOMAIN" --proof-window-blocks "$PROOF_WINDOW_BLOCKS" \
  --program-state-cell-fee "$PROGRAM_STATE_CELL_FEE" \
  ${fees_args[@]+"${fees_args[@]}"} ${multisig_args[@]+"${multisig_args[@]}"} \
  --epoch-blocks "$EPOCH_BLOCKS" --faucet --fri-profile production --out "$TMP/genesis.json" | tee "$TMP/genesis.out"

HC_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_bundle',''))" "$TMP/genesis.json")
HC_AUTH_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_auth',''))" "$TMP/genesis.json")
for pair in "hc_bundle:$HC_REPORTED" "hc_auth:$HC_AUTH_REPORTED"; do
  k=${pair%%:*}; v=${pair#*:}
  [ -n "$v" ] || { echo "cut-chain21: the genesis command wrote no $k" >&2; exit 1; }
  said=$(grep -o "$k [0-9a-f]\{64\}" "$TMP/genesis.out" | head -1 | cut -d' ' -f2 || true)
  [ -z "$said" ] || [ "$said" = "$v" ] || { echo "cut-chain21: the genesis command printed $k $said but wrote $v" >&2; exit 1; }
done
HC_AUTH_MULTISIG_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_auth_multisig',''))" "$TMP/genesis.json")
if [ -z "${AUTH_MULTISIG_SKIPPED:-}" ]; then
  [ -n "$HC_AUTH_MULTISIG_REPORTED" ] || { echo "cut-chain21: the genesis command wrote no hc_auth_multisig — --auth-multisig-guest did not take" >&2; exit 1; }
  said=$(grep -o "hc_auth_multisig [0-9a-f]\{64\}" "$TMP/genesis.out" | head -1 | cut -d' ' -f2 || true)
  [ "$said" = "$HC_AUTH_MULTISIG_REPORTED" ] || { echo "cut-chain21: the genesis command printed hc_auth_multisig '${said}' but wrote $HC_AUTH_MULTISIG_REPORTED" >&2; exit 1; }
  [ "$HC_AUTH_MULTISIG_REPORTED" = "$EXPECT_HC_AUTH_MULTISIG" ] || { echo "cut-chain21: this rand-node's multisig auth guest is $HC_AUTH_MULTISIG_REPORTED, not EXPECT_HC_AUTH_MULTISIG $EXPECT_HC_AUTH_MULTISIG — another build's guest" >&2; exit 1; }
else
  [ -z "$HC_AUTH_MULTISIG_REPORTED" ] || { echo "cut-chain21: AUTH_MULTISIG_SKIPPED yet the genesis command wrote hc_auth_multisig" >&2; exit 1; }
  HC_AUTH_MULTISIG_REPORTED=SKIPPED
fi
echo "cut-chain21: this rand-node reports hc_bundle $HC_REPORTED, hc_auth $HC_AUTH_REPORTED, hc_auth_multisig $HC_AUTH_MULTISIG_REPORTED$([ -n "${AUTH_MULTISIG_SKIPPED:-}" ] || echo " (= EXPECT_HC_AUTH_MULTISIG)")"
if [ -n "$TREASURY_ID" ]; then
  # `genesis --multisig` prints `  multisig <id> <balance> RAND, 2 of 3 signers`: the same id, the same balance.
  said=$(sed -n 's/^  multisig \([0-9a-f]\{64\}\) .*/\1/p' "$TMP/genesis.out")
  [ "$said" = "$TREASURY_ID" ] || { echo "cut-chain21: rand-node genesis --multisig printed treasury id '${said}', the offline derivation $TREASURY_ID" >&2; exit 1; }
  said_bal=$(sed -n 's/^  multisig [0-9a-f]\{64\} \([0-9.]*\) RAND, 2 of 3 signers$/\1/p' "$TMP/genesis.out")
  want_bal=$(python3 -c 'import os,sys; exec(os.environ["UNITS_PY"]); print(fmt(int(open(sys.argv[1]).read())))' "$TMP/treasury-balance")
  [ -n "$said_bal" ] && [ "$said_bal" = "$want_bal" ] || { echo "cut-chain21: rand-node genesis printed the treasury as '${said_bal:-nothing}' RAND (2 of 3), TREASURY says $want_bal RAND" >&2; exit 1; }
  echo "cut-chain21: rand-node genesis --multisig prints the same treasury id and $said_bal RAND, 2 of 3"
fi
export HC_REPORTED
[ -n "${AUTH_MULTISIG_SKIPPED:-}" ] || export HC_AUTH_MULTISIG_REPORTED
# Built in $TMP; lands at $OUT only once it has passed every check, `init` and the field probe.
FINAL_OUT=$OUT; OUT=$TMP/genesis.json; export OUT

py_splice
# OPS-6 (docs/deploy.md, "Cut policy" / "Key separation"): while deploy/key-separation says
# `met: no`, the finished file must carry `"testnet": true` (py_splice asserts it too).
require_key_separation_or_testnet "$OUT"
echo "cut-chain21: key separation: $(sed -n 's/^met:[[:space:]]*//p' deploy/key-separation | head -1) — the finished file carries testnet: true (OPS-6)"

INIT=$("$NODE" init --datadir "$TMP/probe" --genesis "$OUT")
echo "$INIT"
HASH=$(printf '%s\n' "$INIT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ -n "$HASH" ] || { echo "cut-chain21: rand-node init printed no genesis hash" >&2; exit 1; }
[ "$HASH" != "$CHAIN20_HASH" ] || { echo "cut-chain21: init derived chain 20's hash" >&2; exit 1; }
grep -q "(chain id $CHAIN_ID)" <<<"$INIT" || { echo "cut-chain21: init does not say chain id $CHAIN_ID" >&2; exit 1; }
# What `init` prints of chain 20's carried gas fields: its gas line names the ceilings and the byte load.
grep -qF "ceiling $MAX_GAS_PRICE/$MAX_BYTE_PRICE, byte load paying" <<<"$INIT" \
  || { echo "cut-chain21: init's gas line does not say 'ceiling $MAX_GAS_PRICE/$MAX_BYTE_PRICE, byte load paying'" >&2; exit 1; }
HASH2=$("$NODE" init --datadir "$TMP/probe2" --genesis "$OUT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ "$HASH2" = "$HASH" ] || { echo "cut-chain21: init re-derived $HASH2, first $HASH" >&2; exit 1; }
# `init` prints no line for the three new sections — but it has run Genesis::validate over them
# (perps' collateral index and requirements included). The field probe proves each is in the
# hash, and `check-limits` reads them back from a running node (`rand_getLimits.fee_rules`,
# `.perps`, `.multisig`; `rand_getPerps`; `rand_getMultisig`).
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
    kill -0 "$PROBE_PID" 2>/dev/null || { echo "cut-chain21: the loopback probe node exited: $(tail -3 "$TMP/probe-node.log")$([ -n "${AUTH_MULTISIG_SKIPPED:-}" ] || echo " — a genesis with hc_auth_multisig needs the msauth verifier key: RAND_MSAUTH_VK=<msauth-vk-production.bin> (feat/private-multisig's crates/randprotocol-zkvm/keys/)")" >&2; exit 1; }
    sleep 1
  done
  echo "cut-chain21: loopback probe node up on 127.0.0.1:$RPCP — check-limits:"
  CHECK_RPC=http://127.0.0.1:$RPCP CHECK_GENESIS=$OUT EXPECT_GENESIS_HASH=$HASH TREASURY_ID=$TREASURY_ID py_check_limits
  kill "$PROBE_PID" 2>/dev/null || true; wait "$PROBE_PID" 2>/dev/null || true; PROBE_PID=
fi

[ ! -e "$FINAL_OUT" ] || { echo "cut-chain21: $FINAL_OUT appeared during the cut — refusing to overwrite it" >&2; exit 1; }
cp "$OUT" "$FINAL_OUT"; OUT=$FINAL_OUT
TS=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['timestamp_ms'])" "$OUT")
AGE=$(( ( $(date +%s) * 1000 - TS ) / 1000 ))

cat <<EOF

cut-chain21: wrote $OUT (sha256 $(shasum -a 256 "$OUT" | cut -c1-64))
cut-chain21: genesis hash $HASH
cut-chain21: chain id $CHAIN_ID, hc_bundle $HC_REPORTED (guest v3), hc_auth $HC_AUTH_REPORTED, hc_auth_multisig $HC_AUTH_MULTISIG_REPORTED, hardening_v6, consensus_domain 1, no aggregation, no vesting
cut-chain21: limits: max_proof_bytes $MAX_PROOF_BYTES, max_block_bytes $MAX_BLOCK_BYTES (chain 21's for private multisig; 6 MiB pending the measured msauth proof)$([ -n "${AUTH_MULTISIG_SKIPPED:-}" ] && echo " — hc_auth_multisig SKIPPED (this binary has no --auth-multisig-guest), NOT what chain 21 will be")
cut-chain21: testnet: true; binding_domain: $BINDING_DOMAIN; proof_window_blocks: $PROOF_WINDOW_BLOCKS
cut-chain21: gas: $GAS_PRICE/gas, $BYTE_PRICE/KiB, bundle limit $BUNDLE_GAS_LIMIT, dynamic $GAS_DYNAMIC, ceilings $MAX_GAS_PRICE/$MAX_BYTE_PRICE, byte load $GAS_BYTE_LOAD
cut-chain21: envelope_bytes $ENVELOPE_BYTES — every genesis note sealed in the 1 860-B form
cut-chain21: bridge.fees: mint $BRIDGE_MINT_BPS bps, burn $BRIDGE_BURN_BPS bps, recipient fingerprint $FEE_RECIPIENT_FINGERPRINT (from $FEE_RECIPIENT_FILE)
cut-chain21: staking: chain 20's (max_stake_entry_bps_per_epoch $STAKE_ENTRY_BPS, admission_by_vote); no slashing
cut-chain21: program_state: cell_fee $PROGRAM_STATE_CELL_FEE
cut-chain21: fees: $([ -n "${FEES_SKIPPED:-}" ] && echo "SKIPPED (this binary has no --fees) — NOT what chain 21 will be" || echo "$FEES_JSON (no subsidy_net_of_fees: aggregation is refused until re-measured)")
cut-chain21: perps: $([ -n "${PERPS_SKIPPED:-}" ] && echo "SKIPPED (no PERP_PROVER) — NOT what chain 21 will be" || echo "BTC-PERP on zUSD (asset 1), lot 100000, tick 100000000, 20x, maintenance 250 bps, fees 5/2 bps; max_tier 18, 24 inputs a block, 64 blocks a proof, min deposit 100000000 (1 zUSD)")
cut-chain21: perps engine_hc: $([ -n "${PERPS_SKIPPED:-}" ] && echo "SKIPPED" || echo "$EXPECT_ENGINE_HC ($PERP_IMAGE)")
cut-chain21: PERPS GENESIS ROOT ${PERP_GENESIS_ROOT:-SKIPPED}
cut-chain21: multisig: $([ -n "${MULTISIG_SKIPPED:-}" ] && echo "SKIPPED (this binary has no --multisig) — NOT what chain 21 will be" || echo "create_fee $MULTISIG_CREATE_FEE (1 RAND); the treasury 2 of 3, $(python3 -c 'import os,sys; exec(os.environ["UNITS_PY"]); print(fmt(int(open(sys.argv[1]).read())))' "$TMP/treasury-balance") RAND NEW ISSUANCE (not carried), salt $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["accounts"][0]["salt"])' "$TMP/multisig.json")")
cut-chain21: TREASURY ID ${TREASURY_ID:-SKIPPED}
cut-chain21: 26 validators × $STAKE_RAND RAND (quorum 18); faucet minters: $FAUCET_MINTERS
cut-chain21: bridge: $(python3 -c "import json,sys;b=json.load(open(sys.argv[1]))['bridge'];print('emitters', json.dumps(b['emitters'], sort_keys=True), '| min_inbound_sequence', json.dumps(b['min_inbound_sequence'], sort_keys=True), '| burn_sequence', b['burn_sequence'], '| guardian set', b['guardian_set_index'], '| rotation', json.dumps(b['rotation']))" "$OUT")
cut-chain21: NOT carried: shielded notes of wallets the operator does not hold, and any unwithdrawn validator rewards — the cut record's drops: line.
cut-chain21: next: the second operator rebuilds the hash from this file on another machine and writes \`second-hash: $HASH\` into $CUT_RECORD — deploy/cutover-fleet-chain21.sh (to be derived from chain 20's) push refuses without it.
cut-chain21: record in $CUT_RECORD: the genesis hash, the TREASURY ID and the PERPS GENESIS ROOT above (treasury-id: / perps-genesis-root: lines).
cut-chain21: after launch: NODE=… $0 check-limits <first node's RPC> $OUT   (before the first bundle and the first state proof)
cut-chain21: operations: msauth-vk-production.bin (sha256 68facb06…cd30) beside rand-node on every chain-21 node; NTP on every validator (perps block time is consensus input); a perp-view service and a prover host (~22 GB a proof); token collateral is outside the supply audit (M6).

⚠  Stamped $AGE s ago; the chain's clock starts there. Launch within MINUTES, or delete $OUT and re-cut.
EOF
[ "${DRY_RUN:-}" != 1 ] || echo "cut-chain21: DRY RUN — every step above ran on synthetic inputs; $OUT is NOT chain 21, launch nothing from it.$([ -n "${FEES_SKIPPED:-}" ] && echo ' ⚠ FEES SKIPPED.')$([ -n "${PERPS_SKIPPED:-}" ] && echo ' ⚠ PERPS SKIPPED.')$([ -n "${MULTISIG_SKIPPED:-}" ] && echo ' ⚠ MULTISIG SKIPPED.')$([ -n "${AUTH_MULTISIG_SKIPPED:-}" ] && echo ' ⚠ AUTH_MULTISIG SKIPPED.')"
