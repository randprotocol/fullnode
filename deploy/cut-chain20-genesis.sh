#!/usr/bin/env bash
# Cut the chain-20 genesis: chain 19's shape and value, cut from a snapshot of chain 19, on the
# v0.6.8 build (main + RPL-2), with the genesis fields audit v6 and RPL-2 left for "the next cut"
# (docs/deploy.md, every "The next cut" section) switched on.
#
#   deploy/cut-chain20-genesis.sh snapshot <dir>     # chain 19 still up, bridge daemons stopped
#   WALLET=<v0.6.7 rand> deploy/cut-chain20-genesis.sh balances <dir>
#                                                    # read-only toward the chain: the RAND carry list
#   CUT_RECORD=<record> CHAIN19_SNAPSHOT=<dir> NODE=<v0.6.8 rand-node> WALLET=<v0.6.8 rand> \
#     deploy/cut-chain20-genesis.sh                  # the cut
#   NODE=<v0.6.8 rand-node> deploy/cut-chain20-genesis.sh check-limits <rpc url> <genesis file>
#                                                    # after launch: what the first node serves
#   SELFTEST=1 deploy/cut-chain20-genesis.sh         # no network, no binaries: the assembly on fixtures
#   DRY_RUN=1 NODE=… WALLET=… deploy/cut-chain20-genesis.sh
#                                                    # no network: the REAL cut path (rand-node genesis,
#                                                    # alloc-note, init, a loopback probe node) on inputs
#                                                    # synthesised from the committed chain-19 genesis
#
# DERIVED from deploy/cut-chain19-genesis.sh (chain 19 — v0.6.7, live since 2026-10-01 03:43 UTC,
# genesis a3defc93…228a — is chain 20's predecessor): the same snapshot / balances / carry-over
# rule / splice, with chain 19 as the source. Read it first. What this script does that chain 19's
# did not:
#
#   * THE NEW GENESIS FIELDS, each the value docs/deploy.md recommends (the user's standing rule:
#     take the recommended value every time), each asserted on the finished file, each proved to
#     be part of the genesis hash by this rand-node (the cut re-derives the hash with the field
#     taken out and refuses if it does not move — a build that ignores a field would launch a chain
#     without it), and each read back from the first node after launch (`check-limits`):
#       - `testnet: true` (`--testnet`; STAKE-2) — required: a faucet beside a bridge on a chain id
#         past 19 (`GenesisError::FaucetWithBridgeNeedsTestnet`; 14–19 are grandfathered by id).
#       - `binding_domain: 1` (`--binding-domain 1`; BIND-1, issue #79) — the genesis hash in every
#         transaction binding and every signed action message. Every signer needs a v0.6.8 build:
#         the wallets, the operator commands, the bridge relayer and `rand-bridge-gov`.
#       - `proof_window_blocks: 1024` (`--proof-window-blocks 1024`; issue #118) — ~20 minutes at
#         1.17 s blocks for a bundle's anchor and time (256 blocks, ~5 minutes, on chain 19).
#       - `gas.dynamic`: `max_gas_price "10000"`, `max_byte_price "80000"` (100× the starting
#         prices) and `byte_load "paying"` (`--max-gas-price --max-byte-price --gas-byte-load
#         paying`; POOL-2). The rest of the gas section is chain 19's, asserted equal.
#       - `bridge.rotation: {delay_secs: 86400, needs_possession: true}` (BRG-14, issue #89),
#         spliced into the bridge JSON (no flag exists).
#       - `staking`: chain 19's section with the fixed `max_stake_entry_per_epoch` replaced by
#         `max_stake_entry_bps_per_epoch: 2500` (the two are refused together) and
#         `admission_by_vote: true`. NOT `staking.slashing`: docs/deploy.md recommends it only once
#         stake is held by more than one operator (D8), and all 26 keys are one operator's.
#       - `program_state: {cell_fee: 10000000}` (`--program-state-cell-fee 10000000`, RPL-2; the
#         value docs/program-state.md on feat/rpl2 gives: 0.01 RAND a created cell). The flag
#         exists only on a build carrying RPL-2: the real cut REFUSES a rand-node without it;
#         DRY_RUN skips the section, LOUDLY, when the binary in hand lacks it (main today).
#       - `bridge.fees: {mint_bps: 10, burn_bps: 10, recipient: <rand1…>}` (docs/bridge.md §25,
#         docs/deploy.md "The next cut: `bridge.fees`"; the user's decision 2026-10-01): the zUSD
#         bridge fee taken in zUSD on Rand, both ways, as a shielded note to `recipient`. Spliced
#         beside `rotation` (no flag). The recipient is the user's own wallet, read from
#         FEE_RECIPIENT_FILE (default ~/.rand-chain20/fee-recipient-address.txt) and refused unless
#         its fingerprint — computed by the WALLET binary (`rand contacts add`, under a throwaway
#         key in a temp dir) — is FEE_RECIPIENT_FINGERPRINT (default 89DS-4Q4X-HXSX-MBYW). A
#         validator's payout address is refused as the recipient (FEE_RECIPIENT_IS_PAYOUT_OK=1).
#       - No `vesting` section (chain 19 has none; one there is refused), no `aggregation`.
#   * THE BRIDGE IS CHAIN 19'S, NOT RE-DEPLOYED: EMITTER_2..5 default to chain 19's genesis
#     `bridge.emitters` (the 2026-09-30 endpoints; Solana unchanged), checked against
#     deploy/genesis-chain19.json itself, and refused otherwise unless EMITTERS_CHANGED=1. The
#     2026-09-19 endpoints chains 14–18 trusted are refused outright, EMITTERS_CHANGED or not.
#   * THE REPLAY FLOORS, per source chain 2..5: `auto` (default) = that endpoint's next outbound
#     sequence at the snapshot — last minted + 1 when every lock minted on chain 19 (the custody ==
#     locked check fails otherwise) — never below chain 19's own floor. An explicit floor overrides
#     it, from MIN_INBOUND_<c>=<n> or MIN_INBOUND_FILE (lines "<chain> <floor>"; one source per
#     chain — both for one chain is refused). A floor below 1 on chains 2, 3 and 4 is refused
#     outright: sequence 0 on each redeployed endpoint is the operator's consume-step lock, which
#     must never mint. `none` is refused on every chain (each endpoint was minted from).
#   * OPS-7, deploy/lib/cut-policy.sh (chain 19's script did not use it): the cut refuses a chain id
#     any deploy/genesis*.json already has (`refuse_reused_chain_id`) and a missing or unfilled cut
#     record (`require_cut_record "$CUT_RECORD"`, deploy/cut-record.template). The second
#     operator's rebuild (`require_second_rebuild`) is checked by deploy/cutover-fleet-chain20.sh
#     `push`, after the file exists and before it goes anywhere.
#   * `balances` rescans every wallet from leaf 0 (`rand sync --rescan`; BALANCES_RESCAN=0 to sync
#     incrementally): a key file's note store on the laptop can be stale — the relayer's is (the
#     relayer runs on droplet rand-relayer-1; the laptop holds only its key), and the scan must
#     rest on the chain alone. REQUIRED_WALLETS (default `relayer`) names key files that must be
#     present under WALLETS_DIRS before the scan starts.
#   * The SSH tunnel to obs1 is checked (`rand_getGenesisHash` answers, and is chain 19's) right
#     before `snapshot` and right before `balances`, not only described.
#   * NODE must report rand-node 0.6.8 for the cut (NODE_VERSION_OK=1 to override knowingly);
#     `balances` runs with chain 19's own build, v0.6.7 (WALLET).
#
# Traps carried from the chain-17, 18 and 19 cuts (AGENTS.md):
#   - `balances` scans CURATED directories of wallet key files, `$WALLETS_DIRS` =
#     ~/.rand-chain17/alloc-wallets (symlinks: shielded-1..5 and the relayer →
#     ~/.rand-chain14/wallets/relayer.key.json; that link went missing once and the scan then listed
#     its alloc as "uncovered"), ~/.rand-chain18/wallets and ~/.rand-chain19/wallets. Never a
#     checkout's `wallets/`. CHECK BEFORE THE SCAN that every wallet holding RAND on chain 19 has its
#     key file (or a symlink) in one of them; the scan also lists chain 19's genesis allocs that no
#     scanned wallet covers, and the cut refuses while that list is non-empty.
#   - `balances` refuses to overwrite <dir>/balances.json and $ALLOC_ADDRESSES: move a first scan
#     aside to re-scan.
#   - The public RPC (Cloudflare) answers Python's urllib with 403: point CHAIN19_RPC at an SSH
#     tunnel to obs1's RPC (the archive, `prune_floor` 0), e.g.
#     `ssh -N -L 8545:127.0.0.1:8545 root@168.144.46.203` → CHAIN19_RPC=http://127.0.0.1:8545.
#     The tunnel died twice in the hour of the chain-18 cut (once silently); this script now refuses
#     to start `snapshot` or `balances` on a dead one — re-open it and re-run.
#   - Take the snapshot with the SAME EMITTER_* the cut uses (the defaults): custody and sequences
#     are read at those addresses, and the cut refuses a snapshot read anywhere else.
#   - `rand-node genesis` writes no bridge section: the hash that matters is the one `rand-node
#     init` prints on the FINISHED file (this script's last lines), never the base file's.
#
# The carry-over rule (chain 19's, unchanged): zUSD per-backing `locked` = chain 19's at the
# snapshot with one fresh genesis note per $ZUSD_CARRY line (Σ notes == Σ locked == source custody);
# RAND = one genesis note per operator wallet the `balances` scan found holding RAND, at its
# chain-19 balance (Σ alloc == Σ scanned); a validator's unwithdrawn rewards are refused unless
# REWARDS_DROPPED_OK=1 (never carried); pending notes refused unless PENDING_OK=1; uncovered
# chain-19 genesis allocs refused unless UNCOVERED_ALLOCS_OK=1. SHIELDED NOTES OF WALLETS THE
# OPERATOR DOES NOT HOLD ARE NOT CARRIED — the cut record's `drops:` line must say so.
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash (fresh note randomness and a
# fresh timestamp). Cut once, distribute the file byte-identically, launch within minutes.
set -euo pipefail
cd "$(dirname "$0")/.."
. deploy/lib/key-guard.sh
. deploy/lib/cut-policy.sh

NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
CHAIN_ID=${CHAIN_ID:-20}
OUT=${OUT:-deploy/genesis-chain20.json}
CUT_RECORD=${CUT_RECORD:-$HOME/.rand-chain20/cut-record.txt}   # deploy/cut-record.template, filled in and published before the cut
EXPECT_NODE_VERSION=${EXPECT_NODE_VERSION:-0.6.8}
CHAIN19_GENESIS=${CHAIN19_GENESIS:-deploy/genesis-chain19.json}
CHAIN19_HASH=${CHAIN19_HASH:-a3defc937d561d4beb1df9a08c9cb87a3dc32dadbfc2d1814ab6f627b0a2228a}
CHAIN19_GENESIS_SHA256=${CHAIN19_GENESIS_SHA256:-92e46bc06068793c2301db8da1221822bf37b1262e3ae6c9aa3905f71c2a46e0}
CHAIN19_RPC=${CHAIN19_RPC:-http://127.0.0.1:8545}          # snapshot/balances: an SSH tunnel to obs1's RPC (the archive; Cloudflare 403s urllib)
CHAIN19_SNAPSHOT=${CHAIN19_SNAPSHOT:-}                       # the cut: the snapshot directory

# ── public inputs, all outside the repository ─────────────────────────────────────────────────
VALIDATORS_TSV=${VALIDATORS_TSV:-$HOME/.rand-chain14/public/validators.tsv}   # name addr pk peer payout (18)
REGISTRATIONS=${REGISTRATIONS:-$HOME/.rand-chain15/registrations}              # <name>.txt, one per bonded validator (8)
BONDED=${BONDED:-obs1 archive2 g1 g2 g3 g4 g5 g6}
GENESIS_NAMES=${GENESIS_NAMES:-a b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1}
FAUCET_MINTERS=${FAUCET_MINTERS:-$GENESIS_NAMES}   # chain 19's list; another one needs FAUCET_MINTERS_CHANGED=1
FAUCET_RECIPIENTS=${FAUCET_RECIPIENTS:-}           # unset: chain 19's genesis allowlist; a file ("<name> rand1…") changes it
STAKE_RAND=${STAKE_RAND:-1000}
ALLOC_ADDRESSES=${ALLOC_ADDRESSES:-$HOME/.rand-chain20/alloc-rand.txt}   # "<label> rand1… <RAND>" per line (`balances` writes it)
ZUSD_CARRY=${ZUSD_CARRY:-$HOME/.rand-chain20/zusd-carry.txt}             # "<label> rand1… <zUSD>" per line
WALLETS_DIRS=${WALLETS_DIRS:-$HOME/.rand-chain17/alloc-wallets $HOME/.rand-chain18/wallets $HOME/.rand-chain19/wallets}   # `balances`: dirs of *.key.json (a missing dir is skipped, printed); never a checkout's wallets/
REQUIRED_WALLETS=${REQUIRED_WALLETS:-relayer}      # `balances`: <name>.key.json that must be under WALLETS_DIRS before the scan (the relayer's link went missing once)
BALANCES_RESCAN=${BALANCES_RESCAN:-1}              # `balances`: `rand sync --rescan` (from leaf 0) — never trust a laptop note store
RELAYER_DONE_DIR=${RELAYER_DONE_DIR:-}             # optional: a copy of the relayer's done/ (done/<chain>/<seq>; the relayer runs on rand-relayer-1), a floor cross-check
EXPECT_HC_BUNDLE=${EXPECT_HC_BUNDLE:-60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce}   # bundle guest v3, chain 19's
EXPECT_HC_AUTH=${EXPECT_HC_AUTH:-1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1}     # the auth guest, chain 19's

# ── chain 19's limits (asserted equal to its genesis unless LIMITS_CHANGED=1) ───────────────────
MAX_PROGRAM_WORDS=${MAX_PROGRAM_WORDS:-65535}
MAX_PROOF_BYTES=${MAX_PROOF_BYTES:-4194304}
MAX_BLOCK_BYTES=${MAX_BLOCK_BYTES:-20971520}
MAX_CALL_ENVELOPE_BYTES=${MAX_CALL_ENVELOPE_BYTES:-65536}
MAX_PROGRAM_PUBLIC_WORDS=${MAX_PROGRAM_PUBLIC_WORDS:-32768}
EPOCH_BLOCKS=${EPOCH_BLOCKS:-1000}

# ── the source endpoints chain 19 trusts (its genesis `bridge.emitters`): chain 20 keeps them ───
C19_EMITTER_2=0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa   # Ethereum  0x7aF6b17047C1db6cB54347FdEa45cF9179075bfA (2026-09-30)
C19_EMITTER_3=0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa   # BNB Chain 0x7aF6b17047C1db6cB54347FdEa45cF9179075bfA (2026-09-30)
C19_EMITTER_4=0000000000000000000000006410797df959987a5baf65b5fab97edeb34d5163   # Tron      TK6JJv55CCkFjNHq7WwoU91GKaZEiC93me (2026-09-30)
C19_EMITTER_5=d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a   # Solana, never redeployed
# The 2026-09-19 endpoints chains 14–18 trusted: never again (their old locks would replay).
OLD_EMITTERS="000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892 0000000000000000000000000992df85dcce77ded2c0387f1fa9cf98ac859700"
EMITTER_2=${EMITTER_2:-$C19_EMITTER_2}
EMITTER_3=${EMITTER_3:-$C19_EMITTER_3}
EMITTER_4=${EMITTER_4:-$C19_EMITTER_4}
EMITTER_5=${EMITTER_5:-$C19_EMITTER_5}
for c in 2 3 4 5; do
  e=EMITTER_$c; o=C19_EMITTER_$c
  case " $OLD_EMITTERS " in *" ${!e} "*)
    echo "cut-chain20: EMITTER_$c=${!e} is a 2026-09-19 endpoint chains 14–18 trusted — never again (EMITTERS_CHANGED does not override this)" >&2; exit 1;; esac
  [ "${!e}" = "${!o}" ] || [ "${EMITTERS_CHANGED:-}" = 1 ] || {
    echo "cut-chain20: EMITTER_$c=${!e} is not chain 19's endpoint ${!o} — set EMITTERS_CHANGED=1 only for a knowingly new endpoint" >&2; exit 1; }
done
# Replay floors: MIN_INBOUND_<c> (env) or MIN_INBOUND_FILE ("<chain> <floor>" per line), else `auto`.
if [ -n "${MIN_INBOUND_FILE:-}" ]; then
  [ -f "$MIN_INBOUND_FILE" ] || { echo "cut-chain20: MIN_INBOUND_FILE=$MIN_INBOUND_FILE is not a file" >&2; exit 1; }
  while read -r fc fv rest; do
    case "$fc" in ''|'#'*) continue;; 2|3|4|5) ;; *) echo "cut-chain20: $MIN_INBOUND_FILE: '$fc $fv' — the chain must be 2, 3, 4 or 5" >&2; exit 1;; esac
    [ -z "$rest" ] && [[ "$fv" =~ ^[0-9]+$ ]] || { echo "cut-chain20: $MIN_INBOUND_FILE: '$fc $fv $rest' is not \"<chain> <floor>\"" >&2; exit 1; }
    v=MIN_INBOUND_$fc
    [ -z "${!v:-}" ] || { echo "cut-chain20: chain $fc's floor is given twice (MIN_INBOUND_$fc=${!v} and $MIN_INBOUND_FILE) — one source per chain" >&2; exit 1; }
    printf -v "$v" '%s' "$fv"
  done < "$MIN_INBOUND_FILE"
fi
for c in 2 3 4 5; do
  v=MIN_INBOUND_$c
  [ -n "${!v:-}" ] || printf -v "$v" auto
  case "${!v}" in
    auto) ;;
    none) echo "cut-chain20: MIN_INBOUND_$c=none — every chain-20 endpoint was minted from on chain 19; its old locks would replay" >&2; exit 1;;
    *) [[ "${!v}" =~ ^[0-9]+$ ]] || { echo "cut-chain20: MIN_INBOUND_$c=${!v}: a sequence or \`auto\`" >&2; exit 1; }
       if [ "$c" != 5 ] && [ "${!v}" -lt 1 ]; then
         echo "cut-chain20: MIN_INBOUND_$c=${!v} is below 1 — sequence 0 of the redeployed chain-$c endpoint is the operator's consume-step lock and must never mint" >&2; exit 1; fi
       [ "${!v}" -ge 1 ] || { echo "cut-chain20: MIN_INBOUND_$c=0 is no floor" >&2; exit 1; };;
  esac
done
# What the cut is expected to derive: chain 19's genesis floors and burn sequence, if nothing moved
# on chain 19 (a live bridge legitimately moves them — compared and warned about, never refused).
EXPECT_FLOORS=${EXPECT_FLOORS:-2:1 3:1 4:1 5:4}
EXPECT_BURN_SEQUENCE=${EXPECT_BURN_SEQUENCE:-8}
ETH_RPC=${ETH_RPC:-https://ethereum-rpc.publicnode.com}
BSC_RPC=${BSC_RPC:-https://bsc-rpc.publicnode.com}
TRON_API=${TRON_API:-https://api.trongrid.io}
SOL_RPC=${SOL_RPC:-https://api.mainnet-beta.solana.com}
SOL_PROGRAM=${SOL_PROGRAM:-FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu}

# ── gas: chain 19's section, plus audit v6 POOL-2's ceilings and paying byte load ──────────────
GAS_PRICE=${GAS_PRICE:-100}
BYTE_PRICE=${BYTE_PRICE:-800}
BUNDLE_GAS_LIMIT=${BUNDLE_GAS_LIMIT:-20479}                  # gas_max(14, 0, 0), every bundle proof's declared limit
GAS_DYNAMIC=${GAS_DYNAMIC:-$((MAX_BLOCK_BYTES / 2)),262144,1250}
MAX_GAS_PRICE=${MAX_GAS_PRICE:-10000}                        # 100× the start (docs/deploy.md, POOL-2)
MAX_BYTE_PRICE=${MAX_BYTE_PRICE:-80000}                      # 100× the start
GAS_BYTE_LOAD=${GAS_BYTE_LOAD:-paying}
ENVELOPE_BYTES=${ENVELOPE_BYTES:-1860}
# ── the audit-v6 / RPL-2 genesis fields (docs/deploy.md "The next cut" sections) ────────────────
BINDING_DOMAIN=${BINDING_DOMAIN:-1}
PROOF_WINDOW_BLOCKS=${PROOF_WINDOW_BLOCKS:-1024}
STAKE_ENTRY_BPS=${STAKE_ENTRY_BPS:-2500}
ROTATION_DELAY_SECS=${ROTATION_DELAY_SECS:-86400}
ROTATION_NEEDS_POSSESSION=${ROTATION_NEEDS_POSSESSION:-true}
PROGRAM_STATE_CELL_FEE=${PROGRAM_STATE_CELL_FEE:-10000000}   # 0.01 RAND a created cell: docs/program-state.md (feat/rpl2 6f5a4708)
PROGRAM_STATE_SKIPPED=${PROGRAM_STATE_SKIPPED:-}             # set by DRY_RUN only, when the binary lacks RPL-2
BRIDGE_MINT_BPS=${BRIDGE_MINT_BPS:-10}                       # docs/deploy.md "The next cut: bridge.fees": 0.1 % each way
BRIDGE_BURN_BPS=${BRIDGE_BURN_BPS:-10}
FEE_RECIPIENT_FILE=${FEE_RECIPIENT_FILE:-$HOME/.rand-chain20/fee-recipient-address.txt}   # the user's own wallet (one rand1… line)
FEE_RECIPIENT_FINGERPRINT=${FEE_RECIPIENT_FINGERPRINT:-89DS-4Q4X-HXSX-MBYW}
FEE_RECIPIENT=${FEE_RECIPIENT:-}                             # set by load_fee_recipient (the selftest sets a fixture)

export CHAIN_ID CHAIN19_GENESIS CHAIN19_HASH CHAIN19_GENESIS_SHA256 CHAIN19_RPC VALIDATORS_TSV REGISTRATIONS BONDED GENESIS_NAMES \
  FAUCET_MINTERS FAUCET_RECIPIENTS STAKE_RAND ALLOC_ADDRESSES ZUSD_CARRY WALLETS_DIRS RELAYER_DONE_DIR EXPECT_HC_BUNDLE \
  EXPECT_HC_AUTH MAX_PROGRAM_WORDS MAX_PROOF_BYTES MAX_BLOCK_BYTES MAX_CALL_ENVELOPE_BYTES \
  MAX_PROGRAM_PUBLIC_WORDS EPOCH_BLOCKS EMITTER_2 EMITTER_3 EMITTER_4 EMITTER_5 C19_EMITTER_2 C19_EMITTER_3 \
  C19_EMITTER_4 C19_EMITTER_5 OLD_EMITTERS EXPECT_FLOORS EXPECT_BURN_SEQUENCE MIN_INBOUND_2 MIN_INBOUND_3 MIN_INBOUND_4 MIN_INBOUND_5 \
  ETH_RPC BSC_RPC TRON_API SOL_RPC SOL_PROGRAM GAS_PRICE BYTE_PRICE BUNDLE_GAS_LIMIT GAS_DYNAMIC MAX_GAS_PRICE MAX_BYTE_PRICE \
  GAS_BYTE_LOAD ENVELOPE_BYTES BINDING_DOMAIN PROOF_WINDOW_BLOCKS STAKE_ENTRY_BPS ROTATION_DELAY_SECS ROTATION_NEEDS_POSSESSION \
  PROGRAM_STATE_CELL_FEE PROGRAM_STATE_SKIPPED BALANCES_RESCAN BRIDGE_MINT_BPS BRIDGE_BURN_BPS FEE_RECIPIENT \
  FEE_RECIPIENT_FINGERPRINT

# Decimal RAND/zUSD text → base units, the exact rule of `parse_amount` (no float anywhere).
# shellcheck disable=SC2089,SC2090  # python source in a string, exported whole, never word-split
UNITS_PY='
def units(s, decimals=9):
    s = s.strip()
    whole, _, frac = s.partition(".")
    if len(frac) > decimals or not (whole or frac) or not (whole or "0").isdigit() or not (frac or "0").isdigit():
        raise SystemExit(f"cut-chain20: {s!r} is not an amount with at most {decimals} decimals")
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
            raise SystemExit(f"cut-chain20: {path}: {line.rstrip()!r} is not \"<label> rand1… <amount>\"")
        rows.append((f[0], f[1], f[2]))
    return rows
'
# shellcheck disable=SC2090
export UNITS_PY

# The tunnel trap (chain 18, twice in one hour): before a step that reads chain 19, it answers, and
# it is chain 19 — not a dead port, not some other node.
need_chain19_rpc() {
  local got
  got=$(curl -s -m 10 -X POST "$CHAIN19_RPC" -H 'content-type: application/json' \
          -d '{"jsonrpc":"2.0","id":1,"method":"rand_getGenesisHash","params":[]}' 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("result",""))' 2>/dev/null || true)
  [ -n "$got" ] || { echo "cut-chain20: $CHAIN19_RPC is not answering — the SSH tunnel to obs1 is down? Re-open it (ssh -N -L 8545:127.0.0.1:8545 root@<obs1>) and re-run; nothing was read" >&2; exit 1; }
  [ "$got" = "$CHAIN19_HASH" ] || { echo "cut-chain20: $CHAIN19_RPC serves genesis $got, not chain 19 ($CHAIN19_HASH)" >&2; exit 1; }
  echo "cut-chain20: $CHAIN19_RPC answers as chain 19 ($(date -u +%T))"
}

# The fee recipient: one rand1… address from FEE_RECIPIENT_FILE whose fingerprint, as the WALLET
# binary computes it, is FEE_RECIPIENT_FINGERPRINT. `rand contacts add` prints an address's
# fingerprint; it runs under a throwaway --key in a temp dir (it writes only <key>.contacts.json).
load_fee_recipient() {
  local d got
  [ -f "$FEE_RECIPIENT_FILE" ] || { echo "cut-chain20: no fee recipient file $FEE_RECIPIENT_FILE (the user's wallet address, one rand1… line)" >&2; exit 1; }
  FEE_RECIPIENT=$(tr -d ' \t\r\n' < "$FEE_RECIPIENT_FILE")
  case "$FEE_RECIPIENT" in rand1*) ;; *) echo "cut-chain20: $FEE_RECIPIENT_FILE does not hold a rand1… address" >&2; exit 1;; esac
  [ "$(wc -l < "$FEE_RECIPIENT_FILE" | tr -d ' ')" -le 1 ] || { echo "cut-chain20: $FEE_RECIPIENT_FILE holds more than one line" >&2; exit 1; }
  [ -x "$WALLET" ] || { echo "cut-chain20: WALLET=$WALLET is not executable — it computes the fee recipient's fingerprint" >&2; exit 1; }
  d=$(mktemp -d)
  got=$("$WALLET" --key "$d/fingerprint-only.key.json" contacts add fee-recipient "$FEE_RECIPIENT" --yes 2>&1 | sed -n 's/^fingerprint \([0-9A-Z-]*\)$/\1/p' | head -1 || true)
  rm -rf "$d"
  [ -n "$got" ] || { echo "cut-chain20: $WALLET printed no fingerprint for the fee recipient in $FEE_RECIPIENT_FILE (not a shielded address?)" >&2; exit 1; }
  [ "$got" = "$FEE_RECIPIENT_FINGERPRINT" ] || { echo "cut-chain20: the fee recipient in $FEE_RECIPIENT_FILE has fingerprint $got, not FEE_RECIPIENT_FINGERPRINT $FEE_RECIPIENT_FINGERPRINT — refusing (the wrong wallet would collect every bridge fee for the chain's life)" >&2; exit 1; }
  export FEE_RECIPIENT
  echo "cut-chain20: bridge fee recipient: ${#FEE_RECIPIENT}-char address from $FEE_RECIPIENT_FILE, fingerprint $got (= FEE_RECIPIENT_FINGERPRINT)"
}

# ══ snapshot: read-only reads of chain 19 and of the source endpoints ═════════════════════════
py_snapshot() {
  python3 - <<'PY'
import base64, hashlib, json, os, struct, sys, time, urllib.request, urllib.error
E = os.environ
sha = hashlib.sha256(open(E["CHAIN19_GENESIS"], "rb").read()).hexdigest()
if sha != E["CHAIN19_GENESIS_SHA256"]:
    sys.exit(f"cut-chain20: {E['CHAIN19_GENESIS']} is not chain 19's committed genesis file "
             f"(sha256 {sha[:8]}…, expected {E['CHAIN19_GENESIS_SHA256'][:8]}…)")
g19 = json.load(open(E["CHAIN19_GENESIS"]))
if g19.get("vesting"):
    sys.exit("cut-chain20: chain 19's genesis has a vesting section — this script carries none; extend it first")
BACKINGS = g19["tokens"]["tokens"][0]["backings"]

def post(url, body, headers=None):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json", "user-agent": "rand-cut-chain20/1", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def rand(method, params=None):
    r = post(E["CHAIN19_RPC"], {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
    if "error" in r:
        sys.exit(f"cut-chain20: {method}: {r['error']}")
    return r["result"]

def eth_call(url, to, data):
    r = post(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": to, "data": data}, "latest"]})
    if "error" in r:
        sys.exit(f"cut-chain20: eth_call {to} on {url}: {r['error']}")
    return int(r["result"], 16)

def tron(contract41, selector, param=""):
    r = post(E["TRON_API"] + "/wallet/triggerconstantcontract",
             {"owner_address": E["TRON_ENDPOINT41"], "contract_address": contract41,
              "function_selector": selector, "parameter": param})
    if not r.get("constant_result"):
        sys.exit(f"cut-chain20: Tron {selector} on {contract41}: {r}")
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
        sys.exit(f"cut-chain20: Solana getProgramAccounts: {r['error']}")
    return [base64.b64decode(a["account"]["data"][0]) for a in r["result"]]

snap = {"taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
snap["genesis_hash"] = rand("rand_getGenesisHash")
if snap["genesis_hash"] != E["CHAIN19_HASH"]:
    sys.exit(f"cut-chain20: {E['CHAIN19_RPC']} serves {snap['genesis_hash']}, not chain 19")
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
    sys.exit(f"cut-chain20: {len(cfgs)} Solana config accounts, expected 1")
off = 1 + 32 * 3 + 1 + 32 + 4
seq["5"] = struct.unpack_from("<Q", cfgs[0], off)[0]
for acc in sol_accounts("4"):
    mint = acc[1:33].hex()
    cu, fe = struct.unpack_from("<QQ", acc, 1 + 32 + 2 + 8 * 4)
    custody[f"5:{mint}"] = {"custody": cu, "fees": fe, "mint": b58(acc[1:33])}
snap["source"] = {"emitters": {c: E[f"EMITTER_{c}"] for c in "2345"}, "next_sequence": seq, "custody": custody}
json.dump(snap, open(os.path.join(E["SNAP"], "chain19-state.json"), "w"), indent=1)
print(f"cut-chain20: snapshot of chain 19 at height {snap['status_height']} → {E['SNAP']}/chain19-state.json")
print(f"cut-chain20: source next sequences {seq}; burn_sequence {snap['bridge']['burn_sequence']}; "
      f"zUSD supply {snap['tokens']['tokens'][0]['total_supply']}")
for k, v in custody.items():
    if v["custody"]:
        print(f"cut-chain20: custody {k[:2]}…{k[-8:]} = {v['custody']}")
PY
}

# ══ balances: every wallet the operator holds, scanned on chain 19 → the RAND carry list ══════
# Read-only toward the chain; it does write each wallet's note store (<key>.notes.json) as any
# `rand sync` does. The key files are opened by `rand` only — this script never reads them.
py_balances() {
  python3 - <<'PY'
import glob, json, os, re, subprocess, sys, time, urllib.request
E = os.environ
exec(E["UNITS_PY"])
def rpc(method):
    req = urllib.request.Request(E["CHAIN19_RPC"], json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode(),
                                 {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["result"]
if rpc("rand_getGenesisHash") != E["CHAIN19_HASH"]:
    sys.exit(f"cut-chain20: {E['CHAIN19_RPC']} is not chain 19")
status0 = rpc("rand_status")
if int(status0.get("prune_floor", 0) or 0) > 0:
    sys.exit(f"cut-chain20: {E['CHAIN19_RPC']} is pruned (prune_floor {status0['prune_floor']}) — "
             f"`balances` needs a full scan; point CHAIN19_RPC at an archive (obs1, rand-archive-2)")
def rand(key, *args):
    p = subprocess.run([E["WALLET"], "--rpc", E["CHAIN19_RPC"], "--key", key, *args], capture_output=True, text=True)
    if p.stderr.strip():
        print(p.stderr.strip(), file=sys.stderr)   # RS-1's pruned-node warning, the rescan notice: never swallowed
    if p.returncode != 0:
        sys.exit(f"cut-chain20: rand {' '.join(args)} for {key}: {p.stderr.strip()}")
    return p.stdout
files = []
for d in E["WALLETS_DIRS"].split():
    if os.path.isdir(d):
        files += sorted(glob.glob(os.path.join(d, "*.key.json")))
    else:
        print(f"cut-chain20: {d} does not exist — skipped")
if not files:
    sys.exit("cut-chain20: no *.key.json under WALLETS_DIRS")
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
        sys.exit(f"cut-chain20: could not read a balance for {f}: {out!r}")
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
        sys.exit(f"cut-chain20: {prev['file']} and {f} are one address with different balances — reconcile the note stores")
    if not prev:
        by_addr[addr] = row
    print(f"cut-chain20:   {label:<24} {fmt(ru):>18} RAND  {zu:>12} zUSD units{'  (duplicate key file)' if prev else ''}")
height1 = rpc("rand_status")["height"]
if pending_by_wallet and not E.get("PENDING_OK"):
    detail = "; ".join(f"{label}: " + ", ".join(f"asset {a} amount {amt} ({since})" for a, amt, since in rows) for label, rows in pending_by_wallet)
    sys.exit(f"cut-chain20: pending note(s) would be dropped from the carry silently: {detail} — wait for them to "
             f"clear (or fail) and re-run, or set PENDING_OK=1 to drop them")
elif pending_by_wallet:
    detail = "; ".join(f"{label}: " + ", ".join(f"asset {a} amount {amt}" for a, amt, _ in rows) for label, rows in pending_by_wallet)
    print(f"cut-chain20: ⚠ dropping pending note(s) (PENDING_OK=1): {detail}")
rows = sorted(by_addr.values(), key=lambda r: r["label"])
carry = [r for r in rows if r["rand_units"] > 0]
labels = [r["label"] for r in carry]
if len(set(labels)) != len(labels):
    sys.exit("cut-chain20: two wallets with one label — rename a key file")
total = sum(r["rand_units"] for r in carry)

# ── chain 19's own genesis alloc notes this scan does not cover ────────────────────────────────
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            sys.exit(f"cut-chain20: {s!r} is not base58")
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
g19 = json.load(open(E["CHAIN19_GENESIS"]))
alloc_pks = {n["opening"]["pk"]: n["amount"] for n in g19["alloc"] if n.get("opening", {}).get("asset", 0) == 0}
uncovered = [{"pk": pk, "amount": amt} for pk, amt in alloc_pks.items() if pk not in scanned_pks]
if uncovered:
    print("cut-chain20: uncovered genesis allocs (no scanned wallet's pk matches — the cut refuses "
          "unless UNCOVERED_ALLOCS_OK=1): " + ", ".join(f"{u['pk'][:12]}… ({u['amount']})" for u in uncovered))

json.dump({"chain19_hash": E["CHAIN19_HASH"], "taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "height_from": height0, "height_to": height1, "wallets": rows, "carried_rand_units": total,
           "uncovered_genesis_allocs": uncovered, "rescanned": sync == ["sync", "--rescan"]},
          open(os.path.join(E["SNAP"], "balances.json"), "w"), indent=1)
os.makedirs(os.path.dirname(E["ALLOC_ADDRESSES"]) or ".", exist_ok=True)
with open(E["ALLOC_ADDRESSES"], "w") as out:
    out.write(f"# chain-20 RAND carry: chain-19 balances at heights {height0}..{height1}, `balances` step\n")
    for r in carry:
        out.write(f"{r['label']} {r['address']} {fmt(r['rand_units'])}\n")
print(f"cut-chain20: {len(carry)} wallet(s) with RAND, Σ {fmt(total)} RAND → {E['ALLOC_ADDRESSES']} (+ {E['SNAP']}/balances.json)")
z = [r for r in rows if r["zusd_units"]]
if z:
    op_total = sum(r["zusd_units"] for r in z)
    print(f"cut-chain20: zUSD held by operator wallets: " + ", ".join(f"{r['label']} {r['zusd_units']}" for r in z) + f" (Σ {op_total})")
    if os.path.isfile(E["ZUSD_CARRY"]):
        carry_total = sum(units(a, 8) for _, _, a in alloc_lines(E["ZUSD_CARRY"]))
        if carry_total != op_total:
            print(f"cut-chain20: ⚠ Σ operator-wallet zUSD ({op_total}) != Σ ZUSD_CARRY ({carry_total}) — "
                  f"a non-operator holder (e.g. Anish's wallet) legitimately differs; verify by hand")
PY
}

# ══ the cut, step 1: the validators, from the chain-19 register ═══════════════════════════════
py_validators() {
  python3 - <<'PY'
import json, os, sys
E = os.environ
need = lambda c, m: c or sys.exit(f"cut-chain20: {m}")
snap = json.load(open(E["SNAPSHOT_FILE"]))
g19 = json.load(open(E["CHAIN19_GENESIS"]))
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
    need(addr in register, f"{name} ({addr}) is not in chain 19's register")
    rows.append({"name": name, "address": addr, "public_key": raw[8:8 + n].hex(), "payout": register[addr]["payout"]})
stake = int(E["STAKE_RAND"]) * 10**9
need(len(rows) == len(register) == 26, f"{len(rows)} validators assembled, chain 19's register holds {len(register)}")
for r in rows:
    live = register.get(r["address"])
    need(live is not None, f"{r['name']} ({r['address']}) is not in chain 19's register")
    need(live["payout"] == r["payout"], f"{r['name']}: payout differs from chain 19's register")
    need(int(live["stake"]) == stake and not live["pending"], f"{r['name']}: chain 19 stake {live['stake']} / pending {live['pending']}, not a plain {stake}")
    need(live["active"], f"{r['name']} is not active on chain 19")
    need(int(live.get("rewards", "0")) == 0 or E.get("REWARDS_DROPPED_OK"),
         f"{r['name']}: chain 19 shows {live['rewards']} unwithdrawn reward units — withdraw them before the cut "
         f"(rewards are not carried), or set REWARDS_DROPPED_OK=1 to drop them")
need(len({r["public_key"] for r in rows}) == 26 and len({r["address"] for r in rows}) == 26, "a validator twice")
total_rewards = sum(int(register[r["address"]].get("rewards", "0")) for r in rows)
if total_rewards:
    print(f"cut-chain20: ⚠ dropping {total_rewards} unwithdrawn reward unit(s) across the register (REWARDS_DROPPED_OK=1)")
need([(v["public_key"], v["payout"]) for v in g19["validators"]] == [(r["public_key"], r["payout"]) for r in rows],
     "the 26 are not chain 19's genesis validators (keys, payouts or order)")
json.dump(rows, open(os.path.join(E["TMP"], "validators.json"), "w"))
with open(os.path.join(E["TMP"], "validator-args"), "w") as f:
    for r in rows:
        f.write(f"--validator\n{r['public_key']},{E['STAKE_RAND']},{r['payout']}\n")
t = g19["tokens"]
json.dump({"registration_fee": t["registration_fee"], "mint_cap_per_day": t["mint_cap_per_day"], "tokens": []},
          open(os.path.join(E["TMP"], "tokens.json"), "w"))
print(f"cut-chain20: 26 validators × {E['STAKE_RAND']} RAND, equal to chain 19's register at height {snap['status_height']}")
PY
}

# ══ the cut, step 2: splice bridge, tokens, staking; assert every carried sum and every new field ═
py_splice() {
  python3 - <<'PY'
import json, os, re, sys, time
E = os.environ
exec(E["UNITS_PY"])
out = E["OUT"]
g = json.load(open(out))
g19 = json.load(open(E["CHAIN19_GENESIS"]))
snap = json.load(open(E["SNAPSHOT_FILE"]))
sb = snap["bridge"]
warnings = []

def need(cond, msg):
    if not cond:
        sys.exit(f"cut-chain20: {msg}")

need(snap["genesis_hash"] == E["CHAIN19_HASH"], "the snapshot is not of chain 19")
need(not g19.get("vesting"), "chain 19's genesis has a vesting section — this script carries none")
b19 = g19["bridge"]
need({c: E[f"C19_EMITTER_{c}"] for c in "2345"} == b19["emitters"], "C19_EMITTER_* are not deploy/genesis-chain19.json's emitters")

# ── bridge: chain 19's live values, the floors re-derived, the rotation rules added ─────────────
rotated = E.get("BRIDGE_ROTATED")
for k in ("guardians", "guardian_set_index", "pq_guardians", "pause_key"):
    need(sb[k] == b19[k] or rotated, f"chain 19's live {k} differs from its genesis — a rotation; set BRIDGE_ROTATED=1 to carry the live value")
need(sb["emitter"] == b19["emitter"], "the Rand-side emitter differs from chain 19's")
need(not sb["mint_paused"], "chain 19's mints are paused — decide what chain 20 starts with")
need(sb["emitters"] == b19["emitters"], "chain 19's live emitter table differs from its genesis")
need(int(sb["rules_v2"]["global_mint_cap_per_window"]) == int(b19["rules_v2"]["global_mint_cap_per_window"])
     and int(sb["rules_v2"]["cap_window_secs"]) == int(b19["rules_v2"]["cap_window_secs"]), "rules_v2 differs from chain 19's genesis")
need(int(sb["registration_fee"]) == int(g19["tokens"]["registration_fee"]), "registration_fee differs from chain 19's")
need(sb["burn_sequence"] >= b19["burn_sequence"], "chain 19's burn sequence went backwards")
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
need(emitters == b19["emitters"] or E.get("EMITTERS_CHANGED") == "1",
     "the emitter table is not chain 19's (deploy/genesis-chain19.json) — EMITTERS_CHANGED=1 only for a knowingly new endpoint")
changed = [c for c in "2345" if emitters[c] != b19["emitters"][c]]

floor19 = {str(k): int(v) for k, v in (b19.get("min_inbound_sequence") or {}).items()}
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
             f"would NEVER mint on chain 20 (refused on an endpoint chain 19 already trusts)")
        warnings.append(f"chain {c}: floor {v} is ahead of the endpoint's next sequence {next_seq} (FLOOR_AHEAD_OK=1)")
    if c not in changed and c in floor19:
        need(int(v) >= floor19[c], f"MIN_INBOUND_{c}={v} is below chain 19's own floor {floor19[c]} — it would re-open minted locks")
    if int(v) < next_seq:
        need(allow_unminted,
             f"chain {c}'s endpoint has emitted up to {next_seq - 1} but the floor is {v}: locks {v}..{next_seq - 1} will mint "
             f"on chain 20 — drain them on chain 19 first, or set ALLOW_UNMINTED_LOCKS=1 if they are user locks chain 19 never minted")
        unminted[c] = (int(v), next_seq - 1)
        warnings.append(f"chain {c}: locks {v}..{next_seq - 1} were emitted and are NOT below the floor — they will mint on chain 20 (ALLOW_UNMINTED_LOCKS=1)")
    if E.get("RELAYER_DONE_DIR") and c not in changed:
        d = os.path.join(E["RELAYER_DONE_DIR"], c)
        done = [int(m.group()) for m in (re.match(r"\d+", x) for x in (os.listdir(d) if os.path.isdir(d) else [])) if m]
        last = max(done) if done else floor19.get(c, 1) - 1
        need(int(v) == last + 1, f"chain {c}: the relayer's done/ says last minted {last}, the floor is {v} (last minted + 1 = {last + 1})")
    floor[c] = int(v)
need(set(floor) == set("2345"), "a replay floor for every endpoint chain 19 trusts")
want_floor = {c: int(v) for c, v in (x.split(":") for x in E["EXPECT_FLOORS"].split())}
if floor != want_floor:
    warnings.append(f"min_inbound_sequence is {floor}, EXPECTED {want_floor} (EXPECT_FLOORS) — confirm every difference against the endpoints before launch")
if int(sb["burn_sequence"]) != int(E["EXPECT_BURN_SEQUENCE"]):
    warnings.append(f"burn_sequence is {sb['burn_sequence']}, EXPECTED {E['EXPECT_BURN_SEQUENCE']} — a burn landed on chain 19 since; confirm its release before launch")

need(E["ROTATION_NEEDS_POSSESSION"] in ("true", "false"), "ROTATION_NEEDS_POSSESSION is true or false")
rotation = {"delay_secs": int(E["ROTATION_DELAY_SECS"]), "needs_possession": E["ROTATION_NEEDS_POSSESSION"] == "true"}
g["bridge"] = {
    "emitter": b19["emitter"],
    "guardians": guardians,
    "emitters": emitters,
    "pq_guardians": pq_guardians,
    "pause_key": pause_key,
    "rules_v2": b19["rules_v2"],
    "guardian_set_index": int(sb["guardian_set_index"]),
    "burn_sequence": int(sb["burn_sequence"]),
    "min_inbound_sequence": floor,
    "rotation": rotation,
    "fees": {"mint_bps": int(E["BRIDGE_MINT_BPS"]), "burn_bps": int(E["BRIDGE_BURN_BPS"]), "recipient": E["FEE_RECIPIENT"]},
}

# ── tokens: zUSD at genesis, locked = chain 19's per backing == custody == supply ───────────────
tok = snap["tokens"]["tokens"]
z = [t for t in tok if t["symbol"] == "zUSD" and t["index"] == 1]
need(len(z) == 1, "chain 19 does not list zUSD at index 1")
others = [t for t in tok if t is not z[0]]
need(not others or E.get("ALLOW_DROPPED_TOKENS"),
     f"chain 19 lists {len(others)} more token(s) ({', '.join(t['symbol'] for t in others)}) the cut cannot carry — set ALLOW_DROPPED_TOKENS=1 to drop them")
if others:
    warnings.append(f"dropped chain-19 tokens: {', '.join(str(t['index']) + ':' + t['symbol'] for t in others)}")
z19 = g19["tokens"]["tokens"][0]
live_backings = z[0]["authority"]["backings"]
need([(b["chain"], b["token"], b["decimals"]) for b in live_backings] == [(b["chain"], b["token"], b["decimals"]) for b in z19["backings"]],
     "chain 19's live backings differ from its genesis list")
backings = []
for lb in live_backings:
    b = {"chain": lb["chain"], "token": lb["token"], "decimals": lb["decimals"]}
    if int(lb["locked"]) > 0:
        b["locked"] = int(lb["locked"])
    backings.append(b)
locked_total = sum(b.get("locked", 0) for b in backings)
need(int(z[0]["total_supply"]) == locked_total, f"chain 19's zUSD supply {z[0]['total_supply']} != Σ locked {locked_total}")
for b in backings:
    key = f"{b['chain']}:{b['token']}"
    have = snap["source"]["custody"].get(key)
    need(have is not None, f"the snapshot has no custody reading for {key}")
    d = b["decimals"]
    if d > 8:
        need(have["custody"] % 10**(d - 8) == 0, f"custody {key} has dust below zUSD's eighth decimal")
    scaled = have["custody"] // 10**(d - 8) if d >= 8 else have["custody"] * 10**(8 - d)
    if scaled != b.get("locked", 0):
        # An unminted user lock (ALLOW_UNMINTED_LOCKS=1, above) is custody chain 19 never locked:
        # custody may exceed locked on that chain only, never fall below it.
        need(str(b["chain"]) in unminted and scaled > b.get("locked", 0),
             f"source custody {key} = {have['custody']} (= {scaled} zUSD units), chain 19 locks {b.get('locked', 0)}")
        warnings.append(f"custody {key} = {scaled} zUSD units, above chain 19's locked {b.get('locked', 0)} — the unminted lock(s) on chain {b['chain']}")

t = g["tokens"]
need(t["registration_fee"] == g19["tokens"]["registration_fee"] and t["mint_cap_per_day"] == g19["tokens"]["mint_cap_per_day"], "tokens header")
t["tokens"] = [{"name": z19["name"], "symbol": z19["symbol"], "salt": z19["salt"], "backings": backings}]
for k in ("max_tokens", "burn_registration_fee", "bound_note_value"):
    t[k] = g19["tokens"][k]
need({k: v for k, v in t.items() if k != "tokens"} == {k: v for k, v in g19["tokens"].items() if k != "tokens"}, "the token switches are not chain 19's")

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
    need(bal["chain19_hash"] == E["CHAIN19_HASH"], "balances.json is not of chain 19")
    scanned = sorted((w["address"], w["rand_units"]) for w in bal["wallets"] if w["rand_units"] > 0)
    listed = sorted((addr, units(a)) for _, addr, a in alloc)
    need(sum(u for _, u in scanned) == alloc_total, f"Σ alloc RAND {alloc_total} != Σ scanned balances {sum(u for _, u in scanned)}")
    need(scanned == listed, "ALLOC_ADDRESSES is not the scanned wallets one-for-one (address, amount) — regenerate it with `balances`")
    uncovered = bal.get("uncovered_genesis_allocs") or []
    need(not uncovered or E.get("UNCOVERED_ALLOCS_OK"),
         "chain 19 genesis alloc(s) match no scanned wallet, so their value would be dropped silently: "
         + ", ".join(f"pk {u['pk'][:12]}… ({u['amount']})" for u in uncovered)
         + " — find the key file(s) and add its directory to WALLETS_DIRS, or set UNCOVERED_ALLOCS_OK=1 to drop them")
    if uncovered:
        warnings.append("dropped uncovered chain-19 genesis alloc(s): " + ", ".join(f"pk {u['pk'][:12]}… ({u['amount']})" for u in uncovered))
    if not bal.get("rescanned"):
        warnings.append("balances.json was NOT taken with `rand sync --rescan` (BALANCES_RESCAN=0) — a stale note store could have read low")
    rand_carry = f"== Σ scanned ({len(scanned)} wallets, heights {bal['height_from']}..{bal['height_to']})"
else:
    need(E.get("NO_BALANCES"), f"no {bal_file or 'balances.json'} — run `balances` (the carry-over rule), or set NO_BALANCES=1 to cut from a hand-made list")
    rand_carry = "NOT checked against a scan (NO_BALANCES=1)"
    warnings.append("RAND allocs were not checked against scanned balances")
g["alloc"] = g["alloc"] + token_notes

# ── staking: chain 19's, the entry budget in basis points, admission by vote; no slashing ───────
s19 = g19["staking"]
need("slashing" not in s19, "chain 19's staking has `slashing` — this script carries none")
if E.get("FAUCET_RECIPIENTS"):
    recipients = [l.split()[-1] for l in open(E["FAUCET_RECIPIENTS"]) if l.strip() and not l.startswith("#")]
    need(recipients and all(r.startswith("rand1") for r in recipients) and len(set(recipients)) == len(recipients),
         "FAUCET_RECIPIENTS: rand1… addresses, each once")
    need(recipients == s19["faucet_recipients"] or E.get("FAUCET_RECIPIENTS_CHANGED"),
         f"the faucet allowlist differs from chain 19's ({len(s19['faucet_recipients'])} → {len(recipients)}) "
         f"— set FAUCET_RECIPIENTS_CHANGED=1 if that is the decision")
    if recipients != s19["faucet_recipients"]:
        warnings.append(f"faucet allowlist changed from chain 19's ({len(s19['faucet_recipients'])} → {len(recipients)})")
else:
    recipients = s19["faucet_recipients"]
vals = {v["name"]: v for v in json.load(open(os.path.join(E["TMP"], "validators.json")))}
minters = []
for name in E["FAUCET_MINTERS"].split():
    need(name in vals, f"FAUCET_MINTERS names {name}, not a chain-20 validator")
    minters.append(vals[name]["address"])
need(minters and len(set(minters)) == len(minters), "faucet_minters empty or a key twice")
need(minters == s19["faucet_minters"] or E.get("FAUCET_MINTERS_CHANGED"),
     "faucet_minters differ from chain 19's (set FAUCET_MINTERS_CHANGED=1 if that is the decision)")
staking = {k: v for k, v in s19.items() if k != "max_stake_entry_per_epoch"}
staking.update(faucet_recipients=recipients, faucet_minters=minters,
               max_stake_entry_bps_per_epoch=int(E["STAKE_ENTRY_BPS"]), admission_by_vote=True)
g["staking"] = staking
g["consensus_domain"] = 1

order = ["chain_id", "timestamp_ms", "validators", "alloc", "faucet", "confidential", "fri_profile",
         "hc_bundle", "bridge", "tokens", "aggregation", "consensus_domain", "staking", "epoch_blocks",
         "max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes",
         "max_program_public_words", "envelope_bytes", "vesting", "hardening_v6", "hc_auth", "gas",
         "testnet", "binding_domain", "proof_window_blocks", "program_state"]
unknown = [k for k in g if k not in order]
need(not unknown, f"the genesis command wrote fields this script does not know: {unknown}")
g = {k: g[k] for k in order if k in g}

# ── assertions over the bytes that ship ───────────────────────────────────────────────────────
need(g["chain_id"] == int(E["CHAIN_ID"]) == 20, f"chain_id is {g['chain_id']}")
need(g.get("hardening_v6") is True, "hardening_v6 is not true — --hardening-v6 did not take")
need(g["hc_bundle"] == E["HC_REPORTED"], "hc_bundle is not what this rand-node reports")
need(g["hc_bundle"] == g19["hc_bundle"] == E["EXPECT_HC_BUNDLE"], f"hc_bundle {g['hc_bundle']} is not chain 19's bundle guest v3")
need(g.get("hc_auth") == g19.get("hc_auth") == E["EXPECT_HC_AUTH"], f"hc_auth {g.get('hc_auth')} is not chain 19's auth guest")
need(g["faucet"] is True and g["confidential"] is True and g["fri_profile"] == "production", "faucet/confidential/fri_profile wrong")
need("aggregation" not in g, "an aggregation section is present — none belongs in chain 20")
need("vesting" not in g, "a vesting section is present — none belongs in chain 20")
need(g.get("envelope_bytes") == int(E["ENVELOPE_BYTES"]) == 1860 == g19.get("envelope_bytes"), f"envelope_bytes is {g.get('envelope_bytes')!r}, not 1860")
for i, n in enumerate(g["alloc"]):
    size = sum(len(v) // 2 for v in n["envelope"].values())
    need(size == 1860, f"alloc note {i}'s envelope is {size} B, not 1860 — sealed in the legacy format (alloc-note without --envelope-bytes?)")
# the new top-level fields
need(g.get("testnet") is True, f"testnet is {g.get('testnet')!r}, not true — --testnet did not take (a faucet beside a bridge on chain 20 needs it)")
need(g.get("binding_domain") == int(E["BINDING_DOMAIN"]) == 1, f"binding_domain is {g.get('binding_domain')!r}, not 1 — --binding-domain 1 did not take")
need(g.get("proof_window_blocks") == int(E["PROOF_WINDOW_BLOCKS"]) == 1024, f"proof_window_blocks is {g.get('proof_window_blocks')!r}, not 1024")
if E.get("PROGRAM_STATE_SKIPPED"):
    need("program_state" not in g, "PROGRAM_STATE_SKIPPED yet a program_state section is present")
    warnings.append("PROGRAM_STATE SKIPPED — this rand-node has no --program-state-cell-fee (not RPL-2); "
                    "the real cut refuses such a binary; this file is NOT what chain 20 will be")
else:
    need(g.get("program_state") == {"cell_fee": int(E["PROGRAM_STATE_CELL_FEE"])},
         f"program_state is {g.get('program_state')!r}, not {{'cell_fee': {E['PROGRAM_STATE_CELL_FEE']}}} — --program-state-cell-fee did not take")
    need(int(E["PROGRAM_STATE_CELL_FEE"]) == 10000000, "the program_state cell fee is not docs/program-state.md's 10000000 (0.01 RAND)")
# the gas section: chain 19's, plus the two ceilings and the paying byte load
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
want_gas_section = {**g19["gas"], "dynamic": {**g19["gas"]["dynamic"], "max_gas_price": E["MAX_GAS_PRICE"],
                                              "max_byte_price": E["MAX_BYTE_PRICE"], "byte_load": "paying"}}
need(gas == want_gas_section or E.get("GAS_CHANGED"), f"the gas section {gas} is not chain 19's plus the POOL-2 fields {want_gas_section} (GAS_CHANGED=1 if intended)")
# the staking section
st = g["staking"]
need(st.get("admission_by_vote") is True, "staking.admission_by_vote is not true")
need(st.get("max_stake_entry_bps_per_epoch") == int(E["STAKE_ENTRY_BPS"]) == 2500, f"staking.max_stake_entry_bps_per_epoch is {st.get('max_stake_entry_bps_per_epoch')!r}, not 2500")
need("max_stake_entry_per_epoch" not in st, "staking still carries the fixed max_stake_entry_per_epoch (refused beside the bps budget)")
need("slashing" not in st, "staking.slashing is present — recommended only once stake is held by more than one operator (docs/deploy.md, D8)")
# the bridge rotation rules
need(g["bridge"].get("rotation") == {"delay_secs": 86400, "needs_possession": True}, f"bridge.rotation is {g['bridge'].get('rotation')!r}, not {{delay_secs: 86400, needs_possession: true}}")
# the zUSD bridge fees (docs/bridge.md §25)
fees = g["bridge"].get("fees") or {}
need(E.get("FEE_RECIPIENT", "").startswith("rand1"), "FEE_RECIPIENT is unset — load_fee_recipient did not run")
need(fees == {"mint_bps": 10, "burn_bps": 10, "recipient": E["FEE_RECIPIENT"]},
     f"bridge.fees is {({k: (v if k != 'recipient' else v[:12] + '…') for k, v in fees.items()})!r}, not {{mint_bps: 10, burn_bps: 10, recipient: <FEE_RECIPIENT>}}")
payouts = {v["payout"] for v in g["validators"]}
need(fees["recipient"] not in payouts or E.get("FEE_RECIPIENT_IS_PAYOUT_OK"),
     "bridge.fees.recipient is a validator's payout address — docs/deploy.md: a dedicated key, never a validator's (FEE_RECIPIENT_IS_PAYOUT_OK=1 to accept)")
if fees["recipient"] in {a for _, a, _ in alloc}:
    warnings.append("the bridge fee recipient is also a carried RAND wallet (an alloc) — its viewing key sees every fee note")
need(g["epoch_blocks"] == int(E["EPOCH_BLOCKS"]) == g19["epoch_blocks"], "epoch_blocks is not chain 19's")
need(len(g["validators"]) == 26 and all(v["stake"] == int(E["STAKE_RAND"]) * 10**9 for v in g["validators"]), "validators wrong")
need([v["public_key"] for v in g["validators"]] == [vals[n]["public_key"] for n in vals], "validator order/keys wrong")
for i, n in enumerate(g["alloc"]):
    need(n.get("opening") is not None, f"alloc note {i} has no opening (core I-2)")
need(sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 1) == locked_total, "Σ zUSD notes != Σ locked")
need(sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 0) == alloc_total, "Σ RAND notes != Σ alloc list")
for k, want in (("max_program_words", "MAX_PROGRAM_WORDS"), ("max_proof_bytes", "MAX_PROOF_BYTES"),
                ("max_block_bytes", "MAX_BLOCK_BYTES"), ("max_call_envelope_bytes", "MAX_CALL_ENVELOPE_BYTES"),
                ("max_program_public_words", "MAX_PROGRAM_PUBLIC_WORDS")):
    need(g[k] == int(E[want]), f"{k} is {g[k]}")
    need(g[k] == g19[k] or E.get("LIMITS_CHANGED"), f"{k} {g[k]} differs from chain 19's {g19[k]} (LIMITS_CHANGED=1 if intended)")
need(g["max_block_bytes"] >= 3 * g["max_proof_bytes"] + 1048576,
     f"max_block_bytes {g['max_block_bytes']} < 3*max_proof_bytes + 1 MiB: a v3 Call carries three proofs")
# Outside the chain id, the clock, the carried notes, the bridge's burn sequence / floors /
# rotation, the zUSD backings' `locked`, staking, gas and the new fields, every byte is chain 19's.
excused = {"chain_id", "timestamp_ms", "alloc", "bridge", "tokens", "staking", "gas",
           "testnet", "binding_domain", "proof_window_blocks", "program_state"}
if E.get("LIMITS_CHANGED"):
    excused |= {"max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes", "max_program_public_words"}
moved = sorted(k for k in set(g) | set(g19) if k not in excused and g.get(k) != g19.get(k))
need(not moved, f"not chain 19's shape: {moved} differ from chain 19's genesis")
want_staking = {**{k: v for k, v in s19.items() if k != "max_stake_entry_per_epoch"},
                "max_stake_entry_bps_per_epoch": 2500, "admission_by_vote": True}
if not (E.get("FAUCET_RECIPIENTS_CHANGED") or E.get("FAUCET_MINTERS_CHANGED")):
    need(st == want_staking, f"staking is not chain 19's with the bps budget and admission by vote: "
         f"{sorted(k for k in set(st) | set(want_staking) if st.get(k) != want_staking.get(k))} differ")
bridge_moved = sorted(k for k in set(g["bridge"]) | set(b19)
                      if k not in ("burn_sequence", "min_inbound_sequence", "rotation", "fees") and g["bridge"].get(k) != b19.get(k))
need(not bridge_moved or rotated or (bridge_moved == ["emitters"] and E.get("EMITTERS_CHANGED")),
     f"bridge fields {bridge_moved} differ from chain 19's genesis (BRIDGE_ROTATED=1 carries a live rotation)")
strip_locked = lambda toks: [{**t, "backings": [{k: v for k, v in b.items() if k != "locked"} for b in t["backings"]]} for t in toks]
need({**g["tokens"], "tokens": strip_locked(g["tokens"]["tokens"])} == {**g19["tokens"], "tokens": strip_locked(g19["tokens"]["tokens"])},
     "the tokens section differs from chain 19's in more than the backings' locked amounts")
now_ms = int(time.time() * 1000)
need(g["timestamp_ms"] <= now_ms + 15_000, "timestamp_ms is in the future beyond the 15 s vote drift bound")

json.dump(g, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(f"cut-chain20: spliced bridge (set {g['bridge']['guardian_set_index']}, burn seq {g['bridge']['burn_sequence']}, floor {floor}, "
      f"emitters = chain 19's{' (CHANGED: ' + ','.join(changed) + ')' if changed else ''}, rotation {rotation}); "
      f"zUSD locked {locked_total} == notes {notes_total} == chain 19 supply == custody ({len(token_notes)} note(s)); "
      f"RAND allocs Σ {alloc_total} {rand_carry}; staking ({len(recipients)} recipients, {len(minters)} minters, entry 2500 bps, admission by vote, no slashing); "
      f"bridge fees {fees['mint_bps']}/{fees['burn_bps']} bps to {fees['recipient'][:10]}…; "
      f"testnet, binding_domain 1, proof_window_blocks 1024; gas {gas['gas_price']}/{gas['byte_price']} ceilings {dyn['max_gas_price']}/{dyn['max_byte_price']}, byte load {dyn['byte_load']}; "
      f"program_state {g.get('program_state', 'SKIPPED')}; every other field equal to chain 19's genesis")
print("cut-chain20: zUSD locked per backing: " + (", ".join(f"{b['chain']}:{b['token'][-8:]}={b['locked']}" for b in backings if b.get("locked")) or "none"))
for w in warnings:
    print(f"cut-chain20: ⚠ {w}")
PY
}

# ══ the field probe: every new field is part of this rand-node's genesis hash ══════════════════
# For each new field, a copy of the finished file without it (or with chain 19's value back) must
# either be refused by `init` or hash differently. A build that parses a field but leaves it out of
# the hash — or does not know it and drops it — would launch a chain without that rule.
py_variants() {
  python3 - <<'PY'
import copy, json, os
E = os.environ
g = json.load(open(E["OUT"]))
g19 = json.load(open(E["CHAIN19_GENESIS"]))
d = os.path.join(E["TMP"], "variants"); os.makedirs(d)
def drop(name, path):
    v = copy.deepcopy(g); cur = v
    for k in path[:-1]:
        cur = cur[k]
    del cur[path[-1]]
    json.dump(v, open(os.path.join(d, name + ".json"), "w"))
drop("testnet", ["testnet"])
drop("binding_domain", ["binding_domain"])
drop("proof_window_blocks", ["proof_window_blocks"])
drop("gas.dynamic.max_gas_price", ["gas", "dynamic", "max_gas_price"])
drop("gas.dynamic.max_byte_price", ["gas", "dynamic", "max_byte_price"])
drop("gas.dynamic.byte_load", ["gas", "dynamic", "byte_load"])
drop("bridge.rotation", ["bridge", "rotation"])
drop("bridge.fees", ["bridge", "fees"])
drop("staking.admission_by_vote", ["staking", "admission_by_vote"])
v = copy.deepcopy(g); del v["staking"]["max_stake_entry_bps_per_epoch"]
v["staking"]["max_stake_entry_per_epoch"] = g19["staking"]["max_stake_entry_per_epoch"]
json.dump(v, open(os.path.join(d, "staking.max_stake_entry_bps_per_epoch.json"), "w"))
if "program_state" in g:
    drop("program_state", ["program_state"])
PY
}

probe_fields() {   # <finished genesis> <its hash>
  local f name h ok=0
  py_variants
  for f in "$TMP"/variants/*.json; do
    name=$(basename "$f" .json)
    rm -rf "$TMP/vprobe"
    if h=$("$NODE" init --datadir "$TMP/vprobe" --genesis "$f" 2>"$TMP/vprobe.err" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p'); [ -n "$h" ]; then
      [ "$h" != "$2" ] || { echo "cut-chain20: without $name this rand-node derives the SAME genesis hash — it does not hash that field (not the v0.6.8 build?)" >&2; exit 1; }
      echo "cut-chain20:   field probe: without $name → genesis ${h:0:12}… (≠ ${2:0:12}…)"
    else
      echo "cut-chain20:   field probe: without $name → refused by init ($(tail -1 "$TMP/vprobe.err" | cut -c1-90))"
    fi
    ok=$((ok + 1))
  done
  echo "cut-chain20: every new field ($ok probed) is part of this rand-node's genesis hash"
}

# ══ check-limits: what a chain-20 node serves (after launch; DRY_RUN runs it on a loopback node) ═
py_check_limits() {
  python3 - <<'PY'
import json, os, sys, urllib.request
E = os.environ
url, gen = E["CHECK_RPC"], json.load(open(E["CHECK_GENESIS"]))
def rpc(method, params=None):
    req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(),
                                 {"content-type": "application/json", "user-agent": "rand-cut-chain20/1"})
    with urllib.request.urlopen(req, timeout=20) as r:
        out = json.load(r)
    if "error" in out:
        sys.exit(f"check-limits: {method}: {out['error']}")
    return out["result"]
bad = []
def want(what, got, exp):
    print(f"check-limits:   {what:<34} {json.dumps(got)}{'' if got == exp else '   ✗ expected ' + json.dumps(exp)}")
    if got != exp:
        bad.append(what)
want("rand_getGenesisHash", rpc("rand_getGenesisHash"), E["EXPECT_GENESIS_HASH"])
L = rpc("rand_getLimits")
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
want("hc_auth", L.get("hc_auth"), gen["hc_auth"])
if E.get("PROGRAM_STATE_SKIPPED"):
    want("program_state (SKIPPED: absent)", L.get("program_state"), None)
    print("check-limits:   ⚠ PROGRAM_STATE SKIPPED — a real chain-20 node must serve program_state.cell_fee \"10000000\"")
else:
    ps = L.get("program_state") or {}
    want("program_state.cell_fee", ps.get("cell_fee"), str(gen["program_state"]["cell_fee"]))
B = rpc("rand_getBridgeState")
want("bridge emitters", B.get("emitters"), gen["bridge"]["emitters"])
want("bridge min_inbound_sequence", {str(k): v for k, v in (B.get("min_inbound_sequence") or {}).items()}, gen["bridge"]["min_inbound_sequence"])
want("bridge burn_sequence", B.get("burn_sequence"), gen["bridge"]["burn_sequence"])
want("bridge rotation_rules", B.get("rotation_rules"), {"delay_secs": 86400, "needs_possession": True})
want("bridge fees", B.get("fees"), {"mint_bps": 10, "burn_bps": 10, "recipient": gen["bridge"]["fees"]["recipient"]})
if bad:
    sys.exit(f"check-limits: {url} does NOT serve chain 20 as cut: {', '.join(bad)}")
print(f"check-limits: {url} serves chain 20 as cut ({len(L)} limits read)")
PY
}

check_limits() {   # <rpc url> <genesis file>
  local h d
  [ -f "$2" ] || { echo "check-limits: $2 is not a file" >&2; exit 1; }
  [ -x "$NODE" ] || { echo "check-limits: NODE=$NODE is not executable (it re-derives the genesis hash)" >&2; exit 1; }
  d=$(mktemp -d); h=$("$NODE" init --datadir "$d/p" --genesis "$2" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p' || true); rm -rf "$d"
  [ -n "$h" ] || { echo "check-limits: $NODE derived no genesis hash from $2" >&2; exit 1; }
  CHECK_RPC=$1 CHECK_GENESIS=$2 EXPECT_GENESIS_HASH=$h py_check_limits
}

if [ "${1:-}" = check-limits ]; then
  check_limits "${2:?check-limits <rpc url> <genesis file>}" "${3:?check-limits <rpc url> <genesis file>}"
  exit 0
fi

# ══ fixtures: synthetic inputs derived from the committed chain-19 genesis ═════════════════════
# FIXTURE_MODE=selftest (SELFTEST=1): the python steps alone; fake wallet addresses; the base file
# `rand-node genesis` would write faked too (with every new flag's field). FIXTURE_MODE=dryrun
# (DRY_RUN=1): inputs the REAL binaries accept — the committed chain-19 genesis unchanged (its
# sha256 check passes), wallet lines at real addresses (chain 19's validator payouts), no base file.
# BOTH describe chain 19 as the cut expects to find it: its genesis bridge state unmoved (burn
# sequence 8; the four endpoints at their genesis floors 1/1/1/4 as next sequences), zUSD locked
# Solana USDT 10 == custody, the register its 26 validators at 1 000 RAND.
py_fixtures() {
  python3 - <<'PY'
import copy, json, os, time
E = os.environ; st = E["ST"]; dry = E.get("FIXTURE_MODE") == "dryrun"
exec(E["UNITS_PY"])
g19 = json.load(open(E["CHAIN19_GENESIS"]))
os.makedirs(f"{st}/snap"); os.makedirs(f"{st}/reg"); os.makedirs(f"{st}/tmp")
gnames, bnames = E["GENESIS_NAMES"].split(), E["BONDED"].split()
names = gnames + bnames
assert len(names) == len(g19["validators"]) == 26
minters = g19["staking"]["faucet_minters"]
assert len(minters) == len(gnames)
addr = {n: (minters[i] if i < len(gnames) else f"FIXTUREaddr{i:02d}") for i, n in enumerate(names)}
with open(f"{st}/validators.tsv", "w") as f:
    for n, v in zip(names, g19["validators"]):
        if n in gnames:
            f.write(f"{n}\t{addr[n]}\t{v['public_key']}\tpeer\t{v['payout']}\n")
for n, v in zip(names, g19["validators"]):
    if n in bnames:
        pk = bytes.fromhex(v["public_key"])
        open(f"{st}/reg/{n}.txt", "w").write(f"validator {addr[n]} on chain 15\nregistration: {(len(pk).to_bytes(8, 'little') + pk + b'sig').hex()}\n")
if not dry:
    json.dump(g19, open(f"{st}/genesis-chain19.json", "w"))
b = g19["bridge"]; z = g19["tokens"]["tokens"][0]
total = sum(x.get("locked", 0) for x in z["backings"])
live = [{**{k: x[k] for k in ("chain", "token", "decimals")}, "locked": x.get("locked", 0)} for x in z["backings"]]
assert total == 1000000000, "chain 19's zUSD supply is 10, all of it on the Solana USDT backing"
snap = {"taken_at": "dryrun" if dry else "selftest", "genesis_hash": E["CHAIN19_HASH"], "status_height": 50000,
        "validators": [{"address": addr[n], "stake": str(v["stake"]), "pending": [], "rewards": "0", "payout": v["payout"],
                        "nonce": 0, "active": True} for n, v in zip(names, g19["validators"])],
        "bridge": {**{k: b[k] for k in ("emitter", "emitters", "guardian_set_index", "guardians", "pq_guardians", "pause_key")},
                   "burn_sequence": b["burn_sequence"], "mint_paused": False, "registration_fee": str(g19["tokens"]["registration_fee"]),
                   "rules_v2": {"global_mint_cap_per_window": str(b["rules_v2"]["global_mint_cap_per_window"]), "cap_window_secs": b["rules_v2"]["cap_window_secs"]},
                   "min_inbound_sequence": b["min_inbound_sequence"]},
        "tokens": {"tokens": [{"index": 1, "symbol": "zUSD", "total_supply": str(total),
                               "authority": {"kind": "bridged", "backings": [{**x, "locked": str(x["locked"])} for x in live]}}]},
        "supply": {},
        "source": {"emitters": {c: E[f"EMITTER_{c}"] for c in "2345"},
                   "next_sequence": {c: int(b["min_inbound_sequence"][c]) for c in "2345"},
                   "custody": {f"{x['chain']}:{x['token']}": {"custody": x["locked"] * 10**x["decimals"] // 10**8 if x["decimals"] <= 8 else x["locked"] * 10**(x["decimals"] - 8), "fees": 0} for x in live}}}
json.dump(snap, open(f"{st}/snap/chain19-state.json", "w"))
rand_notes = [n for n in g19["alloc"] if n["opening"].get("asset", 0) == 0]
zusd_notes = [n for n in g19["alloc"] if n["opening"].get("asset", 0) == 1]
payouts = list(dict.fromkeys(v["payout"] for v in g19["validators"]))
assert len(payouts) >= len(rand_notes) + 1, "not enough distinct payout addresses for the dry-run carry"
wallets = [{"label": f"w{i}", "address": payouts[i] if dry else f"rand1SELFTEST{i}", "rand_units": n["amount"], "zusd_units": 0, "file": "-"}
           for i, n in enumerate(rand_notes)]
wallets.append({"label": "empty", "address": "rand1FIXTUREempty", "rand_units": 0, "zusd_units": 0, "file": "-"})
json.dump({"chain19_hash": E["CHAIN19_HASH"], "height_from": 50000, "height_to": 50000, "wallets": wallets,
           "uncovered_genesis_allocs": [], "rescanned": True}, open(f"{st}/snap/balances.json", "w"))
with open(f"{st}/alloc-rand.txt", "w") as f:
    f.write(f"# {'dry run' if dry else 'selftest'}\n")
    for w in wallets[:-1]:
        f.write(f"{w['label']} {w['address']} {fmt(w['rand_units'])}\n")
holder = payouts[len(rand_notes)] if dry else "rand1SELFTESTz"
open(f"{st}/zusd-carry.txt", "w").write("".join(f"holder {holder} {fmt(n['amount'], 8)}\n" for n in zusd_notes))
# A filled cut record (the fixture's — the real one is the operator's, published before the cut).
open(f"{st}/cut-record.txt", "w").write(
    "chain-id: 20\nreason: binding_domain, proof_window_blocks, testnet, admission_by_vote, gas ceilings, bridge.rotation and RPL-2 program_state are genesis-gated validity rules\n"
    "carries: fixture register, bridge state and balances\ndrops: fixture: nothing\nclients: fixture: none\n"
    "second-operator: fixture\nrollback: fixture: keep chain 19 dirs and *.pre-c20 binaries a day\n")
if dry:
    raise SystemExit(0)
open(f"{st}/faucet-recipients-changed.txt", "w").write("someone rand1SELFTESTfaucetrecipientchanged\n")
with open(f"{st}/tmp/token-notes.jsonl", "w") as f:
    for n in zusd_notes:
        f.write(json.dumps(n) + "\n")
# what `rand-node genesis --hardening-v6 --bundle-guest v3 --auth-guest --gas-… --testnet
# --binding-domain 1 --proof-window-blocks 1024 --program-state-cell-fee …` writes, before the splice
base = {k: g19[k] for k in ("chain_id", "timestamp_ms", "validators", "faucet", "confidential", "fri_profile", "hc_bundle",
                           "epoch_blocks", "max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes",
                           "max_program_public_words", "envelope_bytes", "hardening_v6", "hc_auth")}
tb, tg, bps = (int(x) for x in E["GAS_DYNAMIC"].split(","))
base.update(chain_id=20, timestamp_ms=int(time.time() * 1000), alloc=rand_notes, hc_bundle=E["EXPECT_HC_BUNDLE"], hc_auth=E["EXPECT_HC_AUTH"],
            tokens={"registration_fee": g19["tokens"]["registration_fee"], "mint_cap_per_day": g19["tokens"]["mint_cap_per_day"], "tokens": []},
            gas={"gas_price": E["GAS_PRICE"], "byte_price": E["BYTE_PRICE"], "bundle_gas_limit": int(E["BUNDLE_GAS_LIMIT"]), "metering": "circuit",
                 "dynamic": {"target_block_bytes": tb, "target_block_gas": tg, "adjust_bps": bps,
                             "min_gas_price": E["GAS_PRICE"], "min_byte_price": E["BYTE_PRICE"],
                             "max_gas_price": E["MAX_GAS_PRICE"], "max_byte_price": E["MAX_BYTE_PRICE"], "byte_load": E["GAS_BYTE_LOAD"]}},
            testnet=True, binding_domain=int(E["BINDING_DOMAIN"]), proof_window_blocks=int(E["PROOF_WINDOW_BLOCKS"]),
            program_state={"cell_fee": int(E["PROGRAM_STATE_CELL_FEE"])})
json.dump(base, open(f"{st}/base.json", "w"))
PY
}

# A fake chain-20 node for the selftest's check-limits: serves <file>'s {method: result} on loopback.
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

# ══ SELFTEST: the python steps on fixtures derived from deploy/genesis-chain19.json ════════════
if [ "${SELFTEST:-}" = 1 ]; then
  ST=$(mktemp -d); FAKE_RPC_PID=; trap 'rm -rf "$ST"; [ -z "$FAKE_RPC_PID" ] || kill "$FAKE_RPC_PID" 2>/dev/null || true' EXIT
  export ST FIXTURE_MODE=selftest FEE_RECIPIENT=rand1SELFTESTfeerecipient
  py_fixtures
  NEW_EMITTER=$(printf '0%.0s' $(seq 63))1
  export SNAPSHOT_FILE=$ST/snap/chain19-state.json BALANCES_FILE=$ST/snap/balances.json CHAIN19_GENESIS=$ST/genesis-chain19.json \
    VALIDATORS_TSV=$ST/validators.tsv REGISTRATIONS=$ST/reg ALLOC_ADDRESSES=$ST/alloc-rand.txt ZUSD_CARRY=$ST/zusd-carry.txt \
    TMP=$ST/tmp HC_REPORTED=$EXPECT_HC_BUNDLE
  pass=0; fail=0
  ok()  { echo "selftest: ok   — $1"; pass=$((pass+1)); }
  bad() { echo "selftest: FAIL — $1"; fail=$((fail+1)); }
  fresh() { cp "$ST/base.json" "$ST/out.json"; export OUT=$ST/out.json; }

  fresh
  if py_validators && py_splice; then
    if python3 - <<'PY'
import json, os
E = os.environ
g = json.load(open(E["OUT"]))
g19 = json.load(open(E["CHAIN19_GENESIS"]))
assert g["chain_id"] == 20 and g["hc_auth"] == g19["hc_auth"] and g["hc_bundle"] == g19["hc_bundle"]
assert list(g)[-6:] == ["hc_auth", "gas", "testnet", "binding_domain", "proof_window_blocks", "program_state"], list(g)
assert g["testnet"] is True and g["binding_domain"] == 1 and g["proof_window_blocks"] == 1024
assert g["program_state"] == {"cell_fee": 10000000}
d = g["gas"]["dynamic"]
assert (d["max_gas_price"], d["max_byte_price"], d["byte_load"]) == ("10000", "80000", "paying")
assert {k: v for k, v in d.items() if k not in ("max_gas_price", "max_byte_price", "byte_load")} == g19["gas"]["dynamic"]
assert g["bridge"]["rotation"] == {"delay_secs": 86400, "needs_possession": True}
assert g["bridge"]["fees"] == {"mint_bps": 10, "burn_bps": 10, "recipient": "rand1SELFTESTfeerecipient"}
assert list(g["bridge"])[-2:] == ["rotation", "fees"]
assert g["bridge"]["emitters"] == g19["bridge"]["emitters"] and g["bridge"]["min_inbound_sequence"] == {"2": 1, "3": 1, "4": 1, "5": 4}
assert g["bridge"]["burn_sequence"] == 8 and g["bridge"]["guardian_set_index"] == 1
s = g["staking"]
assert s["max_stake_entry_bps_per_epoch"] == 2500 and s["admission_by_vote"] is True
assert "max_stake_entry_per_epoch" not in s and "slashing" not in s
assert {k: v for k, v in s.items() if k not in ("max_stake_entry_bps_per_epoch", "admission_by_vote")} == {k: v for k, v in g19["staking"].items() if k != "max_stake_entry_per_epoch"}
assert "vesting" not in g and "aggregation" not in g
assert [(b["chain"], b["token"][:8], b["locked"]) for b in g["tokens"]["tokens"][0]["backings"] if "locked" in b] == [(5, "ce010e60", 1000000000)]
assert g["validators"] == g19["validators"] and g["consensus_domain"] == 1
assert sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 0) == sum(n["amount"] for n in g19["alloc"] if n["opening"].get("asset", 0) == 0)
assert all(sum(len(v) // 2 for v in n["envelope"].values()) == 1860 for n in g["alloc"])
PY
    then ok "the chain-19 fixture assembles into a chain-20 genesis (bridge.fees 10/10 bps to the recipient, testnet, binding_domain 1, proof_window_blocks 1024, gas ceilings 10000/80000 + paying, bridge.rotation 86400/possession, staking 2500 bps + admission by vote and no slashing, program_state cell_fee 10000000, chain 19's emitters, floors 1/1/1/4, burn sequence 8, locked Solana USDT 10, chain 19's validators and allocs)"; else bad "assembled genesis content"; fi
  else bad "the happy path refused"; fi
  cp "$ST/out.json" "$ST/good.json"

  export -f py_validators py_splice
  # PROGRAM_STATE_SKIPPED (DRY_RUN's path on a binary without RPL-2): the section must be absent
  cp "$ST/base.json" "$ST/base.json.keep"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); del d["program_state"]; json.dump(d, open(p,"w"))' "$ST/base.json"
  fresh
  if PROGRAM_STATE_SKIPPED=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 && grep -q 'PROGRAM_STATE SKIPPED' "$ST/log"; then
    ok "PROGRAM_STATE_SKIPPED=1 (DRY_RUN on a binary without RPL-2) cuts without the section, and says so"
  else bad "PROGRAM_STATE_SKIPPED path: $(tail -2 "$ST/log")"; fi
  mv "$ST/base.json.keep" "$ST/base.json"

  # every refusal the cut must make, one per case: <description> <file> <mutation> <expected reason phrase> [env]
  refuse() {
    local what=$1 file=$2 mutation=$3 phrase=$4; shift 4
    cp "$file" "$file.orig"
    python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); $mutation; json.dump(d, open(p,'w'))" "$file"
    fresh
    if (env "$@" bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1); then
      bad "$what — accepted"
    else
      local msg; msg=$(grep -o 'cut-chain20: .*' "$ST/log" | tail -1 | cut -c1-110)
      if grep -qF -- "$phrase" "$ST/log"; then ok "$what — $msg"; else bad "$what — refused, but not for the expected reason (wanted \"$phrase\"): $msg"; fi
    fi
    mv "$file.orig" "$file"
  }
  mkdir -p "$ST/done-ok/2" "$ST/done-ok/5" "$ST/done-bad/5"; touch "$ST/done-ok/5/2" "$ST/done-ok/5/3" "$ST/done-bad/5/9"
  S=$ST/snap/chain19-state.json; B=$ST/base.json; G=$ST/genesis-chain19.json
  # the new fields
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
  refuse "a validator payout as fee recipient" "$S" 'pass' "a validator's payout address" FEE_RECIPIENT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validators"][0]["payout"])' "$ST/genesis-chain19.json")"
  refuse "a stake entry budget off 2500 bps" "$S" 'pass' "not 2500" STAKE_ENTRY_BPS=3333
  refuse "slashing in chain 19's staking"    "$G" 'd["staking"]["slashing"] = {"equivocation_bps": 500, "jail_epochs": 2}' "carries none"
  refuse "a vesting section on chain 19"     "$G" 'd["vesting"] = {"entries": []}' "vesting section"
  refuse "an aggregation section"            "$B" 'd["aggregation"] = {}' "aggregation"
  refuse "a vesting section in the base"     "$B" 'd["vesting"] = {"entries": []}' "vesting section is present"
  refuse "a field the script does not know"  "$B" 'd["extra_unknown"] = 1' "fields this script does not know"
  # chain 19's shape, carried
  refuse "gas prices that are not chain 19's" "$B" 'd["gas"]["gas_price"] = "200"; d["gas"]["dynamic"]["min_gas_price"] = "200"' "is not chain 19's plus the POOL-2 fields" GAS_PRICE=200
  refuse "a bundle_gas_limit off the pin"    "$B" 'd["gas"]["bundle_gas_limit"] = 16383' "not gas_max(14, 0, 0)"
  refuse "a byte target not half the block"  "$B" 'd["gas"]["dynamic"]["target_block_bytes"] = 4194304' "gas.dynamic targets are"
  refuse "a validator payout that is not chain 19's" "$B" 'd["validators"][0]["payout"] = d["validators"][1]["payout"]' "not chain 19's shape: ['validators']"
  refuse "no envelope_bytes"                 "$B" 'del d["envelope_bytes"]' "envelope_bytes is None, not 1860"
  refuse "a legacy (1 348-B) RAND alloc"     "$B" 'd["alloc"][0]["envelope"]["body"] = d["alloc"][0]["envelope"]["body"][:-1024]' "sealed in the legacy format"
  refuse "a legacy (1 348-B) zUSD note"      "$ST/tmp/token-notes.jsonl" 'd["envelope"]["body"] = d["envelope"]["body"][:-1024]' "sealed in the legacy format"
  refuse "hc_auth not chain 19's"            "$G" 'd["hc_auth"] = "cd" * 32' "is not chain 19's auth guest"
  # the bridge: emitters, floors, custody
  refuse "a snapshot read at other emitters" "$S" 'd["source"]["emitters"]["2"] = "00" * 31 + "01"' "other emitters than this cut lists"
  refuse "a guardian rotation on chain 19"   "$S" 'd["bridge"]["guardian_set_index"] = 2' "BRIDGE_ROTATED=1"
  refuse "custody one unit below locked"     "$S" 'd["source"]["custody"][[k for k in d["source"]["custody"] if k.startswith("5:ce01")][0]]["custody"] -= 1' "source custody"
  refuse "custody at Tron above locked"      "$S" 'd["source"]["custody"][[k for k in d["source"]["custody"] if k.startswith("4:")][0]]["custody"] += 1' "source custody"
  refuse "zUSD supply above Σ locked"        "$S" 'd["tokens"]["tokens"][0]["total_supply"] = "1000000001"' "!= Σ locked"
  refuse "an explicit Ethereum floor of 0 reaching the splice" "$S" 'pass' "below 1" MIN_INBOUND_2=0
  refuse "a Solana floor below chain 19's"   "$S" 'pass' "below chain 19's own floor" MIN_INBOUND_5=3
  refuse "a floor above the next sequence"   "$S" 'pass' "would NEVER mint on chain 20" MIN_INBOUND_3=2
  refuse "an unminted BSC lock (next seq 2, explicit floor 1)" "$S" 'd["source"]["next_sequence"]["3"] = 2' "will mint on chain 20" MIN_INBOUND_3=1
  refuse "the relayer's done/ disagreeing"   "$S" 'pass' "the relayer's done/ says" RELAYER_DONE_DIR="$ST/done-bad"
  refuse "a stake that is not 1000 RAND"     "$S" 'd["validators"][3]["stake"] = "2000000000000"' "not a plain"
  refuse "a validator bonded on chain 19"    "$S" 'd["validators"].append(dict(d["validators"][0], address="new"))' "chain 19's register holds"
  refuse "unwithdrawn validator rewards"     "$S" 'd["validators"][0]["rewards"] = "1"' "REWARDS_DROPPED_OK=1 to drop"
  # the RAND carry
  refuse "a scanned balance the list lacks"  "$ST/snap/balances.json" 'd["wallets"][0]["rand_units"] += 1' "!= Σ scanned balances"
  refuse "an uncovered genesis alloc"        "$ST/snap/balances.json" 'd["uncovered_genesis_allocs"] = [{"pk": "ab" * 32, "amount": 1}]' "UNCOVERED_ALLOCS_OK=1 to drop"
  refuse "no balances.json, no NO_BALANCES"  "$S" 'pass' "the carry-over rule" BALANCES_FILE=/nonexistent
  refuse "a changed faucet allowlist"        "$S" 'pass' "FAUCET_RECIPIENTS_CHANGED=1 if that is" FAUCET_RECIPIENTS="$ST/faucet-recipients-changed.txt"

  # floors: the auto path honours a moved endpoint; an explicit unminted-lock floor carries with a warning
  cp "$S" "$S.keep"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["source"]["next_sequence"].update({"2": 3, "5": 6}); json.dump(d, open(p,"w"))' "$S"
  fresh
  if bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 \
     && python3 -c 'import json,os; assert json.load(open(os.environ["OUT"]))["bridge"]["min_inbound_sequence"] == {"2": 3, "3": 1, "4": 1, "5": 6}' \
     && grep -q 'EXPECTED' "$ST/log"; then ok "auto floors follow the endpoints' next sequences (2:3, 5:6), with the expected-floor warning"
  else bad "auto floors: $(tail -2 "$ST/log")"; fi
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["source"]["next_sequence"]["4"] = 2; k=[k for k in d["source"]["custody"] if k.startswith("4:")][0]; d["source"]["custody"][k]["custody"] += 5000000; json.dump(d, open(p,"w"))' "$S"
  fresh
  if MIN_INBOUND_4=1 ALLOW_UNMINTED_LOCKS=1 bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1 \
     && python3 -c 'import json,os; assert json.load(open(os.environ["OUT"]))["bridge"]["min_inbound_sequence"]["4"] == 1' \
     && grep -q 'will mint on chain 20 (ALLOW_UNMINTED_LOCKS=1)' "$ST/log" && grep -q 'the unminted lock(s) on chain 4' "$ST/log"; then
    ok "an explicit floor below an unminted user lock carries with ALLOW_UNMINTED_LOCKS=1 (custody above locked on that chain only), with warnings"
  else bad "ALLOW_UNMINTED_LOCKS path: $(tail -2 "$ST/log")"; fi
  mv "$S.keep" "$S"
  fresh
  if RELAYER_DONE_DIR="$ST/done-ok" bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then
    ok "the relayer's done/ agreeing with every floor is accepted (an empty done/<c> = chain 19's floor − 1)"
  else bad "RELAYER_DONE_DIR agreeing: $(tail -2 "$ST/log")"; fi

  # check-limits against a fake chain-20 node serving the assembled file
  python3 - "$ST/good.json" "$ST/answers.json" <<'PY'
import json, sys
g = json.load(open(sys.argv[1])); d = g["gas"]["dynamic"]
json.dump({"rand_getGenesisHash": "ab" * 32,
           "rand_getLimits": {"proof_window_blocks": 1024, "binding_domain": 1, "testnet": True, "admission_by_vote": True, "slashing": None,
                              "max_gas_price": d["max_gas_price"], "max_byte_price": d["max_byte_price"], "byte_load": "paying",
                              "gas_metering": "circuit", "bundle_gas_limit": 20479, "adjust_bps": 1250, "envelope_bytes": 1860,
                              "hardening_v6": True, "hc_auth": g["hc_auth"],
                              "program_state": {"cell_fee": str(g["program_state"]["cell_fee"]), "max_reads": 8, "max_writes": 8, "max_payouts": 4}},
           "rand_getBridgeState": {"emitters": g["bridge"]["emitters"], "min_inbound_sequence": g["bridge"]["min_inbound_sequence"],
                                   "burn_sequence": g["bridge"]["burn_sequence"], "rotation_rules": {"delay_secs": 86400, "needs_possession": True},
                                   "fees": g["bridge"]["fees"]}},
          open(sys.argv[2], "w"))
PY
  fake_rpc "$ST/answers.json" "$ST/port"
  RPC=http://127.0.0.1:$(cat "$ST/port")
  if CHECK_RPC=$RPC CHECK_GENESIS=$ST/good.json EXPECT_GENESIS_HASH=$(printf 'ab%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1; then
    ok "check-limits accepts a node serving chain 20 as cut ($(grep -c '^check-limits:   ' "$ST/log") values read)"
  else bad "check-limits on a correct node: $(tail -3 "$ST/log")"; fi
  for m in 'L["proof_window_blocks"] = 256' 'L["binding_domain"] = 0' 'L["testnet"] = False' 'L["admission_by_vote"] = False' \
           'L["byte_load"] = None' 'L["max_gas_price"] = None' 'L["program_state"] = None' 'B["rotation_rules"] = None' 'B["min_inbound_sequence"]["2"] = 0' 'B["fees"] = None' 'B["fees"]["burn_bps"] = 20'; do
    cp "$ST/answers.json" "$ST/answers.keep"
    python3 -c "import json,sys; p=sys.argv[1]; a=json.load(open(p)); L=a['rand_getLimits']; B=a['rand_getBridgeState']; $m; json.dump(a, open(p,'w'))" "$ST/answers.json"
    if CHECK_RPC=$RPC CHECK_GENESIS=$ST/good.json EXPECT_GENESIS_HASH=$(printf 'ab%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1; then bad "check-limits accepted a node with $m"
    else grep -q 'does NOT serve chain 20 as cut' "$ST/log" && ok "check-limits refuses a node with $m" || bad "check-limits, $m: $(tail -1 "$ST/log")"; fi
    mv "$ST/answers.keep" "$ST/answers.json"
  done
  if CHECK_RPC=$RPC CHECK_GENESIS=$ST/good.json EXPECT_GENESIS_HASH=$(printf 'cd%.0s' $(seq 32)) py_check_limits >"$ST/log" 2>&1; then bad "check-limits accepted another genesis hash"
  else ok "check-limits refuses a node serving another genesis hash"; fi
  kill "$FAKE_RPC_PID" 2>/dev/null || true; FAKE_RPC_PID=

  # the bash-level guards, each refusing before anything runs
  bash_refuses() {  # <description> <phrase> <env…> -- <args…>
    local what=$1 phrase=$2; shift 2
    local envs=(); while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
    if env -u MIN_INBOUND_2 -u MIN_INBOUND_3 -u MIN_INBOUND_4 -u MIN_INBOUND_5 SELFTEST=0 "${envs[@]}" bash "$0" "$@" >"$ST/log" 2>&1; then bad "$what — accepted"
    else grep -qF -- "$phrase" "$ST/log" && ok "$what — refused before anything runs" || bad "$what — wrong refusal: $(tail -1 "$ST/log")"; fi
  }
  for c in 2 3 4 5; do
    bash_refuses "EMITTER_$c off chain 19's, no EMITTERS_CHANGED" "is not chain 19's endpoint" "EMITTER_$c=$NEW_EMITTER" --
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
  bash_refuses "a valid floor file parses (and the cut then stops at its missing record)" "no cut record" MIN_INBOUND_FILE="$ST/floors-ok" CUT_RECORD="$ST/no-such-record" --
  fresh
  if MIN_INBOUND_2=1 MIN_INBOUND_FILE= bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1; then ok "an explicit floor equal to the next sequence is accepted"; else bad "explicit floor 1: $(tail -1 "$ST/log")"; fi
  bash_refuses "the cut without a cut record (OPS-7)" "no cut record" CUT_RECORD="$ST/no-such-record" CHAIN19_SNAPSHOT="$ST/snap" NODE=/usr/bin/true WALLET=/usr/bin/true --
  python3 -c 'import json,sys; json.dump({"chain_id": 20}, open(sys.argv[1] + "/genesis-chain20.json", "w"))' "$ST" 2>/dev/null
  mkdir -p "$ST/gendir"; cp "$ST/genesis-chain20.json" "$ST/gendir/"; cp "$CHAIN19_GENESIS" "$ST/gendir/genesis-chain19.json"
  bash_refuses "a chain id a committed genesis already has (OPS-7)" "already used by genesis-chain20.json" CUT_POLICY_GENESIS_DIR="$ST/gendir" CUT_RECORD="$ST/cut-record.txt" CHAIN19_SNAPSHOT="$ST/snap" NODE=/usr/bin/true WALLET=/usr/bin/true --
  bash_refuses "snapshot on a dead tunnel" "is not answering" CHAIN19_RPC=http://127.0.0.1:9 -- snapshot "$ST/snap-new"
  mkdir -p "$ST/wd"; echo '{}' > "$ST/wd/shielded-1.key.json"
  bash_refuses "balances without the relayer's key file" "relayer.key.json is in none of" WALLETS_DIRS="$ST/wd" WALLET=/usr/bin/true ALLOC_ADDRESSES="$ST/none.txt" CHAIN19_RPC=http://127.0.0.1:9 -- balances "$ST/snap-bal"
  echo '{}' > "$ST/wd/relayer.key.json"
  bash_refuses "balances on a dead tunnel (relayer present)" "is not answering" WALLETS_DIRS="$ST/wd" WALLET=/usr/bin/true ALLOC_ADDRESSES="$ST/none.txt" CHAIN19_RPC=http://127.0.0.1:9 -- balances "$ST/snap-bal"
  # the fee recipient's fingerprint, computed by WALLET: a fake `rand` that prints one
  printf '#!/usr/bin/env bash\necho "fingerprint ${FAKE_FP:-89DS-4Q4X-HXSX-MBYW}"\necho saved\n' > "$ST/fake-rand"; chmod +x "$ST/fake-rand"
  echo "rand1SELFTESTfeerecipient" > "$ST/fee-ok.txt"; echo "not-an-address" > "$ST/fee-bad.txt"; printf 'rand1a\nrand1b\n' > "$ST/fee-two.txt"
  fp_case() {  # <description> <want ok|refuse> <phrase> <env…>
    local what=$1 want=$2 phrase=$3; shift 3
    if env "$@" bash -c 'WALLET=$FAKE_WALLET; load_fee_recipient' >"$ST/log" 2>&1; then r=ok; else r=refuse; fi
    if [ "$r" = "$want" ] && grep -qF -- "$phrase" "$ST/log"; then ok "$what — $(grep -o 'cut-chain20: .*' "$ST/log" | tail -1 | cut -c1-110)"
    else bad "$what — got $r: $(tail -1 "$ST/log")"; fi
  }
  export -f load_fee_recipient
  fp_case "the fee recipient with the expected fingerprint is loaded" ok "fingerprint 89DS-4Q4X-HXSX-MBYW (= FEE_RECIPIENT_FINGERPRINT)" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-ok.txt"
  fp_case "a fee recipient whose fingerprint differs is refused" refuse "not FEE_RECIPIENT_FINGERPRINT" FAKE_WALLET="$ST/fake-rand" FAKE_FP=AAAA-BBBB-CCCC-DDDD FEE_RECIPIENT_FILE="$ST/fee-ok.txt"
  fp_case "a missing fee recipient file is refused" refuse "no fee recipient file" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/none.txt"
  fp_case "a fee recipient file without an address is refused" refuse "does not hold a rand1" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-bad.txt"
  fp_case "a fee recipient file of two lines is refused" refuse "more than one line" FAKE_WALLET="$ST/fake-rand" FEE_RECIPIENT_FILE="$ST/fee-two.txt"
  fp_case "a wallet that prints no fingerprint is refused" refuse "printed no fingerprint" FAKE_WALLET=/usr/bin/true FEE_RECIPIENT_FILE="$ST/fee-ok.txt"
  echo "selftest: $pass passed, $fail failed"
  [ "$fail" = 0 ]; exit
fi

# ══ DRY_RUN: the REAL cut path on synthetic inputs, no network ══════════════════════════════════
# Everything `snapshot` and `balances` would read off chain 19 and the four source chains is
# synthesised from the committed chain-19 genesis (py_fixtures, FIXTURE_MODE=dryrun) as the cut
# expects to find it. Then the cut below runs unchanged — the real `rand-node genesis` with every
# new flag, `alloc-note`, the splice and every assertion, two `init`s, the field probe — and then a
# LOOPBACK probe node (127.0.0.1 only, no bootstrap, no mDNS, a throwaway key) runs the file so
# `check-limits` reads what a chain-20 node serves. The output lands in a temp dir (DRY_OUT to
# choose), never at deploy/genesis-chain20.json, and is not chain 20: launch nothing from it.
if [ "${DRY_RUN:-}" = 1 ]; then
  ST=$(mktemp -d)
  export ST FIXTURE_MODE=dryrun
  py_fixtures
  CHAIN19_SNAPSHOT=$ST/snap VALIDATORS_TSV=$ST/validators.tsv REGISTRATIONS=$ST/reg \
    ALLOC_ADDRESSES=$ST/alloc-rand.txt ZUSD_CARRY=$ST/zusd-carry.txt CUT_RECORD=$ST/cut-record.txt
  OUT=${DRY_OUT:-$ST/genesis-chain20.DRY-RUN.json}
  export CHAIN19_SNAPSHOT VALIDATORS_TSV REGISTRATIONS ALLOC_ADDRESSES ZUSD_CARRY
  echo "cut-chain20: DRY RUN — synthetic chain-19 snapshot, balances and inputs under $ST (from $CHAIN19_GENESIS); no network; $OUT is NOT chain 20"
fi

if [ "${1:-}" = snapshot ]; then
  SNAP=${2:?snapshot <dir>}
  [ ! -e "$SNAP/chain19-state.json" ] || { echo "cut-chain20: $SNAP/chain19-state.json exists — a snapshot is taken once; move it aside" >&2; exit 1; }
  need_chain19_rpc
  mkdir -p "$SNAP"; export SNAP
  py_snapshot
  exit 0
fi

if [ "${1:-}" = balances ]; then
  SNAP=${2:?balances <snapshot dir>}
  [ ! -e "$SNAP/balances.json" ] || { echo "cut-chain20: $SNAP/balances.json exists — move it aside to re-scan" >&2; exit 1; }
  [ ! -e "$ALLOC_ADDRESSES" ] || { echo "cut-chain20: $ALLOC_ADDRESSES exists — move it aside; \`balances\` writes it" >&2; exit 1; }
  [ -x "$WALLET" ] || { echo "cut-chain20: $WALLET is not executable — a rand that decodes chain 19: v0.6.7 (the chain's own build)" >&2; exit 1; }
  for w in $REQUIRED_WALLETS; do
    found=; for d in $WALLETS_DIRS; do [ -e "$d/$w.key.json" ] && found=$d/$w.key.json; done
    [ -n "$found" ] || { echo "cut-chain20: $w.key.json is in none of WALLETS_DIRS ($WALLETS_DIRS) — link it there before the scan (the relayer's: ~/.rand-chain17/alloc-wallets/relayer.key.json → ~/.rand-chain14/wallets/relayer.key.json)" >&2; exit 1; }
    [ -s "$found" ] || { echo "cut-chain20: $found is empty or a broken link" >&2; exit 1; }
    echo "cut-chain20: required wallet $w: $found"
  done
  need_chain19_rpc
  [ -f "$SNAP/chain19-state.json" ] || { echo "cut-chain20: take the snapshot first ($0 snapshot $SNAP)" >&2; exit 1; }
  refuse_in_tree_key "$SNAP/chain19-state.json"
  export SNAP WALLET WALLETS_DIRS
  py_balances
  exit 0
fi

# ══ the cut ══════════════════════════════════════════════════════════════════════════════════
# OPS-7 first: a reused chain id and a missing cut record are refused before anything else.
refuse_reused_chain_id "$CHAIN_ID"
require_cut_record "$CUT_RECORD"
[ -n "$CHAIN19_SNAPSHOT" ] || { echo "cut-chain20: CHAIN19_SNAPSHOT is unset — run \`$0 snapshot <dir>\` while chain 19 is up" >&2; exit 1; }
SNAPSHOT_FILE=$CHAIN19_SNAPSHOT/chain19-state.json; BALANCES_FILE=$CHAIN19_SNAPSHOT/balances.json
export SNAPSHOT_FILE BALANCES_FILE
for bin in "$NODE" "$WALLET"; do
  [ -x "$bin" ] || { echo "cut-chain20: $bin is not executable — the v0.6.8 binaries (main + RPL-2)" >&2; exit 1; }
done
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$ALLOC_ADDRESSES" "$ZUSD_CARRY" "$CHAIN19_GENESIS" ${FAUCET_RECIPIENTS:+"$FAUCET_RECIPIENTS"}; do
  [ -f "$f" ] || { echo "cut-chain20: missing $f" >&2; exit 1; }
done
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$ALLOC_ADDRESSES" "$ZUSD_CARRY" ${FAUCET_RECIPIENTS:+"$FAUCET_RECIPIENTS"}; do
  refuse_in_tree_key "$f"
done
for n in $BONDED; do refuse_in_tree_key "$REGISTRATIONS/$n.txt"; done
[ "$(shasum -a 256 "$CHAIN19_GENESIS" | cut -c1-64)" = "$CHAIN19_GENESIS_SHA256" ] \
  || { echo "cut-chain20: $CHAIN19_GENESIS is not chain 19's committed genesis file (sha256 ${CHAIN19_GENESIS_SHA256:0:8}…)" >&2; exit 1; }
[ ! -e "$OUT" ] || { echo "cut-chain20: $OUT already exists — a genesis is cut once; move it aside deliberately" >&2; exit 1; }
HELP=$("$NODE" genesis --help)
for flag in --hardening-v6 --bundle-guest --auth-guest --gas-price --gas-dynamic --envelope-bytes \
            --max-gas-price --max-byte-price --gas-byte-load --testnet --binding-domain --proof-window-blocks; do
  grep -q -- "$flag" <<<"$HELP" || { echo "cut-chain20: $NODE genesis has no $flag (not the v0.6.8 build)" >&2; exit 1; }
done
# RPL-2: the one flag main does not have yet.
if ! grep -q -- --program-state-cell-fee <<<"$HELP"; then
  if [ "${DRY_RUN:-}" = 1 ]; then
    PROGRAM_STATE_SKIPPED=1; export PROGRAM_STATE_SKIPPED
    cat >&2 <<EOF
cut-chain20: ⚠⚠⚠ PROGRAM_STATE SKIPPED ⚠⚠⚠ — $NODE genesis has no --program-state-cell-fee: this binary
cut-chain20:     does not carry RPL-2 (main before the rebase lands). The dry run goes on WITHOUT the
cut-chain20:     program_state section; the REAL cut refuses this binary. Re-run DRY_RUN with a v0.6.8 build.
EOF
  else
    echo "cut-chain20: $NODE genesis has no --program-state-cell-fee — not the v0.6.8 build (main + RPL-2); the program_state section cannot be written" >&2; exit 1
  fi
fi
NODE_VERSION=$("$NODE" --version 2>/dev/null || true)
case "$NODE_VERSION" in
  "rand-node $EXPECT_NODE_VERSION"*) ;;
  *) if [ "${DRY_RUN:-}" = 1 ]; then echo "cut-chain20: ⚠ DRY RUN with '$NODE_VERSION', not rand-node $EXPECT_NODE_VERSION — the real cut refuses it" >&2
     else [ "${NODE_VERSION_OK:-}" = 1 ] || { echo "cut-chain20: $NODE reports '$NODE_VERSION', not rand-node $EXPECT_NODE_VERSION — NODE_VERSION_OK=1 to cut with it knowingly" >&2; exit 1; }; fi ;;
esac
echo "cut-chain20: cutting with $NODE_VERSION"
load_fee_recipient

TMP=$(mktemp -d); PROBE_PID=; trap 'rm -rf "$TMP"; [ -z "$PROBE_PID" ] || kill "$PROBE_PID" 2>/dev/null || true' EXIT
export TMP

py_validators

args=()
while IFS= read -r l; do args+=("$l"); done < "$TMP/validator-args"
while read -r label addr amount; do
  case "$label" in ''|'#'*) continue;; esac
  args+=(--alloc "$addr=$amount")
done < "$ALLOC_ADDRESSES"
ps_args=()
[ -n "${PROGRAM_STATE_SKIPPED:-}" ] || ps_args=(--program-state-cell-fee "$PROGRAM_STATE_CELL_FEE")

# zUSD genesis notes: fresh openings, sealed to each carried holder (asset 1 = zUSD, 8 decimals).
: > "$TMP/token-notes.jsonl"
while read -r label addr amount; do
  case "$label" in ''|'#'*) continue;; esac
  "$NODE" alloc-note --to "$addr" --amount "$amount" --asset 1 --envelope-bytes "$ENVELOPE_BYTES" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)))' >> "$TMP/token-notes.jsonl"
  echo "cut-chain20: zUSD genesis note, $amount zUSD to $label"
done < "$ZUSD_CARRY"

echo "cut-chain20: writing the base file (its printed hash is NOT chain 20's)"
"$NODE" genesis --chain-id "$CHAIN_ID" "${args[@]}" \
  --max-program-words "$MAX_PROGRAM_WORDS" \
  --max-proof-bytes "$MAX_PROOF_BYTES" \
  --max-block-bytes "$MAX_BLOCK_BYTES" \
  --max-call-envelope-bytes "$MAX_CALL_ENVELOPE_BYTES" \
  --max-program-public-words "$MAX_PROGRAM_PUBLIC_WORDS" \
  --tokens "$TMP/tokens.json" \
  --bundle-guest v3 --auth-guest --hardening-v6 \
  --gas-price "$GAS_PRICE" --byte-price "$BYTE_PRICE" --bundle-gas-limit "$BUNDLE_GAS_LIMIT" --gas-dynamic "$GAS_DYNAMIC" \
  --max-gas-price "$MAX_GAS_PRICE" --max-byte-price "$MAX_BYTE_PRICE" --gas-byte-load "$GAS_BYTE_LOAD" \
  --envelope-bytes "$ENVELOPE_BYTES" \
  --testnet --binding-domain "$BINDING_DOMAIN" --proof-window-blocks "$PROOF_WINDOW_BLOCKS" \
  ${ps_args[@]+"${ps_args[@]}"} \
  --epoch-blocks "$EPOCH_BLOCKS" --faucet --fri-profile production --out "$TMP/genesis.json" | tee "$TMP/genesis.out"

HC_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_bundle',''))" "$TMP/genesis.json")
HC_AUTH_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_auth',''))" "$TMP/genesis.json")
for pair in "hc_bundle:$HC_REPORTED" "hc_auth:$HC_AUTH_REPORTED"; do
  k=${pair%%:*}; v=${pair#*:}
  [ -n "$v" ] || { echo "cut-chain20: the genesis command wrote no $k" >&2; exit 1; }
  said=$(grep -o "$k [0-9a-f]\{64\}" "$TMP/genesis.out" | head -1 | cut -d' ' -f2 || true)
  [ -z "$said" ] || [ "$said" = "$v" ] || { echo "cut-chain20: the genesis command printed $k $said but wrote $v" >&2; exit 1; }
done
echo "cut-chain20: this rand-node reports hc_bundle $HC_REPORTED, hc_auth $HC_AUTH_REPORTED"
export HC_REPORTED
# Built in $TMP; lands at $OUT only once it has passed every check, `init` and the field probe.
FINAL_OUT=$OUT; OUT=$TMP/genesis.json; export OUT

py_splice

INIT=$("$NODE" init --datadir "$TMP/probe" --genesis "$OUT")
echo "$INIT"
HASH=$(printf '%s\n' "$INIT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ -n "$HASH" ] || { echo "cut-chain20: rand-node init printed no genesis hash" >&2; exit 1; }
[ "$HASH" != "$CHAIN19_HASH" ] || { echo "cut-chain20: init derived chain 19's hash" >&2; exit 1; }
grep -q "(chain id $CHAIN_ID)" <<<"$INIT" || { echo "cut-chain20: init does not say chain id $CHAIN_ID" >&2; exit 1; }
# What `init` prints of the new fields: its gas line names the ceilings and the byte load.
grep -qF "ceiling $MAX_GAS_PRICE/$MAX_BYTE_PRICE, byte load paying" <<<"$INIT" \
  || { echo "cut-chain20: init's gas line does not say 'ceiling $MAX_GAS_PRICE/$MAX_BYTE_PRICE, byte load paying'" >&2; exit 1; }
HASH2=$("$NODE" init --datadir "$TMP/probe2" --genesis "$OUT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ "$HASH2" = "$HASH" ] || { echo "cut-chain20: init re-derived $HASH2, first $HASH" >&2; exit 1; }
# `init` prints no line for testnet, binding_domain, proof_window_blocks, admission_by_vote, the
# rotation rules or program_state: the field probe proves each is in the hash instead, and
# `check-limits` reads each back from a running node.
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
    kill -0 "$PROBE_PID" 2>/dev/null || { echo "cut-chain20: the loopback probe node exited: $(tail -3 "$TMP/probe-node.log")" >&2; exit 1; }
    sleep 1
  done
  echo "cut-chain20: loopback probe node up on 127.0.0.1:$RPCP — check-limits:"
  CHECK_RPC=http://127.0.0.1:$RPCP CHECK_GENESIS=$OUT EXPECT_GENESIS_HASH=$HASH py_check_limits
  kill "$PROBE_PID" 2>/dev/null || true; wait "$PROBE_PID" 2>/dev/null || true; PROBE_PID=
fi

[ ! -e "$FINAL_OUT" ] || { echo "cut-chain20: $FINAL_OUT appeared during the cut — refusing to overwrite it" >&2; exit 1; }
cp "$OUT" "$FINAL_OUT"; OUT=$FINAL_OUT
TS=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['timestamp_ms'])" "$OUT")
AGE=$(( ( $(date +%s) * 1000 - TS ) / 1000 ))

cat <<EOF

cut-chain20: wrote $OUT (sha256 $(shasum -a 256 "$OUT" | cut -c1-64))
cut-chain20: genesis hash $HASH
cut-chain20: chain id $CHAIN_ID, hc_bundle $HC_REPORTED (guest v3), hc_auth $HC_AUTH_REPORTED, hardening_v6, consensus_domain 1, no aggregation, no vesting
cut-chain20: testnet: true; binding_domain: $BINDING_DOMAIN; proof_window_blocks: $PROOF_WINDOW_BLOCKS
cut-chain20: gas: $GAS_PRICE/gas, $BYTE_PRICE/KiB, bundle limit $BUNDLE_GAS_LIMIT, dynamic $GAS_DYNAMIC, ceilings $MAX_GAS_PRICE/$MAX_BYTE_PRICE, byte load $GAS_BYTE_LOAD
cut-chain20: envelope_bytes $ENVELOPE_BYTES — every genesis note sealed in the 1 860-B form
cut-chain20: bridge.fees: mint $BRIDGE_MINT_BPS bps, burn $BRIDGE_BURN_BPS bps, recipient fingerprint $FEE_RECIPIENT_FINGERPRINT (from $FEE_RECIPIENT_FILE)
cut-chain20: staking: chain 19's + max_stake_entry_bps_per_epoch $STAKE_ENTRY_BPS, admission_by_vote; no slashing
cut-chain20: program_state: $([ -n "${PROGRAM_STATE_SKIPPED:-}" ] && echo "SKIPPED (this binary lacks RPL-2) — NOT what chain 20 will be" || echo "cell_fee $PROGRAM_STATE_CELL_FEE")
cut-chain20: 26 validators × $STAKE_RAND RAND (quorum 18); faucet minters: $FAUCET_MINTERS
cut-chain20: bridge: $(python3 -c "import json,sys;b=json.load(open(sys.argv[1]))['bridge'];print('emitters', json.dumps(b['emitters'], sort_keys=True), '| min_inbound_sequence', json.dumps(b['min_inbound_sequence'], sort_keys=True), '| burn_sequence', b['burn_sequence'], '| guardian set', b['guardian_set_index'], '| rotation', json.dumps(b['rotation']))" "$OUT")
cut-chain20: NOT carried: shielded notes of wallets the operator does not hold, and any unwithdrawn validator rewards — the cut record's drops: line.
cut-chain20: next: the second operator rebuilds the hash from this file on another machine and writes \`second-hash: $HASH\` into $CUT_RECORD — deploy/cutover-fleet-chain20.sh push refuses without it.
cut-chain20: after launch: NODE=… $0 check-limits <first node's RPC> $OUT

⚠  Stamped $AGE s ago; the chain's clock starts there. Launch within MINUTES, or delete $OUT and re-cut.
EOF
[ "${DRY_RUN:-}" != 1 ] || echo "cut-chain20: DRY RUN — every step above ran on synthetic inputs; $OUT is NOT chain 20, launch nothing from it.$([ -n "${PROGRAM_STATE_SKIPPED:-}" ] && echo ' ⚠ PROGRAM_STATE SKIPPED.')"
