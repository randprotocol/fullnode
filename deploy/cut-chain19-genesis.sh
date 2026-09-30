#!/usr/bin/env bash
# Cut the chain-19 genesis: a PURE RE-GENESIS of chain 18 — the same software (v0.6.7, constraint
# set 8), the same shape, the same 26 validators — whose only intended difference is the bridge
# section: the Ethereum, BNB Chain and Tron endpoints redeployed on 2026-09-30 (bridge repo
# docs/mainnet-deployment.md "Endpoint redeploy") become the emitters chain 19 trusts.
#
#   deploy/cut-chain19-genesis.sh snapshot <dir>     # chain 18 still up, bridge daemons stopped
#   WALLET=<v0.6.7 rand> deploy/cut-chain19-genesis.sh balances <dir>
#                                                    # read-only: the RAND carry list (chain 18's own build)
#   CHAIN18_SNAPSHOT=<dir> NODE=<v0.6.7 rand-node> WALLET=<v0.6.7 rand> \
#     MIN_INBOUND_2=1 MIN_INBOUND_3=1 MIN_INBOUND_4=1 deploy/cut-chain19-genesis.sh
#   SELFTEST=1 deploy/cut-chain19-genesis.sh         # no network, no binaries: the assembly on fixtures
#   DRY_RUN=1 NODE=… WALLET=… deploy/cut-chain19-genesis.sh
#                                                    # no network: the REAL cut path (rand-node genesis,
#                                                    # alloc-note, init) on inputs synthesised from the
#                                                    # committed chain-18 genesis; writes to a temp dir
#
# DERIVED from deploy/cut-chain18-genesis.sh (chain 18 — v0.6.7-rc1 at its cut, v0.6.7 since, live
# since 2026-09-29 04:56 UTC, genesis a7cb020c…4da76 — is chain 19's predecessor): the same snapshot
# / balances / carry-over rule / splice, with chain 18 as the source. Read it first. What this
# script does that chain 18's did not:
#   - THE NEW EMITTERS ARE THE DEFAULTS, AND PINNED. EMITTER_2/3/4 default to the 2026-09-30
#     endpoints (R19_EMITTER_* below) and the script refuses to run if any EMITTER_<c> is not
#     exactly its pin, unless EMITTERS_CHANGED=1 says so knowingly. EMITTER_5 (Solana, not
#     redeployed) stays chain 18's.
#   - A redeployed endpoint has no `auto` floor: the cut refuses without an explicit
#     MIN_INBOUND_2, MIN_INBOUND_3 and MIN_INBOUND_4 (chain 18's rule, "a changed emitter"). The
#     expected values are 1, 1, 1: each new endpoint's sequence 0 is the operator's consume-step
#     lock (it re-locks exactly what a replayed release then pays out), which must never mint.
#     Solana's floor stays `auto` = its next sequence at the snapshot (4 expected), never below
#     chain 18's own floor (2). `snapshot` and `balances` need none of these.
#   - A floor ABOVE a redeployed endpoint's next sequence (the consume step has not run yet, so the
#     endpoint still reads sequence 0 and the floor is 1) is refused unless FLOOR_AHEAD_OK=1: the
#     sequences below the floor then never mint whatever lock takes them. On an unchanged endpoint
#     it is refused outright, as on chain 18.
#   - The gas section and `envelope_bytes` are no longer new: both are asserted EQUAL to chain
#     18's (GAS_CHANGED=1 to move the gas section knowingly), and every top-level field outside
#     chain_id / timestamp_ms / alloc / bridge / tokens is asserted byte-equal to chain 18's genesis.
#   - One build cuts, scans and runs: `balances`, the cut and the fleet all use v0.6.7 (no new
#     release, no new constraint set). NODE must report 0.6.7 (NODE_VERSION_OK=1 to override).
#
# Traps carried from the chain-18 cut (AGENTS.md "Chain 18 — LIVE"):
#   - `balances` scans CURATED directories of wallet key files, `$WALLETS_DIRS` =
#     ~/.rand-chain17/alloc-wallets (symlinks: shielded-1..5 and the relayer — the six chain-18
#     genesis allocs; the relayer's link went missing once, and the scan then lists its alloc as
#     "uncovered" and the cut refuses) and ~/.rand-chain18/wallets (wallets made on chain 18).
#     Never a checkout's `wallets/`. CHECK BEFORE THE SCAN that every wallet holding RAND on chain 18
#     has its key file (or a symlink) in one of them.
#   - `balances` refuses to overwrite <dir>/balances.json and $ALLOC_ADDRESSES: move a first scan
#     aside to re-scan.
#   - The public RPC (Cloudflare) answers Python's urllib with 403: point CHAIN18_RPC at an SSH
#     tunnel to obs1's RPC (the archive, `prune_floor` 0), e.g.
#     `ssh -N -L 8545:127.0.0.1:8545 root@168.144.46.203` → CHAIN18_RPC=http://127.0.0.1:8545.
#     That tunnel died twice in the hour of the chain-18 cut (once silently): `curl` the port right
#     before `snapshot` and before `balances`, and re-open it.
#   - Take the snapshot with the SAME EMITTER_* the cut uses (the defaults): custody and sequences
#     are read at those addresses, and the cut refuses a snapshot read anywhere else.
#
# What chain 19 is, against chain 18:
#
#   * `rand-node genesis --hardening-v6 --bundle-guest v3 --auth-guest --gas-price 100 --byte-price
#     800 --bundle-gas-limit 20479 --gas-dynamic 10485760,262144,1250 --envelope-bytes 1860`: chain
#     18's flags, unchanged. `hc_bundle` (bundle guest v3 60af094a… — EXPECT_HC_BUNDLE) and `hc_auth`
#     (1e4e347f…39c1 — EXPECT_HC_AUTH) are asserted EQUAL to chain 18's, as are the gas section
#     (Phase 1 prices 100/800, the bundle pin 20 479, the Phase 2 controller at half the 20 MiB
#     block cap / 2^18 gas / 12.5% a step, floors = the starting prices), `envelope_bytes` 1860 (the
#     encrypted memo; every alloc note, RAND and zUSD, sealed in the 1 860-B form) and the caps
#     (4 MiB proofs, 20 MiB blocks). No `aggregation` section (`GenesisError::
#     DynamicGasWithAggregation`).
#   * The build does not change, so nothing about the fleet's binaries changes: a v0.6.7 node runs
#     chain 19 as it runs chain 18 (its refuse-list, `node::CHAINS_THIS_BUILD_CANNOT_RUN`, names
#     chains 14–17 by hash; the wallet's `LEGACY_ENVELOPE_CHAIN_IDS` names 14–17 by id). The roll is
#     still all-stop/all-start (deploy/cutover-fleet-chain19.sh): a new genesis is a new chain.
#   * The 26 validators chain 18 runs, on the same keys (the 18 of $VALIDATORS_TSV and the 8 of
#     $REGISTRATIONS, the assembly chain 18's script used), each with the stake chain 18's REGISTER
#     holds at the snapshot — asserted equal to $STAKE_RAND, not assumed, with no pending unbond.
#     The register must hold exactly these 26 (a validator bonded on chain 18 after genesis is refused
#     here: decide by hand whether chain 19 carries it).
#   * staking, tokens, limits: chain 18's genesis sections, each asserted against the live chain;
#     `faucet_minters` the 18 operator keys ($FAUCET_MINTERS, names).
#   * bridge: chain 18's LIVE guardian set, PQ set, pause key, rules_v2 and burn sequence (8
#     expected; a rotation on chain 18 is refused unless BRIDGE_ROTATED=1), the Rand-side `emitter`
#     unchanged, and the source table `emitters` = EMITTER_2..5 (above). `min_inbound_sequence`:
#     per unchanged source (Solana) the endpoint's next outbound sequence at the snapshot (every
#     lock it emitted minted on chain 14..18 — the custody == locked check below fails if one was
#     not), never below chain 18's own floor, cross-checked against the relayer's done/<chain>/
#     records when RELAYER_DONE_DIR is given; per redeployed source the explicit MIN_INBOUND_<c>.
#     The snapshot reads custody at the NEW endpoints for chains 2/3/4: each must equal chain 18's
#     per-backing `locked` (0 expected — the old Tron endpoint's 9 USDT was rebalanced through
#     Solana on 2026-09-30, so locked is Solana-USDT 10 and nothing else).
#   * THE CARRY-OVER RULE. Chain 19 starts from chain 18's value, but only value whose opening the
#     operator can re-issue:
#       - zUSD: per-backing `locked` = chain 18's at the snapshot, and one fresh genesis note per line
#         of $ZUSD_CARRY (`rand-node alloc-note --asset 1`); Σ notes == Σ locked == source custody.
#       - RAND: every wallet the operator holds (the `balances` step scans each key file under
#         $WALLETS_DIRS on chain 18 and writes $ALLOC_ADDRESSES) gets one genesis alloc note of its
#         chain-18 balance to the same address; Σ alloc == Σ scanned is asserted. `balances` also
#         decodes chain 18's own genesis alloc notes' `pk` and lists any that match none of the
#         scanned wallets ("uncovered genesis allocs"); the cut refuses while that list is
#         non-empty (UNCOVERED_ALLOCS_OK=1 to drop them knowingly). A wallet's pending notes
#         (submitted, not yet confirmed) are refused too (PENDING_OK=1 to drop them). `balances`
#         also refuses against a pruned $CHAIN18_RPC (an archive is needed for a full scan).
#       - vesting: chain 18's genesis `vesting` section, if any (it has none), re-emitted with each
#         entry's claimed amount subtracted (rand_getVesting at the snapshot); verbatim with a
#         warning if the RPC lacks it. THIS IS AN APPROXIMATION: the mathematically right carry is
#         `A·f(t) − C` (`A` = amount, `C` = claimed, `f` = the vesting curve), which the genesis
#         format cannot express without a `claimed` field. Carrying `(A − C)` on the same schedule
#         instead front-loads `C·(1 − f(t))` — that much unlocks early — so an entry with
#         `claimed > 0` is refused unless VESTING_CLAIMED_OK=1 accepts the approximation.
#       - a validator with unwithdrawn `rewards` on chain 18 is refused (withdraw before the cut,
#         or REWARDS_DROPPED_OK=1 to drop them — rewards are NOT carried either way).
#       - SHIELDED NOTES OF WALLETS THE OPERATOR DOES NOT HOLD ARE NOT CARRIED: a genesis alloc note
#         needs an opening, which only the holder (or the cut, for a note it makes itself) has. The
#         launch notes must say so. (Faucet mints to third-party wallets on chain 18 are such notes.)
#
# The `snapshot` step is read-only (JSON-RPC reads of chain 18 and of the four source chains) and is
# taken AFTER the relayer and every guardian have stopped and BEFORE chain 18 stops; `balances` right
# after it (it only syncs note stores next to the operator's key files). Every value the cut
# defaults is checked against the snapshot, not trusted.
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash (fresh note randomness and a
# fresh timestamp). Cut once, distribute the file byte-identically, launch within minutes.
set -euo pipefail
cd "$(dirname "$0")/.."
FULLNODE_DIR=${FULLNODE_DIR:-$(pwd)}    # the repo root the line above just cd'd into ($(cd "$(dirname "$0")/.." && pwd), pre-computed)
. deploy/lib/key-guard.sh

NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
CHAIN_ID=${CHAIN_ID:-19}
OUT=${OUT:-deploy/genesis-chain19.json}
CHAIN18_GENESIS=${CHAIN18_GENESIS:-deploy/genesis-chain18.json}
CHAIN18_HASH=${CHAIN18_HASH:-a7cb020cc99a33c83fc38cfa0ec1db357f67fbf8b6dab13ab1d9812280b4da76}
CHAIN18_GENESIS_SHA256=${CHAIN18_GENESIS_SHA256:-ffeb68f05e8b7bfa4196833340786a744fd1803e57a91d30c19b80b6529da4d7}
CHAIN18_RPC=${CHAIN18_RPC:-http://127.0.0.1:8545}          # snapshot/balances: an SSH tunnel to obs1's RPC (the archive; Cloudflare 403s urllib)
CHAIN18_SNAPSHOT=${CHAIN18_SNAPSHOT:-}                       # the cut: the snapshot directory

# ── public inputs, all outside the repository ─────────────────────────────────────────────────
VALIDATORS_TSV=${VALIDATORS_TSV:-$HOME/.rand-chain14/public/validators.tsv}   # name addr pk peer payout (18)
REGISTRATIONS=${REGISTRATIONS:-$HOME/.rand-chain15/registrations}              # <name>.txt, one per bonded validator (8)
BONDED=${BONDED:-obs1 archive2 g1 g2 g3 g4 g5 g6}
GENESIS_NAMES=${GENESIS_NAMES:-a b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1}
FAUCET_MINTERS=${FAUCET_MINTERS:-$GENESIS_NAMES}   # chain 18's list; another one needs FAUCET_MINTERS_CHANGED=1
FAUCET_RECIPIENTS=${FAUCET_RECIPIENTS:-}           # unset: chain 18's genesis allowlist; a file ("<name> rand1…") changes it
STAKE_RAND=${STAKE_RAND:-1000}
ALLOC_ADDRESSES=${ALLOC_ADDRESSES:-$HOME/.rand-chain19/alloc-rand.txt}   # "<label> rand1… <RAND>" per line (`balances` writes it)
ZUSD_CARRY=${ZUSD_CARRY:-$HOME/.rand-chain19/zusd-carry.txt}             # "<label> rand1… <zUSD>" per line
WALLETS_DIRS=${WALLETS_DIRS:-$HOME/.rand-chain17/alloc-wallets $HOME/.rand-chain18/wallets}   # `balances`: dirs of *.key.json (a missing dir is skipped, printed, never an error) — the curated symlink dir the chain-17 and chain-18 cuts used (shielded-1..5, the relayer: chain 18's six genesis allocs) and the wallets made on chain 18; never a checkout's wallets/
RELAYER_DONE_DIR=${RELAYER_DONE_DIR:-}             # optional: the relayer's done/ (done/<chain>/<seq>), a floor cross-check
EXPECT_HC_BUNDLE=${EXPECT_HC_BUNDLE:-60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce}   # v3
EXPECT_HC_AUTH=${EXPECT_HC_AUTH:-1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1}   # guest_provenance.rs's auth pin; cross-checked against the binary

# ── chain 18's limits (asserted equal to its genesis unless LIMITS_CHANGED=1) ───────────────────
MAX_PROGRAM_WORDS=${MAX_PROGRAM_WORDS:-65535}
MAX_PROOF_BYTES=${MAX_PROOF_BYTES:-4194304}   # 4 MiB, chain 18's: a v3 transaction carries up to THREE proofs (bundle ~1.5 MB + auth ~1.36 MB + call) and Genesis::validate requires max_block_bytes >= 3*max_proof_bytes + 1 MiB with hc_auth (3*4+1 = 13 <= 20)
MAX_BLOCK_BYTES=${MAX_BLOCK_BYTES:-20971520}
MAX_CALL_ENVELOPE_BYTES=${MAX_CALL_ENVELOPE_BYTES:-65536}
MAX_PROGRAM_PUBLIC_WORDS=${MAX_PROGRAM_PUBLIC_WORDS:-32768}
EPOCH_BLOCKS=${EPOCH_BLOCKS:-1000}

# ── the source endpoints chain 18 trusts (its genesis `bridge.emitters`, re-checked below) ─────
C18_EMITTER_2=000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892   # Ethereum
C18_EMITTER_3=000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892   # BNB Chain
C18_EMITTER_4=0000000000000000000000000992df85dcce77ded2c0387f1fa9cf98ac859700   # Tron
C18_EMITTER_5=d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a   # Solana
# ── the source endpoints chain 19 trusts: the 2026-09-30 redeploy (Ethereum, BNB Chain, Tron —
# bridge repo docs/mainnet-deployment.md "Endpoint redeploy"); Solana's program is unchanged ─────
R19_EMITTER_2=0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa   # Ethereum  0x7aF6b17047C1db6cB54347FdEa45cF9179075bfA
R19_EMITTER_3=0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa   # BNB Chain 0x7aF6b17047C1db6cB54347FdEa45cF9179075bfA
R19_EMITTER_4=0000000000000000000000006410797df959987a5baf65b5fab97edeb34d5163   # Tron      TK6JJv55CCkFjNHq7WwoU91GKaZEiC93me
R19_EMITTER_5=$C18_EMITTER_5                                                     # Solana, not redeployed
EMITTER_2=${EMITTER_2:-$R19_EMITTER_2}
EMITTER_3=${EMITTER_3:-$R19_EMITTER_3}
EMITTER_4=${EMITTER_4:-$R19_EMITTER_4}
EMITTER_5=${EMITTER_5:-$R19_EMITTER_5}
# The emitter table is the one thing this genesis changes, so it is pinned: any other value is
# refused before anything runs unless EMITTERS_CHANGED=1 says the pin above is out of date.
for c in 2 3 4 5; do
  e=EMITTER_$c; r=R19_EMITTER_$c
  [ "${!e}" = "${!r}" ] || [ "${EMITTERS_CHANGED:-}" = 1 ] || {
    echo "cut-chain19: EMITTER_$c=${!e} is not the chain-19 endpoint ${!r} (the 2026-09-30 redeploy; Solana unchanged) — set EMITTERS_CHANGED=1 only if that pin is knowingly out of date" >&2; exit 1; }
done
# The fixture modes cut no chain: their floors default to the expected ones (1 for each redeployed
# endpoint). The real cut gets no such default — see the guard below.
if [ "${SELFTEST:-}" = 1 ] || [ "${DRY_RUN:-}" = 1 ]; then
  for c in 2 3 4; do v=MIN_INBOUND_$c; [ -n "${!v:-}" ] || printf -v "$v" 1; done
fi
# C15-1: `auto` (the default, unchanged emitter only) = the endpoint's next sequence at the snapshot;
# a number = that floor; `none` = no floor (a fresh, redeployed endpoint only). `snapshot` and
# `balances` read no floor, so the guard is the cut's alone.
for c in 2 3 4 5; do
  v=MIN_INBOUND_$c; e=EMITTER_$c; o=C18_EMITTER_$c
  if [ -z "${!v:-}" ]; then
    case "${1:-}" in snapshot|balances) printf -v "$v" unset; continue;; esac
    [ "${!e}" = "${!o}" ] || { echo "cut-chain19: EMITTER_$c is not chain 18's endpoint (the redeploy) — set MIN_INBOUND_$c explicitly (last minted + 1: 1 once the operator's consume-step lock has taken sequence 0; or none)" >&2; exit 1; }
    printf -v "$v" auto
  fi
done
# What the cut is expected to derive (bridge repo docs/mainnet-deployment.md, 2026-09-30); a
# different result is printed as a warning, never refused — a live bridge legitimately moves these.
EXPECT_FLOORS=${EXPECT_FLOORS:-2:1 3:1 4:1 5:4}
EXPECT_BURN_SEQUENCE=${EXPECT_BURN_SEQUENCE:-8}
ETH_RPC=${ETH_RPC:-https://ethereum-rpc.publicnode.com}
BSC_RPC=${BSC_RPC:-https://bsc-rpc.publicnode.com}
TRON_API=${TRON_API:-https://api.trongrid.io}
SOL_RPC=${SOL_RPC:-https://api.mainnet-beta.solana.com}
SOL_PROGRAM=${SOL_PROGRAM:-FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu}

# ── gas (spec §4.2, §7.1): chain 18's section, unchanged — Phase 1 prices + the Phase 2 controller ─
GAS_PRICE=${GAS_PRICE:-100}
BYTE_PRICE=${BYTE_PRICE:-800}
# Every bundle proof declares exactly this (spec §4.3): the bundle guest's header ceiling
# gas_max(14, 0, 0) = (2^14 − 1) + 2^12 = 20 479 — v3 included (tier 14, no hash table); the genesis
# refuses any other value (`gas::bundle_gas_limit_pin`). The auth proof's pin (1 279) is a fixed
# rule with no genesis field.
BUNDLE_GAS_LIMIT=${BUNDLE_GAS_LIMIT:-20479}
# target_block_bytes,target_block_gas,adjust_bps — half the block cap in bytes (MAX_BLOCK_BYTES / 2
# = 10 485 760 for chain 18's 20 MiB: a block can be at most twice the target, so an over-full block
# and an empty one move byte_price by the same 12.5%; next_price also caps `used` at 2·target), 2^18
# gas, 12.5% a step; the floors are the starting prices above (rand-node genesis's own rule).
GAS_DYNAMIC=${GAS_DYNAMIC:-$((MAX_BLOCK_BYTES / 2)),262144,1250}
# The encrypted memo (v0.5.10, spec 2026-09-26 §2.4): every note envelope exactly this many bytes.
ENVELOPE_BYTES=${ENVELOPE_BYTES:-1860}

export CHAIN_ID CHAIN18_GENESIS CHAIN18_HASH CHAIN18_GENESIS_SHA256 CHAIN18_RPC VALIDATORS_TSV REGISTRATIONS BONDED GENESIS_NAMES \
  FAUCET_MINTERS FAUCET_RECIPIENTS STAKE_RAND ALLOC_ADDRESSES ZUSD_CARRY WALLETS_DIRS RELAYER_DONE_DIR EXPECT_HC_BUNDLE \
  EXPECT_HC_AUTH MAX_PROGRAM_WORDS MAX_PROOF_BYTES MAX_BLOCK_BYTES MAX_CALL_ENVELOPE_BYTES \
  MAX_PROGRAM_PUBLIC_WORDS EPOCH_BLOCKS EMITTER_2 EMITTER_3 EMITTER_4 EMITTER_5 C18_EMITTER_2 C18_EMITTER_3 \
  C18_EMITTER_4 C18_EMITTER_5 R19_EMITTER_2 R19_EMITTER_3 R19_EMITTER_4 R19_EMITTER_5 EXPECT_FLOORS EXPECT_BURN_SEQUENCE MIN_INBOUND_2 MIN_INBOUND_3 MIN_INBOUND_4 MIN_INBOUND_5 ETH_RPC BSC_RPC \
  TRON_API SOL_RPC SOL_PROGRAM GAS_PRICE BYTE_PRICE BUNDLE_GAS_LIMIT GAS_DYNAMIC ENVELOPE_BYTES

# Decimal RAND/zUSD text → base units, the exact rule of `parse_amount` (no float anywhere).
# shellcheck disable=SC2089,SC2090  # python source in a string, exported whole, never word-split
UNITS_PY='
def units(s, decimals=9):
    s = s.strip()
    whole, _, frac = s.partition(".")
    if len(frac) > decimals or not (whole or frac) or not (whole or "0").isdigit() or not (frac or "0").isdigit():
        raise SystemExit(f"cut-chain19: {s!r} is not an amount with at most {decimals} decimals")
    return int(whole or 0) * 10**decimals + int((frac or "").ljust(decimals, "0") or 0)
def alloc_lines(path):
    rows = []
    for line in open(path):
        f = line.split()
        if not f or f[0].startswith("#"):
            continue
        if len(f) != 3 or not f[1].startswith("rand1"):
            raise SystemExit(f"cut-chain19: {path}: {line.rstrip()!r} is not \"<label> rand1… <amount>\"")
        rows.append((f[0], f[1], f[2]))
    return rows
'
# shellcheck disable=SC2090
export UNITS_PY

# ══ snapshot: read-only reads of chain 18 and of the source endpoints ═════════════════════════
py_snapshot() {
  python3 - <<'PY'
import base64, hashlib, json, os, struct, sys, time, urllib.request, urllib.error
E = os.environ
sha = hashlib.sha256(open(E["CHAIN18_GENESIS"], "rb").read()).hexdigest()
if sha != E["CHAIN18_GENESIS_SHA256"]:
    sys.exit(f"cut-chain19: {E['CHAIN18_GENESIS']} is not chain 18's committed genesis file "
             f"(sha256 {sha[:8]}…, expected {E['CHAIN18_GENESIS_SHA256'][:8]}…)")
g18 = json.load(open(E["CHAIN18_GENESIS"]))
BACKINGS = g18["tokens"]["tokens"][0]["backings"]

def post(url, body, headers=None):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json", "user-agent": "rand-cut-chain19/1", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def rand_raw(method, params=None):
    return post(E["CHAIN18_RPC"], {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})

def rand(method, params=None):
    r = rand_raw(method, params)
    if "error" in r:
        sys.exit(f"cut-chain19: {method}: {r['error']}")
    return r["result"]

def eth_call(url, to, data):
    r = post(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": to, "data": data}, "latest"]})
    if "error" in r:
        sys.exit(f"cut-chain19: eth_call {to} on {url}: {r['error']}")
    return int(r["result"], 16)

def tron(contract41, selector, param=""):
    r = post(E["TRON_API"] + "/wallet/triggerconstantcontract",
             {"owner_address": E["TRON_ENDPOINT41"], "contract_address": contract41,
              "function_selector": selector, "parameter": param})
    if not r.get("constant_result"):
        sys.exit(f"cut-chain19: Tron {selector} on {contract41}: {r}")
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
        sys.exit(f"cut-chain19: Solana getProgramAccounts: {r['error']}")
    return [base64.b64decode(a["account"]["data"][0]) for a in r["result"]]

snap = {"taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
snap["genesis_hash"] = rand("rand_getGenesisHash")
if snap["genesis_hash"] != E["CHAIN18_HASH"]:
    sys.exit(f"cut-chain19: {E['CHAIN18_RPC']} serves {snap['genesis_hash']}, not chain 18")
snap["status_height"] = rand("rand_status")["height"]
snap["validators"] = rand("rand_getValidators")
snap["bridge"] = rand("rand_getBridgeState")
snap["tokens"] = rand("rand_getTokens")
snap["supply"] = rand("rand_getSupply")

# ── the vesting register (v0.5.11): only when chain 18's genesis has a section ────────────────
VESTING_ENTRY_KEYS = {"amount", "claimed", "revoked_at", "revoked_out", "bonded", "unbonding"}
if g18.get("vesting"):
    entries, unavailable = {}, None
    for e in g18["vesting"]["entries"]:
        r = rand_raw("rand_getVesting", [e["id"]])
        if "error" in r:
            unavailable = f"rand_getVesting: {r['error']}"
            break
        res = r.get("result")
        # A disabled or reshaped register ({"enabled": false}, or any answer missing the fields
        # the cut reads) is treated the same as an RPC error: a clean "copy verbatim" fallback,
        # never a KeyError deep in the splice step.
        if not isinstance(res, dict) or not VESTING_ENTRY_KEYS.issubset(res):
            unavailable = f"rand_getVesting: unexpected answer {res!r}"
            break
        entries[e["id"]] = res
    snap["vesting"] = {"unavailable": unavailable} if unavailable else {"entries": entries}
    print(f"cut-chain19: vesting register: {unavailable or f'{len(entries)} entries read'}")
else:
    snap["vesting"] = None     # chain 18 has no vesting section: nothing to carry

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
    sys.exit(f"cut-chain19: {len(cfgs)} Solana config accounts, expected 1")
off = 1 + 32 * 3 + 1 + 32 + 4
seq["5"] = struct.unpack_from("<Q", cfgs[0], off)[0]
for acc in sol_accounts("4"):
    mint = acc[1:33].hex()
    cu, fe = struct.unpack_from("<QQ", acc, 1 + 32 + 2 + 8 * 4)
    custody[f"5:{mint}"] = {"custody": cu, "fees": fe, "mint": b58(acc[1:33])}
snap["source"] = {"emitters": {c: E[f"EMITTER_{c}"] for c in "2345"}, "next_sequence": seq, "custody": custody}
json.dump(snap, open(os.path.join(E["SNAP"], "chain18-state.json"), "w"), indent=1)
print(f"cut-chain19: snapshot of chain 18 at height {snap['status_height']} → {E['SNAP']}/chain18-state.json")
print(f"cut-chain19: source next sequences {seq}; burn_sequence {snap['bridge']['burn_sequence']}; "
      f"zUSD supply {snap['tokens']['tokens'][0]['total_supply']}")
for k, v in custody.items():
    if v["custody"]:
        print(f"cut-chain19: custody {k[:2]}…{k[-8:]} = {v['custody']}")
PY
}

# ══ balances: every wallet the operator holds, scanned on chain 18 → the RAND carry list ══════
# Read-only toward the chain; it does write each wallet's note store (<key>.notes.json) as any
# `rand sync` does. The key files are opened by `rand` only — this script never reads them.
py_balances() {
  python3 - <<'PY'
import glob, json, os, re, subprocess, sys, time, urllib.request
E = os.environ
exec(E["UNITS_PY"])
def rpc(method):
    req = urllib.request.Request(E["CHAIN18_RPC"], json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode(),
                                 {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["result"]
if rpc("rand_getGenesisHash") != E["CHAIN18_HASH"]:
    sys.exit(f"cut-chain19: {E['CHAIN18_RPC']} is not chain 18")
status0 = rpc("rand_status")
if int(status0.get("prune_floor", 0) or 0) > 0:
    sys.exit(f"cut-chain19: {E['CHAIN18_RPC']} is pruned (prune_floor {status0['prune_floor']}) — "
             f"`balances` needs a full scan; point CHAIN18_RPC at an archive (obs1, rand-archive-2)")
def rand(key, *args):
    p = subprocess.run([E["WALLET"], "--rpc", E["CHAIN18_RPC"], "--key", key, *args], capture_output=True, text=True)
    if p.stderr.strip():
        print(p.stderr.strip(), file=sys.stderr)   # RS-1's pruned-node warning and friends: never swallowed
    if p.returncode != 0:
        sys.exit(f"cut-chain19: rand {' '.join(args)} for {key}: {p.stderr.strip()}")
    return p.stdout
files = []
for d in E["WALLETS_DIRS"].split():
    if os.path.isdir(d):
        files += sorted(glob.glob(os.path.join(d, "*.key.json")))
    else:
        print(f"cut-chain19: {d} does not exist — skipped")
if not files:
    sys.exit("cut-chain19: no *.key.json under WALLETS_DIRS")
height0 = status0["height"]
by_addr, pending_by_wallet = {}, []
for f in files:
    label = os.path.basename(f)[: -len(".key.json")]
    addr = rand(f, "address").splitlines()[0].strip()
    rand(f, "sync")
    out = rand(f, "balance")
    line = next((l for l in out.splitlines() if l.startswith("balance: ") and l.endswith(" RAND")), None)
    if line is None:
        sys.exit(f"cut-chain19: could not read a balance for {f}: {out!r}")
    ru = units(line[len("balance: "):-len(" RAND")])
    zo = rand(f, "asset-balance", "1").strip()
    zu = int(zo.split()[2]) if zo.startswith("asset 1: ") else 0
    # `notes` breaks every row out (including a `pending` column); a note held pending (submitted,
    # not yet confirmed) does not count toward `balance` and would otherwise vanish from the carry
    # with no trace.
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
        sys.exit(f"cut-chain19: {prev['file']} and {f} are one address with different balances — reconcile the note stores")
    if not prev:
        by_addr[addr] = row
    print(f"cut-chain19:   {label:<24} {ru / 1e9:>16.9f} RAND  {zu:>12} zUSD units{'  (duplicate key file)' if prev else ''}")
height1 = rpc("rand_status")["height"]
if pending_by_wallet and not E.get("PENDING_OK"):
    detail = "; ".join(f"{label}: " + ", ".join(f"asset {a} amount {amt} ({since})" for a, amt, since in rows) for label, rows in pending_by_wallet)
    sys.exit(f"cut-chain19: pending note(s) would be dropped from the carry silently: {detail} — wait for them to "
             f"clear (or fail) and re-run, or set PENDING_OK=1 to drop them")
elif pending_by_wallet:
    detail = "; ".join(f"{label}: " + ", ".join(f"asset {a} amount {amt}" for a, amt, _ in rows) for label, rows in pending_by_wallet)
    print(f"cut-chain19: ⚠ dropping pending note(s) (PENDING_OK=1): {detail}")
rows = sorted(by_addr.values(), key=lambda r: r["label"])
carry = [r for r in rows if r["rand_units"] > 0]
labels = [r["label"] for r in carry]
if len(set(labels)) != len(labels):
    sys.exit("cut-chain19: two wallets with one label — rename a key file")
total = sum(r["rand_units"] for r in carry)

# ── chain 18's own genesis alloc notes this scan does not cover ────────────────────────────────
# A genesis alloc note's owner is `opening.pk` (32 raw bytes); a shielded address is
# "rand1" + base58(pk || kem_ek), so decoding a scanned wallet's address and comparing its first
# 32 bytes finds every alloc this operator can still open.
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            sys.exit(f"cut-chain19: {s!r} is not base58")
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
g18 = json.load(open(E["CHAIN18_GENESIS"]))
alloc_pks = {n["opening"]["pk"]: n["amount"] for n in g18["alloc"] if n.get("opening", {}).get("asset", 0) == 0}
uncovered = [{"pk": pk, "amount": amt} for pk, amt in alloc_pks.items() if pk not in scanned_pks]
if uncovered:
    print("cut-chain19: uncovered genesis allocs (no scanned wallet's pk matches — the cut refuses "
          "unless UNCOVERED_ALLOCS_OK=1): " + ", ".join(f"{u['pk'][:12]}… ({u['amount']})" for u in uncovered))

json.dump({"chain18_hash": E["CHAIN18_HASH"], "taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "height_from": height0, "height_to": height1, "wallets": rows, "carried_rand_units": total,
           "uncovered_genesis_allocs": uncovered},
          open(os.path.join(E["SNAP"], "balances.json"), "w"), indent=1)
def fmt(u):
    w, f = divmod(u, 10**9)
    return f"{w}" if not f else f"{w}.{f:09d}".rstrip("0")
os.makedirs(os.path.dirname(E["ALLOC_ADDRESSES"]) or ".", exist_ok=True)
with open(E["ALLOC_ADDRESSES"], "w") as out:
    out.write(f"# chain-19 RAND carry: chain-18 balances at heights {height0}..{height1}, `balances` step\n")
    for r in carry:
        out.write(f"{r['label']} {r['address']} {fmt(r['rand_units'])}\n")
print(f"cut-chain19: {len(carry)} wallet(s) with RAND, Σ {fmt(total)} RAND → {E['ALLOC_ADDRESSES']} (+ {E['SNAP']}/balances.json)")
z = [r for r in rows if r["zusd_units"]]
if z:
    op_total = sum(r["zusd_units"] for r in z)
    print(f"cut-chain19: zUSD held by operator wallets: " + ", ".join(f"{r['label']} {r['zusd_units']}" for r in z) + f" (Σ {op_total})")
    if os.path.isfile(E["ZUSD_CARRY"]):
        carry_total = sum(units(a, 8) for _, _, a in alloc_lines(E["ZUSD_CARRY"]))
        if carry_total != op_total:
            print(f"cut-chain19: ⚠ Σ operator-wallet zUSD ({op_total}) != Σ ZUSD_CARRY ({carry_total}) — "
                  f"a non-operator holder (e.g. Anish's wallet) legitimately differs; verify by hand")
PY
}

# ══ the cut, step 1: the validators, from the chain-18 register ═══════════════════════════════
py_validators() {
  python3 - <<'PY'
import json, os, sys
E = os.environ
need = lambda c, m: c or sys.exit(f"cut-chain19: {m}")
snap = json.load(open(E["SNAPSHOT_FILE"]))
g18 = json.load(open(E["CHAIN18_GENESIS"]))
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
    need(addr in register, f"{name} ({addr}) is not in chain 18's register")
    rows.append({"name": name, "address": addr, "public_key": raw[8:8 + n].hex(), "payout": register[addr]["payout"]})
stake = int(E["STAKE_RAND"]) * 10**9
need(len(rows) == len(register) == 26, f"{len(rows)} validators assembled, chain 18's register holds {len(register)}")
for r in rows:
    live = register.get(r["address"])
    need(live is not None, f"{r['name']} ({r['address']}) is not in chain 18's register")
    need(live["payout"] == r["payout"], f"{r['name']}: payout differs from chain 18's register")
    need(int(live["stake"]) == stake and not live["pending"], f"{r['name']}: chain 18 stake {live['stake']} / pending {live['pending']}, not a plain {stake}")
    need(live["active"], f"{r['name']} is not active on chain 18")
    need(int(live.get("rewards", "0")) == 0 or E.get("REWARDS_DROPPED_OK"),
         f"{r['name']}: chain 18 shows {live['rewards']} unwithdrawn reward units — withdraw them before the cut "
         f"(rewards are not carried), or set REWARDS_DROPPED_OK=1 to drop them")
need(len({r["public_key"] for r in rows}) == 26 and len({r["address"] for r in rows}) == 26, "a validator twice")
total_rewards = sum(int(register[r["address"]].get("rewards", "0")) for r in rows)
if total_rewards:
    print(f"cut-chain19: ⚠ dropping {total_rewards} unwithdrawn reward unit(s) across the register (REWARDS_DROPPED_OK=1)")
# Chain 18's genesis set is these 26, in this order, with these payouts: nothing re-keyed.
need([(v["public_key"], v["payout"]) for v in g18["validators"]] == [(r["public_key"], r["payout"]) for r in rows],
     "the 26 are not chain 18's genesis validators (keys, payouts or order)")
json.dump(rows, open(os.path.join(E["TMP"], "validators.json"), "w"))
with open(os.path.join(E["TMP"], "validator-args"), "w") as f:
    for r in rows:
        f.write(f"--validator\n{r['public_key']},{E['STAKE_RAND']},{r['payout']}\n")
t = g18["tokens"]
json.dump({"registration_fee": t["registration_fee"], "mint_cap_per_day": t["mint_cap_per_day"], "tokens": []},
          open(os.path.join(E["TMP"], "tokens.json"), "w"))
print(f"cut-chain19: 26 validators × {E['STAKE_RAND']} RAND, equal to chain 18's register at height {snap['status_height']}")
PY
}

# ══ the cut, step 2: splice bridge, tokens, staking, vesting; assert every carried sum ═════════
py_splice() {
  python3 - <<'PY'
import json, os, re, sys, time
E = os.environ
exec(E["UNITS_PY"])
out = E["OUT"]
g = json.load(open(out))
g18 = json.load(open(E["CHAIN18_GENESIS"]))
snap = json.load(open(E["SNAPSHOT_FILE"]))
sb = snap["bridge"]
warnings = []

def need(cond, msg):
    if not cond:
        sys.exit(f"cut-chain19: {msg}")

t_ms = int(time.time() * 1000)

def vested_fraction(e, at_ms):
    """`vested(entry, t) / amount`, the same cliff-then-linear(-then-step) curve as
    `ledger::vesting::vested` (crates/randprotocol-core/src/ledger/vesting.rs) — used only to
    report how far a claimed-out entry's carry would front-load, never to change the carry."""
    cliff = int(e["start_ms"]) + int(e["cliff_ms"])
    if at_ms < cliff:
        return 0.0
    elapsed = at_ms - cliff
    linear = int(e["linear_ms"])
    if elapsed >= linear:
        return 1.0
    step = e.get("step_ms")
    if step:
        elapsed -= elapsed % int(step)
    return elapsed / linear

need(snap["genesis_hash"] == E["CHAIN18_HASH"], "the snapshot is not of chain 18")
b18 = g18["bridge"]
need({c: E[f"C18_EMITTER_{c}"] for c in "2345"} == b18["emitters"], "C18_EMITTER_* are not chain 18's genesis emitters")

# ── bridge: chain 18's live values, the floor re-derived ──────────────────────────────────────
rotated = E.get("BRIDGE_ROTATED")
for k in ("guardians", "guardian_set_index", "pq_guardians", "pause_key"):
    need(sb[k] == b18[k] or rotated, f"chain 18's live {k} differs from its genesis — a rotation; set BRIDGE_ROTATED=1 to carry the live value")
need(sb["emitter"] == b18["emitter"], "the Rand-side emitter differs from chain 18's")
need(not sb["mint_paused"], "chain 18's mints are paused — decide what chain 19 starts with")
need(sb["emitters"] == b18["emitters"], "chain 18's live emitter table differs from its genesis")
need(int(sb["rules_v2"]["global_mint_cap_per_window"]) == int(b18["rules_v2"]["global_mint_cap_per_window"])
     and int(sb["rules_v2"]["cap_window_secs"]) == int(b18["rules_v2"]["cap_window_secs"]), "rules_v2 differs from chain 18's genesis")
need(int(sb["registration_fee"]) == int(g18["tokens"]["registration_fee"]), "registration_fee differs from chain 18's")
need(sb["burn_sequence"] >= b18["burn_sequence"], "chain 18's burn sequence went backwards")
pq_guardians, guardians, pause_key = sb["pq_guardians"], sb["guardians"], sb["pause_key"]
need(len(pq_guardians) == len(guardians) == 8, f"{len(pq_guardians)} pq_guardians against {len(guardians)} guardians, expected 8 and 8")
for i, k in enumerate(pq_guardians + [pause_key]):
    need(re.fullmatch(r"[0-9a-f]{2624}", k), f"PQ key {i} is not 2624 lowercase hex characters")
need(pause_key not in pq_guardians and len(set(pq_guardians)) == 8 and len(set(guardians)) == 8, "duplicate guardian or pause key")
emitters = {c: E[f"EMITTER_{c}"] for c in "2345"}
for c, e in emitters.items():
    need(re.fullmatch(r"[0-9a-f]{64}", e), f"EMITTER_{c} is not 64 lowercase hex characters")
need(snap["source"]["emitters"] == emitters, "the snapshot read custody/sequences at other emitters than this cut lists")
redeployed = [c for c in "2345" if emitters[c] != b18["emitters"][c]]

floor18 = {str(k): int(v) for k, v in (b18.get("min_inbound_sequence") or {}).items()}
floor = {}
for c in "2345":
    v = E[f"MIN_INBOUND_{c}"]
    next_seq = int(snap["source"]["next_sequence"][c])
    if v == "none":
        need(c in redeployed, f"MIN_INBOUND_{c}=none on an endpoint chains 14–18 minted from — its old locks would replay")
        continue
    if v == "auto":
        need(c not in redeployed, f"MIN_INBOUND_{c}=auto on a redeployed endpoint")
        v = str(next_seq)
    need(v.isdigit() and int(v) > 0, f"MIN_INBOUND_{c} is {v!r}: a positive sequence, `auto` or `none`")
    if int(v) > next_seq:
        # A floor ahead of the endpoint: sequences next_seq..v-1 are not emitted yet and will never
        # mint, whatever lock takes them. Only ever meant for a redeployed endpoint whose
        # consume-step lock (its sequence 0) has not been made by the snapshot.
        need(c in redeployed and E.get("FLOOR_AHEAD_OK"),
             f"MIN_INBOUND_{c}={v} is above chain {c}'s endpoint next sequence {next_seq}: locks {next_seq}..{int(v) - 1} "
             f"would NEVER mint on chain 19" + (" — on a redeployed endpoint set FLOOR_AHEAD_OK=1 if those are the operator's "
             "consume-step locks still to be made" if c in redeployed else " (an unchanged endpoint: refused outright)"))
        warnings.append(f"chain {c}: floor {v} is ahead of the endpoint's next sequence {next_seq} (FLOOR_AHEAD_OK=1) — "
                        f"sequences {next_seq}..{int(v) - 1} will never mint; they must be the operator's consume-step locks")
    if c not in redeployed and c in floor18:
        need(int(v) >= floor18[c], f"MIN_INBOUND_{c}={v} is below chain 18's own floor {floor18[c]} — it would re-open minted locks")
    if int(v) < next_seq and not E.get("ALLOW_UNMINTED_LOCKS"):
        sys.exit(f"cut-chain19: chain {c}'s endpoint has emitted up to {next_seq - 1} but the floor is {v}: locks "
                 f"{v}..{next_seq - 1} will mint on chain 19 — drain them on chain 18 first"
                 + (" (a redeployed endpoint: chain 18 cannot mint them — they are the operator's and must stay below the floor)" if c in redeployed else "")
                 + ", or set ALLOW_UNMINTED_LOCKS=1")
    if E.get("RELAYER_DONE_DIR") and c not in redeployed:
        d = os.path.join(E["RELAYER_DONE_DIR"], c)
        done = [int(m.group()) for m in (re.match(r"\d+", x) for x in (os.listdir(d) if os.path.isdir(d) else [])) if m]
        last = max(done) if done else -1
        need(int(v) == last + 1, f"chain {c}: the relayer's done/ says last minted {last}, the floor is {v} (last minted + 1 = {last + 1})")
    floor[c] = int(v)
need(floor, "no replay floor at all — C15-1 needs one for every endpoint chain 18 inherited")
# The emitter table that ships is the pinned one (the bash guard's rule, re-checked on the values
# the splice actually writes), and the expected floors / burn sequence are compared, not enforced.
need(emitters == {c: E[f"R19_EMITTER_{c}"] for c in "2345"} or E.get("EMITTERS_CHANGED") == "1",
     "the emitter table is not the chain-19 one (R19_EMITTER_*) — EMITTERS_CHANGED=1 if the pin is knowingly out of date")
want_floor = {c: int(v) for c, v in (x.split(":") for x in E["EXPECT_FLOORS"].split())}
if floor != want_floor:
    warnings.append(f"min_inbound_sequence is {floor}, EXPECTED {want_floor} (EXPECT_FLOORS) — confirm every difference against the endpoints before launch")
if int(sb["burn_sequence"]) != int(E["EXPECT_BURN_SEQUENCE"]):
    warnings.append(f"burn_sequence is {sb['burn_sequence']}, EXPECTED {E['EXPECT_BURN_SEQUENCE']} — a burn landed on chain 18 since; confirm its release before launch")

g["bridge"] = {
    "emitter": b18["emitter"],
    "guardians": guardians,
    "emitters": emitters,
    "pq_guardians": pq_guardians,
    "pause_key": pause_key,
    "rules_v2": b18["rules_v2"],
    "guardian_set_index": int(sb["guardian_set_index"]),
    "burn_sequence": int(sb["burn_sequence"]),
    "min_inbound_sequence": floor,
}

# ── tokens: zUSD at genesis, locked = chain 18's per backing == custody == supply ───────────────
tok = snap["tokens"]["tokens"]
z = [t for t in tok if t["symbol"] == "zUSD" and t["index"] == 1]
need(len(z) == 1, "chain 18 does not list zUSD at index 1")
others = [t for t in tok if t is not z[0]]
need(not others or E.get("ALLOW_DROPPED_TOKENS"),
     f"chain 18 lists {len(others)} more token(s) ({', '.join(t['symbol'] for t in others)}) the cut cannot carry — set ALLOW_DROPPED_TOKENS=1 to drop them")
if others:
    warnings.append(f"dropped chain-18 tokens: {', '.join(str(t['index']) + ':' + t['symbol'] for t in others)}")
z18 = g18["tokens"]["tokens"][0]
live_backings = z[0]["authority"]["backings"]
need([(b["chain"], b["token"], b["decimals"]) for b in live_backings] == [(b["chain"], b["token"], b["decimals"]) for b in z18["backings"]],
     "chain 18's live backings differ from its genesis list")
backings = []
for lb in live_backings:
    b = {"chain": lb["chain"], "token": lb["token"], "decimals": lb["decimals"]}
    if int(lb["locked"]) > 0:
        b["locked"] = int(lb["locked"])
    backings.append(b)
locked_total = sum(b.get("locked", 0) for b in backings)
need(int(z[0]["total_supply"]) == locked_total, f"chain 18's zUSD supply {z[0]['total_supply']} != Σ locked {locked_total}")
for b in backings:
    key = f"{b['chain']}:{b['token']}"
    have = snap["source"]["custody"].get(key)
    need(have is not None, f"the snapshot has no custody reading for {key}")
    d = b["decimals"]
    if d > 8:
        need(have["custody"] % 10**(d - 8) == 0, f"custody {key} has dust below zUSD's eighth decimal")
    scaled = have["custody"] // 10**(d - 8) if d >= 8 else have["custody"] * 10**(8 - d)
    need(scaled == b.get("locked", 0), f"source custody {key} = {have['custody']} (= {scaled} zUSD units), chain 18 locks {b.get('locked', 0)}")

t = g["tokens"]
need(t["registration_fee"] == g18["tokens"]["registration_fee"] and t["mint_cap_per_day"] == g18["tokens"]["mint_cap_per_day"], "tokens header")
t["tokens"] = [{"name": z18["name"], "symbol": z18["symbol"], "salt": z18["salt"], "backings": backings}]
for k in ("max_tokens", "burn_registration_fee", "bound_note_value"):
    t[k] = g18["tokens"][k]
need({k: v for k, v in t.items() if k != "tokens"} == {k: v for k, v in g18["tokens"].items() if k != "tokens"}, "the token switches are not chain 18's")

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
    need(bal["chain18_hash"] == E["CHAIN18_HASH"], "balances.json is not of chain 18")
    scanned = sorted((w["address"], w["rand_units"]) for w in bal["wallets"] if w["rand_units"] > 0)
    listed = sorted((addr, units(a)) for _, addr, a in alloc)
    need(sum(u for _, u in scanned) == alloc_total, f"Σ alloc RAND {alloc_total} != Σ scanned balances {sum(u for _, u in scanned)}")
    need(scanned == listed, "ALLOC_ADDRESSES is not the scanned wallets one-for-one (address, amount) — regenerate it with `balances`")
    uncovered = bal.get("uncovered_genesis_allocs") or []
    need(not uncovered or E.get("UNCOVERED_ALLOCS_OK"),
         "chain 18 genesis alloc(s) match no scanned wallet, so their value would be dropped silently: "
         + ", ".join(f"pk {u['pk'][:12]}… ({u['amount']})" for u in uncovered)
         + " — find the key file(s) and add its directory to WALLETS_DIRS, or set UNCOVERED_ALLOCS_OK=1 to drop them")
    if uncovered:
        warnings.append("dropped uncovered chain-18 genesis alloc(s): "
                         + ", ".join(f"pk {u['pk'][:12]}… ({u['amount']})" for u in uncovered))
    rand_carry = f"== Σ scanned ({len(scanned)} wallets, heights {bal['height_from']}..{bal['height_to']})"
else:
    need(E.get("NO_BALANCES"), f"no {bal_file or 'balances.json'} — run `balances` (the carry-over rule), or set NO_BALANCES=1 to cut from a hand-made list")
    rand_carry = "NOT checked against a scan (NO_BALANCES=1)"
    warnings.append("RAND allocs were not checked against scanned balances")
g["alloc"] = g["alloc"] + token_notes

# ── vesting: chain 18's section, the claimed part subtracted ───────────────────────────────────
vest_note = "none (chain 18 has no vesting section)"
if g18.get("vesting"):
    sv = snap.get("vesting") or {}
    entries = []
    if sv.get("unavailable") or "entries" not in sv:
        entries = g18["vesting"]["entries"]
        warnings.append(f"vesting copied VERBATIM ({sv.get('unavailable') or 'not in the snapshot'}) — reconcile claims by hand before launch")
        vest_note = f"{len(entries)} entries verbatim (unreconciled)"
    else:
        dropped = 0
        for e in g18["vesting"]["entries"]:
            r = sv["entries"].get(e["id"])
            need(r is not None, f"vesting entry {e['id'][:12]}… is not in chain 18's register")
            need(int(r["amount"]) == int(e["amount"]), f"vesting entry {e['id'][:12]}…: the register's amount differs from the genesis")
            need(r.get("revoked_at") is None and int(r.get("revoked_out", "0")) == 0,
                 f"vesting entry {e['id'][:12]}… was revoked on chain 18 — carry it by hand")
            need(int(r.get("bonded", "0")) == 0 and not r.get("unbonding"),
                 f"vesting entry {e['id'][:12]}… has vesting stake bonded or unbonding — a bond does not carry; carry it by hand")
            claimed = int(r["claimed"])
            left = int(e["amount"]) - claimed
            need(left >= 0, f"vesting entry {e['id'][:12]}… claimed more than its amount")
            if claimed > 0:
                # The right carry is A·f(t) − C (A = amount, C = claimed, f = the vesting curve at
                # now); the genesis format has no `claimed` field to express it. Carrying (A − C) on
                # the SAME schedule instead gives (A − C)·f(t) = A·f(t) − C·f(t), i.e. C·(1 − f(t))
                # MORE than correct at every future t: that much unlocks early. Refused unless the
                # operator accepts the approximation.
                frac = vested_fraction(e, t_ms)
                frontload = int(round(claimed * (1 - frac)))
                need(E.get("VESTING_CLAIMED_OK"),
                     f"vesting entry {e['id'][:12]}…: claimed {claimed} > 0 — carrying (amount − claimed) on the "
                     f"same schedule front-loads {frontload} unit(s) (C·(1−f(t)), t = now) ahead of the correct "
                     f"A·f(t) − C curve; set VESTING_CLAIMED_OK=1 to accept this approximation")
            if left == 0:
                dropped += 1
                continue
            entries.append({**e, "amount": str(left)})
        if any(int(sv["entries"][e["id"]]["claimed"]) for e in g18["vesting"]["entries"]):
            warnings.append("vesting: claimed amounts were subtracted from carried entries on the SAME schedule "
                            "(VESTING_CLAIMED_OK=1) — this front-loads each entry's claimed amount by C·(1−f(now)) "
                            "units early; the mathematically right carry, A·f(t) − C, is not expressible without a "
                            "`claimed` field in the genesis format")
        vest_note = f"{len(entries)} entries carried, {dropped} fully claimed dropped, Σ {sum(int(e['amount']) for e in entries)}"
    if entries:
        g["vesting"] = {"entries": entries}

# ── staking: chain 18's, the minter list by name ──────────────────────────────────────────────
s18 = g18["staking"]
if E.get("FAUCET_RECIPIENTS"):
    recipients = [l.split()[-1] for l in open(E["FAUCET_RECIPIENTS"]) if l.strip() and not l.startswith("#")]
    need(recipients and all(r.startswith("rand1") for r in recipients) and len(set(recipients)) == len(recipients),
         "FAUCET_RECIPIENTS: rand1… addresses, each once")
    need(recipients == s18["faucet_recipients"] or E.get("FAUCET_RECIPIENTS_CHANGED"),
         f"the faucet allowlist differs from chain 18's ({len(s18['faucet_recipients'])} → {len(recipients)}) "
         f"— set FAUCET_RECIPIENTS_CHANGED=1 if that is the decision")
    if recipients != s18["faucet_recipients"]:
        warnings.append(f"faucet allowlist changed from chain 18's ({len(s18['faucet_recipients'])} → {len(recipients)})")
else:
    recipients = s18["faucet_recipients"]
vals = {v["name"]: v for v in json.load(open(os.path.join(E["TMP"], "validators.json")))}
minters = []
for name in E["FAUCET_MINTERS"].split():
    need(name in vals, f"FAUCET_MINTERS names {name}, not a chain-19 validator")
    minters.append(vals[name]["address"])
need(minters and len(set(minters)) == len(minters), "faucet_minters empty or a key twice")
need(minters == s18["faucet_minters"] or E.get("FAUCET_MINTERS_CHANGED"),
     "faucet_minters differ from chain 18's (set FAUCET_MINTERS_CHANGED=1 if that is the decision)")
g["staking"] = {**s18, "faucet_recipients": recipients, "faucet_minters": minters}
g["consensus_domain"] = 1

order = ["chain_id", "timestamp_ms", "validators", "alloc", "faucet", "confidential", "fri_profile",
         "hc_bundle", "bridge", "tokens", "aggregation", "consensus_domain", "staking", "epoch_blocks",
         "max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes",
         "max_program_public_words", "envelope_bytes", "vesting", "hardening_v6", "hc_auth", "gas"]
unknown = [k for k in g if k not in order]
need(not unknown, f"the genesis command wrote fields this script does not know: {unknown}")
g = {k: g[k] for k in order if k in g}

# ── assertions over the bytes that ship ───────────────────────────────────────────────────────
need(g["chain_id"] == int(E["CHAIN_ID"]) == 19, f"chain_id is {g['chain_id']}")
need(g.get("hardening_v6") is True, "hardening_v6 is not true — --hardening-v6 did not take")
need(g["hc_bundle"] == E["HC_REPORTED"], "hc_bundle is not what this rand-node reports")
# The same build, the same guests: chain 19's are chain 18's.
need(g["hc_bundle"] == g18["hc_bundle"], "hc_bundle differs from chain 18's — --bundle-guest v3 is not the guest chain 18 runs")
need(g["hc_bundle"] == E["EXPECT_HC_BUNDLE"], f"hc_bundle {g['hc_bundle']} is not EXPECT_HC_BUNDLE (the v3 guest)")
need(re.fullmatch(r"[0-9a-f]{64}", g.get("hc_auth") or ""), "hc_auth is missing — --auth-guest did not take")
need(g["hc_auth"] == E["EXPECT_HC_AUTH"], f"hc_auth {g['hc_auth']} is not EXPECT_HC_AUTH {E['EXPECT_HC_AUTH']}")
need(g["hc_auth"] == g18.get("hc_auth"), "hc_auth differs from chain 18's — --auth-guest is not the auth guest chain 18 runs")
need(g["faucet"] is True and g["confidential"] is True and g["fri_profile"] == "production", "faucet/confidential/fri_profile wrong")
need("aggregation" not in g, "an aggregation section is present — none belongs in chain 19")
# The encrypted memo: the field, and every alloc note (RAND via --alloc, zUSD via alloc-note) in its format.
need(g.get("envelope_bytes") == int(E["ENVELOPE_BYTES"]) == 1860, f"envelope_bytes is {g.get('envelope_bytes')!r}, not 1860 — --envelope-bytes did not take")
need(g["envelope_bytes"] == g18.get("envelope_bytes"), "envelope_bytes differs from chain 18's")
for i, n in enumerate(g["alloc"]):
    size = sum(len(v) // 2 for v in n["envelope"].values())
    need(size == 1860, f"alloc note {i}'s envelope is {size} B, not 1860 — sealed in the legacy format (alloc-note without --envelope-bytes?)")
# The gas section (spec §4.2, §7.1): present, Phase 2's controller on, never beside an aggregation
# section (GenesisError::DynamicGasWithAggregation — asserted absent just above, and again here so a
# later edit that adds aggregation back cannot silently defeat it).
need(g.get("gas") is not None, "the gas section is missing — --gas-price did not take")
need("aggregation" not in g, "gas.dynamic cannot ship beside an aggregation section (GenesisError::DynamicGasWithAggregation)")
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
# … and, every rule above holding, the section is chain 18's own, value for value.
need(g["gas"] == g18.get("gas") or E.get("GAS_CHANGED"), f"the gas section {g['gas']} is not chain 18's gas section {g18.get('gas')} (GAS_CHANGED=1 if intended)")
need(g["epoch_blocks"] == int(E["EPOCH_BLOCKS"]) == g18["epoch_blocks"], "epoch_blocks is not chain 18's")
need(len(g["validators"]) == 26 and all(v["stake"] == int(E["STAKE_RAND"]) * 10**9 for v in g["validators"]), "validators wrong")
need([v["public_key"] for v in g["validators"]] == [vals[n]["public_key"] for n in vals], "validator order/keys wrong")
need(g["bridge"]["min_inbound_sequence"], "min_inbound_sequence missing")
for i, n in enumerate(g["alloc"]):
    need(n.get("opening") is not None, f"alloc note {i} has no opening (core I-2)")
need(sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 1) == locked_total, "Σ zUSD notes != Σ locked")
need(sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 0) == alloc_total, "Σ RAND notes != Σ alloc list")
for k, want in (("max_program_words", "MAX_PROGRAM_WORDS"), ("max_proof_bytes", "MAX_PROOF_BYTES"),
                ("max_block_bytes", "MAX_BLOCK_BYTES"), ("max_call_envelope_bytes", "MAX_CALL_ENVELOPE_BYTES"),
                ("max_program_public_words", "MAX_PROGRAM_PUBLIC_WORDS")):
    need(g[k] == int(E[want]), f"{k} is {g[k]}")
    need(g[k] == g18[k] or E.get("LIMITS_CHANGED"), f"{k} {g[k]} differs from chain 18's {g18[k]} (LIMITS_CHANGED=1 if intended)")
need(g["max_block_bytes"] >= 3 * g["max_proof_bytes"] + 1048576,
     f"max_block_bytes {g['max_block_bytes']} < 3*max_proof_bytes + 1 MiB ({3 * g['max_proof_bytes'] + 1048576}): a v3 Call carries three proofs")
# A PURE RE-GENESIS: outside the chain id, the clock, the carried notes, the bridge's emitter table /
# burn sequence / floors and the zUSD backings' `locked`, every byte of the shape is chain 18's.
excused = set()
if E.get("LIMITS_CHANGED"):
    excused |= {"max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes", "max_program_public_words"}
if E.get("FAUCET_RECIPIENTS_CHANGED") or E.get("FAUCET_MINTERS_CHANGED"):
    excused.add("staking")
if E.get("GAS_CHANGED"):
    excused.add("gas")
moved = sorted(k for k in set(g) | set(g18)
               if k not in {"chain_id", "timestamp_ms", "alloc", "bridge", "tokens", "vesting"} | excused and g.get(k) != g18.get(k))
need(not moved, f"not a pure re-genesis: {moved} differ from chain 18's genesis")
bridge_moved = sorted(k for k in set(g["bridge"]) | set(b18)
                      if k not in ("emitters", "burn_sequence", "min_inbound_sequence") and g["bridge"].get(k) != b18.get(k))
need(not bridge_moved or rotated, f"bridge fields {bridge_moved} differ from chain 18's genesis (BRIDGE_ROTATED=1 carries a live rotation)")
strip_locked = lambda toks: [{**t, "backings": [{k: v for k, v in b.items() if k != "locked"} for b in t["backings"]]} for t in toks]
need({**g["tokens"], "tokens": strip_locked(g["tokens"]["tokens"])} == {**g18["tokens"], "tokens": strip_locked(g18["tokens"]["tokens"])},
     "the tokens section differs from chain 18's in more than the backings' locked amounts")
now_ms = int(time.time() * 1000)
need(g["timestamp_ms"] <= now_ms + 15_000, "timestamp_ms is in the future beyond the 15 s vote drift bound")

json.dump(g, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(f"cut-chain19: spliced bridge (set {g['bridge']['guardian_set_index']}, burn seq {g['bridge']['burn_sequence']}, "
      f"floor {floor}, redeployed {redeployed or 'none'}, emitters 2:{emitters['2'][-8:]} 3:{emitters['3'][-8:]} 4:{emitters['4'][-8:]} 5:{emitters['5'][-8:]}); zUSD locked {locked_total} == notes {notes_total} == chain 18 supply "
      f"== custody ({len(token_notes)} note(s)); RAND allocs Σ {alloc_total} {rand_carry}; vesting {vest_note}; "
      f"staking ({len(recipients)} recipients, {len(minters)} minters); hc_bundle v3, hc_auth {g['hc_auth'][:8]}…; "
      f"envelope_bytes {g['envelope_bytes']} ({len(g['alloc'])} notes at 1860 B); "
      f"gas {gas['gas_price']}/gas {gas['byte_price']}/KiB, bundle limit {gas['bundle_gas_limit']}, dynamic {dyn['target_block_bytes']}/{dyn['target_block_gas']}/{dyn['adjust_bps']} bps; "
      f"every other field equal to chain 18's genesis")
print("cut-chain19: zUSD locked per backing: " + (", ".join(f"{b['chain']}:{b['token'][-8:]}={b['locked']}" for b in backings if b.get("locked")) or "none"))
for w in warnings:
    print(f"cut-chain19: ⚠ {w}")
PY
}

# ══ fixtures: synthetic inputs derived from the committed chain-18 genesis ═════════════════════
# FIXTURE_MODE=selftest (SELFTEST=1): the two python steps alone, chain 18 plus a vesting section so
# the claimed-subtraction path runs, fake wallet addresses, the base file `rand-node genesis` would
# write faked too. FIXTURE_MODE=dryrun (DRY_RUN=1): inputs the REAL binaries accept — the committed
# chain-18 genesis unchanged (its sha256 check passes), wallet lines at real addresses (chain 18's
# validator payouts), no base file (`rand-node genesis` writes it). Neither reads any network.
# BOTH describe chain 18 as the 2026-09-30 rebalancing left it, not as its genesis had it: the whole
# zUSD supply locked against Solana USDT (the old Tron endpoint emptied), `burn_sequence` one past
# genesis (8), Solana's endpoint at sequence 4, and the three REDEPLOYED endpoints — read at
# EMITTER_2/3/4, the chain-19 defaults — at sequence 1 (the consume-step lock) holding no custody.
py_fixtures() {
  python3 - <<'PY'
import copy, json, os, time
E = os.environ; st = E["ST"]; dry = E.get("FIXTURE_MODE") == "dryrun"
g18 = json.load(open(E["CHAIN18_GENESIS"]))
os.makedirs(f"{st}/snap"); os.makedirs(f"{st}/reg"); os.makedirs(f"{st}/tmp")
gnames, bnames = E["GENESIS_NAMES"].split(), E["BONDED"].split()
names = gnames + bnames
assert len(names) == len(g18["validators"]) == 26
# Chain 18's faucet_minters are the eighteen genesis validators' addresses in GENESIS_NAMES order
# (its cut wrote them so); the eight bonded ones are looked up in the register only.
minters = g18["staking"]["faucet_minters"]
assert len(minters) == len(gnames)
addr = {n: (minters[i] if i < len(gnames) else f"FIXTUREaddr{i:02d}") for i, n in enumerate(names)}
with open(f"{st}/validators.tsv", "w") as f:
    for n, v in zip(names, g18["validators"]):
        if n in gnames:
            f.write(f"{n}\t{addr[n]}\t{v['public_key']}\tpeer\t{v['payout']}\n")
for n, v in zip(names, g18["validators"]):
    if n in bnames:
        pk = bytes.fromhex(v["public_key"])
        open(f"{st}/reg/{n}.txt", "w").write(f"validator {addr[n]} on chain 15\nregistration: {(len(pk).to_bytes(8, 'little') + pk + b'sig').hex()}\n")
vesting_entries = [
    {"id": "11" * 32, "class": "team", "beneficiary": g18["validators"][0]["public_key"], "amount": "1000000000000",
     "start_ms": g18["timestamp_ms"], "cliff_ms": 0, "linear_ms": 1000, "step_ms": 100},
    {"id": "22" * 32, "class": "investor", "beneficiary": g18["validators"][1]["public_key"], "amount": "5000000000",
     "start_ms": g18["timestamp_ms"], "cliff_ms": 0, "linear_ms": 1000}]
if not dry:
    f18 = copy.deepcopy(g18)
    f18["vesting"] = {"entries": vesting_entries}
    json.dump(f18, open(f"{st}/genesis-chain18.json", "w"))
b = g18["bridge"]; z = g18["tokens"]["tokens"][0]
SOL_USDT = (5, "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264")
total = sum(x.get("locked", 0) for x in z["backings"])
live = [{**{k: x[k] for k in ("chain", "token", "decimals")}, "locked": total if (x["chain"], x["token"]) == SOL_USDT else 0} for x in z["backings"]]
assert sum(x["locked"] for x in live) == total == 1000000000, "chain 18's zUSD supply is 10, all of it on the Solana USDT backing"
snap = {"taken_at": "dryrun" if dry else "selftest", "genesis_hash": E["CHAIN18_HASH"], "status_height": 200000,
        "validators": [{"address": addr[n], "stake": str(v["stake"]), "pending": [], "rewards": "0", "payout": v["payout"],
                        "nonce": 0, "active": True} for n, v in zip(names, g18["validators"])],
        "bridge": {**{k: b[k] for k in ("emitter", "emitters", "guardian_set_index", "guardians", "pq_guardians", "pause_key")},
                   "burn_sequence": b["burn_sequence"] + 1, "mint_paused": False, "registration_fee": str(g18["tokens"]["registration_fee"]),
                   "rules_v2": {"global_mint_cap_per_window": str(b["rules_v2"]["global_mint_cap_per_window"]), "cap_window_secs": b["rules_v2"]["cap_window_secs"]},
                   "min_inbound_sequence": b["min_inbound_sequence"]},
        "tokens": {"tokens": [{"index": 1, "symbol": "zUSD", "total_supply": str(total),
                               "authority": {"kind": "bridged", "backings": [{**x, "locked": str(x["locked"])} for x in live]}}]},
        "supply": {},
        "vesting": None if dry else {"entries": {e["id"]: {"amount": e["amount"], "claimed": "0", "revoked_out": "0", "revoked_at": None, "bonded": "0", "unbonding": []} for e in vesting_entries}},
        "source": {"emitters": {c: E[f"EMITTER_{c}"] for c in "2345"}, "next_sequence": {"2": 1, "3": 1, "4": 1, "5": 4},
                   "custody": {f"{x['chain']}:{x['token']}": {"custody": x["locked"] * 10**x["decimals"] // 10**8 if x["decimals"] <= 8 else x["locked"] * 10**(x["decimals"] - 8), "fees": 0} for x in live}}}
json.dump(snap, open(f"{st}/snap/chain18-state.json", "w"))
rand_notes = [n for n in g18["alloc"] if n["opening"].get("asset", 0) == 0]
zusd_notes = [n for n in g18["alloc"] if n["opening"].get("asset", 0) == 1]
# Real addresses for the real binaries: chain 18's validator payouts, one per carried wallet.
payouts = list(dict.fromkeys(v["payout"] for v in g18["validators"]))
assert len(payouts) >= len(rand_notes) + 1, "not enough distinct payout addresses for the dry-run carry"
wallets = [{"label": f"w{i}", "address": payouts[i] if dry else f"rand1SELFTEST{i}", "rand_units": n["amount"], "zusd_units": 0, "file": "-"}
           for i, n in enumerate(rand_notes)]
assert all(w["rand_units"] % 10**9 == 0 for w in wallets), "a carried amount with RAND decimals"
wallets.append({"label": "empty", "address": "rand1FIXTUREempty", "rand_units": 0, "zusd_units": 0, "file": "-"})
json.dump({"chain18_hash": E["CHAIN18_HASH"], "height_from": 200000, "height_to": 200000, "wallets": wallets, "uncovered_genesis_allocs": []}, open(f"{st}/snap/balances.json", "w"))
with open(f"{st}/alloc-rand.txt", "w") as f:
    f.write(f"# {'dry run' if dry else 'selftest'}\n")
    for w in wallets[:-1]:
        f.write(f"{w['label']} {w['address']} {w['rand_units'] // 10**9}\n")
holder = payouts[len(rand_notes)] if dry else "rand1SELFTESTz"
open(f"{st}/zusd-carry.txt", "w").write("".join(f"holder {holder} {n['amount'] / 1e8:g}\n" for n in zusd_notes))
if dry:
    raise SystemExit(0)
def memo_form(n):
    """A fixture note in the 1 860-B memo form (selftest only: the body padded, nothing opened)."""
    n = copy.deepcopy(n)
    size = sum(len(v) // 2 for v in n["envelope"].values())
    n["envelope"]["body"] += "00" * (1860 - size)
    return n
rand_notes = [memo_form(n) for n in rand_notes]
zusd_notes = [memo_form(n) for n in zusd_notes]
open(f"{st}/faucet-recipients-changed.txt", "w").write("someone rand1SELFTESTfaucetrecipientchanged\n")
with open(f"{st}/tmp/token-notes.jsonl", "w") as f:
    for n in zusd_notes:
        f.write(json.dumps(n) + "\n")
# what `rand-node genesis --hardening-v6 --bundle-guest v3 --auth-guest --gas-price … --gas-dynamic …`
# writes, before the splice (the gas section in its serde form: prices as decimal strings)
base = {k: g18[k] for k in ("chain_id", "timestamp_ms", "validators", "faucet", "confidential", "fri_profile", "hc_bundle",
                           "epoch_blocks", "max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes",
                           "max_program_public_words", "hardening_v6", "hc_auth")}
assert "gas" in g18 and g18.get("envelope_bytes") == 1860, "chain 18 carries the gas section and the memo"
tb, tg, bps = (int(x) for x in E["GAS_DYNAMIC"].split(","))
base.update(chain_id=19, timestamp_ms=int(time.time() * 1000), alloc=rand_notes, hc_bundle=E["EXPECT_HC_BUNDLE"], hc_auth=E["EXPECT_HC_AUTH"],
            tokens={"registration_fee": g18["tokens"]["registration_fee"], "mint_cap_per_day": g18["tokens"]["mint_cap_per_day"], "tokens": []},
            envelope_bytes=int(E["ENVELOPE_BYTES"]),
            gas={"gas_price": E["GAS_PRICE"], "byte_price": E["BYTE_PRICE"], "bundle_gas_limit": int(E["BUNDLE_GAS_LIMIT"]), "metering": "circuit",
                 "dynamic": {"target_block_bytes": tb, "target_block_gas": tg, "adjust_bps": bps,
                             "min_gas_price": E["GAS_PRICE"], "min_byte_price": E["BYTE_PRICE"]}})
json.dump(base, open(f"{st}/base.json", "w"))
PY
}

# ══ SELFTEST: the two python steps on fixtures derived from deploy/genesis-chain18.json ════════
if [ "${SELFTEST:-}" = 1 ]; then
  ST=$(mktemp -d); trap 'rm -rf "$ST"' EXIT
  export ST FIXTURE_MODE=selftest
  py_fixtures
  NEW_EMITTER=$(printf '0%.0s' $(seq 63))1
  export SNAPSHOT_FILE=$ST/snap/chain18-state.json BALANCES_FILE=$ST/snap/balances.json CHAIN18_GENESIS=$ST/genesis-chain18.json \
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
assert g["chain_id"] == 19 and g["hc_auth"] == E["EXPECT_HC_AUTH"] and g["hc_bundle"] == E["EXPECT_HC_BUNDLE"]
assert list(g)[-5:] == ["envelope_bytes", "vesting", "hardening_v6", "hc_auth", "gas"], list(g)
assert g["envelope_bytes"] == 1860 and all(sum(len(v) // 2 for v in n["envelope"].values()) == 1860 for n in g["alloc"])
assert g["gas"]["bundle_gas_limit"] == 20479 and g["gas"]["dynamic"]["target_block_bytes"] * 2 == g["max_block_bytes"] == 20971520
assert (g["max_proof_bytes"], g["max_block_bytes"]) == (4194304, 20971520), "chain 18's caps"
g18 = json.load(open(E["CHAIN18_GENESIS"]))
assert g["bridge"]["min_inbound_sequence"] == {"2": 1, "3": 1, "4": 1, "5": 4}, g["bridge"]["min_inbound_sequence"]
assert g["bridge"]["emitters"] == {"2": "0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa",
                                   "3": "0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa",
                                   "4": "0000000000000000000000006410797df959987a5baf65b5fab97edeb34d5163",
                                   "5": "d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a"}, "the 2026-09-30 endpoints, Solana unchanged"
assert g["bridge"]["emitters"]["5"] == g18["bridge"]["emitters"]["5"] and g["bridge"]["emitter"] == g18["bridge"]["emitter"]
assert g["bridge"]["burn_sequence"] == 8 and g["bridge"]["guardian_set_index"] == 1
assert [(b["chain"], b["token"][:8], b["locked"]) for b in g["tokens"]["tokens"][0]["backings"] if "locked" in b] == [(5, "ce010e60", 1000000000)], "locked: Solana USDT 10, nothing else"
assert g["gas"] == g18["gas"] and g["staking"] == g18["staking"] and g["validators"] == g18["validators"]
assert g["vesting"] == {"entries": json.load(open(E["CHAIN18_GENESIS"]))["vesting"]["entries"]}, g["vesting"]
assert sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 1) == 1000000000
assert len(g["validators"]) == 26 and g["consensus_domain"] == 1
assert g["staking"]["faucet_minters"] == json.load(open(E["CHAIN18_GENESIS"]))["staking"]["faucet_minters"]
PY
    then ok "the chain-18 fixture assembles into a chain-19 genesis (the redeployed emitters, floors 1/1/1/4, burn sequence 8, locked Solana USDT 10, chain 18's gas section, validators and minters, both vesting entries carried unchanged)"; else bad "assembled genesis content"; fi
  else bad "the happy path refused"; fi

  # VESTING_CLAIMED_OK=1: the front-loaded approximation still carries (the fully-claimed entry drops)
  cp "$ST/snap/chain18-state.json" "$ST/snap/chain18-state.json.claimtest"
  python3 -c 'import json,sys
p = sys.argv[1]; d = json.load(open(p))
d["vesting"]["entries"]["11"*32]["claimed"] = "250000000000"
d["vesting"]["entries"]["22"*32]["claimed"] = "5000000000"
json.dump(d, open(p, "w"))' "$ST/snap/chain18-state.json"
  fresh
  if VESTING_CLAIMED_OK=1 py_validators >/dev/null 2>"$ST/log" && VESTING_CLAIMED_OK=1 py_splice >>"$ST/log" 2>&1; then
    if python3 - <<'PY2'
import json, os
g = json.load(open(os.environ["OUT"]))
g18 = json.load(open(os.environ["CHAIN18_GENESIS"]))
assert g["vesting"] == {"entries": [{**g18["vesting"]["entries"][0], "amount": "750000000000"}]}, g["vesting"]
PY2
    then ok "VESTING_CLAIMED_OK=1 carries the front-loaded approximation (fully-claimed entry dropped)"
    else bad "VESTING_CLAIMED_OK=1 produced the wrong genesis: $(tail -3 "$ST/log")"; fi
  else bad "VESTING_CLAIMED_OK=1 happy path refused: $(tail -3 "$ST/log")"; fi
  mv "$ST/snap/chain18-state.json.claimtest" "$ST/snap/chain18-state.json"

  # every refusal the cut must make, one per case: <description> <file> <mutation> <expected reason phrase> [env]
  refuse() {
    local what=$1 file=$2 mutation=$3 phrase=$4; shift 4
    cp "$file" "$file.orig"
    python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); $mutation; json.dump(d, open(p,'w'))" "$file"
    fresh
    if (env "$@" bash -c 'py_validators >/dev/null && py_splice' >"$ST/log" 2>&1); then
      bad "$what — accepted"
    else
      local msg; msg=$(grep -o 'cut-chain19: .*' "$ST/log" | tail -1 | cut -c1-110)
      if grep -qF "$phrase" "$ST/log"; then ok "$what — $msg"; else bad "$what — refused, but not for the expected reason (wanted \"$phrase\"): $msg"; fi
    fi
    mv "$file.orig" "$file"
  }
  export -f py_validators py_splice
  refuse "custody at a new endpoint (Tron) above locked" "$ST/snap/chain18-state.json" 'd["source"]["custody"][[k for k in d["source"]["custody"] if k.startswith("4:")][0]]["custody"] += 1' "source custody"
  refuse "Solana custody one unit below locked" "$ST/snap/chain18-state.json" 'd["source"]["custody"][[k for k in d["source"]["custody"] if k.startswith("5:ce01")][0]]["custody"] -= 1' "source custody"
  refuse "zUSD still locked on Tron on chain 18" "$ST/snap/chain18-state.json" 'bs = d["tokens"]["tokens"][0]["authority"]["backings"]; t = [b for b in bs if b["chain"] == 4][0]; s5 = [b for b in bs if b["chain"] == 5][0]; t["locked"] = "900000000"; s5["locked"] = "100000000"' "source custody"
  refuse "a snapshot read at the old endpoints" "$ST/snap/chain18-state.json" 'd["source"]["emitters"]["2"] = "000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892"' "other emitters than this cut lists"
  refuse "a scanned balance the list lacks"  "$ST/snap/balances.json"      'd["wallets"][0]["rand_units"] += 1' "!= Σ scanned balances"
  refuse "a validator bonded on chain 18"    "$ST/snap/chain18-state.json" 'd["validators"].append(dict(d["validators"][0], address="new"))' "chain 18's register holds"
  refuse "a stake that is not 1000 RAND"     "$ST/snap/chain18-state.json" 'd["validators"][3]["stake"] = "2000000000000"' "not a plain"
  refuse "a second lock on a new endpoint (next seq 2, floor 1)" "$ST/snap/chain18-state.json" 'd["source"]["next_sequence"]["3"] = 2' "will mint on chain 19"
  refuse "an unminted Solana lock (next seq 5, floor 4)" "$ST/snap/chain18-state.json" 'd["source"]["next_sequence"]["5"] = 5' "will mint on chain 19" MIN_INBOUND_5=4
  refuse "a Solana floor below chain 18's"   "$ST/snap/chain18-state.json" 'pass' "below chain 18's own floor" MIN_INBOUND_5=1
  refuse "a Solana floor above its next sequence" "$ST/snap/chain18-state.json" 'pass' "refused outright" MIN_INBOUND_5=5 FLOOR_AHEAD_OK=1
  refuse "no floor on Solana"                "$ST/snap/chain18-state.json" 'pass' "its old locks would replay" MIN_INBOUND_5=none
  refuse "auto on a redeployed endpoint"     "$ST/snap/chain18-state.json" 'pass' "auto on a redeployed endpoint" MIN_INBOUND_2=auto
  refuse "a floor ahead of a new endpoint (consume step not run), no FLOOR_AHEAD_OK" "$ST/snap/chain18-state.json" 'd["source"]["next_sequence"]["4"] = 0' "FLOOR_AHEAD_OK=1"
  refuse "an emitter table that is not the pinned one reaching the splice" "$ST/snap/chain18-state.json" 'd["source"]["emitters"]["4"] = "00" * 31 + "01"' "is not the chain-19 one" EMITTER_4="$NEW_EMITTER"
  refuse "a guardian rotation on chain 18"   "$ST/snap/chain18-state.json" 'd["bridge"]["guardian_set_index"] = 2' "BRIDGE_ROTATED=1"
  refuse "a revoked vesting entry"           "$ST/snap/chain18-state.json" 'd["vesting"]["entries"]["11"*32]["revoked_at"] = 5' "was revoked on chain 18"
  refuse "zUSD supply above Σ locked"        "$ST/snap/chain18-state.json" 'd["tokens"]["tokens"][0]["total_supply"] = "1000000001"' "!= Σ locked"
  refuse "hc_auth not the pinned one"        "$ST/snap/chain18-state.json" 'pass' "is not EXPECT_HC_AUTH" EXPECT_HC_AUTH="$(printf 'cd%.0s' $(seq 32))"
  refuse "hc_auth not chain 18's"            "$ST/genesis-chain18.json"    'd["hc_auth"] = "cd" * 32' "is not the auth guest chain 18 runs"
  refuse "hc_bundle not chain 18's"          "$ST/genesis-chain18.json"    'd["hc_bundle"] = "cd" * 32' "is not the guest chain 18 runs"
  refuse "no balances.json, no NO_BALANCES"  "$ST/snap/chain18-state.json" 'pass' "the carry-over rule" BALANCES_FILE=/nonexistent
  refuse "a vesting entry with claimed but no VESTING_CLAIMED_OK" "$ST/snap/chain18-state.json" 'd["vesting"]["entries"]["11"*32]["claimed"] = "1"' "VESTING_CLAIMED_OK=1 to accept"
  refuse "unwithdrawn validator rewards, no REWARDS_DROPPED_OK"   "$ST/snap/chain18-state.json" 'd["validators"][0]["rewards"] = "1"' "REWARDS_DROPPED_OK=1 to drop"
  refuse "an uncovered genesis alloc, no UNCOVERED_ALLOCS_OK"     "$ST/snap/balances.json"      'd["uncovered_genesis_allocs"] = [{"pk": "ab" * 32, "amount": 1}]' "UNCOVERED_ALLOCS_OK=1 to drop"
  refuse "a changed faucet allowlist, no FAUCET_RECIPIENTS_CHANGED" "$ST/snap/chain18-state.json" 'pass' "FAUCET_RECIPIENTS_CHANGED=1 if that is" FAUCET_RECIPIENTS="$ST/faucet-recipients-changed.txt"
  # the gas section (chain 18's, carried): present, the pinned bundle limit, Phase 2 on at half the block cap
  refuse "gas prices that are not chain 18's" "$ST/base.json"              'd["gas"]["gas_price"] = "200"; d["gas"]["dynamic"]["min_gas_price"] = "200"' "is not chain 18's gas section" GAS_PRICE=200
  refuse "a validator payout that is not chain 18's" "$ST/base.json"       'd["validators"][0]["payout"] = d["validators"][1]["payout"]' "not a pure re-genesis: ['validators']"
  refuse "a field chain 18's genesis does not carry" "$ST/base.json"       'd["extra_unknown"] = 1' "fields this script does not know"
  refuse "no gas section"                    "$ST/base.json"               'del d["gas"]' "the gas section is missing"
  refuse "a bundle_gas_limit off the pin"    "$ST/base.json"               'd["gas"]["bundle_gas_limit"] = 16383' "not gas_max(14, 0, 0)"
  refuse "gas.dynamic missing"               "$ST/base.json"               'del d["gas"]["dynamic"]' "Phase 2 is off"
  refuse "a byte target not half the block"  "$ST/base.json"               'd["gas"]["dynamic"]["target_block_bytes"] = 4194304' "gas.dynamic targets are"
  refuse "floors not the starting prices"    "$ST/base.json"               'd["gas"]["dynamic"]["min_gas_price"] = "50"' "floors are not the section's own starting prices"
  refuse "an aggregation section beside gas" "$ST/base.json"               'd["aggregation"] = {}' "aggregation"
  # the encrypted memo (chain 18's, carried): the field, and every note in the 1 860-B form
  refuse "no envelope_bytes"                 "$ST/base.json"               'del d["envelope_bytes"]' "envelope_bytes is None, not 1860"
  refuse "a legacy (1 348-B) RAND alloc"     "$ST/base.json"               'd["alloc"][0]["envelope"]["body"] = d["alloc"][0]["envelope"]["body"][:-1024]' "sealed in the legacy format"
  refuse "a legacy (1 348-B) zUSD note"      "$ST/tmp/token-notes.jsonl"   'd["envelope"]["body"] = d["envelope"]["body"][:-1024]' "sealed in the legacy format"
  # FLOOR_AHEAD_OK=1: the consume step has not run (a new endpoint still at sequence 0), floor 1 kept
  cp "$ST/snap/chain18-state.json" "$ST/snap/chain18-state.json.aheadtest"
  python3 -c 'import json,sys
p = sys.argv[1]; d = json.load(open(p)); d["source"]["next_sequence"].update({"2": 0, "3": 0, "4": 0}); json.dump(d, open(p, "w"))' "$ST/snap/chain18-state.json"
  fresh
  if FLOOR_AHEAD_OK=1 py_validators >/dev/null 2>"$ST/log" && FLOOR_AHEAD_OK=1 py_splice >>"$ST/log" 2>&1 \
     && python3 -c 'import json,os; assert json.load(open(os.environ["OUT"]))["bridge"]["min_inbound_sequence"] == {"2": 1, "3": 1, "4": 1, "5": 4}' \
     && [ "$(grep -c 'is ahead of the endpoint' "$ST/log")" = 3 ]; then
    ok "FLOOR_AHEAD_OK=1 keeps floor 1 on three endpoints still at sequence 0, with a warning each"
  else bad "FLOOR_AHEAD_OK=1 path: $(tail -3 "$ST/log")"; fi
  mv "$ST/snap/chain18-state.json.aheadtest" "$ST/snap/chain18-state.json"
  # the expected floors / burn sequence are compared and warned about, never refused
  cp "$ST/snap/chain18-state.json" "$ST/snap/chain18-state.json.warntest"
  python3 -c 'import json,sys
p = sys.argv[1]; d = json.load(open(p)); d["bridge"]["burn_sequence"] = 9; json.dump(d, open(p, "w"))' "$ST/snap/chain18-state.json"
  fresh
  if py_validators >/dev/null 2>"$ST/log" && py_splice >>"$ST/log" 2>&1 && grep -q 'burn_sequence is 9, EXPECTED 8' "$ST/log" \
     && python3 -c 'import json,os; assert json.load(open(os.environ["OUT"]))["bridge"]["burn_sequence"] == 9'; then
    ok "a burn sequence past the expected one is carried, with a warning"
  else bad "burn-sequence warning path: $(tail -3 "$ST/log")"; fi
  mv "$ST/snap/chain18-state.json.warntest" "$ST/snap/chain18-state.json"
  # the bash-level guards, each refusing before anything runs
  if env -u MIN_INBOUND_2 SELFTEST=0 bash "$0" >"$ST/log" 2>&1; then bad "a redeployed endpoint without MIN_INBOUND — accepted"
  else grep -q 'set MIN_INBOUND_2 explicitly' "$ST/log" && ok "the redeployed Ethereum endpoint without MIN_INBOUND_2 — refused before anything runs" || bad "missing MIN_INBOUND_2: wrong refusal: $(tail -1 "$ST/log")"; fi
  for c in 2 3 4 5; do
    if env SELFTEST=0 "EMITTER_$c=$NEW_EMITTER" bash "$0" >"$ST/log" 2>&1; then bad "EMITTER_$c off its pin — accepted"
    else grep -q "EMITTER_$c=$NEW_EMITTER is not the chain-19 endpoint" "$ST/log" && ok "EMITTER_$c off its chain-19 pin, no EMITTERS_CHANGED — refused before anything runs" || bad "EMITTER_$c off its pin: wrong refusal: $(tail -1 "$ST/log")"; fi
  done
  if env SELFTEST=0 EMITTER_2=000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892 bash "$0" >"$ST/log" 2>&1; then bad "chain 18's old Ethereum endpoint — accepted"
  else grep -q 'is not the chain-19 endpoint' "$ST/log" && ok "chain 18's old Ethereum endpoint as EMITTER_2 — refused before anything runs" || bad "old endpoint: wrong refusal: $(tail -1 "$ST/log")"; fi
  if env -u MIN_INBOUND_2 -u MIN_INBOUND_3 -u MIN_INBOUND_4 SELFTEST=0 CHAIN18_SNAPSHOT= bash "$0" snapshot >"$ST/log" 2>&1; then bad "snapshot with no directory — accepted"
  else grep -q 'snapshot <dir>' "$ST/log" && ok "snapshot needs no MIN_INBOUND_* (it stops at its own missing argument, not at the floor guard)" || bad "snapshot guard: $(tail -1 "$ST/log")"; fi
  echo "selftest: $pass passed, $fail failed"
  [ "$fail" = 0 ]; exit
fi

# ══ DRY_RUN: the REAL cut path on synthetic inputs, no network ══════════════════════════════════
# Everything `snapshot` and `balances` would read off chain 18 and the four source chains is
# synthesised from the committed chain-18 genesis (py_fixtures, FIXTURE_MODE=dryrun) AS THE CUT IS
# EXPECTED TO FIND IT: the register = its 26 validators at 1 000 RAND; the bridge = its bridge
# section with `burn_sequence` 8; the source reads taken at the chain-19 emitters (EMITTER_2/3/4 =
# the 2026-09-30 endpoints, each at sequence 1 with no custody; Solana at sequence 4 holding 10
# USDT); zUSD locked = Solana USDT 10 and nothing else; the RAND carry = its six RAND allocs
# re-addressed to its validators' payouts, the zUSD carry = its one 10-zUSD note. MIN_INBOUND_2/3/4
# default to 1 here (the real cut has no default). Then the cut below runs unchanged — the real
# `rand-node genesis`, `alloc-note`, the splice and every assertion (the pinned emitter table, the
# floors 1/1/1/4, "every other field equal to chain 18's"), two `rand-node init`s — so `init`
# proves this build accepts a chain-19 genesis. The output lands in a temp dir (DRY_OUT to
# choose), never at deploy/genesis-chain19.json, and is not chain 19: launch nothing from it.
if [ "${DRY_RUN:-}" = 1 ]; then
  ST=$(mktemp -d)
  export ST FIXTURE_MODE=dryrun
  py_fixtures
  CHAIN18_SNAPSHOT=$ST/snap VALIDATORS_TSV=$ST/validators.tsv REGISTRATIONS=$ST/reg \
    ALLOC_ADDRESSES=$ST/alloc-rand.txt ZUSD_CARRY=$ST/zusd-carry.txt
  OUT=${DRY_OUT:-$ST/genesis-chain19.DRY-RUN.json}
  export CHAIN18_SNAPSHOT VALIDATORS_TSV REGISTRATIONS ALLOC_ADDRESSES ZUSD_CARRY
  echo "cut-chain19: DRY RUN — synthetic chain-18 snapshot, balances and inputs under $ST (from $CHAIN18_GENESIS); no network; $OUT is NOT chain 19"
fi

if [ "${1:-}" = snapshot ]; then
  SNAP=${2:?snapshot <dir>}
  [ ! -e "$SNAP/chain18-state.json" ] || { echo "cut-chain19: $SNAP/chain18-state.json exists — a snapshot is taken once; move it aside" >&2; exit 1; }
  mkdir -p "$SNAP"; export SNAP
  py_snapshot
  exit 0
fi

if [ "${1:-}" = balances ]; then
  SNAP=${2:?balances <snapshot dir>}
  [ -f "$SNAP/chain18-state.json" ] || { echo "cut-chain19: take the snapshot first ($0 snapshot $SNAP)" >&2; exit 1; }
  [ ! -e "$SNAP/balances.json" ] || { echo "cut-chain19: $SNAP/balances.json exists — move it aside to re-scan" >&2; exit 1; }
  [ ! -e "$ALLOC_ADDRESSES" ] || { echo "cut-chain19: $ALLOC_ADDRESSES exists — move it aside; \`balances\` writes it" >&2; exit 1; }
  [ -x "$WALLET" ] || { echo "cut-chain19: $WALLET is not executable — a rand that decodes chain 18: v0.6.7 (the chain's own build; ~/rand-node-a/bin-v067rc1/rand is the macOS one)" >&2; exit 1; }
  refuse_in_tree_key "$SNAP/chain18-state.json"
  export SNAP WALLET WALLETS_DIRS
  py_balances
  exit 0
fi

# ══ the cut ══════════════════════════════════════════════════════════════════════════════════
[ -n "$CHAIN18_SNAPSHOT" ] || { echo "cut-chain19: CHAIN18_SNAPSHOT is unset — run \`$0 snapshot <dir>\` while chain 18 is up" >&2; exit 1; }
[ -n "$EXPECT_HC_AUTH" ] || echo "cut-chain19: EXPECT_HC_AUTH is unset — the cut will print what the binary reports and then refuse" >&2
SNAPSHOT_FILE=$CHAIN18_SNAPSHOT/chain18-state.json; BALANCES_FILE=$CHAIN18_SNAPSHOT/balances.json
export SNAPSHOT_FILE BALANCES_FILE
for bin in "$NODE" "$WALLET"; do
  [ -x "$bin" ] || { echo "cut-chain19: $bin is not executable — the v0.6.7 binaries (chain 18's own build; macOS: ~/rand-node-a/bin-v067rc1/)" >&2; exit 1; }
done
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$ALLOC_ADDRESSES" "$ZUSD_CARRY" "$CHAIN18_GENESIS" ${FAUCET_RECIPIENTS:+"$FAUCET_RECIPIENTS"}; do
  [ -f "$f" ] || { echo "cut-chain19: missing $f" >&2; exit 1; }
done
# Every operator input lives outside the repository (OPS-1): the cut reads public halves only,
# but a key-shaped file inside the tree is refused on principle.
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$ALLOC_ADDRESSES" "$ZUSD_CARRY" ${FAUCET_RECIPIENTS:+"$FAUCET_RECIPIENTS"}; do
  refuse_in_tree_key "$f"
done
for n in $BONDED; do refuse_in_tree_key "$REGISTRATIONS/$n.txt"; done
[ "$(shasum -a 256 "$CHAIN18_GENESIS" | cut -c1-64)" = "$CHAIN18_GENESIS_SHA256" ] \
  || { echo "cut-chain19: $CHAIN18_GENESIS is not chain 18's committed genesis file (sha256 ${CHAIN18_GENESIS_SHA256:0:8}…)" >&2; exit 1; }
[ ! -e "$OUT" ] || { echo "cut-chain19: $OUT already exists — a genesis is cut once; move it aside deliberately" >&2; exit 1; }
for flag in --hardening-v6 --bundle-guest --auth-guest --gas-price --gas-dynamic --envelope-bytes; do
  "$NODE" genesis --help | grep -q -- "$flag" || { echo "cut-chain19: $NODE genesis has no $flag (not the v0.6.7 build)" >&2; exit 1; }
done
# One build cuts, scans and runs chain 19: chain 18's. Anything else is the wrong binary.
NODE_VERSION=$("$NODE" --version 2>/dev/null || true)
case "$NODE_VERSION" in
  "rand-node 0.6.7"*) ;;
  *) [ "${NODE_VERSION_OK:-}" = 1 ] || { echo "cut-chain19: $NODE reports '$NODE_VERSION', not rand-node 0.6.7 (chain 18's build; 0.6.7-rc.1 is the same consensus) — NODE_VERSION_OK=1 to cut with it knowingly" >&2; exit 1; } ;;
esac
echo "cut-chain19: cutting with $NODE_VERSION"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
export TMP

py_validators

args=()
while IFS= read -r l; do args+=("$l"); done < "$TMP/validator-args"
while read -r label addr amount; do
  case "$label" in ''|'#'*) continue;; esac
  args+=(--alloc "$addr=$amount")
done < "$ALLOC_ADDRESSES"

# zUSD genesis notes: fresh openings, sealed to each carried holder (asset 1 = zUSD, 8 decimals).
: > "$TMP/token-notes.jsonl"
while read -r label addr amount; do
  case "$label" in ''|'#'*) continue;; esac
  "$NODE" alloc-note --to "$addr" --amount "$amount" --asset 1 --envelope-bytes "$ENVELOPE_BYTES" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)))' >> "$TMP/token-notes.jsonl"
  echo "cut-chain19: zUSD genesis note, $amount zUSD to $label"
done < "$ZUSD_CARRY"

echo "cut-chain19: writing the base file (its printed hash is NOT chain 19's)"
"$NODE" genesis --chain-id "$CHAIN_ID" "${args[@]}" \
  --max-program-words "$MAX_PROGRAM_WORDS" \
  --max-proof-bytes "$MAX_PROOF_BYTES" \
  --max-block-bytes "$MAX_BLOCK_BYTES" \
  --max-call-envelope-bytes "$MAX_CALL_ENVELOPE_BYTES" \
  --max-program-public-words "$MAX_PROGRAM_PUBLIC_WORDS" \
  --tokens "$TMP/tokens.json" \
  --bundle-guest v3 --auth-guest --hardening-v6 \
  --gas-price "$GAS_PRICE" --byte-price "$BYTE_PRICE" --bundle-gas-limit "$BUNDLE_GAS_LIMIT" --gas-dynamic "$GAS_DYNAMIC" \
  --envelope-bytes "$ENVELOPE_BYTES" \
  --epoch-blocks "$EPOCH_BLOCKS" --faucet --fri-profile production --out "$TMP/genesis.json" | tee "$TMP/genesis.out"

# What the binary wrote is authoritative; its stdout is cross-checked where it names a value.
HC_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_bundle',''))" "$TMP/genesis.json")
HC_AUTH_REPORTED=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('hc_auth',''))" "$TMP/genesis.json")
for pair in "hc_bundle:$HC_REPORTED" "hc_auth:$HC_AUTH_REPORTED"; do
  k=${pair%%:*}; v=${pair#*:}
  [ -n "$v" ] || { echo "cut-chain19: the genesis command wrote no $k" >&2; exit 1; }
  said=$(grep -o "$k [0-9a-f]\{64\}" "$TMP/genesis.out" | head -1 | cut -d' ' -f2 || true)
  [ -z "$said" ] || [ "$said" = "$v" ] || { echo "cut-chain19: the genesis command printed $k $said but wrote $v" >&2; exit 1; }
done
echo "cut-chain19: this rand-node reports hc_bundle $HC_REPORTED (expect v3 $EXPECT_HC_BUNDLE)"
echo "cut-chain19: this rand-node reports hc_auth   $HC_AUTH_REPORTED"
[ -n "$EXPECT_HC_AUTH" ] || { echo "cut-chain19: EXPECT_HC_AUTH is unset — pin the v0.6.7 release binary's value (above, if this IS the release build) and re-run" >&2; exit 1; }
export HC_REPORTED
# Everything is built in $TMP and lands at $OUT only once it has passed every check and `init`,
# so a refused cut leaves no half-made file behind to be mistaken for the genesis.
FINAL_OUT=$OUT; OUT=$TMP/genesis.json; export OUT

py_splice

INIT=$("$NODE" init --datadir "$TMP/probe" --genesis "$OUT")
echo "$INIT"
HASH=$(printf '%s\n' "$INIT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ -n "$HASH" ] || { echo "cut-chain19: rand-node init printed no genesis hash" >&2; exit 1; }
[ "$HASH" != "$CHAIN18_HASH" ] || { echo "cut-chain19: init derived chain 18's hash" >&2; exit 1; }
# A second init on a fresh dir must re-derive the same hash from the finished bytes.
HASH2=$("$NODE" init --datadir "$TMP/probe2" --genesis "$OUT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ "$HASH2" = "$HASH" ] || { echo "cut-chain19: init re-derived $HASH2, first $HASH" >&2; exit 1; }
[ ! -e "$FINAL_OUT" ] || { echo "cut-chain19: $FINAL_OUT appeared during the cut — refusing to overwrite it" >&2; exit 1; }
cp "$OUT" "$FINAL_OUT"; OUT=$FINAL_OUT
TS=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['timestamp_ms'])" "$OUT")
AGE=$(( ( $(date +%s) * 1000 - TS ) / 1000 ))

cat <<EOF

cut-chain19: wrote $OUT (sha256 $(shasum -a 256 "$OUT" | cut -c1-64))
cut-chain19: genesis hash $HASH
cut-chain19: chain id $CHAIN_ID, hc_bundle $HC_REPORTED (guest v3), hc_auth $HC_AUTH_REPORTED, hardening_v6, consensus_domain 1, no aggregation
cut-chain19: gas: $GAS_PRICE/gas, $BYTE_PRICE/KiB, bundle limit $BUNDLE_GAS_LIMIT (auth 1279), dynamic $GAS_DYNAMIC (chain 18's section; constraint set 8, v0.6.7)
cut-chain19: envelope_bytes $ENVELOPE_BYTES — the encrypted memo on; every genesis note sealed in the 1 860-B form
cut-chain19: 26 validators × $STAKE_RAND RAND (quorum 18); faucet minters: $FAUCET_MINTERS
cut-chain19: bridge: $(python3 -c "import json,sys;b=json.load(open(sys.argv[1]))['bridge'];print('emitters', json.dumps(b['emitters'], sort_keys=True), '| min_inbound_sequence', json.dumps(b['min_inbound_sequence'], sort_keys=True), '| burn_sequence', b['burn_sequence'], '| guardian set', b['guardian_set_index'])" "$OUT")
cut-chain19: floors asked 2:$MIN_INBOUND_2 3:$MIN_INBOUND_3 4:$MIN_INBOUND_4 5:$MIN_INBOUND_5 (auto = the snapshot's next sequence); expected $EXPECT_FLOORS, burn sequence $EXPECT_BURN_SEQUENCE
cut-chain19: NOT carried: shielded notes of wallets the operator does not hold, and any unwithdrawn validator rewards — say so in the launch notes.

⚠  Stamped $AGE s ago; the chain's clock starts there. Launch within MINUTES, or delete $OUT and re-cut.
EOF
[ "${DRY_RUN:-}" != 1 ] || echo "cut-chain19: DRY RUN — every step above ran on synthetic inputs; $OUT is NOT chain 19, launch nothing from it."
