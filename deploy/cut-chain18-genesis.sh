#!/usr/bin/env bash
# Cut the chain-18 genesis: chain 16's shape, the 26 validators chain 16 runs, PLUS the gas
# section (spec 2026-09-28-gas-model-design.md §4.2/§7.1, Phase 1 fixed prices + Phase 2 dynamic
# controller) — the ISA-metered fee that replaces the flat tier schedule.
#
# DERIVATION NOTE: there is no chain-17 cut script in this tree (delegated proving, v0.6.3) at the
# time this script was written, so this is derived directly from deploy/cut-chain16-genesis.sh —
# read it first. If chain 17 is cut before chain 18 is, re-derive this script from
# deploy/cut-chain17-genesis.sh instead (its snapshot/carry-over shape, not chain 16's) before
# using it for a real cut; the env var names below (CHAIN16_*) would become CHAIN17_*.
#
#   deploy/cut-chain18-genesis.sh snapshot <dir>     # chain 16 still up, bridge daemons stopped
#   CHAIN16_SNAPSHOT=<dir> NODE=… WALLET=… deploy/cut-chain18-genesis.sh
#   DRY_RUN=1 deploy/cut-chain18-genesis.sh snapshot <dir>   # no RPC/network: writes a stub
#   DRY_RUN=1 CHAIN16_SNAPSHOT=<dir> deploy/cut-chain18-genesis.sh   # cut against synthetic inputs
#
# What chain 18 is, against chain 16 (cut-chain16-genesis.sh; read it first):
#
#   * TWENTY-SIX validators, every one on the key it runs on chain 16 today — the eighteen chain-16
#     genesis validators (chain 14's keys, public half in $VALIDATORS_TSV) and the eight bonded on
#     chain 16 on 2026-09-27 (obs1, rand-archive-2, the six guardian hosts; public keys read out of
#     the registrations in $REGISTRATIONS). Peer ids and deploy/nodes.env stay valid. Equal stake,
#     1000 RAND each: it is what every one of the 26 has bonded on chain 16 (the register shows no
#     other amount and no pending unbond) and what chain 16's genesis gave its eighteen. Quorum is
#     now 18 of 26 — the guardian hosts count for liveness.
#   * `rand-node genesis --hardening-v6 --bundle-guest v2 --gas-price 100 --byte-price 800
#     --bundle-gas-limit 20479 --gas-dynamic 10485760,262144,1250`: the v0.6 validity rules, the
#     branch-free hidden-asset guest (hc_bundle is whatever THIS rand-node reports for v2; the cut
#     is made with the release binary the fleet will run — never a local build) AND the gas
#     section on, testnet with the Phase 2 controller running: mins equal the fixed prices, target
#     bytes half the 20 MiB block cap (MAX_BLOCK_BYTES, below), target gas 2^18, 12.5%/step.
#     Constraint set 8 does not touch the hidden-asset guest's own words (only the STARK verifier key), so **hc_bundle is asserted
#     EQUAL to chain 16's**, not different — unlike chain 16's own script, which asserted its
#     hc_bundle differed from chain 15's v1 guest.
#   * The genesis MUST NOT carry an `aggregation` section beside `gas.dynamic`
#     (`GenesisError::DynamicGasWithAggregation`, genesis.rs) — chain 16 already cuts without one
#     (no live chain carries an `aggregation` section yet), and this script asserts it explicitly
#     below rather than relying on that being true by omission alone.
#   * staking: chain 16's section, its faucet allowlist unchanged, plus `faucet_minters` (LEDGER-1):
#     the operator's genesis validator keys that may sign a faucet Mint ($FAUCET_MINTERS, names).
#   * tokens: chain 16's section — zUSD listed at genesis with chain 14's name/symbol/salt (asset id
#     32e5ab28…), max_tokens, burn_registration_fee, bound_note_value.
#   * bridge: chain 16's CURRENT guardian set, PQ set, pause key, emitters and rules_v2, the burn
#     sequence carried on, and `min_inbound_sequence` per source chain (C15-1).
#   * zUSD carried at genesis: the custody chain 16 leaves behind as per-backing `locked`, and one
#     fresh genesis note per line of $ZUSD_CARRY (made here by `rand-node alloc-note --asset 1`), so
#     Σ notes == Σ locked == source custody at block 0.
#
# ROLLOUT ORDER (spec §11, and the release-gating rule): tag the fullnode release that carries cs8
# (v0.6.6 unless the line has moved) only after the full suite on the testbox and a final review;
# ship the clients (core re-vendored at cs8, `--gas-limit` in the apps) and randscan's
# `randscan-viewing`/pv decoding BEFORE the cut — a wallet still on cs7 can prove nothing chain 18
# accepts. Then the cut: every proof format changes (constraint set 8 changes every verifier key),
# so the cutover is all-stop/all-start (deploy/cutover-fleet-chain18.sh), no mixed fleet, obs1
# first, then the validators, A/D/C bootstraps as in chain 16's runbook.
#
# The `snapshot` step (read-only: JSON-RPC reads of chain 16 and of the four source chains) records
# what the cut asserts against: chain 16's register, bridge state, token registry and supply, each
# source endpoint's next outbound sequence and custody. Take it AFTER the relayer and every guardian
# have stopped (no more mints or releases) and BEFORE chain 16 stops. Every value below that
# defaults to "what chain 16 held on 2026-09-28" is checked against the snapshot, not trusted.
# DRY_RUN=1 replaces every live RPC read (chain 16's and the four source chains') with a synthetic
# snapshot built from freshly generated keys, so `snapshot` and the cut both run offline; see the
# DRY_RUN block below for exactly what it fabricates and why each value is safe to invent.
#
# THE BRIDGE REDEPLOY (planned 2026-09-29 00:00 UTC — R1/R3 on the EVM/Tron endpoints; Solana is not
# redeployed): the endpoint contracts are not upgradeable, so a redeploy means new emitter
# addresses on chains 2, 3 and 4, custody moved to them, and new contracts whose `sequence` starts
# at 0. If the redeploy happens BEFORE this cut:
#   - set EMITTER_2 / EMITTER_3 / EMITTER_4 to the new endpoints' 32-byte wire forms (left-padded);
#   - set MIN_INBOUND_2/3/4 explicitly: `none` for a fresh endpoint (its old locks already fail the
#     emitter check, and a floor of 2 would refuse its first two real locks), or last-minted+1 if
#     the new endpoint minted anything on chain 16 before the cut; the script refuses a changed
#     emitter whose floor is left at its default;
#   - take the snapshot with the same EMITTER_* so custody is read at the new addresses.
# If it happens AFTER the cut, it is a chain-18 matter (the emitter table is genesis-fixed: listing
# a new endpoint then needs its own governance path) — decide before cutting which it is.
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash (fresh note randomness and a
# fresh timestamp). Cut once, distribute the file byte-identically, launch within minutes.
set -euo pipefail
DRY_RUN=${DRY_RUN:-0}
cd "$(dirname "$0")/.."
. deploy/lib/key-guard.sh

NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
CHAIN_ID=${CHAIN_ID:-18}
OUT=${OUT:-deploy/genesis-chain18.json}
# DRY_RUN=1 must be unmistakable: force a distinct output path (and, below, a distinct snapshot
# filename) so a real cut can never find a dry-run artifact sitting at its own path, and a dry
# run can never be confused for — or silently overwrite — a real one. Unconditional, not
# `${OUT:-…}`: OUT already has a real default just above.
SNAPSHOT_BASENAME=chain16-state.json
if [ "$DRY_RUN" = 1 ]; then
  OUT=deploy/genesis-chain18.DRY-RUN.json
  SNAPSHOT_BASENAME=chain16-state.DRY-RUN.json
fi
export SNAPSHOT_BASENAME
CHAIN16_GENESIS=${CHAIN16_GENESIS:-deploy/genesis-chain16.json}
# Chain 16 was not yet live when this script was written (v0.6.1, "cut in flight") — unlike
# chain 16's script, which pinned chain 15's already-known hash, there is no baked default here.
# Set it once chain 16 is up; DRY_RUN=1 fills a stub (see the DRY_RUN block below).
CHAIN16_HASH=${CHAIN16_HASH:-}
CHAIN16_RPC=${CHAIN16_RPC:-http://127.0.0.1:8545}          # snapshot only: any chain-16 node
CHAIN16_SNAPSHOT=${CHAIN16_SNAPSHOT:-}                       # the cut: the snapshot directory

# ── public inputs, all outside the repository ─────────────────────────────────────────────────
VALIDATORS_TSV=${VALIDATORS_TSV:-$HOME/.rand-chain14/public/validators.tsv}   # name addr pk peer payout (18)
REGISTRATIONS=${REGISTRATIONS:-$HOME/.rand-chain16/registrations}              # <name>.txt, one per bonded validator (8)
BONDED=${BONDED:-obs1 archive2 g1 g2 g3 g4 g5 g6}
GENESIS_NAMES=${GENESIS_NAMES:-a b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1}
# LEDGER-1: who may sign a faucet Mint. Default: the eighteen operator keys chain 16 already lets
# mint (its genesis validators — the pool policy on every v0.5.9+ node); the eight bonded keys (the
# guardian hosts hold theirs on their own droplets) are left out. `FAUCET_MINTERS="$GENESIS_NAMES
# $BONDED"` names all 26; the lead decides.
FAUCET_MINTERS=${FAUCET_MINTERS:-$GENESIS_NAMES}
STAKE_RAND=${STAKE_RAND:-1000}
FAUCET_RECIPIENTS=${FAUCET_RECIPIENTS:-$HOME/.rand-chain16/faucet-recipients.txt}  # "<name> rand1…" per line
ALLOC_ADDRESSES=${ALLOC_ADDRESSES:-$HOME/.rand-chain18/alloc-rand.txt}          # "<label> rand1… <RAND>" per line
ZUSD_CARRY=${ZUSD_CARRY:-$HOME/.rand-chain18/zusd-carry.txt}                    # "<label> rand1… <zUSD>" per line
PQ_GUARDIANS=${PQ_GUARDIANS:-$HOME/.rand-bridge/mainnet-set1/pq-guardians-chain16.json}
PQ_GUARDIANS_SHA256=${PQ_GUARDIANS_SHA256:-b1f6e8781784fa6e88e295ff27626a9a42d1c1d4348826e49ef751ab06dd7fb1}  # inherited: the guardian-set-1 PQ file has not changed (rotation on hold) as of this writing — reconfirm against the bridge session at chain-18 cut time
PAUSE_KEY=${PAUSE_KEY:-$HOME/.rand-bridge/mainnet-set1/pause-key-chain16.pub}
EXPECT_HC_BUNDLE=${EXPECT_HC_BUNDLE:-}         # optional pin: the v2 hc the release binary reports

# ── chain 16's limits and economics, unchanged ───────────────────────────────────────────────
MAX_PROGRAM_WORDS=${MAX_PROGRAM_WORDS:-65535}
MAX_PROOF_BYTES=${MAX_PROOF_BYTES:-8388608}
MAX_BLOCK_BYTES=${MAX_BLOCK_BYTES:-20971520}
MAX_CALL_ENVELOPE_BYTES=${MAX_CALL_ENVELOPE_BYTES:-65536}
MAX_PROGRAM_PUBLIC_WORDS=${MAX_PROGRAM_PUBLIC_WORDS:-32768}
REGISTRATION_FEE=${REGISTRATION_FEE:-1000000000}
MINT_CAP_PER_DAY=${MINT_CAP_PER_DAY:-10000000000000}
FAUCET_BUDGET_PER_EPOCH=${FAUCET_BUDGET_PER_EPOCH:-10000000000000}
BOND_ACTIVATION_EPOCHS=${BOND_ACTIVATION_EPOCHS:-2}
MAX_WEIGHT_BPS=${MAX_WEIGHT_BPS:-3333}
MAX_STAKE_ENTRY_PER_EPOCH=${MAX_STAKE_ENTRY_PER_EPOCH:-10000000000000}
MAX_TOKENS=${MAX_TOKENS:-4096}
GLOBAL_MINT_CAP_PER_WINDOW=${GLOBAL_MINT_CAP_PER_WINDOW:-400000000000}
CAP_WINDOW_SECS=${CAP_WINDOW_SECS:-86400}

# ── the bridge: chain 16's values on 2026-09-28 (each one checked against the snapshot) ─────────
GUARDIAN_SET_INDEX=${GUARDIAN_SET_INDEX:-1}
BURN_SEQUENCE=${BURN_SEQUENCE:-7}               # chain 16 made no burn: still chain 14's final 7
LOCKED_TRON_USDT=${LOCKED_TRON_USDT:-900000000} # 9 zUSD (8 decimals) = 9 USDT in the Tron endpoint
LOCKED_SOL_USDT=${LOCKED_SOL_USDT:-100000000}   # 1 zUSD = 1 USDT in the Solana program's custody
BRIDGE_EMITTER=${BRIDGE_EMITTER:-c02df6ba70c2457a7406780da97492a6acb57dc40751e6279f003a570559d15f}
GUARDIANS=(
  29851d77b4b5b095cd10f85ad76ee917dcf0f0ac
  ba56d1cec76b461b7aeb04a559350962070b5f7f
  c0a9fc250cfe2ae8ebfb6704777e6be4fbe3e374
  6f7196e8448415f667b32cf162e8689f98e6a987
  4dc932582668dbfeb24c03b22701f7e93ad53320
  6d63947627cac07bb863d36e015a714099a57359
  849f4e9e2420e115fa6e6715f53279af0a679c39
  98fffdec75284d77433404c1c0fc9f90abb58a9c
)
C16_EMITTER_2=000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892   # Ethereum
C16_EMITTER_3=000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892   # BNB Chain
C16_EMITTER_4=0000000000000000000000000992df85dcce77ded2c0387f1fa9cf98ac859700   # Tron
C16_EMITTER_5=d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a   # Solana
EMITTER_2=${EMITTER_2:-$C16_EMITTER_2}
EMITTER_3=${EMITTER_3:-$C16_EMITTER_3}
EMITTER_4=${EMITTER_4:-$C16_EMITTER_4}
EMITTER_5=${EMITTER_5:-$C16_EMITTER_5}
# C15-1: one past the last lock chain 14 or 16 minted from each source (chain 16 is chain 18's
# predecessor here — see the header). On 2026-09-28 every source endpoint's next sequence was 2 and
# chain 14 minted sequences 0 and 1 from each (the relayer's done/<chain>/{0,1} records, the
# round-1/round-2 mints); whether chain 16 minted anything by chain 18's own snapshot time is TBD —
# read from the snapshot's own next_sequence, not assumed unchanged from chain 16's cut day.
# `none` = no floor.
for c in 2 3 4 5; do
  v=MIN_INBOUND_$c; e=EMITTER_$c; o=C16_EMITTER_$c
  if [ -z "${!v:-}" ]; then
    [ "${!e}" = "${!o}" ] || { echo "cut-chain18: EMITTER_$c is not chain 16's endpoint (a redeploy?) — set MIN_INBOUND_$c explicitly (none, or last minted + 1)" >&2; exit 1; }
    printf -v "$v" 2
  fi
done
# ── gas (spec §4.2, §7.1): Phase 1 fixed prices + Phase 2 dynamic controller, testnet on ──────
GAS_PRICE=${GAS_PRICE:-100}
BYTE_PRICE=${BYTE_PRICE:-800}
# Every bundle proof declares exactly this (spec §4.3): the v2 guest's header ceiling
# gas_max(14, 0, 0) = (2^14 − 1) + 2^12 = 20 479 — the absorb term included (circuits 18c2627); the
# bare cycle budget 16 383 would refuse every bundle the fleet's prover makes.
BUNDLE_GAS_LIMIT=${BUNDLE_GAS_LIMIT:-20479}
# target_block_bytes,target_block_gas,adjust_bps — half the 20 MiB cap in bytes (10 485 760 =
# MAX_BLOCK_BYTES / 2: a block can then be at most twice the target, so an over-full block and an
# empty one move byte_price by the same 12.5%; next_price also caps `used` at 2·target, which
# bounds the gas meter the same way), 2^18 gas, 12.5% per step; mins default to
# gas_price/byte_price above (rand-node genesis's own rule).
GAS_DYNAMIC=${GAS_DYNAMIC:-$((MAX_BLOCK_BYTES / 2)),262144,1250}

ETH_RPC=${ETH_RPC:-https://ethereum-rpc.publicnode.com}
BSC_RPC=${BSC_RPC:-https://bsc-rpc.publicnode.com}
TRON_API=${TRON_API:-https://api.trongrid.io}
SOL_RPC=${SOL_RPC:-https://api.mainnet-beta.solana.com}
SOL_PROGRAM=${SOL_PROGRAM:-FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu}

export CHAIN_ID OUT CHAIN16_GENESIS CHAIN16_HASH CHAIN16_RPC VALIDATORS_TSV REGISTRATIONS BONDED GENESIS_NAMES \
  FAUCET_MINTERS STAKE_RAND FAUCET_RECIPIENTS PQ_GUARDIANS PAUSE_KEY EXPECT_HC_BUNDLE MAX_PROGRAM_WORDS \
  MAX_PROOF_BYTES MAX_BLOCK_BYTES MAX_CALL_ENVELOPE_BYTES MAX_PROGRAM_PUBLIC_WORDS REGISTRATION_FEE \
  MINT_CAP_PER_DAY FAUCET_BUDGET_PER_EPOCH BOND_ACTIVATION_EPOCHS MAX_WEIGHT_BPS MAX_STAKE_ENTRY_PER_EPOCH \
  MAX_TOKENS GLOBAL_MINT_CAP_PER_WINDOW CAP_WINDOW_SECS GUARDIAN_SET_INDEX BURN_SEQUENCE LOCKED_TRON_USDT \
  LOCKED_SOL_USDT BRIDGE_EMITTER EMITTER_2 EMITTER_3 EMITTER_4 EMITTER_5 C16_EMITTER_2 C16_EMITTER_3 \
  C16_EMITTER_4 C16_EMITTER_5 MIN_INBOUND_2 MIN_INBOUND_3 MIN_INBOUND_4 MIN_INBOUND_5 ETH_RPC BSC_RPC \
  TRON_API SOL_RPC SOL_PROGRAM GAS_PRICE BYTE_PRICE BUNDLE_GAS_LIMIT GAS_DYNAMIC
GUARDIANS_JOINED=$(IFS=,; echo "${GUARDIANS[*]}"); export GUARDIANS_JOINED

# The zUSD backings, chain 16's order (a genesis-listed token's backings are part of its hash).
BACKINGS_PY='
USDT_TRON = "000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c"
USDT_SOL = "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264"
BACKINGS = [
    {"chain": 2, "token": "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7", "decimals": 6},
    {"chain": 2, "token": "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "decimals": 6},
    {"chain": 3, "token": "00000000000000000000000055d398326f99059ff775485246999027b3197955", "decimals": 18},
    {"chain": 3, "token": "0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d", "decimals": 18},
    {"chain": 4, "token": USDT_TRON, "decimals": 6},
    {"chain": 5, "token": USDT_SOL, "decimals": 6},
    {"chain": 5, "token": "c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61", "decimals": 6},
]
'
export BACKINGS_PY

# ══ snapshot: read-only reads of chain 16 and of the source endpoints ═════════════════════════
if [ "${1:-}" = snapshot ]; then
  SNAP=${2:?snapshot <dir>}
  [ ! -e "$SNAP/$SNAPSHOT_BASENAME" ] || { echo "cut-chain18: $SNAP/$SNAPSHOT_BASENAME exists — a snapshot is taken once; move it aside" >&2; exit 1; }
  mkdir -p "$SNAP"; export SNAP

  # ── DRY_RUN=1: no live RPC, no source-chain reads. Everything the real snapshot step would read
  # off chain 16 and the four bridge endpoints is instead generated here, once, into $SNAP/dryrun:
  # 26 real (freshly keygen'd, so every length/format check the cut script runs is exercised
  # honestly) validator and payout keypairs, a synthetic chain-16 register and bridge/tokens
  # state built from this script's OWN env-var defaults (so the two sides can never disagree),
  # and a probe `rand-node genesis --bundle-guest v2` run once to read hc_bundle — a pure function
  # of the guest binary, so the value this writes into the stub predecessor genesis is exactly
  # what the real cut's own `rand-node genesis --bundle-guest v2` call reports later, even though
  # that happens in a separate process (a second invocation of this script). The `cut` phase reads
  # these files back automatically when it also sees DRY_RUN=1 (see below); nothing here is a
  # stand-in for the real bridge/token/validator amounts a true chain-16 snapshot would carry —
  # only their *shape* is exercised, so a dry run proves the script's plumbing and its assertions,
  # not any real chain-16 state.
  if [ "$DRY_RUN" = 1 ]; then
    python3 - <<'PY'
import hashlib, json, os, re, secrets, subprocess
E = os.environ
exec(E["BACKINGS_PY"])
SNAP, NODE, WALLET = E["SNAP"], E["NODE"], E["WALLET"]
D = os.path.join(SNAP, "dryrun")
KEYS = os.path.join(D, "keys")
os.makedirs(KEYS, exist_ok=True)
os.makedirs(os.path.join(D, "registrations"), exist_ok=True)

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout

def node_keypair(name):
    kf = os.path.join(KEYS, f"node-{name}.key.json")
    run(NODE, "keygen", "--out", kf)
    fields = dict(l.split(": ", 1) for l in run(NODE, "address", "--key", kf).splitlines())
    return fields["address"], fields["public_key"], fields["peer_id"]

def wallet_address(name):
    kf = os.path.join(KEYS, f"payout-{name}.key.json")
    run(WALLET, "--key", kf, "keygen")
    return run(WALLET, "--key", kf, "address").strip().splitlines()[0]

genesis_names, bonded = E["GENESIS_NAMES"].split(), E["BONDED"].split()
need_names = len(genesis_names) == 18 and len(bonded) == 8
if not need_names:
    raise SystemExit(f"cut-chain18: DRY_RUN expects 18 genesis names and 8 bonded names, got {len(genesis_names)}/{len(bonded)}")
vals = {}
for n in genesis_names + bonded:
    addr, pk, peer = node_keypair(n)
    vals[n] = {"address": addr, "public_key": pk, "peer_id": peer, "payout": wallet_address(n)}
stake = int(E["STAKE_RAND"]) * 10**9

with open(os.path.join(D, "validators.tsv"), "w") as f:
    f.write("# dry-run synthetic validators\n# name\taddress\tpublic_key\tpeer_id\tpayout\n")
    for n in genesis_names:
        v = vals[n]
        f.write(f"{n}\t{v['address']}\t{v['public_key']}\t{v['peer_id']}\t{v['payout']}\n")

for n in bonded:
    v = vals[n]
    raw = (len(bytes.fromhex(v["public_key"])).to_bytes(8, "little") + bytes.fromhex(v["public_key"])).hex()
    with open(os.path.join(D, "registrations", f"{n}.txt"), "w") as f:
        f.write(f"validator {v['address']} on chain 16\nregistration: {raw}\n")

# PQ guardians / pause key: only length-checked (`[0-9a-f]{2624}` = Dilithium2's 1312 bytes) —
# synthetic random bytes are fine, no signature is ever verified against them in this script.
pq_guardians = [secrets.token_hex(1312) for _ in range(8)]
pause_key = secrets.token_hex(1312)
pq_path = os.path.join(D, "pq-guardians.json")
json.dump({"pq_guardians": pq_guardians}, open(pq_path, "w"))
open(os.path.join(D, "pq-guardians.sha256"), "w").write(hashlib.sha256(open(pq_path, "rb").read()).hexdigest())
open(os.path.join(D, "pause-key.pub"), "w").write(pause_key + "\n")

extra = [wallet_address(f"extra{i}") for i in range(3)]
with open(os.path.join(D, "faucet-recipients.txt"), "w") as f:
    for i, a in enumerate(extra):
        f.write(f"extra{i} {a}\n")
with open(os.path.join(D, "alloc-rand.txt"), "w") as f:
    f.write(f"extra0 {extra[0]} 1\n")

locked_tron, locked_sol = int(E["LOCKED_TRON_USDT"]), int(E["LOCKED_SOL_USDT"])
assert locked_tron % 10**8 == 0 and locked_sol % 10**8 == 0, "LOCKED_*_USDT must be whole-RAND-display amounts for the dry-run carry lines"
with open(os.path.join(D, "zusd-carry.txt"), "w") as f:
    f.write(f"extra1 {extra[1]} {locked_tron // 10**8}\n")
    f.write(f"extra2 {extra[2]} {locked_sol // 10**8}\n")

# hc_bundle is a pure function of the guest binary (--bundle-guest v2), independent of chain id,
# validators or anything else — a probe genesis with one throwaway validator reads it exactly as
# the real cut's own genesis call will, so the two match even across separate script invocations.
probe = os.path.join(D, "probe-genesis.json")
out = run(NODE, "genesis", "--chain-id", "16",
          "--validator", f"{vals[genesis_names[0]]['public_key']},{E['STAKE_RAND']},{vals[genesis_names[0]]['payout']}",
          "--bundle-guest", "v2", "--hardening-v6",
          "--epoch-blocks", "1000", "--faucet", "--fri-profile", "production", "--out", probe)
m = re.search(r"hc_bundle ([0-9a-f]{64})\)", out)
if not m:
    raise SystemExit("cut-chain18: DRY_RUN probe genesis printed no hc_bundle")
hc_bundle = m.group(1)

g15 = {
    "hc_bundle": hc_bundle,
    "validators": [{"public_key": vals[n]["public_key"]} for n in genesis_names],
    # The token "switches" (registration_fee, mint_cap_per_day, max_tokens,
    # burn_registration_fee, bound_note_value) must match this script's own env-var defaults
    # exactly — the cut script asserts the chain-18 tokens header equals chain 16's verbatim.
    "tokens": {
        "registration_fee": int(E["REGISTRATION_FEE"]), "mint_cap_per_day": int(E["MINT_CAP_PER_DAY"]),
        "max_tokens": int(E["MAX_TOKENS"]), "burn_registration_fee": True, "bound_note_value": True,
        "tokens": [{
            "name": "zUSD (dry run)", "symbol": "zUSD", "salt": "aa" * 32,
            "backings": [{"chain": b["chain"], "token": b["token"], "decimals": b["decimals"]} for b in BACKINGS],
        }],
    },
    # Bypassed by FAUCET_RECIPIENTS_CHANGED=1 (set for DRY_RUN below) — present only so the
    # comparisons in the cut script's python do not KeyError on a missing "staking" key or a
    # missing "faucet_recipients" (one comparison indexes it directly, before the `or` bypass).
    "staking": {"faucet_recipients": []},
}
json.dump(g15, open(os.path.join(D, "chain16-genesis-stub.json"), "w"))

chain16_hash = secrets.token_hex(32)
open(os.path.join(D, "chain16-hash.txt"), "w").write(chain16_hash)

live_backings, custody = [], {}
for b in BACKINGS:
    entry = dict(b)
    key = f"{b['chain']}:{b['token']}"
    if b["token"] == USDT_TRON:
        entry["locked"] = locked_tron; custody[key] = {"custody": locked_tron // 100}
    elif b["token"] == USDT_SOL:
        entry["locked"] = locked_sol; custody[key] = {"custody": locked_sol // 100}
    else:
        entry["locked"] = 0; custody[key] = {"custody": 0}
    live_backings.append(entry)

emitters = {c: E[f"EMITTER_{c}"] for c in "2345"}
snap = {
    "taken_at": "dry-run",
    "genesis_hash": chain16_hash,
    "status_height": 999999,
    "validators": [
        {"address": vals[n]["address"], "payout": vals[n]["payout"], "stake": stake, "pending": False, "active": True}
        for n in genesis_names + bonded
    ],
    "bridge": {
        "guardians": E["GUARDIANS_JOINED"].split(","),
        "guardian_set_index": int(E["GUARDIAN_SET_INDEX"]),
        "pq_guardians": pq_guardians,
        "pause_key": pause_key,
        "burn_sequence": int(E["BURN_SEQUENCE"]),
        "mint_paused": False,
        "emitter": E["BRIDGE_EMITTER"],
        "rules_v2": {"global_mint_cap_per_window": int(E["GLOBAL_MINT_CAP_PER_WINDOW"]), "cap_window_secs": int(E["CAP_WINDOW_SECS"])},
        "registration_fee": int(E["REGISTRATION_FEE"]),
        "emitters": emitters,
    },
    "tokens": {"tokens": [{"symbol": "zUSD", "index": 1, "authority": {"backings": live_backings}, "total_supply": locked_tron + locked_sol}]},
    "supply": None,
    "source": {"emitters": emitters, "next_sequence": {"2": 2, "3": 2, "4": 2, "5": 2}, "custody": custody},
}
json.dump(snap, open(os.path.join(SNAP, E["SNAPSHOT_BASENAME"]), "w"), indent=1)
print(f"cut-chain18: DRY RUN — synthetic chain 16 at height {snap['status_height']} → {SNAP}/{E['SNAPSHOT_BASENAME']}")
print(f"cut-chain18: DRY RUN — inputs written under {D} (validators.tsv, registrations/, pq-guardians.json, "
      f"pause-key.pub, faucet-recipients.txt, alloc-rand.txt, zusd-carry.txt, chain16-genesis-stub.json)")
print(f"cut-chain18: DRY RUN — hc_bundle {hc_bundle} (probe genesis, guest v2)")
PY
    exit 0
  fi

  python3 - <<'PY'
import base64, json, os, struct, sys, time, urllib.request
E = os.environ
exec(E["BACKINGS_PY"])

def post(url, body, headers=None):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json", "user-agent": "rand-cut-chain18/1", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def rand(method, params=None):
    r = post(E["CHAIN16_RPC"], {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
    if "error" in r:
        sys.exit(f"cut-chain18: {method}: {r['error']}")
    return r["result"]

def eth_call(url, to, data):
    r = post(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": to, "data": data}, "latest"]})
    if "error" in r:
        sys.exit(f"cut-chain18: eth_call {to} on {url}: {r['error']}")
    return int(r["result"], 16)

def tron(contract41, selector, param=""):
    r = post(E["TRON_API"] + "/wallet/triggerconstantcontract",
             {"owner_address": E["TRON_ENDPOINT41"], "contract_address": contract41,
              "function_selector": selector, "parameter": param})
    if not r.get("constant_result"):
        sys.exit(f"cut-chain18: Tron {selector} on {contract41}: {r}")
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
        sys.exit(f"cut-chain18: Solana getProgramAccounts: {r['error']}")
    return [base64.b64decode(a["account"]["data"][0]) for a in r["result"]]

snap = {"taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
snap["genesis_hash"] = rand("rand_getGenesisHash")
if snap["genesis_hash"] != E["CHAIN16_HASH"]:
    sys.exit(f"cut-chain18: {E['CHAIN16_RPC']} serves {snap['genesis_hash']}, not chain 16")
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
    sys.exit(f"cut-chain18: {len(cfgs)} Solana config accounts, expected 1")
off = 1 + 32 * 3 + 1 + 32 + 4
seq["5"] = struct.unpack_from("<Q", cfgs[0], off)[0]
for acc in sol_accounts("4"):
    mint = acc[1:33].hex()
    cu, fe = struct.unpack_from("<QQ", acc, 1 + 32 + 2 + 8 * 4)
    custody[f"5:{mint}"] = {"custody": cu, "fees": fe, "mint": b58(acc[1:33])}
snap["source"] = {"emitters": {c: E[f"EMITTER_{c}"] for c in "2345"}, "next_sequence": seq, "custody": custody}
json.dump(snap, open(os.path.join(E["SNAP"], "chain16-state.json"), "w"), indent=1)
print(f"cut-chain18: snapshot of chain 16 at height {snap['status_height']} → {E['SNAP']}/chain16-state.json")
print(f"cut-chain18: source next sequences {seq}; burn_sequence {snap['bridge']['burn_sequence']}; "
      f"zUSD supply {snap['tokens']['tokens'][0]['total_supply']}")
for k, v in custody.items():
    if v["custody"]:
        print(f"cut-chain18: custody {k[:2]}…{k[-8:]} = {v['custody']}")
PY
  exit 0
fi

# ══ the cut ══════════════════════════════════════════════════════════════════════════════════
[ -n "$CHAIN16_SNAPSHOT" ] || { echo "cut-chain18: CHAIN16_SNAPSHOT is unset — run \`$0 snapshot <dir>\` while chain 16 is up" >&2; exit 1; }
if [ "$DRY_RUN" = 1 ]; then
  # Unconditional, not `${VAR:-…}`: every one of these eight already has a real default from the
  # "public inputs" block above (e.g. $HOME/.rand-chain16/…), so a fill-if-empty default would be
  # a no-op here. DRY_RUN always reads the files `snapshot` generated — it is not a way to mix one
  # real input with synthetic ones; pass a real value for one variable and unset DRY_RUN instead.
  DR=$CHAIN16_SNAPSHOT/dryrun
  [ -d "$DR" ] || { echo "cut-chain18: DRY_RUN=1 needs \`DRY_RUN=1 $0 snapshot $CHAIN16_SNAPSHOT\` run first (no $DR)" >&2; exit 1; }
  VALIDATORS_TSV=$DR/validators.tsv
  REGISTRATIONS=$DR/registrations
  PQ_GUARDIANS=$DR/pq-guardians.json
  PQ_GUARDIANS_SHA256=$(cat "$DR/pq-guardians.sha256")
  PAUSE_KEY=$DR/pause-key.pub
  FAUCET_RECIPIENTS=$DR/faucet-recipients.txt
  ALLOC_ADDRESSES=$DR/alloc-rand.txt
  ZUSD_CARRY=$DR/zusd-carry.txt
  CHAIN16_GENESIS=$DR/chain16-genesis-stub.json
  CHAIN16_HASH=$(cat "$DR/chain16-hash.txt")
  # The synthetic predecessor's staking section has no faucet_recipients worth matching (see the
  # generator above) — this is the one env var a real cut would set deliberately; DRY_RUN sets it
  # unconditionally, since the whole predecessor snapshot is synthetic in this mode anyway.
  FAUCET_RECIPIENTS_CHANGED=1
  export VALIDATORS_TSV REGISTRATIONS PQ_GUARDIANS PQ_GUARDIANS_SHA256 PAUSE_KEY FAUCET_RECIPIENTS \
    ALLOC_ADDRESSES ZUSD_CARRY CHAIN16_GENESIS CHAIN16_HASH FAUCET_RECIPIENTS_CHANGED
  echo "cut-chain18: DRY RUN — reading synthetic inputs from $DR (chain16_hash ${CHAIN16_HASH:0:16}…)"
fi
[ -n "$CHAIN16_HASH" ] || { echo "cut-chain18: CHAIN16_HASH is unset — chain 16 was not live when this script was written (see the header); set it once chain 16's genesis hash is known, or run with DRY_RUN=1" >&2; exit 1; }
SNAPSHOT_FILE=$CHAIN16_SNAPSHOT/$SNAPSHOT_BASENAME; export SNAPSHOT_FILE
for bin in "$NODE" "$WALLET"; do
  [ -x "$bin" ] || { echo "cut-chain18: $bin is not executable — the cs8/gas release binaries (v0.6.6+)" >&2; exit 1; }
done
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$PQ_GUARDIANS" "$PAUSE_KEY" "$FAUCET_RECIPIENTS" "$ALLOC_ADDRESSES" "$ZUSD_CARRY" "$CHAIN16_GENESIS"; do
  [ -f "$f" ] || { echo "cut-chain18: missing $f" >&2; exit 1; }
done
# Every operator input lives outside the repository (OPS-1): the cut reads public halves only,
# but a key-shaped file inside the tree is refused on principle.
for f in "$SNAPSHOT_FILE" "$VALIDATORS_TSV" "$PQ_GUARDIANS" "$PAUSE_KEY" "$FAUCET_RECIPIENTS" "$ALLOC_ADDRESSES" "$ZUSD_CARRY"; do
  refuse_in_tree_key "$f"
done
for n in $BONDED; do refuse_in_tree_key "$REGISTRATIONS/$n.txt"; done
[ "$(shasum -a 256 "$PQ_GUARDIANS" | cut -c1-64)" = "$PQ_GUARDIANS_SHA256" ] \
  || { echo "cut-chain18: $PQ_GUARDIANS is not the file the bridge session published (sha256)" >&2; exit 1; }
[ ! -e "$OUT" ] || { echo "cut-chain18: $OUT already exists — a genesis is cut once; move it aside deliberately" >&2; exit 1; }
"$NODE" genesis --help | grep -q -- --hardening-v6 || { echo "cut-chain18: $NODE has no --hardening-v6 (not v0.6+)" >&2; exit 1; }
"$NODE" genesis --help | grep -q -- --bundle-guest || { echo "cut-chain18: $NODE has no --bundle-guest" >&2; exit 1; }
"$NODE" genesis --help | grep -q -- --gas-price || { echo "cut-chain18: $NODE has no --gas-price (not the gas/cs8 build)" >&2; exit 1; }
"$NODE" genesis --help | grep -q -- --gas-dynamic || { echo "cut-chain18: $NODE has no --gas-dynamic (Phase 2, spec §7.1)" >&2; exit 1; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
export TMP

# ── the validator list: 18 from the chain-14 public table, 8 from the chain-16 registrations ───
python3 - <<'PY'
import json, os, sys
E = os.environ
need = lambda c, m: c or sys.exit(f"cut-chain18: {m}")
snap = json.load(open(E["SNAPSHOT_FILE"]))
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
    need(head[0] == "validator" and head[2:] == ["on", "chain", "16"] and reg[0] == "registration:", f"{name}.txt is not a chain-16 registration")
    raw = bytes.fromhex(reg[1])
    n = int.from_bytes(raw[:8], "little")
    need(n == 1312, f"{name}.txt: a {n}-byte public key, expected Dilithium2's 1312")
    addr = head[1]
    need(addr in register, f"{name} ({addr}) is not in chain 16's register")
    rows.append({"name": name, "address": addr, "public_key": raw[8:8 + n].hex(), "payout": register[addr]["payout"]})
stake = int(E["STAKE_RAND"]) * 10**9
need(len(rows) == len(register) == 26, f"{len(rows)} validators assembled, chain 16's register holds {len(register)}")
for r in rows:
    live = register.get(r["address"])
    need(live is not None, f"{r['name']} ({r['address']}) is not in chain 16's register")
    need(live["payout"] == r["payout"], f"{r['name']}: payout differs from chain 16's register")
    need(int(live["stake"]) == stake and not live["pending"], f"{r['name']}: chain 16 stake {live['stake']} / pending {live['pending']}, not a plain {stake}")
    need(live["active"], f"{r['name']} is not active on chain 16")
need(len({r["public_key"] for r in rows}) == 26 and len({r["address"] for r in rows}) == 26, "a validator twice")
g15 = {v["public_key"] for v in json.load(open(E["CHAIN16_GENESIS"]))["validators"]}
need({r["public_key"] for r in rows if r["name"] in E["GENESIS_NAMES"].split()} == g15, "the eighteen are not chain 16's genesis keys")
json.dump(rows, open(os.path.join(E["TMP"], "validators.json"), "w"))
with open(os.path.join(E["TMP"], "validator-args"), "w") as f:
    for r in rows:
        f.write(f"--validator\n{r['public_key']},{E['STAKE_RAND']},{r['payout']}\n")
PY

cat > "$TMP/tokens.json" <<JSON
{ "registration_fee": $REGISTRATION_FEE, "mint_cap_per_day": $MINT_CAP_PER_DAY, "tokens": [] }
JSON

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
  "$NODE" alloc-note --to "$addr" --amount "$amount" --asset 1 | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)))' >> "$TMP/token-notes.jsonl"
  echo "cut-chain18: zUSD genesis note, $amount zUSD to $label"
done < "$ZUSD_CARRY"

echo "cut-chain18: writing the base file (its printed hash is NOT chain 18's)"
"$NODE" genesis --chain-id "$CHAIN_ID" "${args[@]}" \
  --max-program-words "$MAX_PROGRAM_WORDS" \
  --max-proof-bytes "$MAX_PROOF_BYTES" \
  --max-block-bytes "$MAX_BLOCK_BYTES" \
  --max-call-envelope-bytes "$MAX_CALL_ENVELOPE_BYTES" \
  --max-program-public-words "$MAX_PROGRAM_PUBLIC_WORDS" \
  --tokens "$TMP/tokens.json" \
  --bundle-guest v2 --hardening-v6 \
  --gas-price "$GAS_PRICE" --byte-price "$BYTE_PRICE" --bundle-gas-limit "$BUNDLE_GAS_LIMIT" --gas-dynamic "$GAS_DYNAMIC" \
  --epoch-blocks 1000 --faucet --fri-profile production --out "$TMP/genesis.json" | tee "$TMP/genesis.out"

HC_REPORTED=$(sed -n 's/.*hc_bundle \([0-9a-f]\{64\}\))$/\1/p' "$TMP/genesis.out")
[ -n "$HC_REPORTED" ] || { echo "cut-chain18: could not read hc_bundle out of the genesis command's output" >&2; exit 1; }
export HC_REPORTED
# Everything is built in $TMP and lands at $OUT only once it has passed every check and `init`,
# so a refused cut leaves no half-made file behind to be mistaken for the genesis.
FINAL_OUT=$OUT; OUT=$TMP/genesis.json; export OUT

python3 - <<'PY'
import json, os, re, sys, time
E = os.environ
exec(E["BACKINGS_PY"])
out = E["OUT"]
g = json.load(open(out))
g15 = json.load(open(E["CHAIN16_GENESIS"]))
snap = json.load(open(E["SNAPSHOT_FILE"]))
sb = snap["bridge"]

def need(cond, msg):
    if not cond:
        sys.exit(f"cut-chain18: {msg}")

need(snap["genesis_hash"] == E["CHAIN16_HASH"], "the snapshot is not of chain 16")

# ── bridge: chain 16's live values, the floor added ───────────────────────────────────────────
pq_guardians = json.load(open(E["PQ_GUARDIANS"]))["pq_guardians"]
pause_key = open(E["PAUSE_KEY"]).read().strip()
guardians = E["GUARDIANS_JOINED"].split(",")
need(len(pq_guardians) == len(guardians) == 8, f"{len(pq_guardians)} pq_guardians against {len(guardians)} guardians, expected 8 and 8")
for i, k in enumerate(pq_guardians + [pause_key]):
    need(re.fullmatch(r"[0-9a-f]{2624}", k), f"PQ key {i} is not 2624 lowercase hex characters")
need(pause_key not in pq_guardians, "pause_key is one of the pq_guardians")
need(len(set(pq_guardians)) == 8 and len(set(guardians)) == 8, "duplicate guardian key")
# Chain 16's live bridge must still be what chain 18 starts from: no rotation, no PQ or pause-key
# rotation, no burn since the snapshot values these defaults encode.
need(sb["guardians"] == guardians, "chain 16's live guardian set differs from GUARDIANS")
need(sb["guardian_set_index"] == int(E["GUARDIAN_SET_INDEX"]), f"chain 16 is at guardian set {sb['guardian_set_index']}")
need(sb["pq_guardians"] == pq_guardians, "chain 16's live PQ guardians differ from PQ_GUARDIANS")
need(sb["pause_key"] == pause_key, "chain 16's live pause key differs from PAUSE_KEY")
need(sb["burn_sequence"] == int(E["BURN_SEQUENCE"]), f"chain 16's next burn sequence is {sb['burn_sequence']}, BURN_SEQUENCE {E['BURN_SEQUENCE']}")
need(not sb["mint_paused"], "chain 16's mints are paused — decide what chain 18 starts with")
need(sb["emitter"] == E["BRIDGE_EMITTER"], "the Rand-side emitter differs from chain 16's")
need(int(sb["rules_v2"]["global_mint_cap_per_window"]) == int(E["GLOBAL_MINT_CAP_PER_WINDOW"])
     and sb["rules_v2"]["cap_window_secs"] == int(E["CAP_WINDOW_SECS"]), "rules_v2 differs from chain 16's")
need(int(sb["registration_fee"]) == int(E["REGISTRATION_FEE"]), "registration_fee differs from chain 16's")
emitters = {c: E[f"EMITTER_{c}"] for c in "2345"}
for c, e in emitters.items():
    need(re.fullmatch(r"[0-9a-f]{64}", e), f"EMITTER_{c} is not 64 lowercase hex characters")
need(snap["source"]["emitters"] == emitters, "the snapshot read custody/sequences at other emitters than this cut lists")
redeployed = [c for c in "2345" if emitters[c] != sb["emitters"][c]]

floor = {}
for c in "2345":
    v = E[f"MIN_INBOUND_{c}"]
    next_seq = snap["source"]["next_sequence"][c]
    if v == "none":
        need(c in redeployed, f"MIN_INBOUND_{c}=none on an endpoint chain 14/16 minted from — its old locks would replay")
        continue
    need(v.isdigit() and int(v) > 0, f"MIN_INBOUND_{c} is {v!r}: a positive sequence or `none`")
    # Above the endpoint's next sequence the floor would refuse locks nobody has minted yet.
    need(int(v) <= next_seq, f"MIN_INBOUND_{c}={v} is above chain {c}'s endpoint next sequence {next_seq}")
    if int(v) < next_seq and not E.get("ALLOW_UNMINTED_LOCKS"):
        sys.exit(f"cut-chain18: chain {c}'s endpoint has emitted up to {next_seq - 1} but the floor is {v}: locks "
                 f"{v}..{next_seq - 1} will mint on chain 18 — drain them on chain 16 first, or set ALLOW_UNMINTED_LOCKS=1")
    floor[c] = int(v)
need(floor, "no replay floor at all — C15-1 needs one for every endpoint chain 16 inherited")

g["bridge"] = {
    "emitter": E["BRIDGE_EMITTER"],
    "guardians": guardians,
    "emitters": emitters,
    "pq_guardians": pq_guardians,
    "pause_key": pause_key,
    "rules_v2": {"global_mint_cap_per_window": int(E["GLOBAL_MINT_CAP_PER_WINDOW"]),
                 "cap_window_secs": int(E["CAP_WINDOW_SECS"])},
    "guardian_set_index": int(E["GUARDIAN_SET_INDEX"]),
    "burn_sequence": int(E["BURN_SEQUENCE"]),
    "min_inbound_sequence": floor,
}

# ── tokens: zUSD at genesis, custody == locked == chain 16's supply ─────────────────────────────
locked = {4: int(E["LOCKED_TRON_USDT"]), 5: int(E["LOCKED_SOL_USDT"])}
backings = []
for b in BACKINGS:
    b = dict(b)
    if b["token"] == USDT_TRON:
        b["locked"] = locked[4]
    elif b["token"] == USDT_SOL:
        b["locked"] = locked[5]
    backings.append({k: v for k, v in b.items() if k != "locked" or v > 0})
# The backing list (order, token, decimals) is chain 16's; the locked amounts are whatever chain 16
# holds at the snapshot, checked just below.
need([{k: v for k, v in b.items() if k != "locked"} for b in backings]
     == [{k: v for k, v in b.items() if k != "locked"} for b in g15["tokens"]["tokens"][0]["backings"]],
     "the backings are not chain 16's (order, tokens or decimals)")
tok = snap["tokens"]["tokens"]
need(len(tok) == 1 and tok[0]["symbol"] == "zUSD" and tok[0]["index"] == 1, "chain 16 lists another token than zUSD alone")
live_backings = tok[0]["authority"]["backings"]
need([(b["chain"], b["token"], b["decimals"]) for b in live_backings] == [(b["chain"], b["token"], b["decimals"]) for b in BACKINGS],
     "chain 16's live backings differ from the list")
for lb, b in zip(live_backings, backings):
    need(int(lb["locked"]) == b.get("locked", 0), f"chain 16 locks {lb['locked']} on chain {b['chain']} {b['token'][-8:]}, the cut {b.get('locked', 0)}")
locked_total = sum(b.get("locked", 0) for b in backings)
need(int(tok[0]["total_supply"]) == locked_total, f"chain 16's zUSD supply {tok[0]['total_supply']} != Σ locked {locked_total}")
# Custody on the source chains, in each backing's own decimals, scaled to zUSD's eight.
for b in BACKINGS:
    key = f"{b['chain']}:{b['token']}"
    have = snap["source"]["custody"].get(key)
    need(have is not None, f"the snapshot has no custody reading for {key}")
    scaled = have["custody"] * 10**8 // 10**b["decimals"] if b["decimals"] >= 8 else have["custody"] * 10**(8 - b["decimals"])
    if b["decimals"] > 8:
        need(have["custody"] % 10**(b["decimals"] - 8) == 0, f"custody {key} has dust below zUSD's eighth decimal")
    want = next((x.get("locked", 0) for x in backings if x["chain"] == b["chain"] and x["token"] == b["token"]), 0)
    need(scaled == want, f"source custody {key} = {have['custody']} (= {scaled} zUSD units), genesis locks {want}")

t = g["tokens"]
need(t["registration_fee"] == int(E["REGISTRATION_FEE"]) and t["mint_cap_per_day"] == int(E["MINT_CAP_PER_DAY"]), "tokens header")
z15 = g15["tokens"]["tokens"][0]
t["tokens"] = [{"name": z15["name"], "symbol": z15["symbol"], "salt": z15["salt"], "backings": backings}]
t["max_tokens"] = int(E["MAX_TOKENS"])
t["burn_registration_fee"] = True
t["bound_note_value"] = True
need({k: v for k, v in t.items() if k != "tokens"} == {k: v for k, v in g15["tokens"].items() if k != "tokens"}, "the token switches are not chain 16's")

token_notes = [json.loads(l) for l in open(os.path.join(E["TMP"], "token-notes.jsonl")) if l.strip()]
need(token_notes, "ZUSD_CARRY carries no note")
notes_total = 0
for i, n in enumerate(token_notes):
    need(n.get("opening", {}).get("asset") == 1, f"token note {i} is not an asset-1 (zUSD) note with an opening")
    notes_total += n["amount"]
need(notes_total == locked_total, f"zUSD genesis notes sum to {notes_total}, backings lock {locked_total} — they must be equal")
g["alloc"] = g["alloc"] + token_notes

# ── staking: chain 16's, plus LEDGER-1's minter list ──────────────────────────────────────────
recipients = [l.split()[-1] for l in open(E["FAUCET_RECIPIENTS"]) if l.strip() and not l.startswith("#")]
need(recipients and all(r.startswith("rand1") for r in recipients), "faucet_recipients must be rand1… addresses")
need(len(set(recipients)) == len(recipients), "a faucet recipient is listed twice")
need(recipients == g15["staking"]["faucet_recipients"] or E.get("FAUCET_RECIPIENTS_CHANGED"),
     "the faucet allowlist differs from chain 16's (set FAUCET_RECIPIENTS_CHANGED=1 if that is the decision)")
vals = {v["name"]: v for v in json.load(open(os.path.join(E["TMP"], "validators.json")))}
minters = []
for name in E["FAUCET_MINTERS"].split():
    need(name in vals, f"FAUCET_MINTERS names {name}, not a chain-18 validator")
    minters.append(vals[name]["address"])
need(minters and len(set(minters)) == len(minters), "faucet_minters empty or a key twice")
g["staking"] = {
    "faucet_budget_per_epoch": E["FAUCET_BUDGET_PER_EPOCH"],
    "bond_activation_epochs": int(E["BOND_ACTIVATION_EPOCHS"]),
    "max_weight_bps": int(E["MAX_WEIGHT_BPS"]),
    "max_stake_entry_per_epoch": E["MAX_STAKE_ENTRY_PER_EPOCH"],
    "registration_v2": True,
    "faucet_recipients": recipients,
    "faucet_minters": minters,
}
need({k: v for k, v in g["staking"].items() if k != "faucet_minters"} == g15["staking"] or E.get("FAUCET_RECIPIENTS_CHANGED"),
     "the staking section is not chain 16's")
g["consensus_domain"] = 1

order = ["chain_id", "timestamp_ms", "validators", "alloc", "faucet", "confidential", "fri_profile",
         "hc_bundle", "bridge", "tokens", "aggregation", "consensus_domain", "staking", "epoch_blocks",
         "max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes",
         "max_program_public_words", "envelope_bytes", "vesting", "hardening_v6", "gas"]
unknown = [k for k in g if k not in order]
need(not unknown, f"the genesis command wrote fields this script does not know: {unknown}")
g = {k: g[k] for k in order if k in g}

# ── assertions over the bytes that ship ───────────────────────────────────────────────────────
need(g["chain_id"] == int(E["CHAIN_ID"]) == 18, f"chain_id is {g['chain_id']}")
need(g["consensus_domain"] == 1, "consensus_domain is not 1")
need(g.get("hardening_v6") is True, "hardening_v6 is not true — --hardening-v6 did not take")
need(g["hc_bundle"] == E["HC_REPORTED"], "hc_bundle is not what this rand-node reports")
# Constraint set 8 changes the STARK verifier key, not the hidden-asset guest's own words: unlike
# chain 16's script (which asserted its hc_bundle differed from chain 15's v1 guest), chain 18's
# hc_bundle must be UNCHANGED from chain 16's — a different value here means --bundle-guest v2
# silently picked up a different guest program than chain 16 ran, which would be a real problem.
need(g["hc_bundle"] == g15["hc_bundle"], "hc_bundle differs from chain 16's — --bundle-guest v2 is not the same guest chain 16 runs")
if E.get("EXPECT_HC_BUNDLE"):
    need(g["hc_bundle"] == E["EXPECT_HC_BUNDLE"], f"hc_bundle {g['hc_bundle']} is not EXPECT_HC_BUNDLE")
need(g["faucet"] is True, "faucet is not true — the allowlist needs it on")
need(g["confidential"] is True and g["fri_profile"] == "production", "confidential/fri_profile wrong")
need("aggregation" not in g and "vesting" not in g and "envelope_bytes" not in g,
     "an aggregation, vesting or envelope_bytes section is present — none belongs in chain 18")
# The gas section (spec §4.2, §7.1): present, Phase 2's dynamic controller on, and — the rule
# genesis.rs's validate() enforces as GenesisError::DynamicGasWithAggregation — never beside an
# aggregation section (already asserted absent, just above; this repeats the assertion against the
# gas section itself so a future edit that adds aggregation back cannot silently defeat it).
need(g.get("gas") is not None, "the gas section is missing — --gas-price did not take")
need("aggregation" not in g, "gas.dynamic cannot ship beside an aggregation section (GenesisError::DynamicGasWithAggregation)")
gas = g["gas"]
need(int(gas["gas_price"]) == int(E["GAS_PRICE"]) and int(gas["byte_price"]) == int(E["BYTE_PRICE"]),
     f"gas prices are {gas['gas_price']}/{gas['byte_price']}, expected {E['GAS_PRICE']}/{E['BYTE_PRICE']}")
need(gas["bundle_gas_limit"] == int(E["BUNDLE_GAS_LIMIT"]), f"bundle_gas_limit is {gas['bundle_gas_limit']}")
need(gas.get("dynamic") is not None, "gas.dynamic is missing — --gas-dynamic did not take (Phase 2 is off)")
dyn = gas["dynamic"]
want_bytes, want_gas, want_bps = (int(x) for x in E["GAS_DYNAMIC"].split(","))
need(dyn["target_block_bytes"] == want_bytes and dyn["target_block_gas"] == want_gas and dyn["adjust_bps"] == want_bps,
     f"gas.dynamic targets are {dyn}, expected {E['GAS_DYNAMIC']}")
need(dyn["target_block_bytes"] * 2 == int(E["MAX_BLOCK_BYTES"]),
     f"target_block_bytes {dyn['target_block_bytes']} is not half max_block_bytes {E['MAX_BLOCK_BYTES']}")
need(int(dyn["min_gas_price"]) == int(E["GAS_PRICE"]) and int(dyn["min_byte_price"]) == int(E["BYTE_PRICE"]),
     "gas.dynamic's floors are not the section's own starting prices")
need(g["epoch_blocks"] == 1000, "epoch_blocks is not 1000")
need(len(g["validators"]) == 26 and all(v["stake"] == int(E["STAKE_RAND"]) * 10**9 for v in g["validators"]), "validators wrong")
need([v["public_key"] for v in g["validators"]] == [vals[n]["public_key"] for n in vals], "validator order/keys wrong")
need(len(g["staking"]["faucet_minters"]) == len(E["FAUCET_MINTERS"].split()), "faucet_minters missing")
need(g["bridge"]["min_inbound_sequence"], "min_inbound_sequence missing")
for i, n in enumerate(g["alloc"]):
    need(n.get("opening") is not None, f"alloc note {i} has no opening (core I-2)")
need(sum(n["amount"] for n in g["alloc"] if n["opening"].get("asset", 0) == 1) == locked_total, "Σ zUSD notes != Σ locked")
for k, want in (("max_program_words", "MAX_PROGRAM_WORDS"), ("max_proof_bytes", "MAX_PROOF_BYTES"),
                ("max_block_bytes", "MAX_BLOCK_BYTES"), ("max_call_envelope_bytes", "MAX_CALL_ENVELOPE_BYTES"),
                ("max_program_public_words", "MAX_PROGRAM_PUBLIC_WORDS")):
    need(g[k] == int(E[want]), f"{k} is {g[k]}")
now_ms = int(time.time() * 1000)
need(g["timestamp_ms"] <= now_ms + 15_000, "timestamp_ms is in the future beyond the 15 s vote drift bound")

json.dump(g, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(f"cut-chain18: spliced bridge (set {g['bridge']['guardian_set_index']}, burn seq {g['bridge']['burn_sequence']}, "
      f"floor {floor}, redeployed {redeployed or 'none'}), zUSD at genesis (locked {locked_total} == notes {notes_total} "
      f"== chain 16 supply == custody, {len(token_notes)} note(s)), staking ({len(recipients)} recipients, "
      f"{len(minters)} minters), consensus_domain 1, hardening_v6")
PY

INIT=$("$NODE" init --datadir "$TMP/probe" --genesis "$OUT")
echo "$INIT"
HASH=$(printf '%s\n' "$INIT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ -n "$HASH" ] || { echo "cut-chain18: rand-node init printed no genesis hash" >&2; exit 1; }
[ ! -e "$FINAL_OUT" ] || { echo "cut-chain18: $FINAL_OUT appeared during the cut — refusing to overwrite it" >&2; exit 1; }
cp "$OUT" "$FINAL_OUT"; OUT=$FINAL_OUT
TS=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['timestamp_ms'])" "$OUT")
AGE=$(( ( $(date +%s) * 1000 - TS ) / 1000 ))

# DRY_RUN=1 must be unmistakable in the one place an operator is most likely to skim: every line
# of this banner is prefixed, on top of $OUT and the snapshot filename already being distinct.
BANNER_TAG=""
[ "$DRY_RUN" != 1 ] || BANNER_TAG="DRY RUN — "

cat <<EOF

${BANNER_TAG}cut-chain18: wrote $OUT (sha256 $(shasum -a 256 "$OUT" | cut -c1-64))
${BANNER_TAG}cut-chain18: genesis hash $HASH
${BANNER_TAG}cut-chain18: chain id $CHAIN_ID, hc_bundle $HC_REPORTED (guest v2, == chain 16's), hardening_v6, consensus_domain 1, no aggregation
${BANNER_TAG}cut-chain18: gas price $GAS_PRICE/gas, $BYTE_PRICE/KiB, bundle limit $BUNDLE_GAS_LIMIT, dynamic $GAS_DYNAMIC
${BANNER_TAG}cut-chain18: 26 validators × $STAKE_RAND RAND (quorum 18); faucet minters: $FAUCET_MINTERS
${BANNER_TAG}cut-chain18: bridge set $GUARDIAN_SET_INDEX, burn sequence $BURN_SEQUENCE, floors 2:$MIN_INBOUND_2 3:$MIN_INBOUND_3 4:$MIN_INBOUND_4 5:$MIN_INBOUND_5
${BANNER_TAG}cut-chain18: zUSD at genesis — locked Tron-USDT $LOCKED_TRON_USDT, Sol-USDT $LOCKED_SOL_USDT

${BANNER_TAG}⚠  Stamped $AGE s ago; the chain's clock starts there. Launch within MINUTES, or delete $OUT and re-cut.
EOF
