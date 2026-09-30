# Sourced by the chain-cut scripts (audit v6, OPS-7): the written cut policy of docs/deploy.md,
# "Cut policy", made mechanical. Chains 15 to 18 were four hard forks in 2.7 days, each on one
# operator's go, none with a list of what it carried and dropped written beforehand. A cut script
# sources this file and calls, before it stops anything:
#
#   require_cut_record <file>            returns 1 unless <file> exists and carries a non-empty
#                                        `reason:`, `carries:`, `drops:`, `clients:`,
#                                        `second-operator:` and `rollback:` line
#                                        (deploy/cut-record.template is the form)
#   refuse_reused_chain_id <id>          returns 1 when any deploy/genesis*.json in this
#                                        repository already has that `chain_id`, or <id> is not a
#                                        positive integer
#   require_second_rebuild <file> <hash> returns 1 unless <file> carries `second-hash: <hash>` —
#                                        the genesis hash the second operator got by rebuilding the
#                                        genesis from the tag on another machine — equal to <hash>,
#                                        the author's
#
# Each prints why on stderr. They return rather than exit, so a caller under `set -e` stops and a
# caller that wants to collect every refusal can. What this cannot check: that the record is
# true, that it was published before the cut, that the second operator is a second person. Those
# are the policy's, and the record is the evidence.
#
#   SELFTEST=1 bash deploy/lib/cut-policy.sh     # exercises all three on temp files, no network
#
# CUT_POLICY_GENESIS_DIR overrides the directory scanned for genesis files (the selftest's use).

CUT_RECORD_FIELDS="reason carries drops clients second-operator rollback"

# The value of `<field>:` in <file>: the rest of the first line that starts with it, trimmed.
_cut_record_value() {
  local file=$1 field=$2
  sed -n "s/^${field}:[[:space:]]*//p" "$file" | head -1 | sed 's/[[:space:]]*$//'
}

require_cut_record() {
  local file=${1:-} field value missing=""
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    echo "cut-policy: no cut record at '${file}' — copy deploy/cut-record.template, fill it in and publish it before the cut (docs/deploy.md, \"Cut policy\")" >&2
    return 1
  fi
  for field in $CUT_RECORD_FIELDS; do
    value=$(_cut_record_value "$file" "$field")
    case "$value" in
      ""|"<"*">"|TODO*|todo*) missing="$missing $field" ;;
    esac
  done
  if [ -n "$missing" ]; then
    echo "cut-policy: refusing the cut — $file has no value for:$missing" >&2
    echo "cut-policy: every one of '$CUT_RECORD_FIELDS' needs a non-empty line (write 'nothing' for an empty list, not a blank)" >&2
    return 1
  fi
}

refuse_reused_chain_id() {
  local id=${1:-} dir
  case "$id" in
    ""|*[!0-9]*|0) echo "cut-policy: '$id' is not a chain id (a positive integer)" >&2; return 1 ;;
  esac
  dir=${CUT_POLICY_GENESIS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}
  python3 - "$id" "$dir" <<'PY'
import glob, json, os, sys
want, d = int(sys.argv[1]), sys.argv[2]
files = sorted(glob.glob(os.path.join(d, "genesis*.json")))
if not files:
    sys.stderr.write(f"cut-policy: no genesis*.json under {d} — cannot tell whether chain id {want} was used\n")
    sys.exit(1)
used = []
for f in files:
    try:
        cid = json.load(open(f)).get("chain_id")
    except Exception as e:
        sys.stderr.write(f"cut-policy: cannot read {f}: {e}\n")
        sys.exit(1)
    if cid == want:
        used.append(os.path.basename(f))
if used:
    sys.stderr.write(f"cut-policy: refusing chain id {want} — already used by {', '.join(used)}; a chain id is never reused (signatures and bridge messages bind it)\n")
    sys.exit(1)
PY
}

require_second_rebuild() {
  local file=${1:-} hash=${2:-} second
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    echo "cut-policy: no cut record at '${file}'" >&2
    return 1
  fi
  case "$hash" in
    *[!0-9a-f]*|"") echo "cut-policy: '$hash' is not a genesis hash (64 lowercase hex)" >&2; return 1 ;;
  esac
  if [ ${#hash} -ne 64 ]; then
    echo "cut-policy: '$hash' is not a genesis hash (64 lowercase hex)" >&2
    return 1
  fi
  second=$(_cut_record_value "$file" "second-hash")
  if [ -z "$second" ]; then
    echo "cut-policy: refusing to publish genesis $hash — $file has no 'second-hash:' line; the second operator rebuilds the genesis from the tag on another machine and writes the hash they got" >&2
    return 1
  fi
  if [ "$second" != "$hash" ]; then
    echo "cut-policy: refusing to publish — the author's genesis hash $hash and the second operator's $second differ" >&2
    return 1
  fi
}

# ══ SELFTEST (only when this file is run, not sourced) ═══════════════════════════════════════
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${SELFTEST:-}" = 1 ]; then
  set -u
  ST=$(mktemp -d "${TMPDIR:-/tmp}/cut-policy-selftest.XXXXXX")
  trap 'rm -rf "$ST"' EXIT
  PASS=0; FAIL=0
  ok()  { PASS=$((PASS + 1)); echo "  ok   $1"; }
  bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }
  accepts() { local what=$1; shift; if "$@" 2>"$ST/err"; then ok "$what"; else bad "$what — refused: $(cat "$ST/err")"; fi; }
  refuses() { local what=$1; shift; if "$@" 2>"$ST/err"; then bad "$what — accepted"; else ok "$what"; fi; }

  full() {
    cat <<'EOF'
# a filled record
reason: constraint set 9 changes every verifier key; a rolling update cannot carry it
carries: the validator register; zUSD per backing; operator wallets w1..w5 at their balances
drops: nothing
clients: rand CLI v0.7.0; clients repo at tag v0.7.0; randscan; website WASM; bridge relayer
second-operator: operator-b, rebuilt on host-b
rollback: keep the old data dirs and *.pre-c19 binaries for a day; all-stop, re-point, all-start
EOF
  }
  full > "$ST/good"
  accepts "a complete record is accepted" require_cut_record "$ST/good"
  refuses "a missing record is refused" require_cut_record "$ST/absent"
  refuses "no argument is refused" require_cut_record
  for f in $CUT_RECORD_FIELDS; do
    full | grep -v "^$f:" > "$ST/no-$f"
    refuses "a record without '$f:' is refused" require_cut_record "$ST/no-$f"
    full | sed "s/^$f:.*/$f:   /" > "$ST/blank-$f"
    refuses "a record with a blank '$f:' is refused" require_cut_record "$ST/blank-$f"
  done
  full | sed 's/^drops:.*/drops: <every non-operator balance not carried>/' > "$ST/placeholder"
  refuses "the template's placeholder is not a value" require_cut_record "$ST/placeholder"
  HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
  if [ -f "$HERE/../cut-record.template" ]; then
    refuses "the unfilled template is refused" require_cut_record "$HERE/../cut-record.template"
  else
    bad "deploy/cut-record.template is missing"
  fi
  if require_cut_record "$ST/no-drops" 2>"$ST/err"; then :; fi
  if grep -q "drops" "$ST/err"; then ok "the refusal names the missing field"; else bad "the refusal does not name the missing field: $(cat "$ST/err")"; fi

  mkdir "$ST/gen" "$ST/empty"
  echo '{"chain_id": 17, "validators": []}' > "$ST/gen/genesis-chain17.json"
  echo '{"chain_id": 18, "validators": []}' > "$ST/gen/genesis-chain18.json"
  echo '{"chain_id": 5}' > "$ST/gen/genesis.json"
  export CUT_POLICY_GENESIS_DIR="$ST/gen"
  accepts "a chain id no genesis file has is accepted" refuse_reused_chain_id 19
  refuses "a chain id a genesis-chainN.json has is refused" refuse_reused_chain_id 18
  refuses "a chain id the bare genesis.json has is refused" refuse_reused_chain_id 5
  refuses "a non-numeric chain id is refused" refuse_reused_chain_id 18a
  refuses "chain id 0 is refused" refuse_reused_chain_id 0
  refuses "an empty chain id is refused" refuse_reused_chain_id ""
  if refuse_reused_chain_id 18 2>"$ST/err"; then :; fi
  if grep -q "genesis-chain18.json" "$ST/err"; then ok "the refusal names the file that used the id"; else bad "the refusal does not name the file: $(cat "$ST/err")"; fi
  export CUT_POLICY_GENESIS_DIR="$ST/empty"
  refuses "a directory with no genesis file fails closed" refuse_reused_chain_id 19
  echo 'not json' > "$ST/empty/genesis-chain3.json"
  refuses "an unreadable genesis file fails closed" refuse_reused_chain_id 19
  unset CUT_POLICY_GENESIS_DIR
  # The repository's own files: every chain id they hold is refused, the next one is not.
  LIVE=$(python3 -c "import glob,json,sys; print(max(json.load(open(f)).get('chain_id',0) for f in glob.glob(sys.argv[1]+'/genesis*.json')))" "$HERE/..")
  refuses "this repository's highest chain id ($LIVE) is refused" refuse_reused_chain_id "$LIVE"
  accepts "the id after it ($((LIVE + 1))) is accepted" refuse_reused_chain_id "$((LIVE + 1))"

  H=a7cb020cc99a33c83fc38cfa0ec1db357f67fbf8b6dab13ab1d9812280b4da76
  { full; echo "second-hash: $H"; } > "$ST/rebuilt"
  accepts "a matching second-operator hash is accepted" require_second_rebuild "$ST/rebuilt" "$H"
  refuses "a record without second-hash is refused" require_second_rebuild "$ST/good" "$H"
  refuses "a different second-operator hash is refused" require_second_rebuild "$ST/rebuilt" "${H%6}7"
  refuses "a malformed author hash is refused" require_second_rebuild "$ST/rebuilt" "a7cb020c"

  echo "cut-policy selftest: $PASS passed, $FAIL failed"
  [ "$FAIL" -eq 0 ]
  exit $?
fi
