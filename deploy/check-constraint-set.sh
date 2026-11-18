#!/usr/bin/env bash
# deploy/check-constraint-set.sh — the node's constraint set is the vendored zkVM's (issue #166,
# ZKVM-201). Run from the repo root.
#
#   deploy/check-constraint-set.sh [--before N] [--upstream <circuits>/research/src/machine.rs>]
#   deploy/check-constraint-set.sh --chain N --genesis-hash <64 hex> [--binary-set M] [--print-row]
#
# Three numbers have to be one number:
#   - the vendored zkVM's      `pub const CONSTRAINT_SET: u32`       crates/randprotocol-zkvm/src/machine.rs
#   - the node's               `pub const BUILD_CONSTRAINT_SET: u32` crates/randprotocol-node/src/node.rs
#   - circuits' at CIRCUITS_PIN (`--upstream`, CI's guest-provenance job)
# The node's is a literal on purpose: moving it refuses every chain cut under the old set — the
# running chain included — so it is moved by hand, at a chain cut, never by a sync. The build
# fails when the first two differ (a `const` assertion beside the node's constant); this script
# says so first, in words, and is how `deploy/sync-zkvm.sh` ends: `--before N` is the vendored
# number before the sync, printed beside the one after it.
#
# `--chain N --genesis-hash H` (a chain cut; deploy/cut-chain22-genesis.sh calls it) also wants the
# chain's row in `CHAIN_CONSTRAINT_SETS` (crates/randprotocol-node/src/constraint_set.rs): exactly
#     (N, "H", <the node's BUILD_CONSTRAINT_SET>),
# and no other row for chain N or for hash H. A genesis hash does not exist before its cut, so the
# row cannot precede it: the cut prints the row (`--print-row`: that one line on stdout, the table
# not consulted) and the cut script's `check-limits` runs this until the tree has it. The hash is
# taken, never derived: only `rand-node init` derives a genesis hash. `--binary-set M` is the set
# a rand-node binary says it is (the `constraint-set` marker its `init` wrote); it must be the
# node's number too, or the binary was not built from this tree.
#
# Exit 0 when the numbers agree (and the row is there), 1 when they do not (or an anchor moved).
# The two file paths can be overridden by VENDORED_MACHINE_RS and NODE_RS, and the table's by
# CONSTRAINT_SET_RS.
set -euo pipefail
VENDORED_MACHINE_RS=${VENDORED_MACHINE_RS:-crates/randprotocol-zkvm/src/machine.rs}
NODE_RS=${NODE_RS:-crates/randprotocol-node/src/node.rs}
CONSTRAINT_SET_RS=${CONSTRAINT_SET_RS:-crates/randprotocol-node/src/constraint_set.rs}
BEFORE=
UPSTREAM=
CHAIN=
GENESIS_HASH=
BINARY_SET=
PRINT_ROW=
while [ $# -gt 0 ]; do
  case "$1" in
    --before) BEFORE=${2:?--before needs a number}; shift 2 ;;
    --upstream) UPSTREAM=${2:?--upstream needs a path to machine.rs}; shift 2 ;;
    --chain) CHAIN=${2:?--chain needs a chain id}; shift 2 ;;
    --genesis-hash) GENESIS_HASH=${2:?--genesis-hash needs the hash rand-node init printed}; shift 2 ;;
    --binary-set) BINARY_SET=${2:?--binary-set needs a number}; shift 2 ;;
    --print-row) PRINT_ROW=1; shift ;;
    *) echo "check-constraint-set.sh: unknown argument $1" >&2; exit 1 ;;
  esac
done
if [ -n "$CHAIN$GENESIS_HASH$BINARY_SET$PRINT_ROW" ]; then
  [[ "$CHAIN" =~ ^[1-9][0-9]*$ ]] || { echo "check-constraint-set.sh: --chain '$CHAIN' is not a chain id (--chain and --genesis-hash go together)" >&2; exit 1; }
  [[ "$GENESIS_HASH" =~ ^[0-9a-f]{64}$ ]] || { echo "check-constraint-set.sh: --genesis-hash '$GENESIS_HASH' is not a genesis hash (64 lowercase hex, as \`rand-node init\` prints it)" >&2; exit 1; }
  [ -z "$BINARY_SET" ] || [[ "$BINARY_SET" =~ ^[0-9]+$ ]] || { echo "check-constraint-set.sh: --binary-set '$BINARY_SET' is not a number" >&2; exit 1; }
fi
# --print-row prints the row and nothing else on stdout: the rest goes to stderr.
say() { if [ -n "$PRINT_ROW" ]; then echo "$@" >&2; else echo "$@"; fi; }

# The one `pub const <name>: u32 = <n>;` line of a file; anything else is a moved anchor.
read_const() {
  local n
  n=$(sed -n "s/^pub const $2: u32 = \([0-9][0-9]*\);.*$/\1/p" "$1")
  if ! [[ "$n" =~ ^[0-9]+$ ]]; then
    echo "check-constraint-set.sh: no single \`pub const $2: u32 = <n>;\` in $1 — an anchor moved; update this script" >&2
    exit 1
  fi
  echo "$n"
}

VENDORED=$(read_const "$VENDORED_MACHINE_RS" CONSTRAINT_SET)
NODE=$(read_const "$NODE_RS" BUILD_CONSTRAINT_SET)

if [ -n "$BEFORE" ]; then
  if [ "$BEFORE" = "$VENDORED" ]; then
    say "CONSTRAINT_SET: $BEFORE before the sync, $VENDORED after it (unchanged)"
  else
    say "CONSTRAINT_SET: $BEFORE before the sync, $VENDORED after it — THE CONSTRAINT SET MOVED"
  fi
else
  say "CONSTRAINT_SET: vendored zkVM $VENDORED, node BUILD_CONSTRAINT_SET $NODE"
fi

FAIL=0
if [ "$VENDORED" != "$NODE" ]; then
  # The chains the table lists under the node's current number: what a bump stops running.
  REFUSED=$(sed -n "s/^    (\([0-9][0-9]*\), \"[0-9a-f]\{64\}\", $NODE),$/\1/p" "$CONSTRAINT_SET_RS" | paste -sd' ' -)
  cat >&2 <<MSG
check-constraint-set.sh: the vendored zkVM is constraint set $VENDORED and the node's
BUILD_CONSTRAINT_SET ($NODE_RS) is $NODE. The workspace does not build like this, and must not
be made to by editing the number alone:
  - a constraint set is a chain cut. A constraint-set-$VENDORED binary verifies no proof made under
    set $NODE; chains listed under set $NODE in $CONSTRAINT_SET_RS: ${REFUSED:-none}.
  - if this sync was not meant to move the constraint set, re-sync from the circuits commit
    ci.yml's CIRCUITS_PIN names (git checkout -- crates/randprotocol-zkvm to undo this one).
  - if it was: set BUILD_CONSTRAINT_SET to $VENDORED, give CHAINS_THIS_BUILD_CANNOT_RUN a row and a
    reason for each chain above, add the new chain's row to CHAIN_CONSTRAINT_SETS once its
    genesis is cut, and ship the build only with that cut — never as a roll onto a running chain.
MSG
  FAIL=1
fi

if [ -n "$UPSTREAM" ]; then
  PINNED=$(read_const "$UPSTREAM" CONSTRAINT_SET)
  if [ "$PINNED" != "$VENDORED" ]; then
    echo "check-constraint-set.sh: circuits at the pin ($UPSTREAM) is constraint set $PINNED; the vendored zkVM is $VENDORED — CIRCUITS_PIN and the vendored tree disagree" >&2
    FAIL=1
  else
    say "circuits at the pin: constraint set $PINNED"
  fi
fi

if [ -n "$CHAIN" ]; then
  ROW="($CHAIN, \"$GENESIS_HASH\", $NODE),"
  if [ -n "$BINARY_SET" ] && [ "$BINARY_SET" != "$NODE" ]; then
    echo "check-constraint-set.sh: the rand-node binary is constraint set $BINARY_SET (its init wrote that marker) and this tree's BUILD_CONSTRAINT_SET is $NODE — the binary was not built from this tree, so this tree's row for chain $CHAIN would name the wrong set. Run this from the checkout the binary was built from" >&2
    FAIL=1
  fi
  if [ -n "$PRINT_ROW" ]; then
    # Only a row the numbers above stand behind is printed.
    [ "$FAIL" = 0 ] || exit 1
    echo "$ROW"
    exit 0
  fi
  # Every table row for this chain id or this hash, as `<chain> <hash> <set>`: one, and this one.
  ROWS=$(sed -n 's/^    (\([0-9][0-9]*\), "\([0-9a-f]\{64\}\)", \([0-9][0-9]*\)),$/\1 \2 \3/p' "$CONSTRAINT_SET_RS")
  if [ -z "$ROWS" ]; then
    echo "check-constraint-set.sh: no \`(chain, \"hash\", set),\` rows in $CONSTRAINT_SET_RS — an anchor moved; update this script" >&2
    exit 1
  fi
  MINE=$(awk -v c="$CHAIN" -v h="$GENESIS_HASH" '$1 == c || $2 == h' <<<"$ROWS")
  if [ "$MINE" = "$CHAIN $GENESIS_HASH $NODE" ]; then
    echo "CHAIN_CONSTRAINT_SETS: chain $CHAIN, genesis $GENESIS_HASH, constraint set $NODE — the row is there"
  else
    cat >&2 <<MSG
check-constraint-set.sh: CHAIN_CONSTRAINT_SETS ($CONSTRAINT_SET_RS) does not hold chain $CHAIN's row.
  wanted, exactly:   $ROW
  found for chain $CHAIN or that hash: ${MINE:-nothing}
Add the row (and raise the array's length), run the table's tests
(cargo test -p randprotocol-node --lib constraint_set) and commit: a release built without it
runs chain $CHAIN only by each datadir's marker, and a datadir copied without its marker is then
bound to no constraint set at all (issue #166). No release is signed off for chain $CHAIN from a
tree without this row.
MSG
    FAIL=1
  fi
fi
exit $FAIL
