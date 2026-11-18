#!/usr/bin/env bash
# deploy/check-constraint-set.sh — the node's constraint set is the vendored zkVM's (issue #166,
# ZKVM-201). Run from the repo root.
#
#   deploy/check-constraint-set.sh [--before N] [--upstream <circuits>/research/src/machine.rs>]
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
# Exit 0 when the numbers agree, 1 when they do not (or an anchor moved). The two file paths can
# be overridden by VENDORED_MACHINE_RS and NODE_RS, and the table's by CONSTRAINT_SET_RS.
set -euo pipefail
VENDORED_MACHINE_RS=${VENDORED_MACHINE_RS:-crates/randprotocol-zkvm/src/machine.rs}
NODE_RS=${NODE_RS:-crates/randprotocol-node/src/node.rs}
CONSTRAINT_SET_RS=${CONSTRAINT_SET_RS:-crates/randprotocol-node/src/constraint_set.rs}
BEFORE=
UPSTREAM=
while [ $# -gt 0 ]; do
  case "$1" in
    --before) BEFORE=${2:?--before needs a number}; shift 2 ;;
    --upstream) UPSTREAM=${2:?--upstream needs a path to machine.rs}; shift 2 ;;
    *) echo "check-constraint-set.sh: unknown argument $1" >&2; exit 1 ;;
  esac
done

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
    echo "CONSTRAINT_SET: $BEFORE before the sync, $VENDORED after it (unchanged)"
  else
    echo "CONSTRAINT_SET: $BEFORE before the sync, $VENDORED after it — THE CONSTRAINT SET MOVED"
  fi
else
  echo "CONSTRAINT_SET: vendored zkVM $VENDORED, node BUILD_CONSTRAINT_SET $NODE"
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
    echo "circuits at the pin: constraint set $PINNED"
  fi
fi
exit $FAIL
