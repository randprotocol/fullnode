# Sourced by the fleet scripts (WEB-502). The fleet's host list is NOT in this repository: the
# committed deploy/nodes.env holds documentation-range placeholders (203.0.113.x). The operator's
# real list is configuration/fleet/nodes.env in the private configuration repository; point the
# scripts at it with NODES_ENV.
#
#   require_fleet_env        NODES_ENV (default: deploy/nodes.env) must exist and name no placeholder host
#   fleet_ip <NAME>          the address of NODE_<NAME>= (or ARCHIVE=, ARCHIVE2=) in NODES_ENV, e.g. fleet_ip E
#   refuse_placeholder NAME VALUE   fail when VALUE holds a placeholder (an env-supplied BUILD_HOST, BOOTS ...)
#   refuse_placeholder_script FILE  fail when a script's own text carries placeholder hosts
#
# Each failure prints why on stderr and exits (these are for scripts, not for a shell).
#   SELFTEST=1 bash deploy/lib/fleet-env.sh
_FLEET_MSG="set NODES_ENV to the operator's fleet list (configuration/fleet/nodes.env in the private configuration repository)"
_FLEET_PLACEHOLDER='203\.0\.113\.'

_fleet_default() { echo "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/nodes.env"; }

require_fleet_env() {
  NODES_ENV="${NODES_ENV:-$(_fleet_default)}"; export NODES_ENV
  [ -f "$NODES_ENV" ] || { echo "fleet-env: $NODES_ENV does not exist — $_FLEET_MSG" >&2; exit 1; }
  if grep -vE '^[[:space:]]*#' "$NODES_ENV" | grep -qE "$_FLEET_PLACEHOLDER"; then
    echo "fleet-env: $NODES_ENV still holds placeholder hosts (203.0.113.x) — $_FLEET_MSG" >&2; exit 1
  fi
}

fleet_ip() {
  local n=$1 key
  require_fleet_env
  case "$n" in ARCHIVE|ARCHIVE2) key=$n ;; *) key=NODE_$n ;; esac
  local ip
  ip=$(sed -n "s#^$key=/ip4/\([0-9.]*\)/tcp/.*#\1#p" "$NODES_ENV" | head -1)
  [ -n "$ip" ] || { echo "fleet-env: no $key address in $NODES_ENV" >&2; exit 1; }
  echo "$ip"
}

refuse_placeholder() {
  case "$2" in
    *203.0.113.*) echo "fleet-env: $1 holds a placeholder host ($2) — $_FLEET_MSG, or set $1 yourself" >&2; exit 1 ;;
  esac
}

refuse_placeholder_script() {
  if grep -vE '^[[:space:]]*#' "$1" | grep -qE "$_FLEET_PLACEHOLDER"; then
    echo "fleet-env: $1 carries placeholder hosts (203.0.113.x); run the operator's copy of it (the private configuration repository), or edit the addresses in" >&2; exit 1
  fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${SELFTEST:-}" = 1 ]; then
  export SELFTEST=0; ST=$(mktemp -d); trap 'rm -rf "$ST"' EXIT; PASS=0; FAIL=0
  t() { local what=$1 want=$2; shift 2; if ( "$@" ) >/dev/null 2>"$ST/err"; then got=0; else got=1; fi
        if [ "$got" = "$want" ]; then PASS=$((PASS+1)); echo "  ok   $what"; else FAIL=$((FAIL+1)); echo "  FAIL $what: $(cat "$ST/err")"; fi; }
  printf '# 203.0.113.9 in a comment is fine\nNODE_E=/ip4/203.0.113.33/tcp/30303/p2p/x\n' > "$ST/ph.env"
  printf 'NODE_E=/ip4/198.18.0.5/tcp/30303/p2p/x   # real\nARCHIVE=/ip4/198.18.0.6/tcp/30303/p2p/y\n' > "$ST/real.env"
  t "placeholders in NODES_ENV refuse" 1 env NODES_ENV="$ST/ph.env" bash -c 'source "$0"; require_fleet_env' "${BASH_SOURCE[0]}"
  t "a missing NODES_ENV refuses" 1 env NODES_ENV="$ST/none.env" bash -c 'source "$0"; require_fleet_env' "${BASH_SOURCE[0]}"
  t "a real list passes" 0 env NODES_ENV="$ST/real.env" bash -c 'source "$0"; require_fleet_env' "${BASH_SOURCE[0]}"
  t "fleet_ip reads NODE_E" 0 env NODES_ENV="$ST/real.env" bash -c 'source "$0"; [ "$(fleet_ip E)" = 198.18.0.5 ]' "${BASH_SOURCE[0]}"
  t "fleet_ip reads ARCHIVE" 0 env NODES_ENV="$ST/real.env" bash -c 'source "$0"; [ "$(fleet_ip ARCHIVE)" = 198.18.0.6 ]' "${BASH_SOURCE[0]}"
  t "fleet_ip of an unknown name refuses" 1 env NODES_ENV="$ST/real.env" bash -c 'source "$0"; fleet_ip Z' "${BASH_SOURCE[0]}"
  t "refuse_placeholder refuses a placeholder value" 1 bash -c 'source "$0"; refuse_placeholder BUILD_HOST 203.0.113.33' "${BASH_SOURCE[0]}"
  t "refuse_placeholder passes a real value" 0 bash -c 'source "$0"; refuse_placeholder BUILD_HOST 198.18.0.5' "${BASH_SOURCE[0]}"
  printf 'echo 203.0.113.5\n' > "$ST/s.sh"; printf '# 203.0.113.5\necho hi\n' > "$ST/c.sh"
  t "a script carrying a placeholder host refuses" 1 bash -c 'source "$0"; refuse_placeholder_script "$1"' "${BASH_SOURCE[0]}" "$ST/s.sh"
  t "a placeholder only in a comment passes" 0 bash -c 'source "$0"; refuse_placeholder_script "$1"' "${BASH_SOURCE[0]}" "$ST/c.sh"
  t "the committed deploy/nodes.env refuses by default" 1 env -u NODES_ENV bash -c 'source "$0"; require_fleet_env' "${BASH_SOURCE[0]}"
  echo "fleet-env selftest: $PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]; exit $?
fi
