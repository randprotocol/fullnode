#!/usr/bin/env bash
# Install or refresh the laptop's launchd jobs (ops review OPS-5):
#
#   deploy/install-launchd.sh [node-a|fleet-watch|all]      (default: all)
#
# The jobs run COPIES of deploy/run-a.sh and deploy/fleet-watch.sh (with the deploy/nodes.env
# fleet-watch reads) under $NODE_A_HOME/deploy (default ~/rand-node-a/deploy), never the shared
# checkout: several sessions work in that checkout, and a branch switch or an uncommitted edit
# there would silently change what launchd runs as validator A at its next restart.
#
# Run it from a clean checkout of the commit you mean to run. It copies the scripts, writes the
# plist into ~/Library/LaunchAgents with this user's home substituted for the committed paths,
# then reloads the job (bootout + bootstrap). Reloading node-a RESTARTS VALIDATOR A — for a new
# binary alone, `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a` is enough. NO_RELOAD=1
# copies without reloading. Re-run it whenever run-a.sh, fleet-watch.sh or nodes.env changes.
set -euo pipefail
cd "$(dirname "$0")/.."
WHAT=${1:-all}
HOME_A=${NODE_A_HOME:-$HOME/rand-node-a}
DEST=$HOME_A/deploy
AGENTS=$HOME/Library/LaunchAgents
DOMAIN=gui/$(id -u)
# The plists are committed with the operator's absolute paths (launchd expands neither ~ nor $HOME).
COMMITTED_HOME=/Users/dendisuhubdy

[ -z "$(git status --porcelain --untracked-files=no -- deploy/run-a.sh deploy/fleet-watch.sh deploy/nodes.env deploy/launchd)" ] \
  || { echo "install-launchd: the checkout's deploy/ scripts differ from HEAD — install from a clean checkout" >&2; exit 1; }

install -d -m 700 "$DEST" "$AGENTS"

install_job() {
  local label=$1; shift
  local f
  for f in "$@"; do install -m 644 "deploy/$f" "$DEST/$f"; done
  chmod 755 "$DEST"/*.sh
  sed -e "s|$COMMITTED_HOME/rand-node-a|$HOME_A|g" -e "s|$COMMITTED_HOME|$HOME|g" \
    "deploy/launchd/$label.plist" > "$AGENTS/$label.plist"
  plutil -lint "$AGENTS/$label.plist" >/dev/null
  echo "installed $label → $AGENTS/$label.plist (runs $DEST/$1, $(git rev-parse --short HEAD))"
  if [ "${NO_RELOAD:-}" = 1 ]; then echo "   NO_RELOAD=1 — not reloaded"; return; fi
  launchctl bootout "$DOMAIN/$label" 2>/dev/null || true
  launchctl bootstrap "$DOMAIN" "$AGENTS/$label.plist"
  echo "   reloaded $label"
}

case "$WHAT" in
  node-a)      install_job org.randprotocol.node-a run-a.sh ;;
  fleet-watch) install_job org.randprotocol.fleet-watch fleet-watch.sh nodes.env ;;
  all)         install_job org.randprotocol.node-a run-a.sh
               install_job org.randprotocol.fleet-watch fleet-watch.sh nodes.env ;;
  *) echo "usage: deploy/install-launchd.sh [node-a|fleet-watch|all]" >&2; exit 1 ;;
esac
