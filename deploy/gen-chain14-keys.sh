#!/usr/bin/env bash
# Generate the chain-14 validator keys and payout wallets — OFF-REPO, one directory, once.
#
#   deploy/gen-chain14-keys.sh            # KEYDIR defaults to ~/.rand-chain14
#   KEYDIR=/Volumes/keys/rand-chain14 deploy/gen-chain14-keys.sh
#
# Audit v3 OPS-1: chains 8–13 all ran on `deploy/node-a..f.key.json` and
# `deploy/payout/*.key.json`, which are committed to a PUBLIC repository. A published validator
# key on a chain with a live bridge lets anyone finalize conflicting blocks, so chain 14 starts on
# eighteen validator keys and eighteen payout wallets that were never in the tree and never will
# be. `deploy/lib/key-guard.sh`'s `refuse_in_tree_key` is run over every file this writes: if
# KEYDIR resolves inside the repository, nothing is generated.
#
# What it writes under $KEYDIR (dir 0700, every key file 0600):
#
#   node-<name>.key.json        the validator key (`rand-node keygen`) — also the p2p identity
#   payout/<name>.key.json      that validator's payout wallet (`rand keygen`)
#   public/validators.tsv       name, validator address, public key, peer id, payout address
#   public/nodes-chain14.env    the regenerated deploy/nodes.env, with the NEW peer ids
#
# Only `public/` is safe to copy anywhere. Nothing in it is a secret; everything beside it is.
#
# **Peer ids change.** A node's libp2p identity is `derive_subkey(b"rand-p2p-identity")` of the
# validator key, so a fresh key is a fresh peer id: every `--bootstrap` multiaddr on the fleet
# changes with this generation, `deploy/nodes.env` has to be replaced by `public/nodes-chain14.env`,
# and `deploy/cutover-droplet-chain14.sh` writes a whole new systemd unit rather than sed-ing the
# datadir the way `deploy/cutover-droplet.sh` did for chains 9–13.
#
# Re-running is refused per file: a key that already exists is never overwritten (`rand keygen`
# refuses on its own; `rand-node keygen` would happily truncate, so this script checks first).
# Delete a file deliberately to regenerate it.
set -euo pipefail
cd "$(dirname "$0")/.."
. deploy/lib/key-guard.sh

NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
KEYDIR=${KEYDIR:-$HOME/.rand-chain14}

# The eighteen validators, in the order chain 14's genesis lists them — the chain-13 order, which
# is the chain-7 order for the twelve regional droplets (deploy/nodes.env lists them the same way).
NAMES=(a b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1)

for bin in "$NODE" "$WALLET"; do
  [ -x "$bin" ] || { echo "gen-chain14-keys: $bin is not executable — cargo build --release -p randprotocol-node -p randprotocol-client" >&2; exit 1; }
done

# KEYDIR must not be inside the repository, and the check has to happen before anything is
# written: refuse_in_tree_key only sees a file that already exists.
ROOT=$(git rev-parse --show-toplevel); ROOT=$(cd "$ROOT" && pwd -P)
mkdir -p "$KEYDIR/payout" "$KEYDIR/public"
chmod 700 "$KEYDIR" "$KEYDIR/payout"
ABS=$(cd "$KEYDIR" && pwd -P)
case "$ABS" in
  "$ROOT"/*|"$ROOT")
    echo "gen-chain14-keys: KEYDIR $ABS is inside the repository ($ROOT) — that is OPS-1 again" >&2
    exit 1 ;;
esac

made=0; kept=0
for n in "${NAMES[@]}"; do
  nk="$KEYDIR/node-$n.key.json"
  pk="$KEYDIR/payout/$n.key.json"
  if [ -e "$nk" ]; then kept=$((kept + 1)); else
    # `rand-node keygen` truncates an existing path without asking, so the guard above is this
    # script's, not the binary's.
    "$NODE" keygen --out "$nk" > /dev/null
    made=$((made + 1))
  fi
  # `rand keygen` refuses an existing path itself (there is no second copy of a spend key).
  [ -e "$pk" ] || "$WALLET" --key "$pk" keygen > /dev/null
  chmod 600 "$nk" "$pk"
  refuse_in_tree_key "$nk"
  refuse_in_tree_key "$pk"
done

# The public half: addresses, public keys, peer ids, payout addresses. Safe to publish; it is
# exactly what the genesis file and deploy/nodes.env will carry anyway.
{
  printf '# chain-14 validators, generated %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# name\taddress\tpublic_key\tpeer_id\tpayout\n'
  for n in "${NAMES[@]}"; do
    a=$("$NODE" address --key "$KEYDIR/node-$n.key.json")
    printf '%s\t%s\t%s\t%s\t%s\n' "$n" \
      "$(printf '%s\n' "$a" | sed -n 's/^address: //p')" \
      "$(printf '%s\n' "$a" | sed -n 's/^public_key: //p')" \
      "$(printf '%s\n' "$a" | sed -n 's/^peer_id: //p')" \
      "$("$WALLET" --key "$KEYDIR/payout/$n.key.json" address | tail -1)"
  done
} > "$KEYDIR/public/validators.tsv"

# The new deploy/nodes.env. The IP of every droplet is unchanged — only the peer id moves — so the
# addresses are read out of the committed nodes.env and re-joined with the fresh peer ids. Node A
# is the laptop behind NAT and has no dialable multiaddr, exactly as today.
# awk, not sed: BSD sed does not read `\t` in a pattern as a tab.
peer_of() { awk -F'\t' -v n="$1" '$1 == n { print $4 }' "$KEYDIR/public/validators.tsv"; }
ip_of() { sed -n "s#^NODE_$1=/ip4/\([0-9.]*\)/tcp/30303/p2p/.*#\1#p" deploy/nodes.env; }
{
  printf '# Chain 14: every peer id changed with the OPS-1 key rotation (a p2p identity is\n'
  printf '# `derive_subkey(b"rand-p2p-identity")` of the validator key). Generated %s by\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# deploy/gen-chain14-keys.sh; the IPs are unchanged from chain 13.\n'
  printf 'NODE_A_PEER=%s   # laptop, LAN 192.168.100.123 (NAT)\n' "$(peer_of a)"
  for n in b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1; do
    u=$(printf '%s' "$n" | tr '[:lower:]' '[:upper:]')
    ip=$(ip_of "$u")
    [ -n "$ip" ] || { echo "gen-chain14-keys: no NODE_$u address in deploy/nodes.env" >&2; exit 1; }
    printf 'NODE_%s=/ip4/%s/tcp/30303/p2p/%s\n' "$u" "$ip" "$(peer_of "$n")"
  done
} > "$KEYDIR/public/nodes-chain14.env"

chmod 644 "$KEYDIR/public/validators.tsv" "$KEYDIR/public/nodes-chain14.env"
echo "gen-chain14-keys: $made new validator keys, $kept kept, 18 payout wallets under $KEYDIR"
echo "gen-chain14-keys: public half in $KEYDIR/public/ (validators.tsv, nodes-chain14.env)"
echo "gen-chain14-keys: nothing here may ever be committed — the repository is public"
