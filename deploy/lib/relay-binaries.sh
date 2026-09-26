# Sourced by deploy/update-droplet.sh and deploy/cutover-droplet-chain14.sh (ops review OPS-3).
# The binaries used to be fanned out droplet-to-droplet over a forwarded agent (`ssh -A`), which
# hands the laptop's agent — every key it holds, for every droplet — to each droplet for the
# length of the session: root there could use it to log in anywhere the laptop can. Instead they
# are relayed through the laptop, as deploy/roll-all.sh does, with the sha256 checked at each hop:
#
#   build host ──scp──▶ laptop scratch (mktemp; checked) ──scp──▶ droplet /root/ (checked)
#
#   relay_binaries <ip>   needs BUILD_HOST, BUILD_DIR, BIN_NODE, BIN_WALLET, WANT (rand-node's
#                         sha256) and WANT_WALLET (rand's); leaves /root/$BIN_NODE and
#                         /root/$BIN_WALLET on <ip>, mode 755, both verified; exits 1 on any
#                         mismatch before the droplet's service is touched.
relay_binaries() {
  local ip=$1 local_dir opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20"
  local_dir=$(mktemp -d "${TMPDIR:-/tmp}/rand-relay.XXXXXX")
  # shellcheck disable=SC2064  # expand local_dir now: the trap must remove this directory
  trap "rm -rf '$local_dir'" EXIT
  # shellcheck disable=SC2086  # $opts is a list of ssh options
  scp -q $opts "root@$BUILD_HOST:$BUILD_DIR/$BIN_NODE" "root@$BUILD_HOST:$BUILD_DIR/$BIN_WALLET" "$local_dir/"
  [ "$(shasum -a 256 "$local_dir/$BIN_NODE" | cut -d' ' -f1)" = "$WANT" ] \
    || { echo "relay: $BIN_NODE fetched from $BUILD_HOST does not match ${WANT:0:12} — not touching $ip" >&2; exit 1; }
  [ "$(shasum -a 256 "$local_dir/$BIN_WALLET" | cut -d' ' -f1)" = "$WANT_WALLET" ] \
    || { echo "relay: $BIN_WALLET fetched from $BUILD_HOST does not match ${WANT_WALLET:0:12} — not touching $ip" >&2; exit 1; }
  # shellcheck disable=SC2086
  scp -q $opts "$local_dir/$BIN_NODE" "$local_dir/$BIN_WALLET" "root@$ip:/root/"
  # shellcheck disable=SC2086
  ssh $opts "root@$ip" "set -e
    chmod 755 /root/$BIN_NODE /root/$BIN_WALLET
    [ \"\$(sha256sum /root/$BIN_NODE | cut -d' ' -f1)\" = \"$WANT\" ] || { echo 'copied $BIN_NODE does not match the expected sha — not touching this node' >&2; exit 1; }
    [ \"\$(sha256sum /root/$BIN_WALLET | cut -d' ' -f1)\" = \"$WANT_WALLET\" ] || { echo 'copied $BIN_WALLET does not match the expected sha — not touching this node' >&2; exit 1; }"
  rm -rf "$local_dir"
  trap - EXIT
}
