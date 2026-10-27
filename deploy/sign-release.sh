#!/usr/bin/env bash
# Sign a release's SHA256SUMS with every release key available here (PROC-5), then check the
# result against deploy/release-signers and deploy/release-threshold.
#
#   deploy/sign-release.sh <SHA256SUMS> [<private key> ...]
#
# Keys: the arguments, else $RELEASE_KEYS (space-separated paths), else every ~/.rand-release/*_ed25519*
# private key (files without .pub). Run it on a machine that is not the build host; ssh-keygen
# asks for each key's passphrase on the terminal. Writes, beside <SHA256SUMS>:
#   SHA256SUMS.sig    the first key's signature (what every roll script takes as RELEASE_SIG)
#   SHA256SUMS.sig2 ... SHA256SUMS.sigN    the others, picked up automatically by the verifier
# Upload all of them to the release. With the committed threshold at 1 one key is enough; at 2 the
# keys of two different holders must have signed, and a second holder runs this on their own
# machine against the same SHA256SUMS, then copies their .sig as SHA256SUMS.sig<N>.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SUMS=${1:?usage: sign-release.sh <SHA256SUMS> [<private key> ...]}; shift
[ -f "$SUMS" ] || { echo "$SUMS: no such file" >&2; exit 1; }
KEYS=("$@")
if [ "${#KEYS[@]}" -eq 0 ] && [ -n "${RELEASE_KEYS:-}" ]; then read -r -a KEYS <<< "$RELEASE_KEYS"; fi
if [ "${#KEYS[@]}" -eq 0 ]; then
    for k in "$HOME"/.rand-release/*_ed25519* "$HOME"/.rand-release/*_ecdsa* "$HOME"/.rand-release/*_sk*; do
        [ -f "$k" ] || continue
        case "$k" in *.pub|*.sig) continue;; esac
        head -1 "$k" 2>/dev/null | grep -q -- '-----BEGIN OPENSSH PRIVATE KEY-----' || continue   # real private keys only
        KEYS+=("$k")
    done
fi
[ "${#KEYS[@]}" -gt 0 ] || { echo "no signing key: pass private key paths, or set RELEASE_KEYS, or put them in ~/.rand-release/" >&2; exit 1; }
rm -f "$SUMS".sig "$SUMS".sig[0-9]
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
n=0
for k in "${KEYS[@]}"; do
    [ -f "$k" ] || { echo "$k: no such key" >&2; exit 1; }
    n=$((n + 1))
    [ "$n" -le 9 ] || { echo "at most 9 signatures" >&2; exit 1; }
    out="$SUMS.sig"; [ "$n" -eq 1 ] || out="$SUMS.sig$n"
    # ssh-keygen writes <file>.sig; sign a private copy so each key's signature lands in its own file.
    cp "$SUMS" "$T/SHA256SUMS"; rm -f "$T/SHA256SUMS.sig"
    ssh-keygen -Y sign -n rand-release -f "$k" "$T/SHA256SUMS" >/dev/null
    mv "$T/SHA256SUMS.sig" "$out"
    echo "signed with $k -> $out"
done
# shellcheck source=lib/verify-release.sh
source "$HERE/lib/verify-release.sh"
verify_release_sums "$SUMS" "$SUMS.sig"
