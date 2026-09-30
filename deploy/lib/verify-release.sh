# Sourced by deploy/update-droplet.sh and deploy/roll-all.sh (audit v6, PROC-5). Until now the
# sha256 a host checked before installing a binary as root was copied from the build by the person
# who made the build: it detects a corrupt download, not a compromised build host. The build host
# was the trust root of the fleet. This adds a signature over the release's SHA256SUMS, made with
# a key that is NOT on the build host, and refuses to install without it.
#
#   verify_release_sums <SHA256SUMS> <SHA256SUMS.sig> [<allowed_signers>]
#       returns 1 unless <SHA256SUMS.sig> is an SSH signature (`ssh-keygen -Y sign -n
#       rand-release`) over exactly the bytes of <SHA256SUMS>, made by a key listed in
#       <allowed_signers> (default: deploy/release-signers). A missing signature, a signature
#       that does not verify, a signer that is not listed, a signature made for another
#       namespace, and an allowed-signers file with no key in it are all refusals — with no key
#       configured the answer is "refuse", never "pass".
#   verify_binary <file> <SHA256SUMS> [<name>]
#       returns 1 unless <file>'s sha256 is the one <SHA256SUMS> lists for <name> (default: the
#       file's basename). Call it only with a SHA256SUMS that verify_release_sums accepted.
#   release_sha <SHA256SUMS> <name>
#       prints the sha256 <SHA256SUMS> lists for <name>; returns 1 when it lists none or several.
#
# Each prints why on stderr and returns (does not exit), so a caller under `set -e` stops.
#
# Signing, by the release key holder, on a machine that is not the build host:
#
#   ssh-keygen -Y sign -n rand-release -f <private key or hardware-backed key handle> SHA256SUMS
#
# writes SHA256SUMS.sig beside it. The public half goes in deploy/release-signers as one line,
#   <who> namespaces="rand-release" <key type> <base64 key>
# SSH signatures because ssh-keygen is already on every host and a FIDO2/hardware-backed key
# (ed25519-sk) signs the same way.
#
#   SELFTEST=1 bash deploy/lib/verify-release.sh    # a throwaway key in a temp dir (VERBOSE=1
#                                                   # prints each refusal's reason)
RELEASE_NAMESPACE=rand-release

_vr_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

_vr_default_signers() {
  echo "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/release-signers"
}

verify_release_sums() {
  local sums=${1:-} sig=${2:-} signers=${3:-} principals principal ok=""
  [ -n "$signers" ] || signers=$(_vr_default_signers)
  if [ -z "$sums" ] || [ ! -f "$sums" ]; then
    echo "verify-release: no SHA256SUMS at '$sums'" >&2; return 1
  fi
  if [ -z "$sig" ] || [ ! -s "$sig" ]; then
    echo "verify-release: refusing — no signature at '$sig'. A release's SHA256SUMS is signed by the release key holder: ssh-keygen -Y sign -n $RELEASE_NAMESPACE -f <key> SHA256SUMS" >&2; return 1
  fi
  if [ ! -f "$signers" ]; then
    echo "verify-release: refusing — no allowed-signers file at '$signers'" >&2; return 1
  fi
  if ! grep -qvE '^[[:space:]]*(#|$)' "$signers"; then
    echo "verify-release: refusing — $signers lists no release key. The operator adds the public key held off the build host; until then nothing verifies" >&2; return 1
  fi
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "verify-release: refusing — ssh-keygen is not installed, so the signature cannot be checked" >&2; return 1
  fi
  # Who signed: the principals the allowed-signers file gives the key inside the signature. None
  # means the signer is not one of ours, whatever the signature says.
  if ! principals=$(ssh-keygen -Y find-principals -s "$sig" -f "$signers" 2>/dev/null) || [ -z "$principals" ]; then
    echo "verify-release: refusing — the key that signed $sig is not in $signers" >&2; return 1
  fi
  # The signature itself, over these bytes, in our namespace, by that signer.
  while IFS= read -r principal; do
    [ -n "$principal" ] || continue
    if ssh-keygen -Y verify -f "$signers" -I "$principal" -n "$RELEASE_NAMESPACE" -s "$sig" < "$sums" >/dev/null 2>&1; then
      ok=$principal; break
    fi
  done <<EOF
$principals
EOF
  if [ -z "$ok" ]; then
    echo "verify-release: refusing — $sig does not verify over $sums in namespace $RELEASE_NAMESPACE (the file was changed after signing, or it was signed for something else)" >&2; return 1
  fi
  echo "verify-release: $sums is signed by $ok" >&2
}

release_sha() {
  local sums=${1:-} name=${2:-} found
  if [ -z "$sums" ] || [ ! -f "$sums" ] || [ -z "$name" ]; then
    echo "verify-release: release_sha needs a SHA256SUMS file and a name" >&2; return 1
  fi
  # `<64 hex>  <name>` or `<64 hex> *<name>` — sha256sum's two forms.
  found=$(awk -v n="$name" '{ f = $2; sub(/^\*/, "", f); if (f == n && length($1) == 64 && $1 !~ /[^0-9a-f]/) print $1 }' "$sums")
  case "$found" in
    "") echo "verify-release: $sums lists no sha256 for '$name'" >&2; return 1 ;;
    *"
"*) echo "verify-release: $sums lists '$name' more than once" >&2; return 1 ;;
  esac
  echo "$found"
}

verify_binary() {
  local file=${1:-} sums=${2:-} name=${3:-} want have
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    echo "verify-release: no binary at '$file'" >&2; return 1
  fi
  [ -n "$name" ] || name=$(basename "$file")
  want=$(release_sha "$sums" "$name") || return 1
  have=$(_vr_sha256 "$file")
  if [ "$have" != "$want" ]; then
    echo "verify-release: refusing — $file is ${have:0:16}…, the signed SHA256SUMS says ${want:0:16}… for $name" >&2; return 1
  fi
}

# ══ SELFTEST (only when this file is run, not sourced) ═══════════════════════════════════════
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${SELFTEST:-}" = 1 ]; then
  set -u
  ST=$(mktemp -d "${TMPDIR:-/tmp}/verify-release-selftest.XXXXXX")
  trap 'rm -rf "$ST"' EXIT
  PASS=0; FAIL=0
  ok()  { PASS=$((PASS + 1)); echo "  ok   $1"; }
  bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }
  accepts() { local what=$1; shift; if "$@" >/dev/null 2>"$ST/err"; then ok "$what"; else bad "$what — refused: $(cat "$ST/err")"; fi; }
  # VERBOSE=1 prints each refusal's own words, to check a case is refused for its reason.
  refuses() { local what=$1; shift; if "$@" >/dev/null 2>"$ST/err"; then bad "$what — accepted"; else ok "$what"; [ "${VERBOSE:-}" != 1 ] || sed "s|$ST|<tmp>|g; s/^/         /" "$ST/err"; fi; }

  # Two throwaway keys, made here and deleted with the directory; neither is printed.
  ssh-keygen -q -t ed25519 -N '' -C selftest-release -f "$ST/release" || { echo "ssh-keygen cannot make a key"; exit 1; }
  ssh-keygen -q -t ed25519 -N '' -C selftest-stranger -f "$ST/stranger" || { echo "ssh-keygen cannot make a key"; exit 1; }
  printf 'selftest-release namespaces="%s" %s\n' "$RELEASE_NAMESPACE" "$(cut -d' ' -f1,2 "$ST/release.pub")" > "$ST/signers"

  mkdir "$ST/rel"
  printf 'node binary\n' > "$ST/rel/rand-node"
  printf 'wallet binary\n' > "$ST/rel/rand"
  ( cd "$ST/rel" && for f in rand rand-node; do echo "$(_vr_sha256 "$f")  $f"; done > SHA256SUMS )
  ssh-keygen -q -Y sign -n "$RELEASE_NAMESPACE" -f "$ST/release" "$ST/rel/SHA256SUMS" 2>/dev/null

  accepts "a good signature by a listed key passes" verify_release_sums "$ST/rel/SHA256SUMS" "$ST/rel/SHA256SUMS.sig" "$ST/signers"
  accepts "a binary the signed sums list passes" verify_binary "$ST/rel/rand-node" "$ST/rel/SHA256SUMS"
  accepts "a binary under another local name passes when named" verify_binary "$ST/rel/rand" "$ST/rel/SHA256SUMS" rand

  cp "$ST/rel/SHA256SUMS" "$ST/tampered-sums"
  printf 'x' | dd of="$ST/tampered-sums" bs=1 seek=0 conv=notrunc 2>/dev/null
  refuses "tampered sums are refused" verify_release_sums "$ST/tampered-sums" "$ST/rel/SHA256SUMS.sig" "$ST/signers"

  cp "$ST/rel/rand-node" "$ST/rand-node"; printf 'one more byte' >> "$ST/rand-node"
  refuses "a tampered binary is refused" verify_binary "$ST/rand-node" "$ST/rel/SHA256SUMS"

  refuses "unsigned sums (no .sig) are refused" verify_release_sums "$ST/rel/SHA256SUMS" "$ST/rel/absent.sig" "$ST/signers"
  : > "$ST/empty.sig"
  refuses "an empty .sig is refused" verify_release_sums "$ST/rel/SHA256SUMS" "$ST/empty.sig" "$ST/signers"

  cp "$ST/rel/SHA256SUMS" "$ST/stranger-sums"
  ssh-keygen -q -Y sign -n "$RELEASE_NAMESPACE" -f "$ST/stranger" "$ST/stranger-sums" 2>/dev/null
  refuses "a valid signature by a key not in the allowed list is refused" verify_release_sums "$ST/stranger-sums" "$ST/stranger-sums.sig" "$ST/signers"

  cp "$ST/rel/SHA256SUMS" "$ST/other-ns"
  ssh-keygen -q -Y sign -n file -f "$ST/release" "$ST/other-ns" 2>/dev/null
  refuses "a signature made for another namespace is refused" verify_release_sums "$ST/other-ns" "$ST/other-ns.sig" "$ST/signers"

  printf '# a header and no key\n\n' > "$ST/no-keys"
  refuses "an allowed-signers file with no key refuses, it does not pass" verify_release_sums "$ST/rel/SHA256SUMS" "$ST/rel/SHA256SUMS.sig" "$ST/no-keys"
  HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
  if grep -qvE '^[[:space:]]*(#|$)' "$HERE/../release-signers" 2>/dev/null; then
    echo "  note deploy/release-signers holds a key; the default-file refusal is not exercised"
  else
    refuses "the repository's deploy/release-signers (no key yet) refuses by default" verify_release_sums "$ST/rel/SHA256SUMS" "$ST/rel/SHA256SUMS.sig"
  fi

  printf 'not in the sums\n' > "$ST/rand-prover"
  refuses "a binary the sums do not list is refused" verify_binary "$ST/rand-prover" "$ST/rel/SHA256SUMS"
  if [ "$(release_sha "$ST/rel/SHA256SUMS" rand 2>/dev/null)" = "$(_vr_sha256 "$ST/rel/rand")" ]; then ok "release_sha reads the listed sha256"; else bad "release_sha reads the listed sha256"; fi

  echo "verify-release selftest: $PASS passed, $FAIL failed"
  [ "$FAIL" -eq 0 ]
  exit $?
fi
