#!/usr/bin/env bash
# Sign a release's SHA256SUMS with the release keys held here (PROC-5), then check the result
# against deploy/release-signers and deploy/release-threshold.
#
#   deploy/sign-release.sh <SHA256SUMS> [<private key> ...]            # the first signer
#   deploy/sign-release.sh --append <SHA256SUMS> [<private key> ...]   # every later signer
#   deploy/sign-release.sh --replace <SHA256SUMS> [<private key> ...]  # throw the signatures away, start over
#   SELFTEST=1 bash deploy/sign-release.sh                             # throwaway keys in a temp dir
#
# Keys: the arguments, else $RELEASE_KEYS (space-separated paths), else every ~/.rand-release/*_ed25519*
# private key (files without .pub). Run it on a machine that is not the build host; ssh-keygen
# asks for each key's passphrase on the terminal. Signatures live beside <SHA256SUMS>:
#   SHA256SUMS.sig    the first signature (what every roll script takes as RELEASE_SIG)
#   SHA256SUMS.sig2 ... SHA256SUMS.sig9    the others, picked up automatically by the verifier
# Upload all of them to the release.
#
# Two holders (monorepo#14). The first holder signs: `sign-release.sh SHA256SUMS`, and sends
# SHA256SUMS and SHA256SUMS.sig* to the second (or uploads them to the draft release). The second
# holder, on their own machine, with the same files in one directory, runs
# `sign-release.sh --append SHA256SUMS`: it keeps every signature already there, adds theirs in
# the first free slot, and refuses
#   - when a signature already there is not a good signature over this SHA256SUMS (the file
#     changed since it was signed, or the .sig belongs to another release): nothing is added to a
#     set that does not hold together;
#   - when the key has already signed (a second signature by one key counts for nothing, and
#     would look like two).
# Without --append or --replace the script refuses to run where signatures already exist: until
# monorepo#14 it deleted them, so a second holder running it erased the first holder's signature.
#
# $RELEASE_SIGNERS names another allowed-signers file for this script's own final check (a holder
# whose key is not yet in deploy/release-signers; the self-test). The roll scripts never read it.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
NAMESPACE=rand-release

# The fingerprint of the key that made signature $2 over file $1, or nothing when $2 is not a
# good signature over exactly those bytes in the release namespace. No trust decision: that is
# verify_release_sums's, against the listed keys.
signer_of() {
    # `|| true`: a signature that does not verify is an empty answer, not an exit under `set -e`.
    { ssh-keygen -Y check-novalidate -n "$NAMESPACE" -s "$2" < "$1" 2>/dev/null || true; } | sed -n 's/.* key \(SHA256:[A-Za-z0-9+\/=]*\).*/\1/p' | head -1
}

sign_release() {
    local mode=first
    case "${1:-}" in --append) mode=append; shift ;; --replace) mode=replace; shift ;; esac
    local sums=${1:?usage: sign-release.sh [--append|--replace] <SHA256SUMS> [<private key> ...]}; shift
    [ -f "$sums" ] || { echo "$sums: no such file" >&2; return 1; }
    local keys=("$@") k
    if [ "${#keys[@]}" -eq 0 ] && [ -n "${RELEASE_KEYS:-}" ]; then read -r -a keys <<< "$RELEASE_KEYS"; fi
    if [ "${#keys[@]}" -eq 0 ]; then
        for k in "$HOME"/.rand-release/*_ed25519* "$HOME"/.rand-release/*_ecdsa* "$HOME"/.rand-release/*_sk*; do
            [ -f "$k" ] || continue
            case "$k" in *.pub|*.sig) continue;; esac
            head -1 "$k" 2>/dev/null | grep -q -- '-----BEGIN OPENSSH PRIVATE KEY-----' || continue   # real private keys only
            keys+=("$k")
        done
    fi
    [ "${#keys[@]}" -gt 0 ] || { echo "no signing key: pass private key paths, or set RELEASE_KEYS, or put them in ~/.rand-release/" >&2; return 1; }
    for k in "${keys[@]}"; do [ -f "$k" ] || { echo "$k: no such key" >&2; return 1; }; done

    # The signatures already beside the sums, by slot (1 is .sig).
    local slots=("$sums.sig" "$sums.sig2" "$sums.sig3" "$sums.sig4" "$sums.sig5" "$sums.sig6" "$sums.sig7" "$sums.sig8" "$sums.sig9")
    local existing=() s
    for s in "${slots[@]}"; do [ -e "$s" ] && existing+=("$s"); done
    case "$mode" in
        first)
            if [ "${#existing[@]}" -gt 0 ]; then
                echo "sign-release: ${existing[*]} already exist(s). To add your signature beside them: --append. To discard them and start over: --replace. Nothing was changed." >&2
                return 1
            fi ;;
        replace) rm -f "${slots[@]}"; existing=() ;;
        append) ;;
    esac

    # Whose signatures are already there. In append mode every one of them must be a good
    # signature over THESE sums before anything is added.
    local signed_by="" fp
    for s in ${existing[@]+"${existing[@]}"}; do
        fp=$(signer_of "$sums" "$s")
        if [ -z "$fp" ]; then
            echo "sign-release: $s is not a good signature over $sums (the file changed after it was signed, or the signature is another release's). Not adding to it; nothing was changed." >&2
            return 1
        fi
        signed_by="$signed_by $fp"
    done

    # Sign with every key into a private directory first, so a refusal part-way leaves the
    # release directory exactly as it was.
    local tmp; tmp=$(mktemp -d); trap 'rm -rf "'"$tmp"'"' RETURN
    local n=0 new=()
    for k in "${keys[@]}"; do
        n=$((n + 1))
        cp "$sums" "$tmp/SHA256SUMS"; rm -f "$tmp/SHA256SUMS.sig"
        ssh-keygen -Y sign -n "$NAMESPACE" -f "$k" "$tmp/SHA256SUMS" >/dev/null
        fp=$(signer_of "$sums" "$tmp/SHA256SUMS.sig")
        [ -n "$fp" ] || { echo "sign-release: the signature made with $k does not verify over $sums; nothing was changed" >&2; return 1; }
        case " $signed_by " in
            *" $fp "*) echo "sign-release: the key $k ($fp) has already signed $sums: one key's second signature counts for nothing. Nothing was changed." >&2; return 1 ;;
        esac
        signed_by="$signed_by $fp"
        mv "$tmp/SHA256SUMS.sig" "$tmp/new.$n"
        new+=("$k")
    done

    # Place each new signature in the first free slot.
    local i=0 placed
    for k in "${new[@]}"; do
        i=$((i + 1)); placed=""
        for s in "${slots[@]}"; do
            if [ ! -e "$s" ]; then mv "$tmp/new.$i" "$s"; placed=$s; break; fi
        done
        [ -n "$placed" ] || { echo "sign-release: all nine signature slots are taken; the signature made with $k was not written" >&2; return 1; }
        echo "signed with $k -> $placed"
    done
    set -f; echo "sign-release: $sums now carries $(echo $signed_by | wc -w | tr -d ' ') signature(s), each by a different key"; set +f

    # shellcheck source=lib/verify-release.sh
    source "$HERE/lib/verify-release.sh"
    if [ ! -e "$sums.sig" ]; then
        echo "sign-release: there is no $sums.sig (the first slot, which every roll script names); move one signature there" >&2; return 1
    fi
    verify_release_sums "$sums" "$sums.sig" ${RELEASE_SIGNERS:+"$RELEASE_SIGNERS"}
}

# ══ SELFTEST ═════════════════════════════════════════════════════════════════════════════════
if [ "${SELFTEST:-}" = 1 ]; then
    set +e
    ST=$(mktemp -d "${TMPDIR:-/tmp}/sign-release-selftest.XXXXXX"); trap 'rm -rf "$ST"' EXIT
    PASS=0; FAIL=0
    ok()  { PASS=$((PASS + 1)); echo "  ok   $1"; }
    bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }
    # Three throwaway keys with no passphrase, made here and deleted with the directory; a
    # fourth that is listed nowhere. None is printed, none is in deploy/release-signers.
    for who in alice bob carol stranger; do
        ssh-keygen -q -t ed25519 -N '' -C "selftest-$who" -f "$ST/$who" || { echo "ssh-keygen cannot make a key"; exit 1; }
    done
    for who in alice bob carol; do
        printf 'selftest-%s namespaces="%s" %s\n' "$who" "$NAMESPACE" "$(cut -d' ' -f1,2 "$ST/$who.pub")"
    done > "$ST/signers"
    export RELEASE_SIGNERS="$ST/signers"
    R="$ST/rel"; mkdir "$R"; printf 'aaaa  rand-node\nbbbb  rand\n' > "$R/SHA256SUMS"
    # The script under test, run as a holder would run it (SELFTEST off), at threshold T.
    run() { local t=$1; shift; SELFTEST=0 RELEASE_THRESHOLD=$t bash "$HERE/sign-release.sh" "$@" > "$ST/out" 2>&1; }
    snapshot() { ( cd "$R" && for f in SHA256SUMS.sig*; do [ -e "$f" ] && { echo "$f"; cksum < "$f"; }; done ) 2>/dev/null; }
    said() { grep -q -- "$1" "$ST/out"; }

    run 1 "$R/SHA256SUMS" "$ST/alice" && [ -s "$R/SHA256SUMS.sig" ] && [ ! -e "$R/SHA256SUMS.sig2" ] \
        && ok "the first holder signs: one signature, 1-of-3 verifies" || bad "the first holder signs: $(cat "$ST/out")"
    cp "$R/SHA256SUMS.sig" "$ST/first.sig"; before=$(snapshot)

    if run 1 "$R/SHA256SUMS" "$ST/bob"; then bad "a second run without --append was accepted"
    elif [ "$(snapshot)" = "$before" ] && said "already exist" && said -- "--append"; then ok "a second holder who forgets --append is refused, and the first signature is untouched"
    else bad "a second run without --append: $(cat "$ST/out")"; fi

    run 2 "$R/SHA256SUMS" "$ST/alice"   # for its exit code only: nothing may change
    run 2 --append "$R/SHA256SUMS" "$ST/bob" && cmp -s "$R/SHA256SUMS.sig" "$ST/first.sig" && [ -s "$R/SHA256SUMS.sig2" ] && said "2 of the required 2" \
        && ok "the second holder appends: the first signature is kept, theirs is .sig2, 2-of-3 verifies" || bad "the second holder appends: $(cat "$ST/out")"
    before=$(snapshot)

    if run 2 --append "$R/SHA256SUMS" "$ST/alice"; then bad "a duplicate signer was accepted"
    elif [ "$(snapshot)" = "$before" ] && said "has already signed"; then ok "a key that already signed is refused in append mode, and nothing changes"
    else bad "a duplicate signer: $(cat "$ST/out")"; fi
    if run 2 --append "$R/SHA256SUMS" "$ST/carol" "$ST/bob"; then bad "a batch with a duplicate signer was accepted"
    elif [ "$(snapshot)" = "$before" ] && said "has already signed"; then ok "a batch that includes a duplicate adds none of its signatures"
    else bad "a batch with a duplicate: $(cat "$ST/out")"; fi

    run 3 --append "$R/SHA256SUMS" "$ST/carol" && [ -s "$R/SHA256SUMS.sig3" ] && said "3 of the required 3" \
        && ok "a third holder appends: .sig3, 3-of-3 verifies" || bad "a third holder appends: $(cat "$ST/out")"

    rm -f "$R/SHA256SUMS.sig2"
    ( SELFTEST=0 RELEASE_THRESHOLD=2 bash -c 'source "$0"; verify_release_sums "$1" "$1.sig" "$2"' "$HERE/lib/verify-release.sh" "$R/SHA256SUMS" "$ST/signers" ) >/dev/null 2>&1 \
        && ok "2-of-3 verifies with a slot missing (.sig and .sig3)" || bad "2-of-3 with a gap was refused"
    run 3 --append "$R/SHA256SUMS" "$ST/bob" && [ -s "$R/SHA256SUMS.sig2" ] && ok "an append fills the first free slot" || bad "filling a gap: $(cat "$ST/out")"

    # A signature by a key that is listed nowhere is added (the script does not decide trust) but
    # counts for nothing: 3 listed signers, not 4.
    run 3 --append "$R/SHA256SUMS" "$ST/stranger" && [ -s "$R/SHA256SUMS.sig4" ] && said "3 of the required 3" && said "not counted" \
        && ok "an unlisted key's signature is not counted by the check" || bad "an unlisted signer: $(cat "$ST/out")"

    # The sums change after signing: nothing may be appended to the stale set.
    cp -R "$R" "$ST/stale"; printf 'cccc  rand-prover\n' >> "$ST/stale/SHA256SUMS"; R="$ST/stale"; before=$(snapshot)
    ssh-keygen -q -t ed25519 -N '' -C selftest-dave -f "$ST/dave"
    if run 1 --append "$R/SHA256SUMS" "$ST/dave"; then bad "an append to signatures over other bytes was accepted"
    elif [ "$(snapshot)" = "$before" ] && said "is not a good signature over"; then ok "an append is refused when a signature there is not over this SHA256SUMS"
    else bad "an append to a stale set: $(cat "$ST/out")"; fi

    run 1 --replace "$R/SHA256SUMS" "$ST/alice" && [ -s "$R/SHA256SUMS.sig" ] && [ ! -e "$R/SHA256SUMS.sig2" ] && [ ! -e "$R/SHA256SUMS.sig4" ] \
        && ok "--replace discards every signature and signs afresh" || bad "--replace: $(cat "$ST/out")"

    # Threshold 2 with one listed signer: signed, but the check says it is not enough yet.
    if run 2 --replace "$R/SHA256SUMS" "$ST/alice"; then bad "one signature passed a threshold of 2"
    elif [ -s "$R/SHA256SUMS.sig" ] && said "the threshold is 2"; then ok "one signature at threshold 2 is written and reported as not enough"
    else bad "threshold 2, one signer: $(cat "$ST/out")"; fi

    if run 1 "$ST/absent" "$ST/alice"; then bad "a missing SHA256SUMS was accepted"; else ok "a missing SHA256SUMS is refused"; fi
    mkdir "$ST/e"; cp "$ST/rel/SHA256SUMS" "$ST/e/"
    if run 1 "$ST/e/SHA256SUMS" "$ST/no-such-key"; then bad "a missing key was accepted"
    elif [ ! -e "$ST/e/SHA256SUMS.sig" ]; then ok "a missing key is refused and nothing is written"
    else bad "a missing key left a signature behind"; fi

    committed=$(grep -cvE '^[[:space:]]*(#|$)' "$HERE/release-signers")
    grep -q 'selftest-' "$HERE/release-signers" && bad "a self-test key is in deploy/release-signers" || ok "no self-test key is in deploy/release-signers ($committed key(s) listed there)"
    echo "sign-release selftest: $PASS passed, $FAIL failed"
    [ "$FAIL" -eq 0 ]; exit $?
fi

sign_release "$@"
