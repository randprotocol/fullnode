# Sourced by deploy/rebuild-vps.sh and deploy/push-to-vps.sh (ops review OPS-1): what reaches a
# build host is the commit's tracked files, never the working directory. Rsyncing `./` shipped
# every untracked file with it — wallets/*.key.json (spend keys), logs, scratch — and built the
# binary from whatever the tree held, not from the commit it reports.
#
#   stage_clean_tree     run from the repository root; sets
#                          STAGE  a fresh mktemp directory holding the tree to rsync (removed on exit)
#                          REV    the commit sha, with -dirty when tracked files differ from HEAD
#
# A clean tree is `git archive HEAD`. Tracked files that differ from HEAD are refused unless
# ALLOW_DIRTY=1, and then the stage is `git ls-files` copied from the working tree — still only
# tracked files, never an untracked one. `.git-rev` is written into the stage, not the checkout.
stage_clean_tree() {
  REV=$(git rev-parse HEAD)
  STAGE=$(mktemp -d "${TMPDIR:-/tmp}/rand-stage.XXXXXX")
  # shellcheck disable=SC2064  # expand STAGE now: the trap must remove this directory
  trap "rm -rf '$STAGE'" EXIT
  if [ -z "$(git status --porcelain --untracked-files=no)" ]; then
    git archive --format=tar HEAD | tar -x -C "$STAGE"
  elif [ "${ALLOW_DIRTY:-}" = 1 ]; then
    echo "warning: tracked files differ from HEAD — ALLOW_DIRTY=1, shipping the working copies of tracked files only" >&2
    REV="$REV-dirty"
    # A tracked file deleted in the working tree is skipped rather than failing the copy.
    git ls-files -z | while IFS= read -r -d '' f; do
      [ -e "$f" ] || [ -L "$f" ] || continue
      printf '%s\0' "$f"
    done | rsync -a --from0 --files-from=- ./ "$STAGE/"
  else
    echo "refusing: tracked files differ from HEAD — commit them, or set ALLOW_DIRTY=1 to ship the working copies (the build then reports $REV-dirty)" >&2
    git status --short --untracked-files=no >&2
    exit 1
  fi
  # rand_getVersion's git_sha: the tree reaches the host without .git, so the node's build.rs
  # reads the commit from .git-rev there.
  echo "$REV" > "$STAGE/.git-rev"
}
