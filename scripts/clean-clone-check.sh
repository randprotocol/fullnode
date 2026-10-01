#!/usr/bin/env bash
# scripts/clean-clone-check.sh — audit v6 PROC-2 (issue #109): this workspace resolves and builds
# from a clone of this repository ALONE, with no sibling `circuits/` checkout.
#
# Until 2026-10-01 `crates/randprotocol-zkvm/Cargo.toml` had path dependencies on
# `../../../circuits/guests-compiled/{evm-core,sbpf-core}` and it and `crates/randprotocol-rvm`
# an optional one on `../../../circuits/rand-zkvm-cuda`; cargo reads every path dependency's
# manifest, optional or not, so `cargo metadata` failed on the first one a lone clone lacks. The
# first two are vendored now (`vendor/circuits/`, deploy/sync-zkvm.sh) and the third is a git
# dependency on zkp-circuits at a pinned revision, which cargo fetches itself.
#
# What this does: copies the tracked and untracked-unignored files of the working tree (so an
# uncommitted change is tested too) into a fresh temporary directory whose parent holds no
# `circuits/`, and runs `cargo metadata --locked` there, then `cargo check --workspace --locked`
# with any extra arguments given (`--release`, `--tests`, …). `CARGO_TARGET_DIR` is honoured, so
# a warm target directory keeps the check short. `METADATA_ONLY=1` stops after the metadata step
# (seconds, no build). CI's `clean-clone` job (.github/workflows/ci.yml) is the same test run on a
# runner that checked out this repository and nothing else.
#
# Run from anywhere: `scripts/clean-clone-check.sh [cargo check args…]`.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/rand-clean-clone.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
COPY="$TMP/fullnode"
mkdir -p "$COPY"
( cd "$ROOT" && git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf - ) | tar -xf - -C "$COPY"
if [ -e "$TMP/circuits" ]; then
  echo "clean-clone-check: $TMP/circuits exists; this would not be a clean clone" >&2
  exit 2
fi
cd "$COPY"
echo "clean-clone-check: $COPY (no sibling circuits/)"
cargo metadata --locked --format-version 1 > /dev/null
echo "clean-clone-check: cargo metadata --locked ok"
if [ "${METADATA_ONLY:-0}" = "1" ]; then
  exit 0
fi
cargo check --workspace --locked "$@"
echo "clean-clone-check: cargo check --workspace --locked $* ok"
