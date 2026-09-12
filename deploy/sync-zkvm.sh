#!/usr/bin/env bash
# deploy/sync-zkvm.sh — copy the research zkVM into crates/shrugg-zkvm. Run from the repo root.
#
# Local additions (executor.rs, codec.rs, address.rs, the extended guests.rs and asm.rs,
# tests/executor.rs, tests/shielded.rs) are preserved; machine.rs gets a
# small post-sync patch exposing log_ext_degrees_pub (M4.1: now (tier, program_log_height,
# input_log_height)-keyed — the input table's declared height joins the program table's as a
# third, proof-declared key component; see the M4.1 patch comment below). tests/backend.rs,
# tests/cheating.rs, tests/emulator.rs, tests/isa.rs, tests/tables.rs and tests/zk.rs are vendored
# wholesale, as before — nothing sync-script-specific changed for them under M4.1.
#
# Shielded pool S1: the note layer — `notes.rs`, `viewing.rs`, `ledger.rs` — IS vendored now. The
# node's shielded pool is built on exactly the research crate's note commitments, nullifiers,
# key hierarchy, envelope format and commitment tree, so a second hand-written copy on this side
# would be a soundness bug waiting to happen; `crates/shrugg-zkvm/Cargo.toml` therefore carries
# `ml-kem`/`chacha20poly1305` (the same pinned versions upstream uses) and `src/lib.rs` names the
# three modules. Node-specific code that bridges them to `shrugg-core`'s pure data types lives in
# the hand-maintained `src/address.rs`; the three vendored files are never hand-edited.
#
# Still not vendored: arx.rs (no longer exists upstream since M3.3's Poseidon2 switch, kept in the
# exclude list anyway, harmless); lib.rs and main.rs (hand-maintained on this side — they name
# modules that only exist on one side or the other); and, on the test side, `tests/viewing.rs` and
# `tests/bundle.rs`. Those two are excluded purely for runtime: each proves several `bundle`/
# `transfer` guests at tier 14 and takes minutes, so they stay upstream, where they are the
# authority on the note layer's behaviour. `crates/shrugg-zkvm/tests/shielded.rs` is this side's
# own, much smaller check that the vendored layer agrees with `shrugg-core`'s types (trees, the
# pinned `hc_bundle`, one end-to-end bundle proof).
#
# `hash.rs` IS vendored (M3.4): it is core, not note-layer-specific — the program digest `hc`
# `isa::Program::digest` computes and the `POSEIDON2` syscall's reference sponge both live there.
# M4.1 added a second sponge, `input_digest` (`H_IN`, the salted private-input commitment), which
# reads a second domain tag the same way `program_digest` does. Both tags live in `notes.rs`
# upstream (`notes::domain::HC` and `notes::domain::IN`) and `tables/cpu.rs`'s matching in-circuit
# copies of them; both are still patched below to local `hash::HC_DOMAIN` / `hash::IN_DOMAIN`
# constants. That patch predates the note layer being vendored and is deliberately kept rather
# than reverted: it is two `sed` lines plus a two-constant insertion, whereas reverting it would
# mean re-patching `hash.rs`/`tables/cpu.rs` in the opposite direction on every resync. What keeps
# the two copies honest is `tests/shielded.rs`, which asserts `notes::domain::HC == hash::HC_DOMAIN`
# and `notes::domain::IN == hash::IN_DOMAIN` — now that `notes.rs` is vendored, a drifting tag is a
# test failure on this side rather than a silent divergence.
#
# M4.1 also vendors `tables/input.rs` (new — the salted-input-commitment witness table) and picks
# up `isa.rs`'s new `Program::from_flat_binary`/`to_flat_binary` loader automatically, since
# `isa.rs` is not excluded. `guests.rs` IS excluded (hand-maintained), so upstream's new
# `guests::compiled` module — `tests/e2e.rs` (vendored wholesale) now calls
# `guests::compiled::fib()` — is mirrored by hand into the local `guests.rs`, with its
# `include_bytes!` path adjusted for this crate's shallower layout (`guests-compiled/` sits
# directly under `crates/shrugg-zkvm/`, not two levels up as it does from `research/src/`). The
# compiled binary itself, `guests-compiled/bin/fib.bin`, is not part of `research/src` or
# `research/tests` either, so it needs its own copy step (below) rather than riding along with
# either rsync.
#
# The CUDA backend is *not* vendored either: crates/shrugg-zkvm depends on it by path, as
# ../../../circuits/rand-zkvm-cuda, so `circuits` must be checked out beside `fullnode` when building
# with --features cuda or --features mock-cuda.
set -euo pipefail
SRC=${1:-../circuits/research}
DST=crates/shrugg-zkvm
mkdir -p "$DST/src" "$DST/tests"
rsync -a --delete --exclude target --exclude .git --exclude Cargo.lock --exclude rust-toolchain.toml \
      --exclude executor.rs --exclude codec.rs --exclude guests.rs --exclude asm.rs \
      --exclude address.rs --exclude arx.rs \
      --exclude lib.rs --exclude main.rs "$SRC/src/" "$DST/src/"
rsync -a --delete --exclude executor.rs --exclude shielded.rs \
      --exclude viewing.rs --exclude bundle.rs "$SRC/tests/" "$DST/tests/"
[ -f "$DST/src/guests.rs" ] || cp "$SRC/src/guests.rs" "$DST/src/guests.rs"
# M4.1: vendor the compiled guest binary `tests/e2e.rs::compiled_fib_*` and the local
# `guests::compiled::fib()` (see the header comment) both need. It lives beside `research/`, not
# inside it, so `$SRC/../guests-compiled` — fail loudly rather than leaving a stale/missing binary
# that only shows up as a runtime `include_bytes!` compile error far from this script.
FIB_SRC="$SRC/../guests-compiled/bin/fib.bin"
if [ ! -f "$FIB_SRC" ]; then
  echo "sync-zkvm.sh: expected compiled guest binary at $FIB_SRC — not found" >&2
  exit 1
fi
mkdir -p "$DST/guests-compiled/bin"
cp "$FIB_SRC" "$DST/guests-compiled/bin/fib.bin"
[ -f "$FIB_SRC.sha256" ] && cp "$FIB_SRC.sha256" "$DST/guests-compiled/bin/fib.bin.sha256" || true
# rand_zkvm -> shrugg_zkvm, but the *dependency* rand_zkvm_cuda keeps its own name (it is an
# unmodified external crate), so park it behind a placeholder while the rename runs.
grep -rl "rand_zkvm" "$DST/src" "$DST/tests" | xargs -I{} sed -i '' \
      -e 's/rand_zkvm_cuda/@@RAND_ZKVM_CUDA@@/g' \
      -e 's/rand_zkvm/shrugg_zkvm/g' \
      -e 's/@@RAND_ZKVM_CUDA@@/rand_zkvm_cuda/g' {} 2>/dev/null || true
# M4.1: `verifier_key` grew from a (tier, program_log_height) 2-tuple key to a (tier,
# program_log_height, input_log_height) 3-tuple (the input table's height is proof-declared, just
# like the program table's since M3.4) — the wrapper's signature has to track that, or the chain
# executor's degree-bits pre-check (`ZkExecutor::verify_call`) won't compile against it. The
# anchor is the exact `verifier_key` signature line; if upstream's signature ever changes again
# without this script being updated, `str.replace` would silently no-op and the build would fail
# downstream with a much more confusing "no method named `log_ext_degrees_pub`" error far from
# here — so this asserts the anchor is present and aborts the sync (non-zero exit) instead.
if ! grep -q "log_ext_degrees_pub" "$DST/src/machine.rs"; then
  python3 - "$DST/src/machine.rs" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
anchor = "    pub fn verifier_key(&self, tier: Tier, program_log_height: u8, input_log_height: u8) -> Arc<CommonData<Config>> {"
wrapper = (
    "    /// Public wrapper used by the chain executor to check a proof's degree bits.\n"
    "    pub fn log_ext_degrees_pub(&self, tier: Tier, program_log_height: u8, input_log_height: u8) -> Vec<usize> "
    "{ self.log_ext_degrees(tier, program_log_height, input_log_height) }\n\n"
)
assert anchor in s, (
    "machine.rs's verifier_key signature no longer matches the anchor this script patches on "
    "(expected the M4.1 3-arg (tier, program_log_height, input_log_height) form) — update "
    "deploy/sync-zkvm.sh's log_ext_degrees_pub patch to match the new signature before re-running"
)
s = s.replace(anchor, wrapper + anchor, 1)
open(p, 'w').write(s)
PY
fi
# M3.4/M4.1: `hash.rs`'s program-digest header and `tables/cpu.rs`'s in-circuit copy of the same
# constant both read `crate::notes::domain::HC` upstream; M4.1 added a second such pair for the
# input digest, `crate::notes::domain::IN`. The patch predates `notes.rs` being vendored and is
# kept rather than reversed (see the header comment above): two `sed` lines and one inserted
# constant block, versus re-patching in the opposite direction on every resync.
if grep -Eq "crate::notes::domain::(HC|IN)" "$DST/src/hash.rs" "$DST/src/tables/cpu.rs" 2>/dev/null; then
  grep -rl "crate::notes::domain::HC" "$DST/src" | xargs -I{} sed -i '' 's/crate::notes::domain::HC/crate::hash::HC_DOMAIN/g' {}
  # No word-boundary anchor needed: `domain::IN` has no colliding sibling constant (NK, PK, NF,
  # CM, OVK, KEM_SEED, NODE, HC, OUT, IN, TEST — nothing else starts with "IN"), and BSD sed
  # (macOS) does not support `\b` — a `\b`-anchored pattern here would silently fail to match at
  # all rather than fail loudly, which is worse than the (nonexistent) collision risk it guards.
  grep -rl "crate::notes::domain::IN" "$DST/src" | xargs -I{} sed -i '' 's/crate::notes::domain::IN/crate::hash::IN_DOMAIN/g' {}
fi
if ! grep -q "const HC_DOMAIN" "$DST/src/hash.rs"; then
  python3 - "$DST/src/hash.rs" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
anchor = "use std::sync::OnceLock;\n"
const = anchor + (
    "\n/// `notes::domain::HC` (= 8) and `notes::domain::IN` (= 10), inlined: `program_digest`/\n"
    "/// `input_digest` below and `tables::cpu`'s digest-row prefixes both need these exact domain\n"
    "/// tags to agree, and this patch predates `notes.rs` being vendored — it is kept rather than\n"
    "/// reversed; see `deploy/sync-zkvm.sh`'s header comment.\n"
    "///\n"
    "/// `pub`, not `pub(crate)`: `tests/shielded.rs` asserts these equal the vendored\n"
    "/// `notes::domain::HC` / `notes::domain::IN`, which is what keeps the two copies from drifting\n"
    "/// across a resync, and an integration test is a separate crate.\n"
    "pub const HC_DOMAIN: u32 = 8;\n"
    "pub const IN_DOMAIN: u32 = 10;\n"
)
assert anchor in s, "hash.rs no longer has the expected anchor line; update the sync script's patch"
s = s.replace(anchor, const, 1)
open(p, 'w').write(s)
PY
fi
REV=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "synced zkVM from $SRC at $REV into $DST"
echo "reminder: --features cuda / mock-cuda need circuits checked out at ../../../circuits/rand-zkvm-cuda (i.e. circuits/ beside fullnode/)"
