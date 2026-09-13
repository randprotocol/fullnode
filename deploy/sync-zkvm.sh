#!/usr/bin/env bash
# deploy/sync-zkvm.sh — copy the research zkVM into crates/shrugg-zkvm. Run from the repo root.
#
# Local additions (executor.rs, codec.rs, address.rs, the extended guests.rs and asm.rs,
# tests/executor.rs, tests/shielded.rs) are preserved; machine.rs gets a
# small post-sync patch exposing log_ext_degrees_pub (M4.2: now a five-argument
# (tier, program_log_height, input_log_height, keccak_log_height, mem_log_height) function —
# see the M4.2 patch comment below). tests/backend.rs,
# tests/cheating.rs, tests/emulator.rs, tests/isa.rs, tests/keccak.rs, tests/tables.rs and
# tests/zk.rs are vendored wholesale, as before.
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
# M4.2 (constraint set 5, upstream ffd9e1e) changes five things this script has to know about.
# (1) A ninth AIR table, `tables/keccak.rs` (Keccak-f[1600]), plus its host reference `src/keccak.rs`
# and its own `tests/keccak.rs`: all three ride along with the two rsyncs, but `src/lib.rs` is
# hand-maintained on this side, so `pub mod keccak;` has to be added there by hand, and
# `crates/shrugg-zkvm/Cargo.toml` needs upstream's `p3-keccak = "=0.7.0"` (the table's AIR) and the
# `hex = "0.4"` dev-dependency `tests/keccak.rs`'s known-answer vectors use.
# (2) The keccak table is *optional per proof*: `Proof::keccak_log_height == 0` means the batch has
# eight instances and no keccak table at all, and `Proof::mem_log_height` is proof-declared too.
# Both are untrusted words, both are range-checked by `machine::check_declared_heights` before
# anything is sized from them — the chain executor calls that same function rather than restating
# its rules (`src/executor.rs`).
# (3) `Machine::verifier_key` is keyed on four components now, `(tier, program_log_height,
# input_log_height, keccak_log_height)`, while `log_ext_degrees` takes five (the declared
# `mem_log_height` as well, which `verifier_key` deliberately does not take — every valid memory
# height yields the same `CommonData`). The `log_ext_degrees_pub` patch below follows both.
# (4) The 2026-09-12 zk-audit port (ZC1/ZC2 cpu hash row-group entry gates and the HASH_FIN pin,
# ZM2's additive memory sort key, ZM3's `Instr::encode` immediate-range asserts, ZM4's Poseidon2
# pointer bound, ZH1-ZH4's tier/length caps) arrives entirely through the rsyncs — nothing here.
# (5) The production FRI profile is back to 80 queries / blowup 8 / 20 PoW bits, so proofs are
# ~1.20 MB (tier 10) / ~1.25 MB (tier 12) and a keccak-bearing proof is ~1.91 MB larger. That is
# not a sync-script concern, but it is why `shrugg-core`'s `MAX_PROOF_BYTES` moved to 2 MiB.
# `guests.rs` and `asm.rs` stay excluded, so M4.2's `guests::compiled::keccak256()`,
# `guests::keccak_demo()` and `asm::call_keccak()` are mirrored by hand into the local copies —
# the vendored `tests/{asm,cheating,e2e,emulator}.rs` call all three by name.
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
# M4.1/M4.2: vendor the compiled guest binaries the vendored `tests/e2e.rs` and the local
# `guests::compiled::{fib,keccak256}()` (see the header comment) need — `fib.bin` since M4.1,
# `keccak256.bin` since M4.2. They live beside `research/`, not inside it, so
# `$SRC/../guests-compiled` — fail loudly rather than leaving a stale/missing binary that only
# shows up as a runtime `include_bytes!` compile error far from this script.
mkdir -p "$DST/guests-compiled/bin"
for GUEST in fib keccak256; do
  BIN_SRC="$SRC/../guests-compiled/bin/$GUEST.bin"
  if [ ! -f "$BIN_SRC" ]; then
    echo "sync-zkvm.sh: expected compiled guest binary at $BIN_SRC — not found" >&2
    exit 1
  fi
  cp "$BIN_SRC" "$DST/guests-compiled/bin/$GUEST.bin"
  [ -f "$BIN_SRC.sha256" ] && cp "$BIN_SRC.sha256" "$DST/guests-compiled/bin/$GUEST.bin.sha256" || true
done
# rand_zkvm -> shrugg_zkvm, but the *dependency* rand_zkvm_cuda keeps its own name (it is an
# unmodified external crate), so park it behind a placeholder while the rename runs.
grep -rl "rand_zkvm" "$DST/src" "$DST/tests" | xargs -I{} sed -i '' \
      -e 's/rand_zkvm_cuda/@@RAND_ZKVM_CUDA@@/g' \
      -e 's/rand_zkvm/shrugg_zkvm/g' \
      -e 's/@@RAND_ZKVM_CUDA@@/rand_zkvm_cuda/g' {} 2>/dev/null || true
# M4.2: `verifier_key`'s key grew a fourth component — it is `(tier, program_log_height,
# input_log_height, keccak_log_height)` now, the keccak table's declared height joining the
# program table's (M3.4) and the input table's (M4.1) as proof-declared key material, with
# `keccak_log_height == 0` a legitimate value meaning "this proof declares no keccak table".
# `log_ext_degrees` takes a *fifth* argument on top of those four, the declared `mem_log_height`:
# `verifier_key` deliberately does not take it (every valid memory height yields the same
# `CommonData` — see that function's doc comment) but the degree-bit vector does depend on it, and
# `Machine::verify` compares `proof.batch.degree_bits` against the five-argument call. The wrapper
# therefore forwards all five, or the chain executor's degree-bits pre-check
# (`ZkExecutor::decode_and_check`) could not reproduce what `verify` checks.
#
# The anchor is the exact `verifier_key` signature line — patched *in front of* it, so the wrapper
# lands next to the function whose arity it tracks; if upstream's signature ever changes again
# without this script being updated, `str.replace` would silently no-op and the build would fail
# downstream with a much more confusing "no method named `log_ext_degrees_pub`" error far from
# here — so this asserts the anchor is present and aborts the sync (non-zero exit) instead.
if ! grep -q "log_ext_degrees_pub" "$DST/src/machine.rs"; then
  python3 - "$DST/src/machine.rs" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
anchor = "    pub fn verifier_key(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8) -> Arc<CommonData<Config>> {"
wrapper = (
    "    /// Public wrapper used by the chain executor to check a proof's degree bits. Takes the\n"
    "    /// declared `mem_log_height` as well as `verifier_key`'s four key components: the degree\n"
    "    /// vector depends on it even though the verifier key does not, and `verify` compares\n"
    "    /// `proof.batch.degree_bits` against exactly this call.\n"
    "    pub fn log_ext_degrees_pub(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, mem_log_height: u8) -> Vec<usize> "
    "{ self.log_ext_degrees(tier, program_log_height, input_log_height, keccak_log_height, mem_log_height) }\n\n"
)
assert anchor in s, (
    "machine.rs's verifier_key signature no longer matches the anchor this script patches on "
    "(expected the M4.2 4-arg (tier, program_log_height, input_log_height, keccak_log_height) "
    "form) — update deploy/sync-zkvm.sh's log_ext_degrees_pub patch to match the new signature "
    "before re-running"
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
