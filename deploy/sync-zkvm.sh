#!/usr/bin/env bash
# deploy/sync-zkvm.sh — copy the research zkVM into crates/shrugg-zkvm. Run from the repo root.
#
# Local additions (executor.rs, codec.rs, the extended guests.rs and asm.rs, tests/executor.rs) are preserved; machine.rs gets a
# small post-sync patch exposing log_ext_degrees_pub (M3.4: now (tier, program_log_height)-keyed,
# since the program table's height is proof-declared, not tier-derived).
#
# Not vendored: the research crate's viewing-key stack (arx.rs — no longer exists upstream since
# M3.3's Poseidon2 switch, kept in the exclude list anyway, harmless — notes.rs, viewing.rs,
# ledger.rs and tests/viewing.rs). The node has no use for it yet and it drags in
# ml-kem/chacha20poly1305, so those files are excluded here; lib.rs and main.rs are hand-maintained
# on this side for the same reason (they name modules that only exist upstream).
#
# `hash.rs` IS vendored (M3.4): it is core, not viewing-key-specific — the program digest `hc`
# `isa::Program::digest` computes and the `POSEIDON2` syscall's reference sponge both live there.
# Its one dependency on the excluded `notes.rs` (the `HC` domain tag `notes::domain::HC`, folded
# into the program digest's first permutation) and `tables/cpu.rs`'s matching in-circuit copy of
# the same constant are patched below to a local `hash::HC_DOMAIN` instead of pulling `notes.rs`
# in just for one `u32`.
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
      --exclude arx.rs --exclude notes.rs --exclude viewing.rs --exclude ledger.rs \
      --exclude lib.rs --exclude main.rs "$SRC/src/" "$DST/src/"
rsync -a --delete --exclude executor.rs --exclude viewing.rs "$SRC/tests/" "$DST/tests/"
[ -f "$DST/src/guests.rs" ] || cp "$SRC/src/guests.rs" "$DST/src/guests.rs"
# rand_zkvm -> shrugg_zkvm, but the *dependency* rand_zkvm_cuda keeps its own name (it is an
# unmodified external crate), so park it behind a placeholder while the rename runs.
grep -rl "rand_zkvm" "$DST/src" "$DST/tests" | xargs -I{} sed -i '' \
      -e 's/rand_zkvm_cuda/@@RAND_ZKVM_CUDA@@/g' \
      -e 's/rand_zkvm/shrugg_zkvm/g' \
      -e 's/@@RAND_ZKVM_CUDA@@/rand_zkvm_cuda/g' {} 2>/dev/null || true
# M3.4: `verifier_key` is now `(tier, program_log_height)`-keyed (the program table's height is
# proof-declared, not tier-derived) — the wrapper's signature has to track that, or the chain
# executor's degree-bits pre-check (`ZkExecutor::verify_call`) won't compile against it.
if ! grep -q "log_ext_degrees_pub" "$DST/src/machine.rs"; then
  python3 - "$DST/src/machine.rs" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
s=s.replace("    pub fn verifier_key(&self, tier: Tier, program_log_height: u8) -> Arc<CommonData<Config>> {",
"    /// Public wrapper used by the chain executor to check a proof's degree bits.\n    pub fn log_ext_degrees_pub(&self, tier: Tier, program_log_height: u8) -> Vec<usize> { self.log_ext_degrees(tier, program_log_height) }\n\n    pub fn verifier_key(&self, tier: Tier, program_log_height: u8) -> Arc<CommonData<Config>> {")
open(p,'w').write(s)
PY
fi
# M3.4: `hash.rs`'s program-digest header and `tables/cpu.rs`'s in-circuit copy of the same
# constant both read `crate::notes::domain::HC` upstream; `notes.rs` isn't vendored (see the
# header comment above), so redirect both to a local constant instead of pulling it in.
if grep -q "crate::notes::domain::HC" "$DST/src/hash.rs" "$DST/src/tables/cpu.rs" 2>/dev/null; then
  grep -rl "crate::notes::domain::HC" "$DST/src" | xargs -I{} sed -i '' 's/crate::notes::domain::HC/crate::hash::HC_DOMAIN/g' {}
fi
if ! grep -q "pub(crate) const HC_DOMAIN" "$DST/src/hash.rs"; then
  python3 - "$DST/src/hash.rs" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
anchor = "use std::sync::OnceLock;\n"
const = anchor + (
    "\n/// `notes::domain::HC` (= 8), inlined: `notes.rs` isn't vendored into this crate (it drags in\n"
    "/// ml-kem/chacha20poly1305 for a viewing-key stack the node has no use for yet — see\n"
    "/// `deploy/sync-zkvm.sh`'s header comment), but `program_digest` below and `tables::cpu`'s\n"
    "/// digest-row prefix both need this exact domain tag to agree. Keep in sync with\n"
    "/// `research/src/notes.rs`'s `domain::HC` by hand across a resync.\n"
    "pub(crate) const HC_DOMAIN: u32 = 8;\n"
)
assert anchor in s, "hash.rs no longer has the expected anchor line; update the sync script's patch"
s = s.replace(anchor, const, 1)
open(p, 'w').write(s)
PY
fi
REV=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "synced zkVM from $SRC at $REV into $DST"
echo "reminder: --features cuda / mock-cuda need circuits checked out at ../../../circuits/rand-zkvm-cuda (i.e. circuits/ beside fullnode/)"
