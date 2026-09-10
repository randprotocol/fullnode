#!/usr/bin/env bash
# deploy/sync-zkvm.sh — copy the research zkVM into crates/shrugg-zkvm. Run from the repo root.
#
# Local additions (executor.rs, codec.rs, the extended guests.rs and asm.rs, tests/executor.rs) are preserved; machine.rs gets a
# small post-sync patch exposing log_ext_degrees.
#
# Not vendored: the research crate's viewing-key stack (arx.rs, notes.rs, viewing.rs, ledger.rs and
# tests/viewing.rs). The node has no use for it yet and it drags in ml-kem/chacha20poly1305, so those
# files are excluded here; lib.rs and main.rs are hand-maintained on this side for the same reason
# (they name modules that only exist upstream).
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
if ! grep -q "log_ext_degrees_pub" "$DST/src/machine.rs"; then
  python3 - "$DST/src/machine.rs" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
s=s.replace("    pub fn verifier_key(&self, program: &Program, tier: Tier) -> CommonData<Config> {",
"    /// Public wrapper used by the chain executor to check a proof's degree bits.\n    pub fn log_ext_degrees_pub(&self, program: &Program, tier: Tier) -> Vec<usize> { self.log_ext_degrees(program, tier) }\n\n    pub fn verifier_key(&self, program: &Program, tier: Tier) -> CommonData<Config> {")
open(p,'w').write(s)
PY
fi
REV=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "synced zkVM from $SRC at $REV into $DST"
echo "reminder: --features cuda / mock-cuda need circuits checked out at ../../../circuits/rand-zkvm-cuda (i.e. circuits/ beside fullnode/)"
