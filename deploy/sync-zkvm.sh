#!/usr/bin/env bash
# deploy/sync-zkvm.sh — copy the research zkVM into crates/shrugg-zkvm. Run from the repo root.
# Local additions (executor.rs, codec.rs, the extended guests.rs) are preserved; machine.rs gets a
# small post-sync patch exposing log_ext_degrees.
set -euo pipefail
SRC=${1:-../circuits/research}
DST=crates/shrugg-zkvm
mkdir -p "$DST/src" "$DST/tests"
rsync -a --delete --exclude target --exclude .git --exclude Cargo.lock --exclude rust-toolchain.toml \
      --exclude executor.rs --exclude codec.rs --exclude guests.rs "$SRC/src/" "$DST/src/"
rsync -a --delete "$SRC/tests/" "$DST/tests/"
[ -f "$DST/src/guests.rs" ] || cp "$SRC/src/guests.rs" "$DST/src/guests.rs"
grep -rl "rand_zkvm" "$DST/src" "$DST/tests" | xargs -I{} sed -i '' 's/rand_zkvm/shrugg_zkvm/g' {} 2>/dev/null || true
if ! grep -q "log_ext_degrees_pub" "$DST/src/machine.rs"; then
  python3 - "$DST/src/machine.rs" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
s=s.replace("    pub fn verifier_key(&self, program: &Program, tier: Tier) -> CommonData<Config> {",
"    /// Public wrapper used by the chain executor to check a proof's degree bits.\n    pub fn log_ext_degrees_pub(&self, program: &Program, tier: Tier) -> Vec<usize> { self.log_ext_degrees(program, tier) }\n\n    pub fn verifier_key(&self, program: &Program, tier: Tier) -> CommonData<Config> {")
open(p,'w').write(s)
PY
fi
# lib.rs: make sure the local modules are declared
grep -q "pub mod executor;" "$DST/src/lib.rs" || printf 'pub mod executor;\npub mod codec;\n' >> "$DST/src/lib.rs"
REV=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "synced zkVM from $SRC at $REV into $DST"
