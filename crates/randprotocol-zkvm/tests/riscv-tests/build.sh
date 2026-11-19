#!/usr/bin/env bash
# Rebuilds bin/*.bin and SHA256SUMS from an upstream riscv-tests checkout (README.md has what and
# why). Usage: build.sh <path to a riscv-tests checkout at the pinned commit>
#
# Needs: a clang with a riscv32 target ($CLANG, else Homebrew's), Rust 1.98.1 with llvm-tools (for
# rust-lld), and this repository (guest-sdk/guest.ld, rand-guest).
set -euo pipefail
PINNED=3df703cd52d5f0d8224e3c50bf03c6cb70efff98
src="${1:?usage: build.sh <riscv-tests checkout>}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
got="$(git -C "$src" rev-parse HEAD)"
if [ "$got" != "$PINNED" ]; then
  echo "riscv-tests is at $got, not the pinned $PINNED" >&2
  exit 1
fi
clang="${CLANG:-/opt/homebrew/opt/llvm/bin/clang}"
lld="$(rustc +1.98.1 --print sysroot)/lib/rustlib/$(rustc +1.98.1 -vV | sed -n 's/^host: //p')/bin/rust-lld"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rm -f "$here"/bin/*.bin
for suite in rv32ui rv32um; do
  for s in "$src/isa/$suite"/*.S; do
    name="$suite-$(basename "$s" .S)"
    # `fence_i` needs FENCE.I and self-modifying code; the machine has neither, and its loader
    # refuses the instruction, so there is no image to keep.
    if [ "$name" = rv32ui-fence_i ]; then continue; fi
    "$clang" --no-default-config --target=riscv32-unknown-none-elf -march=rv32im -mabi=ilp32 \
      -mno-relax -nostdlib -c -I "$here/env" -I "$src/isa/macros/scalar" "$s" -o "$work/$name.o"
    "$lld" -flavor gnu -T "$root/guest-sdk/guest.ld" "$work/$name.o" -o "$work/$name.elf"
    (cd "$root/rand-guest" && cargo +1.98.1 run --quiet --release -- pack "$work/$name.elf" --out "$work/$name.bin" >/dev/null)
    cp "$work/$name.bin" "$here/bin/$name.bin"
  done
done
(cd "$here/bin" && shasum -a 256 *.bin > ../SHA256SUMS)
echo "wrote $(ls "$here/bin" | wc -l | tr -d ' ') images and SHA256SUMS"
