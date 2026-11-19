# riscv-tests for the RV32IM core (ZKVM-118)

The official RISC-V unit tests for the base integer instructions and the M extension
(`rv32ui`, `rv32um`), run through `src/emulator.rs` by `tests/riscv_tests.rs`. They are the
emulator's one reference from outside this repository: the AIR is tested against the emulator, and
until these the emulator was tested against nothing else.

## What is here

- `bin/*.bin` — 49 images in the zkVM's image container, one per upstream test, built from
  [riscv-software-src/riscv-tests](https://github.com/riscv-software-src/riscv-tests) at commit
  `3df703cd52d5f0d8224e3c50bf03c6cb70efff98` (2026-10-19). `SHA256SUMS` pins each.
- `env/riscv_test.h` — the only file of ours in a test: the frame that starts it and reports pass
  or fail through `WRITE_OUTPUT` and `HALT` instead of upstream's machine-mode `env/p`. Test
  bodies and `test_macros.h` are upstream's, unmodified.
- `build.sh` — rebuilds the images from an upstream checkout at that commit.
- `LICENSE.riscv-tests` — upstream's licence (BSD 3-clause), which covers the images.

Built on 2026-11-18 with Homebrew clang 23.1.4 as the assembler and Rust 1.98.1's `rust-lld`,
against `guest-sdk/guest.ld`, packed by `rand-guest pack`. These are assembly sources, so the
compiler version does not shape the code the way it does for a C or Rust guest; the digests are
of this build, and a rebuild with another assembler is expected, not guaranteed, to reproduce them.

## What passes, and the two that are not ordinary passes

48 tests halt with `out[0] = 1`: every `rv32ui` test but the two below, and all eight `rv32um`
tests (`mul`, `mulh`, `mulhsu`, `mulhu`, `div`, `divu`, `rem`, `remu`).

- **`rv32ui-ma_data`** exercises misaligned loads and stores. This machine does not implement
  them: a misaligned access is a trap (`ExecError::Misaligned`, `docs/01-isa.md`), and the guests
  are compiled never to emit one. The test is kept and asserted to trap that way.
- **`rv32ui-fence_i`** needs `FENCE.I` and self-modifying code. The machine has no such
  instruction and its program is not writable, so the loader refuses the image; none is kept.

## What this does not cover

The emulator only, at the instruction level. It is not a differential run against Spike or
another emulator over random programs, and it does not exercise the syscalls. `riscv_tests.rs`
also proves eight of the tests under the test profile, which holds the AIR to those; the other
forty are run on the emulator only.
