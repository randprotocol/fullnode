# Writing and deploying a RISC-V program

This page takes a program from source to a deployed RAND program. The toolchain is `rand-guest`,
in the circuits repo (`github.com/dendisuhubdy/zkp-circuits`, local
`~/Github/randprotocol/circuits`, main `7ef3220`). Its full reference is `rand-guest/README.md`
there. The chain side is in [`confidential.md`](confidential.md) and [`cli.md`](cli.md). To deploy
Solidity or Solana programs, see [`translators.md`](translators.md).

**How the outputs were made.** Every output below was produced on 2026-09-19 with circuits
`7ef3220` and fullnode `0cfd1e3`, on a macOS laptop. The deploys and the call ran against a local
one-validator chain with the **test** FRI profile, not the fleet. On a production-profile chain the
commands and the printed lines are the same; the proof sizes and times differ.

## 1. The Rand ISA

| property | value |
|---|---|
| base ISA | RV32IM: RV32I plus the M extension (`mul mulh mulhu mulhsu div divu rem remu`) |
| encodings | 32-bit only. RVC (16-bit) is refused |
| loads and stores | word, halfword and byte; memory is word-addressed underneath |
| alignment | a misaligned access is a constraint violation. Rust guests build with `-unaligned-scalar-mem` |
| program size | at most 65 535 words at any tier; the chain's cap is lower (§8) |
| proof system | Plonky3 batch STARK over Goldilocks, Poseidon2 hashing |
| tiers | tier `t` (10, 12, …, 20) proves up to `2^t − 1` cycles, with a separate Poseidon2 budget. The proof reveals the tier, not the cycle count |

### What `rand-guest check` refuses

`check` runs every text word through the machine's own decoder. A guest that passes cannot fail
in-circuit for an encoding, syscall-number or layout reason.

| finding | refused |
|---|---|
| `Compressed` | a 16-bit (RVC) encoding |
| `Undecodable` | an opcode, funct or shift amount the machine does not implement |
| `Fence` | `FENCE` and `FENCE.I`: no memory-ordering instructions |
| `Csr` | any CSR instruction: the machine has no CSRs |
| `Ebreak` | `EBREAK`: traps are not modelled |
| `Syscall` | an `ecall` whose `a7` is statically known and names no implemented syscall |
| `Cap` | more words than `--max-words`, counted as the loader counts them (text plus the data prologue) |
| `Layout` | a text base that is not word-aligned |

An `ecall` whose `a7` is not statically known is counted (`unresolved_ecalls`, printed as "ecall(s)
with a non-static a7"), not refused. `check` does not check pointer arguments, stack overflow, or
run-time alignment; `run` reports those as traps.

This is what a refusal looks like. The input is a hand-built image with one `fence` added:

```
$ rand-guest check fence.elf
note: the loader refuses this image (Decode { index: 3, word: 267386895, err: Opcode(15) }), so its data prologue could not be counted; the word count below is the text alone
0x0000100c  0x0ff0000f  Fence: FENCE/FENCE.I: the machine has no memory ordering instructions
10 words against a cap of 4096 (fits); 0 ecall(s) with a non-static a7
REJECTED
```

The exit status is 1.

### The syscall ABI

The syscall number goes in `a7`, the first argument in `a0`, a second in `a1`. A returned word
comes back in `a0`. Pointer arguments are **word** addresses (the byte pointer divided by 4).

| `a7` | syscall | arguments | C wrapper (`guest.h`) | Rust (`guest_sdk`) |
|---|---|---|---|---|
| 0 | halt | — | `rand_halt()` | `halt()` |
| 1 | write output | `a0` slot 0–7, `a1` word | `rand_write_output(slot, word)` | `write_output(slot, word)` |
| 2 | read private input | `a0` index; returns the word | `rand_read_input(idx)` | `read_input(idx)` |
| 3 | Poseidon2 | `a0` word ptr, `a1` n ≤ 4096; digest overwrites `ptr..ptr+8` | `rand_poseidon2(ptr, n)` | `poseidon2(ptr, n)` |
| 4 | Keccak-f[1600] | `a0` word ptr to a 50-word state, permuted in place | `rand_keccak(ptr)` | `keccak(ptr)`, `keccak256(msg)` |
| 5 | SHA-256 compression | `a0` word ptr to 24 words: block at 0..16, state at 16..24 | `rand_sha256_compress(ptr)` | `sha256_compress(ptr)`, `sha256(msg)` |
| 6 | read public input | `a0` index; returns the word | `rand_read_public(idx)` | `read_public(idx)` |

- Private inputs are bound to the salted commitment `H_IN`. A read past the end cannot be proven.
- `rand call` seals the private inputs into the call envelope, so the envelope cap bounds them:
  at most `(max_call_envelope_bytes − 1 252) / 4` words, read from `rand_getLimits`. That is
  4 295 words on a chain without the field (18 432 bytes) and 16 071 on chain 13 (65 536 bytes). A
  node without `rand_getLimits` gets the old 4 096. `--no-envelope` seals nothing and applies no
  word cap.
- Public inputs are bound to the unsalted `H_PUB`. A program's public input is fixed at deploy
  (`rand program deploy --public <FILE>`, §8.1): every call proves over the same words, and a call
  carries none of its own.
- The eight output words are published in the call's receipt. What they mean is up to the program.

Three chain rules limit which syscalls a deployed program can use. Each depends on the chain's
genesis limits (§8.1):

| syscall | chain without the limit fields (chain 12) | chain 13 |
|---|---|---|
| 6, read public | every call is verified against the **empty** public segment, so a program that reads public words cannot be called | the program's public input is fixed at deploy (up to `max_program_public_words`, 32 768) and every call is verified against its digest |
| 4, Keccak | a proof that carries the keccak table measured 3 198 430 bytes at tier 10, production profile, above the 2 MiB proof cap: refused by size | the proof cap is 8 MiB (`max_proof_bytes`), so such a proof fits; bytes past 2 MiB + 18 432 cost 1 000 units per KiB |
| 5, SHA-256 | the sha256 table adds 400 563 bytes to a production proof (measured upstream); with a hash-free 1 298 729-byte tier-10 proof, about 1.70 MB, under 2 MiB. This is a sum of two measurements, not a measured proof | fits under 8 MiB |

## 2. The image container

`rand-guest build` and `rand-guest pack` write the image container. `rand program deploy` reads it.

| word | value |
|---|---|
| 0 | `0x444e4152` (`IMAGE_MAGIC`, the bytes `RAND` read little-endian) |
| 1 | `1` (the version) |
| 2 | `text_base` |
| 3 | `n_text` |
| 4 | `data_base` |
| 5 | `n_data` |
| then | `n_text` text words, then `n_data` data words |

- The loader (`Program::from_flat_image`) synthesises a prologue of `li`/`sw` instructions below
  the text. It writes the data segment into RAM before the guest's own code runs. So a guest with
  `.rodata` works.
- The deployed program is the prologue plus the text. Its `base_pc` is the prologue's start.
- `IMAGE_MAGIC` never decodes as an RV32 instruction, so a raw `.bin` of words is never mistaken
  for a container. A file that starts with the magic but is malformed is a deploy error.

## 3. Install the toolchain

| component | pinned version | how |
|---|---|---|
| Rust | 1.98.1 | the `cargo +1.98.1` / `rustup +1.98.1` commands below need it installed |
| RISC-V target | `riscv32im-unknown-none-elf` | `rustup +1.98.1 target add riscv32im-unknown-none-elf` |
| linker | `rust-lld` from the pinned toolchain | `rustup +1.98.1 component add llvm-tools` |
| clang (C guests and translators) | 23.1.1 | `brew install llvm` (Apple's clang has no RISC-V backend), or set `$CLANG` |
| `cc` crate (translators only) | 1.4.6 | pinned in the generated `Cargo.toml` and `Cargo.lock` |

Build the tool once, from the circuits checkout:

```
$ (cd rand-guest && cargo +1.98.1 build --release)
```

The examples below call it as `rand-guest`, meaning `rand-guest/target/release/rand-guest`.

**A guest directory must sit inside a circuits checkout.** `build` finds `guest-sdk/` above it:

```
$ rand-guest build --lang c /some/dir/outside/csum
Error: /some/dir/outside/csum is not inside a circuits checkout (no guest-sdk/ above it)
```

## 4. Deploy a Rust program, step by step

### 4.1 Write the guest

A guest is a `no_std`, `no_main` binary crate that depends on `guest-sdk`. This one sums a list of
private inputs. Put it at `my-guests/sum/` in the circuits checkout.

`my-guests/sum/Cargo.toml`:

```toml
[package]
name = "sum-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
guest-sdk = { path = "../../guest-sdk" }

[profile.release]
opt-level = 3
lto = true
panic = "abort"
codegen-units = 1

[workspace]
```

`my-guests/sum/src/main.rs`:

```rust
#![no_std]
#![no_main]

use guest_sdk::{halt, read_input, write_output};

/// Input 0 is a count n; inputs 1..=n are the values.
/// Output 0 is their sum (mod 2^32); output 1 is n.
#[no_mangle]
pub extern "C" fn main() -> ! {
    let n = read_input(0);
    let mut sum = 0u32;
    for i in 1..=n {
        sum = sum.wrapping_add(read_input(i));
    }
    write_output(0, sum);
    write_output(1, n);
    halt();
}
```

- The entry point is `main`. `guest-sdk` supplies `_start`.
- End with `halt()`. It never returns.
- The empty `[workspace]` keeps the guest out of any parent workspace.
- Do not add a `.cargo/config.toml` or any RUSTFLAGS. `build` refuses config files (§7).

### 4.2 Build

`build` compiles, checks and packs in one step. It writes `image.bin` and `image.bin.sha256` into
the guest directory unless `--out` says otherwise.

```
$ rand-guest build my-guests/sum
     Locking 1 package to latest compatible version
   Compiling guest-sdk v0.1.0 (…/guest-sdk)
warning: unstable feature specified for `-Ctarget-feature`: `unaligned-scalar-mem`
warning: `guest-sdk` (lib) generated 1 warning
   Compiling sum-guest v0.1.0 (…/my-guests/sum)
warning: `sum-guest` (bin "sum-guest") generated 1 warning (1 duplicate)
    Finished `release` profile [optimized] target(s) in 0.29s
31 words against a cap of 4096 (fits); 0 ecall(s) with a non-static a7
OK
wrote my-guests/sum/image.bin and its .sha256 (31 words, hc a2af88deb4b21f4577acb4ac740e8644386de91a3d136b0ef8bcd2bb63df45b4, program id b2d5b50cbb2f2d686eccef01711be7f0eed9c335be20e01c9bbb29465fa428f4)
```

The `unaligned-scalar-mem` warning is expected. `build` sets that flag on purpose (§1).

### 4.3 Check

`build` already ran the check. To re-check an image or an ELF:

```
$ rand-guest check my-guests/sum/image.bin
31 words against a cap of 4096 (fits); 0 ecall(s) with a non-static a7
OK
```

Pass `--max-words N` to check against a raised chain cap. The default is 4096.

### 4.4 Run

`run` executes the image on the emulator. `--input` takes the private words in order. `--tier`
also reports whether the run fits that tier.

```
$ rand-guest run my-guests/sum/image.bin --input 3 100 200 300 --tier 10
out[0] = 600
out[1] = 3
out[2] = 0
out[3] = 0
out[4] = 0
out[5] = 0
out[6] = 0
out[7] = 0
cycles 39
tier 10
tier 10: fits (cycles 50 of 1023, Poseidon2 permutations 11 of 128)
```

`tier 10` is the smallest tier the run fits. The fit line counts the digest rows too, so its cycle
figure is higher than `cycles`. A trap prints `trap: <error>` and exits 2.

### 4.5 Deploy

The wallet deploys the image file directly.

```
$ rand program deploy my-guests/sum/image.bin
program id: b2d5b50cbb2f2d686eccef01711be7f0eed9c335be20e01c9bbb29465fa428f4 (31 words, hc de88afa2451fb2b4acb4ac7744860e741ae96d380e6b133dbbd2bcf8b445df63)
warning: chain uses the insecure test FRI profile
proving bundle (tier 14; about a minute on a laptop)…
proved in 97.0s: tier 14, 323108 bytes
submitted deploy 60d8b3962433672dc6af036096ff509105e3b86a8e7e4d9053c208d68c38fed6
  0 RAND out, 999.9959 RAND change, fee 0.0041 RAND, anchored at height 8
```

What the wallet does, in order:

1. Loads the container and prints the program id, the word count and `hc`.
2. Asks the node `rand_estimateFee` for a deploy of that many words. The node applies the chain's
   cap. An over-cap program is refused here, before any proving.
3. Proves a zero-value bundle that pays the deploy fee (`0.001 RAND + 100 000 units per word`;
   `rand fee deploy <words>` asks the node).
4. Submits and waits for the commit.

The `hc` the wallet prints is spelled differently from `rand-guest`'s. §7.1 explains why.

### 4.6 Call it

This session was captured before chain 13. On a chain-13 node `rand program show` also prints
`public_words_len` (0) and `public_digest` (null), and the receipt carries `"h_pub": null`: the
call was checked against the empty public input (`docs/rpc.md`, `rand_getReceipt`).

```
$ rand program show b2d5b50cbb2f2d686eccef01711be7f0eed9c335be20e01c9bbb29465fa428f4
{
  "base_pc": 4096,
  "code_hash": "de88afa2451fb2b4acb4ac7744860e741ae96d380e6b133dbbd2bcf8b445df63",
  "deployed_at": 108,
  "id": "b2d5b50cbb2f2d686eccef01711be7f0eed9c335be20e01c9bbb29465fa428f4",
  "words_len": 31
}
$ rand call b2d5b50cbb2f2d686eccef01711be7f0eed9c335be20e01c9bbb29465fa428f4 --input 3 --input 100 --input 200 --input 300
warning: chain uses the insecure test FRI profile
proving the call locally (4 inputs stay private)…
proved in 6.0s: tier 10, 296521 bytes, outputs [600, 3, 0, 0, 0, 0, 0, 0]
proving bundle (tier 14; about a minute on a laptop)…
proved in 97.0s: tier 14, 323493 bytes
submitted call aeb64e6887a1da21d2403771fb0aed373fa586448d5106364cb8fc69293f3491
  0 RAND out, 999.9939 RAND change, fee 0.002 RAND, anchored at height 120
{
  "h_in": "3bbbb6df49482846365c5fc188ac851f1a6bf17dfcc736706b6905e409be42c4",
  "height": 221,
  "index": 0,
  "outputs": [
    600,
    3,
    0,
    0,
    0,
    0,
    0,
    0
  ],
  "program": "b2d5b50cbb2f2d686eccef01711be7f0eed9c335be20e01c9bbb29465fa428f4",
  "tier": 10,
  "tx": "aeb64e6887a1da21d2403771fb0aed373fa586448d5106364cb8fc69293f3491"
}
input transcript published; open it with `rand open-call aeb64e6887a1da21d2403771fb0aed373fa586448d5106364cb8fc69293f3491`
```

The receipt's outputs equal `rand-guest run`'s. The call proof and the bundle proof are both made
in the wallet. That run's peak memory footprint was 5.74 GB (`/usr/bin/time -l`, test profile).
Call envelopes, auditors and `open-call` are in [`confidential.md`](confidential.md#call-input-envelopes).

## 5. Deploy a C program, step by step

### 5.1 Write the guest

A C guest directory holds only `.c` files. `build --lang c` supplies `guest.h`, `_start` and a
small runtime (`rt.c`: `memcpy`, `memmove`, `memset`, `memcmp` and the 64-bit division helpers).
It refuses a directory that has its own `guest.h` or `start.S`.

`my-guests/csum/sum.c`:

```c
/* Input 0 is a count n; inputs 1..=n are the values.
 * Output 0 is their sum (mod 2^32); output 1 is n. */
#include "guest.h"

void main(void) {
    uint32_t n = rand_read_input(0);
    uint32_t sum = 0;
    for (uint32_t i = 1; i <= n; i++) {
        sum += rand_read_input(i);
    }
    rand_write_output(0, sum);
    rand_write_output(1, n);
    rand_halt();
}
```

### 5.2 Build, check, run

```
$ rand-guest build --lang c my-guests/csum
29 words against a cap of 4096 (fits); 0 ecall(s) with a non-static a7
OK
wrote my-guests/csum/image.bin and its .sha256 (29 words, hc 0ce4fddb98b6e30b1f0e2e1894b690311a3eccb158dd772c8e6b69c4ac7e3e1c, program id 5cf0d2804c0b5b282d9ba191481bb6286d3b3c5738d6f9e712f0b3b5e6d5b7d5)
$ rand-guest check my-guests/csum/image.bin
29 words against a cap of 4096 (fits); 0 ecall(s) with a non-static a7
OK
$ rand-guest run my-guests/csum/image.bin --input 3 100 200 300 --tier 10
out[0] = 600
out[1] = 3
out[2] = 0
out[3] = 0
out[4] = 0
out[5] = 0
out[6] = 0
out[7] = 0
cycles 36
tier 10
tier 10: fits (cycles 47 of 1023, Poseidon2 permutations 11 of 128)
```

The C build compiles with `clang --no-default-config --target=riscv32-unknown-none-elf
-march=rv32im -mabi=ilp32 -mno-relax -nostdlib -ffreestanding -fno-builtin -ffunction-sections
-fdata-sections -Os`, then links with `rust-lld --gc-sections` against the same `guest.ld` as Rust
guests. The runtime helpers are byte loops. Copy and divide in words in a hot loop.

### 5.3 Deploy

The same command as for Rust:

```
rand program deploy my-guests/csum/image.bin
```

The committed C example, `guests-compiled/c-fib`, builds to 25 words and gives `fib(20) = 6765`,
the same as the Rust `fib` guest.

## 6. Deploy a hand-built RISC-V image

Any toolchain can produce the ELF. `rand-guest pack` wraps it into the container and `check`
decides whether the machine accepts it. This example is assembly.

`double.S` reads private input 0 and writes twice its value to output 0:

```asm
# double.S: reads private input 0, writes 2*x to output slot 0, halts.
    .section .text._start
    .globl _start
_start:
    li   a0, 0          # input index 0
    li   a7, 2          # SYS_READ_INPUT
    ecall               # a0 = input[0]
    slli a1, a0, 1      # a1 = 2 * input[0]
    li   a0, 0          # output slot 0
    li   a7, 1          # SYS_WRITE_OUTPUT
    ecall
    li   a7, 0          # SYS_HALT
    ecall
```

Assemble with the pinned clang and link with the pinned `rust-lld` against `guest-sdk/guest.ld`
(text at `0x1000`):

```
$ CLANG=/opt/homebrew/opt/llvm/bin/clang
$ LLD=$(rustc +1.98.1 --print sysroot)/lib/rustlib/aarch64-apple-darwin/bin/rust-lld
$ $CLANG --no-default-config --target=riscv32-unknown-none-elf -march=rv32im -mabi=ilp32 -mno-relax -c double.S -o double.o
$ $LLD -flavor gnu -T guest-sdk/guest.ld double.o -o double.elf
$ rand-guest pack double.elf --out double.bin
wrote double.bin (60 bytes) and double.bin.sha256
$ rand-guest check double.bin
9 words against a cap of 4096 (fits); 0 ecall(s) with a non-static a7
OK
$ rand-guest run double.bin --input 21
out[0] = 42
out[1] = 0
out[2] = 0
out[3] = 0
out[4] = 0
out[5] = 0
out[6] = 0
out[7] = 0
cycles 9
tier 10
$ rand-guest info double.bin
form: image container
text 9 words at 0x1000; data 0 words (0 non-zero) at 0x0; prologue 0 words; program 9 words from base_pc 0x1000
hc 9e6b00148a12aa70c41df1cbea018c3d0c18d739a6e182cd0c20ff8f1a5ab93c
program id e5fc40a4d0883e45d006faa3ac0334645668e2b3991db8311d187d0ccda07de2
9 words against a cap of 4096: fits
```

The `LLD` path names the host triple (`aarch64-apple-darwin` here). Then deploy it like any other
image: `rand program deploy double.bin`.

- A hand-built image is not reproducible from source by anyone else unless you publish the exact
  source and tools. Its `hc` is still the image's digest.
- Keep `a7` set by an `li` right before each `ecall`. `check` tracks `a7` only in straight-line
  code; a jump into the middle of a block can hide a bad syscall number from it. The machine
  still traps on it at run time.

## 7. `hc`, the program id, and the hermetic build

### 7.1 Two identities for one program

Both are hashes of the same `(base_pc, words)`.

| name | what it is | used for |
|---|---|---|
| `hc` | the circuit's Poseidon2 digest of the program (`Program::digest()`, eight words) | a call proof is verified against it. Stored as `code_hash` |
| program id | `blake3("rand-program" ‖ base_pc ‖ words)` | the key a program is stored and called under |

**`hc` has two spellings.** `rand-guest` prints each of the eight words as big-endian hex. The
wallet, `rand program show` and `rand_getProgram` print each word's little-endian bytes. The digest
is the same; the text differs. The ERC-20 image from [`translators.md`](translators.md):

| printed by | `hc` |
|---|---|
| `rand-guest build` / `info` | `a0feae92a7311c9562495717100eb7aea71270a38ed435d06dc31387e0ea8ff6` |
| `rand program deploy`, `rand program show` (`code_hash`) | `92aefea0951c31a717574962aeb70e10a37012a7d035d48e8713c36df68feae0` |

Each group of eight hex digits is byte-reversed: `a0feae92` becomes `92aefea0`. The program id is
spelled the same way by both tools.

### 7.2 The pinned toolchain

| pin | value | refused otherwise? |
|---|---|---|
| Rust | 1.98.1 | `build` runs `cargo +1.98.1` |
| clang | 23.1.1 | yes, unless `RAND_GUEST_CLANG_UNPINNED=1`; then `hc` will not match published images |
| `cc` crate | 1.4.6 (translators) | pinned in the generated `Cargo.lock` |

### 7.3 Why the build is hermetic

`hc` must be a function of the source and the pinned toolchain alone. Otherwise nobody could
rebuild a published source to a deployed `hc`. `build` enforces this:

- **The environment is scrubbed.** cargo and clang never see `RUSTFLAGS`,
  `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`, the guest target's `CARGO_TARGET_*`
  overrides, any `CARGO_PROFILE_*`, `CARGO_INCREMENTAL`, a `RUSTC` or wrapper override,
  `RUSTC_BOOTSTRAP`, any `CARGO_UNSTABLE_*`, the target-dir variables, or clang's
  `CCC_OVERRIDE_OPTIONS`, `CPATH`, `C_INCLUDE_PATH` and `COMPILER_PATH`.
- **Cargo config files are refused.** A `.cargo/config` or `.cargo/config.toml` in the guest's
  directory, an ancestor, or `$CARGO_HOME` would be merged into the build. `build` refuses and
  names each file.
- **Paths are remapped.** `--remap-path-prefix` (Rust) and `-ffile-prefix-map` (C) map the
  checkout to `/rand-circuits`, so panic strings do not depend on where the checkout lives.
- **clang reads no config files** (`--no-default-config`).
- **The previous ELF is deleted first**, so a stale one is never packed.

**Evidence.** The Rust `fib` guest was rebuilt for this page in a checkout at a different path. It
gave `hc ed475c16f1a55122316cd1a2a37da4318c4983ac89127795c99dd4375e27b99e`, the same as the
committed `guests-compiled/bin/fib.bin`. `rand-guest/tests/build.rs` gates the four committed
guests on every run: `evm.bin` and `sbpf.bin` byte for byte, `fib` and `keccak256` by program
equality.

## 8. The program-size cap is a genesis parameter

A `Deploy` may carry at most `max_program_words` words.

| genesis | cap |
|---|---|
| no `max_program_words` field (chain 12) | 4096 |
| `max_program_words: N`, `1 ≤ N ≤ 65535` | N |
| any value | never above 65 535, the zkVM's own limit |

- The cap is part of the genesis hash. It cannot be raised on a running chain. A raised cap needs
  a new chain.
- `rand-node genesis --max-program-words N` writes the field. Setting it to 4096 is a different
  chain from leaving it out.
- Every node needs a v0.4 build before `rand-node init` on such a file. An older build silently
  drops the field and computes a different genesis hash ([`cli.md`](cli.md#rand-node-init)).
- `rand-guest build` and `check` measure against `--max-words`, default 4096. Pass the target
  chain's cap.

This is what an over-cap deploy looks like on a chain without the field. The wallet stops before
proving:

```
$ rand program deploy erc20.bin
program id: f074c4eb834cf01886a8241b6a2e0caf6e1cee5327fee6cb1a1a37436607280d (11686 words, hc 92aefea0951c31a717574962aeb70e10a37012a7d035d48e8713c36df68feae0)
Error: words must be at most 4096 (this chain's program cap) (rpc -32602)
```

And the same image on a local chain cut with `--max-program-words 65535`:

```
$ rand-node genesis --chain-id 992 --validator "v.key.json,1000,$ADDR" --alloc "$ADDR=1000" --faucet --fri-profile test --max-program-words 65535 --out g-65535.json
...
wrote g-65535.json (genesis hash cbf56531bc09a07dd8c87614b123a4aa56ffd2aef9df1aeeb6d3651bcc7ef510, 1 validators, 1 notes, 1000 blocks/epoch, programs up to 65535 words, faucet on, confidential on, fri test, hc_bundle 4a27356f379571036025a4a8661c294b0edec2b7cf7fbfd60b472b186cbd4afb)
$ rand fee deploy 11686
1.1696 RAND
$ rand program deploy erc20.bin
program id: f074c4eb834cf01886a8241b6a2e0caf6e1cee5327fee6cb1a1a37436607280d (11686 words, hc 92aefea0951c31a717574962aeb70e10a37012a7d035d48e8713c36df68feae0)
warning: chain uses the insecure test FRI profile
proving bundle (tier 14; about a minute on a laptop)…
proved in 96.9s: tier 14, 325668 bytes
submitted deploy effe6f7c5f4c085c6de7c483dcd3dc84a4b0fb64e12fe070f13d6d9e5af6cb33
  0 RAND out, 998.8304 RAND change, fee 1.1696 RAND, anchored at height 12
```

A wallet's note store is per key file, not per chain. Use a separate key file (or move
`<key>.notes.json` aside) when you switch between chains, or the wallet fails with `no leaf at
index N`.

### 8.1 The call limits and a program's public input

Four more genesis fields follow the same rules as `max_program_words`: optional, bound into the
genesis hash only when present, fixed for the life of the chain, and reported by
`rand_getLimits`.

| field | absent (chain 12) | bounds | chain 13 |
|---|---:|---|---:|
| `max_proof_bytes` | 2 097 152 | 1 MiB ..= 32 MiB | 8 388 608 |
| `max_block_bytes` | 4 194 304 | 4 MiB ..= 64 MiB, and ≥ 2 × `max_proof_bytes` + 1 MiB | 20 971 520 |
| `max_call_envelope_bytes` | 18 432 | 18 432 ..= 1 MiB | 65 536 |
| `max_program_public_words` | 0 (no public input) | 0 ..= 65 535 | 32 768 |

`rand-node genesis` writes each with its flag (`--max-proof-bytes`, `--max-block-bytes`,
`--max-call-envelope-bytes`, `--max-program-public-words`; [`cli.md`](cli.md#rand-node-genesis)).

**A public input fixed at deploy.** A program that reads public words (syscall 6) gets them from
its deploy:

```
rand program deploy image.bin --public words.txt     # whitespace-separated u32 words
rand program deploy image.bin --public program.so    # an ELF, word-encoded as the sBPF guest reads it
```

- The program id then binds the public input:
  `blake3("rand-program-2", base_pc ‖ u32_le(len(words)) ‖ words ‖ u32_le(len(public)) ‖ public)`.
  Without `--public` the id is unchanged, `blake3("rand-program", base_pc ‖ words)`, so
  `rand-guest info` prints the no-public id. The id `deploy` prints is the one to call.
- The deploy pays for its public words as code words (`0.001 RAND + 100 000 units per word` over
  both), and the node stores the words and their digest `H_PUB`.
- `rand call <id>` fetches the public input (`rand_getProgramPublic`), checks that code and public
  input hash to the id, and proves over them. The chain checks the proof's `H_PUB` against the
  deploy's digest, so a proof over any other public words is refused (`PublicValues`). The receipt
  carries `h_pub`.
- `rand call <id> --expect-public <FILE>` refuses before proving unless the program's public input
  is exactly that file's words.

**Call fee over the free allowance.** A call is priced as before up to 2 097 152 + 18 432 bytes of
call proof plus input envelope; every KiB (or part of one) past that adds 1 000 units (0.000001 RAND). `rand fee call <tier> --bytes
B` asks the node.

### The testnet chain with a raised cap

| | |
|---|---|
| chain | 13 (not cut yet) |
| genesis hash | `TODO-CONTROLLER` |
| `max_program_words` | `TODO-CONTROLLER` |
| pinned build | `TODO-CONTROLLER` |

Chain 13's call limits are the values in §8.1 (`deploy/cut-chain13-genesis.sh`). Until chain 13
is live, deploy only images of at most 4096 words, and no `--public`, on the testnet.
