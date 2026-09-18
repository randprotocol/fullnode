# The Solana and Ethereum translators

Two tools turn another chain's bytecode into a Rand RISC-V program:

| tool | input | output |
|---|---|---|
| `sbpf2rv` | a Solana sBPF ELF (`program.so`) | a C crate that `rand-guest build` compiles to a RAND image |
| `evm2rv` | EVM runtime bytecode (`solc --bin-runtime`) | a C crate that `rand-guest build` compiles to a RAND image |

Both live in the circuits repo (`github.com/dendisuhubdy/zkp-circuits`, local
`~/Github/randprotocol/circuits`, main `7ef3220`). The authorities are
`sbpf2rv/README.md`, `evm2rv/README.md` and the design specs in
`docs/superpowers/specs/2026-09-18-{sbpf-to-rv32-translator,evm-to-rv32-translator}-design.md`.
This page is the fullnode-side summary. The toolchain they feed is in [`guests.md`](guests.md).

Each walkthrough below is copied from the circuits READMEs, where every command was run and the
output pasted. The ERC-20 walkthrough was also re-run for this page on 2026-09-19 at circuits
`7ef3220`; its words, cycles, word counts and `hc` matched the README exactly.

## 1. What a translator is

The circuits repo already has two interpreter guests: `guests-compiled/bin/evm.bin` runs EVM
bytecode opcode by opcode, and `guests-compiled/bin/sbpf.bin` runs an sBPF ELF instruction by
instruction. A translator does the same job ahead of time. It emits C for one specific program,
so the image runs that program natively.

- Translation is **off-chain**. The developer runs the translator and deploys the resulting RV32
  image with `rand program deploy`. The chain never sees the source bytecode.
- The translated image reuses the interpreter's input ABI. It takes the same input words and
  publishes the same eight output words.
- The chain treats a translated image like any other program. It stores the image and its
  program id, and verifies call proofs against its `hc`.

## 2. Trust model

Three facts make a translated image trustworthy.

1. **`hc` binds the translated code.** The translated logic is compiled into the image, and `hc`
   is the image's digest. A proof that verifies against `hc` is a run of that image.
2. **A guard binds `hc` to the source.** The translated code still reads parts of its source at
   run time: the EVM image reads the input vector's code for `CODECOPY` and `CODESIZE`; the sBPF
   image loads the ELF from the public tape. Without a check, one `hc` could run over a
   caller-chosen source. So each image carries a digest of its source and checks it before any
   translated code runs.

   | translator | what the guard hashes | on a mismatch |
   |---|---|---|
   | `evm2rv` | the source bytecode (`POSEIDON2` over its length and bytes) | status 2, `gas_used` 0, halt `OutOfBounds` |
   | `sbpf2rv` | the loaded program: text, rodata, their addresses, the entry | status 2 over the pre-state, halt `BadElf` |

3. **A verifier rebuilds to check `hc`.** Whether `hc` is the faithful translation of a given
   source is checked by rebuilding: run the pinned translator on the published source, build with
   the pinned toolchain, and compare `hc`. The build is hermetic for exactly this reason
   ([`guests.md`](guests.md#7-hc-the-program-id-and-the-hermetic-build)). For `evm2rv`, use the
   same `--stage` and `--chain-id`.

The chain does not record the source bytecode or its hash. Fullnode stores the image and its
program id only. A deployer who wants the source known publishes it beside the program. Anyone can
then rebuild it to the deployed `hc`.

## 3. The parity guarantee

**Claim.** For every input, the translated image publishes the same status and the same eight
output words as the interpreter guest. For `evm2rv`, `gas_used` also matches.

**Method.** Each translator has an oracle test suite that runs the real pipeline (translate,
`rand-guest build`, run on the emulator) against the interpreter guest and against the
interpreter run natively on the host.

| translator | tests |
|---|---|
| `sbpf2rv` | `tests/parity.rs` (the real pipeline against `run_call` and `sbpf.bin`), `tests/fuzz.rs` (differential fuzzing on the host), `tests/emit.rs`, `tests/scan.rs` |
| `evm2rv` | `cargo +1.98.1 test --release`: 70 tests plus 2 ignored proofs. `tests/parity.rs` runs the ERC-20's 8 vectors under both stages; `tests/fuzz.rs` runs 10 000 random programs against the interpreter |

### Accepted divergences

A translated run may halt where the interpreter would not, or halt differently. Each divergence
errs on the safe side: the translation never completes a run the interpreter halts, and none of
them changes a published word of a run both sides complete.

**`evm2rv`** (the observable contract is the status, the eight words and `gas_used`):

| # | divergence | why it is safe |
|---|---|---|
| 1 | The halt kind. Static gas is charged at the head of each block, so a block that would halt midway can halt `OutOfGas` at its head instead, or the reverse. | Both are status 2 with `gas_used` equal to the limit. The halt kind is not public. |
| 2 | The translation runs a little more. It implements `CHAINID` and `ORIGIN`, and runs calls to precompiles 1–9, where the interpreter traps. A call on too shallow a stack underflows at the block head. | Both sides give status 2 on the stack case. |
| 3 | The code guard. Given code other than its source, the interpreter would run it; the translation refuses it. | Status 2, `gas_used` 0. |

**`sbpf2rv`**:

| # | divergence | why it is safe |
|---|---|---|
| 1 | A `callx` target outside the set the scanner found gives `BadJump`, where the interpreter may execute real code. | Fuzzed 117-for-117: adding the target as a named entry makes both sides agree exactly. |
| 2 | Budget checks may be deferred one basic block. To fit SPL Token under the 65 535-word cap, 1 505 of its 3 546 blocks skip their own instruction-limit check. | Only the halt kind can differ, inside the one limit-crossing block. Status and the eight words are equal. |
| 3 | Only the source program runs. An ELF that loads to a different program halts `BadElf`. | Status 2 over the pre-state. An ELF that differs only where `elf::load` does not look runs on both sides. |

## 4. Walkthrough: an ERC-20 from Solidity to a deploy

Every command runs from the root of a circuits checkout. The output shown is real output. Long
output is cut where marked `...`.

### 4.0 The toolchain

The pins are Rust 1.98.1, clang 23.1.1 and the `cc` crate 1.4.6. `hc` depends on all three.

```
$ /opt/homebrew/opt/llvm/bin/clang --version | head -1
Homebrew clang version 23.1.1
```

On macOS, `brew install llvm` gives this clang. Build the two tools once:

```
$ (cd evm2rv && cargo +1.98.1 build --release)
$ (cd rand-guest && cargo +1.98.1 build --release)
```

### 4.1 Solidity to runtime bytecode

`evm2rv` takes **runtime** bytecode, not creation code. A proof is of one call to a deployed
contract, so the constructor never runs. The state it would have written is part of the
pre-state, as storage witnesses.

```
solc --optimize --optimize-runs 200 --evm-version shanghai --bin-runtime MyToken.sol
```

The last line of output is the hex. Save it as `mytoken.hex`.

- Use `--evm-version shanghai`. Newer targets emit `MCOPY` and other Cancun opcodes, which trap.
- The committed ERC-20 (`guests-compiled/evm/contracts/erc20.runtime.hex`, 1 296 bytes) was
  compiled with solc **0.8.37** (`0.8.37+commit.f401782d`) and exactly these flags.
- `guests-compiled/evm/contracts/SOLC.md` names the binary and its sha256.
  `guests-compiled/evm/contracts/build.sh` recompiles it and diffs the result when a solc is on
  `PATH`.

### 4.2 Translate

```
$ evm2rv/target/release/evm2rv guests-compiled/evm/contracts/erc20.runtime.hex --out evm2rv/target/erc20 --chain-id 12
1296 code bytes: 74 blocks, 798 opcodes, 51 jumpdests (stage 2)
CHAINID is the constant 12
no trapping opcodes present
wrote evm2rv/target/erc20 (crate erc20-runtime): contract.c, Cargo.toml, Cargo.lock, build.rs, src/main.rs, shim.ld
```

- A `.hex` file is read as hex text. Any other extension is read as raw bytes.
- `--out` must be inside a circuits checkout, because `rand-guest build` needs one.
- `--chain-id N` is the value `CHAINID` returns, baked into the C. It is required when the code
  contains `CHAINID`. This ERC-20 does not, so `hc` is the same with or without it.
- Any trapping opcode is listed as a warning, with its pc.

`contract.c` ends with the code guard:

```
$ tail -7 evm2rv/target/erc20/contract.c
   from. Before any of the code above runs, the shim hashes the input vector's code the same way and
   refuses any other (OutOfBounds, status 2, gas_used 0). */
const uint32_t *evm_code_digest(void);
const uint32_t *evm_code_digest(void) {
    static const uint32_t d[8] = {0xf679280fu, 0x86c10e83u, 0x7e8f1f39u, 0xa2377de3u, 0x8a2e282fu, 0xc54cad42u, 0xddfaf009u, 0x7d28a8afu};
    return d;
}
```

There are two translation stages. Both give the same results and the same gas. Each is a
different program, so each has its own `hc`.

| stage | source | what it does | flag |
|---|---|---|---|
| one | `src/emit.rs` | every opcode over `evm-rt`'s memory stack | `--stage 1` |
| two | `src/lift.rs` | each block's words in C locals, constants folded at translation | `--stage 2` (the default) |

### 4.3 Build the image

```
$ rand-guest/target/release/rand-guest build evm2rv/target/erc20 --max-words 65535
...
warning: erc20-runtime@0.1.0: evm2rv: clang Homebrew clang version 23.1.1 (/opt/homebrew/opt/llvm/bin/clang)
    Finished `release` profile [optimized] target(s) in 3.50s
11686 words against a cap of 65535 (fits); 0 ecall(s) with a non-static a7
OK
wrote evm2rv/target/erc20/image.bin and its .sha256 (11686 words, hc a0feae92a7311c9562495717100eb7aea71270a38ed435d06dc31387e0ea8ff6, program id f074c4eb834cf01886a8241b6a2e0caf6e1cee5327fee6cb1a1a37436607280d)
```

`--max-words 65535` is needed, because the default cap is 4 096 words. The build refuses any clang
other than 23.1.1. `RAND_GUEST_CLANG_UNPINNED=1` builds anyway, with a warning that `hc` will not
match published images.

### 4.4 Run a transfer

The input vector is the interpreter's: the code, the calldata, the caller and other environment
words, the gas limit, the pre-state root, and one storage witness per slot the call touches. The
`erc20_vector` example prints the parity test's `transfer` (ALICE sends BOB 250 of her 1 000) as
921 words. It also has `approve` and `transferFrom`.

```
$ (cd evm2rv && cargo +1.98.1 run -q --release --example erc20_vector -- transfer > target/transfer.words)
921 input words
$ rand-guest/target/release/rand-guest run evm2rv/target/erc20/image.bin --input $(cat evm2rv/target/transfer.words)
out[0] = 1
out[1] = 513227413
out[2] = 3087537901
out[3] = 995619457
out[4] = 4004100029
out[5] = 234390638
out[6] = 3262201797
out[7] = 3842361427
cycles 66235
tier 18
```

`out[0]` is the status: 1 success, 0 revert, 2 exceptional halt. `out[1..8]` is the `EVM_OUT`
digest over the code hash, both state roots, the return data and the logs.

### 4.5 The same eight words as the interpreter

The interpreter guest, on the same input:

```
$ rand-guest/target/release/rand-guest run guests-compiled/bin/evm.bin --input $(cat evm2rv/target/transfer.words)
out[0] = 1
out[1] = 513227413
out[2] = 3087537901
out[3] = 995619457
out[4] = 4004100029
out[5] = 234390638
out[6] = 3262201797
out[7] = 3842361427
cycles 121638
tier 18
```

The interpreter run natively on the host (the tests' oracle):

```
$ (cd evm2rv && cargo +1.98.1 run -q --release --example erc20_vector -- transfer --expected)
out[0] = 1
out[1] = 513227413
...
out[7] = 3842361427
interpreter (native): status 1, Return, gas_used 29956
```

The check, as one command:

```
$ diff <(rand-guest/target/release/rand-guest run evm2rv/target/erc20/image.bin --input $(cat evm2rv/target/transfer.words) | grep '^out') \
       <(rand-guest/target/release/rand-guest run guests-compiled/bin/evm.bin --input $(cat evm2rv/target/transfer.words) | grep '^out') \
  && echo "the eight words are identical"
the eight words are identical
```

The same `diff` over the `approve` and `transferFrom` vectors also printed "the eight words are
identical" when re-run for this page.

### 4.6 Deploy

```
$ rand-guest/target/release/rand-guest info evm2rv/target/erc20/image.bin
form: image container
text 11147 words at 0x10000; data 408 words (205 non-zero) at 0x1ae2c; prologue 539 words; program 11686 words from base_pc 0xf794
hc a0feae92a7311c9562495717100eb7aea71270a38ed435d06dc31387e0ea8ff6
program id f074c4eb834cf01886a8241b6a2e0caf6e1cee5327fee6cb1a1a37436607280d
11686 words against a cap of 4096: does not fit
```

The wallet deploys the image with:

```
rand program deploy evm2rv/target/erc20/image.bin
```

It prints the program id, the word count and `hc`, then checks the chain's program cap with
`rand_estimateFee` before it proves anything. The image is 11 686 words.

- Chain 12 runs the default cap of 4 096 words, so the deploy is refused there.
- On a local test chain cut with `--max-program-words 65535`, this exact deploy was run on
  2026-09-19 and committed (fee 1.1696 RAND; output in
  [`guests.md`](guests.md#8-the-program-size-cap-is-a-genesis-parameter)).
- It needs a chain whose genesis sets `max_program_words >= 11686`
  ([`guests.md`](guests.md#8-the-program-size-cap-is-a-genesis-parameter)).
- The chain that raises the cap is chain 13: genesis `TODO-CONTROLLER`, `max_program_words`
  `TODO-CONTROLLER`, pinned build `TODO-CONTROLLER`. It is not cut yet.

### 4.6.1 Call it

A translated ERC-20 takes no public input, so it is called like any program: the input vector
goes in as private words with `rand call`. The call proof carries the keccak table, so it needs a
chain whose `max_proof_bytes` admits it (chain 13: 8 MiB).

```
$ (cd evm2rv && cargo +1.98.1 run -q --release --example erc20_vector -- approve > target/approve.words)
649 input words
$ rand call f074c4eb834cf01886a8241b6a2e0caf6e1cee5327fee6cb1a1a37436607280d \
    $(for w in $(cat evm2rv/target/approve.words); do printf -- '--input %s ' $w; done)
warning: chain uses the insecure test FRI profile
proving the call locally (649 inputs stay private)…
proved in 392.6s: tier 16, 796019 bytes, outputs [1, 942495465, 790002515, 1351749335, 1059083501, 2923046783, 2814575942, 696258848]
proving bundle (tier 14; about a minute on a laptop)…
proved in 95.8s: tier 14, 324997 bytes
submitted call 33d2242d326bc77f909634c209b8c608cf5b0dfd6b8457c447ac425365b1a80c
  0 RAND out, 998.8281 RAND change, fee 0.0023 RAND, anchored at height 515
{
  "h_in": "81652149634be59a6777edf24862d244f1186a116c7b74b0fa473eeb5e1b8d80",
  "h_pub": null,
  "height": 628,
  "index": 0,
  "outputs": [1, 942495465, 790002515, 1351749335, 1059083501, 2923046783, 2814575942, 696258848],
  "program": "f074c4eb834cf01886a8241b6a2e0caf6e1cee5327fee6cb1a1a37436607280d",
  "tier": 16,
  "tx": "33d2242d326bc77f909634c209b8c608cf5b0dfd6b8457c447ac425365b1a80c"
}
```

(The receipt's `outputs` array is folded onto one line here.) This ran on 2026-09-19 on a local
one-validator chain cut with chain 13's five limits and the test FRI profile. The receipt's eight
words equal `rand-guest run`'s on the same vector, and `rand open-call` on the transaction
re-opened the 649 words and reproduced them (`verdict: faithful`).

- The call proof is 796 019 bytes and the sealed transcript 2 700 bytes (a 2 640-byte body and
  the 60-byte sender wrap). Together they are under the 2 097 152 + 18 432 free allowance, so
  the fee is `0.001 + call_fee(16)` = 0.0023 RAND.
- The whole command took 505.6 s: 392.6 s for the call proof and 95.8 s for the fee bundle. Peak
  memory was 19.8 GB maximum RSS and a 22.9 GB peak footprint (`/usr/bin/time -l`), on a 48 GB
  laptop.
- `approve` is tier 16. `transfer` and `transferFrom` are tier 18 and need about 85 GB to prove
  (§6.5), so they were not run on the laptop. Their call path is the same.

Before a call on the testnet, read [§7, What works on chain today](#7-what-works-on-chain-today).

### 4.7 ERC-20 numbers

Measured with `rand-guest run` on the vectors `tests/parity.rs` pins, with the code guard in.
Tier in parentheses. The three call rows were re-run for this page and matched.

| vector | interpreter (`evm.bin`) | stage one | stage two (default) |
|---|---:|---:|---:|
| `transfer(BOB, 250)` | 121 638 (18) | 80 211 (18) | **66 235** (18) |
| `approve(BOB, 5)` | 85 645 (18) | 56 261 (16) | **48 119** (16) |
| `transferFrom(ALICE, BOB, 100)` | 161 434 (18) | 110 074 (18) | **88 824** (18) |
| transfer of 5 000 of 1 000 (reverts) | 88 092 (18) | 54 256 (16) | 46 830 (16) |
| transfer, out of gas at 100 | 49 504 (16) | 32 831 (16) | 32 382 (16) |
| transfer, out of gas at 20 000 | 103 736 (18) | 67 815 (18) | 57 427 (16) |
| transfer, out of gas at 29 955 | 120 235 (18) | 78 553 (18) | 65 038 (18) |

| program | words | hc |
|---|---:|---|
| interpreter (`evm.bin`) | 18 009 | `7e1aea2b…854c08` |
| ERC-20, stage one | 15 804 | `9cdb79e7f05d53f6503f0eb777bb0c2356d29cab516a0378864802e42fd048c8` |
| ERC-20, stage two | 11 686 | `a0feae92a7311c9562495717100eb7aea71270a38ed435d06dc31387e0ea8ff6` |

- Stage two runs the three calls in 54.5 % (`transfer`), 56.2 % (`approve`) and 55.0 %
  (`transferFrom`) of the interpreter's cycles. Stage one takes 65.7 % to 68.2 %.
- The shared harness (decoding the input, verifying each storage witness, the ABI's `keccak256`
  calls, the output digest) is about 39 928 of stage two's 66 235 transfer cycles: about 60 %.
  No translation work can go below that floor.
- The transfer stays at tier 18. Its 66 235 cycles plus 3 155 digest rows are 69 390 rows, 3 855
  over tier 16's 65 535.
- The code guard costs 1 008 cycles and 167 words on the transfer, either stage.

## 5. Walkthrough: SPL Token from an ELF to a deploy

Every command below was run on 2026-09-18 against the committed ELF
`guests-compiled/sbpf/programs/spl_token.so`, the interpreter's own test fixture. Output is
pasted, and abbreviated only where it repeats.

```text
sbpf2rv <program.so> --out <dir inside a circuits checkout> [--name <crate>]
rand-guest build <dir> --max-words 65535
```

### 5.1 Translate

```text
$ sbpf2rv guests-compiled/sbpf/programs/spl_token.so --out <dir> --name spl-token
entry pc 225: 30 function(s), 3546 block(s), 12061 instruction(s), 30 callx target(s), 0 refusal(s), 4 warning(s)
  fn 225: 2065 block(s)
  fn 0: 41 block(s)
  fn 117: 52 block(s)
  ...                                              (30 functions in all)
  warning: UnknownSyscall { pc: 7803, hash: 2720453611 }
  warning: UnknownSyscall { pc: 9530, hash: 2720453611 }
  warning: UnknownSyscall { pc: 8698, hash: 2720453611 }
  warning: UnknownSyscall { pc: 11547, hash: 331461893 }
wrote <dir>/program.c (521757 bytes of C) and the spl-token shim crate: rand-guest build <dir>
```

- `0 refusal(s)`: nothing about the ELF's instructions is refused.
- The four warnings are real syscalls the `Transfer` instruction never reaches: hash
  `2720453611` is `sol_set_return_data` (three call sites) and hash `331461893` is
  `sol_get_sysvar` (one).

### 5.2 Build

```text
$ rand-guest build <dir> --max-words 65535
   Compiling sbpf-core v0.1.0 (…/guests-compiled/sbpf-core)
   Compiling guest-sdk v0.1.0 (…/guest-sdk)
   Compiling cc v1.4.6
   Compiling spl-token v0.1.0 (<dir>)
warning: spl-token@0.1.0: sbpf2rv: clang Homebrew clang version 23.1.1
    Finished `release` profile [optimized] target(s) in 5.81s
65096 words against a cap of 65535 (fits); 2 ecall(s) with a non-static a7
OK
wrote <dir>/image.bin and its .sha256 (65096 words, hc 8ca905ae3c62f503de7de86829040f323e098b53dba5fffe09b42f1aad16758b, program id 65d234ce9ca4d082f487c038abfa76e67f41a0d91e10b9ac388f1e1541d59184)
```

`program.c` ends with the ELF guard's constant: the digest of the loaded program it was translated
from. So `hc` binds that program.

### 5.3 Run, and compare with the interpreter

The `Transfer` 250 vector has two word lists, built by `tests/parity.rs` from
`SbpfCall::public_words()` and `input_words()`:

- **27 151 public words**: the ELF itself, word-encoded. This is why the image still carries the
  whole ELF, not just its hash.
- **10 458 private words**: the serialized instruction (the accounts, then the `Transfer`
  discriminant and the amount).

Abbreviated to the first words of each list:

```text
$ rand-guest run <dir>/image.bin \
    --public 108600 1179403647 65794 0 0 17235971 1 2088 …   (27 151 words)
    --input  41825 4 0 65791 0 50529027 50529027 50529027 …  (10 458 words)
out[0] = 1
out[1] = 2892832079
out[2] = 376091303
out[3] = 1311040261
out[4] = 2015764099
out[5] = 3682593600
out[6] = 3311553006
out[7] = 141115266
cycles 765851
tier 20
```

The same two word lists against the interpreter's committed guest:

```text
$ rand-guest run guests-compiled/bin/sbpf.bin \
    --public 108600 1179403647 65794 0 0 17235971 1 2088 …   (27 151 words)
    --input  41825 4 0 65791 0 50529027 50529027 50529027 …  (10 458 words)
out[0] = 1
out[1] = 2892832079
out[2] = 376091303
out[3] = 1311040261
out[4] = 2015764099
out[5] = 3682593600
out[6] = 3311553006
out[7] = 141115266
cycles 694498
tier 20
```

All eight words are identical. The translated image costs 71 353 more cycles: the ELF guard costs
72 949, against the program's own 13 k saving. Both land in tier 20.

Regenerate every SPL number with:

```text
cd sbpf2rv && cargo +1.98.1 test --test parity the_spl_token -- --nocapture
```

### 5.4 Deploy, with the ELF as the public input

The image reads the ELF from the public tape, so the ELF is the program's public input, fixed at
deploy. Pass the `.so` file itself: the wallet word-encodes it as the sBPF guest reads it (the
byte length, then the bytes four per word, little-endian), the same 27 151 words as
`SbpfCall::public_words()`.

```text
$ rand fee deploy 65096 --public-words 27151
9.2257 RAND
$ rand program deploy <dir>/image.bin --public guests-compiled/sbpf/programs/spl_token.so
program id: 740236918310f8e52bb0c1ef49b2b0e0c018762e289666660685b0694c8dd00a (65096 words, hc ae05a98c03f5623c68e87dde320f0429538b093efeffa5db1a2fb4098b7516ad, public input 27151 words, digest ec57b10ed6f3a3d5fe87ec072f691322ad747377ba2f0a1788bcfe3e7334d67e)
warning: chain uses the insecure test FRI profile
proving bundle (tier 14; about a minute on a laptop)…
proved in 93.2s: tier 14, 322819 bytes
submitted deploy 25933b2c013e674092d237aa728434d999884770330236ae27cd67b2cc226eea
  0 RAND out, 989.6024 RAND change, fee 9.2257 RAND, anchored at height 909
$ rand program show 740236918310f8e52bb0c1ef49b2b0e0c018762e289666660685b0694c8dd00a
{
  "base_pc": 64428,
  "code_hash": "ae05a98c03f5623c68e87dde320f0429538b093efeffa5db1a2fb4098b7516ad",
  "deployed_at": 1006,
  "id": "740236918310f8e52bb0c1ef49b2b0e0c018762e289666660685b0694c8dd00a",
  "public_digest": "ec57b10ed6f3a3d5fe87ec072f691322ad747377ba2f0a1788bcfe3e7334d67e",
  "public_words_len": 27151,
  "words_len": 65096
}
```

This ran on 2026-09-19 on the same local chain as §4.6.1 (chain 13's limits, test FRI profile).

- The deploy needs `max_program_words >= 65096` and `max_program_public_words >= 27151`. Chain
  13 sets 65 535 and 32 768. Chain 12 refuses both.
  Chain 13 values: genesis `TODO-CONTROLLER`, `max_program_words` `TODO-CONTROLLER`.
- The fee counts the public words with the code words: `0.001 + 100 000 units × (65 096 +
  27 151)` = 9.2257 RAND.
- The id binds the ELF (`rand-program-2`), so it is not the `65d234ce…` that `rand-guest info`
  prints for the bare image. Call the id `deploy` printed.
- `rand_getProgramPublic` serves the 27 151 words back; they start `108600 1179403647 65794 0 0
  17235971 1 2088`, the same words as §5.3.

### 5.5 Call it

A call carries only the private words, the serialized instruction (10 458 words for `Transfer`
250). `rand call` fetches the ELF from the node, checks that code and ELF hash to the program id,
and proves over them:

```text
rand call 740236918310f8e52bb0c1ef49b2b0e0c018762e289666660685b0694c8dd00a \
    --expect-public guests-compiled/sbpf/programs/spl_token.so \
    --input <w0> --input <w1> …     # the 10 458 words of SbpfCall::input_words()
```

The circuits repo has no command that prints those words yet; `sbpf2rv/tests/parity.rs` builds
them in code.

- 10 458 words fit chain 13's input cap, `(65 536 − 1 252) / 4` = 16 071. They would not fit a
  default chain's 4 295.
- `--expect-public` is optional. With it, the wallet refuses before proving unless the program's
  public input is exactly that file's words. Measured on the chain above, with no proving done:

```text
$ rand call 740236918310f8e52bb0c1ef49b2b0e0c018762e289666660685b0694c8dd00a --input 1 --expect-public spl_token-flipped.so
Error: the program's public input differs from --expect-public at word 27150 (0 on chain, 16777216 expected); not proving
$ rand call 740236918310f8e52bb0c1ef49b2b0e0c018762e289666660685b0694c8dd00a --input 1 --expect-public other.txt
Error: the program's public input is 27151 words and --expect-public has 4; not proving
```

  (`spl_token-flipped.so` is the ELF with its last byte changed; `other.txt` is `1 2 3 4`.) Each
  exited 1 in under 0.01 s, at 11 MB maximum RSS.
- The chain checks the call proof's `H_PUB` against the deploy's `public_digest`, so a proof over
  any other public words is refused with `PublicValues`.
- **Not run: the call proof itself.** Every SPL vector is tier 20, which needs about 330 GB to
  prove (§6.5). That is more than any machine this was tested on.

### 5.6 SPL Token numbers

Measured on a 16-core macOS laptop with 48 GB, 2026-09-18, with the ELF guard in place.

| vector | status | sBPF insns | translated cycles | `sbpf.bin` cycles | tier (both) | translated saves |
|---|---|---:|---:|---:|---|---:|
| `Transfer` 250 | 1 | 143 | 765 851 | 694 498 | 20 | −71 353 |
| `Transfer` more than the balance | 0 | 133 | 748 836 | 679 814 | 20 | −69 022 |
| `MintTo` 250 | 1 | 120 | 708 648 | 634 423 | 20 | −74 225 |
| `MintTo` by a non-authority | 0 | 134 | 696 694 | 627 241 | 20 | −69 453 |
| `Burn` 250 | 1 | 131 | 710 245 | 637 038 | 20 | −73 207 |
| `Burn` above the balance | 0 | 121 | 695 434 | 624 781 | 20 | −70 653 |
| `Transfer` with two accounts | 0 | 69 | 645 015 | 569 656 | 20 | −75 359 |
| account count above `MAX_ACCOUNTS` | 2 | 0 | 303 933 | 304 616 | 20 | 683 |

| image | words |
|---|---:|
| translated SPL Token (`hc 8ca905ae…758b`) | 65 096 of the 65 535 cap (439 spare; the guard added 271) |
| interpreter `sbpf.bin` | 8 317 |

**Where the cycles go.** About 98 % of every run is the fixed sBPF ABI harness, the same
`sbpf-core` code on both sides. The program's own execution is 1–3 %.

| stage (`Transfer` 250) | translated | `sbpf.bin` |
|---|---:|---:|
| decode_input: read both tapes | 302 881 | 302 880 |
| elf::load: parse, relocate, hash syscall names | 177 012 | 173 859 |
| check_region: the zero scan pinning the region | 103 829 | 103 824 |
| zero the sBPF stack and heap | 49 181 | 49 181 |
| output_hash | 25 994 | 20 348 |
| canonical input_hash | 18 620 | 16 225 |
| the ELF guard | 72 949 | — |
| public output words, program id | 3 753 | 3 504 |
| other: entry, glue | 2 724 | 2 646 |
| **program: sBPF execution** | **8 908** | **22 031** |
| total | 765 851 | 694 498 |

**Does translation pay off for SPL Token? Not today.** Translated execution is about 2.4–2.5×
cheaper per sBPF instruction (about 62 cycles against about 154 on the transfer). That saves
11.0–13.1 k cycles on these vectors. The larger shim harness and the guard cost more than that, so
the translated image is 69–75 k cycles dearer per vector. Translation pays off only for
compute-heavy programs: at the measured ~90 cycles saved per instruction, a program executing
10 000 instructions saves about 0.9 M cycles.

## 6. Limits

### 6.1 EVM environment opcodes

| opcode | translation |
|---|---|
| `ADDRESS`, `CALLER`, `CALLVALUE`, `CALLDATASIZE`, `CODESIZE` | from the input vector, as the interpreter reads them |
| `CHAINID` | the `--chain-id` constant, baked in, so `hc` binds it; 2 gas |
| `ORIGIN` | equals `CALLER` (one call, no relayer); 2 gas |
| `GASPRICE`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`, `SELFBALANCE`, `BASEFEE`, `BLOCKHASH` | trap (status 2), as in the interpreter |

The nine block-context opcodes trap until there is a design for binding them. A private input word
is bound only to the salted `H_IN`, which a verifier cannot open, so it cannot carry a block fact
a prover could not forge. Binding them needs a chain decision on which block a proof is checked
against. Until then, a contract that reads the time or the block number (a permit deadline, for
example) traps.

### 6.2 EVM calls and precompiles

- `CALL`, `CALLCODE`, `DELEGATECALL` and `STATICCALL` run a precompile when the target is 1 to 9,
  with Shanghai gas. Any other target traps, as in the interpreter.
- A nonzero value on `CALL` or `CALLCODE` traps. There is no balance model.
- `modexp`'s base and modulus are capped at 1 024 bytes each. The exponent is not capped.

All nine precompiles are software. The largest tier is 2^20 cycles. Measured with one known answer
each (`evm-rt/test/rv32-precompiles`):

| precompile | vector | cycles | fits 2^20? |
|---|---|---:|---|
| 1 ecrecover | ValidKey | 14 510 525 | no |
| 2 sha256 | "abc" / 200 bytes | 2 791 / 5 289 | yes |
| 3 ripemd160 | "abc" | 12 195 | yes |
| 4 identity | 100 bytes | 4 498 | yes |
| 5 modexp | nagydani-1-square / -1-pow0x10001 | 122 332 / 874 548 | yes |
| 5 modexp | eip_example1 (256-bit) | 11 170 118 | no |
| 5 modexp | nagydani-5-pow0x10001 (1 024-byte) | 55 076 950 | no |
| 6 bn256 add | chfast1 | 978 262 | yes, just |
| 7 bn256 mul | chfast1 | 3 060 669 | no |
| 8 bn256 pairing | 1 pair / 2 pairs | 1 853 656 212 / 2 019 000 469 | no |
| 9 blake2f | 12 rounds | 14 493 | yes (up to about 1 800 rounds) |

The ones over 2^20 cycles are correct but cannot be proven today. They are the coprocessor
backlog: ecrecover, bn256 mul, the pairing, modexp past small operands, and blake2f past about
1 800 rounds.

### 6.3 sBPF: what traps

Nothing is refused at translation. A static finding is a warning; the translated program traps at
run time only if it reaches the site, exactly as the interpreter does.

| warning | what the translated program does if it runs |
|---|---|
| `UnknownSyscall` | `sbpf_trap(UnknownSyscall, hash)` |
| `Cpi` (a `sol_invoke_signed*` hash) | the same `UnknownSyscall` trap. CPI is not implemented |
| `RegisterOutOfRange` | `sbpf_trap(BadInsn, opc)` |
| `UnknownOpcode` (incl. the v2-only `sdiv`/`srem`/pqr family, `hor64`) | `sbpf_trap(BadInsn, opc)` |
| `JumpOutOfText` | `sbpf_trap(BadJump)` |
| `BadCallImmSrc` | `sbpf_trap(BadInsn, 0x85)` |

`sol_ed25519_verify` and `sol_secp256k1_recover` trap, as they do on the interpreter. Software
implementations exist in `sbpf-rt/` but are not linked, as coprocessor backlog:

| operation | cycles |
|---|---:|
| `sol_secp256k1_recover` (go-ethereum's ecrecover vector) | 15 730 633 |
| `sol_ed25519_verify`, per call | about 14 290 782 |

Both are far past the 2^20-cycle tier cap.

### 6.4 The SPL harness cost

The sBPF ABI harness (tape reads, ELF load, region check, stack zeroing, hashes) is about 98 % of
a translated SPL Token run and keeps every SPL vector in tier 20. Translation does not change the
tier. A translated SPL proof therefore needs the same large machine as the interpreter's.

### 6.5 Proving memory

The prover is single-threaded: a 16-vCPU box ran at 99 % of one core. The translated ERC-20
calls land in tier 16 (`approve`) or 18 (`transfer`, `transferFrom`); every SPL Token vector lands
in tier 20.

| workload | tier | measured | final number |
|---|---|---|---|
| ERC-20 (66 k–162 k cycles) | 18 | OOM-killed on a 48 GB laptop at 24.7 GB after 1 016 s. A 64 GB droplet run was above 47 GB at 25 min | translated `transfer` (`a0feae92…`): 85.0 GB peak RSS, 3 230.5 s (53.8 min), 811 600-byte proof. Interpreter `evm.bin` (`7e1aea2b…`): 85.5 GB peak RSS, 3 143.3 s (52.4 min), 805 108-byte proof. Measured on a DigitalOcean m-16vcpu-128gb, 2026-09-19 |
| SPL Token (about 700 k–770 k cycles) | 20 | stopped on a 48 GB laptop at about 31 GB; OOM-killed on a 64 GB droplet at 65.1 GB after 10 m 41 s. Needs more than 64 GB | not yet proven. Extrapolated from the measured tier-16/18 scaling (memory about ×3.9, time about ×4.1 per +2 tiers): about 330 GB and about 3.6 h, more than DigitalOcean's largest memory droplet (m-32vcpu-256gb, 256 GB) |

The translated ERC-20 `transfer` and `approve` proofs have been produced and verified; the SPL
Token proof has not (see the extrapolation above). Proving cost is set by the tier, not the cycle
count: translated and interpreted `transfer` are both tier 18 and cost the same to prove.
Translation lowers proving cost only when it drops a call into a smaller tier, as it does for
`approve` (tier 16 translated against tier 18 interpreted): 786.7 s (13.1 min) and 21.7 GB peak
RSS instead of about 53 min and 85 GB. The translated and interpreted `transfer` proofs carry
identical public output words, so parity is confirmed on the real prover. The circuits READMEs'
proof runs used `FriProfile::Test`. The same `approve` proved inside `rand call` on the 48 GB
laptop (§4.6.1, test profile, 2026-09-19) took 392.6 s for a 796 019-byte proof, at 19.8 GB
maximum RSS and a 22.9 GB peak footprint for the whole command. [`node-hardware.md`](node-hardware.md#5-prover-memory-per-tier)
has the full table.

## 7. What works on chain today

The translators' own pipeline (translate, build, run, compare) works today on any laptop with the
pinned toolchain. On chain, each step depends on the chain's genesis limits
([`guests.md` §8.1](guests.md#81-the-call-limits-and-a-programs-public-input)). Chain 12 sets none
of them; chain 13 sets all five.

| step | ERC-20 (stage two) | SPL Token |
|---|---|---|
| deploy on chain 12 (cap 4 096, no public input) | refused: 11 686 words | refused: 65 096 words and a 27 151-word public input |
| deploy on chain 13's limits | admitted: `rand program deploy image.bin`, fee 1.1696 RAND (run, §4.6) | admitted: `rand program deploy image.bin --public spl_token.so`, fee 9.2257 RAND (run, §5.4) |
| call inputs | 649–1 201 private words (921 for `transfer`, 649 for `approve`): under the input cap on any chain (4 295 by default, 16 071 on chain 13) | 10 458 private words, under chain 13's 16 071 and over a default chain's 4 295; the 27 151 ELF words are the deploy's public input, which `rand call` fetches itself |
| call proof size | the harness calls `KECCAK`, so the proof carries the keccak table: 3 198 430 bytes at tier 10 (production), over chain 12's 2 MiB cap and under chain 13's 8 MiB. Test profile: 796 019 bytes at tier 16 (`approve`), 811 600 at tier 18 (`transfer`) | tier 20; not yet proven |
| call on chain 13's limits | `approve` called through `rand call` on a local chain: receipt outputs equal `rand-guest run`'s, fee 0.0023 RAND (§4.6.1). `transfer` needs a tier-18 prover | a mismatched public input is refused before proving (§5.5); the call proof itself needs a tier-20 prover |
| call proof memory | tier 16 fits a 48 GB laptop; tier 18 needs about 85 GB (§6.5) | tier 20, about 330 GB extrapolated (§6.5) |

In short: v0.4 delivers the translation, the parity evidence, the deploy path for both images, and
the call path on chain 13's limits. What remains is hardware: a ≥ 128 GB prover for the tier-18
ERC-20 calls, and one far larger than any DigitalOcean droplet for SPL Token's tier 20.
