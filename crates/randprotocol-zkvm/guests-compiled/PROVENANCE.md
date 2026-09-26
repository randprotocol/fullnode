# Provenance of the vendored guests and assets

Every file under `guests-compiled/` is a copy, made by `deploy/sync-zkvm.sh`, of the file at the
same path under `guests-compiled/` in the public circuits repository
(<https://github.com/randprotocol/zkp-circuits>). Nothing here is built or edited in this
repository. The copies are byte-identical to this circuits commit:

circuits: 573ef2e47c60de958c14fe60a97adb1e9822b3a6

That is the commit `.github/workflows/ci.yml` checks out as `CIRCUITS_PIN`; `tests/guest_provenance.rs`
refuses a manifest whose commit differs from it.

`SHA256SUMS`, beside this file, lists every vendored file's sha256 (`shasum -a 256 -c SHA256SUMS`
checks it from this directory). Three things check the files against it, and against their source:

- `crates/randprotocol-zkvm/tests/guest_provenance.rs` (every `cargo test`): each file hashes to its
  `SHA256SUMS` line, no file here is missing from the manifest, each `bin/<guest>.bin.sha256` names
  the same digest, and the chain-14 bundle guest's `hc` is still the genesis pin (below).
- CI's `guest-provenance` job: compares each copy byte for byte with circuits at `CIRCUITS_PIN`,
  runs circuits' rebuild gate (the four guests from source), and recompiles `erc20.runtime.hex`
  with the pinned `solc`.
- By hand, anyone: the commands in the table.

## The four guests

Source: the guest crate `guests-compiled/<guest>/` (`src/main.rs`, `Cargo.toml`, `Cargo.lock`, a
linker script) plus `guest-sdk/`; `evm` and `sbpf` also link `guests-compiled/evm-core` and
`guests-compiled/sbpf-core`, the same crates this workspace depends on by path. The toolchain is
`rand-guest` (`circuits/rand-guest`), which pins Rust `1.98.1` for target
`riscv32im-unknown-none-elf`, fixes the flags, and remaps the checkout path so an image does not
depend on where it was built.

| file | sha256 | last changed in circuits | form |
|---|---|---|---|
| `bin/fib.bin` | `9237c02d3aedbd31fe9dbe2e166635711477aba443cd27c01dd4c5576052760a` | `f5c8839` | legacy flat binary |
| `bin/keccak256.bin` | `bacb79815e2762cbbac0d9f96e398a5576f5907f9707d7dbe02f8e00b66f091d` | `d3bcd0c` | legacy flat binary |
| `bin/evm.bin` | `5500886fa2fca18dcdce367b5a4a405d2fefa4af5fc9967b4f0c69fe7ae5440d` | `11f54b8` | image container |
| `bin/sbpf.bin` | `d49f105066b1da5e75e2442ef48f377126ebe423d31ea90d90de2ae53332b759` | `66fb6a7` | image container |

Rebuild and compare, from a circuits checkout at the commit above (needs
`rustup toolchain install 1.98.1 --target riscv32im-unknown-none-elf --component llvm-tools`, and
no `.cargo/config.toml` in `$CARGO_HOME` or above the checkout — `rand-guest` refuses to build
under one):

    cd rand-guest && cargo test --release --test build -- --exact build_reproduces_every_committed_image_and_reports_hc

That builds all four from source into a temporary directory. `evm.bin` and `sbpf.bin` are compared
byte for byte with the committed images. `fib.bin` and `keccak256.bin` are legacy flat binaries,
which `rand-guest build` does not write (it writes only the image container), so for those two the
test compares the program instead: same `base_pc`, same words, same `hc`
(`circuits/guests-compiled/README.md`). One guest at a time:

    cd rand-guest && cargo run --release -- build ../guests-compiled/evm --out /tmp/evm.bin --max-words 65535

`bin/<guest>.bin.sha256` are circuits' own pins, in `shasum` form, copied with each binary.

## The two third-party assets

These are not built from source in either repository. They are the inputs the EVM and sBPF
interpreters are tested on (`src/evm.rs`'s `erc20_code`, `src/sbpf.rs`'s `SPL_TOKEN_ELF`), and the
chain never admits them as programs of its own.

**`evm/contracts/erc20.runtime.hex`** — sha256
`6fc11e9b7f42b965e541e4d506c0ebf2dea7a1e29cc0dd94f40fe04fd390a6a9`. The runtime bytecode of circuits' `guests-compiled/evm/contracts/ERC20.sol`
(added in circuits `a9c813e`), compiled by solc `0.8.37+commit.f401782d`:

    solc --optimize --optimize-runs 200 --evm-version shanghai --bin-runtime contracts/ERC20.sol

run from `guests-compiled/evm`; the last line of its output is the file. circuits'
`guests-compiled/evm/contracts/SOLC.md` records the compile and `contracts/build.sh` repeats and
diffs it. The compiler binaries, from <https://github.com/ethereum/solidity/releases/tag/v0.8.37>:

| asset | sha256 |
|---|---|
| `solc-macos` | `a27396e7732aa52e80ff89ad7bd8a2e46fec2a6dcc4ef20cd16e5e0c502d6821` |
| `solc-static-linux` | `5de843c2c93563cc66425c99a4fb13fdbf32b4c4ae07469480faaf126e14404a` |

The Linux digest is also the one `https://binaries.soliditylang.org/linux-amd64/list.json`
publishes for 0.8.37. Recompiled with `solc-macos` on 2026-09-26: exactly this file. CI
recompiles it with `solc-static-linux`.

**`sbpf/programs/spl_token.so`** — sha256 `8190d3f7ceb6cb7a7a8d8924bff89f9f611e15ce1f806f2b6237f3311a98f697`.
The SPL Token program's sBPF ELF as deployed on Solana mainnet-beta (added in circuits `cbf5dad`,
fetched 2026-09-13 at slot 446 590 705). It is not compiled from source here: no Solana
toolchain is involved, and the on-chain bytes are the artifact.

| | |
|---|---|
| program id | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| program-data account | `3gvYRKWyXRR9xKWe1ZjPhLY5ZJRN7KDB4rFZFGoJfFk2` |
| loader | `BPFLoaderUpgradeab1e11111111111111111111111`, upgrade authority none (immutable) |
| deployed at slot | 419 472 000 |
| source release | **unknown**: neither circuits nor this repository records which `solana-program-library` tag built these bytes |

The file is the program-data account's data after its fixed 45-byte `ProgramData` header (the
account is 108 645 bytes, the ELF 108 600). Re-fetch and compare:

    curl -s https://api.mainnet-beta.solana.com -X POST -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["3gvYRKWyXRR9xKWe1ZjPhLY5ZJRN7KDB4rFZFGoJfFk2",{"encoding":"base64"}]}' \
      | jq -r '.result.value.data[0]' | base64 -d | tail -c +46 | shasum -a 256

Re-fetched on 2026-09-26: the same digest. CI does not run this, because a public RPC endpoint
can rate-limit a runner. circuits' `guests-compiled/sbpf/programs/SPL_TOKEN.md` has the ELF's
section and relocation inventory.

## The guest the chain runs is not here

Chain 14's bundle guest, the hidden-asset bundle (`hc_bundle`
`83d3a3704a1fcdb9bae7136c0a947ffa34bd53f055388395ed705fe8cacd0ef8`, `deploy/genesis-chain14.json`),
is not a vendored binary. It is `guests::bundle_hidden()` in `src/guests.rs`: hand-written
assembly in this crate's own DSL (`src/asm.rs`), assembled at run time. Its source is the program.
`tests/guest_provenance.rs` asserts that `ZkExecutor::hc_bundle()` still equals the genesis pin,
so a change to that source that would move `hc` fails a test instead of forking a node. No
genesis pins any of the four guests above. One reaches a chain only as a program someone deploys
(`rand program deploy`), and the chain names it by its `hc`.
