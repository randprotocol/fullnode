# Prover in the browser: a feasibility spike

Can the full node's bundle prover run in a browser tab as WebAssembly? This crate answers that
by proving one synthetic transfer, the hidden-asset bundle of
`crates/randprotocol-zkvm/tests/shielded.rs::bundle_witness`, natively or as WASM, and
reporting tier, proof size and time. It is not shipped and not a workspace member.

## The answer (2026-09-17, chain 18 code)

No, not until the prover's peak memory drops well under 4 GiB, the WebAssembly ceiling.

| Run (Apple M4 Max, production FRI profile, tier 14) | Prove | Verify | Peak memory |
|---|---|---|---|
| Native, one thread | 96–99 s | 3.3 s cold | 5.64 GB |
| Native, `--features parallel` (Plonky3 rayon) | 11–12 s | 0.35 s | 5.73 GB |
| WebAssembly (opt-level 1, V8 in Node) | out of memory after 3 min, in the hiding-MMCS commit | | 4 GiB cap |

The same limit rules out proving on phones; the wallets send to a paired or RandProtocol prover.
Rerun this when the prover's memory changes.

Checked again on 2026-10-02 against `main` (v0.7.0): it builds and proves; test profile, one
thread, 108 s prove and 4.6 s verify, 346,790 proof bytes at tier 14.

## Running it

```sh
cd spikes/prover-wasm
cargo run --release --bin spike-native                    # test profile
cargo run --release --bin spike-native -- --production    # the chain's profile
cargo run --release --features parallel --bin spike-native -- --production

# WebAssembly. An optimised build of the zkvm crate takes hours; opt-level 1 takes minutes.
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' CARGO_PROFILE_RELEASE_OPT_LEVEL=1 \
  wasm-pack build --release --target nodejs --out-dir pkg
```

The WASM module exports `proveDemoBundle(production, verify)`, which returns the same JSON line.
Build output (`target*/`, `pkg*/`) is ignored.
