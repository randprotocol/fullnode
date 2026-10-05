# Provenance of the vendored circuits crates

`evm-core/` and `sbpf-core/` are copies, made by `deploy/sync-zkvm.sh`, of the crates at
`guests-compiled/evm-core` and `guests-compiled/sbpf-core` in the public circuits repository
(<https://github.com/randprotocol/zkp-circuits>): the `no_std` EVM and sBPF interpreter cores
that `crates/randprotocol-zkvm`'s `src/evm.rs` and `src/sbpf.rs` run natively and the `evm` and
`sbpf` guests (`crates/randprotocol-zkvm/guests-compiled/`) are compiled from. Nothing here is
edited in this repository. Each crate is copied whole except its `Cargo.lock` (the workspace's
lock is the one cargo reads) and `target/`; the manifests are verbatim, their `[workspace]` table
included, which is why the root `Cargo.toml` lists both paths under `[workspace] exclude`. The
copies are byte-identical to this circuits commit:

circuits: 5ff7676a6da6ddf22ebf581efa09557696799a95

That is the commit `.github/workflows/ci.yml` checks out as `CIRCUITS_PIN`, and the commit
`crates/randprotocol-zkvm/guests-compiled/PROVENANCE.md` names;
`crates/randprotocol-zkvm/tests/guest_provenance.rs` refuses a manifest whose commit differs from
either.

Why vendored (audit v6, PROC-2, issue #109): until 2026-10-01 both were path dependencies on a
sibling `circuits/` checkout, and cargo loads every path dependency's manifest, so a clone of
this repository alone failed at `cargo metadata`. Neither crate has a dependency of its own
(`deploy/sync-zkvm.sh` refuses to vendor one that grew any), so the copies add nothing to the
dependency tree beyond themselves. The third sibling path, the CUDA backend `rand-zkvm-cuda`, is
not vendored: it is an optional git dependency on the same repository at a pinned revision
(`crates/randprotocol-zkvm/Cargo.toml` says how that revision relates to `CIRCUITS_PIN`).

`SHA256SUMS`, beside this file, lists every vendored file's sha256 (`shasum -a 256 -c SHA256SUMS`
checks it from this directory). What checks the files against it, and against their source:

- `crates/randprotocol-zkvm/tests/guest_provenance.rs` (every `cargo test`): each file hashes to
  its `SHA256SUMS` line, no file here is missing from the manifest, and the commit above is
  `CIRCUITS_PIN`.
- CI's `guest-provenance` job: compares each copy byte for byte with circuits at `CIRCUITS_PIN`.
- By hand: `diff -r --exclude Cargo.lock --exclude target vendor/circuits/evm-core
  <circuits>/guests-compiled/evm-core` (and `sbpf-core`) from a circuits checkout at the commit
  above.

Licence: GPL-3.0-only, the circuits repository's licence at its root; the two manifests carry
no `license` field of their own, which `deny.toml`'s `[[licenses.clarify]]` entries state.
