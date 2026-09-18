# Program cap as a genesis parameter, and deploying a `rand-guest` image — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a v0.4 chain accept programs up to the loader's 65 535-word limit, and let `rand program deploy` deploy the image container `rand-guest build` produces — with the running chain 12 byte-for-byte unaffected.

**Architecture:** An optional genesis field `max_program_words`, absent means today's 4 096 and leaves the genesis hash, file and state root identical (the pattern the `bridge` and `aggregation` sections use). The ledger holds the cap; admission and `rand_estimateFee` read it instead of the constant. The wallet's program loader recognises the RAND image container by its first word and loads it with the vendored `isa::Program::from_flat_image`, the same loader the prover uses, so the deployed program is exactly what `rand-guest` reported (same words, same `hc`, same program id).

**Tech Stack:** Rust 1.98.1, the fullnode workspace.

**Spec:** `circuits/docs/superpowers/specs/2026-09-18-rand-guest-toolchain-design.md` §1 (the deploy arrow) and §8 (the cap), both approved by the user 2026-09-18 ("raise the cap as a genesis parameter, cut with the v0.4 chain").

## Global Constraints

- A genesis file without `max_program_words` must hash exactly as today: the pinned genesis test and `deploy/genesis-chain12.json`'s hash `605eb7830963833ef897455b98cd2a641aec58e0291460898a5d19ab88760ef0` do not move.
- When present, the field is part of the genesis hash and must lie in `1..=65535` (`u16::MAX`, the loader's own limit); the node refuses a genesis outside it.
- No chain is cut by this plan; the v0.4 chain cut is the user's decision.
- `rand program deploy` of a raw `.bin` that is not an image container keeps today's behaviour (words from base 0); JSON keeps today's behaviour.
- Commit prefixes `genesis:`, `ledger:`, `node:`, `wallet:`, `docs:`; every message ends with:
  `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB`.

---

### Task 1: `max_program_words` in genesis, the ledger, admission and the fee estimate

**Files:**
- Modify: `crates/randprotocol-core/src/genesis.rs` (the field, validation, hash binding when present), `crates/randprotocol-core/src/gas.rs` (`MAX_PROGRAM_WORDS` stays as the default; add `MAX_PROGRAM_WORDS_LIMIT = 65_535`), the ledger (`crates/randprotocol-core/src/ledger/mod.rs`: the cap stored from genesis; the `Action::Deploy` check at ~783 reads it), `crates/randprotocol-node/src/rpc.rs` (~1097: `rand_estimateFee`'s deploy check reads the ledger's cap), `crates/randprotocol-node/src/main.rs` (`rand-node genesis --max-program-words N`), `docs/rpc.md` / `docs/confidential.md` where the 4 096 limit is stated.
- Test: `genesis.rs` tests; `ledger/mod.rs` tests (the existing oversized-deploy test at ~1811 plus the new cases); the pinned genesis-hash test in `crates/randprotocol-node/src/main.rs` (must stay green where it is green on main — note it currently fails on main for an unrelated reason; do not "fix" it here, only confirm this change does not alter its computed hash).

- [ ] **Step 1:** tests first — (a) a genesis without the field has the same hash as before (compute the hash of `deploy/genesis-chain12.json` and assert `605eb783…`); (b) a genesis with `max_program_words: 65535` hashes differently and builds; (c) `0` and `65536` are refused; (d) on a ledger built with the default, a 4 097-word deploy is refused and a 4 096-word one admitted; on a ledger with 65 535, a 5 000-word deploy is admitted; (e) `rand_estimateFee` with `{"kind":"deploy","words":5000}` errors under the default cap and returns a fee under 65 535.
- [ ] **Step 2:** implement: `#[serde(default, skip_serializing_if = "Option::is_none")] pub max_program_words: Option<u32>` on `Genesis`, bound into `hash()` only when `Some` (follow how `bridge`/`aggregation` are bound), validated in the same place `epoch_blocks` is; the ledger keeps `max_program_words: usize` (default `gas::MAX_PROGRAM_WORDS`) and restores it on reload the way the aggregation gate is restored (read how `reload_ledger` restores it — AGENTS.md records that a missed restore forks at first restart); admission and RPC read it.
- [ ] **Step 3:** check that a 65 535-word deploy transaction fits every size limit on its path: the transaction byte cap, the mempool's admission cap, `RPC_MAX_BODY_BYTES`, gossip message size, and the block cap. A 65 535-word program is 262 140 bytes of words plus the bundle; raise any cap that would refuse it only if it is a local constant with no consensus meaning, and report any consensus-relevant cap instead of changing it.
- [ ] **Step 4:** run `cargo test -p randprotocol-core` and `cargo test -p randprotocol-node --lib`; the 20 aggregation tests there need a `RECURSION_FIXTURES` cache this machine does not have and fail on main too — report them as pre-existing, not as regressions.
- [ ] **Step 5:** commit.

---

### Task 2: the wallet deploys a `rand-guest` image

**Files:**
- Modify: `crates/randprotocol-zkvm/src/codec.rs` (`program_from_bytes`: if the first word is `isa::IMAGE_MAGIC`, return `Program::from_flat_image(bytes)`; otherwise today's raw-words behaviour), `crates/randprotocol-client/src/main.rs` (`program deploy` prints the program id, `hc` and word count before proving, and calls `rand_estimateFee` for the deploy first so a program over the chain's cap is refused before a proof is paid for), `docs/cli.md` and `docs/confidential.md` (the deploy section names `rand-guest build` and the image container).
- Test: a unit test in `codec.rs` that `program_from_bytes` on the vendored `crates/randprotocol-zkvm/guests-compiled/bin/evm.bin` equals `guests::compiled::evm()` (same `base_pc`, `words`, digest), and that a raw non-container `.bin` still loads from base 0; a wallet test (or a node RPC test) that deploying an over-cap program through the wallet fails before any proving with an error naming the cap.

- [ ] **Step 1:** tests first; **Step 2:** implement; **Step 3:** `cargo test -p randprotocol-zkvm --lib codec` and the client tests that do not prove (`cargo test -p randprotocol-client --lib`); do not run the proving suites; **Step 4:** commit.
