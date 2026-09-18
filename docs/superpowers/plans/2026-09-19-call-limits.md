# Call limits and deploy-time public input: the implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development. Steps use checkbox syntax.

**Goal:** Make the v0.4 translated programs callable on chain 13. Four new genesis parameters join `max_program_words`: `max_proof_bytes`, `max_block_bytes`, `max_call_envelope_bytes` and `max_program_public_words`. A program also gains a public input that is fixed at deploy.

**Architecture:** Each limit is an optional genesis field, threaded exactly like `max_program_words` (commit `ec9ae48`). `Deploy` carries an optional public input. It is bound into the program id (a new domain) and stored once as a digest, plus its words in a separate column. Calls are verified against that digest. The wallet and RPC derive their caps from `rand_getLimits`.

**Tech stack:** Rust 1.98.1 workspace (`crates/randprotocol-{core,zkvm,node,client}`), RocksDB storage, bincode wire, JSON-RPC.

**Spec:** `docs/superpowers/specs/2026-09-19-call-limits-design.md`. It is binding. Read §3–§8 before any task.

## Global Constraints

- A genesis with none of the new fields must hash **byte for byte** as today. The chain-12 genesis hash `605eb783…` stays pinned by the existing test in `crates/randprotocol-node/src/main.rs` (~930).
- Defaults when a field is absent:

  | field | default |
  |---|---|
  | `max_proof_bytes` | 2 097 152 |
  | `max_block_bytes` | 4 194 304 |
  | `max_call_envelope_bytes` | 18 432 |
  | `max_program_public_words` | 0 |

- Bounds, which `build` refuses otherwise:

  | field | allowed range |
  |---|---|
  | `max_proof_bytes` | 1 MiB ..= 32 MiB |
  | `max_block_bytes` | 4 MiB ..= 64 MiB, and ≥ 2·`max_proof_bytes` + 1 MiB (the effective proof cap) |
  | `max_call_envelope_bytes` | 18 432 ..= 1 MiB |
  | `max_program_public_words` | 0 ..= 65 535 |

- Hash binding: each field is appended with its name tag only when present, in the order `max_program_words`, `max_proof_bytes`, `max_block_bytes`, `max_call_envelope_bytes`, `max_program_public_words`.
- Program id with no public input is unchanged: `blake3("rand-program", base_pc ‖ words)`. With a public input it is `blake3("rand-program-2", base_pc ‖ words ‖ u32_le(len) ‖ public)`.
- There are no per-call public words.
- The call fee is:

  ```
  call_fee(tier, bytes) = CALL_BASE + CALL_PER_TIER_STEP·step(tier) + CALL_PER_KIB·ceil(max(0, bytes − CALL_FREE_BYTES)/1024)
  CALL_FREE_BYTES = 2 097 152 + 18 432
  CALL_PER_KIB = 1 000
  ```

  `bytes` = call proof length + input envelope's encoded length. Every call at or under the free allowance costs exactly what it costs today.
- Every existing test must stay green, except the 21 node lib tests that need `RECURSION_FIXTURES` (absent on this laptop) and `the_genesis_hash_is_pinned` (already failing on main). Report those as known environment failures, not regressions.
- Commit prefixes: `genesis:`, `ledger:`, `node:`, `rpc:`, `wallet:`, `docs:`, `deploy:`. End every message with:
  ```
  Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01W1ULycUJmCEW99uG1CfJYB
  ```
- Never use bare `git stash`. Work only in `/Users/dendisuhubdy/Github/randprotocol/fullnode/.worktrees/call-limits`.

---

### Task 1: the four genesis parameters

**Files:** `crates/randprotocol-core/src/genesis.rs`, `crates/randprotocol-core/src/ledger/mod.rs` (fields, defaults, setters, accessors), `crates/randprotocol-core/src/gas.rs` (the default constants keep their names), `crates/randprotocol-node/src/node.rs` (`reload_ledger`), `crates/randprotocol-node/src/main.rs` (`genesis` flags `--max-proof-bytes`, `--max-block-bytes`, `--max-call-envelope-bytes`, `--max-program-public-words`), `crates/randprotocol-node/src/storage.rs` (restart and replay test).

**Interfaces produced:**
- `Genesis.{max_proof_bytes: Option<u32>, max_block_bytes: Option<u32>, max_call_envelope_bytes: Option<u32>, max_program_public_words: Option<u32>}`
- Ledger accessors `max_proof_bytes() -> usize`, `max_block_bytes() -> usize`, `max_call_envelope_bytes() -> usize`, `max_program_public_words() -> usize`, each with a `set_*`.
- `GenesisError::{BadMaxProofBytes, BadMaxBlockBytes, BadMaxCallEnvelopeBytes, BadMaxProgramPublicWords}`

**Tests first:**
- each field is refused out of bounds, including the block ≥ 2·proof + 1 MiB rule;
- each field present changes the hash, and absent leaves it unchanged;
- the chain-12 genesis file still hashes to `605eb783…`;
- `rand-node genesis --max-proof-bytes …` writes the field;
- restart and reload restore all four, following the `02b892b` test.

This task changes only the plumbing: no validation rule uses the new values yet.

### Task 2: the ledger rules and fees use the parameters

**Files:** `ledger/mod.rs` (`validate_inner` step 1 uses `max_proof_bytes` for every proof and `max_block_bytes` for the whole transaction; step 7 passes `max_call_envelope_bytes` to `call_envelope::validate`; `apply_block_for_sync` uses `max_block_bytes`), `ledger/call_envelope.rs` (the cap becomes a parameter), `gas.rs` (`call_fee(tier, bytes)`, `CALL_FREE_BYTES`, `CALL_PER_KIB`; update every caller), `ledger/mod.rs` step 10 (the fee check uses `call_fee(outcome.tier, bytes)`), `crates/randprotocol-node/src/node.rs` (packing with `candidates_within(.., ledger.max_block_bytes())`), `crates/randprotocol-node/src/mempool.rs` if it hard-codes the cap.

**Tests first:**
- a proof of 2 MiB + 1 B is refused on a default ledger and accepted with `max_proof_bytes` = 8 MiB;
- the whole-transaction cap follows `max_block_bytes`;
- an envelope over the cap is refused, and one under a raised cap is accepted;
- `apply_block_for_sync` refuses a block over the cap and accepts one under a raised cap;
- `call_fee(t, CALL_FREE_BYTES)` equals today's `call_fee(t)`; one KiB over adds 1 000; the result is monotonic;
- a call paying today's fee with an oversized proof is refused for its fee.

### Task 3: a program's public input fixed at deploy

**Files:**
- `crates/randprotocol-core/src/types/transaction.rs`: `Action::Deploy { base_pc, words, public: Vec<u32> }`. Update every constructor and match in the workspace. The encoding changes, which is fine for chain 13.
- `crates/randprotocol-core/src/program.rs`: `program_id_with_public(base_pc, words, public)` implements the id rule; `program_id` is kept for empty public input. `ProgramRecord.public_digest: Option<[u32; 8]>`. `CallReceipt.h_pub: Option<Word8>`.
- `ledger/mod.rs`:
  - deploy validation refuses `public.len() > max_program_public_words` with `ValidationError::ProgramPublicTooLarge`;
  - the deploy fee becomes `deploy_fee(words.len() + public.len())`;
  - the record stores the digest (`public_digest` from the zkVM, via the executor trait or a core helper; keep core free of zkVM deps as it is today);
  - receipts carry `h_pub`.
- `crates/randprotocol-zkvm/src/executor.rs`: `verify_call` checks `proof.public_values[pv::PUB0..+8]` against the record's digest, or against `public_digest(&[])` when there is none. The node never re-hashes public words on a call.
- `crates/randprotocol-node/src/storage.rs`: a new CF `program_public` (program id → the words, bincode) with a put at deploy and a get.
- `crates/randprotocol-core/src/confidential.rs`: if the trait needs a digest helper, add `fn public_digest(&self, words: &[u32]) -> [u32; 8]` to `ConfidentialExecutor`, implemented by `ZkExecutor` with `hash::public_digest`.

**Tests first:**
- a deploy with public words gets the new id, pays for its public words, and stores the digest and the words;
- a deploy over the public cap is refused;
- a call proved with the right public words verifies, with `h_pub` in the receipt;
- a call proved with other public words, or with `&[]`, against such a program fails with `PublicValues`;
- a program with no public input still verifies `&[]` proofs, and its id is unchanged;
- storage round trip, and a restart keeps the public words.

### Task 4: the RPC and the node's local limits

**Files:** `crates/randprotocol-node/src/rpc.rs`:
- **`rand_getLimits`:** returns `{max_program_words, max_proof_bytes, max_block_bytes, max_call_envelope_bytes, max_program_public_words}`.
- **`rand_getProgramPublic(id)`:** returns the words as hex (LE bytes, like code), or an empty array.
- **`rand_getProgram`:** adds `public_words_len` and `public_digest`.
- **`rand_estimateFee`:**
  - `{"kind":"deploy","words":N,"public_words":M}`;
  - `{"kind":"call","tier":T,"bytes":B}`, with `bytes` optional, defaulting to 0 so old callers are unchanged;
  - `receipt_json` adds `h_pub`.
- **`RPC_MAX_BODY_BYTES`:** computed from the ledger's limits at startup and stored in `RpcState`.

**Also:** `crates/randprotocol-node/src/network/mod.rs`:
- `SYNC_MAX_WIRE_BYTES` becomes `max_block_bytes + 2 MiB` at startup;
- the response limit keeps its formula;
- `GOSSIP_MAX_TRANSMIT_SIZE` becomes `max(16 MiB, max_block_bytes + 1 MiB)`.

Pass them through the network config, not globals, if the code allows.

**Docs:** `docs/rpc.md` documents the two new methods and the new fields, with a changelog line.

**Tests first:**
- each RPC method's JSON shape;
- `estimateFee` for deploy with public words, and for a call with bytes;
- the local limits computed from a 20 MiB ledger;
- two local nodes sync a block larger than 6 MiB (a network test, if the harness supports it).

### Task 5: the wallet

**Files:** `crates/randprotocol-zkvm/src/call_envelope.rs` and `executor.rs` (`MAX_CALL_INPUT_WORDS` becomes a function parameter; `prove_call` and `seal_call_envelope` take `max_input_words` and `public: &[u32]`; the provers pass `public` to `prove_salted`), `crates/randprotocol-client/src/{lib.rs,main.rs,wallet.rs}`.
- **`rand program deploy <image> [--public <file>]`:** the file is either whitespace-separated u32 words or a `.so` ELF, which is word-encoded exactly as research `SbpfCall::public_words` does. Read that code, and reuse it via the vendored path if available; else implement the same encoding with a test against a known vector. The pre-check checks the public length against `rand_getLimits`.
- **`rand call`:**
  - fetches `rand_getProgramPublic`;
  - proves with it;
  - derives the input cap from `rand_getLimits`: (`max_call_envelope_bytes` − the envelope's fixed overhead) / 4, falling back to 4 096 when the method is missing;
  - pre-checks the proof size against `max_proof_bytes`;
  - computes the fee with the byte term.
- **Docs:** `docs/cli.md`.

**Tests first:** the cap derivation, including the fallback; the public-file parsing for both the words form and the ELF form; and an end-to-end run on a local test-profile chain (follow the existing client end-to-end tests):
1. genesis with `--max-program-public-words 64 --max-program-words 4096`;
2. deploy a small guest that reads public words, with `--public`;
3. call it, and get a receipt with `h_pub`;
4. a call against a mismatched public input is refused.

### Task 6: the chain-13 cut script, the docs, and translator end to end

**Files:**
- `deploy/cut-chain13-genesis.sh`: a copy of `cut-chain12-genesis.sh` with `CHAIN_ID=13`, `OUT=deploy/genesis-chain13.json`, and the five fields at the chain-13 values (65 535, 8 MiB, 20 MiB, 65 536, 32 768), each overridable by env. Do NOT run it against the fleet; the controller cuts.
- `docs/translators.md`, `docs/guests.md`, `docs/confidential.md`: calls to translated programs, and `--public`.
- `CHANGELOG.md`: the v0.4 section lists the call limits and deploy-time public input as claims with tests.

**End to end (a local test-profile chain with the chain-13 values):**
- Deploy the translated ERC-20 image (circuits main 7ef3220, built with `rand-guest build`; the image is at `~/Github/randprotocol/circuits/evm2rv/target/proofimg/erc20/image.bin` if present, else rebuild per `evm2rv/README.md`).
- Call it. Use `approve` (tier 16): tier 18 needs about 85 GB to prove, and this laptop has 48 GB. Record the receipt, the fee, the proof bytes and the time.
- Deploy the SPL image with its ELF as `--public`. Show that a call with a mismatched public input is refused before proving. A full SPL call proof (tier 20) needs about 330 GB and is out of scope.
- Record the measured numbers in the report.
