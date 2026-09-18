# Call limits as genesis parameters, and a program's public input fixed at deploy

Status: approved by the user 2026-09-19. Target: chain 13 and the v0.4 tag.

## 1. Problem

The v0.4 translators produce programs that deploy on a chain with a raised `max_program_words` but
cannot be *called*:

| program | what blocks a call | today's rule |
|---|---|---|
| translated ERC-20 (evm2rv) | the harness uses the KECCAK syscall; a production call proof carrying the keccak table measured 3 198 430 B at tier 10 (~3.5 MB extrapolated at tier 18) | `MAX_PROOF_BYTES` = 2 MiB per proof, and the whole transaction ≤ `MAX_BLOCK_BYTES` = 4 MiB (fee-bundle proof ~1.3 MB + call proof ~3.5 MB ≈ 4.8 MB) |
| translated SPL Token (sbpf2rv) | its image reads the ELF (27 151 words) from the public tape | every call is verified against an **empty** public segment (`executor.rs:326`, `verify_public(&hc, &[], proof)`) |
| any call with more than 4 096 private input words (SPL needs 10 458) | the wallet seals the inputs into the call envelope | `MAX_CALL_INPUT_WORDS` = 4 096 (wallet), derived from the consensus cap `MAX_CALL_ENVELOPE_BYTES` = 18 432 |

All three caps are consensus rules (ledger `validate_inner` step 1 and step 7, and
`apply_block_for_sync`), so changing any of them is a new chain. Chain 13 is being cut for the raised
program cap anyway; this design lands with it.

## 2. Decisions (user, 2026-09-19)

1. The limits become **optional genesis parameters**, threaded exactly as `max_program_words` was
   (`ec9ae48`): absent means today's constant, so a genesis without them hashes as before.
2. A program's **public input is fixed at deploy** ("option 2"), chosen as the most private design.
   A proof's public input is visible to every verifier by definition. Fixing it at deploy means no call
   carries public data: every call to a program shows the same public input, already on chain since its
   deploy, and everything that varies per call goes through the private tape and the sealed envelope.
   There are **no per-call public words**.
3. The node's local transport limits (sync wire budget, RPC body limit, gossip transmit size) scale
   with the chosen block size instead of being fixed constants.

## 3. Genesis parameters

Five optional fields on `Genesis` (`randprotocol-core/src/genesis.rs`). `max_program_words` already exists; the other four are new:

| field | default (absent) | bounds (refused otherwise) | chain 13 value |
|---|---|---|---|
| `max_program_words` (exists) | 4 096 | 1 ..= 65 535 | 65 535 |
| `max_proof_bytes` | 2 097 152 (2 MiB) | 1 MiB ..= 32 MiB | 8 MiB |
| `max_block_bytes` | 4 194 304 (4 MiB) | 4 MiB ..= 64 MiB, and ≥ 2 × `max_proof_bytes` + 1 MiB | 20 MiB |
| `max_call_envelope_bytes` | 18 432 | 18 432 ..= 1 MiB | 65 536 |
| `max_program_public_words` | 0 (no public input: today's behaviour) | 0 ..= 65 535 (the zkVM's `PublicTooLong` bound) | 32 768 |

The chain-13 values need a basis:
- 8 MiB of proof allows the ERC-20 call (about 3.5 MB) with room for a tier-20 SPL call proof. That proof has never been produced, but it grows only about 2.4 % per two tiers.
- 20 MiB of block holds two worst-case proofs, the fee bundle's and the call's, plus the envelopes.
- 64 KiB of envelope holds about 15 000 sealed input words, enough for SPL's 10 458.
- 32 768 public words hold SPL Token's 27 151-word ELF.

Threading, per field (the `max_program_words` pattern):
- a `#[serde(default, skip_serializing_if = "Option::is_none")]` field;
- a `GenesisError` variant for out-of-bounds or inconsistent values, checked in `build`;
- a ledger field with a default, a `set_*`, and an accessor;
- restored in `node.rs::reload_ledger`;
- bound into the genesis hash with a name tag, appended only when present (`commit.extend(b"<name>"); commit.extend(n.to_be_bytes())`), in a fixed order after `max_program_words`;
- a `rand-node genesis --<flag>` option.

A chain-12-shaped genesis (no fields) keeps its hash byte for byte, and a test pins that.

## 4. The ledger rules that change

- **Step 1 (sizes):** `MAX_PROOF_BYTES` becomes `self.max_proof_bytes`, for the fee bundle, the call, the aggregate and the bridge-burn proofs alike. The whole-transaction cap `MAX_BLOCK_BYTES` becomes `self.max_block_bytes`.
- **Step 7 (the envelope):** `call_envelope::validate` takes `self.max_call_envelope_bytes`.
- **`apply_block_for_sync`:** the block byte cap becomes `self.max_block_bytes`. `MAX_BLOCK_TXS` is unchanged.
- **Proposer packing** (`node.rs:1089`, `candidates_within`): it uses the ledger's `max_block_bytes`.

## 5. A program's public input

**Deploy.** `Action::Deploy { base_pc, words }` gains `public: Vec<u32>`, with `#[serde(default)]` on the struct field only where the codec allows. It is a format change regardless, so chain 13 is a fresh chain.
- The ledger refuses `public.len() > self.max_program_public_words`, with a new `ValidationError::ProgramPublicTooLarge`.
- **Program id:**
  - with `public` empty: unchanged, `blake3("rand-program", base_pc ‖ words)`, so every existing id and test holds;
  - with `public` non-empty: `blake3("rand-program-2", base_pc ‖ words ‖ len(public) ‖ public)`.

  The same code with a different public input is a different program.
- **The program record** stores `public_digest: Option<[u32; 8]>`: `hash::public_digest(public)` when non-empty, else `None`. It also stores the words themselves, so provers can fetch them. The words go in a separate storage column (CF `program_public`), keyed by program id; `ProgramRecord` stays small.
- **The deploy fee** charges `DEPLOY_PER_WORD` for public words too: `deploy_fee(words.len() + public.len())`.

**Call verification.**
- `ConfidentialExecutor::verify_call` is unchanged in signature. The executor verifies with `verify(hc, proof)` and then compares `proof.public_values[PUB0..PUB0+8]` with the record's digest. For a record without one, it compares against `public_digest(&[])`, which is exactly today's behaviour.
- The node never re-hashes the public words on a call. The digest was computed once, at deploy.

**Receipts.** `CallReceipt` gains `h_pub: Option<Word8>`, the public digest the proof was checked against. That changes the storage and wire format, which is fine on a new chain. `receipt_json` exposes it.

## 6. The wallet and the RPC

**RPC.**
- `rand_getProgram` returns `public_words_len` and `public_digest`.
- A new method `rand_getProgramPublic(id)` returns the public words as hex.
- A new method `rand_getLimits` returns the chain's five limits, so wallets derive their caps instead of hard-coding them.
- `rand_estimateFee`, for `{"kind":"deploy"}`, accepts `public_words`.
- For `{"kind":"call"}`, it accepts `bytes`: see §7.

**Wallet.**
- `rand program deploy <image> [--public <file of u32 words | ELF .so>]`. The pre-check refuses a public input over the chain's cap before any proving.
- `rand call` fetches the program's public words, if any, and passes them to the prover. It uses `Machine::prove_salted(.., public, ..)` in place of `&[]`.
- `MAX_CALL_INPUT_WORDS` stops being a constant. The wallet derives it from `rand_getLimits().max_call_envelope_bytes`, less the envelope's fixed overhead, divided by 4, and keeps 4 096 as the fallback when talking to an older node.
- `seal_call_envelope` and `prove_call` take the cap as a parameter.
- `rand call` also pre-checks the proof size against `max_proof_bytes` before submitting.

## 7. Fees

Calls today are priced by tier alone, and the mempool orders by total fee. With a proof cap four times larger, a large proof would buy block space at the price of a small one.

**Proposal:** add a byte term to a call that charges only for bytes above today's free allowance, so every existing call costs what it costs now:

```
call_fee(tier, bytes) = CALL_BASE + CALL_PER_TIER_STEP·step(tier) + CALL_PER_KIB · ceil(max(0, bytes − CALL_FREE_BYTES) / 1024)
bytes = len(call proof) + len(input envelope)
CALL_FREE_BYTES = 2 MiB + 18 432   (today's two caps)
CALL_PER_KIB    = 1 000 base units (0.00001 RAND per KiB; a 3.5 MB keccak call pays ~0.015 RAND extra)
```

The ledger checks `fee ≥ BUNDLE_BASE + call_fee(outcome.tier, bytes)`. The pre-verify floor is unchanged.

**Open for the user:** the value of `CALL_PER_KIB`. The proposal keeps it small, because this is a testnet economics knob, not a security bound. The block cap is the security bound.

## 8. Local limits

The node computes these at startup from the ledger's limits instead of from constants:

| limit | today | new |
|---|---|---|
| sync wire budget (`SYNC_MAX_WIRE_BYTES`) | 6 MiB | `max_block_bytes + 2 MiB` |
| sync response limit | 2 × that + 256 KiB | unchanged formula |
| RPC body (`RPC_MAX_BODY_BYTES`) | the formula over the proof and envelope constants | the same formula over the genesis values |
| gossip transmit (`GOSSIP_MAX_TRANSMIT_SIZE`) | 16 MiB | `max(16 MiB, max_block_bytes + 1 MiB)` |

The admission throttles are unchanged.

## 9. What is out of scope

- Per-call public words (decision 2).
- Changing the prover's memory. A tier-20 call proof still needs about 330 GB to produce, so SPL Token becomes callable in principle but not on today's hardware. The docs say so.
- Changes to aggregation. Chain 13 is cut without the aggregation section, as chains 9–12 were.

## 10. Testing

- **Genesis:** each field is bounded, refused out of range, and bound into the hash. A chain-12 genesis keeps its hash byte for byte, and the existing test is extended. Restart and replay restore every field, following the `02b892b` pattern.
- **Ledger:**
  - a proof over the default cap is refused on a default chain and accepted on a raised one;
  - the block byte cap holds in both `apply_block_for_sync` and packing;
  - an envelope over the cap is refused.
- **Public input:**
  - a deploy with public words gets the new id, pays for its public words, and stores the digest;
  - a call proved with the right public words verifies;
  - one proved with other public words, or with `&[]`, fails with `PublicValues`;
  - a record without public words still verifies proofs made with `&[]`;
  - `h_pub` appears in the receipt.
- **Wallet:**
  - end to end on a local test-profile chain: deploy with `--public`, call, receipt;
  - the input cap is derived from `rand_getLimits`, with the fallback against an old node;
  - the pre-checks refuse an over-cap public input or proof before proving.
- **Fees:** `call_fee` is unchanged for bytes ≤ `CALL_FREE_BYTES`, and linear above.
- **Local limits:** the node on a 20 MiB genesis syncs a block larger than 6 MiB between two local nodes.
- **End to end with the translators, on a local test-profile chain with the chain-13 values:**
  - deploy the translated ERC-20 image and call `transfer` through `rand call`. This is proved at tier 18 under the test profile, so it runs where memory allows. If the laptop cannot prove tier 18, test the call path with the tier-16 `approve` vector instead;
  - deploy the SPL image with its ELF as the public input, and check that the call path refuses a mismatched public input without proving.

## 11. Rollout

The fields ship in the fullnode build that cuts chain 13. `deploy/cut-chain13-genesis.sh` is `cut-chain12-genesis.sh` plus the five fields at the chain-13 values and `--chain-id 13`. The rollout uses `deploy/cutover-droplet.sh`, as every chain cut has.
