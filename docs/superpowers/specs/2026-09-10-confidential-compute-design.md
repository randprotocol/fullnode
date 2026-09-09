# Confidential arbitrary computation on the SHRUGG chain — design

Date: 2026-09-10
Status: approved by the user on 2026-09-10 (decisions recorded at the end)

## Goal

Make SHRUGG the gas coin for confidential computation. A user runs a program off-chain inside the
Rand zkVM (`circuits/research`, crate `rand_zkvm`: RV32I under a Plonky3 batch STARK, Goldilocks,
Poseidon2, ZK-hiding FRI) on private inputs, and submits only a proof plus the eight public output
words. Every node verifies the proof against the program stored on chain, charges SHRUGG gas by tier,
records the outputs, and optionally applies a value transfer gated by the outcome. Plain SHRUGG
transfers keep working exactly as today.

What the chain learns per call: the program id, the gas tier, the eight outputs, who paid.
What stays private: inputs, registers, memory, branches, the actual cycle count (tier padding).

## What the zkVM provides (read from `circuits/research/src`)

| item | API | notes |
|---|---|---|
| program | `isa::Program { base_pc: u32, words: Vec<u32> }` | RV32I subset; `Instr::decode` validates each word |
| execute | `emulator::execute(&program, &inputs, max_cycles)` | inputs are `u32` words read by `ecall SYS_READ_INPUT`; outputs are 8 words written by `SYS_WRITE_OUTPUT` |
| tiers | `machine::Tier(t)`, `TIERS = [10,12,14,16,18,20]` | tier t proves up to `2^t - 1` cycles; padding hides the real count |
| prove | `Machine::new(FriProfile::Production).prove(&program, &inputs, tier)` → `(Proof, Execution)` | fresh OS entropy per proof (zero knowledge) |
| proof | `Proof { tier, public_values: [pc_entry, tier, out0..out7], batch }`, `to_bytes()` (postcard) | verifier checks `pc_entry == program.base_pc` and `tier` |
| verify | `Machine::verify(&program, &proof)` | **needs the full program**, not a hash |
| code hash | `Machine::code_hash(&program, tier)` | Poseidon2 Merkle root of the preprocessed program + byte tables |

Measured on this laptop (Apple Silicon), production profile (blowup 8, 80 queries, 20 PoW bits),
`balance_check` at tier 10:

| step | time / size |
|---|---|
| prove (user side) | 22 s |
| verifier key for a program (preprocessed program + 2^16-row byte table, FRI blowup 8) | 2.2 s, **cacheable per program** |
| verify with cached key | **19 ms** (test profile: 4 ms) |
| proof bytes | 878 KB (tier 12: 873 KB; test profile: 209 KB) |
| proof (de)serialization | < 1 ms |

The demo's 2.2 s "verify" is almost entirely key computation; the STARK check itself is 19 ms.

Toolchain: Plonky3 0.7 needs Rust ≥ 1.98 (`maybe_uninit_slice`); the node workspace compiles on
1.98.1 unchanged, so the whole workspace moves to `rust-toolchain.toml = 1.98.1`.

## Integration shape

`rand_zkvm` is copied into the workspace as `crates/shrugg-zkvm` (its own `Cargo.toml`, tests and
demo binary kept; no code changes except the crate name and a `Program`/`Proof` byte codec). The
research tree stays the upstream; a `deploy/sync-zkvm.sh` copies it over and the commit message
records the upstream revision. Reason: droplets and the other laptop build from this repo alone.

`shrugg-core::confidential` becomes real:

```rust
pub trait ConfidentialExecutor: Send + Sync {
    /// Verify `proof` for `program`; on success return the eight public outputs and the tier.
    fn verify(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError>;
}
pub struct CallOutcome { pub tier: u8, pub outputs: [u32; 8] }
pub struct ZkExecutor { machine: Machine, keys: Mutex<LruCache<(ProgramId, Tier), CommonData>> }   // in shrugg-zkvm, implements the trait
pub struct StubExecutor;   // kept for tests and for chains with `confidential: false`
```

The verifier key (`CommonData`) is computed once per (program, tier) and cached. Nodes compute it
when a `Deploy` transaction is admitted to the mempool (so the proposer and every receiver already
have it when the block is applied) and lazily on first use otherwise; a deploy therefore costs a node
about 2 s of CPU once, and every call after that about 20 ms. The cache is bounded (LRU, 64 entries;
recompute on miss).

## Chain data model

### Programs (on-chain code)

```rust
pub type ProgramId = Hash;                      // blake3("shrugg-program" || base_pc || words)
pub struct ProgramRecord {
    pub id: ProgramId,
    pub base_pc: u32,
    pub words: Vec<u32>,                        // ≤ MAX_PROGRAM_WORDS (4096 → 16 KiB)
    pub code_hash: Vec<u8>,                     // = program id bytes in v0 (see implementation note)
    pub deployer: Address,
    pub deployed_at: u64,                       // block height
}
```

Programs are immutable and content-addressed; deploying the same code twice is a no-op that still
pays gas. They live in the ledger (`programs: BTreeMap<ProgramId, ProgramRecord>`) and in a
RocksDB column family `programs`. The state root becomes
`blake3(accounts_root || programs_root)` where `programs_root` is the Merkle root over program ids
(the bytes are content-addressed so ids commit to the code).

### Transactions

`TxKind` gains two variants and `Confidential` is removed (it was the stub):

```rust
Deploy { base_pc: u32, words: Vec<u32> }
Call {
    program: ProgramId,
    proof: Vec<u8>,                             // postcard(rand_zkvm::Proof), ≤ MAX_PROOF_BYTES (1 MiB)
    recipients: Vec<Address>,                   // public candidate recipients the program may pick from (≤ 8)
}
```

**Program-driven effects.** The eight public output words are the program's instruction to the
chain (`shrugg_core::effect`):

| word | meaning |
|---|---|
| `out0` | effect kind: `0` none, `1` transfer |
| `out1` | recipient index into `recipients` (must be `< recipients.len()` when kind is `1`) |
| `out2`, `out3` | amount in units as a little-endian `u64` (`out2` low, `out3` high) |
| `out4..out7` | free data, recorded in the receipt |

With kind `1` the chain moves `amount` from the caller to `recipients[out1]` inside the same
transaction. The program decides *whether*, *to whom* (from the public list) and *how much*, based
on private inputs; the chain learns only the result. A program that emits kind `0` just pays gas and
records its outputs. Guests get an assembler helper `emit_transfer(index_reg, amount_lo_reg, amount_hi_reg)`.

Validity (ledger):
- `Deploy`: every word decodes as an instruction, `words.len() ≤ MAX_PROGRAM_WORDS`,
  `base_pc % 4 == 0`, `fee ≥ gas(Deploy)`.
- `Call`: program exists; `proof.len() ≤ MAX_PROOF_BYTES`; `recipients.len() ≤ 8`; executor
  verifies the proof against the stored program; `fee ≥ gas(Call, tier)`; the decoded effect is
  well formed (known kind, index in range) and, for a transfer, the caller's balance covers
  `amount + fee`; nonce and signature as for transfers. Validity is a pure function of the
  transaction and the pre-state, as for every other kind.
- A block containing an invalid call is invalid (as for every other tx kind). Proposers verify
  before including, so an honest proposer never wastes a slot.

Receipts: `CallReceipt { tx: Hash, program: ProgramId, tier: u8, outputs: [u32; 8], effect: Option<(Address, u128)>, height, index }`
stored in a `receipts` column family (not part of the state root; derivable from blocks).

### Gas (v0 schedule, in SHRUGG smallest units; 1 SHRUGG = 1e9)

| operation | minimum fee | rationale |
|---|---|---|
| Transfer / Mint | 0 (unchanged; fee is a tip) | |
| Deploy | `DEPLOY_PER_WORD = 100_000` per word → 1 KiB program = 0.0256 SHRUGG | pays for the 2 s key computation every node does once, and permanent code storage |
| Call | `CALL_BASE = 1_000_000` (0.001 SHRUGG) + `CALL_PER_TIER_STEP = 100_000` × (tier − 10) / 2 | a proof is ~0.9 MB of bandwidth and block storage on every node; bytes barely grow with tier, so the tier surcharge is small |

The minimum is the gas; anything above is a tip. All of it goes to the block proposer, as today.
All numbers are constants in `shrugg_core::gas`, easy to retune.

Block limits, driven by proof size: `MAX_BLOCK_BYTES = 4 MiB` of transactions (the proposer stops
adding candidates past it), which is 4 calls per block, about 4 confidential calls per second at the
current 1 s block time; verification of a full block is under 100 ms with cached keys. Gossipsub's
message cap stays at 16 MiB. Proofs stay in blocks (needed for `verify --mode full` and for syncing
peers to re-check history); pruning proofs after finality is a follow-on.

### Mempool and verification cost

Proofs are verified once at mempool admission; the tx hash is remembered in a bounded set of
verified hashes so block application and sync do not verify again on the same node. Blocks received
from peers are verified fully (their calls were not seen in this node's mempool unless gossiped).
`shrugg-node verify --mode full` re-verifies every proof in history; `quick` trusts the QCs.

## RPC and wallet

| method | params | result |
|---|---|---|
| `shrugg_getProgram` | `[program_id]` | record without words, plus `words_len`, `code_hash` |
| `shrugg_getProgramCode` | `[program_id]` | `{ base_pc, words: [u32] }` |
| `shrugg_getReceipt` | `[tx_hash]` | `CallReceipt` or null |
| `shrugg_estimateFee` | `[kind, size_or_tier]` | minimum fee in units |
| `shrugg_sendTransaction` | unchanged; carries Deploy/Call like any other tx | |

Wallet (`shrugg`):
```
shrugg program build --guest balance_check --arg 1000 --out prog.bin   # built-in guests, until a RISC-V toolchain flow exists
shrugg program deploy prog.bin                                         # prints the program id, pays deploy gas
shrugg program show <id>
shrugg program deploy prog.bin | prog.json                            # .bin = raw little-endian u32 words; .json = {base_pc, words}
shrugg call <id> --input 400 --input 250 ... [--tier 12] [--to <addr>]...  # proves locally, submits, waits, prints outputs + receipt
                                                                         # --to builds the public recipient list the program may pick from
shrugg receipt <tx>
```
`call` runs the prover on the user's machine; only the proof leaves it. The wallet links the zkVM
crate for proving; the node links it for verifying.

## Storage and sync

New column families `programs` (id → record) and `receipts` (tx hash → receipt), written in the
same commit batch. `verify_chain` replays programs too (they are part of the ledger). Genesis gains
`"confidential": true` (default true on new chains; part of the genesis hash) so a chain can be run
without the executor for tests.

## Testing

- shrugg-zkvm: upstream tests unchanged (e2e, zk, cheating).
- shrugg-core: gas schedule; effect decoding (kinds, index range, u64 amount); Deploy validity (bad
  opcode, too large); Call validity with a real proof (test FRI profile for speed): wrong program,
  tampered outputs, wrong tier, too-small fee, transfer effect applied vs kind 0, index out of range,
  insufficient balance for the emitted amount; state root covers programs.
- shrugg-node: storage round trips for programs/receipts; mempool admission of a call; a cluster
  test that deploys a program, proves a call on the client side, submits it to one node, and checks
  every node stored the same receipt and applied the gated transfer identically; restart with a
  program on chain re-verifies in `full` mode.
- Testnet: deploy a `private_payment` guest (reads private balances, pays recipient 0 an amount only
  if their sum clears a threshold), call it from the laptop, see the payment land on all nodes.

## Out of scope for this step

Cross-program calls, persistent per-program storage (state machines), a RISC-V compiler flow
(programs come from the built-in assembler for now), a shielded balance model (the whitepaper's
notes/nullifiers), fee markets. Each is a follow-on with this step as its base.

## Implementation notes (2026-09-10)

- Deploy validation must be cheap because it runs inside block application on every node. The
  zkVM's Poseidon2 code commitment costs 2 s, so `code_hash` on chain is the content id, and the
  verifier key (which embeds the zk commitment) is computed by a background task when a deploy
  commits (`ConfidentialExecutor::warm`) and at startup for stored programs. `shrugg_zkvm::executor::zk_code_hash`
  computes the zk commitment on demand for explorers.
- Receipts travel inside `CommittedBlock` (consensus attaches them when a block is applied); a
  syncing node recomputes them and rejects a batch whose receipts differ.

## Decisions (user, 2026-09-10)

1. Call effect: **program-driven transfers** (outputs choose recipient index and amount, see the
   effect table), not a caller-supplied gated transfer.
2. Gas schedule v0 as listed.
3. zkVM vendored into `crates/shrugg-zkvm`; workspace toolchain 1.98.1.
4. Programs: built-in guests plus raw `.bin`/`.json` word files.

## Measurements

From `cargo run --release` in `circuits/research` on Apple Silicon (M-series), Rust 1.98.1:

```
production: FRI 80 queries / 20 PoW bits, prove 21986 ms, proof 877154 B, verify 2215.7 ms (2219 ms of it = verifier key)
test:       FRI 16 queries /  4 PoW bits, prove 22908 ms, proof 211422 B
fib(20)       130 cycles  tier 10  879715 B
memcpy(8)     136 cycles  tier 10  880930 B
bubble_sort   206 cycles  tier 10  882918 B
balance_check  26 cycles  tier 10  884482 B
```

Cached-key verification: production 19 ms, test 4 ms (measured with a throwaway example that
precomputed `verifier_key` and called `verify_batch` directly).
