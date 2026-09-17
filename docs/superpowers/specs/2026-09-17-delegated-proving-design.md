# Delegated proof generation (v1) — design

Status: **approved by the user 2026-09-17; implementation on `feat/delegated-proof-generation`.**
If the experiment in §11 succeeds, the delegated path becomes the documented default for
light clients and the branch is tagged **v0.3**. This spec is v1: a *trusted* prover the wallet
is configured with. It builds none of the whitepaper's attribution layer (no register, no
beacon, no attestation, no bond) and changes nothing on the chain.

Related: the whitepaper's "Proving Topologies: Local and Delegated" and its delegation-boundary
remark (`../whitepaper/randprotocol.tex`, `rem:delegationboundary`); `docs/confidential.md`
(the prover, `H_IN` and the salt); `docs/shielded.md` (the key hierarchy, envelopes);
`docs/block-space.md` (why delegation alone does not move chain TPS); `docs/aggregation.md`
(the forward path delegation makes natural); `docs/zkvm.md` §5 (the FRI profiles).

## 0. The decisions this spec records

Asked and answered 2026-09-17:

| question | ruling |
|---|---|
| The bundle guest takes the spend key as a private input, so a delegated prover receives it | **Accepted for v1.** A trusted prover. The custody exposure is the first line of §9 and of the operator doc. Splitting the key (a proof-authorizing key inside the circuit, a spend authorization outside it) is the v2 item that must land before any *untrusted* prover. |
| How a wallet finds and authenticates the prover | **Static URL plus a pinned key.** Wallet config holds the prover's HTTPS URL and its `rand1…` address. No chain change, no registry. |
| Who submits the transaction | **The prover returns the proof; the wallet submits.** The prover is a pure proving service with no connection to any node. |
| Which transaction kinds delegate | **Everything the wallet proves**: the 2-in-2-out bundle (a transfer, a bond, both bundles of a bridge burn) and a program call, with or without its input envelope. |
| Service shape | **Async job API in a standalone `rand-prover` binary.** Submit, poll, fetch. Validators never link it. |

Rejected on the way: a synchronous request that blocks for the whole proof (a call proof is
minutes; phones and proxies drop the connection); a prover mode inside `rand-node` (a
witness-holding GPU service in the consensus process, in every node build).

## 1. What this is

A wallet that cannot prove in useful time — a phone, a browser, a laptop that does not want
to spend a hundred seconds per transfer — hands the *witness* of its proof to a prover it
trusts, and gets the *proof* back. Everything else stays where it is: the wallet still scans,
selects notes, fetches the anchor and Merkle paths, builds the input vector, checks the returned
proof against the digest it computed itself, seals the envelopes, and submits. The chain sees a
transaction indistinguishable from a locally proved one. Consensus, admission, the ledger, the
RPC and the wire format do not change.

What changes is the latency budget of one transfer (numbers from `docs/block-space.md`,
`docs/aggregation.md`, the whitepaper's performance targets):

| stage | local (today) | delegated |
|---|---|---|
| prove the bundle | ~95–100 s, laptop CPU, tier 14 | 3–10 s target on a GPU; the same ~100 s on a CPU prover |
| ship the witness and the proof | — | one ~5 KB request, one ~1.3 MB response |
| verify at admission (per validator) | ~16 ms warm | unchanged |
| HotStuff three-chain commit | ~3 s nominal | unchanged |

Chain throughput does not move: the 1.3 MB proof still goes in the block, and three of them
fill a 4 MiB block. Delegation buys latency and phone support, and it is what makes the
aggregation doc's forward path (sender → aggregator, one aggregate per block) natural, because
the prover already holds every bundle proof it made.

## 2. Components

```
┌──────────────┐  sealed job (ML-KEM-768 → prover)   ┌──────────────────┐
│  rand wallet │ ───────── POST /v1/jobs ──────────▶ │   rand-prover    │
│  (any device)│ ◀──────── GET  /v1/jobs/{id} ────── │  (GPU or CPU box)│
│              │ ◀──────── GET  /v1/jobs/{id}/result │                  │
│  builds the  │  sealed result (ML-KEM-768 → wallet)│  decapsulates,   │
│  witness,    │                                     │  proves, seals,  │
│  checks the  │                                     │  zeroizes        │
│  proof,      │                                     └──────────────────┘
│  submits ────┼──── rand_sendTransaction ──────────▶  rand-node (unchanged)
└──────────────┘
```

Three pieces of code, one of them new:

| piece | crate | what |
|---|---|---|
| **job codec and sealing** | `randprotocol-zkvm`, new module `delegate` (node-owned, like `address.rs` and `call_envelope.rs`; never touched by `deploy/sync-zkvm.sh`) | the `JobRequest` / `JobResult` types, their postcard form, and the seal/open functions both ends share |
| **the prover service** | new crate `crates/randprotocol-prover`, binary `rand-prover` | HTTP server, queue, one proving slot per backend, key file, auth, zeroization |
| **the wallet side** | `randprotocol-client` | a `Prover` value (local or remote) threaded where a `Backend` is today; three flags; the digest and salt handling that already exists, reused |

Plus one small change in the zkVM crate (§6) so a delegated call proof on a GPU backend can
return its `H_IN` salt.

## 3. Job types

Everything the wallet proves is one of two prover functions, so there are two job kinds.

```rust
pub enum JobKind {
    /// `executor::prove_bundle`: the fixed-width input vector of the pinned bundle guest.
    /// Covers a transfer, a bond, and each of a bridge burn's two bundles.
    Bundle { inputs: Vec<u32> },                       // exactly notes::bundle_input::COUNT words
    /// `executor::prove` / `executor::prove_call`: a deployed program on private inputs.
    Program {
        base_pc: u32,
        words: Vec<u32>,                               // the program, as `rand_getProgramCode` returns it
        inputs: Vec<u32>,                              // ≤ call_envelope::MAX_CALL_INPUT_WORDS
        tier: Option<u8>,                              // `None`: the smallest that fits, as today
        want_salt: bool,                               // true when the wallet will seal an input envelope
    },
}

pub struct JobRequest {
    pub version: u32,                                  // 1
    pub profile: String,                               // "production" | "test", `ZkExecutor::profile_from_str`
    pub kind: JobKind,
    pub deadline_secs: u32,                            // the prover must *start* before this, or refuse (§7)
    pub reply_ek: Vec<u8>,                             // a fresh ML-KEM-768 encapsulation key, this job only
}

pub enum JobResult {
    Bundle { proof: Vec<u8>, digest: Word8, tier: u8 },
    Program { proof: Vec<u8>, outputs: [u32; 8], tier: u8, salt: Option<[u32; 4]> },
    Failed { error: String },                          // the prover's error text, never its inputs
}
```

The prover is a pure function of the job: it never reads the chain, needs no anchor, no
witness paths, no note store, and has no retry loop. The wallet keeps all of that, including the
"tree moved" retry around fetching paths, which happens *before* a job is built.

`inputs` is the spend key and the notes for a bundle, or the program's private inputs for a
call. Both are held in `Zeroizing` on both ends.

## 4. Sealing

A job is sealed the way a note envelope is, with the same two primitives the envelope layer
already pins (`ml-kem 0.3.2`, `chacha20poly1305 0.11.0`), in a module that reuses nothing
from the vendored `viewing.rs` (its helpers are private, and that file stays byte-identical to
upstream).

- **The prover's identity is a `rand1…` address.** Its ML-KEM-768 encapsulation key is the
  address's `kem_ek`; its decapsulation key is derived from the prover's wallet key file
  exactly as a receiving wallet derives its own (`ViewingKey::kem_seed`). So `rand keygen`
  makes a prover key, `rand address` prints what a wallet pins, and no new key format exists.
- **Job:** `SealedJob { kem_ct, body }`. `kem_ct` is the encapsulation to the prover's
  `kem_ek`; `body` is ChaCha20-Poly1305 under the shared secret, random 12-byte nonce
  prepended, associated data `b"rand-prover-job-v1"`, plaintext `postcard(JobRequest)`.
- **Result:** `SealedResult { kem_ct, body }`, the same construction to the job's `reply_ek`,
  associated data `b"rand-prover-result-v1"`, plaintext `postcard(JobResult)`. The wallet draws
  a fresh ML-KEM keypair per job from OS entropy and forgets it after opening the result.
- TLS is the operator's (a reverse proxy in front of `rand-prover`). The sealing is what
  protects the witness; TLS protects the bearer token and hides which wallet talks to which
  prover from the path.

A tampered `body` fails authentication and is reported as a transport error; it can never
yield a job the prover proves or a result the wallet submits.

## 5. The service

`rand-prover run --key prover.key.json --listen 127.0.0.1:8600 [--token <bearer>] [--cuda]
[--slots 1] [--max-queue 8] [--allow-open]`.

| route | body | answer |
|---|---|---|
| `POST /v1/jobs` | `application/octet-stream`, `postcard(SealedJob)` | `202 {"id": "<32 hex>", "position": n}` or `429 {"error": "...", "retry_after_secs": n}` when the queue is full or the job cannot start before its deadline |
| `GET /v1/jobs/{id}` | — | `{"state": "queued" \| "proving" \| "done" \| "failed" \| "expired", "position"?: n, "elapsed_ms"?: n}` |
| `GET /v1/jobs/{id}/result` | — | `200 application/octet-stream postcard(SealedResult)` once done or failed; `404` before; results are kept for 10 minutes after completion, then dropped |
| `GET /v1/health` | — | `{"version", "backend": "cpu" \| "cuda", "slots", "queue_depth", "proving", "address": "rand1…"}` — the address so a wallet can check its pin |

- **One proving slot per backend** by default (`--slots`), a bounded FIFO queue
  (`--max-queue`). A CUDA build proves on the GPU; the default build proves on the CPU and says
  so in `/v1/health`, so a deployment without a GPU is visible rather than mysterious.
- **Auth.** `--token` sets a bearer the wallet must send. Without it the service refuses to
  bind to anything but loopback unless `--allow-open` is passed, because each job is seconds
  of GPU or a minute of CPU and an open endpoint is a free denial-of-service. Under the token,
  at most two jobs in flight per client IP.
- **Deadline.** On submit the prover estimates when the job would start (queue depth times
  the running average of that kind's proving time, seeded at 100 s for a bundle and 30 s for a
  program on the CPU, a tenth of that on CUDA). If the estimate exceeds `deadline_secs` the job
  is refused with `429` and the estimate, and the wallet re-plans. A queued job whose deadline
  passes before it starts is marked `expired` and never proved. This is what keeps a queued job
  from producing a proof the chain will reject: a bundle binds the head height as its `time`,
  and admission accepts a 256-block window.
- **Hygiene.** The decrypted `JobRequest` lives in `Zeroizing`; inputs are never logged, never
  written to disk, and dropped the moment the proof exists. Logs carry the job id, kind, tier,
  queue wait and proving time only. Results are kept sealed, so a leaked result store is
  ciphertext to the job's one-time key.
- **Key file.** A wallet key file (`KEY_FILE_VERSION` 2). `rand-prover address --key …` prints
  the address to pin. The prover's spend key is never used to spend; it exists because the
  address derivation and the decapsulation key both hang off a spend key today, and inventing a
  second key format for the same 1184-byte key would be the larger change.

## 6. The zkVM change

`executor::prove_call` returns the `H_IN` salt so the wallet can seal the call-input envelope,
and today it does so on the CPU backend only: `Machine::prove_with` draws the salt inside
`prove_on` for the reference and CUDA backends and drops it. A delegated call with an envelope
needs the salt back on a GPU prover, so:

- `Machine::prove_salted_with(backend, program, inputs, public, salt, tier)` is added;
  `prove_on` takes the salt as a parameter; `prove_with` draws a fresh salt and calls
  `prove_salted_with`. Nothing about which salt is used changes for any existing caller.
- `executor::prove_call` draws its salt and calls `prove_salted_with` on every backend. The
  "draws its H_IN salt inside the prover and cannot return it" refusal goes away, and with it
  the wallet's "a GPU proof has to go without an envelope" note.

The freshness rule (`Machine::prove`'s doc comment) is kept: the salt is drawn from OS entropy
once per proof by the one function that then uses it.

## 7. The wallet side

Three flags, global like `--rpc` and `--key`, env-backed the same way:

| flag | env | meaning |
|---|---|---|
| `--prover <url>` | `RAND_PROVER` | the service; unset means local proving, exactly as today |
| `--prover-address <rand1…>` | `RAND_PROVER_ADDRESS` | the key jobs are sealed to; required with `--prover`, and checked against `/v1/health` before the first job |
| `--prover-token <bearer>` | `RAND_PROVER_TOKEN` | sent as `Authorization: Bearer` |

`--cuda` and `--prover` together are an error: the wallet proves in one place.

Inside the wallet, `pub enum Prover { Local(Backend), Remote(RemoteProver) }` with two methods,
`prove_bundle(profile, inputs)` and `prove_program(profile, program, inputs, tier, want_salt)`,
both async, replaces the `backend: Backend` parameter of `submit`, `send`, `submit_burn`,
`prove_bundles` and `prove_one`, and of the `Call` command's two prover calls in `main.rs`.
`Local` calls the three `executor` functions it does today. `Remote` builds the job, seals it,
posts it, polls `GET /v1/jobs/{id}` (every second, backing off to five), fetches and opens the
result, and returns exactly what the local call would have.

What stays in the wallet, unchanged, is what makes a wrong prover harmless short of custody:

- the digest check in `prove_one` (`digest != expected` refuses to submit), so a proof for any
  other bundle is caught before the chain sees it;
- the call-input envelope is sealed by the wallet from the returned salt, with the wallet's own
  viewing key, so the prover never holds the envelope key;
- envelopes, the transaction key per envelope, submission and wait-for-commit are the same code.

**No silent fallback.** If the prover is unreachable, refuses (429), fails, or expires the job,
the wallet reports it and stops, naming the local path (`drop --prover to prove here, about a
minute and a half on a laptop`). A user who chose delegation for a phone would rather be told
than wait a hundred seconds for a proof that may never come.

The deadline the wallet sends is `--prover-deadline` (default 120 s). It is not derived from
the chain's block interval, which the wallet does not know; the operator doc says how to set it
from `epoch_blocks`-style facts about the chain.

## 8. Errors

| where | what | wallet reports |
|---|---|---|
| connect / TLS / 5xx | transport | the prover is unreachable, the local alternative |
| `401` | wrong or missing token | as such |
| `429` | queue full or cannot start before the deadline | the prover's estimate, suggest a larger `--prover-deadline` or later |
| `/v1/health` address ≠ `--prover-address` | wrong pin | refuses before sending any job |
| result fails to open | tampered or mis-sealed | as a transport error; never retried with the same job |
| `JobResult::Failed` | the prover's error text | verbatim, prefixed with "prover:" |
| digest mismatch | a proof for some other bundle | the existing "refusing to submit" error, now naming the prover |
| `expired` | started too late | re-plan is the user's: run the command again |

## 9. Security

**The prover holds the spend key.** A bundle's input vector is `bundle_inputs(&w.sk, …)`: the
guest derives `nk` from `sk` in-circuit, so the witness a wallet delegates contains the root
key of that wallet. A compromised or malicious prover can spend every note the wallet has ever
owned and every note it will ever receive at that address. This is not a privacy leak, it is
custody, and it is why v1 is a *trusted* prover: one the user runs, or one run by an operator
the user would hand a key file to. The operator doc opens with this sentence. The fix is the v2
circuit change: a proof-authorizing key that can build proofs but not spend, and a spend
authorization the wallet signs outside the circuit — Sapling's split. Until it lands, nothing
in this design may be pointed at an untrusted prover, and the wallet says so when `--prover` is
first used (a one-line warning per run).

What the prover *cannot* do, and why:

- **Forge or alter a transaction.** The proof binds the anchor, both nullifiers, both
  commitments, fee, burn, asset and time through the published digest; the wallet recomputes
  that digest from its own plaintext and refuses anything else. A call proof binds `hc` and
  `H_IN`.
- **Read or forge envelopes.** Sealed by the wallet with a fresh transaction key per envelope;
  the prover sees the note plaintext (it is in the witness) but holds no key that opens an
  envelope on chain, and cannot substitute one, because the wallet builds them after the proof.
- **Replay a job.** Each job carries a one-time `reply_ek`; each result is sealed to it and
  opened once. A replayed job proves the same bundle again, which the chain rejects as a
  double spend of the same nullifiers and which the wallet never submits.
- **Be spammed for free.** Bearer token, per-IP in-flight cap, bounded queue, deadline refusal.

Soundness is untouched: the STARK verifies or it does not, and the node re-verifies every proof
regardless of who made it (`docs/architecture.md` §9).

## 10. Privacy

Against everyone but the prover, unchanged: the chain and the network see what they see today.
Against the prover, none. It learns the two input notes (owner, value, blinding, position in
the tree), the two output notes (recipient address, value, change), fee and burn, and, unless
the operator's proxy hides it, the client's IP. It can link one wallet's transactions over time
by the recurring `pk`. The whitepaper's mitigations apply in order: local proving for anything
high-value (one flag away), a prover inside a TEE with remote attestation (an operator choice
this design neither requires nor prevents), and threshold or MPC proving as future work. What
the whitepaper's attribution layer would add in v2 is accountability for *which* prover did
the job, never confidentiality from it.

## 11. The experiment, and what v0.3 means

The user's rule: switch and tag v0.3 if delegation wins the comparison. The comparison is the
five columns of the 2026-09-17 side-by-side, measured rather than argued:

| column | measurement | passes when |
|---|---|---|
| **speed** | submit-to-commit wall clock of `rand send`, twenty runs each: local on the laptop; delegated to `rand-prover` on the CPU of a droplet; delegated to a GPU host if one is available | delegated GPU beats local by ≥ 5×; delegated CPU is within 10 % of local (the plumbing costs nothing) |
| **consensus finality** | `rand_getBlock` timestamps of the committing block versus submission, same runs | unchanged from local within noise |
| **aggregation** | not exercised in v1 (gated off on chain 12); recorded as "unchanged, forward path enabled by design" | — |
| **security** | the tamper test and the digest-mismatch test pass; the custody warning prints; the prover refuses an open bind without `--allow-open` | all pass |
| **privacy** | the prover's log after twenty jobs contains no input word, no note, no address; a packet capture of a job shows only ciphertext and the token | both hold |

A CPU prover cannot win the speed row; only a GPU host can. If no GPU host is available when
the experiment runs, the branch still merges (the plumbing is correct and phone support is
real), but the *switch* — making delegation the documented default for light clients — and the
v0.3 tag wait for the GPU measurement. The README's "what a client needs" row changes only then.

## 12. Testing

- **`delegate` unit tests:** seal/open round-trip for a job and a result; a flipped byte in
  `body` fails to open; a result sealed to the wrong `reply_ek` fails to open; the wire form of
  a `JobRequest` is stable (a pinned hex vector, so the prover and wallet cannot drift).
- **Prover crate tests:** an in-process server on the CPU backend and the test profile.
  Submit a `Program` job for the `fib` guest (tier 10, seconds), poll to `done`, open the
  result, verify the proof with `Machine::verify`. A second test with `--max-queue 0` and one
  job proving gets `429`. A third submits with `deadline_secs: 0` and reads `expired`. A fourth
  posts garbage and gets `400`, with the queue untouched. A fifth checks `/v1/health` reports
  the key file's address.
- **Wallet integration (`tests/wallet_flow.rs`):** one more bundle proof, taken through an
  in-process `rand-prover` instead of the local prover, under the same proving slot: `send`
  with `Prover::Remote`, the payment scans on the receiving side, the change is spendable.
  Then a tamper test: a mock prover that answers with a proof of a *different* bundle, and the
  wallet's digest check refuses to submit. And a `Call` through the remote prover with an
  envelope, opened back under the caller's viewing key — this is what §6 is for.
- **Unchanged suites** stay green: core, node, client, cluster, zkVM (`prove_with` callers
  see the same salts drawn the same way).

## 13. Docs

- `docs/delegated-proving.md`: the operator's and the wallet user's page — the custody
  sentence first, then running `rand-prover`, pinning its address, the three flags, the
  deadline, what is logged, the experiment's numbers once measured.
- `README.md`: a row in the component table, a line under the wallet section, the crate in
  the crate list.
- `AGENTS.md`: the entry for this branch.
- The whitepaper's reconciliation section is the whitepaper repo's to update, from this spec,
  after the experiment.

## 14. Out of scope, so nobody assumes it

No prover register on chain, no beacon assignment, no attestation, no prover bond or slashing,
no fee paid to the prover through the protocol (an operator's business), no prover-side
submission, no multi-prover fan-out, no TEE integration, no key split (v2). None of these are
needed for the experiment, and every one of them is a chain change or a separate design.
