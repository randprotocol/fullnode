# Block aggregation — the chain-side spec

Status: **written for user review 2026-09-15; not approved.** This formalizes the approved design
— `docs/aggregation.md` §1–§4 with the user's rulings of 2026-09-13
(`docs/superpowers/specs/2026-09-13-aggregation-design.md` §0) — against what the recursion
milestones actually delivered (M5.1–M5.3 in `circuits/`: the rVM machine, the N-generic
aggregate program, and the chain-facing API), and against the 2026-09-15 sequencing ruling
(production-profile proofs execute on a ≥ 64 GB machine after chain-side aggregation lands).
It redesigns nothing. Every place it must *change* the 2026-09-13 design is user-facing and
listed in §0.3.

Related: `docs/aggregation.md` (the approved starting point), `docs/block-space.md` (the numbers
and the rejected remedies), `docs/staking.md` (the register pattern), `docs/supply.md` (the
audit §5 extends), `docs/fees.md`, `docs/shielded.md`, `docs/rpc.md` (the conventions §8
follows), `circuits/docs/superpowers/specs/2026-09-13-zkvm-m5-recursion-vm-design.md` (M5),
`circuits/recursion/docs/02-aggregate.md` (the authoritative API, admission stub and vectors),
`circuits/recursion/docs/01-rvm-machine.md` (the machine facts),
`circuits/docs/superpowers/plans/2026-09-15-zkvm-m5-4.md` Appendix A (the runbook §10 sequences
against).

## 0.1 What M5 delivered that this spec binds

From `circuits/recursion/docs/02-aggregate.md`, verbatim where it matters:

- **The API.** `InnerProof = rand_zkvm::machine::Proof` (the 34 public values ride inside it);
  `InnerVerifierKey { shape, key }`; `aggregate(m, vk, proofs, tier) -> Result<AggregateProof,
  AggregateError>`; `verify_aggregate(m, program, a) -> Result<Vec<[u32; 8]>,
  VerifyAggregateError>` (each covered bundle's `OUT0..7`, in proof order);
  `aggregate_program(vk) -> Program` and `aggregate_program_digest(shape, key) -> [F; 4]` — the
  registered artifact and its name. `AggregateProof { proof, public }`: the rVM proof's four
  batch public values are the interface digest; `public` is the `[vk ‖ N ‖ 34·N]` list as
  auxiliary data. On chain the list is **recomputed, not carried** — see §4.
- **The interface digest.** `inner_vk_digest(shape, key)` (a `PaddingFreeSponge<Perm, 8, 4, 4>`
  over `[RVM_VK_DOMAIN = 16 ‖ shape words ‖ cap(16)]`), then the list `[inner_vk_digest(4) ‖
  N ‖ per bundle its 34 pv in cover order]`, then `public_digest` over it (state
  `[0,0,0,0, RVM_PUB_DOMAIN = 17, len, 0, 0]`, one permutation per four words overwriting rate
  lanes 0..4, a partial trailing block overwriting only its own lanes, digest = lanes 0..4).
- **The measured N-economics and machine classes** (`circuits/recursion/tests/pins.json` and
  `02-aggregate.md`'s tables): test profile N=1/2/3 = 441 782 / 883 240 / 1 324 694 rows at
  tiers 19/20/21; production N=1 measured 1 968 758 rows at tier 21 (48.6 GB oracle, ≥ 64 GB
  host), N=2 tier 22 (~95.3 GB, ≥ 128 GB), N=3 tier 23 (~127 GB, ≥ 160 GB; the rung does not
  exist until M5.4's GPU backend adds it). The N=1 test-profile aggregate is proven (328 121
  bytes, ~27–30 min wall, 30 GB peak); N≥2 test-profile and all production runs are deferred to
  the ≥ 64 GB batch machine per the 2026-09-15 ruling.
- **The startup key-build story** (finding (c) of the M5.3 handoff): the rVM verifier key is a
  startup/registration cost, not per-block — the program builds in seconds, the preprocessed
  commitment (the `InnerKey`'s cap) is built once per `(tier, program digest, reduce)` and
  cached in a 64-entry FIFO (18.31 s measured at 2^19 test profile; ~30–70 s estimated at 2^21
  production). A warm aggregate verify is ~1–2 s.
- **The four findings the chain must absorb.** (a) sealed history must carry each covered
  bundle's **declared shape** — `tier` plus the six declared log-heights (`program`, `input`,
  `keccak`, `sha256`, `public`, `mem`), which live in the proof header, not the 34 public
  values; (b) admission must check **every covered bundle's** declared shape equals the
  aggregate's registered shape; (c) the key build is startup, not per-block (above); (d) no
  extra `H_IN` binding — `H_IN` is already bound through `pv::IN0..7` in the interface list.

## 0.2 The open questions of `docs/aggregation.md` §5, settled

| question | settlement |
|---|---|
| subsidy amount, halving, cap | 2026-09-13 ruling: **100 SHRUGG per sealed block**, halving every **210 000 sealed blocks**, zero from the 64th halving (§5) |
| proving share | 2026-09-13 ruling: **floor to the proposer, excess to the aggregator** (§5) |
| sealing window `k`; double coverage | **256 finalised blocks**, then never; the first finalised aggregate covering a bundle wins, a later one naming it is invalid (§3, §6) |
| submission spam | 2026-09-13 ruling: **registered aggregators with a refundable bond**, every submission signed; slashing for equivocation only (§2) |
| the verifier guest | **delivered and measured** (M5.1–M5.3): the rVM, the N-generic aggregate program, the admission stub below. `MAX_COVERS` is set from the measured classes (§3) |

## 0.3 What changes from the 2026-09-13 design (user-facing by definition)

1. **Admission gains the declared-shape check (finding (b)).** The 2026-09-13 admission checked
   `HC0..7` of each covered bundle's public values against the registered guest `hc`. That pins
   the *guest* but not the *shape*: two proofs of the same guest at different declared heights
   have different `InnerShape`s, and the aggregate program is specialised to exactly one.
   Admission now reads each covered bundle's declared shape (seven small integers from its
   stored proof header) and refuses on the first that differs from the registered shape (§4
   step 6) — cheap, before any hashing.
2. **The pruned record grows by ~280 bytes per bundle (finding (a)).** The 2026-09-13 pruning
   kept "every public field" (~3 KB per transfer). Verifying an aggregate after pruning also
   needs each covered bundle's **34 public values** (272 bytes) and its **declared shape** (7
   bytes) — both live in the proof bytes today and vanish with them. The pruned record keeps
   both (§6): about 3.3 KB per sealed transfer, still ~400× smaller than the 1.3 MB raw form.
   (The M5.3 plan sized the shape record at 9 bytes; this spec fixes the encoding at 7 — one
   byte for `tier`, one for each of the six heights — which changes nothing about the
   requirement.)
3. **The verifier-key pin is settled.** The 2026-09-13 open item ("which digests the chain
   registers per constraint set") is answered: genesis pins, per admitted shape, the shape
   record plus `aggregate_program_digest(shape, key)` — the rVM program's `[F; 4]` digest. The
   `InnerKey`'s preprocessed cap is **derived at startup** (the ~30–70 s key build), never
   carried in genesis and never built per block (§2.3).
4. **`MAX_COVERS` is set from measured numbers**: **3** at activation (§3.3), with the admitted
   tiers a genesis parameter so a later chain cut can raise it when M5.4's GPU numbers land.
5. **The Aggregate action does not carry the `public` list.** `verify_aggregate`'s digest check
   is the node's own recompute-and-compare (§4 step 7); carrying the list would be ~0.9 KB of
   redundant wire per aggregate. `AggregateProof.public` stays the *prover's* auxiliary data,
   not the transaction's.
6. **Activation sequencing is stated explicitly** (§10): chain 9 activates after the production
   proofs run on the ≥ 64 GB batch machine, per the 2026-09-15 ruling — a dependency, not a
   date.

## 1. Roles and hardware

Unchanged from `docs/aggregation.md` §1, with M5's measured costs replacing its estimates:

| role | hardware | does | measured cost |
|---|---|---|---|
| **proposer** (HotStuff leader) | CPU | orders transactions, verifies one aggregate per sealing block | aggregate verify ~1–2 s warm (the startup key build is once, §2.3); a bundle verify is 838 ms cold / ~16 ms warm as today |
| **aggregator** (prover) | GPU (CPU allowed) | proves one rVM STARK over N bundle proofs of the registered shape; submits it for a sealing window | production N=1 tier 21 on ≥ 64 GB; N=2/3 on the GPU node (M5.4; ≥ 128/160 GB host, 80 GB device class) |

Validators stay CPU-cheap; the prover set is permissionless (§2). A chain with no aggregator
online runs exactly as today (`docs/aggregation.md` §4 fallback): raw bundle proofs, three per
block, no subsidy.

## 2. The aggregator register

### 2.1 State

One row per registered aggregator, keyed by base58 address, modelled on S2's validator register
(`docs/staking.md` §1, `crates/shrugg-core/src/ledger/staking.rs`):

```rust
AggregatorEntry {
    public_key: PublicKey,            // Dilithium2: signs this aggregator's actions
    bond:       u64,                  // burned in at registration, paid out at withdrawal
    payout:     ShieldedAddress,      // shrugg1… — where subsidy, proving shares and the bond go
    nonce:      u64,                  // replay protection for its signed actions
    unbonding:  Option<u64>,          // the release height, set by UnbondAggregator
}
```

The register is hashed into the state root as a component present only when
`genesis.aggregation` is `Some`, exactly as the bridge's component is gated: the leaf is
`blake3("shrugg-aggregator-leaf-1", addr || bond || nonce || release || payout pk || payout
kem_ek)`, and the root joins the state root as `… || aggregators_root` under the new domain
`shrugg-state-3`. A chain without the section keeps the current root byte for byte.

### 2.2 Joining, leaving, slashing

- **`Action::RegisterAggregator { registration: AggregatorRegistration { public_key, payout,
  signature } }`** rides a bundle whose `burn == AGGREGATOR_BOND` (genesis parameter, default
  `100 * UNITS_PER_SHRUGG`), exactly as a validator's `Bond` burns stake. The signature is over
  `blake3("shrugg-aggregator-register", chain_id || payout)`. Refused if the address is
  registered. The entry is created with `nonce = 0`.
- **`Action::UnbondAggregator { aggregator, nonce, signature }`**: bundle-less, validator-style
  signed over the register nonce. Sets `unbonding = Some(head_height + AGGREGATION_WINDOW)`
  (§3.3; 256 at activation). An aggregator with `unbonding` set may not submit aggregates.
- **`Action::WithdrawAggregator { aggregator, nonce, time, r, envelope, signature }`**:
  bundle-less; after the release height, pays `bond − BUNDLE_BASE` as a deposit note the ledger
  derives from `time` and `r` (`note_commitment(payout.pk, [0;8], bond − BUNDLE_BASE, 0, time,
  r)`, the note sealed by `envelope`; `time` window-checked as a `Withdraw`'s), `BUNDLE_BASE`
  to the proposer, and deletes the entry — S2's `Withdraw` verbatim.
- **`Action::SlashAggregator { a, b }`**: bundle-less, no fee, anyone may submit. `a` and `b`
  are two signed aggregator headers with the same address, the same `nonce`, and different
  content — the only equivocation provable on chain. Burns the bond (supply term `slashed`,
  §5.3) and deletes the entry. Everything else invalid is simply refused.

One monotonic `nonce` per entry is shared by all three signed actions and by every `Aggregate`
submission; each accepted action consumes `nonce + 1`.

### 2.3 The registered artifacts and the startup key-build obligation

`genesis.aggregation: Option<AggregationConfig>` carries:

```rust
AggregationConfig {
    bond: u64,                    // AGGREGATOR_BOND, default 100 SHRUGG
    max_covers: u32,              // MAX_COVERS, 3 at activation (§3.3)
    subsidy_base: u64,            // 100 * UNITS_PER_SHRUGG (§5.1)
    halving_blocks: u64,          // 210_000 (§5.1)
    window: u64,                  // AGGREGATION_WINDOW, 256 (§3.3)
    admitted_shapes: Vec<AdmittedShape>,
}

AdmittedShape {
    profile: FriProfile,          // Production at activation
    tier: u8,                     // the registered bundle guest's production tier
    program_log_height: u8, input_log_height: u8,
    keccak_log_height: u8, sha256_log_height: u8,
    public_log_height: u8, mem_log_height: u8,
    hc: Hash,                     // the bundle guest's digest (the pv::HC0..7 admission pins)
    aggregate_program_digest: [u64; 4],   // aggregate_program_digest(shape, key), M5.3-measured
}
```

At activation `admitted_shapes` has exactly one entry — the constraint-set-6 bundle guest at
its production shape; the exact heights and the two digests are filled in by the activation
task from measurement (§10). The `InnerKey`'s preprocessed cap is **not** in genesis: every
node derives it at startup from `(profile, the six heights)` via the machine's `verifier_key`
— the ~30–70 s startup key build (finding (c)), cached in the 64-entry FIFO thereafter. A node
that has not completed the build does not admit aggregates; a node need not hold the *prover*'s
key at all, only the verifier's.

## 3. The `Aggregate` action

### 3.1 Wire format

```
Action::Aggregate {
    covers:     Vec<Hash>,       // bundle transaction hashes, in the order the proof lists them
    proof:      Vec<u8>,         // postcard(recursion::machine::Proof); the four batch public
                                 // values (the interface digest) ride inside it
    aggregator: Address,
    nonce:      u64,
    time:       u32,             // window-checked; the payout note's time
    r:          Word8,           // the payout note's blinding factor
    envelope:   Envelope,        // the payout note sealed to the entry's payout address
    signature:  Signature,       // over blake3("shrugg-aggregate",
                                 //   chain_id || nonce || time || r || covers || proof hash)
}
```

Bundle-less. Size cap `MAX_AGGREGATE_BYTES = MAX_PROOF_BYTES + MAX_COVERS · 32 + (4 + 1 +
34 · MAX_COVERS) · 8 + MAX_ENVELOPE_BYTES + 3 000` — the rVM proof (328 121 bytes measured at
the test profile; ~0.5–0.6 MB estimated at production, far under the 2 MiB cap
`circuits/recursion/docs/01-rvm-machine.md` records), the covers, the recomputed interface
list's length bound, the envelope, and fixed overhead. The action carries **no** declared-shape
records and **no** public list: the node holds the covered bundles and recomputes both (§4).

### 3.2 What an aggregate may cover

A bundle transaction hash names a **coverable** bundle at head height `h` when all of:

1. the bundle's block is **finalised** (the same finality rule `apply_synced` uses today);
2. its block height is **greater than `h − AGGREGATION_WINDOW`** (256 at activation) — and it
   is a chain-9 block: nothing from chain 8's history is ever coverable (§9);
3. it is not already covered (`sealed_by` absent, §6.1);
4. its declared shape equals a registered shape (checked per bundle at admission, §4 step 6).

There is **no contiguity requirement**: `covers` is any subset of coverable bundles. The
subsidy design pays per sealed block, and the selection rule (§3.4) pays for coverage, so an
aggregator is rewarded for filling its window, not for ordering it.

A bundle whose window passes uncovered **stays raw forever**: valid, kept, and never payable
(`docs/aggregation.md` §4). The excess above the floor it attached goes to the proposer that
included it (§5.2), not to any aggregator.

### 3.3 The window, the cap, the admitted tiers

- `AGGREGATION_WINDOW = 256` finalised blocks (the 2026-09-13 ruling's `k`), the same constant
  as the anchor/time window already in the ledger.
- `MAX_COVERS = 3` at activation. Basis: the measured per-N rows (test profile 441 782 /
  883 240 / 1 324 694; production N=1 measured 1 968 758) and the machine classes of §0.1 —
  production N=1 is provable on the ≥ 64 GB batch machine, N=2/N=3 arrive with M5.4's GPU
  numbers (≥ 128/160 GB host, the tier-23 rung M5.4 adds). The register admits the rVM tiers
  `{21, 22, 23}` for the one registered inner shape; a proof at any other tier is invalid.
- Raising `MAX_COVERS` later is a chain cut with a new `AggregationConfig`, not a spec change.

### 3.4 Selection

A proposer includes **at most one** `Aggregate` per block. Among the valid submissions it
holds, it picks the one with the largest `covers.len()`; ties go to the lowest proof hash.
Losing submissions stay pooled until any bundle they cover is sealed by another aggregate
(the pool's `still_applies` drops them) or their window passes.

## 4. Admission

The exact algorithm, in order, cheap before expensive (`crates/shrugg-core/src/ledger/mod.rs`'s
`validate_inner` discipline, extended), with the M5.3 admission stub as steps 6–8. A rejection
at any step invalidates the transaction; the error names the step.

1. **Size caps; `chain_id`.**
2. **The aggregator**: registered, not unbonding; `nonce` equals the entry's; the signature
   verifies over the action's signing hash.
3. **`time`** within the ledger's ordinary window.
4. **The cover set**: `1 ≤ covers.len() ≤ MAX_COVERS`; no duplicates; every hash names a bundle
   transaction that is coverable at the head (§3.2 — finalised, inside the window, chain-9,
   unsealed).
5. **The payout note's commitment is new** — derived from `time`, `r`, the entry's payout and
   the amount the block would pay (§5.4), and claimed in the mempool the way a `BridgeAttest`'s
   derived commitment is claimed (`crates/shrugg-node/src/mempool.rs`'s
   `derived_commitment` pattern); the `(aggregator, nonce)` pair is claimed the way an
   `Unbond`'s register nonce is. The `covers` are deliberately **not** claimed: overlapping
   submissions may pool (§3.4).
6. **Per covered bundle, the shape check (finding (b))**: read its declared shape — `tier`,
   `program_log_height`, `input_log_height`, `keccak_log_height`, `sha256_log_height`,
   `public_log_height`, `mem_log_height` — from its stored proof header; refuse the whole
   transaction on the first bundle whose shape does not equal a registered shape, naming the
   bundle and the mismatched value. (While bundles are raw, the header is read from the proof
   bytes; on a pruned store, from the kept record — §6.2.) Pure integer compares; no hashing.
7. **The digest compare**: recompute the interface list from the registered shape and the
   covered bundles — `inner_vk_digest(shape, key)` (a startup constant per registered shape,
   §2.3), `covers.len()`, then each bundle's **34 public values** in `covers` order
   (`PC_ENTRY, TIER, OUT0..7, HC0..7, IN0..7, PUB0..7`; `HC0..7` must equal the registered
   guest's `hc`, which stops an aggregate covering a proof of some other guest or set) — and
   `public_digest` over it (`RVM_PUB_DOMAIN = 17`, the capacity-seeded padding-free sponge).
   The four words must equal the aggregate proof's batch public values, which are decoded from
   `proof` without any verification. Mismatch: the aggregate binds a different set than the
   chain recomputes — invalid.
8. **The proof**: `Machine::verify` on the rVM proof against the registered aggregate program
   — the one expensive step, last, ~1–2 s warm, run off the consensus loop on the RPC
   hardening task's verification workers (`crates/shrugg-node/src/admission.rs`; an aggregate
   occupies a slot far longer than a bundle's ~20 ms, which the 64-deep queue and the
   per-peer token bucket already bound), and reported to gossipsub exactly once, as today.
9. **Payment** (§5): the subsidy for the block's `sealed_blocks` index plus the proving shares
   of the covered bundles, paid as one derived deposit note (§5.4).

**The conformance suite.** The pinned vectors of `circuits/recursion/docs/02-aggregate.md`
(reproduced by `cargo test -p recursion --test aggregate the_admission_stub_vectors`) are the
admission stub's acceptance test: the fullnode's step 6–7 must reproduce, byte-for-byte, the
pinned `inner_vk_digest` (`33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8`
for the test-profile fixture shape), the 107-word interface list, and its digest
(`9f11f1aeb33546be79efe66a4829dc39c28f49f2ebd0bb055ac8a1a3fe088dcd`) for the 3-proof
test-profile fixture set. The stub is not trusted with admission until all three match.

## 5. Subsidy and the fee split

### 5.1 The subsidy

The block that includes an `Aggregate` mints `subsidy(n)` to the aggregator, where `n` is the
ledger's `sealed_blocks` counter — incremented per included aggregate, so an idle chain does
not consume the schedule:

```
subsidy(n) = subsidy_base >> (n / halving_blocks)        // 100 SHRUGG, halving every 210 000
           = 0                              once n / halving_blocks >= 64
```

The 64th halving ends issuance; the geometric total is `210 000 × 100 × (2 − ε)` ≈ **42 M
SHRUGG**, the schedule's asymptote, not a consensus cap anyone must enforce — the shift itself
is the whole rule, and it is plain `u64` arithmetic in `crates/shrugg-core/src/gas.rs`'s units
(`UNITS_PER_SHRUGG = 10⁹`, so `subsidy_base = 100 × 10⁹`).

Per `docs/aggregation.md` §3.2, the subsidy rewards *coverage* — a fixed amount per sealed
block, never per bundle — and it does not buy security: consensus weight stays with bonded
stake.

### 5.2 The proving share

Per the 2026-09-13 ruling: **the proposer keeps exactly the floor, the aggregator takes the
excess.**

- When a bundle is included in its block, the proposer's `rewards` are credited
  `BUNDLE_BASE`; the excess `fee − BUNDLE_BASE` goes to a ledger bucket
  `unsealed_fees: BTreeMap<Hash, (u64, Address, u64)>` — excess, the including proposer, the
  coverable-until height — derived state, rebuilt on replay, not in the state root (the map
  repeats information the state already holds).
- When an `Aggregate` covers the bundle, its excess moves to the aggregator's payment (§5.4).
- When the bundle's window passes uncovered, the excess is credited to the recorded proposer's
  `rewards`, at block commit. The sweep is bounded by construction (the bucket holds at most
  `AGGREGATION_WINDOW × 3` entries).
- Nothing is minted and nothing is lost anywhere in this flow; it is register arithmetic.

### 5.3 Supply accounting

`docs/supply.md`'s audit (`crates/shrugg-core/src/ledger/supply.rs`) gains four counters:

| counter | what it sums | when it moves |
|---|---|---|
| `subsidised` | every `subsidy(n)` minted | an `Aggregate` commits |
| `sealed_blocks` | the schedule index `n` itself | an `Aggregate` commits |
| `aggregator_bonds` | bonds burned in minus bonds paid out (bonds slashed) | register / withdraw / slash |
| `slashed` | bonds burned by `SlashAggregator` | a slash commits |

and the identity becomes

```
pool_value     = genesis_deposited + faucet_minted + withdraw_deposited + subsidised
               − fees_paid − burned
register_total = Σ validators (stake + pending + rewards) + Σ aggregators (bond + unbonding-payments-due)
issued         = genesis_deposited + genesis_staked + faucet_minted + subsidised

invariant:     total_supply == issued − slashed
```

A slash destroys issuance (the bond was burned into `slashed`, not paid out), so `slashed`
appears on the right-hand side; every other movement is a transfer between the two halves.
`shrugg_getSupply` reports `subsidised`, `sealed_blocks`, `aggregator_bonds` and `slashed`
separately from `faucet_minted`, so an auditor checks the schedule against `sealed_blocks`
directly (§8).

### 5.4 How the payment lands

Subsidy plus the covered bundles' proving shares are paid as **one deposit note** to the
aggregator's payout address, derived exactly as a validator's `Withdraw` note:
`note_commitment(payout.pk, [0;8], subsidy(n) + Σ excesses, 0, time, r)`, sealed by the
action's `envelope`; the amount is public in that block only, and the note's later spend is
unlinkable as any other. The proposer's `BUNDLE_BASE` per covered bundle is already paid
through the bundle's own inclusion, unchanged.

## 6. Sealing and pruning

### 6.1 What a sealing block records

The `Aggregate` is an ordinary transaction in a later block — nothing else. Node state derived
from committed blocks (never consensus state):

- per bundle, `sealed_by: Option<Hash>` — the hash of the `Aggregate` transaction that covers
  it; and
- per block, `sealed: bool` — every bundle in it has a `sealed_by`.

### 6.2 Pruning

Policy (never a consensus rule): after a bundle has been sealed for `AGGREGATION_WINDOW`
blocks, a node **may** drop its raw proof bytes; `--keep-raw-proofs` keeps them for archives.
The pruned record keeps, per bundle:

- the full transaction, with `bundle.proof` replaced by its hash and a `pruned` marker (the
  2026-09-13 form);
- the bundle's **34 public values** (272 bytes); and
- its **declared shape** — 7 bytes: `tier` and the six log-heights (finding (a); the M5.3
  plan's 9-byte sizing becomes this spec's exact 7).

About **3.3 KB per sealed transfer** against ~1.3 MB raw — history stays about 400× smaller,
and replay from public fields is byte-identical, as the 2026-09-13 design promised. What a
node must **never** prune: aggregate proofs (they *are* the proof of the sealed window), the
`covers` lists, and the raw proofs of unsealed bundles.

**State-root consequences: none, and here is the proof.** The state root hashes ledger state —
the note tree, the nullifier set, the registers, the program records — and the ledger's apply
path re-derives every one of those from a bundle's *public fields* (anchor, nullifiers,
commitments, fee, burn, asset, time, envelopes). Proof bytes were never in the state root: they
are witness data the ledger verifies and forgets, held in the node-local transaction store
(`crates/shrugg-node/src/storage.rs`'s `CF_TXS`), which no root reads. Pruning touches only
that store, so two nodes — one pruned, one archival — derive the same state root at every
height, and `verify_chain` on a pruned store reproduces the same ledger.

**The trust-model argument.** `docs/block-space.md` rejected proof pruning *without* a
recursive proof because a syncing node would have to trust finality signatures for old history
— the long-range-attack shape. Pruning behind an aggregate is not that shape: every bundle in
history remains covered by a STARK the node verified **itself** — the raw proof while raw, the
aggregate proof after sealing — and the aggregate's admission (§4) is run by the node against
its own store of covered bundles' public values and shapes, not by any quorum. Finality
signatures are never part of the argument; there is nothing new to trust, only less to store.

## 7. Sync in sealed form

The sync protocol gains a second block form: bundles with `proof = pruned(hash)` plus the
covering `Aggregate` transactions, which are ordinary transactions in later blocks and arrive
in order anyway.

- **What a joining node downloads and verifies**: blocks; for each sealing block, the aggregate
  (recomputed and verified per §4 — steps 6–8 against the node's store of covered public values
  and shapes); and each covered bundle's ledger effect from its public fields, exactly as an
  unpruned sync. One rVM verification per sealed window instead of one RV32 verification per
  bundle.
- **The acceptance rule** (`apply_synced`): a pruned bundle is accepted only if its block is
  finalised, a covering `Aggregate` has already been applied, and that aggregate's `covers`
  names the bundle's hash. Otherwise the node requests the raw form from another peer — the
  2026-09-13 rule, verbatim.
- **Failure modes**: a pruned bundle whose covering aggregate never arrives → raw-form
  fallback; an aggregate that fails any admission step → the sealing block is invalid and the
  sync batch fails exactly as an invalid raw block fails today; a peer serving a pruned bundle
  with no aggregate and no raw form → the batch is retried from another peer, no ban (serving
  pruned history is policy, not malice).
- `verify_chain` on a pruned store applies the same rule and fails a pruned bundle whose
  covering aggregate is missing.

## 8. RPC

In `docs/rpc.md`'s conventions (and its changelog's shape — this entry states plainly that the
wire format, block rules and consensus change: a hard fork, not an interop-compatible
hardening):

- **`shrugg_submitAggregate`** is `shrugg_sendTransaction` — no new path; `tx_json` renders the
  four new actions (`RegisterAggregator`, `UnbondAggregator`, `WithdrawAggregator`,
  `SlashAggregator`) and `Aggregate`.
- **`shrugg_getBlockByHeight` / `shrugg_getBlockByHash`** gain `sealed` and per-bundle
  `sealed_by`.
- **`shrugg_getAggregate(hash)`** returns the public fields: `covers`, `aggregator`,
  `subsidy`, `proving_share`, `n` (the schedule index).
- **`shrugg_getAggregators`** lists the register (address, bond, payout, nonce, unbonding).
- **`shrugg_getUnsealed(from, limit)`** pages the bundles an aggregator may still cover: hash,
  height, excess fee — the daemon's work list.
- **`shrugg_getSupply`** gains `subsidised`, `sealed_blocks`, `aggregator_bonds`, `slashed`
  (§5.3).
- **`shrugg_status`** gains `aggregation: { registered, unsealed, verify_queue }` beside the
  existing fields.
- The **node CLI** for the role: `shrugg-node aggregator register --bond --payout`, `unbond`,
  `withdraw` (the validator commands' twins), and `shrugg-node aggregate --watch` — a daemon
  that polls `shrugg_getUnsealed`, fetches the raw bundles, calls `recursion::aggregate` (CPU
  or, with M5.4, GPU), and submits. A separate process from the validator; needs only an RPC
  endpoint.

## 9. Genesis and migration

**This is chain-9 material — a hard fork.** `genesis.aggregation: Option<AggregationConfig>`
(§2.3) is `None` on chains 1–8 and `Some` on chain 9, the same gating the bridge used.

Settled explicitly: **chain 8 keeps its per-bundle proofs forever.** No aggregate may name a
chain-8 bundle (§3.2.2 — the cover set is chain-9 blocks only), so chain 8's history is
unaggregated, unprunable under §6.2, and verified bundle-by-bundle as today. Chain 9's history
starts unsealed and aggregates from its first finalised window. The chain-9 genesis carries the
one admitted shape record (§2.3) with its two digests filled from measurement (§10), and the
state root gains the `aggregators_root` component under `shrugg-state-3` from block 0.

## 10. Testing and activation sequencing

**Testing** (the M5.3 doc's discipline: conformance vectors, real proofs, measured numbers in
the docs):

- **Core**: register round trips (register/unbond/withdraw/slash); admission order with a stub
  `verify_aggregate`, each step's refusal named; the fee bucket's three exits (covered,
  expired, never-included); the subsidy schedule at the halving edges (`n = 0`, `209 999`,
  `210 000`, the 64th halving's zero); the supply invariant with subsidies, bonds, a withdraw
  and a slash.
- **The admission conformance suite**: the pinned hex vectors of §4, byte-for-byte.
- **Node**: `sealed_by`/`sealed`, pruning and the kept record, sync in pruned form with the
  raw-form fallback, `verify_chain` on a pruned store.
- **Cluster**: one real aggregate over three real test-profile bundle proofs (the M5.3 fixture
  shape, the same proof `circuits` produces), sealed, pruned on one node, that node resyncs a
  fresh peer in pruned form; heights and state roots agree.
- **Docs carry measured numbers**: the registered shape's digests, the startup key-build time,
  the warm aggregate verify, the cluster run's walls — `docs/aggregation.md` is amended, not
  rewritten, when the measurements land.

**Activation sequencing** (the 2026-09-15 ruling, stated as dependencies, not dates):

1. The production proofs run on the ≥ 64 GB batch machine: M5.2's tier-21 exit and the
   production N=1 aggregate (and N≥2 as the bigger classes arrive) — `circuits`' M5.4 plan
   Appendix A's runbook, runs 3–8.
2. From those runs, the activation task fills `admitted_shapes[0]`: the production heights,
   `hc`, and `aggregate_program_digest`, all measured.
3. The fullnode implementation (this spec's plan) lands: register, action, admission with the
   conformance suite green, subsidy, sealing, pruning, sync, RPC.
4. The cluster test on CPU; then the aggregator daemon on the GPU host as M5.4 delivers it.
5. Chain 9's genesis is cut with `aggregation: Some(..)`; aggregation activates.

## 11. Out of scope

The 2026-09-13 design's §5, unchanged: the forward path (bundles travel to aggregators before
inclusion); self-recursion trees on chain (one aggregate per block suffices); pricing the
proving share by anything other than the sender's excess; any change to the bundle guest or
the RV32 machine; the GPU backend itself (M5.4's, in `circuits/`).

## 12. Open items

- `admitted_shapes[0]`'s exact numbers (the production heights, `hc`,
  `aggregate_program_digest`) — measured by the activation task (§10.2).
- `MAX_COVERS > 3` and the tier-23 rung's admission, when M5.4's GPU numbers land — a later
  chain cut with a new `AggregationConfig`.
- The subsidy schedule's first review point: the first halving at 210 000 sealed blocks, or
  earlier if the fee volume arrives sooner.
