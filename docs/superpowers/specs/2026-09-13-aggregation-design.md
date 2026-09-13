# Block-level proof aggregation — chain-side design

Status: **all four sections approved by the user in conversation on 2026-09-13; not built.** Plan
follows M5.3 (the interfaces it consumes). This is the fullnode half of the remedy chosen in
`docs/block-space.md` §6 and sketched in `docs/aggregation.md` §1–§4; it settles that note's §5
open questions with the user's rulings of 2026-09-13. The zkVM half — the recursion VM whose proof
this design consumes — is `circuits/docs/superpowers/specs/2026-09-13-zkvm-m5-recursion-vm-design.md`
(M5). Nothing here can be implemented until M5.3 delivers `aggregate`/`verify_aggregate`; the spec
is written now so the plan can follow M5 without a second design round.

Related: `docs/staking.md` (the register pattern every structure here copies), `docs/supply.md`
(the invariant §2 extends), `docs/fees.md`, `docs/shielded.md`, `docs/rpc.md`.

## 0. The user's rulings (2026-09-13)

| question (`aggregation.md` §5) | ruling |
|---|---|
| subsidy amount, halving, cap | Bitcoin-style: **100 SHRUGG per sealed block**, halving every **210 000 sealed blocks**, zero after 64 halvings (geometric cap ≈ 42 M SHRUGG) |
| proving share | **floor to the proposer, excess to the aggregator**: the proposer keeps exactly `BUNDLE_BASE` (0.001 SHRUGG) per bundle; everything a sender attaches above the floor is the proving share |
| sealing window `k` | **256 finalised blocks** (`ANCHOR_WINDOW`/`TIME_WINDOW`), then never: an older bundle stays raw, no subsidy, the proposer keeps the excess |
| double coverage | the first finalised aggregate covering a bundle wins; a later one covering it is invalid |
| submission spam | **registered aggregators with a refundable bond**, every submission signed; the bond is slashed only for equivocation |
| the verifier | a recursion VM (M5); one level of recursion first |

## 1. The aggregator register and the `Aggregate` action (approved)

Two pieces of ledger state and three actions, all modelled on S2's staking register.

**Register.** `AggregatorEntry { public_key: PublicKey, bond: u64, payout: ShieldedAddress, nonce: u64, unbonding: Option<u64 /*release height*/> }`
in `ledger/aggregation.rs`, keyed by address, hashed into the state root as a component present
only on chains whose genesis enables aggregation (`genesis.aggregation: Option<AggregationConfig>`,
the way `bridge` gates its component): the leaf is
`blake3("shrugg-aggregator-leaf-1", addr || bond || nonce || release || payout pk || payout kem_ek)`
and the root joins the state root as `… || aggregators_root` under a new domain
`shrugg-state-3`. A chain without the section keeps the current root byte for byte.

**Joining, leaving.**
- `Action::RegisterAggregator { registration: AggregatorRegistration { public_key, payout, signature } }`
  on a bundle whose `burn == AGGREGATOR_BOND` (genesis parameter, default `100 * UNITS_PER_SHRUGG`),
  exactly as a validator's `Bond` burns stake; the signature is over
  `blake3("shrugg-aggregator-register", chain_id || payout)`. Refused if the address is registered.
- `Action::UnbondAggregator { aggregator, nonce, signature }`: bundle-less, validator-style signed;
  sets `unbonding = Some(height + 256)`; a submitting aggregator with `unbonding` set is refused.
- `Action::WithdrawAggregator { aggregator, nonce, time, r, envelope, signature }`: bundle-less;
  after the release height, pays `bond − BUNDLE_BASE` as a deposit note the ledger derives
  (`note_commitment(payout.pk, [0;8], bond − BUNDLE_BASE, 0, time, r)`, `time` window-checked),
  `BUNDLE_BASE` to the proposer, and deletes the entry — the S2 `Withdraw` pattern verbatim.

**The aggregate.**
```
Action::Aggregate {
    covers: Vec<Hash>,            // bundle transaction hashes, in the order the proof lists them
    proof: AggregateProof,        // the rVM proof (M5 §6); its public values are recomputed, not carried
    aggregator: Address,
    nonce: u64,
    time: u32,                    // window-checked; the payout note's time
    r: Word8,
    envelope: Envelope,           // the payout note sealed to `payout`
    signature: Signature,         // over blake3("shrugg-aggregate", chain_id || nonce || time || r || covers || proof hash)
}
```
Bundle-less. Size cap `MAX_AGGREGATE_BYTES` = the proof cap plus `MAX_COVERS · 32` bytes.

**Admission** (spec §7 order, cheap before expensive):
1. size caps; `chain_id`;
2. `aggregator` registered, not unbonding; `nonce` equals the entry's; signature valid;
3. `time` within the window;
4. `1 ≤ covers.len() ≤ MAX_COVERS` (genesis parameter; M5.3 measures the guest's capacity), no
   duplicates, every hash names a bundle transaction in a **finalised** block within the last 256
   blocks, none already covered (`sealed_by` absent);
5. the payout note `cm` is new (`derived_commitment` claims it in the mempool, as a `Withdraw`'s);
6. the expected public values are built from the covered bundles' public fields (M5 §4.4 as
   corrected by M5 §12: the 4-element inner verifier key digest the chain pins for the current
   constraint set, `N`, then each bundle's **all 26** public values in `pv` order — `PC_ENTRY`,
   `TIER`, `OUT0..7`, `HC0..7` = the registered bundle guest's `hc`, `IN0..7` — in `covers` order)
   and `verify_aggregate(rvm_vk, proof)` must return exactly them — the one expensive step, last.
   Checking `HC0..7` against the registered `hc` is what stops an aggregate from covering a proof
   of some other guest.

**Selection.** A proposer includes at most one `Aggregate` per block. Among the valid submissions
it holds, it picks the one with the largest `covers.len()`; ties by the lowest proof hash. Losing
submissions stay pooled until any bundle they cover is sealed by another (then `still_applies`
drops them) or their window passes.

**Slashing.** Only equivocation is provable on chain: two submissions signed by the same aggregator
with the same `nonce` and different content. `Action::SlashAggregator { a, b }` carrying both
signed headers burns the bond (supply term `slashed`) and deletes the entry; anyone may submit it,
bundle-less, no fee. Everything else invalid is simply refused.

## 2. Payment and supply (approved)

- **Subsidy.** The block that includes an `Aggregate` mints `subsidy(n)` to the aggregator, where
  `n` = the number of sealed blocks so far (a ledger counter incremented per included aggregate, so
  an idle chain does not consume the schedule): `subsidy(n) = 100 SHRUGG >> (n / 210_000)`, zero
  once the shift reaches 64.
- **Proving share.** When a bundle is included in its block, the proposer is credited only
  `BUNDLE_BASE`; the excess `fee − BUNDLE_BASE` goes to an `unsealed_fees: BTreeMap<Hash, u64>`
  ledger bucket keyed by bundle hash (part of the state; its root is not needed since the map is
  derived from bundles already in the state root — it is rebuilt on replay). When an `Aggregate`
  covers the bundle, its excess moves to the aggregator; when the bundle's 256-block window passes
  uncovered, the excess is credited to the block proposer that included the bundle (the entry
  records that proposer). Nothing is minted or lost here.
- **One note.** Subsidy plus proving shares are paid as one deposit note to the aggregator's payout
  address, derived from `time` and `r` exactly as a validator's `Withdraw` note; the amount is
  public in that block only.
- **Supply invariant** (`docs/supply.md`) gains two terms:
  `supply = genesis + faucet + Σ subsidies − burns − slashed`, with `aggregator_bonds` tracked as
  its own counter (burned in on registration, paid out on withdraw). `shrugg_getSupply` reports
  `subsidised`, `sealed_blocks`, `aggregator_bonds` and `slashed` separately.

## 3. Sealed history, pruning, sync (approved)

- **Sealed.** Storage records per bundle `sealed_by: Option<Hash>` (the `Aggregate` transaction)
  and per block `sealed: bool` once every bundle in it has one. Both are node state derived from
  committed blocks, not consensus state.
- **Pruning.** A node may drop the raw proof bytes of any sealed bundle (`CF_TXS` keeps the
  transaction with `bundle.proof` replaced by its hash and a `pruned` marker). Every public field
  stays, so replay is byte-identical. Pruning is policy: `--keep-raw-proofs` for archives; default
  on after a bundle has been sealed for 256 blocks. A pruned node's state root is unchanged.
- **Sync.** The sync protocol gains a second block form: bundles with `proof = pruned(hash)` plus
  the covering `Aggregate` transactions (which are ordinary transactions in later blocks, so a
  syncing node receives them in order anyway). `apply_synced` accepts a pruned bundle only if the
  block is finalised, a covering `Aggregate` is already applied, and the aggregate's `covers`
  names the bundle's hash; otherwise it requests the raw form from another peer. `verify_chain`
  applies the same rule and fails a pruned bundle whose covering aggregate is missing.
- **Trust model:** unchanged. Every bundle in history is covered by a proof the node verified
  itself (raw or aggregate). Disk: about 1.3 MB → about 3 KB per sealed transfer. Throughput:
  unchanged in this phase (three raw bundles per block); the forward path is out of scope.

## 4. RPC, wallet, aggregator daemon, tests, rollout (approved)

- **RPC.** `shrugg_getBlockByHeight` gains `sealed` and per-bundle `sealed_by`;
  `shrugg_getAggregate(tx)` returns the public fields (`covers`, `aggregator`, `subsidy`,
  `proving_share`, `n`); `shrugg_getAggregators` lists the register; `shrugg_getUnsealed(from, limit)`
  pages the bundles an aggregator may still cover (hash, height, excess fee); `shrugg_submitAggregate`
  is `shrugg_sendTransaction` (no new path). `tx_json` renders the four actions.
- **Node CLI (the aggregator role).** `shrugg-node aggregator register --bond --payout`, `unbond`,
  `withdraw` (the validator commands' twins), and `shrugg-node aggregate --watch`: a daemon that
  polls `shrugg_getUnsealed`, fetches the raw bundles, calls `recursion::aggregate` (CPU or GPU),
  and submits. It is a separate process from the validator and needs only an RPC endpoint.
- **Wallet.** No change: a sender attaches `--fee` above the floor to be sealed first; `shrugg fee`
  prints the floor and the current median excess.
- **Genesis.** `aggregation: Option<AggregationConfig { bond, max_covers, subsidy_base, halving_blocks, window }>`;
  chain 8 has none; enabling it is a chain cut (like the bridge).
- **Tests.** Core: register/unbond/withdraw/slash round trips; admission order with a stub
  `verify_aggregate`; the fee bucket's three exits (covered, expired, never-included); the subsidy
  schedule at the halving edges; the supply invariant with subsidies, bonds and a slash. Node:
  `sealed_by`/pruning/sync in pruned form/`verify_chain` on a pruned store. Cluster: one real
  aggregate over three real bundles (M5.3's proof), sealed, pruned on one node, that node resyncs
  a fresh peer in pruned form, heights and roots agree.
- **Rollout.** A chain cut (new genesis with the section), after M5.3; the aggregator daemon runs
  first on the laptop's GPU-less CPU for the cluster test, then on a GPU host.

## 5. Out of scope

The forward path (bundles travel to aggregators before inclusion; raw proofs never enter a
block); self-recursion trees on chain (one aggregate per block suffices); pricing the proving
share by anything other than the sender's excess; any change to the bundle guest or the RV32
machine.

## 6. Open items

- `MAX_COVERS`: M5.3's measured N on the laptop and on a GPU.
- Whether the aggregate should also carry the inner proofs' `H_IN` values (not needed: the bundle
  digest already binds each bundle; recorded from the M5 spec).
- The rVM verifier-key pin: which digests the chain registers per constraint set and how the
  vendoring carries them (the re-vendor task).
