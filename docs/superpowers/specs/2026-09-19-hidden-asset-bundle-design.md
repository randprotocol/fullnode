# The hidden-asset bundle: one proof moves any asset, and nobody can tell which

Status: design decided 2026-09-19 (the user chose "build the hidden-asset guest first"; the shape
below follows the measured spike, `spike-hidden-asset-report.md` in the RPL ledger directory).
Target: chain 14 and v0.5. Supersedes the two-bundle token transfer of the RPL spec (§4
`TokenTransfer`, "Two-bundle rules", "What is public") — everything else in the RPL spec stands.

## 1. Problem

Today's `bundle()` guest (`crates/randprotocol-zkvm/src/guests.rs`, local code, not vendored)
balances ONE asset whose index is a public field of the bundle, and refuses a fee on a non-RAND
bundle. So an RPL token transfer carries two bundles (a RAND fee bundle and an asset bundle), costs
two proofs, and tells every observer which token moved. The user wants a zUSD transfer to be
indistinguishable on chain from a RAND payment.

## 2. The measured answer

A 4-in/4-out guest with a private asset proves at **today's tier 14, ~98–100 s, 5.7 GB, 1.43 MB**
(two runs each, Production FRI, CPU) — *if* it reads its private inputs in a loop and its Merkle
check reads each sibling straight from the input. Written in `bundle()`'s unrolled style it lands at
tier 16: ~400 s and 21–22 GB, which excludes 16 GB wallets. Headroom at tier 14: 13 % of cycles
(2 071), 11 % of permutations (235).

## 3. Decisions

1. **One bundle per transaction, four input and four output slots.** Slots 0–1 (in and out) carry a
   **private** asset `A`; slots 2–3 carry RAND (asset 0). `A` may be 0, in which case slots 0–1 carry
   RAND too. — *4/4 over 3/3*: a plain RAND payment keeps today's shape (value and fee in slots 2–3,
   slots 0–1 dummy), and a token transfer can pay its fee from up to two RAND notes. 3/3 would force
   every token transfer's fee out of a single RAND note. The 13 % headroom is accepted; if a later
   relation change needs more than ~2 000 cycles, the fallback is 3/3 with the same two
   optimisations (35 % headroom), which this spec's layout generalises to.
2. **Written with looped reads and the fused Merkle loop** (spike variant `hidden-fused`). The
   unrolled style is forbidden for this guest: it quadruples cost.
3. **The relation** (all arithmetic checks feed the existing `bad` taint accumulator, as `bundle()`):
   - `nk`, `pk_self` from `sk`; every input note is staged with owner `pk_self` and committed.
   - A non-dummy input (`amount != 0`) is Merkle-verified, its root equals `anchor`, and its asset
     equals its slot's asset (`A` for 0–1, 0 for 2–3). A dummy skips those three checks and cannot
     carry value (the skip condition reads the registers that feed the sums).
   - Nullifier `nf_i = H_NF(nk, cm_in_i)` for all four inputs, dummies included.
   - Outputs are staged with `from = pk_self`, asset = the slot's asset (structural), time = the
     bundle's time, and committed.
   - All 6 nullifier pairs and all 6 output-commitment pairs differ.
   - `< 2^63` on all 8 amounts, `fee`, `burn_a`, `burn_r`.
   - Two conservation sums, carry-checked: `in0 + in1 = out0 + out1 + burn_a` and
     `in2 + in3 = out2 + out3 + fee + burn_r`.
   - `burn_asset = A` if `burn_a != 0`, else 0 (branch-free).
4. **Public digest** (a new domain tag, 16): `H(anchor, nf0..3, cm0..3, fee, burn_a, burn_r,
   burn_asset, time, bad)` — 82 words. **`A` is not in it.** A burn names its asset because a burn is
   a public boundary anyway (the chain must debit that token's supply).
5. **The transaction binding (Task 5b) carries over unchanged**: the new guest is proved against the
   transaction's binding words through the public input segment, exactly as today's.
6. **Core `Bundle`** becomes: `anchor`, `nullifiers: [Word8; 4]`, `commitments: [Word8; 4]`, `fee`,
   `burn_a`, `burn_r`, `burn_asset: u32`, `time`, `envelopes: [Envelope; 4]`, `proof`. The public
   `asset` field is removed.
7. **Actions**:
   - A transfer of ANY asset is `Action::None` — `TokenTransfer` is removed.
   - Every action is single-bundle again: `BridgeBurn` and `TokenBurn` lose `asset_bundle`; the
     ledger requires `bundle.burn_asset == action.asset`, `bundle.burn_a == action.amount`,
     `bundle.burn_r == 0`. `Bond` and `RegisterAggregator` burn RAND through `burn_r` with
     `burn_a == 0`. Every other action requires `burn_a == burn_r == 0`.
   - `TokenMint`, `RegisterToken`'s initial mint and `BridgeAttest` still append ONE chain-computed
     note (unchanged).
   - `Action::asset_bundle()` and the two-bundle machinery (`check_asset_bundle`, the second proof
     size cap, the second note set) are deleted.
   - `TokenTransfer`'s memo goes with it. Allowances (RPL Task 9) are not on the v0.5 path; a memo
     returns with them, designed then.
8. **The ledger never learns `A`.** It needs no registry check on it: token notes only enter the pool
   through a public mint or deposit of a registered index, and in-pool conservation preserves the
   asset. A made-up `A` can only ever carry value 0.
9. **Fees stay RAND only.** A token-only sender must hold RAND (unchanged decision).
10. **Hard fork.** `hc_bundle` in genesis pins the new guest's digest; chain 14 only. The old
    `bundle()` is removed from the chain path (kept only if a test still needs it).

## 4. What an observer sees afterwards

Every transfer — RAND, zUSD or any RPL token — publishes 4 nullifiers, 4 commitments, a RAND fee, a
time, the proof and 4 envelopes, and `burn_a = burn_r = 0, burn_asset = 0`. Nothing distinguishes a
zUSD payment from a RAND payment. What stays public by design: mints and deposits (amount, index,
recipient), burns (amount, asset, destination), and the action kind of those boundary events. With a
transaction key or a viewing key, the notes open to their full plaintext, asset included (randscan).

## 5. Costs accepted

- The commitment tree and the nullifier set grow twice as fast (4 + 4 per transaction, dummies
  included) — that is what makes the shapes identical.
- ~+2.3 KB of envelopes per transaction (on a 1.43 MB proof).
- A modest proving headroom (13 % / 11 %) at tier 14.
- Block aggregation's admitted shape and recursion fixtures assume today's bundle; aggregation is
  inactive on every chain and must be re-measured before it is activated.

## 6. Soundness review

The spike wrote no cheating tests. Before this ships, the guest gets an adversarial review of its
own and a `tests/cheating`-style suite with real proofs, each case a witness that would be accepted
if the check were missing:
- value moved from a token slot into a RAND slot, and the reverse;
- an A-slot input whose note asset differs from `A`; an R-slot input whose asset is not 0;
- two A-inputs of different assets;
- `burn_asset` not equal to `A` while `burn_a != 0`; `burn_asset != 0` while `burn_a == 0`;
- 64-bit overflow in either sum; an amount `>= 2^63`;
- any duplicated nullifier or output commitment among the four;
- a dummy input carrying value; a real input with a root other than `anchor`;
- the fused Merkle loop's sibling index redirected (it is a program constant plus a fixed stride —
  show a prover cannot change it);
- a proof against the empty public segment or another transaction's binding (Task 5b's tests, on the
  new guest).

## 7. Scope of the change (planned as tasks H1–H5)

H1 the guest, its layouts (`notes::hidden_input`, `hidden_digest`), the prover/verifier-key heights,
and the honest-path proof tests · H2 the cheating suite and its review · H3 core: the `Bundle`
shape, the stub executor, the ledger rules above, deleting the two-bundle machinery · H4 node:
note indexing (4 per bundle), mempool keys, sealed/pruned forms, RPC `tx_json`, genesis `hc_bundle`
· H5 client: note selection across two assets in one plan, 4 envelopes, `rand send` for any asset,
bridge-burn and token-burn on the one bundle. RPL plan Tasks 6–8 then land on this shape.
