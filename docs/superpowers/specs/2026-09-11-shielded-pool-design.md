# Fully shielded pool — design

Date: 2026-09-11. Status: draft for review. Supersedes the transparent account ledger described in
`docs/architecture.md` ("Ledger") for the next chain. Builds on the zkVM at `circuits/research`
35fceab (milestones 2 and 3, vendored in fullnode f1a29dd) and on the note and viewing-key layer in
`research/src/{notes,viewing,ledger}.rs` (`research/docs/06-viewing-keys.md`).

## 1. Goal

Every SHRUGG balance becomes a set of unspent notes. There is no transparent pool: no
`Account { nonce, balance }`, no plaintext transfer, no plaintext amount anywhere on chain. A
balance is visible only to whoever holds the owner's viewing key, and a transaction's sender,
receiver and amount are visible only to the two parties, to whoever they hand a per-transaction key,
or to whoever holds a party's viewing key. Explorers and validators see commitments, nullifiers,
ciphertexts, fees and proofs.

Two things stay public by decision (user, 2026-09-10): **stake weights** (who validates and with how
much, because HotStuff quorum counting and leader rotation read them) and **fees** (because the
proposer is paid and admission must be cheap). Program deployments stay public as today; call
outputs stay public but can no longer move value.

Decisions already taken by the user and not re-opened here: fully shielded (no transparent pool);
fees proved in-transaction as a value balance; faucet and staking redesigned as shielded operations;
shielded stake with public weights; wait for the in-circuit Poseidon2 hash (done, M3); the note
model of M1.5/M3.3 (nullifier `H_NF(nk, cm)`, sender bound into the commitment, ML-KEM-768 +
ChaCha20-Poly1305 envelopes, party- and transaction-scoped disclosure).

## 2. Non-goals

- Hiding the transaction *type* or the program a call runs. `hc` is binding, not hiding.
- Hiding stake weights or validator identity.
- Perfect zero knowledge (Plonky3 0.7's hiding FRI is statistical).
- Proving on chain that an envelope decrypts to the committed note. As in Zcash, a sender who
  publishes garbage ciphertext has paid to lose the money; the receiver's wallet refuses to treat it
  as paid. Recorded as a later extension.
- Multi-asset value balance beyond what the bridge needs (section 10).
- Recursion or batching of proofs.

## 3. Shape of a transaction

Every transaction is a **bundle**: up to two spent notes, up to two created notes, one public fee,
one STARK proof, and an optional public **action**. The bundle pays the fee for the action.

```
Transaction {
  chain_id: u64,
  bundle: Bundle {
    anchor:       Word8,          // a recent commitment-tree root
    nullifiers:   [Word8; 2],     // nf of each spent note (dummy inputs still publish one)
    commitments:  [Word8; 2],     // cm of each created note (dummy outputs still publish one)
    fee:          u64,            // units, public, always asset 0 (SHRUGG)
    burn:         u64,            // units leaving the pool into the action (0 for none)
    asset:        u32,            // asset id balanced by this bundle; 0 = SHRUGG
    time:         u64,            // block height the sender targets
    envelopes:    [Envelope; 2],  // ciphertext per created note
    proof:        Vec<u8>,        // postcard(rand_zkvm::Proof)
  },
  action: Action,                 // None | Deploy | Call | Bond | Unbond | Withdraw | BridgeBurn | BridgeAttest
}
```

There is no signature and no nonce. The proof authorizes the spend (the spending key is a private
input; the guest derives `nk` and `pk` from it in-circuit) and the nullifiers are the replay
protection. Actions that need an identity outside the pool (Unbond, Withdraw) carry a Dilithium2
signature by the validator key inside the action, not on the transaction.

Bundles are fixed 2-in-2-out. Fewer real inputs or outputs use **dummy notes**: an input note with
amount 0 skips the Merkle membership check in-circuit (its nullifier is still derived and published,
so it looks like any other), and an output note with amount 0 is a real commitment to a random note
that nobody can spend for value. A transaction is therefore always the same size and shape, and an
observer cannot tell one-in-one-out from two-in-two-out.

`burn` is how value leaves the pool into a public action (Bond, BridgeBurn, or paying a Deploy fee
above the bundle fee is not needed; see section 6). `burn` is zero for a plain transfer. Value enters
the pool only through **deposits** (section 6): Withdraw of stake or rewards, faucet Mint, and
BridgeAttest, each creating one note whose amount is public in that transaction only.

## 4. The transfer relation (guest `bundle`)

One guest program, hash `hc_bundle`, pinned in genesis. Private inputs: spending key; for each of
two inputs `(from, amount, asset, time, r, path, index)`; for each of two outputs `(pk, time, r)`
plus the amounts; the public fee, burn and asset. The guest proves:

1. `nk = H_NK(sk)`, `pk_self = H_PK(nk)`; both input notes have `pk = pk_self`.
2. For each input with `amount > 0`: `cm_in = H_CM(note)` and `MERKLE_VERIFY(cm_in, path, index)`
   equals `anchor`. Inputs with `amount = 0` skip step 2.
3. `nf_i = H_NF(nk, cm_in_i)` for both inputs, dummy or not.
4. Each output note is `(pk_out, from = pk_self, amount_out, asset, time, r_out)` and
   `cm_out = H_CM(note)`.
5. Value balance in units, 64-bit: `amount_in_1 + amount_in_2 = amount_out_1 + amount_out_2 + fee + burn`,
   with no wrap-around (each amount is two u32 words; the guest checks carries with RV32M-free
   add-with-carry sequences, and every amount is below `2^63` so the sum cannot overflow).
6. Every note's `asset` equals the bundle's public `asset`; `fee` is charged in asset 0, so a bundle
   with `asset != 0` must have `fee = 0` in this bundle and be paired with a second SHRUGG bundle
   (section 10). For the first release `asset` is always 0.
7. `time` is copied into both output notes.
8. The single public output is
   `digest = H(BUNDLE, anchor, nf_1, nf_2, cm_1, cm_2, fee, burn, asset, time, bad)`, 8 words in
   `OUT0..OUT7`, a fixed 47-word preimage under its own domain tag. `bad` is the guest's taint
   accumulator: this ISA has no in-circuit assert, so every arithmetic relation above (balance,
   range, anchor agreement between two real inputs, per-input asset) ORs its violation into
   `bad`, and the ledger recomputes the digest with `bad = 0`. A violated relation therefore
   yields a digest the ledger can never reproduce. (Ruling 2026-09-11: the taint must land on a
   word the verifier fixes itself; an earlier plan draft XORed it into `time`, which the sender
   supplies, and a sender could have published `time ^ 1` to pass the check.)

The chain recomputes `digest` from the plaintext bundle fields and compares. The proof is verified
last, after every cheap check (section 7). `hc` must equal `hc_bundle`.

Cost estimate, to be measured in the zkVM task that builds this guest (section 12): two Merkle
walks of 32 hashes, six note hashes, one output hash, about 80 permutations at a few cycles each,
plus 64-bit bookkeeping. The current one-in-one-out guest runs 4903 cycles at 4554 program words
because the Merkle walk is unrolled; the looped routine is a prerequisite, and the target is tier 12
(4095 cycles) or 14. Amount width is `u64` units (18.4 billion SHRUGG per note at
`UNITS_PER_SHRUGG = 1e9`), up from the research crate's `u32`.

## 5. Notes, keys, addresses

Unchanged from `research/src/notes.rs` except the amount width:

```
Note { pk: Word8, from: Word8, amount: u64 (2 words), asset: u32, time: u32, r: Word8 }   // 28 words
cm = H(CM, note words)          nf = H(NF, nk, cm)          nk = H(NK, sk)          pk = H(PK, nk)
```

Keys: `sk` (spend), `nk` (viewing; derives `pk`, every nullifier, `ovk`, and the ML-KEM-768
decapsulation seed). A **shielded address** is `(pk, kem_ek)`, encoded base58 with a `shrugg1`
prefix. The ML-KEM-768 encapsulation key is 1184 bytes, so an address is about 1.6 KB. That is the
price of a post-quantum envelope consistent with the chain's Dilithium2 choice; a 32-byte X25519
address would be shorter and not post-quantum. Ruling: keep ML-KEM.

Envelopes are the research crate's `Envelope { kem_ct, to_receiver, to_sender, body }` with `cm`
as AEAD associated data. Both the receiver (via KEM) and the sender (via `ovk`) can open a note.
A `TxKey` opens exactly one transaction's two envelopes.

Validator keys stay Dilithium2 and stay public; a validator also holds a shielded address for
Withdraw payouts.

## 6. Actions

| action | public fields | value flow | who authorizes |
|---|---|---|---|
| None | — | none | the bundle proof |
| Deploy | `base_pc, words` | none; fee floor `100_000 * words` on the bundle fee | the bundle proof |
| Call | `program, proof, outputs are in proof` | none; kind-1 transfers are removed; fee floor `call_fee(tier)` on the bundle fee | the bundle proof |
| Bond | `validator: Address(pk_dilithium), amount` | `burn = amount` leaves the pool into the validator's stake | the bundle proof (any note holder can bond to any validator) |
| Unbond | `validator, amount, sig` | stake → pending, released after `UNBONDING_EPOCHS` | validator signature |
| Withdraw | `validator, amount, time, r, envelope, sig` | bundle-less; released stake or rewards → one new note worth `amount − BUNDLE_BASE`, the base credited to the block proposer | validator signature |
| Mint (faucet) | `cm, envelope, amount ≤ 100 SHRUGG` | new note of public amount; only when genesis `faucet = true` | the node key (as today) |
| BridgeAttest | attestation bytes, `cm, envelope` | new note of public amount in the bridged asset | guardian quorum (as today) |
| BridgeBurn | `asset, amount, destination, sig-free` | `burn = amount` in `asset` leaves the pool to the bridge | the bundle proof |

Deposits (Withdraw, Mint, BridgeAttest) create a note whose amount is public in that one
transaction. The note is then indistinguishable from any other in the tree; the first spend of it
hides where it went. This is the same privacy shape as a Zcash t→z transaction and is the only place
an amount is ever public.

A bundle may carry at most one action. Deploy and Call no longer need a caller balance: the bundle
pays. Call outputs remain eight public words recorded in the receipt; effect kind 1 (transfer to a
recipient list) is deleted because there are no accounts to pay. Programs that want to move value
compose with the pool by having the caller include the payment in the same bundle's outputs.

### 6.1 Call input envelopes (viewing keys for program calls)

Added 2026-09-11 at the user's request; phase S3. Today a confidential call leaves nothing on
chain a viewing key could open: its private inputs never leave the wallet. Zcash-style
disclosure for calls needs the inputs on chain, encrypted, bound to the proof.

- **What goes on chain.** A `Call` action gains `input_envelope: CallEnvelope { kem_ct, to_sender,
  to_auditor, body }`. `body` is the call's private input vector plus the `H_IN` salt (zkVM M4.1),
  encrypted with ChaCha20-Poly1305 under a fresh per-call key `K_call`, with `H_IN` as the AEAD
  associated data. `to_sender` seals `K_call` under the caller's `ovk` (the same sender path the
  note envelope uses); `to_auditor` and `kem_ct` optionally seal it to one designated auditor
  address with ML-KEM-768. Size cap: inputs are at most 4096 words, so `body` is at most 16 KiB
  plus the tag; the transaction size cap in section 7 grows by that much for calls.
- **Binding without in-circuit encryption.** The chain checks nothing about the ciphertext, as
  with note envelopes. A holder who decrypts obtains `(salt, inputs)` and recomputes
  `H_IN = input_digest(salt, inputs)` against the receipt's public value; a mismatch means the
  caller published a false envelope, which the holder can prove to anyone by showing the
  decryption. Because the proof binds `H_IN` to every `READ_INPUT`, a matching envelope is a
  faithful transcript of what the program read.
- **Who can open it.** A party viewing key (`nk`, via `ovk`) opens every call that party made; a
  per-call `TxKey` (`K_call`) opens one call; the auditor address, if set, opens that call. With
  the inputs, the program words (public) and the emulator, the holder re-runs the call and sees
  exactly what it computed, which is the explorer's "show me this call" view under a viewing key.
- **What stays hidden.** Everyone else sees `H_IN`, the ciphertext, and the public receipt as
  before. The bundle carrying the call already lets a party key show the call's value flow; the
  input envelope adds the computation itself.
- **Voluntary disclosure (user decision 2026-09-11).** The chain never requires disclosure and
  no validator, explorer or bridge holds a key. The wallet always writes the envelope, so the
  caller keeps the ability to unmask a call later for compliance; whether to hand out a party
  key, a per-call key, or nothing is the caller's choice at the time an auditor asks. A caller
  who wants no disclosure path at all can pass `--no-envelope`, which forfeits that option for
  that call permanently; the chain accepts both.
- **Dependencies.** zkVM M4.1 (`H_IN`, salt) and the note envelope code (`viewing.rs`), both
  existing; no zkVM change beyond M4.1.

## 7. Validity and admission order

Cheap before expensive, in this order, in both the mempool and the ledger:

1. Size caps: transaction ≤ 8 KiB before the proof, proof ≤ 1 MiB, envelopes ≤ 2 KiB each.
2. `chain_id` matches.
3. `fee ≥ fee_floor(action)`: `BUNDLE_BASE = 1_000_000` units (0.001 SHRUGG) for every bundle, plus
   the Deploy or Call floor. Transfers therefore cost 0.001 SHRUGG; the faucet mints 100.
4. `anchor` is one of the last `ANCHOR_WINDOW = 64` roots (the research crate uses 16; 64 gives a
   prover about a minute at 1 s blocks).
5. `time` is within `[height - 64, height]`.

> **2026-09-12: raised to 256.** Both windows are 256 blocks in the implementation
> (`shrugg_core::ledger::{ANCHOR_WINDOW, TIME_WINDOW}`). The measured tier-14 bundle proof is
> ~100 s and the fleet makes a block every ~2 s, so the 64 assumed here — a minute at 1 s blocks —
> expired an honest transfer's anchor while it was still being proved.

6. Neither nullifier is in the nullifier set, the two differ, and neither appears twice in the
   block. Neither commitment exists in the tree.
7. Action-specific cheap checks: program exists; Bond target is a validator or a registration
   (section 8); signatures on Unbond/Withdraw; attestation size before decode before recovery.
8. Recompute `digest` from the plaintext fields; it must equal `proof.public_values[OUT0..OUT7]`;
   `HC0..HC7` must equal `hc_bundle`; tier and `program_log_height` in range; degree bits match.
9. `Machine::verify(&hc_bundle, &proof)`.
10. For Call: the action's own proof, verified the same way against the program's `code_hash`.

A block with any invalid transaction is invalid. Two transactions in one block that spend the same
nullifier are both rejected with the block.

## 8. Staking with public weights

The one public register on the chain:

```
ValidatorEntry { key: PublicKey (Dilithium2), stake: u64, pending: Vec<(u64 release_epoch, u64 amount)>, rewards: u64, payout: ShieldedAddress }
```

- **Epochs**: `EPOCH_BLOCKS = 1000`. The validator set used by HotStuff for epoch `e` is computed
  from the register as of the last block of epoch `e - 1`: every entry with `stake ≥ MIN_STAKE`
  (1000 SHRUGG), capped at `MAX_VALIDATORS = 100` by stake, sorted by address. Weights are the
  `stake` field. `ValidatorSet::has_quorum` and `leader` are unchanged.
- **Registration** is a Bond to a key not yet in the register with `amount ≥ MIN_STAKE`; the
  action carries the validator's Dilithium2 public key and payout address signed by that key.
- **Bond** adds `amount` to `stake` immediately; it counts from the next epoch.
- **Unbond** moves `amount` from `stake` to `pending` with `release_epoch = current + UNBONDING_EPOCHS`
  (2). Stake below `MIN_STAKE` after an unbond drops the validator from the next epoch's set.
- **Rewards**: every bundle fee in a block is credited to the proposer's `rewards` field. Withdraw
  moves released `pending` amounts and `rewards` into a new note at the payout address. A proposer
  may include its own withdraw in a block it proposes, in which case the bundle base it pays out
  comes right back to it as the proposer's reward — value-neutral.
- **Slashing**: none in this release. Double-vote evidence is out of scope; the register carries no
  `jailed` flag yet. Recorded as a follow-up.
- The register is hashed into the state root (section 9). It is the only place on the chain where
  an amount is stored in the clear.

Genesis: `validators: [{public_key, stake, payout}]` seeds the register; `alloc` becomes a list of
`(cm, envelope, amount)` deposit notes, generated by `shrugg-node genesis` from shielded addresses.

## 9. State, storage, state root

Ledger state:

```
CommitmentTree   depth 32, Poseidon2, append-only; frontier stored, not the full tree
anchors          the last ANCHOR_WINDOW roots with their heights
nullifiers       set of Word8
validators       the register (section 8)
programs         as today
bridge           as today (bridged balances become notes; the bridge keeps emitters, guardian sets, asset registry, spent digests)
```

`state_root = blake3("shrugg-state-2" || tree_root || nullifier_root || validators_root || programs_root [|| bridge_root])`.
`nullifier_root` is a BLAKE3 Merkle root over the sorted nullifier set, recomputed per block
(O(n); an incremental accumulator is a follow-up once the set passes about 10^6 entries).
`validators_root` is a BLAKE3 Merkle root over entries in address order.

RocksDB column families added: `notes` (leaf index → cm), `nullifiers` (nf → height),
`anchors` (height → root), `envelopes` (tx hash → bytes), `validators` (address → entry);
removed: `accounts`. `meta` gains the tree frontier. A commit is one fsynced WriteBatch as today.

Startup verification and sync re-execute every bundle including its proof (`--verify-chain quick`
re-verifies proofs; `off` trusts the stored state as today).

## 10. Bridge on the shielded chain

Bridged assets are notes with `asset = bridge asset id`. BridgeAttest deposits a note of public
amount; BridgeBurn burns from a bundle in that asset. Because the fee is in SHRUGG and a bundle
balances one asset, a BridgeBurn transaction carries **two bundles**: an asset bundle (fee 0,
`burn = amount`) and a SHRUGG bundle paying the fee. This is the only two-bundle transaction and is
scheduled last (phase S3). The bridge's own state (emitters, guardian sets, asset registry, spent
digests, burn log) is unchanged and stays public; its per-account balances are deleted.

## 11. What the explorer and RPC see

Removed: `shrugg_getBalance`, `shrugg_getAccount`, plaintext transfer bodies, per-account history.
Added: `shrugg_getCommitments(from_index, limit)`, `shrugg_getNullifiers(height)`,
`shrugg_getEnvelopes(height)`, `shrugg_getAnchor(height)`, `shrugg_getValidators` (public register),
`shrugg_getWitness(cm)` (Merkle path for a wallet that lacks a local tree). Fees, actions, program
ids, receipts, validators and bridge state remain public. Transaction bodies are public but contain
only commitments, nullifiers, ciphertexts, fee, burn, time and the proof.

A wallet scans by trial-decrypting every envelope with its `nk` (receiver path) and `ovk` (sender
path) and keeps its own witness tree. An explorer that is handed a party viewing key or a `TxKey`
can render that party's or that transaction's rows, and only those, exactly as
`viewing::scan`/`verify_row` do today. This satisfies the two user requirements: balances and
transactions are private unless the viewing key is given.

## 12. Phases

| phase | scope | depends on |
|---|---|---|
| Z (zkVM, `circuits/research`) | looped `MERKLE_VERIFY`; the 2-in-2-out `bundle` guest with `u64` amounts, dummy inputs, fee and burn; `H_OUT` over the 9-field preimage; measured tier; vendored | M3 (done) |
| S1 (fullnode) | notes ledger, `Bundle` transaction, admission order, storage, state root, deposits via Mint, wallet (keys, scanning, proving, `shrugg send`), RPC redaction, genesis with deposit notes, `--verify-chain` replay | Z |
| S2 | validator register, Bond/Unbond/Withdraw, epochs, rewards, `shrugg-node genesis` seeding | S1 |
| S3 | Deploy/Call riding on bundles (kind 1 removed), call input envelopes (section 6.1), bridge as notes with the two-bundle BridgeBurn | S1, zkVM M4.1, bridge merge |

Each phase is a hard fork; S1 alone is a new chain. The chain 5 fork the fleet session is
preparing (for f1a29dd) is independent of this; the shielded chain is the fork after it.

## 13. Rulings made in this draft

| ruling | why | cost if wrong |
|---|---|---|
| 2-in-2-out fixed shape with dummy notes | uniform transaction size and shape; Sapling-proven | wallets with many small notes need chained transactions |
| `u64` amounts | SHRUGG units are 1e9 per coin; u32 cannot hold one coin | note format change if supply ever exceeds 1.8e10 SHRUGG |
| fee public, paid to proposer's public rewards | matches "public stake weights"; keeps admission cheap | fee amounts leak transaction class (transfer vs call) |
| deposits with public amount (Withdraw, Mint, BridgeAttest) | value must enter the pool somewhere; same as Zcash t→z | one-hop amount visibility on deposits |
| anchor window 64, time window 64 | proving takes seconds to a minute | stale-anchor rejections if blocks are faster than expected |
| Call effect kind 1 deleted | no accounts to pay | programs that paid recipients must be rewritten to pay via the bundle |
| ML-KEM addresses (1.6 KB) | post-quantum, consistent with Dilithium2 | long addresses, larger envelopes |
| no slashing in this release | needs evidence transactions and a jail state, a separate design | misbehaving validators lose nothing beyond exclusion |
| nullifier root recomputed per block | simple and exact | O(n) per block; needs an accumulator past ~10^6 nullifiers |
| `hc_bundle` pinned in genesis | one relation, one verifier key | changing the guest is a hard fork (it is anyway: constraint sets are) |

## 14. Open items carried forward

- Envelope validity proved in-circuit (so a sender cannot burn a receiver's note by publishing
  garbage ciphertext).
- Slashing and jailing.
- Nullifier accumulator; commitment tree checkpointing for fast wallet sync.
- Production Poseidon2 round constants (the research crate still uses a development seed).
- A hiding salt for `hc` if program identity should ever be private.
- Batching or recursion to amortize per-transaction verify cost (16 ms warm today).
