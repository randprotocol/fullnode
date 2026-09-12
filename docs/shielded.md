# The shielded pool

Phase S1 replaced SHRUGG's account ledger with a shielded note pool. There are no accounts, no
balances and no addresses-with-money on this chain: value exists only as **notes**, each one a
commitment in an append-only tree, and the only way to learn what a note is worth is to hold the
key that opens it.

This page is the user's guide to that: the keys, what the chain publishes and what it does not,
the wallet commands, the RPC surface, the order a node admits a transaction in, and what is
still leaked. The design spec is
`docs/superpowers/specs/2026-09-11-shielded-pool-design.md`; the wire-level reference is
`docs/rpc.md`; the confidential-computation half is `docs/confidential.md`.

## 1. Keys and addresses

One secret, everything else derived:

```
spend key   SpendKey([u32; 8])           256 bits, in <key>.key.json, mode 0600
   │
   ├─ viewing key   nk = H(NK, sk)       sees the whole history; cannot spend
   │     ├─ pk      = H(PK, nk)          the field a note names its owner by
   │     ├─ nullifier(cm) = H(NF, nk, cm)  what a spend publishes
   │     ├─ ovk                          opens envelopes this wallet sent
   │     └─ ML-KEM-768 decapsulation key opens envelopes sent to this wallet
   └─ address       shrugg1 + base58(pk || kem_ek)     1668 characters
```

A **shielded address** is 32 bytes of `pk` plus the 1184-byte ML-KEM-768 encapsulation key
envelopes are sealed to, base58 after the `shrugg1` prefix — about 1.6 KB of text. It is public
by design: anyone may pay it, and holding it tells you nothing about what it holds.

The key file is version 2 and carries the spend key alone, because every other key above is a
pure derivation of it:

```json
{ "version": 2, "spend_key": "0101010101010101010101010101010101010101010101010101010101010101" }
```

`shrugg keygen` refuses to overwrite an existing file: there is no second copy of a spend key,
and overwriting one destroys every note it could still open. Next to it lives
`<key>.key.json.notes.json`, the note store — a cache of the notes this key has opened, every row
of which is recoverable by rescanning from leaf 0. It holds note plaintexts, so it is written
mode 0600 like the key itself.

A validator key is a different thing entirely: a 32-byte seed and a Dilithium2 key pair, whose
base58 address is public and appears in blocks as a proposer. Validators have addresses; wallets
have shielded addresses; the two never mix.

## 2. Notes, bundles and what is on chain

A **note** is `{ pk, from, amount, asset, time, r }` — 28 words, 112 bytes. It never appears on
chain. What appears is:

- its **commitment** `cm`, a Poseidon2 hash of those words, appended as a leaf of a depth-32
  tree, and
- its **envelope**, the note's plaintext sealed to the owner's address (ML-KEM-768 +
  ChaCha20-Poly1305, 1348 bytes) so only the owner — or the sender, through `ovk` — can read it.

Spending a note publishes its **nullifier** `H_NF(nk, cm)`, which is unlinkable to the
commitment without `nk`. The nullifier set is what prevents a double spend.

Every transaction that moves value carries a **bundle**: a fixed 2-in-2-out shape proved by the
pinned `bundle` zkVM guest.

```
Bundle { anchor, nullifiers[2], commitments[2], fee, burn, asset, time, envelopes[2], proof }
Transaction { chain_id, bundle: Option<Bundle>, action }
Action = None | Mint { .. } | Deploy { base_pc, words } | Call { program, proof }
```

The shape is fixed, so one input and one output are often dummies: a dummy input is a zero-value
note owned by the spender, and the change output is published even when the change is zero. A
transaction that looked different when there was no change would leak that there was none.

### What is public and what is hidden

| | public on chain | hidden |
|---|---|---|
| **transfer** (`Action::None`) | anchor, both nullifiers, both commitments, fee, `burn = 0`, `asset = 0`, `time`, two envelope ciphertexts, the bundle proof | who sent it, who is paid, the amount, the change, which leaves were spent, whether an input was a dummy |
| **Deploy** | everything above, plus `base_pc` and the program's words (so the program id and its code) | who deployed it, and what the paying notes were worth |
| **Call** | everything a transfer publishes, plus the program id, the call proof, and the receipt's tier and eight output words | the private inputs, registers, memory, branches taken, the real cycle count (only the padded tier shows), who called it |
| **Mint** (faucet) | the new note's commitment, its envelope, the **amount in the clear**, and the minting validator's public key (shown as its address) and signature | who the note is for — only the address holder can open the envelope; the address itself is never published |

A mint is how value enters the pool at all, and its amount is public by design (spec §6: the same
one-hop visibility Zcash's t→z has). Genesis deposit notes are the same trade: `alloc` in
`genesis.json` carries `{ cm, envelope, amount }`, so everyone can add up the initial supply and
nobody can say whose it is.

The fee is public too, and paid to the block proposer's `rewards` field in the validator register
— the one place on this chain where an amount is stored in the clear.

## 3. The wallet

`shrugg` talks to a node's JSON-RPC and does all the private work locally. Global options:
`--rpc` (`SHRUGG_RPC`, default `http://127.0.0.1:8545`) and `--key` (`SHRUGG_KEY`, default
`wallet.key.json`).

| command | what it does |
|---|---|
| `shrugg keygen` | write a new spend-key file; refuses to overwrite |
| `shrugg address` | print this wallet's `shrugg1…` address |
| `shrugg balance` | scan, then print what this wallet can spend |
| `shrugg sync` | scan without printing a balance |
| `shrugg notes` | every note this wallet has opened, with `spent` and `pending` |
| `shrugg history` | every note this wallet created for someone else |
| `shrugg send <TO> <AMOUNT>` | select, prove a bundle, submit, wait for the commit |
| `shrugg faucet [ADDRESS]` | ask a validator to mint (testnet chains only) |
| `shrugg program build/deploy/show` | assemble, deploy (paid by a bundle), inspect a program |
| `shrugg call <PROGRAM>` | prove a call locally, pay through a bundle, print the receipt |
| `shrugg receipt <TX>` | the receipt of a committed call |
| `shrugg fee bundle\|deploy <words>\|call <tier>` | the schedule's floor |
| `shrugg tx/block/head/status/peers/validators` | plain chain reads |

```bash
shrugg keygen                                      # wrote wallet.key.json
shrugg address                                     # shrugg1x7Qk…  (1668 characters)
shrugg faucet                                      # 100 SHRUGG into a note only you can open
shrugg sync                                        # scanned 41 leaves and 37 blocks; 1 notes, 1 unspent
shrugg balance                                     # balance: 100 SHRUGG / notes: 1 unspent
shrugg notes
#    index              amount    height    spent  pending
#       40                 100        37    false  -
shrugg send shrugg1q9f… 1.5                        # proves ~100 s, then waits for the commit
shrugg history                                     # what this wallet has paid out
shrugg fee call 14                                 # 0.0022 SHRUGG
shrugg program build --guest private_payment --arg 1000 --out pp.json
shrugg program deploy pp.json                      # a bundle pays the deploy floor
shrugg call <program id> --input 400 --input 250 --input 300 --input 75
shrugg receipt <tx hash>
```

`send` prints what it did and nothing about anyone else:

```
proving bundle (tier 14; about a minute on a laptop)…
proved in 98.3s: tier 14, 302857 bytes
submitted transfer 4f2c…  1.5 SHRUGG out, 98.499 SHRUGG change, fee 0.001 SHRUGG, anchored at height 192
balance: 98.499 SHRUGG
```

Three things to know about spending:

- **A bundle spends exactly two notes.** If a wallet's value is spread over three or more notes,
  no amount of dust adds up to a third input slot — the wallet says
  `need more than two notes; the largest two hold N units — consolidate first`. Consolidating is
  a `send` to your own address.
- **`--no-wait`** returns as soon as the node accepts the bundle. The inputs are then marked
  `pending` rather than spent: not spendable, but not written off either. The next `sync`
  resolves it — the nullifier appeared, or the blocks the wallet has read reach past
  `time + TIME_WINDOW` (256 blocks), after which that bundle can never be admitted and the note
  is spendable again.
- **The fee floor is 0.001 SHRUGG** for a transfer, plus the action's own floor for a deploy or a
  call. `shrugg fee` asks the node rather than guessing.

## 4. RPC

Full parameter and error detail is in `docs/rpc.md`; this is the shielded subset with one example
each. Every example is one HTTP POST of
`{"jsonrpc":"2.0","id":1,"method":…,"params":…}` to the node's `/`.

**`shrugg_getTreeInfo`** — how far a wallet still has to scan.

```json
→ {"method":"shrugg_getTreeInfo","params":[]}
← {"next_index": 41, "root": "6b1d…c4", "nullifiers": 12}
```

**`shrugg_getCommitments(from_index, limit)`** — a page of leaves, oldest first, at most 1000 per
call. This is the whole of a wallet's scan: every leaf and every envelope go to everyone, and
only a viewing key tells them apart.

```json
→ {"method":"shrugg_getCommitments","params":[40, 500]}
← [{"index": 40, "cm": "2a9f…07", "height": 37,
    "envelope": {"kem_ct": "b41c…", "to_receiver": "77e0…", "to_sender": "0c31…", "body": "9dd2…"}}]
```

**`shrugg_getNullifiers(from_height, limit)`** — what has been spent, by block.

```json
→ {"method":"shrugg_getNullifiers","params":[0, 500]}
← [{"height": 37, "nullifier": "8c04…d1"}, {"height": 41, "nullifier": "12be…9a"}]
```

**`shrugg_getAnchor([height])`** — the tree root a prover may build against. With no parameter it
serves the head, which is the only anchor a wallet should use.

```json
→ {"method":"shrugg_getAnchor","params":[]}
← {"height": 192, "root": "6b1d…c4"}
```

**`shrugg_getWitness(index)`** — the Merkle path of one leaf, leaf-first, 32 levels. `null` past
the end of the tree. See §6: this is the one request that says something about the caller.

```json
→ {"method":"shrugg_getWitness","params":[40]}
← {"index": 40, "root": "6b1d…c4", "path": ["0000…00", "f2a1…3b", … 32 entries …]}
```

**`shrugg_sendTransaction(hex)`** — `bincode(Transaction)` as hex. Returns the transaction hash;
acceptance is not commitment, so poll `shrugg_getTransaction`.

```json
→ {"method":"shrugg_sendTransaction","params":["0700000000000000012a9f…"]}
← "4f2c8b31…e7"
```

**`shrugg_mint(address[, amount])`** — the testnet faucet, on chains whose genesis says
`"faucet": true`. The node signs the mint with its own validator key; an observer answers
`faucet mints are signed by validators; ask a validator node`.

```json
→ {"method":"shrugg_mint","params":["shrugg1x7Qk…", "100000000000"]}
← "9ab1c0…4f"
```

**`shrugg_getTransaction(hash)`** — what an explorer can say, which is almost nothing:

```json
← {"height": 192, "index": 0, "block_hash": "63f6…08",
   "tx": {"hash": "4f2c…e7", "chain_id": 7,
     "bundle": {"anchor": "6b1d…c4", "nullifiers": ["8c04…d1", "5e77…20"],
                "commitments": ["2a9f…07", "b310…88"], "fee": 1000000, "burn": 0,
                "asset": 0, "time": 5, "proof_len": 302857, "envelope_len": [1348, 1348]},
     "action": {"kind": "none"}}}
```

There is no `from`, no `to`, no `nonce` and no amount in that reply, and there is nothing in the
stored block either — the node has nothing more to redact.

## 5. How a node admits a transaction

Cheap before expensive, in this exact order (`Ledger::validate_inner`, spec §7). The mempool runs
the same check before gossiping, so a bad transaction is refused once, at the edge.

1. **Size caps** — each envelope ≤ 2048 bytes, the bundle proof ≤ 1 MiB, a program ≤ 4096 words,
   a call proof ≤ 1 MiB.
2. **Chain id** matches this chain.
3. **Shape and fee floor** — a mint carries no bundle, everything else must; `asset = 0` and
   `burn = 0` in this release; `fee ≥ fee_floor(action)`.
4. **Anchor** — the bundle's anchor is one of the last `ANCHOR_WINDOW = 256` *block-end* roots. A
   root the tree only passes through mid-block is never an anchor.
5. **Time** — `time` is within `[height - 256, height]` (`TIME_WINDOW`).
6. **Nullifiers and commitments** — the two nullifiers differ and neither is in the spent set;
   the two commitments differ and neither is already a leaf.
7. **Action checks** — faucet enabled, mint under the 100 SHRUGG cap, minter is a validator and
   its signature verifies; program decodes (Deploy); program exists (Call).
8. **Bundle digest** — the ledger recomputes the digest from the bundle's published plaintext and
   it must equal what the proof published. A proof whose witness broke the relation publishes a
   tainted digest, which matches no plaintext.
9. **Bundle proof** — `Machine::verify` against the genesis-pinned `hc_bundle`.
10. **Call proof and its tier fee** — the call's own STARK against the program's `code_hash`, then
    `fee ≥ BUNDLE_BASE + call_fee(tier)`, which is only knowable once the tier is.

A block containing any invalid transaction is invalid. Two bundles in one block spending the same
nullifier fail at step 6, and the mempool never holds both in the first place: it indexes every
pending nullifier and commitment and refuses a conflict outright.

The windows are 256 blocks because proving takes real time: a tier-14 bundle proof measures about
100 seconds, and a chain making a block every two seconds gives such a proof roughly eight
minutes of anchor validity. On a faster chain a wallet can still lose the race, in which case the
node answers `anchor is not one of the last 256 roots` and the wallet reproves.

## 6. What still leaks

The pool hides amounts, senders and recipients. It does not hide everything, and the gaps are
worth naming.

- **Witness requests.** `shrugg_getWitness(index)` tells the node exactly which leaf a wallet is
  about to spend — the single largest leak in S1. A wallet that keeps its own copy of the tree
  never asks, and that (a local wallet tree) is the first follow-up. Until then: run your own
  node, or ask for witnesses you do not need alongside the ones you do.
- **Scanning.** `shrugg_getCommitments` hands out everything to everyone, so scanning itself
  reveals nothing about which leaves are yours — but it does tell the node that *somebody* at
  your IP is scanning, and how far. Trial decryption is local and the node never sees a viewing
  key.
- **Timing and the fee.** A transaction's fee is public, and the fee floors differ by action, so
  a watcher can tell a transfer from a deploy from a call. Submission timing links a bundle to
  whoever was connected to that node's RPC at that moment.
- **Deposits.** Mint and genesis alloc amounts are in the clear. The one-hop link from "100
  SHRUGG was minted" to "a note worth 100 SHRUGG exists" is unavoidable until value can enter the
  pool with a proof instead of a public amount.
- **The program.** A deployed program is public code, and `hc` is binding, not hiding: anyone who
  can enumerate candidate programs can confirm which was deployed.

### Disclosing on purpose

The envelope layer supports two grains of disclosure, and neither is something the chain can
compel:

- **A viewing key** (`nk`, derived from the spend key) opens *everything* that wallet has ever
  received — and, through the outgoing viewing key derived alongside it, everything it has ever
  sent, including the nullifier of each spend, so an auditor holding it can check a claimed
  history against the chain row by row. It cannot spend: producing a bundle needs the spend key.
  It is all-or-nothing, and it is retroactive and forward-looking at once.
- **A per-transaction key** (`TxKey`) opens exactly the one envelope it sealed, and nothing else
  — the right grain for "show me this payment" without handing over a history. Each envelope is
  sealed under a fresh one for precisely this reason.

In S1 the wallet derives the viewing key on every run and never stores it, and it draws each
`TxKey` fresh and drops it after sealing. So per-transaction disclosure is a property of the
format the chain already enforces, not yet a command the CLI offers; exporting either key is a
wallet change, not a chain change.

## 7. What is next

S1 is the pool itself. Two phases follow, each a hard fork (see spec §12):

**S2 — staking on the shielded chain.** The validator register gains `Bond`, `Unbond` and
`Withdraw`: stake moves in from a bundle, unbonds after two epochs of 1000 blocks, and a
validator's accumulated `rewards` (which S1 already credits on every bundle fee) become
withdrawable into a note at a payout address. `shrugg-node genesis` seeds the register. The
wallet's local commitment tree — the answer to the witness leak above — lands alongside it.

**S3 — the bridge, and private call inputs.** Bridged assets become notes with
`asset = <bridge asset id>`; `BridgeBurn` becomes the one two-bundle transaction (an asset bundle
that burns, and a SHRUGG bundle that pays the fee). Call inputs gain their own envelopes (spec
§6.1), so a caller can disclose what a program ran on without publishing it. `docs/bridge.md`
describes the bridge as it stood on the account chain; none of it is wired up here until S3.

Not scheduled yet: slashing and jailing, a nullifier accumulator to replace the per-block
recomputation of the nullifier root, and proof batching to amortize the ~16 ms warm verify.
