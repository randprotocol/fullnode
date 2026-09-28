# The shielded pool

Phase S1 replaced RAND's account ledger with a shielded note pool. There are no accounts, no
balances and no addresses-with-money on this chain: value exists only as **notes**, each one a
commitment in an append-only tree, and the only way to learn what a note is worth is to hold the
key that opens it.

This page is the user's guide to that: the keys, what the chain publishes and what it does not,
the wallet commands, the RPC surface, the order a node admits a transaction in, and what is
still leaked. The design spec is
`docs/superpowers/specs/2026-09-11-shielded-pool-design.md`; the wire-level reference is
`docs/rpc.md`; the confidential-computation half is `docs/confidential.md`. Staking, the one part of
this chain with public amounts, is `docs/staking.md`, and the audit that adds the two halves up is
`docs/supply.md`.

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
   └─ address       rand1 + base58(pk || kem_ek)     1668 characters
```

A **shielded address** is 32 bytes of `pk` plus the 1184-byte ML-KEM-768 encapsulation key
envelopes are sealed to, base58 after the `rand1` prefix — about 1.6 KB of text. It is public
by design: anyone may pay it, and holding it tells you nothing about what it holds.

The key file is version 2 and carries the spend key alone, because every other key above is a
pure derivation of it:

```json
{ "version": 2, "spend_key": "0101010101010101010101010101010101010101010101010101010101010101" }
```

`rand keygen` refuses to overwrite an existing file: there is no second copy of a spend key,
and overwriting one destroys every note it could still open. Next to it lives
`<key>.key.json.notes.json`, the note store — a cache of the notes this key has opened, every row
of which is recoverable by rescanning from leaf 0. It holds note plaintexts, so it is written
mode 0600 like the key itself.

The spend key is the only authority to spend. Under bundle guests v1 and v2 the bundle proof
itself takes `sk` as a private input. On a chain whose genesis names `hc_auth` (split
authorisation, v0.6.3, §2) the bundle proof takes only `nk`, and `sk` enters a second, tiny auth
proof the wallet always makes on its own machine — which is what lets a delegated prover
(`docs/prover.md`) prove a bundle without being able to spend. Addresses, keys and existing notes
are the same either way: `pk = H(PK, nk)` does not change.

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
  A genesis that sets `envelope_bytes: 1860` (spec 2026-09-26 §2.3–§2.4) grows the sealed body
  by a fixed 512-byte memo field — `len (u16 LE) ‖ UTF-8 text ‖ zero padding`, at most 510 bytes
  of text — so every note-creating envelope on that chain is exactly 1860 bytes whether or not it
  carries a memo: a dummy or change output is padded the same way, and nothing on chain
  distinguishes a memo, its length, or its absence. The memo is not in the note, the commitment,
  or any proof, and is readable by exactly whoever can already read the note: the owner (ML-KEM),
  the sender (`ovk`), or anyone handed that output's per-transaction key
  (`rand_checkTransaction`, `rand tx-key`). A malformed memo field (bad length, invalid UTF-8, or
  non-zero padding) opens as no memo — it never costs the owner the note itself. On a chain
  without `envelope_bytes` (chains 14 and 15) wallets keep sealing today's 1348-byte envelope and
  refuse a non-empty memo before proving, rather than silently dropping it — but that chain's
  ledger still accepts any envelope up to 2048 bytes, so a memo-carrying 1860-byte envelope from
  another sender is valid there and opens with its memo. A memo can be present on any chain, and
  is anyone's text: every wallet shows it through one display rule (`docs/cli.md`, "How a memo is
  shown").

Spending a note publishes its **nullifier** `H_NF(nk, cm)`, which is unlinkable to the
commitment without `nk`. The nullifier set is what prevents a double spend.

Every transaction that moves value carries exactly one **bundle**: since chain 14 the fixed
4-in-4-out hidden-asset shape proved by the pinned hidden-asset zkVM guest
(`docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md`). Slots 0–1 carry a *private*
asset `A`, slots 2–3 carry RAND; a dummy slot is a zero-amount note, so every bundle publishes four
nullifiers and four commitments whatever it moves.

```
Bundle { anchor, nullifiers[4], commitments[4], fee, burn_a, burn_r, burn_asset, time,
         envelopes[4], proof, auth_commit, auth_proof }     // the last two since v0.6.3
Transaction { chain_id, bundle: Option<Bundle>, action }
Action = None | Mint { .. } | Deploy { base_pc, words } | Call { program, proof, input_envelope }
       | Bond { validator, amount, registration } | Unbond { .. } | Withdraw { .. } // phase S2
       | BridgeAttest { attestation, recipient, r, time, asset, envelope }         // phase S3
       | BridgeBurn { asset, amount, relayer_fee, to_chain, token, to }
       | RegisterToken { .. } | TokenMint { .. } | SetAuthority { .. } | TokenBurn { asset, amount }
```

A note's `asset` word is `0` for RAND and otherwise the token registry's dense index
(`docs/bridge.md`). The asset a bundle moves is not public: a transfer of any asset is
`Action::None` with `burn_a = burn_r = burn_asset = 0`. Only a burn names an asset — a `TokenBurn`
or `BridgeBurn` bundle publishes `burn_asset == asset`, `burn_a == amount`, `burn_r == 0` — and
RAND leaves the pool only through `burn_r` (a `Bond`'s stake, a `RegisterAggregator`'s bond). The
three staking variants are on the wire but every one of them is still refused
(`UnsupportedAction`) until phase S2 lands.

The shape is fixed, so one input and one output are often dummies: a dummy input is a zero-value
note owned by the spender, and the change output is published even when the change is zero. A
transaction that looked different when there was no change would leak that there was none. (The
*transaction* looks the same; the bundle *proof* does not yet — it reveals which input slots are
real, see "What the proofs leak today" below.)

### Split authorisation: bundle guest v3 and the auth proof (v0.6.3, genesis `hc_auth`)

Spec `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4. A genesis cut with
`rand-node genesis --bundle-guest v3 --auth-guest` pins bundle guest v3 as `hc_bundle`
(`60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce`) and the auth guest as
`hc_auth` (`1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1`); the two come as a
pair, both ways. Every bundle on such a chain carries two proofs:

```
auth guest        private: sk, salt          nk = H(NK, sk);  c = H(AUTH, nk ‖ salt)
                  publishes c                proved against the transaction's binding
                  16 input words (auth::auth_input), tier 10

bundle guest v3   private: nk, salt, and v1's witness otherwise (hidden_input_v3: nk at 0,
                  salt at 1 204, 1 212 words)
                  pk_self = H(PK, nk);  every input owned by pk_self;  c = H(AUTH, nk ‖ salt)
                  digest = H(64, anchor, nf0..3, cm0..3, fee, burn_a, burn_r, burn_asset, time,
                             c, bad)
```

`AUTH` is the node-local domain tag 65 (`auth::AUTH_DOMAIN`). The v3 digest is v1's preimage with
the eight words of `c` inserted immediately before `bad` (`hidden_bundle_preimage_v3`); it keeps
tag 64, which is safe because the v1/v2 and v3 messages absorb a different number of sponge
blocks (21 against 23 permutations). The bundle publishes `c` as `auth_commit` and carries the auth
proof as `auth_proof`. The ledger (`Ledger::check_bundle_proof`):

- on a chain without `hc_auth` refuses any bundle whose `auth_commit` is not zero or whose
  `auth_proof` is not empty (`AuthUnexpected`), and recomputes the v1 digest, byte for byte as
  before;
- on a chain with it, before the bundle digest: refuses a bundle without an auth proof
  (`AuthMissing`), decodes the auth proof at the auth guest's pinned shape (`InvalidAuthProof`)
  and requires the `c` it publishes to equal `auth_commit` (`AuthMismatch`); then recomputes the
  v3 digest (with `auth_commit`) against the bundle proof, verifies the bundle proof, and finally
  verifies the auth proof against `hc_auth` and the **same** transaction binding, its `c` again
  equal to `auth_commit`.

All four refusals are permanent. A pruned bundle keeps its auth proof — the covering aggregate
does not stand in for it — and the sync path verifies it there too.

What this buys: a prover holding `nk` and the salt can make the bundle proof but not an auth proof
for it, and an auth proof is bound to one transaction's binding, so it cannot be moved onto
another. A witness with another key's `nk` taints the bundle proof, whose digest then matches no
plaintext. The salt is 256 fresh random bits per bundle, drawn by the wallet: a repeated salt
would repeat `c` and link two transactions to one wallet, and the guest cannot tell — so
`auth_commit` is public but, with a fresh salt, links nothing. A wallet that proves for itself
makes both proofs too: one shape for every transaction, so a self-proved and a delegated one look
the same on chain.

The transaction id moved with it: `rand-txid-3` hashes `auth_commit` as is and the auth proof by
its digest, like the bundle proof, so the pruned marker form still hashes to the raw id; the
transaction binding blanks both proofs and keeps `auth_commit`. Every transaction id changes, and
the bundle wire gained the two fields — so the build that carries them (v0.6.3) runs chain 17 on
and refuses chains 14–16 at startup (`node::CHAINS_THIS_BUILD_CANNOT_RUN`).

The cost is size: the auth proof is about 1.37 MB at Production FRI, so a transfer carries about
2.85 MB of proof (1.49 MB of it the bundle proof, in one measured run) — one per block at the 4 MiB
default (spec §4.2). The soundness evidence is in
`docs/confidential.md` ("The hidden-asset bundle guest: soundness").

### What is public and what is hidden

| | public on chain | hidden |
|---|---|---|
| **transfer** (`Action::None`) | anchor, all four nullifiers, all four commitments, fee, `burn_a = burn_r = burn_asset = 0`, `time`, four envelope ciphertexts, the bundle proof (and on a split-authorisation chain `auth_commit` and the auth proof, both unlinkable under a fresh salt) — **and, under the v1 guest chains 14 and 15 run, read off that proof: which input slots are real and the popcount of each spent leaf index** (see "What the proofs leak today", below, and §6, "The bundle proof's instruction counts") | who sent it, who is paid, the amount, the change, which leaves were spent (beyond their popcounts under v1); which asset only partly under v1 — the real-slot pattern tells a RAND bundle from a token one. Under the branch-free guest (v2), selected by a later genesis's `hc_bundle`, which asset moved and which slots were dummies are hidden too |
| **Deploy** | everything above, plus `base_pc` and the program's words (so the program id and its code) | who deployed it, and what the paying notes were worth |
| **Call** | everything a transfer publishes, plus the program id, the call proof, and the receipt's tier and eight output words — **and, read off the call proof, what its small committed tables hold** (see below) | registers, memory, the real cycle count (only the padded tier shows), who called it; the private inputs and the branches taken only as far as "What the proofs leak today" allows |
| **Mint** (faucet) | the new note's commitment, its envelope, the **amount in the clear**, the recipient's `pk` and the note's `time`/`r` (POOL-1: the commitment opening, checked by the ledger, not merely declared), and the minting validator's public key (shown as its address) and signature | which notes the recipient later spends and to whom — the address that received a mint is now public, but nothing about its later use is |
| **BridgeAttest** | the attestation (so the source chain, the token, the **amount**, the recipient's address hash and the guardian signatures), the recipient's shielded address, the deposit note's `asset` index, `r` and `time`, and the fee bundle | which notes paid the fee, and everything about the deposit note's later spend |
| **BridgeBurn** / **TokenBurn** | the asset index, the **amount**, the relayer fee and the destination chain and address (`BridgeBurn` only), and the one bundle's public fields (`burn_a`, `burn_asset` equal the amount and asset) | which notes were burned, and who burned them |

### What the proofs leak today (the 2026-09-27 zkVM/ISA review)

The table above is what the protocol publishes on purpose. Two findings of the 2026-09-27 review
(`INT-1` family and `INT-2`/`GV-1`, both High, both live on chain 15) show the proofs themselves
disclose more, and until the next chain cut they do:

- **Every bundle proof reveals which of its four input slots are real, and the popcount of each
  spent note's leaf index** (INT-2 / GV-1). The batch STARK publishes each table's LogUp running
  total unblinded, and the hidden-asset guest takes a different branch for a dummy input than for a
  real one and walks each Merkle path bit by bit — so the per-table totals separate the real slots
  from the dummies (in particular, whether slots 0–1 spend anything, i.e. whether the bundle moves
  a token or only RAND) and count the one bits of every spent index. The review recovered both
  uniquely, at the Test and the Production profile. So a transfer's *asset class* (RAND or a token,
  not which token) and a coarse fingerprint of *which leaves* it spends are public today; who, how
  much, and which token stay hidden. The dummy slots are **not** indistinguishable from real ones,
  whatever an earlier version of this page said.
- **A small committed table of a call proof is readable from its openings** (INT-1, COV-2, INT-6,
  HCS-3). The proof opens every table at 80 FRI query points plus two out-of-domain points, and a
  table is hiding only while it has more random rows than that; below 2^7 rows the openings
  determine it. So a call proved by a wallet older than v0.6 with 31 or fewer private words carries
  its private inputs in the proof (its input table is 2^3–2^5 rows), a one-permutation keccak call
  carries its hashed secret, and 64-row tables leak Boolean and small-count columns by lattice
  reduction. The **program table** of every program under 64 words — all 105 programs on chain 15
  are 43 words — publishes its per-instruction fetch counts, i.e. the call's control flow. The
  declared hash-table heights (`keccak_log_height`, `sha256_log_height`) say whether a call hashed
  and roughly how often.
- **A call's LogUp totals are a public function of its private inputs, so low-entropy inputs can
  be brute-forced from them** (INT-2 on calls; the v0.6 rescan). The same unblinded terminals as
  the bundle item above: the input table's is the sum over its rows of one term per committed
  `(index, word)` pair — every word on the tape, read or not — and the challenges come from public
  transcript data, so anyone holding the proof and the program can compute the total a *candidate*
  input list would produce and compare. It is unsalted: `H_IN`'s salt enters the digest, not this
  sum. The 2^7 table floor does not help — it hides the table's rows from the openings, not the
  total, which is computed over the raw trace before any hiding. So a call whose private inputs are
  a few small words — an amount under a million, a PIN, a handful of flags — is a search of millions
  to billions of candidates, the size the review ran for the bundle leak (there the true witness was
  the unique match among 1.3 million). High-entropy inputs (keys, 256-bit secrets, random
  blindings) are out of reach.
  **Until the fix, a program that takes low-entropy private inputs should also take at least two
  uniformly random private words (four for 128 bits) and read them into the computation** — padding
  the tape alone masks the input table's own total, but the cpu and memory tables' totals depend on
  the words the program reads and what it does with them, so the salt must pass through the same
  tables the secret does. The generic fix is LogUp blinding (a random masking term in every
  table's total), which changes every verifier key and so is chain 16's.
- **The branch-free bundle guest (v2) still has two witness-dependent traces, both on the Merkle
  path bit** (the v0.6 rescan). v2's address swap writes each path cell from `sw SA` or `sw NA`,
  one clock apart depending on the bit, so (1) the memory table's access timestamps and (2) the
  range-check histogram of timestamp differences both depend on every spent input's leaf-index bits
  — in principle more than v1's popcount, a function of the bits themselves. Both enter LogUp
  totals that also sum over secret hash words (the note secrets and sibling hashes the same tables
  carry), which is why the rescan judged them unrecoverable by the candidate search above; that is
  a judgement, not a measurement — the rescan did not quantify them, and v2's
  witness-independence test compares access counts per address, not timestamps. LogUp blinding
  closes both.

What is already fixed, and what needs the cut:

- v0.6's prover floors the input, keccak and sha256 tables at 2^7 rows, and every v0.6 node's pool
  refuses a call proof that does not (`CallRevealsPrivateInputs`) — no cut needed, but calls already
  committed on chain 15 stay exposed for ever.
- The program table can only be floored when the chain stops pinning its height to the deployed
  record's: that is genesis `hardening_v6` (the next cut), under which wallets prove, and nodes
  require, a floor of 2^7 rows (`docs/deploy.md`, "The program-table floor").
- The bundle's real-slot and popcount leak needs a circuit change — LogUp blinding, or a
  branch-free bundle guest whose trace does not depend on which slots are dummies — and so a chain
  cut with a new `hc_bundle`. It is not fixed on chain 15. v0.6 carries the branch-free guest (v2,
  `rand-node genesis --bundle-guest v2`), which removes the real-slot and popcount leak and leaves
  the two Merkle-bit residuals above.
- A call's input totals, and v2's residuals, need LogUp blinding — a verifier-key change, due
  with chain 16's other key changes. Until then the only mitigation is the program's own random
  salt words, above.

A `Call`'s `input_envelope` is the one optional publication in that table: the call's private inputs,
sealed so that the caller, a per-call key, or a named auditor can open them later
(`docs/confidential.md` §call input envelopes). The chain checks only its size.

A mint is how value enters the pool at all, and its amount is public by design (spec §6: the same
one-hop visibility Zcash's t→z has), and since chain 14 (POOL-1) so is its recipient: the ledger
recomputes the note's commitment from the action's own `pk`, `time` and `r` rather than trusting a
declared `cm`. Genesis deposit notes on a `tokens`-genesis chain carry the same opening, for the
same reason (core review I-2): `alloc` in `genesis.json` carries `{ cm, envelope, amount, opening? }`
where `opening` is `{ pk, time, r }`, **required** when the genesis has a `tokens` section (optional,
and usually absent, otherwise) — `rand-node init` recomputes the commitment at asset 0 from it, so
everyone can add up the initial supply and see who it belongs to. A pre-chain-14 genesis with no
`tokens` section keeps the older, opaque `{ cm, envelope, amount }` form.

The fee is public too, and paid to the block proposer's `rewards` field in the validator register
— the one place on this chain where an amount is stored in the clear.

Staking is the deliberate exception to all of the above, and it has its own page. A `Bond` publishes
the validator and the amount, and takes the stake out of the pool as its bundle's `burn`; an
`Unbond` and a `Withdraw` are signed by the validator's own key and carry no bundle at all; a
`Withdraw` pays released stake and rewards back into a deposit note at the register's published
payout address. What stays hidden is which notes paid for a bond, and what becomes of a withdrawn
note afterwards. See `docs/staking.md`, and `docs/supply.md` for the audit that ties the register and
the pool back together.

## 3. The wallet

`rand` talks to a node's JSON-RPC and does all the private work locally. Global options:
`--rpc` (`RAND_RPC`, default `http://127.0.0.1:8545`) and `--key` (`RAND_KEY`, default
`wallet.key.json`).

| command | what it does |
|---|---|
| `rand keygen` | write a new spend-key file; refuses to overwrite |
| `rand address` | print this wallet's `rand1…` address |
| `rand balance` | scan, then print what this wallet can spend |
| `rand sync` | scan without printing a balance |
| `rand notes` | every note this wallet has opened, with `spent` and `pending` |
| `rand history` | every note this wallet created for someone else |
| `rand send <TO> [AMOUNT]` | select, prove a bundle, submit, wait for the commit (`AMOUNT` may come from a `randpay:` link) |
| `rand bond <VALIDATOR> <AMOUNT>` | stake onto a validator: the bundle burns the amount (`docs/staking.md`) |
| `rand faucet [ADDRESS]` | ask a validator to mint (testnet chains only) |
| `rand program build/deploy/show` | assemble, deploy (paid by a bundle), inspect a program |
| `rand call <PROGRAM>` | prove a call locally, pay through a bundle, print the receipt |
| `rand open-call <TX>` | open a committed call's input transcript and check it against its `H_IN` |
| `rand receipt <TX>` | the receipt of a committed call |
| `rand asset-balance [INDEX]` | what this wallet holds in a bridged asset, or a row per asset |
| `rand bridge-mint <ATTESTATION> --pq <QUORUM>` | deposit a guardian-signed attestation as a note, with its Dilithium2 co-signatures; one RAND fee bundle |
| `rand bridge-rotate <ROTATION> --pq <QUORUM>` | submit a guardian-set rotation with the PQ quorum; one RAND fee bundle |
| `rand bridge-pause --sig <SIG>` / `rand bridge-unpause --pq <QUORUM>` | pause or lift bridge minting; bundle-less, fee-less, no key file |
| `rand token register-bridged … --pq <QUORUM>` / `rand token list-backing … --pq <QUORUM>` | list a bridged token or a new backing after genesis; one RAND fee bundle |
| `rand token create --name … --symbol … --decimals … (--fixed-supply <N> --to <ADDR> \| --authority-key-out <FILE> [--initial <N> --to <ADDR>])` | register a token (RPL spec §4) at the next index — fixed supply or `Key`-authorised (a fresh Dilithium2 key file, `rand-node keygen`'s shape); one RAND fee bundle |
| `rand token mint --asset <A> --to <ADDR> --amount <N> --authority-key <FILE>` | mint more of a `Key`-authorised token, signed by its authority; one RAND fee bundle |
| `rand token set-authority --asset <A> --authority-key <FILE> (--new-key <FILE> \| --renounce)` | hand a `Key`-authorised token to another key, or renounce minting for good |
| `rand token info <A>` / `rand token list` | a token's public row, or every token's, from the whole `rand_getTokens` listing |
| `rand bridge-burn <ASSET> <AMOUNT> <CHAIN> <TOKEN> <TO>` | burn a bridged asset outbound; one bundle burns the asset and pays the RAND fee |
| `rand bridge` / `rand bridge-message <SEQ>` | the bridge's public state; one outbound message |
| `rand fee bundle\|deploy <words>\|call <tier>` | the schedule's floor |
| `rand tx/block/head/status/peers/validators` | plain chain reads |

```bash
rand keygen                                      # wrote wallet.key.json
rand address                                     # rand1x7Qk…  (1668 characters)
rand faucet                                      # 100 RAND into a note only you can open
rand sync                                        # scanned 41 leaves and 37 blocks; 1 notes, 1 unspent
rand balance                                     # balance: 100 RAND / notes: 1 unspent
rand notes
#    index              amount    height    spent  pending
#       40                 100        37    false  -
rand send rand1q9f… 1.5                        # proves ~100 s, then waits for the commit
rand history                                     # what this wallet has paid out
rand fee call 14                                 # 0.0022 RAND
rand program build --guest private_payment --arg 1000 --out pp.json
rand program deploy pp.json                      # a bundle pays the deploy floor
rand call <program id> --input 400 --input 250 --input 300 --input 75
rand receipt <tx hash>
```

`send` prints what it did and nothing about anyone else:

```
proving bundle (tier 14; about a minute on a laptop)…
proved in 98.3s: tier 14, 302857 bytes
submitted transfer 4f2c…  1.5 RAND out, 98.499 RAND change, fee 0.001 RAND, anchored at height 192
balance: 98.499 RAND
```

Three things to know about spending:

- **Each of a bundle's two groups spends at most two notes.** A RAND payment (or a bond, a
  deploy, a call) uses only slots 2–3, so it spends at most two RAND notes, as before chain 14. A
  token transfer or burn spends up to two notes of the token in slots 0–1 *and* up to two RAND
  notes in slots 2–3 for the fee. If either group's value is spread over three or more notes, no
  amount of dust adds up to a third input slot in that group — the wallet says
  `need more than two notes; the largest two hold N units — consolidate first`. Consolidating is
  a `send` to your own address.
- **`--no-wait`** returns as soon as the node accepts the bundle. The inputs are then marked
  `pending` rather than spent: not spendable, but not written off either. The next `sync`
  resolves it — the nullifier appeared, or the blocks the wallet has read reach past
  `time + TIME_WINDOW` (256 blocks), after which that bundle can never be admitted and the note
  is spendable again. Every `sync` reads up to the head it saw when it started, whether or not
  those blocks spent anything, so the second condition arrives on a quiet chain too. That head,
  and therefore the moment a pending note clears, is whatever the node the wallet points at
  reports: a node that lies about its head can make the wallet retry a spend the chain will
  refuse as spent, never lose funds.
- **The fee floor is 0.001 RAND** for a transfer, plus the action's own floor for a deploy or a
  call. `rand fee` asks the node rather than guessing.

## 4. RPC

Full parameter and error detail is in `docs/rpc.md`; this is the shielded subset with one example
each. Every example is one HTTP POST of
`{"jsonrpc":"2.0","id":1,"method":…,"params":…}` to the node's `/`.

**`rand_getTreeInfo`** — how far a wallet still has to scan.

```json
→ {"method":"rand_getTreeInfo","params":[]}
← {"next_index": 41, "root": "6b1d…c4", "nullifiers": 12}
```

**`rand_getCommitments(from_index, limit)`** — a page of leaves, oldest first, at most 1000 per
call. This is the whole of a wallet's scan: every leaf and every envelope go to everyone, and
only a viewing key tells them apart.

```json
→ {"method":"rand_getCommitments","params":[40, 500]}
← [{"index": 40, "cm": "2a9f…07", "height": 37,
    "envelope": {"kem_ct": "b41c…", "to_receiver": "77e0…", "to_sender": "0c31…", "body": "9dd2…"}}]
```

**`rand_getNullifiers(from_height, limit)`** — what has been spent, by block.

```json
→ {"method":"rand_getNullifiers","params":[0, 500]}
← [{"height": 37, "nullifier": "8c04…d1"}, {"height": 41, "nullifier": "12be…9a"}]
```

**`rand_getAnchor([height])`** — the tree root a prover may build against. With no parameter it
serves the head, which is the only anchor a wallet should use.

```json
→ {"method":"rand_getAnchor","params":[]}
← {"height": 192, "root": "6b1d…c4"}
```

**`rand_importViewingKey(nk[, rescan_from_height])`** and **`rand_getViewingNotes(nk[, from_index, limit])`** —
the explorer's path: hand the *node* a viewing key (in memory, capped at 64, gone at restart) and
it scans on the holder's behalf, the Zcash `z_importviewingkey` analogue. This is the one
exception to "the node never holds a key"; see §6.

```json
→ {"method":"rand_importViewingKey","params":["0c31…9e", 0]}
← {"imported": true, "rescan_from_height": 0, "viewing_keys": 1}
→ {"method":"rand_getViewingNotes","params":["0c31…9e"]}
← {"scanned_index": 41, "next_index": 41, "complete": true,
   "notes": [{"index": 40, "cm": "2a9f…07", "height": 37, "role": "received",
              "note": {"pk": "…", "from": "…", "amount": "100000000000", "asset": 0, "time": 5},
              "nullifier": "8c04…d1", "spent": false}]}
```

**`rand_getWitness(index)`** — the Merkle path of one leaf, leaf-first, 32 levels. `null` past
the end of the tree. See §6: this is the one request that says something about the caller, which
is why a current wallet never makes it — the method stays for wallets built before the local
tree.

```json
→ {"method":"rand_getWitness","params":[40]}
← {"index": 40, "root": "6b1d…c4", "path": ["0000…00", "f2a1…3b", … 32 entries …]}
```

**`rand_sendTransaction(hex)`** — `bincode(Transaction)` as hex. Returns the transaction hash;
acceptance is not commitment, so poll `rand_getTransaction`.

```json
→ {"method":"rand_sendTransaction","params":["0700000000000000012a9f…"]}
← "4f2c8b31…e7"
```

**`rand_mint(address[, amount])`** — the testnet faucet, on chains whose genesis says
`"faucet": true`. The node signs the mint with its own validator key; an observer answers
`faucet mints are signed by validators; ask a validator node`.

```json
→ {"method":"rand_mint","params":["rand1x7Qk…", "100000000000"]}
← "9ab1c0…4f"
```

**`rand_getTransaction(hash)`** — what an explorer can say, which is almost nothing:

```json
← {"height": 192, "index": 0, "block_hash": "63f6…08",
   "tx": {"hash": "4f2c…e7", "chain_id": 7,
     "bundle": {"anchor": "6b1d…c4",
                "nullifiers": ["8c04…d1", "5e77…20", "03aa…6f", "e19b…42"],
                "commitments": ["2a9f…07", "b310…88", "77c1…0e", "5d20…b3"],
                "fee": "1000000", "burn_a": "0", "burn_r": "0", "burn_asset": 0, "time": 5,
                "proof_len": 1431562, "envelope_len": [1380, 1380, 1380, 1380]},
     "action": {"kind": "none"}}}
```

Since chain 14 the bundle always has four slots (dummies included) and no public `asset` field —
slots 0–1 carry a private asset, slots 2–3 RAND, and a transfer of any RPL token is `"kind":
"none"`, the same shape as a RAND payment (`docs/rpc.md`'s `rand_getTransaction`, `docs/tokens.md`).

There is no `from`, no `to`, no `nonce` and no amount in that reply, and there is nothing in the
stored block either — the node has nothing more to redact.

**`rand_checkTransaction(hash, key)`** — the other side of that redaction, for exactly one key
holder: what does this `TxKey` disclose about this transaction. Stateless (the key is dropped
with the call), and a wrong key is indistinguishable from one that sealed nothing.

```json
→ {"method":"rand_checkTransaction","params":["4f2c…e7", "77e0…1b"]}
← {"tx": "4f2c…e7", "height": 192,
   "disclosed": [{"output": "bundle:0", "cm": "2a9f…07", "index": 40,
                  "note": {"pk": "…", "from": "…", "amount": "1500000000", "asset": 0, "time": 5}}]}
```

## 5. How a node admits a transaction

Cheap before expensive, in this exact order (`Ledger::validate_inner`, spec §7). The mempool runs
the same check before gossiping, so a bad transaction is refused once, at the edge.

1. **Size caps** — the whole transaction ≤ `max_block_bytes`, each of the bundle's four envelopes
   ≤ 2048 bytes, the bundle proof ≤ `max_proof_bytes` (2 MiB by default, `gas::MAX_PROOF_BYTES`),
   a program ≤ `max_program_words`, a call proof ≤ `max_proof_bytes` too, and the same for a
   `Mint`'s or an `Aggregate`'s envelope and an `Aggregate`'s own proof and wire size. The sealed
   (pruned) marker form is refused here outside sealed-form sync (`PrunedFormOutsideSync`), before
   any proof work.
2. **Chain id** matches this chain.
3. **Shape and fee floor** — a mint, an `Unbond` and a `Withdraw` carry no bundle and everything
   else must carry exactly one, the hidden-asset bundle (chain 14): `check_burn_shape` fixes which
   of the bundle's three burn fields (`burn_a`/`burn_r`/`burn_asset`) the action may set — a
   `TokenBurn` or `BridgeBurn` must burn its own `asset`/`amount` through `burn_a`/`burn_asset`, a
   `Bond` or `RegisterAggregator` must burn its bonded amount through `burn_r`, and every other
   action burns nothing; `fee ≥ fee_floor(action)` — zero for the bundle-less actions, since they
   have nothing to pay a fee *from*.
4. **Anchor** — the bundle's anchor is one of the last `ANCHOR_WINDOW = 256` *block-end* roots. A
   root the tree only passes through mid-block is never an anchor.
5. **Time** — `time` is within `[height - 256, height]` (`TIME_WINDOW`).
6. **Nullifiers and commitments** — all four nullifiers differ from each other and none is in the
   spent set; all four commitments differ from each other and none is already a leaf.
7. **Action checks** — faucet enabled, mint under the 100 RAND cap, minter is a validator and
   its signature verifies; program decodes (Deploy); program exists and the input envelope is
   within its own cap (Call); for the staking actions the rules of `docs/staking.md` — a
   registration present exactly when the validator is unknown, the register's nonce and the
   validator's signature, enough stake to unbond, enough released to withdraw, and the deposit note
   a withdraw derives not already in the tree; the bridge's own rules for `BridgeAttest`/
   `BridgeBurn` (`docs/bridge.md` §5) and for the pause/listing actions (`docs/bridge.md`'s v0.5
   section); and RPL's rules for its four actions (`docs/tokens.md`) — all of it before the
   bundle's proof, so a transaction that cannot apply costs no STARK verification.
8. **Bundle digest** — the ledger recomputes the digest from the bundle's published plaintext and
   it must equal what the proof published. A proof whose witness broke the relation publishes a
   tainted digest, which matches no plaintext. On a split-authorisation chain (§2) the auth fields
   are checked first — present exactly when the genesis names `hc_auth`, and the `c` the auth proof
   publishes (read, not yet verified) equal to `auth_commit` — and the digest is the v3 one, with
   `auth_commit` inside.
9. **Bundle proof** — `Machine::verify_public` against the genesis-pinned `hc_bundle` and the
   transaction's binding (`Transaction::binding`: a hash of the whole transaction with every proof
   blanked, eight words the proof carries as its public input). This is what keeps a proof from
   being copied onto a changed transaction — another action, another envelope, another chain id
   (`docs/confidential.md`, "Transaction binding"). On a split-authorisation chain the auth proof
   is verified next, against `hc_auth` and the same binding.
10. **Call proof and its tier fee** — the call's own STARK against the program's `code_hash`, then
    `fee ≥ BUNDLE_BASE + call_fee(tier)`, which is only knowable once the tier is.

A block containing any invalid transaction is invalid. Two bundles in one block spending the same
nullifier fail at step 6, and the mempool never holds both in the first place: it indexes every
pending nullifier and commitment and refuses a conflict outright.

The windows are 256 blocks because proving takes real time: a tier-14 bundle proof measures about
100 seconds, and a chain making a block every two seconds gives such a proof roughly eight
minutes of anchor validity. On a faster chain a wallet can still lose the race, in which case the
node answers `anchor is not one of the last 256 roots` and the wallet reproves.

Since the transaction binding (chain 14) the wallet builds the whole transaction — outputs,
envelopes, action — *before* it proves, because each bundle's proof commits to all of it. A wallet
built before that fork proves against the empty public segment and is refused; every wallet must
run the new `rand` at the fork.

## 6. What still leaks

The pool hides amounts, senders and recipients. It does not hide everything, and the gaps are
worth naming.

- **Witness requests — closed.** `rand_getWitness(index)` used to tell the node exactly which
  leaf a wallet was about to spend — the single largest leak in S1. The wallet now keeps its own
  copy of the commitment tree, built during the scan from the same `rand_getCommitments` pages it
  already reads, and computes every witness itself: a send never calls `rand_getWitness`, and the
  only tree question left is `rand_getAnchor`, which names no leaf (audit v3 PRIV-1). The method
  stays on the node for wallets built before this change.
- **Scanning.** `rand_getCommitments` hands out everything to everyone, so scanning itself
  reveals nothing about which leaves are yours — but it does tell the node that *somebody* at
  your IP is scanning, and how far. Trial decryption is local and, on that path, the node never
  sees a viewing key. The exception is the explorer's import below: a node an operator handed a
  viewing key to knows exactly which leaves that key opens — which the key's holder could have
  computed anyway — and the IP of whoever asked it to.
- **Timing and the fee.** A transaction's fee is public, and the fee floors differ by action, so
  a watcher can tell a transfer from a deploy from a call. Submission timing links a bundle to
  whoever was connected to that node's RPC at that moment.
- **Deposits.** Mint, genesis alloc and bridge-deposit amounts are in the clear, and a bridge
  deposit also publishes its asset and the recipient's shielded address in that one transaction.
  The one-hop link from "100 RAND was minted" to "a note worth 100 RAND exists" is unavoidable
  until value can enter the pool with a proof instead of a public amount. A bridge *burn* leaks the
  same way on the way out, and deliberately: the guardians releasing on the other chain need the
  amount and the destination.
- **The program.** A deployed program is public code, and `hc` is binding, not hiding: anyone who
  can enumerate candidate programs can confirm which was deployed.
- **The bundle proof's instruction counts (INT-2 / GV-1) — live on chains 14 and 15, closed by
  the branch-free guest at the next cut.** Every proof carries one LogUp total per table,
  unblinded, and the program table's is a public linear function of how many times each
  instruction ran. The v1 hidden-asset guest (`guests::bundle_hidden`, `hc_bundle` `83d3a370…`)
  skips the Merkle and asset checks for a dummy input and takes a different branch for a left
  and a right Merkle child, so from any v1 bundle anyone can read **which of the four input slots
  are real** — and so whether it moved a token (a RAND payment keeps slots 0–1 dummy) — and **the
  number of 1 bits in each spent note's leaf index** (the 2026-09-27 zkVM review's
  `audit_logup_leak` recovered the true pattern uniquely among 1.3 million candidates). Amounts,
  owners, the asset id and the leaves themselves stay hidden.

  The fix is a second guest, **`guests::bundle_hidden_v2`** (`hc_bundle`
  `651043e2ff2fef28df2d8edbdbbc387668577af72dcc584ee7d850e093a2839b`): the same relation, the same
  1 204-word witness and the same published digest (so the ledger, the wallet's plaintext and
  every digest check are unchanged), with an instruction trace that does not depend on the
  witness. Every slot, dummy or real, runs the full Merkle membership and asset check, and the
  failure bit is masked by the slot's realness in arithmetic (`bad |= real & fail`, `real` taken
  from the same registers that feed the conservation sums, so a note carrying value is never
  exempt); the Merkle step writes the running node and the sibling to two fixed slots chosen by
  address arithmetic on the index bit, the same instructions for a left and a right child. Its
  only branches are counted loops over program constants. `tests/hidden_bundle.rs` checks that
  honest witnesses differing in real/dummy slots, RAND/token and leaf-index popcounts run
  identical per-instruction fetch counts (the program table's `MULT`, from which that total is
  computed), syscalls, input reads per index, memory and ALU event counts and table heights —
  and that v1's differ — and the whole cheating suite (`tests/hidden_cheating.rs`, the fuzz
  included) runs both guests and requires the same digest from each. v2 proves at tier 14 at v1's
  declared heights, so one verifier key serves both, and costs every witness about what v1's
  four-real-input bundle did (12 272 cycles against v1's worst 14 242).

  **v2 takes effect only on a genesis whose `hc_bundle` names it** — the next chain cut. A node
  build carries both guests and runs a genesis naming either (`node::check_build_runs_genesis`
  refuses any other digest); a wallet proves the guest `rand_status`'s `hc_bundle` names and
  refuses a chain whose guest it does not carry. Chains 14 and 15 stay on v1, and every bundle
  already on them keeps what it leaked.

  What v2 does not hide is the part of INT-2 that is not about control flow: a table whose
  lookups are indexed by *values* (the range and nibble tables, the memory and input tables) has a
  total that is a function of the private values themselves. For a bundle those values are
  dominated by keys and hash outputs, where the review found nothing recoverable, but the general
  fix — blinding each table's total in the proof system — is a constraint change for every
  program, not a guest change, and is not done (the review's R3, its second half; a chain cut).

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
  sealed under a fresh one for precisely this reason. `rand_checkTransaction(hash, key)` makes
  the check one stateless RPC call for whoever holds the pair (Monero's `check_tx_proof` shape):
  what comes back is the note the key sealed, bound to its on-chain commitment and leaf.

In S1 the wallet derives the viewing key on every run and never stores it, and it draws each
`TxKey` fresh and drops it after sealing. Since the RPC-hardening work a *node* may also be
handed a viewing key: `rand_importViewingKey` imports one (in memory only, capped at 64 keys,
cleared at restart — deliberately never on disk) and `rand_getViewingNotes` serves what the
node's scan found, the Zcash `z_importviewingkey` shape an explorer such as RandScan needs.
That is the one place "the node never holds a key" stops being true, and it is a property of an
explicit operator decision, scoped to that node: the RPC layer has no type for a spend key, so an
imported key can disclose notes but never move them, and a port that has seen an import should be
treated as key-bearing. Both keys can now leave the wallet on the holder's say-so: `rand viewing-key` prints `nk`, and
`rand tx-key <hash>` prints each of a transaction's output keys this wallet can open — recovered
from the chain, since every envelope carries its key under the sender's `ovk` and under the
receiver's KEM secret, so nothing had to be stored when it was sealed.

Phase S3 added the same two grains for *computation*, and these the CLI does offer: a call may
publish its private inputs as a sealed transcript, openable by the caller's viewing key, by a
per-call key (`--print-call-key`), or by an auditor named when the call was made (`--auditor`), and
`rand open-call` checks the opened transcript against the `H_IN` the proof published and re-runs
the program on it, and exits non-zero rather than believing it if either check fails. `--no-envelope` publishes nothing at all, which is irreversible: once the salt is
gone, nobody can open that call. See `docs/confidential.md` §call input envelopes.

## 7. What is next

S1 was the pool itself. Two phases follow it, each a hard fork (see spec §12), and both are in this
release — S3 landed first, which is the order they arrived in, not the order they were planned in:

**S2 — staking on the shielded chain: here.** The validator register gained `Bond`, `Unbond` and
`Withdraw`: stake moves in from a bundle as its `burn`, unbonds over two epochs, and a validator's
accumulated `rewards` (which S1 already credited on every bundle fee) are withdrawable into a note at
its payout address. Epochs re-derive the validator set from the register, `rand-node genesis` seeds
it, and `rand_getSupply` audits the pool against it. The whole of it is `docs/staking.md` and
`docs/supply.md`. What S2 did **not** bring is the wallet's local commitment tree — the answer to the
witness leak in §6; that has since landed on its own (audit v3 PRIV-1), and every current wallet
computes its witnesses itself.

**S3 — the bridge, and private call inputs — has landed.** A bridged asset is a note whose `asset`
word is the registry's index for it; `BridgeAttest` deposits one note that the *chain* computes from
the amount the guardians signed; `BridgeBurn` burns the asset from one hidden-asset bundle
(its slots 0–1) that also pays the RAND fee (slots 2–3); before chain 14 it carried two bundles. Call inputs have their own envelopes
(spec §6.1), so a caller can disclose what a program ran on without publishing it. `docs/bridge.md`
and `docs/confidential.md` are the references; a chain turns the bridge on with a `bridge` section in
its genesis, which is a hard fork for the chains that take it and a no-op for the ones that do not.

Not scheduled yet: slashing and jailing, a nullifier accumulator to replace the per-block
recomputation of the nullifier root, and proof batching to amortize the ~16 ms warm verify.
