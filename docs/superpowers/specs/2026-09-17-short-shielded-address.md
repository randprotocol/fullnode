# Short shielded addresses — the receiver id and the receiver record

Status: **draft for the user's review, 2026-09-17.** Nothing here is implemented.

Design: Anish Mohammad (https://github.com/zeroknowledge), 2026-09-16 — "give users a short,
stable RAND address; keep the large encryption key behind the scenes; a ~256-bit receiver id
that points to an updatable, receiver-authorised record (note public value + current ML-KEM-768
key); the record reaches a sender either inline with a payment request or by lookup; the wallet
verifies the receiver authorised it, never trusting whoever supplied it." The user's rulings of
2026-09-17: (1) the record is signed by the wallet's existing spend key, no separate signing key
to manage; (2) registry lookups are served by the explorer.

Related: `docs/shielded.md` (notes, envelopes, the wallet), `docs/bridge.md` §10 (the 32-byte
recipient hash the bridge already uses), `docs/staking.md` (payouts in register state),
`docs/rpc.md`, `../randscan/docs/api.md` (the explorer's API conventions), the notes module
(`crates/randprotocol-zkvm/src/notes.rs`: `SpendKey`, `ViewingKey`), `crates/randprotocol-core/src/notes.rs`
(`ShieldedAddress`, `Envelope`), `crates/randprotocol-client/src/wallet.rs`.

## 0. Summary

Today a shielded address is `rand1` + base58(`pk` ‖ `kem_ek`): 32 + 1,184 bytes, **1,667
characters**, no checksum. The ML-KEM-768 encapsulation key is there because a sender needs it
to seal the note envelope, and nothing else in the system needs it in the address.

After this spec:

| | today | after |
|---|---|---|
| address | 1,667 chars, `rand1` + base58(pk ‖ kem_ek) | **54 chars**, `rand1` + base58(id ‖ checksum) |
| what the address is | the record itself | a 32-byte **receiver id** = blake3(receiver signing key) |
| where the KEM key lives | in the address | in a signed, versioned **receiver record** |
| how a sender gets the record | from the address | inline with a payment request, or from the explorer's registry |
| how a sender trusts it | implicitly | two checks: blake3(record.signing_key) == id, and the Dilithium2 signature verifies |
| register-state payouts | full address, 1.2 KB each | the 32-byte id; the record resolved at withdraw time |
| bridge recipient | 32-byte `recipient_hash` of the full address | the receiver id, directly |

The receiver id is the same 32-byte form as the transparent account address (blake3 of a
Dilithium2 public key, base58): **one wallet, one identity**, shielded and transparent. A hard
fork on the address format, register state and the bridge wire format: it ships as a chain cut
(§9).

## 1. The keys

A shielded wallet today is one file: the 32-byte **spend key** `sk` (`SpendKey`), from which the
notes module derives the viewing key `vk` and the note public value `pk = vk.pk()`, and from
which the wallet derives its ML-KEM-768 keypair (`address_of(&vk)` in `wallet.rs`). There is no
signing key in a shielded wallet; Dilithium2 keys are the node's and the account's.

**The receiver signing key** is derived, not added: `sign_seed = blake3("rand-receiver-sign-1" ‖
sk)`, `signing = Keypair::from_seed(sign_seed)` (the crate's deterministic Dilithium2
derivation). It exists whenever the spend key does, needs no separate backup, and is the user's
ruling (1) in the only form a shielded wallet can take it. Its hash is the wallet's transparent
address too — `Address::from(signing.public_key())` — which is what makes the identity single.

**The receiver id**: `id = blake3(signing.public_key())`, 32 bytes — `Address`, unchanged.

## 2. The address

`rand1` + base58(`id` ‖ `checksum`), `checksum = blake3("rand-receiver-addr-1" ‖ id)[..4]`.
54 characters (Algorand: 58, QRL: 79). `ShieldedAddress::parse` accepts this form only; the
long form is gone. The prefix stays `rand1` so nothing downstream (explorer, wallets, docs)
learns a new prefix; the length and the checksum tell the forms apart, and a long-form string
fails the length check with a message naming the change.

Type: `ReceiverId(pub [u8; 32])`, `Display`/`parse` as above. The bridge's `recipient_hash` goes
away: the 32-byte `to` field of a bridge transfer payload *is* the receiver id (§6.4).

## 3. The receiver record

```
ReceiverRecord {
    version:     u32,          // strictly increasing per id; 1 at first publication
    pk:          Word8,        // the note public value envelopes are addressed to
    kem_ek:      [u8; 1184],   // the current ML-KEM-768 encapsulation key
    signing_key: PublicKey,    // Dilithium2, 1,312 bytes — what the id is the hash of
    signature:   Signature,    // Dilithium2 over the signing hash below, ~2,420 bytes
}
signing hash = blake3("rand-receiver-record-1" ‖ chain_id ‖ version ‖ pk ‖ kem_ek)
```

About 5 KB, dominated by the signature. **Verification** (`ReceiverRecord::verify(&self, id,
chain_id) -> Result<(), RecordError>`), the same function in the wallet, the ledger and the
explorer:

1. `blake3(signing_key) == id` — the record belongs to this address;
2. the signature verifies under `signing_key` over the signing hash — the receiver authorised
   exactly these `pk`, `kem_ek`, `version` for this chain.

Nothing about who supplied the record enters the check. `chain_id` in the hash keeps a record
published on one chain from being replayed on another with the same key.

**Rotation**: a new record with `version + 1` and a new `kem_ek`. `pk` may not change (a
changed `pk` would orphan every note the old `pk` owns; a receiver who wants a new `pk` makes a
new wallet). The address never changes.

## 4. Delivery path 1: the payment request

A receiver who has never registered can still be paid: the wallet emits a **payment request**
that carries the record.

- Text/URI form: `rand:<address>?rec=<base64url(ReceiverRecord)>[&amount=…][&memo=…]`, ~6.8 KB.
  Fits a link, a chat message, a file, an NFC tag; too big for a QR code.
- QR form: `rand:<address>?rec=<https URL the record can be fetched from>` or just the address
  (the sender's wallet then looks the record up, §5). The explorer's registry URL is the
  default fetch hint once the receiver is registered.

The sender's wallet parses the request, runs `verify` against the address, seals the envelope
to `kem_ek`, addresses the note to `pk`. `rand send <address>` with no record and no registry
answer is an error that says so ("no receiver record for rand1…: ask the receiver for a payment
request, or for them to register").

## 5. Delivery path 2: the registry, served by the explorer

The registry is **chain state** (§6): every published record is in a block, so every node holds
the current record per id and the explorer indexes it like everything else. The user's ruling
(2): wallets look records up from the explorer, not from validator RPC.

- `GET /receivers/<address>` → the current `ReceiverRecord` (JSON, the signature and signing key
  hex), `404` if never registered. `GET /receivers/<address>/history` → every version with the
  block it was published in.
- The wallet **verifies** what the explorer returns exactly as it verifies a payment request. A
  bad or compromised explorer can withhold a record or serve an old version; it cannot forge
  one. A stale version only means the sender seals to a key the receiver rotated away from —
  the receiver's wallet keeps its previous KEM secret keys, so the note is still openable
  (`RETIRED_KEM_KEYS = 4`, then a warning in the receiver's wallet).
- `rand send` takes `--registry <url>` (default: the explorer at `https://randscan.org/api/v1`)
  and `--record <file>` for the offline path. The node keeps `rand_getReceiver(id)` for the
  explorer's own indexer and for operators; it is not the wallet's default.

Privacy: a lookup tells the explorer which receiver a sender is about to pay. The payment-request
path leaks nothing; a wallet that cares can fetch over Tor or from several sources. This is the
ENS trade-off and is stated in `docs/shielded.md`, not hidden.

## 6. Chain state and actions

### 6.1 The registry

`receivers: BTreeMap<ReceiverId, ReceiverRecord>` in the ledger, committed into the state root
as a sixth component (`receivers_root` = merkle over leaves `blake3("rand-receiver-leaf-1" ‖ id ‖
version ‖ pk ‖ kem_ek)`; the signing key and signature are checked at apply, not hashed again).
Domain bump: `rand-state-4`.

### 6.2 `Action::RegisterReceiver { record }`

A bundle-carrying transaction whose action publishes a record. Validity (`validate_inner`, cheap
before expensive): `record.verify(id = blake3(record.signing_key), chain_id)`; if the id already
has a record, `record.version == current.version + 1` and `record.pk == current.pk`; else
`version == 1`. Size cap: one record per action (`MAX_RECORD_BYTES = 8 KiB`). The fee is the
bundle's ordinary fee; the bundle's proof is the ordinary bundle proof (a transfer to oneself
is the usual way to pay it). Apply: insert/replace.

### 6.3 A transfer that registers the receiver

The first payment to an unregistered receiver may carry the record: `Action::RegisterReceiver`
on the **sender's** transfer bundle, with the same validity rules — the record must verify
under the id it names, whoever pays for its inclusion. The receiver never needs notes to be
registered; the sender pays once. A receiver who only ever uses payment requests never appears
on chain.

### 6.4 Payouts and the bridge

- `ValidatorEntry.payout`, `AggregatorEntry.payout`, `GenesisValidator.payout`,
  `Registration.payout`, `AggregatorRegistration.payout`: `ReceiverId` instead of
  `ShieldedAddress`. The derived notes (`Withdraw`, `WithdrawAggregator`, the aggregate's
  payout) are committed to `pk`, so at validate/apply the ledger resolves `pk` from
  `receivers[payout]` — a payout id with no record is refused at registration time
  (`RegisterValidator`/`RegisterAggregator` require the record to exist, or to be carried in the
  same transaction). The genesis file carries each validator's record next to its id.
- `BridgeAttest.recipient`: `ReceiverId`; the guardians' 32-byte `to` field is the id; the
  deposit note's `pk` comes from the registry, so a bridge deposit to an unregistered receiver
  is refused (`BridgeError::UnknownReceiver`) — the depositor registers first or the attestation
  carries the record (§6.3's rule, one action over).

### 6.5 What does not change

Notes, commitments, nullifiers, envelopes, the bundle guest and its proof, the aggregate
program: the receiver id is never inside a proof. `Envelope` is still sealed to a `kem_ek`; only
where the sender found the key changed.

## 7. Wallet flows

- `rand address`: the 54-char address. `rand address --record`: the current record as JSON;
  `rand request [--amount] [--memo]`: the payment-request URI (with the record).
- `rand register [--rotate]`: publishes version 1, or version + 1 with a fresh KEM key,
  paying with a self-transfer. The wallet file keeps the retired KEM secret keys.
- `rand send <address> <amount> [--record f | --registry url]`: resolve → verify → seal → prove
  → submit. With neither flag: the registry; on a 404, the error in §4.
- `rand balance`/scan: unchanged (`vk` scans; retired KEM keys tried in order for envelopes).

## 8. The explorer

Indexer: `RegisterReceiver` (standalone or carried) → `receivers(id, version, pk, kem_ek,
signing_key, signature, tx_hash, height)`, current row per id, history kept. API: §5. The
explorer verifies every record it stores with the same `verify` (a defence against its own
bugs, not a trust boundary: the chain already verified it). Transaction pages show the receiver
id where they show addresses today; the address search accepts the 54-char form.

## 9. Migration and the chain cut

Register state, the state root, the bridge wire format and the address text form change:
**chain 11**, cut like chain 10 (`deploy/cut-chain11-genesis.sh`: each validator's payout as an
id plus its record; the five genesis notes' owners as ids plus records). Wallet files are
unchanged; `rand address` simply prints the short form. Explorer: one migration
(`008_receivers.sql`), redeployed with the cut.

## 10. Test plan (each a failing test first)

- core: `verify` accepts a well-formed record and refuses a wrong id, a wrong chain, a wrong
  version, a changed pk, a tampered field, a bad signature; the address round-trips and refuses
  a bad checksum and the long form; the state root moves with the registry; a `RegisterReceiver`
  applies standalone and carried; a withdraw resolves its pk from the registry; a bridge attest
  to an unregistered receiver is refused.
- client: request → send round-trip with no registry; rotation keeps old notes openable; the
  §4 error text.
- node: `rand_getReceiver`; a cluster test registering through a sender-paid transfer and paying
  the receiver twice across a rotation.
- explorer: the `/receivers` endpoints against the mock node and the real node.

## 11. Open questions for the user

1. **`RETIRED_KEM_KEYS = 4`** (how many rotated-away KEM secrets a wallet keeps): fine, or
   unbounded?
2. **Sender-paid registration (§6.3)**: keep, or require every receiver to register itself?
   Keeping it is what makes "first payment without registering" true for a wallet with no notes.
3. **Bridge deposits to unregistered receivers** are refused under §6.4. The alternative — a
   bridge deposit that carries the record in the attestation — makes the guardians' payload
   bigger. Refuse, or carry?
