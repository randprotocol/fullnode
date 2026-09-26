# Address sharing and the encrypted memo — design

Status: design approved in conversation 2026-09-26, written spec awaiting review.
Scope: fullnode (this repo), the website (`../randprotocol.org`), the wallet apps (`../clients`).
Ships in: the launch genesis (the memo's envelope rule); everything else is client-side.

## 1. Decision and why

The launch address stays the **ML-KEM-768 shielded address** exactly as it is today:
`rand1` + base58(`pk` 32 B ‖ `kem_ek` 1 184 B), 1 667 characters. It is fully post-quantum and
any sender can pay it with nothing but the address — no registration, no lookup.

Shorter alternatives were weighed and rejected (2026-09-26):

| option | length | why not |
|---|---|---|
| receiver id + registry (v0.2 / S3, PR #5) | 54–64 | needs registration or a lookup before the first payment |
| hash + auto-published ML-KEM key | ~64 | still a lookup; a never-published address needs the long form anyway |
| X25519 inline hybrid (S5) | ~93 | the first payment is classically confidential only |
| CTIDH-1024 hybrid | ~270 | isogeny security disputed; every note costs a ~200 ms group action to scan, ~10 000× today's ML-KEM decapsulation — balance checks become unusable |
| ML-KEM-512 inline | ~1 100 | level 1 instead of 3 for a 30 % saving |

No standardized post-quantum KEM has a public key under ~700 bytes (lattice) and hash-based
cryptography has no public-key encryption, so a short, lookup-free, standardized PQ address does
not exist. The address's *usability* is fixed instead, by four things this spec defines:

1. a **fingerprint** — 16 characters a human can compare,
2. **QR codes**,
3. **`randpay:` payment links** — address, amount, asset, memo,
4. **contacts** — a long address is pasted once and named,

and one protocol addition the payment link needs:

5. an **encrypted on-chain memo** in every envelope, fixed-size so its presence never shows.

## 2. Formats (one implementation, in `randprotocol-core`)

Every surface uses the same Rust code: the website through `server/address-wasm` (path deps on
this repo), the apps through `clients/core` (this repo vendored as a submodule). Nothing below is
re-implemented in Swift, Java or JavaScript.

### 2.1 Fingerprint

```
fingerprint(addr) = crockford32( first 80 bits of
                      blake3("rand-address-fingerprint-1" ‖ pk_bytes ‖ kem_ek) )
```

- `blake3` with the domain prepended, i.e. `Hash::digest_domain(b"rand-address-fingerprint-1", raw)`
  over the same 1 216 raw bytes the text form encodes.
- The first 10 digest bytes, read big-endian, as 16 Crockford base32 digits
  (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), most significant first, printed uppercase in four groups
  of four joined by `-`: `1WCV-YC8F-47BY-5RZY`.
- Comparison (`fingerprint_matches(a, b)`) ignores case and `-`, and maps `O`→`0`, `I`/`L`→`1`.
- Strength: forging a different address with the same fingerprint costs ~2^80 key-grinding
  attempts (60 bits was rejected: ~weeks on a GPU farm).
- Display only: no RPC, transaction or URI carries a fingerprint. It is always recomputed from
  the address in hand.

API: `ShieldedAddress::fingerprint(&self) -> Fingerprint` (`Display` = the grouped form),
`Fingerprint::parse(&str)`, `PartialEq` = the lenient comparison.

### 2.2 The `randpay:` URI

```
randpay:<rand1 address>[?<param>=<value>[&…]]
```

| param | value | default |
|---|---|---|
| `amount` | a decimal in the asset's display units (RAND: 9 decimals; a token: its registry `decimals`) | absent — the payer enters it |
| `asset` | a registry index (`0` = RAND) or an `rpl1…` token id | `0` |
| `memo` | percent-encoded UTF-8, ≤ 510 bytes once decoded | absent — empty memo |

Parsing (`PaymentUri::parse`) refuses: a scheme other than `randpay` (case-insensitive), an
address that does not parse, an unknown parameter, a repeated parameter, an amount that is not a
positive decimal or has more fraction digits than the asset allows (checked where the asset's
decimals are known — the send path, not the parser), a memo over 510 bytes or not valid UTF-8.
`PaymentUri::format` emits parameters in the order above, percent-encoding only what RFC 3986
requires in a query value. A URI round-trips byte-for-byte.

Size: ~1 700 characters with the address; it fits one QR code at error correction **M** in byte
mode (≈ version 33). The QR everywhere encodes the `randpay:` URI (a bare address is the URI with
no parameters), never the raw address, so any scanner routes it to a wallet.

### 2.3 The encrypted memo

The note plaintext sealed in `Envelope.body` grows from the note alone to the note and a
512-byte memo field:

```
body plaintext = note (112 B) ‖ memo_field (512 B)
memo_field     = len (u16 LE, 0..=510) ‖ utf8 text (len B) ‖ zero padding
```

- `len = 0` is "no memo". A field whose `len > 510`, whose text is not UTF-8, or whose padding is
  not all zero opens as **no memo** (the note itself still opens — a malformed memo never costs
  the payee the payment).
- Sealing is unchanged otherwise: ChaCha20-Poly1305 under the transaction key, AAD
  `rand-envelope-body ‖ cm`. So the memo is readable by exactly the parties who can read the
  note today: the payee (ML-KEM), the sender (`ovk`), and anyone handed that output's transaction
  key (`rand tx-key`, `rand_checkTransaction`, randscan).
- Every envelope becomes exactly **1 860 bytes**: `kem_ct` 1 088 + `to_receiver` 60 +
  `to_sender` 60 + `body` 652 (12 nonce + 624 + 16 tag). Dummy outputs (sealed to a throwaway
  key) and change outputs carry an all-zero memo field and are the same size, so nothing on chain
  distinguishes a memo, its length, or its absence.
- The zk side is untouched: the memo is not in the note, the commitment, or any proof.
- `viewing.rs` is vendored from `research`: the sealing change lands upstream first and is
  re-vendored with `deploy/sync-zkvm.sh`, like every zk-side change. `Note::from_bytes` keeps its
  exact-length check; the body opener splits off the first 112 bytes.

### 2.4 The envelope rule (genesis-gated)

A new optional genesis field `envelope_bytes: u32`:

- **Absent** (chain 14, every existing genesis): today's rule, byte-for-byte — an envelope is at
  most `MAX_ENVELOPE_BYTES` (2 048). Old-format envelopes stay valid; memo-carrying ones are
  also valid there (they fit), just not enforced uniform.
- **Present**: every note-creating envelope must be **exactly** `envelope_bytes` long —
  `Bundle.envelopes[..]`, `Mint`, `Withdraw`, `BridgeAttest`, `Aggregate`, `TokenMint`,
  `RegisterToken`'s initial mint — else `TxError::EnvelopeSize { expected, got }` (permanent).
  `validate` accepts only `1860` in this release (the one layout a wallet can produce); a future
  layout is a new value.
- Replayed like every validity rule; stored in the ledger's genesis-derived parameters beside
  `max_call_envelope_bytes`.
- The launch genesis sets `envelope_bytes: 1860`. Chain cost: +512 B per output (a bundle has
  four), ≈ +2 KB per transfer against a ~1.2 MB proof — under 0.2 %.

Wallet compatibility: a wallet built before this change cannot open a 652-byte body (its
`Note::from_bytes` sees 624 bytes); a new wallet opens both lengths (112 → note only, 624 → note +
memo). The launch chain is fresh, so no deployed wallet meets the new form unprepared, but the
apps and website must ship the new core before the launch genesis goes live.

## 3. Surfaces

The confirmation shown before any send, on every surface, is:
`to <contact name, if any> · fingerprint XXXX-XXXX-XXXX-XXXX · <amount> <asset> · memo "<text>"`.

### 3.1 CLI (`rand`, this repo)

- `rand address` — prints the address and `fingerprint XXXX-XXXX-XXXX-XXXX`.
  `--uri [--amount A] [--asset X] [--memo M]` prints a `randpay:` link;
  `--qr` renders that link as a QR in the terminal (Unicode half blocks);
  `--qr-png <file>` writes it as a PNG.
- `rand contacts add <name> <rand1…|randpay:…>` — shows the fingerprint and asks `add? [y/N]`
  (`--yes` skips); `rand contacts list`, `show <name>` (address, fingerprint, QR with `--qr`),
  `remove <name>`. Stored in `<key>.contacts.json` beside the key file, mode 0600, written
  atomically (temp file + rename). A name is 1–64 characters, not starting with `rand1` or
  `randpay:` (case-insensitive), unique; an address may appear under one name only.
- `rand send <to> [amount] [--asset X] [--memo M] [--yes]` — `<to>` is a `rand1…` address, a
  `randpay:` URI, or a contact name, tried in that order. A URI's amount/asset/memo fill in what
  the command line leaves out; a value given both ways and differing is refused, never guessed.
  `amount` becomes optional only when the URI carries one. Prints the confirmation line and asks
  before proving unless `--yes`.
- `rand notes` and `rand history` gain a memo column (truncated to the terminal, full with
  `--memo`); `rand tx-key` is unchanged.

### 3.2 Website (`randprotocol.org`)

- `server/address-wasm` gains `fingerprint(address)`, `uri_format(address, amount?, asset?, memo?)`
  and `uri_parse(uri)`; `server/viewing-wasm` returns each note's memo.
- `/address` — the fingerprint under the address, a QR of the `randpay:` link, copy buttons for
  address and link, and a link builder (amount, asset, memo) that re-renders the QR.
- `/account` — each received and sent note shows its memo.
- Contacts: saved in browser storage, per browser, with the fingerprint shown on add; clearing
  site data clears them (said on the page).
- CSP: the QR renderer is local code, no new origin; `server/csp-keypages.sh` regenerates the
  hashes after the pages change.

### 3.3 Wallet apps (`../clients`)

- `clients/core` re-vendors this repo at the commit that lands §2 and exposes, through its one
  `call(method, params)` entry point: `address.fingerprint`, `uri.parse`, `uri.format`; `send`
  takes `memo`; the note list returns `memo`.
- Receive screen (every client): address, fingerprint, QR of the `randpay:` link, share / copy,
  an optional amount-asset-memo form that rebuilds the link.
- Send screen: paste an address or link, scan a QR (camera on iOS, Android, desktop; the
  extensions and the web wallet use the browser camera API when granted and fall back to paste),
  or pick a contact; then the confirmation line above.
- `randpay:` links open the wallet: a URL scheme on iOS (`CFBundleURLSchemes`), an intent filter
  on Android, a registered protocol handler in the Tauri desktop app, `registerProtocolHandler`
  for the web wallet where the browser allows it (the extensions offer paste only).
- Contacts: stored in each client's existing encrypted vault beside the key, same rules as the
  CLI (§3.1). No sync between devices.

## 4. Testing

- **Vectors** (`crates/randprotocol-core/tests/vectors/address-sharing.json`, consumed by core,
  `address-wasm` and `clients/core`): address → fingerprint; URI round-trips; every refusal in
  §2.2; memo fields (empty, 510 bytes, 511 refused at format, malformed-on-open → no memo); a
  sealed envelope's length 1 860. Seed vector:
  address = the `rand18pdYjYn3m…6T2Djprc` wallet in Appendix A, fingerprint `1WCV-YC8F-47BY-5RZY`.
- **Consensus, red-first**: under `envelope_bytes: 1860`, a 1 859- and a 1 861-byte envelope are
  refused in each action of §2.4 (each test quoted failing before the rule exists); a genesis
  with `envelope_bytes: 1000` fails `validate`; without the field, chain 14's genesis hash and a
  replay of its fixture blocks are unchanged.
- **Round trip**: the wallet-flow test sends with a memo, the payee's scan and the sender's
  history both show it, `rand_checkTransaction` with the output's tx key shows it, and every
  envelope in the block is 1 860 bytes.
- **CLI**: contacts file mode and atomic write; send resolution order; conflicting URI/flag
  values refused.
- **Apps and website**: each consumes the vectors; a manual check scans a phone QR from
  `/address` and from `rand address --qr` into each app.

## 5. Order of work

1. `research`: memo field in `viewing.rs` sealing/opening; re-vendor here.
2. `randprotocol-core`: fingerprint, `PaymentUri`, `envelope_bytes` rule, vectors.
3. `rand` CLI: address/contacts/send/notes; wallet-flow round trip.
4. `randprotocol.org`: wasm exports, `/address`, `/account`, contacts; redeploy.
5. `clients`: re-vendor core, entry points, receive/send screens, link handlers, contacts.
6. The launch genesis sets `envelope_bytes: 1860`; the apps and website are released first.

## 6. Out of scope

Short addresses of any kind (§1); contact sync across devices; memos on `Call` envelopes
(their own format and cap); a human-readable name service; a memo in the proof or commitment.

## Appendix A — the seed vector

A throwaway wallet generated 2026-09-26 for this spec (key never used, not kept):

```
address:
rand18pdYjYn3mQ32Hzc7kzf8cwVK3UyNJpiEEnjHm2zSpGYY2uyRskgaDmDd9LDuUHbLjqo7EfguCcudiPnXorA1B16Cfbt9y815cDMaDXLp7WjWnmdhBqeJS8PZF6fGa4TUsxqBRm5ihqaR1AknXm9p7zXBSziZdwJgsALuS4X4NVStM3bkANWScfpdhyKftjCx4QJo6GyY9UKhE3HKi7TZVYCQY73WZSkY7XpBjQ9GRYaHpnuGvg5Yro2nQqQVkFVABf1KsTAo18uM9UgxLxjaQzJiHpBpT9r4MeTGXhiqWFFeg7yPiL25sN3WmoRuYBJxfsAwfE52y4qEGzp5sDvjfE5gKJG7rzydwpcECWxD8Gi3FdEqXT9WgFf6g9vEtuARoewEi41zBWK6ScXbVDPpEEEFptFNd6LxaGXDq74rrLtfch6mARA1R6zpwXpxE4XZUDV4F1FTLZ31NgAbvBse2FJdDR5657WdoM9zCLuwH9hBhzCNiuNmt9eyspeWBAYNcU7n8JwQK1s3EgfJaeutUyyfV2A5nUng7v4mSwoYbmHc7u31TrwxqDaynXWZZF5EhcpxXJm98gkR19ybBmpnoeyH1eWkmeo6mPmfic55euA4VuhzMhjJ2SPjrQME54yuZsGmHvz2CrN9GJfQUXzdjxmYf9CRS8s634i1n7bPqx76NUN8dCp2WfspmfNdSSeCK8TCaKp71WYMzD7KFsCkxbSEPzLYWd17GYGgrWecP8caYC1My36w8Pbqyez1GDatW7hnMi4VznDNBaz3K6NS82djJVSXAv6J7qvFZ4zr2FpD4mvrELW9jaSdeH6KtZj1FS7uVmzcjKip2MYKnxrzj7ynkrtNbxQyDHt5bPoXSgoPfWqJBjijdTAPVwvmxofQoXZvhhJupcRB6Z9fpfCjHPoE4LCRM1tif7jhg3bnxhrefyfjtCQs1L9ZfC2pHqgZXdFxeZBWGZL7uEmzZ3d7A7d9mPNH6j4AwFXobNc6f6u912w8LtHemSLeNPVwiHZLdGY7ppxiJaao8Dr82ZSh9LGvF9f7p2CRYh9gdEyy86N3U3p1zQ8usSsrzE1nUVAwV5uUxFQBv7t2acdX6kLs4ZPe2k57szeCnQDv7iyQpbfMh79L61n6bMvrPLZ1njAZrD2uj6i4cUUdbhV82b6xKUpzB75iExZPoQGo9yqeD3kF8rRLLbs2rRZatvi7nACnY33ijPcmeUyjSvBPvkn5wHyfcfsX7rNWowA7EoJA8ik2NmkjumxRvpbZss9dMDJnVYMxHUSyDaKBna1Q3V64Q34n87c3PLAwzEfx8xJcfzdsvzCcWjyBEk1DcY7DQ18N5E4k97gou9rHuugrzddvRkyPzgTtBCuB2ZiAxsDNYF8H7QZN7ouDsqGT6u5XcV1w58pGUSm4GY2idEh53bXLyFrUFqb3H2gmswBw2mG4heNLVuJGmCSZ6m5nab9Apya9ruuSaYdBro9d9ra1PAMufm7de5vzwHiRJeEKTmm2YioywpqmiCKhxrDwhM1eFuE4ozMK39T1UJX8zTe1qU9vSQ6jdaoqrKPNvnCeVtMKHj9c8vG7J7Sm8m6bkXEyhCfoW7NeuKwVFwrwukk3pm7EpLCRrcKL3gyfZzch4jMdxFHUPJQsk6Qhv6T2Djprc
fingerprint: 1WCV-YC8F-47BY-5RZY
```

(Computed with a scratch Python blake3 over the decoded 1 216 bytes; the Rust implementation
must reproduce it before any other vector is generated from it.)
