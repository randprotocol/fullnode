# Address sharing and the encrypted memo — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the ML-KEM-768 `rand1…` address and make it usable — a 16-character fingerprint, QR codes, `randpay:` payment links, contacts, and a fixed-size 512-byte encrypted memo in every envelope — across the node, the CLI, the website, randscan's viewing crate and the wallet apps.

**Architecture:** One Rust implementation. The memo's sealing lives in the zkVM note layer (`circuits/research/src/viewing.rs`, vendored into `crates/randprotocol-zkvm`); the fingerprint, the `randpay:` URI and the envelope-format choice live in `randprotocol-core`; the genesis field `envelope_bytes` makes the 1 860-byte envelope a validity rule. The website (`server/address-wasm`) and the apps (`clients/core`) call this code; randscan's `randscan-viewing` (a native re-implementation, used by `/account` and the explorer) is taught the new body length. **The envelope format follows the chain:** a wallet seals the memo form only where `rand_getLimits.envelope_bytes` is set, and today's form on chain 14 — so an old wallet on chain 14 never receives a note it cannot open.

**Tech Stack:** Rust (workspace, `cargo test`), ML-KEM-768 + ChaCha20-Poly1305 (existing), blake3 (existing), wasm-bindgen, Astro (website), vanilla JS + `node --test` (clients `ui/`), SwiftUI (iOS), Java (Android), Tauri 2 (desktop).

**Spec:** `docs/superpowers/specs/2026-09-26-address-sharing-and-memo-design.md` (approved 2026-09-26). This plan adds one rule the spec did not state (the format follows the chain, above) and one repo it did not name (randscan) — both forced by the code as it is.

## Global Constraints

- Address text form is unchanged: `rand1` + base58(`pk` 32 B ‖ `kem_ek` 1 184 B).
- Fingerprint: first 80 bits of `blake3("rand-address-fingerprint-1" ‖ pk ‖ kem_ek)`, 16 Crockford base32 digits `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, uppercase, groups of 4 joined by `-`; comparison ignores case and `-`, maps `O`→`0`, `I`/`L`→`1`.
- Seed vector: the Appendix A address of the spec → `1WCV-YC8F-47BY-5RZY`.
- `randpay:` params exactly `amount`, `asset`, `memo`, emitted in that order; memo ≤ 510 bytes UTF-8.
- Memo field: 512 bytes = `len` u16 LE (0..=510) ‖ UTF-8 ‖ zero padding. Body plaintext 624 B; sealed body 652 B; envelope exactly 1 860 B.
- Genesis `envelope_bytes`: absent = today's `≤ 2048` rule byte-for-byte; present must equal `1860`.
- A vendored file (`crates/randprotocol-zkvm/src/{notes,viewing,ledger}.rs`, `crates/randprotocol-rvm/**`) is never hand-edited: change `circuits/research` and re-run `deploy/sync-zkvm.sh`.
- Never run `cargo fmt` on this repo (it is not rustfmt-clean).
- Every regression test is shown red before its fix (revert the fix half, quote the failure in the commit message).
- Commit messages end with the session's two attribution lines.
- Work in a worktree per repo: `git worktree add /tmp/fullnode-memo -b feat/address-sharing main` (and `feat/address-sharing` branches in `circuits`, `randprotocol.org`, `randscan`, `clients`). In `/tmp/fullnode-memo` run `ln -s /Users/dendisuhubdy/Github/randprotocol/circuits /tmp/circuits` first (path deps).
- Nothing is deployed, pushed or rolled without the user's go typed in the executing session.

## Review Focus

1. A payee on chain 14 running an **older** wallet receives from a **new** wallet → must still open the note (the format follows the chain; Task 7 pins it).
2. A memo containing multi-byte UTF-8 exactly at the 510-byte edge, or cut mid-character by a hand-built URI → refused at format/parse, never truncated into invalid UTF-8 (Tasks 1, 4).
3. A `randpay:` link whose amount has more decimals than the asset (RAND: 9) → refused before proving, not rounded (Task 8).
4. A contact name that looks like an address or URI (`rand1abc`, `RANDPAY:x`) → refused at `contacts add` so `send` resolution is never ambiguous (Task 8).
5. A malformed memo field inside a valid envelope (len 600, bad UTF-8, non-zero padding) → the note still opens and counts toward the balance; only the memo is dropped (Tasks 1, 11).

---

## Part A — the note layer and the chain (circuits, fullnode)

### Task 1: The memo in the note layer (`circuits/research`)

**Files:**
- Modify: `/Users/dendisuhubdy/Github/randprotocol/circuits/research/src/viewing.rs`
- Test: `/Users/dendisuhubdy/Github/randprotocol/circuits/research/tests/viewing.rs`

**Interfaces:**
- Produces (in `rand_zkvm::viewing`):
  - `pub const MEMO_FIELD_BYTES: usize = 512;`
  - `pub const MEMO_TEXT_MAX_BYTES: usize = 510;`
  - `pub fn memo_field(text: &str) -> Option<[u8; MEMO_FIELD_BYTES]>` — `None` when `text.len() > 510`.
  - `pub fn memo_text(field: &[u8]) -> Option<String>` — `None` for empty or malformed.
  - `impl Envelope { pub fn seal_with_memo(sender: &ViewingKey, receiver: &Address, note: &Note, tx_key: &TxKey, memo: &[u8; MEMO_FIELD_BYTES]) -> Envelope; pub fn memo(&self, cm: Word8, key: &TxKey) -> Option<String>; }`
  - `open_with_tx_key` / `open_as_receiver` / `open_as_sender` keep their signatures and accept both body lengths (112-byte note, or 624-byte note ‖ memo).

- [ ] **Step 1: Branch.** `cd /Users/dendisuhubdy/Github/randprotocol/circuits && git worktree add /tmp/circuits-memo -b feat/address-sharing main`. Work in `/tmp/circuits-memo/research`.

- [ ] **Step 2: Write the failing tests** — append to `research/tests/viewing.rs`:

```rust
use rand_zkvm::viewing::{memo_field, memo_text, MEMO_FIELD_BYTES, MEMO_TEXT_MAX_BYTES};

#[test]
fn memo_field_round_trips_and_bounds() {
    assert_eq!(memo_text(&memo_field("").unwrap()), None, "len 0 is no memo");
    assert_eq!(memo_text(&memo_field("Invoice #42").unwrap()).as_deref(), Some("Invoice #42"));
    let edge = "é".repeat(255); // 510 bytes
    assert_eq!(edge.len(), MEMO_TEXT_MAX_BYTES);
    assert_eq!(memo_text(&memo_field(&edge).unwrap()).as_deref(), Some(edge.as_str()));
    assert!(memo_field(&"x".repeat(511)).is_none(), "511 bytes refused");
}

#[test]
fn a_malformed_memo_field_reads_as_no_memo() {
    let mut f = memo_field("ok").unwrap();
    f[0] = 0x58; f[1] = 0x02; // len 600 > 510
    assert_eq!(memo_text(&f), None);
    let mut f = memo_field("ok").unwrap();
    f[2] = 0xff; // not UTF-8
    assert_eq!(memo_text(&f), None);
    let mut f = memo_field("ok").unwrap();
    f[MEMO_FIELD_BYTES - 1] = 1; // non-zero padding
    assert_eq!(memo_text(&f), None);
    assert_eq!(memo_text(&[0u8; 3]), None, "wrong length");
}

#[test]
fn a_memo_envelope_is_1860_bytes_and_opens_for_the_same_keys() {
    let (alice, bob) = (SpendKey::random().viewing_key(), SpendKey::random().viewing_key());
    let note = Note::new(bob.pk(), alice.pk(), 5, 0, 7);
    let key = TxKey::random();
    let e = Envelope::seal_with_memo(&alice, &bob.address(), &note, &key, &memo_field("rent").unwrap());
    let len = e.kem_ct.len() + e.to_receiver.len() + e.to_sender.len() + e.body.len();
    assert_eq!(len, 1860);
    let cm = note.commitment();
    let (k, n) = e.open_as_receiver(cm, &bob).unwrap();
    assert_eq!(n, note);
    assert_eq!(e.memo(cm, &k).as_deref(), Some("rent"));
    let (k2, _) = e.open_as_sender(cm, &alice).unwrap();
    assert_eq!(e.memo(cm, &k2).as_deref(), Some("rent"));
    assert_eq!(e.open_with_tx_key(cm, &key), Some(note));
    // A legacy envelope still opens, and has no memo.
    let old = Envelope::seal(&alice, &bob.address(), &note, &key);
    assert_eq!(old.open_with_tx_key(cm, &key), Some(note));
    assert_eq!(old.memo(cm, &key), None);
}
```

(Use the imports the file already has for `SpendKey`, `Note`, `Envelope`, `TxKey`; add any missing ones from `rand_zkvm::{notes, viewing}`.)

- [ ] **Step 3: Run, expect a compile failure** — `cd /tmp/circuits-memo/research && cargo test --release --test viewing memo` → `unresolved imports memo_field, memo_text…`.

- [ ] **Step 4: Implement** in `research/src/viewing.rs`, after `fn open(...)`:

```rust
/// The memo that rides in a note's body (fullnode spec 2026-09-26 §2.3): a fixed 512-byte field
/// so its presence and length never show on chain.
pub const MEMO_FIELD_BYTES: usize = 512;
/// `len` (u16 LE) ‖ text ‖ zero padding: at most 510 bytes of UTF-8.
pub const MEMO_TEXT_MAX_BYTES: usize = MEMO_FIELD_BYTES - 2;

/// The field for `text`, or `None` if it does not fit.
pub fn memo_field(text: &str) -> Option<[u8; MEMO_FIELD_BYTES]> {
    let t = text.as_bytes();
    if t.len() > MEMO_TEXT_MAX_BYTES { return None; }
    let mut f = [0u8; MEMO_FIELD_BYTES];
    f[..2].copy_from_slice(&(t.len() as u16).to_le_bytes());
    f[2..2 + t.len()].copy_from_slice(t);
    Some(f)
}

/// The text a field carries: `None` for an empty field and for any malformed one — a bad
/// length, invalid UTF-8, or non-zero padding. A malformed memo never costs the payee the note.
pub fn memo_text(field: &[u8]) -> Option<String> {
    if field.len() != MEMO_FIELD_BYTES { return None; }
    let len = u16::from_le_bytes([field[0], field[1]]) as usize;
    if len == 0 || len > MEMO_TEXT_MAX_BYTES { return None; }
    if field[2 + len..].iter().any(|&b| b != 0) { return None; }
    String::from_utf8(field[2..2 + len].to_vec()).ok()
}

/// The body plaintext: the note alone (the original layout) or the note and a memo field.
fn body_parts(pt: &[u8]) -> Option<(Note, Option<&[u8]>)> {
    match pt.len() {
        n if n == Note::BYTES => Some((Note::from_bytes(pt)?, None)),
        n if n == Note::BYTES + MEMO_FIELD_BYTES => Some((Note::from_bytes(&pt[..Note::BYTES])?, Some(&pt[Note::BYTES..]))),
        _ => None,
    }
}
```

Then, in `impl Envelope`, replace `open_with_tx_key` and add the two new methods:

```rust
    /// Seals `note` and a memo field to `receiver`: the same four parts as [`Envelope::seal`],
    /// the body carrying `note ‖ memo` (1 860 bytes in all).
    pub fn seal_with_memo(sender: &ViewingKey, receiver: &Address, note: &Note, tx_key: &TxKey, memo: &[u8; MEMO_FIELD_BYTES]) -> Envelope {
        let mut e = Envelope::seal(sender, receiver, note, tx_key);
        let pt = [&note.to_bytes()[..], &memo[..]].concat();
        e.body = seal(&tx_key.0, &aad(AAD_BODY, note.commitment()), &pt);
        e
    }

    pub fn open_with_tx_key(&self, cm: Word8, key: &TxKey) -> Option<Note> {
        let pt = open(&key.0, &aad(AAD_BODY, cm), &self.body)?;
        let (note, _) = body_parts(&pt)?;
        (note.commitment() == cm).then_some(note)
    }

    /// The memo sealed with the note, if any: open the body with the transaction key (from
    /// [`Envelope::open_as_receiver`], [`Envelope::open_as_sender`] or a disclosure).
    pub fn memo(&self, cm: Word8, key: &TxKey) -> Option<String> {
        let pt = open(&key.0, &aad(AAD_BODY, cm), &self.body)?;
        let (note, memo) = body_parts(&pt)?;
        if note.commitment() != cm { return None; }
        memo_text(memo?)
    }
```

- [ ] **Step 5: Run** `cargo test --release --test viewing` → all pass (the existing `envelope_opens_for_exactly_the_right_keys` included). Show red: temporarily make `body_parts` accept only `Note::BYTES`, rerun, quote the `a_memo_envelope…` failure; restore.

- [ ] **Step 6: Commit** (in `circuits`):

```bash
git add research/src/viewing.rs research/tests/viewing.rs
git commit -m "research: a fixed 512-byte encrypted memo in the note body (seal_with_memo, memo)

<red failure quoted here>

Co-Authored-By: …
Claude-Session: …"
```

---

### Task 2: Re-vendor the note layer into fullnode; seal by chain format

**Files:**
- Modify (vendored, by script): `crates/randprotocol-zkvm/src/viewing.rs`, `crates/randprotocol-zkvm/src/notes.rs`
- Modify: `crates/randprotocol-core/src/notes.rs` (constants + `EnvelopeFormat`)
- Modify: `crates/randprotocol-zkvm/src/address.rs` (`seal_note_as`, `open_memo`)
- Test: `crates/randprotocol-zkvm/tests/shielded.rs`, `crates/randprotocol-core/src/notes.rs` tests

**Interfaces:**
- Consumes: Task 1's `seal_with_memo`, `memo`, `memo_field`.
- Produces:
  - `randprotocol_core::notes::{MEMO_FIELD_BYTES = 512, MEMO_TEXT_MAX_BYTES = 510, MEMO_ENVELOPE_BYTES = 1860}`
  - `randprotocol_core::notes::EnvelopeFormat { Legacy, Memo }` with `fn for_chain(envelope_bytes: Option<u32>) -> EnvelopeFormat` (`Some(1860)` → `Memo`, anything else → `Legacy`)
  - `randprotocol_zkvm::address::seal_note_as(format: EnvelopeFormat, sender: &ViewingKey, to: &ShieldedAddress, note: &Note, tx_key: &TxKey, memo: &str) -> Result<Envelope, String>` — `Legacy` with a non-empty memo is `Err("this chain carries no memo")`; a memo over 510 bytes is `Err("memo is N bytes, at most 510")`.
  - `randprotocol_zkvm::address::open_memo(e: &Envelope, cm: Word8, key: &TxKey) -> Option<String>`
  - `seal_note` stays (= `seal_note_as(Legacy, …, "")`) so existing callers compile unchanged.

- [ ] **Step 1: Inspect the drift before re-vendoring.** From `/tmp/fullnode-memo`:
  `diff <(sed 's/SHRUGG/RAND/g' /tmp/circuits-memo/research/src/viewing.rs) crates/randprotocol-zkvm/src/viewing.rs` and the same for `notes.rs`. Expected: Task 1's memo code **plus** research's versioned-KEM functions (`kem_keys_at`, `address_at`, `open_as_receiver_at`, `kem_seed_at`, `domain::KEM_SEED_VERSION`) that fullnode reverted at `17db41d`. Those are additive and `kem_seed_at(0) == kem_seed()` (research's own test pins it), so nothing here changes meaning. **If the diff shows anything else, stop and report it.**

- [ ] **Step 2: Re-vendor.** `deploy/sync-zkvm.sh /tmp/circuits-memo/research` (set `RVM_SRC=/Users/dendisuhubdy/Github/randprotocol/circuits/recursion` so the recursion section is a no-op re-copy). Then `git status` — only `crates/randprotocol-zkvm/src/{viewing,notes}.rs` (and `domain.rs` if the KEM version tag lives there) may change; revert anything else the script touched and report it.

- [ ] **Step 3: Write the failing tests.** In `crates/randprotocol-core/src/notes.rs`'s test module:

```rust
    #[test]
    fn the_memo_envelope_is_1860_bytes_and_the_format_follows_the_chain() {
        assert_eq!(MEMO_ENVELOPE_BYTES, 1088 + 60 + 60 + (12 + 112 + MEMO_FIELD_BYTES + 16));
        assert_eq!(EnvelopeFormat::for_chain(None), EnvelopeFormat::Legacy);
        assert_eq!(EnvelopeFormat::for_chain(Some(1860)), EnvelopeFormat::Memo);
        assert_eq!(EnvelopeFormat::for_chain(Some(2048)), EnvelopeFormat::Legacy);
    }
```

In `crates/randprotocol-zkvm/tests/shielded.rs`:

```rust
#[test]
fn seal_note_as_follows_the_format_and_keeps_the_memo() {
    use randprotocol_core::notes::{EnvelopeFormat, MEMO_ENVELOPE_BYTES};
    use randprotocol_zkvm::address::{open_memo, seal_note_as};
    let (a, b) = (SpendKey::random().viewing_key(), SpendKey::random().viewing_key());
    let to = randprotocol_zkvm::address::address_of(&b);
    let note = Note::new(b.pk(), a.pk(), 9, 0, 1);
    let key = TxKey::random();
    let e = seal_note_as(EnvelopeFormat::Memo, &a, &to, &note, &key, "hi").unwrap();
    assert_eq!(e.len(), MEMO_ENVELOPE_BYTES);
    assert_eq!(open_memo(&e, note.commitment(), &key).as_deref(), Some("hi"));
    let e = seal_note_as(EnvelopeFormat::Memo, &a, &to, &note, &key, "").unwrap();
    assert_eq!(e.len(), MEMO_ENVELOPE_BYTES, "an empty memo pads to the same size");
    let old = seal_note_as(EnvelopeFormat::Legacy, &a, &to, &note, &key, "").unwrap();
    assert_eq!(old.len(), 1348);
    assert!(seal_note_as(EnvelopeFormat::Legacy, &a, &to, &note, &key, "x").unwrap_err().contains("no memo"));
    assert!(seal_note_as(EnvelopeFormat::Memo, &a, &to, &note, &key, &"x".repeat(511)).unwrap_err().contains("at most 510"));
}
```

- [ ] **Step 4: Run** `cargo test --release -p randprotocol-core notes::` and `cargo test --release -p randprotocol-zkvm --test shielded seal_note_as` → compile errors (names missing).

- [ ] **Step 5: Implement.** In `crates/randprotocol-core/src/notes.rs`, beside `MAX_ENVELOPE_BYTES`:

```rust
/// The memo field sealed with every note on a chain whose genesis sets `envelope_bytes`
/// (spec 2026-09-26 §2.3); mirrors `randprotocol-zkvm`'s `viewing::MEMO_FIELD_BYTES`.
pub const MEMO_FIELD_BYTES: usize = 512;
pub const MEMO_TEXT_MAX_BYTES: usize = MEMO_FIELD_BYTES - 2;
/// Every envelope's exact size under `envelope_bytes`: ML-KEM ciphertext, two wrapped keys, and
/// the sealed `note ‖ memo` body.
pub const MEMO_ENVELOPE_BYTES: usize = 1088 + 60 + 60 + (12 + 112 + MEMO_FIELD_BYTES + 16);

/// Which body a wallet seals: the chain decides, through its genesis `envelope_bytes`
/// (`rand_getLimits`). Chain 14 and every chain without the field stay on `Legacy`, so a wallet
/// that predates the memo can still open everything sent to it there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeFormat { Legacy, Memo }

impl EnvelopeFormat {
    pub fn for_chain(envelope_bytes: Option<u32>) -> EnvelopeFormat {
        if envelope_bytes == Some(MEMO_ENVELOPE_BYTES as u32) { EnvelopeFormat::Memo } else { EnvelopeFormat::Legacy }
    }
}
```

In `crates/randprotocol-zkvm/src/address.rs`, after `seal_note`:

```rust
/// Seals `note` to `to` in the chain's envelope `format`, with `memo` (empty for none).
pub fn seal_note_as(
    format: randprotocol_core::notes::EnvelopeFormat,
    sender: &ViewingKey,
    to: &ShieldedAddress,
    note: &Note,
    tx_key: &TxKey,
    memo: &str,
) -> Result<Envelope, String> {
    use randprotocol_core::notes::EnvelopeFormat;
    let to = to_research(to)?;
    match format {
        EnvelopeFormat::Legacy if !memo.is_empty() => Err("this chain carries no memo".into()),
        EnvelopeFormat::Legacy => Ok(envelope_to_core(&viewing::Envelope::seal(sender, &to, note, tx_key))),
        EnvelopeFormat::Memo => {
            let field = viewing::memo_field(memo)
                .ok_or_else(|| format!("memo is {} bytes, at most {}", memo.len(), viewing::MEMO_TEXT_MAX_BYTES))?;
            Ok(envelope_to_core(&viewing::Envelope::seal_with_memo(sender, &to, note, tx_key, &field)))
        }
    }
}

/// The memo sealed in `e`'s body, opened with that output's transaction key.
pub fn open_memo(e: &Envelope, cm: Word8, key: &TxKey) -> Option<String> {
    envelope_from_core(e).memo(cm, key)
}
```

Add to the same file's tests: `assert_eq!(randprotocol_core::notes::MEMO_FIELD_BYTES, viewing::MEMO_FIELD_BYTES);`.

- [ ] **Step 6: Run** both tests → pass; `cargo check --workspace --tests` → clean (the vendored `Proof`/types unchanged).

- [ ] **Step 7: Commit** `zkvm: re-vendor the note layer with the memo; core: EnvelopeFormat and the 1860-byte constant`.

---

### Task 3: The fingerprint (`randprotocol-core`)

**Files:**
- Create: `crates/randprotocol-core/src/fingerprint.rs`
- Modify: `crates/randprotocol-core/src/lib.rs` (`pub mod fingerprint;`), `crates/randprotocol-core/src/notes.rs` (`ShieldedAddress::fingerprint`)
- Create: `crates/randprotocol-core/tests/vectors/address-sharing.json`, `crates/randprotocol-core/tests/address_sharing_vectors.rs`

**Interfaces:**
- Produces: `randprotocol_core::fingerprint::Fingerprint([u8; 10])`; `impl Display` (grouped form); `Fingerprint::parse(&str) -> Option<Fingerprint>` (lenient); `impl PartialEq` (byte equality — leniency lives in `parse`); `ShieldedAddress::fingerprint(&self) -> Fingerprint`.

- [ ] **Step 1: Write the vectors file** `crates/randprotocol-core/tests/vectors/address-sharing.json`:

```json
{
  "fingerprints": [
    { "address": "<the full Appendix A address from the spec, verbatim>", "fingerprint": "1WCV-YC8F-47BY-5RZY" }
  ],
  "uris": [],
  "memos": []
}
```

- [ ] **Step 2: Write the failing test** `crates/randprotocol-core/tests/address_sharing_vectors.rs`:

```rust
use randprotocol_core::fingerprint::Fingerprint;
use randprotocol_core::notes::ShieldedAddress;

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/address-sharing.json")).unwrap()
}

#[test]
fn fingerprints_match_the_vectors() {
    for v in vectors()["fingerprints"].as_array().unwrap() {
        let a = ShieldedAddress::parse(v["address"].as_str().unwrap()).unwrap();
        assert_eq!(a.fingerprint().to_string(), v["fingerprint"].as_str().unwrap());
    }
}

#[test]
fn fingerprint_parse_is_lenient() {
    let f = Fingerprint::parse("1WCV-YC8F-47BY-5RZY").unwrap();
    assert_eq!(Fingerprint::parse("1wcvyc8f47by5rzy"), Some(f));
    assert_eq!(Fingerprint::parse("IWCV-YC8F-47BY-5RZY"), Some(f), "I reads as 1");
    assert_eq!(Fingerprint::parse("1WCV-YC8F-47BY-5RZ"), None, "15 digits");
    assert_eq!(Fingerprint::parse("1WCV-YC8F-47BY-5RZU"), None, "U is not a digit");
}
```

(`serde_json` is already a dependency of the core crate; if it is not a dev-dependency, add `serde_json = { workspace = true }` under `[dev-dependencies]`.)

- [ ] **Step 3: Run** `cargo test --release -p randprotocol-core --test address_sharing_vectors` → compile error.

- [ ] **Step 4: Implement** `crates/randprotocol-core/src/fingerprint.rs`:

```rust
//! The address fingerprint (spec 2026-09-26 §2.1): 80 bits of a domain-tagged blake3 over the
//! address's raw bytes, as 16 Crockford base32 digits a person can read out and compare.
//! Display only — nothing on chain or on the wire carries one.

use crate::crypto::Hash;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DOMAIN: &[u8] = b"rand-address-fingerprint-1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 10]);

impl Fingerprint {
    /// Over the address's raw bytes (`pk` ‖ `kem_ek`, the 1 216 bytes its text form encodes).
    pub fn of_raw(raw: &[u8]) -> Fingerprint {
        let h = Hash::digest_domain(DOMAIN, raw).0;
        Fingerprint(h[..10].try_into().unwrap())
    }

    fn digits(&self) -> [u8; 16] {
        let n = u128::from_be_bytes([[0u8; 6].as_slice(), &self.0].concat().try_into().unwrap());
        std::array::from_fn(|i| ALPHABET[((n >> (5 * (15 - i))) & 31) as usize])
    }

    /// Case- and hyphen-insensitive; `O` reads as `0`, `I`/`L` as `1`.
    pub fn parse(s: &str) -> Option<Fingerprint> {
        let mut n: u128 = 0;
        let mut count = 0;
        for c in s.chars().filter(|&c| c != '-') {
            let c = match c.to_ascii_uppercase() { 'O' => '0', 'I' | 'L' => '1', c => c };
            let d = ALPHABET.iter().position(|&a| a as char == c)? as u128;
            n = (n << 5) | d;
            count += 1;
        }
        if count != 16 { return None; }
        Some(Fingerprint(n.to_be_bytes()[6..].try_into().unwrap()))
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = self.digits();
        let s = std::str::from_utf8(&d).unwrap();
        write!(f, "{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
    }
}
```

In `notes.rs`'s `impl ShieldedAddress`:

```rust
    /// The 16-character fingerprint shown beside this address everywhere (spec §2.1).
    pub fn fingerprint(&self) -> crate::fingerprint::Fingerprint {
        let mut raw = word8_to_bytes(&self.pk).to_vec();
        raw.extend_from_slice(&self.kem_ek);
        crate::fingerprint::Fingerprint::of_raw(&raw)
    }
```

- [ ] **Step 5: Run** → pass. **This is the gate the spec names**: if the vector does not reproduce, stop — the scratch computation and the Rust disagree, and one of them is wrong; report both values.

- [ ] **Step 6: Commit** `core: the address fingerprint (80 bits, Crockford base32) with the seed vector`.

---

### Task 4: The `randpay:` URI (`randprotocol-core`)

**Files:**
- Create: `crates/randprotocol-core/src/payment_uri.rs`
- Modify: `crates/randprotocol-core/src/lib.rs` (`pub mod payment_uri;`)
- Modify: `crates/randprotocol-core/tests/vectors/address-sharing.json` (`uris`), `crates/randprotocol-core/tests/address_sharing_vectors.rs`

**Interfaces:**
- Produces:

```rust
pub struct PaymentUri { pub address: ShieldedAddress, pub amount: Option<String>, pub asset: Option<String>, pub memo: Option<String> }
impl PaymentUri {
    pub fn parse(s: &str) -> Result<PaymentUri, UriError>;
    pub fn format(&self) -> String;          // params in order amount, asset, memo
}
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum UriError { Scheme, Address(String), UnknownParam(String), Repeated(String), BadAmount(String), BadAsset(String), MemoTooLong(usize), BadEncoding }
```

`amount` is kept as the decimal text: only the send path knows the asset's decimals (RAND 9; a token's from `rand_getTokens`), and it checks it there (Task 8). The parser checks it is a positive decimal: `^[0-9]+(\.[0-9]+)?$`, not all zeros. `asset` is `^[0-9]+$` or `rpl1…` (checked with the existing `rpl1` parser in `ledger/tokens.rs`; if that parser lives elsewhere, use it by its real path) or 64 hex.

- [ ] **Step 1: Add vectors** — `uris` array entries of the form `{ "uri": "...", "ok": true, "amount": "1.5", "asset": null, "memo": "Invoice #42" }` and refusals `{ "uri": "...", "err": "UnknownParam" }`, with `<A>` standing for the Appendix A address (the test substitutes it):

```json
"uris": [
  { "uri": "randpay:<A>", "ok": true, "amount": null, "asset": null, "memo": null },
  { "uri": "randpay:<A>?amount=1.5&memo=Invoice%20%2342", "ok": true, "amount": "1.5", "asset": null, "memo": "Invoice #42" },
  { "uri": "RANDPAY:<A>?asset=0", "ok": true, "amount": null, "asset": "0", "memo": null, "canonical": "randpay:<A>?asset=0" },
  { "uri": "randpay:<A>?memo=%C3%A9", "ok": true, "amount": null, "asset": null, "memo": "é" },
  { "uri": "bitcoin:<A>", "err": "Scheme" },
  { "uri": "randpay:rand1abc", "err": "Address" },
  { "uri": "randpay:<A>?fee=1", "err": "UnknownParam" },
  { "uri": "randpay:<A>?amount=1&amount=2", "err": "Repeated" },
  { "uri": "randpay:<A>?amount=-1", "err": "BadAmount" },
  { "uri": "randpay:<A>?amount=0.0", "err": "BadAmount" },
  { "uri": "randpay:<A>?asset=zusd", "err": "BadAsset" },
  { "uri": "randpay:<A>?memo=%FF", "err": "BadEncoding" },
  { "uri": "randpay:<A>?memo=<511 x's>", "err": "MemoTooLong" }
]
```

(Write the 511-character memo out literally in the file.)

- [ ] **Step 2: Failing test** — append to `address_sharing_vectors.rs`:

```rust
use randprotocol_core::payment_uri::{PaymentUri, UriError};

fn seed_address() -> String {
    vectors()["fingerprints"][0]["address"].as_str().unwrap().to_string()
}

#[test]
fn uris_match_the_vectors() {
    let a = seed_address();
    for v in vectors()["uris"].as_array().unwrap() {
        let uri = v["uri"].as_str().unwrap().replace("<A>", &a);
        match PaymentUri::parse(&uri) {
            Ok(p) => {
                assert!(v["ok"].as_bool().unwrap_or(false), "{uri} should be refused");
                assert_eq!(p.amount.as_deref(), v["amount"].as_str());
                assert_eq!(p.asset.as_deref(), v["asset"].as_str());
                assert_eq!(p.memo.as_deref(), v["memo"].as_str());
                let canonical = v.get("canonical").and_then(|c| c.as_str()).map(|c| c.replace("<A>", &a)).unwrap_or(uri.clone());
                assert_eq!(p.format(), canonical, "round trip");
            }
            Err(e) => {
                let want = v["err"].as_str().unwrap_or_else(|| panic!("{uri} refused: {e:?}"));
                assert!(format!("{e:?}").starts_with(want), "{uri}: {e:?} is not {want}");
            }
        }
    }
}
```

- [ ] **Step 3: Run** → compile error.

- [ ] **Step 4: Implement** `payment_uri.rs`:

```rust
//! `randpay:` payment links (spec 2026-09-26 §2.2).

use crate::notes::{ShieldedAddress, MEMO_TEXT_MAX_BYTES};

pub const SCHEME: &str = "randpay";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentUri {
    pub address: ShieldedAddress,
    pub amount: Option<String>,
    pub asset: Option<String>,
    pub memo: Option<String>,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum UriError {
    #[error("not a randpay: link")]
    Scheme,
    #[error("bad address: {0}")]
    Address(String),
    #[error("unknown parameter {0}")]
    UnknownParam(String),
    #[error("parameter {0} given twice")]
    Repeated(String),
    #[error("bad amount {0}")]
    BadAmount(String),
    #[error("bad asset {0}")]
    BadAsset(String),
    #[error("memo is {0} bytes, at most 510")]
    MemoTooLong(usize),
    #[error("bad percent-encoding")]
    BadEncoding,
}

fn decode(s: &str) -> Result<String, UriError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3).ok_or(UriError::BadEncoding)?;
            out.push(u8::from_str_radix(h, 16).map_err(|_| UriError::BadEncoding)?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| UriError::BadEncoding)
}

fn encode(s: &str) -> String {
    let mut out = String::new();
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

fn is_amount(a: &str) -> bool {
    let mut parts = a.splitn(2, '.');
    let int = parts.next().unwrap_or("");
    let frac = parts.next();
    !int.is_empty()
        && int.bytes().all(|c| c.is_ascii_digit())
        && frac.map_or(true, |f| !f.is_empty() && f.bytes().all(|c| c.is_ascii_digit()))
        && a.bytes().any(|c| (b'1'..=b'9').contains(&c))
}

fn is_asset(a: &str) -> bool {
    (!a.is_empty() && a.bytes().all(|c| c.is_ascii_digit()))
        || (a.len() == 64 && a.bytes().all(|c| c.is_ascii_hexdigit()))
        || crate::ledger::tokens::parse_token_id(a).is_some()
}

impl PaymentUri {
    pub fn parse(s: &str) -> Result<PaymentUri, UriError> {
        let (scheme, rest) = s.split_once(':').ok_or(UriError::Scheme)?;
        if !scheme.eq_ignore_ascii_case(SCHEME) {
            return Err(UriError::Scheme);
        }
        let (addr, query) = rest.split_once('?').unwrap_or((rest, ""));
        let address = ShieldedAddress::parse(addr).map_err(|e| UriError::Address(e.to_string()))?;
        let mut uri = PaymentUri { address, amount: None, asset: None, memo: None };
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = decode(v)?;
            let slot = match k {
                "amount" => &mut uri.amount,
                "asset" => &mut uri.asset,
                "memo" => &mut uri.memo,
                _ => return Err(UriError::UnknownParam(k.into())),
            };
            if slot.is_some() {
                return Err(UriError::Repeated(k.into()));
            }
            *slot = Some(v);
        }
        if let Some(a) = &uri.amount { if !is_amount(a) { return Err(UriError::BadAmount(a.clone())); } }
        if let Some(a) = &uri.asset { if !is_asset(a) { return Err(UriError::BadAsset(a.clone())); } }
        if let Some(m) = &uri.memo { if m.len() > MEMO_TEXT_MAX_BYTES { return Err(UriError::MemoTooLong(m.len())); } }
        Ok(uri)
    }

    pub fn format(&self) -> String {
        let mut s = format!("{SCHEME}:{}", self.address);
        let params = [("amount", &self.amount), ("asset", &self.asset), ("memo", &self.memo)];
        let mut sep = '?';
        for (k, v) in params {
            if let Some(v) = v {
                s.push(sep);
                s.push_str(k);
                s.push('=');
                s.push_str(&encode(v));
                sep = '&';
            }
        }
        s
    }
}
```

`crate::ledger::tokens::parse_token_id` stands for the existing `rpl1…` decoder; before writing the call, find it (`grep -rn "rpl1" crates/randprotocol-core/src | grep "fn "`) and use its real name and return type (`is_some()` / `is_ok()` accordingly).

- [ ] **Step 5: Run** → pass. Show red by removing the `Repeated` check; quote; restore.

- [ ] **Step 6: Commit** `core: randpay: payment links (amount, asset, memo), parse and format, vectors`.

---

### Task 5: The genesis `envelope_bytes` rule

**Files:**
- Modify: `crates/randprotocol-core/src/genesis.rs` (field, validate, hash binding, apply)
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (field, getter/setter, `TxError::EnvelopeSize`, checks at the envelope cap sites ~1245–1300)
- Modify: `crates/randprotocol-core/src/ledger/aggregation.rs` (~403, ~546)
- Modify: `crates/randprotocol-node/src/node.rs:~169` (restore on reload), `crates/randprotocol-node/src/rpc.rs` (`ChainLimits.envelope_bytes`)
- Test: `genesis.rs` tests, `ledger/mod.rs` tests, `rpc.rs` `get_limits_reports_the_chains_five_limits`

**Interfaces:**
- Produces: `Genesis.envelope_bytes: Option<u32>`; `GenesisError::BadEnvelopeBytes(u32)`; `Ledger::envelope_bytes() -> Option<usize>`, `Ledger::set_envelope_bytes(Option<usize>)`; `TxError::EnvelopeSize { expected: usize, got: usize }` (permanent in `admission::is_permanent`); `ChainLimits.envelope_bytes: Option<usize>` serialized as `"envelope_bytes": null | 1860`.

- [ ] **Step 1: Failing tests.** In `genesis.rs` tests, next to `the_call_limits_are_optional_and_bound_into_the_hash_only_when_present`:

```rust
    #[test]
    fn envelope_bytes_is_optional_bound_into_the_hash_and_only_1860() {
        let plain = genesis(2);
        let json = plain.to_json();
        assert!(!json.contains("envelope_bytes"));
        assert_eq!(build(&plain).ledger.envelope_bytes(), None);
        let mut g = plain.clone();
        g.envelope_bytes = Some(1860);
        let s = build(&g);
        assert_eq!(s.ledger.envelope_bytes(), Some(1860));
        assert_ne!(s.hash(), build(&plain).hash(), "a new chain");
        assert_eq!(s.ledger.state_root(), build(&plain).ledger.state_root(), "not state");
        for bad in [0u32, 1348, 1859, 1861, 2048] {
            let mut g = plain.clone();
            g.envelope_bytes = Some(bad);
            assert!(matches!(refused(&g), Some(GenesisError::BadEnvelopeBytes(n)) if n == bad), "{bad}");
        }
    }

    #[test]
    fn under_envelope_bytes_every_alloc_envelope_is_exactly_that_long() {
        let mut g = genesis(2);
        g.envelope_bytes = Some(1860);
        // `genesis(2)`'s alloc envelopes are the test fixture's short ones.
        assert!(matches!(refused(&g), Some(GenesisError::BadEnvelopeBytes(_)) | Some(GenesisError::AllocEnvelopeSize { .. })));
    }
```

(If `genesis(2)` has no alloc notes, build one with the existing `opened_alloc()` helper and a `vec![0; 1000]` body.) Add `GenesisError::AllocEnvelopeSize { cm: String, got: usize }`.

In `ledger/mod.rs` tests, one test per action kind the check covers. Use the existing test helpers that build a bundle transaction and a mint (search the module for the helper used by the `EnvelopeTooLarge` tests, `grep -n "EnvelopeTooLarge" crates/randprotocol-core/src/ledger/mod.rs`, and reuse it):

```rust
    #[test]
    fn under_envelope_bytes_a_bundle_envelope_must_be_exactly_that_long() {
        for (len, ok) in [(1859usize, false), (1860, true), (1861, false)] {
            let (mut ledger, mut tx) = /* the existing bundle-tx helper */;
            ledger.set_envelope_bytes(Some(1860));
            for e in tx.bundle.as_mut().unwrap().envelopes.iter_mut() {
                e.body = vec![0; len - (e.kem_ct.len() + e.to_receiver.len() + e.to_sender.len())];
            }
            let r = ledger.check_caps(&tx); // the function holding the cap block at ~1240; use its real name
            if ok { assert!(!matches!(r, Err(TxError::EnvelopeSize { .. })), "{len}"); }
            else { assert_eq!(r.unwrap_err(), TxError::EnvelopeSize { expected: 1860, got: len }); }
        }
    }
```

and the same shape for `Action::Mint` (a 1 859-byte envelope refused). Plus the regression that **without** the field a 1 348-byte and a 1 860-byte envelope both pass (chain 14 unchanged).

In `rpc.rs`'s `get_limits_reports_the_chains_five_limits`, add `"envelope_bytes": null` to the first expected object and `"envelope_bytes": null` to the second (`raised_genesis` does not set it); add a third case with `g.envelope_bytes = Some(1860)` expecting `1860`.

- [ ] **Step 2: Run** `cargo test --release -p randprotocol-core envelope_bytes` and `-p randprotocol-node get_limits` → compile errors.

- [ ] **Step 3: Implement.**

`genesis.rs` — the field, after `max_program_public_words`:

```rust
    /// Spec 2026-09-26 §2.4: every note envelope is exactly this many bytes (only `1860`, the
    /// memo layout, is accepted). Absent means today's rule — at most `MAX_ENVELOPE_BYTES` — and
    /// a genesis hash unchanged byte for byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_bytes: Option<u32>,
```

`validate` (beside the call-limits checks):

```rust
        if let Some(n) = self.envelope_bytes {
            if n as usize != crate::notes::MEMO_ENVELOPE_BYTES {
                return Err(GenesisError::BadEnvelopeBytes(n));
            }
        }
```

with `#[error("bad envelope_bytes {0} (only {} is supported)", crate::notes::MEMO_ENVELOPE_BYTES)] BadEnvelopeBytes(u32),` and `#[error("alloc note {cm}'s envelope is {got} bytes, the genesis requires envelope_bytes")] AllocEnvelopeSize { cm: String, got: usize },`.

Hash binding — **after** the `staking` block, last, so every existing genesis hashes as before:

```rust
        if let Some(n) = self.envelope_bytes {
            commit.extend_from_slice(b"envelope_bytes");
            commit.extend_from_slice(&n.to_be_bytes());
        }
```

Apply (beside `set_max_program_public_words`): `ledger.set_envelope_bytes(self.envelope_bytes.map(|n| n as usize));`. In the alloc loop, after `let envelope = n.envelope.to_envelope()?;`:

```rust
            if let Some(want) = self.envelope_bytes {
                if envelope.len() != want as usize {
                    return Err(GenesisError::AllocEnvelopeSize { cm: n.cm.clone(), got: envelope.len() });
                }
            }
```

`ledger/mod.rs` — field `envelope_bytes: Option<usize>` (initialised `None` in both constructors at ~550 and ~599), getter/setter next to `max_call_envelope_bytes`, and one helper used at every note-envelope site:

```rust
    /// The note-envelope rule: exactly `envelope_bytes` when the genesis sets it, else at most
    /// `MAX_ENVELOPE_BYTES` (today's rule, byte for byte).
    fn check_note_envelope(&self, e: &Envelope) -> Result<(), TxError> {
        match self.envelope_bytes {
            Some(want) if e.len() != want => Err(TxError::EnvelopeSize { expected: want, got: e.len() }),
            None if e.len() > MAX_ENVELOPE_BYTES => Err(TxError::EnvelopeTooLarge),
            _ => Ok(()),
        }
    }
```

Replace each `e.len() > MAX_ENVELOPE_BYTES` guard in the cap block (bundle envelopes, `Mint`, `Withdraw`, `BridgeAttest`, `Aggregate`, `TokenMint`, `RegisterToken` initial) with a call to it — e.g. for the bundle: `for e in &b.envelopes { self.check_note_envelope(e)?; }`, and for the match arms move the envelope checks out of the `match` guards into a preceding `match &tx.action { Action::Mint { envelope, .. } | Action::Withdraw { envelope, .. } | … => self.check_note_envelope(envelope)?, Action::RegisterToken { initial: Some(m), .. } => self.check_note_envelope(&m.envelope)?, _ => {} }` so the remaining arms keep their order. Do the same at `aggregation.rs` ~403 and ~546 (they take the ledger or its cap — pass `self.envelope_bytes` through if they are free functions). Add `TxError::EnvelopeSize { .. }` to `admission::is_permanent` (`crates/randprotocol-node/src/admission.rs`).

`node.rs` ~169 (reload): `ledger.set_envelope_bytes(gs.ledger.envelope_bytes());` with the same "a node that forgot it forks at its first restart" comment as its neighbours.

`rpc.rs` `ChainLimits`: add `pub envelope_bytes: Option<usize>,` and `envelope_bytes: ledger.envelope_bytes(),` in `of`.

- [ ] **Step 4: Run** the new tests → pass. Show red: comment out the `Some(want)` arm; quote the bundle test's failure; restore. Run `cargo test --release -p randprotocol-core genesis::` whole (the hash-pinning tests must stay green — chain 14's genesis hash unchanged).

- [ ] **Step 5: Commit** `core: genesis envelope_bytes — every note envelope exactly 1860 bytes where set (spec §2.4)`.

---

### Task 6: The node's own envelopes and disclosures carry the chain format and the memo

**Files:**
- Modify: `crates/randprotocol-node/src/main.rs:~40-50` (`seal_deposit`), `~72-80` (`sealed_withdraw_note`) — and every caller that can read the chain's `envelope_bytes`
- Modify: `crates/randprotocol-node/src/node.rs:~1805` (faucet mint)
- Modify: `crates/randprotocol-node/src/viewing.rs:~198-270` (`disclosed`, viewing notes), `crates/randprotocol-node/src/rpc.rs:~841` (`note_json` gains `memo`)
- Test: `rpc.rs` `check_transaction_discloses_what_the_key_sealed_and_nothing_more` (~5314), a new node test for the faucet envelope size

**Interfaces:**
- Consumes: `seal_note_as`, `open_memo`, `EnvelopeFormat::for_chain`, `Ledger::envelope_bytes`.
- Produces: `note_json(note, memo: Option<&str>)` → adds `"memo": string | null` to every disclosed/viewing note object (`rand_checkTransaction`, `rand_getViewingNotes`).

- [ ] **Step 1: Failing tests.** (a) A faucet mint on a genesis with `envelope_bytes: 1860` produces a 1 860-byte envelope and is admitted — extend the existing faucet test in `node.rs` (find it with `grep -n "fn .*faucet" crates/randprotocol-node/src/node.rs`) with a variant built from `fixtures::genesis(1)` plus `envelope_bytes = Some(1860)`, asserting `tx.action`'s envelope `len() == 1860`. (b) In `rpc.rs`, a copy of `check_transaction_discloses_what_the_key_sealed_and_nothing_more` on the memo genesis, sealing its bundle output with `seal_note_as(EnvelopeFormat::Memo, …, "invoice 7")`, asserting `disclosed[0]["note"]["memo"] == "invoice 7"`; and in the original test assert `["memo"] == null`.

- [ ] **Step 2: Run** → (a) fails with `EnvelopeSize { expected: 1860, got: 1348 }`, (b) fails on the missing `memo` key. Quote both.

- [ ] **Step 3: Implement.** Faucet (`node.rs`):

```rust
        let format = randprotocol_core::notes::EnvelopeFormat::for_chain(
            self.hs.tip_ledger().envelope_bytes().map(|n| n as u32),
        );
        let envelope = randprotocol_zkvm::address::seal_note_as(format, &throwaway, &to, &note, &TxKey::random(), "")?;
```

`main.rs`: give `seal_deposit` and `sealed_withdraw_note` a `format: EnvelopeFormat` parameter and call `seal_note_as(format, …, "")`. `seal_deposit` is used by the `genesis` command — pass `EnvelopeFormat::for_chain(genesis.envelope_bytes)` from the genesis being built (add a `--envelope-bytes 1860` flag to `rand-node genesis` that sets the field before the alloc notes are sealed). `sealed_withdraw_note`'s callers (`withdraw`, `withdraw-aggregator`, `aggregate`) read the chain's format with one `rand_getLimits` call (`envelope_bytes` field; absent on an old node → `None`).

`viewing.rs` `disclosed` and the viewing-note path: after a note opens with key `k`, `let memo = randprotocol_zkvm::address::open_memo(e, cm, &k);` and pass it to `note_json`. `note_json(n: &Note, memo: Option<&str>)` adds `"memo": memo`.

- [ ] **Step 4: Run** → pass; `cargo test --release -p randprotocol-node --lib` (the recursion-fixture tests skipped by name as usual) and `cargo check --workspace --tests`.

- [ ] **Step 5: Commit** `node: faucet, payouts and genesis notes sealed in the chain's envelope format; disclosures carry the memo`.

---

### Task 7: The wallet library — format from the chain, memo on send, memo in the store

**Files:**
- Modify: `crates/randprotocol-client/src/wallet.rs` — `Spend` (+`memo`), the output sealing at ~1536–1545, `send`/`send_asset`/`send_asset_with` (+`memo: &str`), deposit/mint sealers ~2395/~2414, `classify`/`Found` (carry memo), `OwnedNote` and `SentRow` (+`memo: Option<String>`, `#[serde(default)]`), `output_keys` (memo per row)
- Modify: `crates/randprotocol-client/src/lib.rs` (`RpcClient::envelope_format()` via `rand_getLimits`)
- Test: `wallet.rs` unit tests (`FakeChain` at ~3658), `crates/randprotocol-client/tests/wallet_flow.rs`

**Interfaces:**
- Consumes: `seal_note_as`, `open_memo`, `EnvelopeFormat`.
- Produces:
  - `RpcClient::envelope_format(&self) -> Result<EnvelopeFormat>` (cached per client; an old node without the field or without `rand_getLimits` → `Legacy`).
  - `wallet::send_asset(rpc, w, store, to, asset, amount, memo: &str, fee, profile, backend, chain_id, wait)` — `memo` inserted after `amount`; `send` likewise.
  - `OwnedNote.memo: Option<String>`, `SentRow.memo: Option<String>`, `OutputKey.memo: Option<String>`.
  - `Found::Received(Note, Option<String>)`, `Found::Sent(Note, Option<String>)`.

- [ ] **Step 1: Failing tests** in `wallet.rs`'s tests (the `FakeChain` harness):

```rust
    #[tokio::test]
    async fn on_a_memo_chain_every_output_is_1860_bytes_and_the_payee_reads_the_memo() {
        let chain = FakeChain::with_envelope_bytes(Some(1860)); // add this constructor: sets rand_getLimits' field
        let (alice, bob) = (chain.funded_wallet(10), chain.fresh_wallet());
        chain.send(&alice, &bob.address, 1, "coffee").await.unwrap();
        for e in chain.last_tx().bundle.unwrap().envelopes.iter() { assert_eq!(e.len(), 1860); }
        let bob_store = chain.scan(&bob).await;
        assert_eq!(bob_store.notes[0].memo.as_deref(), Some("coffee"));
        let alice_store = chain.scan(&alice).await;
        assert_eq!(alice_store.sent[0].memo.as_deref(), Some("coffee"));
    }

    #[tokio::test]
    async fn on_chain_14_the_wallet_seals_the_old_format_and_refuses_a_memo() {
        let chain = FakeChain::with_envelope_bytes(None);
        let (alice, bob) = (chain.funded_wallet(10), chain.fresh_wallet());
        let err = chain.send(&alice, &bob.address, 1, "coffee").await.unwrap_err();
        assert!(err.to_string().contains("no memo"));
        chain.send(&alice, &bob.address, 1, "").await.unwrap();
        for e in chain.last_tx().bundle.unwrap().envelopes.iter() { assert_eq!(e.len(), 1348, "an old wallet can open it"); }
    }

    #[test]
    fn a_store_written_before_the_memo_loads() {
        let json = r#"{"index":1,"note":"<a 224-hex-char note>","cm":"<64 hex>","nf":"<64 hex>","spent":false,"height":3}"#;
        let n: OwnedNote = serde_json::from_str(json).unwrap();
        assert_eq!(n.memo, None);
    }
```

The `FakeChain` helpers named here (`with_envelope_bytes`, `funded_wallet`, `fresh_wallet`, `send`, `last_tx`, `scan`) are thin wrappers over what the harness already does in its existing send tests; write the ones that do not exist by lifting the setup code from the nearest existing test (`grep -n "FakeChain::" crates/randprotocol-client/src/wallet.rs`). For the store test, fill the hex placeholders from `Note::new(...).to_bytes()` in the test itself rather than a literal, using `format!`.

- [ ] **Step 2: Run** → compile errors, then (after stubbing) the 1348-vs-1860 assertion fails. Quote it.

- [ ] **Step 3: Implement.**
  - `lib.rs`: `pub async fn envelope_format(&self) -> Result<EnvelopeFormat>` — `rand_getLimits`, read `envelope_bytes` as `Option<u32>`; `-32601` or a missing field → `EnvelopeFormat::Legacy`; memoise in a `OnceCell`.
  - `Spend` gains `pub memo: &'a str`. At the sealing site (~1540) the payee slot gets `seal_note_as(format, &w.vk, dest, &note, &key, spend.memo)`; `Payee::Me` (change) and `Payee::Nobody` (dummies) get `seal_note_as(format, …, "")` — every slot the same size. `format` is fetched once per `submit_spend` from `rpc.envelope_format()`.
  - Deposit/mint sealers (~2395, ~2414) take `format` and seal with `""`.
  - `classify`: after `open_as_receiver` returns `(key, note)`, `let memo = env.memo(cm, &key);` → `Found::Received(note, memo)`; likewise for the sender path. `scan` writes `memo` into `OwnedNote`/`SentRow`. `output_keys` fills `OutputKey.memo`.
  - Every other caller of `send`/`send_asset` in the workspace passes `""` (`cargo check --workspace --tests` finds them: the node's tests, `wallet_flow.rs`, cluster tests).

- [ ] **Step 4: Run** the three tests → pass; `cargo test --release -p randprotocol-client --lib`.

- [ ] **Step 5: Commit** `client: seal in the chain's envelope format; memo on send, in the note store and in tx keys`.

---

### Task 8: The CLI — fingerprint, links, QR, contacts, send resolution, memo columns

**Files:**
- Create: `crates/randprotocol-client/src/contacts.rs`
- Create: `crates/randprotocol-client/src/qr.rs` (terminal + PNG rendering over the `qrcode` crate)
- Modify: `crates/randprotocol-client/src/main.rs` (`Cmd::Address`, new `Cmd::Contacts`, `Cmd::Send`, `Cmd::Notes`, `Cmd::History`), `crates/randprotocol-client/src/lib.rs` (`pub mod contacts; pub mod qr;`), `crates/randprotocol-client/Cargo.toml` (`qrcode = { version = "0.14", default-features = false, features = ["image"] }`, `image = { version = "0.25", default-features = false, features = ["png"] }`)
- Test: `contacts.rs` unit tests, `main.rs` unit tests for `resolve_recipient`

**Interfaces:**
- Consumes: `ShieldedAddress::fingerprint`, `PaymentUri`, `wallet::send_asset(... memo ...)`.
- Produces:
  - `contacts::Contacts { entries: BTreeMap<String, String> }` with `load(key_path: &Path) -> Result<Contacts>` (file `<key>.contacts.json`, missing → empty), `save(&self, key_path)` (mode 0600, temp + rename), `add(&mut self, name, &ShieldedAddress) -> Result<()>`, `remove(&mut self, name) -> Result<()>`, `get(&self, name) -> Option<ShieldedAddress>`, `name_of(&self, &ShieldedAddress) -> Option<&str>`.
  - `fn resolve_recipient(to: &str, contacts: &Contacts) -> Result<(ShieldedAddress, Option<PaymentUri>, Option<String>)>` — address, the URI if one was given, the contact name if any.
  - `fn merge_uri(flag: Option<String>, uri: Option<String>, what: &str) -> Result<Option<String>>` — refuses a differing pair.
  - `wallet::parse_asset_amount(rpc, asset: u32, text: &str) -> Result<u64>` — RAND via `parse_amount` (9 decimals); a token via its registry `decimals` from the `rand_getTokens` listing; more fraction digits than allowed → `Err("… has at most N decimals")`.

- [ ] **Step 1: Failing tests.** `contacts.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn addr() -> ShieldedAddress {
        randprotocol_zkvm::address::address_of(&randprotocol_zkvm::notes::SpendKey::random().viewing_key())
    }
    #[test]
    fn names_that_look_like_addresses_or_links_are_refused() {
        let mut c = Contacts::default();
        for bad in ["", "rand1abc", "RAND1abc", "randpay:x", "RandPay:x", &"n".repeat(65)] {
            assert!(c.add(bad, &addr()).is_err(), "{bad:?}");
        }
        c.add("alice", &addr()).unwrap();
        assert!(c.add("alice", &addr()).is_err(), "unique name");
    }
    #[test]
    fn an_address_lives_under_one_name() {
        let (mut c, a) = (Contacts::default(), addr());
        c.add("alice", &a).unwrap();
        assert!(c.add("alice2", &a).is_err());
        assert_eq!(c.name_of(&a), Some("alice"));
    }
    #[test]
    fn the_file_is_private_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("w.key.json");
        let (mut c, a) = (Contacts::default(), addr());
        c.add("alice", &a).unwrap();
        c.save(&key).unwrap();
        let p = dir.path().join("w.key.json.contacts.json");
        #[cfg(unix)]
        { use std::os::unix::fs::PermissionsExt; assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600); }
        assert_eq!(Contacts::load(&key).unwrap().get("alice"), Some(a));
    }
}
```

`main.rs` tests:

```rust
    #[test]
    fn a_recipient_resolves_as_address_then_link_then_contact() {
        let a = /* a fresh address as above */;
        let mut c = contacts::Contacts::default();
        c.add("bob", &a).unwrap();
        assert_eq!(resolve_recipient(&a.to_string(), &c).unwrap().0, a);
        let (x, uri, _) = resolve_recipient(&format!("randpay:{a}?amount=2"), &c).unwrap();
        assert_eq!((x, uri.unwrap().amount.as_deref()), (a.clone(), Some("2")));
        let (x, _, name) = resolve_recipient("bob", &c).unwrap();
        assert_eq!((x, name.as_deref()), (a, Some("bob")));
        assert!(resolve_recipient("carol", &c).is_err());
    }
    #[test]
    fn a_flag_and_a_link_that_disagree_are_refused() {
        assert_eq!(merge_uri(Some("1".into()), None, "amount").unwrap(), Some("1".into()));
        assert_eq!(merge_uri(None, Some("1".into()), "amount").unwrap(), Some("1".into()));
        assert_eq!(merge_uri(Some("1".into()), Some("1".into()), "amount").unwrap(), Some("1".into()));
        assert!(merge_uri(Some("1".into()), Some("2".into()), "amount").is_err());
    }
```

And for `parse_asset_amount`, a unit test on its pure core `fn parse_decimal(text: &str, decimals: u8) -> Result<u64>`: `("1.5", 9) → 1_500_000_000`, `("1.1234567891", 9)` → Err containing `"at most 9 decimals"`, `("2", 0) → 2`, `("0.5", 0)` → Err.

- [ ] **Step 2: Run** `cargo test --release -p randprotocol-client contacts:: resolve_recipient merge_uri parse_decimal` → compile errors.

- [ ] **Step 3: Implement.**

`contacts.rs`:

```rust
//! Named addresses (spec 2026-09-26 §3.1), at `<key path>.contacts.json`, mode 0600.

use anyhow::{anyhow, Result};
use randprotocol_core::notes::ShieldedAddress;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Contacts { pub entries: BTreeMap<String, String> }

fn path_for(key: &Path) -> PathBuf { PathBuf::from(format!("{}.contacts.json", key.display())) }

impl Contacts {
    pub fn load(key: &Path) -> Result<Contacts> {
        match std::fs::read_to_string(path_for(key)) {
            Ok(s) => Ok(serde_json::from_str(&s)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Contacts::default()),
            Err(e) => Err(e.into()),
        }
    }
    pub fn save(&self, key: &Path) -> Result<()> {
        let p = path_for(key);
        let tmp = p.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
            let mut f = o.open(&tmp)?;
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, p)?;
        Ok(())
    }
    pub fn add(&mut self, name: &str, a: &ShieldedAddress) -> Result<()> {
        let lower = name.to_ascii_lowercase();
        if name.is_empty() || name.chars().count() > 64 || lower.starts_with("rand1") || lower.starts_with("randpay:") {
            return Err(anyhow!("a contact name is 1-64 characters and cannot start with rand1 or randpay:"));
        }
        if self.entries.contains_key(name) { return Err(anyhow!("a contact named {name} exists")); }
        if let Some(other) = self.name_of(a) { return Err(anyhow!("this address is already saved as {other}")); }
        self.entries.insert(name.to_string(), a.to_string());
        Ok(())
    }
    pub fn remove(&mut self, name: &str) -> Result<()> {
        self.entries.remove(name).map(|_| ()).ok_or_else(|| anyhow!("no contact named {name}"))
    }
    pub fn get(&self, name: &str) -> Option<ShieldedAddress> {
        self.entries.get(name).and_then(|s| ShieldedAddress::parse(s).ok())
    }
    pub fn name_of(&self, a: &ShieldedAddress) -> Option<&str> {
        let s = a.to_string();
        self.entries.iter().find(|(_, v)| **v == s).map(|(k, _)| k.as_str())
    }
}
```

`qr.rs`:

```rust
//! `randpay:` links as QR codes: level M, byte mode (spec §2.2).

use anyhow::Result;
use qrcode::{EcLevel, QrCode};

pub fn terminal(text: &str) -> Result<String> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)?;
    Ok(code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build())
}

pub fn png(text: &str, path: &std::path::Path) -> Result<()> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)?;
    code.render::<image::Luma<u8>>().min_dimensions(600, 600).build().save(path)?;
    Ok(())
}
```

Add a test: `terminal(&format!("randpay:{addr}?amount=1&memo={}", "x".repeat(200)))` is `Ok` (fits at M).

`main.rs`:
- `Cmd::Address` becomes `Address { #[arg(long)] uri: bool, #[arg(long)] amount: Option<String>, #[arg(long)] asset: Option<String>, #[arg(long)] memo: Option<String>, #[arg(long)] qr: bool, #[arg(long)] qr_png: Option<PathBuf> }`. Handler: print `a` and `fingerprint {a.fingerprint()}`; build `PaymentUri { address: a, amount, asset, memo }` (validate by `PaymentUri::parse(&u.format())?`); `--uri` prints it; `--qr` prints `qr::terminal`; `--qr-png` writes `qr::png`.
- `Cmd::Contacts { #[command(subcommand)] op: ContactsOp }` with `Add { name, to, #[arg(long)] yes: bool }`, `List`, `Show { name, #[arg(long)] qr: bool }`, `Remove { name }`. `Add` accepts an address or a link (`PaymentUri::parse` then `.address`), prints `fingerprint …`, asks `add {name}? [y/N]` on stdin unless `--yes`.
- `Cmd::Send`: `amount: Option<String>` (positional, optional), `#[arg(long)] memo: Option<String>`, `#[arg(long)] yes: bool`. Flow: `resolve_recipient` → `merge_uri` for amount/asset/memo → `amount` required after merge (`"no amount: give one or use a link that carries it"`) → `resolve_asset` → `wallet::parse_asset_amount` → print `to {name · }fingerprint {fp} · {amount} {asset} · memo "{memo}"` → confirm unless `--yes` → `send_asset(…, memo.as_deref().unwrap_or(""), …)`.
- `Cmd::Notes`: add a `memo` column (first 24 chars, `…` if cut); `--memo` prints it whole. `Cmd::History`: same, and the `to` column shows the contact name when the recipient's pk matches a contact's.

`parse_decimal` goes in `wallet.rs` beside `resolve_asset`:

```rust
pub fn parse_decimal(text: &str, decimals: u8) -> Result<u64> {
    let (int, frac) = text.split_once('.').unwrap_or((text, ""));
    if int.is_empty() || !int.bytes().all(|c| c.is_ascii_digit()) || !frac.bytes().all(|c| c.is_ascii_digit()) || (text.contains('.') && frac.is_empty()) {
        return Err(anyhow!("{text} is not a decimal amount"));
    }
    if frac.len() > decimals as usize {
        return Err(anyhow!("{text}: this asset has at most {decimals} decimals"));
    }
    let scaled = format!("{int}{frac:0<width$}", width = decimals as usize);
    scaled.parse::<u64>().map_err(|_| anyhow!("{text} is too large"))
}
```

`parse_asset_amount(rpc, asset, text)`: asset 0 → `parse_decimal(text, 9)`; otherwise read the token row's `decimals` from the same `rand_getTokens` paging `resolve_asset` does (whole listing, never a single-token lookup) → `parse_decimal(text, decimals)`. **Behaviour change to call out in the commit:** a token amount on the command line is now in the token's display units, matching links; the old whole-smallest-unit form is gone.

- [ ] **Step 4: Run** all Task 8 tests → pass. `cargo build --release -p randprotocol-client` and a manual smoke: `rand --key <scratch key> address --qr` renders; `rand contacts add x <addr> --yes`; `rand contacts list`.

- [ ] **Step 5: Commit** `rand: fingerprint, randpay: links and QR on address; contacts; send by address, link or name with a memo`.

---

### Task 9: End-to-end round trip, docs, and the genesis cut hook

**Files:**
- Modify: `crates/randprotocol-client/tests/wallet_flow.rs` (a memo-chain round trip)
- Modify: `docs/cli.md`, `docs/rpc.md` (`rand_getLimits.envelope_bytes`, `memo` in disclosed notes, changelog), `docs/shielded.md` (the memo field and envelope size), `docs/deploy.md` ("The next cut": set `envelope_bytes: 1860` with `rand-node genesis --envelope-bytes 1860`; ship apps + website first)
- Modify: `crates/randprotocol-core/tests/vectors/address-sharing.json` (`memos` array: empty, `"Invoice #42"`, the 510-byte `é`×255, and the three malformed fields as hex)

- [ ] **Step 1: Failing test** in `wallet_flow.rs` — a new `#[tokio::test]` next to the existing flow, same one-node in-process chain, genesis with `envelope_bytes = Some(1860)`; take `proving_slot` around the send (as the file's existing sends do); faucet → send 1 RAND with memo `"round trip"` → payee scan shows `memo == Some("round trip")` → sender `history` row shows it → `rand_checkTransaction(hash, <output tx key>)` returns `note.memo == "round trip"` → every envelope in the committed bundle is 1 860 bytes.

- [ ] **Step 2: Run** `cargo test --release -p randprotocol-client --test wallet_flow memo` (≈ one bundle proof, a few minutes) → pass (Tasks 5–7 already landed; if it fails, the failure is a real integration bug — fix it in the owning task's code and note it).

- [ ] **Step 3: Memo vectors.** Add the `memos` entries and a `memos_match_the_vectors` test in `address_sharing_vectors.rs` that runs each through `randprotocol_zkvm`'s `memo_field`/`memo_text` — put that test in `crates/randprotocol-zkvm/tests/shielded.rs` (core cannot depend on zkvm), reading the same JSON via `include_str!("../../randprotocol-core/tests/vectors/address-sharing.json")`.

- [ ] **Step 4: Docs** as listed; each doc change is the behaviour the code now has, no more.

- [ ] **Step 5: Full suite** detached: `nohup cargo test --workspace --release -- --skip round_trips --skip two_test_profile > /tmp/memo-suite.log 2>&1 &`; record pass counts per binary in the commit message. Recursion-fixture tests skipped by name as the release suites do.

- [ ] **Step 6: Commit** `address sharing: wallet-flow memo round trip, vectors, docs (cli, rpc, shielded, deploy)`.

---

## Part B — randscan's viewing crate and the website

### Task 10: `randscan-viewing` opens the memo body

**Files:**
- Modify: `/Users/dendisuhubdy/Github/randprotocol/randscan/crates/randscan-viewing/src/lib.rs` (`open_note`, `fn opened` ~409)
- Test: the same crate's tests

**Interfaces:**
- Produces: `open_note(...)` JSON gains `"memo": string | null`; bodies of 112 and 624 plaintext bytes both open.

- [ ] **Step 1: Branch** `git -C /Users/dendisuhubdy/Github/randprotocol/randscan worktree add /tmp/randscan-memo -b feat/address-sharing main`.
- [ ] **Step 2: Failing test** — seal a memo envelope with fullnode's `seal_note_as` is not available here (native crate), so use a fixture: generate with fullnode (`cargo run` a scratch test in `/tmp/fullnode-memo` that prints `{cm, envelope_json, viewing_key, memo}` for one memo envelope and one legacy envelope) and paste both into `randscan-viewing/tests/fixtures/memo.json`. Test: `open_note(cm, env, "viewing", vk)` → `memo == "fixture memo"`; the legacy one → `memo == null`; a body with a corrupted memo field (re-sealed in the scratch generator with len 600) → note opens, `memo == null`.
- [ ] **Step 3: Run** → the memo envelope returns `"null"` (body length not accepted). Quote.
- [ ] **Step 4: Implement** — where the crate decrypts the body and parses 112 bytes into `Note`, accept `112 | 624` exactly as `body_parts` in Task 1, parse the memo field with the same rules as `memo_text` (copy the 12-line function with a comment naming its source, `circuits/research/src/viewing.rs`), add `memo: Option<String>` to `OpenedNote`.
- [ ] **Step 5: Run** → pass; `cargo test` in the crate.
- [ ] **Step 6: Commit** in randscan: `viewing: open the 1860-byte memo envelope; memo in open_note`. (The explorer's own pages showing the memo is randscan work outside this plan; the JSON field is what they need.)

### Task 11: The website — wasm exports, `/address`, `/account`, contacts

**Files:**
- Modify: `/Users/dendisuhubdy/Github/randprotocol/randprotocol.org/server/address-wasm/src/lib.rs` (exports `fingerprint`, `uriFormat`, `uriParse`)
- Replace: `randprotocol.org/src/scripts/qr.js` with the clients' `ui/lib/qr.js` encoder (versions 1–40), keeping the exported names `qrMatrix(text)` and `qrSvgPath(matrix)` and switching level to M
- Create: `randprotocol.org/src/scripts/contacts.js`
- Modify: `src/components/WalletGenerator.astro`, `src/pages/address.astro`, `src/components/BalanceViewer.astro`
- Test: `randprotocol.org/tests/contacts.test.mjs`, `tests/qr.test.mjs`, `server/address-wasm` Rust tests

**Interfaces:**
- Consumes: Tasks 3–4 (path deps on the fullnode checkout — point the build at `/tmp/fullnode-memo` via the relative path the Cargo.toml already uses, i.e. build from a website worktree beside a fullnode checkout at the Task 9 commit).
- Produces (wasm): `fingerprint(address: &str) -> Result<String, JsError>`, `uriFormat(address, amount?, asset?, memo?) -> Result<String, JsError>`, `uriParse(uri) -> Result<String /* JSON {address, amount, asset, memo, fingerprint} */, JsError>`. JS: `contacts.js` exports `listContacts()`, `addContact(name, address)`, `removeContact(name)` over `localStorage` key `rand.contacts.v1`, every access in try/catch, same name rules as the CLI.

- [ ] **Step 1: Branch** `git -C …/randprotocol.org worktree add /tmp/site-memo -b feat/address-sharing main`.
- [ ] **Step 2: Failing tests.** Rust (address-wasm): `fingerprint(<seed address>) == "1WCV-YC8F-47BY-5RZY"`; `uriParse(uriFormat(a, Some("1.5"), None, Some("hi")))` round-trips. JS `tests/qr.test.mjs`: `qrMatrix("randpay:" + "x".repeat(1700))` returns a matrix of size ≥ 129 (version ≥ 29) and does not throw. `tests/contacts.test.mjs` (node's test runner with a `globalThis.localStorage` shim): add/list/remove; `addContact("rand1x", …)` throws; `localStorage` throwing on `getItem` → `listContacts()` returns `[]`.
- [ ] **Step 3: Run** `cargo test --release` in `server/address-wasm` and `node --test tests/` → failures (missing exports; qr throws past version 10).
- [ ] **Step 4: Implement.**
  - address-wasm:

```rust
#[wasm_bindgen]
pub fn fingerprint(address: &str) -> Result<String, JsError> {
    let a = ShieldedAddress::parse(address).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(a.fingerprint().to_string())
}
#[wasm_bindgen(js_name = uriFormat)]
pub fn uri_format(address: &str, amount: Option<String>, asset: Option<String>, memo: Option<String>) -> Result<String, JsError> {
    let a = ShieldedAddress::parse(address).map_err(|e| JsError::new(&e.to_string()))?;
    let u = PaymentUri { address: a, amount, asset, memo };
    PaymentUri::parse(&u.format()).map_err(|e| JsError::new(&e.to_string()))?; // validate
    Ok(u.format())
}
#[wasm_bindgen(js_name = uriParse)]
pub fn uri_parse(uri: &str) -> Result<String, JsError> {
    let u = PaymentUri::parse(uri).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "address": u.address.to_string(), "amount": u.amount, "asset": u.asset,
        "memo": u.memo, "fingerprint": u.address.fingerprint().to_string() }).to_string())
}
```

  - `qr.js`: port the encoder from `clients/ui/lib/qr.js` (copy with a header comment naming the source file and commit), wrap its output in the existing `qrMatrix`/`qrSvgPath` API, level M.
  - `WalletGenerator.astro` / `address.astro`: under `[data-gen-address]` and `[data-acct-address]` render `fingerprint …`; an SVG QR of `uriFormat(address)`; buttons "Copy address" and "Copy payment link"; a small form (amount, asset, memo) that re-renders the QR and the link on input; a contacts panel (list, add with fingerprint shown, remove) with the note "Saved in this browser only; clearing site data removes them."
  - `BalanceViewer.astro`: add a Memo column rendering `r.note.memo ?? "—"` as text (never `innerHTML`).
  - Rebuild the pinned wasm modules: `server/address-wasm/build.sh` and `server/viewing-wasm/build.sh` (the latter from `/tmp/randscan-memo`), committing the regenerated `SHA256`/`BUILT_FROM`.
  - `server/csp-keypages.sh` after `npm run build` to refresh the inline-script hashes.
- [ ] **Step 5: Run** all tests → pass; `npm run build` → clean; `npm run preview` and check `/address` renders the QR and fingerprint for a generated wallet (scan it with a phone camera: it must read as a `randpay:` link).
- [ ] **Step 6: Commit** in the website repo. **Deploy (`server/deploy-site.sh`) only on the user's go.**

---

## Part C — the wallet apps (`../clients`)

### Task 12: `clients/core` — re-vendor and the new methods

**Files:**
- Modify: `clients/core/vendor/fullnode` (submodule → the Task 9 commit, pushed to a `feat/address-sharing` branch of fullnode first — **pushing needs the user's go**; until then point the submodule at a local path for development: `git -C clients/core/vendor/fullnode fetch /tmp/fullnode-memo feat/address-sharing && git checkout FETCH_HEAD`)
- Modify: `clients/core/crates/wallet-core/src/lib.rs` (dispatch arms; `ProveRequest.memo`, `ProveRequest.envelope_bytes`; `OwnedNote.memo`, `SentRow.memo` in `scan_page`)
- Test: `clients/core/crates/wallet-core` tests

**Interfaces:**
- Produces (dispatch methods): `"address_fingerprint" {address} -> {fingerprint}`; `"uri_parse" {uri} -> {address, amount, asset, memo, fingerprint}`; `"uri_format" {address, amount?, asset?, memo?} -> {uri}`; `"prove_transfer"` accepts `memo: string` (default `""`) and `envelope_bytes: number | null` (from the engine's `rand_getLimits` call; null → legacy format); `"scan_page"` rows gain `memo`.

- [ ] **Step 1: Failing tests** (in wallet-core's test module):

```rust
#[test]
fn fingerprint_and_links_through_dispatch() {
    let a = SEED_ADDRESS; // the Appendix A address, as a const in the test module
    let v = dispatch("address_fingerprint", &json!({"address": a})).unwrap();
    assert_eq!(v["fingerprint"], "1WCV-YC8F-47BY-5RZY");
    let u = dispatch("uri_format", &json!({"address": a, "amount": "1.5", "memo": "hi"})).unwrap();
    let p = dispatch("uri_parse", &json!({"uri": u["uri"]})).unwrap();
    assert_eq!((p["amount"].as_str(), p["memo"].as_str()), (Some("1.5"), Some("hi")));
    assert!(dispatch("uri_parse", &json!({"uri": "randpay:rand1x"})).is_err());
}
```

and a `prove_transfer`-free check of the sealing choice: a helper `seal_outputs_for(envelope_bytes: Option<u32>, memo: &str)` factored out of `prove_transfer`'s sealing step, asserting 1 860-byte envelopes with `Some(1860)` and 1 348 with `None`, and `Err` for `None` + non-empty memo.

- [ ] **Step 2: Run** `cargo test --release -p wallet-core` → failures.
- [ ] **Step 3: Implement** the arms with `randprotocol_core::{fingerprint, payment_uri}`; in `prove_transfer` compute `EnvelopeFormat::for_chain(req.envelope_bytes)` and seal every output through `randprotocol_zkvm::address::seal_note_as(format, …, memo_or_empty)`; in `scan_page` open the memo with `open_memo` using the tx key the open returned. Update the pinned commit mentioned in `core/Cargo.toml` and `core/README.md` comments.
- [ ] **Step 4: Run** → pass; `core/scripts/build-wasm.sh` succeeds.
- [ ] **Step 5: Commit** `core: re-vendor fullnode (address sharing); fingerprint, randpay links, memo on send and scan`.

### Task 13: Shared UI (`clients/ui`) — receive, send, contacts, memo

**Files:**
- Modify: `ui/screens/receive.js`, `ui/screens/send.js`, `ui/screens/send/markup.js`, `ui/screens/send/state.js`, `ui/backend.js` (send request `{asset, to, amount, memo}`), `ui/engine/backend-shared.js` (storage key `contacts`; `rand_getLimits` → `envelope_bytes` passed to `prove_transfer`), the notes list screen (the file that renders `notes`; find with `grep -ln "notes" ui/screens`)
- Create: `ui/screens/contacts.js`, `ui/lib/contacts.js`, `ui/lib/scan-qr.js`
- Test: `ui/test/contacts.test.mjs`, `ui/test/send.test.mjs` (extend), `ui/test/screens.test.mjs` (extend)

**Interfaces:**
- Consumes: Task 12 dispatch methods through the backend's `core.call`.
- Produces: `ui/lib/contacts.js` — `listContacts(storage)`, `addContact(storage, name, address)`, `removeContact(storage, name)`, `nameOf(storage, address)`, same rules as the CLI; `ui/lib/scan-qr.js` — `scanQr(videoEl) -> Promise<string>` using `BarcodeDetector` when `'BarcodeDetector' in globalThis`, else rejects `new Error('camera scanning is not available here; paste the link')`.

- [ ] **Step 1: Failing tests.** `contacts.test.mjs` (with the in-memory storage helper the other engine tests use): add/list/remove; `rand1…`/`randpay:` names refused; duplicate address refused. `send.test.mjs`: pasting a `randpay:` link into the recipient fills amount and memo in the draft; a link amount that differs from an already-typed amount shows the error "The link asks for X; you typed Y" and blocks Continue; the confirmation markup contains the fingerprint and `memo "…"`; on a chain whose limits have `envelope_bytes: null`, the memo field is hidden and a link's memo shows the notice "This network doesn't carry memos; the memo will not be sent" and blocks Continue until cleared. `screens.test.mjs`: the receive screen renders the fingerprint text, a QR canvas, and "Copy payment link".
- [ ] **Step 2: Run** `node --test ui/test` → failures.
- [ ] **Step 3: Implement.**
  - `receive.js`: `core.call('address_fingerprint', {address})`; QR of `uri_format({address})` via `encodeBytes(new TextEncoder().encode(uri))` at level M (extend `ui/lib/qr.js`'s `encodeBytes` with an `ecLevel` parameter defaulting to its current L so existing callers are unchanged); amount/asset/memo inputs that rebuild the link and QR; Share/Copy buttons through `platform.share?.()`/`platform.copy`.
  - `send.js` + `state.js`: recipient input accepts address, link (`uri_parse`) or contact name (picker); merge rules as the CLI; memo textarea with a live byte counter "N/510 bytes" (UTF-8 length); confirmation line from spec §3; the camera button calls `platform.scanQr?.()` (native shells) or `scanQr(video)` (browser), hidden when neither exists.
  - `contacts.js` screen: list, add (paste/scan, fingerprint shown before save), remove; registered with `registerScreen('contacts', …)` and linked from the send screen's recipient picker and from settings.
  - Notes list: show `memo` under the amount when present (text node, never `innerHTML`).
- [ ] **Step 4: Run** → pass (`node --test ui/test web/wallet/test extension/test`).
- [ ] **Step 5: Commit** `ui: receive with fingerprint and randpay QR; send by link, scan or contact with a memo; contacts`.

### Task 14: Shells — desktop deep links, web wallet handler, extension packaging

**Files:**
- Modify: `desktop/src-tauri/Cargo.toml` (`tauri-plugin-deep-link = "2"`), `desktop/src-tauri/src/main.rs` (register plugin, forward `randpay:` URLs to the UI as an event), `desktop/src-tauri/tauri.conf.json` (`plugins.deep-link.desktop.schemes: ["randpay"]`), `desktop/ui-shell/main.js` (on the event, open the send screen with the link)
- Modify: `web/wallet/main.js` (`navigator.registerProtocolHandler('web+randpay', location.origin + '/#/send?uri=%s')` inside try/catch — browsers only allow `web+` custom schemes, so the web wallet also accepts `web+randpay:` and strips `web+`), `ui/app.js` router (`#/send?uri=` opens send pre-filled)
- Modify: `chrome/pack.sh`, `firefox/pack.sh` only if the new `ui/lib/*.js` files are excluded by their rsync filters (check; they should not be)
- Test: `web/wallet/test` (router opens send with a link), desktop: `cargo check` in `desktop/src-tauri`

- [ ] **Step 1: Failing test** in `web/wallet/test`: mounting the app at `#/send?uri=<encoded randpay link>` lands on the send screen with the recipient filled; `web+randpay:` prefix is accepted.
- [ ] **Step 2: Run** → fails.
- [ ] **Step 3: Implement** as listed. The URI parsing always goes through `core.call('uri_parse')`; the shell only forwards the string.
- [ ] **Step 4: Run** tests; `cargo check` in `desktop/src-tauri`; `desktop/scripts/stage-ui.mjs` then `npm run tauri dev` smoke: `open "randpay:<addr>?amount=1"` on macOS opens the app on the send screen.
- [ ] **Step 5: Commit** `shells: randpay: links open the send screen (desktop deep link, web wallet handler)`.

### Task 15: iOS

**Files:**
- Modify: `ios/RandWallet/Info.plist` (`CFBundleURLTypes` with scheme `randpay`), the app entry (`.onOpenURL` → route to `SendView` with the link), `ios/RandWallet/UI/ReceiveView.swift` (fingerprint text, QR of the link at `inputCorrectionLevel = "M"`, amount/asset/memo fields, share sheet), `ios/RandWallet/UI/SendView.swift` (parse links through the core, memo field with byte counter, confirmation line, contact picker; `QRScannerView` result goes through `uri_parse`)
- Create: `ios/RandWallet/Storage/Contacts.swift` (Keychain-backed JSON beside the existing storage, same rules), `ios/RandWallet/UI/ContactsView.swift`
- Test: the iOS test target (`ios/RandWalletTests`, create if absent via `project.yml`) — `ContactsTests` (rules), `SendLinkTests` (a link fills amount/memo; a mismatch is refused)

- [ ] **Step 1–2:** Write the two XCTest files; run `xcodebuild test -scheme RandWallet -destination 'platform=iOS Simulator,name=iPhone 16'` → fail.
- [ ] **Step 3:** Implement as listed; the core is reached through the existing XCFramework `rand_wallet_call` wrapper (rebuild with `core/scripts/build-ios.sh`).
- [ ] **Step 4:** Tests pass; simulator smoke: `xcrun simctl openurl booted "randpay:<addr>?amount=1&memo=hi"` opens Send pre-filled.
- [ ] **Step 5: Commit** `ios: randpay links, fingerprint and memo on receive/send, contacts`.

### Task 16: Android

**Files:**
- Modify: `android/app/src/main/AndroidManifest.xml` (on `SendActivity`: `<intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="randpay"/></intent-filter>`; `<uses-permission android:name="android.permission.CAMERA"/>`), `android/app/build.gradle` (`com.journeyapps:zxing-android-embedded:4.3.0` for scanning), `ReceiveActivity.java` (fingerprint, QR at `ErrorCorrectionLevel.M` of the link, amount/asset/memo, share intent), `SendActivity.java` (handle `getIntent().getData()`, Scan button, memo field with byte counter, confirmation, contact picker), `res/layout/activity_receive.xml`, `activity_send.xml`
- Create: `store/Contacts.java` (EncryptedSharedPreferences JSON, same rules), `ui/ContactsActivity.java`, `res/layout/activity_contacts.xml`
- Test: `android/app/src/test/java/org/randprotocol/wallet/store/ContactsTest.java`, `…/ui/SendLinkTest.java` (pure logic: link merge rules extracted into a `SendDraft` class)

- [ ] **Step 1–2:** Write the JUnit tests; `./gradlew testDebugUnitTest` → fail.
- [ ] **Step 3:** Implement as listed (core via the existing JNI `NativeCore.call`; rebuild `.so` with `core/scripts/build-android.sh`).
- [ ] **Step 4:** Tests pass; emulator smoke: `adb shell am start -a android.intent.action.VIEW -d "randpay:<addr>?amount=1"` opens Send pre-filled; Scan reads a QR from `/address` on the website.
- [ ] **Step 5: Commit** `android: randpay links, QR scan, fingerprint and memo, contacts`.

---

## Part D — release order

### Task 17: Cross-repo verification and the launch checklist

**Files:**
- Modify: `docs/deploy.md` ("The next cut" → an "Address sharing" checklist)

- [ ] **Step 1:** Run every repo's suite once more on the final commits: fullnode (Task 9's), `circuits/research` viewing tests, randscan-viewing, website `node --test tests/` + `cargo test` in address-wasm, clients `node --test ui/test web/wallet/test extension/test` + `cargo test` in core + gradle + xcodebuild. Record counts.
- [ ] **Step 2: Bridge relayer check.** `grep -rn "seal_note\|Envelope::seal\|envelope" ../bridge --include=*.rs | head` — a relayer that builds `BridgeAttest` envelopes itself must seal the 1 860-byte form on the launch chain. If it calls `randprotocol-client`'s deposit sealer (Task 7), nothing to do; if it has its own, add a task to the bridge repo before the cut and report it.
- [ ] **Step 3:** Write the checklist into `docs/deploy.md`: (1) apps and website released with the new core; (2) randscan deployed with Task 10; (3) the launch genesis cut with `rand-node genesis --envelope-bytes 1860`; (4) after the cut, `rand_getLimits.envelope_bytes == 1860` on every node and a faucet mint's envelope is 1 860 bytes.
- [ ] **Step 4: Commit** `docs: address-sharing release checklist`. Merging to `main` of each repo is a rebase + fast-forward (no merge commits); pushes, the website deploy, app store uploads and the cut each wait for the user's go.
