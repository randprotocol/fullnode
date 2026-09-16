//! Resolving a receiver id to the address a note is sealed to (spec §4–§5).
//!
//! A `rand1…` receiver id says *who*, not *how*: the 1,184-byte ML-KEM-768 encapsulation key an
//! envelope is sealed to lives in a signed [`ReceiverRecord`] the id resolves to. Two paths
//! deliver one, and this module is both of them:
//!
//! - **the payment request** ([`PaymentRequest`]): a URI the receiver hands the sender, carrying
//!   the record inline. Needs no chain, no explorer and no registration — a receiver who has
//!   never been on chain can still be paid.
//! - **the registry** ([`resolve`]): the explorer's `GET {registry}/receivers/{id}`, which
//!   indexes every `RegisterReceiver` the chain has committed.
//!
//! **Nothing here trusts whoever supplied the record.** Every path ends in
//! `ReceiverRecord::verify(&id, chain_id)` — blake3 of the record's signing key is the id, and
//! the receiver's own Dilithium2 signature covers `(chain_id, version, pk, kem_ek)`. A hostile
//! explorer, a tampered URI or a doctored file can withhold a record or serve a stale one; it
//! cannot make this wallet seal a note to a key the receiver did not authorise. A stale version
//! is harmless: the receiver keeps every retired KEM secret (spec §7) and opens the note anyway.

use anyhow::{anyhow, Context, Result};
use randprotocol_core::genesis::ReceiverRecordHex;
use randprotocol_core::notes::ShieldedAddress;
use randprotocol_core::receiver::{ReceiverId, ReceiverRecord};
use std::path::Path;

/// Where `rand send` looks a receiver id up when it is handed no record: the explorer's API
/// (spec §5, the user's ruling 2 — registry lookups are the explorer's, not a validator's).
pub const DEFAULT_REGISTRY: &str = "https://randscan.org/api/v1";

/// The §4 error, verbatim: what a sender is told when no path delivered a record. It names the
/// two things that can fix it, because both are the receiver's to do and neither is obvious.
pub fn no_record_error(id: &ReceiverId) -> anyhow::Error {
    anyhow!("no receiver record for {id}: ask the receiver for a payment request, or for them to register")
}

// ---------------------------------------------------------------- the payment request

/// A payment request (spec §4): the receiver's id, the record that resolves it, and optionally
/// what they are asking for.
///
/// The record travels *with* the request — about 6.8 KB of URI — which is what makes this the
/// path that needs no chain state at all. `id` is carried beside it rather than derived so that
/// a tampered record fails [`resolve_from_request`] loudly instead of resolving to whatever
/// identity the tamperer signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    pub id: ReceiverId,
    pub record: ReceiverRecord,
    /// Units, not RAND: the wire carries the integer the wallet spends in.
    pub amount: Option<u64>,
    pub memo: Option<String>,
}

impl PaymentRequest {
    /// `rand:<address>?rec=<base64url(bincode(record))>[&amount=…][&memo=…]`.
    pub fn to_uri(&self) -> String {
        let mut uri = format!("rand:{}?rec={}", self.id, base64url_encode(&bincode::serialize(&self.record).expect("a record serializes")));
        if let Some(a) = self.amount {
            uri.push_str(&format!("&amount={a}"));
        }
        if let Some(m) = &self.memo {
            uri.push_str(&format!("&memo={}", percent_encode(m)));
        }
        uri
    }

    /// The inverse of [`to_uri`](Self::to_uri). Shape only — that the record is *this* id's is
    /// [`resolve_from_request`]'s job, and it is a different kind of failure.
    pub fn parse(s: &str) -> Result<PaymentRequest> {
        let rest = s.strip_prefix("rand:").context("a payment request starts with `rand:`")?;
        let (address, query) = rest.split_once('?').context("a payment request carries a `?rec=` record")?;
        let id = ReceiverId::parse(address).map_err(|e| anyhow!("{e}")).context("the request's address")?;
        let (mut rec, mut amount, mut memo) = (None, None, None);
        for part in query.split('&') {
            let Some((k, v)) = part.split_once('=') else { continue };
            match k {
                "rec" => {
                    let bytes = base64url_decode(v).context("the request's `rec` is not base64url")?;
                    rec = Some(bincode::deserialize(&bytes).context("the request's `rec` is not a receiver record")?);
                }
                "amount" => amount = Some(v.parse::<u64>().context("the request's `amount` is not a number of units")?),
                "memo" => memo = Some(percent_decode(v).context("the request's `memo` is not valid text")?),
                _ => {}
            }
        }
        Ok(PaymentRequest { id, record: rec.context("a payment request carries a `rec=` record")?, amount, memo })
    }
}

/// The address to seal to, from a request — after the one check that matters.
pub fn resolve_from_request(req: &PaymentRequest, chain_id: u64) -> Result<ShieldedAddress> {
    verified(&req.record, &req.id, chain_id)
}

// ---------------------------------------------------------------- resolution

/// Resolve `id` to the address a note is sealed to, in the order [`rand send`] uses: an
/// offline `--record` file first, then the registry, then the §4 error.
///
/// `registry` is `None` for a wallet told to consult none — the offline path — and the error it
/// returns is the same one a 404 produces, because the sender's situation is the same.
pub async fn resolve(
    id: &ReceiverId,
    chain_id: u64,
    record_file: Option<&Path>,
    registry: Option<&str>,
) -> Result<ShieldedAddress> {
    Ok(ShieldedAddress::from(&resolve_record(id, chain_id, record_file, registry).await?))
}

/// The same resolution, keeping the record itself — what a sender who is also *publishing* it
/// needs (the sender-paid registration of spec §6.3). The record it returns has been verified.
pub async fn resolve_record(
    id: &ReceiverId,
    chain_id: u64,
    record_file: Option<&Path>,
    registry: Option<&str>,
) -> Result<ReceiverRecord> {
    let record = match record_file {
        Some(path) => Some(record_from_file(path)?),
        None => match registry {
            Some(registry) => fetch_record(registry, id).await?,
            None => None,
        },
    };
    let record = record.ok_or_else(|| no_record_error(id))?;
    verified(&record, id, chain_id)?;
    Ok(record)
}

/// A `ReceiverRecordHex` JSON file — the exact file `rand address --record` writes and
/// `rand-node genesis --receiver` reads.
pub fn record_from_file(path: &Path) -> Result<ReceiverRecord> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading the record file {}", path.display()))?;
    record_from_json(&serde_json::from_str(&text).with_context(|| format!("{} is not a receiver record JSON file", path.display()))?)
}

/// A record out of the explorer's (or the node's) JSON: the same hex fields `ReceiverRecordHex`
/// has. The explorer adds `tx_hash` and `height`, which are ignored — they are about where the
/// record was published, and nothing in the verification depends on that.
pub fn record_from_json(v: &serde_json::Value) -> Result<ReceiverRecord> {
    let hex: ReceiverRecordHex = serde_json::from_value(v.clone()).context("a receiver record's fields")?;
    hex.to_record().map_err(|e| anyhow!("{e}"))
}

/// `GET {registry}/receivers/{id}`. `None` for a 404 — never registered, which is an answer and
/// not a failure. Any other status, or a body that is not a record, is an error: a sender must
/// not treat a broken explorer as "this receiver does not exist" and fall back to nothing.
async fn fetch_record(registry: &str, id: &ReceiverId) -> Result<Option<ReceiverRecord>> {
    let url = format!("{}/receivers/{id}", registry.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .with_context(|| format!("asking the registry at {url}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(anyhow!("the registry at {url} answered {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.with_context(|| format!("decoding the registry's reply from {url}"))?;
    if v.is_null() {
        return Ok(None);
    }
    Ok(Some(record_from_json(&v)?))
}

/// The one gate every supplied record passes through (spec §3). Nothing about who supplied it
/// enters the check.
pub fn verified(record: &ReceiverRecord, id: &ReceiverId, chain_id: u64) -> Result<ShieldedAddress> {
    record
        .verify(id, chain_id)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| format!("the record offered for {id} is not one that receiver signed"))?;
    Ok(ShieldedAddress::from(record))
}

// ---------------------------------------------------------------- publishing a record

/// What `rand register` should do, given what the chain already holds for this id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterPlan {
    /// Publish a record built at this KEM key version; its record version is `kem_version + 1`.
    Publish { kem_version: u32 },
    /// The chain already holds a record and no rotation was asked for. Not an error: the wallet
    /// is in the state the user asked for.
    AlreadyRegistered { version: u32 },
    /// `--rotate` on an id the chain has never seen — there is nothing to rotate *from*, and
    /// version 1 is the only record a first registration may publish.
    NothingToRotate,
}

/// The version a registration must publish, taken from the chain and never from the wallet's own
/// counter (spec §6.2: the ledger admits exactly `current + 1`, or 1 for a first registration).
///
/// This is the whole of the retry story. A rotation whose transaction did not commit leaves a
/// wallet whose counter has moved and a chain that has not; deriving the next version from the
/// counter would then publish `current + 2`, which the ledger refuses — and refuses again on
/// every later attempt, because the counter moves each time. Deriving it from `current` instead
/// makes a retry publish the same version as the attempt that failed, which is what idempotent
/// means here. A counter that has run ahead is reconciled back down to what the chain will
/// accept, so that what the wallet advertises is what it published.
pub fn registration_target(chain_version: Option<u32>, rotate: bool) -> RegisterPlan {
    match (chain_version, rotate) {
        // A rotation publishes `current + 1`, i.e. KEM key version `current` (record version
        // `kem + 1`).
        (Some(current), true) => RegisterPlan::Publish { kem_version: current },
        (None, true) => RegisterPlan::NothingToRotate,
        (None, false) => RegisterPlan::Publish { kem_version: 0 },
        (Some(version), false) => RegisterPlan::AlreadyRegistered { version },
    }
}

/// Whether a sender-paid registration (spec §6.3) may ride a payment, and if not, why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CarriedRegistration {
    Publish,
    /// Pay without registering, and say this.
    Skip(String),
}

/// Decide whether the record a sender resolved can be published on the bundle that pays its
/// owner.
///
/// The asymmetry that makes this worth a function: the registration is free to skip and
/// expensive to get wrong. A record at a version the ledger will not accept does not merely fail
/// to register — it makes the whole transaction inadmissible, and the payment inside it is a
/// bundle proof that has already been paid for in a minute and a half of this machine. So the
/// only version that rides is the one the chain will take, and every other case pays.
pub fn carried_registration(record_version: u32, chain_version: Option<u32>) -> CarriedRegistration {
    let wanted = chain_version.map_or(1, |c| c + 1);
    if record_version == wanted {
        return CarriedRegistration::Publish;
    }
    CarriedRegistration::Skip(match chain_version {
        Some(c) => format!(
            "the chain holds version {c} of this record and only version {wanted} may follow it, \
             while the record offered is version {record_version}"
        ),
        None => format!(
            "this receiver has never registered, so only version 1 may be published, \
             while the record offered is version {record_version}"
        ),
    })
}

// ---------------------------------------------------------------- URI encodings

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url (RFC 4648 §5), by hand: the record is the only thing this wallet
/// base64s, and a dependency for forty lines of table lookup is not worth the supply chain.
fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let take = chunk.len() + 1;
        for i in 0..take {
            out.push(B64[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

fn base64url_decode(s: &str) -> Result<Vec<u8>> {
    let value = |c: u8| -> Result<u32> {
        B64.iter().position(|&b| b == c).map(|i| i as u32).ok_or_else(|| anyhow!("{} is not base64url", c as char))
    };
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        if chunk.len() == 1 {
            return Err(anyhow!("truncated base64url"));
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push(((n >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Percent-encoding for the memo, which is free text and would otherwise be able to add query
/// parameters of its own. Unreserved characters (RFC 3986 §2.3) pass through.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).context("a truncated percent escape")?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex)?, 16).context("a bad percent escape")?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;
    use randprotocol_zkvm::notes::SpendKey;

    /// The offline path end to end (spec §4): a request round-trips through its URI, resolves
    /// with no chain and no explorer, and refuses a record that was touched on the way.
    #[test]
    fn a_payment_request_round_trips_and_resolves_offline() {
        let w = Wallet::from_spend_key(SpendKey([11; 8]));
        let req = PaymentRequest { id: w.id, record: w.record(10), amount: Some(1_500_000_000), memo: Some("coffee".into()) };
        let uri = req.to_uri();
        assert!(uri.starts_with(&format!("rand:{}?rec=", w.id)));
        let back = PaymentRequest::parse(&uri).unwrap();
        assert_eq!(back, req);
        let addr = resolve_from_request(&back, 10).unwrap();
        assert_eq!(addr.pk, w.vk.pk());
        let mut forged = back.clone();
        forged.record.kem_ek[0] ^= 1;
        assert!(resolve_from_request(&forged, 10).is_err(), "a tampered record never resolves");
    }

    /// The parts of a request that are not the record: amounts and memos survive the URI, and a
    /// memo cannot smuggle a parameter of its own past the encoder.
    #[test]
    fn a_request_carries_its_amount_and_its_memo_or_neither() {
        let w = Wallet::from_spend_key(SpendKey([12; 8]));
        let bare = PaymentRequest { id: w.id, record: w.record(3), amount: None, memo: None };
        assert_eq!(PaymentRequest::parse(&bare.to_uri()).unwrap(), bare);
        assert!(!bare.to_uri().contains("amount"));
        let tricky =
            PaymentRequest { id: w.id, record: w.record(3), amount: Some(1), memo: Some("rent & water=100".into()) };
        let uri = tricky.to_uri();
        assert!(!uri.contains("water=100"), "a memo is escaped, not spliced into the query: {uri}");
        assert_eq!(PaymentRequest::parse(&uri).unwrap(), tricky);
        // A request with no record at all is not a request: the record is the whole point.
        assert!(PaymentRequest::parse(&format!("rand:{}?amount=1", w.id)).is_err());
        assert!(PaymentRequest::parse("http://example.com/?rec=x").is_err());
    }

    /// The §4 error, word for word: the wallet says who could not be resolved and the two things
    /// that fix it. A sender who gets this has not lost a proof — nothing has been proved yet.
    #[tokio::test]
    async fn resolving_with_no_record_and_no_registry_is_the_spec_s_error() {
        let w = Wallet::from_spend_key(SpendKey([13; 8]));
        let e = resolve(&w.id, 7, None, None).await.unwrap_err().to_string();
        assert_eq!(
            e,
            format!("no receiver record for {}: ask the receiver for a payment request, or for them to register", w.id)
        );
    }

    /// The file path: `rand address --record`'s own output resolves, and the same file under
    /// another id does not — the record is checked against the id being paid, not the id it
    /// names itself.
    #[test]
    fn a_record_file_resolves_and_is_checked_against_the_id_being_paid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rec.json");
        let w = Wallet::from_spend_key(SpendKey([14; 8]));
        std::fs::write(&path, serde_json::to_string_pretty(&ReceiverRecordHex::from_record(&w.record(7))).unwrap()).unwrap();
        let record = record_from_file(&path).unwrap();
        assert_eq!(verified(&record, &w.id, 7).unwrap().pk, w.vk.pk());
        let other = Wallet::from_spend_key(SpendKey([15; 8]));
        assert!(verified(&record, &other.id, 7).is_err(), "not the id it was asked for");
        assert!(verified(&record, &w.id, 8).is_err(), "the chain id is signed over too");
    }

    /// What `rand register` publishes is the chain's business, not this wallet's counter. The
    /// ledger accepts exactly `current + 1`, so a rotation whose transaction never committed has
    /// to be retried at the *same* version — and a wallet whose counter ran ahead of the chain
    /// (that is what a failed rotation leaves behind) is reconciled down to it rather than
    /// wedged one version past what the chain will ever accept.
    #[test]
    fn a_registration_takes_its_version_from_the_chain_and_not_from_this_wallet() {
        // Never registered: version 1, which is the only first registration the ledger admits.
        assert_eq!(registration_target(None, false), RegisterPlan::Publish { kem_version: 0 });
        // Registered at version 1: a rotation publishes version 2, i.e. KEM key version 1.
        assert_eq!(registration_target(Some(1), true), RegisterPlan::Publish { kem_version: 1 });
        assert_eq!(registration_target(Some(7), true), RegisterPlan::Publish { kem_version: 7 });
        // Already there, and no rotation asked for: nothing to do, and not an error.
        assert_eq!(registration_target(Some(3), false), RegisterPlan::AlreadyRegistered { version: 3 });
        // A rotation of an id the chain has never seen has nothing to rotate *from*.
        assert_eq!(registration_target(None, true), RegisterPlan::NothingToRotate);

        // The reconciliation, at the only place it is visible: a wallet whose own counter is
        // ahead of the chain publishes what the chain will accept, and its address moves back
        // to match what it published — two failed rotations do not cost two versions.
        let mut w = crate::wallet::Wallet::from_spend_key_at(SpendKey([21; 8]), 4);
        let RegisterPlan::Publish { kem_version } = registration_target(Some(1), true) else {
            panic!("a rotation of a registered id publishes");
        };
        w.kem_version = kem_version;
        assert_eq!(w.kem_version, 1, "the chain's version, not the wallet's 4");
        assert_eq!(w.record(9).version, 2, "which is exactly current + 1");
        assert_eq!(w.record(9).kem_ek, w.current_address().kem_ek, "and what it publishes is what it advertises");
    }

    /// A sender-paid registration rides a payment that has already been proved for — so the one
    /// version that may ride is the one the ledger will accept. Anything else is skipped with a
    /// reason, and the payment still goes through: the alternative is a rejected transaction
    /// that takes the payment down with it.
    #[test]
    fn a_sender_paid_registration_rides_only_the_version_the_chain_will_accept() {
        assert_eq!(carried_registration(1, None), CarriedRegistration::Publish);
        assert_eq!(carried_registration(3, Some(2)), CarriedRegistration::Publish);
        // A stale request against a chain that has moved on, and a request from the future.
        let CarriedRegistration::Skip(why) = carried_registration(1, Some(2)) else {
            panic!("version 1 cannot be published over version 2");
        };
        assert!(why.contains("holds version 2") && why.contains("version 1"), "{why}");
        let CarriedRegistration::Skip(why) = carried_registration(5, Some(2)) else {
            panic!("version 5 skips two versions the ledger requires");
        };
        assert!(why.contains("holds version 2"), "{why}");
        // Never registered, but the record offered is not a first registration.
        let CarriedRegistration::Skip(why) = carried_registration(2, None) else {
            panic!("an unregistered id is registered at version 1 or not at all");
        };
        assert!(why.contains("version 1"), "{why}");
    }

    /// The two encodings the URI is made of, against their own edge cases: every length modulo
    /// three, and every byte value.
    #[test]
    fn base64url_and_percent_encoding_round_trip() {
        for len in 0..=32 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 11) as u8).collect();
            let text = base64url_encode(&bytes);
            assert!(!text.contains('+') && !text.contains('/') && !text.contains('='), "url alphabet: {text}");
            assert_eq!(base64url_decode(&text).unwrap(), bytes, "len {len}");
        }
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(base64url_decode(&base64url_encode(&all)).unwrap(), all);
        assert!(base64url_decode("a*b").is_err());
        let text = "a b&c=d%e\u{00e9}";
        assert_eq!(percent_decode(&percent_encode(text)).unwrap(), text);
        assert!(percent_decode("%zz").is_err());
    }
}
