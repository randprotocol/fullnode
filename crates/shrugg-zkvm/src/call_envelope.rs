//! The call-input envelope: a confidential call's private inputs, sealed so that the caller,
//! a per-call key, or a designated auditor can read them later (spec §6.1).
//!
//! This is the note layer's disclosure story applied to computation instead of value. A
//! transfer publishes an [`crate::viewing::Envelope`] carrying the created note; a call
//! publishes a [`CallEnvelope`] carrying `(salt, inputs)` — the preimage of the proof's public
//! input commitment `H_IN` (`pv::IN0..7`, `hash::input_digest`). Three keys open it, and they
//! are the same three scopes the note layer has:
//!
//! | key handed over | who holds it | what it opens |
//! |---|---|---|
//! | the caller's [`ViewingKey`] (via `ovk`) | the caller's wallet | every call that wallet made |
//! | the [`CallKey`] of one call | the caller, and whoever it gave it to | that one call |
//! | the auditor's `ViewingKey` | the auditor named when sealing | that one call |
//!
//! **Binding.** The chain checks nothing about these bytes beyond their size
//! (`shrugg_core::ledger::call_envelope`). What ties an envelope to its call is the AEAD: the
//! body's associated data is the 32 bytes of `H_IN` as the receipt publishes them, so an
//! envelope lifted onto another call authenticates for nobody. What makes an opened transcript
//! *faithful* is the holder's own recomputation, [`call_envelope_is_faithful`]: `H_IN` commits
//! in-circuit to every word the guest read, so a transcript that hashes to the receipt's `H_IN`
//! is what the program was actually fed — and a caller who published anything else is caught by
//! whoever decrypts, who can show the decryption to anyone.
//!
//! **Not vendored.** `viewing.rs` is synced verbatim from the research crate and must stay
//! byte-identical across a `deploy/sync-zkvm.sh` resync, so the two AEAD helpers below are a
//! deliberate re-implementation of its private `seal`/`open` — same crate, same construction,
//! same 12-byte-nonce prefix layout — rather than an edit to it. `viewing::Envelope`'s own
//! domain tags are untouched; the ones here are distinct (`shrugg-call-*`), so no wrap of one
//! kind is ever a wrap of another.

use crate::notes::{words_to_bytes, ViewingKey};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::kem::FromSeed;
use ml_kem::{Decapsulate, Encapsulate, MlKem768};
use rand::Rng;
use shrugg_core::notes::{ShieldedAddress, Word8};
use shrugg_core::types::{CallEnvelope, MAX_CALL_ENVELOPE_BYTES};

type Dk = ml_kem::ml_kem_768::DecapsulationKey;
type Ek = ml_kem::ml_kem_768::EncapsulationKey;
type KemCt = ml_kem::ml_kem_768::Ciphertext;

/// Longest private-input vector a call may seal a transcript for (spec §6.1). The cap is the
/// program's, not the envelope's: 4096 words is 16 KiB of plaintext, which the ledger's
/// [`MAX_CALL_ENVELOPE_BYTES`] accommodates for an unaudited call. Adding an auditor costs an
/// ML-KEM-768 ciphertext (1088 bytes) on top, so the largest *audited* vector is smaller; both
/// limits are enforced by [`seal_call_envelope`] rather than discovered when a block refuses
/// the transaction.
pub const MAX_CALL_INPUT_WORDS: usize = 4096;

/// The per-call disclosure key, `K_call`. Handing it over discloses exactly one call's inputs.
///
/// Fresh per envelope, drawn from OS entropy by [`seal_call_envelope`] — it is never derived
/// from the caller's keys, so giving one away says nothing about any other call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallKey(pub [u8; 32]);

impl CallKey {
    pub fn random() -> CallKey {
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        CallKey(k)
    }
}

const AAD_SENDER: &[u8] = b"shrugg-call-sender";
const AAD_AUDITOR: &[u8] = b"shrugg-call-auditor";

/// Random-nonce ChaCha20-Poly1305; the 12-byte nonce is prepended to the ciphertext. The same
/// construction and layout as the vendored `viewing.rs`'s private `seal` (see the module doc
/// comment for why it is re-implemented here instead of reused).
fn seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&Nonce::from(nonce), Payload { msg: pt, aad })
        .expect("aead");
    [&nonce[..], &ct].concat()
}

fn open(key: &[u8; 32], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.len() < 12 {
        return None;
    }
    let nonce: [u8; 12] = ct[..12].try_into().ok()?;
    ChaCha20Poly1305::new(&Key::from(*key)).decrypt(&Nonce::from(nonce), Payload { msg: &ct[12..], aad }).ok()
}

/// The body's associated data: the call's public input commitment, as the 32 little-endian
/// bytes of `pv::IN0..7`.
fn body_aad(h_in: &Word8) -> Vec<u8> {
    words_to_bytes(h_in)
}

/// `salt || inputs`, every word little-endian — the plaintext under `K_call`.
fn plaintext(salt: [u32; 4], inputs: &[u32]) -> Vec<u8> {
    let mut pt = words_to_bytes(&salt);
    pt.extend_from_slice(&words_to_bytes(inputs));
    pt
}

/// The inverse of [`plaintext`]: 16 salt bytes followed by whole words, or nothing.
fn parse_plaintext(pt: &[u8]) -> Option<([u32; 4], Vec<u32>)> {
    if pt.len() < 16 || pt.len() % 4 != 0 {
        return None;
    }
    let word = |b: &[u8]| u32::from_le_bytes(b.try_into().expect("4 bytes"));
    let salt: [u32; 4] = std::array::from_fn(|i| word(&pt[4 * i..4 * i + 4]));
    let inputs = pt[16..].chunks_exact(4).map(word).collect();
    Some((salt, inputs))
}

/// The auditor's ML-KEM-768 keys, rebuilt from its viewing key exactly as `viewing.rs` does
/// (its own `kem_keys` is private to that vendored file).
fn kem_keys(vk: &ViewingKey) -> (Dk, Ek) {
    MlKem768::from_seed(&ml_kem::Seed::from(vk.kem_seed()))
}

/// Seals `(salt, inputs)` for the call whose proof publishes `h_in`, under a fresh `K_call`
/// that is wrapped to the caller's outgoing viewing key and, when `auditor` is given, to that
/// address's ML-KEM-768 encapsulation key. With no auditor the `kem_ct` and `to_auditor` parts
/// are empty — the shape the chain sees for a call that keeps only the caller's own path open.
///
/// `salt` must be the salt that produced `h_in` (`executor::prove_call` returns both); this
/// function does not check that, because a caller is free to publish a false transcript and
/// the point of [`call_envelope_is_faithful`] is that whoever opens it catches them.
pub fn seal_call_envelope(
    caller: &ViewingKey,
    auditor: Option<&ShieldedAddress>,
    h_in: &Word8,
    salt: [u32; 4],
    inputs: &[u32],
) -> Result<(CallEnvelope, CallKey), String> {
    if inputs.len() > MAX_CALL_INPUT_WORDS {
        return Err(format!("a call may seal at most {MAX_CALL_INPUT_WORDS} input words, got {}", inputs.len()));
    }
    let key = CallKey::random();
    let (kem_ct, to_auditor) = match auditor {
        None => (Vec::new(), Vec::new()),
        Some(a) => {
            let a = crate::address::to_research(a)?;
            let ek = ml_kem::kem::Key::<Ek>::try_from(&a.kem_ek[..])
                .ok()
                .and_then(|k| Ek::new(&k).ok())
                .ok_or_else(|| "auditor address is not a valid ML-KEM-768 encapsulation key".to_string())?;
            let (ct, ss) = ek.encapsulate_with_rng(&mut rand::rng());
            let ss: [u8; 32] = ss.into();
            (ct.to_vec(), seal(&ss, AAD_AUDITOR, &key.0))
        }
    };
    let envelope = CallEnvelope {
        kem_ct,
        to_sender: seal(&caller.ovk(), AAD_SENDER, &key.0),
        to_auditor,
        body: seal(&key.0, &body_aad(h_in), &plaintext(salt, inputs)),
    };
    // The ledger's cap is the reason the wallet is told now rather than by a rejected block:
    // the proof is already paid for by the time an envelope is sealed.
    if envelope.len() > MAX_CALL_ENVELOPE_BYTES {
        return Err(format!(
            "the sealed call envelope is {} bytes, over the {MAX_CALL_ENVELOPE_BYTES}-byte cap; \
             seal fewer input words or drop the auditor",
            envelope.len()
        ));
    }
    Ok((envelope, key))
}

/// Opens the transcript with the per-call key. `h_in` is the call receipt's public input
/// commitment, which the body is sealed against: a wrong one fails authentication rather than
/// yielding garbage.
pub fn open_call_with_key(e: &CallEnvelope, h_in: &Word8, key: &CallKey) -> Option<([u32; 4], Vec<u32>)> {
    parse_plaintext(&open(&key.0, &body_aad(h_in), &e.body)?)
}

/// Opens as the caller, through `ovk` — the key that opens every call this wallet made.
pub fn open_call_as_sender(e: &CallEnvelope, h_in: &Word8, vk: &ViewingKey) -> Option<(CallKey, [u32; 4], Vec<u32>)> {
    let key = CallKey(open(&vk.ovk(), AAD_SENDER, &e.to_sender)?.try_into().ok()?);
    let (salt, inputs) = open_call_with_key(e, h_in, &key)?;
    Some((key, salt, inputs))
}

/// Opens as the auditor named when the envelope was sealed: decapsulate, unwrap `K_call`, open
/// the body. `None` for every other viewing key, and for a call sealed without an auditor.
pub fn open_call_as_auditor(e: &CallEnvelope, h_in: &Word8, auditor: &ViewingKey) -> Option<(CallKey, [u32; 4], Vec<u32>)> {
    let (dk, _) = kem_keys(auditor);
    let ct = KemCt::try_from(&e.kem_ct[..]).ok()?;
    let ss: [u8; 32] = dk.decapsulate(&ct).into();
    let key = CallKey(open(&ss, AAD_AUDITOR, &e.to_auditor)?.try_into().ok()?);
    let (salt, inputs) = open_call_with_key(e, h_in, &key)?;
    Some((key, salt, inputs))
}

/// True iff `input_digest(salt, inputs) == h_in` — what a holder checks before trusting an
/// opened transcript. The proof binds `H_IN` to every word the guest read, so a transcript that
/// passes this is a faithful record of the call's private inputs, and one that fails is proof
/// (to anyone the holder shows the decryption to) that the caller published a lie.
pub fn call_envelope_is_faithful(h_in: &Word8, salt: [u32; 4], inputs: &[u32]) -> bool {
    crate::hash::input_digest(salt, inputs) == *h_in
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notes::SpendKey;

    /// The wire layout, byte for byte — the half of the format no round trip would catch,
    /// since both sides of one are this file.
    #[test]
    fn the_four_parts_have_exactly_the_sizes_the_layout_implies() {
        let caller = SpendKey([1; 8]).viewing_key();
        let auditor = crate::address::address_of(&SpendKey([2; 8]).viewing_key());
        let inputs = [4u32, 5, 6];
        let (e, key) = seal_call_envelope(&caller, Some(&auditor), &[9; 8], [1, 2, 3, 4], &inputs).unwrap();
        assert_eq!(e.kem_ct.len(), 1088, "an ML-KEM-768 ciphertext");
        assert_eq!(e.to_sender.len(), 12 + 32 + 16, "nonce + K_call + tag");
        assert_eq!(e.to_auditor.len(), 12 + 32 + 16);
        assert_eq!(e.body.len(), 12 + 16 + 4 * inputs.len() + 16, "nonce + salt + inputs + tag");
        // The body's plaintext is the salt words followed by the input words, and nothing else.
        let pt = open(&key.0, &body_aad(&[9; 8]), &e.body).unwrap();
        assert_eq!(&pt[..16], &words_to_bytes(&[1u32, 2, 3, 4])[..]);
        assert_eq!(&pt[16..], &words_to_bytes(&inputs)[..]);
        assert_eq!(parse_plaintext(&pt), Some(([1, 2, 3, 4], inputs.to_vec())));
        // A zero-input call is still a well-formed transcript: the salt alone.
        let (e, key) = seal_call_envelope(&caller, None, &[9; 8], [1, 2, 3, 4], &[]).unwrap();
        assert_eq!(open_call_with_key(&e, &[9; 8], &key), Some(([1, 2, 3, 4], Vec::new())));
    }

    /// Truncated or mis-shaped plaintexts are rejected rather than silently reinterpreted.
    #[test]
    fn a_plaintext_that_is_not_a_salt_and_whole_words_is_not_a_transcript() {
        assert_eq!(parse_plaintext(&[0; 15]), None, "shorter than the salt");
        assert_eq!(parse_plaintext(&[0; 18]), None, "a partial word after the salt");
        assert_eq!(parse_plaintext(&[0; 16]), Some(([0; 4], Vec::new())));
    }

    /// Two envelopes never share a per-call key, and the wraps are keyed independently.
    #[test]
    fn every_call_gets_a_fresh_key() {
        let caller = SpendKey([3; 8]).viewing_key();
        let (a, ka) = seal_call_envelope(&caller, None, &[1; 8], [0; 4], &[1]).unwrap();
        let (b, kb) = seal_call_envelope(&caller, None, &[1; 8], [0; 4], &[1]).unwrap();
        assert_ne!(ka, kb);
        assert_ne!(a.body, b.body, "a fresh key and a fresh nonce per envelope");
        assert_eq!(open_call_with_key(&a, &[1; 8], &kb), None, "one call's key opens one call");
    }
}
