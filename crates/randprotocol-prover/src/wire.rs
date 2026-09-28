//! The sealed job a wallet sends a prover, and the sealed reply it gets back.
//!
//! A job is `kem_ct (1088) ‖ nonce (12) ‖ ChaCha20-Poly1305(postcard(ProveJob))`: ML-KEM-768 to
//! the prover's encapsulation key, the shared secret run through `blake3::derive_key` under
//! [`KDF_CONTEXT`] — the same primitives, at the same pinned versions, as the note envelope
//! (`randprotocol_zkvm::viewing`). The reply is sealed under the job's one-time `reply_key`, so
//! only the wallet that sent the job can read the proof.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::{Decapsulate, Encapsulate};
use rand::Rng;
use randprotocol_core::notes::{Word8, KEM_EK_BYTES};
use randprotocol_core::types::TX_BINDING_WORDS;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const WIRE_VERSION: u32 = 1;
pub const KEM_CT_BYTES: usize = 1088;
pub const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
/// A sealed job is 1 100 B of KEM+nonce plus postcard(ProveJob): 1 204 witness words ≈ 5 KB. 64 KiB bounds any honest job.
pub const MAX_SEALED_JOB_BYTES: usize = 64 * 1024;

pub type Dk = ml_kem::ml_kem_768::DecapsulationKey;
pub type Ek = ml_kem::ml_kem_768::EncapsulationKey;
type KemCt = ml_kem::ml_kem_768::Ciphertext;

const KDF_CONTEXT: &str = "rand-prover-request-1";
const AAD_JOB: &[u8] = b"rand-prover-job-1";
const AAD_REPLY: &[u8] = b"rand-prover-reply-1";

/// Which key the witness carries: a spend key's witness can move the notes it proves for, a
/// viewing key's cannot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessKind { SpendKey, ViewingKey }

impl WitnessKind {
    pub fn as_str(self) -> &'static str {
        match self { WitnessKind::SpendKey => "spend_key", WitnessKind::ViewingKey => "viewing_key" }
    }
    pub fn parse(s: &str) -> Option<WitnessKind> {
        match s { "spend_key" => Some(WitnessKind::SpendKey), "viewing_key" => Some(WitnessKind::ViewingKey), _ => None }
    }
}

/// One proving job. `inputs` is the guest's private witness and `token`/`reply_key` are
/// secrets, so the job zeroizes itself on drop and its `Debug` prints none of them.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProveJob {
    pub version: u32,
    pub token: [u8; 32],
    #[zeroize(skip)]
    pub witness_kind: WitnessKind,
    pub hc_bundle: Word8,
    pub profile: String,
    pub binding: [u32; TX_BINDING_WORDS],
    pub inputs: Vec<u32>,
    pub reply_key: [u8; 32],
}

impl std::fmt::Debug for ProveJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProveJob")
            .field("version", &self.version)
            .field("witness_kind", &self.witness_kind)
            .field("profile", &self.profile)
            .field("hc_bundle", &self.hc_bundle)
            .field("inputs_len", &self.inputs.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProveReply { pub proof: Vec<u8>, pub digest: Word8, pub tier: u8 }

#[derive(Debug)]
pub enum WireError {
    /// The prover's encapsulation key is the wrong length or not a valid ML-KEM-768 key.
    BadKey(String),
    /// A sealed job longer than [`MAX_SEALED_JOB_BYTES`].
    TooLong(usize),
    Malformed(String),
    /// AEAD authentication failed: sealed to another prover's key, or tampered with.
    NotForThisProver,
    /// A job whose wire version this build does not speak.
    Version(u32),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::BadKey(why) => write!(f, "bad prover encapsulation key: {why}"),
            WireError::TooLong(n) => write!(f, "sealed job of {n} bytes exceeds {MAX_SEALED_JOB_BYTES}"),
            WireError::Malformed(why) => write!(f, "malformed sealed message: {why}"),
            WireError::NotForThisProver => write!(f, "sealed message does not open under this key"),
            WireError::Version(v) => write!(f, "wire version {v}, this build speaks {WIRE_VERSION}"),
        }
    }
}

impl std::error::Error for WireError {}

fn job_key(ss: &[u8; 32]) -> [u8; 32] { blake3::derive_key(KDF_CONTEXT, ss) }

/// Random-nonce ChaCha20-Poly1305; the 12-byte nonce is prepended to the ciphertext.
fn aead_seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(&Key::from(*key)).encrypt(&Nonce::from(nonce), Payload { msg: pt, aad }).expect("aead");
    [&nonce[..], &ct].concat()
}

fn aead_open(key: &[u8; 32], aad: &[u8], body: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if body.len() < NONCE_BYTES + TAG_BYTES { return None; }
    let nonce: [u8; NONCE_BYTES] = body[..NONCE_BYTES].try_into().ok()?;
    ChaCha20Poly1305::new(&Key::from(*key)).decrypt(&Nonce::from(nonce), Payload { msg: &body[NONCE_BYTES..], aad }).ok().map(Zeroizing::new)
}

/// Seals `job` to the prover whose ML-KEM-768 encapsulation key is `kem_ek`.
pub fn seal_job(kem_ek: &[u8], job: &ProveJob) -> Result<Vec<u8>, WireError> {
    if kem_ek.len() != KEM_EK_BYTES { return Err(WireError::BadKey(format!("{} bytes, expected {KEM_EK_BYTES}", kem_ek.len()))); }
    let key = ml_kem::kem::Key::<Ek>::try_from(kem_ek).map_err(|_| WireError::BadKey("malformed".into()))?;
    let ek = Ek::new(&key).map_err(|_| WireError::BadKey("invalid".into()))?;
    let (kem_ct, ss) = ek.encapsulate_with_rng(&mut rand::rng());
    let mut ss: [u8; 32] = ss.into();
    let mut k = job_key(&ss);
    ss.zeroize();
    let pt = Zeroizing::new(postcard::to_allocvec(job).map_err(|e| WireError::Malformed(e.to_string()))?);
    let body = aead_seal(&k, AAD_JOB, &pt);
    k.zeroize();
    let out = [&kem_ct[..], &body].concat();
    if out.len() > MAX_SEALED_JOB_BYTES { return Err(WireError::TooLong(out.len())); }
    Ok(out)
}

/// Opens a sealed job with the prover's decapsulation key. Length is checked before any
/// cryptography; a job sealed to another key fails authentication as [`WireError::NotForThisProver`]
/// (ML-KEM's implicit rejection yields a random shared secret, never an error).
pub fn open_job(dk: &Dk, sealed: &[u8]) -> Result<ProveJob, WireError> {
    if sealed.len() > MAX_SEALED_JOB_BYTES { return Err(WireError::TooLong(sealed.len())); }
    if sealed.len() < KEM_CT_BYTES + NONCE_BYTES + TAG_BYTES { return Err(WireError::Malformed("too short".into())); }
    let ct = KemCt::try_from(&sealed[..KEM_CT_BYTES]).map_err(|_| WireError::Malformed("kem ciphertext".into()))?;
    let mut ss: [u8; 32] = dk.decapsulate(&ct).into();
    let mut k = job_key(&ss);
    ss.zeroize();
    let pt = aead_open(&k, AAD_JOB, &sealed[KEM_CT_BYTES..]);
    k.zeroize();
    let pt = pt.ok_or(WireError::NotForThisProver)?;
    let job: ProveJob = postcard::from_bytes(&pt).map_err(|e| WireError::Malformed(e.to_string()))?;
    if job.version != WIRE_VERSION { return Err(WireError::Version(job.version)); }
    Ok(job)
}

/// Seals a reply under the job's one-time `reply_key`.
pub fn seal_reply(reply_key: &[u8; 32], reply: &ProveReply) -> Vec<u8> {
    let pt = postcard::to_allocvec(reply).expect("a reply always serializes");
    aead_seal(reply_key, AAD_REPLY, &pt)
}

pub fn open_reply(reply_key: &[u8; 32], sealed: &[u8]) -> Result<ProveReply, WireError> {
    if sealed.len() < NONCE_BYTES + TAG_BYTES { return Err(WireError::Malformed("too short".into())); }
    let pt = aead_open(reply_key, AAD_REPLY, sealed).ok_or(WireError::NotForThisProver)?;
    postcard::from_bytes(&pt).map_err(|e| WireError::Malformed(e.to_string()))
}

/// A fresh one-time reply key; a wallet makes one per job.
pub fn fresh_reply_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rng().fill_bytes(&mut k);
    k
}
