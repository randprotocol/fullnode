//! Delegated proof generation: the job a wallet seals to a `rand-prover` and the result it
//! gets back (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md` §3–§4).
//!
//! Node-local, like `address.rs` and `call_envelope.rs`: never touched by
//! `deploy/sync-zkvm.sh`. It reuses the two primitives the envelope layer pins (ML-KEM-768,
//! ChaCha20-Poly1305) but none of `viewing.rs`'s private helpers, so that file stays
//! byte-identical to upstream.
//!
//! A job carries a witness — for a bundle, the spend key and the notes — so the prover a job
//! is sealed to is trusted with custody, not just privacy (spec §9). The wallet says so.

use crate::address::address_of;
use crate::notes::ViewingKey;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::kem::FromSeed;
use ml_kem::{Decapsulate, Encapsulate, KeyExport, MlKem768};
use rand::Rng;
use randprotocol_core::notes::{ShieldedAddress, Word8, KEM_EK_BYTES};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

type Dk = ml_kem::ml_kem_768::DecapsulationKey;
type Ek = ml_kem::ml_kem_768::EncapsulationKey;
type KemCt = ml_kem::ml_kem_768::Ciphertext;

/// Bump when `JobRequest`'s encoding changes; the prover refuses other versions.
pub const VERSION: u32 = 1;
const AAD_JOB: &[u8] = b"rand-prover-job-v1";
const AAD_RESULT: &[u8] = b"rand-prover-result-v1";

/// What to prove. Everything the wallet proves is one of `executor`'s two shapes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobKind {
    /// `executor::prove_bundle`: exactly `notes::bundle_input::COUNT` words. A transfer, a
    /// bond, or one of a bridge burn's two bundles.
    Bundle { inputs: Vec<u32> },
    /// `executor::prove` (`want_salt: false`) or `executor::prove_call` (`want_salt: true`):
    /// a program on private inputs. The wallet asks for the salt when it will seal an input
    /// envelope with it.
    Program { base_pc: u32, words: Vec<u32>, inputs: Vec<u32>, tier: Option<u8>, want_salt: bool },
}

impl JobKind {
    pub fn name(&self) -> &'static str {
        match self {
            JobKind::Bundle { .. } => "bundle",
            JobKind::Program { .. } => "program",
        }
    }
    fn inputs_mut(&mut self) -> &mut Vec<u32> {
        match self {
            JobKind::Bundle { inputs } => inputs,
            JobKind::Program { inputs, .. } => inputs,
        }
    }
}

/// One proving job. Zeroizes its private inputs on drop, on both ends of the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRequest {
    pub version: u32,
    /// `"production"` or `"test"` — `executor::ZkExecutor::profile_from_str`.
    pub profile: String,
    pub kind: JobKind,
    /// The prover must *start* within this many seconds of receipt or refuse the job: a
    /// bundle binds the head height it was planned at, and admission accepts a 256-block window.
    pub deadline_secs: u32,
    /// A fresh ML-KEM-768 encapsulation key for this job only; the result is sealed to it.
    pub reply_ek: Vec<u8>,
}

impl Drop for JobRequest {
    fn drop(&mut self) {
        self.kind.inputs_mut().zeroize();
    }
}

/// What comes back. `Failed` carries the prover's error text and never its inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobResult {
    Bundle { proof: Vec<u8>, digest: Word8, tier: u8 },
    Program { proof: Vec<u8>, outputs: [u32; 8], tier: u8, salt: Option<[u32; 4]> },
    Failed { error: String },
}

/// The wire form of a job or a result: an ML-KEM-768 ciphertext and an AEAD body whose
/// 12-byte nonce is prepended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub kem_ct: Vec<u8>,
    pub body: Vec<u8>,
}

/// The wallet's one-time key for one job's result.
pub struct ReplyKey {
    dk: Dk,
    pub ek: Vec<u8>,
}

impl ReplyKey {
    pub fn generate() -> ReplyKey {
        let mut seed = [0u8; 64];
        rand::rng().fill_bytes(&mut seed);
        let (dk, ek) = MlKem768::from_seed(&ml_kem::Seed::from(seed));
        ReplyKey { dk, ek: ek.to_bytes().to_vec() }
    }
}

/// The prover's identity: a `rand1…` address, whose decapsulation key is derived from a
/// wallet key exactly as a receiving wallet derives its own.
pub struct ProverKey {
    dk: Dk,
    pub address: ShieldedAddress,
}

impl ProverKey {
    pub fn from_viewing_key(vk: &ViewingKey) -> ProverKey {
        let (dk, _) = MlKem768::from_seed(&ml_kem::Seed::from(vk.kem_seed()));
        ProverKey { dk, address: address_of(vk) }
    }
}

fn seal_to(ek_bytes: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, String> {
    if ek_bytes.len() != KEM_EK_BYTES {
        return Err(format!("encapsulation key is {} bytes, expected {KEM_EK_BYTES}", ek_bytes.len()));
    }
    let key = ml_kem::kem::Key::<Ek>::try_from(ek_bytes).map_err(|_| "malformed encapsulation key".to_string())?;
    let ek = Ek::new(&key).map_err(|_| "invalid encapsulation key".to_string())?;
    let (kem_ct, ss) = ek.encapsulate_with_rng(&mut rand::rng());
    let ss: [u8; 32] = ss.into();
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(&Key::from(ss))
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| "aead".to_string())?;
    Ok(Sealed { kem_ct: kem_ct.to_vec(), body: [&nonce[..], &ct].concat() })
}

fn open_with(dk: &Dk, aad: &[u8], sealed: &Sealed) -> Result<Vec<u8>, String> {
    let ct = KemCt::try_from(&sealed.kem_ct[..]).map_err(|_| "malformed kem ciphertext".to_string())?;
    let ss: [u8; 32] = dk.decapsulate(&ct).into();
    if sealed.body.len() < 12 {
        return Err("body too short".into());
    }
    let nonce: [u8; 12] = sealed.body[..12].try_into().expect("12 bytes");
    ChaCha20Poly1305::new(&Key::from(ss))
        .decrypt(&Nonce::from(nonce), Payload { msg: &sealed.body[12..], aad })
        .map_err(|_| "failed to open: wrong key or tampered".to_string())
}

pub fn seal_job(to: &ShieldedAddress, job: &JobRequest) -> Result<Sealed, String> {
    let pt = postcard::to_allocvec(job).map_err(|e| e.to_string())?;
    seal_to(&to.kem_ek, AAD_JOB, &pt)
}

pub fn open_job(key: &ProverKey, sealed: &Sealed) -> Result<JobRequest, String> {
    let mut pt = open_with(&key.dk, AAD_JOB, sealed)?;
    let job: JobRequest = postcard::from_bytes(&pt).map_err(|e| e.to_string())?;
    pt.zeroize();
    if job.version != VERSION {
        return Err(format!("job version {} is not {VERSION}", job.version));
    }
    Ok(job)
}

pub fn seal_result(reply_ek: &[u8], result: &JobResult) -> Result<Sealed, String> {
    let pt = postcard::to_allocvec(result).map_err(|e| e.to_string())?;
    seal_to(reply_ek, AAD_RESULT, &pt)
}

pub fn open_result(key: &ReplyKey, sealed: &Sealed) -> Result<JobResult, String> {
    let pt = open_with(&key.dk, AAD_RESULT, sealed)?;
    postcard::from_bytes(&pt).map_err(|e| e.to_string())
}

pub fn encode(sealed: &Sealed) -> Vec<u8> {
    postcard::to_allocvec(sealed).expect("sealed serialises")
}

pub fn decode(bytes: &[u8]) -> Result<Sealed, String> {
    postcard::from_bytes(bytes).map_err(|e| format!("not a sealed job: {e}"))
}
