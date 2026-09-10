//! The attestation envelope: [`Signature`], [`Body`], and [`Attestation`],
//! plus their big-endian byte encodings.

use alloc::vec::Vec;

use crate::{CodecError, Cur, VERSION};

/// One guardian's signature over an attestation's digest `mu`.
///
/// Encoded as `index (1) || r (32) || s (32) || v (1)` = 66 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub index: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// Fixed length, in bytes, of an encoded [`Signature`].
const SIGNATURE_LEN: usize = 66;
/// Fixed length, in bytes, of an encoded [`Body`] header (everything but
/// the trailing payload).
const BODY_HEADER_LEN: usize = 51;

impl Signature {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.index);
        out.extend_from_slice(&self.r);
        out.extend_from_slice(&self.s);
        out.push(self.v);
    }

    fn decode(cur: &mut Cur<'_>) -> Result<Signature, CodecError> {
        Ok(Signature {
            index: cur.u8()?,
            r: cur.arr()?,
            s: cur.arr()?,
            v: cur.u8()?,
        })
    }
}

/// The signed body of an attestation: metadata plus an opaque, chain-shaped
/// payload (see [`crate::Payload`]).
///
/// Encoded as `timestamp (4) || nonce (4) || emitter_chain (2) ||
/// emitter_address (32) || sequence (8) || consistency_level (1) ||
/// payload (..)`, all integers big-endian.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub timestamp: u32,
    pub nonce: u32,
    pub emitter_chain: u16,
    pub emitter_address: [u8; 32],
    pub sequence: u64,
    pub consistency_level: u8,
    pub payload: Vec<u8>,
}

impl Body {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.emitter_chain.to_be_bytes());
        out.extend_from_slice(&self.emitter_address);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.push(self.consistency_level);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Body, CodecError> {
        if bytes.len() < BODY_HEADER_LEN {
            return Err(CodecError::Truncated);
        }
        let mut cur = Cur::new(bytes);
        let timestamp = cur.u32()?;
        let nonce = cur.u32()?;
        let emitter_chain = cur.u16()?;
        let emitter_address = cur.arr()?;
        let sequence = cur.u64()?;
        let consistency_level = cur.u8()?;
        let payload = bytes[cur.pos()..].to_vec();
        Ok(Body {
            timestamp,
            nonce,
            emitter_chain,
            emitter_address,
            sequence,
            consistency_level,
            payload,
        })
    }
}

/// A guardian-signed attestation: a guardian set index, the guardian
/// signatures over `mu = keccak256(keccak256(body))`, and the signed
/// [`Body`] itself.
///
/// Encoded as `version (1) || guardian_set_index (4) || n_sigs (1) ||
/// signatures (66 * n_sigs) || body (..)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub guardian_set_index: u32,
    pub signatures: Vec<Signature>,
    pub body: Body,
}

impl Attestation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + SIGNATURE_LEN * self.signatures.len());
        out.push(VERSION);
        out.extend_from_slice(&self.guardian_set_index.to_be_bytes());
        out.push(self.signatures.len() as u8);
        for sig in &self.signatures {
            sig.encode(&mut out);
        }
        out.extend_from_slice(&self.body.encode());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Attestation, CodecError> {
        let mut cur = Cur::new(bytes);
        let version = cur.u8()?;
        if version != VERSION {
            return Err(CodecError::BadVersion);
        }
        let guardian_set_index = cur.u32()?;
        let n_sigs = cur.u8()?;
        let mut signatures = Vec::with_capacity(n_sigs as usize);
        for _ in 0..n_sigs {
            signatures.push(Signature::decode(&mut cur)?);
        }
        let body = Body::decode(&bytes[cur.pos()..])?;
        Ok(Attestation {
            guardian_set_index,
            signatures,
            body,
        })
    }

    /// The body bytes as they appear in the envelope, i.e. exactly what
    /// gets hashed to produce `mu`.
    pub fn body_bytes(bytes: &[u8]) -> Result<&[u8], CodecError> {
        let mut cur = Cur::new(bytes);
        let version = cur.u8()?;
        if version != VERSION {
            return Err(CodecError::BadVersion);
        }
        let _guardian_set_index = cur.u32()?;
        let n_sigs = cur.u8()?;
        for _ in 0..n_sigs {
            cur.take(SIGNATURE_LEN)?;
        }
        let tail = &bytes[cur.pos()..];
        if tail.len() < BODY_HEADER_LEN {
            return Err(CodecError::Truncated);
        }
        Ok(tail)
    }
}
