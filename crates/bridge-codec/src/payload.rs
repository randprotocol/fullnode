//! The attestation payload: [`Transfer`] and [`GuardianSetUpgrade`], wrapped
//! in the [`Payload`] enum that is carried inside [`crate::Body::payload`].

use alloc::vec::Vec;

use crate::{CodecError, Cur, GuardianKey, TRANSFER_PAYLOAD_LEN};

const TRANSFER_ID: u8 = 1;
const GUARDIAN_SET_UPGRADE_ID: u8 = 2;
/// Length, in bytes, of a [`GuardianSetUpgrade`] header: id (1) +
/// new_index (4) + guardian count (1).
const GUARDIAN_SET_UPGRADE_HEADER_LEN: usize = 6;
/// Length, in bytes, of one encoded [`GuardianKey`].
const GUARDIAN_KEY_LEN: usize = 20;

/// A cross-chain asset transfer.
///
/// Encoded as `id (1) = 1 || amount (32) || token_address (32) ||
/// token_chain (2) || to (32) || to_chain (2) || fee (32)`, all integers
/// big-endian; total length is [`TRANSFER_PAYLOAD_LEN`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub amount: [u8; 32],
    pub token_address: [u8; 32],
    pub token_chain: u16,
    pub to: [u8; 32],
    pub to_chain: u16,
    pub fee: [u8; 32],
}

impl Transfer {
    /// The transfer amount as a u128, or `None` if the u256 value's top 16
    /// bytes are non-zero (i.e. it does not fit in a u128).
    pub fn amount_u128(&self) -> Option<u128> {
        u128_from_u256(&self.amount)
    }

    /// The transfer fee as a u128, or `None` if the u256 value's top 16
    /// bytes are non-zero (i.e. it does not fit in a u128).
    pub fn fee_u128(&self) -> Option<u128> {
        u128_from_u256(&self.fee)
    }

    /// Widens a u128 into the big-endian u256 layout used by attestation
    /// amounts: the top 16 bytes are zero, the bottom 16 bytes are `v`.
    pub fn u256_from_u128(v: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&v.to_be_bytes());
        out
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(TRANSFER_ID);
        out.extend_from_slice(&self.amount);
        out.extend_from_slice(&self.token_address);
        out.extend_from_slice(&self.token_chain.to_be_bytes());
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.to_chain.to_be_bytes());
        out.extend_from_slice(&self.fee);
    }

    fn decode(bytes: &[u8]) -> Result<Transfer, CodecError> {
        if bytes.len() != TRANSFER_PAYLOAD_LEN {
            return Err(CodecError::BadPayloadLength);
        }
        let mut cur = Cur::new(bytes);
        let _id = cur.u8()?;
        let amount = cur.arr()?;
        let token_address = cur.arr()?;
        let token_chain = cur.u16()?;
        let to = cur.arr()?;
        let to_chain = cur.u16()?;
        let fee = cur.arr()?;
        Ok(Transfer {
            amount,
            token_address,
            token_chain,
            to,
            to_chain,
            fee,
        })
    }
}

fn u128_from_u256(bytes: &[u8; 32]) -> Option<u128> {
    if bytes[0..16].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u128::from_be_bytes(bytes[16..32].try_into().unwrap()))
}

/// A guardian-set upgrade: the new guardian set index (which must be
/// `current + 1`, enforced by callers, not this crate) and the new set of
/// guardian keys.
///
/// Encoded as `id (1) = 2 || new_index (4) || n (1) || keys (20 * n)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianSetUpgrade {
    pub new_index: u32,
    pub keys: Vec<GuardianKey>,
}

impl GuardianSetUpgrade {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(GUARDIAN_SET_UPGRADE_ID);
        out.extend_from_slice(&self.new_index.to_be_bytes());
        out.push(self.keys.len() as u8);
        for key in &self.keys {
            out.extend_from_slice(key);
        }
    }

    fn decode(bytes: &[u8]) -> Result<GuardianSetUpgrade, CodecError> {
        let mut cur = Cur::new(bytes);
        let _id = cur.u8()?;
        let new_index = cur.u32()?;
        let n = cur.u8()?;
        if n == 0 {
            return Err(CodecError::ZeroGuardians);
        }
        let expected_len = GUARDIAN_SET_UPGRADE_HEADER_LEN + GUARDIAN_KEY_LEN * n as usize;
        if bytes.len() < expected_len {
            return Err(CodecError::Truncated);
        }
        if bytes.len() > expected_len {
            return Err(CodecError::TrailingBytes);
        }
        let mut keys = Vec::with_capacity(n as usize);
        for _ in 0..n {
            keys.push(cur.arr()?);
        }
        Ok(GuardianSetUpgrade { new_index, keys })
    }
}

/// The decoded body of an attestation's `payload` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    Transfer(Transfer),
    GuardianSetUpgrade(GuardianSetUpgrade),
}

impl Payload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TRANSFER_PAYLOAD_LEN);
        match self {
            Payload::Transfer(t) => t.encode(&mut out),
            Payload::GuardianSetUpgrade(g) => g.encode(&mut out),
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Payload, CodecError> {
        let id = *bytes.first().ok_or(CodecError::Truncated)?;
        match id {
            TRANSFER_ID => Transfer::decode(bytes).map(Payload::Transfer),
            GUARDIAN_SET_UPGRADE_ID => {
                GuardianSetUpgrade::decode(bytes).map(Payload::GuardianSetUpgrade)
            }
            _ => Err(CodecError::BadPayloadId),
        }
    }
}
