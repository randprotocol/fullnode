//! The eight public output words of a call are the program's instruction to the chain.

use crate::crypto::Address;

pub const KIND_NONE: u32 = 0;
pub const KIND_TRANSFER: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    Transfer { to: Address, amount: u128 },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum EffectError {
    #[error("unknown effect kind {0}")]
    UnknownKind(u32),
    #[error("recipient index {index} out of range (list has {len})")]
    RecipientIndex { index: u32, len: usize },
}

/// Decode `outputs` against the call's public recipient list.
/// out0 = kind, out1 = recipient index, out2|out3 = amount as little-endian u64, out4..7 free.
pub fn decode(outputs: &[u32; 8], recipients: &[Address]) -> Result<Effect, EffectError> {
    match outputs[0] {
        KIND_NONE => Ok(Effect::None),
        KIND_TRANSFER => {
            let index = outputs[1];
            let to = *recipients
                .get(index as usize)
                .ok_or(EffectError::RecipientIndex { index, len: recipients.len() })?;
            let amount = (outputs[2] as u64) | ((outputs[3] as u64) << 32);
            Ok(Effect::Transfer { to, amount: amount as u128 })
        }
        other => Err(EffectError::UnknownKind(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn addr(n: u8) -> Address {
        Keypair::from_seed([n; 32]).unwrap().address()
    }

    #[test]
    fn kind_none_ignores_other_words() {
        assert_eq!(decode(&[0, 99, 1, 1, 0, 0, 0, 0], &[]), Ok(Effect::None));
    }

    #[test]
    fn transfer_picks_recipient_and_u64_amount() {
        let list = [addr(1), addr(2)];
        let out = [1, 1, 0xffff_ffff, 1, 0, 0, 0, 0];
        assert_eq!(decode(&out, &list), Ok(Effect::Transfer { to: addr(2), amount: 0x1_ffff_ffff }));
    }

    #[test]
    fn errors() {
        assert_eq!(decode(&[7, 0, 0, 0, 0, 0, 0, 0], &[]), Err(EffectError::UnknownKind(7)));
        assert_eq!(decode(&[1, 2, 5, 0, 0, 0, 0, 0], &[addr(1)]), Err(EffectError::RecipientIndex { index: 2, len: 1 }));
    }
}
