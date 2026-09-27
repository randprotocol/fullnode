//! `randpay:` links as QR codes: level M, byte mode (spec §2.2).

use anyhow::Result;
use qrcode::{EcLevel, QrCode};

/// What every wallet says when a link will not fit any QR code (web, iOS, Android, the website).
pub const TOO_LONG: &str = "This link is too long for a QR code; share or copy it instead.";

/// `text` at level M, or [`TOO_LONG`] when it does not fit version 40 (2 331 bytes).
fn encode(text: &str) -> Result<QrCode> {
    QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).map_err(|e| match e {
        qrcode::types::QrError::DataTooLong => anyhow::anyhow!(TOO_LONG),
        other => anyhow::anyhow!("{other}"),
    })
}

pub fn terminal(text: &str) -> Result<String> {
    let code = encode(text)?;
    Ok(code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build())
}

pub fn png(text: &str, path: &std::path::Path) -> Result<()> {
    let code = encode(text)?;
    code.render::<image::Luma<u8>>().min_dimensions(600, 600).build().save(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::notes::ShieldedAddress;
    use randprotocol_core::payment_uri::PaymentUri;

    /// A real address from the shared vectors: 1 666 characters, the longest a `rand1…` address
    /// can be (`rand1` plus base58 of 32 + 1 184 bytes, at most 1 661 characters).
    fn longest_address() -> ShieldedAddress {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../randprotocol-core/tests/vectors/address-sharing.json")).unwrap();
        let a = ShieldedAddress::parse(v["fingerprints"][0]["address"].as_str().unwrap()).unwrap();
        assert_eq!(a.to_string().len(), 1666);
        a
    }

    fn link(memo: String) -> String {
        PaymentUri { address: longest_address(), amount: Some("1".into()), asset: None, memo: Some(memo) }.format()
    }

    /// Which memos fit a level-M QR code (version 40: 2 331 bytes) beside the longest address and
    /// `amount=1`, measured: a memo of unreserved ASCII (letters, digits, `-._~`) fits at the full
    /// 510 bytes; every other byte is percent-encoded to three characters, so a memo that is all
    /// such bytes (spaces, punctuation, any non-ASCII text) fits only up to 214 bytes — a 510-byte
    /// memo of `é` does not. What does not fit is refused with the same sentence every wallet
    /// shows, never a QR of some other text.
    #[test]
    fn which_memos_fit_at_level_m_beside_the_longest_address() {
        terminal(&link("x".repeat(510))).expect("510 bytes of unreserved ASCII fit");
        terminal(&link(" ".repeat(214))).expect("214 percent-encoded bytes fit");
        for too_long in [" ".repeat(215), "é".repeat(255)] {
            let e = terminal(&link(too_long)).expect_err("does not fit").to_string();
            assert_eq!(e, TOO_LONG);
        }
    }
}
