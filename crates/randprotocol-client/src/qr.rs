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

#[cfg(test)]
mod tests {
    use super::*;

    /// A `randpay:` link with a near-maximum memo still fits at error-correction level M —
    /// `rand address --qr` must never fail on a memo the chain itself would accept.
    #[test]
    fn a_link_with_a_long_memo_fits_at_level_m() {
        let addr = "rand1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let text = format!("randpay:{addr}?amount=1&memo={}", "x".repeat(200));
        terminal(&text).expect("fits at level M");
    }
}
