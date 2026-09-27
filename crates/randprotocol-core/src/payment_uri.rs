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
            // Exactly two hex digits: `u8::from_str_radix` alone also takes a sign, so `%+1`
            // would have decoded as byte 1.
            let h = s.get(i + 1..i + 3).ok_or(UriError::BadEncoding)?;
            if !h.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(UriError::BadEncoding);
            }
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
        || crate::token_id::decode(a).is_ok()
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
