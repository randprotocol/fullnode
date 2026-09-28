//! Which web origins may read the `prover_*` listener's replies (`docs/prover.md` §6.1).
//!
//! The listener hands out a stable identifier — `prover_info`'s `kem_ek` and `kem_fingerprint` —
//! and a desktop wallet serves it on `127.0.0.1:8600`, so a CORS answer of `*` would let any
//! website the user visits read that identifier and follow the user across sites. The pairing
//! token protects submission, not enumeration. So by default only wallet-shaped origins are
//! answered: browser extensions and pages served from this machine's loopback. Anything else is
//! refused (a 403 preflight, `-32007` to every method, no CORS headers). `*` is opt-in.

/// The default list: browser-extension wallets (any extension id) and loopback pages (any port).
pub const DEFAULT_ORIGINS: [&str; 6] = [
    "chrome-extension://*",
    "moz-extension://*",
    "safari-web-extension://*",
    "http://localhost:*",
    "http://127.0.0.1:*",
    "http://[::1]:*",
];

/// The origins whose pages may read this listener's replies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowedOrigins {
    /// Every origin (`Access-Control-Allow-Origin: *`); opt-in, `--allow-origin '*'`.
    Any,
    /// Patterns, each one of: an exact origin (`https://wallet.example`, `http://host:8080`);
    /// `scheme://*`, any extension id under that scheme (one host label of letters, digits, `-`,
    /// `_` or `.`, no port); `scheme://host:*`, that exact scheme and host on any port (or none).
    /// No other wildcard exists.
    List(Vec<String>),
}

impl Default for AllowedOrigins {
    fn default() -> AllowedOrigins {
        AllowedOrigins::List(DEFAULT_ORIGINS.iter().map(|s| s.to_string()).collect())
    }
}

impl AllowedOrigins {
    /// `--allow-origin` values: none = the default list; any `*` = [`AllowedOrigins::Any`];
    /// otherwise the given list is the whole list, each pattern checked by [`check_pattern`].
    pub fn from_flags(values: &[String]) -> Result<AllowedOrigins, String> {
        if values.is_empty() {
            return Ok(AllowedOrigins::default());
        }
        if values.iter().any(|v| v == "*") {
            return Ok(AllowedOrigins::Any);
        }
        for v in values {
            check_pattern(v)?;
        }
        Ok(AllowedOrigins::List(values.to_vec()))
    }

    /// Whether a page on `origin` (the request's `Origin` header, verbatim) may read replies.
    pub fn allows(&self, origin: &str) -> bool {
        match self {
            AllowedOrigins::Any => true,
            AllowedOrigins::List(l) => l.iter().any(|p| matches(p, origin)),
        }
    }

    /// The effective list as `prover_info` serves it: the patterns, or `["*"]`.
    pub fn to_list(&self) -> Vec<String> {
        match self {
            AllowedOrigins::Any => vec!["*".into()],
            AllowedOrigins::List(l) => l.clone(),
        }
    }
}

/// Refuses a pattern [`AllowedOrigins::allows`] would read differently than it looks: no
/// `scheme://`, a path or trailing slash, or a `*` anywhere but the two wildcard positions.
pub fn check_pattern(p: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("--allow-origin {p:?}: {why}"));
    let Some((scheme, rest)) = p.split_once("://") else { return bad("expected scheme://host, e.g. https://wallet.example") };
    if !scheme.starts_with(|c: char| c.is_ascii_lowercase()) || !scheme.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c)) {
        return bad("the scheme must be lowercase letters, digits, +, - or .");
    }
    if rest == "*" {
        return Ok(());
    }
    let authority = rest.strip_suffix(":*").unwrap_or(rest);
    if authority.is_empty() {
        return bad("no host");
    }
    if authority.contains(|c: char| "*/?#@ ".contains(c)) {
        return bad("an origin is scheme://host[:port], no path or trailing slash; `*` only as scheme://* or scheme://host:*");
    }
    if authority != authority.to_ascii_lowercase() {
        return bad("a browser sends origins in lowercase");
    }
    Ok(())
}

/// One pattern against one origin, as [`AllowedOrigins::List`] describes: exact, `scheme://*`
/// or `scheme://host:*`. Prefix-then-shape, never a substring test, so `http://localhost.evil`
/// is not `http://localhost:*`.
fn matches(pattern: &str, origin: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*').filter(|p| p.ends_with("://")) {
        return match origin.strip_prefix(prefix) {
            Some(id) => !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
            None => false,
        };
    }
    if let Some(base) = pattern.strip_suffix(":*") {
        let Some(tail) = origin.strip_prefix(base) else { return false };
        // No port: the scheme's default one.
        if tail.is_empty() {
            return true;
        }
        let Some(port) = tail.strip_prefix(':') else { return false };
        return !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u32>().is_ok_and(|n| n <= 65_535);
    }
    pattern == origin
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> AllowedOrigins { AllowedOrigins::default() }

    #[test]
    fn the_default_admits_extensions_and_loopback_on_any_port() {
        for o in [
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            "moz-extension://2b0c6f2a-8d6e-4f5b-9c1d-3e4f5a6b7c8d",
            "safari-web-extension://2B0C6F2A-8D6E-4F5B-9C1D-3E4F5A6B7C8D",
            "http://localhost:5173",
            "http://localhost",
            "http://127.0.0.1:3000",
            "http://[::1]:8080",
        ] {
            assert!(d().allows(o), "{o}");
        }
    }

    #[test]
    fn the_default_refuses_websites_and_look_alikes() {
        for o in [
            "https://evil.example",
            "null",
            "",
            "http://localhost.evil.example",
            "http://localhost.evil.example:80",
            "http://localhost:5173.evil.example",
            "http://localhost:",
            "http://localhost:abc",
            "http://localhost:99999",
            "http://localhost:80/",
            "https://localhost:5173",
            "http://127.0.0.1.evil.example:1",
            "http://evil.example#http://localhost:1",
            "http://user@localhost:1",
            "chrome-extension://",
            "chrome-extension://abc/def",
            "chrome-extension://abc:1",
            "chrome-extension://abc@evil.example",
            "xchrome-extension://abc",
            "chrome-extension:/abc",
            "CHROME-EXTENSION://abc",
            "http://[::2]:1",
            "http://[::1]x:1",
        ] {
            assert!(!d().allows(o), "{o}");
        }
    }

    #[test]
    fn an_exact_pattern_is_exact() {
        let l = AllowedOrigins::List(vec!["https://wallet.example".into()]);
        assert!(l.allows("https://wallet.example"));
        for o in ["https://wallet.example:443", "https://wallet.example/", "http://wallet.example", "https://wallet.example.evil", "https://x.wallet.example", "https://wallet.exampl"] {
            assert!(!l.allows(o), "{o}");
        }
    }

    #[test]
    fn any_allows_everything() {
        assert!(AllowedOrigins::Any.allows("https://evil.example"));
        assert!(AllowedOrigins::Any.allows("null"));
    }

    #[test]
    fn flags_replace_the_default_and_star_means_any() {
        assert_eq!(AllowedOrigins::from_flags(&[]).unwrap(), d());
        assert_eq!(AllowedOrigins::from_flags(&["*".into()]).unwrap(), AllowedOrigins::Any);
        assert_eq!(AllowedOrigins::from_flags(&["https://a.example".into(), "*".into()]).unwrap(), AllowedOrigins::Any);
        let l = AllowedOrigins::from_flags(&["https://a.example".into()]).unwrap();
        assert!(!l.allows("chrome-extension://abc"), "the given list is the whole list");
        for bad in ["localhost:5173", "https://a.example/", "https://*.example", "https://a.example:*:*", "https://a*", "http://localhost:8*", "*://a.example", "https://a.example/path", "https://"] {
            assert!(AllowedOrigins::from_flags(&[bad.into()]).is_err(), "{bad}");
        }
        for ok in DEFAULT_ORIGINS {
            assert!(check_pattern(ok).is_ok(), "{ok}");
        }
    }
}
