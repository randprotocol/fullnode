//! Pairing a wallet with a prover: the `randprover:` link that carries the prover's key, its URL
//! and a bearer token, and the prover-side store that keeps only each token's hash.

use crate::key::fingerprint_of;
use rand::Rng;
use randprotocol_core::crypto::Hash;
use randprotocol_core::fingerprint::Fingerprint;
use randprotocol_core::notes::KEM_EK_BYTES;
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Write};
use std::path::Path;

pub const TOKEN_DOMAIN: &[u8] = b"rand-prover-token-1";
pub const LINK_SCHEME: &str = "randprover:";
const PAIRINGS_VERSION: u32 = 1;

/// `randprover:{base58 kem_ek}?url={percent-encoded}&token={64 hex}[&own=1]`.
pub struct PairingLink {
    pub kem_ek: Vec<u8>,
    pub url: String,
    pub token: [u8; 32],
    /// A label: the operator minted the link with `--own`, for a machine the wallet's owner runs.
    /// It decides nothing (VK-4, audit v6) — the link is the prover's to write, so a flag in it
    /// can never be what releases key material, and since the spend-key witness was retired every
    /// pairing receives the same thing, a viewing-key witness.
    pub own: bool,
}

impl std::fmt::Debug for PairingLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingLink")
            .field("fingerprint", &self.fingerprint().to_string())
            .field("url", &self.url)
            .field("own", &self.own)
            .finish_non_exhaustive()
    }
}

impl PairingLink {
    pub fn format(&self) -> String {
        let mut s = format!(
            "{LINK_SCHEME}{}?url={}&token={}",
            bs58::encode(&self.kem_ek).into_string(),
            percent_encode(&self.url),
            hex::encode(self.token)
        );
        if self.own { s.push_str("&own=1"); }
        s
    }

    pub fn parse(s: &str) -> Result<PairingLink, String> {
        let rest = s.strip_prefix(LINK_SCHEME).ok_or_else(|| format!("not a {LINK_SCHEME} link"))?;
        let (key, query) = rest.split_once('?').ok_or("the link has no ?url=…&token=… part")?;
        let kem_ek = bs58::decode(key).into_vec().map_err(|e| format!("prover key is not base58: {e}"))?;
        if kem_ek.len() != KEM_EK_BYTES {
            return Err(format!("prover key is {} bytes, expected {KEM_EK_BYTES}", kem_ek.len()));
        }
        let (mut url, mut token, mut own) = (None, None, None);
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').ok_or_else(|| format!("malformed parameter {pair:?}"))?;
            let slot = match k {
                "url" => &mut url,
                "token" => &mut token,
                "own" => &mut own,
                _ => continue,
            };
            if slot.replace(v).is_some() { return Err(format!("parameter {k} given twice")); }
        }
        let url = percent_decode(url.ok_or("the link has no url")?)?;
        check_link_url(&url)?;
        let token_hex = token.ok_or("the link has no token")?;
        let mut token = [0u8; 32];
        hex::decode_to_slice(token_hex, &mut token).map_err(|e| format!("token is not 64 hex digits: {e}"))?;
        let own = match own {
            None => false,
            Some("1") => true,
            Some(v) => return Err(format!("own={v:?}, expected 1 or absent")),
        };
        Ok(PairingLink { kem_ek, url, token, own })
    }

    pub fn fingerprint(&self) -> Fingerprint { fingerprint_of(&self.kem_ek) }
}

/// The rule for the URL a `randprover:` link carries (VK-5, audit v6): not empty, and printable
/// ASCII only (U+0021–U+007E). The URL is the prover's to choose and the wallet shows it to its
/// owner, so a link must not be able to carry a terminal escape (`ESC [ 2K` and a redrawn
/// `(own: …)` line), a newline, a bidi override that reorders the host name, or an invisible
/// format character. Printable ASCII excludes every one of those — all of Cc, Cf, Zl, Zp and
/// every space — without a Unicode table in this crate (the wallet's display sanitiser, which has
/// one, sits in a crate that depends on this one); an internationalised host name goes in its
/// `xn--` form, which is also the form that cannot be a homograph. Checked where a link is
/// parsed and where one is minted (`rand-prover pair --url`). The refusal never echoes the URL.
pub fn check_link_url(url: &str) -> Result<(), String> {
    if url.is_empty() { return Err("the link's url is empty".into()); }
    if let Some(at) = url.chars().position(|c| !c.is_ascii_graphic()) {
        return Err(format!(
            "the link's url is not printable ASCII (character {} is a control, space, format or non-ASCII character); \
             a prover URL carries none — write an internationalised host name in its xn-- form",
            at + 1
        ));
    }
    Ok(())
}

/// Everything but RFC 3986's unreserved characters is escaped, so the URL survives as one
/// query value whatever it holds.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or("url: truncated %-escape")?;
            let hex = std::str::from_utf8(hex).map_err(|_| "url: bad %-escape")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| format!("url: bad %-escape %{hex}"))?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "url: not UTF-8".into())
}

/// `blake3(TOKEN_DOMAIN ‖ token)` — what the prover stores and compares against.
pub fn token_hash(token: &[u8; 32]) -> [u8; 32] { Hash::digest_domain(TOKEN_DOMAIN, token).0 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pairing {
    pub label: String,
    /// Hex of [`token_hash`]; the token itself is never stored.
    pub token_hash: String,
    pub own: bool,
    pub created_unix: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Pairings {
    pub version: u32,
    pub pairings: Vec<Pairing>,
}

impl Pairings {
    /// A missing file is an empty store.
    pub fn load(path: &Path) -> std::io::Result<Pairings> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Ok(Pairings { version: PAIRINGS_VERSION, pairings: Vec::new() })
            }
            Err(e) => return Err(e),
        };
        let bad = |why: String| Error::new(ErrorKind::InvalidData, format!("{}: {why}", path.display()));
        let ps: Pairings = serde_json::from_str(&text).map_err(|e| bad(e.to_string()))?;
        if ps.version != PAIRINGS_VERSION {
            return Err(bad(format!("version {}, expected {PAIRINGS_VERSION}", ps.version)));
        }
        Ok(ps)
    }

    /// Writes `<path>.tmp` at mode 0600, syncs it, and renames it over `path`.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        let out = Pairings { version: PAIRINGS_VERSION, pairings: self.pairings.clone() };
        let text = serde_json::to_string_pretty(&out).map_err(Error::other)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        // The mode above applies only to a file this call creates; a stale .tmp keeps its own.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    }

    /// Mints a fresh token for `label` and records only its hash; the caller hands the token to
    /// the wallet (in a [`PairingLink`]) and it is never recoverable from the store.
    pub fn pair(&mut self, label: &str, own: bool) -> Result<[u8; 32], String> {
        if label.is_empty() { return Err("a pairing needs a label".into()); }
        if self.pairings.iter().any(|p| p.label == label) {
            return Err(format!("a pairing labelled {label:?} already exists; unpair it first"));
        }
        let mut token = [0u8; 32];
        rand::rng().fill_bytes(&mut token);
        let created_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.pairings.push(Pairing { label: label.into(), token_hash: hex::encode(token_hash(&token)), own, created_unix });
        Ok(token)
    }

    pub fn unpair(&mut self, label: &str) -> bool {
        let before = self.pairings.len();
        self.pairings.retain(|p| p.label != label);
        self.pairings.len() != before
    }

    pub fn lookup(&self, token: &[u8; 32]) -> Option<&Pairing> {
        let h = hex::encode(token_hash(token));
        self.pairings.iter().find(|p| p.token_hash == h)
    }
}
