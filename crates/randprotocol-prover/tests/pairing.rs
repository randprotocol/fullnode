use randprotocol_prover::key::*;
use randprotocol_prover::pairing::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn a_key_file_is_0600_written_once_and_loads_to_the_same_ek() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("prover.key.json");
    let k = ProverKey::generate();
    k.save_new(&p).unwrap();
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(k.save_new(&p).unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
    let l = ProverKey::load(&p).unwrap();
    assert_eq!(l.kem_ek(), k.kem_ek());
    assert_eq!(l.fingerprint(), k.fingerprint());
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(text.contains("\"rand-prover-key\""));
}

#[test]
fn a_world_readable_key_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("prover.key.json");
    ProverKey::generate().save_new(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ProverKey::load(&p).is_err());
}

#[test]
fn the_fingerprint_is_16_crockford_digits_over_the_ek() {
    let k = ProverKey::from_seed([9; 64]);
    let s = k.fingerprint().to_string();
    assert_eq!(s.len(), 19, "{s}");
    assert_eq!(s.matches('-').count(), 3);
    assert_eq!(fingerprint_of(k.kem_ek()), k.fingerprint());
    assert_ne!(fingerprint_of(k.kem_ek()), randprotocol_core::fingerprint::Fingerprint::of_raw(k.kem_ek()), "its own domain, not the address's");
}

#[test]
fn a_pairing_link_round_trips_and_carries_own() {
    let k = ProverKey::from_seed([1; 64]);
    let link = PairingLink { kem_ek: k.kem_ek().to_vec(), url: "https://prover.example:8600/".into(), token: [0xab; 32], own: true };
    let s = link.format();
    assert!(s.starts_with("randprover:"), "{s}");
    assert!(s.contains("&own=1"), "{s}");
    assert!(s.contains("?url=https%3A%2F%2Fprover.example%3A8600%2F"), "{s}");
    let back = PairingLink::parse(&s).unwrap();
    assert_eq!(back.kem_ek, link.kem_ek);
    assert_eq!(back.url, link.url);
    assert_eq!(back.token, link.token);
    assert!(back.own);
    let not_own = PairingLink { own: false, ..link };
    assert!(!not_own.format().contains("own="));
    assert!(!PairingLink::parse(&not_own.format()).unwrap().own);
}

#[test]
fn a_malformed_link_is_refused_with_a_reason() {
    assert!(PairingLink::parse("randprover:").is_err());
    assert!(PairingLink::parse("http://x?url=y&token=00").is_err());
    let k = ProverKey::from_seed([1; 64]);
    let ok = PairingLink { kem_ek: k.kem_ek().to_vec(), url: "http://127.0.0.1:8600".into(), token: [1; 32], own: true }.format();
    assert!(PairingLink::parse(&ok.replace("token=", "token=zz")).is_err(), "bad hex");
    assert!(PairingLink::parse(&ok[..ok.len() - 40]).is_err(), "truncated");
    let e = PairingLink::parse(&ok.replacen("randprover:", "randprover:1", 1)).unwrap_err();
    assert!(e.contains("key"), "{e}");
}

#[test]
fn pairings_mint_lookup_and_revoke_without_storing_the_token() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("pairings.json");
    let mut ps = Pairings::load(&p).unwrap();
    assert!(ps.pairings.is_empty());
    let t1 = ps.pair("laptop", true).unwrap();
    let t2 = ps.pair("phone", false).unwrap();
    assert_ne!(t1, t2);
    assert!(ps.pair("laptop", true).is_err(), "duplicate label");
    ps.save(&p).unwrap();
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(!text.contains(&hex::encode(t1)), "the token itself is never on disk");
    let ps = Pairings::load(&p).unwrap();
    assert_eq!(ps.lookup(&t1).unwrap().label, "laptop");
    assert!(ps.lookup(&t1).unwrap().own);
    assert_eq!(ps.lookup(&t2).unwrap().label, "phone");
    assert!(ps.lookup(&[0; 32]).is_none());
    let mut ps = ps;
    assert!(ps.unpair("laptop"));
    assert!(!ps.unpair("laptop"));
    assert!(ps.lookup(&t1).is_none());
}
