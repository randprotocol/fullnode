use randprotocol_core::fingerprint::Fingerprint;
use randprotocol_core::notes::ShieldedAddress;
use randprotocol_core::payment_uri::PaymentUri;

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/address-sharing.json")).unwrap()
}

fn seed_address() -> String {
    vectors()["fingerprints"][0]["address"].as_str().unwrap().to_string()
}

#[test]
fn fingerprints_match_the_vectors() {
    for v in vectors()["fingerprints"].as_array().unwrap() {
        let a = ShieldedAddress::parse(v["address"].as_str().unwrap()).unwrap();
        assert_eq!(a.fingerprint().to_string(), v["fingerprint"].as_str().unwrap());
    }
}

#[test]
fn fingerprint_parse_is_lenient() {
    let f = Fingerprint::parse("1WCV-YC8F-47BY-5RZY").unwrap();
    assert_eq!(Fingerprint::parse("1wcvyc8f47by5rzy"), Some(f));
    assert_eq!(Fingerprint::parse("IWCV-YC8F-47BY-5RZY"), Some(f), "I reads as 1");
    assert_eq!(Fingerprint::parse("1WCV-YC8F-47BY-5RZ"), None, "15 digits");
    assert_eq!(Fingerprint::parse("1WCV-YC8F-47BY-5RZU"), None, "U is not a digit");
}

#[test]
fn uris_match_the_vectors() {
    let a = seed_address();
    for v in vectors()["uris"].as_array().unwrap() {
        let uri = v["uri"].as_str().unwrap().replace("<A>", &a);
        match PaymentUri::parse(&uri) {
            Ok(p) => {
                assert!(v["ok"].as_bool().unwrap_or(false), "{uri} should be refused");
                assert_eq!(p.amount.as_deref(), v["amount"].as_str());
                assert_eq!(p.asset.as_deref(), v["asset"].as_str());
                assert_eq!(p.memo.as_deref(), v["memo"].as_str());
                let canonical = v.get("canonical").and_then(|c| c.as_str()).map(|c| c.replace("<A>", &a)).unwrap_or(uri.clone());
                assert_eq!(p.format(), canonical, "round trip");
            }
            Err(e) => {
                let want = v["err"].as_str().unwrap_or_else(|| panic!("{uri} refused: {e:?}"));
                assert!(format!("{e:?}").starts_with(want), "{uri}: {e:?} is not {want}");
            }
        }
    }
}
