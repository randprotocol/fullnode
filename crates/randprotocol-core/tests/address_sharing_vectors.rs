use randprotocol_core::fingerprint::Fingerprint;
use randprotocol_core::notes::ShieldedAddress;

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/address-sharing.json")).unwrap()
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
