//! The committed vectors under `tests/fixtures/` (vendored by the clients' core) and the seeded
//! generator that writes them.
mod gen; // tests/gen/mod.rs: `pub fn vectors() -> BTreeMap<&'static str, String>` — file name → pretty JSON, deterministic

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Regenerate every fixture: `cargo +1.98.1 test -p randprotocol-msig -- --ignored regen_fixtures`.
#[test]
#[ignore = "writes tests/fixtures/*.json; run after a format change, then commit the files"]
fn regen_fixtures() {
    for (name, json) in gen::vectors() {
        std::fs::write(format!("{DIR}/{name}"), json).unwrap();
    }
}

/// The committed vectors are exactly what the seeded generator produces (so the clients' vendored copy is current).
#[test]
fn the_committed_fixtures_equal_the_regenerated_ones() {
    let want = gen::vectors();
    let mut on_disk: Vec<String> = std::fs::read_dir(DIR).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    on_disk.sort();
    assert_eq!(on_disk, want.keys().map(|k| k.to_string()).collect::<Vec<_>>(), "the fixture set");
    for (name, json) in want {
        assert_eq!(std::fs::read_to_string(format!("{DIR}/{name}")).unwrap(), json, "{name} is stale: run regen_fixtures");
    }
}

/// The generator is deterministic: two runs agree byte for byte (no OS entropy anywhere).
#[test]
fn the_generator_is_deterministic() {
    assert_eq!(gen::vectors(), gen::vectors());
}
