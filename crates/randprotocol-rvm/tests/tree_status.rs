//! The CI guard for the test-profile tree fixtures (monorepo issue 55, ZKVM-102).
//!
//! The tree tests in `tests/tree.rs` need proofs no hosted runner can make (tier-18 rVM proofs
//! over tier-16 RV32 proofs), so CI cannot run them, and on a box without fresh fixtures they
//! skip. What CI can do is keep the *declared* state honest: `tests/tree-fixtures.status` says
//! whether the fixtures and their pins are current, and this file — no proofs, milliseconds —
//! refuses a state that contradicts what the cheap pins say.
//!
//! - `state = current` and the leaf moved: red. The leaf of the test tree is the N = 1 test
//!   aggregate, whose rows `pins.json` records (`aggregate_test_n1_cpu_rows`, re-recorded by
//!   every change to the aggregate program). If that no longer equals the rows the tree
//!   fixtures were recorded against, the fixtures are stale and nobody said so.
//! - `state = stale` without saying since when and which pins: red.
//! - anything else in `state`: red.
use std::collections::HashMap;

fn manifest(path: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn status() -> HashMap<String, String> {
    manifest("tests/tree-fixtures.status")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once('=').unwrap_or_else(|| panic!("tree-fixtures.status: not `key = value`: {l}"));
            (k.trim().to_string(), v.trim().to_string())
        })
        .collect()
}

/// A top-level numeric field of `tests/pins.json`.
fn top_level_pin(key: &str) -> u64 {
    let s = manifest("tests/pins.json");
    let needle = format!("\n  \"{key}\": ");
    let at = s.find(&needle).unwrap_or_else(|| panic!("pins.json has no top-level `{key}`")) + needle.len();
    s[at..].split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap_or_else(|_| panic!("pins.json `{key}` is not a number"))
}

#[test]
fn the_declared_tree_fixture_state_agrees_with_the_pins() {
    let st = status();
    let get = |k: &str| st.get(k).unwrap_or_else(|| panic!("tree-fixtures.status has no `{k}`")).as_str();
    let recorded: u64 = get("recorded_leaf_cpu_rows").parse().expect("recorded_leaf_cpu_rows is a number");
    let now = top_level_pin("aggregate_test_n1_cpu_rows");
    assert!(!get("recorded_at").is_empty(), "recorded_at names the commit the fixtures were recorded at");
    match get("state") {
        "current" => {
            assert_eq!(
                recorded, now,
                "tree-fixtures.status says the test-tree fixtures are current, recorded against a leaf of {recorded} rows, \
                 but the leaf (pins.json aggregate_test_n1_cpu_rows) is now {now} rows: regenerate them \
                 (scripts/regen-tree-fixtures.sh) or declare `state = stale` with `stale_since` and `stale_pins`"
            );
            eprintln!("TREE-FIXTURES declared current: recorded against a leaf of {recorded} rows at {}", get("recorded_at"));
        }
        "stale" => {
            let (since, pins) = (get("stale_since"), get("stale_pins"));
            assert!(!since.is_empty() && !pins.is_empty(), "a stale declaration says since when (`stale_since`) and which pins (`stale_pins`)");
            assert_ne!(
                recorded, now,
                "tree-fixtures.status says stale, but the leaf's rows equal the recorded ones ({now}): if the fixtures were \
                 regenerated and the pins re-recorded, set `state = current`; if they are stale for another reason, record \
                 the leaf rows they were made against"
            );
            eprintln!(
                "TREE-FIXTURES DECLARED STALE since {since}: recorded against a leaf of {recorded} rows ({}), the leaf is now {now} rows. \
                 Stale pins: {pins}. The fixture-gated tests in tests/tree.rs skip without fresh fixtures; regenerate with \
                 scripts/regen-tree-fixtures.sh.",
                get("recorded_at")
            );
        }
        other => panic!("tree-fixtures.status: `state` is `{other}`, not `current` or `stale`"),
    }
}

/// The regeneration script exists, is executable, and names the generator test and the
/// environment variable the tree tests read — so a rename of either cannot leave it pointing at
/// nothing.
#[test]
fn the_regen_script_names_the_generator_and_the_require_variable() {
    let script = manifest("scripts/regen-tree-fixtures.sh");
    let tree = manifest("tests/tree.rs");
    for needle in ["generate_test_tree_fixtures", "RECURSION_REQUIRE_TREE_FIXTURES", "RECURSION_FIXTURES"] {
        assert!(script.contains(needle), "scripts/regen-tree-fixtures.sh does not mention {needle}");
        assert!(tree.contains(needle) || needle == "RECURSION_FIXTURES", "tests/tree.rs does not mention {needle}");
    }
    assert!(tree.contains("fn generate_test_tree_fixtures()"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/regen-tree-fixtures.sh")).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "scripts/regen-tree-fixtures.sh is not executable");
    }
}
