//! rVM phase 4 (circuits `57fb9dc`, `recursion/docs/09-phase4-spans.md` §5–§6) changed recursion
//! opcodes 25/27 (the 4th word is now an absolute address) without changing the verifier key: a
//! pre-phase-4 digest or key would still verify, meaning something else. The MODQ chip, merged
//! with it, then moved every inner-shape pin once more, so the intermediate phase-4 values are
//! stale too. None may remain in crates/, deploy/, scripts/, vendor/ or AGENTS.md.
//!
//! Not listed: `dsl-sample.digest` `8c77648e…` (phase-4-invariant — the DSL sample program has no
//! `SPONGE`/`COMPRESS` span and circuits' suite still pins the same value at `57fb9dc`).

const STALE: &[&str] = &[
    // inner_vk_digest, pre-MODQ (unchanged by phase 4 itself; moved by the MODQ chip).
    "346ee1841980e46a3501f5b04cdf40dd3208e5b1c67360285353cf7a0b735fb9",
    // The pinned-vectors interface digest over the pre-cs9 fixture set.
    "3534960f6757e6e034518a5a1926f6107c9cda7c9d5d96296b6d4ed5c3984629",
    // verify_rv32.digest: pre-phase-4, then phase 4 before the MODQ re-pin.
    "cf5a350a62fa00bb6e84fa0de311a726aac7c610d23ce272b8c80795bac51788",
    "6a70c377ac93c0aa4032d4ceed45c4747e77a8aa0758f3953b34732e187cd344",
    // Production aggregate_program_digest: pre-phase-4, then phase 4 before the MODQ re-pin.
    "dc350ecf6b60af74f4bb032bdf607c3fa0fbd6317705f0b1077e71b455e38ba0",
    "e0eede8b4d72c32bd8808c7fa26be74eab401adc185e353a413fa3c0dde6b6c3",
    // The pre-phase-4 test tree's step programs (rv32t_leaf, rv32t_int at tier 19).
    "2c586636c4c0f94cdf13b410154679d995eefad11e27371e0786e89e206ccd34",
    "04b1677122526e51c0d278375b0c30ebd37f94ba8a2afed3cd3e019ecdc3c226",
    // PIN_VK_LEAF / pins.json tree_test.vk_leaf_*.
    "1769152780461762224", "4754121159208375271", "16285051620565002471", "12356170513791122891",
    // PIN_VK_T_LEAF / vk_t_leaf_*.
    "7711328338169539612", "5984874271003933741", "17134834717916042633", "2542356665053237370",
    // PIN_VK_INT / vk_int_*.
    "12189568167191873679", "7035563939045772652", "12535684755110529647", "4848701472125205360",
    // PIN_VK_FIX / vk_fix_* (the level-3 fixed point, dropped: the fixed point is level 2).
    "4756771443877942240", "18437901406829798119", "13732813924430148200", "10825047408558662485",
];

#[test]
fn no_pre_phase4_recursion_digest_or_key_remains() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut hits = Vec::new();
    for dir in ["crates", "deploy", "scripts", "vendor"] {
        walk(&root.join(dir), &mut |p, text| {
            if p.ends_with("no_pre_phase4_recursion_pins.rs") {
                return;
            }
            for lit in STALE {
                if text.contains(lit) {
                    hits.push(format!("{}: {lit}", p.display()));
                }
            }
        });
    }
    // The agent log names pins in prose; a stale full literal there reads as current.
    let agents = root.join("AGENTS.md");
    let text = std::fs::read_to_string(&agents).unwrap();
    for lit in STALE {
        if text.contains(lit) {
            hits.push(format!("{}: {lit}", agents.display()));
        }
    }
    assert!(hits.is_empty(), "pre-rVM-phase-4 pins remain:\n{}", hits.join("\n"));
}

fn walk(d: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &str)) {
    for e in std::fs::read_dir(d).unwrap().flatten() {
        let p = e.path();
        if p.file_name().is_some_and(|n| n == "target" || n == ".git") {
            continue;
        }
        if p.is_dir() {
            walk(&p, f)
        } else if let Ok(t) = std::fs::read_to_string(&p) {
            f(&p, &t)
        }
    }
}
