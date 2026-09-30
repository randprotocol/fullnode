//! `rand-prover run --accept-spend-key` (VK-4, audit v6): the flag is retired, and an operator's
//! unit file that still passes it fails at startup with the reason.

use std::process::Command;

#[test]
fn run_refuses_the_retired_spend_key_flag_loudly() {
    let home = tempfile::tempdir().unwrap();
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_rand-prover")).arg("--home").arg(home.path()).arg("run").args(extra).output().expect("rand-prover runs")
    };
    // Before the key is even looked for: this home has none, and the refusal is still the flag's.
    let out = run(&["--accept-spend-key"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("--accept-spend-key was retired in this release"), "{err}");
    assert!(err.contains("spend-key witness") && err.contains("remove the flag"), "{err}");
    assert!(!err.contains("prover.key.json"), "refused before anything else is checked: {err}");
    // `run --help` no longer offers it.
    let help = run(&["--help"]);
    assert!(!String::from_utf8_lossy(&help.stdout).contains("--accept-spend-key"));
}
