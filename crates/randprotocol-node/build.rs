//! Captures the git commit the node was built from, for `rand_getVersion`. A checkout answers
//! `git rev-parse HEAD`; a deploy worktree without `.git` answers the `.git-rev` file the
//! deploy scripts write at the workspace root; anything else is "unknown".
use std::path::Path;
use std::process::Command;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let git = |args: &[&str]| {
        Command::new("git").args(args).current_dir(&root).output().ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let sha = match git(&["rev-parse", "HEAD"]) {
        Some(s) if !s.is_empty() => {
            let dirty = git(&["status", "--porcelain"]).map(|s| !s.is_empty()).unwrap_or(false);
            if dirty { format!("{s}-dirty") } else { s }
        }
        _ => std::fs::read_to_string(root.join(".git-rev")).map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into()),
    };
    println!("cargo:rustc-env=RAND_GIT_SHA={sha}");
    // `.git` is a plain file (not a directory) inside a worktree, pointing at the real gitdir
    // elsewhere on disk — `<root>/.git/HEAD` does not exist there, so `git rev-parse
    // --git-path HEAD` resolves the actual HEAD file to watch. If that lookup fails (no git, or
    // not a repo at all) this `rerun-if-changed` is simply skipped; the `.git-rev` one below is
    // unconditional so a deploy worktree still rebuilds when that file changes.
    if let Some(head_path) = git(&["rev-parse", "--git-path", "HEAD"]) {
        let head_path = if Path::new(&head_path).is_absolute() { head_path } else { root.join(&head_path).display().to_string() };
        println!("cargo:rerun-if-changed={head_path}");
    }
    println!("cargo:rerun-if-changed={}", root.join(".git-rev").display());
}
