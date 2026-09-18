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
    let head = git(&["rev-parse", "HEAD"]).filter(|s| !s.is_empty());
    let from_git = head.is_some();
    let sha = match head {
        Some(s) => {
            // Tracked changes only: an untracked scratch file (a log, a wallet dir) does not
            // change what was compiled, and would otherwise mark every laptop build dirty.
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).map(|s| !s.is_empty()).unwrap_or(false);
            if dirty { format!("{s}-dirty") } else { s }
        }
        None => std::fs::read_to_string(root.join(".git-rev")).map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into()),
    };
    println!("cargo:rustc-env=RAND_GIT_SHA={sha}");
    // What to watch so a new commit re-runs this script. Every path is resolved through
    // `git rev-parse --git-path`, because `.git` is a plain file (not a directory) inside a
    // worktree, pointing at the real gitdir elsewhere on disk — `<root>/.git/HEAD` does not
    // exist there, and a branch's ref lives in the common dir, not the worktree's. If a lookup
    // fails (no git, or not a repo at all) its line is simply skipped.
    //
    // HEAD alone is not enough: a commit on the checked-out branch rewrites the branch's ref,
    // not HEAD (which still names the branch), so the ref file is watched too, and
    // `packed-refs` for a branch whose ref has been packed. A path is only emitted if it
    // exists — Cargo treats a missing one as always stale and would re-run this (and rebuild
    // the crate) on every build; a packed branch's loose ref is watched through its directory
    // instead, which changes when the next commit writes the ref back out.
    let git_path = |p: &str| {
        git(&["rev-parse", "--git-path", p]).map(|g| if Path::new(&g).is_absolute() { g.into() } else { root.join(g) })
    };
    let watch = |p: &Path| {
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    };
    if let Some(head) = git_path("HEAD") {
        watch(&head);
    }
    if let Some(branch) = git(&["rev-parse", "--symbolic-full-name", "HEAD"]).filter(|r| r.starts_with("refs/")) {
        if let Some(r) = git_path(&branch) {
            match r.exists() {
                true => watch(&r),
                false => {
                    if let Some(dir) = r.parent() {
                        watch(dir);
                    }
                }
            }
        }
    }
    if let Some(packed) = git_path("packed-refs") {
        watch(&packed);
    }
    // A deploy tree without `.git` answers from `.git-rev`, so it rebuilds when that file
    // changes — emitted even when the file is missing there, since that tree has nothing else
    // to go on. A checkout never reads the file (git wins above), so it does not watch it:
    // watching a missing file would mark the crate dirty on every build.
    if !from_git {
        println!("cargo:rerun-if-changed={}", root.join(".git-rev").display());
    }
}
