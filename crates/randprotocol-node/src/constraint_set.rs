//! Which constraint set a datadir's proofs were made under, and whether this build may touch it
//! (issue #166, ZKVM-201).
//!
//! A genesis names guests by digest and nothing about the zkVM's AIRs, so a binary of another
//! constraint set that still carries the chain's guests passes every genesis check, then verifies
//! none of the chain's proofs: its startup walk reads that as a corrupt chain and truncates it,
//! and so does `verify --repair`. The genesis format is consensus-visible and stays as it is, so
//! the constraint set is bound outside it, twice:
//!
//! - **[`CHAIN_CONSTRAINT_SETS`]**, a build-time table from the genesis hash of every public chain
//!   since 14 to the set it was cut under. It is what covers a datadir written before the marker
//!   existed — every chain-21 host — and it needs no file on disk.
//! - **The marker**, `<datadir>/constraint-set` ([`MARKER_FILE`]): one decimal number, written by
//!   `init` and by the first start on a datadir this build is entitled to (below). It is what
//!   covers a chain the table does not list: a devnet, or a later cut before its row lands.
//!
//! [`bind`] reads both before the database is opened and refuses when either names another set
//! than [`BUILD_CONSTRAINT_SET`], naming both numbers; a refusal writes nothing. What is left is a
//! datadir with a database, no marker and an unlisted genesis — a devnet made before this guard.
//! Nothing says what wrote it, so it starts, but nothing is truncated on it
//! ([`Truncation::Refused`]) until a clean walk under this build, or the operator, writes the
//! marker.

use crate::node::BUILD_CONSTRAINT_SET;
use anyhow::{anyhow, bail, Context, Result};
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::genesis::{Genesis, GenesisState};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The marker's file name, beside `genesis.json` and `db/`.
pub const MARKER_FILE: &str = "constraint-set";

/// Every public chain since 14 by genesis hash, with the constraint set its proofs were made
/// under (`node::CHAINS_THIS_BUILD_CANNOT_RUN` holds the same hashes for 14-21, each with its
/// reason). **A chain cut adds its row here**, and a constraint-set bump needs no other edit to
/// refuse the chains before it: every row whose set is not [`BUILD_CONSTRAINT_SET`] is refused.
///
/// **Adding a row.** A genesis hash does not exist before its cut, so the row follows the cut: the
/// cut script prints it and appends it to the cut record (`constraint-set-row:`), and its
/// `check-limits` — `deploy/check-constraint-set.sh --chain N --genesis-hash <hash>` — exits
/// non-zero until this table holds exactly that row at [`BUILD_CONSTRAINT_SET`]. The tests below
/// hold the table to the committed `deploy/genesis-chain<N>.json` files in both directions, so a
/// tree that commits a new chain's genesis without its row does not pass them.
///
/// **Where the sets come from** (checked against this repository's records, 2026-11-18; every row
/// confirmed, none contradicted, none without evidence). `machine::CONSTRAINT_SET` exists as a
/// constant only since 2026-10-12 (4219d5f5, at 9), so for 14-20 the evidence is the written
/// record and the vendored zkVM's own text at the commit that added each genesis file — the
/// highest "constraint set N" it names there is the row's set every time:
///
/// | chain | set | record |
/// |---|---|---|
/// | 14 | 6 | cut 2026-09-20 (ed882418), between set 6 (2026-09-14, `docs/confidential.md` "Constraint set 6") and set 7 (2026-09-28); `main.rs` `this_build_refuses_chains_14_to_17`, written at v0.6.1: "chains 14 and 15 (constraint set 6)" |
/// | 15 | 6 | cut 2026-09-26 (5b351300), the same window and the same test |
/// | 16 | 7 | `AGENTS.md` "v0.6.1 — constraint set 7 (2026-09-28; … chain 16's build)"; `docs/confidential.md` "Constraint set 7 (… fullnode v0.6.1, chain 16 only)" |
/// | 17 | 7 | `docs/confidential.md` "Chain 17 (constraint set 7, v0.6.3 …)"; the vendored zkVM at b388540c names nothing above 7 |
/// | 18 | 8 | `AGENTS.md` "Chain 18 — LIVE … the first gas-metered chain, constraint set 8"; `deploy/chain18-bridge-steps.md` |
/// | 19 | 8 | `AGENTS.md` "A pure re-genesis of chain 18 on the same build (v0.6.7, constraint set 8)"; `deploy/chain19-bridge-steps.md` |
/// | 20 | 8 | cut 2026-10-01 on v0.6.8 (74cfaca0: the vendored zkVM names nothing above 8; set 9 arrived 2026-10-12); `CHANGELOG.md` v0.8.0 "Chain 21 onward; not for chain 20. Constraint set 9 …" |
/// | 21 | 9 | `deploy/cut-records/chain21.record` `reason:` "constraint set 9 … changes every verifier key"; the genesis file re-derived in the tests below |
///
/// No record states chain 20's set in one sentence the way chains 16-19 have one; its row rests on
/// the build it was cut with and on v0.8.0's refusal of it.
pub const CHAIN_CONSTRAINT_SETS: [(u64, &str, u32); 8] = [
    (14, "1cff3b7da248d93ab547aef5c05bb7d0d22da510b592dab9cf7374807de7c7ff", 6),
    (15, "cc30e0854fb25b3abcee96bb7bc206dcd6e37862f6dfe80a05b3e474c2d1b6b8", 6),
    (16, "20925ae63cfa6e6c96f3ff369486ead8ea04821fec026a55df9e2893f3d53005", 7),
    (17, "d1afefc3dd68f73e3799aa0803b692d0e6a5c7c27d228bdeb3d06cdf4027e7ff", 7),
    (18, "a7cb020cc99a33c83fc38cfa0ec1db357f67fbf8b6dab13ab1d9812280b4da76", 8),
    (19, "a3defc937d561d4beb1df9a08c9cb87a3dc32dadbfc2d1814ab6f627b0a2228a", 8),
    (20, "6210cf071a390d7ac61d8cbea5dd9d139d1a493a862b54a45a498f36af2d5135", 8),
    (21, "ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a", 9),
];

/// The listed chain with this genesis hash (hex): its chain id and constraint set.
pub fn listed(genesis_hash: &str) -> Option<(u64, u32)> {
    CHAIN_CONSTRAINT_SETS.iter().find(|(_, h, _)| *h == genesis_hash).map(|(chain, _, set)| (*chain, *set))
}

/// Refuse a listed chain cut under another constraint set than this build's. A pure check on the
/// genesis, so `node::check_build_runs_genesis` makes it for `run` and `verify` before anything
/// is read from the datadir.
pub fn refuse_a_listed_chain_of_another_set(gs: &GenesisState) -> Result<()> {
    refuse_listed_under(&gs.hash().to_hex(), BUILD_CONSTRAINT_SET)
}

fn refuse_listed_under(genesis_hash: &str, build: u32) -> Result<()> {
    match listed(genesis_hash) {
        Some((chain, set)) if set != build => bail!(
            "genesis {genesis_hash} is chain {chain}, whose proofs were made under constraint set {set}; this build is \
             constraint set {build} and verifies none of them, so its startup replay would refuse the chain's own \
             history and truncate it. Nothing was written. Run the release built for constraint set {set} on this \
             datadir"
        ),
        _ => Ok(()),
    }
}

/// `genesis.build(executor)`, the guard's refusal in place of the build's own error when the file
/// names a listed chain of another constraint set.
///
/// Constraint set 11 replaced the Poseidon2 round constants (Grain), which moves every note
/// commitment, Merkle root and state root, so a genesis file cut under an earlier set no longer
/// *builds* under this one: its allocation notes' openings fail their commitments
/// (`NoteCommitmentMismatch`) and its genesis hash — which covers the state root — cannot even be
/// computed. The hash-keyed refusals ([`refuse_a_listed_chain_of_another_set`],
/// `node::CHAINS_THIS_BUILD_CANNOT_RUN`) then never see a hash. So a build failure on a file whose
/// `chain_id` is a listed chain of another set is reported as that chain's refusal, naming both
/// sets, with the build's error appended; any other failure is the build's error. Nothing is read
/// from or written to the datadir before this runs.
pub fn build_genesis(genesis: &Genesis, executor: &dyn ConfidentialExecutor) -> Result<GenesisState> {
    genesis.build(executor).map_err(|e| unbuildable_under(genesis.chain_id, BUILD_CONSTRAINT_SET, &e.to_string()))
}

fn unbuildable_under(chain_id: u64, build: u32, error: &str) -> anyhow::Error {
    match CHAIN_CONSTRAINT_SETS.iter().find(|(c, _, set)| *c == chain_id && *set != build) {
        Some((chain, hash, set)) => anyhow!(
            "this genesis file names chain {chain} (genesis {hash}), whose proofs were made under constraint set {set}; \
             this build is constraint set {build}, under which the file does not even build ({error}), and it verifies \
             none of the chain's proofs. Nothing was written. Run the release built for constraint set {set} on this \
             datadir"
        ),
        None => anyhow!("{error}"),
    }
}

/// The marker's value: `None` when there is no file. A file that is not one decimal number is an
/// error, not a missing marker — it is never guessed at or overwritten.
pub fn read_marker(datadir: &Path) -> Result<Option<u32>> {
    let path = datadir.join(MARKER_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("reading {}: {e}", path.display())),
    };
    let set = text.trim().parse::<u32>().map_err(|_| {
        anyhow!(
            "{} is not a constraint-set number (it holds {:?}); it names the constraint set this datadir's proofs \
             were made under and is never rewritten by the node — restore it, or write the right number into it",
            path.display(),
            text.chars().take(40).collect::<String>()
        )
    })?;
    Ok(Some(set))
}

/// Write the marker for this build's constraint set: a temporary file, synced, renamed over the
/// name, so a crash leaves the old state or the new one and never half a number.
pub fn write_marker(datadir: &Path) -> Result<()> {
    let path = datadir.join(MARKER_FILE);
    let tmp = datadir.join(format!("{MARKER_FILE}.tmp"));
    let mut f = std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(format!("{BUILD_CONSTRAINT_SET}\n").as_bytes()).with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all().with_context(|| format!("syncing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// What [`bind`] found for a datadir this build may open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// The marker is there and names this build's constraint set.
    Marked,
    /// No marker, and this build is entitled to write one before it opens the database: the
    /// genesis is a listed chain of this build's set (a datadir from before the marker), or the
    /// datadir has no database yet, so whatever it comes to hold is made under this build.
    Unmarked,
    /// No marker, an unlisted genesis and a database already there: nothing says which
    /// constraint set wrote it. It may be opened; nothing may be truncated on it
    /// ([`Truncation::Refused`]), and the marker is written only after a clean walk.
    Unknown,
}

/// Check the datadir against this build's constraint set, reading only `<datadir>/constraint-set`
/// and whether `<datadir>/db` exists. An `Err` is a refusal that names both numbers.
pub fn bind(datadir: &Path, gs: &GenesisState) -> Result<Binding> {
    bind_under(datadir, &gs.hash().to_hex(), BUILD_CONSTRAINT_SET)
}

fn bind_under(datadir: &Path, genesis_hash: &str, build: u32) -> Result<Binding> {
    refuse_listed_under(genesis_hash, build)?;
    match read_marker(datadir)? {
        Some(set) if set != build => bail!(
            "{} was written under constraint set {set} ({} says so); this build is constraint set {build} and \
             verifies none of its proofs, so its startup replay would refuse the chain's own history and truncate \
             it. Nothing was written. Run the release built for constraint set {set} on this datadir",
            datadir.display(),
            datadir.join(MARKER_FILE).display()
        ),
        Some(_) => Ok(Binding::Marked),
        None if listed(genesis_hash).is_some() || !datadir.join("db").exists() => Ok(Binding::Unmarked),
        None => Ok(Binding::Unknown),
    }
}

/// Whether a chain walk that finds a problem may truncate the store to the last good block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Truncation {
    /// The datadir is bound to this build's constraint set, so a block that does not verify is
    /// damage.
    Allowed,
    /// [`Binding::Unknown`]: a block that does not verify may be an intact block of another
    /// constraint set, and truncating would destroy it. Carries the datadir, for the message.
    Refused { datadir: PathBuf },
}

impl Truncation {
    /// The policy for a datadir bound as `binding`.
    pub fn for_binding(binding: Binding, datadir: &Path) -> Truncation {
        match binding {
            Binding::Marked | Binding::Unmarked => Truncation::Allowed,
            Binding::Unknown => Truncation::Refused { datadir: datadir.to_path_buf() },
        }
    }

    /// The refusal for a walk that found `problem` at `height`, or `Ok` when truncating is allowed.
    pub fn check(&self, height: u64, problem: &str) -> Result<()> {
        let Truncation::Refused { datadir } = self else { return Ok(()) };
        let marker = datadir.join(MARKER_FILE);
        bail!(
            "the chain does not verify under this build (constraint set {BUILD_CONSTRAINT_SET}) at height {height}: \
             {problem}. Not truncating: {} has no {MARKER_FILE} marker and its genesis is not a chain this build \
             lists, so damage cannot be told apart from a datadir written under another constraint set, whose \
             history a truncation would destroy. If it was written under constraint set {BUILD_CONSTRAINT_SET}, \
             record that (`echo {BUILD_CONSTRAINT_SET} > {}`) and run this again; otherwise run the release that \
             wrote it",
            datadir.display(),
            marker.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN_21: &str = "ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a";
    const UNLISTED: &str = "00000000000000000000000000000000000000000000000000000000000000aa";

    /// Every name and byte under `dir`, so "nothing was written" is an equality.
    fn tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    out.push((p.clone(), Vec::new()));
                    stack.push(p);
                } else {
                    out.push((p.clone(), std::fs::read(&p).unwrap()));
                }
            }
        }
        out.sort();
        out
    }

    /// Chain 21 was cut under constraint set 9 and this build is 11 (chain 22's): the row is
    /// pinned here as well as in the table, and this build refuses chain 21, naming both sets.
    #[test]
    fn chain_21_is_listed_under_constraint_set_9_and_this_set_11_build_refuses_it() {
        assert_eq!(listed(CHAIN_21), Some((21, 9)));
        assert_eq!(BUILD_CONSTRAINT_SET, 11, "set 11 is chain 22's; chain 22's row follows its cut");
        let e = refuse_listed_under(CHAIN_21, BUILD_CONSTRAINT_SET).unwrap_err().to_string();
        assert!(e.contains("chain 21") && e.contains("constraint set 9") && e.contains("constraint set 11"), "{e}");
        refuse_listed_under(CHAIN_21, 9).unwrap();
    }

    /// Constraint set 11 moved every Poseidon2 output, so chain 21's committed genesis file does not
    /// build under this build at all; `build_genesis` reports that as chain 21's refusal (both sets
    /// named), and a failure on an unlisted chain id stays the build's own error.
    #[test]
    fn a_listed_chain_of_an_earlier_set_whose_file_no_longer_builds_is_refused_by_chain_id() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain21.json");
        let file = Genesis::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
        let executor = crate::node::executor_for_profile(&file.fri_profile).unwrap();
        let e = build_genesis(&file, executor.as_ref()).expect_err("a set-9 genesis does not build under set 11").to_string();
        assert!(e.contains("chain 21") && e.contains(CHAIN_21) && e.contains("constraint set 9") && e.contains("constraint set 11"), "{e}");
        assert!(e.contains("Nothing was written"), "{e}");
        let other = unbuildable_under(999, BUILD_CONSTRAINT_SET, "boom").to_string();
        assert_eq!(other, "boom");
        assert_eq!(unbuildable_under(21, 9, "boom").to_string(), "boom", "a set-9 build gets the build's own error");
    }

    /// The table and the refuse-list cannot drift: every chain `CHAINS_THIS_BUILD_CANNOT_RUN`
    /// names since 14 is listed here, by the same hash and chain id, under a set below this
    /// build's — and every row here below this build's set has its row and reason there. Neither
    /// list lets through what the other refuses.
    #[test]
    fn every_chain_the_build_cannot_run_is_listed_under_an_earlier_set() {
        let refused = crate::node::CHAINS_THIS_BUILD_CANNOT_RUN;
        for (chain, hash, _) in refused {
            assert!(chain >= 14, "chain {chain}: this table starts at 14 — widen it before listing an earlier chain");
            let (listed_chain, set) = listed(hash).unwrap_or_else(|| panic!("chain {chain} is not in CHAIN_CONSTRAINT_SETS"));
            assert_eq!(listed_chain, chain, "{hash}");
            assert!(set < BUILD_CONSTRAINT_SET, "chain {chain} is refused by hash but listed under set {set}");
        }
        for (chain, hash, set) in CHAIN_CONSTRAINT_SETS {
            if set < BUILD_CONSTRAINT_SET {
                assert!(
                    refused.iter().any(|(c, h, _)| *c == chain && *h == hash),
                    "chain {chain} (set {set}) is refused by its set and has no row in CHAINS_THIS_BUILD_CANNOT_RUN: \
                     give it one, for its reason"
                );
            }
        }
    }

    /// The table's shape: chain ids strictly ascending (so unique), each hash 64 lowercase hex
    /// and in one row, no set above this build's (a chain cannot have been cut under a set that
    /// did not exist yet) and none going down as the chains go up.
    #[test]
    fn the_table_is_ascending_unique_and_no_row_is_ahead_of_this_build() {
        for pair in CHAIN_CONSTRAINT_SETS.windows(2) {
            assert!(pair[0].0 < pair[1].0, "chain ids ascend: {} then {}", pair[0].0, pair[1].0);
            assert!(pair[0].2 <= pair[1].2, "chain {} is set {}, the chain before it set {}", pair[1].0, pair[1].2, pair[0].2);
        }
        let mut hashes = std::collections::BTreeSet::new();
        for (chain, hash, set) in CHAIN_CONSTRAINT_SETS {
            assert!(chain >= 14, "chain {chain}");
            assert_eq!(hash.len(), 64, "chain {chain}");
            assert!(hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "chain {chain}: {hash}");
            assert!(hashes.insert(hash), "chain {chain}: {hash} is in two rows");
            assert!((1..=BUILD_CONSTRAINT_SET).contains(&set), "chain {chain} is listed under set {set}; this build is {BUILD_CONSTRAINT_SET}");
        }
    }

    /// `deploy/genesis-chain<N>.json`, N ≥ 14, built by the loader `run` uses (`Genesis::from_json`,
    /// the file's own executor, `build`): chain id and genesis hash. Constraint set 11 moved every
    /// Poseidon2 output, so the files of chains cut under earlier sets do not build here
    /// ([`build_genesis`]); for those the hash is the row's own, and this checks instead that the
    /// file names that chain and does not build (the refusal above).
    fn committed_genesis_files() -> Vec<(u64, String)> {
        let deploy = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy");
        let mut out = Vec::new();
        for e in std::fs::read_dir(deploy).unwrap() {
            let path = e.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            let Some(n) = name.strip_prefix("genesis-chain").and_then(|r| r.strip_suffix(".json")) else { continue };
            let Ok(n) = n.parse::<u64>() else { continue };
            if n < 14 {
                continue;
            }
            let file = randprotocol_core::genesis::Genesis::from_json(&std::fs::read_to_string(&path).unwrap())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let executor = crate::node::executor_for_profile(&file.fri_profile).unwrap();
            assert_eq!(file.chain_id, n, "{name}");
            match file.build(executor.as_ref()) {
                Ok(gs) => out.push((n, gs.hash().to_hex())),
                Err(e) => {
                    let (_, hash, set) = CHAIN_CONSTRAINT_SETS
                        .iter()
                        .find(|(c, _, _)| *c == n)
                        .unwrap_or_else(|| panic!("{name} does not build ({e}) and names no listed chain"));
                    assert!(*set < BUILD_CONSTRAINT_SET, "{name} is listed under this build's set {set} and does not build: {e}");
                    out.push((n, hash.to_string()));
                }
            }
        }
        out.sort();
        out
    }

    /// The table is the committed genesis files, both ways: every `deploy/genesis-chain<N>.json`
    /// since 14 hashes to its chain's row, and every row has its file. A cut that commits the
    /// new chain's genesis without its row fails here (issue #166's open item (a)); so does a row
    /// with a mistyped hash. Chain 21's — the running chain — is this build's set.
    #[test]
    fn the_table_is_the_committed_genesis_files() {
        let files = committed_genesis_files();
        for (chain, hash) in &files {
            let row = listed(hash).unwrap_or_else(|| {
                panic!(
                    "deploy/genesis-chain{chain}.json hashes to {hash}, which CHAIN_CONSTRAINT_SETS does not list: add \
                     ({chain}, \"{hash}\", {BUILD_CONSTRAINT_SET}), — the row its cut printed"
                )
            });
            assert_eq!(row.0, *chain, "{hash} is listed as chain {}, and is deploy/genesis-chain{chain}.json", row.0);
        }
        for (chain, hash, _) in CHAIN_CONSTRAINT_SETS {
            assert!(
                files.iter().any(|(c, h)| *c == chain && h == hash),
                "chain {chain}'s row ({hash}) is no committed deploy/genesis-chain{chain}.json"
            );
        }
        let chain_21 = files.iter().find(|(c, _)| *c == 21).expect("deploy/genesis-chain21.json");
        assert_eq!(chain_21.1, CHAIN_21);
        assert_eq!(listed(&chain_21.1), Some((21, 9)), "chain 21 is constraint set 9; this build (11) is chain 22's");
    }

    /// The accident the issue describes: a re-vendored build (constraint set 10 here, 11 for
    /// this build) on a chain-21 datadir that predates the marker. The table refuses it, naming
    /// the chain and both numbers, and the datadir is byte-identical afterwards.
    #[test]
    fn a_constraint_set_10_build_refuses_an_unmarked_chain_21_datadir_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("db")).unwrap();
        std::fs::write(dir.path().join("db/CURRENT"), b"MANIFEST-000001\n").unwrap();
        std::fs::write(dir.path().join("genesis.json"), b"{}").unwrap();
        let before = tree(dir.path());
        let e = bind_under(dir.path(), CHAIN_21, 10).unwrap_err().to_string();
        assert!(e.contains("chain 21") && e.contains("constraint set 9") && e.contains("constraint set 10"), "{e}");
        assert_eq!(tree(dir.path()), before);
        // The same datadir under this build: bound, and entitled to its marker.
        assert_eq!(bind_under(dir.path(), CHAIN_21, 9).unwrap(), Binding::Unmarked);
        assert_eq!(tree(dir.path()), before, "bind never writes");
        // And this build's own set.
        let e = bind_under(dir.path(), CHAIN_21, BUILD_CONSTRAINT_SET).unwrap_err().to_string();
        assert!(e.contains("chain 21") && e.contains("constraint set 9") && e.contains("constraint set 11"), "{e}");
        assert_eq!(tree(dir.path()), before);
    }

    /// A marker of another set refuses whatever the genesis is, names both numbers and the file,
    /// and writes nothing; the marker of this build's set binds.
    #[test]
    fn a_marker_of_another_set_refuses_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("db")).unwrap();
        std::fs::write(dir.path().join(MARKER_FILE), b"8\n").unwrap();
        let before = tree(dir.path());
        for genesis in [UNLISTED, CHAIN_21] {
            let e = bind_under(dir.path(), genesis, 9).unwrap_err().to_string();
            assert!(e.contains("constraint set 8") && e.contains("constraint set 9") && e.contains(MARKER_FILE), "{e}");
        }
        assert_eq!(tree(dir.path()), before);
        assert_eq!(bind_under(dir.path(), UNLISTED, 8).unwrap(), Binding::Marked);
    }

    /// An unmarked datadir of an unlisted genesis: entitled to a marker while it has no
    /// database, unknown once it has one — and an unknown datadir is opened but never truncated.
    #[test]
    fn an_unmarked_unlisted_datadir_is_unknown_once_it_has_a_database() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(bind_under(dir.path(), UNLISTED, 9).unwrap(), Binding::Unmarked);
        assert_eq!(Truncation::for_binding(Binding::Unmarked, dir.path()), Truncation::Allowed);
        std::fs::create_dir_all(dir.path().join("db")).unwrap();
        assert_eq!(bind_under(dir.path(), UNLISTED, 9).unwrap(), Binding::Unknown);
        let policy = Truncation::for_binding(Binding::Unknown, dir.path());
        let e = policy.check(7, "bundle proof does not verify").unwrap_err().to_string();
        assert!(e.contains("Not truncating") && e.contains("height 7") && e.contains("bundle proof does not verify"), "{e}");
        assert!(e.contains(&format!("echo {BUILD_CONSTRAINT_SET} > ")), "says how to record the set: {e}");
        Truncation::Allowed.check(7, "anything").unwrap();
    }

    /// The marker round-trips, a rewrite leaves no temporary file, and a file that is not a
    /// number is refused rather than read as missing.
    #[test]
    fn the_marker_round_trips_and_a_garbled_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_marker(dir.path()).unwrap(), None);
        write_marker(dir.path()).unwrap();
        write_marker(dir.path()).unwrap();
        assert_eq!(read_marker(dir.path()).unwrap(), Some(BUILD_CONSTRAINT_SET));
        assert_eq!(std::fs::read_to_string(dir.path().join(MARKER_FILE)).unwrap(), format!("{BUILD_CONSTRAINT_SET}\n"));
        assert_eq!(tree(dir.path()).len(), 1, "no temporary file is left");
        assert_eq!(bind_under(dir.path(), UNLISTED, BUILD_CONSTRAINT_SET).unwrap(), Binding::Marked);
        std::fs::write(dir.path().join(MARKER_FILE), b"nine").unwrap();
        let e = bind_under(dir.path(), UNLISTED, BUILD_CONSTRAINT_SET).unwrap_err().to_string();
        assert!(e.contains("not a constraint-set number"), "{e}");
        assert_eq!(std::fs::read(dir.path().join(MARKER_FILE)).unwrap(), b"nine", "never overwritten");
    }
}
