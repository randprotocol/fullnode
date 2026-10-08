//! `rand-node bench apply`: the validator hot path at synthetic load
//! (`docs/superpowers/specs/2026-10-05-validator-hot-path-design.md` §3, the acceptance of
//! `docs/compute-optimization.md` §3.6). One validator, the `StubExecutor`, `--bundles`
//! synthetic bundles a block for `--blocks` blocks through the real `HotStuff` path — propose,
//! apply, vote, QC, commit, prune — with one timing row every `--report-every` blocks.

use anyhow::{bail, Context};
use randprotocol_core::confidential::{ConfidentialExecutor, StubExecutor};
use randprotocol_core::consensus::{Action, ConsensusConfig, ConsensusMessage, HotStuff};
use randprotocol_core::crypto::{Hash, Keypair};
use randprotocol_core::gas;
use randprotocol_core::genesis::{Genesis, GenesisState, GenesisValidator};
use randprotocol_core::ledger::{Ledger, NoVerified};
use randprotocol_core::notes::{word8_from_bytes, word8_to_hex, Bundle, Envelope, ShieldedAddress, Word8, KEM_EK_BYTES};
use randprotocol_core::types::{Action as TxAction, Block, Transaction};
use std::sync::Arc;
use std::time::Instant;

/// The bundle guest commitment the harness genesis pins; every synthetic proof is made for it.
const HC: Word8 = [3; 8];
const CHAIN_ID: u64 = 1;

/// What `rand-node bench apply` was asked for.
#[derive(Clone, Debug)]
pub struct BenchArgs {
    pub bundles: usize,
    pub blocks: u64,
    pub report_every: u64,
    pub incremental_nullifier_root: bool,
    pub fail_over_ms: u64,
}

/// One timing row: the leader's `propose`, a replica's apply of the same block, the state root
/// and a ledger clone at the tip, the nullifier-set size, and resident / peak memory.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Row {
    pub height: u64,
    pub propose_ms: f64,
    pub apply_ms: f64,
    pub root_ms: f64,
    pub clone_ms: f64,
    pub nullifiers: usize,
    pub rss_mb: f64,
    pub peak_rss_mb: f64,
}

/// The last row and whether its apply time is within the budget.
#[derive(Clone, Copy, Debug)]
pub struct Verdict {
    pub last: Row,
    pub passed: bool,
}

/// The one-validator genesis: faucet and confidential on, no staking/tokens/gas sections, the
/// test FRI profile (nothing is proved), and the accumulator flag when asked.
fn genesis(key: &Keypair, incremental_nullifier_root: bool) -> anyhow::Result<GenesisState> {
    let payout = ShieldedAddress { pk: [1; 8], kem_ek: vec![1; KEM_EK_BYTES] }.to_string();
    let g = Genesis {
        chain_id: CHAIN_ID,
        timestamp_ms: 0,
        validators: vec![GenesisValidator {
            public_key: key.public_key().clone(),
            stake: randprotocol_core::ledger::staking::MIN_STAKE as u128,
            payout,
        }],
        alloc: Vec::new(),
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&HC),
        bridge: None,
        tokens: None,
        aggregation: None,
        consensus_domain: None,
        staking: None,
        epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
        max_program_words: None,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words: None,
        envelope_bytes: None,
        vesting: None,
        hardening_v6: None,
        hc_auth: None,
        gas: None,
        testnet: None,
        binding_domain: None,
        proof_window_blocks: None,
        program_state: None,
        fees: None,
        incremental_nullifier_root: incremental_nullifier_root.then_some(true),
    };
    g.build(&StubExecutor).context("building the harness genesis")
}

fn envelope() -> Envelope {
    Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
}

/// A fresh nullifier or commitment: distinct across the whole run, so every insert grows the
/// sets and every membership probe runs at the real set size.
fn fresh_word(counter: &mut u64) -> Word8 {
    *counter += 1;
    let h = Hash::digest_domain(b"rand-bench-apply-word", &counter.to_be_bytes());
    word8_from_bytes(h.as_bytes()).expect("32 bytes")
}

/// Widen two fresh words to a bundle's four slots; the two extra slots are the dummy notes an
/// honest bundle carries, derived from the given ones by a slot tag so all four are distinct.
fn pad4(w: [Word8; 2]) -> [Word8; 4] {
    let tag = |x: Word8, k: u32| {
        let mut y = x;
        y[7] ^= 0xd0d0_0000 | k;
        y
    };
    [w[0], w[1], tag(w[0], 2), tag(w[1], 3)]
}

/// `bundles` synthetic bundle transactions against `tip`: two spends and two dummy slots, four commitments, anchored at
/// the tip root, timed at the block being proposed, stub-proved and bound.
fn candidates(tip: &Ledger, height: u64, bundles: usize, counter: &mut u64) -> Vec<Transaction> {
    (0..bundles)
        .map(|_| {
            let nfs = [fresh_word(counter), fresh_word(counter)];
            let cms = [fresh_word(counter), fresh_word(counter)];
            let mut b = Bundle {
                anchor: tip.root(),
                nullifiers: pad4(nfs),
                commitments: pad4(cms),
                fee: gas::BUNDLE_BASE,
                burn_a: 0,
                burn_r: 0,
                burn_asset: 0,
                time: height as u32,
                envelopes: [envelope(), envelope(), envelope(), envelope()],
                proof: vec![],
                auth_commit: [0; 8],
                auth_proof: Vec::new(),
            };
            let d = StubExecutor.bundle_digest(&b.digest_input());
            b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
            StubExecutor::bound(Transaction::shielded(CHAIN_ID, b, TxAction::None))
        })
        .collect()
}

/// The host's page size, which `/proc/self/statm` counts in: `sysconf(_SC_PAGESIZE)`, or 4 096
/// if it reports none. Not a constant: aarch64 Linux hosts run 16 KiB and 64 KiB pages, where a
/// fixed 4 096 under-reports `rss_mb` by 4× or 16× (final review M5).
#[cfg(all(unix, any(target_os = "linux", test)))]
fn page_size() -> u64 {
    // SAFETY: sysconf reads a configuration value and has no other effect.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 { n as u64 } else { 4096 }
}

#[cfg(target_os = "linux")]
fn current_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages.saturating_mul(page_size()))
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn current_rss_bytes() -> u64 {
    // `libc` marks `mach_task_self` deprecated in favour of the `mach2` crate; the node takes no
    // new dependency for one syscall wrapper.
    #[allow(deprecated)]
    // SAFETY: task_info on the calling task with a correctly sized out-struct; the only
    // observable effect is the struct being filled.
    unsafe {
        let mut info: libc::mach_task_basic_info = std::mem::zeroed();
        let mut count = (std::mem::size_of::<libc::mach_task_basic_info>() / std::mem::size_of::<libc::natural_t>())
            as libc::mach_msg_type_number_t;
        let kr = libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as libc::task_info_t,
            &mut count,
        );
        if kr == libc::KERN_SUCCESS {
            info.resident_size
        } else {
            0
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn current_rss_bytes() -> u64 {
    0
}

fn peak_rss_bytes() -> u64 {
    // SAFETY: getrusage fills a plain struct for the calling process.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let v = ru.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        v
    } else {
        v * 1024
    }
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1_000.0
}

/// The column header the rows print under.
pub fn header() -> String {
    format!(
        "{:>7} {:>11} {:>9} {:>8} {:>9} {:>11} {:>8} {:>12}",
        "height", "propose_ms", "apply_ms", "root_ms", "clone_ms", "nullifiers", "rss_mb", "peak_rss_mb"
    )
}

/// One row, aligned under [`header`].
pub fn format_row(r: &Row) -> String {
    format!(
        "{:>7} {:>11.1} {:>9.1} {:>8.2} {:>9.2} {:>11} {:>8.0} {:>12.0}",
        r.height, r.propose_ms, r.apply_ms, r.root_ms, r.clone_ms, r.nullifiers, r.rss_mb, r.peak_rss_mb
    )
}

/// Run the harness: drive `args.blocks` blocks of `args.bundles` bundles through the real
/// consensus path and judge the last block's replica apply time against `fail_over_ms`.
pub fn run(args: &BenchArgs) -> anyhow::Result<Verdict> {
    if args.bundles > gas::MAX_BLOCK_TXS {
        bail!("--bundles {} is over MAX_BLOCK_TXS ({}); the raw lane is capped there", args.bundles, gas::MAX_BLOCK_TXS);
    }
    if args.blocks == 0 || args.report_every == 0 {
        bail!("--blocks and --report-every must be at least 1");
    }
    let key = Keypair::from_seed([1; 32]).context("key")?;
    let gs = genesis(&key, args.incremental_nullifier_root)?;
    let mut cfg = ConsensusConfig::new(CHAIN_ID, gs.validators.clone(), gs.hash());
    cfg.epoch_blocks = gs.epoch_blocks;
    cfg.domain = gs.signing_domain();
    let mut node = HotStuff::new(cfg, Some(key), gs.block.clone(), gs.ledger.clone(), Arc::new(StubExecutor));
    let _ = node.start();

    println!("{}", header());
    let mut counter = 0u64;
    let mut now_ms = 1u64;
    let mut last = None;
    for height in 1..=args.blocks {
        now_ms += 1;
        let txs = candidates(node.tip_ledger(), height, args.bundles, &mut counter);
        // The replica's cost, measured apart from the leader's: apply the proposed block on a
        // clone of the pre-block tip, as a validator would.
        let mut replica = node.tip_ledger().clone();

        let t = Instant::now();
        let actions = node.propose(height, txs, now_ms).with_context(|| format!("propose at height {height}"))?;
        let propose_ms = ms(t);

        let block: &Block = actions
            .iter()
            .find_map(|a| match a {
                Action::Broadcast(ConsensusMessage::Proposal(b)) => Some(b),
                _ => None,
            })
            .context("propose broadcast no proposal")?;
        if block.transactions.len() != args.bundles {
            bail!(
                "block {height} carries {} of {} candidates; the synthetic bundles are being refused",
                block.transactions.len(),
                args.bundles
            );
        }
        let t = Instant::now();
        replica
            .apply_block_for_sync(block, &Default::default(), &[], &StubExecutor, &NoVerified)
            .map_err(|e| anyhow::anyhow!("replica apply at {height}: {e:?}"))?;
        let apply_ms = ms(t);
        drop(replica);

        if height % args.report_every == 0 || height == args.blocks {
            let tip = node.tip_ledger();
            let t = Instant::now();
            let _ = tip.state_root();
            let root_ms = ms(t);
            let t = Instant::now();
            let c = tip.clone();
            let clone_ms = ms(t);
            drop(c);
            let row = Row {
                height,
                propose_ms,
                apply_ms,
                root_ms,
                clone_ms,
                nullifiers: tip.nullifiers().len(),
                rss_mb: current_rss_bytes() as f64 / 1e6,
                peak_rss_mb: peak_rss_bytes() as f64 / 1e6,
            };
            println!("{}", format_row(&row));
            last = Some(row);
        }
    }
    let last = last.expect("at least one row");
    let passed = last.apply_ms <= args.fail_over_ms as f64;
    println!(
        "verdict: apply {:.1} ms at block {} ({} nullifiers) — {} the {} ms budget",
        last.apply_ms,
        last.height,
        last.nullifiers,
        if passed { "within" } else { "OVER" },
        args.fail_over_ms
    );
    Ok(Verdict { last, passed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_run_fills_every_block_and_reports_the_last_row() {
        let args = BenchArgs { bundles: 16, blocks: 12, report_every: 4, incremental_nullifier_root: false, fail_over_ms: 10_000 };
        let v = run(&args).expect("the harness runs");
        assert_eq!(v.last.height, 12, "the last row is the last block");
        // Four nullifier slots a bundle (two spends, two dummies), every candidate carried (the harness aborts otherwise).
        assert_eq!(v.last.nullifiers, 12 * 16 * 4);
        assert!(v.passed, "a 12-block run is under any sane budget: {:?}", v.last);
    }

    /// The page size is the host's, not an assumed 4 096 (16 384 on Apple silicon).
    #[cfg(unix)]
    #[test]
    fn the_page_size_is_the_hosts() {
        let p = page_size();
        assert!(p >= 4096 && p.is_power_of_two(), "{p}");
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            assert_eq!(p, 16_384);
        }
    }

    #[test]
    fn bundles_above_the_cap_are_refused_before_any_block() {
        let args = BenchArgs { bundles: randprotocol_core::gas::MAX_BLOCK_TXS + 1, blocks: 1, report_every: 1, incremental_nullifier_root: false, fail_over_ms: 1 };
        let err = run(&args).expect_err("refused").to_string();
        assert!(err.contains("MAX_BLOCK_TXS") && err.contains("2000"), "{err}");
    }
}
