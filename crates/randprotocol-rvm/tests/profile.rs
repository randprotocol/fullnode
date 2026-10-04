//! The row profile of the verifier program: where the cpu rows go, by phase and by opcode, at
//! both FRI profiles — the measurement every precompile decision in `docs/00`–`03` was gated on,
//! re-taken on the current tree. Emulation only (no rVM proof), so it runs in seconds against the
//! cached fixtures; `#[ignore]`d for the production-profile fixture's one-off proving cost.
//!
//! Run: `cargo test --release -p recursion --test profile -- --ignored --nocapture`
mod common;

use randprotocol_zkvm::machine::FriProfile;
use randprotocol_rvm::dsl::Checkpoints;
use randprotocol_rvm::emulator::execute;
use randprotocol_rvm::isa::Op;
use randprotocol_rvm::programs::verify_rv32;
use randprotocol_rvm::shape::{InnerKey, InnerShape};
use randprotocol_rvm::witness::WitnessTape;

const MAX_CYCLES: usize = 1 << 24;

fn profile(profile: FriProfile) {
    let p = common::bundle_proofs(profile, 1).pop().unwrap();
    let shape = InnerShape::of(
        profile,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height,
        p.proof.public_log_height,
        p.proof.mem_log_height,
    );
    let key = InnerKey::of(profile, &shape);
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build(profile, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES).expect("accepts a real proof");

    let rows = exec.cpu_rows();
    println!("== profile {profile:?}: inner tier {:?}, {} cpu rows, {} permutations, {} mem accesses, {} witness words, {} program instrs",
        p.proof.tier, rows, exec.permutations(), exec.mem_accesses(), exec.hints_read, vp.program.instrs.len());
    println!("-- builder stats: spills {} reloads {} perms {} cells {} live_max {}",
        vp.stats.spills, vp.stats.reloads, vp.stats.perms, vp.stats.cells, vp.stats.live_max);

    println!("-- rows by phase (program instructions in emission order)");
    let mut acc = 0usize;
    for (name, n) in &vp.phase_rows {
        acc += n;
        println!("   {n:>9}  {:5.1}%  {name}", 100.0 * *n as f64 / vp.program.instrs.len() as f64);
    }
    println!("   {acc:>9}  total");

    println!("-- executed opcode histogram");
    let h = exec.histogram();
    let mut idx: Vec<usize> = (0..Op::COUNT).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(h[i]));
    for i in idx {
        if h[i] == 0 {
            continue;
        }
        println!("   {:>9}  {:5.1}%  {}", h[i], 100.0 * h[i] as f64 / rows as f64, Op::ALL[i].mnemonic());
    }

    // The reduce chip: rows (one per reduced column) and dispatches.
    let reduce_dispatches = exec.events.iter().filter(|e| e.reduce.is_some()).count();
    println!("-- reduce dispatches {reduce_dispatches}");
    // RAM accesses by kind (the register file is not in the event log; `docs/01` has its count).
    let (mut reads, mut writes) = (0usize, 0usize);
    for e in &exec.events {
        for m in &e.mem {
            if m.is_write { writes += 1 } else { reads += 1 }
        }
    }
    println!("-- ram accesses: {reads} reads, {writes} writes; max_addr {}", exec.max_addr);
}

#[test]
#[ignore = "the measurement: emulation over one cached fixture per profile; production costs one ~100 s proof the first time"]
fn where_the_rows_go() {
    profile(FriProfile::Test);
    profile(FriProfile::Production);
}
