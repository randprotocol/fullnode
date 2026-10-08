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
    let reg = randprotocol_rvm::tables::cpu::register_accesses(&exec.events).len();
    println!("== profile {profile:?}: inner tier {:?}, {} cpu rows, {} permutations, {} mem accesses, {} reg accesses, {} witness words, {} program instrs",
        p.proof.tier, rows, exec.permutations(), exec.mem_accesses(), reg, exec.hints_read, vp.program.instrs.len());
    println!("-- shape: log_arities {:?} (sum of arities {}), degree_bits {:?}, queries {}",
        shape.log_arities, shape.log_arities.iter().map(|la| 1usize << la).sum::<usize>(), shape.degree_bits, shape.num_queries);
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

    // Phase 3 Task 0: executed rows per call site (the builder's spans), split into the site's own
    // instructions, the reloads and the spills the allocator inserted inside it.
    let names = &vp.stats.span_names;
    let mut by: Vec<[usize; 3]> = vec![[0; 3]; names.len()];
    let mut ops: Vec<[usize; Op::COUNT]> = vec![[0; Op::COUNT]; names.len()];
    for e in &exec.events {
        let s = vp.stats.pc_span[e.pc as usize] as usize;
        by[s][vp.stats.pc_kind[e.pc as usize] as usize] += 1;
        ops[s][e.instr.op as usize] += 1;
    }
    println!("-- rows per call site (executed; reloads and spills inside it; per query; every opcode, most frequent first)");
    for (s, name) in names.iter().enumerate() {
        let total: usize = by[s].iter().sum();
        if total == 0 {
            continue;
        }
        let mut top: Vec<(usize, usize)> = ops[s].iter().copied().enumerate().filter(|(_, n)| *n > 0).collect();
        top.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
        // Every opcode the span executed, not a top six (Task 5 sweep): the band formulas read
        // opcodes below the sixth (Cut D's EINV and FSUB inside `reduce`), so the list is whole.
        let top: Vec<String> = top.iter().map(|&(o, n)| format!("{} {n}", Op::ALL[o].mnemonic())).collect();
        println!("   {total:>9}  {:5.1}%  {name:<20} reload {:>7} spill {:>6}  /query {:>8.1}  [{}]",
            100.0 * total as f64 / rows as f64, by[s][1], by[s][2], total as f64 / shape.num_queries as f64, top.join(", "));
    }
    let (reloads, spills): (usize, usize) = by.iter().fold((0, 0), |(r, s), b| (r + b[1], s + b[2]));
    println!("-- reloads {reloads}, spills {spills}");

    let reduce_dispatches = exec.events.iter().filter(|e| e.reduce.is_some()).count();
    println!("-- reduce dispatches {reduce_dispatches}");
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
