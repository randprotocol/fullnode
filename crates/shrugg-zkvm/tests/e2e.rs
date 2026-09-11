use p3_matrix::Matrix;
use shrugg_zkvm::asm::{ops::*, Assembler};
use shrugg_zkvm::guests;
use shrugg_zkvm::machine::{FriProfile, Machine, Tier};

/// M3.4 (fix): the program table's height is proof-declared, not derived from the tier
/// (`tables::program::program_log_height`'s doc comment) — a program can be far longer than
/// `Tier::cpu_height()` while still executing briefly, since a digest row absorbs up to 4
/// `PROGRAM_WORD`s per *cycle* but a program's word count has no such per-cycle cap. Build one:
/// a trivial computation followed by a large block of never-executed instructions, long enough
/// that the program table alone would have overflowed a small tier's `cpu_height()`-sized table
/// under the pre-fix code (`Tier::program_height() = cpu_height()`, since deleted).
///
/// The tier this proves at is `Tier(14)`, not `Tier(10)` (whose `cpu_height` the program's
/// length is checked against): the ~300 digest-row permutations this program's length costs
/// need a `poseidon2_height` budget only `Tier(14)` (or higher) provides —
/// `Tier::poseidon2_height`'s own scaling relative to `cpu_height` is a separate, pre-existing
/// concern this fix does not touch (see the fix report). What this test isolates is exactly
/// the bug this fix closes: the *program table's own height* — independently confirmed below
/// via `traces.program.height()` — tracks the program's length, not the tier, so it is not the
/// thing that would have forced a larger tier here.
#[test]
fn a_program_much_longer_than_a_small_tiers_cpu_height_but_briefly_executed_proves() {
    use shrugg_zkvm::machine::build_traces_salted;
    let m = Machine::new(FriProfile::Test);
    let mut a = Assembler::new(0);
    a.extend(li(5, 42)); // t0 = 42
    a.extend(write_output(0, 5));
    a.extend(halt());
    // Never executed (the guest already halted above) — padding to push `len` past
    // `Tier(10).cpu_height()` (1 024) without meaningfully touching the cycle count.
    for _ in 0..1200 {
        a.push(addi(0, 0, 0)); // a decodable no-op: x0 = x0 + 0
    }
    let p = a.assemble();
    assert!(p.len() > Tier(10).cpu_height(), "program must exceed a small tier's cpu height to exercise the fix");

    let exec = shrugg_zkvm::emulator::execute(&p, &[], 1 << 20).unwrap();
    assert!(exec.cycles() < 20, "only the leading few instructions ever execute");
    let traces = build_traces_salted(&p, &[], [0u32; 4], &exec, Tier(14)).unwrap();
    // The program table's own height is driven by the program's length (`program_log_height`),
    // not by `Tier(14).cpu_height()` (16 384) — it is far smaller, and in particular still
    // bigger than `Tier(10).cpu_height()` would have offered, confirming the fix actually sized
    // the table from `p.len()` rather than coincidentally inheriting a large tier's height.
    assert!(traces.program.height() > Tier(10).cpu_height());
    assert!(traces.program.height() < Tier(14).cpu_height());

    let proof = m.prove_traces(&p, &traces, Tier(14));
    assert_eq!(exec.outputs[0], 42);
    m.verify(&p.digest(), &proof).unwrap();
}

#[test]
fn every_guest_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    // M4.1 salted H_IN (controller ruling): `prove_salted` with a fixed salt, so the expected
    // H_IN below is reproducible — `prove`'s own OS-entropy salt would make it a different,
    // unpredictable value on every run.
    let salt = [11u32, 22, 33, 44];
    for (name, program, inputs) in guests::all() {
        let (proof, exec) = m.prove_salted(&program, &inputs, salt, None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(proof.tier, Tier(10), "{name} should fit the smallest tier");
        assert_eq!(proof.public_values[2], exec.outputs[0] as u64);
        m.verify(&program.digest(), &proof).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(proof.size() > 0);

        use shrugg_zkvm::tables::cpu::pv;
        let expected_hin = shrugg_zkvm::hash::input_digest(salt, &inputs);
        for k in 0..8 {
            assert_eq!(proof.public_values[pv::IN0 + k], expected_hin[k] as u64, "{name}: H_IN word {k}");
        }
    }
}

#[test]
fn tier_padding_hides_cycle_count() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(5);
    let (p10, e) = m.prove(&p, &[], Some(Tier(10))).unwrap();
    let (p12, _) = m.prove(&p, &[], Some(Tier(12))).unwrap();
    assert!(e.cycles() < 100);
    m.verify(&p.digest(), &p10).unwrap();
    m.verify(&p.digest(), &p12).unwrap();
    assert_ne!(p10.batch.degree_bits, p12.batch.degree_bits);
    assert_eq!(p10.public_values[1], 10);
    assert_eq!(p12.public_values[1], 12);
}

#[test]
fn a_fresh_verifier_accepts_the_proof() {
    let prover = Machine::new(FriProfile::Test);
    let verifier = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = prover.prove(&p, &[], None).unwrap();
    // M3.4: the verifier never touches `p`'s words at all — only its digest, `hc`, which
    // both sides compute identically (`Program::digest` is a pure host-side function, no
    // `Machine` involved) and which the proof itself carries as a public value.
    verifier.verify(&p.digest(), &proof).unwrap();
    assert_eq!(p.code_hash(), p.digest().iter().map(|w| format!("{w:08x}")).collect::<String>());
    assert_ne!(p.code_hash(), guests::fib(11).code_hash());
}

#[test]
fn verifier_key_is_cached_after_first_verify() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    let t0 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    let first = t0.elapsed();
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    let second = t1.elapsed();
    // Threshold retuned in M2.3: splitting the 2^16-row byte table into the 256-row range
    // and nibble tables made the uncached key build itself much cheaper, so the fixed
    // per-verify FRI-opening cost that caching can't remove is now a bigger share of
    // `first` — the measured ratio dropped from well under 10% to a consistent ~23-24%
    // (repeated locally), so 10% is no longer a safe bound. 40% keeps a comfortable margin
    // above that while still requiring a real, substantial caching win, not just noise.
    assert!(
        second < first * 2 / 5,
        "cached verify should be under 40% of the first: first={first:?} second={second:?}"
    );
    assert_eq!(m.cached_keys(), 1);
}

#[test]
#[ignore]
fn measure_production_profile_at_tier_10_and_12() {
    let m = Machine::new(FriProfile::Production);
    // `fib(650)` runs 3910 cycles: past tier 10's max (1023) and within tier 12's max
    // (4095), so `prove(.., Some(Tier(12)))` actually exercises tier 12's padded height
    // rather than erroring `TooManyCycles` (as `fib(900)`, 5410 cycles, does).
    for (label, tier, n) in [("tier 10", Tier(10), 10u32), ("tier 12", Tier(12), 650u32)] {
        let p = guests::fib(n);
        let t0 = std::time::Instant::now();
        let (proof, _) = m.prove(&p, &[], Some(tier)).unwrap();
        let prove_time = t0.elapsed();
        let t1 = std::time::Instant::now();
        m.verify(&p.digest(), &proof).unwrap();
        let verify_time = t1.elapsed();
        println!("{label}: proof size = {} bytes, prove = {:?}, verify = {:?}", proof.size(), prove_time, verify_time);
    }
}

#[test]
fn compiled_fib_matches_the_hand_written_guest() {
    use shrugg_zkvm::emulator::execute;
    let compiled = guests::compiled::fib();
    let hand = guests::fib(20);
    let exec_c = execute(&compiled, &[20], 50_000).unwrap();
    let exec_h = execute(&hand, &[], 50_000).unwrap();
    assert_eq!(exec_c.outputs[0], exec_h.outputs[0]);
}

#[test]
fn compiled_fib_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::fib();
    let (proof, exec) = m.prove(&p, &[20], None).unwrap();
    eprintln!("compiled fib(20): tier {:?}, {} cycles, proof {} bytes", proof.tier, exec.cycles(), proof.size());
    m.verify(&p.digest(), &proof).unwrap();
}
