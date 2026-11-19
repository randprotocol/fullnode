mod common;
use randprotocol_zkvm::gas::{gas_max, KECCAK_GAS, POSEIDON2_ABSORB_GAS, SHA256_GAS};
use randprotocol_zkvm::machine::{check_public_values, Tier, VerifyError};
use randprotocol_zkvm::tables::cpu::pv;

#[test]
fn the_public_value_layout_gains_gas_limit_last() {
    assert_eq!(pv::GAS, 34);
    assert_eq!(pv::NUM, 35);
    // Constraint set 11 (ZKVM-202): 192, 64 and 3 through set 10.
    assert_eq!((KECCAK_GAS, SHA256_GAS, POSEIDON2_ABSORB_GAS), (134, 49, 4));
}

#[test]
fn gas_max_is_the_headers_ceiling() {
    // Cycles `2^t − 1`, plus `3 · 2^(t−3)` for the absorb rows' permutations (at most `2^(t−3)`
    // poseidon2 slots, +3 each), plus the declared hash tables' blocks (+133 and +48 each).
    assert_eq!(gas_max(Tier(10), 0, 0), 1_407);
    assert_eq!(gas_max(Tier(10), 5, 0), 1_407 + 133);
    assert_eq!(gas_max(Tier(10), 0, 6), 1_407 + 48);
    assert_eq!(gas_max(Tier(14), 0, 0), 22_527);
    assert_eq!(gas_max(Tier(14), 12, 13), 22_527 + 128 * 133 + 128 * 48);
    assert_eq!(gas_max(Tier(20), 20, 20), 1_048_575 + 393_216 + 32_768 * 133 + 16_384 * 48);
}

/// Final review, item 1: the probe — ten `POSEIDON2` calls over 12 words (30 absorb rows) and a
/// filler loop. Its run fits tier 10's cycle and permutation budgets, so the auto-tier picks
/// tier 10, yet its gas passes the old ceiling `2^10 − 1 = 1 023` (the absorb rows' extra weight was not
/// in it): the default proof was refused `GasLimitBelowRun` with no limit that made it provable.
fn poseidon2_probe(loops: i32) -> randprotocol_zkvm::isa::Program {
    use randprotocol_zkvm::asm::{ops::*, Assembler};
    use randprotocol_zkvm::isa::BranchCond;
    const S0: u32 = 8; const T0: u32 = 5; const T2: u32 = 7;
    let mut a = Assembler::new(0);
    a.extend(li(S0, 0x1000));
    for i in 0..12 { a.extend(li(T0, i + 1)); a.push(sw(S0, T0, 4 * i)); }
    for _ in 0..10 { a.extend(call_poseidon2(0x1000 / 4, 12)); }
    a.extend(li(T2, loops));
    a.label("fill");
    a.push(addi(T2, T2, -1));
    a.branch(BranchCond::Ne, T2, 0, "fill");
    a.extend(halt());
    a.assemble()
}

#[test]
fn a_run_past_the_cycle_budget_in_gas_proves_at_its_tier() {
    use randprotocol_zkvm::emulator::{execute, HashRow};
    use randprotocol_zkvm::gas::gas_of;
    use randprotocol_zkvm::machine::{FriProfile, Machine};
    let p = poseidon2_probe(PROBE_LOOPS);
    let e = execute(&p, &[], &[], 100_000).unwrap();
    let absorbs = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(HashRow::Absorb { .. }))).count();
    assert_eq!(absorbs, 30, "ten 12-word messages at rate 4");
    let gas = gas_of(&p, &[], &[], &e.events);
    assert!(gas > 1_023, "the probe's gas {gas} must pass the old ceiling");
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], &[], None).expect("the probe proves at its auto tier");
    assert_eq!(proof.tier, Tier(10));
    assert_eq!(proof.public_values[pv::GAS], gas_max(Tier(10), proof.keccak_log_height, proof.sha256_log_height));
    assert!(proof.public_values[pv::GAS] >= gas);
    assert!(m.verify(&p.digest(), &proof).is_ok());
}
/// 998 cycles + 18 digest-prefix rows (≤ tier 10's 1 023), gas 1 160 since constraint set 11
/// (1 114 in set 10, 1 078 before ZKV-5).
const PROBE_LOOPS: i32 = 440;

/// Final review, item 2: `gas_max` clamps the tier to `[10, 20]` before shifting, so an untrusted
/// header's absurd tier neither panics (debug) nor wraps the shift (release).
#[test]
fn gas_max_clamps_an_absurd_tier() {
    assert_eq!(gas_max(Tier(200), 0, 0), gas_max(Tier(20), 0, 0));
    assert_eq!(gas_max(Tier(usize::MAX), 0, 0), gas_max(Tier(20), 0, 0));
    assert_eq!(gas_max(Tier(0), 0, 0), gas_max(Tier(10), 0, 0));
}

/// Final review, item 2: a real proof whose `tier` and `pv::TIER` both say 200 (the review's probe
/// shape) is refused by `check_public_values` as a tier, not a panic in the gas check's shift.
#[test]
fn check_public_values_refuses_an_absurd_tier() {
    let (p, mut proof) = common::fib_proof_tier_10();
    proof.tier = Tier(200);
    proof.public_values[pv::TIER] = 200;
    assert_eq!(check_public_values(&p.digest(), &proof), Err(VerifyError::Tier));
}

/// Review focus 3: a limit past the header's ceiling is refused natively, before any key.
///
/// Deviation from the brief's verbatim listing: `machine::Proof` carries a `BatchProof<Config>`
/// (from `p3_batch_stark`, not vendored here) that is not `Clone`, so two independent
/// `proof.clone()`s cannot be made. `tests/bundle.rs::a_malformed_proof_is_rejected_as_a_proof_error`
/// already established the idiom for this exact situation in this crate: one mutable proof,
/// `public_values` (a plain `Vec<u64>`, which *is* `Clone`) saved and restored between checks.
#[test]
fn a_limit_above_the_header_ceiling_is_refused() {
    let (p, mut proof) = common::fib_proof_tier_10();   // the helper the executor tests use for a real tier-10 proof
    let hc = p.digest();
    assert_eq!(check_public_values(&hc, &proof), Ok(()));
    let honest_pvs = proof.public_values.clone();

    proof.public_values[pv::GAS] = gas_max(Tier(10), 0, 0) + 1;
    assert_eq!(check_public_values(&hc, &proof), Err(VerifyError::GasLimit));

    proof.public_values = honest_pvs;
    proof.public_values[pv::GAS] = u64::MAX;
    assert_eq!(check_public_values(&hc, &proof), Err(VerifyError::PublicValues));
}

// ─────────────────────── Task A2: `gas_of`, the native meter over an execution ───────────────────────

mod gas_of_tests {
    use randprotocol_zkvm::asm::{ops::*, Assembler};
    use randprotocol_zkvm::emulator::{execute, HashRow, Syscall};
    use randprotocol_zkvm::gas::gas_of;
    use randprotocol_zkvm::guests;

    /// The digest-prefix rows every execution pays once, for the given input/public counts —
    /// the same three calls `gas_of` itself makes.
    fn digest_rows(p: &randprotocol_zkvm::isa::Program, n_inputs: usize, n_public: usize) -> usize {
        p.digest_rows() + randprotocol_zkvm::hash::input_digest_row_count(n_inputs) + randprotocol_zkvm::hash::public_digest_row_count(n_public)
    }

    /// A hash-free program: gas is the digest rows at the absorb weight plus one per cycle.
    #[test]
    fn gas_of_counts_rows_with_no_hash_syscall() {
        let mut a = Assembler::new(0);
        a.push(addi(5, 0, 7));
        a.push(addi(6, 5, 1));
        a.extend(halt());
        let p = a.assemble();
        let e = execute(&p, &[], &[], 1_000).unwrap();
        let rows = digest_rows(&p, 0, 0);
        assert_eq!(gas_of(&p, &[], &[], &e.events), (4 * rows + e.events.len()) as u64);
    }

    /// `guests::keccak_demo(b"hi")` is one `SYS_KECCAK` row plus its permutation (see
    /// `tests/cheating.rs`'s `setup_keccak`): the KECCAK row still counts once toward the plain
    /// per-row sum, and `gas_of` must add 133 more for it (`KECCAK_GAS - 1`).
    #[test]
    fn gas_of_charges_133_beyond_its_base_row_for_a_keccak_call() {
        let p = guests::keccak_demo(b"hi");
        let e = execute(&p, &[], &[], 10_000).unwrap();
        let keccaks = e.events.iter().filter(|ev| matches!(ev.sys, Some(Syscall::Keccak { .. }))).count() as u64;
        assert_eq!(keccaks, 1, "keccak_demo hashes exactly one rate block");
        let rows = digest_rows(&p, 0, 0);
        let expected = (4 * rows + e.events.len()) as u64 + keccaks * 133;
        assert_eq!(gas_of(&p, &[], &[], &e.events), expected);
    }

    /// `guests::poseidon2_demo` over 8 words absorbs at rate 4, so two `HashRow::Absorb` rows;
    /// `gas_of` must add 3 more for each (`POSEIDON2_ABSORB_GAS - 1`), i.e. +6 total.
    #[test]
    fn gas_of_charges_3_beyond_its_base_row_per_poseidon2_absorb_row() {
        let p = guests::poseidon2_demo(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let e = execute(&p, &[], &[], 10_000).unwrap();
        let absorbs = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(HashRow::Absorb { .. }))).count() as u64;
        assert_eq!(absorbs, 2, "8 words at rate 4 absorb in exactly two blocks");
        let rows = digest_rows(&p, 0, 0);
        let expected_extra = absorbs * 3;
        assert_eq!(expected_extra, 6, "2 absorb rows -> +6 gas");
        let expected = (4 * rows + e.events.len()) as u64 + expected_extra;
        assert_eq!(gas_of(&p, &[], &[], &e.events), expected);
    }

    /// `POSEIDON2_LEN` (HCS-4/cs7) shares the same absorb-row weight — `gas_of` must not
    /// special-case it away just because its ecall's `sys` variant differs from `Poseidon2`.
    #[test]
    fn gas_of_charges_the_same_absorb_weight_for_poseidon2_len() {
        let p = guests::poseidon2_len_demo(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let e = execute(&p, &[], &[], 10_000).unwrap();
        let absorbs = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(HashRow::Absorb { .. }))).count() as u64;
        assert_eq!(absorbs, 2);
        let rows = digest_rows(&p, 0, 0);
        let expected = (4 * rows + e.events.len()) as u64 + absorbs * 3;
        assert_eq!(gas_of(&p, &[], &[], &e.events), expected);
    }
}

/// ZKV-5 (constraint set 10): a digest-prefix row — `IS_DIGEST`, `IS_INDIGEST`, `IS_PUBDIGEST` — makes
/// one `POSEIDON2` call and counts against the poseidon2 table exactly as an absorb row does, so it
/// weighs what an absorb row weighs.
mod digest_prefix {
    use super::common;
    use randprotocol_zkvm::asm::{ops::*, Assembler};
    use randprotocol_zkvm::emulator::execute;
    use randprotocol_zkvm::gas::{gas_max, gas_of, POSEIDON2_ABSORB_GAS};
    use randprotocol_zkvm::isa::{BranchCond, Program};
    use randprotocol_zkvm::machine::{build_traces_salted, FriProfile, Machine, ProveError, Tier, CONSTRAINT_SET};
    use randprotocol_zkvm::tables::cpu::{col, pv};
    use randprotocol_zkvm::tables::F;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};

    const INPUTS: [u32; 5] = [1, 2, 3, 4, 5];
    const PUBLIC: [u32; 5] = [6, 7, 8, 9, 10];

    /// `(program, input, public)` prefix row counts.
    fn regions(p: &Program, n_in: usize, n_pub: usize) -> (usize, usize, usize) {
        (p.digest_rows(), randprotocol_zkvm::hash::input_digest_row_count(n_in), randprotocol_zkvm::hash::public_digest_row_count(n_pub))
    }

    #[test]
    fn the_gas_column_climbs_by_the_absorb_weight_across_all_three_regions() {
        assert_eq!(CONSTRAINT_SET, 11);
        let p = randprotocol_zkvm::guests::fib(20);
        let e = execute(&p, &INPUTS, &PUBLIC, 10_000).unwrap();
        let gas = gas_of(&p, &INPUTS, &PUBLIC, &e.events);
        let t = build_traces_salted(&p, &INPUTS, &PUBLIC, [0; 4], &e, Tier(10), gas).unwrap();
        let (d, i, q) = regions(&p, INPUTS.len(), PUBLIC.len());
        assert!(d >= 2 && i >= 2 && q >= 2, "every region needs an interior transition: {d} {i} {q}");
        for r in 0..d + i + q {
            assert_eq!(t.cpu.values[r * col::WIDTH + col::GAS], F::from_u64((r as u64 + 1) * POSEIDON2_ABSORB_GAS), "prefix row {r}");
        }
    }

    /// `(rows of the cpu trace to charge 1 instead of the absorb weight)`, the claim a prover would
    /// make to keep the cs8 price: the `GAS` chain rebuilt with those rows at weight 1, and `pv::GAS`
    /// lowered by exactly what that saves, so the `HALT` row's limbs (and with them `RANGE8`) are
    /// untouched and only the gas chain can object.
    fn undercharge(t: &mut randprotocol_zkvm::machine::Traces, rows: std::ops::Range<usize>) {
        let w = col::WIDTH;
        let cell = |t: &randprotocol_zkvm::machine::Traces, r: usize, c: usize| t.cpu.values[r * w + c].as_canonical_u64();
        let height = t.cpu.values.len() / w;
        let mut prev_old = 0;
        let mut new = 0;
        let mut r = 0;
        while r < height && cell(t, r, col::IS_REAL) == 1 {
            let old = cell(t, r, col::GAS);
            new += if rows.contains(&r) { 1 } else { old - prev_old };
            prev_old = old;
            t.cpu.values[r * w + col::GAS] = F::from_u64(new);
            r += 1;
        }
        let saved = prev_old - new;
        for p in r..height { t.cpu.values[p * w + col::GAS] = F::from_u64(new); }
        let pv = t.public_values[pv::GAS].as_canonical_u64();
        t.public_values[pv::GAS] = F::from_u64(pv - saved);
    }

    /// One forgery per weight the AIR now carries: the first row's constant, then the chain's three
    /// selectors. Each forgery leaves the `HALT` limbs and `RANGE8` untouched, so the gas chain is
    /// what refuses it; dropping any one term from the AIR fails this test at the honest proof.
    #[test]
    fn a_prefix_row_charged_one_is_refused() {
        let m = Machine::new(FriProfile::Test);
        let p = randprotocol_zkvm::guests::fib(20);
        let e = execute(&p, &INPUTS, &PUBLIC, 10_000).unwrap();
        let gas = gas_of(&p, &INPUTS, &PUBLIC, &e.events);
        let (d, i, q) = regions(&p, INPUTS.len(), PUBLIC.len());
        let honest = build_traces_salted(&p, &INPUTS, &PUBLIC, [0; 4], &e, Tier(10), gas).unwrap();
        assert!(m.verify(&p.digest(), &m.prove_traces(&p, &honest, Tier(10))).is_ok());
        for (name, rows) in [("row 0", 0..1), ("IS_DIGEST", 1..d), ("IS_INDIGEST", d..d + i), ("IS_PUBDIGEST", d + i..d + i + q)] {
            let mut forged = build_traces_salted(&p, &INPUTS, &PUBLIC, [0; 4], &e, Tier(10), gas).unwrap();
            undercharge(&mut forged, rows);
            assert!(common::rejects(|| m.verify(&p.digest(), &m.prove_traces(&p, &forged, Tier(10)))), "{name} charged 1 verified");
        }
    }

    /// `n` program words whose run is `cycles` cycles: a counted loop, then dead words after `HALT`
    /// that only the program-digest rows ever touch.
    fn filler(words: usize, cycles: usize) -> Program {
        const T2: u32 = 7;
        let build = |loops: i32, nop: bool, dead: usize| {
            let mut a = Assembler::new(0);
            a.extend(li(T2, loops));
            if nop { a.push(addi(0, 0, 0)); }
            a.label("fill");
            a.push(addi(T2, T2, -1));
            a.branch(BranchCond::Ne, T2, 0, "fill");
            a.extend(halt());
            for _ in 0..dead { a.push(addi(0, 0, 0)); }
            a.assemble()
        };
        for loops in 1..(cycles as i32) {
            for nop in [false, true] {
                let p = build(loops, nop, 0);
                if execute(&p, &[], &[], 1 << 20).unwrap().events.len() == cycles { return build(loops, nop, words - p.words.len()); }
            }
        }
        panic!("no loop count runs {cycles} cycles");
    }

    /// The ceiling (`gas_max`'s `3 · 2^(t−3)` term) holds with the prefix priced at an absorb row's 4, and tightly. The
    /// run's gas is `(P + C) + 3·(P + A) + …` for `P` prefix rows, `C` cycles, `A` absorb rows: `P + C`
    /// is bounded by the cpu height less a padding row, and `P + A` by the poseidon2 table's `2^(t−3)`
    /// slots, because every prefix and absorb row is one permutation. So a run filling both budgets
    /// with prefix rows alone spends exactly the hash-free ceiling; it proves with zero slack, and
    /// neither budget has a row to spare.
    #[test]
    fn a_run_filling_both_budgets_with_prefix_rows_spends_exactly_the_ceiling() {
        let slots = Tier(10).poseidon2_height() / randprotocol_zkvm::tables::poseidon2::BLOCK;
        assert_eq!(slots, 128);
        let (i, q) = (randprotocol_zkvm::hash::input_digest_row_count(0), randprotocol_zkvm::hash::public_digest_row_count(0));
        let digest_rows = slots - i - q;
        let cycles = Tier(10).max_cycles() - slots;
        let p = filler(4 * digest_rows, cycles);
        assert_eq!(p.digest_rows(), digest_rows);
        let e = execute(&p, &[], &[], 1 << 20).unwrap();
        let gas = gas_of(&p, &[], &[], &e.events);
        assert_eq!(gas, gas_max(Tier(10), 0, 0));

        let m = Machine::new(FriProfile::Test);
        let t = build_traces_salted(&p, &[], &[], [0; 4], &e, Tier(10), gas).unwrap();
        assert!(m.verify(&p.digest(), &m.prove_traces(&p, &t, Tier(10))).is_ok());

        // One more permutation (one word past the last digest row, one cycle fewer so the cycle
        // budget is not what answers) has no slot.
        let over = filler(4 * digest_rows + 1, cycles - 1);
        let e = execute(&over, &[], &[], 1 << 20).unwrap();
        assert!(matches!(
            build_traces_salted(&over, &[], &[], [0; 4], &e, Tier(10), gas_max(Tier(10), 0, 0)),
            Err(ProveError::TooManyPoseidon2Permutations { .. })
        ));
    }
}

// ─────────────────────── Task A3: the `GAS` column, in the circuit ───────────────────────

mod gas_column_tests {
    use super::common;
    use randprotocol_zkvm::emulator::execute;
    use randprotocol_zkvm::gas::{gas_max, gas_of};
    use randprotocol_zkvm::machine::{build_traces_salted, FriProfile, Machine, ProveError, ProveOptions, Tier};
    use randprotocol_zkvm::tables::cpu::pv;
    use randprotocol_zkvm::tables::F;
    use p3_field::PrimeCharacteristicRing;

    /// A real proof's `GAS_LIMIT` is the header ceiling by default, and verifies — the `HALT`
    /// row's limbs carry the whole slack `gas_max − gas`.
    #[test]
    fn a_default_proof_declares_the_ceiling_and_verifies() {
        let (p, proof) = common::fib_proof_tier_10();
        // Constraint set 11: the ceiling of the *declared* header, poseidon2 height included.
        assert_eq!(proof.public_values[pv::GAS], randprotocol_zkvm::gas::gas_max_declared(Tier(10), proof.keccak_log_height, proof.sha256_log_height, 0, proof.poseidon2_log_height));
        assert!(proof.public_values[pv::GAS] < gas_max(Tier(10), 0, 0), "fib declares a short poseidon2 table");
        let m = Machine::new(FriProfile::Test);
        assert!(m.verify(&p.digest(), &proof).is_ok());
    }

    /// Review focus 1: the honest boundary `GAS == GAS_LIMIT` verifies (zero slack, all four
    /// limbs zero); the prover refuses one below and one past the header before building a trace;
    /// and a limit one below the run, forced into the public values under the honest trace, is
    /// refused by the AIR — the `HALT` row's limbs cannot represent `−1`.
    ///
    /// (Task A4 adds `ProveOptions.gas_limit` and the `prove_with_options` spelling of this test;
    /// here the limit goes through `build_traces_salted` and `prove_traces`.)
    #[test]
    fn a_limit_one_below_the_run_is_refused() {
        let m = Machine::new(FriProfile::Test);
        let p = randprotocol_zkvm::guests::fib(20);
        let e = execute(&p, &[], &[], 10_000).unwrap();
        let gas = gas_of(&p, &[], &[], &e.events);
        let max = gas_max(Tier(10), 0, 0);
        assert!(gas < max);

        let t = build_traces_salted(&p, &[], &[], [0; 4], &e, Tier(10), gas).unwrap();
        let exact = m.prove_traces(&p, &t, Tier(10));
        assert_eq!(exact.public_values[pv::GAS], gas);
        assert!(m.verify(&p.digest(), &exact).is_ok(), "GAS == GAS_LIMIT is honest");

        assert!(matches!(
            build_traces_salted(&p, &[], &[], [0; 4], &e, Tier(10), gas - 1),
            Err(ProveError::GasLimitBelowRun { gas: g, limit }) if g == gas && limit == gas - 1
        ));
        assert!(matches!(
            build_traces_salted(&p, &[], &[], [0; 4], &e, Tier(10), max + 1),
            Err(ProveError::GasLimitAboveHeader { limit, max: m }) if limit == max + 1 && m == max
        ));

        // A cheating prover past the refusal: the honest trace, the public value lowered by one.
        let mut forged = build_traces_salted(&p, &[], &[], [0; 4], &e, Tier(10), gas).unwrap();
        forged.public_values[pv::GAS] = F::from_u64(gas - 1);
        assert!(common::rejects(|| m.verify(&p.digest(), &m.prove_traces(&p, &forged, Tier(10)))));
        // And one that also satisfies the halt-row equation by writing `−1` into limb 0: only the
        // `RANGE8` lookup on the limbs stands between it and a verifying proof.
        let w = randprotocol_zkvm::tables::cpu::col::WIDTH;
        let halt = (0..forged.cpu.values.len() / w).find(|&r| forged.cpu.values[r * w + randprotocol_zkvm::tables::cpu::col::SYS_HALT] == F::ONE).unwrap();
        forged.cpu.values[halt * w + randprotocol_zkvm::tables::cpu::col::GD0] = -F::ONE;
        assert!(common::rejects(|| m.verify(&p.digest(), &m.prove_traces(&p, &forged, Tier(10)))));
    }

    /// Task A4: `ProveOptions.gas_limit` is the `Machine::prove_with_options` spelling of the same
    /// rule — `None` (the default) declares the header's ceiling, `Some(g)` overrides it, and the
    /// same two refusals fire before any key is built.
    #[test]
    fn the_default_limit_is_the_ceiling_and_the_option_can_go_below() {
        let m = Machine::new(FriProfile::Test);
        let p = randprotocol_zkvm::guests::fib(20);
        let e = execute(&p, &[], &[], 10_000).unwrap();
        let gas = gas_of(&p, &[], &[], &e.events);
        let dflt = m.prove_with_options(&p, &[], &[], Some(Tier(10)), ProveOptions::default()).unwrap().0;
        assert_eq!(dflt.public_values[pv::GAS], randprotocol_zkvm::gas::gas_max_declared(Tier(10), dflt.keccak_log_height, dflt.sha256_log_height, 0, dflt.poseidon2_log_height));
        let tight = m.prove_with_options(&p, &[], &[], Some(Tier(10)), ProveOptions { gas_limit: Some(gas + 5), ..Default::default() }).unwrap().0;
        assert_eq!(tight.public_values[pv::GAS], gas + 5);
        assert!(m.verify(&p.digest(), &tight).is_ok());
        assert!(matches!(
            m.prove_with_options(&p, &[], &[], Some(Tier(10)), ProveOptions { gas_limit: Some(u64::MAX), ..Default::default() }),
            Err(ProveError::GasLimitAboveHeader { .. })
        ));
    }

    /// The `HALT` row's four byte limbs hold `gas_max − gas` at every header the verifier admits:
    /// the largest ceiling (tier 20, both hash tables at their flat cap of `2^20` rows) is under
    /// `2^32`.
    #[test]
    fn every_admissible_ceiling_fits_the_four_gas_limbs() {
        assert!(gas_max(Tier(20), 20, 20) < 1 << 32);
    }

    /// Task A1's deferred clamp: `gas_max` clamps an untrusted height at 40 (no shift overflow),
    /// and an absurd `u8` height does not panic.
    #[test]
    fn gas_max_clamps_an_absurd_height() {
        assert_eq!(gas_max(Tier(10), 41, 0), gas_max(Tier(10), 40, 0));
        let _ = gas_max(Tier(10), 255, 255);
    }
}

/// Constraint set 11 (ZKVM-202): a `MODQ` row weighs by op — `NTT`/`INTT` 193, `DOT4` 264, `MSUB4` 304
/// (one flat 168 through set 10) — and `gas_max_with_modq` allows every 1 024-row modq block the
/// heaviest. `gas_max` is its modq-free case. The cpu row cannot tell the op; the modq chip prices
/// the call on the `MODQ` bus into the cpu's `MODQ_W`, and the forgeries below are the ways a
/// prover could try to pay less than the op it ran.
mod modq {
    use super::common;
    use randprotocol_zkvm::emulator::{execute, Execution, Syscall};
    use randprotocol_zkvm::gas::{gas_max, gas_max_with_modq, gas_of, modq_gas, modq_op, row_gas, MODQ_DOT4_GAS, MODQ_INTT_GAS, MODQ_MAX_GAS, MODQ_MSUB4_GAS, MODQ_NTT_GAS};
    use randprotocol_zkvm::isa::Program;
    use randprotocol_zkvm::machine::{build_traces_salted, FriProfile, Machine, Tier, Traces};
    use randprotocol_zkvm::modq::{Args, Op};
    use randprotocol_zkvm::tables::cpu::{col, pv};
    use randprotocol_zkvm::tables::F;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};

    const OPS: [(Op, u64); 4] = [(Op::Ntt, 193), (Op::Intt, 193), (Op::Dot4, 264), (Op::Msub4, 304)];

    #[test]
    fn modq_gas_is_per_op() {
        assert_eq!((MODQ_NTT_GAS, MODQ_INTT_GAS, MODQ_DOT4_GAS, MODQ_MSUB4_GAS), (193, 193, 264, 304));
        for (op, w) in OPS {
            assert_eq!(modq_gas(op), w);
            assert_eq!(modq_op(op as u32 | 7 << 8 | 3 << 16 | 9 << 24), op, "the op is a1's low two bits, whatever the operands");
        }
        assert_eq!(MODQ_MAX_GAS, 304, "the ceiling's modq term takes the heaviest op");
        assert_eq!(gas_max_with_modq(Tier(10), 0, 0, 10), gas_max(Tier(10), 0, 0) + 303);
        assert_eq!(gas_max_with_modq(Tier(14), 12, 13, 16), gas_max(Tier(14), 12, 13) + 64 * 303);
    }

    #[test]
    fn every_admissible_modq_ceiling_fits_the_four_gas_limbs() {
        assert!(gas_max_with_modq(Tier(20), 20, 20, 20) < 1 << 32);
    }

    #[test]
    fn gas_max_with_modq_clamps_an_absurd_height() {
        assert_eq!(gas_max_with_modq(Tier(10), 0, 0, 41), gas_max_with_modq(Tier(10), 0, 0, 40));
        let _ = gas_max_with_modq(Tier(10), 255, 255, 255);
    }

    /// One call of each op, in `OPS` order, over an arena the guest never fills: every polynomial
    /// is zero, which is as good a `MODQ` operand as any and keeps the run inside tier 10.
    fn four_ops() -> (Program, Execution) {
        use randprotocol_zkvm::asm::{ops::*, Assembler};
        let calls = [
            Args { op: Op::Ntt, out: 0, a: 0, b: 0 },
            Args { op: Op::Intt, out: 0, a: 0, b: 0 },
            Args { op: Op::Dot4, out: 8, a: 0, b: 4 },
            Args { op: Op::Msub4, out: 0, a: 8, b: 4 },
        ].map(Args::encode);
        let mut a = Assembler::new(0);
        for a1 in calls { a.extend(call_modq(0x1000, a1)); }
        a.extend(halt());
        let p = a.assemble();
        let e = execute(&p, &[], &[], 1 << 10).unwrap();
        assert!(e.halted);
        (p, e)
    }

    const TIER: Tier = Tier(10);
    /// Four blocks: a `2^12`-row modq table.
    const MLH: u8 = 12;

    fn traces(p: &Program, e: &Execution) -> Traces {
        let gas = gas_of(p, &[], &[], &e.events);
        assert!(gas <= gas_max_with_modq(TIER, 0, 0, MLH));
        build_traces_salted(p, &[], &[], [0; 4], e, TIER, gas).unwrap()
    }

    fn cell(t: &Traces, r: usize, c: usize) -> u64 { t.cpu.values[r * col::WIDTH + c].as_canonical_u64() }

    /// The cpu rows of the four `MODQ` calls, in `OPS` order.
    fn modq_rows(t: &Traces) -> Vec<usize> {
        let rows: Vec<usize> = (0..t.cpu.values.len() / col::WIDTH).filter(|&r| cell(t, r, col::SYS_MODQ) == 1).collect();
        assert_eq!(rows.len(), 4);
        rows
    }

    /// The emulator's meter and the trace agree, op by op: `row_gas` is the op's weight, the cpu
    /// row's `MODQ_W` is that weight less the row's own 1, the `GAS` column climbs by exactly it,
    /// and `MODQ_W` is zero on every other row.
    #[test]
    fn a_modq_row_weighs_what_its_op_weighs_in_the_emulator_and_in_the_trace() {
        let (p, e) = four_ops();
        let evs: Vec<_> = e.events.iter().filter(|ev| matches!(ev.sys, Some(Syscall::Modq { .. }))).collect();
        assert_eq!(evs.len(), 4);
        for (ev, (op, w)) in evs.iter().zip(OPS) {
            let Some(Syscall::Modq { a1, .. }) = ev.sys else { unreachable!() };
            assert_eq!(Args::decode(a1).unwrap().op, op);
            assert_eq!(row_gas(ev), w, "{op:?}");
        }
        let prefix = p.digest_rows() + randprotocol_zkvm::hash::input_digest_row_count(0) + randprotocol_zkvm::hash::public_digest_row_count(0);
        assert_eq!(gas_of(&p, &[], &[], &e.events), 4 * prefix as u64 + e.events.len() as u64 + OPS.iter().map(|(_, w)| w - 1).sum::<u64>());

        let t = traces(&p, &e);
        let rows = modq_rows(&t);
        for (&r, (op, w)) in rows.iter().zip(OPS) {
            assert_eq!(cell(&t, r, col::MODQ_W), w - 1, "{op:?}: MODQ_W");
            assert_eq!(cell(&t, r, col::GAS) - cell(&t, r - 1, col::GAS), w, "{op:?}: the GAS step");
        }
        for r in 0..t.cpu.values.len() / col::WIDTH {
            if !rows.contains(&r) { assert_eq!(cell(&t, r, col::MODQ_W), 0, "row {r} is not a MODQ row"); }
        }
        let halt = (0..t.cpu.values.len() / col::WIDTH).find(|&r| cell(&t, r, col::SYS_HALT) == 1).unwrap();
        assert_eq!(cell(&t, halt, col::GAS), gas_of(&p, &[], &[], &e.events), "the trace's meter is the emulator's");
    }

    /// Rebuild the `GAS` chain with row `r` weighing `weight(r, honest)` in place of its honest
    /// weight, and move `pv::GAS` by the difference, so the `HALT` row's limbs (and `RANGE8`) are
    /// untouched and only the rules on the weight can object.
    fn rechain(t: &mut Traces, weight: impl Fn(usize, i64) -> i64) {
        let w = col::WIDTH;
        let height = t.cpu.values.len() / w;
        let (mut prev_old, mut new, mut r) = (0i64, 0i64, 0);
        while r < height && cell(t, r, col::IS_REAL) == 1 {
            let old = cell(t, r, col::GAS) as i64;
            new += weight(r, old - prev_old);
            prev_old = old;
            t.cpu.values[r * w + col::GAS] = F::from_u64(new as u64);
            r += 1;
        }
        for p in r..height { t.cpu.values[p * w + col::GAS] = F::from_u64(new as u64); }
        let pv = t.public_values[pv::GAS].as_canonical_u64() as i64;
        t.public_values[pv::GAS] = F::from_u64((pv + new - prev_old) as u64);
    }

    fn verifies(m: &Machine, p: &Program, t: &Traces) -> Result<(), randprotocol_zkvm::machine::VerifyError> {
        m.verify(&p.digest(), &m.prove_traces(p, t, TIER))
    }

    /// A prover must not claim one op's work at another's price. Per op, three forgeries, each with
    /// the `GAS` chain and `pv::GAS` made consistent with the claim so nothing else can object:
    ///
    /// 1. the row's `MODQ_W` set to a cheaper op's weight (for the transforms, which are the
    ///    cheapest, to the pre-set-11 flat 167 and to nothing) — the `MODQ` lookup has no such
    ///    entry: the chip's is `(clk, base, a1, weight of a1's op)`;
    /// 2. `MODQ_W` honest but the chain stepped by the cheaper weight — the gas chain adds `MODQ_W`;
    /// 3. the honest row untouched and the saving taken as a negative `MODQ_W` on the plain row
    ///    before it — `MODQ_W` is pinned to zero off a `MODQ` row.
    ///
    /// Dropping the fourth lookup field, the chain's `MODQ_W` term or the pin from the AIR lets the
    /// matching forgery through.
    #[test]
    fn a_modq_op_claimed_at_another_weight_is_refused() {
        let m = Machine::new(FriProfile::Test);
        let (p, e) = four_ops();
        let honest = traces(&p, &e);
        assert!(verifies(&m, &p, &honest).is_ok(), "the honest four-op run proves and verifies");
        let rows = modq_rows(&honest);
        for (&r, (op, w)) in rows.iter().zip(OPS) {
            let cheaper: Vec<u64> = match op {
                Op::Ntt | Op::Intt => vec![168, 1],
                Op::Dot4 => vec![MODQ_NTT_GAS],
                Op::Msub4 => vec![MODQ_NTT_GAS, MODQ_DOT4_GAS],
            };
            for claimed in cheaper {
                assert!(claimed < w);
                let mut forged = traces(&p, &e);
                forged.cpu.values[r * col::WIDTH + col::MODQ_W] = F::from_u64(claimed - 1);
                rechain(&mut forged, |row, honest| if row == r { claimed as i64 } else { honest });
                assert!(common::rejects(|| verifies(&m, &p, &forged)), "{op:?} with MODQ_W for a weight of {claimed} verified");
            }
            let claimed = if matches!(op, Op::Ntt | Op::Intt) { 1 } else { MODQ_NTT_GAS as i64 };
            let mut forged = traces(&p, &e);
            rechain(&mut forged, |row, honest| if row == r { claimed } else { honest });
            assert!(common::rejects(|| verifies(&m, &p, &forged)), "{op:?} stepped by {claimed} under an honest MODQ_W verified");
        }
        // The credit: the `MSUB4` row honest, and the plain row before it carrying −(304 − 193).
        let r = rows[3];
        assert_eq!((cell(&honest, r - 1, col::SYS_MODQ), cell(&honest, r - 1, col::IS_REAL)), (0, 1));
        let credit = (MODQ_MSUB4_GAS - MODQ_NTT_GAS) as i64;
        let mut forged = traces(&p, &e);
        forged.cpu.values[(r - 1) * col::WIDTH + col::MODQ_W] = -F::from_u64(credit as u64);
        rechain(&mut forged, |row, honest| if row == r - 1 { honest - credit } else { honest });
        assert!(common::rejects(|| verifies(&m, &p, &forged)), "a negative MODQ_W on a plain row verified");
    }
}
