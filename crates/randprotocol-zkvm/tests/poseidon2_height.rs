//! The proof-declared poseidon2 table height — live since constraint set 11 (monorepo issue 65,
//! ZKVM-112; `docs/05-roadmap.md`). Through set 10 the table was `2^(t+2)` rows at every tier; now
//! a proof declares `Proof::poseidon2_log_height`, one of `t + 2, t, …` down to the private-data
//! floor (`POSEIDON2_HEIGHT_STEP = 2`), and the verifier range-checks it with the other declared
//! heights before it builds anything. Tiers 10 to 12 only. Forgeries at a declared height are in
//! `tests/cheating.rs`.
use p3_matrix::Matrix;
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::guests;
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::{self, build_traces, check_poseidon2_log_height, FriProfile, Machine, ProveError, ProveOptions, Tier, VerifierKeyShape, VerifyError, POSEIDON2_HEIGHT_STEP};

fn hashing_guest() -> Program {
    // 64 words through POSEIDON2: 16 absorb rows, on top of the digest rows of a program that
    // stores those 64 words one by one.
    let msg: Vec<u32> = (0..64).collect();
    guests::poseidon2_demo(&msg)
}

/// The permutations a run makes, counted as `build_traces` counts them.
fn permutations(p: &Program, exec: &randprotocol_zkvm::emulator::Execution) -> usize {
    let absorb = exec.events.iter().filter(|e| matches!(e.hash_row, Some(randprotocol_zkvm::emulator::HashRow::Absorb { .. }))).count();
    p.digest_rows() + randprotocol_zkvm::hash::input_digest_row_count(0) + randprotocol_zkvm::hash::public_digest_row_count(0) + absorb
}

fn prove_declaring(m: &Machine, p: &Program, tier: Tier, h: Option<u8>) -> Result<machine::Proof, ProveError> {
    m.prove_with_options(p, &[], &[], Some(tier), ProveOptions { poseidon2_log_height: h, ..Default::default() }).map(|(p, _)| p)
}

// ─────────────────────────── the admitted set ───────────────────────────

#[test]
fn the_admitted_heights_are_the_tiers_maximum_and_every_fourth_of_it() {
    assert_eq!(POSEIDON2_HEIGHT_STEP, 2);
    assert_eq!(Tier(10).admitted_poseidon2_log_heights(), vec![8, 10, 12]);
    assert_eq!(Tier(14).admitted_poseidon2_log_heights(), vec![8, 10, 12, 14, 16]);
    assert_eq!(Tier(20).admitted_poseidon2_log_heights(), vec![8, 10, 12, 14, 16, 18, 20, 22]);
    for t in machine::TIERS {
        let tier = Tier(t);
        let admitted = tier.admitted_poseidon2_log_heights();
        assert_eq!(*admitted.last().unwrap(), tier.max_poseidon2_log_height(), "the full height is admitted");
        assert_eq!(1usize << tier.max_poseidon2_log_height(), tier.poseidon2_height());
        assert_eq!(admitted.len(), (t - 4) / 2, "tier {t}");
        for h in 0..=40u8 {
            assert_eq!(check_poseidon2_log_height(tier, h).is_ok(), admitted.contains(&h), "tier {t}, height {h}");
        }
    }
}

#[test]
fn each_refusal_has_its_own_error() {
    let tier = Tier(12);
    assert_eq!(check_poseidon2_log_height(tier, 6), Err(VerifyError::Poseidon2HeightBelowFloor { declared: 6 }));
    assert_eq!(check_poseidon2_log_height(tier, 0), Err(VerifyError::Poseidon2HeightBelowFloor { declared: 0 }));
    assert_eq!(check_poseidon2_log_height(tier, 7), Err(VerifyError::Poseidon2HeightNotAdmitted { declared: 7 }));
    assert_eq!(check_poseidon2_log_height(tier, 11), Err(VerifyError::Poseidon2HeightNotAdmitted { declared: 11 }));
    assert_eq!(check_poseidon2_log_height(tier, 15), Err(VerifyError::Poseidon2HeightExceedsTier { declared: 15, max: 14 }));
    assert_eq!(check_poseidon2_log_height(tier, 255), Err(VerifyError::Poseidon2HeightExceedsTier { declared: 255, max: 14 }));
    assert_eq!(check_poseidon2_log_height(Tier(11), 10), Err(VerifyError::Tier));
    assert_eq!(check_poseidon2_log_height(Tier(99), 10), Err(VerifyError::Tier));
    // And it is part of `check_declared_heights_with_modq`, last.
    assert_eq!(machine::check_declared_heights_with_modq(tier, 7, 7, 0, 0, 0, 7, 14, 11), Err(VerifyError::Poseidon2HeightNotAdmitted { declared: 11 }));
    assert_eq!(machine::check_declared_heights_with_modq(tier, 7, 7, 0, 0, 0, 7, 14, 8), Ok(()));
}

#[test]
fn the_declared_height_is_the_smallest_admitted_one_that_holds_the_run() {
    let tier = Tier(12);
    assert_eq!(tier.poseidon2_log_height_for(0), Some(8));
    assert_eq!(tier.poseidon2_log_height_for(8), Some(8), "eight blocks fill 2^8 rows");
    assert_eq!(tier.poseidon2_log_height_for(9), Some(10));
    assert_eq!(tier.poseidon2_log_height_for(32), Some(10));
    assert_eq!(tier.poseidon2_log_height_for(33), Some(12));
    assert_eq!(tier.poseidon2_log_height_for(512), Some(14));
    assert_eq!(tier.poseidon2_log_height_for(513), None, "more than the tier holds");
}

/// The gas ceiling's permutation term follows the declared height (item 2 of the roadmap's list):
/// `3 · 2^p2lh / 32`, and at the full height it is the tier's `3 · 2^(t−3)`.
#[test]
fn the_gas_ceiling_follows_the_declared_height() {
    use randprotocol_zkvm::gas::{gas_max_declared, gas_max_with_modq};
    for t in machine::TIERS {
        let tier = Tier(t);
        assert_eq!(gas_max_declared(tier, 0, 0, 0, tier.max_poseidon2_log_height()), gas_max_with_modq(tier, 0, 0, 0));
        for h in tier.admitted_poseidon2_log_heights() {
            assert_eq!(gas_max_declared(tier, 0, 0, 0, h), (1u64 << t) - 1 + 3 * (1u64 << (h - 5)), "tier {t}, height {h}");
        }
        // Clamped, never more than the full table's.
        assert_eq!(gas_max_declared(tier, 0, 0, 0, 255), gas_max_with_modq(tier, 0, 0, 0));
    }
}

// ─────────────────────────── proving and verifying ───────────────────────────

/// The issue's first acceptance line: a guest with no POSEIDON2 call proves with the poseidon2
/// table at the floor height, and the proof verifies.
#[test]
fn a_guest_that_does_not_hash_proves_at_the_floor() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, exec) = m.prove(&p, &[], &[], None).unwrap();
    let tier = proof.tier;
    assert_eq!(permutations(&p, &exec), p.digest_rows() + 2, "the program digest, the input salt row and the public header row");
    assert_eq!(proof.poseidon2_log_height, 8, "the smallest admitted height");
    // The poseidon2 instance is the seventh (index 6); +1 is the hiding PCS's extra bit.
    assert_eq!(proof.batch.degree_bits[6], 8 + 1);
    assert_eq!(proof.public_values[randprotocol_zkvm::tables::cpu::pv::GAS], randprotocol_zkvm::gas::gas_max_declared(tier, 0, 0, 0, 8), "the default gas word is the declared header's ceiling");
    m.verify(&p.digest(), &proof).unwrap();
    assert_eq!(m.key_builds(), 1);
    // The same program declaring the tier's full height verifies too, under another key.
    let full = prove_declaring(&m, &p, tier, Some(tier.max_poseidon2_log_height())).unwrap();
    assert_eq!(full.batch.degree_bits[6], tier.0 + 2 + 1);
    m.verify(&p.digest(), &full).unwrap();
    assert_eq!(m.key_builds(), 2);
    let exec = execute(&p, &[], &[], tier.max_cycles()).unwrap();
    let t = build_traces(&p, &[], &[], &exec, tier).unwrap();
    let total: usize = t.as_slice().iter().map(|m| m.width() * m.height()).sum();
    let full_p2 = t.poseidon2.width() * tier.poseidon2_height();
    eprintln!(
        "fib(10), tier {}: main-trace cells {} at the full poseidon2 height -> {total} declared ({:.1} % fewer)",
        tier.0,
        total - t.poseidon2.width() * t.poseidon2.height() + full_p2,
        100.0 * (full_p2 - t.poseidon2.width() * t.poseidon2.height()) as f64 / (total - t.poseidon2.width() * t.poseidon2.height() + full_p2) as f64
    );
}

/// A guest that does hash declares what it needs.
#[test]
fn a_hashing_guest_declares_what_it_needs() {
    let m = Machine::new(FriProfile::Test);
    let p = hashing_guest();
    let (proof, exec) = m.prove(&p, &[], &[], Some(Tier(12))).unwrap();
    let perms = permutations(&p, &exec);
    let tier = proof.tier;
    assert_eq!(Some(proof.poseidon2_log_height), tier.poseidon2_log_height_for(perms));
    assert!(perms * 32 <= 1 << proof.poseidon2_log_height);
    assert!(proof.poseidon2_log_height > 8 && proof.poseidon2_log_height < tier.max_poseidon2_log_height(), "between the floor and the tier's height");
    m.verify(&p.digest(), &proof).unwrap();
}

/// The key is a function of the declared height: at the tier's maximum it is the full-height key
/// the 6-height `verifier_key` builds; lower is a different key.
#[test]
fn the_key_depends_on_the_declared_height() {
    let m = Machine::new(FriProfile::Test);
    let tier = Tier(10);
    let full = VerifierKeyShape::full_height(tier, 7, 7, 0, 0, 0, 7);
    assert_eq!(full.poseidon2_log_height, 12);
    let bytes = |c: &p3_batch_stark::CommonData<machine::Config>| postcard::to_allocvec(&c.preprocessed.as_ref().unwrap().commitment).unwrap();
    assert_eq!(bytes(&m.verifier_key_for(full)), bytes(&m.verifier_key(tier, 7, 7, 0, 0, 7)));
    let lower = VerifierKeyShape { poseidon2_log_height: 8, ..full };
    assert_ne!(bytes(&m.verifier_key_for(lower)), bytes(&m.verifier_key_for(full)));
    assert!(m.has_cached_key(lower) && m.has_cached_key(full));
}

/// An explicit gas limit above the default height's ceiling raises the declared height until the
/// header can carry it; above the full height's ceiling it is refused.
#[test]
fn an_explicit_gas_limit_raises_the_default_height() {
    let p = guests::fib(10);
    let tier = Tier(10);
    let exec = execute(&p, &[], &[], tier.max_cycles()).unwrap();
    let full = randprotocol_zkvm::gas::gas_max(tier, 0, 0);
    let t = machine::build_traces_salted(&p, &[], &[], [0; 4], &exec, tier, full).unwrap();
    assert_eq!(t.poseidon2_log_height, 12);
    let t = machine::build_traces_salted(&p, &[], &[], [0; 4], &exec, tier, randprotocol_zkvm::gas::gas_max_declared(tier, 0, 0, 0, 8) + 1).unwrap();
    assert_eq!(t.poseidon2_log_height, 10);
    assert!(matches!(machine::build_traces_salted(&p, &[], &[], [0; 4], &exec, tier, full + 1), Err(ProveError::GasLimitAboveHeader { .. })));
}

// ─────────────────────────── refusals ───────────────────────────

/// The issue's second acceptance line: a declared height outside the admitted set is refused
/// before any key is built.
#[test]
fn a_height_outside_the_admitted_set_is_refused_before_any_key_is_built() {
    let prover = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    // The full height, so no relabelling below can push the gas word over its ceiling first.
    let mut proof = prove_declaring(&prover, &p, Tier(10), Some(12)).unwrap();
    let tier = proof.tier;
    let honest = proof.poseidon2_log_height;
    // A fresh verifier, so its build count starts at zero.
    let v = Machine::new(FriProfile::Test);
    for h in (0..=64u8).chain([127, 128, 200, 255]) {
        if tier.admitted_poseidon2_log_heights().contains(&h) {
            continue;
        }
        proof.poseidon2_log_height = h;
        // What a forger would also edit, so the degree-bits comparison could not be what stops it.
        proof.batch.degree_bits[6] = h as usize + 1;
        let err = v.verify(&p.digest(), &proof).unwrap_err();
        assert!(
            matches!(err, VerifyError::Poseidon2HeightBelowFloor { .. } | VerifyError::Poseidon2HeightExceedsTier { .. } | VerifyError::Poseidon2HeightNotAdmitted { .. } | VerifyError::GasLimit),
            "height {h}: {err:?}"
        );
    }
    assert_eq!(v.key_builds(), 0, "no refusal above built a key");
    // An admitted height that is not the proof's: refused by the degree-bits comparison, again
    // with no key built.
    proof.batch.degree_bits[6] = honest as usize + 1;
    for h in tier.admitted_poseidon2_log_heights().into_iter().filter(|h| *h != honest) {
        proof.poseidon2_log_height = h;
        let err = v.verify(&p.digest(), &proof).unwrap_err();
        assert!(matches!(err, VerifyError::Tier | VerifyError::GasLimit), "height {h}: {err:?}");
    }
    assert_eq!(v.key_builds(), 0);
    proof.poseidon2_log_height = honest;
    v.verify(&p.digest(), &proof).unwrap();
    assert_eq!(v.key_builds(), 1);
}

/// The prover refuses a declared height its run does not fit, or that the verifier would not
/// admit.
#[test]
fn the_prover_refuses_a_height_that_does_not_hold_the_run() {
    let m = Machine::new(FriProfile::Test);
    let p = hashing_guest();
    let proof = prove_declaring(&m, &p, Tier(12), None).unwrap();
    let (tier, needed) = (proof.tier, proof.poseidon2_log_height);
    assert!(needed > 8, "the guest needs more than the floor");
    for h in [needed - 2, needed - 1, 7, 0, tier.max_poseidon2_log_height() + 2] {
        assert!(matches!(prove_declaring(&m, &p, tier, Some(h)), Err(ProveError::TooManyPoseidon2Permutations { .. })), "height {h}");
    }
}

// ─────────────────────────── measurement ───────────────────────────

/// The ERC-20 transfer (the compiled EVM guest, tier 18): the poseidon2 height it declares and the
/// main-trace cells against the full height. Traces only — nothing is proved (a tier-18 proof is a
/// big-host run), so this is a cell count, not a prove-time or peak-heap figure.
///
/// ```sh
/// cargo test --release --test poseidon2_height erc20 -- --nocapture
/// ```
#[test]
fn erc20_transfer_cells_with_a_declared_poseidon2_height() {
    use evm_core::u256::U256;
    use randprotocol_zkvm::evm::{erc20_transfer, ALICE, BOB};
    let p = guests::compiled::evm();
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let inputs = call.input_words();
    let exec = execute(&p, &inputs, &[], Tier(20).max_cycles()).unwrap();
    let absorb = exec.events.iter().filter(|e| matches!(e.hash_row, Some(randprotocol_zkvm::emulator::HashRow::Absorb { .. }))).count();
    let perms = p.digest_rows() + randprotocol_zkvm::hash::input_digest_row_count(inputs.len()) + randprotocol_zkvm::hash::public_digest_row_count(0) + absorb;
    let cycles = exec.cycles() + p.digest_rows() + randprotocol_zkvm::hash::input_digest_row_count(inputs.len()) + randprotocol_zkvm::hash::public_digest_row_count(0);
    let tier = Tier::for_workload(cycles, perms).unwrap();
    let t = build_traces(&p, &inputs, &[], &exec, tier).unwrap();
    let declared = t.poseidon2_log_height;
    assert_eq!(Some(declared), tier.poseidon2_log_height_for(perms));
    let total: usize = t.as_slice().iter().map(|m| m.width() * m.height()).sum();
    let p2 = t.poseidon2.width() * t.poseidon2.height();
    let p2_full = t.poseidon2.width() * tier.poseidon2_height();
    eprintln!(
        "erc20 transfer: tier {}, {cycles} cycles, {perms} poseidon2 permutations ({} of them the program digest); poseidon2 table 2^{} -> 2^{declared}; \
         main-trace cells {} -> {total} ({:.1} % fewer)",
        tier.0,
        p.digest_rows(),
        tier.0 + 2,
        total - p2 + p2_full,
        100.0 * (p2_full - p2) as f64 / (total - p2 + p2_full) as f64,
    );
    assert!(declared <= tier.max_poseidon2_log_height());
}
