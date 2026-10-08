//! The verifier's cheap header checks at every boundary, without a proof: `check_declared_heights`
//! for each declared table at its floor, its cap, and one past each, at every tier; the order
//! the checks run in; `Tier`'s own arithmetic and the auto-tier pick at its budget edges; and
//! `gas_max`/`row_gas` as the exact formulas the spec states.
use randprotocol_zkvm::gas::{gas_max, gas_of, row_gas, KECCAK_GAS, POSEIDON2_ABSORB_GAS, SHA256_GAS};
use randprotocol_zkvm::machine::{check_declared_heights, Tier, VerifyError, MAX_MEM_LOG_HEIGHT, TIERS};
use randprotocol_zkvm::tables::{input, keccak, program, public, sha256, MIN_PRIVATE_TABLE_LOG_HEIGHT as FLOOR};

/// A declaration every tier admits: every table at the private-data floor, no hash tables, the
/// memory table at the tier's own floor.
fn minimal(t: Tier) -> (u8, u8, u8, u8, u8, u8) { (FLOOR, FLOOR, 0, 0, FLOOR, t.min_mem_log_height()) }

fn check(t: Tier, d: (u8, u8, u8, u8, u8, u8)) -> Result<(), VerifyError> {
    check_declared_heights(t, d.0, d.1, d.2, d.3, d.4, d.5)
}

#[test]
fn the_minimal_declaration_passes_at_every_tier() {
    for &t in &TIERS {
        assert_eq!(check(Tier(t), minimal(Tier(t))), Ok(()), "tier {t}");
    }
    assert_eq!(FLOOR, 7);
    assert_eq!(program::MIN_LOG_HEIGHT, FLOOR);
    assert_eq!(input::MIN_LOG_HEIGHT, FLOOR);
    assert_eq!(public::MIN_LOG_HEIGHT, FLOOR);
}

#[test]
fn a_tier_outside_the_table_is_refused_before_anything_else_is_read() {
    for t in [0usize, 9, 11, 13, 15, 17, 19, 21, 22, 64, 99, usize::MAX] {
        assert_eq!(check(Tier(t), minimal(Tier(10))), Err(VerifyError::Tier), "tier {t}");
        // Even with every other field absurd: the tier guard comes first, so nothing shifts by it.
        assert_eq!(check_declared_heights(Tier(t), 255, 255, 255, 255, 255, 255), Err(VerifyError::Tier));
    }
}

#[test]
fn the_program_table_is_bounded_by_the_floor_and_its_own_cap() {
    let t = Tier(10);
    let m = minimal(t);
    for (plh, want) in [(0u8, Err(VerifyError::ProgramHeight)), (FLOOR - 1, Err(VerifyError::ProgramHeight)), (FLOOR, Ok(())), (program::MAX_LOG_HEIGHT, Ok(())), (program::MAX_LOG_HEIGHT + 1, Err(VerifyError::ProgramHeight)), (255, Err(VerifyError::ProgramHeight))] {
        assert_eq!(check(t, (plh, m.1, m.2, m.3, m.4, m.5)), want, "plh = {plh}");
    }
    assert_eq!(program::MAX_LOG_HEIGHT, 22);
}

#[test]
fn the_input_and_public_tables_are_bounded_by_the_floor_and_their_caps() {
    let t = Tier(12);
    let m = minimal(t);
    for (h, ok) in [(0u8, false), (FLOOR - 1, false), (FLOOR, true), (input::MAX_LOG_HEIGHT, true), (input::MAX_LOG_HEIGHT + 1, false), (255, false)] {
        let got = check(t, (m.0, h, m.2, m.3, m.4, m.5));
        assert_eq!(got, if ok { Ok(()) } else { Err(VerifyError::InputHeight) }, "ilh = {h}");
    }
    for (h, ok) in [(0u8, false), (FLOOR - 1, false), (FLOOR, true), (public::MAX_LOG_HEIGHT, true), (public::MAX_LOG_HEIGHT + 1, false), (255, false)] {
        let got = check(t, (m.0, m.1, m.2, m.3, h, m.5));
        assert_eq!(got, if ok { Ok(()) } else { Err(VerifyError::PublicHeight) }, "pub = {h}");
    }
    assert_eq!((input::MAX_LOG_HEIGHT, public::MAX_LOG_HEIGHT), (20, 20));
}

#[test]
fn the_keccak_table_is_bounded_by_the_tier_relation_then_the_flat_cap_at_every_tier() {
    for &t in &TIERS {
        let tier = Tier(t);
        let m = minimal(tier);
        let tier_max = tier.max_keccak_log_height();
        assert_eq!(tier_max as usize, t + 5);
        for klh in 0..=u8::MAX {
            let want = if klh == 0 {
                Ok(())
            } else if !(FLOOR..=keccak::MAX_LOG_HEIGHT).contains(&klh) {
                Err(VerifyError::KeccakHeight)
            } else if klh > tier_max {
                Err(VerifyError::KeccakHeightExceedsTier)
            } else {
                Ok(())
            };
            assert_eq!(check(tier, (m.0, m.1, klh, m.3, m.4, m.5)), want, "tier {t}, klh {klh}");
        }
        // The largest legal height at this tier, and one past it, by name.
        let top = tier_max.min(keccak::MAX_LOG_HEIGHT);
        assert_eq!(check(tier, (m.0, m.1, top, m.3, m.4, m.5)), Ok(()));
        let past = check(tier, (m.0, m.1, top + 1, m.3, m.4, m.5));
        assert_eq!(past, if tier_max < keccak::MAX_LOG_HEIGHT { Err(VerifyError::KeccakHeightExceedsTier) } else { Err(VerifyError::KeccakHeight) }, "tier {t}");
    }
}

#[test]
fn the_sha256_table_is_bounded_by_the_tier_relation_then_the_flat_cap_at_every_tier() {
    assert_eq!(sha256::MIN_LOG_HEIGHT, 6, "one block is 64 rows");
    for &t in &TIERS {
        let tier = Tier(t);
        let m = minimal(tier);
        let tier_max = tier.max_sha256_log_height();
        assert_eq!(tier_max as usize, (t + 6).min(sha256::MAX_LOG_HEIGHT as usize), "the method folds the flat cap in");
        for slh in 0..=u8::MAX {
            let want = if slh == 0 {
                Ok(())
            } else if !(FLOOR..=sha256::MAX_LOG_HEIGHT).contains(&slh) {
                Err(VerifyError::Sha256Height)
            } else if slh > tier_max {
                Err(VerifyError::Sha256HeightExceedsTier)
            } else {
                Ok(())
            };
            assert_eq!(check(tier, (m.0, m.1, m.2, slh, m.4, m.5)), want, "tier {t}, slh {slh}");
        }
    }
    // The one-block height (6) is under the privacy floor and refused as a range error, never as
    // a tier error.
    assert_eq!(check(Tier(20), (FLOOR, FLOOR, 0, sha256::MIN_LOG_HEIGHT, FLOOR, 22)), Err(VerifyError::Sha256Height));
    assert_eq!(check(Tier(20), (FLOOR, FLOOR, keccak::MIN_LOG_HEIGHT, 0, FLOOR, 22)), Err(VerifyError::KeccakHeight));
}

#[test]
fn the_memory_table_is_bounded_by_the_tier_floor_and_the_flat_ceiling_at_every_tier() {
    for &t in &TIERS {
        let tier = Tier(t);
        let m = minimal(tier);
        let floor = tier.min_mem_log_height();
        assert_eq!(floor as usize, t + 2);
        for mlh in 0..=u8::MAX {
            let want = if (floor..=MAX_MEM_LOG_HEIGHT).contains(&mlh) { Ok(()) } else { Err(VerifyError::MemoryHeight) };
            assert_eq!(check(tier, (m.0, m.1, m.2, m.3, m.4, mlh)), want, "tier {t}, mlh {mlh}");
        }
    }
    assert_eq!(Tier(20).min_mem_log_height(), 22, "tier 20 leaves two bits of headroom under the ceiling");
}

#[test]
fn the_checks_run_in_declaration_order_so_the_first_bad_field_names_the_error() {
    // Every field bad at once, then fixed one at a time from the front: each step moves the
    // error to the next field.
    let t = Tier(10);
    let bad = (0u8, 0u8, 25u8, 25u8, 0u8, 0u8);
    assert_eq!(check(t, bad), Err(VerifyError::ProgramHeight));
    assert_eq!(check(t, (FLOOR, 0, 25, 25, 0, 0)), Err(VerifyError::InputHeight));
    assert_eq!(check(t, (FLOOR, FLOOR, 25, 25, 0, 0)), Err(VerifyError::KeccakHeight));
    assert_eq!(check(t, (FLOOR, FLOOR, 16, 25, 0, 0)), Err(VerifyError::KeccakHeightExceedsTier));
    assert_eq!(check(t, (FLOOR, FLOOR, 15, 25, 0, 0)), Err(VerifyError::Sha256Height));
    assert_eq!(check(t, (FLOOR, FLOOR, 15, 17, 0, 0)), Err(VerifyError::Sha256HeightExceedsTier));
    assert_eq!(check(t, (FLOOR, FLOOR, 15, 16, 0, 0)), Err(VerifyError::PublicHeight));
    assert_eq!(check(t, (FLOOR, FLOOR, 15, 16, FLOOR, 0)), Err(VerifyError::MemoryHeight));
    assert_eq!(check(t, (FLOOR, FLOOR, 15, 16, FLOOR, 12)), Ok(()));
}

// ─────────────────────────── Tier ───────────────────────────

#[test]
fn tier_arithmetic_is_pinned_at_every_tier() {
    for &t in &TIERS {
        let tier = Tier(t);
        assert_eq!(tier.cpu_height(), 1 << t);
        assert_eq!(tier.max_cycles(), (1 << t) - 1, "one padding row");
        assert_eq!(tier.alu_height(), 1 << (t + 1), "two ALU rows per cycle");
        assert_eq!(tier.poseidon2_height(), 1 << (t + 2));
        assert_eq!(tier.poseidon2_height() / randprotocol_zkvm::tables::poseidon2::BLOCK, 1 << (t - 3), "permutation slots");
        assert_eq!(tier.min_mem_log_height() as usize, t + 2, "four accesses per cycle");
    }
    assert_eq!(TIERS, [10, 12, 14, 16, 18, 20]);
}

#[test]
fn the_auto_tier_pick_flips_exactly_at_each_cycle_budget() {
    assert_eq!(Tier::for_cycles(0), Some(Tier(10)));
    for (i, &t) in TIERS.iter().enumerate() {
        let budget = (1usize << t) - 1;
        assert_eq!(Tier::for_cycles(budget), Some(Tier(t)), "exactly the budget fits tier {t}");
        let next = TIERS.get(i + 1).map(|n| Tier(*n));
        assert_eq!(Tier::for_cycles(budget + 1), next, "one more cycle needs the next tier");
    }
    assert_eq!(Tier::for_cycles(1 << 20), None);
    assert_eq!(Tier::for_cycles(usize::MAX), None);
}

#[test]
fn the_workload_pick_also_flips_exactly_at_each_permutation_budget() {
    for (i, &t) in TIERS.iter().enumerate() {
        let slots = 1usize << (t - 3);
        assert_eq!(Tier::for_workload(1, slots), Some(Tier(t)), "{slots} permutations fit tier {t}");
        let next = TIERS.get(i + 1).map(|n| Tier(*n));
        assert_eq!(Tier::for_workload(1, slots + 1), next);
        // Both budgets bind: a cycle count past the tier moves up even with few permutations.
        assert_eq!(Tier::for_workload((1 << t) - 1, 1), Some(Tier(t)));
        assert_eq!(Tier::for_workload(1 << t, 1), next);
    }
    // The cycle-only pick would have chosen tier 10 here; the permutation budget says 12.
    assert_eq!(Tier::for_cycles(600), Some(Tier(10)));
    assert_eq!(Tier::for_workload(600, 151), Some(Tier(12)));
}

// ─────────────────────────── gas ───────────────────────────

#[test]
fn gas_max_is_the_four_term_formula_at_every_tier() {
    for &t in &TIERS {
        let base = ((1u64 << t) - 1) + (1u64 << (t - 2));
        assert_eq!(gas_max(Tier(t), 0, 0), base, "tier {t}");
        for h in FLOOR..=keccak::MAX_LOG_HEIGHT {
            assert_eq!(gas_max(Tier(t), h, 0) - base, (1u64 << h) / 32 * (KECCAK_GAS - 1), "tier {t} klh {h}");
        }
        for h in FLOOR..=sha256::MAX_LOG_HEIGHT {
            assert_eq!(gas_max(Tier(t), 0, h) - base, (1u64 << h) / 64 * (SHA256_GAS - 1), "tier {t} slh {h}");
        }
        // The two hash terms add independently.
        assert_eq!(gas_max(Tier(t), 10, 12) - base, (gas_max(Tier(t), 10, 0) - base) + (gas_max(Tier(t), 0, 12) - base));
    }
}

#[test]
fn gas_max_is_monotone_in_the_tier_and_in_each_height() {
    for w in TIERS.windows(2) {
        assert!(gas_max(Tier(w[0]), 0, 0) < gas_max(Tier(w[1]), 0, 0));
        assert!(gas_max(Tier(w[0]), 20, 20) < gas_max(Tier(w[1]), 20, 20));
    }
    for h in 1..40u8 {
        assert!(gas_max(Tier(10), h, 0) <= gas_max(Tier(10), h + 1, 0), "klh {h}");
        assert!(gas_max(Tier(10), 0, h) <= gas_max(Tier(10), 0, h + 1), "slh {h}");
    }
    // A sub-block height contributes nothing: fewer rows than one block is zero blocks.
    assert_eq!(gas_max(Tier(10), 4, 0), gas_max(Tier(10), 0, 0));
    assert_eq!(gas_max(Tier(10), 0, 5), gas_max(Tier(10), 0, 0));
    assert_eq!(gas_max(Tier(10), 5, 6), gas_max(Tier(10), 0, 0) + 191 + 63, "exactly one block each");
}

#[test]
fn row_gas_weighs_each_row_kind_exactly_once() {
    use randprotocol_zkvm::emulator::{execute, HashRow, Syscall};
    use randprotocol_zkvm::guests;
    let classify = |e: &randprotocol_zkvm::emulator::Execution| {
        let mut seen = std::collections::BTreeMap::new();
        for ev in &e.events {
            let kind = match (&ev.sys, &ev.hash_row) {
                (Some(Syscall::Keccak { .. }), _) => "keccak",
                (Some(Syscall::Sha256 { .. }), _) => "sha256",
                (_, Some(HashRow::Ecall { .. })) => "hash ecall",
                (_, Some(HashRow::Absorb { .. })) => "absorb",
                (_, Some(HashRow::WriteOut { .. })) => "write-out",
                (Some(_), None) => "other syscall",
                (None, None) => "plain",
            };
            let prev = seen.insert(kind, row_gas(ev));
            if let Some(prev) = prev { assert_eq!(prev, row_gas(ev), "{kind} rows all weigh the same"); }
        }
        seen
    };
    let p = guests::poseidon2_demo(&[1, 2, 3, 4, 5]);
    let seen = classify(&execute(&p, &[], &[], 10_000).unwrap());
    assert_eq!(seen.get("plain"), Some(&1));
    assert_eq!(seen.get("other syscall"), Some(&1));
    assert_eq!(seen.get("hash ecall"), Some(&1));
    assert_eq!(seen.get("write-out"), Some(&1));
    assert_eq!(seen.get("absorb"), Some(&POSEIDON2_ABSORB_GAS));
    let seen = classify(&execute(&guests::keccak_demo(b"x"), &[], &[], 10_000).unwrap());
    assert_eq!(seen.get("keccak"), Some(&KECCAK_GAS));
    let seen = classify(&execute(&guests::sha256_demo(), &[], &[], 10_000).unwrap());
    assert_eq!(seen.get("sha256"), Some(&SHA256_GAS));
}

#[test]
fn gas_of_is_the_prefix_rows_plus_the_row_weights_and_grows_with_the_inputs() {
    use randprotocol_zkvm::emulator::execute;
    use randprotocol_zkvm::guests;
    let p = guests::balance_check(1000);
    let inputs = [400u32, 250, 300, 75];
    let e = execute(&p, &inputs, &[], 10_000).unwrap();
    let rows: u64 = e.events.iter().map(row_gas).sum();
    let prefix = |n_in: usize, n_pub: usize| (p.digest_rows() + randprotocol_zkvm::hash::input_digest_row_count(n_in) + randprotocol_zkvm::hash::public_digest_row_count(n_pub)) as u64;
    assert_eq!(gas_of(&p, &inputs, &[], &e.events), prefix(4, 0) + rows);
    // The digest prefix is charged for what is *committed*, whether or not the guest reads it:
    // four more private words are one more indigest row, and four public words one pubdigest row
    // (the empty segment's header row is already paid).
    let more: Vec<u32> = inputs.iter().copied().chain([1, 2, 3, 4]).collect();
    assert_eq!(gas_of(&p, &more, &[], &e.events), prefix(4, 0) + rows + 1);
    assert_eq!(gas_of(&p, &inputs, &[1, 2, 3, 4], &e.events), prefix(4, 0) + rows);
    assert_eq!(gas_of(&p, &inputs, &[1, 2, 3, 4, 5], &e.events), prefix(4, 0) + rows + 1);
    // And every run under the header fits the ceiling.
    assert!(gas_of(&p, &inputs, &[], &e.events) <= gas_max(Tier::for_cycles(e.cycles() + prefix(4, 0) as usize).unwrap(), 0, 0));
}
