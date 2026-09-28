//! ISA-1 residual (randprotocol/fullnode#53): the pc window on the prover and in `Machine::verify`.
//!
//! The circuit does its PC arithmetic in the field — the program table's PC chain, the cpu's
//! fall-through `PC + 4`, the JAL/JALR link — while the emulator wraps mod 2^32, so a program whose
//! *padded* program table (`2^program_log_height` rows, floored at `2^7` since constraint set 7)
//! crosses 2^32 has rows whose field PCs no execution produces, and no honest proof of it verifies.
//! The node refuses such a deploy (`pc_window_fits` in fullnode's core, the floored table since
//! PCW-FLOOR); these tests pin the zkVM's own two halves: the prover refuses to prove it, and the
//! verifier refuses a proof whose claimed entry pc puts its declared table past the wrap, before any
//! key is built.
use randprotocol_zkvm::guests;
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::{FriProfile, Machine, ProveError, Tier, VerifyError};
use randprotocol_zkvm::tables::{cpu::pv, program};

/// `guests::fib(10)` (a handful of words, relative branches only) moved to `base_pc`.
fn fib_at(base_pc: u32) -> Program {
    let p = guests::fib(10);
    assert!(p.len() < 1 << program::MIN_LOG_HEIGHT, "fib(10) pads to the floored 128-row table");
    Program::new(base_pc, p.words)
}

/// The highest `base_pc` whose floored 128-row table still ends at or below 2^32.
const LAST_FIT: u32 = (1u64 << 32).wrapping_sub(4 << program::MIN_LOG_HEIGHT) as u32;

#[test]
fn the_window_predicate_measures_the_floored_padded_table() {
    assert_eq!(LAST_FIT, 0xffff_fe00);
    assert!(program::pc_window_fits(0, program::program_log_height(15)));
    assert!(program::pc_window_fits(0xffff_fe00, program::program_log_height(15)), "128 rows end exactly at 2^32");
    assert!(!program::pc_window_fits(0xffff_fe04, program::program_log_height(15)), "one word higher crosses");
    assert!(!program::pc_window_fits(0xffff_ffc0, program::program_log_height(15)), "the rescan's case: 15 words fit, 128 rows do not");
    assert!(!program::pc_window_fits(0xffff_fe00, program::program_log_height(128)), "128 words pad to 256 rows");
    assert!(program::pc_window_fits(0xffff_fc00, program::program_log_height(128)));
    assert!(!program::pc_window_fits((u32::MAX & !3) as u64, program::MAX_LOG_HEIGHT));
    assert!(!program::pc_window_fits(1 << 32, program::MIN_LOG_HEIGHT), "an entry pc past u32 never fits");
}

#[test]
fn the_prover_refuses_a_program_whose_padded_table_crosses_the_pc_wrap() {
    let m = Machine::new(FriProfile::Test);
    let p = fib_at(LAST_FIT + 4);
    match m.prove_salted(&p, &[], &[], [0; 4], Some(Tier(10))) {
        Err(ProveError::PcWindow { base_pc, log_height }) => {
            assert_eq!((base_pc, log_height), (LAST_FIT + 4, program::MIN_LOG_HEIGHT));
        }
        Err(e) => panic!("expected PcWindow, got {e:?}"),
        Ok((proof, _)) => panic!(
            "the prover proved a program whose padded table crosses 2^32 (base_pc {:#x}, {} rows); \
             Machine::verify says {:?}",
            p.base_pc,
            1u64 << proof.program_log_height,
            m.verify(&p.digest(), &proof).err()
        ),
    }
}

#[test]
fn a_program_whose_padded_table_ends_exactly_at_the_wrap_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    let p = fib_at(LAST_FIT);
    let (proof, exec) = m.prove_salted(&p, &[], &[], [0; 4], Some(Tier(10))).expect("the last base_pc that fits proves");
    assert_eq!(exec.outputs[0], 55, "fib(10)");
    m.verify(&p.digest(), &proof).expect("and verifies");
}

#[test]
fn the_verifier_refuses_a_claimed_entry_pc_past_the_window_before_building_a_key() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove_salted(&p, &[], &[], [0; 4], Some(Tier(10))).unwrap();
    m.verify(&p.digest(), &proof).expect("the honest proof verifies");
    // A fresh verifier, so its key cache shows whether a refusal came before a key was built.
    let v = Machine::new(FriProfile::Test);
    for (entry, crosses) in [(LAST_FIT as u64 + 4, true), (u32::MAX as u64 & !3, true), ((1u64 << 32) + 4, true), (LAST_FIT as u64, false)] {
        let mut bad: randprotocol_zkvm::machine::Proof = postcard::from_bytes(&proof.to_bytes()).unwrap();
        bad.public_values[pv::PC_ENTRY] = entry;
        let got = v.verify(&p.digest(), &bad);
        if crosses {
            assert_eq!(v.cached_keys(), 0, "entry pc {entry:#x}: refused before any key is built");
        }
        assert!(got.is_err(), "a rewritten entry pc never verifies");
        assert_eq!(
            matches!(got, Err(VerifyError::PcWindow { .. })),
            crosses,
            "entry pc {entry:#x}: PcWindow expected = {crosses}, got {got:?}"
        );
    }
}
