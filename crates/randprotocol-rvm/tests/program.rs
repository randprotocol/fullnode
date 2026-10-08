//! The preprocessed program table and the program-dependent verifier key (plan Task 2).
mod common;

use p3_air::BaseAir;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use randprotocol_rvm::emulator::Event;
use randprotocol_rvm::isa::{Instr, Op, Program, F};
use randprotocol_rvm::machine::{program_log_height, FriProfile, Machine, Tier};
use randprotocol_rvm::tables::program::{col, pre, program_trace, ProgramAir};
use std::sync::Arc;

fn instr(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}

fn toy() -> Program {
    Program {
        instrs: vec![
            instr(Op::Faddi, 1, 0, 7),
            instr(Op::Faddi, 2, 0, 5),
            instr(Op::Fadd, 3, 1, 2),
            instr(Op::Public, 0, 3, 0),
            instr(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    }
}

fn event(clk: u32, pc: u32) -> Event {
    Event {
        clk,
        pc,
        next_pc: pc + 1,
        instr: instr(Op::Faddi, 1, 0, 0),
        a: [F::ZERO; 2],
        b_val: [F::ZERO; 2],
        d: [F::ZERO; 2],
        mem: vec![],
        perm: None,
        reduce: None,
        fold: None,
        pow: None,
    }
}

#[test]
fn the_preprocessed_trace_encodes_the_programs_words_at_their_rows() {
    let p = toy();
    let air = ProgramAir { program: Arc::new(p.clone()), height: 8 };
    let trace = BaseAir::<F>::preprocessed_trace(&air).expect("the program table is preprocessed");
    assert_eq!(trace.height(), 8);
    assert_eq!(trace.width(), pre::WIDTH);
    for (i, want) in p.instrs.iter().enumerate() {
        let row: Vec<F> = (0..4).map(|k| trace.get(i, k).unwrap()).collect();
        let got = Instr::decode(<[F; 4]>::try_from(row.as_slice()).unwrap()).unwrap();
        assert_eq!(got, *want, "row {i} encodes instruction {i}");
    }
    for i in p.instrs.len()..8 {
        for k in 0..4 {
            assert_eq!(trace.get(i, k).unwrap(), F::ZERO, "padding row {i} is zero words");
        }
    }
}

#[test]
fn the_witness_fill_counts_fetches_and_zeroes_padding() {
    let p = toy();
    // pcs 0 (twice), 2, 3 — row 1 and row 4 (HALT is never reached in this fragment) unfetched.
    let events = vec![event(0, 0), event(1, 0), event(2, 2), event(3, 3)];
    let t = program_trace(&p, &events, 8);
    for i in 0..8 {
        assert_eq!(t.get(i, col::IDX).unwrap(), F::from_u32(i as u32), "IDX is the row index, padding included");
        let is_real = t.get(i, col::IS_REAL).unwrap();
        assert_eq!(is_real, if i < p.instrs.len() { F::ONE } else { F::ZERO }, "IS_REAL is a prefix");
        let mult = t.get(i, col::MULT).unwrap().as_canonical_u64();
        let want = [2u64, 0, 1, 1, 0, 0, 0, 0][i];
        assert_eq!(mult, want, "fetch count at row {i}");
    }
}

#[test]
fn the_verifier_key_binds_the_program() {
    let m = Machine::new(FriProfile::Test);
    let a = toy();
    let mut b = toy();
    b.instrs[2] = instr(Op::Fsub, 3, 1, 2);

    let ka = m.verifier_key(&a, Tier(8), 0);
    let kb = m.verifier_key(&b, Tier(8), 0);
    let roots = |k: &p3_batch_stark::CommonData<randprotocol_rvm::machine::Config>| {
        k.preprocessed.as_ref().expect("the batch has preprocessed columns").commitment.roots().to_vec()
    };
    assert_ne!(roots(&ka), roots(&kb), "one word differs, so the preprocessed cap differs");
    let ka2 = m.verifier_key(&a, Tier(8), 0);
    assert_eq!(roots(&ka), roots(&ka2), "the same program reproduces the same cap");
}

#[test]
fn program_log_height_pins_the_measured_sizes() {
    assert_eq!(program_log_height(5_692_650), 23, "the measured cs6 program, pre-cut");
    assert_eq!(program_log_height(1_950_000), 21, "the post-cut exit target");
    assert_eq!(program_log_height(5), 3);
    assert_eq!(program_log_height(0), 2, "an empty program still gets the floor");
}

/// Fix round 1 (Task 1a review): `check_layout` bounds every base and the length before it sums
/// them — a `u64::MAX` key or vals base would otherwise wrap `+ 1` to 0 and pass, and the chip's
/// preprocessed `L_KEY` (`F::from_u64(u64::MAX)`) would read cells the emulator never touches.
#[test]
fn a_layout_entry_whose_addresses_wrap_is_illegal_at_registration() {
    use randprotocol_rvm::isa::{DecodeError, ReduceEntry};
    let mut p = common::reduce_chain_program(false);
    p.reduce_layout[0] = ReduceEntry { key: u64::MAX, vals: u64::MAX, len: 1, row: 0, alpha: 0, res: 2, chain_start: true, carry: false };
    assert_eq!(randprotocol_rvm::machine::Machine::check_program(&p), Err(DecodeError::Layout { entry: 0 }));
    for (field, v) in [("vals", 0), ("row", 1), ("key", 2), ("alpha", 3), ("res", 4)] {
        let mut q = common::reduce_chain_program(false);
        let e = &mut q.reduce_layout[0];
        let slot = [&mut e.vals, &mut e.row, &mut e.key, &mut e.alpha, &mut e.res];
        *slot.into_iter().nth(v).unwrap() = randprotocol_rvm::isa::MEM_LIMIT;
        assert_eq!(randprotocol_rvm::machine::Machine::check_program(&q), Err(DecodeError::Layout { entry: 0 }), "{field} at 2^24");
    }
}

/// Task 5 sweep (Task 1a review): the legal side of the bound. Each address field of an entry put
/// so that its top cell is exactly `2^24 − 1` — `vals + 2·len − 1`, `row + len − 1`, `key + 1`,
/// `alpha + 1`, `res + 1` — is accepted at registration and by the emulator, which reads and
/// writes those cells; one cell further is refused by both, at the same entry. (The wrap test
/// above covers the bases at `2^24` and the `u64::MAX` sums.)
#[test]
fn a_layout_entry_whose_top_cell_is_the_last_one_is_legal_and_one_more_is_not() {
    use randprotocol_rvm::emulator::{execute, ExecError};
    use randprotocol_rvm::isa::{DecodeError, ReduceEntry, MEM_LIMIT};
    let top = MEM_LIMIT - 1;
    let at_top = |field: usize, past: u64| -> randprotocol_rvm::isa::Program {
        let mut q = common::reduce_chain_program(false);
        let e: &mut ReduceEntry = &mut q.reduce_layout[0];
        let len = e.len as u64;
        match field {
            0 => e.vals = top + 1 - 2 * len + past,
            1 => e.row = top + 1 - len + past,
            2 => e.key = top - 1 + past,
            3 => e.alpha = top - 1 + past,
            _ => e.res = top - 1 + past,
        }
        q
    };
    for (field, name) in ["vals", "row", "key", "alpha", "res"].iter().enumerate() {
        let legal = at_top(field, 0);
        assert!(randprotocol_rvm::isa::layout_entry_in_bounds(&legal.reduce_layout[0]), "{name}: top cell 2^24 − 1 is in bounds");
        assert_eq!(randprotocol_rvm::machine::Machine::check_program(&legal), Ok(()), "{name}: top cell 2^24 − 1 registers");
        assert!(execute(&legal, &[], 10_000).is_ok(), "{name}: top cell 2^24 − 1 runs");
        let past = at_top(field, 1);
        assert_eq!(randprotocol_rvm::machine::Machine::check_program(&past), Err(DecodeError::Layout { entry: 0 }), "{name}: top cell 2^24");
        assert!(
            matches!(execute(&past, &[], 10_000), Err(ExecError::ReduceLayout { entry: 0, .. })),
            "{name}: the emulator refuses top cell 2^24 at the same entry"
        );
    }
}
