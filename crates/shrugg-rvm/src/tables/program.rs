//! The program table (plan R1): a **preprocessed** trace of the encoded program, committed by
//! the verifier key's preprocessed cap, plus a small witness trace for the fetch bookkeeping.
//!
//! There is no in-circuit `hc` digest: the rVM's program is a public, registered artifact
//! (spec §2 — the fullnode registers its digest), so the RV32 machine's M3.4 reason for moving
//! the program into the witness (program hiding) does not exist here — and at the measured
//! 5 692 650 instructions its one-permutation-per-instruction digest would be a 2^23-row hash
//! table no machine in the fleet can prove. Spec §5's own phrase — the digest "exposed in the
//! verifier key" — is exactly what a preprocessed table means: the key's cap binds every word,
//! and word legality is a registration-time host check (`Machine::check_program`), not an
//! in-circuit decoder.
use super::{bus, pad_height, F};
use crate::emulator::Event;
use crate::isa::Program;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

pub mod col {
    pub const IDX: usize = 0;
    pub const IS_REAL: usize = 1;
    pub const MULT: usize = 2;
    pub const WIDTH: usize = 3;
}
pub mod pre {
    pub const W0: usize = 0; // 4: the encoded instruction's four words
    pub const WIDTH: usize = 4;
}
use col::*;

/// The program table's height floor — `machine::PROGRAM_MIN_HEIGHT`, re-exported here so the
/// table's own module reads like its siblings.
pub const MIN_HEIGHT: usize = crate::machine::PROGRAM_MIN_HEIGHT;

/// One row per instruction plus one padding row, floored — `machine::program_log_height`'s rule,
/// re-exported so the canonical definition stays single.
pub use crate::machine::program_log_height;

/// The air carries the registered program: the preprocessed trace is built from it, which is
/// what makes the verifier key program-dependent (R6).
#[derive(Clone, Debug)]
pub struct ProgramAir {
    pub program: Arc<Program>,
    pub height: usize,
}

impl ProgramAir {
    pub fn new(program: Arc<Program>) -> Self {
        let height = pad_height(program.instrs.len() + 1, MIN_HEIGHT);
        ProgramAir { program, height }
    }
}

impl<Fld: Field> BaseAir<Fld> for ProgramAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let mut v = Fld::zero_vec(self.height * pre::WIDTH);
        for (i, instr) in self.program.instrs.iter().enumerate() {
            let w = instr.encode();
            for k in 0..4 {
                v[i * pre::WIDTH + pre::W0 + k] = Fld::from_u64(p3_field::PrimeField64::as_canonical_u64(&w[k]));
            }
        }
        Some(RowMajorMatrix::new(v, pre::WIDTH))
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ProgramAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let w = |i: usize| -> AB::Expr { p.current(pre::W0 + i).unwrap().into() };
        let one = AB::Expr::ONE;

        b.assert_bool(v(IS_REAL));
        // Real rows form a prefix — the `tables/public.rs` pattern.
        b.when_transition().assert_zero((one.clone() - v(IS_REAL)) * n(IS_REAL));
        // IDX is the row index (the pc), padding included — harmless there, nothing reads it.
        b.when_first_row().assert_zero(v(IDX));
        b.when_transition().assert_zero(n(IDX) - v(IDX) - one.clone());
        // AGENTS.md invariant 2: no fetch count where there is no instruction to fetch.
        b.assert_zero((one.clone() - v(IS_REAL)) * v(MULT));
        // Provide the instruction at this row's pc with its fetch count.
        let msg: Vec<AB::Expr> = std::iter::once(v(IDX)).chain((0..4).map(w)).collect();
        bus::PROGRAM.table_entry(b, msg, v(MULT));
    }
}

/// The witness trace: `IDX` = row index, `IS_REAL` on instruction rows, `MULT` = the number of
/// times the execution fetched that pc. The rVM's first program is straight-line (every count is
/// 0 or 1), but the builder counts generally — a later program with loops fetches a row many
/// times, which is exactly what `MULT` exists to carry.
pub fn program_trace(program: &Program, events: &[Event], height: usize) -> RowMajorMatrix<F> {
    assert!(
        program.instrs.len() <= height,
        "program table needs {} rows, height {height}",
        program.instrs.len()
    );
    let mut counts: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    for e in events {
        *counts.entry(e.pc).or_default() += 1;
    }
    let mut v = F::zero_vec(height * col::WIDTH);
    for i in 0..height {
        let r = &mut v[i * col::WIDTH..(i + 1) * col::WIDTH];
        r[IDX] = F::from_u32(i as u32);
        if i < program.instrs.len() {
            r[IS_REAL] = F::ONE;
            r[MULT] = F::from_u64(*counts.get(&(i as u32)).unwrap_or(&0));
        }
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
