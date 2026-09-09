//! Preprocessed, pre-decoded program ROM. Its commitment is the code hash hc.
use super::{bus, pad_height, F};
use crate::emulator::CycleEvent;
use crate::isa::{Decoded, Instr, Program};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use std::collections::HashMap;

pub mod pre {
    pub const PC: usize = 0;
    pub const FIELDS: usize = 1;
    pub const VALID: usize = 1 + crate::isa::Decoded::NUM_FIELDS; // 19
    pub const WIDTH: usize = VALID + 1;                            // 20
}
pub mod col { pub const MULT: usize = 0; pub const WIDTH: usize = 1; }
pub const MIN_HEIGHT: usize = 16;
pub const MESSAGE_LEN: usize = 1 + Decoded::NUM_FIELDS;

#[derive(Clone, Debug)]
pub struct ProgramAir { pub program: Program }

impl ProgramAir {
    pub fn height(&self) -> usize { pad_height(self.program.len() + 1, MIN_HEIGHT) }
}

impl<Fld: Field> BaseAir<Fld> for ProgramAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let h = self.height();
        let mut v = Fld::zero_vec(h * pre::WIDTH);
        for (i, w) in self.program.words.iter().enumerate() {
            let d = Instr::decode(*w).expect("program contains an undecodable word").decoded().to_fields();
            let r = i * pre::WIDTH;
            v[r + pre::PC] = Fld::from_u32(self.program.pc_of(i));
            for (j, f) in d.iter().enumerate() { v[r + pre::FIELDS + j] = Fld::from_u32(*f); }
            v[r + pre::VALID] = Fld::ONE;
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
        let mult = b.main().current(col::MULT).unwrap();
        let valid = p.current(pre::VALID).unwrap();
        // Padding rows can never be fetched.
        b.assert_zero(mult.into() * (AB::Expr::ONE - valid.into()));
        let msg: Vec<AB::Expr> = (0..MESSAGE_LEN).map(|i| p.current(i).unwrap().into()).collect();
        bus::PROGRAM.table_entry(b, msg, mult.into());
    }
}

/// Main column: how many times each instruction was fetched.
pub fn program_trace(program: &Program, events: &[CycleEvent]) -> RowMajorMatrix<F> {
    let air = ProgramAir { program: program.clone() };
    let h = air.height();
    let mut counts: HashMap<u32, u64> = HashMap::new();
    for e in events { *counts.entry(e.pc).or_default() += 1; }
    let mut v = F::zero_vec(h * col::WIDTH);
    for i in 0..program.len() {
        v[i * col::WIDTH + col::MULT] = F::from_u64(*counts.get(&program.pc_of(i)).unwrap_or(&0));
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
