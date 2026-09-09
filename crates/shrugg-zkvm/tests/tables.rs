use shrugg_zkvm::machine::{make_config, FriProfile};
use shrugg_zkvm::tables::byte::{byte_trace, ByteAir, ByteCounts};
use shrugg_zkvm::tables::bus;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField64;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use shrugg_zkvm::tables::F;
use shrugg_zkvm::isa::Instr;
use shrugg_zkvm::tables::program::{self, program_trace, ProgramAir};
use shrugg_zkvm::emulator::execute;
use shrugg_zkvm::guests;
use shrugg_zkvm::tables::memory::{self, memory_trace};
use shrugg_zkvm::tables::alu::{self, fill_row};
use shrugg_zkvm::emulator::AluEvent;
use shrugg_zkvm::isa::AluOp;

/// A throwaway table that asks the byte table questions. main: [x, y, z, is_real]
#[derive(Clone)]
struct Asker;
impl<Fld> BaseAir<Fld> for Asker { fn width(&self) -> usize { 4 } }
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Asker where AB::F: p3_field::Field {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let (x, y, z, r) = (m.current(0).unwrap(), m.current(1).unwrap(), m.current(2).unwrap(), m.current(3).unwrap());
        b.assert_bool(r);
        bus::RANGE8.lookup_key(b, [x.into()], Count::bounded(r.into(), 1));
        bus::AND8.lookup_key(b, [x.into(), y.into(), z.into()], Count::bounded(r.into(), 1));
    }
}

#[test]
fn byte_table_answers_range_and_and_lookups() {
    let config = make_config(FriProfile::Test);
    let mut counts = ByteCounts::default();
    let rows: Vec<(u32, u32)> = vec![(0xf0, 0x3c), (7, 7), (255, 0), (1, 2)];
    let mut asker = vec![F::ZERO; 16 * 4];
    for (i, (x, y)) in rows.iter().enumerate() {
        counts.range8(*x);
        counts.and8(*x, *y);
        asker[4 * i] = F::from_u32(*x);
        asker[4 * i + 1] = F::from_u32(*y);
        asker[4 * i + 2] = F::from_u32(x & y);
        asker[4 * i + 3] = F::ONE;
    }
    let asker_trace = RowMajorMatrix::new(asker, 4);
    let byte = byte_trace(&counts);
    // prove with a two-AIR enum local to the test
    #[derive(Clone)]
    enum T { Byte(ByteAir), Ask(Asker) }
    impl<Fld: p3_field::Field> BaseAir<Fld> for T {
        fn width(&self) -> usize { match self { T::Byte(a) => <ByteAir as BaseAir<Fld>>::width(a), T::Ask(a) => <Asker as BaseAir<Fld>>::width(a) } }
        fn preprocessed_width(&self) -> usize { match self { T::Byte(a) => <ByteAir as BaseAir<Fld>>::preprocessed_width(a), _ => 0 } }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> { match self { T::Byte(a) => <ByteAir as BaseAir<Fld>>::preprocessed_trace(a), _ => None } }
    }
    impl<AB: AirBuilder + p3_air::PermutationAirBuilder + InteractionBuilder> Air<AB> for T where AB::F: p3_field::Field {
        fn eval(&self, b: &mut AB) { match self { T::Byte(a) => a.eval(b), T::Ask(a) => a.eval(b) } }
    }
    let airs = vec![T::Byte(ByteAir), T::Ask(Asker)];
    let instances = vec![
        StarkInstance { air: &airs[0], trace: &byte, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &asker_trace, public_values: vec![] },
    ];
    let pd = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &pd);
    verify_batch(&config, &airs, &proof, &[vec![], vec![]], &pd.common).unwrap();
}

#[test]
fn program_table_rows_are_decoded_instructions_and_fetch_counts() {
    let p = guests::fib(5);
    let air = ProgramAir { program: p.clone() };
    let pre: RowMajorMatrix<F> = <ProgramAir as BaseAir<F>>::preprocessed_trace(&air).unwrap();
    assert_eq!(pre.height(), air.height());
    assert_eq!(pre.height(), 16);
    // row 2 is the third instruction
    let d = Instr::decode(p.words[2]).unwrap().decoded().to_fields();
    let row: Vec<F> = pre.values[2 * program::pre::WIDTH..3 * program::pre::WIDTH].to_vec();
    assert_eq!(row[program::pre::PC], F::from_u32(8));
    for (i, f) in d.iter().enumerate() { assert_eq!(row[program::pre::FIELDS + i], F::from_u32(*f), "field {i}"); }
    assert_eq!(row[program::pre::VALID], F::ONE);
    let last = pre.height() - 1;
    assert_eq!(pre.values[last * program::pre::WIDTH + program::pre::VALID], F::ZERO);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = program_trace(&p, &e.events);
    let total: u64 = t.values.iter().map(|x| x.as_canonical_u64()).sum();
    assert_eq!(total as usize, e.events.len(), "every cycle fetched exactly one row");
}

#[test]
fn memory_trace_is_sorted_and_consistent() {
    let p = guests::memcpy(4);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut counts = ByteCounts::default();
    let t = memory_trace(&e.events, 1 << 12, &mut counts);
    let w = memory::col::WIDTH;
    let accesses: usize = e.events.iter().map(|c| c.accesses.len()).sum();
    let real: usize = (0..t.height()).filter(|r| t.values[r * w + memory::col::IS_REAL] == F::ONE).count();
    assert_eq!(real, accesses);
    let key = |r: usize| t.values[r * w + memory::col::SPACE].as_canonical_u64() << 30 | t.values[r * w + memory::col::ADDR].as_canonical_u64();
    let ts = |r: usize| t.values[r * w + memory::col::TS].as_canonical_u64();
    for r in 0..real - 1 {
        assert!((key(r), ts(r)) < (key(r + 1), ts(r + 1)), "row {r} not sorted");
        if key(r) == key(r + 1) && t.values[(r + 1) * w + memory::col::IS_WRITE] == F::ZERO {
            assert_eq!(t.values[r * w + memory::col::VALUE], t.values[(r + 1) * w + memory::col::VALUE], "read at row {} must see previous value", r + 1);
        }
    }
    // Δ limbs were counted: 4 range checks per real transition
    let total: u64 = counts.range.iter().sum();
    assert_eq!(total as usize, 4 * (real - 1));
}

#[test]
fn alu_rows_recompose_and_carry() {
    let mut counts = ByteCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Add, a: 0xffff_ffff, b: 1, c: 0 }, &mut counts);
    assert_eq!(row[alu::col::FLAG0 + AluOp::Add.code() as usize], F::ONE);
    assert_eq!(row[alu::col::C], F::ZERO);
    for i in 0..4 { assert_eq!(row[alu::col::CARRY0 + i], F::ONE, "carry {i}"); }
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Sra, a: 0x8000_0000, b: 4, c: 0xf800_0000 }, &mut counts);
    assert_eq!(row[alu::col::SA], F::ONE);
    assert_eq!(row[alu::col::SH], F::from_u32(4));
    assert_eq!(row[alu::col::PW], F::from_u32(16));
    // q = (~a) >> 4 = 0x07ff_ffff ; c = ~q
    assert_eq!(row[alu::col::Q0], F::from_u32(0xff));
    assert_eq!(row[alu::col::C0 + 3], F::from_u32(0xf8));
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Slt, a: 0xffff_ffff, b: 0, c: 1 }, &mut counts);
    assert_eq!((row[alu::col::SA], row[alu::col::SB], row[alu::col::CARRY0 + 3]), (F::ONE, F::ZERO, F::ZERO));
}

#[test]
#[should_panic(expected = "does not match")]
fn alu_fill_rejects_wrong_result() {
    let mut counts = ByteCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Add, a: 1, b: 1, c: 3 }, &mut counts);
}

use shrugg_zkvm::tables::cpu::{self, cpu_trace, public_values};

#[test]
fn cpu_trace_mirrors_events_and_pads() {
    let p = guests::fib(3);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = cpu_trace(&e.events, 64);
    let w = cpu::col::WIDTH;
    assert_eq!(t.height(), 64);
    for (i, ev) in e.events.iter().enumerate() {
        let r = &t.values[i * w..(i + 1) * w];
        assert_eq!(r[cpu::col::CLK], F::from_u32(ev.clk));
        assert_eq!(r[cpu::col::PC], F::from_u32(ev.pc));
        assert_eq!(r[cpu::col::NEXT_PC], F::from_u32(ev.next_pc));
        assert_eq!(r[cpu::col::IS_REAL], F::ONE);
        let d = ev.dec.to_fields();
        for k in 0..18 { assert_eq!(r[cpu::col::DEC0 + k], F::from_u32(d[k])); }
        assert_eq!((r[cpu::col::A], r[cpu::col::B], r[cpu::col::C]), (F::from_u32(ev.a), F::from_u32(ev.b), F::from_u32(ev.c)));
    }
    let last_real = e.events.len() - 1;
    assert_eq!(t.values[last_real * w + cpu::col::SYS_HALT], F::ONE);
    let write_row = e.events.iter().position(|ev| matches!(ev.sys, Some(shrugg_zkvm::emulator::Syscall::WriteOutput { .. }))).unwrap();
    assert_eq!(t.values[write_row * w + cpu::col::OUT_SEL0], F::ONE);
    let pad = &t.values[(last_real + 1) * w..(last_real + 2) * w];
    assert!(pad.iter().all(|x| *x == F::ZERO));
    let pv = public_values(0, 10, &e.outputs);
    assert_eq!(pv.len(), cpu::pv::NUM);
    assert_eq!(pv[cpu::pv::OUT0], F::from_u32(2));
}
