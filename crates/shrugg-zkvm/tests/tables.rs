use shrugg_zkvm::machine::{make_config, FriProfile};
use shrugg_zkvm::tables::range::{self, range_trace, RangeAir, RangeCounts};
use shrugg_zkvm::tables::nibble::{self, nibble_trace, NibbleCounts};
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
use shrugg_zkvm::tables::program::{self, fill_word_row, program_trace, ProgramAir};
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::StdRng;
use rand::SeedableRng;
use shrugg_zkvm::emulator::execute;
use shrugg_zkvm::guests;
use shrugg_zkvm::tables::memory::{self, memory_trace};
use shrugg_zkvm::tables::alu::{self, fill_row};
use shrugg_zkvm::emulator::AluEvent;
use shrugg_zkvm::isa::AluOp;

/// A throwaway table that asks both of the range table's questions. main: [x, r_range, s,
/// pw, r_pow2]. Two separate weighted lookups per row (rather than one column each for
/// RANGE8 and POW2) so a row can exercise either, both, or neither independently — the
/// fourth row here exercises RANGE8 only, since there are 4 range checks but only 3 pow2
/// checks to answer.
#[derive(Clone)]
struct RangeAsker;
impl<Fld> BaseAir<Fld> for RangeAsker { fn width(&self) -> usize { 5 } }
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for RangeAsker where AB::F: p3_field::Field {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let (x, rr, s, pw, rp) = (
            m.current(0).unwrap(), m.current(1).unwrap(), m.current(2).unwrap(), m.current(3).unwrap(), m.current(4).unwrap(),
        );
        b.assert_bool(rr);
        b.assert_bool(rp);
        bus::RANGE8.lookup_key(b, [x.into()], Count::bounded(rr.into(), 1));
        bus::POW2.lookup_key(b, [s.into(), pw.into()], Count::bounded(rp.into(), 1));
    }
}

#[test]
fn range_table_answers_range8_and_pow2_lookups() {
    let config = make_config(FriProfile::Test);
    let mut counts = RangeCounts::default();
    let xs = [0u32, 7, 255, 31];
    let pow2s = [(0u32, 1u32), (5, 32), (31, 1u32 << 31)];
    for x in xs { counts.range8(x); }
    for (s, _) in pow2s { counts.pow2(s); }
    let mut asker = vec![F::ZERO; 16 * 5];
    for (i, x) in xs.iter().enumerate() {
        asker[5 * i] = F::from_u32(*x);
        asker[5 * i + 1] = F::ONE;
        if let Some((s, pw)) = pow2s.get(i) {
            asker[5 * i + 2] = F::from_u32(*s);
            asker[5 * i + 3] = F::from_u32(*pw);
            asker[5 * i + 4] = F::ONE;
        }
    }
    let asker_trace = RowMajorMatrix::new(asker, 5);
    let range = range_trace(&counts);
    #[derive(Clone)]
    enum T { Range(RangeAir), Ask(RangeAsker) }
    impl<Fld: p3_field::Field> BaseAir<Fld> for T {
        fn width(&self) -> usize { match self { T::Range(a) => <RangeAir as BaseAir<Fld>>::width(a), T::Ask(a) => <RangeAsker as BaseAir<Fld>>::width(a) } }
        fn preprocessed_width(&self) -> usize { match self { T::Range(a) => <RangeAir as BaseAir<Fld>>::preprocessed_width(a), _ => 0 } }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> { match self { T::Range(a) => <RangeAir as BaseAir<Fld>>::preprocessed_trace(a), _ => None } }
    }
    impl<AB: AirBuilder + p3_air::PermutationAirBuilder + InteractionBuilder> Air<AB> for T where AB::F: p3_field::Field {
        fn eval(&self, b: &mut AB) { match self { T::Range(a) => a.eval(b), T::Ask(a) => a.eval(b) } }
    }
    let airs = vec![T::Range(RangeAir), T::Ask(RangeAsker)];
    let instances = vec![
        StarkInstance { air: &airs[0], trace: &range, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &asker_trace, public_values: vec![] },
    ];
    let pd = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &pd);
    verify_batch(&config, &airs, &proof, &[vec![], vec![]], &pd.common).unwrap();
}

#[test]
fn bumping_a_range_pow2_multiplicity_on_a_non_pow2_row_is_rejected_directly() {
    // row_of(200,0) has a=200 ≥ 32, so is_pow2 is 0 there
    let counts = RangeCounts::default();
    let t = range_trace(&counts);
    assert_eq!(t.values[200 * range::col::WIDTH + range::col::M_POW2], F::ZERO);
}

#[test]
fn nibble_table_answers_and4_or4_xor4_lookups() {
    let mut counts = NibbleCounts::default();
    counts.and4(0xf, 0x3); counts.or4(0x5, 0xa); counts.xor4(0x1, 0x1);
    let t = nibble_trace(&counts);
    assert_eq!(t.values[nibble::row_of(0xf,0x3) * nibble::col::WIDTH + nibble::col::M_AND], F::ONE);
    assert_eq!(t.values[nibble::row_of(0x5,0xa) * nibble::col::WIDTH + nibble::col::M_OR], F::ONE);
    assert_eq!(t.values[nibble::row_of(0x1,0x1) * nibble::col::WIDTH + nibble::col::M_XOR], F::ONE);
}

#[test]
fn program_table_rows_are_decoded_instructions_and_fetch_counts() {
    let p = guests::fib(5);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = program_trace(&p, &e.events, 16);
    assert_eq!(t.height(), 16);
    let w = program::col::WIDTH;
    // row 2 is the third instruction
    let d = Instr::decode(p.words[2]).unwrap().decoded().to_fields();
    let row: Vec<F> = t.values[2 * w..3 * w].to_vec();
    assert_eq!(row[program::col::PC], F::from_u32(8));
    assert_eq!(row[program::col::WORD], F::from_u32(p.words[2]));
    for (i, f) in d.iter().enumerate() { assert_eq!(row[program::col::RD + i], F::from_u32(*f), "field {i}"); }
    assert_eq!(row[program::col::VALID], F::ONE);
    assert_eq!(row[program::col::MULT_WORD], F::ONE);
    let last = t.height() - 1;
    assert_eq!(t.values[last * w + program::col::VALID], F::ZERO, "padding row must be invalid");
    assert_eq!(t.values[last * w + program::col::MULT], F::ZERO);
    let total: u64 = (0..t.height()).map(|r| t.values[r * w + program::col::MULT].as_canonical_u64()).sum();
    assert_eq!(total as usize, e.events.len(), "every cycle fetched exactly one row");
}

/// CRITICAL 1 regression (M3.4 fix, positive check): the honest trace builder must actually
/// exercise the new `MULT_WORD == VALID` invariant on every row — not just the rows a
/// hand-picked example touches — across every guest this crate ships
/// (`an_undigested_reachable_program_tail_is_rejected` in `tests/cheating.rs` is the negative,
/// tampered-witness counterpart).
#[test]
fn every_guest_program_trace_has_mult_word_equal_to_valid() {
    for (name, program, inputs) in guests::all() {
        let e = execute(&program, &inputs, 1 << 20).unwrap_or_else(|err| panic!("{name}: {err:?}"));
        let height = 1usize << program::program_log_height(program.len());
        let t = program_trace(&program, &e.events, height);
        let w = program::col::WIDTH;
        for r in 0..t.height() {
            let row = &t.values[r * w..(r + 1) * w];
            assert_eq!(row[program::col::MULT_WORD], row[program::col::VALID], "{name}: row {r}: MULT_WORD != VALID");
        }
    }
}

/// Every legal encoding `asm::ops` can produce, each over random register/immediate operands —
/// one instance per mnemonic, covering every `Instr` variant, every `AluOp` (RV32I and the
/// M2.6 M-extension), every load/store width, and every branch condition.
fn rand_u32(rng: &mut StdRng) -> u32 { StandardUniform.sample(rng) }

fn every_legal_encoding(rng: &mut StdRng) -> Vec<u32> {
    use shrugg_zkvm::asm::ops::*;
    use shrugg_zkvm::isa::BranchCond;
    let r = |rng: &mut StdRng| -> u32 { rand_u32(rng) % 32 };
    // Audit ZM3 (2026-09-12): in-range immediates only — `Instr::encode` now *asserts* the
    // field widths instead of silently truncating, and this helper used to rely on the
    // truncation (an unwitting live demonstration of the bug).
    let imm = |rng: &mut StdRng| -> i32 { (rand_u32(rng) % 4096) as i32 - 2048 }; // 12-bit signed
    let bimm = |rng: &mut StdRng| -> i32 { ((rand_u32(rng) % 8192) as i32 - 4096) & !1 }; // 13-bit signed, even
    let jimm = |rng: &mut StdRng| -> i32 { ((rand_u32(rng) % (1 << 21)) as i32 - (1 << 20)) & !1 }; // 21-bit signed, even
    let shamt = |rng: &mut StdRng| -> u32 { rand_u32(rng) % 32 };
    let mut out = Vec::new();
    let (rd, rs1, rs2) = (r(rng), r(rng), r(rng));
    for f in [addi, andi, ori, xori, slti, sltiu] as [fn(u32, u32, i32) -> Instr; 6] { out.push(f(rd, rs1, imm(rng)).encode()); }
    for f in [slli, srli, srai] as [fn(u32, u32, u32) -> Instr; 3] { out.push(f(rd, rs1, shamt(rng)).encode()); }
    for f in [add, sub, and, or, xor, sll, srl, sra, slt, sltu, mul, mulh, mulhu, mulhsu, div, divu, rem, remu]
        as [fn(u32, u32, u32) -> Instr; 18]
    {
        out.push(f(rd, rs1, rs2).encode());
    }
    for f in [lb, lbu, lh, lhu, lw] as [fn(u32, u32, i32) -> Instr; 5] { out.push(f(rd, rs1, imm(rng)).encode()); }
    for f in [sb, sh, sw] as [fn(u32, u32, i32) -> Instr; 3] { out.push(f(rs1, rs2, imm(rng)).encode()); }
    out.push(lui(rd, rand_u32(rng)).encode());
    out.push(auipc(rd, rand_u32(rng)).encode());
    out.push(jalr(rd, rs1, imm(rng)).encode());
    out.push(ecall().encode());
    for cond in [BranchCond::Eq, BranchCond::Ne, BranchCond::Lt, BranchCond::Ge, BranchCond::Ltu, BranchCond::Geu] {
        out.push((Instr::Branch { cond, rs1, rs2, imm: bimm(rng) as u32 }).encode());
    }
    out.push((Instr::Jal { rd, imm: jimm(rng) as u32 }).encode());
    out
}

/// A trivial `PROGRAM_WORD` consumer: requests exactly the message a program-table row at the
/// same index provides, at count `VALID` (main columns `[pc, word, valid]`). Used only by
/// `program_decoder_equals_instr_decode` below, so that test's lone `ProgramAir` instance can
/// give the M3.4 fix's `MULT_WORD = VALID` a matching consumer — required for `PROGRAM_WORD`
/// to balance now that a `VALID = 1` row's `MULT_WORD` can no longer sit at 0 — without pulling
/// in the whole `cpu` table. Fed the program trace's own `PC`/`WORD`/`VALID` columns verbatim,
/// so every message it asks for is one the program table actually provides, at the same count,
/// by construction rather than by coincidence.
#[derive(Clone)]
struct WordEcho;
impl<Fld> BaseAir<Fld> for WordEcho { fn width(&self) -> usize { 3 } }
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for WordEcho
where
    AB::F: p3_field::Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let (pc, word, valid) = (m.current(0).unwrap(), m.current(1).unwrap(), m.current(2).unwrap());
        b.assert_bool(valid.into());
        bus::PROGRAM_WORD.lookup_key(b, [pc.into(), word.into()], Count::bounded(valid.into(), 1));
    }
}

/// M3.4 review fix: the in-circuit decoder against `Instr::decode` directly, over 10⁴ random
/// 32-bit words plus every legal encoding `asm::ops` can produce. For each word: `fill_word_row`
/// (the same row-filling logic `program_trace` uses for every real program row) must produce
/// `VALID`/the 23 `Decoded` fields matching `Instr::decode(word)` exactly (`VALID = 1` and
/// `Decoded::to_fields()` on success, `VALID = 0` — fields unconstrained by this test, since
/// `Decoded` has no meaning for a word that doesn't decode — on error); and, built into one
/// trace and run through a real `prove_batch`/`verify_batch` round trip, every row's own AIR
/// constraints must hold. `MULT` stays 0 throughout, so `PROGRAM` trivially balances with no
/// consumer table (that bus is untouched by the M3.4 fix this test now also exercises); `MULT_WORD`
/// is set to `VALID` on every row (the fix: `mult_word = valid`, not merely zeroed on invalid
/// rows — `an_undigested_reachable_program_tail_is_rejected` in `tests/cheating.rs` is the
/// negative counterpart), which needs `WordEcho` (above) in the same batch as its matching
/// consumer so `PROGRAM_WORD` balances too — this test is about the decoder's own row
/// constraints (now including the fixed multiplicity gate), not the buses beyond what's needed
/// to let `MULT_WORD = VALID` appear in a standalone batch at all.
#[test]
fn program_decoder_equals_instr_decode() {
    let mut rng = StdRng::seed_from_u64(0x5EC0DE);
    let mut words: Vec<u32> = (0..10_000).map(|_| rand_u32(&mut rng)).collect();
    words.extend(every_legal_encoding(&mut rng));

    let w = program::col::WIDTH;
    let height = shrugg_zkvm::tables::pad_height(words.len(), 16);
    let mut v = F::zero_vec(height * w);
    for (i, &word) in words.iter().enumerate() {
        let pc = 4 * i as u32;
        fill_word_row(&mut v[i * w..(i + 1) * w], pc, word);
        let row = &v[i * w..(i + 1) * w];
        match Instr::decode(word) {
            Ok(instr) => {
                assert_eq!(row[program::col::VALID], F::ONE, "word {word:#010x} should decode");
                for (k, f) in instr.decoded().to_fields().iter().enumerate() {
                    assert_eq!(row[program::col::RD + k], F::from_u32(*f), "word {word:#010x} field {k}");
                }
            }
            Err(_) => assert_eq!(row[program::col::VALID], F::ZERO, "word {word:#010x} should not decode"),
        }
        // M3.4 fix: MULT_WORD must equal VALID exactly, not just be zeroed on invalid rows.
        v[i * w + program::col::MULT_WORD] = row[program::col::VALID];
    }
    // Padding rows past the sampled words: `PC` still increments by 4 (the AIR's transition
    // rule is unconditional), and `RD_IS_ZERO` must still satisfy the is-zero gadget for
    // `RD = 0` (unconditional too, not gated by `VALID` — see `program_trace`'s own padding
    // handling, which this mirrors). `VALID = 0` there already, so `MULT_WORD` stays at its
    // `zero_vec` default of 0, already matching `VALID` with no extra assignment needed.
    for i in words.len()..height {
        v[i * w + program::col::PC] = F::from_u32(4 * i as u32);
        v[i * w + program::col::RD_IS_ZERO] = F::ONE;
    }
    // `WordEcho`'s matching-consumer trace: the same `PC`/`WORD`/`VALID` columns, row for row.
    let mut echo = F::zero_vec(height * 3);
    for i in 0..height {
        echo[3 * i] = v[i * w + program::col::PC];
        echo[3 * i + 1] = v[i * w + program::col::WORD];
        echo[3 * i + 2] = v[i * w + program::col::VALID];
    }
    let echo_trace = RowMajorMatrix::new(echo, 3);
    let trace = RowMajorMatrix::new(v, w);

    #[derive(Clone)]
    enum T { Program(ProgramAir), Echo(WordEcho) }
    impl<Fld> BaseAir<Fld> for T {
        fn width(&self) -> usize { match self { T::Program(a) => <ProgramAir as BaseAir<Fld>>::width(a), T::Echo(a) => <WordEcho as BaseAir<Fld>>::width(a) } }
    }
    impl<AB: AirBuilder + InteractionBuilder> Air<AB> for T
    where
        AB::F: p3_field::Field,
    {
        fn eval(&self, b: &mut AB) { match self { T::Program(a) => a.eval(b), T::Echo(a) => a.eval(b) } }
    }

    let config = make_config(FriProfile::Test);
    let airs = vec![T::Program(ProgramAir), T::Echo(WordEcho)];
    let instances = vec![
        StarkInstance { air: &airs[0], trace: &trace, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &echo_trace, public_values: vec![] },
    ];
    let pd = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &pd);
    verify_batch(&config, &airs, &proof, &[vec![], vec![]], &pd.common).unwrap();
}

#[test]
fn memory_trace_is_sorted_and_consistent() {
    let p = guests::memcpy(4);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut counts = RangeCounts::default();
    let t = memory_trace(&e.events, 0, 1 << 12, &mut counts);
    let w = memory::col::WIDTH;
    let accesses: usize = e.events.iter().map(|c| c.accesses.len()).sum();
    let real: usize = (0..t.height()).filter(|r| t.values[r * w + memory::col::IS_REAL] == F::ONE).count();
    assert_eq!(real, accesses);
    // Audit ZM2 (2026-09-12): `+`, mirroring both the AIR's own key arithmetic and
    // `memory_trace`'s — `|` only coincides with it below `addr < 2^30`.
    let key = |r: usize| (t.values[r * w + memory::col::SPACE].as_canonical_u64() << 30) + t.values[r * w + memory::col::ADDR].as_canonical_u64();
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
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Add, a: 0xffff_ffff, b: 1, c: 0 }, &mut range, &mut nibble);
    assert_eq!(row[alu::col::FLAG0 + AluOp::Add.code() as usize], F::ONE);
    assert_eq!(row[alu::col::C], F::ZERO);
    for i in 0..4 { assert_eq!(row[alu::col::CARRY0 + i], F::ONE, "carry {i}"); }
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Sra, a: 0x8000_0000, b: 4, c: 0xf800_0000 }, &mut range, &mut nibble);
    assert_eq!(row[alu::col::SA], F::ONE);
    assert_eq!(row[alu::col::SHH], F::ZERO); // b=4 < 16, so bit4 of b is 0
    assert_eq!(row[alu::col::PW], F::from_u32(16));
    // q = (~a) >> 4 = 0x07ff_ffff ; c = ~q
    assert_eq!(row[alu::col::Q0], F::from_u32(0xff));
    assert_eq!(row[alu::col::C0 + 3], F::from_u32(0xf8));
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Slt, a: 0xffff_ffff, b: 0, c: 1 }, &mut range, &mut nibble);
    assert_eq!((row[alu::col::SA], row[alu::col::SB], row[alu::col::CARRY0 + 3]), (F::ONE, F::ZERO, F::ZERO));
}

/// M2.4: `slt`/`sltu`/`eq` rows no longer RANGE8-check their `C0..3` limb, since
/// `(cmp+eq)*C*(C-1)=0` already forces `C ∈ {0,1}` directly — a stronger constraint
/// than a byte-range check, so the RANGE8 lookup on `C0..3` was redundant there.
/// Method: call `fill_row` directly (the exact code path that decides whether to
/// call `range.range8()` per limb) and sum the resulting `RangeCounts`.
#[test]
fn cmp_and_eq_rows_do_not_range_check_their_c_limb() {
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    // slt: A(4) + B(4) + S(4, cmp gate, unchanged) = 12, not 4(A)+4(B)+4(C)+4(S)=16.
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Slt, a: 3, b: 9, c: 1 }, &mut range, &mut nibble);
    assert_eq!(range.range.iter().sum::<u64>(), 12);

    // eq: A(4) + B(4) = 8, not 4(A)+4(B)+4(C)=12 (eq has no S/T/Q scratch limbs at all).
    let mut range = RangeCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Eq, a: 3, b: 3, c: 1 }, &mut range, &mut nibble);
    assert_eq!(range.range.iter().sum::<u64>(), 8);

    // sltu: A(4) + B(4) + S(4, cmp gate) = 12, C dropped same as slt.
    let mut range = RangeCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Sltu, a: 3, b: 9, c: 1 }, &mut range, &mut nibble);
    assert_eq!(range.range.iter().sum::<u64>(), 12);
}

/// M2.4: bitwise rows no longer RANGE8-check ANY of `A0..3`/`B0..3`/`C0..3` — the
/// nibble lookups (`bitwise_high_nibble`) already bind all twelve limbs on these
/// rows (verified: each limb's low nibble gets a real AND4/OR4/XOR4 lookup, and its
/// derived high nibble gets a second one, so both halves — hence the whole byte —
/// are forced into range by the nibble table alone). Before M2.4 these rows paid
/// RANGE8 (12) *and* nibble (8) for the same bytes; after, only the nibble lookups
/// remain: `add/sub`'s 12 RANGE8 lookups collapse to 0, leaving just the 8 nibble
/// lookups already present since Task 3.
#[test]
fn bitwise_rows_no_longer_range_check_their_byte_limbs() {
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::And, a: 0x12, b: 0x34, c: 0x12 & 0x34 }, &mut range, &mut nibble);
    assert_eq!(range.range.iter().sum::<u64>(), 0, "no RANGE8 lookups on a bitwise row");
    let total_nibble: u64 = nibble.and.iter().sum::<u64>() + nibble.or.iter().sum::<u64>() + nibble.xor.iter().sum::<u64>();
    assert_eq!(total_nibble, 8, "4 limbs x {{lo, hi}} = 8 nibble lookups, unchanged from Task 3");
}

#[test]
#[should_panic(expected = "does not match")]
fn alu_fill_rejects_wrong_result() {
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let mut row = vec![F::ZERO; alu::col::WIDTH];
    fill_row(&mut row, &AluEvent { op: AluOp::Add, a: 1, b: 1, c: 3 }, &mut range, &mut nibble);
}

use shrugg_zkvm::tables::cpu::{self, cpu_trace, public_values};

#[test]
fn input_digest_of_empty_is_not_the_zero_digest() {
    use shrugg_zkvm::hash::input_digest;
    assert_ne!(input_digest([0u32; 4], &[]), [0u32; 8]);
    // Salted H_IN (controller ruling): the salt row alone (`n_in == 0` needs no separate
    // real-input block any more) is still exactly 1 row.
    assert_eq!(input_digest_rows_len(&[]), 1);
}
fn input_digest_rows_len(inputs: &[u32]) -> usize { shrugg_zkvm::hash::input_digest_rows([0u32; 4], inputs).len() }

#[test]
fn input_table_shape_and_padding() {
    use shrugg_zkvm::tables::input::{col, input_trace};
    let t = input_trace(&[10, 20, 30], &[0, 2, 1], 8);
    assert_eq!(t.height(), 8);
    for (i, (word, mult)) in [(10u32, 0u32), (20, 2), (30, 1)].iter().enumerate() {
        let r = i * col::WIDTH;
        assert_eq!(t.values[r + col::IDX], shrugg_zkvm::tables::F::from_u32(i as u32));
        assert_eq!(t.values[r + col::WORD], shrugg_zkvm::tables::F::from_u32(*word));
        assert_eq!(t.values[r + col::IS_REAL], shrugg_zkvm::tables::F::ONE);
        assert_eq!(t.values[r + col::MULT_READ], shrugg_zkvm::tables::F::from_u32(*mult));
    }
    for i in 3..8 {
        let r = i * col::WIDTH;
        assert_eq!(t.values[r + col::IS_REAL], shrugg_zkvm::tables::F::ZERO);
        assert_eq!(t.values[r + col::WORD], shrugg_zkvm::tables::F::ZERO);
        assert_eq!(t.values[r + col::MULT_READ], shrugg_zkvm::tables::F::ZERO);
        assert_eq!(t.values[r + col::IDX], shrugg_zkvm::tables::F::from_u32(i as u32));
    }
}

#[test]
fn cpu_trace_mirrors_events_and_pads() {
    let p = guests::fib(3);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let t = cpu_trace(&p, &[], [0u32; 4], &e.events, 64, &mut range, &mut nibble);
    let w = cpu::col::WIDTH;
    // M4.1: ordinary events now start after both the program-digest prefix (`dr`) and the
    // (always >= 1) input-digest prefix (`shrugg_zkvm::hash::input_digest_row_count(0) == 1`
    // here, since this test passes no inputs).
    let dr = p.digest_rows() + shrugg_zkvm::hash::input_digest_row_count(0);
    assert_eq!(t.height(), 64);
    // Row 0 is the first of the `dr` M3.4 digest rows; ordinary events start at row `dr`.
    assert_eq!(t.values[cpu::col::IS_DIGEST], F::ONE);
    for (i, ev) in e.events.iter().enumerate() {
        let r = &t.values[(dr + i) * w..(dr + i + 1) * w];
        assert_eq!(r[cpu::col::CLK], F::from_u32(dr as u32 + ev.clk));
        assert_eq!(r[cpu::col::PC], F::from_u32(ev.pc));
        assert_eq!(r[cpu::col::NEXT_PC], F::from_u32(ev.next_pc));
        assert_eq!(r[cpu::col::IS_REAL], F::ONE);
        assert_eq!(r[cpu::col::IS_DIGEST], F::ZERO);
        let d = ev.dec.to_fields();
        for k in 0..23 { assert_eq!(r[cpu::col::DEC0 + k], F::from_u32(d[k])); }
        assert_eq!((r[cpu::col::A], r[cpu::col::B], r[cpu::col::C]), (F::from_u32(ev.a), F::from_u32(ev.b), F::from_u32(ev.c)));
    }
    let last_real = dr + e.events.len() - 1;
    assert_eq!(t.values[last_real * w + cpu::col::SYS_HALT], F::ONE);
    let write_row = dr + e.events.iter().position(|ev| matches!(ev.sys, Some(shrugg_zkvm::emulator::Syscall::WriteOutput { .. }))).unwrap();
    assert_eq!(t.values[write_row * w + cpu::col::OUT_SEL0], F::ONE);
    // Padding rows are all-zero except the `written` accumulators, which must carry the
    // final per-slot write counts through to the last row for the unwritten-slot constraint.
    let pad = &t.values[(last_real + 1) * w..(last_real + 2) * w];
    for (i, x) in pad.iter().enumerate() {
        let expected = if i == cpu::col::WRITTEN0 { F::ONE } else { F::ZERO };
        assert_eq!(*x, expected, "padding column {i}");
    }
    let last = &t.values[(t.height() - 1) * w..t.height() * w];
    assert_eq!(last[cpu::col::WRITTEN0], F::ONE, "slot 0 was written");
    for k in 1..8 { assert_eq!(last[cpu::col::WRITTEN0 + k], F::ZERO, "slot {k} was not"); }
    let pv = public_values(0, 10, &e.outputs, &p.digest(), &shrugg_zkvm::hash::input_digest([0u32; 4], &[]));
    assert_eq!(pv.len(), cpu::pv::NUM);
    assert_eq!(pv[cpu::pv::OUT0], F::from_u32(2));
}

#[test]
fn cpu_trace_limbs_and_counts_every_load_store_address() {
    let p = guests::memcpy(4);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    let t = cpu_trace(&p, &[], [0u32; 4], &e.events, 1 << 10, &mut range, &mut nibble);
    let w = cpu::col::WIDTH;
    // M4.1: as in `cpu_trace_mirrors_events_and_pads`, ordinary events start after both the
    // program-digest prefix and the (always >= 1) input-digest prefix.
    let idr = shrugg_zkvm::hash::input_digest_row_count(0);
    let dr = p.digest_rows() + idr;
    let is_mem = |i: usize| { let d = &e.events[i].dec; d.is_lb + d.is_lh + d.is_lw + d.is_sb + d.is_sh + d.is_sw == 1 };
    let is_store = |i: usize| { let d = &e.events[i].dec; d.is_sb + d.is_sh + d.is_sw == 1 };
    let mem_rows: Vec<usize> = (0..e.events.len()).filter(|i| is_mem(*i)).collect();
    let n_stores = mem_rows.iter().filter(|i| is_store(**i)).count();
    assert!(!mem_rows.is_empty(), "memcpy loads and stores");
    for i in &mem_rows {
        let addr = e.events[*i].mem_addr;
        assert!(addr < 1 << 30, "row {i}: mem_addr must fit the AND4 bound");
        let row = dr + i;
        for k in 0..4 {
            assert_eq!(t.values[row * w + cpu::col::MA0 + k], F::from_u32((addr >> (8 * k)) & 0xff), "row {i} limb {k}");
        }
    }
    // Every load/store row RANGE8-checks its MA0..3 address limbs and its W0..3 word limbs
    // (8), plus the store's own RB0..3 rs2 limbs (4 more) on store rows only; memcpy uses
    // only LW/SW, so every load/store row also pays the same two AND4 lookups (the
    // low-nibble dummy range check and the MA3_HI-against-0xC extraction) — sign-extraction
    // AND4 lookups only fire on LB/LH rows, which memcpy never uses. M3.4: `range` is shared
    // with the digest-row prefix too (`fill_digest_rows`) — 3 RANGE8 lookups per digest row
    // (`LEFT0`/`LEFT0+1`/`IDX0`) plus 32 more on the last one (`DHVL0..31`, the canonical
    // 8-word digest encoding). `LEFT0`/`LEFT0+1`/`IDX0`/`IDX0+1` are all four RANGE8-checked
    // on a digest row (unlike a hash row, whose `IDX0+1` uses the tighter hash-only AND4
    // bound instead) — 4 per digest row. M4.1: the input-digest prefix (`idr` rows here, always
    // >= 1 since this test passes no inputs) pays the identical 4-per-row rate (already folded
    // into `dr = program digest rows + idr`) plus its own 32-word `IHVL0..31` canonical
    // encoding on its own last row — a second +32, on top of the program digest's own.
    let digest_range8 = 4 * dr + 32 + 32;
    assert_eq!(range.range.iter().sum::<u64>() as usize, 8 * mem_rows.len() + 4 * n_stores + digest_range8);
    let nibble_total: u64 = nibble.and.iter().sum();
    assert_eq!(nibble_total as usize, 2 * mem_rows.len());
}

/// M2.6 mul family: `mul`/`mulhu` pay the standard 12 (A0..3/B0..3/C0..3, `g_ab`/`g_c` both
/// include `is_mul`) plus 4 (`T0..3`, LO's own limbs, unconditional on every mul-family row
/// — this is the fix that pins `CARRY` even when the row doesn't select `LO` as its output,
/// see the `alu` module doc comment) plus 3 (`S1..3`, `CARRY`'s own limbs) = 19, no AND4
/// (neither needs a sign bit). `mulh` additionally extracts both `SA` and `SB` (dummy +
/// real each = 4 AND4); `mulhsu` extracts only `SA` (2 AND4, since it treats `B` as
/// unsigned) — this is the exact per-op lookup-gate accounting the M2.4 table established
/// for the RV32I ops, extended to M2.6.
#[test]
fn mul_family_lookup_counts_per_op() {
    let cases = [
        (AluOp::Mul, 0xdead_beefu32, 0x1234_5678u32, 19usize, 0usize),
        (AluOp::Mulhu, 0xffff_ffffu32, 0xffff_ffffu32, 19, 0),
        (AluOp::Mulh, (-2i32) as u32, (-3i32) as u32, 19, 4),
        (AluOp::Mulhsu, (-1i32) as u32, 7u32, 19, 2),
    ];
    for (op, a, b, want_range, want_nibble) in cases {
        let mut range = RangeCounts::default();
        let mut nibble = NibbleCounts::default();
        let c = op.eval(a, b);
        let mut row = vec![F::ZERO; alu::col::WIDTH];
        fill_row(&mut row, &AluEvent { op, a, b, c }, &mut range, &mut nibble);
        assert_eq!(range.range.iter().sum::<u64>() as usize, want_range, "{op:?} RANGE8 count");
        let nibble_total: u64 = nibble.and.iter().sum::<u64>() + nibble.or.iter().sum::<u64>() + nibble.xor.iter().sum::<u64>();
        assert_eq!(nibble_total as usize, want_nibble, "{op:?} AND4/OR4/XOR4 count");
    }
}

/// M2.6 div family: every op pays the standard 12 (A0..3/B0..3/C0..3) plus 8 (`Q0..3`/
/// `S0..3`, the quotient/remainder core limbs, unconditional on every `is_div` row
/// regardless of `DIVZ`) = 20, plus (only when `B != 0`, `normal` gated) 4 more for the
/// `R < |B|` diff limbs = 24. `div`/`rem` additionally extract both `SA` and `SB` (4 AND4);
/// `divu`/`remu` extract neither.
#[test]
fn div_family_lookup_counts_per_op() {
    // B != 0: the R < |B| diff-limb check fires.
    let cases = [
        (AluOp::Divu, 10u32, 3u32, 24usize, 0usize),
        (AluOp::Remu, 10u32, 3u32, 24, 0),
        (AluOp::Div, (-7i32) as u32, 2u32, 24, 4),
        (AluOp::Rem, (-7i32) as u32, 2u32, 24, 4),
    ];
    for (op, a, b, want_range, want_nibble) in cases {
        let mut range = RangeCounts::default();
        let mut nibble = NibbleCounts::default();
        let c = op.eval(a, b);
        let mut row = vec![F::ZERO; alu::col::WIDTH];
        fill_row(&mut row, &AluEvent { op, a, b, c }, &mut range, &mut nibble);
        assert_eq!(range.range.iter().sum::<u64>() as usize, want_range, "{op:?} RANGE8 count (B != 0)");
        let nibble_total: u64 = nibble.and.iter().sum::<u64>() + nibble.or.iter().sum::<u64>() + nibble.xor.iter().sum::<u64>();
        assert_eq!(nibble_total as usize, want_nibble, "{op:?} AND4 count (B != 0)");
    }
    // B == 0 (DIVZ): the R < |B| diff-limb check does not fire (nothing to compare
    // against), dropping 4 RANGE8 lookups relative to the B != 0 case above.
    let divz_cases = [
        (AluOp::Divu, 10u32, 0u32, 20usize, 0usize),
        (AluOp::Remu, 10u32, 0u32, 20, 0),
        (AluOp::Div, (-7i32) as u32, 0u32, 20, 4),
        (AluOp::Rem, (-7i32) as u32, 0u32, 20, 4),
    ];
    for (op, a, b, want_range, want_nibble) in divz_cases {
        let mut range = RangeCounts::default();
        let mut nibble = NibbleCounts::default();
        let c = op.eval(a, b);
        let mut row = vec![F::ZERO; alu::col::WIDTH];
        fill_row(&mut row, &AluEvent { op, a, b, c }, &mut range, &mut nibble);
        assert_eq!(range.range.iter().sum::<u64>() as usize, want_range, "{op:?} RANGE8 count (B == 0)");
        let nibble_total: u64 = nibble.and.iter().sum::<u64>() + nibble.or.iter().sum::<u64>() + nibble.xor.iter().sum::<u64>();
        assert_eq!(nibble_total as usize, want_nibble, "{op:?} AND4 count (B == 0)");
    }
}

/// Pins each table's *symbolic* max constraint degree — the number that determines how many
/// FRI quotient chunks its instance needs (`log2_ceil(max_degree + 1 - 1)` under this
/// machine's `is_zk = 1` hiding PCS), against `p3_batch_stark`'s ceiling of `1 << log_blowup =
/// 8` chunks (`generic_config`'s `log_blowup: 3`, i.e. `log2_ceil(constraint_degree - 1) <=
/// 3`, i.e. `max_degree <= 8`).
///
/// `shrugg_zkvm::machine::max_constraint_degrees` runs the *exact* computation
/// `ProverData::from_airs_and_degrees` (hence `Machine::verifier_key`) performs to size each
/// instance's quotient — `p3_batch_stark::symbolic::get_max_constraint_degree` against the
/// real, same-bus-packed lookup contexts for that `(program, tier)` — so this test is pinning
/// what actually ships, not a hand-recount. No proving: `ProverData::from_airs_and_degrees`
/// only commits the preprocessed columns and walks the symbolic constraint tree: sub-second.
///
/// Chip order is `machine::chips()`'s: program, cpu, memory, alu, range, nibble, poseidon2,
/// input, keccak.
///
/// If any of these numbers moves, re-measure (this test will fail with the new number) and:
/// - update the assertion and its comment below,
/// - update `docs/02-tables-and-buses.md`'s "max constraint degree" line,
/// - if a degree now exceeds 8, `log_blowup` (or the AIR) must change — 8 is this config's
///   hard ceiling, not a soft target.
#[test]
fn alu_max_constraint_degree_is_pinned() {
    use shrugg_zkvm::machine::{max_constraint_degrees, Tier};
    use shrugg_zkvm::tables::program::MIN_LOG_HEIGHT;
    // Tier-invariant (and, M3.4 fix, program-log-height-invariant): no table here uses
    // periodic columns, so the symbolic degree doesn't depend on trace height — any tier and
    // any declared program height give the same numbers. `Tier(10)`/`MIN_LOG_HEIGHT` (the
    // smallest of each) are used only because `max_constraint_degrees` needs concrete values
    // to size the tables.
    // M4.2 (Task 6): the keccak table is optional per proof, so `chips()` — and therefore this
    // list — has two shapes. Pin both. `klh = 0` is the eight-chip batch a keccak-free proof
    // uses; `klh = keccak::MIN_LOG_HEIGHT` is the nine-chip one. Every shared table's degree
    // must be identical between them: dropping an instance changes the batch's instance count,
    // not any other AIR's constraints or its own packed lookups.
    let keccak_free = max_constraint_degrees(
        Tier(10),
        MIN_LOG_HEIGHT,
        shrugg_zkvm::tables::input::MIN_LOG_HEIGHT,
        0,
        Tier(10).min_mem_log_height(),
    );
    assert_eq!(keccak_free.len(), 8, "eight chips when the proof declares no keccak table");

    let degrees = max_constraint_degrees(
        Tier(10),
        MIN_LOG_HEIGHT,
        shrugg_zkvm::tables::input::MIN_LOG_HEIGHT,
        shrugg_zkvm::tables::keccak::MIN_LOG_HEIGHT,
        Tier(10).min_mem_log_height(),
    );
    assert_eq!(degrees.len(), 9, "one degree per chip in machine::chips() order");
    assert_eq!(keccak_free[..], degrees[..8], "the other eight tables are unaffected");

    // program: M3.4's main-trace in-circuit decoder. Every one-hot flag pin
    // (`flag*(op-code)=0`) and field-consistency equation is at most degree 2 in the
    // columns; the packed PROGRAM/PROGRAM_WORD lookup fraction-pins don't exceed that either.
    assert_eq!(degrees[0], 2, "program table max constraint degree");

    // cpu: measured max is 8 — but (checked via get_symbolic_constraints directly) it comes
    // from the *packed* lookup fraction-pins (the batch-stark same-bus folding that groups
    // several of CPU's outgoing bus messages together up to the quotient-chunk-preserving
    // budget), not from CPU's own row logic: CPU's most complex single AIR constraint is only
    // degree 6. Still exactly at this config's degree-8 ceiling, same as ALU.
    assert_eq!(degrees[1], 8, "cpu table max constraint degree");

    // memory: measured max is 4, on both the main-AIR side and the packed lookups — comfortably
    // under the degree-8 ceiling (log_chunks = 2, half the budget ALU/CPU spend).
    assert_eq!(degrees[2], 4, "memory table max constraint degree");

    // alu: measured max is 8 — the M2.6 `div` sign-fix identity (reconstructing the true
    // remainder sign from the flipped/unflipped RANGE8-checked byte limbs and the divisor's
    // sign bit) is this AIR's single degree-8 constraint, one shy of this config's degree-9
    // ceiling (`log_blowup = 3` => `constraint_degree <= 9` with `is_zk = 1` => `max_degree <=
    // 8`). See `src/tables/alu.rs`'s div comments for the identity itself.
    assert_eq!(degrees[3], 8, "alu table max constraint degree");

    // range: single preprocessed-answering chip; its one main-AIR constraint and its packed
    // RANGE8/POW2 lookup fraction-pins all sit at degree 2.
    assert_eq!(degrees[4], 2, "range table max constraint degree");

    // nibble: no main-AIR constraints at all (it has no row-level validity marker of its own —
    // AGENTS.md's cheating-tests note; `LOOKUP_BALANCE_PANIC` is what catches an unpaid
    // multiplicity here). Its packed AND4/OR4/XOR4 lookup fraction-pins are degree 2.
    assert_eq!(degrees[5], 2, "nibble table max constraint degree");

    // poseidon2: measured max is 4, exactly the M3.1 design's own degree estimate — the S-box
    // split (`x3 = (s+rc)^3`, degree 3 in columns; `x7 = x3*x3*(s+rc)`, degree 3) gated by a
    // degree-1 preprocessed selector lands at degree 4, and the packed `POSEIDON2` lookup
    // (the table's only bus interaction) doesn't raise it further. Comfortably under the
    // degree-8 ceiling `alu`/`cpu` already sit at.
    assert_eq!(degrees[6], 4, "poseidon2 table max constraint degree");

    // input: a boolean flag, an arithmetic-sequence pin, and a degree-2 provided count on the
    // busier of its two split buses — `IS_REAL` alone on `INPUT_DIGEST` (degree 1) and
    // `IS_REAL * MULT_READ` on `INPUT_READ` (degree 2) — no table here is anywhere close to
    // the degree-8 ceiling.
    assert_eq!(degrees[7], 2, "input table max constraint degree");

    // keccak (M4.2): measured max is 3, exactly the module doc's own claim — the three cubic
    // rules that must be cubic (`xor3`, the parity triple product, χ's `p ⊕ (¬q ∧ r)`), with
    // every other rule written to stay at or below that (rule 5 deliberately spelled
    // `is_round · A = Σ …` rather than `is_round · (A − Σ …)` to avoid a fourth degree). The
    // chip's own packed `MEMORY`/`KECCAK` lookups — selector-weighted message columns times a
    // degree-2 `IS_REAL · sel_sum` count — don't raise it either.
    assert_eq!(degrees[8], 3, "keccak table max constraint degree");
}

mod poseidon2_tests {
    use super::*;
    use p3_air::PermutationAirBuilder;
    use p3_field::Field;
    use p3_symmetric::Permutation;
    use rand::distr::{Distribution, StandardUniform};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use shrugg_zkvm::machine::permutation;
    use shrugg_zkvm::tables::poseidon2::{
        self, permute_scalar, poseidon2_trace, round_constants, Poseidon2Air, Poseidon2Event,
        BLOCK, HALF_FULL_ROUNDS, PARTIAL_ROUNDS, ROUND_ROWS,
    };

    fn random_state(rng: &mut StdRng) -> [F; 8] {
        core::array::from_fn(|_| StandardUniform.sample(rng))
    }

    /// Step 1 — the M3-correctness anchor: `permute_scalar` (built only from `mds_light`/
    /// `internal_matmul`/`cube` plus the RNG-reproduced `round_constants`) must equal
    /// `Poseidon2Goldilocks::<8>::permute` from `machine::permutation()` (which is seeded from
    /// the exact same `PERM_SEED`), on 10^4 random states. This is what proves the round-
    /// constant reproduction (`round_constants`'s RNG replay) is correct, not just that the
    /// linear-layer arithmetic happens to match in isolation.
    #[test]
    fn poseidon2_scalar_helpers_match_plonky3() {
        let perm = permutation();
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        for i in 0..10_000 {
            let state = random_state(&mut rng);
            let want = perm.permute(state);
            let got = permute_scalar(state);
            assert_eq!(got, want, "mismatch on random state {i}");
        }
    }

    /// Step 2 — the preprocessed trace's row-kind one-hot pattern and round constants.
    #[test]
    fn poseidon2_preprocessed_trace_has_the_right_shape() {
        let height = BLOCK * 4;
        let pre: RowMajorMatrix<F> = Poseidon2Air::preprocessed_trace_at(height);
        assert_eq!(pre.height(), height);
        let row = |r: usize| -> &[F] { &pre.values[r * poseidon2::pre::WIDTH..(r + 1) * poseidon2::pre::WIDTH] };
        // row 0: first full round, IS_FIRST set.
        let r0 = row(0);
        assert_eq!(r0[poseidon2::pre::IS_FULL], F::ONE);
        assert_eq!(r0[poseidon2::pre::IS_PARTIAL], F::ZERO);
        assert_eq!(r0[poseidon2::pre::IS_IDLE], F::ZERO);
        assert_eq!(r0[poseidon2::pre::IS_FIRST], F::ONE);
        assert_eq!(r0[poseidon2::pre::IS_LAST], F::ZERO);
        // row 29: last round row (terminal full round), IS_LAST set.
        let r29 = row(29);
        assert_eq!(r29[poseidon2::pre::IS_FULL], F::ONE);
        assert_eq!(r29[poseidon2::pre::IS_FIRST], F::ZERO);
        assert_eq!(r29[poseidon2::pre::IS_LAST], F::ONE);
        // rows 30, 31: idle.
        for r in [30usize, 31] {
            let row = row(r);
            assert_eq!(row[poseidon2::pre::IS_IDLE], F::ONE, "row {r}");
            assert_eq!(row[poseidon2::pre::IS_FULL], F::ZERO, "row {r}");
            assert_eq!(row[poseidon2::pre::IS_PARTIAL], F::ZERO, "row {r}");
            assert_eq!(row[poseidon2::pre::IS_FIRST], F::ZERO, "row {r}");
            assert_eq!(row[poseidon2::pre::IS_LAST], F::ZERO, "row {r}");
        }
        // row 4: first partial round — only RC0 is nonzero.
        let r4 = row(4);
        assert_eq!(r4[poseidon2::pre::IS_PARTIAL], F::ONE);
        let rc = round_constants();
        assert_eq!(r4[poseidon2::pre::RC0], rc.internal[0]);
        assert_ne!(r4[poseidon2::pre::RC0], F::ZERO, "RC0 should be a genuine round constant");
        for i in 1..8 {
            assert_eq!(r4[poseidon2::pre::RC0 + i], F::ZERO, "lane {i}");
        }
        // The pattern repeats identically at block 1 (row 32 == row 0's pattern).
        assert_eq!(row(32), row(0));
    }

    /// Step 4 — `poseidon2_trace`'s row bookkeeping (not just its final output) matches an
    /// independent round-by-round scalar replay built from the same verified helpers, catching
    /// any off-by-one in which row gets which round's constants or output.
    #[test]
    fn poseidon2_trace_matches_plonky3_round_by_round() {
        let mut rng = StdRng::seed_from_u64(0xFEED);
        let inputs: Vec<[F; 8]> = (0..10).map(|_| random_state(&mut rng)).collect();
        let events: Vec<Poseidon2Event> = inputs
            .iter()
            .map(|&input| Poseidon2Event { input, output: permute_scalar(input) })
            .collect();
        let height = BLOCK * events.len();
        let trace = poseidon2_trace(&events, height);
        let w = poseidon2::col::WIDTH;
        let rc = round_constants();

        for (b, ev) in events.iter().enumerate() {
            let mut s = ev.input;
            for r in 0..BLOCK {
                let row = &trace.values[(b * BLOCK + r) * w..(b * BLOCK + r + 1) * w];
                for i in 0..8 {
                    assert_eq!(row[poseidon2::col::S0 + i], s[i], "block {b} row {r} lane {i}: S");
                    assert_eq!(row[poseidon2::col::IN0 + i], ev.input[i], "block {b} row {r} lane {i}: IN");
                }
                if r < HALF_FULL_ROUNDS {
                    let pre_state = if r == 0 { poseidon2::mds_light(s) } else { s };
                    let round = rc.initial[r];
                    let mut x7 = [F::ZERO; 8];
                    for i in 0..8 {
                        let p = pre_state[i] + round[i];
                        let x3 = poseidon2::cube(p);
                        assert_eq!(row[poseidon2::col::X3_0 + i], x3, "block {b} row {r} lane {i}: X3");
                        x7[i] = x3 * x3 * p;
                        assert_eq!(row[poseidon2::col::X7_0 + i], x7[i], "block {b} row {r} lane {i}: X7");
                    }
                    s = poseidon2::mds_light(x7);
                } else if r < HALF_FULL_ROUNDS + PARTIAL_ROUNDS {
                    let round0 = rc.internal[r - HALF_FULL_ROUNDS];
                    let p0 = s[0] + round0;
                    let x3_0 = poseidon2::cube(p0);
                    assert_eq!(row[poseidon2::col::X3_0], x3_0, "block {b} row {r}: X3 lane 0");
                    let mut x7 = s;
                    x7[0] = x3_0 * x3_0 * p0;
                    for i in 0..8 {
                        assert_eq!(row[poseidon2::col::X7_0 + i], x7[i], "block {b} row {r} lane {i}: X7");
                    }
                    s = poseidon2::internal_matmul(x7);
                } else if r < ROUND_ROWS {
                    let k = r - HALF_FULL_ROUNDS - PARTIAL_ROUNDS;
                    let round = rc.terminal[k];
                    let mut x7 = [F::ZERO; 8];
                    for i in 0..8 {
                        let p = s[i] + round[i];
                        let x3 = poseidon2::cube(p);
                        assert_eq!(row[poseidon2::col::X3_0 + i], x3, "block {b} row {r} lane {i}: X3");
                        x7[i] = x3 * x3 * p;
                        assert_eq!(row[poseidon2::col::X7_0 + i], x7[i], "block {b} row {r} lane {i}: X7");
                    }
                    s = poseidon2::mds_light(x7);
                }
            }
            assert_eq!(s, ev.output, "block {b}: final state disagrees with the event's own output");
            // MULT == 1 exactly on the last round row (29), 0 elsewhere in the block.
            for r in 0..BLOCK {
                let row = &trace.values[(b * BLOCK + r) * w..(b * BLOCK + r + 1) * w];
                let want = if r == ROUND_ROWS - 1 { F::ONE } else { F::ZERO };
                assert_eq!(row[poseidon2::col::MULT], want, "block {b} row {r}: MULT");
                assert_eq!(row[poseidon2::col::IS_REAL], F::ONE, "block {b} row {r}: IS_REAL");
            }
        }
    }

    /// A throwaway table that looks up `POSEIDON2`, mirroring
    /// `tests/tables.rs::range_table_answers_range8_and_pow2_lookups`'s `RangeAsker` pattern:
    /// main = `[gate, in0..7, out0..7]`; provides one weighted lookup per row.
    #[derive(Clone)]
    struct Poseidon2Asker;
    impl<Fld> BaseAir<Fld> for Poseidon2Asker {
        fn width(&self) -> usize { 17 }
    }
    impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Poseidon2Asker
    where
        AB::F: Field,
    {
        fn eval(&self, b: &mut AB) {
            let m = b.main();
            let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
            let gate = v(0);
            b.assert_bool(gate.clone());
            let msg: Vec<AB::Expr> = (1..17).map(v).collect();
            bus::POSEIDON2.lookup_key(b, msg, Count::bounded(gate, 1));
        }
    }

    /// Step 5 — a small table of `Poseidon2Event`s (some real, some padding), asked for over
    /// `POSEIDON2` by a throwaway consumer AIR, proves and verifies under the real batch
    /// STARK — the constraint-level counterpart to the two round-by-round tests above (those
    /// check the arithmetic directly; this checks the AIR the prover/verifier actually run).
    #[test]
    fn poseidon2_table_answers_lookups_under_a_constraint_check() {
        let mut rng = StdRng::seed_from_u64(0xA5A5);
        let n_real = 3;
        let n_blocks = 8; // height = 256, comfortably more blocks than real events
        let height = BLOCK * n_blocks;
        let events: Vec<Poseidon2Event> = (0..n_real)
            .map(|_| {
                let input = random_state(&mut rng);
                Poseidon2Event { input, output: permute_scalar(input) }
            })
            .collect();
        let trace = poseidon2_trace(&events, height);

        let asker_height = 4usize; // power of two >= n_real
        let mut asker = vec![F::ZERO; asker_height * 17];
        for (i, ev) in events.iter().enumerate() {
            asker[i * 17] = F::ONE;
            for k in 0..8 {
                asker[i * 17 + 1 + k] = ev.input[k];
            }
            for k in 0..8 {
                asker[i * 17 + 9 + k] = ev.output[k];
            }
        }
        let asker_trace = RowMajorMatrix::new(asker, 17);

        #[derive(Clone)]
        enum T {
            P(Poseidon2Air, usize),
            A(Poseidon2Asker),
        }
        impl<Fld: Field> BaseAir<Fld> for T {
            fn width(&self) -> usize {
                match self {
                    T::P(a, _) => <Poseidon2Air as BaseAir<Fld>>::width(a),
                    T::A(a) => <Poseidon2Asker as BaseAir<Fld>>::width(a),
                }
            }
            fn preprocessed_width(&self) -> usize {
                match self {
                    T::P(a, _) => <Poseidon2Air as BaseAir<Fld>>::preprocessed_width(a),
                    T::A(_) => 0,
                }
            }
            fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
                match self {
                    T::P(_, h) => Some(Poseidon2Air::preprocessed_trace_at(*h)),
                    T::A(_) => None,
                }
            }
        }
        impl<AB: AirBuilder + PermutationAirBuilder + InteractionBuilder> Air<AB> for T
        where
            AB::F: Field,
        {
            fn eval(&self, b: &mut AB) {
                match self {
                    T::P(a, _) => a.eval(b),
                    T::A(a) => a.eval(b),
                }
            }
        }

        let airs = vec![T::P(Poseidon2Air, height), T::A(Poseidon2Asker)];
        let instances = vec![
            StarkInstance { air: &airs[0], trace: &trace, public_values: vec![] },
            StarkInstance { air: &airs[1], trace: &asker_trace, public_values: vec![] },
        ];
        let config = make_config(FriProfile::Test);
        let pd = ProverData::from_instances(&config, &instances);
        let proof = prove_batch(&config, &instances, &pd);
        verify_batch(&config, &airs, &proof, &[vec![], vec![]], &pd.common).unwrap();
    }
}

mod keccak_tests {
    use super::*;
    use shrugg_zkvm::keccak::RC;
    use shrugg_zkvm::tables::keccak::{self, col, pre, KeccakAir, BLOCK, ROUNDS};

    /// M4.2 Task 3, Step 4 — the preprocessed trace's one-hot pattern and round-constant bits,
    /// and the pinned main width (`4 + 100 + 100 + 320 + 320 + 1600 + 100 + 64 + 4`).
    #[test]
    fn keccak_preprocessed_trace_has_the_right_shape() {
        assert_eq!(col::WIDTH, 2612, "keccak main width");
        assert_eq!(pre::WIDTH, 24 + 3 + 8 + 64, "keccak preprocessed width");

        let height = BLOCK * 2;
        let p: RowMajorMatrix<F> = KeccakAir::preprocessed_trace_at(height);
        assert_eq!(p.height(), height);
        assert_eq!(p.width(), pre::WIDTH);
        let row = |r: usize| -> &[F] { &p.values[r * pre::WIDTH..(r + 1) * pre::WIDTH] };

        for r in 0..height {
            let want_first = r % BLOCK == 0;
            let want_last = r % BLOCK == ROUNDS - 1;
            let want_idle = r % BLOCK >= ROUNDS;
            assert_eq!(row(r)[pre::IS_FIRST], F::from_bool(want_first), "IS_FIRST row {r}");
            assert_eq!(row(r)[pre::IS_LAST_ROUND], F::from_bool(want_last), "IS_LAST_ROUND row {r}");
            assert_eq!(row(r)[pre::IS_IDLE], F::from_bool(want_idle), "IS_IDLE row {r}");
            // Exactly one of the 24 round selectors on a round row, none on an idle row; and
            // exactly one of the 8 idle selectors on an idle row, none on a round row.
            let n_round: usize = (0..ROUNDS).filter(|&i| row(r)[pre::IS_ROUND0 + i] == F::ONE).count();
            let n_idle: usize = (0..8).filter(|&i| row(r)[pre::IS_IDLE0 + i] == F::ONE).count();
            assert_eq!(n_round, usize::from(!want_idle), "round one-hot row {r}");
            assert_eq!(n_idle, usize::from(want_idle), "idle one-hot row {r}");
            if !want_idle {
                assert_eq!(row(r)[pre::IS_ROUND0 + r % BLOCK], F::ONE, "round selector row {r}");
            } else {
                assert_eq!(row(r)[pre::IS_IDLE0 + (r % BLOCK - ROUNDS)], F::ONE, "idle selector row {r}");
            }
        }
        // IS_FIRST at rows 0 and 32 only, IS_LAST_ROUND at 23 and 55, IS_IDLE on 24..31, 56..63
        // — spelled out, as the brief asks, on top of the generic sweep above.
        for r in [0usize, 32] { assert_eq!(row(r)[pre::IS_FIRST], F::ONE); }
        for r in [23usize, 55] { assert_eq!(row(r)[pre::IS_LAST_ROUND], F::ONE); }
        for r in (24..32).chain(56..64) { assert_eq!(row(r)[pre::IS_IDLE], F::ONE, "row {r}"); }

        // RC bits: row 0 is RC[0] == 1, row 23 is RC[23], and every idle row is all zero.
        for (r, want) in [(0usize, RC[0]), (23, RC[23]), (7, RC[7]), (32, RC[0]), (55, RC[23])] {
            for z in 0..64 {
                let bit = F::from_bool((want >> z) & 1 == 1);
                assert_eq!(row(r)[pre::RC0 + z], bit, "RC bit {z} of row {r}");
            }
        }
        for r in 24..32 {
            for z in 0..64 { assert_eq!(row(r)[pre::RC0 + z], F::ZERO, "RC bit {z} of idle row {r}"); }
        }
        // The pattern repeats identically block to block.
        assert_eq!(row(32), row(0));
        assert_eq!(row(63), row(31));
        assert_eq!(keccak::MIN_LOG_HEIGHT, 5);
        // M4.2 (controller ruling 2): the upper bound is the tier's, not a flat constant of
        // this module's — one permutation costs one cycle, so `klh <= t + 5`.
        use shrugg_zkvm::machine::Tier;
        assert_eq!(Tier(10).max_keccak_log_height(), 15);
        assert_eq!(Tier(20).max_keccak_log_height(), 25);
    }
}
