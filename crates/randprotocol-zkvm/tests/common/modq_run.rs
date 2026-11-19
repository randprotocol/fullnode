//! MODQ (private multisig phase 3): the chip standalone on the real `ModqAir` -- the modq table, a
//! `MODQ` asker in place of the cpu, a permissive `MEMORY` twin in place of the memory table and
//! the range table. Uses only public `randprotocol_zkvm` API, so it builds without the `cheating` feature
//! (the vendored fullnode build); `tests/modq.rs` runs on it. The forgery/defence-switch variant
//! lives in `modq_harness` behind `cheating`.
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use randprotocol_zkvm::emulator::{Execution, MemAccess};
use randprotocol_zkvm::machine::{make_config, FriProfile, VerifyError};
use randprotocol_zkvm::tables::modq::{col, ModqAir, ModqEvent};
use randprotocol_zkvm::tables::range::{range_trace, RangeAir, RangeCounts};
use randprotocol_zkvm::tables::{bus, F};

/// The cpu's side of `MODQ`: one `(CLK, BASE, A1, MODQ_W)` lookup per real row. The fourth field
/// (constraint set 11) is the call's gas beyond its row's 1, which the cpu takes from the chip's
/// entry: a free witness on this side, exactly as the cpu's `MODQ_W` is on a `MODQ` row.
#[derive(Clone)]
pub struct Asker;
impl<Fld> BaseAir<Fld> for Asker { fn width(&self) -> usize { 5 } }
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Asker where AB::F: Field {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        b.assert_bool(v(0));
        bus::MODQ.lookup_key(b, [v(1), v(2), v(3), v(4)], Count::bounded(v(0), 1));
    }
}

/// A permissive memory table: receives each `(space, addr, ts, value, is_write)` row given.
#[derive(Clone)]
pub struct MemoryTwin;
impl<Fld> BaseAir<Fld> for MemoryTwin { fn width(&self) -> usize { 6 } }
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MemoryTwin where AB::F: Field {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        b.assert_bool(v(0));
        bus::MEMORY.receive(b, [v(1), v(2), v(3), v(4), v(5)], Count::bounded(v(0), 1));
    }
}

/// The modq side of the batch: the real `ModqAir` here, `ModqAirWithout(off)` in `modq_harness`.
/// Both share `ModqAir`'s preprocessed trace; only `eval` differs, so `run_raw_on` is written once.
pub trait ModqSide: Clone + Send + Sync {
    fn main_width(&self) -> usize;
    fn pre_width(&self) -> usize;
    fn eval_on<AB: AirBuilder + PermutationAirBuilder + InteractionBuilder>(&self, b: &mut AB) where AB::F: Field;
}
impl ModqSide for ModqAir {
    fn main_width(&self) -> usize { <ModqAir as BaseAir<F>>::width(self) }
    fn pre_width(&self) -> usize { <ModqAir as BaseAir<F>>::preprocessed_width(self) }
    fn eval_on<AB: AirBuilder + PermutationAirBuilder + InteractionBuilder>(&self, b: &mut AB) where AB::F: Field { self.eval(b) }
}

#[derive(Clone)]
pub enum T<S> { S(S, usize), A(Asker), M(MemoryTwin), R(RangeAir) }
impl<Fld: Field, S: ModqSide> BaseAir<Fld> for T<S> {
    fn width(&self) -> usize {
        match self {
            T::S(a, _) => a.main_width(),
            T::A(a) => <Asker as BaseAir<Fld>>::width(a),
            T::M(a) => <MemoryTwin as BaseAir<Fld>>::width(a),
            T::R(a) => <RangeAir as BaseAir<Fld>>::width(a),
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            T::S(a, _) => a.pre_width(),
            T::R(a) => <RangeAir as BaseAir<Fld>>::preprocessed_width(a),
            _ => 0,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        match self {
            T::S(_, h) => Some(ModqAir::preprocessed_trace_at(*h)),
            T::R(a) => <RangeAir as BaseAir<Fld>>::preprocessed_trace(a),
            _ => None,
        }
    }
}
impl<AB: AirBuilder + PermutationAirBuilder + InteractionBuilder, S: ModqSide> Air<AB> for T<S> where AB::F: Field {
    fn eval(&self, b: &mut AB) {
        match self { T::S(a, _) => a.eval_on(b), T::A(a) => a.eval(b), T::M(a) => a.eval(b), T::R(a) => a.eval(b) }
    }
}

/// The run's `MODQ` calls as chip events, at the emulator's own clock (the standalone harness has
/// no digest prefix).
pub fn events(exec: &Execution) -> Vec<ModqEvent> {
    exec.events.iter()
        .filter_map(|e| e.modq.as_ref().map(|m| ModqEvent { clk: m.clk, base: m.base, a1: m.a1, inputs: m.inputs.clone() }))
        .collect()
}

/// The memory twin's trace: one row per `(clk, access)`.
pub fn twin_of(accesses: &[(u32, Vec<MemAccess>)]) -> RowMajorMatrix<F> {
    let rows: Vec<(u32, MemAccess)> = accesses.iter().flat_map(|(clk, a)| a.iter().map(move |x| (*clk, *x))).collect();
    let mut v = F::zero_vec(rows.len().next_power_of_two().max(4) * 6);
    for (i, (clk, a)) in rows.iter().enumerate() {
        v[i * 6..(i + 1) * 6].copy_from_slice(&[F::ONE, F::from_u32(a.space), F::from_u32(a.addr), F::from_u32(a.ts(*clk)), F::from_u32(a.value), F::from_bool(a.is_write)]);
    }
    RowMajorMatrix::new(v, 6)
}

/// Prove and verify the four-table batch: the modq `trace` under `ModqAir`, an asker
/// row per `(clk, base, a1)` in `asks`, the memory `twin` and the range table of `range`.
pub fn run_raw(trace: &RowMajorMatrix<F>, range: &RangeCounts, asks: &[(u32, u32, u32)], twin: &RowMajorMatrix<F>) -> Result<(), VerifyError> {
    run_raw_on(ModqAir, trace, range, asks, twin)
}

/// What the table's entry for `(clk, base, a1)` says the call weighs beyond its row's 1 — the
/// linear form of rule 7 over the block's op flags, read off the first row of the block that
/// carries the key — or, when no block does, what `a1`'s op weighs. This is the value a prover
/// puts in the cpu's `MODQ_W` to balance the bus: the asker asks with it, so a forged block is
/// asked for at the forged block's own price and only the chip's rules are under test.
pub fn asked_weight(trace: &RowMajorMatrix<F>, clk: u32, base: u32, a1: u32) -> F {
    use randprotocol_zkvm::gas::{modq_gas, modq_op, MODQ_DOT4_GAS, MODQ_INTT_GAS, MODQ_MSUB4_GAS, MODQ_NTT_GAS};
    let w = col::WIDTH;
    let key = [F::from_u32(clk), F::from_u32(base), F::from_u32(a1)];
    for b in 0..trace.values.len() / w / randprotocol_zkvm::tables::modq::BLOCK {
        let row = &trace.values[b * randprotocol_zkvm::tables::modq::BLOCK * w..][..w];
        if row[col::IS_REAL] != F::ZERO && [row[col::CLK], row[col::BASE], row[col::A1]] == key {
            return row[col::IS_NTT] * F::from_u64(MODQ_NTT_GAS - 1) + row[col::IS_INTT] * F::from_u64(MODQ_INTT_GAS - 1)
                + row[col::IS_DOT] * F::from_u64(MODQ_DOT4_GAS - 1) + row[col::IS_MSUB] * F::from_u64(MODQ_MSUB4_GAS - 1);
        }
    }
    F::from_u64(modq_gas(modq_op(a1)) - 1)
}

/// `run_raw` with the modq table under any `ModqSide` (`modq_harness` passes `ModqAirWithout(off)`).
pub fn run_raw_on<S: ModqSide>(side: S, trace: &RowMajorMatrix<F>, range: &RangeCounts, asks: &[(u32, u32, u32)], twin: &RowMajorMatrix<F>) -> Result<(), VerifyError> {
    let priced: Vec<(u32, u32, u32, F)> = asks.iter().map(|&(clk, base, a1)| (clk, base, a1, asked_weight(trace, clk, base, a1))).collect();
    run_priced_on(side, trace, range, &priced, twin)
}

/// `run_raw` with each ask's weight given: `(clk, base, a1, weight − 1)`. What a cpu row claiming a
/// call at a price of its choosing looks like to the chip.
pub fn run_priced(trace: &RowMajorMatrix<F>, range: &RangeCounts, asks: &[(u32, u32, u32, F)], twin: &RowMajorMatrix<F>) -> Result<(), VerifyError> {
    run_priced_on(ModqAir, trace, range, asks, twin)
}

pub fn run_priced_on<S: ModqSide>(side: S, trace: &RowMajorMatrix<F>, range: &RangeCounts, asks: &[(u32, u32, u32, F)], twin: &RowMajorMatrix<F>) -> Result<(), VerifyError> {
    let mut asker = F::zero_vec(asks.len().next_power_of_two().max(4) * 5);
    for (i, &(clk, base, a1, weight)) in asks.iter().enumerate() {
        asker[i * 5..i * 5 + 5].copy_from_slice(&[F::ONE, F::from_u32(clk), F::from_u32(base), F::from_u32(a1), weight]);
    }
    let asker = RowMajorMatrix::new(asker, 5);
    let range_t = range_trace(range);
    let airs = vec![T::S(side, trace.values.len() / col::WIDTH), T::A(Asker), T::M(MemoryTwin), T::R(RangeAir)];
    let instances = vec![
        StarkInstance { air: &airs[0], trace, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &asker, public_values: vec![] },
        StarkInstance { air: &airs[2], trace: twin, public_values: vec![] },
        StarkInstance { air: &airs[3], trace: &range_t, public_values: vec![] },
    ];
    let config = make_config(FriProfile::Test);
    let pd = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &pd);
    verify_batch(&config, &airs, &proof, &[vec![], vec![], vec![], vec![]], &pd.common).map_err(|e| VerifyError::Batch(format!("{e:?}")))
}

