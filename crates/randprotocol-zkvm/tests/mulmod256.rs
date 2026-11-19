//! The 256-bit modular multiply-add chip prototype (`tables::mulmod256`, feature `next-set`;
//! monorepo issue 68, ZKVM-115): its host arithmetic against a big-integer oracle, its
//! constraints on honest rows, real proofs of the chip standalone with the range table, and a
//! forgery suite — wrong result, non-canonical result, wrong quotient, out-of-range limbs.
//!
//! "Standalone" is the limit of what is shown: the chip is not part of the machine, there is
//! no syscall, no memory traffic and no guest. A forgery here is a forged *chip row*; nothing
//! about how a cpu row would bind to one is tested, because that binding does not exist yet.
mod common;
use common::*;

use num_bigint::BigUint;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_batch_stark::{prove_batch_with_layout_and_self_check, verify_batch, ProverData, QuotientLayout, SelfCheck, StarkInstance};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use randprotocol_zkvm::machine::{make_config, FriProfile, Val, VerifyError};
use randprotocol_zkvm::tables::mulmod256::{self as mm, col, fill_row, mulmod, mulmod256_trace, Mulmod256Air, MulmodEvent, Witness, LOOKUPS_PER_ROW, N, NCARRY, NQ};
use randprotocol_zkvm::tables::range::{range_trace, RangeAir, RangeCounts};
use randprotocol_zkvm::tables::F;

// ─────────────────────────── moduli ───────────────────────────

fn le32(hex: &str) -> [u8; 32] {
    let mut b = hex::decode(hex).unwrap();
    assert_eq!(b.len(), 32);
    b.reverse();
    b.try_into().unwrap()
}

/// The fields the issue names: secp256k1's base field and group order, ed25519's field,
/// bn254's base field.
fn moduli() -> Vec<(&'static str, [u8; 32])> {
    vec![
        ("secp256k1 p", le32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")),
        ("secp256k1 n", le32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")),
        ("ed25519 p", le32("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")),
        ("bn254 p", le32("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47")),
    ]
}

fn big(x: &[u8]) -> BigUint {
    BigUint::from_bytes_le(x)
}

fn random32(rng: &mut StdRng) -> [u8; 32] {
    core::array::from_fn(|_| rng.random())
}

fn event(rng: &mut StdRng, p: [u8; 32]) -> MulmodEvent {
    MulmodEvent { a: random32(rng), b: random32(rng), c: random32(rng), p }
}

// ─────────────────────────── the standalone batch ───────────────────────────

#[derive(Clone)]
enum T {
    M(Mulmod256Air),
    R(RangeAir),
}
impl<Fld: Field> BaseAir<Fld> for T {
    fn width(&self) -> usize {
        match self {
            T::M(a) => <Mulmod256Air as BaseAir<Fld>>::width(a),
            T::R(a) => <RangeAir as BaseAir<Fld>>::width(a),
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            T::M(_) => 0,
            T::R(a) => <RangeAir as BaseAir<Fld>>::preprocessed_width(a),
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        match self {
            T::M(_) => None,
            T::R(a) => <RangeAir as BaseAir<Fld>>::preprocessed_trace(a),
        }
    }
}
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for T
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        match self {
            T::M(a) => a.eval(b),
            T::R(a) => a.eval(b),
        }
    }
}

/// Prove the two-table batch — the chip's `trace` and the range table of `range` — and verify
/// it. The prover's debug self-check is off, so a forged trace reaches the verifier in a debug
/// build too; returns `(result, proof bytes)`.
fn prove_and_verify(trace: &RowMajorMatrix<F>, range: &RangeCounts) -> (Result<(), VerifyError>, usize) {
    let (r, bytes, _, _) = prove_and_verify_with_shape(trace, range);
    (r, bytes)
}

/// [`prove_and_verify`], also returning what the batch committed for the chip beyond its main
/// columns: the LogUp auxiliary columns (as committed: base-field, the extension columns
/// flattened) and the quotient chunks.
fn prove_and_verify_with_shape(trace: &RowMajorMatrix<F>, range: &RangeCounts) -> (Result<(), VerifyError>, usize, usize, usize) {
    let range_t = range_trace(range);
    let airs = vec![T::M(Mulmod256Air), T::R(RangeAir)];
    let instances = vec![StarkInstance { air: &airs[0], trace, public_values: vec![] }, StarkInstance { air: &airs[1], trace: &range_t, public_values: vec![] }];
    let config = make_config(FriProfile::Test);
    let pd = ProverData::from_instances(&config, &instances);
    let proof = prove_batch_with_layout_and_self_check(&config, &instances, &pd, QuotientLayout::PerChunk, SelfCheck::Skip);
    let bytes = postcard::to_allocvec(&proof).unwrap().len();
    let chip = &proof.opened_values.instances[0];
    let (aux, chunks) = (chip.permutation_local.len(), chip.base_opened_values.quotient_chunks.len());
    (verify_batch(&config, &airs, &proof, &[vec![], vec![]], &pd.common).map_err(|e| VerifyError::Batch(format!("{e:?}"))), bytes, aux, chunks)
}

const HEIGHT: usize = 128;
/// Committed LogUp auxiliary columns (base-field: 118 extension columns, flattened) the batch
/// prover adds for the chip's 351 lookups.
const AUX_COLUMNS: usize = 236;

/// A trace of `honest` events with row 0 replaced by `forged` (and its carries), as a cheating
/// prover would build it: every lookup of a limb that is a byte is counted, so the range table
/// balances wherever it can.
fn forged_trace(honest: &[MulmodEvent], forged: &Witness, carries: &[i64; NCARRY]) -> (RowMajorMatrix<F>, RangeCounts) {
    let mut range = RangeCounts::default();
    let mut t = mulmod256_trace(&honest[1..], HEIGHT, &mut range);
    // Shift the honest rows down one and put the forgery first.
    let w = col::WIDTH;
    t.values.copy_within(0..(honest.len() - 1) * w, w);
    for x in &mut t.values[..w] {
        *x = F::ZERO;
    }
    fill_row(&mut t.values[..w], forged, carries, &mut range);
    (t, range)
}

fn refused(forged: &Witness, carries: &[i64; NCARRY], honest: &[MulmodEvent]) -> bool {
    let (t, range) = forged_trace(honest, forged, carries);
    rejects(|| prove_and_verify(&t, &range).0)
}

fn sample_events(seed: u64, n: usize) -> Vec<MulmodEvent> {
    let mut rng = StdRng::seed_from_u64(seed);
    let ms = moduli();
    (0..n).map(|i| event(&mut rng, ms[i % ms.len()].1)).collect()
}

// ─────────────────────────── host arithmetic ───────────────────────────

#[test]
fn the_host_arithmetic_is_big_integer_arithmetic() {
    let mut rng = StdRng::seed_from_u64(0x115);
    for (name, p) in moduli() {
        let mut cases: Vec<MulmodEvent> = (0..200).map(|_| event(&mut rng, p)).collect();
        let (zero, one, max) = ([0u8; 32], core::array::from_fn(|i| (i == 0) as u8), [0xffu8; 32]);
        let mut pm1 = p;
        pm1[0] -= 1; // every modulus here is odd
        for a in [zero, one, max, p, pm1] {
            for b in [zero, one, max, pm1] {
                for c in [zero, max, pm1] {
                    cases.push(MulmodEvent { a, b, c, p });
                }
            }
        }
        for e in &cases {
            let (q, r) = mulmod(&e.a, &e.b, &e.c, &e.p).unwrap_or_else(|| panic!("{name}: no row for {e:?}"));
            let n = big(&e.a) * big(&e.b) + big(&e.c);
            assert_eq!(big(&r), &n % big(&e.p), "{name}: remainder");
            assert_eq!(big(&q), &n / big(&e.p), "{name}: quotient");
            assert!(big(&r) < big(&e.p));
        }
    }
}

#[test]
fn a_zero_modulus_or_a_quotient_past_33_bytes_has_no_row() {
    let max = [0xffu8; 32];
    assert!(mulmod(&max, &max, &max, &[0; 32]).is_none(), "p = 0");
    // p = 2^248 - 1: (2^256 - 1)^2 / p needs 34 bytes.
    let mut small = [0xffu8; 32];
    small[31] = 0;
    assert!(mulmod(&max, &max, &max, &small).is_none());
    // The same modulus with reduced operands is fine.
    let (_, r) = mulmod(&small, &[0; 32], &[0; 32], &small).unwrap();
    assert_eq!(r, [0; 32]);
    // p = 2^248 exactly: the largest quotient is (2^512 - 2^256) / 2^248 < 2^264, 33 bytes.
    let mut p248 = [0u8; 32];
    p248[31] = 1;
    assert!(mulmod(&max, &max, &max, &p248).is_some());
    // p = 1: only tiny operands have a row.
    let one: [u8; 32] = core::array::from_fn(|i| (i == 0) as u8);
    assert!(mulmod(&max, &max, &max, &one).is_none());
    assert_eq!(mulmod(&one, &one, &[0; 32], &one).unwrap().1, [0; 32]);
}

// ─────────────────────────── the constraints, row by row ───────────────────────────

fn row_of(w: &Witness, carries: &[i64; NCARRY]) -> Vec<Val> {
    let mut row = vec![F::ZERO; col::WIDTH];
    fill_row(&mut row, w, carries, &mut RangeCounts::default());
    row
}

fn row_holds(row: &[Val]) -> bool {
    let (_, constraints) = symbolic_air(&Mulmod256Air);
    let rows = Rows { cur: row.to_vec(), next: row.to_vec(), pre_cur: vec![], pre_next: vec![], public: vec![] };
    constraints.iter().all(|c| eval_rows(c, &rows) == Val::ZERO)
}

#[test]
fn honest_rows_satisfy_every_constraint_and_a_padding_row_does_too() {
    for e in sample_events(1, 64) {
        let w = Witness::honest(&e).unwrap();
        assert!(row_holds(&row_of(&w, &w.carries().unwrap())));
    }
    assert!(row_holds(&vec![F::ZERO; col::WIDTH]), "the all-zero padding row");
}

/// The shape the prices in `docs/05-roadmap.md` are computed from.
#[test]
fn the_chips_shape_is_pinned() {
    assert_eq!((N, NQ, NCARRY), (32, 33, 63));
    assert_eq!(col::WIDTH, 384);
    assert_eq!(LOOKUPS_PER_ROW, 351);
    let (interactions, constraints) = symbolic_air(&Mulmod256Air);
    assert_eq!(interactions.len(), LOOKUPS_PER_ROW, "one RANGE8 lookup per checked limb");
    assert!(interactions.iter().all(|i| i.bus_name == randprotocol_zkvm::tables::bus::RANGE8.name()));
    // IS_REAL boolean + 64 limb equations + 32 boolean carries + 32 chain equations + the last carry.
    assert_eq!(constraints.len(), 1 + 64 + 32 + 32 + 1);
    // Every limb column except the boolean DC is the subject of exactly one lookup.
    let mut rng = StdRng::seed_from_u64(2);
    let w = Witness::honest(&sample_events(3, 1)[0]).unwrap();
    let row = row_of(&w, &w.carries().unwrap());
    let rows = Rows { cur: row.clone(), next: row, pre_cur: vec![], pre_next: vec![], public: vec![] };
    for c in 1..col::WIDTH {
        let looked_up = interactions.iter().filter(|i| i.fields.iter().any(|f| depends(f, &rows, Slot::Cur, c, &mut rng))).count();
        let is_dc = (col::DC..col::DC + N).contains(&c);
        assert_eq!(looked_up, if is_dc { 0 } else { 1 }, "column {c}");
    }
}

// ─────────────────────────── real proofs ───────────────────────────

/// 100 operations over the four moduli, proved and verified with the range table.
#[test]
fn a_hundred_operations_prove_and_verify() {
    let events = sample_events(4, 100);
    let mut range = RangeCounts::default();
    let trace = mulmod256_trace(&events, HEIGHT, &mut range);
    assert_eq!(range.range.iter().sum::<u64>(), (100 * LOOKUPS_PER_ROW) as u64);
    let t0 = std::time::Instant::now();
    let (result, bytes, aux, chunks) = prove_and_verify_with_shape(&trace, &range);
    result.expect("the honest batch verifies");
    // Base-field cells one operation commits: the main row plus the LogUp auxiliary columns.
    // The cpu table's row is 283 main columns, for scale.
    let cells = col::WIDTH + aux;
    eprintln!(
        "mulmod256 standalone: 100 operations in a 2^7-row table; {} main columns, {} RANGE8 lookups per row, {aux} LogUp auxiliary base columns, {chunks} quotient chunks; \
         {cells} committed base cells per operation; prove + verify {:.2} s, proof {bytes} bytes (Test profile)",
        col::WIDTH,
        LOOKUPS_PER_ROW,
        t0.elapsed().as_secs_f64()
    );
    assert_eq!(aux, AUX_COLUMNS, "the LogUp packing moved: re-price docs/05-roadmap.md's ZKVM-115 table");
}

/// The forgery harness refuses nothing honest: the honest witness, pushed through the same
/// path the forgeries take, verifies. Without this a harness that refused everything would
/// pass every test below.
#[test]
fn the_forgery_harness_accepts_the_honest_row() {
    let events = sample_events(5, 8);
    let w = Witness::honest(&events[0]).unwrap();
    let carries = w.carries().unwrap();
    assert!(!refused(&w, &carries, &events), "the honest row was refused: the harness is broken");
}

// ─────────────────────────── the forgery suite ───────────────────────────

/// A wrong result: `r + 1` (with `D` re-solved, so the canonical-result chain is satisfied).
/// The product identity no longer holds at limb 0, so there are no carries that fit; the
/// forger's best attempt keeps the honest ones.
#[test]
fn a_wrong_result_is_refused() {
    let events = sample_events(6, 8);
    let honest = Witness::honest(&events[0]).unwrap();
    let carries = honest.carries().unwrap();
    for delta in [1i64, -1, 2] {
        let mut w = honest.clone();
        // Stay a byte: pick a limb the delta does not push out of range.
        let i = (0..N).find(|i| (0..256).contains(&(w.r[*i] + delta))).unwrap();
        w.r[i] += delta;
        w.solve_d();
        assert!(w.carries().is_none() || w.carries() != Some(carries), "the forged limbs do not satisfy the identity");
        assert!(!row_holds(&row_of(&w, &carries)), "delta {delta}: a constraint must fail");
        assert!(refused(&w, &carries, &events), "delta {delta}");
    }
}

/// A non-canonical result: `r + p` with `q − 1`. `a·b + c = (q − 1)·p + (r + p)` is a true
/// integer identity and every limb is a byte — only `R ≤ P − 1` stands in the way.
#[test]
fn a_non_canonical_result_is_refused() {
    // bn254's p is below 2^254, so r + p fits 256 bits for every r < p.
    let p = moduli()[3].1;
    let mut rng = StdRng::seed_from_u64(7);
    let events: Vec<MulmodEvent> = (0..8).map(|_| event(&mut rng, p)).collect();
    let honest = Witness::honest(&events[0]).unwrap();
    let mut w = honest.clone();
    // r += p
    let mut carry = 0i64;
    for i in 0..N {
        let x = w.r[i] + w.p[i] + carry;
        w.r[i] = x % 256;
        carry = x / 256;
    }
    assert_eq!(carry, 0, "r + p fits 256 bits");
    // q -= 1
    let mut borrow = 1i64;
    for i in 0..NQ {
        let x = w.q[i] - borrow;
        borrow = (x < 0) as i64;
        w.q[i] = x + 256 * borrow;
    }
    assert_eq!(borrow, 0, "q >= 1 for random operands");
    let carries = w.carries().expect("the forged limbs still satisfy a*b + c = q*p + r");
    assert!(w.a.iter().chain(&w.q).chain(&w.r).all(|x| (0..256).contains(x)), "and every limb is a byte");
    // Whatever D the forger writes, the chain cannot close: with D re-solved its last carry is 1.
    w.solve_d();
    assert_eq!(w.dc[N - 1], 1);
    assert!(refused(&w, &carries, &events), "D re-solved");
    // And with the carry lied about, an equation of the chain fails instead.
    w.dc[N - 1] = 0;
    assert!(refused(&w, &carries, &events), "the last carry forced to 0");
}

/// A wrong quotient, with the result left alone.
#[test]
fn a_wrong_quotient_is_refused() {
    let events = sample_events(8, 8);
    let honest = Witness::honest(&events[0]).unwrap();
    let carries = honest.carries().unwrap();
    for limb in [0usize, 16, NQ - 1] {
        let mut w = honest.clone();
        w.q[limb] = (w.q[limb] + 1) % 256;
        assert!(w.carries().is_none(), "no carries fit a wrong quotient with the same result");
        assert!(refused(&w, &carries, &events), "quotient limb {limb}");
    }
}

/// Out-of-range limbs. Each forgery re-encodes an honest value with a limb outside `0..256`
/// — `x_i += 256, x_{i+1} −= 1`, or the other way — so the integer is unchanged, the carries
/// can be re-solved and every arithmetic constraint holds. What refuses it is the `RANGE8`
/// lookup of the limb the range table does not have.
#[test]
fn out_of_range_limbs_are_refused_by_the_range_lookups_alone() {
    let events = sample_events(9, 8);
    let honest = Witness::honest(&events[0]).unwrap();
    type Pick = fn(&mut Witness) -> &mut [i64];
    let fields: [(&str, Pick); 6] = [
        ("a", |w| &mut w.a[..]),
        ("b", |w| &mut w.b[..]),
        ("c", |w| &mut w.c[..]),
        ("p", |w| &mut w.p[..]),
        ("q", |w| &mut w.q[..]),
        ("r", |w| &mut w.r[..]),
    ];
    for (name, pick) in fields {
        for up in [true, false] {
            let mut w = honest.clone();
            let limbs = pick(&mut w);
            // A position where the re-encoding leaves the neighbour a byte.
            let i = (0..limbs.len() - 1).find(|i| if up { limbs[i + 1] >= 1 } else { limbs[i + 1] <= 254 }).unwrap();
            if up {
                limbs[i] += 256;
                limbs[i + 1] -= 1;
            } else {
                limbs[i] -= 256;
                limbs[i + 1] += 1;
            }
            if name == "p" || name == "r" {
                w.solve_d();
            }
            let Some(carries) = w.carries() else { panic!("{name}: the re-encoded limbs keep the integer identity") };
            // p and r also feed the canonical chain, whose byte-wise equations a re-encoding
            // breaks; for the other four every arithmetic constraint holds and only the lookup fails.
            if name != "p" && name != "r" {
                assert!(row_holds(&row_of(&w, &carries)), "{name} ({up}): every arithmetic constraint holds");
            }
            assert!(refused(&w, &carries, &events), "{name}, limb {i}, {}", if up { "+256" } else { "-256" });
        }
    }
}

/// An out-of-range carry limb: the same carry, its low byte 256 too large and its high byte
/// one smaller. The limb equations hold; the lookup does not.
#[test]
fn an_out_of_range_carry_limb_is_refused() {
    let events = sample_events(10, 8);
    let w = Witness::honest(&events[0]).unwrap();
    let carries = w.carries().unwrap();
    let (mut t, range) = forged_trace(&events, &w, &carries);
    for k in [0usize, 31, NCARRY - 1] {
        let (lo, hi) = (t.values[col::CL + k], t.values[col::CH + k]);
        t.values[col::CL + k] = lo + F::from_u64(256);
        t.values[col::CH + k] = hi - F::ONE;
        assert!(row_holds(&t.values[..col::WIDTH]), "carry {k}: the limb equations still hold");
        assert!(rejects(|| prove_and_verify(&t, &range).0), "carry {k}");
        (t.values[col::CL + k], t.values[col::CH + k]) = (lo, hi);
    }
    // And the harness is sound: the restored trace verifies.
    prove_and_verify(&t, &range).0.expect("the restored honest trace verifies");
}

/// A row that claims `IS_REAL = 1` for limbs taken from another operation's result.
#[test]
fn a_row_with_another_operations_result_is_refused() {
    let events = sample_events(11, 8);
    let mut w = Witness::honest(&events[0]).unwrap();
    let other = Witness::honest(&events[1]).unwrap();
    let carries = w.carries().unwrap();
    w.r = other.r;
    w.q = other.q;
    w.solve_d();
    assert!(refused(&w, &carries, &events));
    let _ = mm::CARRY_OFFSET;
}
