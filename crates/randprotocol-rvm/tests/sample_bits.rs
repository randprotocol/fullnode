//! S1b (phase 5): the query-index `sample_bits` gadget — honest acceptance against p3's
//! `DuplexChallenger::sample_bits`, the edge values, the forgeries the range argument
//! (`docs/10` §S1b) must refuse, and a forged range-LOAD limb refused by the machine.
use p3_challenger::{CanObserve, CanSample, CanSampleBits};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use rand::{RngExt, SeedableRng};
use randprotocol_rvm::dsl::{transcript::{low_bits_gadget, low_bits_tape, DslChallenger}, Builder, Checkpoints, Liveness, Precompiles};
use randprotocol_rvm::emulator::{execute, ExecError};
use randprotocol_rvm::isa::F;

type Chal = randprotocol_zkvm::machine::Challenger;
const P: u64 = 0xFFFF_FFFF_0000_0001;
const BUILDS: [Precompiles; 2] = [Precompiles::On, Precompiles::Off];

fn builder(pc: Precompiles) -> Builder {
    Builder::with_opts(Checkpoints::Off, Liveness::On, pc)
}

/// The trap a refusal must raise: the gadget's own assertion (`INV` of zero) or a range `LOAD`.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Trap {
    InverseOfZero,
    AddressOutOfRange,
}

fn gadget_prog(x: u64, bits: usize, pc: Precompiles) -> randprotocol_rvm::isa::Program {
    let mut b = builder(pc);
    let xh = b.constant(F::from_u64(x));
    let buf = low_bits_gadget(&mut b, xh, bits);
    for k in 0..bits {
        let v = b.load(buf, k as i64);
        b.public(v);
    }
    b.finish()
}

fn honest(x: u64, bits: usize) {
  for pc in BUILDS {
    let p = gadget_prog(x, bits, pc);
    let got = execute(&p, &low_bits_tape(x, bits), 1_000_000).expect("honest accepted").public;
    let want: Vec<F> = (0..bits).map(|k| F::from_u64((x >> k) & 1)).collect();
    assert_eq!(got, want, "x {x:#x} bits {bits} {pc:?}");
  }
}

fn refuse(x: u64, bits: usize, tape: Vec<F>, want: Trap, what: &str) {
  for pc in BUILDS {
    let p = gadget_prog(x, bits, pc);
    let got = match execute(&p, &tape, 1_000_000) {
        Err(ExecError::InverseOfZero { .. }) => Trap::InverseOfZero,
        Err(ExecError::AddressOutOfRange { .. }) => Trap::AddressOutOfRange,
        other => panic!("{what} ({pc:?}): must trap, got {other:?}"),
    };
    assert_eq!(got, want, "{what} ({pc:?}): trapped for the wrong reason");
  }
}

#[test]
fn honest_random_and_edges() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for bits in [8usize, 19, 20, 24, 27, 32] {
        for x in [0, 1, 2, (1u64 << 32) - 2, (1u64 << 32) - 1, 1u64 << 32, P - 2, P - 1] {
            honest(x, bits);
        }
        for _ in 0..200 {
            honest(rng.random::<u64>() % P, bits);
        }
    }
}

#[test]
fn matches_native_challenger() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(9);
    for bits in [8usize, 19, 20, 27] {
        let seed = F::from_u64(rng.random::<u64>() % P);
        let mut nat = Chal::new(randprotocol_zkvm::machine::permutation());
        nat.observe(seed);
        let want = nat.sample_bits(bits);
        let mut nat2 = Chal::new(randprotocol_zkvm::machine::permutation());
        nat2.observe(seed);
        let x: F = nat2.sample();
      for pc in BUILDS {
        let mut b = builder(pc);
        let mut ch = DslChallenger::new(&mut b);
        let s = b.constant(seed);
        ch.observe(&mut b, s);
        let buf = ch.sample_index_bits(&mut b, bits);
        for k in 0..bits {
            let v = b.load(buf, k as i64);
            b.public(v);
        }
        let got = execute(&b.finish(), &low_bits_tape(x.as_canonical_u64(), bits), 1_000_000).unwrap().public;
        let want_bits: Vec<F> = (0..bits).map(|k| F::from_u64(((want as u64) >> k) & 1)).collect();
        assert_eq!(got, want_bits, "{pc:?}");
      }
    }
}

/// Tape from explicit integer limbs (field-encoded), `u` chosen as the best a cheater can do.
fn tape(bitsv: u64, bits: usize, a: F, h0: F, h1: F, u: F) -> Vec<F> {
    let mut t: Vec<F> = (0..bits).map(|k| F::from_u64((bitsv >> k) & 1)).collect();
    t.extend([a, h0, h1, u]);
    t
}

#[test]
fn refuses_the_non_canonical_alias() {
    // X = x + p for small x: H = 2^32 − 1, L = x + 1. d = 0, so d·u = 0 ≠ L for every u.
    for bits in [8usize, 19, 32] {
        for x in [0u64, 1, 5, 12345, (1 << 32) - 2] {
            let xx = x as u128 + P as u128;
            assert!(xx < 1u128 << 64);
            let l = (xx & 0xFFFF_FFFF) as u64;
            let h = (xx >> 32) as u64;
            assert_eq!(h, 0xFFFF_FFFF);
            for u in [F::ZERO, F::ONE, F::from_u64(l)] {
                let t = tape(l, bits, F::from_u64(l >> bits), F::from_u64(h & 0xFF_FFFF), F::from_u64(h >> 24), u);
                refuse(x, bits, t, Trap::InverseOfZero, &format!("alias x={x} bits={bits}"));
            }
        }
    }
}

#[test]
fn refuses_a_shifted_index_or_limb() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    for bits in [8usize, 19, 27] {
        for _ in 0..50 {
            let x = rng.random::<u64>() % P;
            let lo = x & 0xFFFF_FFFF;
            let hi = x >> 32;
            let two_b_inv = F::from_u64(1u64 << bits).inverse();
            // 1. A different index, `a` solved for in the field: `a'` is out of range.
            let idx = lo & ((1 << bits) - 1);
            let idx2 = (idx + 1 + rng.random::<u64>() % ((1 << bits) - 1)) & ((1 << bits) - 1);
            assert_ne!(idx, idx2);
            let a2 = (F::from_u64(lo) - F::from_u64(idx2)) * two_b_inv;
            let d = F::from_u64(hi) - F::from_u64(0xFFFF_FFFF);
            let u = if d == F::ZERO { F::ZERO } else { F::from_u64(lo) * d.inverse() };
            let t = tape(idx2, bits, a2, F::from_u64(hi & 0xFF_FFFF), F::from_u64(hi >> 24), u);
            refuse(x, bits, t, Trap::AddressOutOfRange, "shifted index");
            // 2. A different index with `h0` absorbing the difference: h0' = h0 + (idx − idx2)/2^32.
            let h0b = F::from_u64(hi & 0xFF_FFFF) + (F::from_u64(idx) - F::from_u64(idx2)) * F::from_u64(1 << 32).inverse();
            let lo2 = F::from_u64(idx2 + ((lo >> bits) << bits));
            let hi2 = h0b + F::from_u64((hi >> 24) << 24);
            let d2 = hi2 - F::from_u64(0xFFFF_FFFF);
            let u2 = if d2 == F::ZERO { F::ZERO } else { lo2 * d2.inverse() };
            let t = tape(idx2, bits, F::from_u64(lo >> bits), h0b, F::from_u64(hi >> 24), u2);
            refuse(x, bits, t, Trap::AddressOutOfRange, "index difference in h0");
            // 3. h1 out of range, h0 compensating (h1 + 1, h0 − 2^24).
            let h0c = F::from_u64(hi & 0xFF_FFFF) - F::from_u64(1 << 24);
            let t = tape(lo, bits, F::from_u64(lo >> bits), h0c, F::from_u64((hi >> 24) + 1), u);
            refuse(x, bits, t, Trap::AddressOutOfRange, "h0 negative");
            // 4. a non-boolean bit 0 carrying the whole low half.
            let mut t = tape(0, bits, F::ZERO, F::from_u64(hi & 0xFF_FFFF), F::from_u64(hi >> 24), u);
            t[0] = F::from_u64(lo);
            if lo > 1 {
                refuse(x, bits, t, Trap::InverseOfZero, "non-boolean bit");
            }
        }
    }
}

/// The honest gadget proves and verifies at the widths in use (19, the old claim, and 20, the
/// production width: `log_global_max_height` 17 + `INNER_LOG_BLOWUP` 3); a forged range-LOAD limb
/// is refused by the machine (a prover constraint panic or a verify error both count, as in
/// `cheating.rs`'s `rejects()`), not by `Machine::verify` alone.
#[test]
fn the_gadget_proves_and_verifies_on_the_machine() {
    for bits in [19usize, 20] {
        proves_and_refuses_a_forged_limb(bits);
    }
}

fn proves_and_refuses_a_forged_limb(bits: usize) {
    use randprotocol_rvm::machine::{build_traces, FriProfile, Machine, Tier};
    let x = 0x1234_5678_9abc_def0u64 % P;
    let mut b = Builder::new(Checkpoints::Off);
    let xh = b.constant(F::from_u64(x));
    let buf = low_bits_gadget(&mut b, xh, bits);
    for k in 0..4 {
        let v = b.load(buf, k as i64);
        b.public(v);
    }
    let p = b.finish();
    let exec = execute(&p, &low_bits_tape(x, bits), 1_000_000).unwrap();
    let m = Machine::new(FriProfile::Test);
    let t = build_traces(&p, &exec, Tier(10)).unwrap();
    let proof = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p, &proof).unwrap();
    // A range LOAD row's limb forged: rejected (the mechanism the range checks rely on).
    let w = randprotocol_rvm::tables::cpu::col::WIDTH;
    let row = exec.events.iter().position(|e| e.instr.op == randprotocol_rvm::isa::Op::Load && e.instr.rd == 0).unwrap();
    let mut t2 = t;
    t2.cpu.values[row * w + randprotocol_rvm::tables::cpu::col::LIMB2] += F::ONE;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = m.prove_traces(&p, &t2, Tier(10));
        m.verify(&p, &proof)
    }));
    assert!(matches!(r, Err(_) | Ok(Err(_))), "a forged range limb must be refused");
}

/// Review Focus 4: the range argument holds for 8 ≤ bits ≤ 32 only; any other width is refused
/// when the program is built, by name.
#[test]
#[should_panic(expected = "sample_index_bits")]
fn a_width_below_eight_is_refused_at_build() {
    let mut b = Builder::new(Checkpoints::Off);
    let x = b.constant(F::from_u64(5));
    low_bits_gadget(&mut b, x, 7);
}

#[test]
#[should_panic(expected = "sample_index_bits")]
fn a_width_above_thirty_two_is_refused_at_build() {
    let mut b = Builder::new(Checkpoints::Off);
    let x = b.constant(F::from_u64(5));
    low_bits_gadget(&mut b, x, 33);
}

/// The tape is `bits` booleans then `a, h0, h1, u`: `bits + 4` words, the limbs the canonical ones.
#[test]
fn the_tape_is_the_bits_then_four_limbs() {
    for (v, bits) in [(P - 1, 19usize), (0x1234_5678_9abc_def0 % P, 8), ((1u64 << 32) - 1, 32)] {
        let t = low_bits_tape(v, bits);
        assert_eq!(t.len(), bits + 4);
        let (lo, hi) = (v & 0xFFFF_FFFF, v >> 32);
        assert_eq!(t[bits], F::from_u64(lo >> bits));
        assert_eq!(t[bits + 1], F::from_u64(hi & 0xFF_FFFF));
        assert_eq!(t[bits + 2], F::from_u64(hi >> 24));
    }
}

// ── RVM-201: an isolating test for each of the five S1b assertions that had no behavioural test ──
//
// The gadget has nine soundness assertions: every bit boolean (the top bit's, then the other
// `bits − 1`), the paired range loads on `a` (lower, upper) and on `h0`/`h1` (`h0` lower only; `h1`
// lower, upper), the canonicality equation and the decomposition equation. Four were exercised
// above; these five were not: the top bit's booleanity, `a`'s upper bound, `h1`'s lower and upper
// bounds, and the decomposition equality.
//
// Each test hands the gadget a tape that satisfies EVERY assertion but the one under test
// (derived by hand in the comments), and checks three things:
//   1. the real gadget refuses it, with the trap that assertion raises;
//   2. MUTATION CONTROL: `mutant_prog` is the gadget re-built here assertion for assertion with
//      exactly the target assertion deleted (`Skip`) — it ACCEPTS the same tape, so the real
//      gadget's refusal is that assertion's and nothing else's. Deleting the assertion from
//      `low_bits_gadget` has the same effect as the mutant: the refusal in (1) would vanish and
//      the test fail. `the_mutant_with_nothing_deleted_is_the_gadget` pins the copy to the real
//      program so the control cannot drift from it;
//   3. every OTHER single deletion still refuses the tape (the target is still there to catch it).

#[derive(Clone, Copy, Debug, PartialEq)]
enum Skip {
    None,
    TopBool,
    ALo,
    AHi,
    H0,
    H1Lo,
    H1Hi,
    Canon,
    Decomp,
}
const ALL_SKIPS: [Skip; 8] = [Skip::TopBool, Skip::ALo, Skip::AHi, Skip::H0, Skip::H1Lo, Skip::H1Hi, Skip::Canon, Skip::Decomp];

/// `low_bits_gadget` on the constant `x`, its low bits published, with one assertion deleted.
fn mutant_prog(x: u64, bits: usize, pc: Precompiles, skip: Skip) -> randprotocol_rvm::isa::Program {
    let mut b = builder(pc);
    let xh = b.constant(F::from_u64(x));
    let arr = b.hint_array_padded(bits, 65 - bits);
    let top = bits - 1;
    let mut idx = b.get(arr, top);
    if skip != Skip::TopBool {
        let sq = b.mul(idx, idx);
        b.assert_eq(sq, idx, &format!("sample_bits bit {top}"));
    }
    for k in (0..top).rev() {
        let bk = b.get(arr, k);
        let sq = b.mul(bk, bk);
        b.assert_eq(sq, bk, &format!("sample_bits bit {k}"));
        let d = b.mul_const(idx, F::TWO);
        idx = b.add(d, bk);
    }
    let a = b.hint();
    let h0 = b.hint();
    let h1 = b.hint();
    let u = b.hint();
    let wa = 32 - bits;
    if skip != Skip::ALo {
        b.range_load(a, 0);
    }
    if wa < 24 && skip != Skip::AHi {
        b.range_load(a, (1u64 << 24) - (1u64 << wa));
    }
    if skip != Skip::H0 {
        b.range_load(h0, 0);
    }
    if skip != Skip::H1Lo {
        b.range_load(h1, 0);
    }
    if skip != Skip::H1Hi {
        b.range_load(h1, (1u64 << 24) - (1u64 << 8));
    }
    let a_sh = b.mul_const(a, F::from_u64(1u64 << bits));
    let lo = b.add(idx, a_sh);
    let h1_sh = b.mul_const(h1, F::from_u64(1u64 << 24));
    let hi = b.add(h0, h1_sh);
    let d = b.add_const(hi, -F::from_u64(0xFFFF_FFFF));
    let du = b.mul(d, u);
    if skip != Skip::Canon {
        b.assert_eq(du, lo, "sample_bits canonicality");
    }
    let shifted = b.mul_const(hi, F::from_u64(1 << 32));
    let sum = b.add(lo, shifted);
    if skip != Skip::Decomp {
        b.assert_eq(sum, xh, "sample_bits decomposition");
    }
    let buf = arr.base;
    for k in 0..bits {
        let v = b.load(buf, k as i64);
        b.public(v);
    }
    b.finish()
}

#[test]
fn the_mutant_with_nothing_deleted_is_the_gadget() {
    for bits in [8usize, 19, 32] {
        for pc in BUILDS {
            let real = gadget_prog(0x1234_5678_9abc_def0 % P, bits, pc);
            let copy = mutant_prog(0x1234_5678_9abc_def0 % P, bits, pc, Skip::None);
            assert_eq!(real.instrs, copy.instrs, "bits {bits} {pc:?}: the mutation control drifted from low_bits_gadget");
        }
    }
}

fn trap_of(p: &randprotocol_rvm::isa::Program, tape: &[F]) -> Result<Vec<F>, Trap> {
    match execute(p, tape, 1_000_000) {
        Ok(e) => Ok(e.public),
        Err(ExecError::InverseOfZero { .. }) => Err(Trap::InverseOfZero),
        Err(ExecError::AddressOutOfRange { .. }) => Err(Trap::AddressOutOfRange),
        Err(other) => panic!("unexpected execution error {other:?}"),
    }
}

/// The three checks above for `tape` against the constant `x`, target assertion `target`.
/// Returns what the mutant published, so a caller can show the deletion is not harmless.
fn isolating(what: &str, x: u64, bits: usize, tape: &[F], want: Trap, target: Skip) -> Vec<F> {
    let mut mutant_out = Vec::new();
    for pc in BUILDS {
        let real = trap_of(&gadget_prog(x, bits, pc), tape);
        assert_eq!(real, Err(want), "{what} x={x:#x} bits={bits} {pc:?}: the real gadget must refuse with {want:?}");
        mutant_out = trap_of(&mutant_prog(x, bits, pc, target), tape)
            .unwrap_or_else(|t| panic!("{what} x={x:#x} bits={bits} {pc:?}: with {target:?} deleted the tape must be ACCEPTED, trapped {t:?} (another assertion also catches it: not isolating)"));
        for other in ALL_SKIPS.into_iter().filter(|s| *s != target) {
            assert!(trap_of(&mutant_prog(x, bits, pc, other), tape).is_err(), "{what} {pc:?}: deleting {other:?} must not let the tape through");
        }
    }
    mutant_out
}

fn honest_bits(x: u64, bits: usize) -> Vec<F> {
    (0..bits).map(|k| F::from_u64((x >> k) & 1)).collect()
}

/// Top bit: `b_top' = b_top + 2`, `a' = a − 1`. Then `idx' = idx + 2^bits` and `L' = L`, so
/// canonicality and decomposition hold, every range holds (`a' < a`), and only `b_top·b_top = b_top`
/// is false.
#[test]
fn refuses_a_non_boolean_top_bit() {
    for bits in [8usize, 19, 27] {
        for x in [0xA5A5_5A5Au64 | 0x0012_3400_0000_0000, 0xFFFF_FFFFu64, 0x8000_0000 | 1 << 40] {
            let (lo, hi) = (x & 0xFFFF_FFFF, x >> 32);
            assert!(lo >> bits >= 1, "x needs a >= 1");
            let mut t: Vec<F> = honest_bits(lo, bits);
            t[bits - 1] += F::TWO;
            let d = F::from_u64(hi) - F::from_u64(0xFFFF_FFFF);
            let u = if d == F::ZERO { F::ZERO } else { F::from_u64(lo) * d.inverse() };
            t.extend([F::from_u64((lo >> bits) - 1), F::from_u64(hi & 0xFF_FFFF), F::from_u64(hi >> 24), u]);
            let out = isolating("top bit", x, bits, &t, Trap::InverseOfZero, Skip::TopBool);
            assert_ne!(out, honest_bits(x, bits), "the deleted assertion lets a non-boolean index bit through");
        }
    }
}

/// `a`'s upper bound (`bits = 19`: `a < 2^13`): `a' = a + 2^13`, so `L' = L + 2^32`, and `H' = H − 1`
/// restores `L' + 2^32·H' = x`. `a'` is still `< 2^24` and `H' ≥ 0` is in range; canonicality holds
/// with `u = L'/(H' − (2^32 − 1))`. Only `a < 2^13` is false. (`idx` is unchanged — `2^32 ≡ 0`
/// modulo `2^bits` — so this bound is defence in depth for the index, not an output forgery.)
#[test]
fn refuses_a_above_its_upper_bound() {
    for bits in [16usize, 19, 27] {
        let wa = 32 - bits;
        for x in [(5u64 << 32) | 0x0001_2345, (1u64 << 32) | 0xFFFF, 0x1234_5678_9abc_def0 % P] {
            let (lo, hi) = (x & 0xFFFF_FFFF, x >> 32);
            assert!(hi >= 1);
            let a2 = (lo >> bits) + (1u64 << wa);
            assert!(a2 < 1 << 24);
            let h = hi - 1;
            let lo2 = F::from_u64(lo) + F::from_u64(1 << 32);
            let d = F::from_u64(h) - F::from_u64(0xFFFF_FFFF);
            let u = if d == F::ZERO { F::ZERO } else { lo2 * d.inverse() };
            let t = tape(lo, bits, F::from_u64(a2), F::from_u64(h & 0xFF_FFFF), F::from_u64(h >> 24), u);
            isolating("a upper", x, bits, &t, Trap::AddressOutOfRange, Skip::AHi);
        }
    }
}

/// `h1`'s lower bound: the negative alias `X = x − p ≡ x`. Write `X = L + 2^32·H'` with `L ∈ [0,2^32)`
/// and `H' ∈ [−2^32, −1]`; then `h1' = ⌊H'/2^24⌋ ∈ [−256, −1]`, `h0' = H' mod 2^24`. `h1' + 2^24 − 2^8`
/// is in `[0, 2^24)`, so the upper bound is satisfied; `h0'`, `a`, `idx` are in range; `H' ≠ 2^32 − 1`
/// so `u = L/(H' − (2^32 − 1))` satisfies canonicality. Only `h1 < 2^24` (the field value `p − |h1'|`)
/// is false. The deleted assertion is not harmless: the index decodes `x − 1`, not `x`
/// (`−p ≡ −1` modulo `2^32`).
#[test]
fn refuses_a_negative_h1() {
    for bits in [8usize, 19, 32] {
        for x in [0u64, 7, 12345, (1 << 32) + 3, 0x1234_5678_9abc_def0 % P, P - 1] {
            let big_x = x as i128 - P as i128;
            let l = big_x.rem_euclid(1 << 32) as u64;
            let hh = big_x.div_euclid(1 << 32); // H' in [-2^32, -1]
            let h1 = hh.div_euclid(1 << 24); // in [-256, -1]
            let h0 = hh.rem_euclid(1 << 24) as u64;
            assert!((-256..0).contains(&h1));
            let h1f = -F::from_u64((-h1) as u64);
            let hhf = F::from_u64(h0) + F::from_u64(1 << 24) * h1f;
            let d = hhf - F::from_u64(0xFFFF_FFFF);
            assert_ne!(d, F::ZERO);
            let u = F::from_u64(l) * d.inverse();
            let t = tape(l, bits, F::from_u64(l >> bits), F::from_u64(h0), h1f, u);
            let out = isolating("h1 lower", x, bits, &t, Trap::AddressOutOfRange, Skip::H1Lo);
            if bits < 32 && x & ((1 << bits) - 1) != (x.wrapping_sub(1) & ((1 << bits) - 1)) {
                assert_ne!(out, honest_bits(x, bits), "the deleted bound lets the index of x − 1 through");
            }
        }
    }
}

/// `h1`'s upper bound: `x = hi·2^32 + (2^32 − 1)`. Take `L' = 0`, `H' = hi + 2^32` (`h1' = ⌊hi/2^24⌋ + 256`,
/// still `< 2^24`, so the lower bound holds). Then `L' + 2^32·H' = 2^32·hi + 2^64 ≡ 2^32·hi + 2^32 − 1 = x`
/// (`2^64 ≡ 2^32 − 1`), canonicality holds with `u = 0` (`L' = 0`, `H' ≠ 2^32 − 1` as a field value),
/// every other range holds. Only `h1 < 2^8` is false — and the deleted bound is not harmless: the
/// index decodes `0`, where `x`'s low bits are all ones.
#[test]
fn refuses_h1_above_its_upper_bound() {
    for bits in [8usize, 19, 32] {
        for hi in [0u64, 5, 0x00AB_CDEF] {
            let x = (hi << 32) | 0xFFFF_FFFF;
            let h1 = (hi >> 24) + 256;
            let t = tape(0, bits, F::ZERO, F::from_u64(hi & 0xFF_FFFF), F::from_u64(h1), F::ZERO);
            let out = isolating("h1 upper", x, bits, &t, Trap::AddressOutOfRange, Skip::H1Hi);
            assert_ne!(out, honest_bits(x, bits), "the deleted bound lets the index 0 through for an all-ones low half");
        }
    }
}

/// The decomposition equality: an honest tape — every bit, limb and `u` canonical and in range, so
/// every other assertion holds — for a DIFFERENT value `x' ≠ x`. Only `L + 2^32·H = x` is false.
#[test]
fn refuses_a_tape_for_another_value() {
    for bits in [8usize, 19, 32] {
        for (x, other) in [(5u64, 6u64), (0x1234_5678_9abc_def0 % P, 0x1234_5678_9abc_def1 % P), ((1 << 32) - 1, 1 << 32), (P - 1, 0)] {
            let t = low_bits_tape(other, bits);
            let out = isolating("decomposition", x, bits, &t, Trap::InverseOfZero, Skip::Decomp);
            assert_eq!(out, honest_bits(other, bits), "the deleted equality publishes the other value's bits");
        }
    }
}
