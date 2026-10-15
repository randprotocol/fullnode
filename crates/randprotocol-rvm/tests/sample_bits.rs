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
