//! The DSL is what every rVM program is written in, so these tests pin the three things a program
//! author depends on: the field values a built program emulates to, that the allocator's spills are
//! invisible to the result, and that a failed assertion names its own checkpoint.
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use shrugg_rvm::dsl::{Builder, Checkpoints};
use shrugg_rvm::emulator::{execute, ExecError};
use shrugg_rvm::isa::{EF, F};

fn run(b: Builder, witness: &[F]) -> Vec<F> {
    let p = b.finish();
    execute(&p, witness, 1_000_000).unwrap().public
}


#[test]
fn a_dsl_program_emulates_to_the_expected_field_values() {
    let mut b = Builder::new(Checkpoints::Off);
    let x = b.constant(F::from_u64(7));
    let y = b.constant(F::from_u64(5));
    let s = b.add(x, y);
    let d = b.sub(x, y);
    let m = b.mul(x, y);
    let iv = b.inv(y);
    let one = b.mul(y, iv);
    for v in [s, d, m, one] {
        b.public(v);
    }

    let ex = b.ext_constant(EF::from_basis_coefficients_slice(&[F::from_u64(3), F::ONE]).unwrap());
    let ey = b.ext_constant(EF::from_basis_coefficients_slice(&[F::TWO, F::from_u64(9)]).unwrap());
    let ep = b.ext_mul(ex, ey);
    let ei = b.ext_inv(ex);
    let eone = b.ext_mul(ex, ei);
    b.public_ext(ep);
    b.public_ext(eone);

    let got = run(b, &[]);
    let want_p = EF::from_basis_coefficients_slice(&[F::from_u64(3), F::ONE]).unwrap()
        * EF::from_basis_coefficients_slice(&[F::TWO, F::from_u64(9)]).unwrap();
    let mut want = vec![F::from_u64(12), F::TWO, F::from_u64(35), F::ONE];
    want.extend_from_slice(want_p.as_basis_coefficients_slice());
    want.extend_from_slice(EF::ONE.as_basis_coefficients_slice());
    assert_eq!(got, want);
}

#[test]
fn the_allocator_spills_to_memory_and_the_result_is_unchanged() {
    // 40 live handles against 27 allocatable registers: the allocator must spill.
    let mut b = Builder::new(Checkpoints::Off);
    let vals: Vec<_> = (1..=40u64).map(|k| b.constant(F::from_u64(k))).collect();
    let mut acc = vals[0];
    for v in &vals[1..] {
        acc = b.add(acc, *v);
    }
    b.public(acc);
    let (p, stats) = b.finish_stats();
    assert!(stats.spills > 0, "40 simultaneously-live handles must spill: {stats:?}");
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, vec![F::from_u64(40 * 41 / 2)]);
}

#[test]
fn the_allocator_spills_extension_handles_to_consecutive_cells() {
    // 20 pairs against 13 aligned register pairs: the STOREE/LOADE spill path, which the base-field
    // test above never touches.
    let mut b = Builder::new(Checkpoints::Off);
    let vals: Vec<_> = (1..=20u64)
        .map(|k| {
            let c = [F::from_u64(k), F::from_u64(2 * k)];
            b.ext_constant(EF::from_basis_coefficients_slice(&c).unwrap())
        })
        .collect();
    let mut acc = vals[0];
    for v in &vals[1..] {
        acc = b.ext_add(acc, *v);
    }
    b.public_ext(acc);
    let (p, stats) = b.finish_stats();
    assert!(stats.spills > 0 && stats.reloads > 0, "20 pairs must spill and reload: {stats:?}");
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, [210u64, 420].map(F::from_u64).to_vec());
}

#[test]
fn a_counted_loop_runs_the_expected_number_of_iterations() {
    let mut b = Builder::new(Checkpoints::Off);
    let p = b.alloc(1);
    let z = b.constant(F::ZERO);
    b.store(p, 0, z);
    let n = b.constant(F::from_u64(9));
    b.counted_loop(n, |b, _i| {
        let cur = b.load(p, 0);
        let next = b.add_const(cur, F::from_u64(3));
        b.store(p, 0, next);
    });
    let out = b.load(p, 0);
    b.public(out);
    assert_eq!(run(b, &[]), vec![F::from_u64(27)]);
}

#[test]
fn hint_arrays_read_the_witness_in_order() {
    let mut b = Builder::new(Checkpoints::Off);
    let a = b.hint_array(4);
    let e = b.hint_ext_array(2);
    for k in [3usize, 0, 1] {
        let v = b.get(a, k);
        b.public(v);
    }
    let v = b.get_ext(e, 1);
    b.public_ext(v);
    let w: Vec<F> = (10..18u64).map(F::from_u64).collect();
    assert_eq!(run(b, &w), [13u64, 10, 11, 16, 17].map(F::from_u64).to_vec());
}

#[test]
fn a_failed_assert_eq_halts_at_the_named_checkpoint() {
    let mut b = Builder::new(Checkpoints::Off);
    let x = b.constant(F::from_u64(1));
    let y = b.constant(F::from_u64(2));
    b.assert_eq(x, x, "equal values");
    b.assert_eq(x, y, "the zeta checkpoint");
    b.public(x);
    let p = b.finish();
    match execute(&p, &[], 1_000_000) {
        Err(ExecError::InverseOfZero { pc }) => {
            assert_eq!(p.checkpoint_at(pc), Some("the zeta checkpoint"));
        }
        other => panic!("expected a trap, got {other:?}"),
    }
}

#[test]
fn the_program_digest_of_the_sample_program_is_stable() {
    fn sample() -> shrugg_rvm::isa::Program {
        let mut b = Builder::new(Checkpoints::Off);
        let x = b.constant(F::from_u64(7));
        let y = b.add_const(x, F::from_u64(5));
        let z = b.mul(x, y);
        b.public(z);
        b.finish()
    }
    let a = sample();
    let b2 = sample();
    assert_eq!(a.digest(), b2.digest(), "building twice reproduces the digest");
    assert_eq!(a.instrs.len(), b2.instrs.len());
    // A changed constant is a changed digest.
    let mut c = Builder::new(Checkpoints::Off);
    let x = c.constant(F::from_u64(8));
    let y = c.add_const(x, F::from_u64(5));
    let z = c.mul(x, y);
    c.public(z);
    assert_ne!(a.digest(), c.finish().digest());

    // And the digest is pinned against a committed file, so a change to *how* the builder emits
    // this program — not only to what it computes — has to be a deliberate, reviewed one.
    let pinned = include_str!("dsl-sample.digest").trim();
    assert_eq!(
        hex_digest(a.digest()),
        pinned,
        "the sample program's digest moved; if that is intended, write the new value into \
         recursion/tests/dsl-sample.digest"
    );
}

/// The brief's six tests leave most of the builder's surface unexercised, and Tasks 3–6 are written
/// against all of it, so the rest is covered here: the operations those tests never emit, the
/// pointer/`POSEIDON2` pairing (differentially, against the permutation the machine itself uses),
/// the loop guard, the two assertion forms' names, and the two checkpoint builds.
#[test]
fn the_remaining_operations_match_the_field() {
    let mut b = Builder::new(Checkpoints::Off);
    let z = b.zero();
    let seven = b.constant(F::from_u64(7));
    let c = b.copy(seven);
    let m = b.mul_const(c, F::from_u64(6));
    let plus_zero = b.add(m, z);
    b.public(plus_zero);

    let e = b.ext_lift(seven);
    let k = b.ext_constant(EF::from_basis_coefficients_slice(&[F::ONE, F::TWO]).unwrap());
    let s = b.ext_add(e, k);
    let d = b.ext_sub(s, k);
    let t = b.ext_mul_base(s, m);
    let (c0, c1) = b.ext_parts(t);
    b.public_ext(d);
    b.public(c0);
    b.public(c1);

    // `unrolled` has no allocation restriction, so its body may keep values in registers.
    let cell = b.alloc(1);
    b.store(cell, 0, z);
    b.unrolled(5, |b, i| {
        let cur = b.load(cell, 0);
        let next = b.add_const(cur, F::from_u64(i as u64 + 1));
        b.store(cell, 0, next);
    });
    let sum = b.load(cell, 0);
    b.public(sum);

    // 7·6 = 42; (7 + 0X) + (1 + 2X) − (1 + 2X) = 7 + 0X; (8 + 2X)·42 = 336 + 84X; 1+2+3+4+5 = 15.
    assert_eq!(run(b, &[]), [42u64, 7, 0, 336, 84, 15].map(F::from_u64).to_vec());
}

#[test]
fn poseidon2_permutes_the_eight_cells_at_an_offset_pointer() {
    let mut b = Builder::new(Checkpoints::Off);
    let a = b.hint_array(12);
    let tail = b.offset(a.base, 4);
    b.poseidon2(tail);
    for k in 0..12 {
        let v = b.get(a, k);
        b.public(v);
    }
    let w: Vec<F> = (100..112u64).map(F::from_u64).collect();

    let mut want = w[..4].to_vec();
    let input: [F; 8] = core::array::from_fn(|k| w[4 + k]);
    want.extend_from_slice(&shrugg_zkvm::hash::permute_state(input));
    assert_eq!(run(b, &w), want);
}

#[test]
#[should_panic(expected = "the body moved handle")]
fn a_loop_body_that_evicts_a_pre_existing_handle_is_refused() {
    let mut b = Builder::new(Checkpoints::Off);
    let n = b.constant(F::TWO);
    b.counted_loop(n, |b, _i| {
        // Thirty simultaneously-live handles (kept alive by the fold below) against 25
        // allocatable registers: the counter is the farthest-next-use resident, so the replay
        // evicts it — and a once-emitted body that spills its own counter would not count.
        // (Pre-liveness, thirty dropped handles did the same; liveness frees dead-on-arrival
        // handles instantly, so the pressure now has to be *real*.)
        let vals: Vec<_> = (0..30u64).map(|k| b.constant(F::from_u64(k))).collect();
        let mut s = vals[0];
        for v in &vals[1..] {
            s = b.add(s, *v);
        }
        let _ = s;
    });
    // The invariant is a replay-time property of the emitted-once body's allocation: it fires
    // when the program is built, where the pre-liveness builder caught it at emit time.
    let _ = b.finish();
}

#[test]
#[should_panic(expected = "the iteration count is a compile-time zero")]
fn a_counted_loop_with_a_statically_zero_count_is_refused() {
    // A do-while over a zero counter is not an empty loop, it is a 2^64-iteration one. A count the
    // builder can see is zero is a build-time error rather than a program that never halts.
    let mut b = Builder::new(Checkpoints::Off);
    let n = b.zero();
    b.counted_loop(n, |b, _i| {
        b.constant(F::ONE);
    });
}

#[test]
fn the_assertion_forms_name_their_own_checkpoints() {
    let mut b = Builder::new(Checkpoints::Off);
    let one = b.constant(F::ONE);
    let z = b.zero();
    b.assert_nonzero(one, "a value that is not zero");
    let lifted = b.ext_lift(one);
    let literal = b.ext_constant(EF::ONE);
    b.assert_eq_ext(lifted, literal, "one lifts to one");
    b.assert_nonzero(z, "the zero we planted");
    let p = b.finish();

    let names: Vec<&str> = p.checkpoints.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        names,
        ["a value that is not zero", "one lifts to one (c0)", "one lifts to one (c1)", "the zero we planted"]
    );
    assert!(p.checkpoints.windows(2).all(|w| w[0].0 < w[1].0), "the table must be pc-sorted");
    match execute(&p, &[], 1_000_000) {
        Err(ExecError::InverseOfZero { pc }) => {
            assert_eq!(p.checkpoint_at(pc), Some("the zero we planted"));
        }
        other => panic!("expected a trap, got {other:?}"),
    }
}

/// `ext_inv_checked` is both an inverse and an assertion in one row: it hands back `a⁻¹` and names
/// the `EINV` that computes it, so a zero operand traps at that name. The verifier program's
/// `inv_vanishing` *is* its `Z_H(zeta) != 0` check, which is why the two are one instruction.
#[test]
fn ext_inv_checked_is_the_inverse_and_the_assertion_at_once() {
    // A non-zero operand: the inverse comes back, and nothing traps.
    let mut b = Builder::new(Checkpoints::Off);
    // A genuinely non-base element: `7 + 3·X`.
    let v = EF::from_basis_coefficients_slice(&[F::from_u64(7), F::from_u64(3)]).unwrap();
    let x = b.ext_constant(v);
    let inv = b.ext_inv_checked(x, "x is zero");
    let prod = b.ext_mul(x, inv);
    b.public_ext(prod);
    let p = b.finish();
    assert_eq!(p.checkpoints.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>(), ["x is zero"]);
    assert_eq!(execute(&p, &[], 1_000).unwrap().public, vec![F::ONE, F::ZERO]);

    // A zero operand: the same instruction is the trap, and it resolves to the name.
    let mut b = Builder::new(Checkpoints::Off);
    let z = b.ext_constant(EF::ZERO);
    let _ = b.ext_inv_checked(z, "the zero we planted");
    let p = b.finish();
    match execute(&p, &[], 1_000) {
        Err(ExecError::InverseOfZero { pc }) => {
            assert_eq!(p.checkpoint_at(pc), Some("the zero we planted"));
        }
        other => panic!("expected a trap, got {other:?}"),
    }
}

#[test]
fn checkpoints_publish_only_when_they_are_on_and_record_their_names_either_way() {
    fn build(mode: Checkpoints) -> (Vec<String>, shrugg_rvm::isa::Program) {
        let mut b = Builder::new(mode);
        let x = b.constant(F::from_u64(4));
        let e = b.ext_lift(x);
        b.checkpoint("zeta", e);
        b.public(x);
        let names = b.checkpoint_names().to_vec();
        (names, b.finish())
    }
    let (off_names, off) = build(Checkpoints::Off);
    let (on_names, on) = build(Checkpoints::On);
    assert_eq!(off_names, on_names, "the two builds' checkpoint tables must line up");
    assert_eq!(off_names, ["zeta"]);
    assert_eq!(execute(&off, &[], 1_000).unwrap().public, vec![F::from_u64(4)]);
    assert_eq!(
        execute(&on, &[], 1_000).unwrap().public,
        vec![F::from_u64(4), F::ZERO, F::from_u64(4)]
    );
}

/// The four digest elements as canonical big-endian `u64`s, which is how the committed `.digest`
/// files in this crate are written.
fn hex_digest(d: [F; 4]) -> String {
    use p3_field::PrimeField64;
    d.iter()
        .map(|x| hex::encode(x.as_canonical_u64().to_be_bytes()))
        .collect::<Vec<_>>()
        .join("")
}

// ── Task 7: liveness in the register allocator ────────────────────────────────────────────────

#[test]
fn die_immediately_handles_cost_nothing_and_live_max_is_measured() {
    // Forty sequential constants, each published and dead on the spot: liveness frees each at
    // its last use, so nothing ever spills. (The plan's "spills 0" case; every number below is
    // measured, not a target.)
    let mut b = Builder::new(Checkpoints::Off);
    for k in 0..40u64 {
        let c = b.constant(F::from_u64(k));
        b.public(c);
    }
    let (_p, stats) = b.finish_stats();
    assert_eq!((stats.spills, stats.reloads, stats.live_max), (0, 0, 1), "die-immediately: {stats:?}");

    // The fold's creation phase keeps all 40 constants simultaneously live — the only reason it
    // spills at all — and the fold's progressive deaths stop it at the minimum: 16 spills, 16
    // reloads, a 16-cell arena peak (the pre-liveness allocator spilled and reloaded every one
    // of the 40, keeping them all forever).
    let mut b = Builder::new(Checkpoints::Off);
    let vals: Vec<_> = (1..=40u64).map(|k| b.constant(F::from_u64(k))).collect();
    let mut acc = vals[0];
    for v in &vals[1..] {
        acc = b.add(acc, *v);
    }
    b.public(acc);
    let (_p, stats) = b.finish_stats();
    assert_eq!(
        (stats.spills, stats.reloads, stats.live_max, stats.cells),
        (16, 16, 25, 16),
        "the 40-constant fold, measured: {stats:?}"
    );
}
