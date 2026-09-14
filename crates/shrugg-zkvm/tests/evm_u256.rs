//! `evm_core::u256` against `num-bigint`: every 256-bit routine the EVM's arithmetic opcodes
//! need, checked on random operand pairs drawn to hit the carry paths (full-width values, small
//! values, values one or two below 2^256, and values with only the top and bottom limbs set).
//! `num-bigint` is the oracle for all of it — none of the expected values are hand-derived.

use evm_core::u256::U256;
use num_bigint::{BigInt, BigUint, Sign};
use rand::{RngExt, SeedableRng};

fn big(u: &U256) -> BigUint {
    BigUint::from_bytes_be(&u.to_be_bytes())
}
fn signed(u: &U256) -> BigInt {
    let b = BigInt::from_biguint(Sign::Plus, big(u));
    if u.is_neg() {
        b - (BigInt::from(1u8) << 256)
    } else {
        b
    }
}
fn modulus() -> BigUint {
    BigUint::from(1u8) << 256
}
fn rnd(rng: &mut impl RngExt) -> U256 {
    // mix full-width values with small ones and with values near 2^256 so every carry path is hit
    match rng.random_range(0..4) {
        0 => U256(core::array::from_fn(|_| rng.random())),
        1 => U256::from_u64(rng.random()),
        2 => U256::MAX.sub(&U256::from_u32(rng.random_range(0..3))),
        _ => {
            let mut l = [0u32; 8];
            l[7] = rng.random();
            l[0] = rng.random();
            U256(l)
        }
    }
}

#[test]
fn arithmetic_matches_num_bigint_on_ten_thousand_random_pairs() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(43);
    let m = modulus();
    for _ in 0..10_000 {
        let (a, b) = (rnd(&mut rng), rnd(&mut rng));
        let (ba, bb) = (big(&a), big(&b));
        assert_eq!(big(&a.add(&b)), (&ba + &bb) % &m);
        assert_eq!(big(&a.sub(&b)), (&ba + &m - &bb) % &m);
        assert_eq!(big(&a.mul(&b)), (&ba * &bb) % &m);
        if !b.is_zero() {
            assert_eq!(big(&a.div(&b)), &ba / &bb);
            assert_eq!(big(&a.rem(&b)), &ba % &bb);
        } else {
            assert_eq!(a.div(&b), U256::ZERO);
            assert_eq!(a.rem(&b), U256::ZERO);
        }
    }
}

#[test]
fn signed_division_and_modulo_follow_the_evm() {
    // EVM: SDIV truncates toward zero; SMOD takes the dividend's sign; MIN / -1 = MIN; x / 0 = 0.
    let mut rng = rand::rngs::StdRng::seed_from_u64(44);
    for _ in 0..10_000 {
        let (a, b) = (rnd(&mut rng), rnd(&mut rng));
        let (sa, sb) = (signed(&a), signed(&b));
        if sb.sign() == Sign::NoSign {
            assert_eq!(a.sdiv(&b), U256::ZERO);
            assert_eq!(a.smod(&b), U256::ZERO);
            continue;
        }
        // BigInt division truncates toward zero, remainder has the dividend's sign
        let q = &sa / &sb;
        let r = &sa % &sb;
        assert_eq!(
            signed(&a.sdiv(&b)),
            if q == (BigInt::from(1u8) << 255) {
                -(BigInt::from(1u8) << 255u32)
            } else {
                q
            }
        );
        assert_eq!(signed(&a.smod(&b)), r);
    }
    let min = {
        let mut l = [0u32; 8];
        l[7] = 0x8000_0000;
        U256(l)
    };
    assert_eq!(min.sdiv(&U256::MAX), min);
    assert_eq!(min.smod(&U256::MAX), U256::ZERO);
}

#[test]
fn modular_ops_use_a_wide_intermediate() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(45);
    let m = modulus();
    for _ in 0..10_000 {
        let (a, b, n) = (rnd(&mut rng), rnd(&mut rng), rnd(&mut rng));
        let (ba, bb, bn) = (big(&a), big(&b), big(&n));
        if n.is_zero() {
            assert_eq!(a.addmod(&b, &n), U256::ZERO);
            assert_eq!(a.mulmod(&b, &n), U256::ZERO);
            continue;
        }
        assert_eq!(big(&a.addmod(&b, &n)), (&ba + &bb) % &bn); // NOT (a + b mod 2^256) mod n
        assert_eq!(big(&a.mulmod(&b, &n)), (&ba * &bb) % &bn);
    }
    assert_eq!(
        big(&U256::MAX.addmod(&U256::MAX, &U256::from_u32(7))),
        (&m - 1u8 + &m - 1u8) % 7u8
    );
}

#[test]
fn exp_shifts_byte_and_signextend() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(46);
    let m = modulus();
    for _ in 0..2_000 {
        let a = rnd(&mut rng);
        let e = U256::from_u32(rng.random_range(0..300));
        assert_eq!(big(&a.exp(&e)), big(&a).modpow(&big(&e), &m));
        let n = rng.random_range(0..300u32);
        let sh = U256::from_u32(n);
        assert_eq!(
            big(&a.shl(&sh)),
            if n >= 256 {
                BigUint::ZERO
            } else {
                (big(&a) << n) % &m
            }
        );
        assert_eq!(
            big(&a.shr(&sh)),
            if n >= 256 { BigUint::ZERO } else { big(&a) >> n }
        );
        let sar = signed(&a) >> n.min(255);
        assert_eq!(
            signed(&a.sar(&sh)),
            if n >= 256 {
                if a.is_neg() {
                    BigInt::from(-1)
                } else {
                    BigInt::ZERO
                }
            } else {
                sar
            }
        );
    }
    // BYTE: index 0 is the most significant byte; index >= 32 is zero.
    let v = U256::from_be_bytes(&core::array::from_fn(|i| i as u8));
    assert_eq!(v.byte(&U256::from_u32(0)), U256::ZERO);
    assert_eq!(v.byte(&U256::from_u32(31)), U256::from_u32(31));
    assert_eq!(v.byte(&U256::from_u32(32)), U256::ZERO);
    assert_eq!(v.byte(&U256::MAX), U256::ZERO);
    // SIGNEXTEND b: sign-extend from byte b (0 = lowest byte); b >= 31 is the identity.
    assert_eq!(U256::from_u32(0xff).signextend(&U256::from_u32(0)), U256::MAX);
    assert_eq!(
        U256::from_u32(0x7f).signextend(&U256::from_u32(0)),
        U256::from_u32(0x7f)
    );
    assert_eq!(
        U256::from_u32(0x80ff).signextend(&U256::from_u32(1)),
        U256::MAX.sub(&U256::from_u32(0x7f00))
    );
    assert_eq!(v.signextend(&U256::from_u32(31)), v);
    assert_eq!(v.signextend(&U256::MAX), v);
    // EXP with a zero exponent is 1 even for 0^0.
    assert_eq!(U256::ZERO.exp(&U256::ZERO), U256::ONE);
}

/// Not in the M4.3 plan's test list, but `lt`/`slt`/`xor`/`low_u64` are part of Task 1's
/// interface and nothing else in this file exercises them; the same oracle covers them for free,
/// and `LT`/`GT`/`SLT`/`SGT` are where an off-by-one limb comparison would otherwise hide until
/// Task 3's `revm` differential.
#[test]
fn comparison_and_bitwise_match_num_bigint() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(47);
    for _ in 0..10_000 {
        let (a, b) = (rnd(&mut rng), rnd(&mut rng));
        assert_eq!(a.lt(&b), big(&a) < big(&b));
        assert_eq!(a.slt(&b), signed(&a) < signed(&b));
        assert_eq!(big(&a.and(&b)), big(&a) & big(&b));
        assert_eq!(big(&a.or(&b)), big(&a) | big(&b));
        assert_eq!(big(&a.xor(&b)), big(&a) ^ big(&b));
        assert_eq!(big(&a.not()), big(&U256::MAX) ^ big(&a));
        let low64: u64 = (big(&a) % (BigUint::from(1u8) << 64u32)).try_into().unwrap();
        assert_eq!(a.low_u64(), low64);
    }
    assert!(!U256::ZERO.lt(&U256::ZERO));
    assert!(U256::MAX.slt(&U256::ZERO)); // -1 < 0
    assert!(!U256::MAX.lt(&U256::ZERO)); // 2^256 - 1 > 0 unsigned
}

#[test]
fn byte_conversions_round_trip_and_pushn_right_aligns() {
    let bytes: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
    let v = U256::from_be_bytes(&bytes);
    assert_eq!(v.to_be_bytes(), bytes);
    assert_eq!(
        v.0[0],
        u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]])
    );
    assert_eq!(U256::from_be_slice(&[0x12, 0x34]), U256::from_u32(0x1234));
    assert_eq!(U256::from_be_slice(&[]), U256::ZERO);
    assert_eq!(U256::from_u64(0x1_0000_0000).0, [0, 1, 0, 0, 0, 0, 0, 0]);
    assert!(U256::from_u32(5).fits_u32());
    assert!(!U256::from_u64(1 << 40).fits_u32());
    assert_eq!(U256::from_u32(0x100).bit_len(), 9);
    assert_eq!(U256::ZERO.bit_len(), 0);
    assert_eq!(U256::from_u32(0x100).byte_len(), 2);
}
