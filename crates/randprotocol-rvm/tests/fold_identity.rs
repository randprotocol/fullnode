//! Phase 3, Task 0: the arity-a FRI fold is a size-a inverse DFT on the bit-reversed coset values
//! followed by Horner at `u = β / s` — `out = Σ_m B_m·u^m`, `B_m = (1/a)·Σ_k y_k·c_k^{−m}`,
//! `c_k = g_a^{rev(k)}`, `s = g_{h+la}^{rev(index, h)}` — checked against Plonky3's own
//! `TwoAdicFriFolding::fold_row` (barycentric Lagrange) before any row of the FOLD kind is built.
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
use p3_util::reverse_bits_len;
use rand::{RngExt, SeedableRng};
use randprotocol_rvm::isa::{EF, F};
use std::marker::PhantomData;

mod common;

fn dft_horner(index: usize, log_height: usize, la: usize, beta: EF, ys: &[EF]) -> EF {
    let a = 1usize << la;
    let s = F::two_adic_generator(log_height + la).exp_u64(reverse_bits_len(index, log_height) as u64);
    let g = F::two_adic_generator(la);
    let inv_a = F::from_usize(a).inverse();
    let b: Vec<EF> = (0..a)
        .map(|m| {
            let mut acc = EF::ZERO;
            for (k, y) in ys.iter().enumerate() {
                let ck_inv = g.exp_u64(reverse_bits_len(k, la) as u64).inverse();
                acc += *y * ck_inv.exp_u64(m as u64);
            }
            acc * inv_a
        })
        .collect();
    let u = beta * s.inverse();
    b.iter().rev().fold(EF::ZERO, |acc, &bm| acc * u + bm)
}

#[test]
fn the_fold_is_an_inverse_dft_then_horner_at_every_arity() {
    let folding: TwoAdicFriFolding<(), ()> = TwoAdicFriFolding(PhantomData);
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x0f01d);
    for la in 1..=3usize {
        for _ in 0..256 {
            let log_height = rng.random_range(1..=20usize);
            let index = rng.random_range(0..1usize << log_height);
            let beta = common::random_ext(&mut rng);
            let ys: Vec<EF> = (0..1usize << la).map(|_| common::random_ext(&mut rng)).collect();
            let want = <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<F, EF>>::fold_row(
                &folding, index, log_height, la, beta, ys.iter().copied(),
            );
            assert_eq!(dft_horner(index, log_height, la, beta, &ys), want, "la {la}, h {log_height}, index {index}");
        }
    }
}

/// Cut E2: the emulator's fold (the chip's coefficient table, then Horner) is `fold_row`.
#[test]
fn the_emulators_fold_is_fold_row() {
    let folding: TwoAdicFriFolding<(), ()> = TwoAdicFriFolding(PhantomData);
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x0f02d);
    for la in 1..=3usize {
        for _ in 0..256 {
            let log_height = rng.random_range(1..=20usize);
            let index = rng.random_range(0..1usize << log_height);
            let beta = common::random_ext(&mut rng);
            let ys: Vec<EF> = (0..1usize << la).map(|_| common::random_ext(&mut rng)).collect();
            let s = F::two_adic_generator(log_height + la).exp_u64(reverse_bits_len(index, log_height) as u64);
            let want = <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<F, EF>>::fold_row(&folding, index, log_height, la, beta, ys.iter().copied());
            assert_eq!(randprotocol_rvm::emulator::fold_dft_horner(&ys, beta * s.inverse()), want, "la {la}");
        }
    }
}
