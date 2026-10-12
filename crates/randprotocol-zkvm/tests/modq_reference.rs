//! MODQ phase 3, Task 1: the reference semantics agree with dilithium-core mod q.

fn canon(x: i64) -> u32 { x.rem_euclid(randprotocol_zkvm::modq::Q as i64) as u32 }

#[test]
fn modq_agrees_with_the_reference_ntt_invntt_and_montgomery_product_mod_q() {
    use dilithium_core::{ntt, reduce::montgomery_reduce};
    use randprotocol_zkvm::modq;
    let q = modq::Q as i64;
    let mont = (1i64 << 32) % q;                                   // 4 193 792
    let mont_inv = (1..q).find(|x| x * mont % q == 1).unwrap();
    let mut s = 7u64;
    let mut next = move || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    for _ in 0..40 {
        let a: [i32; 256] = core::array::from_fn(|_| (next() % (2 * q as u64 - 1)) as i32 - (q as i32 - 1));
        let ac: [u32; 256] = core::array::from_fn(|i| canon(a[i] as i64));
        let (mut r, mut m) = (a, ac);
        ntt::ntt(&mut r);
        modq::ntt(&mut m);
        assert_eq!(m, core::array::from_fn(|i| canon(r[i] as i64)), "ntt ≡ reference ntt");
        let (mut r, mut m) = (a, ac);
        ntt::invntt_tomont(&mut r);
        modq::intt(&mut m);
        assert_eq!(core::array::from_fn::<u32, 256, _>(|i| canon(r[i] as i64)),
                   core::array::from_fn(|i| canon(m[i] as i64 * mont)), "invntt_tomont ≡ 2^32 · intt");
        for i in 0..256 {
            let (x, y) = (a[i] as i64, a[255 - i] as i64);
            assert_eq!(canon(montgomery_reduce(x * y) as i64), canon(x * y % q * mont_inv), "pointwise_montgomery ≡ a·b·2^-32");
        }
    }
}
