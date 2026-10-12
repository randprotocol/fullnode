//! The host side of `dilithium-core`: its `Keccak` over this crate's own permutation.
pub struct HostKeccak;
impl dilithium_core::Keccak for HostKeccak {
    fn permute(&mut self, s: &mut [u64; 25]) { crate::keccak::keccak_f(s) }
}

/// `dilithium_core::ring::Ring` over this crate's `modq` semantics: the emulator's exact
/// arithmetic (canonical outputs, inputs read mod q), applied to the arena in place.
pub struct HostModq;
impl dilithium_core::ring::Ring for HostModq {
    fn ntt(&mut self, ar: &mut dilithium_core::ring::Arena, p: usize) {
        crate::modq::ntt(&mut ar.p[p]);
    }
    fn intt(&mut self, ar: &mut dilithium_core::ring::Arena, p: usize) {
        crate::modq::intt(&mut ar.p[p]);
    }
    fn dot4(&mut self, ar: &mut dilithium_core::ring::Arena, out: usize, a: usize, b: usize) {
        let av: [crate::modq::Poly; 4] = core::array::from_fn(|k| ar.p[a + k]);
        let bv: [crate::modq::Poly; 4] = core::array::from_fn(|k| ar.p[b + k]);
        ar.p[out] = crate::modq::dot4(&av, &bv);
    }
    fn msub4(&mut self, ar: &mut dilithium_core::ring::Arena, out: usize, c: usize, t: usize) {
        let mut w: [crate::modq::Poly; 4] = core::array::from_fn(|k| ar.p[out + k]);
        let tv: [crate::modq::Poly; 4] = core::array::from_fn(|k| ar.p[t + k]);
        crate::modq::msub4(&mut w, &ar.p[c], &tv);
        for k in 0..4 {
            ar.p[out + k] = w[k];
        }
    }
}
