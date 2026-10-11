//! `dilithium-core`: a no_std Dilithium2 verifier that runs on the host and, compiled to
//! riscv32im, inside the rVM. The Keccak-f[1600] permutation is a trait so the guest can route it
//! to the `KECCAK` syscall while the host uses its own implementation.
#![no_std]

pub mod fips202;
pub mod ntt;
pub mod packing;
pub mod params;
pub mod poly;
pub mod reduce;
pub mod ring;
pub mod rounding;
pub mod verify;

pub use fips202::{shake256, Shake};
pub use verify::{verify, verify_reference, verify_with, verify_words_with};

// The word paths view the byte-oriented wire format as little-endian words.
#[cfg(not(target_endian = "little"))]
compile_error!("dilithium-core's word paths assume a little-endian target");

/// Round-3 Dilithium2 public-key bytes (`rho` ‖ packed `t1`).
pub const PK_BYTES: usize = 1312;
/// Round-3 Dilithium2 signature bytes (`c` ‖ packed `z` ‖ hint section).
pub const SIG_BYTES: usize = 2420;
const _: () = assert!(PK_BYTES == params::PUBLICKEYBYTES && SIG_BYTES == params::SIGNBYTES);

/// A Keccak-f[1600] permutation provider.
pub trait Keccak {
    fn permute(&mut self, s: &mut [u64; 25]);

    /// The same permutation on the `KECCAK` syscall's 50-word layout (lane `i`'s low word at `2i`,
    /// high word at `2i + 1`). The default joins, permutes and splits; the guest overrides it with
    /// the bare syscall.
    fn permute_words(&mut self, w: &mut [u32; 50]) {
        let mut s = [0u64; 25];
        for i in 0..25 {
            s[i] = w[2 * i] as u64 | (w[2 * i + 1] as u64) << 32;
        }
        self.permute(&mut s);
        for i in 0..25 {
            w[2 * i] = s[i] as u32;
            w[2 * i + 1] = (s[i] >> 32) as u32;
        }
    }
}

impl<K: Keccak + ?Sized> Keccak for &mut K {
    fn permute(&mut self, s: &mut [u64; 25]) {
        (**self).permute(s)
    }
    fn permute_words(&mut self, w: &mut [u32; 50]) {
        (**self).permute_words(w)
    }
}
