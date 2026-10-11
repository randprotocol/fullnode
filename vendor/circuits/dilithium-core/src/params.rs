//! Round-3 Dilithium2 parameters, from `crystals-dilithium` 2.0.0's `params.rs` and
//! `params/lvl2.rs` (only what verify uses).

// Specification defined constants (params.rs)
pub const Q: i32 = (1 << 23) - (1 << 13) + 1; // prime defining the field
pub const N: i32 = 256; // ring defining polynomial degree
pub const D: i32 = 13; // dropped bits

// Implementation specific values (params.rs)
pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const POLYT1_PACKEDBYTES: usize = 320;

// Specification defined constants (params/lvl2.rs)
pub const TAU: usize = 39; // number of +-1s in c
pub const GAMMA1: usize = 1 << 17; // y coefficient range
pub const GAMMA2: usize = (Q as usize - 1) / 88; // low-order rounding range
pub const K: usize = 4; // rows in A
pub const L: usize = 4; // columns in A
pub const ETA: usize = 2;
pub const BETA: usize = TAU * ETA;
pub const OMEGA: usize = 80;

// Implementation specific values (params/lvl2.rs)
pub const POLYZ_PACKEDBYTES: usize = 576;
pub const POLYW1_PACKEDBYTES: usize = 192;
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
pub const PUBLICKEYBYTES: usize = SEEDBYTES + K * POLYT1_PACKEDBYTES;
pub const SIGNBYTES: usize = SEEDBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;

// fips202.rs
pub const SHAKE128_RATE: usize = 168;
pub const SHAKE256_RATE: usize = 136;
