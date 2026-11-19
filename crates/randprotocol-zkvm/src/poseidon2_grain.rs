//! The Poseidon2 round-constant derivation: the Grain LFSR in its self-shrinking mode, as the
//! Poseidon paper specifies it (Grassi, Khovratovich, Rechberger, Roy, Schofnegger, "Poseidon: A
//! New Hash Function for Zero-Knowledge Proof Systems", USENIX Security 2021, section 4.3 and
//! appendix F) and as the Poseidon2 reference script uses it (`poseidon2_rust_params.sage` in
//! HorizenLabs/poseidon2: the same generator, drawing `R_F * t + R_P` elements).
//!
//! Nothing hashes through this: it derives the committed table in
//! [`crate::poseidon2_constants`] (live since constraint set 11, monorepo issue 60, ZKVM-107),
//! and the tests below re-run it and compare. `tools/poseidon2_grain/grain.py` is a second
//! implementation in standard-library Python, for re-deriving the table without building this
//! crate.
//!
//! The procedure, in full — there is no seed and no free parameter beyond the six numbers that
//! describe the permutation itself:
//!
//! 1. An 80-bit state `b0..b79`, each field written most significant bit first: the field type
//!    (2 bits; 1 is a prime field), the S-box (4 bits; 0 is `x^alpha`), `n` = the field's bit
//!    length (12 bits), `t` = the width (12 bits), `R_F` (10 bits), `R_P` (10 bits), then thirty
//!    1 bits.
//! 2. One step computes `b[i+80] = b[i+62] ^ b[i+51] ^ b[i+38] ^ b[i+23] ^ b[i+13] ^ b[i]` and
//!    shifts. The first 160 steps' outputs are discarded.
//! 3. Outputs are then read in pairs: a pair `(1, x)` yields the bit `x`; a pair `(0, x)` yields
//!    nothing.
//! 4. A field element is `n` yielded bits, most significant first. A value `>= p` is discarded
//!    and redrawn, so every constant is canonical.
//! 5. Poseidon2's order: the first `R_F / 2` full rounds (`t` constants each), the `R_P` partial
//!    rounds (one constant each, for lane 0), the last `R_F / 2` full rounds.

/// The six numbers the generator is initialised from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrainParams {
    /// 1 for a prime field (0 is a binary field, which this code does not sample).
    pub field_type: u8,
    /// 0 for the S-box `x^alpha` (1 is `x^-1`).
    pub sbox: u8,
    /// The prime's bit length.
    pub n: u16,
    /// The permutation's width.
    pub t: u16,
    /// Full rounds, both halves together.
    pub r_f: u16,
    /// Partial rounds.
    pub r_p: u16,
}

/// Width-8 Poseidon2 over Goldilocks with the S-box `x^7`: a 64-bit prime field, 8 full and 22
/// partial rounds — the round numbers `p3_poseidon2::poseidon2_round_numbers_128` gives for this
/// field, width and degree, and the ones the `poseidon2` chip's AIR lays out
/// (`tables::poseidon2::{HALF_FULL_ROUNDS, PARTIAL_ROUNDS}`).
pub const GOLDILOCKS_WIDTH_8: GrainParams = GrainParams { field_type: 1, sbox: 0, n: 64, t: 8, r_f: 8, r_p: 22 };

/// The Goldilocks prime, `2^64 - 2^32 + 1`.
pub const GOLDILOCKS_P: u64 = 0xffff_ffff_0000_0001;

/// The generator: an 80-bit shift register, kept as a ring buffer of bits.
pub struct Grain {
    state: [bool; 80],
    head: usize,
}

impl Grain {
    /// Steps 1 and 2 of the module comment: the initial state, then 160 discarded outputs.
    pub fn new(p: GrainParams) -> Self {
        let mut state = [false; 80];
        let mut at = 0;
        for (value, width) in [(p.field_type as u32, 2), (p.sbox as u32, 4), (p.n as u32, 12), (p.t as u32, 12), (p.r_f as u32, 10), (p.r_p as u32, 10), ((1 << 30) - 1, 30)] {
            assert!(value >> width == 0, "a Grain parameter does not fit its field");
            for i in 0..width {
                state[at] = (value >> (width - 1 - i)) & 1 == 1;
                at += 1;
            }
        }
        assert_eq!(at, 80);
        let mut g = Self { state, head: 0 };
        for _ in 0..160 {
            g.step();
        }
        g
    }

    fn step(&mut self) -> bool {
        let b = |i: usize| self.state[(self.head + i) % 80];
        let new = b(62) ^ b(51) ^ b(38) ^ b(23) ^ b(13) ^ b(0);
        self.state[self.head] = new;
        self.head = (self.head + 1) % 80;
        new
    }

    /// Step 3: the next yielded bit.
    pub fn bit(&mut self) -> bool {
        loop {
            let first = self.step();
            let second = self.step();
            if first {
                return second;
            }
        }
    }

    /// Step 4, for a prime `p` of exactly `n <= 64` bits: the next field element below `p`.
    pub fn element(&mut self, n: u16, p: u64) -> u64 {
        assert!((1..=64).contains(&n));
        loop {
            let mut x = 0u64;
            for _ in 0..n {
                x = (x << 1) | self.bit() as u64;
            }
            if x < p {
                return x;
            }
        }
    }
}

/// Step 5 for [`GOLDILOCKS_WIDTH_8`]: `(initial, internal, terminal)`, laid out as
/// `poseidon2_constants`'s three tables are.
pub fn goldilocks_width_8() -> ([[u64; 8]; 4], [u64; 22], [[u64; 8]; 4]) {
    let p = GOLDILOCKS_WIDTH_8;
    let mut g = Grain::new(p);
    let mut next = || g.element(p.n, GOLDILOCKS_P);
    let mut initial = [[0u64; 8]; 4];
    let mut internal = [0u64; 22];
    let mut terminal = [[0u64; 8]; 4];
    for row in &mut initial {
        for x in row {
            *x = next();
        }
    }
    for x in &mut internal {
        *x = next();
    }
    for row in &mut terminal {
        for x in row {
            *x = next();
        }
    }
    (initial, internal, terminal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The initial state, bit for bit, for the one parameter set this crate uses:
    /// `01 | 0000 | 000001000000 | 000000001000 | 0000001000 | 0000010110 | 1 x 30`.
    #[test]
    fn the_initial_state_is_the_papers_encoding() {
        let want = "01".to_owned() + "0000" + "000001000000" + "000000001000" + "0000001000" + "0000010110" + &"1".repeat(30);
        assert_eq!(want.len(), 80);
        // Rebuild the state without the 160 warm-up steps.
        let p = GOLDILOCKS_WIDTH_8;
        let mut bits = String::new();
        for (value, width) in [(p.field_type as u32, 2), (p.sbox as u32, 4), (p.n as u32, 12), (p.t as u32, 12), (p.r_f as u32, 10), (p.r_p as u32, 10), ((1 << 30) - 1, 30)] {
            for i in 0..width {
                bits.push(if (value >> (width - 1 - i)) & 1 == 1 { '1' } else { '0' });
            }
        }
        assert_eq!(bits, want);
    }

    /// A different parameter set gives a different stream (the parameters are the only input),
    /// and the same set gives the same one.
    #[test]
    fn the_stream_is_a_function_of_the_parameters() {
        let a = goldilocks_width_8();
        assert_eq!(a, goldilocks_width_8());
        let mut other = Grain::new(GrainParams { t: 12, ..GOLDILOCKS_WIDTH_8 });
        assert_ne!(other.element(64, GOLDILOCKS_P), a.0[0][0]);
    }

    /// Every constant is canonical, and the 86 are pairwise distinct.
    #[test]
    fn the_constants_are_canonical_and_distinct() {
        let (i, m, t) = goldilocks_width_8();
        let mut all: Vec<u64> = i.iter().flatten().chain(m.iter()).chain(t.iter().flatten()).copied().collect();
        assert_eq!(all.len(), 86);
        assert!(all.iter().all(|x| *x < GOLDILOCKS_P));
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 86);
    }

    /// The committed table (`poseidon2_constants`, the one every hash reads) is this
    /// derivation, all 86 values, regenerated here. (It lives here rather than in
    /// `poseidon2_constants.rs` because that file is also compiled into `rand-zkvm-cuda` by
    /// `#[path]` and may name no `crate::` path.)
    #[test]
    fn the_table_is_the_grain_derivation() {
        use crate::poseidon2_constants::{INITIAL, INTERNAL, TERMINAL};
        let (initial, internal, terminal) = goldilocks_width_8();
        assert_eq!(initial, INITIAL, "initial rows");
        assert_eq!(internal, INTERNAL, "internal scalars");
        assert_eq!(terminal, TERMINAL, "terminal rows");
    }

    /// The `poseidon2` chip's own arithmetic (`mds_light`, `internal_matmul`, `cube` — what the
    /// AIR constrains row by row), handed the derived constants, computes the permutation every
    /// hash uses: the switch to this table (ZKVM-107) changed preprocessed constants, not
    /// constraints.
    #[test]
    fn the_chips_arithmetic_computes_the_permutation() {
        use crate::tables::poseidon2::{permute_scalar_with, RoundConstants};
        use p3_goldilocks::Goldilocks;
        use p3_symmetric::Permutation;
        use rand::distr::StandardUniform;
        use rand::rngs::StdRng;
        use rand::{RngExt, SeedableRng};
        let (initial, internal, terminal) = goldilocks_width_8();
        let rc = RoundConstants { initial: initial.map(Goldilocks::new_array), internal: Goldilocks::new_array(internal), terminal: terminal.map(Goldilocks::new_array) };
        let perm = crate::poseidon2_constants::permutation();
        let mut rng = StdRng::seed_from_u64(0x60);
        for i in 0..2_000 {
            let x: [Goldilocks; 8] = core::array::from_fn(|_| rng.sample(StandardUniform));
            assert_eq!(permute_scalar_with(&rc, x), perm.permute(x), "state {i}");
        }
    }
}
