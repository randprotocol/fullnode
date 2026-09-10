//! The seven tables of the machine and the buses that connect them.
pub mod range;
pub mod nibble;
pub mod program;
pub mod memory;
pub mod alu;
pub mod cpu;
pub mod poseidon2;

pub type F = p3_goldilocks::Goldilocks;

/// Bus catalogue. A bus is a name; the batch verifier checks every bus balances.
pub mod bus {
    use p3_lookup::{LookupBus, PermutationCheckBus};
    /// cpu → program: (pc, 23 decoded fields). Program provides. Instruction-row fetches only.
    pub const PROGRAM: LookupBus<'static> = LookupBus::new("PROGRAM");
    /// cpu (digest rows) → program: (pc, word). Program provides — the M3.4 digest bus,
    /// separate from `PROGRAM` so a digest row's raw-word lookups never interact with an
    /// ordinary instruction fetch's multiplicity accounting.
    pub const PROGRAM_WORD: LookupBus<'static> = LookupBus::new("PROGRAM_WORD");
    /// cpu ↔ memory: (space, addr, ts, value, is_write). Multiset equality.
    pub const MEMORY: PermutationCheckBus<'static> = PermutationCheckBus::new("MEMORY");
    /// cpu → alu: (op, a, b, c). Alu provides.
    pub const ALU: LookupBus<'static> = LookupBus::new("ALU");
    /// x in [0,256). Range provides.
    pub const RANGE8: LookupBus<'static> = LookupBus::new("RANGE8");
    /// (a, b, a&b) with a,b in [0,16). Nibble provides.
    pub const AND4: LookupBus<'static> = LookupBus::new("AND4");
    pub const OR4: LookupBus<'static> = LookupBus::new("OR4");
    pub const XOR4: LookupBus<'static> = LookupBus::new("XOR4");
    /// (s, 2^s) for s < 32. Range provides.
    pub const POW2: LookupBus<'static> = LookupBus::new("POW2");
    /// (in0..7, out0..7): a width-8 Poseidon2 permutation. Poseidon2 table provides.
    pub const POSEIDON2: LookupBus<'static> = LookupBus::new("POSEIDON2");
}

/// Split a u32 into four little-endian bytes as field elements.
pub fn limbs(x: u32) -> [F; 4] {
    use p3_field::PrimeCharacteristicRing;
    core::array::from_fn(|i| F::from_u32((x >> (8 * i)) & 0xff))
}

/// Next power of two ≥ n, at least `min`.
pub fn pad_height(n: usize, min: usize) -> usize {
    n.max(min).next_power_of_two()
}
