//! The five tables of the machine and the buses that connect them.
pub mod byte;
pub mod program;
pub mod memory;
pub mod alu;
pub mod cpu;

pub type F = p3_goldilocks::Goldilocks;

/// Bus catalogue. A bus is a name; the batch verifier checks every bus balances.
pub mod bus {
    use p3_lookup::{LookupBus, PermutationCheckBus};
    /// cpu → program: (pc, 18 decoded fields). Program provides.
    pub const PROGRAM: LookupBus<'static> = LookupBus::new("PROGRAM");
    /// cpu ↔ memory: (space, addr, ts, value, is_write). Multiset equality.
    pub const MEMORY: PermutationCheckBus<'static> = PermutationCheckBus::new("MEMORY");
    /// cpu → alu: (op, a, b, c). Alu provides.
    pub const ALU: LookupBus<'static> = LookupBus::new("ALU");
    /// x in [0,256). Byte provides.
    pub const RANGE8: LookupBus<'static> = LookupBus::new("RANGE8");
    /// (a, b, a&b). Byte provides.
    pub const AND8: LookupBus<'static> = LookupBus::new("AND8");
    pub const OR8: LookupBus<'static> = LookupBus::new("OR8");
    pub const XOR8: LookupBus<'static> = LookupBus::new("XOR8");
    /// (s, 2^s) for s < 32. Byte provides.
    pub const POW2: LookupBus<'static> = LookupBus::new("POW2");
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
