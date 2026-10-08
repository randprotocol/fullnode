//! The tables of the rVM and the buses that connect them (plan, "The tables and buses").
pub mod cpu;
pub mod memory;
pub mod poseidon2;
pub mod program;
pub mod public;
pub mod range;
pub mod reduce;

pub type F = p3_goldilocks::Goldilocks;

/// Bus catalogue. A bus is a name; the batch verifier checks every bus balances.
/// Thirteen buses (Cut D adds `REDUCE_LAYOUT`, Cut E2 `FOLD` and `FOLD_COEFF`, Cut F `POW`; plan R7, R9), not spec
/// §5's four: the public table, the sponge and compress row kinds and the reduce chip each need
/// their own channel, and `MEMORY` splits into `REG`/`RAM` (R4).
pub mod bus {
    use p3_lookup::{LookupBus, PermutationCheckBus};
    /// cpu/chips ↔ register memory: (addr, ts, value, is_write), addr = 2^24 + idx, idx < 32.
    /// Multiset equality, the RV32 `MEMORY` bus's pattern on a split address class.
    pub const REG: PermutationCheckBus<'static> = PermutationCheckBus::new("REG");
    /// cpu/chips ↔ RAM: (addr, ts, value, is_write), addr < 2^24. Multiset equality.
    pub const RAM: PermutationCheckBus<'static> = PermutationCheckBus::new("RAM");
    /// cpu (POSEIDON2 rows) → poseidon2: (clk, ptr). The permutation's input and output travel
    /// on `RAM`, sent by the chip itself — the keccak/sha256 pattern.
    pub const POSEIDON2: LookupBus<'static> = LookupBus::new("POSEIDON2");
    /// cpu (SPONGE rows) → poseidon2: (clk, state_ptr, src_ptr). Task 9.
    pub const SPONGE: LookupBus<'static> = LookupBus::new("SPONGE");
    /// cpu → program: (pc, w0..3), the four encoded words of the instruction at `pc`. Program
    /// provides with count `MULT` (the row's fetch count).
    pub const PROGRAM: LookupBus<'static> = LookupBus::new("PROGRAM");
    /// x in [0, 256). Range provides; the cpu's address limbs and both memory tables' delta
    /// limbs consume — the only range check in the machine (spec §3).
    pub const RANGE8: LookupBus<'static> = LookupBus::new("RANGE8");
    /// cpu (PUBLIC rows) → public: (idx, value), one per published word. Public provides with
    /// count `IS_REAL`; set equality forces the published values to be the proof's four public
    /// values in order (R5).
    pub const PUBLIC: LookupBus<'static> = LookupBus::new("PUBLIC");
    /// cpu (REDUCE rows) → reduce: (clk, entry). The entry id is the instruction's immediate (Cut D).
    pub const REDUCE: LookupBus<'static> = LookupBus::new("REDUCE");
    /// reduce → reduce (Cut D): (entry, addr_v, addr_r, row_end, key, alpha, res, chain_start + 2·carry).
    /// The chip's preprocessed provider region (the program's reduce layout, `MULT` per row) provides;
    /// each run's first row consumes — so every address a run touches is one the verifier key commits.
    pub const REDUCE_LAYOUT: LookupBus<'static> = LookupBus::new("REDUCE_LAYOUT");
    /// cpu (COMPRESS rows) → poseidon2: (clk, state_ptr, sib_ptr, bit). Cut C: one Merkle level.
    pub const COMPRESS: LookupBus<'static> = LookupBus::new("COMPRESS");
    /// cpu (FOLD rows) → reduce (Cut E2): (clk, msg, u0, u1, arity). One fold run per dispatch.
    pub const FOLD: LookupBus<'static> = LookupBus::new("FOLD");
    /// reduce → reduce (Cut E2): (arity, k, c0..c7). The preprocessed coefficient table provides
    /// (14 rows: arity 2, 4, 8), each phase-1 fold row consumes its own.
    pub const FOLD_COEFF: LookupBus<'static> = LookupBus::new("FOLD_COEFF");
    /// cpu (POW rows) → reduce (Cut F): (clk, bits_buf, off + 256·L, G, base).
    pub const POW: LookupBus<'static> = LookupBus::new("POW");
}

/// Next power of two ≥ n, at least `min` — `research/src/tables/mod.rs`'s helper, verbatim.
pub fn pad_height(n: usize, min: usize) -> usize {
    n.max(min).next_power_of_two()
}
