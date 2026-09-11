//! Registers and RAM in one table, sorted by (space, addr, ts). Read-after-write
//! consistency is a transition constraint; the CPU's accesses reach here through
//! the MEMORY multiset bus.
use super::{bus, limbs, range::RangeCounts, F};
use crate::emulator::CycleEvent;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const SPACE: usize = 0; pub const ADDR: usize = 1; pub const TS: usize = 2; pub const VALUE: usize = 3;
    pub const IS_WRITE: usize = 4; pub const IS_REAL: usize = 5; pub const ADDR_CHANGED: usize = 6; pub const DIFF_INV: usize = 7;
    pub const D0: usize = 8; pub const D1: usize = 9; pub const D2: usize = 10; pub const D3: usize = 11;
    pub const WIDTH: usize = 12;
}
pub const KEY_SHIFT: u32 = 30;

#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryAir;

impl<Fld> BaseAir<Fld> for MemoryAir { fn width(&self) -> usize { col::WIDTH } }

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MemoryAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        use col::*;
        let m = b.main();
        let l = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let shift = AB::Expr::from_u64(1 << KEY_SHIFT);

        b.assert_bool(l(IS_REAL));
        b.assert_bool(l(IS_WRITE));
        b.assert_bool(l(ADDR_CHANGED));
        // A read of never-written memory returns zero.
        b.when_first_row().assert_zero(l(IS_REAL) * (one.clone() - l(IS_WRITE)) * l(VALUE));

        let key_l = l(SPACE) * shift.clone() + l(ADDR);
        let key_n = n(SPACE) * shift + n(ADDR);
        let dk = key_n - key_l;
        let both = l(IS_REAL) * n(IS_REAL);
        let delta = l(ADDR_CHANGED) * (dk.clone() - one.clone())
            + (one.clone() - l(ADDR_CHANGED)) * (n(TS) - l(TS) - one.clone());
        let delta_limbs = l(D0) + l(D1) * AB::Expr::from_u32(1 << 8) + l(D2) * AB::Expr::from_u32(1 << 16) + l(D3) * AB::Expr::from_u32(1 << 24);

        let mut t = b.when_transition();
        // padding is a suffix
        t.assert_zero((one.clone() - l(IS_REAL)) * n(IS_REAL));
        // addr_changed == (key_n != key_l)
        t.assert_zero(both.clone() * (l(ADDR_CHANGED) - dk.clone() * l(DIFF_INV)));
        t.assert_zero(both.clone() * (one.clone() - l(ADDR_CHANGED)) * dk);
        // strictly increasing (key, ts): delta ≥ 0 is enforced by the byte lookups below
        t.assert_zero(both.clone() * (delta - delta_limbs));
        // read-after-write: same address, next is a read → same value
        t.assert_zero(n(IS_REAL) * (one.clone() - l(ADDR_CHANGED)) * (one.clone() - n(IS_WRITE)) * (n(VALUE) - l(VALUE)));
        // first touch of a fresh address as a read → zero
        t.assert_zero(n(IS_REAL) * l(ADDR_CHANGED) * (one.clone() - n(IS_WRITE)) * n(VALUE));
        drop(t);

        for d in [D0, D1, D2, D3] {
            bus::RANGE8.lookup_key(b, [l(d)], Count::bounded(both.clone(), 1));
        }
        bus::MEMORY.receive(b, [l(SPACE), l(ADDR), l(TS), l(VALUE), l(IS_WRITE)], Count::bounded(l(IS_REAL), 1));
    }
}

/// M3.4: `clk_offset` is `Program::digest_rows() + input_digest_rows` (M4.1: the cpu
/// table's *two* digest-row prefixes) — the cpu table's digest-row prefixes shift every
/// ordinary event's own `CLK` forward by that many rows (`tables::cpu::cpu_trace`), and
/// the `MEMORY` bus timestamps (`ts = 4*CLK + slot`) this table sends must use that same
/// shifted `CLK` or the two sides' `(space, addr, ts, value, is_write)` tuples stop matching.
pub fn memory_trace(events: &[CycleEvent], clk_offset: u32, height: usize, counts: &mut RangeCounts) -> RowMajorMatrix<F> {
    // (key, ts, space, addr, value, is_write)
    let mut rows: Vec<(u64, u64, u32, u32, u32, bool)> = Vec::new();
    for e in events {
        for a in &e.accesses {
            // The sort key must be computed exactly the way the AIR recomputes it —
            // `SPACE·2^30 + ADDR` (`eval`'s `key_l`/`key_n`), i.e. `+`, not `|`. With `|`,
            // any RAM address `>= 2^30` (reachable only through POSEIDON2 absorb/write-back
            // addresses — `HASH_PTR < 2^30` is the AIR's bound, plus at most 4099 derived
            // words) aliases the address with its bit 30 cleared: rows sort into an order
            // whose in-circuit keys *decrease* across the boundary (the `dk` delta limbs then
            // reject an honest trace), and `(1, x)` / `(1, 2^30+x)` collide into one key
            // entirely. `+` is injective and monotone over every provable trace: register
            // addresses are `< 32` and RAM addresses stay `< 2^31` (ordinary word addresses
            // are `alu_out >> 2 < 2^30`; hash-derived ones `< 2^30 + 4099`).
            rows.push((((a.space as u64) << KEY_SHIFT) + a.addr as u64, a.ts(clk_offset + e.clk) as u64, a.space, a.addr, a.value, a.is_write));
        }
    }
    rows.sort_by_key(|r| (r.0, r.1));
    assert!(rows.len() < height, "memory table needs at least one padding row: {} accesses, height {height}", rows.len());
    let mut v = F::zero_vec(height * col::WIDTH);
    for (i, r) in rows.iter().enumerate() {
        let base = i * col::WIDTH;
        v[base + col::SPACE] = F::from_u32(r.2);
        v[base + col::ADDR] = F::from_u32(r.3);
        v[base + col::TS] = F::from_u64(r.1);
        v[base + col::VALUE] = F::from_u32(r.4);
        v[base + col::IS_WRITE] = F::from_bool(r.5);
        v[base + col::IS_REAL] = F::ONE;
        if let Some(nx) = rows.get(i + 1) {
            let changed = nx.0 != r.0;
            let delta: u64 = if changed { nx.0 - r.0 - 1 } else {
                assert!(nx.1 > r.1, "two accesses to the same address at the same timestamp");
                if !nx.5 { assert_eq!(nx.4, r.4, "read does not match last write at key {:#x}", r.0); }
                nx.1 - r.1 - 1
            };
            if changed && !nx.5 { assert_eq!(nx.4, 0, "first read of a fresh address must be zero"); }
            v[base + col::ADDR_CHANGED] = F::from_bool(changed);
            v[base + col::DIFF_INV] = if changed { F::from_u64(nx.0 - r.0).inverse() } else { F::ZERO };
            assert!(delta < 1 << 32);
            let dl = limbs(delta as u32);
            for (j, c) in [col::D0, col::D1, col::D2, col::D3].iter().enumerate() {
                v[base + c] = dl[j];
                counts.range8((delta >> (8 * j)) as u32 & 0xff);
            }
        }
    }
    if let Some(first) = rows.first() { if !first.5 { assert_eq!(first.4, 0); } }
    RowMajorMatrix::new(v, col::WIDTH)
}
