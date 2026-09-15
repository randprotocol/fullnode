//! The memory table (plan R4): one AIR instantiated twice — the register table (cells
//! `2^24 + k`, `k < 32`, on the `REG` bus) and the RAM table (cells below `2^24`, on the `RAM`
//! bus). `research/src/tables/memory.rs` minus `SPACE`: the register/RAM split carries the space
//! in the address and the bus, not a column. Sorted by `(addr, ts)`; read-after-write
//! consistency is a transition constraint; the cpu's and the chips' accesses reach here through
//! the two multiset buses.
use super::{bus, range::RangeCounts, F};
use crate::emulator::MemAccess;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const ADDR: usize = 0;
    pub const TS: usize = 1;
    pub const VALUE: usize = 2;
    pub const IS_WRITE: usize = 3;
    pub const IS_REAL: usize = 4;
    pub const ADDR_CHANGED: usize = 5;
    pub const DIFF_INV: usize = 6;
    pub const D0: usize = 7;
    pub const D1: usize = 8;
    pub const D2: usize = 9;
    pub const D3: usize = 10;
    pub const WIDTH: usize = 11;
}
use col::*;

/// Register `k` is the memory-bus cell `REGISTER_BASE + k` (R4). RAM addresses stay below
/// `2^24` (`isa::MEM_LIMIT`), so the two classes partition the address space — and the two buses
/// partition the messages, since the cpu and the chips build register messages from the
/// 5-bit-range-checked index and RAM messages from the 3-byte-limb-checked address.
pub const REGISTER_BASE: u64 = 1 << 24;

/// One AIR, two instances: `register` picks the bus the instance receives on (`REG` or `RAM`).
/// The table does not constrain its address range itself — the *senders* enforce it (the cpu's
/// index decompositions and address limbs), and a row planted in the wrong table is an unclaimed
/// supply on its bus, since each bus balances independently.
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryAir {
    pub register: bool,
}

impl<Fld: Field> BaseAir<Fld> for MemoryAir {
    fn width(&self) -> usize { col::WIDTH }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MemoryAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let l = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;

        b.assert_bool(l(IS_REAL));
        b.assert_bool(l(IS_WRITE));
        b.assert_bool(l(ADDR_CHANGED));
        // A read of never-written memory returns zero.
        b.when_first_row().assert_zero(l(IS_REAL) * (one.clone() - l(IS_WRITE)) * l(VALUE));

        let dk = n(ADDR) - l(ADDR);
        let both = l(IS_REAL) * n(IS_REAL);
        let delta = l(ADDR_CHANGED) * (dk.clone() - one.clone())
            + (one.clone() - l(ADDR_CHANGED)) * (n(TS) - l(TS) - one.clone());
        let delta_limbs = l(D0)
            + l(D1) * AB::Expr::from_u32(1 << 8)
            + l(D2) * AB::Expr::from_u32(1 << 16)
            + l(D3) * AB::Expr::from_u32(1 << 24);

        let mut t = b.when_transition();
        // Padding is a suffix.
        t.assert_zero((one.clone() - l(IS_REAL)) * n(IS_REAL));
        // addr_changed == (key_n != key_l)
        t.assert_zero(both.clone() * (l(ADDR_CHANGED) - dk.clone() * l(DIFF_INV)));
        t.assert_zero(both.clone() * (one.clone() - l(ADDR_CHANGED)) * dk);
        // Strictly increasing (addr, ts): delta ≥ 0 is enforced by the byte lookups below.
        t.assert_zero(both.clone() * (delta - delta_limbs));
        // Read-after-write: same address, next is a read → same value.
        t.assert_zero(n(IS_REAL) * (one.clone() - l(ADDR_CHANGED)) * (one.clone() - n(IS_WRITE)) * (n(VALUE) - l(VALUE)));
        // First touch of a fresh address as a read → zero.
        t.assert_zero(n(IS_REAL) * l(ADDR_CHANGED) * (one.clone() - n(IS_WRITE)) * n(VALUE));
        drop(t);

        for d in [D0, D1, D2, D3] {
            bus::RANGE8.lookup_key(b, [l(d)], Count::bounded(both.clone(), 1));
        }
        // The one sort key is the address itself — research's audit-ZM2 lesson (compute the key
        // exactly as the AIR does) applies unchanged; the delta fits four bytes
        // (addresses < 2^24 + 32, timestamps < 16·2^22 at the top tier).
        let msg = [l(ADDR), l(TS), l(VALUE), l(IS_WRITE)];
        let count = Count::bounded(l(IS_REAL), 1);
        if self.register {
            bus::REG.receive(b, msg, count);
        } else {
            bus::RAM.receive(b, msg, count);
        }
    }
}

/// One sorted trace per instance. `accesses` is the emulator's `MemAccess` log filtered to the
/// instance's address class (`build_traces` splits it); the emulator's `16·clk + slot`
/// timestamps are already the cpu's and the chips' common clock, so the trace is a plain sort.
/// The `RangeCounts` are shared with every other table: the range table's `MULT` column must
/// account for every `RANGE8` lookup the whole batch performs.
pub fn memory_trace(accesses: &[MemAccess], height: usize, counts: &mut RangeCounts) -> RowMajorMatrix<F> {
    let mut rows: Vec<&MemAccess> = accesses.iter().collect();
    rows.sort_by_key(|a| (a.addr, a.ts));
    assert!(
        rows.len() < height,
        "memory table needs at least one padding row: {} accesses, height {height}",
        rows.len()
    );
    let mut v = F::zero_vec(height * col::WIDTH);
    for (i, r) in rows.iter().enumerate() {
        let base = i * col::WIDTH;
        v[base + ADDR] = F::from_u64(r.addr);
        v[base + TS] = F::from_u64(r.ts as u64);
        v[base + VALUE] = r.value;
        v[base + IS_WRITE] = F::from_bool(r.is_write);
        v[base + IS_REAL] = F::ONE;
        if let Some(nx) = rows.get(i + 1) {
            let changed = nx.addr != r.addr;
            let delta: u64 = if changed {
                nx.addr - r.addr - 1
            } else {
                assert!(nx.ts > r.ts, "two accesses to the same address at the same timestamp");
                if !nx.is_write {
                    assert_eq!(nx.value, r.value, "read does not match last write at addr {:#x}", r.addr);
                }
                nx.ts as u64 - r.ts as u64 - 1
            };
            if changed && !nx.is_write {
                assert_eq!(nx.value, F::ZERO, "first read of a fresh address must be zero");
            }
            v[base + ADDR_CHANGED] = F::from_bool(changed);
            v[base + DIFF_INV] = if changed { F::from_u64(nx.addr - r.addr).inverse() } else { F::ZERO };
            assert!(delta < 1 << 32);
            for (j, c) in [D0, D1, D2, D3].iter().enumerate() {
                let limb = (delta >> (8 * j)) as u32 & 0xff;
                v[base + c] = F::from_u32(limb);
                counts.range8(limb);
            }
        }
    }
    if let Some(first) = rows.first() {
        if !first.is_write {
            assert_eq!(first.value, F::ZERO, "first read of a fresh address must be zero");
        }
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
