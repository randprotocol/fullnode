//! The builder: value slots, a two-pass register allocator with liveness, and the control
//! constructs rVM programs are made of.
//!
//! **The allocator (M5.2 Task 7).** Every public method buffers handle-annotated operations —
//! `Mat` (a materialise), `Def` (a fresh handle), `Instr` (one annotated instruction), and
//! group/loop markers — and `finish()` replays them, assigning registers, emitting spill and
//! reload instructions, and resolving branch targets and checkpoint pcs. With
//! [`Liveness::On`] the replay **frees a handle's register at its last use** (last-use is
//! computed over the whole buffered program, clamped out of loop bodies: anything a loop body
//! touches stays live until the loop ends) and reuses spill cells, so pressure — and with it
//! spill/reload traffic — collapses. With [`Liveness::Off`] the replay runs the pre-liveness
//! policy verbatim (handles live to the end of the program, the oldest resident spills first,
//! no cell reuse) and reproduces the pre-Task-7 instruction stream **byte for byte** — the
//! differential reference `tests/dsl.rs` and `tests/verifier.rs` pin against the On build.
//!
//! **Scratch registers.** `r26..r31` are never allocated to a handle: where a spilled operand is
//! reloaded, where a comparison's difference lands, and where the hash layer's raw sequences do
//! their work. Six, because the deepest sequence — the Merkle walk's child select — needs a
//! reloaded index bit, two reloaded base addresses and three working registers at once; the
//! replay assigns scratch slots in buffered order and asserts the bound.
//!
//! **Discipline the replay depends on.** A handle's `Def` entry is followed immediately by its
//! defining instruction(s), with nothing in between that could allocate — otherwise the replay
//! could spill a register whose value has not been written yet (the pre-liveness rule, carried).
//! Loop bodies leave the allocation of every handle that existed before them untouched; the
//! replay checks it at the loop markers, where the pre-liveness builder checked it at emit time.

use std::collections::{HashMap, VecDeque};

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use super::{Array, Ext, Felt, Ptr};
use crate::isa::{Instr, Op, Program, EF, F, MEM_LIMIT, NUM_REGS};

/// The first cell a user allocation can use. Cells `0..MEM_BASE` are the spill arena.
///
/// `2^22`, a quarter of the `2^24`-cell address space. With liveness the arena holds only the
/// handles spilled *concurrently* — the pre-liveness "every handle the program ever spills"
/// requirement (on the order of `10^6` cells for the verifier program) is gone — but the base is
/// where every program already built points its user allocations, and moving it changes every
/// digest for no benefit.
pub const MEM_BASE: u64 = 1 << 22;

/// The registers handles are allocated from, in allocation-preference order. Width-2 handles take an
/// aligned pair, so `r25` is reachable only by a width-1 handle: twelve pairs, twenty-five singles.
const ALLOCATABLE: [u8; 25] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];
/// Never allocated to a handle. Contiguous, so a width-2 reload can take any two in order.
const SCRATCH: [u8; 6] = [26, 27, 28, 29, 30, 31];

/// Should `Builder::checkpoint` publish its value?
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Checkpoints {
    Off,
    On,
}

/// Should `Builder::finish` free a handle's register at its last use (Task 7), or run the
/// pre-liveness policy that keeps every handle to the end of the program? `Off` exists as the
/// differential reference for `On` — it reproduces the pre-Task-7 stream byte for byte — not as
/// a mode anyone should build with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Liveness {
    On,
    Off,
}

/// Should the build use the Task 8/9 precompiles? `Off` compiles the reduction and the leaf
/// sponges as ordinary instruction sequences — the differential references — `On` emits
/// `REDUCE`/`SPONGE`. The shipped program is always `On`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Precompiles {
    Off,
    On,
}

/// What a built program cost. `cells` counts the memory cells the program reserves: the spill
/// arena's peak concurrent usage plus everything [`Builder::alloc`] handed out. `phase_rows` is
/// the final instruction count per [`Builder::note_phase`] section, spill and reload insertions
/// included — the pre-liveness builder counted the same thing inline at the phase boundaries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub instrs: usize,
    pub spills: usize,
    pub reloads: usize,
    pub perms: usize,
    pub cells: u64,
    /// Peak simultaneously-live handles over the build (Task 7): the number the liveness
    /// analysis exists to shrink — the pre-liveness build's answer is "every handle the program
    /// ever creates".
    pub live_max: usize,
    pub phase_rows: Vec<(&'static str, usize)>,
}

// ------------------------------------------------------------------ the buffered operations

/// A register reference in a buffered instruction: a handle's home (lane 0 or 1 of the pair), a
/// materialise's output (the [`Op2::Mat`] entry's index), a symbolic scratch slot (per group,
/// assigned in buffered order at replay), or a literal register (`r0` and the raw layer's own).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum RRef {
    Home(u32, u8),
    Mat(u32, u8),
    Scratch(u32),
    Raw(u8),
}

impl RRef {
    pub(super) fn scratch(sym: u8) -> RRef {
        RRef::Scratch(sym as u32)
    }
}

/// The fourth word of a buffered instruction: a register reference or an immediate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum BRef {
    Home(u32, u8),
    Mat(u32, u8),
    Scratch(u32),
    Imm(F),
}

/// A register reference as the fourth word of an instruction.
pub(super) fn bref_of(r: RRef) -> BRef {
    match r {
        RRef::Home(id, lane) => BRef::Home(id, lane),
        RRef::Mat(e, lane) => BRef::Mat(e, lane),
        RRef::Scratch(sym) => BRef::Scratch(sym),
        RRef::Raw(r) => BRef::Imm(F::from_u8(r)),
    }
}

#[derive(Clone, Debug)]
enum Op2 {
    /// A `begin()`/`raw_group()` marker: scratch assignment resets here.
    Group,
    /// A materialise: at replay, the handle's home register if resident, else a reload into the
    /// next scratch slot. Field references to this entry are `RRef::Mat(index)`.
    Mat { id: u32 },
    /// A fresh handle: at replay, claim its home register (evicting if needed).
    Def { id: u32, width: u8 },
    /// A `take_scratch` call: reserve `n` symbolic scratch slots, assigned in order at replay.
    TakeScratch { n: usize },
    /// One annotated instruction. `target` is a buffer index for `Jmp`/`Jeq`/`Jne` (or
    /// `u32::MAX`): branch targets are buffer positions, resolved to final pcs at replay.
    Instr { op: Op, rd: RRef, ra: RRef, b: BRef, target: u32, checkpoint: Option<String> },
    /// Loop markers, paired by `id`: the liveness clamp and the allocation-invariant check.
    LoopTop { id: u32 },
    LoopEnd { id: u32 },
    /// A phase boundary for `Stats::phase_rows`: the replay counts emitted instructions between
    /// consecutive markers.
    Phase { name: &'static str },
}

struct Slot {
    width: u8,
    /// The value, when it is a compile-time constant ([`Builder::constant`], [`Builder::zero`]).
    /// Only [`Builder::counted_loop`] reads it; it is deliberately *not* propagated through
    /// arithmetic.
    konst: Option<F>,
    /// The `r0` handle: reads as the literal register 0, never allocated, never freed.
    zero: bool,
}

/// A pointer: a value slot holding a base address, plus a compile-time cell delta that is folded
/// into the immediate of whatever `LOAD`/`STORE` uses it.
#[derive(Clone, Copy, Debug)]
struct PtrSlot {
    holder: u32,
    delta: i64,
    /// The holder's compile-time value: the `FADDI` immediate `alloc` materialised it with.
    /// Every `Ptr` descends from `alloc` (through `offset`), so every pointer's absolute
    /// address is a compile-time constant — which is what `reduce` writes into a descriptor.
    base_value: u64,
}

pub struct Builder {
    mode: Checkpoints,
    liveness: Liveness,
    precompiles: Precompiles,
    ops: Vec<Op2>,
    /// The names passed to [`Builder::checkpoint`], in order, whatever the mode.
    names: Vec<String>,
    slots: Vec<Slot>,
    ptrs: Vec<PtrSlot>,
    next_cell: u64,
    /// Scratch slots handed out in the current group (buffered; the replay assigns concrete
    /// registers in the same order).
    scratch: usize,
    zero: Option<Felt>,
    /// The sixteen cells `dsl::hash` hashes through, allocated on first use.
    hash: Option<Ptr>,
    /// Loop markers are paired by a counter, so nested loops match up.
    next_loop: u32,
    /// Instructions buffered so far — the incremental count `note_phase`'s callers measure with.
    buf_instrs: usize,
    stats: Stats,
}

impl Builder {
    pub fn new(checkpoints: Checkpoints) -> Self {
        Self::with_liveness(checkpoints, Liveness::On)
    }

    pub fn with_liveness(checkpoints: Checkpoints, liveness: Liveness) -> Self {
        Self::with_opts(checkpoints, liveness, Precompiles::On)
    }

    pub fn with_opts(checkpoints: Checkpoints, liveness: Liveness, precompiles: Precompiles) -> Self {
        Builder {
            mode: checkpoints,
            liveness,
            precompiles,
            ops: Vec::new(),
            names: Vec::new(),
            slots: Vec::new(),
            ptrs: Vec::new(),
            next_cell: MEM_BASE,
            scratch: 0,
            zero: None,
            hash: None,
            next_loop: 0,
            buf_instrs: 0,
            stats: Stats::default(),
        }
    }

    /// The instructions buffered so far, spill/reload insertions excluded (they exist only at
    /// replay). What `Builder::stats` reported incrementally before Task 7.
    pub(crate) fn emitted(&self) -> usize {
        self.buf_instrs
    }

    /// Mark a phase boundary for `Stats::phase_rows`.
    pub fn note_phase(&mut self, name: &'static str) {
        self.ops.push(Op2::Phase { name });
    }

    /// The precompile policy this builder emits with.
    pub fn precompiles(&self) -> Precompiles {
        self.precompiles
    }

    /// Build the program and return it with its [`Stats`]: the replay computes spills, reloads,
    /// the final instruction count and `live_max`, so they are only knowable here. This is what
    /// every caller that wants the numbers uses; `finish` discards them.
    pub fn finish_stats(mut self) -> (Program, Stats) {
        self.emit(Op::Halt, RRef::Raw(0), RRef::Raw(0), BRef::Imm(F::ZERO));
        self.replay()
    }

    /// The names passed to [`Builder::checkpoint`], in order. Identical under both
    /// [`Checkpoints`] modes.
    pub fn checkpoint_names(&self) -> &[String] {
        &self.names
    }

    /// Close the program: append `HALT` and replay the buffered operations into the final
    /// instruction stream — see the module doc comment for the two policies. [`Builder::finish_stats`]
    /// returns the build's cost numbers with it.
    pub fn finish(self) -> Program {
        self.finish_stats().0
    }

    // ---------------------------------------------------------------- values

    pub fn constant(&mut self, v: F) -> Felt {
        self.begin();
        let (id, rd) = self.new_handle(1);
        self.emit(Op::Faddi, rd, RRef::Raw(0), BRef::Imm(v));
        self.slots[id as usize].konst = Some(v);
        Felt(id)
    }

    /// The constant zero: `r0` itself, so this costs no instruction and never spills.
    pub fn zero(&mut self) -> Felt {
        if let Some(z) = self.zero {
            return z;
        }
        let id = self.slots.len() as u32;
        self.slots.push(Slot { width: 1, konst: Some(F::ZERO), zero: true });
        let z = Felt(id);
        self.zero = Some(z);
        z
    }

    pub fn add(&mut self, a: Felt, b: Felt) -> Felt {
        self.bin(Op::Fadd, a, b)
    }

    pub fn sub(&mut self, a: Felt, b: Felt) -> Felt {
        self.bin(Op::Fsub, a, b)
    }

    pub fn mul(&mut self, a: Felt, b: Felt) -> Felt {
        self.bin(Op::Fmul, a, b)
    }

    pub fn add_const(&mut self, a: Felt, c: F) -> Felt {
        self.un(Op::Faddi, a, c)
    }

    pub fn mul_const(&mut self, a: Felt, c: F) -> Felt {
        self.un(Op::Fmuli, a, c)
    }

    /// `a⁻¹`, the inverse supplied as a hint; the row constrains `a·a⁻¹ = 1`, so a zero operand is
    /// an unsatisfiable row and an emulator error rather than a silent zero.
    pub fn inv(&mut self, a: Felt) -> Felt {
        self.un(Op::Inv, a, F::ZERO)
    }

    pub fn copy(&mut self, a: Felt) -> Felt {
        self.un(Op::Mov, a, F::ZERO)
    }

    // ------------------------------------------------------- extension values

    pub fn ext_constant(&mut self, v: EF) -> Ext {
        self.begin();
        let c = v.as_basis_coefficients_slice();
        let (c0, c1) = (c[0], c[1]);
        let (id, rd) = self.new_handle(2);
        self.emit(Op::Faddi, rd, RRef::Raw(0), BRef::Imm(c0));
        self.emit(Op::Faddi, RRef::Home(id, 1), RRef::Raw(0), BRef::Imm(c1));
        Ext(id)
    }

    /// `a` as `a + 0·X`.
    pub fn ext_lift(&mut self, a: Felt) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let (id, rd) = self.new_handle(2);
        self.emit(Op::Mov, rd, ra, BRef::Imm(F::ZERO));
        self.emit(Op::Mov, RRef::Home(id, 1), RRef::Raw(0), BRef::Imm(F::ZERO));
        Ext(id)
    }

    pub fn ext_add(&mut self, a: Ext, b: Ext) -> Ext {
        self.ebin(Op::Eadd, a, b)
    }

    pub fn ext_sub(&mut self, a: Ext, b: Ext) -> Ext {
        self.ebin(Op::Esub, a, b)
    }

    pub fn ext_mul(&mut self, a: Ext, b: Ext) -> Ext {
        self.ebin(Op::Emul, a, b)
    }

    pub fn ext_mul_base(&mut self, a: Ext, b: Felt) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let rb = self.materialise(b.0);
        let (id, rd) = self.new_handle(2);
        self.emit(Op::Emulf, rd, ra, bref_of(rb));
        Ext(id)
    }

    pub fn ext_inv(&mut self, a: Ext) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let (id, rd) = self.new_handle(2);
        self.emit(Op::Einv, rd, ra, BRef::Imm(F::ZERO));
        Ext(id)
    }

    /// `c0 + c1·X` from its two coefficients: two `MOV`s into an aligned register pair.
    pub fn ext_from_parts(&mut self, c0: Felt, c1: Felt) -> Ext {
        self.begin();
        let a0 = self.materialise(c0.0);
        let a1 = self.materialise(c1.0);
        let (id, rd) = self.new_handle(2);
        self.emit(Op::Mov, rd, a0, BRef::Imm(F::ZERO));
        self.emit(Op::Mov, RRef::Home(id, 1), a1, BRef::Imm(F::ZERO));
        Ext(id)
    }

    /// `(c0, c1)` of `a = c0 + c1·X`.
    pub fn ext_parts(&mut self, a: Ext) -> (Felt, Felt) {
        self.begin();
        let ra = self.materialise(a.0);
        let (i0, r0) = self.new_handle(1);
        self.emit(Op::Mov, r0, ra, BRef::Imm(F::ZERO));
        let (i1, r1) = self.new_handle(1);
        self.emit(Op::Mov, r1, lane1(ra), BRef::Imm(F::ZERO));
        (Felt(i0), Felt(i1))
    }

    // --------------------------------------------------------------- witness

    pub fn hint(&mut self) -> Felt {
        self.begin();
        let (id, rd) = self.new_handle(1);
        self.emit(Op::Hint, rd, RRef::Raw(0), BRef::Imm(F::ZERO));
        Felt(id)
    }

    pub fn hint_ext(&mut self) -> Ext {
        self.begin();
        let (id, rd) = self.new_handle(2);
        self.emit(Op::Hinte, rd, RRef::Raw(0), BRef::Imm(F::ZERO));
        Ext(id)
    }

    /// `n` witness words, read in order into `n` fresh cells, through one scratch register.
    pub fn hint_array(&mut self, n: usize) -> Array<Felt> {
        let base = self.alloc(n as u64);
        let holder = self.ptrs[base.0 as usize].holder;
        self.begin();
        let rp = self.materialise(holder);
        let s = self.take_scratch(1);
        for k in 0..n {
            self.emit(Op::Hint, RRef::scratch(s), RRef::Raw(0), BRef::Imm(F::ZERO));
            self.emit(Op::Store, RRef::scratch(s), rp, BRef::Imm(imm(k as i64)));
        }
        Array::new(base, n, 1)
    }

    /// `n` extension elements — `2n` witness words — into `2n` fresh cells.
    pub fn hint_ext_array(&mut self, n: usize) -> Array<Ext> {
        let base = self.alloc(2 * n as u64);
        let holder = self.ptrs[base.0 as usize].holder;
        self.begin();
        let rp = self.materialise(holder);
        let s = self.take_scratch(2);
        for k in 0..n {
            self.emit(Op::Hinte, RRef::scratch(s), RRef::Raw(0), BRef::Imm(F::ZERO));
            self.emit(Op::Storee, RRef::scratch(s), rp, BRef::Imm(imm(2 * k as i64)));
        }
        Array::new(base, n, 2)
    }

    // ---------------------------------------------------------------- memory

    /// Reserve `cells` cells. The base is a compile-time constant, materialised once with
    /// `FADDI rd, r0, base`.
    pub fn alloc(&mut self, cells: u64) -> Ptr {
        let base = self.next_cell;
        assert!(base + cells <= MEM_LIMIT, "the rVM's {MEM_LIMIT}-cell memory is full");
        self.next_cell += cells;
        self.stats.cells += cells;
        self.begin();
        let (id, rd) = self.new_handle(1);
        self.emit(Op::Faddi, rd, RRef::Raw(0), BRef::Imm(F::from_u64(base)));
        self.ptrs.push(PtrSlot { holder: id, delta: 0, base_value: base });
        Ptr(self.ptrs.len() as u32 - 1)
    }

    /// Reserve `cells` cells addressed **absolutely**: no holder register at all — every
    /// `LOAD`/`STORE` compiles to `r0` plus the full address immediate, and a register-only
    /// address operand (`POSEIDON2`, `SPONGE`) pays one `FADDI` into scratch per use. The
    /// pointer therefore claims no register and has no allocation the replay's loop invariant
    /// could see moved — the shape M5.3's interface-sponge state and cursor need: they live
    /// across the counted loop while the body's register pressure churns underneath.
    pub fn alloc_absolute(&mut self, cells: u64) -> Ptr {
        let base = self.next_cell;
        assert!(base + cells <= MEM_LIMIT, "the rVM's {MEM_LIMIT}-cell memory is full");
        self.next_cell += cells;
        self.stats.cells += cells;
        let z = self.zero();
        self.ptrs.push(PtrSlot { holder: z.0, delta: 0, base_value: base });
        Ptr(self.ptrs.len() as u32 - 1)
    }

    /// `p` shifted by `cells`. Free: the delta is folded into the immediate of every access.
    pub fn offset(&mut self, p: Ptr, cells: i64) -> Ptr {
        let it = self.ptrs[p.0 as usize];
        self.ptrs.push(PtrSlot { holder: it.holder, delta: it.delta + cells, base_value: it.base_value });
        Ptr(self.ptrs.len() as u32 - 1)
    }

    pub fn load(&mut self, p: Ptr, off: i64) -> Felt {
        self.begin();
        let (rp, at) = self.address(p, off);
        let (id, rd) = self.new_handle(1);
        self.emit(Op::Load, rd, rp, BRef::Imm(at));
        Felt(id)
    }

    pub fn store(&mut self, p: Ptr, off: i64, v: Felt) {
        self.begin();
        let rv = self.materialise(v.0);
        let (rp, at) = self.address(p, off);
        self.emit(Op::Store, rv, rp, BRef::Imm(at));
    }

    /// `v` stored at the absolute address *held in* `addr` — the runtime-addressed store the
    /// counted loop's staging needs (M5.3's interface sponge writes its next rate lane through
    /// a cursor cell, not a compile-time pointer). One row, no immediate.
    pub fn store_indirect(&mut self, addr: Felt, v: Felt) {
        self.begin();
        let ra = self.materialise(addr.0);
        let rv = self.materialise(v.0);
        self.emit(Op::Store, rv, ra, BRef::Imm(F::ZERO));
    }

    pub fn load_ext(&mut self, p: Ptr, off: i64) -> Ext {
        self.begin();
        let (rp, at) = self.address(p, off);
        let (id, rd) = self.new_handle(2);
        self.emit(Op::Loade, rd, rp, BRef::Imm(at));
        Ext(id)
    }

    pub fn store_ext(&mut self, p: Ptr, off: i64, v: Ext) {
        self.begin();
        let rv = self.materialise(v.0);
        let (rp, at) = self.address(p, off);
        self.emit(Op::Storee, rv, rp, BRef::Imm(at));
    }

    pub fn get(&mut self, a: Array<Felt>, idx: usize) -> Felt {
        assert!(idx < a.len, "index {idx} is past the end of a {}-element array", a.len);
        self.load(a.base, (idx * a.stride) as i64)
    }

    pub fn get_ext(&mut self, a: Array<Ext>, idx: usize) -> Ext {
        assert!(idx < a.len, "index {idx} is past the end of a {}-element array", a.len);
        self.load_ext(a.base, (idx * a.stride) as i64)
    }

    /// `n` cells from `src + src_off` to `dst + dst_off`, two rows per cell, through one scratch
    /// register and no allocator state changes beyond the two materialised base addresses.
    pub fn copy_cells(&mut self, dst: Ptr, dst_off: i64, src: Ptr, src_off: i64, n: usize) {
        if n == 0 {
            return;
        }
        let abs = |p: Ptr| self.slots[self.ptrs[p.0 as usize].holder as usize].zero;
        if abs(src) || abs(dst) {
            // An absolute side folds its whole address into the immediate — one `address` call
            // per element per side, no holder to materialise.
            self.begin();
            let t = self.take_scratch(1);
            for k in 0..n as i64 {
                let (rs, at_s) = self.address(src, src_off + k);
                let (rd, at_d) = self.address(dst, dst_off + k);
                self.emit(Op::Load, RRef::scratch(t), rs, BRef::Imm(at_s));
                self.emit(Op::Store, RRef::scratch(t), rd, BRef::Imm(at_d));
            }
            return;
        }
        let (from, to) = (self.ptrs[src.0 as usize], self.ptrs[dst.0 as usize]);
        self.begin();
        let rs = self.materialise(from.holder);
        let rd = self.materialise(to.holder);
        let t = self.take_scratch(1);
        for k in 0..n as i64 {
            self.emit(Op::Load, RRef::scratch(t), rs, BRef::Imm(imm(from.delta + src_off + k)));
            self.emit(Op::Store, RRef::scratch(t), rd, BRef::Imm(imm(to.delta + dst_off + k)));
        }
    }

    /// `n` zero cells at `p + off`, one row per cell — `r0` is the value.
    pub fn zero_cells(&mut self, p: Ptr, off: i64, n: usize) {
        if n == 0 {
            return;
        }
        if self.slots[self.ptrs[p.0 as usize].holder as usize].zero {
            self.begin();
            for k in 0..n as i64 {
                let (rp, at) = self.address(p, off + k);
                self.emit(Op::Store, RRef::Raw(0), rp, BRef::Imm(at));
            }
            return;
        }
        let it = self.ptrs[p.0 as usize];
        self.begin();
        let rp = self.materialise(it.holder);
        for k in 0..n as i64 {
            self.emit(Op::Store, RRef::Raw(0), rp, BRef::Imm(imm(it.delta + off + k)));
        }
    }

    /// The sixteen cells the DSL's hash layer works through, allocated once per program.
    pub(super) fn hash_scratch(&mut self) -> Ptr {
        if let Some(p) = self.hash {
            return p;
        }
        let p = self.alloc(16);
        self.hash = Some(p);
        p
    }

    /// Forget the cached hash scratch region; the next [`Builder::hash_scratch`] allocates a
    /// fresh one. M5.3's aggregate program calls this before its counted loop: a scratch holder
    /// allocated before the loop but first re-used inside it is exactly the handle the body's
    /// register pressure evicts — and the replay's loop invariant then names — while a scratch
    /// allocated *inside* the body is ordinary per-iteration state, free to churn. The pre-loop
    /// region's sixteen cells stay allocated (its holder dies at its last pre-loop use, so the
    /// invariant sees nothing), sixteen cells once, against the alternative.
    pub(crate) fn release_hash_scratch(&mut self) {
        self.hash = None;
    }

    // ---------------------------------------------------- the REDUCE precompile (Task 8)

    /// One run of the batch-opening reduction over `vals.len == row.len` columns:
    /// `acc += Σ_k alpha_pow·(vals_k − row_k)·inv` and `alpha_pow ·= alpha`, in one `REDUCE`
    /// instruction — the precompile form of the compiled loop [`run_reduce_sequence`] replaces,
    /// and differentially pinned to (`tests/precompiles.rs`). The 11-cell descriptor —
    /// `[vals_base, row_base, len, inv, acc, alpha_pow, alpha]` — is built fresh per call; the
    /// accumulator and running power are read back out of it, so a height group's runs chain
    /// exactly like the compiled loop's.
    pub fn reduce(&mut self, vals: Array<Ext>, row: Array<Felt>, inv: Ext, acc: Ext, alpha_pow: Ext, alpha: Ext) -> (Ext, Ext) {
        assert!(
            vals.len <= row.len,
            "a reduction run covers `vals.len` columns of the opened row (the rest are salts and              the hiding wrapper's hidden values, hashed by the leaf sponge, not reduced)"
        );
        self.begin();
        let descr = self.alloc(11);
        let vb = self.constant(F::from_u64(self.addr_of(vals.base)));
        self.store(descr, 0, vb);
        let rb = self.constant(F::from_u64(self.addr_of(row.base)));
        self.store(descr, 1, rb);
        let ln = self.constant(F::from_u64(vals.len as u64));
        self.store(descr, 2, ln);
        self.store_ext(descr, 3, inv);
        self.store_ext(descr, 5, acc);
        self.store_ext(descr, 7, alpha_pow);
        self.store_ext(descr, 9, alpha);
        let holder = self.ptrs[descr.0 as usize].holder;
        let ra = self.materialise(holder);
        self.emit(Op::Reduce, RRef::Raw(0), ra, BRef::Imm(F::ZERO));
        let acc_out = self.load_ext(descr, 5);
        let apow_out = self.load_ext(descr, 7);
        (acc_out, apow_out)
    }

    /// One `SPONGE` instruction (Task 9): absorb the four cells at `src` into rate lanes 0–3 of
    /// the state at `state`, permuted in place by the poseidon2 chip. `Ptr` deltas are folded
    /// into the registers first, the `poseidon2` rule (`Builder::poseidon2`).
    pub fn sponge_absorb(&mut self, state: Ptr, src: Ptr) {
        self.begin();
        let ra = self.ptr_reg(state);
        let rb = self.ptr_reg(src);
        self.emit(Op::Sponge, RRef::Raw(0), ra, bref_of(rb));
        self.stats.perms += 1;
    }

    /// The register a `Ptr`'s address lives in, folding any compile-time delta in first. An
    /// absolute pointer has no holder: the address is a constant, materialised into scratch.
    fn ptr_reg(&mut self, p: Ptr) -> RRef {
        let it = self.ptrs[p.0 as usize];
        if self.slots[it.holder as usize].zero {
            let s = self.take_scratch(1);
            self.emit(Op::Faddi, RRef::scratch(s), RRef::Raw(0), BRef::Imm(imm(it.base_value as i64 + it.delta)));
            return RRef::scratch(s);
        }
        let holder = self.materialise(it.holder);
        if it.delta == 0 {
            holder
        } else {
            let s = self.take_scratch(1);
            self.emit(Op::Faddi, RRef::scratch(s), holder, BRef::Imm(imm(it.delta)));
            RRef::scratch(s)
        }
    }

    // --------------------------------------------------------------- hashing

    /// Permute the eight cells at `p` in place. `POSEIDON2`'s pointer is a register with no
    /// immediate, so a `Ptr` carrying a compile-time delta — or an absolute pointer's constant
    /// address — costs one `FADDI` into scratch to fold it in first.
    pub fn poseidon2(&mut self, p: Ptr) {
        self.begin();
        let ra = self.ptr_reg(p);
        self.emit(Op::Poseidon2, RRef::Raw(0), ra, BRef::Imm(F::ZERO));
        self.stats.perms += 1;
    }

    // --------------------------------------------------------------- control

    /// `a == b`, or the program traps at a `pc` that names `what`.
    pub fn assert_eq(&mut self, a: Felt, b: Felt, what: &str) {
        self.begin();
        let ra = self.materialise(a.0);
        let rb = self.materialise(b.0);
        let t = self.take_scratch(1);
        self.emit_r(Op::Fsub, RRef::scratch(t), ra, bref_of(rb));
        let over = self.ops.len() as u32 + 2;
        self.emit(Op::Jeq, RRef::scratch(t), RRef::Raw(0), BRef::Imm(F::ZERO));
        self.set_target(over);
        self.trap(what);
    }

    /// Two [`Builder::assert_eq`]s, one per coefficient, named `"<what> (c0)"` and `"<what> (c1)"`.
    pub fn assert_eq_ext(&mut self, a: Ext, b: Ext, what: &str) {
        let (a0, a1) = self.ext_parts(a);
        let (b0, b1) = self.ext_parts(b);
        self.assert_eq(a0, b0, &format!("{what} (c0)"));
        self.assert_eq(a1, b1, &format!("{what} (c1)"));
    }

    /// `a != 0` **and** `a⁻¹`, in one row — the value and the assertion at once.
    pub fn ext_inv_checked(&mut self, a: Ext, what: &str) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let (id, rd) = self.new_handle(2);
        self.emit(Op::Einv, rd, ra, BRef::Imm(F::ZERO));
        self.name_last(what);
        Ext(id)
    }

    /// `a != 0`, in one row: `INV` of zero is exactly the trap, so the inverse *is* the assertion.
    pub fn assert_nonzero(&mut self, a: Felt, what: &str) {
        self.begin();
        let ra = self.materialise(a.0);
        let t = self.take_scratch(1);
        self.emit(Op::Inv, RRef::scratch(t), ra, BRef::Imm(F::ZERO));
        self.name_last(what);
    }

    /// `body` emitted `n` times, with the iteration index as a Rust `usize`.
    pub fn unrolled(&mut self, n: usize, mut body: impl FnMut(&mut Self, usize)) {
        for i in 0..n {
            body(self, i);
        }
    }

    /// `body` emitted once and executed when `a == b`: a `JNE` over it. Assertions branch to a
    /// trap; this is the working conditional — the one the runtime-length sponge's rate-fill
    /// branch needs (M5.3). The body's allocation effects are its own; a taken branch simply
    /// skips its rows.
    pub fn if_eq(&mut self, a: Felt, b: Felt, body: impl FnOnce(&mut Self)) {
        self.begin();
        let ra = self.materialise(a.0);
        let rb = self.materialise(b.0);
        self.emit(Op::Jne, ra, rb, BRef::Imm(F::ZERO));
        let at = self.ops.len() as u32 - 1;
        body(self);
        // The branch lands on the group marker that follows the body, so it resolves even when
        // the body's last buffer entry is itself a marker.
        self.begin();
        let over = self.ops.len() as u32 - 1;
        self.set_target_at(at, over);
    }

    /// `body` emitted **once** and executed `n` times, with a down-counter as its index. The
    /// preconditions are unchanged from the pre-liveness builder: `n >= 1`, and the body must
    /// not move any handle that existed before the loop — the replay checks the allocation
    /// invariant at the loop markers (the pre-liveness builder checked it at emit time).
    pub fn counted_loop(&mut self, n: Felt, mut body: impl FnMut(&mut Self, Felt)) {
        assert!(
            self.slots[n.0 as usize].konst != Some(F::ZERO),
            "counted_loop: the iteration count is a compile-time zero. The counter is tested after \
             the body, so this would run the body once and then 2^64 - 2^32 more times, not zero \
             times — n >= 1 is the precondition. Branch around the loop instead."
        );
        self.begin();
        let rn = self.materialise(n.0);
        let (ctr, rc) = self.new_handle(1);
        self.emit(Op::Mov, rc, rn, BRef::Imm(F::ZERO));

        let loop_id = self.next_loop;
        self.next_loop += 1;
        let top = self.ops.len() as u32;
        self.ops.push(Op2::LoopTop { id: loop_id });
        body(self, Felt(ctr));
        self.ops.push(Op2::LoopEnd { id: loop_id });

        self.begin();
        self.emit(Op::Faddi, RRef::Home(ctr, 0), RRef::Home(ctr, 0), BRef::Imm(F::NEG_ONE));
        self.emit(Op::Jne, RRef::Home(ctr, 0), RRef::Raw(0), BRef::Imm(F::ZERO));
        self.set_target(top + 1);
    }

    /// [`counted_loop`] with its counter in a memory cell, not a register: `cell` (one
    /// **absolute** cell, [`Builder::alloc_absolute`]) holds the remaining count, reloaded,
    /// decremented and stored back once per iteration, so the loop keeps no register resident
    /// and the body receives no counter. That is the shape a big body needs: a resident counter
    /// whose only use is the post-body decrement is the first handle the body's register
    /// pressure evicts, and the replay's loop invariant then names it (M5.3's aggregate program
    /// hit exactly this). The trip count and the test-after-the-body order are
    /// [`counted_loop`]'s: `n >= 1` is the precondition.
    pub fn counted_loop_mem(&mut self, cell: Ptr, n: Felt, mut body: impl FnMut(&mut Self)) {
        assert!(
            self.slots[self.ptrs[cell.0 as usize].holder as usize].zero,
            "counted_loop_mem's counter cell must be absolute (alloc_absolute): a register-backed \
             cell's holder lives across the body and the loop invariant forbids moving it"
        );
        assert!(
            self.slots[n.0 as usize].konst != Some(F::ZERO),
            "counted_loop_mem: the iteration count is a compile-time zero — n >= 1 is the \
             precondition. Branch around the loop instead."
        );
        self.store(cell, 0, n);

        let loop_id = self.next_loop;
        self.next_loop += 1;
        let top = self.ops.len() as u32;
        self.ops.push(Op2::LoopTop { id: loop_id });
        body(self);
        self.ops.push(Op2::LoopEnd { id: loop_id });

        let t = self.load(cell, 0);
        let dec = self.add_const(t, F::NEG_ONE);
        self.store(cell, 0, dec);
        self.begin();
        let r = self.materialise(dec.0);
        self.emit(Op::Jne, r, RRef::Raw(0), BRef::Imm(F::ZERO));
        self.set_target(top + 1);
    }

    // ---------------------------------------------------------------- output

    pub fn public(&mut self, v: Felt) {
        self.begin();
        let ra = self.materialise(v.0);
        self.emit(Op::Public, RRef::Raw(0), ra, BRef::Imm(F::ZERO));
    }

    /// `c0` then `c1`, the order `BasedVectorSpace` reads an extension element in.
    pub fn public_ext(&mut self, v: Ext) {
        self.begin();
        let ra = self.materialise(v.0);
        self.emit(Op::Public, RRef::Raw(0), ra, BRef::Imm(F::ZERO));
        self.emit(Op::Public, RRef::Raw(0), lane1(ra), BRef::Imm(F::ZERO));
    }

    /// An intermediate value a differential test wants to see: published under
    /// [`Checkpoints::On`], nothing at all under `Off`.
    pub fn checkpoint(&mut self, name: &str, v: Ext) {
        self.names.push(name.to_string());
        if self.mode == Checkpoints::On {
            self.public_ext(v);
        }
    }

    // ------------------------------------------------------------- raw emission

    /// Start a raw instruction group: releases every scratch register the previous one held.
    pub(super) fn raw_group(&mut self) {
        self.begin();
    }

    /// `n` further contiguous scratch registers, reserved until the next [`Builder::raw_group`].
    pub(super) fn raw_scratch(&mut self, n: usize) -> u8 {
        self.take_scratch(n)
    }

    /// A field reference to `v`, reloading a spilled handle into scratch exactly as any operand is.
    pub(super) fn raw_reg(&mut self, v: Felt) -> RRef {
        self.materialise(v.0)
    }

    /// The field reference and compile-time cell delta an access through `p` uses. An absolute
    /// pointer's delta is its whole address (the reference is `r0`).
    pub(super) fn raw_ptr(&mut self, p: Ptr) -> (RRef, i64) {
        let it = self.ptrs[p.0 as usize];
        if self.slots[it.holder as usize].zero {
            return (RRef::Raw(0), it.base_value as i64 + it.delta);
        }
        (self.materialise(it.holder), it.delta)
    }

    /// One instruction, verbatim, with field references.
    pub(super) fn raw_emit(&mut self, op: Op, rd: RRef, ra: RRef, b: BRef) {
        self.emit(op, rd, ra, b);
    }

    /// A scratch slot as the fourth word of an instruction.
    pub(super) fn raw_scratch_b(s: u8) -> BRef {
        BRef::Scratch(s as u32)
    }

    /// A signed cell delta as an address immediate.
    pub(super) fn raw_imm(delta: i64) -> BRef {
        BRef::Imm(imm(delta))
    }

    // ------------------------------------------------------------- emission

    fn begin(&mut self) {
        self.scratch = 0;
        self.ops.push(Op2::Group);
    }

    fn emit(&mut self, op: Op, rd: RRef, ra: RRef, b: BRef) {
        self.buf_instrs += 1;
        self.ops.push(Op2::Instr { op, rd, ra, b, target: u32::MAX, checkpoint: None });
    }

    fn emit_r(&mut self, op: Op, rd: RRef, ra: RRef, rb: BRef) {
        self.emit(op, rd, ra, rb);
    }

    /// Set the last instruction's branch target (a buffer index).
    fn set_target(&mut self, target: u32) {
        let Some(Op2::Instr { target: t, .. }) = self.ops.last_mut() else {
            panic!("set_target on a non-instruction");
        };
        *t = target;
    }

    /// [`set_target`] for an instruction emitted earlier — `if_eq`'s forward branch, whose
    /// target is only known after the body.
    fn set_target_at(&mut self, at: u32, target: u32) {
        let Some(Op2::Instr { target: t, .. }) = self.ops.get_mut(at as usize) else {
            panic!("set_target_at on a non-instruction");
        };
        *t = target;
    }

    /// Record the last instruction's checkpoint name (assertion traps and checked inverses).
    fn name_last(&mut self, what: &str) {
        let Some(Op2::Instr { checkpoint, .. }) = self.ops.last_mut() else {
            panic!("name_last on a non-instruction");
        };
        *checkpoint = Some(what.to_string());
    }

    /// The inline trap for an assertion, and the name its `pc` resolves to.
    fn trap(&mut self, what: &str) {
        self.emit(Op::Inv, RRef::Raw(1), RRef::Raw(0), BRef::Imm(F::ZERO));
        self.name_last(what);
    }

    fn un(&mut self, op: Op, a: Felt, c: F) -> Felt {
        self.begin();
        let ra = self.materialise(a.0);
        let (id, rd) = self.new_handle(1);
        self.emit(op, rd, ra, BRef::Imm(c));
        Felt(id)
    }

    fn bin(&mut self, op: Op, a: Felt, b: Felt) -> Felt {
        self.begin();
        let ra = self.materialise(a.0);
        let rb = self.materialise(b.0);
        let (id, rd) = self.new_handle(1);
        self.emit_r(op, rd, ra, bref_of(rb));
        Felt(id)
    }

    fn ebin(&mut self, op: Op, a: Ext, b: Ext) -> Ext {
        self.begin();
        let ra = self.materialise(a.0);
        let rb = self.materialise(b.0);
        let (id, rd) = self.new_handle(2);
        self.emit_r(op, rd, ra, bref_of(rb));
        Ext(id)
    }

    /// The `(field reference, immediate)` pair an access through `p` at `off` uses. An absolute
    /// pointer's holder is the zero slot — `r0` — so its whole address folds into the immediate.
    fn address(&mut self, p: Ptr, off: i64) -> (RRef, F) {
        let it = self.ptrs[p.0 as usize];
        if self.slots[it.holder as usize].zero {
            return (RRef::Raw(0), imm(it.base_value as i64 + it.delta + off));
        }
        (self.materialise(it.holder), imm(it.delta + off))
    }

    /// The absolute address of a pointer, as a compile-time constant (`PtrSlot::base_value`).
    /// Public for the runtime-addressed stores that add a *runtime* offset to it (M5.3's staged
    /// absorb compares its cursor against `addr_of(state) + RATE`).
    pub fn addr_of(&self, p: Ptr) -> u64 {
        let it = self.ptrs[p.0 as usize];
        (it.base_value as i64 + it.delta) as u64
    }

    // ------------------------------------------------------------ allocation (buffer time)

    /// A field reference to `id`, recorded as a `Mat` entry: at replay, the handle's home
    /// register if resident, else a reload into the next scratch slot.
    fn materialise(&mut self, id: u32) -> RRef {
        if self.slots[id as usize].zero {
            return RRef::Raw(0);
        }
        let entry = self.ops.len() as u32;
        self.ops.push(Op2::Mat { id });
        RRef::Mat(entry, 0)
    }

    /// The next `width` symbolic scratch slots of this group.
    fn take_scratch(&mut self, width: usize) -> u8 {
        let at = self.scratch;
        assert!(
            at + width <= SCRATCH.len(),
            "one instruction wanted more than {} scratch registers",
            SCRATCH.len()
        );
        self.scratch = at + width;
        self.ops.push(Op2::TakeScratch { n: width });
        at as u8
    }

    /// A fresh handle: the slot, then the `Def` entry the replay allocates a home for.
    fn new_handle(&mut self, width: u8) -> (u32, RRef) {
        let id = self.slots.len() as u32;
        self.slots.push(Slot { width, konst: None, zero: false });
        self.ops.push(Op2::Def { id, width });
        (id, RRef::Home(id, 0))
    }

    // ------------------------------------------------------------ the replay

    fn replay(self) -> (Program, Stats) {
        let live = self.liveness == Liveness::On;
        let n = self.ops.len();

        // ── pass 1: liveness. last_use[id] is the last buffer index whose instruction or
        // materialise references `id`, with anything a loop body touches clamped to the loop's
        // end (a body re-executes, so "last use" inside it is really "until the loop is over").
        let mut last_use = vec![0u32; self.slots.len()];
        let mut def_idx = vec![u32::MAX; self.slots.len()];
        let mut loops: Vec<(u32, u32)> = Vec::new();
        let mut loop_stack: Vec<u32> = Vec::new();
        for (i, op) in self.ops.iter().enumerate() {
            match op {
                Op2::Mat { id } => last_use[*id as usize] = i as u32,
                Op2::Def { id, .. } => def_idx[*id as usize] = i as u32,
                Op2::Instr { rd, ra, b, .. } => {
                    for id in [rd, ra]
                        .iter()
                        .filter_map(|r| match r {
                            RRef::Home(id, _) => Some(*id),
                            RRef::Mat(e, _) => mat_owner(&self.ops, *e),
                            _ => None,
                        })
                        .chain(match b {
                            BRef::Home(id, _) => Some(*id),
                            BRef::Mat(e, _) => mat_owner(&self.ops, *e),
                            _ => None,
                        })
                    {
                        last_use[id as usize] = i as u32;
                    }
                }
                Op2::LoopTop { .. } => loop_stack.push(i as u32),
                Op2::LoopEnd { .. } => {
                    let top = loop_stack.pop().expect("unbalanced loop markers");
                    loops.push((top, i as u32));
                }
                Op2::Group | Op2::TakeScratch { .. } | Op2::Phase { .. } => {}
            }
        }
        for &(top, end) in &loops {
            for id in 0..self.slots.len() {
                if def_idx[id] != u32::MAX
                    && def_idx[id] < top
                    && last_use[id] > top
                    && last_use[id] < end
                {
                    last_use[id] = end;
                }
            }
        }
        // Deaths, bucketed by buffer index: at index `i` the replay frees exactly
        // `dying_at[i]`, without scanning every handle at every instruction.
        let mut dying_at: Vec<Vec<u32>> = vec![Vec::new(); n];
        for (id, &lu) in last_use.iter().enumerate() {
            if !self.slots[id].zero && def_idx[id] != u32::MAX {
                dying_at[lu as usize].push(id as u32);
            }
        }

        // Per-handle use lists, for the eviction rule's next-use pointers.
        let mut uses: Vec<Vec<u32>> = vec![Vec::new(); self.slots.len()];
        for (i, op) in self.ops.iter().enumerate() {
            match op {
                Op2::Mat { id } => uses[*id as usize].push(i as u32),
                Op2::Instr { rd, ra, b, .. } => {
                    for id in [rd, ra]
                        .iter()
                        .filter_map(|r| match r {
                            RRef::Home(id, _) => Some(*id),
                            RRef::Mat(e, _) => mat_owner(&self.ops, *e),
                            _ => None,
                        })
                        .chain(match b {
                            BRef::Home(id, _) => Some(*id),
                            BRef::Mat(e, _) => mat_owner(&self.ops, *e),
                            _ => None,
                        })
                    {
                        uses[id as usize].push(i as u32);
                    }
                }
                _ => {}
            }
        }
        for (id, us) in uses.iter_mut().enumerate() {
            // The liveness clamp applies to eviction too: pretend the clamped uses sit at the
            // loop end, so a resident used inside a loop is never evicted mid-loop.
            for &(top, end) in &loops {
                if def_idx[id] != u32::MAX && def_idx[id] < top {
                    for u in us.iter_mut() {
                        if *u > top && *u < end {
                            *u = end;
                        }
                    }
                }
            }
            us.sort_unstable();
        }

        // ── pass 2: the walk ──
        let mut out: Vec<Instr> = Vec::with_capacity(n + self.slots.len() / 4);
        let mut pc_of_buf: Vec<u32> = vec![u32::MAX; n];
        let mut checkpoints: Vec<(u32, String)> = Vec::new();
        let mut home: Vec<Option<u8>> = vec![None; self.slots.len()];
        let mut cells: Vec<Option<u64>> = vec![None; self.slots.len()];
        let mut regs: [Option<u32>; NUM_REGS] = [None; NUM_REGS];
        let mut residents: VecDeque<u32> = VecDeque::new();
        // Freed spill cells, by width: a width-2 spill may only reuse a cell pair that died as a
        // pair — a shared list let a width-2 spill overwrite the *neighbour* cell of a live
        // width-1 handle (the ext2 divergence: lane 0 clobbered, lane 1 intact).
        let mut free_cells_1: Vec<u64> = Vec::new();
        let mut free_cells_2: Vec<u64> = Vec::new();
        let mut arena: u64 = 0;
        let mut arena_peak: u64 = 0;
        let mut scratch_c = 0usize;
        let mut scratch_sym = 0u32;
        let mut scratch_slots: HashMap<u32, u8> = HashMap::new();
        let mut mat_out: HashMap<u32, u8> = HashMap::new();
        let mut live_count = 0usize;
        let mut live_max = 0usize;
        let mut phase_rows: Vec<(&'static str, usize)> = Vec::new();
        let mut phase_mark = 0usize;
        let mut stats = self.stats;
        let mut loop_snap: Vec<(u32, Vec<Option<u8>>, Vec<Option<u64>>)> = Vec::new();

        let ops = self.ops;
        for (i, op) in ops.iter().enumerate() {
            pc_of_buf[i] = out.len() as u32;
            match op {
                Op2::Group => {
                    scratch_c = 0;
                    scratch_sym = 0;
                    scratch_slots.clear();
                    mat_out.clear();
                }
                Op2::Mat { id } => {
                    let r = match home[*id as usize] {
                        Some(r) => r,
                        None => {
                            let width = self.slots[*id as usize].width;
                            let slot = take_scratch_concrete(&mut scratch_c, width);
                            let addr = cells[*id as usize].expect("a spilled handle has a cell");
                            let op = if width == 1 { Op::Load } else { Op::Loade };
                            out.push(Instr { op, rd: slot, ra: 0, b: F::from_u64(addr) });
                            stats.reloads += 1;
                            slot
                        }
                    };
                    mat_out.insert(i as u32, r);
                }
                Op2::Def { id, width } => {
                    // The registers the defining instruction(s) read must survive the claim —
                    // the pre-liveness `pinned` list: the next instructions' operand registers.
                    let mut pinned: Vec<u8> = Vec::new();
                    for next in ops[i + 1..].iter().take_while(|o| matches!(o, Op2::Instr { .. })).take(2) {
                        if let Op2::Instr { rd, ra, b, .. } = next {
                            let is_def = matches!(rd, RRef::Home(d, 0) if d == id);
                            for r in [*ra, b_rd_as_rref(b)] {
                                match r {
                                    RRef::Home(h, lane) => {
                                        if let Some(reg) = home[h as usize] {
                                            pinned.push(reg + lane);
                                        }
                                    }
                                    RRef::Mat(e, lane) => {
                                        if let Some(reg) = mat_out.get(&e) {
                                            if *reg < SCRATCH[0] {
                                                pinned.push(reg + lane);
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            if is_def && matches!(self.slots[*id as usize].width, 1) {
                                break;
                            }
                        }
                    }
                    let reg = claim(
                        *width,
                        &pinned,
                        &mut home,
                        &mut cells,
                        &mut regs,
                        &mut residents,
                        &mut free_cells_1,
                        &mut free_cells_2,
                        &mut arena,
                        &mut arena_peak,
                        &mut out,
                        &mut stats,
                        live,
                        &uses,
                        i as u32,
                        &self.slots,
                        &mut live_count,
                    );
                    home[*id as usize] = Some(reg);
                    regs[reg as usize] = Some(*id);
                    if *width == 2 {
                        regs[reg as usize + 1] = Some(*id);
                    }
                    residents.push_back(*id);
                    live_count += 1;
                    live_max = live_max.max(live_count);
                }
                Op2::TakeScratch { n } => {
                    // The concrete slots come from the group's shared counter (reloads and
                    // working slots in one sequence, the pre-liveness order); the symbolic
                    // indices the buffer handed out count TakeScratch calls only.
                    let base = take_scratch_concrete(&mut scratch_c, *n as u8);
                    for k in 0..*n {
                        scratch_slots.insert(scratch_sym + k as u32, base + k as u8);
                    }
                    scratch_sym += *n as u32;
                }
                Op2::Instr { op, rd, ra, b, target, checkpoint } => {
                    let rd = resolve_r(*rd, &home, &mat_out, &scratch_slots);
                    let ra = resolve_r(*ra, &home, &mat_out, &scratch_slots);
                    let b = resolve_b(*b, &home, &mat_out, &scratch_slots);
                    out.push(Instr { op: *op, rd, ra, b });
                    if let Some(name) = checkpoint {
                        checkpoints.push((out.len() as u32 - 1, name.clone()));
                    }
                    let _ = target;
                }
                Op2::LoopTop { id } => {
                    loop_snap.push((*id, home.clone(), cells.clone()));
                }
                Op2::Phase { name } => {
                    phase_rows.push((name, out.len() - phase_mark));
                    phase_mark = out.len();
                }
                Op2::LoopEnd { id } => {
                    let (want_id, was_home, was_cells) = loop_snap.pop().expect("unbalanced LoopEnd");
                    assert_eq!(*id, want_id, "unbalanced loop markers");
                    for h in 0..was_home.len() {
                        assert!(
                            home[h] == was_home[h] && cells[h] == was_cells[h],
                            "counted_loop: the body moved handle {h} from ({:?}, {:?}) to ({:?}, {:?}). A loop body is \
                             emitted once and run many times, so it must leave the allocation of every handle \
                             that existed before it untouched — pass values in and out through memory.",
                            was_home[h], was_cells[h], home[h], cells[h]
                        );
                    }
                }
            }
            // Free the handles whose last use this was (liveness only). A handle dies *after* the
            // instruction that last reads it, so eviction candidates see it through this index.
            if live {
                for id in dying_at[i].iter().copied().collect::<Vec<_>>() {
                    if let Some(r) = home[id as usize].take() {
                        regs[r as usize] = None;
                        if self.slots[id as usize].width == 2 {
                            regs[r as usize + 1] = None;
                        }
                        if let Some(pos) = residents.iter().position(|&h| h == id) {
                            residents.remove(pos);
                        }
                        live_count -= 1;
                    }
                    if let Some(c) = cells[id as usize].take() {
                        match self.slots[id as usize].width {
                            1 => free_cells_1.push(c),
                            _ => free_cells_2.push(c),
                        }
                    }
                }
            }
        }

        // Resolve branch targets (buffer indices) to final pcs.
        for (i, op) in ops.iter().enumerate() {
            if let Op2::Instr { op, target, .. } = op {
                if *target != u32::MAX {
                    let pc = pc_of_buf[i] as usize;
                    let to = pc_of_buf[*target as usize];
                    assert!(to != u32::MAX, "a branch targets a buffer position that emits no instruction");
                    out[pc].b = F::from_u64(to as u64);
                    let _ = op;
                }
            }
        }

        checkpoints.sort_by_key(|(pc, _)| *pc);
        stats.instrs = out.len();
        stats.live_max = live_max;
        stats.cells += arena_peak;
        stats.phase_rows = phase_rows;
        (Program { instrs: out, checkpoints }, stats)
    }
}

/// The `b` field of a buffered instruction as a register reference, when it is one.
fn b_rd_as_rref(b: &BRef) -> RRef {
    match b {
        BRef::Home(id, lane) => RRef::Home(*id, *lane),
        BRef::Mat(e, lane) => RRef::Mat(*e, *lane),
        BRef::Scratch(sym) => RRef::Scratch(*sym),
        BRef::Imm(_) => RRef::Raw(0),
    }
}

/// The handle a `Mat` entry materialises.
fn mat_owner(ops: &[Op2], entry: u32) -> Option<u32> {
    match &ops[entry as usize] {
        Op2::Mat { id } => Some(*id),
        _ => None,
    }
}

/// Lane 1 of the same reference: the upper half of a width-2 operand.
fn lane1(r: RRef) -> RRef {
    match r {
        RRef::Mat(e, 0) => RRef::Mat(e, 1),
        RRef::Home(id, 0) => RRef::Home(id, 1),
        other => panic!("lane1 of a base operand: {other:?}"),
    }
}

/// A concrete scratch register for a width-`width` need: the next slots of the group, asserted
/// against the bound and never colliding with a symbolic slot already taken.
fn take_scratch_concrete(c: &mut usize, width: u8) -> u8 {
    let at = *c;
    assert!(at + width as usize <= SCRATCH.len(), "one instruction wanted more than {} scratch registers", SCRATCH.len());
    *c = at + width as usize;
    SCRATCH[at]
}

/// Resolve a buffered register reference to a concrete register.
fn resolve_r(
    r: RRef,
    home: &[Option<u8>],
    mat_out: &HashMap<u32, u8>,
    scratch_slots: &HashMap<u32, u8>,
) -> u8 {
    match r {
        RRef::Home(id, lane) => home[id as usize].map(|r| r + lane).expect("a handle used after its last use"),
        RRef::Mat(e, lane) => *mat_out.get(&e).expect("a Mat entry with no output") + lane,
        RRef::Scratch(sym) => *scratch_slots.get(&sym).expect("a scratch slot never taken"),
        RRef::Raw(r) => r,
    }
}

fn resolve_b(
    b: BRef,
    home: &[Option<u8>],
    mat_out: &HashMap<u32, u8>,
    scratch_slots: &HashMap<u32, u8>,
) -> F {
    match b {
        BRef::Imm(v) => v,
        BRef::Home(id, lane) => F::from_u8(resolve_r(RRef::Home(id, lane), home, mat_out, scratch_slots)),
        BRef::Mat(e, lane) => F::from_u8(*mat_out.get(&e).expect("a Mat entry with no output") + lane),
        BRef::Scratch(sym) => F::from_u8(*scratch_slots.get(&sym).expect("a scratch slot never taken")),
    }
}

/// Claim a free register (or aligned pair), evicting as needed — the pre-liveness `claim`'s two
/// policies: the oldest resident first (`Off`), or the resident whose next use is farthest (`On`).
#[allow(clippy::too_many_arguments)]
fn claim(
    width: u8,
    pinned: &[u8],
    home: &mut [Option<u8>],
    cells: &mut [Option<u64>],
    regs: &mut [Option<u32>; NUM_REGS],
    residents: &mut VecDeque<u32>,
    free_cells_1: &mut Vec<u64>,
    free_cells_2: &mut Vec<u64>,
    arena: &mut u64,
    arena_peak: &mut u64,
    out: &mut Vec<Instr>,
    stats: &mut Stats,
    live: bool,
    uses: &[Vec<u32>],
    at: u32,
    slots: &[Slot],
    live_count: &mut usize,
) -> u8 {
    loop {
        let vacant = |r: u8| regs[r as usize].is_none();
        let found = if width == 1 {
            ALLOCATABLE.iter().copied().find(|&r| vacant(r))
        } else {
            ALLOCATABLE
                .iter()
                .copied()
                .step_by(2)
                .find(|&r| r < ALLOCATABLE[ALLOCATABLE.len() - 1] && vacant(r) && vacant(r + 1))
        };
        if let Some(r) = found {
            return r;
        }
        // Evict. `Off`: the oldest resident not pinned. `On`: the resident whose next use is
        // farthest away (never a pinned one).
        let victim = if live {
            let mut best: Option<(usize, u32)> = None;
            for (pos, &id) in residents.iter().enumerate() {
                let r = home[id as usize].expect("resident");
                if (0..slots[id as usize].width).any(|k| pinned.contains(&(r + k))) {
                    continue;
                }
                let ptr = uses[id as usize].partition_point(|&u| u <= at);
                let next = uses[id as usize].get(ptr).copied().unwrap_or(u32::MAX);
                if best.is_none_or(|(_, b)| next > b) {
                    best = Some((pos, next));
                }
            }
            best.map(|(pos, _)| pos).unwrap_or_else(|| panic!("every allocatable register is pinned: {} residents, pinned {pinned:?} at buffer {at}", residents.len()))
        } else {
            residents
                .iter()
                .position(|&id| {
                    let r = home[id as usize].expect("resident");
                    !(0..slots[id as usize].width).any(|k| pinned.contains(&(r + k)))
                })
                .expect("every allocatable register is pinned by one instruction")
        };
        let id = residents.remove(victim).expect("a valid resident index");
        let r = home[id as usize].take().expect("resident");
        if live {
            *live_count -= 1;
        }
        regs[r as usize] = None;
        if slots[id as usize].width == 2 {
            regs[r as usize + 1] = None;
        }
        let w = slots[id as usize].width as u64;
        let addr = if live {
            match w {
                1 => free_cells_1.pop().unwrap_or(*arena),
                _ => free_cells_2.pop().unwrap_or(*arena),
            }
        } else {
            *arena
        };
        if addr == *arena {
            *arena += w;
            *arena_peak = (*arena_peak).max(*arena);
        }
        assert!(addr + w <= MEM_BASE, "the {MEM_BASE}-cell spill arena is full; raise dsl::MEM_BASE");
        cells[id as usize] = Some(addr);
        let op = if w == 1 { Op::Store } else { Op::Storee };
        out.push(Instr { op, rd: r, ra: 0, b: F::from_u64(addr) });
        stats.spills += 1;
    }
}

/// A signed cell delta as an address immediate. Negative deltas are the field's negation, which is
/// the right answer for any address that is actually in range: `base + (-k)` is `base - k`.
fn imm(delta: i64) -> F {
    if delta >= 0 {
        F::from_u64(delta as u64)
    } else {
        F::ZERO - F::from_u64(delta.unsigned_abs())
    }
}
