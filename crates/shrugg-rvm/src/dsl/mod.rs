//! The DSL every rVM program is written in (spec §4.1): typed handles over a linear register
//! allocator that spills to memory.
//!
//! A handle is a *virtual id*, never a register index — [`Builder`] decides where a value lives and
//! moves it as pressure demands, so a program is written as straight-line SSA-ish Rust and the
//! twenty-seven allocatable registers are the builder's problem. There are two id spaces, both
//! opaque: [`Felt`]/[`Ext`] index the builder's value slots, and [`Ptr`] indexes its pointer table
//! (a base slot plus a compile-time cell delta, so [`Builder::offset`] folds into a `LOAD`/`STORE`
//! immediate instead of emitting arithmetic).
//!
//! [`Digest`] and [`Array`] are pure address arithmetic: neither costs an instruction to form.
//!
//! On top of the builder sit the two layers every rVM verifier program is written against: [`hash`],
//! the leaf sponge, the truncated-permutation compressor and the Merkle walk, and [`transcript`], the
//! duplex challenger. Both are bit-exact with the Plonky3 code the native verifier calls, and
//! `tests/transcript.rs` checks that against those crates rather than against a second
//! implementation.

use std::marker::PhantomData;

mod builder;
pub mod hash;
pub mod transcript;

pub use builder::{Builder, Checkpoints, Liveness, Precompiles, Stats, MEM_BASE};

/// A digest is **four** field elements on this machine, not eight: `DIGEST_ELEMS = 4` in the
/// `ValMmcs`, `OUT = 4` in the sponge, `CHUNK = 4` in the compressor (spec §12 erratum 1). The
/// permutation *state* is eight wide; a digest is its first four lanes.
pub const DIGEST_ELEMS: usize = 4;

/// A base-field value; the virtual id of the slot holding it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Felt(pub(crate) u32);

/// An extension-field value `c0 + c1·X`; the virtual id of the *pair* holding it. Its two halves
/// always occupy two consecutive registers (or two consecutive cells when spilled), which is what
/// every `E`-operand instruction means by "the pair `(r, r+1)`".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ext(pub(crate) u32);

/// An address: the virtual id of a pointer-table entry, which is a base value plus a compile-time
/// cell delta. Cheap to offset, and never itself a `Felt` — memory is addressed only through here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ptr(pub(crate) u32);

/// Four consecutive cells at `Ptr`: [`DIGEST_ELEMS`] `= 4`, not 8 — see the rulings table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Digest(pub Ptr);

/// `len` elements of `T` at `base`, `stride` cells apart — one cell for a [`Felt`], two for an
/// [`Ext`]. Indexing is compile-time, so `get`/`get_ext` cost exactly one `LOAD`/`LOADE`.
#[derive(Clone, Copy, Debug)]
pub struct Array<T> {
    pub base: Ptr,
    pub len: usize,
    pub stride: usize,
    _t: PhantomData<T>,
}

impl<T> Array<T> {
    pub fn new(base: Ptr, len: usize, stride: usize) -> Self {
        Array { base, len, stride, _t: PhantomData }
    }
}
