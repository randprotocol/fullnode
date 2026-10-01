//! The C ABI a translated contract's runtime (`evm2rv`'s `evm-rt`) calls back into: `SLOAD` and
//! `SSTORE` over the ABI harness's own [`StorageTree`], and Keccak-256 over the guest's [`Host`].
//! The translated code never re-implements the witness tree or the sponge — it borrows this
//! crate's, so the storage root and every hash it computes are the interpreter's by construction.
//!
//! **The host crosses the boundary as a thin pointer.** `extern "C"` functions cannot be generic
//! and a `*mut dyn Host` is a fat pointer C cannot hold, so the shim wraps its host in a
//! [`HostBox`] (a `&mut dyn Host`, itself a [`Host`]) and hands C `&mut box as *mut HostBox as
//! *mut c_void`; these functions cast it back. The tree is passed the same way, as the
//! `*mut StorageTree` of the workspace the executor was lent.
//!
//! **Words.** A slot or value is eight `u32` limbs, least significant first — [`U256`]'s own
//! layout and the C runtime's `u256`. A storage failure is returned as a nonzero [`halt_code`];
//! 0 is success.
//!
//! The interpreter's guest calls none of this; it exists for `evm2rv` shims.

use core::ffi::c_void;

use crate::interp::Halt;
use crate::storage::{StorageError, StorageTree};
use crate::u256::U256;
use crate::{keccak256, Host};

/// A `&mut dyn Host` behind a thin pointer, so C can carry the host as a `void *`. It is a
/// [`Host`] itself, which is what lets the generic [`StorageTree`] methods take it.
pub struct HostBox<'a>(pub &'a mut dyn Host);

impl Host for HostBox<'_> {
    fn keccak_f(&mut self, state: &mut [u32; 50]) {
        self.0.keccak_f(state)
    }
    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        self.0.poseidon2(words, n)
    }
}

// The halt codes the C runtime and the shim agree on. 0 is "no halt" (the FFI's success).
pub const HALT_STOP: u32 = 1;
pub const HALT_RETURN: u32 = 2;
pub const HALT_REVERT: u32 = 3;
pub const HALT_OUT_OF_GAS: u32 = 4;
pub const HALT_STACK_UNDERFLOW: u32 = 5;
pub const HALT_STACK_OVERFLOW: u32 = 6;
pub const HALT_BAD_JUMP: u32 = 7;
pub const HALT_INVALID: u32 = 8;
/// `Halt::Trap(op)`: the opcode travels as the halt's argument.
pub const HALT_TRAP: u32 = 9;
pub const HALT_NO_WITNESS: u32 = 10;
pub const HALT_BAD_WITNESS: u32 = 11;
pub const HALT_OUT_OF_BOUNDS: u32 = 12;

/// A [`Halt`]'s code, never 0. A trap's opcode is not in the code; it is the argument
/// [`halt_from_code`] takes back.
pub const fn halt_code(h: Halt) -> u32 {
    match h {
        Halt::Stop => HALT_STOP,
        Halt::Return => HALT_RETURN,
        Halt::Revert => HALT_REVERT,
        Halt::OutOfGas => HALT_OUT_OF_GAS,
        Halt::StackUnderflow => HALT_STACK_UNDERFLOW,
        Halt::StackOverflow => HALT_STACK_OVERFLOW,
        Halt::BadJump => HALT_BAD_JUMP,
        Halt::Invalid => HALT_INVALID,
        Halt::Trap(_) => HALT_TRAP,
        Halt::NoWitness => HALT_NO_WITNESS,
        Halt::BadWitness => HALT_BAD_WITNESS,
        Halt::OutOfBounds => HALT_OUT_OF_BOUNDS,
    }
}

/// The [`Halt`] a code names (`arg` is a trap's opcode, ignored otherwise); `None` for 0 and for
/// any code outside the table.
pub const fn halt_from_code(code: u32, arg: u32) -> Option<Halt> {
    Some(match code {
        HALT_STOP => Halt::Stop,
        HALT_RETURN => Halt::Return,
        HALT_REVERT => Halt::Revert,
        HALT_OUT_OF_GAS => Halt::OutOfGas,
        HALT_STACK_UNDERFLOW => Halt::StackUnderflow,
        HALT_STACK_OVERFLOW => Halt::StackOverflow,
        HALT_BAD_JUMP => Halt::BadJump,
        HALT_INVALID => Halt::Invalid,
        HALT_TRAP => Halt::Trap(arg as u8),
        HALT_NO_WITNESS => Halt::NoWitness,
        HALT_BAD_WITNESS => Halt::BadWitness,
        HALT_OUT_OF_BOUNDS => Halt::OutOfBounds,
        _ => return None,
    })
}

/// A storage failure as the interpreter's halt (`interp`'s own mapping), as a code.
fn storage_code(e: StorageError) -> u32 {
    halt_code(match e {
        StorageError::NoWitness => Halt::NoWitness,
        StorageError::BadWitness => Halt::BadWitness,
        StorageError::TooMany | StorageError::DuplicateIndex => Halt::OutOfBounds,
    })
}

/// Eight limbs at `p` as a [`U256`]. Aligned word loads: a C `uint32_t *` is 4-aligned, and the
/// byte-wise loads `read_unaligned` would compile to cost four times the guest cycles.
///
/// # Safety
/// `p` must be valid and 4-aligned for reading eight `u32`s.
unsafe fn read_u256(p: *const u32) -> U256 {
    U256(core::array::from_fn(|i| p.add(i).read())) // SAFETY: `i < 8`, inside the eight aligned words the caller vouches for.
}

/// `SLOAD`: `StorageTree::load` of the slot at `slot`, the value written to `out` on success.
/// Returns 0, or the failure's [`halt_code`] (`out` untouched).
///
/// # Safety
/// `tree` is a valid, unaliased `*mut StorageTree`; `host` points to a live [`HostBox`]; `slot` is
/// readable and `out` writable for eight 4-aligned `u32`s.
#[no_mangle]
pub unsafe extern "C" fn evm_sload(
    tree: *mut StorageTree,
    host: *mut c_void,
    slot: *const u32,
    out: *mut u32,
) -> u32 {
    let (tree, h) = (&mut *tree, &mut *(host as *mut HostBox<'_>)); // SAFETY: `# Safety` above — both live and unaliased for this call (the shim's `translated` sets them and does not touch `tree`/`hb` while C runs).
    match tree.load(h, &read_u256(slot)) {
        Ok(v) => {
            for (i, limb) in v.0.iter().enumerate() {
                out.add(i).write(*limb); // SAFETY: `i < 8`, inside `out`'s eight writable words.
            }
            0
        }
        Err(e) => storage_code(e),
    }
}

/// `SSTORE`: `StorageTree::store` of the value at `value` into the slot at `slot`. Returns 0, or
/// the failure's [`halt_code`] (the tree unchanged). The gas the interpreter charges depends on
/// the previous value, so the runtime reads it with [`evm_sload`] first, as the interpreter does.
///
/// # Safety
/// As [`evm_sload`], with `value` readable for eight 4-aligned `u32`s.
#[no_mangle]
pub unsafe extern "C" fn evm_sstore(
    tree: *mut StorageTree,
    host: *mut c_void,
    slot: *const u32,
    value: *const u32,
) -> u32 {
    let (tree, h) = (&mut *tree, &mut *(host as *mut HostBox<'_>)); // SAFETY: as in `evm_sload`.
    match tree.store(h, &read_u256(slot), read_u256(value)) {
        Ok(_) => 0,
        Err(e) => storage_code(e),
    }
}

/// Keccak-256 of `len` bytes at `ptr` into the 32 bytes at `out`, over the host's permutation —
/// this crate's [`keccak256`]. `ptr` may be null when `len` is 0.
///
/// # Safety
/// `host` points to a live [`HostBox`]; `ptr` is readable for `len` bytes (or `len` is 0); `len` is
/// at most `isize::MAX` (2^31 − 1 on the 32-bit guest — `slice::from_raw_parts`'s own bound; the
/// runtime's memory is 64 KiB, so a real call is far below it); `out` is writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn evm_keccak256(host: *mut c_void, ptr: *const u8, len: u32, out: *mut u8) {
    debug_assert!(len <= isize::MAX as u32);
    let h = &mut *(host as *mut HostBox<'_>); // SAFETY: `host` is a live `HostBox`, not otherwise borrowed during the call.
    let msg: &[u8] = if len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(ptr, len as usize) // SAFETY: `len != 0`, so `ptr` is non-null and readable for `len <= isize::MAX` bytes; `u8` needs no alignment.
    };
    let d = keccak256(h, msg);
    core::ptr::copy_nonoverlapping(d.as_ptr(), out, 32); // SAFETY: `out` is writable for 32 bytes and cannot overlap the local `d`.
}
