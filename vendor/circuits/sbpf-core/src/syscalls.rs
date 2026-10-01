//! The syscalls this interpreter implements, dispatched by the murmur3-32 hash of their name that
//! SBPF v1 puts in a `call` immediate.
//!
//! The list is the M4.4 plan's ("Interpreter scope"): `abort`, `sol_panic_`, the `sol_log*` family,
//! the four memory syscalls, `sol_alloc_free_`, and `sol_sha256` — the one that reaches the chip.
//! Anything else, including the names the plan explicitly rules out of scope
//! (`sol_keccak256`, `sol_secp256k1_recover`, the Ed25519 and `sol_invoke_signed_*` families, the
//! sysvar getters, `sol_create_program_address`), is [`Halt::UnknownSyscall`] — a program that
//! needs one cannot be proved rather than being silently given a wrong answer.
//!
//! Every pointer argument is a guest-chosen `u64`. Each is translated through
//! [`Memory`](crate::memory::Memory) before a byte moves, and a whole copy's *both* ranges are
//! checked before any of it happens, so a syscall either does all of its work or none of it.

use crate::interp::{Halt, Vm};
use crate::memory::{Memory, HEAP_BYTES, REGION_HEAP};
use crate::{Host, Sha256};

/// The hash SBPF v1 uses for a syscall name in a `call` immediate: MurmurHash3-32, seed 0, over the
/// raw name bytes. Identical to `solana_sbpf::ebpf::hash_symbol_name` (which reaches the same
/// algorithm through `hash32::Murmur3Hasher`), and `const` so every name below is a compile-time
/// constant and dispatch is a `match` on integers.
pub const fn murmur3_32(name: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = seed;
    let n = name.len();
    let blocks = n / 4;
    let mut i = 0;
    while i < blocks {
        let b = 4 * i;
        let k = (name[b] as u32)
            | ((name[b + 1] as u32) << 8)
            | ((name[b + 2] as u32) << 16)
            | ((name[b + 3] as u32) << 24);
        h ^= premix(k, C1, C2);
        h = h.rotate_left(13);
        h = h.wrapping_mul(5).wrapping_add(0xe654_6b64);
        i += 1;
    }
    let rem = n % 4;
    if rem > 0 {
        let b = blocks * 4;
        let mut k = 0u32;
        let mut j = 0;
        while j < rem {
            k |= (name[b + j] as u32) << (8 * j);
            j += 1;
        }
        h ^= premix(k, C1, C2);
    }
    h ^= n as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

const fn premix(mut k: u32, c1: u32, c2: u32) -> u32 {
    k = k.wrapping_mul(c1);
    k = k.rotate_left(15);
    k.wrapping_mul(c2)
}

/// `abort()` — the Rust panic handler's last call.
pub const ABORT: u32 = murmur3_32(b"abort", 0);
/// `sol_panic_(file, len, line, column)`.
pub const SOL_PANIC: u32 = murmur3_32(b"sol_panic_", 0);
/// `sol_log_(msg, len)`.
pub const SOL_LOG: u32 = murmur3_32(b"sol_log_", 0);
/// `sol_log_64_(a, b, c, d, e)`.
pub const SOL_LOG_64: u32 = murmur3_32(b"sol_log_64_", 0);
/// `sol_log_compute_units_()`.
pub const SOL_LOG_COMPUTE_UNITS: u32 = murmur3_32(b"sol_log_compute_units_", 0);
/// `sol_log_pubkey(pubkey)`.
pub const SOL_LOG_PUBKEY: u32 = murmur3_32(b"sol_log_pubkey", 0);
/// `sol_memcpy_(dst, src, n)` — non-overlapping only.
pub const SOL_MEMCPY: u32 = murmur3_32(b"sol_memcpy_", 0);
/// `sol_memmove_(dst, src, n)` — overlap allowed.
pub const SOL_MEMMOVE: u32 = murmur3_32(b"sol_memmove_", 0);
/// `sol_memset_(dst, c, n)`.
pub const SOL_MEMSET: u32 = murmur3_32(b"sol_memset_", 0);
/// `sol_memcmp_(a, b, n, result)`.
pub const SOL_MEMCMP: u32 = murmur3_32(b"sol_memcmp_", 0);
/// `sol_alloc_free_(size, free_addr)`.
pub const SOL_ALLOC_FREE: u32 = murmur3_32(b"sol_alloc_free_", 0);
/// `sol_sha256(vals, vals_len, result)` — the chip.
pub const SOL_SHA256: u32 = murmur3_32(b"sol_sha256", 0);

/// Every syscall this interpreter implements, with its name. Used by
/// `research/tests/sbpf_elf.rs` to check that the committed SPL Token ELF calls nothing else.
pub const SUPPORTED: &[(u32, &str)] = &[
    (ABORT, "abort"),
    (SOL_PANIC, "sol_panic_"),
    (SOL_LOG, "sol_log_"),
    (SOL_LOG_64, "sol_log_64_"),
    (SOL_LOG_COMPUTE_UNITS, "sol_log_compute_units_"),
    (SOL_LOG_PUBKEY, "sol_log_pubkey"),
    (SOL_MEMCPY, "sol_memcpy_"),
    (SOL_MEMMOVE, "sol_memmove_"),
    (SOL_MEMSET, "sol_memset_"),
    (SOL_MEMCMP, "sol_memcmp_"),
    (SOL_ALLOC_FREE, "sol_alloc_free_"),
    (SOL_SHA256, "sol_sha256"),
];

/// The chunk a copy or a compare moves at a time. A fixed buffer is what lets `sol_memmove_` work
/// over overlapping ranges without allocating and without a second borrow of the same region.
const CHUNK: usize = 64;

/// Runs the syscall `hash` names, with arguments in `r1..r5` and the result in `r0` — the same
/// convention `solana_sbpf::program::BuiltinFunction` has.
pub fn dispatch<H: Host>(vm: &mut Vm<H>, hash: u32) -> Result<(), Halt> {
    let (a, b, c, d) = (vm.regs[1], vm.regs[2], vm.regs[3], vm.regs[4]);
    match hash {
        // The two that end the run. A Solana program's `panic!` reaches one of these, and a
        // proof of a panicking program is exactly what status 2 is for.
        ABORT => return Err(Halt::Trap("abort")),
        SOL_PANIC => return Err(Halt::Trap("sol_panic_")),

        // The log family writes nothing: there is no log to write to in a proof, and nothing
        // on-chain reads one. The arguments are still translated, so a program that passes a bad
        // pointer to `sol_log_` faults here exactly as it would on Solana.
        SOL_LOG => {
            vm.mem.slice(a, usize_of(b)?)?;
            vm.regs[0] = 0;
        }
        SOL_LOG_PUBKEY => {
            vm.mem.slice(a, 32)?;
            vm.regs[0] = 0;
        }
        SOL_LOG_64 | SOL_LOG_COMPUTE_UNITS => vm.regs[0] = 0,

        SOL_MEMCPY | SOL_MEMMOVE => {
            let (dst, src, n) = (a, b, usize_of(c)?);
            if hash == SOL_MEMCPY && !Memory::nonoverlapping(dst, src, c) {
                return Err(Halt::Trap("sol_memcpy_ overlap"));
            }
            // Both ranges first, so a copy that would fault part-way through does nothing at all.
            vm.mem.slice(src, n)?;
            vm.mem.slice_mut(dst, n)?;
            let mut buf = [0u8; CHUNK];
            // Backwards when the destination is the higher of two overlapping ranges, so a
            // `sol_memmove_` does not overwrite bytes it has still to read.
            let backwards = dst > src && !Memory::nonoverlapping(dst, src, c);
            let mut done = 0usize;
            while done < n {
                let k = core::cmp::min(CHUNK, n - done);
                let at = if backwards { (n - done - k) as u64 } else { done as u64 };
                buf[..k].copy_from_slice(vm.mem.slice(src.wrapping_add(at), k)?);
                vm.mem.slice_mut(dst.wrapping_add(at), k)?.copy_from_slice(&buf[..k]);
                done += k;
            }
            vm.regs[0] = 0;
        }
        SOL_MEMSET => {
            let n = usize_of(c)?;
            vm.mem.slice_mut(a, n)?.fill(b as u8);
            vm.regs[0] = 0;
        }
        SOL_MEMCMP => {
            let n = usize_of(c)?;
            vm.mem.slice(a, n)?;
            vm.mem.slice(b, n)?;
            vm.mem.slice_mut(d, 4)?;
            let mut result = 0i32;
            let mut done = 0usize;
            let mut buf = [0u8; CHUNK];
            'outer: while done < n {
                let k = core::cmp::min(CHUNK, n - done);
                buf[..k].copy_from_slice(vm.mem.slice(a.wrapping_add(done as u64), k)?);
                let rhs = vm.mem.slice(b.wrapping_add(done as u64), k)?;
                for j in 0..k {
                    if buf[j] != rhs[j] {
                        result = i32::from(buf[j]) - i32::from(rhs[j]);
                        break 'outer;
                    }
                }
                done += k;
            }
            vm.mem.slice_mut(d, 4)?.copy_from_slice(&result.to_le_bytes());
            vm.regs[0] = 0;
        }

        // A bump allocator over the heap region: `free` is a no-op (the plan's "bump allocator via
        // `sol_alloc_free_`"), and an allocation that does not fit returns a null pointer rather
        // than halting, which is what a Solana program's allocator expects.
        SOL_ALLOC_FREE => {
            if b != 0 {
                vm.regs[0] = 0;
            } else {
                let size = a as usize;
                let base = (vm.heap_used + 7) & !7;
                match base.checked_add(size) {
                    Some(end) if end <= HEAP_BYTES && a <= HEAP_BYTES as u64 => {
                        vm.heap_used = end;
                        vm.regs[0] = REGION_HEAP + base as u64;
                    }
                    _ => vm.regs[0] = 0,
                }
            }
        }

        // The chip: `sol_sha256(vals, vals_len, result)` hashes the concatenation of `vals_len`
        // `(ptr, len)` pairs, each pair sixteen little-endian bytes, and writes the 32-byte digest
        // to `result`. Streamed, so a program may name more bytes than any buffer here could hold.
        SOL_SHA256 => {
            let pairs = usize_of(b)?;
            let bytes = pairs.checked_mul(16).ok_or(Halt::AccessViolation(a))?;
            vm.mem.slice(a, bytes)?;
            vm.mem.slice_mut(c, 32)?;
            let mut s = Sha256::new();
            let mut buf = [0u8; CHUNK];
            for p in 0..pairs {
                let at = a.wrapping_add((16 * p) as u64);
                let pair = vm.mem.slice(at, 16)?;
                let ptr = u64::from_le_bytes([
                    pair[0], pair[1], pair[2], pair[3], pair[4], pair[5], pair[6], pair[7],
                ]);
                let len_u64 = u64::from_le_bytes([
                    pair[8], pair[9], pair[10], pair[11], pair[12], pair[13], pair[14], pair[15],
                ]);
                let len = usize_of(len_u64)?;
                vm.mem.slice(ptr, len)?;
                let mut done = 0usize;
                while done < len {
                    let k = core::cmp::min(CHUNK, len - done);
                    buf[..k].copy_from_slice(vm.mem.slice(ptr.wrapping_add(done as u64), k)?);
                    s.update(vm.host, &buf[..k]);
                    done += k;
                }
            }
            let digest = s.finish(vm.host);
            vm.mem.slice_mut(c, 32)?.copy_from_slice(&digest);
            vm.regs[0] = 0;
        }

        other => return Err(Halt::UnknownSyscall(other)),
    }
    Ok(())
}

/// A guest-supplied length as a `usize`. On the 32-bit target a `u64` length above `u32::MAX` is
/// not a length at all; treating it as an access violation is the same answer the bounds check
/// would give, and keeps the cast from ever truncating.
fn usize_of(n: u64) -> Result<usize, Halt> {
    match usize::try_from(n) {
        Ok(v) => Ok(v),
        Err(_) => Err(Halt::AccessViolation(n)),
    }
}
