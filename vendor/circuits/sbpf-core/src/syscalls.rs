//! The syscalls this interpreter implements, dispatched by the murmur3-32 hash of their name that
//! SBPF v1 puts in a `call` immediate.
//!
//! The list is the M4.4 plan's ("Interpreter scope") — `abort`, `sol_panic_`, the `sol_log*` family,
//! the four memory syscalls, `sol_alloc_free_`, and `sol_sha256` — plus ZKVM-116's first increment:
//! `sol_keccak256` (the Keccak chip), `sol_set_return_data` / `sol_get_return_data`, and the three
//! sysvar getters `sol_get_clock_sysvar`, `sol_get_rent_sysvar` and `sol_get_sysvar` (Clock and
//! Rent only). Anything else — `sol_secp256k1_recover`, the Ed25519 and `sol_invoke_signed_*`
//! families, `sol_create_program_address`, `sol_try_find_program_address` — is
//! [`Halt::UnknownSyscall`]: a program that needs one cannot be proved rather than being silently
//! given a wrong answer.
//!
//! # Compute units
//!
//! Every syscall is charged what Agave charges it (`SVMTransactionExecutionCost`'s defaults, the
//! constants below), against the same meter the instructions run on ([`Vm::consume`]). The charge is
//! in two parts so a translated program can pay the first for free: [`base_cost`] depends only on
//! which syscall it is and is charged before any argument is looked at; the rest depends on a
//! length and is charged where `dispatch` computes it. Two deliberate differences from Agave, both
//! on runs that halt either way: `sol_panic_` is not charged its message length (it traps), and a
//! charge is made before the argument checks rather than between them, so which exceptional halt a
//! doubly-wrong call reports may differ — never whether it halts.
//!
//! # Where the sysvars come from
//!
//! Clock and Rent are chain facts, so they are never read from the private input: the call carries
//! them on the **public** tape after the ELF ([`crate::abi`]), where `H_PUB` binds them and the chain
//! checks them against its own. A call that carries none halts in any sysvar getter
//! (a trap, "sysvar unavailable"), as does `sol_get_sysvar` for any id but Clock's and Rent's
//! — Agave would serve five more and answer `2` for the rest; halting is the reading that never
//! completes a run with an answer the chain did not supply.
//!
//! Every pointer argument is a guest-chosen `u64`. Each is translated through
//! [`Memory`](crate::memory::Memory) before a byte moves, and a whole copy's *both* ranges are
//! checked before any of it happens, so a syscall either does all of its work or none of it.

use crate::interp::{Halt, Vm, CLOCK_BYTES, MAX_RETURN_DATA, RENT_BYTES, SYSVAR_BYTES};
use crate::memory::{Memory, HEAP_BYTES, REGION_HEAP};
use crate::{Host, Keccak256, Sha256};

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
/// `sol_keccak256(vals, vals_len, result)` — the Keccak chip; `sol_sha256`'s shape.
pub const SOL_KECCAK256: u32 = murmur3_32(b"sol_keccak256", 0);
/// `sol_set_return_data(data, len)`.
pub const SOL_SET_RETURN_DATA: u32 = murmur3_32(b"sol_set_return_data", 0);
/// `sol_get_return_data(data, len, program_id)`.
pub const SOL_GET_RETURN_DATA: u32 = murmur3_32(b"sol_get_return_data", 0);
/// `sol_get_clock_sysvar(clock)`.
pub const SOL_GET_CLOCK_SYSVAR: u32 = murmur3_32(b"sol_get_clock_sysvar", 0);
/// `sol_get_rent_sysvar(rent)`.
pub const SOL_GET_RENT_SYSVAR: u32 = murmur3_32(b"sol_get_rent_sysvar", 0);
/// `sol_get_sysvar(sysvar_id, var, offset, length)` (SIMD-0127).
pub const SOL_GET_SYSVAR: u32 = murmur3_32(b"sol_get_sysvar", 0);

/// `SysvarC1ock11111111111111111111111111111111`.
pub const CLOCK_ID: [u8; 32] = [
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155,
    75, 109, 92, 115, 85, 91, 33, 0, 0, 0, 0,
];
/// `SysvarRent111111111111111111111111111111111`.
pub const RENT_ID: [u8; 32] = [
    6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161,
    253, 68, 227, 219, 217, 138, 0, 0, 0, 0,
];

/// Agave's `syscall_base_cost`, `log_64_units` and `log_pubkey_units`.
pub const CU_SYSCALL_BASE: u64 = 100;
/// Agave's `mem_op_base_cost`: the least a memory syscall, or one hashed slice, costs.
pub const CU_MEM_OP_BASE: u64 = 10;
/// Agave's `cpi_bytes_per_unit`: bytes moved per compute unit.
pub const CU_BYTES_PER_UNIT: u64 = 250;
/// Agave's `sha256_base_cost` (`sol_keccak256` is charged the same schedule).
pub const CU_HASH_BASE: u64 = 85;
/// Agave's `sysvar_base_cost`.
pub const CU_SYSVAR_BASE: u64 = 100;
/// `size_of::<Rent>()` in the program's memory: the 17 bytes of fields and 7 of padding.
pub const RENT_STRUCT_BYTES: usize = 24;

/// The part of a syscall's compute-unit charge that depends only on which syscall it is — charged
/// by [`dispatch`] before it looks at an argument, and by a translated program as part of the
/// charge of the basic block the `call` ends (`sbpf2rv`), where it costs no code at all. Zero for a
/// hash this interpreter does not implement.
///
/// | syscall | Agave's charge | here: base + length-dependent |
/// |---|---|---|
/// | `abort` | none | 0 |
/// | `sol_panic_` | `len` | 0 (it traps) |
/// | `sol_log_` | `max(100, len)` | 100 + `len − 100` above 100 |
/// | `sol_log_64_`, `sol_log_pubkey`, `sol_log_compute_units_` | 100 | 100 |
/// | `sol_mem{cpy,move,set,cmp}_` | `max(10, n / 250)` | 10 + `n / 250 − 10` above 2 750 |
/// | `sol_alloc_free_` | none | 0 |
/// | `sol_sha256`, `sol_keccak256` | 85 + per slice `max(10, len / 2)` | 85 + the same |
/// | `sol_set_return_data` | 100 + `len / 250` | 100 + the same |
/// | `sol_get_return_data` | 100 + `(copied + 32) / 250` if anything is copied | 100 + the same |
/// | `sol_get_clock_sysvar` | 100 + `size_of::<Clock>()` | 140 |
/// | `sol_get_rent_sysvar` | 100 + `size_of::<Rent>()` | 124 |
/// | `sol_get_sysvar` | 100 + `32 / 250` + `max(length / 250, 10)` | 110 + `length / 250 − 10` above 2 750 |
pub const fn base_cost(hash: u32) -> u64 {
    match hash {
        SOL_LOG | SOL_LOG_64 | SOL_LOG_COMPUTE_UNITS | SOL_LOG_PUBKEY => CU_SYSCALL_BASE,
        SOL_MEMCPY | SOL_MEMMOVE | SOL_MEMSET | SOL_MEMCMP => CU_MEM_OP_BASE,
        SOL_SHA256 | SOL_KECCAK256 => CU_HASH_BASE,
        SOL_SET_RETURN_DATA | SOL_GET_RETURN_DATA => CU_SYSCALL_BASE,
        SOL_GET_CLOCK_SYSVAR => CU_SYSVAR_BASE + CLOCK_BYTES as u64,
        SOL_GET_RENT_SYSVAR => CU_SYSVAR_BASE + RENT_STRUCT_BYTES as u64,
        SOL_GET_SYSVAR => CU_SYSVAR_BASE + CU_MEM_OP_BASE,
        _ => 0,
    }
}

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
    (SOL_KECCAK256, "sol_keccak256"),
    (SOL_SET_RETURN_DATA, "sol_set_return_data"),
    (SOL_GET_RETURN_DATA, "sol_get_return_data"),
    (SOL_GET_CLOCK_SYSVAR, "sol_get_clock_sysvar"),
    (SOL_GET_RENT_SYSVAR, "sol_get_rent_sysvar"),
    (SOL_GET_SYSVAR, "sol_get_sysvar"),
];

/// The chunk a copy or a compare moves at a time. A fixed buffer is what lets `sol_memmove_` work
/// over overlapping ranges without allocating and without a second borrow of the same region.
const CHUNK: usize = 64;

/// Runs the syscall `hash` names, with arguments in `r1..r5` and the result in `r0` — the same
/// convention `solana_sbpf::program::BuiltinFunction` has.
pub fn dispatch<H: Host>(vm: &mut Vm<H>, hash: u32) -> Result<(), Halt> {
    let (a, b, c, d) = (vm.regs[1], vm.regs[2], vm.regs[3], vm.regs[4]);
    // The fixed part of the charge first, before any argument is looked at — where a translated
    // program has already paid it (see [`base_cost`]).
    let base = base_cost(hash);
    vm.syscall_base_units = vm.syscall_base_units.saturating_add(base);
    vm.consume(base)?;
    match hash {
        // The two that end the run. A Solana program's `panic!` reaches one of these, and a
        // proof of a panicking program is exactly what status 2 is for.
        ABORT => return Err(Halt::Trap("abort")),
        SOL_PANIC => return Err(Halt::Trap("sol_panic_")),

        // The log family writes nothing: there is no log to write to in a proof, and nothing
        // on-chain reads one. The arguments are still translated, so a program that passes a bad
        // pointer to `sol_log_` faults here exactly as it would on Solana.
        SOL_LOG => {
            let n = usize_of(b)?;
            vm.consume_extra((n as u64).saturating_sub(CU_SYSCALL_BASE))?;
            vm.mem.slice(a, n)?;
            vm.regs[0] = 0;
        }
        SOL_LOG_PUBKEY => {
            vm.mem.slice(a, 32)?;
            vm.regs[0] = 0;
        }
        SOL_LOG_64 | SOL_LOG_COMPUTE_UNITS => vm.regs[0] = 0,

        SOL_MEMCPY | SOL_MEMMOVE => {
            let (dst, src, n) = (a, b, usize_of(c)?);
            vm.consume_extra(mem_op_extra(n))?;
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
            vm.consume_extra(mem_op_extra(n))?;
            vm.mem.slice_mut(a, n)?.fill(b as u8);
            vm.regs[0] = 0;
        }
        SOL_MEMCMP => {
            let n = usize_of(c)?;
            vm.consume_extra(mem_op_extra(n))?;
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

        // The chips: `sol_sha256(vals, vals_len, result)` hashes the concatenation of `vals_len`
        // `(ptr, len)` pairs, each pair sixteen little-endian bytes, and writes the 32-byte digest
        // to `result`; `sol_keccak256` is the same call over the other chip. Streamed, so a program
        // may name more bytes than any buffer here could hold.
        SOL_SHA256 => hash_slices::<H, Sha256>(vm, a, b, c)?,
        SOL_KECCAK256 => hash_slices::<H, Keccak256>(vm, a, b, c)?,

        // `sol_set_return_data(data, len)`: replaces the return data with `len` bytes, at most
        // [`MAX_RETURN_DATA`]. A zero length clears it without translating the pointer, as Agave
        // does. What is set when the program returns success is what the public output binds
        // ([`crate::abi`]).
        SOL_SET_RETURN_DATA => {
            let n = usize_of(b)?;
            vm.consume_extra(n as u64 / CU_BYTES_PER_UNIT)?;
            if n > MAX_RETURN_DATA {
                return Err(Halt::Trap("return data too large"));
            }
            if n != 0 {
                let src = vm.mem.slice(a, n)?;
                if let Some(dst) = vm.return_data.get_mut(..n) {
                    dst.copy_from_slice(src);
                }
            }
            vm.return_len = n;
            vm.regs[0] = 0;
        }
        // `sol_get_return_data(data, len, program_id)`: copies `min(len, set)` bytes of the return
        // data and the id of the program that set it — this one, there being no CPI — and returns
        // how many bytes are set. Nothing is translated or written when nothing is copied.
        SOL_GET_RETURN_DATA => {
            let set = vm.return_len;
            let n = core::cmp::min(b, set as u64) as usize;
            if n != 0 {
                vm.consume_extra((n as u64 + 32) / CU_BYTES_PER_UNIT)?;
                // Both ranges first, so the call does all of its work or none of it.
                vm.mem.slice_mut(a, n)?;
                vm.mem.slice_mut(c, 32)?;
                // Agave's `is_nonoverlapping(data, n, program_id, 32)`.
                let apart = if a > c { a - c >= 32 } else { c - a >= n as u64 };
                if !apart {
                    return Err(Halt::Trap("return data overlap"));
                }
                if let Some(src) = vm.return_data.get(..n) {
                    vm.mem.slice_mut(a, n)?.copy_from_slice(src);
                }
                vm.mem.slice_mut(c, 32)?.copy_from_slice(&vm.program_id);
            }
            vm.regs[0] = set as u64;
        }

        // `sol_get_clock_sysvar(clock)` / `sol_get_rent_sysvar(rent)`: the sysvar as the program's
        // own `#[repr(C)]` struct at an 8-aligned address (Agave's `translate_type_mut`, which
        // refuses a misaligned one for a program on the aligned loader). `Clock` is five 8-byte
        // integers, its account data byte for byte; `Rent` is its 17 bytes of fields and then 7 of
        // padding, written as zeros (Agave copies its own struct's padding there, which no program
        // may read).
        SOL_GET_CLOCK_SYSVAR | SOL_GET_RENT_SYSVAR => {
            let (from, fields, size) = if hash == SOL_GET_CLOCK_SYSVAR {
                (0, CLOCK_BYTES, CLOCK_BYTES)
            } else {
                (CLOCK_BYTES, RENT_BYTES, RENT_STRUCT_BYTES)
            };
            if a % 8 != 0 {
                return Err(Halt::AccessViolation(a));
            }
            vm.mem.slice_mut(a, size)?;
            if vm.sysvars_len != SYSVAR_BYTES {
                return Err(Halt::Trap("sysvar unavailable"));
            }
            let dst = vm.mem.slice_mut(a, size)?;
            dst.fill(0);
            if let (Some(d), Some(s)) = (dst.get_mut(..fields), vm.sysvars.get(from..from + fields)) {
                d.copy_from_slice(s);
            }
            vm.regs[0] = 0;
        }
        // `sol_get_sysvar(sysvar_id, var, offset, length)` (SIMD-0127): `length` bytes of the named
        // sysvar's account data from `offset`, or `1` — writing nothing — if that range runs past
        // the data's end. Only Clock and Rent are carried; see the module docs for the rest.
        SOL_GET_SYSVAR => {
            let n = usize_of(d)?;
            vm.consume_extra(mem_op_extra(n))?;
            let mut id = [0u8; 32];
            id.copy_from_slice(vm.mem.slice(a, 32)?);
            vm.mem.slice_mut(b, n)?;
            // `offset + length` must be a `u64` (Agave's `ArithmeticOverflow`).
            let end = match c.checked_add(d) {
                Some(e) => e,
                None => return Err(Halt::AccessViolation(c)),
            };
            let (from, len) = if id == CLOCK_ID {
                (0, CLOCK_BYTES)
            } else if id == RENT_ID {
                (CLOCK_BYTES, RENT_BYTES)
            } else {
                return Err(Halt::Trap("sysvar unavailable"));
            };
            if vm.sysvars_len != SYSVAR_BYTES {
                return Err(Halt::Trap("sysvar unavailable"));
            }
            if end > len as u64 {
                vm.regs[0] = 1;
            } else {
                // `c <= end <= len`, so both fit a `usize` and the range is inside the block.
                let at = from + c as usize;
                if let Some(src) = vm.sysvars.get(at..at + n) {
                    vm.mem.slice_mut(b, n)?.copy_from_slice(src);
                }
                vm.regs[0] = 0;
            }
        }

        other => return Err(Halt::UnknownSyscall(other)),
    }
    Ok(())
}

/// What a memory syscall over `n` bytes costs above [`CU_MEM_OP_BASE`]: Agave charges
/// `max(mem_op_base_cost, n / cpi_bytes_per_unit)`.
fn mem_op_extra(n: usize) -> u64 {
    (n as u64 / CU_BYTES_PER_UNIT).saturating_sub(CU_MEM_OP_BASE)
}

/// The streaming hash a `sol_sha256`-shaped syscall runs: SHA-256 or Keccak-256.
trait SliceHash<H: Host>: Sized {
    fn start() -> Self;
    fn absorb(&mut self, h: &mut H, bytes: &[u8]);
    fn digest(self, h: &mut H) -> [u8; 32];
}

impl<H: Host> SliceHash<H> for Sha256 {
    fn start() -> Self {
        Sha256::new()
    }
    fn absorb(&mut self, h: &mut H, bytes: &[u8]) {
        self.update(h, bytes)
    }
    fn digest(self, h: &mut H) -> [u8; 32] {
        self.finish(h)
    }
}

impl<H: Host> SliceHash<H> for Keccak256 {
    fn start() -> Self {
        Keccak256::new()
    }
    fn absorb(&mut self, h: &mut H, bytes: &[u8]) {
        self.update(h, bytes)
    }
    fn digest(self, h: &mut H) -> [u8; 32] {
        self.finish(h)
    }
}

/// `sol_sha256` / `sol_keccak256`: `(vals, vals_len, result)` in `(a, b, c)`. Each slice is charged
/// `max(10, len / 2)` before it is hashed (Agave's `sha256_byte_cost` is 1 per two bytes), which is
/// also what bounds the slice count: Agave's `sha256_max_slices` is 20 000, and 20 000 slices cost
/// the whole budget.
fn hash_slices<H: Host, D: SliceHash<H>>(vm: &mut Vm<H>, a: u64, b: u64, c: u64) -> Result<(), Halt> {
    let pairs = usize_of(b)?;
    let bytes = pairs.checked_mul(16).ok_or(Halt::AccessViolation(a))?;
    vm.mem.slice(a, bytes)?;
    vm.mem.slice_mut(c, 32)?;
    let mut s = D::start();
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
        vm.consume_extra(core::cmp::max(CU_MEM_OP_BASE, len as u64 / 2))?;
        vm.mem.slice(ptr, len)?;
        let mut done = 0usize;
        while done < len {
            let k = core::cmp::min(CHUNK, len - done);
            buf[..k].copy_from_slice(vm.mem.slice(ptr.wrapping_add(done as u64), k)?);
            s.absorb(vm.host, &buf[..k]);
            done += k;
        }
    }
    let digest = s.digest(vm.host);
    vm.mem.slice_mut(c, 32)?.copy_from_slice(&digest);
    vm.regs[0] = 0;
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
