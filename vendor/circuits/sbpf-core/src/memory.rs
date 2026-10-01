//! The four memory regions an sBPF program sees, and the only two operations on them that the
//! interpreter and the syscalls use. A virtual address's top 32 bits are its region index and its
//! low 32 bits the offset inside that region, so translation is a shift, a table lookup and a
//! bounds check — the same arithmetic `solana_sbpf::memory_region::AlignedMemoryMapping` does.
//!
//! There is no alignment rule: an eight-byte load at an odd address is legal, exactly as
//! `solana-sbpf`'s `ptr::read_unaligned` path makes it.

use crate::interp::Halt;

/// The program's read-only region: the text and the read-only data sections, both rebased here by
/// the ELF loader.
pub const REGION_PROGRAM: u64 = 0x1_0000_0000;
/// The stack. `r10` starts at the top of frame 0 and moves up one [`STACK_FRAME`] per call.
pub const REGION_STACK: u64 = 0x2_0000_0000;
/// The heap `sol_alloc_free_` hands out.
pub const REGION_HEAP: u64 = 0x3_0000_0000;
/// The serialized instruction: accounts, instruction data, program id. Writable — this is where a
/// program's effect on the world lands, and what the public output's `output_hash` covers.
pub const REGION_INPUT: u64 = 0x4_0000_0000;

/// Bytes per stack frame: **Solana's own 4 KiB**, not the M4.4 plan's 512.
///
/// Measured, in Task 6, against the real SPL Token ELF: with 512-byte frames the program faults
/// immediately at `0x1_ffff_f9e8` — 1 560 bytes *below* the stack region's base — because the
/// release build inlines `entrypoint::deserialize`, `Processor::process` and `process_transfer`
/// into one function whose single frame is around 2 KiB. A frame size is not a budget the host may
/// choose: it is part of the ABI the program was compiled against, and a program whose frame does
/// not fit does not run slowly, it does not run at all.
///
/// The plan's 32 KiB *stack* is kept; what gives way is the depth. See [`MAX_CALL_DEPTH`].
pub const STACK_FRAME: usize = 4096;
/// Frames. The push that would make the depth this is refused, as `solana-sbpf`'s
/// `max_call_depth` does.
///
/// **8, not Solana's 64** — the one place this crate is deliberately smaller than the real runtime,
/// because 64 × 4 KiB is 256 KiB and a 1 MiB guest that also carries a 256 KiB ELF buffer, a 48 KiB
/// instruction region and a 32 KiB heap cannot spare it (and `abi::run_call_with` zeroes the stack
/// before every run, so those bytes are RV32 store cycles as well as address space). SPL Token's
/// `Transfer` nests **0** calls deep — measured, `tests/sbpf_abi.rs` — so the headroom here is
/// eight frames against a workload that uses one. A program that nests deeper gets
/// [`Halt::CallDepth`], and this constant plus `STACK_BYTES` is the whole fix.
pub const MAX_CALL_DEPTH: usize = 8;
/// The whole static stack: 32 KiB, the M4.4 plan's number.
pub const STACK_BYTES: usize = STACK_FRAME * MAX_CALL_DEPTH;
/// The whole heap: 32 KiB, Solana's default.
pub const HEAP_BYTES: usize = 32_768;

/// The region index of `addr` — its top 32 bits.
#[inline]
fn region_of(addr: u64) -> u64 {
    addr >> 32
}

/// The offset of `addr` inside its region — its low 32 bits.
#[inline]
fn offset_of(addr: u64) -> usize {
    (addr & 0xffff_ffff) as usize
}

/// The four regions, as borrowed slices. Nothing here owns storage: the stack and heap arrays live
/// in the caller's [`crate::abi::Workspace`] (`.bss` in the guest), the program's spans in the ELF
/// buffer, and the input region in the workspace's decoded input.
pub struct Memory<'a> {
    /// The executable text, based at [`Memory::text_va`]. Read-only.
    pub text: &'a [u8],
    /// The virtual address of `text[0]`.
    pub text_va: u64,
    /// The read-only data span, based at [`Memory::rodata_base`]. In SBPF v1 this span *contains*
    /// the text (the loader borrows one contiguous read-only run beginning at `.text`), so the two
    /// overlap; a load is served by whichever covers it.
    pub rodata: &'a [u8],
    /// The virtual address of `rodata[0]`.
    pub rodata_base: u64,
    pub stack: &'a mut [u8; STACK_BYTES],
    pub heap: &'a mut [u8; HEAP_BYTES],
    pub input: &'a mut [u8],
}

impl<'a> Memory<'a> {
    /// `addr..addr + len` as a readable slice, or [`Halt::AccessViolation`] if any byte of it is
    /// outside every readable region.
    pub fn slice(&self, addr: u64, len: usize) -> Result<&[u8], Halt> {
        let off = offset_of(addr);
        let end = match off.checked_add(len) {
            Some(e) => e,
            None => return Err(Halt::AccessViolation(addr)),
        };
        let region: &[u8] = match region_of(addr) {
            1 => {
                // The program region holds two overlapping spans; try the read-only run first
                // (it is the larger of the two and contains the text in a loaded ELF).
                let rbase = offset_of(self.rodata_base);
                if off >= rbase && end <= rbase + self.rodata.len() {
                    return Ok(&self.rodata[off - rbase..end - rbase]);
                }
                let tbase = offset_of(self.text_va);
                if off >= tbase && end <= tbase + self.text.len() {
                    return Ok(&self.text[off - tbase..end - tbase]);
                }
                return Err(Halt::AccessViolation(addr));
            }
            2 => self.stack,
            3 => self.heap,
            4 => self.input,
            _ => return Err(Halt::AccessViolation(addr)),
        };
        if end > region.len() {
            return Err(Halt::AccessViolation(addr));
        }
        Ok(&region[off..end])
    }

    /// `addr..addr + len` as a writable slice. The program region is read-only, so a store into it
    /// is an access violation however well it is bounded.
    pub fn slice_mut(&mut self, addr: u64, len: usize) -> Result<&mut [u8], Halt> {
        let off = offset_of(addr);
        let end = match off.checked_add(len) {
            Some(e) => e,
            None => return Err(Halt::AccessViolation(addr)),
        };
        let region: &mut [u8] = match region_of(addr) {
            2 => self.stack,
            3 => self.heap,
            4 => self.input,
            _ => return Err(Halt::AccessViolation(addr)),
        };
        if end > region.len() {
            return Err(Halt::AccessViolation(addr));
        }
        Ok(&mut region[off..end])
    }

    /// A 1-, 2-, 4- or 8-byte little-endian load, zero-extended into a `u64`.
    pub fn load(&self, addr: u64, size: usize) -> Result<u64, Halt> {
        let bytes = self.slice(addr, size)?;
        let mut v = 0u64;
        for (i, b) in bytes.iter().enumerate() {
            v |= u64::from(*b) << (8 * i);
        }
        Ok(v)
    }

    /// A 1-, 2-, 4- or 8-byte little-endian store of `v`'s low `size` bytes.
    pub fn store(&mut self, addr: u64, size: usize, v: u64) -> Result<(), Halt> {
        let bytes = self.slice_mut(addr, size)?;
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (v >> (8 * i)) as u8;
        }
        Ok(())
    }

    /// Whether `a..a+n` and `b..b+n` do not overlap — `sol_memcpy_`'s precondition, the same test
    /// Agave's `is_nonoverlapping` makes.
    pub fn nonoverlapping(a: u64, b: u64, n: u64) -> bool {
        if a > b {
            a - b >= n
        } else {
            b - a >= n
        }
    }
}
