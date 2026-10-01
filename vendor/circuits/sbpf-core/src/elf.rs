//! The SBPF v1 ELF loader: enough of ELF64 to load what the pre-versioning Solana toolchain emits
//! for BPFLoader2 — a `ET_DYN`, `EM_BPF`, little-endian 64-bit shared object whose sections sit at
//! their own file offsets — and to apply its three relocation types **in place**, so the loaded
//! program is two borrowed spans of the caller's buffer and nothing is allocated.
//!
//! # What is parsed
//!
//! * the file header: class, endianness, type, machine, `e_flags` (SBPF v1 is anything but the
//!   `0x20` that marks the reserved v2 format), `e_entry`, the section header table;
//! * the section header table, for `.text` (exactly one, as `solana-sbpf` insists) and for the
//!   read-only run `.text`/`.rodata`/`.data.rel.ro`/`.eh_frame`, which must be contiguous in the
//!   table and sit at `sh_addr == sh_offset` — the borrow path, and the only one v1 files need;
//! * `PT_DYNAMIC` (falling back to `SHT_DYNAMIC`, as `solana-sbpf` does for older files) for
//!   `DT_REL`/`DT_RELSZ`/`DT_RELENT`, `DT_SYMTAB`/`DT_SYMENT` and `DT_STRTAB`.
//!
//! # Relocations
//!
//! * `R_BPF_64_64` (1): an `lddw` naming a symbol — `addr = st_value + the 32-bit addend at the
//!   site`, rebased into the program region, written back as the pair's split `imm64`.
//! * `R_BPF_64_RELATIVE` (8): an address with no symbol. A site inside `.text` is an `lddw`'s split
//!   `imm64`; a site in a data section is an eight-byte pointer whose v1 encoding keeps only the
//!   low 32 bits, in the site's *second* word (a toolchain bug `solana-sbpf` still honours, and
//!   must be honoured bit for bit to load the committed ELF).
//! * `R_BPF_64_32` (10): a `call` target. A defined `STT_FUNC` symbol inside `.text` becomes a
//!   slot-relative call (`src` left at 0); anything else is a syscall, and the murmur3 hash of its
//!   name goes in the immediate with `src` set to 1. See [`crate::interp`] for why the convention
//!   lives in the instruction rather than in a function registry, and the `call imm` pass in
//!   [`load`] for how the file's own `BPF_PSEUDO_CALL` marker is normalised into it first.
//!
//! Every offset, length and index in the file is attacker-chosen: nothing here indexes without a
//! check, and every malformed file is [`Halt::BadElf`].

use crate::interp::Halt;
use crate::isa::opc;
use crate::memory::REGION_PROGRAM;
use crate::syscalls::murmur3_32;

/// A loaded program: the executable text and the read-only run, both borrowed from the relocated
/// ELF buffer, with the virtual addresses they were rebased to.
///
/// In SBPF v1 the read-only run *begins* at `.text`, so [`Program::rodata`] contains
/// [`Program::text`]; they are kept apart because only the text is fetched from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Program<'a> {
    pub text: &'a [u8],
    pub text_va: u64,
    pub rodata: &'a [u8],
    pub rodata_va: u64,
    /// The entrypoint, in slots from the start of the text.
    pub entry_pc: usize,
    /// Whether this program came through [`load`] (and so had its relocations applied) or through
    /// [`Program::from_text`].
    pub relocs_applied: bool,
}

impl<'a> Program<'a> {
    /// A bare text section at the base of the program region, entrypoint slot 0 — the shape
    /// `solana_sbpf::elf::Executable::from_text_bytes` produces, which is what the hand-assembled
    /// differential tests compare against.
    pub fn from_text(text: &'a [u8]) -> Result<Self, Halt> {
        if text.len() % 8 != 0 {
            return Err(Halt::BadElf);
        }
        Ok(Program {
            text,
            text_va: REGION_PROGRAM,
            rodata: text,
            rodata_va: REGION_PROGRAM,
            entry_pc: 0,
            relocs_applied: false,
        })
    }
}

// ---- byte readers: every one bounds-checked, every failure `BadElf` ----------------------------

fn u16_at(b: &[u8], off: usize) -> Result<u16, Halt> {
    let s = b.get(off..off.wrapping_add(2)).ok_or(Halt::BadElf)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, Halt> {
    let s = b.get(off..off.wrapping_add(4)).ok_or(Halt::BadElf)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], off: usize) -> Result<u64, Halt> {
    let s = b.get(off..off.wrapping_add(8)).ok_or(Halt::BadElf)?;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn put_u32(b: &mut [u8], off: usize, v: u32) -> Result<(), Halt> {
    let s = b.get_mut(off..off.wrapping_add(4)).ok_or(Halt::BadElf)?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn put_u64(b: &mut [u8], off: usize, v: u64) -> Result<(), Halt> {
    let s = b.get_mut(off..off.wrapping_add(8)).ok_or(Halt::BadElf)?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// A `usize` from a file field, refusing anything that would not index this machine's memory.
fn idx(v: u64) -> Result<usize, Halt> {
    usize::try_from(v).map_err(|_| Halt::BadElf)
}

/// One section header's fields, read out of the table so nothing borrows the buffer.
#[derive(Clone, Copy, Default)]
struct Shdr {
    name: u32,
    kind: u32,
    addr: u64,
    offset: u64,
    size: u64,
    entsize: u64,
}

const SHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

fn shdr_at(elf: &[u8], shoff: usize, i: usize) -> Result<Shdr, Halt> {
    let b = shoff.checked_add(i.checked_mul(SHDR_SIZE).ok_or(Halt::BadElf)?).ok_or(Halt::BadElf)?;
    Ok(Shdr {
        name: u32_at(elf, b)?,
        kind: u32_at(elf, b + 4)?,
        addr: u64_at(elf, b + 16)?,
        offset: u64_at(elf, b + 24)?,
        size: u64_at(elf, b + 32)?,
        entsize: u64_at(elf, b + 56)?,
    })
}

/// A NUL-terminated name out of a string table section, capped so a missing NUL cannot run away.
fn name_in<'a>(elf: &'a [u8], strtab: &Shdr, off: u32) -> Result<&'a [u8], Halt> {
    let start = idx(strtab.offset)?.checked_add(off as usize).ok_or(Halt::BadElf)?;
    let end = core::cmp::min(
        elf.len(),
        start.checked_add(256).ok_or(Halt::BadElf)?,
    );
    let span = elf.get(start..end).ok_or(Halt::BadElf)?;
    let n = span.iter().position(|&c| c == 0).ok_or(Halt::BadElf)?;
    Ok(&span[..n])
}

/// A section's file range, checked against the file's length.
fn file_range(elf: &[u8], s: &Shdr) -> Result<(usize, usize), Halt> {
    let start = idx(s.offset)?;
    let end = start.checked_add(idx(s.size)?).ok_or(Halt::BadElf)?;
    if end > elf.len() {
        return Err(Halt::BadElf);
    }
    Ok((start, end))
}

/// The sections whose contents make up the read-only region, in the order `solana-sbpf` accepts
/// them.
const RO_SECTIONS: [&[u8]; 4] = [b".text", b".rodata", b".data.rel.ro", b".eh_frame"];

/// Loads an SBPF v1 shared object, applying its relocations to `elf` in place.
pub fn load<'a>(elf: &'a mut [u8]) -> Result<Program<'a>, Halt> {
    // ---- file header ------------------------------------------------------------------------
    // An ELF64 header is 64 bytes; nothing below may index into a shorter file.
    if elf.len() < 64 {
        return Err(Halt::BadElf);
    }
    if elf.get(..4) != Some(&[0x7f, b'E', b'L', b'F'][..]) {
        return Err(Halt::BadElf);
    }
    if elf[4] != 2 || elf[5] != 1 {
        return Err(Halt::BadElf); // ELFCLASS64, ELFDATA2LSB
    }
    if u16_at(elf, 16)? != 3 {
        return Err(Halt::BadElf); // ET_DYN
    }
    let machine = u16_at(elf, 18)?;
    if machine != 247 && machine != 263 {
        return Err(Halt::BadElf); // EM_BPF, EM_SBPF
    }
    if u32_at(elf, 48)? == 0x20 {
        return Err(Halt::BadElf); // EF_SBPF_V2: the reserved format, not v1
    }
    let e_entry = u64_at(elf, 24)?;
    let phoff = idx(u64_at(elf, 32)?)?;
    let shoff = idx(u64_at(elf, 40)?)?;
    let phnum = u16_at(elf, 56)? as usize;
    let shnum = u16_at(elf, 60)? as usize;
    let shstrndx = u16_at(elf, 62)? as usize;
    if u16_at(elf, 58)? as usize != SHDR_SIZE || shnum == 0 || shstrndx >= shnum {
        return Err(Halt::BadElf);
    }
    if phnum != 0 && u16_at(elf, 54)? as usize != PHDR_SIZE {
        return Err(Halt::BadElf);
    }
    // The whole table must be inside the file before any of it is trusted.
    shdr_at(elf, shoff, shnum - 1)?;
    let shstrtab = shdr_at(elf, shoff, shstrndx)?;

    // ---- sections: `.text` and the read-only run ---------------------------------------------
    let mut text: Option<Shdr> = None;
    let mut n_text = 0usize;
    let mut ro_lo = u64::MAX;
    let mut ro_hi = 0u64;
    let mut ro_first = usize::MAX;
    let mut ro_last = 0usize;
    let mut ro_count = 0usize;
    for i in 0..shnum {
        let s = shdr_at(elf, shoff, i)?;
        file_range(elf, &s)?;
        let name = name_in(elf, &shstrtab, s.name)?;
        if name == b".text" {
            n_text += 1;
            text = Some(s);
        }
        if RO_SECTIONS.contains(&name) {
            // A read-only section must sit at its own file offset: this loader only has the
            // borrow path, not `solana-sbpf`'s copy-and-zero fallback.
            if s.addr != s.offset {
                return Err(Halt::BadElf);
            }
            if ro_count == 0 {
                ro_first = i;
            }
            ro_last = i;
            ro_count += 1;
            ro_lo = core::cmp::min(ro_lo, s.addr);
            ro_hi = core::cmp::max(ro_hi, s.addr.saturating_add(s.size));
        }
    }
    if n_text != 1 {
        return Err(Halt::BadElf);
    }
    let text = text.ok_or(Halt::BadElf)?;
    // Contiguous in the table, or the run cannot be one borrowed span.
    if ro_count == 0 || ro_last + 1 - ro_first != ro_count {
        return Err(Halt::BadElf);
    }
    let (text_start, text_end) = file_range(elf, &text)?;
    if (text_end - text_start) % 8 != 0 {
        return Err(Halt::BadElf);
    }
    let (ro_start, ro_end) = (idx(ro_lo)?, idx(ro_hi)?);
    if ro_end > elf.len() || ro_start > ro_end {
        return Err(Halt::BadElf);
    }

    // ---- the entrypoint ----------------------------------------------------------------------
    if e_entry < text.addr || e_entry >= text.addr.saturating_add(text.size) {
        return Err(Halt::BadElf);
    }
    let entry_off = e_entry - text.addr;
    if entry_off % 8 != 0 {
        return Err(Halt::BadElf);
    }
    let entry_pc = idx(entry_off / 8)?;

    // ---- `call imm`: the file's `BPF_PSEUDO_CALL` marker, normalised to this crate's ----------
    //
    // The toolchain marks **every** `call imm` it emits with `src = 1` — eBPF's
    // `BPF_PSEUDO_CALL`, "the immediate is a slot-relative target" — and leaves a syscall's
    // immediate at `-1` for `R_BPF_64_32` to fill in. All 158 call sites in the committed SPL
    // Token ELF are `src = 1`: 141 real pc-relative calls with no relocation, and 17 relocated
    // syscalls. `solana-sbpf` ignores `src` entirely on v1 and tells the two apart by the
    // relocation alone.
    //
    // This crate instead carries the distinction *in the instruction*, so the interpreter needs no
    // function registry (see [`crate::interp`]): `src = 0` is a slot-relative call, `src = 1` a
    // syscall whose immediate is the name's murmur3 hash. The file's marker is therefore cleared
    // here — the immediate under it is already exactly the slot-relative form the interpreter
    // wants — which leaves the relocation pass below as the only thing that ever sets `src = 1`,
    // and it sets it only where a relocation named the site. A `call imm` with any other `src` is
    // not something either toolchain emits, and is refused rather than reinterpreted.
    //
    // Only two bytes of each slot are read: the opcode, and the register byte whose high nibble is
    // `src`. Decoding the whole `u64` here cost 430 000 cycles of the SPL Token exit test's first
    // 3.85 M — 11 % of the run — because `u64_at`'s eight bounds-checked byte loads are paid on all
    // 12 826 slots while nothing but the opcode is wanted on 12 668 of them.
    {
        let mut i = text_start;
        while i + 8 <= text_end {
            let op = *elf.get(i).ok_or(Halt::BadElf)?;
            if op == opc::CALL_IMM {
                let regs = elf.get_mut(i + 1).ok_or(Halt::BadElf)?;
                match *regs >> 4 {
                    0 => {}
                    // `src` is the high nibble of the byte after the opcode.
                    1 => *regs &= 0x0f,
                    _ => return Err(Halt::BadElf),
                }
            }
            i += if op == opc::LD_DW_IMM { 16 } else { 8 };
        }
    }

    // ---- the dynamic table -------------------------------------------------------------------
    // `DT_STRTAB` 5, `DT_SYMTAB` 6, `DT_STRSZ` 10, `DT_SYMENT` 11, `DT_REL` 17, `DT_RELSZ` 18,
    // `DT_RELENT` 19. Only the addresses are taken from here; each is then resolved to a section
    // (which is how `solana-sbpf` finds the symbol and string tables too).
    let mut dyn_range: Option<(usize, usize)> = None;
    for i in 0..phnum {
        let b = phoff + i * PHDR_SIZE;
        if u32_at(elf, b)? == 2 {
            // PT_DYNAMIC
            let off = idx(u64_at(elf, b + 8)?)?;
            let len = idx(u64_at(elf, b + 32)?)?;
            let end = off.checked_add(len).ok_or(Halt::BadElf)?;
            if end <= elf.len() {
                dyn_range = Some((off, end));
            }
            break;
        }
    }
    if dyn_range.is_none() {
        for i in 0..shnum {
            let s = shdr_at(elf, shoff, i)?;
            if s.kind == 6 {
                // SHT_DYNAMIC
                dyn_range = Some(file_range(elf, &s)?);
                break;
            }
        }
    }

    let mut dt_rel = 0u64;
    let mut dt_relsz = 0u64;
    let mut dt_relent = 0u64;
    let mut dt_symtab = 0u64;
    let mut dt_strtab = 0u64;
    if let Some((start, end)) = dyn_range {
        let mut at = start;
        while at + 16 <= end {
            let tag = u64_at(elf, at)?;
            let val = u64_at(elf, at + 8)?;
            match tag {
                0 => break, // DT_NULL
                5 => dt_strtab = val,
                6 => dt_symtab = val,
                17 => dt_rel = val,
                18 => dt_relsz = val,
                19 => dt_relent = val,
                _ => {}
            }
            at += 16;
        }
    }

    let relocs_applied = true;
    if dt_rel != 0 {
        if dt_relent != 16 || dt_relsz == 0 || dt_relsz % 16 != 0 {
            return Err(Halt::BadElf);
        }
        let symtab = section_at_addr(elf, shoff, shnum, dt_symtab)?;
        if symtab.entsize != 24 {
            return Err(Halt::BadElf);
        }
        let (symtab_start, symtab_end) = file_range(elf, &symtab)?;
        let strtab = section_at_addr(elf, shoff, shnum, dt_strtab)?;
        file_range(elf, &strtab)?;
        let rel = section_at_addr(elf, shoff, shnum, dt_rel)?;
        let (rel_start, _) = file_range(elf, &rel)?;
        let n_relocs = idx(dt_relsz / 16)?;
        let rel_bytes = n_relocs.checked_mul(16).ok_or(Halt::BadElf)?;
        if rel_start.checked_add(rel_bytes).ok_or(Halt::BadElf)? > elf.len() {
            return Err(Halt::BadElf);
        }

        for k in 0..n_relocs {
            let at = rel_start + 16 * k;
            let r_offset = idx(u64_at(elf, at)?)?;
            let r_info = u64_at(elf, at + 8)?;
            let r_type = r_info as u32;
            let r_sym = idx(r_info >> 32)?;
            // The immediate of the instruction (or the second word of a data pointer) is four
            // bytes into the site.
            let imm_off = r_offset.checked_add(4).ok_or(Halt::BadElf)?;
            let imm_hi = r_offset.checked_add(12).ok_or(Halt::BadElf)?;
            let in_text = r_offset >= text_start && r_offset < text_end;

            match r_type {
                // R_BPF_64_64: an `lddw` naming a symbol; the addend is at the site.
                1 => {
                    let (_, st_value, _) = symbol(elf, symtab_start, symtab_end, r_sym)?;
                    let addend = u64::from(u32_at(elf, imm_off)?);
                    let mut addr = st_value.saturating_add(addend);
                    if addr < REGION_PROGRAM {
                        addr = REGION_PROGRAM.saturating_add(addr);
                    }
                    put_u32(elf, imm_off, addr as u32)?;
                    put_u32(elf, imm_hi, (addr >> 32) as u32)?;
                }
                // R_BPF_64_RELATIVE: an address with no symbol.
                8 => {
                    if in_text {
                        let lo = u64::from(u32_at(elf, imm_off)?);
                        let hi = u64::from(u32_at(elf, imm_hi)?);
                        let mut addr = (hi << 32) | lo;
                        if addr == 0 {
                            return Err(Halt::BadElf);
                        }
                        if addr < REGION_PROGRAM {
                            addr = REGION_PROGRAM.saturating_add(addr);
                        }
                        put_u32(elf, imm_off, addr as u32)?;
                        put_u32(elf, imm_hi, (addr >> 32) as u32)?;
                    } else {
                        // The v1 encoding of a data pointer: only the low 32 bits, in the site's
                        // second word.
                        let low = u64::from(u32_at(elf, imm_off)?);
                        put_u64(elf, r_offset, REGION_PROGRAM.saturating_add(low))?;
                    }
                }
                // R_BPF_64_32: a `call` target.
                10 => {
                    if !in_text {
                        return Err(Halt::BadElf);
                    }
                    let (st_name, st_value, st_info) =
                        symbol(elf, symtab_start, symtab_end, r_sym)?;
                    if st_info & 0x0f == 2 && st_value != 0 {
                        // A defined function: a bpf-to-bpf call. Rewrite it to the slot-relative
                        // form the interpreter takes, leaving `src` at 0.
                        if st_value < text.addr
                            || st_value >= text.addr.saturating_add(text.size)
                            || (st_value - text.addr) % 8 != 0
                        {
                            return Err(Halt::BadElf);
                        }
                        let target_pc = ((st_value - text.addr) / 8) as i64;
                        let site_pc = ((r_offset - text_start) / 8) as i64;
                        let rel = target_pc - (site_pc + 1);
                        let rel = i32::try_from(rel).map_err(|_| Halt::BadElf)?;
                        put_u32(elf, imm_off, rel as u32)?;
                    } else {
                        // A syscall: murmur3 of the name, with `src = 1` as the marker.
                        let hash = murmur3_32(name_in(elf, &strtab, st_name)?, 0);
                        put_u32(elf, imm_off, hash)?;
                        let b = elf
                            .get_mut(r_offset.checked_add(1).ok_or(Halt::BadElf)?)
                            .ok_or(Halt::BadElf)?;
                        *b = (*b & 0x0f) | 0x10;
                    }
                }
                _ => return Err(Halt::BadElf),
            }
        }
    }

    // Reborrow the relocated buffer immutably: the two spans overlap (the read-only run begins at
    // `.text`), which is why this is the one place the `&mut` is given up.
    let elf: &'a [u8] = elf;
    Ok(Program {
        text: &elf[text_start..text_end],
        text_va: REGION_PROGRAM + text.addr,
        rodata: &elf[ro_start..ro_end],
        rodata_va: REGION_PROGRAM + ro_lo,
        entry_pc,
        relocs_applied,
    })
}

/// A section by its virtual address — how the dynamic table names the symbol, string and
/// relocation tables.
fn section_at_addr(elf: &[u8], shoff: usize, shnum: usize, addr: u64) -> Result<Shdr, Halt> {
    if addr == 0 {
        return Err(Halt::BadElf);
    }
    for i in 0..shnum {
        let s = shdr_at(elf, shoff, i)?;
        if s.addr == addr {
            return Ok(s);
        }
    }
    Err(Halt::BadElf)
}

/// Symbol `i`'s `(st_name, st_value, st_info)`, or [`Halt::BadElf`] if the table has no such entry.
fn symbol(elf: &[u8], start: usize, end: usize, i: usize) -> Result<(u32, u64, u8), Halt> {
    let at = start.checked_add(i.checked_mul(24).ok_or(Halt::BadElf)?).ok_or(Halt::BadElf)?;
    if at.checked_add(24).ok_or(Halt::BadElf)? > end {
        return Err(Halt::BadElf);
    }
    Ok((u32_at(elf, at)?, u64_at(elf, at + 8)?, *elf.get(at + 4).ok_or(Halt::BadElf)?))
}
