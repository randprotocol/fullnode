//! A minimal ELF64 builder for the sBPF loader's tests (M4.4 Task 5): one `PT_LOAD` covering the
//! file, one `PT_DYNAMIC`, and the sections an SBPF v1 shared object carries. Every section's
//! `sh_addr` equals its `sh_offset`, which is what the pre-`enable_elf_vaddr` toolchain emitted and
//! what both `sbpf_core::elf::load`'s and `solana-sbpf`'s borrow path requires.
//!
//! Shared by `tests/sbpf_elf.rs` (which tests the loader) and `tests/sbpf_abi.rs` (which needs a
//! real program to run a whole call through `abi::run_call_with`).

/// The file offset — and, since `sh_addr == sh_offset`, the virtual address — `build_elf` puts
/// `.text` at.
pub const TEXT_ADDR: u64 = 0x100;

/// `R_BPF_64_64`: an `lddw` whose imm64 is `symbol.st_value + the value at the site`.
pub const R_BPF_64_64: u32 = 1;
/// `R_BPF_64_RELATIVE`: rebase the address at the site into the program region, no symbol.
pub const R_BPF_64_RELATIVE: u32 = 8;
/// `R_BPF_64_32`: a `call` target — a syscall's name hash, or a defined function's pc.
pub const R_BPF_64_32: u32 = 10;

pub struct Sym {
    pub name: &'static str,
    /// `STT_FUNC | STB_GLOBAL` is `0x12`; an undefined syscall symbol is `0x10` with value 0.
    pub info: u8,
    pub value: u64,
}

pub struct Rel {
    pub offset: u64,
    pub sym: u32,
    pub kind: u32,
}

pub fn align8(n: usize) -> usize {
    (n + 7) & !7
}

pub fn build_elf(text: &[u8], rodata: &[u8], syms: &[Sym], relocs: &[Rel], entry_slot: usize) -> Vec<u8> {
    let text_addr = TEXT_ADDR as usize;
    let rodata_addr = align8(text_addr + text.len());
    // Eight bytes of gap after `.rodata`, so a zero-length `.rodata` cannot share an address with
    // `.dynsym` — both this loader and `solana-sbpf` resolve the dynamic tables by looking up the
    // section at an address, and a real file never has two sections at one.
    let dynsym_addr = align8(rodata_addr + rodata.len() + 8);

    // .dynsym: a null symbol first, then one entry per `syms`; .dynstr holds their names.
    let mut dynstr = vec![0u8];
    let mut dynsym = vec![0u8; 24];
    for s in syms {
        let name_off = dynstr.len() as u32;
        dynstr.extend_from_slice(s.name.as_bytes());
        dynstr.push(0);
        dynsym.extend_from_slice(&name_off.to_le_bytes());
        dynsym.push(s.info);
        dynsym.push(0); // st_other
        dynsym.extend_from_slice(&1u16.to_le_bytes()); // st_shndx: .text
        dynsym.extend_from_slice(&s.value.to_le_bytes());
        dynsym.extend_from_slice(&0u64.to_le_bytes()); // st_size
    }
    let dynstr_addr = dynsym_addr + dynsym.len();
    let reldyn_addr = align8(dynstr_addr + dynstr.len());

    let mut reldyn = Vec::new();
    for r in relocs {
        reldyn.extend_from_slice(&r.offset.to_le_bytes());
        reldyn.extend_from_slice(&((u64::from(r.sym) << 32) | u64::from(r.kind)).to_le_bytes());
    }
    let dynamic_addr = align8(reldyn_addr + reldyn.len());

    // .dynamic: DT_REL/DT_RELSZ/DT_RELENT, DT_SYMTAB/DT_SYMENT, DT_STRTAB/DT_STRSZ, DT_NULL.
    let mut dynamic = Vec::new();
    let dt = |tag: u64, val: u64, out: &mut Vec<u8>| {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&val.to_le_bytes());
    };
    dt(5, dynstr_addr as u64, &mut dynamic); // DT_STRTAB
    dt(6, dynsym_addr as u64, &mut dynamic); // DT_SYMTAB
    dt(10, dynstr.len() as u64, &mut dynamic); // DT_STRSZ
    dt(11, 24, &mut dynamic); // DT_SYMENT
    if !relocs.is_empty() {
        dt(17, reldyn_addr as u64, &mut dynamic); // DT_REL
        dt(18, reldyn.len() as u64, &mut dynamic); // DT_RELSZ
        dt(19, 16, &mut dynamic); // DT_RELENT
    }
    dt(0, 0, &mut dynamic); // DT_NULL

    let shstrtab_addr = dynamic_addr + dynamic.len();
    let names = [
        "", ".text", ".rodata", ".dynsym", ".dynstr", ".rel.dyn", ".dynamic", ".shstrtab",
    ];
    let mut shstrtab = Vec::new();
    let mut name_offsets = Vec::new();
    for n in names {
        name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(n.as_bytes());
        shstrtab.push(0);
    }
    let shoff = align8(shstrtab_addr + shstrtab.len());
    let total = shoff + names.len() * 64;

    let mut elf = vec![0u8; total];
    // ELF header.
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
    elf[18..20].copy_from_slice(&247u16.to_le_bytes()); // e_machine = EM_BPF
    elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    elf[24..32].copy_from_slice(&((text_addr + 8 * entry_slot) as u64).to_le_bytes()); // e_entry
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff
    elf[48..52].copy_from_slice(&0u32.to_le_bytes()); // e_flags: SBPF v1
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
    elf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf[60..62].copy_from_slice(&(names.len() as u16).to_le_bytes()); // e_shnum
    elf[62..64].copy_from_slice(&7u16.to_le_bytes()); // e_shstrndx

    // Program headers: PT_LOAD (R|X) over the whole file, then PT_DYNAMIC.
    let phdr = |i: usize, ty: u32, flags: u32, off: usize, len: usize, elf: &mut Vec<u8>| {
        let b = 64 + i * 56;
        elf[b..b + 4].copy_from_slice(&ty.to_le_bytes());
        elf[b + 4..b + 8].copy_from_slice(&flags.to_le_bytes());
        elf[b + 8..b + 16].copy_from_slice(&(off as u64).to_le_bytes()); // p_offset
        elf[b + 16..b + 24].copy_from_slice(&(off as u64).to_le_bytes()); // p_vaddr
        elf[b + 24..b + 32].copy_from_slice(&(off as u64).to_le_bytes()); // p_paddr
        elf[b + 32..b + 40].copy_from_slice(&(len as u64).to_le_bytes()); // p_filesz
        elf[b + 40..b + 48].copy_from_slice(&(len as u64).to_le_bytes()); // p_memsz
        elf[b + 48..b + 56].copy_from_slice(&8u64.to_le_bytes()); // p_align
    };
    phdr(0, 1, 5, 0, total, &mut elf); // PT_LOAD, PF_R | PF_X
    phdr(1, 2, 6, dynamic_addr, dynamic.len(), &mut elf); // PT_DYNAMIC, PF_R | PF_W

    // Section contents.
    elf[text_addr..text_addr + text.len()].copy_from_slice(text);
    elf[rodata_addr..rodata_addr + rodata.len()].copy_from_slice(rodata);
    elf[dynsym_addr..dynsym_addr + dynsym.len()].copy_from_slice(&dynsym);
    elf[dynstr_addr..dynstr_addr + dynstr.len()].copy_from_slice(&dynstr);
    elf[reldyn_addr..reldyn_addr + reldyn.len()].copy_from_slice(&reldyn);
    elf[dynamic_addr..dynamic_addr + dynamic.len()].copy_from_slice(&dynamic);
    elf[shstrtab_addr..shstrtab_addr + shstrtab.len()].copy_from_slice(&shstrtab);

    // Section headers. `.text` and `.rodata` are adjacent, so the read-only span can be borrowed.
    #[rustfmt::skip]
    let sections: [(u32, u64, u64, usize, u32, u64, u64); 8] = [
        //  type, flags, addr(=offset), size, link, entsize, align
        (0, 0, 0, 0, 0, 0, 0),                                              // NULL
        (1, 0x6, text_addr as u64, text.len(), 0, 0, 8),                    // .text   ALLOC|EXEC
        (1, 0x2, rodata_addr as u64, rodata.len(), 0, 0, 8),                // .rodata ALLOC
        (11, 0x2, dynsym_addr as u64, dynsym.len(), 4, 24, 8),              // .dynsym
        (3, 0x2, dynstr_addr as u64, dynstr.len(), 0, 0, 1),                // .dynstr
        (9, 0x2, reldyn_addr as u64, reldyn.len(), 3, 16, 8),               // .rel.dyn
        (6, 0x3, dynamic_addr as u64, dynamic.len(), 4, 16, 8),             // .dynamic
        (3, 0, shstrtab_addr as u64, shstrtab.len(), 0, 0, 1),              // .shstrtab
    ];
    for (i, &(ty, flags, addr, size, link, entsize, align)) in sections.iter().enumerate() {
        let b = shoff + i * 64;
        elf[b..b + 4].copy_from_slice(&name_offsets[i].to_le_bytes()); // sh_name
        elf[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
        elf[b + 8..b + 16].copy_from_slice(&flags.to_le_bytes());
        elf[b + 16..b + 24].copy_from_slice(&addr.to_le_bytes()); // sh_addr
        elf[b + 24..b + 32].copy_from_slice(&addr.to_le_bytes()); // sh_offset == sh_addr
        elf[b + 32..b + 40].copy_from_slice(&(size as u64).to_le_bytes());
        elf[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
        elf[b + 48..b + 56].copy_from_slice(&align.to_le_bytes());
        elf[b + 56..b + 64].copy_from_slice(&entsize.to_le_bytes());
    }
    // The NULL section header must be entirely zero.
    elf[shoff..shoff + 64].fill(0);
    elf
}

