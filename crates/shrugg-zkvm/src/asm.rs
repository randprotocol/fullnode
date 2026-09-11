//! A small assembler so guests can be written in Rust source without a RISC-V toolchain.
use crate::isa::*;
use std::collections::HashMap;

enum Item { Instr(Instr), Branch { cond: BranchCond, rs1: u32, rs2: u32, label: String }, Jal { rd: u32, label: String } }

pub struct Assembler { base_pc: u32, items: Vec<Item>, labels: HashMap<String, usize> }

impl Assembler {
    pub fn new(base_pc: u32) -> Self { Self { base_pc, items: Vec::new(), labels: HashMap::new() } }
    pub fn label(&mut self, name: &str) { assert!(self.labels.insert(name.to_string(), self.items.len()).is_none(), "duplicate label {name}"); }
    pub fn push(&mut self, i: Instr) { self.items.push(Item::Instr(i)); }
    pub fn extend(&mut self, is: impl IntoIterator<Item = Instr>) { for i in is { self.push(i); } }
    pub fn branch(&mut self, cond: BranchCond, rs1: u32, rs2: u32, label: &str) { self.items.push(Item::Branch { cond, rs1, rs2, label: label.into() }); }
    pub fn jal(&mut self, rd: u32, label: &str) { self.items.push(Item::Jal { rd, label: label.into() }); }
    pub fn assemble(self) -> Program {
        let target = |label: &str, from: usize| -> u32 {
            let to = *self.labels.get(label).unwrap_or_else(|| panic!("unknown label {label}"));
            ((to as i64 - from as i64) * 4) as i32 as u32
        };
        let words = self.items.iter().enumerate().map(|(i, it)| match it {
            Item::Instr(x) => x.encode(),
            Item::Branch { cond, rs1, rs2, label } => Instr::Branch { cond: *cond, rs1: *rs1, rs2: *rs2, imm: target(label, i) }.encode(),
            Item::Jal { rd, label } => Instr::Jal { rd: *rd, imm: target(label, i) }.encode(),
        }).collect();
        Program::new(self.base_pc, words)
    }
}

/// Mnemonic helpers. Immediates are `i32` for readability and stored sign-extended.
pub mod ops {
    use crate::isa::*;
    fn imm(i: i32) -> u32 { i as u32 }
    pub fn addi(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Add, rd, rs1, imm: imm(i) } }
    pub fn andi(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::And, rd, rs1, imm: imm(i) } }
    pub fn ori(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Or, rd, rs1, imm: imm(i) } }
    pub fn xori(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Xor, rd, rs1, imm: imm(i) } }
    pub fn slti(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Slt, rd, rs1, imm: imm(i) } }
    pub fn sltiu(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Sltu, rd, rs1, imm: imm(i) } }
    pub fn slli(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Sll, rd, rs1, imm: sh & 31 } }
    pub fn srli(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Srl, rd, rs1, imm: sh & 31 } }
    pub fn srai(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Sra, rd, rs1, imm: sh & 31 } }
    macro_rules! rrr { ($($name:ident => $op:ident),*) => { $( pub fn $name(rd: u32, rs1: u32, rs2: u32) -> Instr { Instr::AluReg { op: AluOp::$op, rd, rs1, rs2 } } )* } }
    rrr!(add => Add, sub => Sub, and => And, or => Or, xor => Xor, sll => Sll, srl => Srl, sra => Sra, slt => Slt, sltu => Sltu,
         mul => Mul, mulh => Mulh, mulhu => Mulhu, mulhsu => Mulhsu, div => Div, divu => Divu, rem => Rem, remu => Remu);
    pub fn lb(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Byte, signed: true } }
    pub fn lbu(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Byte, signed: false } }
    pub fn lh(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Half, signed: true } }
    pub fn lhu(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Half, signed: false } }
    pub fn lw(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Word, signed: false } }
    pub fn sb(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Store { rs1, rs2, imm: imm(off), width: Width::Byte } }
    pub fn sh(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Store { rs1, rs2, imm: imm(off), width: Width::Half } }
    pub fn sw(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Store { rs1, rs2, imm: imm(off), width: Width::Word } }
    pub fn lui(rd: u32, upper: u32) -> Instr { Instr::Lui { rd, imm: upper & 0xffff_f000 } }
    pub fn auipc(rd: u32, upper: u32) -> Instr { Instr::Auipc { rd, imm: upper & 0xffff_f000 } }
    pub fn jalr(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Jalr { rd, rs1, imm: imm(off) } }
    pub fn ecall() -> Instr { Instr::Ecall }
    pub fn mv(rd: u32, rs: u32) -> Instr { addi(rd, rs, 0) }
    /// Load a 32-bit constant: `lui` + `addi` when needed.
    pub fn li(rd: u32, v: i32) -> Vec<Instr> {
        if (-2048..=2047).contains(&v) { return vec![addi(rd, 0, v)]; }
        let v = v as u32;
        let lo = ((v & 0xfff) as i32) << 20 >> 20;           // sign-extended low 12
        let hi = v.wrapping_sub(lo as u32) & 0xffff_f000;     // upper 20 compensating for negative lo
        if lo == 0 { vec![lui(rd, hi)] } else { vec![lui(rd, hi), addi(rd, rd, lo)] }
    }
    pub fn halt() -> Vec<Instr> { let mut v = li(REG_A7, SYS_HALT as i32); v.push(ecall()); v }
    pub fn write_output(slot: u32, reg: u32) -> Vec<Instr> {
        let mut v = li(REG_A7, SYS_WRITE_OUTPUT as i32); v.extend(li(REG_A0, slot as i32)); v.push(mv(REG_A1, reg)); v.push(ecall()); v
    }
    /// Emit the chain effect "transfer amount (lo, hi registers) to recipient `index`":
    /// out0 = 1, out1 = index, out2 = lo, out3 = hi. Uses a2 as scratch (write_output
    /// clobbers only a7, a0, a1).
    ///
    /// Node-local (not upstream): `guests::private_payment`, the chain's own demo guest, is the
    /// only caller. Kept across a `deploy/sync-zkvm.sh` resync because `asm.rs` is excluded from
    /// the rsync — see that script's header.
    pub fn emit_transfer(index: u32, amount_lo_reg: u32, amount_hi_reg: u32) -> Vec<Instr> {
        let mut v = Vec::new();
        v.extend(li(REG_A2, 1)); v.extend(write_output(0, REG_A2));
        v.extend(li(REG_A2, index as i32)); v.extend(write_output(1, REG_A2));
        v.extend(write_output(2, amount_lo_reg));
        v.extend(write_output(3, amount_hi_reg));
        v
    }
    /// Result lands in a0.
    pub fn read_input(idx: u32) -> Vec<Instr> { let mut v = li(REG_A7, SYS_READ_INPUT as i32); v.extend(li(REG_A0, idx as i32)); v.push(ecall()); v }
    /// M3.2: hashes `n` words at word address `ptr_words` (`a0`, the `MEM_ADDR` word-address
    /// convention) with the `POSEIDON2` sponge, overwriting `ptr_words..ptr_words+8` with the
    /// 8-word digest in place.
    pub fn call_poseidon2(ptr_words: i32, n: usize) -> Vec<Instr> {
        let mut v = li(REG_A7, SYS_POSEIDON2 as i32);
        v.extend(li(REG_A0, ptr_words));
        v.extend(li(REG_A1, n as i32));
        v.push(ecall());
        v
    }
}

// ───────────────────────── M3.3: note-layer guest routines ─────────────────────────
//
// `NOTE_COMMIT`, `NULLIFY` and `MERKLE_VERIFY` are library code, not new syscalls: they
// stage a domain tag plus the relevant `Word8`s into a scratch RAM buffer (word-for-word
// copies), call `ops::call_poseidon2` over that buffer, then copy out the 8-word result — the
// same shape `guests::transfer` used by hand for the M1.5/M3.2 development hash. All addressing is
// relative to a shared RAM-base register `base` (the caller loads its HEAP-relative value
// once, e.g. `guests::transfer`'s `BASE`); `ptr_words` is the scratch buffer's *word* address
// (`(HEAP + buf) / 4`, computed by the caller at assembly time since both are compile-time
// constants — `asm.rs` itself has no HEAP constant).
use crate::notes::{domain, Note};

/// Copies a `Word8` (8 words) from `base + src` to `base + dst`. The `Word8` analogue of a
/// hand-written 2-word `copy` helper.
pub fn copy_word8(a: &mut Assembler, base: u32, tmp: u32, src: i32, dst: i32) {
    for i in 0..8 {
        a.push(ops::lw(tmp, base, src + 4 * i));
        a.push(ops::sw(base, tmp, dst + 4 * i));
    }
}

/// `copy_word8`'s register-indirect twin: copies a `Word8` from `src_reg + {0,4,..,28}`
/// (a RUNTIME address — `src_reg` holds it, unlike `copy_word8`'s compile-time `src: i32`)
/// to `base + dst`. What the looped `MERKLE_VERIFY` needs to read the current level's
/// sibling through a bumped pointer register instead of a per-level compile-time offset.
pub fn copy_word8_from_reg(a: &mut Assembler, base: u32, tmp: u32, src_reg: u32, dst: i32) {
    for i in 0..8 {
        a.push(ops::lw(tmp, src_reg, 4 * i));
        a.push(ops::sw(base, tmp, dst + 4 * i));
    }
}

/// The note layer's key derivation, `nk = H(NK, sk)` then `pk = H(PK, nk)`, from an 8-word
/// spend key at `base + sk_at` to an 8-word `nk` at `base + nk_out` and an 8-word `pk` at
/// `base + pk_out`. Both hashes stage their own preimage at `base + buf` (9 words each) and
/// go through the same `POSEIDON2` syscall every other note-layer hash uses; `tmp` is the
/// single scratch register. `guests::transfer` and `guests::bundle` open with this identical
/// sequence — every spend in this crate derives its own `pk_self` from the private spend key
/// rather than taking an owner from the witness, which is what makes "you can only spend notes
/// committed to your own key" structural — so it is emitted from one place.
pub fn emit_derive_keys(a: &mut Assembler, base: u32, tmp: u32, sk_at: i32, buf: i32, ptr_words: i32, nk_out: i32, pk_out: i32) {
    a.extend(ops::li(tmp, domain::NK as i32));
    a.push(ops::sw(base, tmp, buf));
    copy_word8(a, base, tmp, sk_at, buf + 4);
    a.extend(ops::call_poseidon2(ptr_words, 9));
    copy_word8(a, base, tmp, buf, nk_out);
    a.extend(ops::li(tmp, domain::PK as i32));
    a.push(ops::sw(base, tmp, buf));
    copy_word8(a, base, tmp, nk_out, buf + 4);
    a.extend(ops::call_poseidon2(ptr_words, 9));
    copy_word8(a, base, tmp, buf, pk_out);
}

/// Lays a `Note` out at `base + stage` in the exact field order `emit_note_commit` hashes
/// (`pk(8), from(8), amount_lo, amount_hi, asset, time, r(8)` — `Note::WORDS` words), copying
/// each field from the RAM offset named for it. Every source is a compile-time `base`-relative
/// offset, so a caller stages a note by *naming* where each field comes from, which is what
/// makes a guest's structural claims about a note readable at the call site rather than in a
/// comment over a block of `lw`/`sw` pairs: `guests::bundle` passes its derived `PK` offset as
/// `pk_at` for both inputs ("the owner is always `pk_self`") and as `from_at` for both outputs
/// ("the sender is always `pk_self`"), and passes the bundle's own public `ASSET`/`TIME` input
/// words as `asset_at`/`time_at` for both outputs ("an output has no asset or time of its own
/// to claim"). `tmp` is the single scratch register, clobbered throughout.
#[allow(clippy::too_many_arguments)]
pub fn emit_stage_note(a: &mut Assembler, base: u32, tmp: u32, stage: i32, pk_at: i32, from_at: i32, amount_lo_at: i32, amount_hi_at: i32, asset_at: i32, time_at: i32, r_at: i32) {
    copy_word8(a, base, tmp, pk_at, stage);
    copy_word8(a, base, tmp, from_at, stage + 32);
    a.push(ops::lw(tmp, base, amount_lo_at)); a.push(ops::sw(base, tmp, stage + 64));
    a.push(ops::lw(tmp, base, amount_hi_at)); a.push(ops::sw(base, tmp, stage + 68));
    a.push(ops::lw(tmp, base, asset_at)); a.push(ops::sw(base, tmp, stage + 72));
    a.push(ops::lw(tmp, base, time_at)); a.push(ops::sw(base, tmp, stage + 76));
    copy_word8(a, base, tmp, r_at, stage + 80);
}

/// `NOTE_COMMIT`: `note_words` (`Note::WORDS` words, already laid out at `base + note_at`)
/// hashed as `H(CM_DOMAIN, note_words)`. Stages `[CM_DOMAIN, note_words...]` at `base + buf`
/// (needs `1 + Note::WORDS` = 29 words of scratch), calls `POSEIDON2`, and copies the 8-word
/// digest to `base + cm_out`.
pub fn emit_note_commit(a: &mut Assembler, base: u32, tmp: u32, note_at: i32, buf: i32, ptr_words: i32, cm_out: i32) {
    a.extend(ops::li(tmp, domain::CM as i32));
    a.push(ops::sw(base, tmp, buf));
    for i in 0..Note::WORDS as i32 {
        a.push(ops::lw(tmp, base, note_at + 4 * i));
        a.push(ops::sw(base, tmp, buf + 4 + 4 * i));
    }
    a.extend(ops::call_poseidon2(ptr_words, 1 + Note::WORDS));
    copy_word8(a, base, tmp, buf, cm_out);
}

/// `NULLIFY`: the M1.5 form, `nf = H(NF_DOMAIN, nk, cm)` — bound to the commitment, not a
/// sender-chosen nonce, so two notes for the same owner can never collide to one nullifier.
/// `nk`/`cm` (8 words each) must already be at `base + nk_at` / `base + cm_at`. Stages
/// `[NF_DOMAIN, nk(8), cm(8)]` at `base + buf` (17 words of scratch), calls `POSEIDON2`, and
/// copies the digest to `base + nf_out`.
pub fn emit_nullify(a: &mut Assembler, base: u32, tmp: u32, nk_at: i32, cm_at: i32, buf: i32, ptr_words: i32, nf_out: i32) {
    a.extend(ops::li(tmp, domain::NF as i32));
    a.push(ops::sw(base, tmp, buf));
    copy_word8(a, base, tmp, nk_at, buf + 4);
    copy_word8(a, base, tmp, cm_at, buf + 36);
    a.extend(ops::call_poseidon2(ptr_words, 17));
    copy_word8(a, base, tmp, buf, nf_out);
}

/// `MERKLE_VERIFY`, depth `depth` (32 in this crate), as a counted loop — see the module-level
/// doc comment above (`docs/superpowers/plans/2026-09-11-shielded-pool-z.md` Task 1) for the
/// full calling convention. Unlike the M3.3 unrolled version, the compiled body is emitted
/// once; `ctr` counts `depth` iterations, `path_ptr` walks the sibling array 32 bytes at a
/// time, and `index` is a destructible copy of `index_word` shifted right by 1 each
/// iteration — the same "maintain a pointer, bump it, count down" idiom `guests::memcpy`/
/// `guests::bubble_sort` already use for their own loops, applied here to a `Word8`-at-a-time
/// stride instead of a word-at-a-time one.
///
/// Calling convention (documented here because every field is now either a register the
/// *caller* must dedicate — not shared with anything live across the call — or a compile-time
/// RAM offset, same as before):
///   - `base`      (reg, in)  RAM base, unchanged from the unrolled version.
///   - `tmp`       (reg, scratch) general load/store scratch, unchanged.
///   - `bit`       (reg, scratch) holds the extracted index low bit each iteration.
///   - `index`     (reg, scratch, DESTROYED) — the caller's index value is copied in at the
///                 top of the routine (`mv(index, index_word)`) and shifted right by 1 every
///                 iteration; the caller's own `index_word` register is left untouched (the
///                 unrolled version never destroyed it either, since it only ever read one
///                 fixed bit of it per unrolled level — the loop version must destroy *a copy*
///                 instead, because it reads a different bit each iteration via repeated
///                 `srli ..., 1`, not a per-iteration-constant shift amount).
///   - `index_word`(reg, in, preserved) the caller's original index — read once, not modified.
///   - `path_ptr`  (reg, scratch) initialized to `base + path` and bumped by 32 bytes (one
///                 `Word8` sibling) every iteration — the register-indirect address
///                 `copy_word8_from_reg` reads the current level's sibling from.
///   - `ctr`       (reg, scratch) counts iterations down from `depth` to 0.
///   - `leaf`, `path`, `buf`, `ptr_words`, `root_out`, `depth`, `label_prefix`: same meaning
///     and same compile-time-constant-ness as the unrolled version.
///
/// `leaf`/`root_out` may be the same or different RAM offsets (`guests::transfer` uses
/// different ones, seeding `root_out` from `leaf` once up front, exactly as the unrolled
/// version did); `path`'s per-level sibling for level `l` is `path + 32*l`, now visited by
/// `path_ptr` incrementing rather than by a compile-time-computed offset per unrolled copy.
///
/// Per iteration: extract the low bit of `index` (`andi(bit, index, 1)`), branch to pick
/// `[running, sibling]` (bit 0) or `[sibling, running]` (bit 1) order — reading the sibling
/// through `path_ptr` via `copy_word8_from_reg`, the running node through `root_out` via
/// `copy_word8` (still a compile-time address: only ONE running-node buffer exists, reused
/// in place every iteration, exactly as the unrolled version reused it) — hash the 17-word
/// `[NODE_DOMAIN, left(8), right(8)]` staged at `buf`, copy the digest back into `root_out`,
/// then advance `index >>= 1`, `path_ptr += 32`, `ctr -= 1`, loop. `label_prefix` must still be
/// unique per call site (one `_loop`/`_bit0`/`_done`/`_exit` label set is emitted per call).
#[allow(clippy::too_many_arguments)]
pub fn emit_merkle_verify(
    a: &mut Assembler,
    base: u32,
    tmp: u32,
    bit: u32,
    index: u32,
    index_word: u32,
    path_ptr: u32,
    ctr: u32,
    leaf: i32,
    path: i32,
    buf: i32,
    ptr_words: i32,
    root_out: i32,
    depth: usize,
    label_prefix: &str,
) {
    use crate::isa::{BranchCond, REG_ZERO};
    copy_word8(a, base, tmp, leaf, root_out);
    a.push(ops::mv(index, index_word));
    a.push(ops::addi(path_ptr, base, path));
    a.extend(ops::li(ctr, depth as i32));
    let loop_lbl = format!("{label_prefix}_loop");
    let bit0 = format!("{label_prefix}_bit0");
    let done_lbl = format!("{label_prefix}_done");
    let exit_lbl = format!("{label_prefix}_exit");
    a.label(&loop_lbl);
    a.branch(BranchCond::Eq, ctr, REG_ZERO, &exit_lbl);
    a.push(ops::andi(bit, index, 1));
    a.branch(BranchCond::Eq, bit, REG_ZERO, &bit0);
    // bit == 1: the running node is on the right — [sibling, running].
    copy_word8_from_reg(a, base, tmp, path_ptr, buf + 4);
    copy_word8(a, base, tmp, root_out, buf + 36);
    a.jal(REG_ZERO, &done_lbl);
    a.label(&bit0);
    // bit == 0: the running node is on the left — [running, sibling].
    copy_word8(a, base, tmp, root_out, buf + 4);
    copy_word8_from_reg(a, base, tmp, path_ptr, buf + 36);
    a.label(&done_lbl);
    a.extend(ops::li(tmp, domain::NODE as i32));
    a.push(ops::sw(base, tmp, buf));
    a.extend(ops::call_poseidon2(ptr_words, 17));
    copy_word8(a, base, tmp, buf, root_out);
    a.push(ops::srli(index, index, 1));
    a.push(ops::addi(path_ptr, path_ptr, 32));
    a.push(ops::addi(ctr, ctr, -1));
    a.jal(REG_ZERO, &loop_lbl);
    a.label(&exit_lbl);
}

// ───────────────────────── Task 3: bundle arithmetic routines ─────────────────────────
//
// `guests::bundle` proves relations this ISA has no native assert for (two real inputs'
// Merkle roots agreeing with one claimed anchor, every amount's `< 2^63` range check, 64-bit
// balance conservation) via a taint-and-corrupt idiom instead: each of these routines computes
// a free, unconstrained 0/1 "did this check fail" bit that the caller folds into a monotone
// `bad` accumulator with `emit_or_into`, which is in turn folded into the guest's published
// digest — see `docs/06-viewing-keys.md`'s "The `bundle` relation" section.

/// `dst_bool := (a == b) as u32` for two `Word8`s already in RAM at `base+a_at`/`base+b_at`:
/// XOR all 8 word pairs together (OR-folding the results), then `sltiu(dst_bool, folded, 1)` —
/// `folded == 0` iff every word pair matched. `dst_bool` and `fold` (scratch) must differ from
/// `tmp`.
pub fn emit_eq8(a: &mut Assembler, base: u32, tmp: u32, fold: u32, a_at: i32, b_at: i32, dst_bool: u32) {
    a.push(ops::addi(fold, 0, 0)); // fold := 0
    for i in 0..8 {
        a.push(ops::lw(tmp, base, a_at + 4 * i));
        a.push(ops::lw(dst_bool, base, b_at + 4 * i)); // dst_bool used as scratch here, overwritten below
        a.push(ops::xor(tmp, tmp, dst_bool));
        a.push(ops::or(fold, fold, tmp));
    }
    // 1 iff fold == 0 iff every word matched. NOTE: this must be the *immediate* form
    // (`sltiu`, `AluOp::Sltu` with an `imm`) — `ops::sltu(dst_bool, fold, 1)` would instead
    // compare `fold` against whatever value happens to be sitting in register `x1` (`sltu`'s
    // third argument is a register index, not an immediate), which is not what "compare
    // against the literal 1" means.
    a.push(ops::sltiu(dst_bool, fold, 1));
}

/// `bad := bad | cond` (`cond` a 0/1 register) — monotone: no later call can clear a `bad` an
/// earlier one set.
pub fn emit_or_into(a: &mut Assembler, bad: u32, cond: u32) {
    a.push(ops::or(bad, bad, cond));
}

/// Sets `viol := 1` if the 64-bit value with high word `hi` is `>= 2^63` (i.e. `hi`'s top bit
/// is set — `sltu(viol_inv, hi, 0x8000_0000)` is 1 iff `< 2^63`; `viol := 1 - viol_inv`, via
/// `xori`), else `0`. Used for the "every amount `< 2^63`" checks. `viol` is the only register
/// written: it holds the `0x8000_0000` constant for one instruction before the comparison
/// overwrites it with the comparison's own result, so no scratch register is needed (this
/// routine deliberately takes no `tmp`, unlike the other `emit_*` ones).
pub fn emit_range_check_u63(a: &mut Assembler, hi: u32, viol: u32) {
    a.extend(ops::li(viol, i32::MIN)); // 0x8000_0000 as i32 bit pattern
    a.push(ops::sltu(viol, hi, viol)); // 1 iff hi < 0x8000_0000, i.e. amount < 2^63
    a.push(ops::xori(viol, viol, 1));  // invert: 1 iff amount >= 2^63
}

/// 64-bit `(sum_lo, sum_hi) += (lo, hi)`, carry-aware: `sltu` detects the low-word carry, then
/// the high-word addition is split into two separately-checked steps (`mid = sum_hi + hi`,
/// `sum_hi := mid + low_carry`) so each step's own `sltu`-detects-carry idiom
/// (`guests::balance_check`'s 32-bit-sum idiom) catches its own overflow independently;
/// `carry_out` is their OR. Two checks, not one compare against `hi + low_carry`, because that
/// single-compare shortcut has an edge case: if `hi == 0xffff_ffff` and `low_carry == 1`,
/// `hi + low_carry` itself wraps to `0` (mod 2^32), and comparing `sum_hi` (which is `>= 0`
/// unsigned, always) against that wrapped `0` silently reports no carry when one occurred —
/// exactly the case `u64::MAX + u64::MAX` hits in `sum_hi`'s low 32 bits once high words are
/// `0xffff_ffff` and a low carry is pending. `hi` is destroyed as scratch (it holds the first
/// step's carry once its value has been consumed); `lo` is read once and left alone, but since
/// a caller chaining several addends has to reload `hi` per call anyway it reloads both,
/// exactly as `guests::bundle` already does.
pub fn emit_add64_carry(a: &mut Assembler, sum_lo: u32, sum_hi: u32, lo: u32, hi: u32, tmp: u32, carry_out: u32) {
    a.push(ops::add(tmp, sum_lo, lo));
    a.push(ops::sltu(carry_out, tmp, sum_lo)); // low-word carry-out
    a.push(ops::mv(sum_lo, tmp));
    a.push(ops::add(tmp, sum_hi, hi));         // tmp := mid = sum_hi + hi
    a.push(ops::sltu(hi, tmp, sum_hi));        // hi (scratch) := carry1 = mid < sum_hi
    a.push(ops::add(sum_hi, tmp, carry_out));  // sum_hi := mid + low_carry
    a.push(ops::sltu(carry_out, sum_hi, tmp)); // carry_out := carry2 = sum_hi < mid
    a.push(ops::or(carry_out, carry_out, hi)); // carry_out := carry1 | carry2
}
