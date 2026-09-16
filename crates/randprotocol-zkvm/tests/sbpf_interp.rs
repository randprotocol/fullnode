//! The SBPF v1 interpreter (M4.4 Task 5): hand-assembled programs run through `sbpf_core::Vm`
//! over test buffers, and 500 random ALU/jump programs run through both `Vm` and
//! `solana_sbpf::vm::EbpfVm` — the differential oracle pinned at 0.11.1.
//!
//! A note on versions: what the M4.4 plan calls "SBPF v1" (**fixed**-size stack frames, `lddw`,
//! `le`/`be`, `neg`, no `BPF_PQR` class) is what `solana-sbpf` 0.11.1's enum calls
//! `SBPFVersion::V0` — the format a non-upgradeable BPFLoader2 program like SPL Token is built
//! for. `common::sbpf_oracle`'s `config()` pins that version and reads the frame geometry from
//! `sbpf_core::memory` (Task 6 measured it: Solana's own 4 KiB frames, 8 of them), with no gaps,
//! so the oracle and `sbpf-core` model the same machine.

mod common;
use common::sbpf_oracle as oracle;
use rand::RngExt;
use randprotocol_zkvm::sbpf::{self, asm, insn, lddw};
use sbpf_core::interp::{Halt, MAX_INSTRUCTIONS};
use sbpf_core::isa::opc;
use sbpf_core::memory::{
    HEAP_BYTES, REGION_HEAP, REGION_INPUT, REGION_PROGRAM, REGION_STACK, STACK_FRAME,
};

/// `exit` — every program ends with one.
fn exit() -> [u8; 8] {
    insn(opc::EXIT, 0, 0, 0, 0)
}

/// Runs `text` with an empty input region and returns `r0`.
fn r0(text: &[u8]) -> Result<u64, Halt> {
    sbpf::run_text(text, &mut []).result
}

#[test]
fn alu64_and_alu32_wrap_and_sign_correctly() {
    // MUL64 wraps modulo 2^64.
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, 0x1234_5678_9abc_def0));
    p.push(insn(opc::MUL64_IMM, 1, 0, 0, 0x10));
    p.push(insn(opc::MOV64_REG, 0, 1, 0, 0));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(0x1234_5678_9abc_def0u64.wrapping_mul(0x10)));

    // DIV32 truncates to the low half before dividing, and zero-extends the quotient.
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, 0xffff_ffff_0000_000a));
    p.push(insn(opc::DIV32_IMM, 1, 0, 0, 3));
    p.push(insn(opc::MOV64_REG, 0, 1, 0, 0));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(10 / 3));

    // ARSH64 on a negative value keeps the sign.
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, -16),
        insn(opc::ARSH64_IMM, 0, 0, 0, 2),
        exit(),
    ]);
    assert_eq!(r0(&p), Ok(-4i64 as u64));

    // ARSH32 shifts the low half arithmetically and then zero-extends the 32-bit result.
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, -16),
        insn(opc::ARSH32_IMM, 0, 0, 0, 2),
        exit(),
    ]);
    assert_eq!(r0(&p), Ok(0xffff_fffcu64));

    // NEG32 negates the low half and zero-extends.
    let p = asm(&[insn(opc::MOV64_IMM, 0, 0, 0, 5), insn(opc::NEG32, 0, 0, 0, 0), exit()]);
    assert_eq!(r0(&p), Ok(0xffff_fffbu64));
    // NEG64 negates the whole register.
    let p = asm(&[insn(opc::MOV64_IMM, 0, 0, 0, 5), insn(opc::NEG64, 0, 0, 0, 0), exit()]);
    assert_eq!(r0(&p), Ok(-5i64 as u64));

    // ADD32 *sign*-extends its 32-bit result into the 64-bit register (v1 has no explicit
    // sign-extension flag, so `sign_extension(x: i32) == x as i64 as u64`).
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 0),
        insn(opc::ADD32_IMM, 0, 0, 0, -1),
        exit(),
    ]);
    assert_eq!(r0(&p), Ok(u64::MAX));
    // MOV32 zero-extends instead.
    let p = asm(&[insn(opc::MOV32_IMM, 0, 0, 0, -1), exit()]);
    assert_eq!(r0(&p), Ok(0xffff_ffff));
    // MUL32's 32-bit product also sign-extends.
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 0x1000),
        insn(opc::MUL32_IMM, 0, 0, 0, 0x10_0000),
        exit(),
    ]);
    assert_eq!(r0(&p), Ok(0x1000i32.wrapping_mul(0x10_0000) as i64 as u64));

    // LSH32/RSH32 mask the shift amount to five bits, LSH64/RSH64 to six.
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::LSH32_IMM, 0, 0, 0, 33),
        exit(),
    ]);
    assert_eq!(r0(&p), Ok(2));
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::LSH64_IMM, 0, 0, 0, 65),
        exit(),
    ]);
    assert_eq!(r0(&p), Ok(2));

    // LE and BE with imm 16/32/64; anything else is a bad instruction.
    let mut p = vec![];
    p.extend_from_slice(&lddw(0, 0x0011_2233_4455_6677));
    p.push(insn(opc::BE, 0, 0, 0, 64));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(0x7766_5544_3322_1100));
    let mut p = vec![];
    p.extend_from_slice(&lddw(0, 0x0011_2233_4455_6677));
    p.push(insn(opc::BE, 0, 0, 0, 16));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(0x7766));
    let mut p = vec![];
    p.extend_from_slice(&lddw(0, 0x0011_2233_4455_6677));
    p.push(insn(opc::LE, 0, 0, 0, 32));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(0x4455_6677));
    let p = asm(&[insn(opc::BE, 0, 0, 0, 24), exit()]);
    assert_eq!(r0(&p), Err(Halt::BadInsn(opc::BE)));

    // A division or modulo by zero is an exceptional halt, by register and by immediate.
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 7),
        insn(opc::MOV64_IMM, 1, 0, 0, 0),
        insn(opc::DIV64_REG, 0, 1, 0, 0),
        exit(),
    ]);
    assert_eq!(r0(&p), Err(Halt::DivByZero));
    let p = asm(&[insn(opc::MOD32_IMM, 0, 0, 0, 0), exit()]);
    assert_eq!(r0(&p), Err(Halt::DivByZero));

    // A v2-only opcode byte (here `sdiv64 r0, r1`) is not in v1 and traps.
    let p = asm(&[insn(0xd6, 0, 1, 0, 0), exit()]);
    assert_eq!(r0(&p), Err(Halt::BadInsn(0xd6)));
}

#[test]
fn jumps_take_offsets_in_slots() {
    // `ja +2` skips the two `mov r0, 1` / `mov r0, 2` slots.
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 0),
        insn(opc::JA, 0, 0, 2, 0),
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::MOV64_IMM, 0, 0, 0, 2),
        insn(opc::MOV64_IMM, 0, 0, 0, 3),
        exit(),
    ]);
    assert_eq!(r0(&p), Ok(3));

    // JSLT is signed, JLT unsigned: -1 < 1 signed, but 0xffff_ffff_ffff_ffff > 1 unsigned.
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 0),
        insn(opc::MOV64_IMM, 1, 0, 0, -1),
        insn(opc::JSLT_IMM, 1, 0, 1, 1),
        insn(opc::MOV64_IMM, 0, 0, 0, 9),
        exit(),
    ]);
    assert_eq!(r0(&p), Ok(0));
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 0),
        insn(opc::MOV64_IMM, 1, 0, 0, -1),
        insn(opc::JLT_IMM, 1, 0, 1, 1),
        insn(opc::MOV64_IMM, 0, 0, 0, 9),
        exit(),
    ]);
    assert_eq!(r0(&p), Ok(9));

    // A jump off the end of the text is a bad jump, not a read of whatever follows.
    let p = asm(&[insn(opc::JA, 0, 0, 100, 0), exit()]);
    assert_eq!(r0(&p), Err(Halt::BadJump));
    let p = asm(&[insn(opc::JA, 0, 0, -10, 0), exit()]);
    assert_eq!(r0(&p), Err(Halt::BadJump));
}

#[test]
fn loads_and_stores_respect_regions() {
    // A store into the read-only program region is an access violation.
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_PROGRAM));
    p.push(insn(opc::ST_W_IMM, 1, 0, 0, 1));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Err(Halt::AccessViolation(REGION_PROGRAM)));

    // A load past the end of the input region is an access violation; the last byte inside it is
    // not. The input region here is eight bytes.
    let mut input = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.push(insn(opc::LD_B_REG, 0, 1, 7, 0));
    p.push(exit());
    assert_eq!(sbpf::run_text(&asm(&p), &mut input).result, Ok(8));
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.push(insn(opc::LD_B_REG, 0, 1, 8, 0));
    p.push(exit());
    assert_eq!(
        sbpf::run_text(&asm(&p), &mut input).result,
        Err(Halt::AccessViolation(REGION_INPUT + 8))
    );
    // Eight bytes read from offset 1 straddle the end of an eight-byte region, too.
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.push(insn(opc::LD_DW_REG, 0, 1, 1, 0));
    p.push(exit());
    assert_eq!(
        sbpf::run_text(&asm(&p), &mut input).result,
        Err(Halt::AccessViolation(REGION_INPUT + 1))
    );

    // An 8-byte load at an odd address is fine — sBPF has no alignment rule.
    let mut input = [0u8; 16];
    input[1..9].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.push(insn(opc::LD_DW_REG, 0, 1, 1, 0));
    p.push(exit());
    assert_eq!(sbpf::run_text(&asm(&p), &mut input).result, Ok(0x0123_4567_89ab_cdef));

    // The input region is writable and the run's effect is visible to the caller.
    let mut input = [0u8; 16];
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.push(insn(opc::ST_DW_IMM, 1, 0, 4, 0x7fff_ffff));
    p.push(insn(opc::MOV64_IMM, 0, 0, 0, 0));
    p.push(exit());
    assert_eq!(sbpf::run_text(&asm(&p), &mut input).result, Ok(0));
    assert_eq!(&input[4..12], &0x7fff_ffffu64.to_le_bytes());

    // The stack region is writable through r10, and the heap region through its own base.
    let mut p = vec![];
    p.push(insn(opc::ST_DW_IMM, 10, 0, -8, 42));
    p.push(insn(opc::LD_DW_REG, 0, 10, -8, 0));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(42));
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_HEAP));
    p.push(insn(opc::ST_DW_IMM, 1, 0, 0, 7));
    p.push(insn(opc::LD_DW_REG, 0, 1, 0, 0));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(7));
    // One byte past the heap is not.
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_HEAP + HEAP_BYTES as u64));
    p.push(insn(opc::LD_B_REG, 0, 1, 0, 0));
    p.push(exit());
    assert_eq!(
        r0(&asm(&p)),
        Err(Halt::AccessViolation(REGION_HEAP + HEAP_BYTES as u64))
    );

    // An address in no region at all (region index 0, and region index 5) is a violation. r2 is
    // zero at entry, so `[r2 + 0]` is address 0.
    let p = asm(&[insn(opc::LD_B_REG, 0, 2, 0, 0), exit()]);
    assert_eq!(r0(&p), Err(Halt::AccessViolation(0)));
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, 5u64 << 32));
    p.push(insn(opc::LD_B_REG, 0, 1, 0, 0));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Err(Halt::AccessViolation(5u64 << 32)));

    // The program's own text is readable (it is the read-only region in a text-only program).
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_PROGRAM));
    p.push(insn(opc::LD_B_REG, 0, 1, 0, 0));
    p.push(exit());
    let text = asm(&p);
    assert_eq!(r0(&text), Ok(u64::from(text[0])));
}

#[test]
fn calls_push_frames_and_exit_pops() {
    // `call +2` (pc-relative in slots, from the slot after the call) reaches a function that sets
    // r0 = 7 and returns; the caller's own `mov r0, 1` after the call must not run.
    let p = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::CALL_IMM, 0, 0, 0, 2), // -> pc 4
        insn(opc::JA, 0, 0, 2, 0),       // -> exit at pc 5
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::MOV64_IMM, 0, 0, 0, 7), // the callee
        exit(),                           // and its `exit`, which returns to pc 2
    ]);
    // Slot 5 is both the callee's return and, after the `ja`, the program's exit.
    assert_eq!(r0(&p), Ok(7));

    // r10 moves up by one frame per call, and r6..r9 are callee-saved.
    let p = asm(&[
        insn(opc::MOV64_IMM, 6, 0, 0, 11),
        insn(opc::MOV64_REG, 1, 10, 0, 0),
        insn(opc::CALL_IMM, 0, 0, 0, 3), // -> pc 6
        insn(opc::SUB64_REG, 0, 1, 0, 0),
        insn(opc::ADD64_REG, 0, 6, 0, 0), // r0 = (r10_callee - r10_caller) + r6
        exit(),
        insn(opc::MOV64_IMM, 6, 0, 0, 99), // the callee clobbers r6
        insn(opc::MOV64_REG, 0, 10, 0, 0), // and reports its own r10
        exit(),
    ]);
    // r0 = one frame + 11 (r6 restored), so the callee's clobber did not escape.
    assert_eq!(r0(&p), Ok(STACK_FRAME as u64 + 11));

    // A `call` to a slot outside the text is a bad jump.
    let p = asm(&[insn(opc::CALL_IMM, 0, 0, 0, 1000), exit()]);
    assert_eq!(r0(&p), Err(Halt::BadJump));

    // `callx` takes its target *address* from the register the imm field names (v1), and the
    // address is translated back into a slot index against the text's base.
    let mut p = vec![];
    p.extend_from_slice(&lddw(3, REGION_PROGRAM + 4 * 8));
    p.push(insn(opc::CALL_REG, 0, 0, 0, 3));
    p.push(insn(opc::JA, 0, 0, 2, 0));
    p.push(insn(opc::MOV64_IMM, 0, 0, 0, 1));
    p.push(insn(opc::MOV64_IMM, 0, 0, 0, 8));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(8));

    // The push that would exceed `MAX_CALL_DEPTH` is `CallDepth`: a self-recursive function that
    // never returns. `MAX_CALL_DEPTH` frames of `STACK_FRAME` bytes is exactly the 32 KiB static
    // stack (Task 6: 8 × 4 KiB, Solana's own frame size — see `sbpf_core::memory`).
    let p = asm(&[insn(opc::CALL_IMM, 0, 0, 0, -1), exit()]);
    assert_eq!(r0(&p), Err(Halt::CallDepth));
}

#[test]
fn syscalls_by_hash() {
    // `sol_memset_(dst, c, n)`: fill eight bytes of the input region with 0xab.
    let mut input = [0u8; 16];
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.push(insn(opc::MOV64_IMM, 2, 0, 0, 0xab));
    p.push(insn(opc::MOV64_IMM, 3, 0, 0, 8));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_MEMSET as i32));
    p.push(exit());
    assert_eq!(sbpf::run_text(&asm(&p), &mut input).result, Ok(0));
    assert_eq!(&input[..8], &[0xab; 8]);
    assert_eq!(&input[8..], &[0; 8]);

    // `sol_memcpy_(dst, src, n)`.
    let mut input = [0u8; 16];
    input[..4].copy_from_slice(&[1, 2, 3, 4]);
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT + 8));
    p.extend_from_slice(&lddw(2, REGION_INPUT));
    p.push(insn(opc::MOV64_IMM, 3, 0, 0, 4));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_MEMCPY as i32));
    p.push(exit());
    assert_eq!(sbpf::run_text(&asm(&p), &mut input).result, Ok(0));
    assert_eq!(&input[8..12], &[1, 2, 3, 4]);

    // `sol_memcmp_(a, b, n, result_ptr)` writes the byte difference as an i32.
    let mut input = [0u8; 16];
    input[0] = 5;
    input[4] = 9;
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.extend_from_slice(&lddw(2, REGION_INPUT + 4));
    p.push(insn(opc::MOV64_IMM, 3, 0, 0, 4));
    p.extend_from_slice(&lddw(4, REGION_INPUT + 8));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_MEMCMP as i32));
    p.push(exit());
    assert_eq!(sbpf::run_text(&asm(&p), &mut input).result, Ok(0));
    assert_eq!(i32::from_le_bytes(input[8..12].try_into().unwrap()), 5 - 9);

    // `sol_memmove_` allows overlap where `sol_memcpy_` refuses it.
    let mut input = [1u8, 2, 3, 4, 0, 0, 0, 0];
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT + 2));
    p.extend_from_slice(&lddw(2, REGION_INPUT));
    p.push(insn(opc::MOV64_IMM, 3, 0, 0, 4));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_MEMMOVE as i32));
    p.push(exit());
    assert_eq!(sbpf::run_text(&asm(&p), &mut input.clone()).result, Ok(0));
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT + 2));
    p.extend_from_slice(&lddw(2, REGION_INPUT));
    p.push(insn(opc::MOV64_IMM, 3, 0, 0, 4));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_MEMCPY as i32));
    p.push(exit());
    assert_eq!(
        sbpf::run_text(&asm(&p), &mut input).result,
        Err(Halt::Trap("sol_memcpy_ overlap"))
    );

    // The `sol_log*` family is a no-op that returns 0, and `sol_log_compute_units_` takes no
    // argument at all.
    let mut input = *b"hello, world!\0\0\0";
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.push(insn(opc::MOV64_IMM, 2, 0, 0, 13));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_LOG as i32));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_LOG_COMPUTE_UNITS as i32));
    p.push(exit());
    assert_eq!(sbpf::run_text(&asm(&p), &mut input).result, Ok(0));

    // `sol_alloc_free_` is a bump allocator over the heap region: two allocations are distinct,
    // 8-aligned, inside the heap, and a free is a no-op returning 0.
    let mut p = vec![];
    p.push(insn(opc::MOV64_IMM, 1, 0, 0, 1));
    p.push(insn(opc::MOV64_IMM, 2, 0, 0, 0));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_ALLOC_FREE as i32));
    p.push(insn(opc::MOV64_REG, 6, 0, 0, 0));
    p.push(insn(opc::MOV64_IMM, 1, 0, 0, 1));
    p.push(insn(opc::MOV64_IMM, 2, 0, 0, 0));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_ALLOC_FREE as i32));
    p.push(insn(opc::SUB64_REG, 0, 6, 0, 0));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(8));
    // An allocation larger than the heap fails with a null return rather than a halt.
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, HEAP_BYTES as u64 + 1));
    p.push(insn(opc::MOV64_IMM, 2, 0, 0, 0));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_ALLOC_FREE as i32));
    p.push(exit());
    assert_eq!(r0(&asm(&p)), Ok(0));

    // `abort` and `sol_panic_` are exceptional halts.
    let p = asm(&[insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::ABORT as i32), exit()]);
    assert_eq!(r0(&p), Err(Halt::Trap("abort")));
    let p = asm(&[
        insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_PANIC as i32),
        exit(),
    ]);
    assert_eq!(r0(&p), Err(Halt::Trap("sol_panic_")));

    // An unsupported name (here `sol_keccak256`, which the plan lists as trapping) and a hash
    // belonging to nothing at all are both `UnknownSyscall`.
    let h = sbpf_core::syscalls::murmur3_32(b"sol_keccak256", 0);
    let p = asm(&[insn(opc::CALL_IMM, 0, 1, 0, h as i32), exit()]);
    assert_eq!(r0(&p), Err(Halt::UnknownSyscall(h)));
    let p = asm(&[insn(opc::CALL_IMM, 0, 1, 0, 1), exit()]);
    assert_eq!(r0(&p), Err(Halt::UnknownSyscall(1)));

    // A syscall whose pointer argument leaves its region is an access violation, not a panic.
    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.push(insn(opc::MOV64_IMM, 2, 0, 0, 0));
    p.push(insn(opc::MOV64_IMM, 3, 0, 0, 64));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_MEMSET as i32));
    p.push(exit());
    let mut input = [0u8; 16];
    assert_eq!(
        sbpf::run_text(&asm(&p), &mut input).result,
        Err(Halt::AccessViolation(REGION_INPUT))
    );
}

#[test]
fn the_syscall_hashes_are_murmur3_of_the_name() {
    // The hash sBPF puts in `call imm` is murmur3-32, seed 0, over the raw symbol name — the same
    // function `solana_sbpf::ebpf::hash_symbol_name` uses, so a relocated ELF's call sites and
    // `sbpf-core`'s table agree by construction.
    for name in [
        &b"abort"[..],
        b"sol_panic_",
        b"sol_log_",
        b"sol_log_64_",
        b"sol_log_compute_units_",
        b"sol_log_pubkey",
        b"sol_memcpy_",
        b"sol_memmove_",
        b"sol_memset_",
        b"sol_memcmp_",
        b"sol_alloc_free_",
        b"sol_sha256",
        b"entrypoint",
        b"",
        b"a",
        b"ab",
        b"abc",
        b"abcd",
        b"abcde",
    ] {
        assert_eq!(
            sbpf_core::syscalls::murmur3_32(name, 0),
            solana_sbpf::ebpf::hash_symbol_name(name),
            "{}",
            String::from_utf8_lossy(name)
        );
    }
}

#[test]
fn sol_sha256_hashes_the_concatenation_of_its_vectors() {
    // `sol_sha256(vals_ptr, vals_len, result_ptr)`: `vals` is an array of (ptr, len) pairs and the
    // digest is over their concatenation. Laid out in the input region: two 16-byte pairs at 0,
    // the 6-byte and 7-byte strings at 32 and 40, the 32-byte digest at 64.
    let mut input = vec![0u8; 128];
    input[0..8].copy_from_slice(&(REGION_INPUT + 32).to_le_bytes());
    input[8..16].copy_from_slice(&6u64.to_le_bytes());
    input[16..24].copy_from_slice(&(REGION_INPUT + 40).to_le_bytes());
    input[24..32].copy_from_slice(&7u64.to_le_bytes());
    input[32..38].copy_from_slice(b"abcdef");
    input[40..47].copy_from_slice(b"ghijklm");

    let mut p = vec![];
    p.extend_from_slice(&lddw(1, REGION_INPUT));
    p.push(insn(opc::MOV64_IMM, 2, 0, 0, 2));
    p.extend_from_slice(&lddw(3, REGION_INPUT + 64));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sbpf_core::syscalls::SOL_SHA256 as i32));
    p.push(exit());
    assert_eq!(sbpf::run_text(&asm(&p), &mut input).result, Ok(0));
    assert_eq!(&input[64..96], &randprotocol_zkvm::sha256::sha256(b"abcdefghijklm")[..]);
}

#[test]
fn the_instruction_meter_halts_a_loop() {
    // `ja -1` jumps to itself: the meter is the only thing that ends the run.
    let p = asm(&[insn(opc::JA, 0, 0, -1, 0)]);
    let out = sbpf::run_text(&p, &mut []);
    assert_eq!(out.result, Err(Halt::InstructionLimit));
    assert_eq!(out.instructions, MAX_INSTRUCTIONS);
    assert_eq!(MAX_INSTRUCTIONS, 200_000);

    // A program that fits under the meter reports exactly what it executed; `lddw` is two slots
    // but one instruction.
    let mut p = vec![];
    p.extend_from_slice(&lddw(0, 1));
    p.push(exit());
    let out = sbpf::run_text(&asm(&p), &mut []);
    assert_eq!((out.result, out.instructions), (Ok(1), 2));
}

#[test]
fn a_program_that_runs_off_the_end_of_its_text_halts() {
    // No `exit`: the fetch past the last slot is a bad jump, not a read of adjacent memory.
    let p = asm(&[insn(opc::MOV64_IMM, 0, 0, 0, 1)]);
    assert_eq!(r0(&p), Err(Halt::BadJump));
    // An empty text cannot even fetch its first slot.
    assert_eq!(r0(&[]), Err(Halt::BadJump));
    // A text whose length is not a whole number of slots is rejected at `Program::from_text`.
    assert!(sbpf_core::elf::Program::from_text(&[0u8; 7]).is_err());
}

#[test]
fn the_initial_register_state_matches_solana_sbpf() {
    // r1 = the input region's base, r10 = the top of frame 0, everything else zero.
    let p = asm(&[insn(opc::MOV64_REG, 0, 1, 0, 0), exit()]);
    assert_eq!(r0(&p), Ok(REGION_INPUT));
    let p = asm(&[insn(opc::MOV64_REG, 0, 10, 0, 0), exit()]);
    assert_eq!(r0(&p), Ok(REGION_STACK + STACK_FRAME as u64));
    for reg in [2u8, 3, 4, 5, 6, 7, 8, 9] {
        let p = asm(&[insn(opc::MOV64_REG, 0, reg, 0, 0), exit()]);
        assert_eq!(r0(&p), Ok(0), "r{reg}");
    }
}

/// One random straight-line ALU/jump program: `mov64` immediates into r1..r5, then `n` random
/// ALU and short forward-jump instructions, then `r0 = r1 ^ r2 + r3 | r4 - r5` and `exit`.
fn random_program<R: rand::RngExt>(rng: &mut R, n: usize) -> Vec<u8> {
    #[rustfmt::skip]
    const ALU: &[u8] = &[
        opc::ADD32_IMM, opc::ADD32_REG, opc::SUB32_IMM, opc::SUB32_REG, opc::MUL32_IMM,
        opc::MUL32_REG, opc::DIV32_IMM, opc::DIV32_REG, opc::OR32_IMM, opc::OR32_REG,
        opc::AND32_IMM, opc::AND32_REG, opc::LSH32_IMM, opc::LSH32_REG, opc::RSH32_IMM,
        opc::RSH32_REG, opc::NEG32, opc::MOD32_IMM, opc::MOD32_REG, opc::XOR32_IMM,
        opc::XOR32_REG, opc::MOV32_IMM, opc::MOV32_REG, opc::ARSH32_IMM, opc::ARSH32_REG,
        opc::LE, opc::BE,
        opc::ADD64_IMM, opc::ADD64_REG, opc::SUB64_IMM, opc::SUB64_REG, opc::MUL64_IMM,
        opc::MUL64_REG, opc::DIV64_IMM, opc::DIV64_REG, opc::OR64_IMM, opc::OR64_REG,
        opc::AND64_IMM, opc::AND64_REG, opc::LSH64_IMM, opc::LSH64_REG, opc::RSH64_IMM,
        opc::RSH64_REG, opc::NEG64, opc::MOD64_IMM, opc::MOD64_REG, opc::XOR64_IMM,
        opc::XOR64_REG, opc::MOV64_IMM, opc::MOV64_REG, opc::ARSH64_IMM, opc::ARSH64_REG,
    ];
    #[rustfmt::skip]
    const JMP: &[u8] = &[
        opc::JA, opc::JEQ_IMM, opc::JEQ_REG, opc::JGT_IMM, opc::JGT_REG, opc::JGE_IMM,
        opc::JGE_REG, opc::JLT_IMM, opc::JLT_REG, opc::JLE_IMM, opc::JLE_REG, opc::JSET_IMM,
        opc::JSET_REG, opc::JNE_IMM, opc::JNE_REG, opc::JSGT_IMM, opc::JSGT_REG, opc::JSGE_IMM,
        opc::JSGE_REG, opc::JSLT_IMM, opc::JSLT_REG, opc::JSLE_IMM, opc::JSLE_REG,
    ];

    let mut p: Vec<[u8; 8]> = Vec::new();
    for reg in 1..=5u8 {
        p.extend_from_slice(&lddw(reg, rng.random()));
    }
    // `lddw` is two slots, so the body starts here and every forward jump must stay inside it.
    let body_start = p.len();
    for i in 0..n {
        let jump = rng.random_range(0..5u32) == 0;
        let (dst, src) = (rng.random_range(1..=5u8), rng.random_range(1..=5u8));
        if jump {
            let op = JMP[rng.random_range(0..JMP.len())];
            // Forward only, and never past the end of the body: no loops, so the meter is never
            // the thing that ends the run and the two machines are compared on a value.
            let off = rng.random_range(0..=(n - i - 1)) as i16;
            p.push(insn(op, dst, src, off, rng.random::<i32>() >> 20));
        } else {
            let op = ALU[rng.random_range(0..ALU.len())];
            let imm = match op {
                // A `div`/`mod` by an immediate zero has no defined answer in v1: `solana-sbpf`'s
                // interpreter divides by it (the verifier is what rejects those programs), so the
                // oracle would panic rather than fault. `sbpf-core` halts with `DivByZero`; the
                // *register* forms, which both machines fault on, cover that path below.
                opc::DIV32_IMM | opc::DIV64_IMM | opc::MOD32_IMM | opc::MOD64_IMM => {
                    rng.random_range(1..=i32::MAX)
                }
                // `le`/`be` only take 16, 32 and 64.
                opc::LE | opc::BE => [16, 32, 64][rng.random_range(0..3)],
                _ => rng.random(),
            };
            p.push(insn(op, dst, src, 0, imm));
        }
    }
    debug_assert_eq!(p.len(), body_start + n);
    p.push(insn(opc::XOR64_REG, 1, 2, 0, 0));
    p.push(insn(opc::ADD64_REG, 1, 3, 0, 0));
    p.push(insn(opc::OR64_REG, 1, 4, 0, 0));
    p.push(insn(opc::SUB64_REG, 1, 5, 0, 0));
    p.push(insn(opc::MOV64_REG, 0, 1, 0, 0));
    p.push(exit());
    asm(&p)
}

#[test]
fn random_alu_and_jump_programs_agree_with_solana_sbpf() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(4400);
    let mut faulted = 0usize;
    for case in 0..500 {
        let text = random_program(&mut rng, 24);
        let ours = sbpf::run_text(&text, &mut []).result.map_err(|_| ());
        let theirs = oracle::run_text(&text, &[]).0.map_err(|_| ());
        assert_eq!(ours, theirs, "case {case}, text {}", hex::encode(&text));
        if ours.is_err() {
            faulted += 1;
        }
    }
    // The generator makes division by a zero *register* likely enough that both machines must
    // have agreed on a fault at least once — otherwise this test is only exercising the happy
    // path and the `DivByZero` agreement is untested.
    assert!(faulted > 0, "no case faulted: the fault paths were not compared");
}

#[test]
fn random_memory_programs_agree_with_solana_sbpf() {
    // The same differential over loads and stores: random sizes and offsets against a 64-byte
    // input region, so in-bounds accesses and access violations are both compared.
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(4400);
    let mut violated = 0usize;
    for case in 0..500 {
        let mut p: Vec<[u8; 8]> = Vec::new();
        p.extend_from_slice(&lddw(1, REGION_INPUT));
        p.extend_from_slice(&lddw(2, rng.random::<u64>()));
        for _ in 0..8 {
            let (ld, sz) = (rng.random_range(0..2u32) == 0, rng.random_range(0..4));
            let off = rng.random_range(-8i16..=72);
            let op = if ld {
                [opc::LD_B_REG, opc::LD_H_REG, opc::LD_W_REG, opc::LD_DW_REG][sz]
            } else if rng.random_range(0..2u32) == 0 {
                [opc::ST_B_IMM, opc::ST_H_IMM, opc::ST_W_IMM, opc::ST_DW_IMM][sz]
            } else {
                [opc::ST_B_REG, opc::ST_H_REG, opc::ST_W_REG, opc::ST_DW_REG][sz]
            };
            if ld {
                p.push(insn(op, 3, 1, off, 0));
                p.push(insn(opc::XOR64_REG, 2, 3, 0, 0));
            } else {
                p.push(insn(op, 1, 2, off, rng.random()));
            }
        }
        p.push(insn(opc::MOV64_REG, 0, 2, 0, 0));
        p.push(exit());
        let text = asm(&p);

        let mut ours_mem: Vec<u8> = (0..64u8).collect();
        let mut theirs_mem = ours_mem.clone();
        let ours = sbpf::run_text(&text, &mut ours_mem).result.map_err(|_| ());
        let (theirs, theirs_post) = oracle::run_text(&text, &theirs_mem);
        theirs_mem = theirs_post;
        assert_eq!(ours, theirs.map_err(|_| ()), "case {case}, text {}", hex::encode(&text));
        assert_eq!(ours_mem, theirs_mem, "case {case}: post-state of the input region");
        if ours.is_err() {
            violated += 1;
        }
    }
    assert!(violated > 0, "no case violated a region: the fault paths were not compared");
}

#[test]
fn every_classified_opcode_is_implemented() {
    // The completeness check: `isa::classify` and the interpreter's dispatch are two lists of the
    // same 91 opcode bytes, and this is what stops them drifting apart. A program consisting of the
    // one instruction may halt for any reason at all — an access violation, a bad jump, an unknown
    // syscall — but never with `BadInsn(that byte)`, which is exactly "this interpreter does not
    // implement it".
    let mut implemented = 0usize;
    for byte in 0..=255u8 {
        // `le`/`be` need a width in the immediate; `callx` needs a register number; everything else
        // is happy with a zero immediate.
        let imm = match byte {
            opc::LE | opc::BE => 64,
            _ => 0,
        };
        // `lddw` occupies two slots, so give every program a spare one.
        let p = asm(&[insn(byte, 0, 0, 0, imm), exit(), exit()]);
        let halted_as_unknown = r0(&p) == Err(Halt::BadInsn(byte));
        match sbpf_core::isa::classify(byte) {
            Some(_) => {
                assert!(!halted_as_unknown, "opcode {byte:#04x} is classified but not implemented");
                implemented += 1;
            }
            None => assert!(halted_as_unknown, "opcode {byte:#04x} is not in v1 but did not trap"),
        }
    }
    assert_eq!(implemented, 91);
}

#[test]
fn every_supported_syscall_dispatches() {
    // The syscall list's own completeness check: every name in `syscalls::SUPPORTED` reaches an
    // implementation. The call may still fault on the zero arguments it is given (`sol_memcmp_`
    // writes its result through r4, which is 0 and in no region) or deliberately abort — what it
    // may never be is `UnknownSyscall`.
    assert_eq!(sbpf_core::syscalls::SUPPORTED.len(), 12);
    for &(hash, name) in sbpf_core::syscalls::SUPPORTED {
        assert_eq!(hash, sbpf_core::syscalls::murmur3_32(name.as_bytes(), 0), "{name}");
        let p = asm(&[insn(opc::CALL_IMM, 0, 1, 0, hash as i32), exit()]);
        assert_ne!(r0(&p), Err(Halt::UnknownSyscall(hash)), "{name} does not dispatch");
    }
    // And the names the plan rules out of scope do not secretly dispatch.
    for name in [
        &b"sol_keccak256"[..],
        b"sol_secp256k1_recover",
        b"sol_invoke_signed_rust",
        b"sol_create_program_address",
        b"sol_try_find_program_address",
        b"sol_get_clock_sysvar",
    ] {
        let h = sbpf_core::syscalls::murmur3_32(name, 0);
        let p = asm(&[insn(opc::CALL_IMM, 0, 1, 0, h as i32), exit()]);
        assert_eq!(
            r0(&p),
            Err(Halt::UnknownSyscall(h)),
            "{} must be out of scope",
            String::from_utf8_lossy(name)
        );
    }
}

/// One slot of a program whose `call`s name an absolute target slot, so the same program can be
/// emitted in both conventions: `sbpf-core`'s slot-relative immediate and `solana-sbpf`'s hashed
/// function key.
enum Slot {
    /// `insn(opc, dst, src, off, imm)`.
    Op(u8, u8, u8, i16, i32),
    /// `call` to an absolute slot index.
    Call(usize),
}

fn emit(slots: &[Slot], relative: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, s) in slots.iter().enumerate() {
        out.push(match *s {
            Slot::Op(opc, dst, src, off, imm) => insn(opc, dst, src, off, imm),
            Slot::Call(target) => {
                let imm = if relative {
                    target as i64 - (i as i64 + 1)
                } else {
                    i64::from(oracle::call_imm_for(target))
                };
                insn(opc::CALL_IMM, 0, 0, 0, imm as i32)
            }
        });
    }
    asm(&out)
}

fn call_targets(slots: &[Slot]) -> Vec<usize> {
    slots.iter().filter_map(|s| if let Slot::Call(t) = s { Some(*t) } else { None }).collect()
}

#[test]
fn nested_calls_agree_with_solana_sbpf() {
    use Slot::{Call, Op};
    // Two levels of nesting: each callee clobbers r6/r7, and every caller must see its own back.
    let nested = [
        Op(opc::MOV64_IMM, 6, 0, 0, 1),
        Op(opc::MOV64_IMM, 7, 0, 0, 2),
        Call(6),
        Op(opc::ADD64_REG, 0, 6, 0, 0),
        Op(opc::ADD64_REG, 0, 7, 0, 0),
        Op(opc::EXIT, 0, 0, 0, 0),
        Op(opc::MOV64_IMM, 6, 0, 0, 100), // slot 6: the outer callee
        Op(opc::MOV64_IMM, 7, 0, 0, 200),
        Call(11),
        Op(opc::MOV64_REG, 0, 6, 0, 0), // its own r6 must be back after the inner call
        Op(opc::EXIT, 0, 0, 0, 0),
        Op(opc::MOV64_IMM, 6, 0, 0, 7), // slot 11: the inner callee
        Op(opc::MOV64_REG, 0, 10, 0, 0),
        Op(opc::EXIT, 0, 0, 0, 0),
    ];
    // A frame pointer three frames up, then returned through two `exit`s.
    let frames = [
        Call(3),
        Op(opc::MOV64_REG, 1, 10, 0, 0),
        Op(opc::EXIT, 0, 0, 0, 0),
        Op(opc::MOV64_REG, 0, 10, 0, 0), // slot 3
        Op(opc::EXIT, 0, 0, 0, 0),
    ];
    // A self-recursive call that never returns: both machines must run out of frames.
    let too_deep = [Call(0), Op(opc::EXIT, 0, 0, 0, 0)];
    // A call to a slot past the end of the text.
    let off_the_end = [Call(9_000), Op(opc::EXIT, 0, 0, 0, 0)];

    for (name, slots) in [
        ("nested", &nested[..]),
        ("frames", &frames[..]),
        ("too_deep", &too_deep[..]),
        ("off_the_end", &off_the_end[..]),
    ] {
        let ours = sbpf::run_text(&emit(slots, true), &mut []).result.map_err(|_| ());
        let theirs = oracle::run_text_with_calls(&emit(slots, false), &call_targets(slots), &[])
            .0
            .map_err(|_| ());
        assert_eq!(ours, theirs, "{name}");
    }
    // And the one value worth naming: 100 + 1 + 2.
    assert_eq!(sbpf::run_text(&emit(&nested, true), &mut []).result, Ok(103));
}

#[test]
fn callx_agrees_with_solana_sbpf() {
    // `callx` needs no relocation and no registry in v1 — the target is an address in the register
    // the immediate names — so both machines run the very same bytes.
    for (reg, target) in [(3u8, 4u64), (3, 0), (3, 100), (9, 4)] {
        let mut p: Vec<[u8; 8]> = Vec::new();
        p.extend_from_slice(&lddw(reg, REGION_PROGRAM + 8 * target));
        p.push(insn(opc::CALL_REG, 0, 0, 0, i32::from(reg)));
        p.push(insn(opc::JA, 0, 0, 2, 0));
        p.push(insn(opc::MOV64_IMM, 0, 0, 0, 1));
        p.push(insn(opc::MOV64_IMM, 0, 0, 0, 8));
        p.push(exit());
        let text = asm(&p);
        let ours = sbpf::run_text(&text, &mut []).result.map_err(|_| ());
        let theirs = oracle::run_text(&text, &[]).0.map_err(|_| ());
        assert_eq!(ours, theirs, "callx r{reg} -> slot {target}");
    }
}

/// A one-syscall program: set up `r1..r5` from `args` (each an absolute value, so an input-region
/// pointer is written as `REGION_INPUT + off`), `call` the syscall, and return its `r0`.
///
/// The bytes are identical for both machines. `sbpf-core` reads the `src = 1` marker its loader
/// writes; `solana-sbpf`'s V0 `CALL_IMM` ignores `src` entirely and resolves the immediate through
/// the loader's function registry, which `common::sbpf_oracle` registers under the same twelve
/// murmur3 names — so one program exercises both dispatchers.
fn syscall_program(hash: u32, args: &[u64]) -> Vec<u8> {
    let mut p: Vec<[u8; 8]> = Vec::new();
    for (i, v) in args.iter().enumerate() {
        p.extend_from_slice(&lddw(i as u8 + 1, *v));
    }
    p.push(insn(opc::CALL_IMM, 0, 1, 0, hash as i32));
    p.push(exit());
    asm(&p)
}

/// Runs one syscall program on both machines over the same 128-byte input region and asserts they
/// agree on `r0` (or both fault) **and** on the region byte for byte.
fn assert_syscall_agrees(name: &str, hash: u32, args: &[u64], region: &[u8]) {
    let text = syscall_program(hash, args);
    let mut ours_mem = region.to_vec();
    let ours = sbpf::run_text(&text, &mut ours_mem).result.map_err(|_| ());
    let (theirs, theirs_mem) = oracle::run_text(&text, region);
    assert_eq!(ours, theirs.clone().map_err(|_| ()), "{name}: r0 (theirs: {theirs:?})");
    assert_eq!(ours_mem, theirs_mem, "{name}: the input region's post-state");
}

/// A 128-byte scratch region with recognisable contents.
fn scratch() -> Vec<u8> {
    (0..128u8).collect()
}

#[test]
fn the_memory_syscalls_agree_with_solana_sbpf() {
    use sbpf_core::syscalls as sys;
    let at = |off: u64| REGION_INPUT + off;

    // `sol_memset_(dst, c, n)`: in bounds, zero length, and one byte too long.
    assert_syscall_agrees("memset", sys::SOL_MEMSET, &[at(0), 0xab, 8], &scratch());
    assert_syscall_agrees("memset 0", sys::SOL_MEMSET, &[at(0), 0xab, 0], &scratch());
    assert_syscall_agrees("memset past", sys::SOL_MEMSET, &[at(120), 0xab, 9], &scratch());
    assert_syscall_agrees("memset huge", sys::SOL_MEMSET, &[at(0), 0xab, 1 << 40], &scratch());
    assert_syscall_agrees("memset region 0", sys::SOL_MEMSET, &[0, 0xab, 4], &scratch());

    // `sol_memcpy_(dst, src, n)`: non-overlapping, and the overlap both machines refuse.
    assert_syscall_agrees("memcpy", sys::SOL_MEMCPY, &[at(64), at(0), 32], &scratch());
    assert_syscall_agrees("memcpy touching", sys::SOL_MEMCPY, &[at(8), at(0), 8], &scratch());
    assert_syscall_agrees("memcpy overlap", sys::SOL_MEMCPY, &[at(4), at(0), 8], &scratch());
    assert_syscall_agrees("memcpy overlap rev", sys::SOL_MEMCPY, &[at(0), at(4), 8], &scratch());
    assert_syscall_agrees("memcpy past", sys::SOL_MEMCPY, &[at(120), at(0), 9], &scratch());

    // `sol_memmove_(dst, src, n)`: overlap is allowed, in both directions, and across the 64-byte
    // chunk `sbpf-core` copies in — which is where a backwards copy would go wrong if it did not.
    assert_syscall_agrees("memmove up", sys::SOL_MEMMOVE, &[at(4), at(0), 100], &scratch());
    assert_syscall_agrees("memmove down", sys::SOL_MEMMOVE, &[at(0), at(4), 100], &scratch());
    assert_syscall_agrees("memmove far up", sys::SOL_MEMMOVE, &[at(60), at(0), 68], &scratch());
    assert_syscall_agrees("memmove exact", sys::SOL_MEMMOVE, &[at(0), at(0), 128], &scratch());
    assert_syscall_agrees("memmove past", sys::SOL_MEMMOVE, &[at(0), at(64), 100], &scratch());

    // `sol_memcmp_(a, b, n, result)`: equal, and both signs of unequal — the result is a *signed*
    // i32 written to the region, so a machine that wrote it unsigned would differ here.
    let mut eq = scratch();
    eq[64..96].copy_from_slice(&(0..32u8).collect::<Vec<_>>());
    assert_syscall_agrees("memcmp eq", sys::SOL_MEMCMP, &[at(0), at(64), 32, at(100)], &eq);
    let mut lt = scratch();
    lt[0] = 5;
    lt[64] = 9;
    assert_syscall_agrees("memcmp negative", sys::SOL_MEMCMP, &[at(0), at(64), 8, at(100)], &lt);
    let mut gt = scratch();
    gt[0] = 9;
    gt[64] = 5;
    assert_syscall_agrees("memcmp positive", sys::SOL_MEMCMP, &[at(0), at(64), 8, at(100)], &gt);
    // The difference straddling the 64-byte chunk boundary.
    let mut late = scratch();
    late[70] = 0xff;
    assert_syscall_agrees("memcmp late", sys::SOL_MEMCMP, &[at(0), at(64), 64, at(0)], &late);

    // Atomicity: a syscall does all of its work or none of it, so a four-byte result that only
    // *partly* fits writes nothing at all — not two bytes and then a fault. Likewise a comparison
    // whose difference lies before the point where its range runs out still faults, because the
    // whole range is translated before a byte is read. (This pair is what the differential caught:
    // the oracle used to validate lazily, and wrote a partial result the real runtime never would.)
    assert_syscall_agrees("memcmp bad out", sys::SOL_MEMCMP, &[at(0), at(64), 8, at(126)], &lt);
    assert_syscall_agrees("memcmp bad out edge", sys::SOL_MEMCMP, &[at(0), at(64), 8, at(124)], &lt);
    assert_syscall_agrees("memcmp early diff, short range", sys::SOL_MEMCMP, &[at(0), at(64), 100, at(100)], &lt);
    // And the same for a `memset` that would overrun: nothing is written before it faults.
    assert_syscall_agrees("memset atomic", sys::SOL_MEMSET, &[at(126), 0xab, 4], &scratch());
}

#[test]
fn sol_alloc_free_agrees_with_solana_sbpf() {
    use sbpf_core::syscalls::SOL_ALLOC_FREE;
    // The returned address itself is compared, not just "some address": both allocators hand out
    // 8-aligned blocks going up from the heap region's base.
    for size in [1u64, 7, 8, 9, 4096, HEAP_BYTES as u64, HEAP_BYTES as u64 + 1, 1 << 40] {
        assert_syscall_agrees("alloc", SOL_ALLOC_FREE, &[size, 0], &scratch());
    }
    // A free is a no-op returning 0.
    assert_syscall_agrees("free", SOL_ALLOC_FREE, &[8, REGION_HEAP], &scratch());

    // Two allocations in one run: the second address must be the first plus the aligned size, on
    // both machines. `r6` keeps the first across the second call.
    for size in [1u64, 8, 9, 100] {
        let mut p: Vec<[u8; 8]> = Vec::new();
        p.extend_from_slice(&lddw(1, size));
        p.push(insn(opc::MOV64_IMM, 2, 0, 0, 0));
        p.push(insn(opc::CALL_IMM, 0, 1, 0, SOL_ALLOC_FREE as i32));
        p.push(insn(opc::MOV64_REG, 6, 0, 0, 0));
        p.extend_from_slice(&lddw(1, size));
        p.push(insn(opc::MOV64_IMM, 2, 0, 0, 0));
        p.push(insn(opc::CALL_IMM, 0, 1, 0, SOL_ALLOC_FREE as i32));
        // Store both addresses into the input region so the *values* are compared too, not just
        // their difference.
        p.extend_from_slice(&lddw(3, REGION_INPUT));
        p.push(insn(opc::ST_DW_REG, 3, 6, 0, 0));
        p.push(insn(opc::ST_DW_REG, 3, 0, 8, 0));
        p.push(insn(opc::SUB64_REG, 0, 6, 0, 0));
        p.push(exit());
        let text = asm(&p);
        let mut ours_mem = vec![0u8; 32];
        let ours = sbpf::run_text(&text, &mut ours_mem).result.map_err(|_| ());
        let (theirs, theirs_mem) = oracle::run_text(&text, &[0u8; 32]);
        assert_eq!(ours, theirs.map_err(|_| ()), "two allocations of {size}");
        assert_eq!(ours_mem, theirs_mem, "the two addresses, for size {size}");
        // And the bump really is aligned to 8.
        assert_eq!(ours, Ok((size + 7) & !7), "size {size}");
    }
}

#[test]
fn sol_sha256_agrees_with_solana_sbpf() {
    use sbpf_core::syscalls::SOL_SHA256;
    // `sol_sha256(vals, vals_len, result)`: `vals` is an array of `(ptr, len)` pairs and the digest
    // is over their concatenation. Laid out at 0, the strings at 32, the digest at 64.
    let pairs = |lens: &[(u64, u64)]| {
        let mut region = vec![0u8; 256];
        for (i, (off, len)) in lens.iter().enumerate() {
            region[16 * i..16 * i + 8].copy_from_slice(&(REGION_INPUT + off).to_le_bytes());
            region[16 * i + 8..16 * i + 16].copy_from_slice(&len.to_le_bytes());
        }
        for (i, b) in region[96..256].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        region
    };
    // One segment, several segments, a zero-length segment, and none at all.
    assert_syscall_agrees("sha256 1", SOL_SHA256, &[REGION_INPUT, 1, REGION_INPUT + 64], &pairs(&[(96, 6)]));
    assert_syscall_agrees(
        "sha256 3",
        SOL_SHA256,
        &[REGION_INPUT, 3, REGION_INPUT + 64],
        &pairs(&[(96, 6), (110, 0), (120, 100)]),
    );
    assert_syscall_agrees("sha256 0", SOL_SHA256, &[REGION_INPUT, 0, REGION_INPUT + 64], &pairs(&[]));
    // A segment crossing the 64-byte streaming chunk, and one that straddles a block boundary.
    assert_syscall_agrees("sha256 64", SOL_SHA256, &[REGION_INPUT, 1, REGION_INPUT + 64], &pairs(&[(96, 64)]));
    assert_syscall_agrees("sha256 160", SOL_SHA256, &[REGION_INPUT, 1, REGION_INPUT + 64], &pairs(&[(96, 160)]));
    // A pointer or a result address out of bounds faults on both.
    assert_syscall_agrees(
        "sha256 bad ptr",
        SOL_SHA256,
        &[REGION_INPUT, 1, REGION_INPUT + 64],
        &pairs(&[(96, 1000)]),
    );
    assert_syscall_agrees("sha256 bad out", SOL_SHA256, &[REGION_INPUT, 1, 0], &pairs(&[(96, 6)]));
    // A digest pointer that only partly fits writes no part of the digest.
    assert_syscall_agrees(
        "sha256 bad out edge",
        SOL_SHA256,
        &[REGION_INPUT, 1, REGION_INPUT + 100],
        &pairs(&[(96, 6)]),
    );
    assert_syscall_agrees("sha256 bad vals", SOL_SHA256, &[0, 1, REGION_INPUT + 64], &pairs(&[(96, 6)]));

    // And the digest is the real SHA-256 of the concatenation, not merely a matching one.
    let region = pairs(&[(96, 6), (110, 0), (120, 100)]);
    let text = syscall_program(SOL_SHA256, &[REGION_INPUT, 3, REGION_INPUT + 64]);
    let mut mem = region.clone();
    assert_eq!(sbpf::run_text(&text, &mut mem).result, Ok(0));
    let mut msg = Vec::new();
    msg.extend_from_slice(&region[96..102]);
    msg.extend_from_slice(&region[120..220]);
    assert_eq!(&mem[64..96], &randprotocol_zkvm::sha256::sha256(&msg)[..]);
}

#[test]
fn the_log_and_abort_syscalls_agree_with_solana_sbpf() {
    use sbpf_core::syscalls as sys;
    // The log family writes nothing and returns 0, but still translates its pointers — so a bad
    // one faults on both machines, which is the only observable part.
    assert_syscall_agrees("log", sys::SOL_LOG, &[REGION_INPUT, 13], &scratch());
    assert_syscall_agrees("log 0", sys::SOL_LOG, &[REGION_INPUT, 0], &scratch());
    assert_syscall_agrees("log past", sys::SOL_LOG, &[REGION_INPUT + 120, 9], &scratch());
    assert_syscall_agrees("log bad", sys::SOL_LOG, &[0, 4], &scratch());
    assert_syscall_agrees("log_64", sys::SOL_LOG_64, &[1, 2, 3, 4, 5], &scratch());
    assert_syscall_agrees("log_cu", sys::SOL_LOG_COMPUTE_UNITS, &[], &scratch());
    assert_syscall_agrees("log_pubkey", sys::SOL_LOG_PUBKEY, &[REGION_INPUT], &scratch());
    assert_syscall_agrees("log_pubkey past", sys::SOL_LOG_PUBKEY, &[REGION_INPUT + 100], &scratch());
    assert_syscall_agrees("log_pubkey bad", sys::SOL_LOG_PUBKEY, &[0], &scratch());

    // `abort` and `sol_panic_` end the run on both.
    assert_syscall_agrees("abort", sys::ABORT, &[], &scratch());
    assert_syscall_agrees("panic", sys::SOL_PANIC, &[REGION_INPUT, 4, 1, 2], &scratch());

    // A mutation before an abort is visible in the region on both machines — which is what makes
    // `abi::run_call_with`'s "a failed run binds the pre-state" rule load-bearing rather than
    // vacuous (`tests/sbpf_abi.rs` asserts the rule itself).
    let mut p: Vec<[u8; 8]> = Vec::new();
    p.extend_from_slice(&lddw(3, REGION_INPUT));
    p.push(insn(opc::ST_DW_IMM, 3, 0, 0, 0x7f));
    p.push(insn(opc::CALL_IMM, 0, 1, 0, sys::ABORT as i32));
    p.push(exit());
    let text = asm(&p);
    let mut ours_mem = scratch();
    let ours = sbpf::run_text(&text, &mut ours_mem).result;
    let (theirs, theirs_mem) = oracle::run_text(&text, &scratch());
    assert!(ours.is_err() && theirs.is_err(), "{ours:?} / {theirs:?}");
    assert_eq!(ours_mem, theirs_mem);
    assert_eq!(ours_mem[0], 0x7f, "the store landed before the abort");

    // An unregistered hash is refused by both: `sbpf-core` returns `UnknownSyscall`, `solana-sbpf`
    // `UnsupportedInstruction`, and the plan's out-of-scope names are exactly this case.
    for name in [&b"sol_keccak256"[..], b"sol_invoke_signed_rust", b"sol_get_clock_sysvar"] {
        let h = sbpf_core::syscalls::murmur3_32(name, 0);
        assert_syscall_agrees(&String::from_utf8_lossy(name), h, &[], &scratch());
    }
}
