//! Guest programs shared by tests and the demo. Registers: t0..t6 = x5..x7,x28..x31; s0.. = x8..
use crate::asm::{ops::*, Assembler};
use crate::isa::*;

const T0: u32 = 5; const T1: u32 = 6; const T2: u32 = 7; const T3: u32 = 28; const T4: u32 = 29; const T5: u32 = 30;
const T6: u32 = 31; const S0: u32 = 8; const S1: u32 = 9;
const HEAP: i32 = 0x1000; // data lives above the code

/// M4.1: guests built with the real `riscv32im-unknown-none-elf` toolchain (upstream's
/// `guest-sdk`/`guests-compiled/`, not vendored into this crate — see `deploy/sync-zkvm.sh`'s
/// header comment) and loaded as flat binaries (`isa::Program::from_flat_binary`), as opposed to
/// every other guest in this module, which is written directly against `asm.rs`'s mnemonic
/// helpers. Mirrors upstream `research/src/guests.rs`'s `compiled` module exactly, except the
/// `include_bytes!` path: `guests-compiled/` sits directly under this crate root
/// (`crates/shrugg-zkvm/guests-compiled/bin/fib.bin`, vendored by `deploy/sync-zkvm.sh`'s copy
/// step), one level shallower than upstream's `research/../guests-compiled/`.
pub mod compiled {
    use crate::isa::Program;

    /// `fib`, compiled for `riscv32im-unknown-none-elf` by upstream `guests-compiled/fib`'s
    /// Makefile and vendored as `guests-compiled/bin/fib.bin` — see that Makefile's header
    /// (in `circuits/guests-compiled/fib/`) for the exact `rustc +1.98.1` build it was produced
    /// with. Base `pc = 0x1000`, matching `guest-sdk/guest.ld`'s `ORIGIN`.
    pub fn fib() -> Program {
        const BIN: &[u8] = include_bytes!("../guests-compiled/bin/fib.bin");
        Program::from_flat_binary(0x1000, BIN).expect("fib.bin is a committed, known-good build")
    }
}

/// out0 = fib(n) mod 2^32, computed with a counted loop.
pub fn fib(n: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T0, 0));            // f0
    a.extend(li(T1, 1));            // f1
    a.extend(li(T2, n as i32));     // counter
    a.label("loop");
    a.branch(BranchCond::Eq, T2, 0, "done");
    a.push(add(T3, T0, T1));
    a.push(mv(T0, T1));
    a.push(mv(T1, T3));
    a.push(addi(T2, T2, -1));
    a.jal(0, "loop");
    a.label("done");
    a.extend(write_output(0, T0));
    a.extend(halt());
    a.assemble()
}

/// Writes 1..=n to HEAP, copies to HEAP+4n, outputs the sum of the copy.
pub fn memcpy(n: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T0, HEAP)); a.extend(li(T1, HEAP + 4 * n as i32)); a.extend(li(T2, n as i32)); a.extend(li(T3, 1));
    a.label("fill");
    a.branch(BranchCond::Eq, T2, 0, "copy_setup");
    a.push(sw(T0, T3, 0)); a.push(addi(T0, T0, 4)); a.push(addi(T3, T3, 1)); a.push(addi(T2, T2, -1));
    a.jal(0, "fill");
    a.label("copy_setup");
    a.extend(li(T0, HEAP)); a.extend(li(T2, n as i32)); a.extend(li(T5, 0));
    a.label("copy");
    a.branch(BranchCond::Eq, T2, 0, "done");
    a.push(lw(T4, T0, 0)); a.push(sw(T1, T4, 0)); a.push(lw(T4, T1, 0)); a.push(add(T5, T5, T4));
    a.push(addi(T0, T0, 4)); a.push(addi(T1, T1, 4)); a.push(addi(T2, T2, -1));
    a.jal(0, "copy");
    a.label("done");
    a.extend(write_output(0, T5));
    a.extend(halt());
    a.assemble()
}

/// Stores `values` at HEAP, bubble-sorts them in place (unsigned), outputs min and max.
pub fn bubble_sort(values: &[u32]) -> Program {
    assert!(!values.is_empty(), "bubble_sort guest needs at least one value");
    let n = values.len() as i32;
    let mut a = Assembler::new(0);
    for (i, v) in values.iter().enumerate() {
        a.extend(li(T0, *v as i32)); a.extend(li(T1, HEAP + 4 * i as i32)); a.push(sw(T1, T0, 0));
    }
    a.extend(li(T4, n - 1));                       // outer count
    a.label("outer");
    a.branch(BranchCond::Eq, T4, 0, "done");
    a.extend(li(T0, HEAP)); a.push(mv(T5, T4));    // inner count
    a.label("inner");
    a.branch(BranchCond::Eq, T5, 0, "outer_next");
    a.push(lw(T1, T0, 0)); a.push(lw(T2, T0, 4));
    a.push(sltu(T3, T2, T1));                      // T3 = a[i+1] < a[i]
    a.branch(BranchCond::Eq, T3, 0, "no_swap");
    a.push(sw(T0, T2, 0)); a.push(sw(T0, T1, 4));
    a.label("no_swap");
    a.push(addi(T0, T0, 4)); a.push(addi(T5, T5, -1));
    a.jal(0, "inner");
    a.label("outer_next");
    a.push(addi(T4, T4, -1));
    a.jal(0, "outer");
    a.label("done");
    a.extend(li(T0, HEAP)); a.push(lw(T1, T0, 0)); a.push(lw(T2, T0, 4 * (n - 1)));
    a.extend(write_output(0, T1)); a.extend(write_output(1, T2));
    a.extend(halt());
    a.assemble()
}

/// The confidential-computation demo: reads private inputs 0..3 (balances),
/// sums them, and outputs only whether the sum ≥ `threshold` (1) or not (0).
/// The sum is carry-aware: each addition records whether it wrapped, and a
/// wrap counts as over any 32-bit threshold — the proved relation matches the
/// stated semantics even when the true sum exceeds 2^32.
pub fn balance_check(threshold: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T5, 0));            // sum
    a.extend(li(T4, 0));            // wrapped-carry flag
    for idx in 0..4 {
        a.extend(read_input(idx));
        a.push(add(T5, T5, REG_A0));
        a.push(sltu(T2, T5, REG_A0));       // sum < addend ⟺ the add carried out
        a.push(or(T4, T4, T2));
    }
    a.extend(li(T0, threshold as i32));
    a.push(sltu(T1, T5, T0));       // T1 = sum < threshold
    a.push(xori(T1, T1, 1));        // T1 = sum >= threshold
    a.push(or(T1, T1, T4));         // ... or the true sum overflowed 32 bits
    a.extend(write_output(0, T1));
    a.extend(halt());
    a.assemble()
}

/// Private payment: reads four private balances; if their sum >= threshold, pays recipient 0
/// the surplus (sum - threshold); otherwise emits no effect. Only the effect words are public.
/// Unlike `balance_check` (whose doc comment explains its carry flag), the sum here wraps mod
/// 2^32 with no carry tracking — a wrapped total can only land *below* `threshold` and
/// under-emit, never over-pay (and the ledger independently bounds every effect by the
/// sender's real on-chain balance), so the wrap is safe to accept rather than track.
pub fn private_payment(threshold: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T5, 0));
    for idx in 0..4 {
        a.extend(read_input(idx));
        a.push(add(T5, T5, REG_A0));
    }
    a.extend(li(T0, threshold as i32));
    a.push(sltu(T1, T5, T0));                // T1 = sum < threshold
    a.branch(BranchCond::Ne, T1, 0, "done"); // below threshold: outputs stay 0 (kind none)
    a.push(sub(T2, T5, T0));                 // surplus
    a.extend(li(T3, 0));                     // amount hi
    a.extend(emit_transfer(0, T2, T3));
    a.label("done");
    a.extend(halt());
    a.assemble()
}

/// Exercises every `AluOp` variant and `JALR` through a register-computed target.
///
/// `out0` is an XOR checksum over the results of the bitwise, shift and arithmetic ops (plus
/// the `JALR` link register, which pins `rd = pc + 4`); `out1` is the sum of the six compare
/// results. Both operands have their high bits set and one of them is negative, so `sra`
/// sign-extends, `slt` and `sltu` disagree, and the `and`/`or`/`xor` limbs are non-trivial;
/// every shift amount is at least 8. `AluOp::Eq` has no encoding of its own, so it is
/// reached the only way it can be — through `BEQ`/`BNE`.
pub fn alu_mix() -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(S0, 0));                             // acc
    a.extend(li(S1, 0));                             // compare sum
    a.extend(li(T0, 0xdead_beefu32 as i32));         // negative, high bits set
    a.extend(li(T1, 0x0f0f_1234));                   // positive, high bits set
    let acc = |a: &mut Assembler| a.push(xor(S0, S0, T2));

    a.push(add(T2, T0, T1)); acc(&mut a);
    a.push(sub(T2, T0, T1)); acc(&mut a);
    a.push(and(T2, T0, T1)); acc(&mut a);
    a.push(or (T2, T0, T1)); acc(&mut a);
    a.push(xor(T2, T0, T1)); acc(&mut a);
    // shifts: register form by 12, immediate forms by 20, 24 and 31
    a.extend(li(T3, 12));
    a.push(sll(T2, T1, T3)); acc(&mut a);
    a.push(srl(T2, T0, T3)); acc(&mut a);
    a.push(sra(T2, T0, T3)); acc(&mut a);            // negative sra
    a.push(slli(T2, T1, 20)); acc(&mut a);
    a.push(srli(T2, T0, 24)); acc(&mut a);
    a.push(srai(T2, T0, 31)); acc(&mut a);           // negative sra → all ones
    a.push(andi(T2, T0, -256)); acc(&mut a);
    a.push(ori (T2, T0, 0x7ff)); acc(&mut a);
    a.push(xori(T2, T0, -1)); acc(&mut a);
    // compares with mixed signs: slt and sltu must disagree on (T0, T1)
    let cmp = |a: &mut Assembler, i: Instr| { a.push(i); a.push(add(S1, S1, T2)); };
    cmp(&mut a, slt (T2, T0, T1));                   // signed:   T0 < T1  → 1
    cmp(&mut a, slt (T2, T1, T0));                   //                    → 0
    cmp(&mut a, sltu(T2, T0, T1));                   // unsigned: T0 < T1  → 0
    cmp(&mut a, sltu(T2, T1, T0));                   //                    → 1
    cmp(&mut a, slti (T2, T0, -1));
    cmp(&mut a, sltiu(T2, T1, -1));
    // AluOp::Eq, the only way it is reachable
    a.branch(BranchCond::Eq, T0, T1, "bad");         // not taken
    a.branch(BranchCond::Ne, T0, T1, "call");        // taken
    a.label("bad");
    a.push(addi(S1, 0, 0x7ff));                      // would corrupt out1 if ever reached
    a.label("call");
    // JALR through a register: auipc + addi build the target, jalr links pc + 4 into T6.
    a.push(auipc(T4, 0));                            // T4 = pc of this instruction
    a.push(addi(T4, T4, 16));                        // T4 = address of "target"
    a.push(jalr(T6, T4, 0));
    a.push(addi(S1, 0, 0x7ff));                      // skipped by the jump
    a.label("target");
    a.push(xor(S0, S0, T6));                         // fold the link register into the checksum
    a.extend(write_output(0, S0));
    a.extend(write_output(1, S1));
    a.extend(halt());
    a.assemble()
}

/// M2.5: exercises every sub-word load/store mnemonic (`LB LH LBU LHU SB SH`) as a
/// read-modify-write over word-addressed memory. Packs four individually-stored bytes and
/// two stored halfwords into two words (each `SB`/`SH` must leave every other byte of its
/// word alone), then reads them back through every load width/signedness combination and
/// folds the results into an XOR checksum: a wrong sign-extension, a wrong merged byte, or
/// a misread half all change `out0`. `out1`/`out2` expose the two packed words directly, so
/// a wrong byte/half merge shows up even if the checksum happened to cancel out.
///
/// Ported from upstream `guests.rs`; not part of `all()` (this crate's own deployed guest
/// catalog stays as it was — see `deploy/sync-zkvm.sh`), but the vendored `tests/emulator.rs`,
/// `tests/cheating.rs` and `tests/tables.rs` call it by name directly.
pub fn sub_word_checksum() -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(S0, HEAP));
    // word 0 (offset 0): four individually-stored bytes, 0x81 02 ff 7f (one with the sign
    // bit set at offset 0, one clear at offset 3 — LB must treat them differently).
    for (off, byte) in [(0i32, 0x81u32), (1, 0x02), (2, 0xff), (3, 0x7f)] {
        a.extend(li(T1, byte as i32)); a.push(sb(S0, T1, off));
    }
    // word 1 (offset 4): two stored halfwords, 0x8001 (sign bit set) and 0x00ff (clear).
    a.extend(li(T1, 0x8001u32 as i32)); a.push(sh(S0, T1, 4));
    a.extend(li(T1, 0x00ff)); a.push(sh(S0, T1, 6));

    a.extend(li(T0, 0)); // checksum accumulator
    let fold = |a: &mut Assembler| a.push(xor(T0, T0, T2));

    a.push(lb(T2, S0, 0)); fold(&mut a);   // 0x81 signed   -> 0xffff_ff81
    a.push(lbu(T2, S0, 0)); fold(&mut a);  // 0x81 unsigned -> 0x0000_0081
    a.push(lb(T2, S0, 3)); fold(&mut a);   // 0x7f, sign bit clear either way
    a.push(lh(T2, S0, 4)); fold(&mut a);   // 0x8001 signed   -> 0xffff_8001
    a.push(lhu(T2, S0, 4)); fold(&mut a);  // 0x8001 unsigned -> 0x0000_8001
    a.push(lh(T2, S0, 6)); fold(&mut a);   // 0x00ff, sign bit clear
    a.push(lw(T2, S0, 0)); fold(&mut a);   // the packed word itself, straight LW
    a.push(lw(T2, S0, 4)); fold(&mut a);

    a.extend(write_output(0, T0));
    a.push(lw(T1, S0, 0)); a.extend(write_output(1, T1));
    a.push(lw(T1, S0, 4)); a.extend(write_output(2, T1));
    a.extend(halt());
    a.assemble()
}

/// M2.6: exercises every `AluOp` M-extension variant. `out0` is an XOR fold of every
/// result (mirrors `alu_mix`'s checksum style). Covers: an ordinary unsigned product
/// (`MUL`), all three high-word forms on `-1 * -1` and `-1 * 7` (`MULH MULHU MULHSU`),
/// ordinary unsigned division/remainder (`DIVU REMU`), a negative-dividend signed
/// division/remainder that truncates toward zero (`DIV REM`), division by zero for both
/// signed and unsigned forms, the `MIN / -1` signed overflow case, a negative dividend
/// that divides evenly (remainder exactly zero — the case the remainder sign fix-up's
/// zero-gate exists for), and a small negative dividend with a larger positive divisor
/// (quotient exactly zero with opposite signs — the case the quotient sign fix-up's
/// zero-gate exists for).
///
/// Ported from upstream `guests.rs` (see `sub_word_checksum`'s doc comment for why it isn't
/// in `all()`).
pub fn muldiv() -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(S0, 0)); // acc
    a.extend(li(T0, 6)); a.extend(li(T1, 7));
    let acc = |a: &mut Assembler| a.push(xor(S0, S0, T2));
    a.push(mul(T2, T0, T1)); acc(&mut a);                  // 6*7 = 42
    a.extend(li(T3, -1));                                  // 0xffff_ffff
    a.push(mulh(T2, T3, T3)); acc(&mut a);                 // (-1)*(-1) = 1, mulh = 0
    a.push(mulhu(T2, T3, T3)); acc(&mut a);                // 0xffffffff * 0xffffffff, high word nonzero
    a.push(mulhsu(T2, T3, T1)); acc(&mut a);                // (-1) *s 7 *u
    a.push(divu(T2, T0, T1)); acc(&mut a);                 // 6u/7u = 0
    a.push(remu(T2, T0, T1)); acc(&mut a);                 // 6u%7u = 6
    a.push(div(T2, T3, T1)); acc(&mut a);                  // -1/7 = 0 (truncates toward 0)
    a.push(rem(T2, T3, T1)); acc(&mut a);                  // -1%7 = -1
    a.push(divu(T2, T0, REG_ZERO)); acc(&mut a);           // 6u/0 = 0xffff_ffff
    a.push(remu(T2, T0, REG_ZERO)); acc(&mut a);           // 6u%0 = 6
    a.extend(li(T5, -2147483648i32));                      // 0x8000_0000 = i32::MIN
    a.push(div(T2, T5, T3)); acc(&mut a);                  // MIN / -1 = MIN (signed overflow)
    a.push(rem(T2, T5, T3)); acc(&mut a);                  // MIN % -1 = 0
    a.extend(li(T4, -4)); a.extend(li(T6, 2));
    a.push(div(T2, T4, T6)); acc(&mut a);                  // -4/2 = -2
    a.push(rem(T2, T4, T6)); acc(&mut a);                  // -4%2 = 0, dividend negative
    a.extend(li(T4, -3)); a.extend(li(T6, 10));
    a.push(div(T2, T4, T6)); acc(&mut a);                  // -3/10 = 0, opposite signs
    a.push(rem(T2, T4, T6)); acc(&mut a);                  // -3%10 = -3
    a.extend(write_output(0, S0));
    a.extend(halt());
    a.assemble()
}

/// M3.2: hashes `msg` with the `POSEIDON2` syscall (in place, at `HEAP`) and outputs the
/// 8-word digest — the guest-level correctness anchor for the syscall path, mirrored
/// host-side by `hash::sponge_hash`.
///
/// Ported from upstream `guests.rs` (see `sub_word_checksum`'s doc comment for why it isn't
/// in `all()`).
pub fn poseidon2_demo(msg: &[u32]) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(S0, HEAP));
    for (i, w) in msg.iter().enumerate() { a.extend(li(T0, *w as i32)); a.push(sw(S0, T0, 4 * i as i32)); }
    a.extend(call_poseidon2(HEAP / 4, msg.len()));
    for i in 0..8 { a.push(lw(T1, S0, 4 * i as i32)); a.extend(write_output(i as u32, T1)); }
    a.extend(halt());
    a.assemble()
}

/// (name, program, private inputs)
pub fn all() -> Vec<(&'static str, Program, Vec<u32>)> {
    vec![
        ("private_payment", private_payment(1000), vec![400, 250, 300, 75]),
        ("alu_mix", alu_mix(), vec![]),
        ("fib(20)", fib(20), vec![]),
        ("memcpy(8)", memcpy(8), vec![]),
        ("bubble_sort", bubble_sort(&[9, 3, 0xffff_fff0, 1, 7, 3]), vec![]),
        ("balance_check", balance_check(1000), vec![400, 250, 300, 75]),
    ]
}
