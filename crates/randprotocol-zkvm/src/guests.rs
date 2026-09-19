//! Guest programs shared by tests and the demo. Registers: t0..t6 = x5..x7,x28..x31; s0.. = x8..
use crate::asm::{ops::*, Assembler};
use crate::isa::*;

const T0: u32 = 5; const T1: u32 = 6; const T2: u32 = 7; const T3: u32 = 28; const T4: u32 = 29; const T5: u32 = 30;
const T6: u32 = 31; const S0: u32 = 8; const S1: u32 = 9;
const HEAP: i32 = 0x1000; // data lives above the code

/// M4.1/M4.2 (and, since the constraint-set-6 re-vendor, M4.3/M4.4): guests built with the
/// real `riscv32im-unknown-none-elf` toolchain (upstream's `guest-sdk`/`guests-compiled/`, not
/// vendored into this crate — see `deploy/sync-zkvm.sh`'s header comment) and loaded as flat
/// binaries or image containers (`isa::Program::from_flat_binary`/`from_flat_image`), as
/// opposed to every other guest in this module, which is written directly against `asm.rs`'s
/// mnemonic helpers. Mirrors upstream `research/src/guests.rs`'s `compiled` module exactly,
/// except the `include_bytes!` path: `guests-compiled/` sits directly under this crate root
/// (`crates/randprotocol-zkvm/guests-compiled/bin/{fib,keccak256,evm,sbpf}.bin`, vendored by
/// `deploy/sync-zkvm.sh`'s copy step), one level shallower than upstream's
/// `research/../guests-compiled/`.
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

    /// M4.2's exit guest: Keccak-256 over the `KECCAK` syscall, compiled from upstream
    /// `guests-compiled/keccak256` (see that Makefile's header, in `circuits/guests-compiled/
    /// keccak256/`, for the exact `rustc +1.98.1` build) and vendored as
    /// `guests-compiled/bin/keccak256.bin`. `input[0]` is the message's byte length, `input[1..]`
    /// the message four bytes per word little-endian; the 32-byte digest comes back in output
    /// slots 0..7 the same way. The sponge is `guest_sdk::keccak256` — ordinary compiled guest
    /// code — so the only thing the chip proves is the permutation itself, which is the whole
    /// point of the milestone.
    pub fn keccak256() -> Program {
        const BIN: &[u8] = include_bytes!("../guests-compiled/bin/keccak256.bin");
        Program::from_flat_binary(0x1000, BIN).expect("keccak256.bin is a committed, known-good build")
    }

    /// M4.3's exit guest: an EVM interpreter over the ERC-20 subset, compiled from upstream
    /// `guests-compiled/evm` (`evm-core` plus a 20-line `main`, see that Makefile's header, in
    /// `circuits/guests-compiled/evm/`, for the exact `rustc +1.98.1` build) and vendored as
    /// `guests-compiled/bin/evm.bin`.
    ///
    /// The private input is one call — bytecode, calldata, caller, the pre-state root and a Merkle
    /// witness per storage slot touched (`evm_core::abi`'s layout, built host-side by
    /// `evm::EvmCall::input_words`). The eight public outputs are the status word and the 224-bit
    /// `hash(EVM_OUT, [codehash ‖ pre_root ‖ post_root ‖ return_hash ‖ logs_hash])` that binds the
    /// contract and its state-root transition. Everything but the Keccak-f[1600] permutation and
    /// the Poseidon2 sponge is ordinary compiled guest code: no table, syscall or public value is
    /// new in M4.3.
    /// Unlike `fib` and `keccak256` this one is an **image container**, not a bare flat binary: the
    /// interpreter has a `.rodata` (panic locations, the constants LLVM materialised), and
    /// `Program::from_flat_image` writes it into RAM with a prologue it synthesises below the text —
    /// so the data is part of the program and `hc` binds it (upstream `docs/01-isa.md`).
    pub fn evm() -> Program {
        const BIN: &[u8] = include_bytes!("../guests-compiled/bin/evm.bin");
        Program::from_flat_image(BIN).expect("evm.bin is a committed, known-good build")
    }

    /// M4.4's exit guest: an **sBPF interpreter**, compiled from upstream `guests-compiled/sbpf`
    /// (see that Makefile's header, in `circuits/guests-compiled/sbpf/`, for the exact
    /// `rustc +1.98.1` build) and vendored as `guests-compiled/bin/sbpf.bin`. It reads **two**
    /// vectors: the public one is `[n_elf, elf bytes…]` (`sbpf::SbpfCall::public_words`, bound
    /// by `H_PUB`, which is what a chain checks against the ELF it published) and the private one
    /// is `[n_input, input bytes…]` (`SbpfCall::input_words`). The output is a status word plus a
    /// 224-bit digest over the instruction and the accounts' post-state — *not* the program,
    /// which the guest no longer hashes (`sbpf_core::abi`).
    ///
    /// This is an **image**, not a flat binary: a real compiler output has a `.rodata` (the
    /// interpreter's `Halt::Trap` literals, panic locations and the opcode dispatch's jump tables),
    /// which the flat loader cannot carry. `from_flat_image` synthesises the `li`/`sw` prologue that
    /// writes the data into RAM and reports it as part of the program, so `hc` binds the constants
    /// exactly as it binds the code (upstream `docs/01-isa.md`).
    pub fn sbpf() -> Program {
        const BIN: &[u8] = include_bytes!("../guests-compiled/bin/sbpf.bin");
        Program::from_flat_image(BIN).expect("sbpf.bin is a committed, known-good build")
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
///
/// Node-local (not upstream): the chain's own demo/test guest, deployed by `randprotocol-client` and
/// exercised by `tests/executor.rs` and the node's cluster tests. Kept across a
/// `deploy/sync-zkvm.sh` resync because `guests.rs` is excluded from the rsync.
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

/// Reads the four public words, sums them, and reads `public[1]` a second time — so one proof
/// exercises a multi-word digest region, a `MULT_READ` of 2, and the `PUBLIC_READ` bus.
///
/// Ported from upstream `guests.rs` (constraint set 6's `SYS_READ_PUBLIC` exerciser — see
/// `sub_word_checksum`'s doc comment for why it isn't in `all()`); the vendored
/// `tests/cheating.rs` and `tests/e2e.rs` call it by name.
pub fn public_echo() -> Program {
    let mut a = Assembler::new(0);
    a.extend(read_public(0));
    a.push(mv(T0, REG_A0));
    for i in [1u32, 2, 3] {
        a.extend(read_public(i));
        a.push(add(T0, T0, REG_A0));
    }
    a.extend(read_public(1));
    a.push(add(T0, T0, REG_A0));
    a.extend(write_output(0, T0));
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

/// M4.2 demo: `keccak256(msg)` for a message that fits one rate block (≤ 135 bytes, so a
/// single permutation), with the sponge itself in guest code — exactly what `guest-sdk`'s own
/// `keccak256` does, transcribed against `asm.rs`: XOR the padded 136-byte block into the first
/// 34 words of a 50-word state, call `KECCAK` once, and publish the first 8 words of the
/// permuted state as the 32-byte digest.
///
/// Words 34..49 of the state start at zero and are never written, so the emulator's
/// never-written-reads-zero rule supplies them (and the memory table's own "first touch of a
/// fresh address as a read returns zero" rule proves it).
///
/// The state's base address is held in a register (`S0`), not folded into each `sw`'s
/// immediate: `HEAP + 4·49` is far outside a 12-bit signed I-type field, and AGENTS.md
/// invariant 3 is exactly the silent wrap that would cause.
///
/// Ported from upstream `guests.rs` (see `sub_word_checksum`'s doc comment for why it isn't in
/// `all()`); the vendored `tests/cheating.rs` and `tests/e2e.rs` call it by name.
pub fn keccak_demo(msg: &[u8]) -> Program {
    assert!(msg.len() <= 135, "keccak_demo hashes one rate block");
    let mut block = [0u8; 136];
    block[..msg.len()].copy_from_slice(msg);
    block[msg.len()] ^= 0x01;
    block[135] ^= 0x80;
    let mut a = Assembler::new(0);
    a.extend(li(S0, HEAP));
    for i in 0..34 {
        let w = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
        a.extend(li(T0, w as i32));
        a.push(sw(S0, T0, 4 * i as i32));
    }
    a.extend(call_keccak(HEAP / 4));
    for k in 0..8 {
        a.push(lw(T0, S0, 4 * k as i32));
        a.extend(write_output(k as u32, T0));
    }
    a.extend(halt());
    a.assemble()
}

/// The message `sha256_demo` hashes: 55 bytes, the longest message whose
/// `0x80 ‖ zeros ‖ be64(bit length)` padding still fits a single 512-bit block, so the guest needs
/// exactly one `SHA256` call and no Merkle–Damgård loop at all. Exported so
/// `tests/e2e.rs` can check the published digest against `sha256::sha256` of the very same bytes
/// rather than a copy that could drift.
///
/// Ported from upstream `guests.rs` with the function below.
pub const SHA256_DEMO_MSG: &[u8; 55] = b"The quick brown fox jumps over the lazy dog............";

/// M4.4 demo: `sha256(SHA256_DEMO_MSG)` with the padding done at assembly time and the
/// compression done by the chip — one `SYS_SHA256` call, whose 8 output words are the digest.
///
/// The syscall's buffer is 24 words at `HEAP`: words `0..16` are the padded block as sixteen
/// **big-endian-valued** words (word `i` is `u32::from_be_bytes` of the block's bytes `4i..4i+4`,
/// `sha256::bytes_to_words`' layout), words `16..24` the chaining state, which starts at the FIPS
/// 180-4 `IV` and is overwritten in place with `IV + f(IV, block)` — the digest, big-endian per
/// word, published as `out0..7` in that order.
///
/// One block means the whole of SHA-256 is this one call: `guest_sdk::sha256` is where the general
/// Merkle–Damgård loop and the runtime padding live (`keccak256`'s sponge is the analogue), and a
/// compiled guest over that loop is M4.4's later business. This guest exists to anchor the
/// syscall path end to end at the smallest possible size.
///
/// The buffer's base address is held in a register (`S0`) rather than folded into each `sw`'s
/// immediate: `HEAP` itself is far outside a 12-bit signed I-type field, and AGENTS.md invariant 3
/// is exactly the silent wrap that would cause.
///
/// Ported from upstream `guests.rs` (see `sub_word_checksum`'s doc comment for why it isn't in
/// `all()`); the vendored `tests/{asm,cheating,e2e,emulator}.rs` call it by name.
pub fn sha256_demo() -> Program {
    use crate::sha256::{bytes_to_words, IV};
    let msg = SHA256_DEMO_MSG;
    // `msg ‖ 0x80 ‖ zeros ‖ be64(8·55)`, the one-block padding of `sha256::sha256`.
    let mut block = [0u8; 64];
    block[..msg.len()].copy_from_slice(msg);
    block[msg.len()] = 0x80;
    block[56..].copy_from_slice(&(8 * msg.len() as u64).to_be_bytes());
    let words = bytes_to_words(&block);
    let mut a = Assembler::new(0);
    a.extend(li(S0, HEAP));
    for (i, w) in words.iter().enumerate() {
        a.extend(li(T0, *w as i32));
        a.push(sw(S0, T0, 4 * i as i32));
    }
    for (i, h) in IV.iter().enumerate() {
        a.extend(li(T0, *h as i32));
        a.push(sw(S0, T0, 4 * (crate::sha256::BLOCK_WORDS + i) as i32));
    }
    a.extend(call_sha256(HEAP as u32 / 4));
    for k in 0..8 {
        a.push(lw(T0, S0, 4 * (crate::sha256::BLOCK_WORDS + k) as i32));
        a.extend(write_output(k as u32, T0));
    }
    a.extend(halt());
    a.assemble()
}

/// (name, program, private inputs) — this chain's deployed guest catalog, which the vendored
/// `tests/{asm,backend,e2e,isa,tables}.rs` sweep over. Deliberately NOT upstream's list: it
/// carries the node-local `private_payment` and leaves out the guests upstream added to
/// its own `all()` for coverage (`sub_word_checksum`, `muldiv`, `poseidon2_demo`,
/// `keccak_demo`, `sha256_demo` — all five
/// still exist above and the vendored tests that want them call them by name). Neither
/// `transfer()` nor `bundle()` belongs here either: upstream does not list them, and both prove
/// at tier 14, which would turn every sweeping test into a multi-minute run.
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

/// The shielded transfer: spends one note and creates one of the same amount and asset.
///
/// Private inputs (`notes::input`): the spend key, the spent note's fields, the created
/// note's owner/time/randomness, and the Merkle witness (path, index) for the spent note's
/// commitment. The guest derives `nk = H_NK(sk)` and `pk = H_PK(nk)` itself, so the spent
/// note's owner and the created note's `from` are the address of whoever holds `sk` — that is
/// what authenticates the sender. It recomputes `cm_in` (`NOTE_COMMIT`), proves `cm_in`'s
/// membership in the commitment tree via `MERKLE_VERIFY` (getting `anchor`, the tree root),
/// computes `nf` (`NULLIFY`, bound to `cm_in`, not a sender-chosen nonce) and `cm_out`
/// (`NOTE_COMMIT`), and publishes a single 8-word output-commitment digest,
/// `notes::output_digest(anchor, nf, cm_out, time_out)` (`notes::output::DIGEST`) — see
/// `docs/06-viewing-keys.md`'s "Public outputs" section for why `anchor`/`nf`/`cm_out`/`time`
/// are folded into one digest rather than published as four separate `Word8` outputs.
///
/// `cm_in` itself is never published (M3.3 moves it from a public output to the Merkle
/// witness): only `anchor` is, so the chain no longer shows which commitment a transfer
/// spent.
pub fn transfer() -> Program {
    use crate::asm::{copy_word8, emit_derive_keys, emit_merkle_verify, emit_note_commit, emit_nullify};
    use crate::notes::{domain, input, output, DEPTH};
    const BASE: u32 = 25; // s9: RAM base register, holds HEAP
    const BIT: u32 = 26;  // s10: MERKLE_VERIFY's branch scratch
    const PATH_PTR: u32 = 27;
    const INDEX_WORK: u32 = 24;
    const CTR: u32 = 23;
    const BUF: i32 = 0x000;   // hash scratch: up to 29 words (116 bytes)
    const INP: i32 = 0x100;   // the input::COUNT private inputs
    const NK: i32 = 0x600;
    const PK: i32 = 0x620;
    const CM_IN: i32 = 0x640;
    const NF: i32 = 0x660;
    const CM_OUT: i32 = 0x680;
    const ANCHOR: i32 = 0x6a0;
    let ptr_words = |buf: i32| (HEAP + buf) / 4;
    let inp = |i: usize| INP + 4 * i as i32;
    let mut a = Assembler::new(0);
    a.extend(li(BASE, HEAP));
    // Read every private input once and keep it in RAM.
    for i in 0..input::COUNT {
        a.extend(read_input(i as u32));
        a.push(sw(BASE, REG_A0, inp(i)));
    }
    // nk = H_NK(sk), pk = H_PK(nk) — `sk` is 8 words, so both are 9-word hashes, emitted
    // directly rather than through a note/nullifier-shaped wrapper (`asm::emit_derive_keys`,
    // shared with `bundle`).
    emit_derive_keys(&mut a, BASE, T0, inp(input::SK), BUF, ptr_words(BUF), NK, PK);
    // cm_in = NOTE_COMMIT(pk, in.from, in.amount_lo, in.amount_hi, in.asset, in.time, in.r) —
    // assembled into a Note::WORDS-word staging area at BUF + 0x80 (past the hash scratch
    // region).
    const NOTE_IN: i32 = 0x080;
    copy_word8(&mut a, BASE, T0, PK, NOTE_IN);
    copy_word8(&mut a, BASE, T0, inp(input::IN_FROM), NOTE_IN + 32);
    a.push(lw(T0, BASE, inp(input::IN_AMOUNT_LO))); a.push(sw(BASE, T0, NOTE_IN + 64));
    a.push(lw(T0, BASE, inp(input::IN_AMOUNT_HI))); a.push(sw(BASE, T0, NOTE_IN + 68));
    a.push(lw(T0, BASE, inp(input::IN_ASSET))); a.push(sw(BASE, T0, NOTE_IN + 72));
    a.push(lw(T0, BASE, inp(input::IN_TIME))); a.push(sw(BASE, T0, NOTE_IN + 76));
    copy_word8(&mut a, BASE, T0, inp(input::IN_R), NOTE_IN + 80);
    emit_note_commit(&mut a, BASE, T0, NOTE_IN, BUF, ptr_words(BUF), CM_IN);
    // anchor = MERKLE_VERIFY(cm_in, path, index) — proves cm_in is in the commitment tree.
    a.push(lw(T1, BASE, inp(input::INDEX)));
    emit_merkle_verify(&mut a, BASE, T0, BIT, INDEX_WORK, T1, PATH_PTR, CTR, CM_IN, inp(input::PATH), BUF, ptr_words(BUF), ANCHOR, DEPTH, "transfer_merkle");
    // nf = NULLIFY(nk, cm_in) — bound to the commitment, so two notes can never share one.
    emit_nullify(&mut a, BASE, T0, NK, CM_IN, BUF, ptr_words(BUF), NF);
    // cm_out = NOTE_COMMIT(out.pk, pk, in.amount_lo, in.amount_hi, in.asset, out.time, out.r)
    copy_word8(&mut a, BASE, T0, inp(input::OUT_PK), NOTE_IN);
    copy_word8(&mut a, BASE, T0, PK, NOTE_IN + 32);
    a.push(lw(T0, BASE, inp(input::IN_AMOUNT_LO))); a.push(sw(BASE, T0, NOTE_IN + 64));
    a.push(lw(T0, BASE, inp(input::IN_AMOUNT_HI))); a.push(sw(BASE, T0, NOTE_IN + 68));
    a.push(lw(T0, BASE, inp(input::IN_ASSET))); a.push(sw(BASE, T0, NOTE_IN + 72));
    a.push(lw(T0, BASE, inp(input::OUT_TIME))); a.push(sw(BASE, T0, NOTE_IN + 76));
    copy_word8(&mut a, BASE, T0, inp(input::OUT_R), NOTE_IN + 80);
    emit_note_commit(&mut a, BASE, T0, NOTE_IN, BUF, ptr_words(BUF), CM_OUT);
    // digest = H(OUT_DOMAIN, anchor, nf, cm_out, time_out) — the single published output.
    a.extend(li(T0, domain::OUT as i32));
    a.push(sw(BASE, T0, BUF));
    copy_word8(&mut a, BASE, T0, ANCHOR, BUF + 4);
    copy_word8(&mut a, BASE, T0, NF, BUF + 36);
    copy_word8(&mut a, BASE, T0, CM_OUT, BUF + 68);
    a.push(lw(T0, BASE, inp(input::OUT_TIME))); a.push(sw(BASE, T0, BUF + 100));
    a.extend(call_poseidon2(ptr_words(BUF), 26));
    // Publish.
    for i in 0..8 {
        a.push(lw(T1, BASE, BUF + 4 * i));
        a.extend(write_output((output::DIGEST + i as usize) as u32, T1));
    }
    a.extend(halt());
    a.assemble()
}

/// `NOTE_COMMIT`, standalone: hashes `msg` (`Note::WORDS` words, embedded at assembly time)
/// as `H(CM_DOMAIN, msg)` and outputs the 8-word digest — the fixture that pins the guest's
/// `NOTE_COMMIT` to `notes::hash(notes::domain::CM, ..)`.
pub fn note_commit_probe(msg: &[u32; crate::notes::Note::WORDS]) -> Program {
    use crate::asm::emit_note_commit;
    const BASE: u32 = 25;
    const NOTE_IN: i32 = 0x080;
    const BUF: i32 = 0x000;
    const CM: i32 = 0x100;
    let mut a = Assembler::new(0);
    a.extend(li(BASE, HEAP));
    for (i, w) in msg.iter().enumerate() { a.extend(li(T0, *w as i32)); a.push(sw(BASE, T0, NOTE_IN + 4 * i as i32)); }
    emit_note_commit(&mut a, BASE, T0, NOTE_IN, BUF, (HEAP + BUF) / 4, CM);
    for i in 0..8 { a.push(lw(T1, BASE, CM + 4 * i)); a.extend(write_output(i as u32, T1)); }
    a.extend(halt());
    a.assemble()
}

/// The shielded pool's 2-in-2-out transfer relation
/// (`docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §4). See
/// `docs/superpowers/plans/2026-09-11-shielded-pool-z.md` Task 3 for the full soundness
/// argument: structural ownership/asset/output-time binding (the guest always uses its own
/// derived `pk_self` and the bundle's own public `asset`/`time` fields, so a dishonest witness
/// produces a `cm`/`nf` that cannot match anything real), and the `bad`-flag taint-and-corrupt
/// mechanism for the genuinely arithmetic checks this ISA has no native assert for (both real
/// inputs' Merkle roots agreeing with one claimed `anchor`, every amount's `< 2^63` range
/// check, 64-bit balance conservation, per-input asset agreement with the bundle's public
/// asset, and — nothing else in the relation compares the two inputs/outputs against each
/// other — the same note never spent as both inputs (`nf1 == nf2`) nor the same note minted
/// as both outputs (`cm_out1 == cm_out2`); the ledger independently rejects either duplicate
/// again once applied, so this is defence in depth, not the only place it is caught). `bad`
/// is a monotone OR accumulator, folded as an explicit extra word into the
/// published digest's preimage (`notes::bundle_digest`) — never XORed into a plaintext field a
/// sender publishes, since that would let a cheat simply republish the corrupted plaintext and
/// have the ledger's independent recomputation agree.
///
/// A dummy input (`amount == 0`) skips its `MERKLE_VERIFY`/anchor/asset checks entirely; this
/// is *unconstructible* to abuse (not merely checked), because the skip branch's own condition
/// (`amount_lo | amount_hi == 0`) reads the exact same registers that feed the balance sum — a
/// nonzero amount cannot both contribute value and take the skip branch.
///
/// Publishes `notes::bundle_digest(..)` at `output::DIGEST` (0..8), the same slot `transfer`
/// uses (`transfer` and `bundle` are two different `hc`-pinned programs, never both live in one
/// ledger — S1 decides which).
pub fn bundle() -> Program {
    use crate::asm::{copy_word8, emit_add64_carry, emit_derive_keys, emit_eq8, emit_merkle_verify, emit_note_commit, emit_nullify, emit_or_into, emit_range_check_u63, emit_stage_note};
    use crate::notes::{bundle_input as bi, domain, output, DEPTH};
    const BASE: u32 = 25;   // RAM base (holds HEAP), same convention as transfer()
    const BIT: u32 = 26;    // MERKLE_VERIFY scratch
    const PATH_PTR: u32 = 27;
    const INDEX_WORK: u32 = 24;
    const CTR: u32 = 23;
    const BAD: u32 = 9;     // s1: the taint accumulator, 0 until proven otherwise, never cleared
    const EQFOLD: u32 = 22; // emit_eq8's fold scratch
    const T7: u32 = 21;     // extra general scratch (S0/S1/T0-T6/BASE/BIT/PATH_PTR/INDEX_WORK/CTR/EQFOLD all spoken for)

    // `lw`/`sw`/`addi` immediates are genuine 12-bit signed RISC-V I-type fields
    // (`Instr::encode`'s `i_type` masks to `imm & 0xfff`, decoded back via `sext(.., 12)`) —
    // any offset outside `[-2048, 2047]` silently wraps. `transfer()` never had to think about
    // this because its whole layout stays under `0x6a0` (1696); `bundle()`'s does not — the
    // 612-word `bi::COUNT` private-input array's own last word alone reaches byte offset
    // `4*611 = 2444` past `INP`, and the derived-value scratch (`NK`..`SUM_OUT_HI`) sits at
    // `0xb00..0xc50` (2816..3152), both past `0x7ff`. Fix: `BASE` is loaded with
    // `HEAP + PIVOT`, not `HEAP`, and every RAM constant below is defined already shifted by
    // `-PIVOT` (so e.g. `ANCHOR`'s nominal `0xc00` becomes `0xc00 - PIVOT`) — every constant
    // actually used as an `lw`/`sw`/`addi` immediate anywhere in this function then lands in
    // `[-1536, 1612]`, comfortably inside the 12-bit window. `ptr_words` computes a real
    // absolute word address for the `POSEIDON2` syscall's pointer argument (built via `li`,
    // which is not immediate-width limited — see `ops::li`), so it adds `PIVOT` back rather
    // than being shifted itself.
    //
    // Every region below is disjoint (checked by nominal byte range, before the `-PIVOT`
    // shift, which preserves relative order): `BUF` needs up to 48 words = 0xc0 bytes for the
    // final digest (`0x000..0x0c0`); `NOTE_STAGE` starts exactly where `BUF` ends (`0x0c0`,
    // not `0x080` — `0x080` would have overlapped `BUF`'s digest-time window by 16 words) and
    // needs `Note::WORDS` = 28 words = 0x70 bytes (`0x0c0..0x130`); `INP` starts at `0x140`
    // (comfortably past `0x130`, not `0x100`) and needs `bi::COUNT` = 612 words = 0x990 bytes
    // (`0x140..0xad0`), still clear of `NK` at `0x0b00`.
    const PIVOT: i32 = 0x600;
    const BUF: i32 = 0x000 - PIVOT;      // hash scratch: up to 48 words (192 bytes) for the final digest
    const NOTE_STAGE: i32 = 0x0c0 - PIVOT; // Note::WORDS = 28 word staging area, reused per note
    const INP: i32 = 0x140 - PIVOT;      // bundle_input::COUNT (612) private inputs
    const NK: i32 = 0xb00 - PIVOT;
    const PK: i32 = 0xb20 - PIVOT;
    const CM_IN1: i32 = 0xb40 - PIVOT;
    const NF1: i32 = 0xb60 - PIVOT;
    const CM_IN2: i32 = 0xb80 - PIVOT;
    const NF2: i32 = 0xba0 - PIVOT;
    const CM_OUT1: i32 = 0xbc0 - PIVOT;
    const CM_OUT2: i32 = 0xbe0 - PIVOT;
    const ANCHOR: i32 = 0xc00 - PIVOT;
    const ROOT_TMP: i32 = 0xc20 - PIVOT; // scratch root for whichever input's MERKLE_VERIFY runs
    const SUM_IN_LO: i32 = 0xc40 - PIVOT; const SUM_IN_HI: i32 = 0xc44 - PIVOT;   // staged in RAM so ALU regs stay free
    const SUM_OUT_LO: i32 = 0xc48 - PIVOT; const SUM_OUT_HI: i32 = 0xc4c - PIVOT;

    let ptr_words = |buf: i32| (HEAP + PIVOT + buf) / 4;
    let inp = |i: usize| INP + 4 * i as i32;
    let mut a = Assembler::new(0);
    a.extend(li(BASE, HEAP + PIVOT));
    a.extend(li(BAD, 0));

    // Read every private input once into RAM (same convention as transfer()).
    for i in 0..bi::COUNT {
        a.extend(read_input(i as u32));
        a.push(sw(BASE, REG_A0, inp(i)));
    }

    // nk = H_NK(sk); pk_self = H_PK(nk) — the same `asm::emit_derive_keys` sequence transfer()
    // opens with. `PK` is the owner slot of both inputs and the `from` of both outputs below,
    // so every note this relation touches is tied to the private spend key read at `bi::SK`.
    emit_derive_keys(&mut a, BASE, T0, inp(bi::SK), BUF, ptr_words(BUF), NK, PK);

    // anchor := the private ANCHOR field (the wallet's claimed current tree root); every real
    // input's MERKLE_VERIFY is checked against it via emit_eq8 + emit_or_into(BAD, ..), never
    // overwritten by a derived root (unlike transfer(), where there is only one input and the
    // derived root simply *is* the published anchor) — see Task 3's soundness note for why an
    // equality-then-taint gadget, not a direct overwrite, is required once there are two
    // independent membership checks that must agree with each other and with this value.
    copy_word8(&mut a, BASE, T0, inp(bi::ANCHOR), ANCHOR);

    // ---- input 1 ----
    // §4 item 1, structurally: the spent note's OWNER is `PK` (= pk_self, derived above from
    // the private spend key), never a witness word — a prover can only ever spend a note
    // committed to its own public key. Everything else about the note comes from the witness.
    emit_stage_note(&mut a, BASE, T0, NOTE_STAGE, PK, inp(bi::IN1_FROM), inp(bi::IN1_AMOUNT_LO), inp(bi::IN1_AMOUNT_HI), inp(bi::IN1_ASSET), inp(bi::IN1_TIME), inp(bi::IN1_R));
    emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), CM_IN1);
    // amount1 != 0? — the ONLY branch condition, shared with the balance sum's own addend.
    a.push(lw(T1, BASE, inp(bi::IN1_AMOUNT_LO)));
    a.push(lw(T2, BASE, inp(bi::IN1_AMOUNT_HI)));
    a.push(or(T1, T1, T2));
    a.branch(BranchCond::Eq, T1, REG_ZERO, "bundle_in1_skip");
    a.push(lw(T1, BASE, inp(bi::IN1_INDEX)));
    emit_merkle_verify(&mut a, BASE, T0, BIT, INDEX_WORK, T1, PATH_PTR, CTR, CM_IN1, inp(bi::IN1_PATH), BUF, ptr_words(BUF), ROOT_TMP, DEPTH, "bundle_merkle1");
    emit_eq8(&mut a, BASE, T0, EQFOLD, ANCHOR, ROOT_TMP, T7);
    a.push(xori(T7, T7, 1)); // T7 := 1 iff mismatch
    emit_or_into(&mut a, BAD, T7);
    // Per-input asset agreement with the bundle's public asset field (gated on amount != 0 —
    // a dummy's asset is meaningless): a real note's own historical asset free-rides into
    // cm_in/nf unchecked by anything else in this design, so this is the one place it is
    // checked against what the bundle claims.
    a.push(lw(T0, BASE, inp(bi::IN1_ASSET)));
    a.push(lw(T1, BASE, inp(bi::ASSET)));
    a.push(xor(T0, T0, T1));
    a.push(sltu(T0, REG_ZERO, T0)); // 1 iff they differed
    emit_or_into(&mut a, BAD, T0);
    a.label("bundle_in1_skip");
    emit_nullify(&mut a, BASE, T0, NK, CM_IN1, BUF, ptr_words(BUF), NF1);

    // ---- input 2 (identical shape, same `PK` owner slot) ----
    emit_stage_note(&mut a, BASE, T0, NOTE_STAGE, PK, inp(bi::IN2_FROM), inp(bi::IN2_AMOUNT_LO), inp(bi::IN2_AMOUNT_HI), inp(bi::IN2_ASSET), inp(bi::IN2_TIME), inp(bi::IN2_R));
    emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), CM_IN2);
    a.push(lw(T1, BASE, inp(bi::IN2_AMOUNT_LO)));
    a.push(lw(T2, BASE, inp(bi::IN2_AMOUNT_HI)));
    a.push(or(T1, T1, T2));
    a.branch(BranchCond::Eq, T1, REG_ZERO, "bundle_in2_skip");
    a.push(lw(T1, BASE, inp(bi::IN2_INDEX)));
    emit_merkle_verify(&mut a, BASE, T0, BIT, INDEX_WORK, T1, PATH_PTR, CTR, CM_IN2, inp(bi::IN2_PATH), BUF, ptr_words(BUF), ROOT_TMP, DEPTH, "bundle_merkle2");
    emit_eq8(&mut a, BASE, T0, EQFOLD, ANCHOR, ROOT_TMP, T7);
    a.push(xori(T7, T7, 1));
    emit_or_into(&mut a, BAD, T7);
    a.push(lw(T0, BASE, inp(bi::IN2_ASSET)));
    a.push(lw(T1, BASE, inp(bi::ASSET)));
    a.push(xor(T0, T0, T1));
    a.push(sltu(T0, REG_ZERO, T0));
    emit_or_into(&mut a, BAD, T0);
    a.label("bundle_in2_skip");
    emit_nullify(&mut a, BASE, T0, NK, CM_IN2, BUF, ptr_words(BUF), NF2);

    // ---- outputs: from = pk_self, asset/time = the bundle's own public fields (structural
    // enforcement of §4 items 4/6/7 — there is no other asset/time an output's commitment
    // could use) ----
    emit_stage_note(&mut a, BASE, T0, NOTE_STAGE, inp(bi::OUT1_PK), PK, inp(bi::OUT1_AMOUNT_LO), inp(bi::OUT1_AMOUNT_HI), inp(bi::ASSET), inp(bi::TIME), inp(bi::OUT1_R));
    emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), CM_OUT1);

    emit_stage_note(&mut a, BASE, T0, NOTE_STAGE, inp(bi::OUT2_PK), PK, inp(bi::OUT2_AMOUNT_LO), inp(bi::OUT2_AMOUNT_HI), inp(bi::ASSET), inp(bi::TIME), inp(bi::OUT2_R));
    emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), CM_OUT2);

    // ---- duplicate-input / duplicate-output detection ----
    // The same note spent as both inputs (nf1 == nf2, since a nullifier is a deterministic
    // function of cm_in) would otherwise pass every other check with bad == 0 and a
    // "balanced" 2x-amount output — nothing above compares the two inputs against each
    // other. Likewise two byte-for-byte identical output notes (cm_out1 == cm_out2) mint the
    // same commitment twice. `emit_eq8` returns 1 iff equal, so — unlike the anchor-agreement
    // check above, which wants bad on MISMATCH and so inverts it — this ORs the equality bit
    // straight into `bad`: bad on MATCH. The ledger (Task 4) independently rejects either
    // duplicate again once a bundle is applied (a repeated nullifier / a repeated commitment
    // both already fail there on their own) — this in-circuit check is defence in depth, not
    // the only place a within-bundle duplicate is caught.
    emit_eq8(&mut a, BASE, T0, EQFOLD, NF1, NF2, T7);
    emit_or_into(&mut a, BAD, T7); // T7 := 1 iff nf1 == nf2 (the same note spent twice)
    emit_eq8(&mut a, BASE, T0, EQFOLD, CM_OUT1, CM_OUT2, T7);
    emit_or_into(&mut a, BAD, T7); // T7 := 1 iff cm_out1 == cm_out2 (the same note minted twice)

    // ---- range checks: every amount (both inputs, both outputs, fee, burn) < 2^63 ----
    for hi_off in [
        bi::IN1_AMOUNT_HI, bi::IN2_AMOUNT_HI,
        bi::OUT1_AMOUNT_HI, bi::OUT2_AMOUNT_HI,
        bi::FEE_HI, bi::BURN_HI,
    ] {
        a.push(lw(T1, BASE, inp(hi_off)));
        emit_range_check_u63(&mut a, T1, T2);
        emit_or_into(&mut a, BAD, T2);
    }

    // ---- 64-bit conservation: in1 + in2 == out1 + out2 + fee + burn, no wrap ----
    a.push(lw(T0, BASE, inp(bi::IN1_AMOUNT_LO))); a.push(sw(BASE, T0, SUM_IN_LO));
    a.push(lw(T0, BASE, inp(bi::IN1_AMOUNT_HI))); a.push(sw(BASE, T0, SUM_IN_HI));
    a.push(lw(T3, BASE, SUM_IN_LO)); a.push(lw(T4, BASE, SUM_IN_HI));
    a.push(lw(T1, BASE, inp(bi::IN2_AMOUNT_LO))); a.push(lw(T2, BASE, inp(bi::IN2_AMOUNT_HI)));
    emit_add64_carry(&mut a, T3, T4, T1, T2, T0, T5);
    emit_or_into(&mut a, BAD, T5); // in1+in2 cannot overflow given both are <2^63, but check anyway
    a.push(sw(BASE, T3, SUM_IN_LO)); a.push(sw(BASE, T4, SUM_IN_HI));

    a.push(lw(T3, BASE, inp(bi::OUT1_AMOUNT_LO))); a.push(lw(T4, BASE, inp(bi::OUT1_AMOUNT_HI)));
    a.push(lw(T1, BASE, inp(bi::OUT2_AMOUNT_LO))); a.push(lw(T2, BASE, inp(bi::OUT2_AMOUNT_HI)));
    emit_add64_carry(&mut a, T3, T4, T1, T2, T0, T5);
    emit_or_into(&mut a, BAD, T5);
    a.push(lw(T1, BASE, inp(bi::FEE_LO))); a.push(lw(T2, BASE, inp(bi::FEE_HI)));
    emit_add64_carry(&mut a, T3, T4, T1, T2, T0, T5);
    emit_or_into(&mut a, BAD, T5);
    a.push(lw(T1, BASE, inp(bi::BURN_LO))); a.push(lw(T2, BASE, inp(bi::BURN_HI)));
    emit_add64_carry(&mut a, T3, T4, T1, T2, T0, T5);
    emit_or_into(&mut a, BAD, T5);
    a.push(sw(BASE, T3, SUM_OUT_LO)); a.push(sw(BASE, T4, SUM_OUT_HI));

    // sums must match exactly.
    a.push(lw(T0, BASE, SUM_IN_LO)); a.push(lw(T1, BASE, SUM_OUT_LO));
    a.push(sub(T2, T0, T1)); // 0 iff equal
    a.push(lw(T0, BASE, SUM_IN_HI)); a.push(lw(T1, BASE, SUM_OUT_HI));
    a.push(sub(T3, T0, T1));
    a.push(or(T2, T2, T3));
    a.push(sltu(T2, REG_ZERO, T2)); // T2 := 1 iff (T2 before) != 0, i.e. sums disagree
    emit_or_into(&mut a, BAD, T2);

    // ---- digest: H(BUNDLE, anchor, nf1, nf2, cm1, cm2, fee, burn, asset, time, bad) — `bad`
    // is an EXPLICIT extra word (notes::domain::BUNDLE), never XORed into `time` or any other
    // plaintext-published field: `time` is plaintext the sender publishes alongside the proof,
    // so folding `bad` into it would let a cheating sender simply publish the corrupted `time`
    // and have the ledger's independent recomputation agree. The host reference
    // (`notes::bundle_digest`) always hashes `bad = 0`; only a dishonest guest run ever writes
    // a nonzero `bad` word here, which is what makes its digest fail to match any plaintext.
    a.extend(li(T0, domain::BUNDLE as i32));
    a.push(sw(BASE, T0, BUF));
    copy_word8(&mut a, BASE, T0, ANCHOR, BUF + 4);
    copy_word8(&mut a, BASE, T0, NF1, BUF + 36);
    copy_word8(&mut a, BASE, T0, NF2, BUF + 68);
    copy_word8(&mut a, BASE, T0, CM_OUT1, BUF + 100);
    copy_word8(&mut a, BASE, T0, CM_OUT2, BUF + 132);
    a.push(lw(T0, BASE, inp(bi::FEE_LO))); a.push(sw(BASE, T0, BUF + 164));
    a.push(lw(T0, BASE, inp(bi::FEE_HI))); a.push(sw(BASE, T0, BUF + 168));
    a.push(lw(T0, BASE, inp(bi::BURN_LO))); a.push(sw(BASE, T0, BUF + 172));
    a.push(lw(T0, BASE, inp(bi::BURN_HI))); a.push(sw(BASE, T0, BUF + 176));
    a.push(lw(T0, BASE, inp(bi::ASSET))); a.push(sw(BASE, T0, BUF + 180));
    a.push(lw(T0, BASE, inp(bi::TIME))); a.push(sw(BASE, T0, BUF + 184));
    a.push(sw(BASE, BAD, BUF + 188));
    a.extend(call_poseidon2(ptr_words(BUF), 48)); // domain(1) + msg(47)
    for i in 0..8 {
        a.push(lw(T1, BASE, BUF + 4 * i));
        a.extend(write_output((output::DIGEST + i as usize) as u32, T1));
    }
    a.extend(halt());
    a.assemble()
}

/// Reads the `count` private-input words `start..start + count` into RAM at `base + dst ..`,
/// each word exactly once, through a counted loop four words to an iteration (`addi a0; ecall;
/// sw` per word) — the hidden bundle's input idiom, in place of `bundle()`'s one
/// `li a7; li a0; ecall; sw` sequence per word. The unrolled idiom costs ~4 program words per
/// input word, and since M3.4 every program word is a quarter of a digest permutation: for the
/// hidden bundle's 1 204 input words that alone pushes it past tier 14's permutation budget
/// (the measured spike, spec `2026-09-19-hidden-asset-bundle-design.md` §2). The loop's cost
/// is cycles, not program words.
///
/// Soundness is unchanged by the loop: `idx` starts at the constant `start` (`li`) and moves by
/// the constant stride 4, `ptr` likewise from `base + dst`, and `ctr` counts the constant
/// `count / 4` down — all fixed by the program, which `hc` pins, so a prover cannot make the
/// loop read any other index or write anywhere else. Clobbers `a0`, `a7`, `idx`, `ptr`, `ctr`.
#[allow(clippy::too_many_arguments)]
fn emit_read_inputs(a: &mut Assembler, label: &str, base: u32, idx: u32, ptr: u32, ctr: u32, start: usize, count: usize, dst: i32) {
    const U: usize = 4;
    a.extend(li(REG_A7, SYS_READ_INPUT as i32));
    a.extend(li(idx, start as i32));
    a.push(addi(ptr, base, dst));
    let read = |a: &mut Assembler, j: usize| {
        a.push(addi(REG_A0, idx, j as i32));
        a.push(ecall());
        a.push(sw(ptr, REG_A0, 4 * j as i32));
    };
    if count / U > 0 {
        let top = format!("{label}_top");
        a.extend(li(ctr, (count / U) as i32));
        a.label(&top);
        for j in 0..U {
            read(a, j);
        }
        a.push(addi(idx, idx, U as i32));
        a.push(addi(ptr, ptr, 4 * U as i32));
        a.push(addi(ctr, ctr, -1));
        a.branch(BranchCond::Ne, ctr, REG_ZERO, &top);
    }
    for j in 0..count % U {
        read(a, j);
    }
}

/// The hidden-asset bundle (`docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md`
/// §3): one proof moves any asset, and the asset is **private** — a token transfer publishes
/// exactly what a RAND payment does. Four input and four output slots; slots 0–1 carry the
/// private asset `A` (the witness word `hidden_input::ASSET_A`), slots 2–3 carry RAND (asset 0).
/// `A` may be 0, and then every slot is RAND.
///
/// Private inputs: `hidden::hidden_input` (1 204 words, built by `hidden::hidden_bundle_inputs`).
/// Publishes `hidden::hidden_bundle_digest(anchor, nf0..3, cm0..3, fee, burn_a, burn_r,
/// burn_asset, time)` at `notes::output::DIGEST` — 82 words under `HIDDEN_BUNDLE_DOMAIN` (16),
/// with `bad` as the last word. **`A` is not in it.** Lives beside `bundle()`; nothing on the
/// chain path proves or verifies it yet (spec §7: H3–H5).
///
/// It is `bundle()`'s relation generalised, built from the same `asm` routines and the same two
/// mechanisms (see `bundle()`'s doc comment for their full argument):
///
/// - **Structural binding**: what the guest itself supplies cannot be chosen by a prover. Every
///   input note is staged with owner `pk_self = H_PK(H_NK(sk))`, derived from the private spend
///   key — so a note is spendable only by its owner (anyone else's note stages to a commitment
///   that is not in the tree, and fails its Merkle check below). Every output is staged with
///   `from = pk_self`, `time` = the bundle's (published) time, and asset = its slot's: the
///   witness word `A` for slots 0–1 and a RAM word the guest zeroes itself for slots 2–3. An
///   output's asset, sender and time are not witness words at all (`hidden_input` has no field
///   for them), so a mislabelled output is a commitment the guest never produces.
/// - **The `bad` taint** for the arithmetic checks this ISA has no assert for: each computes a
///   0/1 failure bit and ORs it into the register `BAD` (x9), which nothing else writes and no
///   routine clears (`emit_or_into` is monotone). `BAD` is the last word of the published
///   digest's preimage; the ledger recomputes the digest from plaintext with `bad = 0`, so a
///   tainted run publishes a digest no plaintext reproduces. Never XORed into a published field:
///   a cheat would just publish the corrupted field.
///
/// The relation, check by check (spec §3.3):
///
/// 1. `nk = H_NK(sk)`, `pk_self = H_PK(nk)` (`emit_derive_keys`).
/// 2. For each input slot `k`, `cm_in_k = NOTE_COMMIT(pk_self, from, amount, asset, time, r)`.
///    Then, **only if `amount_lo | amount_hi != 0`** (a real input):
///    - `MERKLE_VERIFY(cm_in_k, path, index)`, fused (below), and its root `eq8`-compared with
///      the private `anchor` (published in the digest): taint on mismatch. With the Merkle check
///      this is membership in the tree at the root the ledger will check `anchor` against.
///    - the note's own `asset` compared with the slot's (`A` for 0–1, 0 for 2–3): taint on
///      mismatch. This is what stops a token note being spent as RAND (or the reverse), and two
///      A-slot notes of different assets: both would have to equal the one `A`.
///
///    The **dummy rule**: a dummy (`amount == 0`) skips those three checks — its path is never
///    read — and cannot carry value, by construction rather than by a check: the skip branch's
///    condition is the OR of the two amount words in the *same registers* (`T1`, `T2`) that are
///    stored as the addends the conservation sums read (`IN_AMT`). A nonzero amount in either
///    word cannot take the skip and contribute value at once.
///
///    `nf_k = H_NF(nk, cm_in_k)` for all four inputs, dummies included — every bundle publishes
///    four nullifiers, whatever its shape.
/// 3. Each output `k`: `cm_out_k = NOTE_COMMIT(pk, pk_self, amount, slot asset, time, r)`.
/// 4. All 6 nullifier pairs and all 6 output-commitment pairs differ (`eq8`, taint on
///    equality): the same note spent twice, or minted twice, in one bundle. Identical dummies
///    collide here too, which is why a wallet draws a fresh `r` for each. (The ledger rejects a
///    repeated nullifier or commitment again on its own; this is defence in depth.)
/// 5. `< 2^63` on all 8 amounts, `fee`, `burn_a`, `burn_r` — 11 range checks (a high word with
///    its top bit set taints). With every term below 2^63 a two-term sum cannot wrap, and the
///    carry checks below catch the longer ones.
/// 6. Two conservation sums, each addition carry-checked (`emit_add64_carry`, taint on any
///    carry), each comparison exact (taint if the 64-bit totals differ):
///    `in0 + in1 == out0 + out1 + burn_a` (asset `A`) and
///    `in2 + in3 == out2 + out3 + fee + burn_r` (RAND — the fee is always RAND). Two groups,
///    two sums: value cannot move between `A` and RAND.
/// 7. `burn_asset = A & -(burn_a != 0)` — branch-free, never a witness word: a burn names `A`,
///    and a bundle that burns nothing from slots 0–1 names asset 0.
/// 8. The digest, `bad` last, is written to `output::DIGEST`.
///
/// **The fused Merkle loop.** Rather than reading a slot's 256-word path into RAM and copying
/// each sibling into the hash buffer per level (`emit_merkle_verify`), each level reads its 8
/// sibling words straight from the private input into the hash buffer with `READ_INPUT`. The
/// input index it reads is `PATH_PTR + j`, where `PATH_PTR` is loaded with the program constant
/// `in_slot(k) + S_PATH` (`li`) and advanced by the constant 8 per level, and the loop runs a
/// constant `DEPTH` levels (`CTR`). Registers are constrained by the cpu AIR and the program is
/// pinned by `hc`, so the sequence of indices the loop reads is fixed —
/// `in_slot(k) + S_PATH + 8·level + j` — and a prover cannot redirect it to other input words
/// (say, another slot's path or a note word). What a prover *does* choose is the witness words
/// at those indices, which is the path, and the root that path produces is exactly what step 2
/// compares with `anchor`. The `READ_INPUT` bus (`tables::input`) returns one word per index,
/// committed in `H_IN`. The leaf index is a 32-bit witness word consumed one bit per level over
/// all `DEPTH = 32` levels. Unread input words (a dummy's path) are legal: the input table's
/// `MULT_READ` may be 0 for any committed word.
///
/// **Cost** (measured by `tests/hidden_bundle.rs`): tier 14, the tier of today's `bundle()`.
/// Written in `bundle()`'s unrolled style it lands at tier 16 (4× time and memory); the looped
/// reads (`emit_read_inputs`) and the fused Merkle loop are what keep it at 14 — do not unroll.
pub fn bundle_hidden() -> Program {
    use crate::asm::{copy_word8, emit_add64_carry, emit_derive_keys, emit_eq8, emit_note_commit, emit_nullify, emit_or_into, emit_range_check_u63, emit_stage_note};
    use crate::hidden::{hidden_input as hi, A_SLOTS, HIDDEN_BUNDLE_DOMAIN, SLOTS};
    use crate::notes::{domain, output, DEPTH};
    const BASE: u32 = 25;       // RAM base (holds HEAP)
    const BIT: u32 = 26;        // Merkle: the current index bit
    const PTR: u32 = 27;        // reads: the RAM destination; Merkle: the sibling's INPUT index
    const IDX: u32 = 24;        // reads: the input index; Merkle: the leaf index, shifted per level
    const CTR: u32 = 23;        // loop counter
    const BAD: u32 = 9;         // s1: the taint accumulator, 0 until proven otherwise, never cleared
    const EQFOLD: u32 = 22;     // emit_eq8's fold scratch
    const T7: u32 = 21;         // emit_eq8's result

    // RAM, byte offsets from `BASE = HEAP`. The whole layout sits below 0x5c0, so every offset
    // is a valid 12-bit `lw`/`sw`/`addi` immediate without `bundle()`'s pivot (the private
    // inputs are read one slot at a time into a 21-word window rather than kept in RAM whole;
    // `Instr::encode` asserts the range, so a layout change that broke it would panic at
    // assembly). Regions are disjoint:
    const BUF: i32 = 0x000;        // hash scratch: 82 words for the digest (..0x148)
    const NOTE_STAGE: i32 = 0x150; // Note::WORDS = 28 (..0x1c0)
    const SLOT: i32 = 0x1c0;       // one input slot's 20 note words, then its index (..0x214)
    const HDR: i32 = 0x220;        // hidden_input ANCHOR..COUNT, 88 words (..0x380)
    const SKR: i32 = 0x380;        // sk (..0x3a0)
    const NK: i32 = 0x3a0;
    const PK: i32 = 0x3c0;
    const CM_IN: i32 = 0x3e0;      // 4 × Word8 (..0x460)
    const NF: i32 = 0x460;         // 4 × Word8 (..0x4e0)
    const CM_OUT: i32 = 0x4e0;     // 4 × Word8 (..0x560)
    const ROOT_TMP: i32 = 0x560;   // the running Merkle node (..0x580)
    const ZERO: i32 = 0x580;       // asset 0 (RAND), written by the guest
    const BURN_ASSET: i32 = 0x584;
    const IN_AMT: i32 = 0x588;     // 4 × (lo, hi): the sums' input addends (..0x5a8)
    const SUM_IN: i32 = 0x5a8;     // (lo, hi)
    const SUM_OUT: i32 = 0x5b0;    // (lo, hi) (..0x5b8)
    const _: () = assert!(BUF + 4 * 82 <= NOTE_STAGE && NOTE_STAGE + 4 * 28 <= SLOT);
    const _: () = assert!(SLOT + 4 * (hi::S_NOTE_WORDS as i32 + 1) <= HDR);
    const _: () = assert!(HDR + 4 * (hi::COUNT - hi::ANCHOR) as i32 <= SKR && SUM_OUT + 8 <= 0x800);

    let ptr_words = |buf: i32| (HEAP + buf) / 4;
    let hdr = |i: usize| HDR + 4 * (i - hi::ANCHOR) as i32;
    let slot = |off: usize| SLOT + 4 * off as i32;
    let slot_index = SLOT + 4 * hi::S_NOTE_WORDS as i32;
    let w8 = |region: i32, k: usize| region + 32 * k as i32;
    let slot_asset = |k: usize| if k < A_SLOTS { hdr(hi::ASSET_A) } else { ZERO };
    let in_amt = |k: usize| (IN_AMT + 8 * k as i32, IN_AMT + 8 * k as i32 + 4);
    let out_amt = |k: usize| (hdr(hi::out(k) + hi::O_AMOUNT_LO), hdr(hi::out(k) + hi::O_AMOUNT_HI));

    let mut a = Assembler::new(0);
    a.extend(li(BASE, HEAP));
    a.extend(li(BAD, 0));
    a.push(sw(BASE, REG_ZERO, ZERO));

    // sk and the header (anchor, outputs, fee, burns, A, time), each word read once.
    emit_read_inputs(&mut a, "hid_sk", BASE, IDX, PTR, CTR, hi::SK, 8, SKR);
    emit_read_inputs(&mut a, "hid_hdr", BASE, IDX, PTR, CTR, hi::ANCHOR, hi::COUNT - hi::ANCHOR, HDR);

    // 1. nk, pk_self.
    emit_derive_keys(&mut a, BASE, T0, SKR, BUF, ptr_words(BUF), NK, PK);

    // 2. inputs.
    for k in 0..SLOTS {
        // The slot's note words and its leaf index; the path is read by the Merkle loop, and
        // only for a real input.
        emit_read_inputs(&mut a, &format!("hid_in{k}"), BASE, IDX, PTR, CTR, hi::in_slot(k), hi::S_NOTE_WORDS, SLOT);
        emit_read_inputs(&mut a, &format!("hid_ix{k}"), BASE, IDX, PTR, CTR, hi::in_slot(k) + hi::S_INDEX, 1, slot_index);
        // Owner = pk_self, structurally.
        emit_stage_note(&mut a, BASE, T0, NOTE_STAGE, PK, slot(hi::S_FROM), slot(hi::S_AMOUNT_LO), slot(hi::S_AMOUNT_HI), slot(hi::S_ASSET), slot(hi::S_TIME), slot(hi::S_R));
        emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), w8(CM_IN, k));
        // The dummy rule: T1/T2 are both the sum's addend (stored to IN_AMT) and the skip
        // condition — nothing reloads the amount in between.
        a.push(lw(T1, BASE, slot(hi::S_AMOUNT_LO)));
        a.push(lw(T2, BASE, slot(hi::S_AMOUNT_HI)));
        a.push(sw(BASE, T1, in_amt(k).0));
        a.push(sw(BASE, T2, in_amt(k).1));
        a.push(or(T1, T1, T2));
        let skip = format!("hid_in{k}_skip");
        a.branch(BranchCond::Eq, T1, REG_ZERO, &skip);

        // The fused MERKLE_VERIFY: the running node in ROOT_TMP, each level's sibling read from
        // input indices PTR + 0..8 (PTR = the slot's path base, a program constant, + 8·level).
        copy_word8(&mut a, BASE, T0, w8(CM_IN, k), ROOT_TMP);
        a.push(lw(IDX, BASE, slot_index));
        a.extend(li(PTR, (hi::in_slot(k) + hi::S_PATH) as i32));
        a.extend(li(CTR, DEPTH as i32));
        let (lp, bit0, done) = (format!("hid_m{k}_loop"), format!("hid_m{k}_bit0"), format!("hid_m{k}_done"));
        let read_sibling = |a: &mut Assembler, dst: i32| {
            for j in 0..8 {
                a.push(addi(REG_A0, PTR, j));
                a.push(ecall());
                a.push(sw(BASE, REG_A0, dst + 4 * j));
            }
        };
        a.label(&lp);
        a.push(andi(BIT, IDX, 1));
        a.extend(li(REG_A7, SYS_READ_INPUT as i32)); // POSEIDON2 below clobbers a7
        a.branch(BranchCond::Eq, BIT, REG_ZERO, &bit0);
        // bit 1: the running node is the right child — [sibling, running].
        read_sibling(&mut a, BUF + 4);
        copy_word8(&mut a, BASE, T0, ROOT_TMP, BUF + 36);
        a.jal(REG_ZERO, &done);
        a.label(&bit0);
        // bit 0: [running, sibling].
        copy_word8(&mut a, BASE, T0, ROOT_TMP, BUF + 4);
        read_sibling(&mut a, BUF + 36);
        a.label(&done);
        a.extend(li(T0, domain::NODE as i32));
        a.push(sw(BASE, T0, BUF));
        a.extend(call_poseidon2(ptr_words(BUF), 17));
        copy_word8(&mut a, BASE, T0, BUF, ROOT_TMP);
        a.push(srli(IDX, IDX, 1));
        a.push(addi(PTR, PTR, 8));
        a.push(addi(CTR, CTR, -1));
        a.branch(BranchCond::Ne, CTR, REG_ZERO, &lp);

        // root == anchor, else taint.
        emit_eq8(&mut a, BASE, T0, EQFOLD, hdr(hi::ANCHOR), ROOT_TMP, T7);
        a.push(xori(T7, T7, 1));
        emit_or_into(&mut a, BAD, T7);
        // the note's asset == the slot's asset, else taint.
        a.push(lw(T0, BASE, slot(hi::S_ASSET)));
        a.push(lw(T1, BASE, slot_asset(k)));
        a.push(xor(T0, T0, T1));
        a.push(sltu(T0, REG_ZERO, T0));
        emit_or_into(&mut a, BAD, T0);
        a.label(&skip);
        emit_nullify(&mut a, BASE, T0, NK, w8(CM_IN, k), BUF, ptr_words(BUF), w8(NF, k));
    }

    // 3. outputs: from = pk_self, asset = the slot's, time = the bundle's.
    for k in 0..SLOTS {
        let o = hi::out(k);
        emit_stage_note(&mut a, BASE, T0, NOTE_STAGE, hdr(o + hi::O_PK), PK, hdr(o + hi::O_AMOUNT_LO), hdr(o + hi::O_AMOUNT_HI), slot_asset(k), hdr(hi::TIME), hdr(o + hi::O_R));
        emit_note_commit(&mut a, BASE, T0, NOTE_STAGE, BUF, ptr_words(BUF), w8(CM_OUT, k));
    }

    // 4. every pair of nullifiers and every pair of output commitments differs.
    for region in [NF, CM_OUT] {
        for i in 0..SLOTS {
            for j in (i + 1)..SLOTS {
                emit_eq8(&mut a, BASE, T0, EQFOLD, w8(region, i), w8(region, j), T7);
                emit_or_into(&mut a, BAD, T7); // taint on equality
            }
        }
    }

    // 5. the 11 range checks.
    let highs = (0..SLOTS).map(|k| in_amt(k).1)
        .chain((0..SLOTS).map(|k| out_amt(k).1))
        .chain([hdr(hi::FEE_HI), hdr(hi::BURN_A_HI), hdr(hi::BURN_R_HI)]);
    for h in highs {
        a.push(lw(T1, BASE, h));
        emit_range_check_u63(&mut a, T1, T2);
        emit_or_into(&mut a, BAD, T2);
    }

    // 6. the two conservation sums, carry-checked, compared exactly.
    let sum = |a: &mut Assembler, terms: &[(i32, i32)], dst: i32| {
        a.push(lw(T3, BASE, terms[0].0));
        a.push(lw(T4, BASE, terms[0].1));
        for &(lo, hi_at) in &terms[1..] {
            a.push(lw(T1, BASE, lo));
            a.push(lw(T2, BASE, hi_at));
            emit_add64_carry(a, T3, T4, T1, T2, T0, T5);
            emit_or_into(a, BAD, T5);
        }
        a.push(sw(BASE, T3, dst));
        a.push(sw(BASE, T4, dst + 4));
    };
    let compare = |a: &mut Assembler| {
        a.push(lw(T0, BASE, SUM_IN));
        a.push(lw(T1, BASE, SUM_OUT));
        a.push(sub(T2, T0, T1));
        a.push(lw(T0, BASE, SUM_IN + 4));
        a.push(lw(T1, BASE, SUM_OUT + 4));
        a.push(sub(T3, T0, T1));
        a.push(or(T2, T2, T3));
        a.push(sltu(T2, REG_ZERO, T2)); // 1 iff the totals differ
        emit_or_into(a, BAD, T2);
    };
    // Asset A: in0 + in1 == out0 + out1 + burn_a.
    sum(&mut a, &[in_amt(0), in_amt(1)], SUM_IN);
    sum(&mut a, &[out_amt(0), out_amt(1), (hdr(hi::BURN_A_LO), hdr(hi::BURN_A_HI))], SUM_OUT);
    compare(&mut a);
    // RAND: in2 + in3 == out2 + out3 + fee + burn_r.
    sum(&mut a, &[in_amt(2), in_amt(3)], SUM_IN);
    sum(&mut a, &[out_amt(2), out_amt(3), (hdr(hi::FEE_LO), hdr(hi::FEE_HI)), (hdr(hi::BURN_R_LO), hdr(hi::BURN_R_HI))], SUM_OUT);
    compare(&mut a);

    // 7. burn_asset = A & -(burn_a != 0).
    a.push(lw(T0, BASE, hdr(hi::BURN_A_LO)));
    a.push(lw(T1, BASE, hdr(hi::BURN_A_HI)));
    a.push(or(T0, T0, T1));
    a.push(sltu(T0, REG_ZERO, T0)); // 1 iff burn_a != 0
    a.push(sub(T0, REG_ZERO, T0));  // all ones iff burn_a != 0
    a.push(lw(T1, BASE, hdr(hi::ASSET_A)));
    a.push(and(T1, T1, T0));
    a.push(sw(BASE, T1, BURN_ASSET));

    // 8. digest = H(HIDDEN_BUNDLE_DOMAIN, anchor, nf0..3, cm0..3, fee, burn_a, burn_r,
    // burn_asset, time, bad) — `hidden::hidden_bundle_preimage`'s order, bad last.
    a.extend(li(T0, HIDDEN_BUNDLE_DOMAIN as i32));
    a.push(sw(BASE, T0, BUF));
    copy_word8(&mut a, BASE, T0, hdr(hi::ANCHOR), BUF + 4);
    let mut off = BUF + 36;
    for region in [NF, CM_OUT] {
        for k in 0..SLOTS {
            copy_word8(&mut a, BASE, T0, w8(region, k), off);
            off += 32;
        }
    }
    let tail = [hdr(hi::FEE_LO), hdr(hi::FEE_HI), hdr(hi::BURN_A_LO), hdr(hi::BURN_A_HI), hdr(hi::BURN_R_LO), hdr(hi::BURN_R_HI), BURN_ASSET, hdr(hi::TIME)];
    for src in tail {
        a.push(lw(T0, BASE, src));
        a.push(sw(BASE, T0, off));
        off += 4;
    }
    a.push(sw(BASE, BAD, off));
    off += 4;
    debug_assert_eq!((off - BUF) / 4, 1 + crate::hidden::PREIMAGE_WORDS as i32);
    a.extend(call_poseidon2(ptr_words(BUF), 1 + crate::hidden::PREIMAGE_WORDS));
    for i in 0..8 {
        a.push(lw(T1, BASE, BUF + 4 * i));
        a.extend(write_output((output::DIGEST + i as usize) as u32, T1));
    }
    a.extend(halt());
    a.assemble()
}

/// `MERKLE_VERIFY`, standalone: `leaf`, `path` (`DEPTH` siblings, leaf to root) and `index`
/// are embedded at assembly time; outputs the computed root — the fixture that pins the
/// guest's `MERKLE_VERIFY` to a host-side `ledger::CommitmentTree`.
pub fn merkle_probe(leaf: crate::notes::Word8, path: &[crate::notes::Word8; crate::notes::DEPTH], index: u32) -> Program {
    use crate::asm::emit_merkle_verify;
    use crate::notes::DEPTH;
    const BASE: u32 = 25;
    const BIT: u32 = 26;
    const PATH_PTR: u32 = 27;
    const INDEX_WORK: u32 = 24;
    const CTR: u32 = 23;
    const LEAF: i32 = 0x080;
    const PATH: i32 = 0x0a0; // DEPTH * 8 words = 1024 bytes -> 0x0a0..0x4a0
    const BUF: i32 = 0x000;
    const ROOT: i32 = 0x4a0;
    let mut a = Assembler::new(0);
    a.extend(li(BASE, HEAP));
    for (i, w) in leaf.iter().enumerate() { a.extend(li(T0, *w as i32)); a.push(sw(BASE, T0, LEAF + 4 * i as i32)); }
    for (level, sib) in path.iter().enumerate() {
        for (i, w) in sib.iter().enumerate() { a.extend(li(T0, *w as i32)); a.push(sw(BASE, T0, PATH + 32 * level as i32 + 4 * i as i32)); }
    }
    a.extend(li(T1, index as i32));
    emit_merkle_verify(&mut a, BASE, T0, BIT, INDEX_WORK, T1, PATH_PTR, CTR, LEAF, PATH, BUF, (HEAP + BUF) / 4, ROOT, DEPTH, "merkle_probe");
    for i in 0..8 { a.push(lw(T2, BASE, ROOT + 4 * i)); a.extend(write_output(i as u32, T2)); }
    a.extend(halt());
    a.assemble()
}
