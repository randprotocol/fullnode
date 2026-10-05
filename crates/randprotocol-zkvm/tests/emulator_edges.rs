//! `emulator.rs` at its corners — the reference semantics the AIR is held to. Every test here
//! runs a hand-assembled program of a few instructions and pins the exact register, memory,
//! event or error it must produce: x0, the compare/shift/wrap rules RISC-V fixes, sub-word
//! access at every offset, the syscall error set, the row (not instruction) cycle budget, and
//! the trace invariants the cpu table relies on.
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::emulator::*;
use randprotocol_zkvm::isa::*;

const T0: u32 = 5;
const T1: u32 = 6;
const T2: u32 = 7;
const S0: u32 = 8;
const S1: u32 = 9;

fn program(f: impl FnOnce(&mut Assembler)) -> Program {
    let mut a = Assembler::new(0);
    f(&mut a);
    a.assemble()
}

fn run(p: &Program, inputs: &[u32]) -> Execution {
    execute(p, inputs, &[], 1 << 16).unwrap()
}

/// The outputs of a program that stages its results in `regs` and halts.
fn outputs(f: impl FnOnce(&mut Assembler), regs: &[u32]) -> [u32; 8] {
    let p = program(|a| {
        f(a);
        for (slot, r) in regs.iter().enumerate() { a.extend(write_output(slot as u32, *r)); }
        a.extend(halt());
    });
    run(&p, &[]).outputs
}

// ─────────────────────────── x0 and the register file ───────────────────────────

#[test]
fn x0_is_hardwired_to_zero_and_never_written() {
    let p = program(|a| {
        a.push(addi(0, 0, 5));
        a.push(lui(0, 0x1000));
        a.push(auipc(0, 0x1000));
        a.extend(li(T0, 77));
        a.push(add(0, T0, T0));
        a.push(mv(T1, 0));
        a.extend(write_output(0, T1));
        a.extend(halt());
    });
    let e = run(&p, &[]);
    assert_eq!(e.outputs[0], 0);
    for ev in &e.events {
        for acc in &ev.accesses {
            assert!(!(acc.space == SPACE_REG && acc.addr == 0 && acc.is_write), "a write to x0 at clk {}", ev.clk);
        }
    }
    // And the five writing instructions carry `writes_rd = 0`, so no write access at all.
    assert!(e.events[..3].iter().all(|ev| ev.dec.writes_rd == 0));
}

#[test]
fn a_register_can_be_both_sources_and_the_destination() {
    let out = outputs(|a| {
        a.extend(li(T0, 3));
        for _ in 0..5 { a.push(add(T0, T0, T0)); }
        a.extend(li(T1, 6));
        a.push(mul(T1, T1, T1));
        a.push(sub(T1, T1, T1));
    }, &[T0, T1]);
    assert_eq!(out[0], 3 << 5);
    assert_eq!(out[1], 0);
}

// ─────────────────────────── compares, shifts, wraps ───────────────────────────

#[test]
fn sltiu_against_minus_one_is_set_for_everything_but_all_ones() {
    let out = outputs(|a| {
        for (i, v) in [0i32, 1, -2, -1].iter().enumerate() {
            a.extend(li(T0, *v));
            a.push(sltiu(T1 + i as u32, T0, -1));
        }
    }, &[T1, T1 + 1, T1 + 2, T1 + 3]);
    assert_eq!(out[..4], [1, 1, 1, 0], "sltiu rd, rs, -1 is `seqz`'s dual: rs != 0xffff_ffff");
}

#[test]
fn slti_against_minus_one_is_the_signed_compare() {
    let out = outputs(|a| {
        for (i, v) in [i32::MIN, -2, -1, 0, i32::MAX].iter().enumerate() {
            a.extend(li(T0, *v));
            a.push(slti(20 + i as u32, T0, -1));   // s4..s8, clear of the syscall registers
        }
    }, &[20, 21, 22, 23, 24]);
    assert_eq!(out[..5], [1, 1, 0, 0, 0]);
}

#[test]
fn register_shift_amounts_use_only_the_low_five_bits() {
    let out = outputs(|a| {
        a.extend(li(T0, 1));
        a.extend(li(T1, 33));
        a.push(sll(S0, T0, T1));               // 1 << (33 & 31) = 2
        a.extend(li(T0, i32::MIN));
        a.extend(li(T1, -1));
        a.push(srl(S1, T0, T1));               // 0x8000_0000 >> 31 = 1
        a.push(sra(T2, T0, T1));               // sign-filled: 0xffff_ffff
        a.extend(li(T1, 32));
        a.push(sll(T1, T0, T1));               // shift by 0: unchanged
    }, &[S0, S1, T2, T1]);
    assert_eq!(out[..4], [2, 1, 0xffff_ffff, 0x8000_0000]);
}

#[test]
fn add_and_sub_wrap_modulo_two_to_the_32() {
    let out = outputs(|a| {
        a.extend(li(T0, i32::MAX));
        a.push(addi(S0, T0, 1));
        a.extend(li(T1, -1));
        a.push(add(S1, T0, T1));
        a.extend(li(T0, 0));
        a.push(sub(T2, T0, T1));               // 0 - (-1) = 1
        a.extend(li(T0, i32::MIN));
        a.push(addi(T0, T0, -1));              // MIN - 1 wraps to MAX
    }, &[S0, S1, T2, T0]);
    assert_eq!(out[..4], [0x8000_0000, 0x7fff_fffe, 1, 0x7fff_ffff]);
}

#[test]
fn lui_then_addi_with_a_negative_low_part_composes_the_right_constant() {
    let out = outputs(|a| {
        a.push(lui(T0, 0x1234_5000));
        a.push(addi(T0, T0, -1));
        a.push(lui(T1, 0x8000_0000));
        a.push(lui(T2, 0xffff_f000));
        a.push(addi(T2, T2, 0x7ff));
    }, &[T0, T1, T2]);
    assert_eq!(out[..3], [0x1234_4fff, 0x8000_0000, 0xffff_f7ff]);
}

#[test]
fn auipc_adds_the_upper_immediate_to_its_own_pc() {
    let mut a = Assembler::new(0x1000);
    a.push(addi(0, 0, 0));
    a.push(addi(0, 0, 0));
    a.push(auipc(T0, 0x2000));                 // at pc 0x1008
    a.push(auipc(T1, 0));                      // at pc 0x100c
    a.push(auipc(T2, 0xffff_f000));            // pc - 0x1000 = 0x10
    a.extend(write_output(0, T0));
    a.extend(write_output(1, T1));
    a.extend(write_output(2, T2));
    a.extend(halt());
    let e = run(&a.assemble(), &[]);
    assert_eq!(e.outputs[..3], [0x3008, 0x100c, 0x10]);
    let ev = &e.events[2];
    assert_eq!((ev.pc, ev.tgt, ev.c, ev.next_pc), (0x1008, 0x3008, 0x3008, 0x100c));
}

// ─────────────────────────── jumps and branches ───────────────────────────

#[test]
fn jal_links_pc_plus_four_and_jumps_by_its_offset() {
    let mut a = Assembler::new(0x1000);
    a.jal(REG_RA, "target");                   // pc 0x1000
    a.extend(li(T0, 99));                      // skipped
    a.label("target");
    a.extend(write_output(0, REG_RA));
    a.extend(write_output(1, T0));
    a.extend(halt());
    let e = run(&a.assemble(), &[]);
    assert_eq!(e.outputs[..2], [0x1004, 0]);
    let j = &e.events[0];
    assert_eq!((j.c, j.next_pc, j.tgt), (0x1004, 0x1008, 0x1008));
    assert_eq!(j.dec.imm, 8);
}

#[test]
fn jalr_with_rd_equal_to_rs1_jumps_through_the_old_value_and_links_the_new() {
    let p = program(|a| {
        a.extend(li(T0, 12));                  // pc 0: t0 = 12
        a.push(jalr(T0, T0, 0));               // pc 4: jump to 12, t0 = 8
        a.extend(li(T1, 99));                  // pc 8: skipped
        a.extend(write_output(0, T0));         // pc 12
        a.extend(write_output(1, T1));
        a.extend(halt());
    });
    let e = run(&p, &[]);
    assert_eq!(e.outputs[..2], [8, 0]);
    assert_eq!(e.events[1].next_pc, 12);
}

#[test]
fn jalr_applies_a_negative_offset_to_the_register() {
    let p = program(|a| {
        a.extend(li(T0, 20));                  // pc 0
        a.push(jalr(0, T0, -8));               // pc 4: to 12
        a.extend(li(T1, 99));                  // pc 8
        a.extend(write_output(0, T1));         // pc 12
        a.extend(halt());
    });
    assert_eq!(run(&p, &[]).outputs[0], 0);
}

#[test]
fn a_jalr_to_a_half_aligned_target_is_a_bad_pc_after_bit_zero_is_cleared() {
    for target in [10i32, 11] {
        let p = program(|a| {
            a.extend(li(T0, target));
            a.push(jalr(0, T0, 0));
            a.extend(halt());
        });
        assert_eq!(execute(&p, &[], &[], 100).unwrap_err(), ExecError::BadPc(10), "target {target}");
    }
}

/// Every condition on the (MIN, MAX) and (x, x) operand pairs, where signed and unsigned
/// orderings disagree and where only the equalities hold.
fn branch_table(a_val: i32, b_val: i32) -> [u32; 6] {
    let conds = [BranchCond::Eq, BranchCond::Ne, BranchCond::Lt, BranchCond::Ge, BranchCond::Ltu, BranchCond::Geu];
    let p = program(|a| {
        a.extend(li(T0, a_val));
        a.extend(li(T1, b_val));
        for (i, cond) in conds.iter().enumerate() {
            let (taken, done) = (format!("t{i}"), format!("d{i}"));
            a.extend(li(T2, 0));
            a.branch(*cond, T0, T1, &taken);
            a.jal(0, &done);
            a.label(&taken);
            a.extend(li(T2, 1));
            a.label(&done);
            a.extend(write_output(i as u32, T2));
        }
        a.extend(halt());
    });
    let o = run(&p, &[]).outputs;
    [o[0], o[1], o[2], o[3], o[4], o[5]]
}

#[test]
fn branches_at_the_signed_unsigned_boundary() {
    //                                         eq ne lt ge ltu geu
    assert_eq!(branch_table(i32::MIN, i32::MAX), [0, 1, 1, 0, 0, 1]);
    assert_eq!(branch_table(i32::MAX, i32::MIN), [0, 1, 0, 1, 1, 0]);
    assert_eq!(branch_table(-1, 0), [0, 1, 1, 0, 0, 1]);
}

#[test]
fn branches_on_equal_operands_take_only_the_inclusive_conditions() {
    assert_eq!(branch_table(i32::MIN, i32::MIN), [1, 0, 0, 1, 0, 1]);
    assert_eq!(branch_table(0, 0), [1, 0, 0, 1, 0, 1]);
}

#[test]
fn a_backward_branch_loop_at_a_nonzero_base_counts_down_to_zero() {
    let mut a = Assembler::new(0x4000);
    a.extend(li(T0, 5));
    a.extend(li(T1, 0));
    a.label("loop");
    a.push(addi(T1, T1, 1));
    a.push(addi(T0, T0, -1));
    a.branch(BranchCond::Ne, T0, 0, "loop");
    a.extend(write_output(0, T1));
    a.extend(halt());
    let e = run(&a.assemble(), &[]);
    assert_eq!(e.outputs[0], 5);
    let taken: Vec<&CycleEvent> = e.events.iter().filter(|ev| ev.dec.is_branch == 1 && ev.next_pc != ev.pc + 4).collect();
    assert_eq!(taken.len(), 4, "four of the five branches jump back");
    assert!(taken.iter().all(|ev| ev.next_pc == 0x4008 && ev.dec.imm == (-8i32) as u32));
}

// ─────────────────────────── loads and stores ───────────────────────────

#[test]
fn unwritten_ram_reads_as_zero_at_every_width() {
    let out = outputs(|a| {
        a.extend(li(S0, 0x100));
        a.push(lw(T0, S0, 0));
        a.push(lh(T1, S0, 2));
        a.push(lb(T2, S0, 3));
        a.push(lhu(S1, S0, 0));
        a.push(lbu(S0, S0, 1));
    }, &[T0, T1, T2, S1, S0]);
    assert_eq!(out[..5], [0; 5]);
}

#[test]
fn byte_and_half_loads_at_every_offset_extend_from_the_right_bits() {
    let out = outputs(|a| {
        a.extend(li(S0, 0x100));
        a.extend(li(T0, 0x807f_ff01u32 as i32));
        a.push(sw(S0, T0, 0));
        a.push(lb(T0, S0, 0));                 // 0x01
        a.push(lb(T1, S0, 1));                 // 0xff -> -1
        a.push(lb(T2, S0, 2));                 // 0x7f
        a.push(lb(S1, S0, 3));                 // 0x80 -> -128
        a.extend(write_output(0, T0)); a.extend(write_output(1, T1));
        a.extend(write_output(2, T2)); a.extend(write_output(3, S1));
        a.push(lbu(T0, S0, 3));                // 0x80
        a.push(lh(T1, S0, 0));                 // 0xff01 -> sign-extended
        a.push(lh(T2, S0, 2));                 // 0x807f -> sign-extended
        a.push(lhu(S1, S0, 2));                // 0x807f
    }, &[]);
    assert_eq!(out[..4], [1, 0xffff_ffff, 0x7f, 0xffff_ff80]);
    // The second batch goes through its own outputs.
    let out2 = outputs(|a| {
        a.extend(li(S0, 0x100));
        a.extend(li(T0, 0x807f_ff01u32 as i32));
        a.push(sw(S0, T0, 0));
        a.push(lbu(T0, S0, 3));
        a.push(lh(T1, S0, 0));
        a.push(lh(T2, S0, 2));
        a.push(lhu(S1, S0, 2));
    }, &[T0, T1, T2, S1]);
    assert_eq!(out2[..4], [0x80, 0xffff_ff01, 0xffff_807f, 0x807f]);
}

#[test]
fn sub_word_stores_write_only_their_bytes_from_the_registers_low_bits() {
    let out = outputs(|a| {
        a.extend(li(S0, 0x100));
        a.extend(li(T0, 0xdead_beefu32 as i32));
        a.push(sb(S0, T0, 1));                 // word 0x100: 0x0000_ef00
        a.push(lw(T1, S0, 0));
        a.push(sh(S0, T0, 6));                 // word 0x104: 0xbeef_0000
        a.push(lw(T2, S0, 4));
        a.push(sb(S0, T0, 7));                 // word 0x104: 0xefef_0000
        a.push(lw(S1, S0, 4));
        a.push(sh(S0, T0, 0));                 // word 0x100: 0x0000_beef (ef00 replaced in the low half)
        a.push(lw(S0, S0, 0));
    }, &[T1, T2, S1, S0]);
    assert_eq!(out[..4], [0x0000_ef00, 0xbeef_0000, 0xefef_0000, 0x0000_beef]);
}

#[test]
fn a_store_event_carries_the_old_word_and_the_merged_word() {
    let p = program(|a| {
        a.extend(li(S0, 0x100));
        a.extend(li(T0, 0x1111_1111));
        a.push(sw(S0, T0, 0));
        a.extend(li(T0, 0xffu32 as i32));
        a.push(sb(S0, T0, 2));
        a.extend(halt());
    });
    let e = run(&p, &[]);
    let sb_row = e.events.iter().find(|ev| ev.dec.is_sb == 1).unwrap();
    assert_eq!(sb_row.mem_addr, 0x40);
    assert_eq!(sb_row.mem_val, 0x1111_1111, "the word before the store");
    let ram: Vec<&MemAccess> = sb_row.accesses.iter().filter(|m| m.space == SPACE_RAM).collect();
    assert_eq!(ram.len(), 2);
    assert_eq!((ram[0].slot, ram[0].value, ram[0].is_write), (SLOT_MEM, 0x1111_1111, false));
    assert_eq!((ram[1].slot, ram[1].value, ram[1].is_write), (SLOT_W, 0x11ff_1111, true));
    assert_eq!(ram[1].ts(sb_row.clk), 4 * sb_row.clk + 3);
}

#[test]
fn negative_offsets_and_x0_as_a_base_address_both_work() {
    let out = outputs(|a| {
        a.extend(li(S0, 0x200));
        a.extend(li(T0, 42));
        a.push(sw(S0, T0, -4));                // 0x1fc
        a.push(lw(T1, 0, 0x1fc));              // through x0
        a.push(lw(T2, S0, -4));
    }, &[T1, T2]);
    assert_eq!(out[..2], [42, 42]);
}

#[test]
fn a_byte_address_that_wraps_below_zero_lands_on_the_top_word() {
    let p = program(|a| {
        a.extend(li(T0, 7));
        a.push(sw(0, T0, -4));                 // byte address 0xffff_fffc, word 0x3fff_ffff
        a.push(lw(T1, 0, -4));
        a.extend(write_output(0, T1));
        a.extend(halt());
    });
    let e = run(&p, &[]);
    assert_eq!(e.outputs[0], 7);
    let st = e.events.iter().find(|ev| ev.dec.is_sw == 1).unwrap();
    assert_eq!((st.alu_out, st.mem_addr), (0xffff_fffc, 0x3fff_ffff));
}

#[test]
fn an_unsigned_half_load_at_an_odd_offset_is_misaligned() {
    for off in [1i32, 3, 0x101] {
        let p = program(|a| {
            a.push(lhu(T0, 0, off));
            a.extend(halt());
        });
        assert_eq!(execute(&p, &[], &[], 100).unwrap_err(), ExecError::Misaligned(off as u32));
    }
    for off in [1i32, 2, 3] {
        let p = program(|a| {
            a.push(lw(T0, 0, 0x100 + off));
            a.extend(halt());
        });
        assert_eq!(execute(&p, &[], &[], 100).unwrap_err(), ExecError::Misaligned(0x100 + off as u32));
    }
}

// ─────────────────────────── syscalls ───────────────────────────

#[test]
fn unknown_syscall_numbers_are_refused_with_their_number() {
    for num in [8i32, 100, -1] {
        let p = program(|a| {
            a.extend(li(REG_A7, num));
            a.push(ecall());
            a.extend(halt());
        });
        assert_eq!(execute(&p, &[], &[], 100).unwrap_err(), ExecError::BadSyscall(num as u32));
    }
}

#[test]
fn output_slots_past_seven_are_refused_with_the_slot() {
    for slot in [8u32, 9, 0xffff_ffff] {
        let p = program(|a| {
            a.extend(write_output(slot, T0));
            a.extend(halt());
        });
        assert_eq!(execute(&p, &[], &[], 100).unwrap_err(), ExecError::OutputSlot(slot));
    }
}

#[test]
fn input_indices_are_bounded_by_the_vector_length() {
    let p = |idx: u32| program(|a| {
        a.extend(read_input(idx));
        a.push(mv(T0, REG_A0));                // `write_output` stages its slot in a0 first
        a.extend(write_output(0, T0));
        a.extend(halt());
    });
    assert_eq!(execute(&p(0), &[], &[], 100).unwrap_err(), ExecError::InputIndex(0));
    assert_eq!(execute(&p(3), &[1, 2, 3], &[], 100).unwrap_err(), ExecError::InputIndex(3));
    assert_eq!(execute(&p(2), &[1, 2, 3], &[], 100).unwrap().outputs[0], 3);
    assert_eq!(execute(&p(0xffff_ffff), &[1, 2, 3], &[], 100).unwrap_err(), ExecError::InputIndex(0xffff_ffff));
}

#[test]
fn read_input_writes_a0_through_the_register_write_slot() {
    let p = program(|a| {
        a.extend(li(REG_A0, 5));
        a.extend(read_input(1));
        a.push(mv(T0, REG_A0));
        a.extend(write_output(0, T0));
        a.extend(halt());
    });
    let e = run(&p, &[7, 42]);
    assert_eq!(e.outputs[0], 42);
    let row = e.events.iter().find(|ev| matches!(ev.sys, Some(Syscall::ReadInput { .. }))).unwrap();
    assert_eq!(row.sys, Some(Syscall::ReadInput { idx: 1, word: 42 }));
    assert_eq!(row.c, 42);
    assert_eq!(row.dec.rd, REG_A0);
    let w = row.accesses.iter().find(|m| m.is_write).expect("the ecall row writes a0");
    assert_eq!((w.space, w.addr, w.slot, w.value), (SPACE_REG, REG_A0, SLOT_W, 42));
    // The ecall row reads a7 as rs1, a0 as rs2 and a1 through the memory slot.
    assert_eq!((row.dec.rs1, row.dec.rs2, row.mem_addr), (REG_A7, REG_A0, ECALL_MEM_REG));
    assert_eq!((row.a, row.b), (SYS_READ_INPUT, 1));
}

#[test]
fn writing_zero_to_a_slot_still_claims_it() {
    let p = program(|a| {
        a.extend(write_output(3, 0));
        a.extend(write_output(3, 0));
        a.extend(halt());
    });
    assert_eq!(execute(&p, &[], &[], 100).unwrap_err(), ExecError::DoubleWrite(3));
}

#[test]
fn every_output_slot_is_writable_in_any_order() {
    let p = program(|a| {
        for slot in (0..8u32).rev() {
            a.extend(li(T0, 100 + slot as i32));
            a.extend(write_output(slot, T0));
        }
        a.extend(halt());
    });
    let e = run(&p, &[]);
    assert_eq!(e.outputs, [100, 101, 102, 103, 104, 105, 106, 107]);
    let writes: Vec<Syscall> = e.events.iter().filter_map(|ev| ev.sys).filter(|s| matches!(s, Syscall::WriteOutput { .. })).collect();
    assert_eq!(writes.len(), 8);
    assert_eq!(writes[0], Syscall::WriteOutput { slot: 7, word: 107 });
}

#[test]
fn halt_ends_the_run_on_its_own_row_and_nothing_after_it_executes() {
    let p = program(|a| {
        a.extend(li(T0, 1));                   // 1 row
        a.extend(write_output(0, T0));         // li a7, li a0, mv a1, ecall: 4 rows
        a.extend(halt());                      // li a7, ecall: 2 rows
        a.extend(li(T0, 2));
        a.extend(write_output(1, T0));
    });
    let e = run(&p, &[]);
    assert!(e.halted);
    assert_eq!(e.cycles(), 7);
    assert_eq!(e.events.len(), 7);
    assert_eq!(e.outputs[..2], [1, 0]);
    let last = e.events.last().unwrap();
    assert_eq!(last.sys, Some(Syscall::Halt));
    assert_eq!(last.instr, Instr::Ecall);
    assert!(e.events[..6].iter().all(|ev| ev.sys != Some(Syscall::Halt)));
}

#[test]
fn falling_off_the_end_of_the_program_is_a_bad_pc_one_past_the_last_word() {
    let p = program(|a| {
        a.extend(li(T0, 1));
        a.extend(write_output(0, T0));
    });
    assert_eq!(execute(&p, &[], &[], 100).unwrap_err(), ExecError::BadPc(4 * p.len() as u32));
    let mut a = Assembler::new(0x2000);
    a.push(addi(0, 0, 0));
    assert_eq!(execute(&a.assemble(), &[], &[], 100).unwrap_err(), ExecError::BadPc(0x2004));
}

// ─────────────────────────── the row budget and the hash row group ───────────────────────────

/// `li a7, 3; li a0, ptr; li a1, n; ecall` is three rows plus the group; `halt` is two.
fn poseidon2_call(ptr: i32, n: usize) -> Program {
    program(|a| {
        a.extend(call_poseidon2(ptr, n));
        a.extend(halt());
    })
}

#[test]
fn the_cycle_budget_counts_rows_not_instructions() {
    // n = 4: an ecall row, one absorb row, two write-back rows.
    let p = poseidon2_call(0x100, 4);
    let e = execute(&p, &[], &[], 9).unwrap();
    assert!(e.halted);
    assert_eq!(e.cycles(), 9);
    assert_eq!(execute(&p, &[], &[], 8).unwrap_err(), ExecError::OutOfCycles(8));
    assert_eq!(execute(&p, &[], &[], 4).unwrap_err(), ExecError::OutOfCycles(4), "dying inside the group");
    let kinds: Vec<Option<bool>> = e.events.iter().map(|ev| ev.hash_row.as_ref().map(|h| h.is_absorb())).collect();
    assert_eq!(kinds, [None, None, None, Some(false), Some(true), Some(false), Some(false), None, None]);
    // Every row of the group sits at the ecall's pc; only the final write-back advances.
    let group = &e.events[3..7];
    assert!(group.iter().all(|ev| ev.pc == 12));
    assert_eq!(group.iter().map(|ev| ev.next_pc).collect::<Vec<_>>(), [12, 12, 12, 16]);
}

#[test]
fn a_zero_length_poseidon2_overwrites_the_buffer_with_the_zero_digest() {
    let p = program(|a| {
        a.extend(li(S0, 0x400));
        for i in 0..8 { a.extend(li(T0, 0x1000 + i)); a.push(sw(S0, T0, 4 * i)); }
        a.extend(call_poseidon2(0x100, 0));
        for i in 0..8 { a.push(lw(T0, S0, 4 * i)); a.extend(write_output(i as u32, T0)); }
        a.extend(halt());
    });
    let e = run(&p, &[]);
    assert_eq!(e.outputs, [0; 8], "`sponge_hash(&[])` is the all-zero digest, written in place");
    let group: Vec<&HashRow> = e.events.iter().filter_map(|ev| ev.hash_row.as_ref()).collect();
    assert_eq!(group.len(), 3, "ecall + two write-back rows, no absorb");
    assert!(matches!(group[0], HashRow::Ecall { ptr: 0x100, n: 0 }));
}

#[test]
fn a_zero_length_poseidon2_len_absorbs_one_empty_block() {
    let p = program(|a| {
        a.extend(li(S0, 0x400));
        a.extend(call_poseidon2_len(0x100, 0));
        for i in 0..8 { a.push(lw(T0, S0, 4 * i)); a.extend(write_output(i as u32, T0)); }
        a.extend(halt());
    });
    let e = run(&p, &[]);
    assert_eq!(e.outputs, randprotocol_zkvm::hash::sponge_hash_len(&[]));
    assert_ne!(e.outputs, [0; 8]);
    let group: Vec<&HashRow> = e.events.iter().filter_map(|ev| ev.hash_row.as_ref()).collect();
    assert_eq!(group.len(), 4, "ecall + one empty absorb + two write-back rows");
    match group[1] {
        HashRow::Absorb { idx, left_before, active, state_in, .. } => {
            assert_eq!((*idx, *left_before, *active), (0, 0, [false; 4]));
            use p3_field::PrimeCharacteristicRing;
            assert_eq!(state_in[4], randprotocol_zkvm::machine::Val::ZERO, "n = 0 in the capacity lane");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn poseidon2_at_the_word_limit_is_accepted_and_costs_1024_absorb_rows() {
    let p = poseidon2_call(0x1000, POSEIDON2_MAX_WORDS as usize);
    let e = execute(&p, &[], &[], 2_000).unwrap();
    let absorbs = e.events.iter().filter(|ev| ev.hash_row.as_ref().is_some_and(|h| h.is_absorb())).count();
    assert_eq!(absorbs, 1024);
    assert_eq!(e.cycles(), 3 + 1 + 1024 + 2 + 2);
    // RAM was zero, so this is the digest of 4096 zero words, written back at `ptr`.
    let want = randprotocol_zkvm::hash::sponge_hash(&[0u32; 4096]);
    let write = e.events.iter().filter_map(|ev| match &ev.hash_row { Some(HashRow::WriteOut { words, fin: false, .. }) => Some(*words), _ => None }).next().unwrap();
    assert_eq!(write, want[..4]);
}

#[test]
fn a_poseidon2_pointer_just_under_two_to_the_30_is_accepted() {
    let ptr = (1u32 << 30) - 1;
    let p = poseidon2_call(ptr as i32, 1);
    let e = execute(&p, &[], &[], 100).unwrap();
    assert!(e.halted);
    let reads: Vec<u32> = e.events.iter().flat_map(|ev| ev.accesses.iter()).filter(|m| m.space == SPACE_RAM && !m.is_write).map(|m| m.addr).collect();
    assert_eq!(reads, [ptr]);
    let writes: Vec<u32> = e.events.iter().flat_map(|ev| ev.accesses.iter()).filter(|m| m.space == SPACE_RAM && m.is_write).map(|m| m.addr).collect();
    assert_eq!(writes, (0..8).map(|k| ptr + k).collect::<Vec<_>>(), "the digest straddles 2^30, which the address arithmetic allows");
    let one_past = poseidon2_call((1u32 << 30) as i32, 1);
    assert_eq!(execute(&one_past, &[], &[], 100).unwrap_err(), ExecError::Poseidon2Ptr(1 << 30));
}

#[test]
fn keccak_and_sha256_pointers_are_accepted_exactly_up_to_their_limits() {
    let k = |ptr: u32| program(|a| { a.extend(call_keccak(ptr as i32)); a.extend(halt()); });
    assert!(execute(&k(KECCAK_PTR_LIMIT), &[], &[], 100).unwrap().halted);
    assert_eq!(execute(&k(KECCAK_PTR_LIMIT + 1), &[], &[], 100).unwrap_err(), ExecError::KeccakPtrOutOfRange(KECCAK_PTR_LIMIT + 1));
    let s = |ptr: u32| program(|a| { a.extend(call_sha256(ptr)); a.extend(halt()); });
    assert!(execute(&s(SHA256_PTR_LIMIT), &[], &[], 100).unwrap().halted);
    assert_eq!(execute(&s(SHA256_PTR_LIMIT + 1), &[], &[], 100).unwrap_err(), ExecError::Sha256PtrOutOfRange(SHA256_PTR_LIMIT + 1));
    assert_eq!(KECCAK_PTR_LIMIT + KECCAK_WORDS, 0x3000_0000);
    assert_eq!(SHA256_PTR_LIMIT + SHA256_WORDS, 0x3000_0000);
}

// ─────────────────────────── trace invariants ───────────────────────────

#[test]
fn every_execution_is_a_clk_numbered_pc_chain_ending_in_halt() {
    let guests = randprotocol_zkvm::guests::all();
    assert!(guests.len() >= 5);
    for (name, p, inputs) in guests {
        let e = execute(&p, &inputs, &[], 1 << 20).unwrap();
        assert!(e.halted, "{name}");
        for (i, ev) in e.events.iter().enumerate() {
            assert_eq!(ev.clk as usize, i, "{name}: clk is the row index");
            if let Some(next) = e.events.get(i + 1) {
                assert_eq!(ev.next_pc, next.pc, "{name}: row {i} hands its next_pc to row {}", i + 1);
            }
            // The two register reads are always slots 0 and 1 of the ordinary rows.
            if ev.hash_row.is_none() || matches!(ev.hash_row, Some(HashRow::Ecall { .. })) {
                assert_eq!((ev.accesses[0].slot, ev.accesses[0].addr, ev.accesses[0].value), (SLOT_R1, ev.dec.rs1, ev.a), "{name} row {i}");
                assert_eq!((ev.accesses[1].slot, ev.accesses[1].addr, ev.accesses[1].value), (SLOT_R2, ev.dec.rs2, ev.b), "{name} row {i}");
            }
        }
        assert_eq!(e.events.last().unwrap().sys, Some(Syscall::Halt), "{name}");
        assert_eq!(e.events[0].pc, p.base_pc, "{name}: execution starts at base_pc");
    }
}

#[test]
fn a_program_that_fills_its_tier_budget_exactly_still_halts() {
    // 1 020 one-row instructions and a two-row halt: exactly tier 10's 1 023 cycles.
    let budget = randprotocol_zkvm::machine::Tier(10).max_cycles();
    let p = program(|a| {
        for _ in 0..budget - 2 { a.push(addi(T0, T0, 1)); }
        a.extend(halt());
    });
    let e = execute(&p, &[], &[], budget).unwrap();
    assert_eq!(e.cycles(), budget);
    assert_eq!(execute(&p, &[], &[], budget - 1).unwrap_err(), ExecError::OutOfCycles(budget - 1));
}
