//! ZKVM-118: the official RISC-V unit tests (`rv32ui`, `rv32um`) through the emulator — its one
//! reference from outside this repository. `tests/riscv-tests/README.md` has the provenance (the
//! upstream commit, the build, the licence) and the two tests that are not ordinary passes.
//!
//! Each image is checked against its pinned SHA-256 before it is run, and the directory is
//! checked against the list, so a test cannot be dropped or swapped without this file changing.
use randprotocol_zkvm::emulator::{execute, ExecError};
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::{FriProfile, Machine};
use std::path::PathBuf;

/// `rv32ui` without `fence_i` (no image: the loader refuses `FENCE.I`) and `ma_data` (its own
/// test below), then `rv32um`.
const PASSING: [&str; 48] = [
    "rv32ui-add", "rv32ui-addi", "rv32ui-and", "rv32ui-andi", "rv32ui-auipc", "rv32ui-beq", "rv32ui-bge", "rv32ui-bgeu",
    "rv32ui-blt", "rv32ui-bltu", "rv32ui-bne", "rv32ui-jal", "rv32ui-jalr", "rv32ui-lb", "rv32ui-lbu", "rv32ui-ld_st",
    "rv32ui-lh", "rv32ui-lhu", "rv32ui-lui", "rv32ui-lw", "rv32ui-or", "rv32ui-ori", "rv32ui-sb", "rv32ui-sh",
    "rv32ui-simple", "rv32ui-sll", "rv32ui-slli", "rv32ui-slt", "rv32ui-slti", "rv32ui-sltiu", "rv32ui-sltu", "rv32ui-sra",
    "rv32ui-srai", "rv32ui-srl", "rv32ui-srli", "rv32ui-st_ld", "rv32ui-sub", "rv32ui-sw", "rv32ui-xor", "rv32ui-xori",
    "rv32um-div", "rv32um-divu", "rv32um-mul", "rv32um-mulh", "rv32um-mulhsu", "rv32um-mulhu", "rv32um-rem", "rv32um-remu",
];
const MISALIGNED: &str = "rv32ui-ma_data";

/// The pass signature of `env/riscv_test.h`: `out[0] = 1` and nothing else. A failure writes the
/// failing case's number to `out[1]` instead.
const PASS: [u32; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
/// Every test fits well inside this (the longest is under a thousand cycles).
const BUDGET: usize = 1 << 14;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/riscv-tests")
}

/// The image of `name`, after checking it against `SHA256SUMS`.
fn image(name: &str) -> Vec<u8> {
    let file = format!("{name}.bin");
    let bytes = std::fs::read(dir().join("bin").join(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    let sums = std::fs::read_to_string(dir().join("SHA256SUMS")).unwrap();
    let pinned = sums.lines().find_map(|l| l.split_once("  ").filter(|(_, f)| *f == file).map(|(h, _)| h)).unwrap_or_else(|| panic!("{file} is not in SHA256SUMS"));
    assert_eq!(hex::encode(randprotocol_zkvm::sha256::sha256(&bytes)), pinned, "{file} is not the pinned image");
    bytes
}

fn program(name: &str) -> Program {
    Program::from_flat_image(&image(name)).unwrap_or_else(|e| panic!("{name}: the loader refuses it: {e:?}"))
}

#[test]
fn the_vendored_images_are_exactly_the_pinned_list() {
    let mut on_disk: Vec<String> = std::fs::read_dir(dir().join("bin")).unwrap().flatten().map(|e| e.file_name().into_string().unwrap()).collect();
    on_disk.sort();
    let mut want: Vec<String> = PASSING.iter().chain([&MISALIGNED]).map(|n| format!("{n}.bin")).collect();
    want.sort();
    assert_eq!(on_disk, want);
    let sums = std::fs::read_to_string(dir().join("SHA256SUMS")).unwrap();
    let mut pinned: Vec<String> = sums.lines().map(|l| l.split_once("  ").expect("`<sha256>  <file>`").1.to_string()).collect();
    pinned.sort();
    assert_eq!(pinned, want, "SHA256SUMS lists other files than bin/ holds");
}

#[test]
fn rv32ui_and_rv32um_pass_on_the_emulator() {
    let mut failed = Vec::new();
    for name in PASSING {
        match execute(&program(name), &[], &[], BUDGET) {
            Ok(exec) if exec.halted && exec.outputs == PASS => {}
            Ok(exec) => failed.push(format!("{name}: failed at test case {} (outputs {:?})", exec.outputs[1], exec.outputs)),
            Err(e) => failed.push(format!("{name}: {e:?}")),
        }
    }
    assert!(failed.is_empty(), "{} of {} riscv-tests fail:\n{}", failed.len(), PASSING.len(), failed.join("\n"));
}

/// `ma_data` is the misaligned-access test. The machine does not implement misaligned loads and
/// stores — one is a trap, by design — so the test must end in exactly that, never in a pass.
#[test]
fn the_misaligned_access_test_traps_as_the_machine_specifies() {
    match execute(&program(MISALIGNED), &[], &[], BUDGET) {
        Err(ExecError::Misaligned(addr)) => assert_ne!(addr % 4, 0, "the trapping address {addr:#x} is aligned"),
        other => panic!("ma_data: expected a Misaligned trap, got {:?}", other.map(|e| e.outputs)),
    }
}

/// The frame can tell a failure from a pass: the same image with one word changed so that a test
/// case's expected value is wrong halts with that case's number in `out[1]` and no pass word.
#[test]
fn a_failing_test_case_is_reported_as_one() {
    let p = program("rv32ui-add");
    let exec = execute(&p, &[], &[], BUDGET).unwrap();
    // The first `bne testreg, x7, fail` that is not taken: make it a `beq`, so a correct result
    // now branches to `fail`.
    let e = exec.events.iter().find(|e| matches!(e.instr, randprotocol_zkvm::isa::Instr::Branch { cond: randprotocol_zkvm::isa::BranchCond::Ne, .. }) && e.next_pc == e.pc + 4).expect("a test case's check");
    let i = ((e.pc - p.base_pc) / 4) as usize;
    let mut words = p.words.clone();
    words[i] ^= 1 << 12; // funct3 001 (bne) -> 000 (beq)
    let broken = Program::new(p.base_pc, words);
    let exec = execute(&broken, &[], &[], BUDGET).unwrap();
    assert!(exec.halted && exec.outputs[0] == 0 && exec.outputs[1] != 0, "a wrong expectation still passed: {:?}", exec.outputs);
}

/// The AIR against the same tests: five `rv32um` tests and three `rv32ui` ones (the ones where a
/// shared misreading is likeliest: the high multiplies, signed division and remainder, the
/// arithmetic shift, a sign-extending load, a sub-word store) are proved under the test profile
/// and verified. Eight, not all 48, for the suite's running time.
#[test]
fn a_subset_proves_and_verifies_with_the_pass_signature() {
    let m = Machine::new(FriProfile::Test);
    for name in ["rv32um-mulh", "rv32um-mulhsu", "rv32um-mulhu", "rv32um-div", "rv32um-rem", "rv32ui-sra", "rv32ui-lb", "rv32ui-sh"] {
        let p = program(name);
        let (proof, exec) = m.prove(&p, &[], &[], None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(exec.outputs, PASS, "{name}");
        m.verify(&p.digest(), &proof).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}
