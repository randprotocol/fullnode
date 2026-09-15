//! The ISA's encoding and the program digest: the two things every later task and every M5.2
//! table are pinned against.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use shrugg_rvm::isa::{DecodeError, Instr, Op, Program, F, RVM_PROGRAM_DOMAIN};

fn instr(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}

#[test]
fn every_opcode_round_trips_through_encode_and_decode() {
    assert_eq!(Op::ALL.len(), 26, "the ISA is twenty-six instructions (Task 8 appended REDUCE = 24, Task 9 SPONGE = 25)");
    for (i, op) in Op::ALL.iter().enumerate() {
        assert_eq!(*op as u8 as usize, i, "opcode numbering is the spec table's order, new opcodes appended");
        let b = if op.b_is_register() { 17 } else { 0xdead_beef_dead };
        let x = instr(*op, 3, 5, b);
        let w = x.encode();
        assert_eq!(w[0], F::from_u64(i as u64));
        assert_eq!(Instr::decode(w).unwrap(), x, "{}", op.mnemonic());
    }
}

#[test]
fn decode_rejects_an_unknown_opcode_and_an_out_of_range_register() {
    let mut w = instr(Op::Fadd, 1, 2, 3).encode();
    w[0] = F::from_u64(26);
    assert_eq!(Instr::decode(w), Err(DecodeError::Opcode(26)));
    let mut w = instr(Op::Fadd, 1, 2, 3).encode();
    w[1] = F::from_u64(32);
    assert_eq!(Instr::decode(w), Err(DecodeError::Register { slot: "rd", value: 32 }));
    let mut w = instr(Op::Fadd, 1, 2, 3).encode();
    w[3] = F::from_u64(99);
    assert_eq!(Instr::decode(w), Err(DecodeError::Register { slot: "rb", value: 99 }));
    // An immediate opcode accepts any field element in the fourth word.
    let mut w = instr(Op::Faddi, 1, 2, 0).encode();
    w[3] = F::from_u64(F::ORDER_U64 - 1);
    assert!(Instr::decode(w).is_ok());
}

#[test]
fn a_program_digest_is_one_permutation_per_instruction_and_binds_length() {
    let p = Program {
        instrs: vec![instr(Op::Faddi, 1, 0, 7), instr(Op::Halt, 0, 0, 0)],
        checkpoints: vec![],
    };
    assert_eq!(p.digest_rows(), 2);

    // Recomputed here from the reference permutation, the same way research/src/hash.rs does it.
    let mut state = [F::ZERO; 8];
    state[4] = F::from_u64(RVM_PROGRAM_DOMAIN);
    state[5] = F::from_u64(2);
    for w in p.encode() {
        state[..4].copy_from_slice(&w);
        state = shrugg_zkvm::hash::permute_state(state);
    }
    assert_eq!(p.digest(), <[F; 4]>::try_from(&state[..4]).unwrap());

    // A different length is a different digest even when the words agree on a prefix.
    let q = Program { instrs: vec![instr(Op::Faddi, 1, 0, 7)], checkpoints: vec![] };
    assert_ne!(p.digest(), q.digest());
    // The domain does not collide with any research domain (14 is the highest, SBPF_OUT).
    assert_eq!(RVM_PROGRAM_DOMAIN, 15);
}
