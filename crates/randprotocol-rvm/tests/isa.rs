//! The ISA's encoding and the program digest: the two things every later task and every M5.2
//! table are pinned against.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_rvm::isa::{DecodeError, Instr, Op, Program, F, RVM_PROGRAM_DOMAIN};

fn instr(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}

#[test]
fn every_opcode_round_trips_through_encode_and_decode() {
    assert_eq!(Op::ALL.len(), 30, "the ISA is thirty instructions (Task 8 appended REDUCE = 24, Task 9 SPONGE = 25, Cut B HINTN = 26, Cut C COMPRESS = 27, phase 3 FOLD = 28, POW = 29)");
    assert_eq!(Op::COUNT, 30);
    assert_eq!(Op::from_u8(26), Some(Op::Hintn));
    assert_eq!(Op::Hintn.mnemonic(), "HINTN");
    assert!(!Op::Hintn.b_is_register(), "HINTN's fourth word is an immediate offset");
    assert_eq!(Op::from_u8(27), Some(Op::Compress));
    assert_eq!(Op::Compress.mnemonic(), "COMPRESS");
    assert!(Op::Compress.b_is_register(), "COMPRESS's fourth word is the sibling's register");
    assert_eq!(Op::from_u8(28), Some(Op::Fold));
    assert_eq!(Op::Fold.mnemonic(), "FOLD");
    assert!(!Op::Fold.b_is_register());
    assert_eq!(Op::from_u8(29), Some(Op::Pow));
    assert_eq!(Op::Pow.mnemonic(), "POW");
    assert!(!Op::Pow.b_is_register(), "POW's fourth word is the immediate off + 256·L");
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
    w[0] = F::from_u64(30);
    assert_eq!(Instr::decode(w), Err(DecodeError::Opcode(30)));
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
        reduce_layout: vec![],
    };
    assert_eq!(p.digest_rows(), 2);

    // Recomputed here from the reference permutation, the same way research/src/hash.rs does it.
    let mut state = [F::ZERO; 8];
    state[4] = F::from_u64(RVM_PROGRAM_DOMAIN);
    state[5] = F::from_u64(2);
    for w in p.encode() {
        state[..4].copy_from_slice(&w);
        state = randprotocol_zkvm::hash::permute_state(state);
    }
    assert_eq!(p.digest(), <[F; 4]>::try_from(&state[..4]).unwrap());

    // A different length is a different digest even when the words agree on a prefix.
    let q = Program { instrs: vec![instr(Op::Faddi, 1, 0, 7)], checkpoints: vec![], reduce_layout: vec![] };
    assert_ne!(p.digest(), q.digest());
    // The domain does not collide with any research domain (14 is the highest, SBPF_OUT).
    assert_eq!(RVM_PROGRAM_DOMAIN, 15);
}

/// Cut D: the reduce layout is part of the program's identity, absorbed after the instructions
/// — and only when present, so a program without one keeps the digest it always had.
#[test]
fn the_reduce_layout_is_absorbed_into_the_digest_only_when_present() {
    use randprotocol_rvm::isa::ReduceEntry;
    let p = Program { instrs: vec![instr(Op::Faddi, 1, 0, 7), instr(Op::Halt, 0, 0, 0)], checkpoints: vec![], reduce_layout: vec![] };
    let e = ReduceEntry { vals: 100, row: 120, len: 3, key: 210, alpha: 212, res: 214, chain_start: true, carry: false };
    let q = Program { reduce_layout: vec![e], ..p.clone() };
    assert_ne!(p.digest(), q.digest(), "a layout changes the digest");
    // Every field is bound, each on its own (Task 5 sweep: the flags and the length too, not only
    // `res`): changing any one of the eight gives a digest distinct from the honest one and from
    // every other single change — including `chain_start` against `carry`, which share one word.
    let variants = [
        ("vals", ReduceEntry { vals: 102, ..e }),
        ("row", ReduceEntry { row: 121, ..e }),
        ("len", ReduceEntry { len: 2, ..e }),
        ("key", ReduceEntry { key: 216, ..e }),
        ("alpha", ReduceEntry { alpha: 218, ..e }),
        ("res", ReduceEntry { res: 216, ..e }),
        ("chain_start", ReduceEntry { chain_start: false, ..e }),
        ("carry", ReduceEntry { carry: true, ..e }),
        ("both flags", ReduceEntry { chain_start: false, carry: true, ..e }),
    ];
    let mut seen = vec![("honest", q.digest())];
    for (name, v) in variants {
        let d = Program { reduce_layout: vec![v], ..p.clone() }.digest();
        for (other, od) in &seen {
            assert_ne!(d, *od, "changing `{name}` collides with {other}");
        }
        seen.push((name, d));
    }
    // And the entry count and order: two entries, and the same two swapped.
    let f = ReduceEntry { vals: 300, row: 320, len: 1, key: 330, alpha: 212, res: 340, chain_start: false, carry: false };
    let two = Program { reduce_layout: vec![e, f], ..p.clone() };
    let swapped = Program { reduce_layout: vec![f, e], ..p.clone() };
    assert_ne!(two.digest(), q.digest(), "a second entry changes the digest");
    assert_ne!(two.digest(), swapped.digest(), "the layout's order is bound");
    assert_eq!(q.digest_rows(), 2 + 2, "two permutations per layout entry");
}
