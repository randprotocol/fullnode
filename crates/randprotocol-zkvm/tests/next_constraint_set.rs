//! Failing by design: the gaps the next constraint set closes, written as the tests it will have to
//! pass. Every test here is `#[ignore]`d with the reason, and every one *fails* on this constraint
//! set when run with `--ignored` — that failure is the finding, pinned. Closing a gap is a change to
//! the AIR (so to every verifier key) or to a syscall's semantics (so to every digest a guest
//! computes with it): a chain cut, never a same-chain release. `docs/05-roadmap.md`, "The next
//! constraint set", has the exact constraint each one needs.
//!
//! When the next set lands, the test that pins its gap loses its `#[ignore]` and passes; the
//! "today" assertions inside each (which document how the gap looks now) flip with it and are
//! deleted.
mod common;
use common::*;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::isa::REG_A0;
use randprotocol_zkvm::machine::{build_traces_salted, Tier, Val};
use randprotocol_zkvm::tables::{bus, cpu, input};

/// A field element that is not a 32-bit word, and whose low 32 bits are the honest word — the
/// shape a cheating prover would give a private input to have one value mean two things.
const NOT_U32: u64 = (1 << 32) + 5;

/// ZKM-1 / ZKH-2 (with ISA-2, ARITH-3, COV-4): a private input word is a field element to the
/// circuit, not a 32-bit word. No table range-checks it: the `input` table provides `(IDX, WORD)`
/// on `INPUT_DIGEST` and `INPUT_READ` and nothing else, and the cpu's `SYS_READ` row receives it
/// into `C` — whose only other appearance is the register write-back on `MEMORY` — so a guest can
/// be handed `2^32 + 5` for a word it believes is `5`, consistently in every table. A guest's
/// 32-bit semantics end there (a later ALU row does range-check its operands, so the value is
/// refused as soon as it meets arithmetic — but a word that is only stored, compared through an
/// equality gadget, hashed, or written to an output is not). `Machine::verify` refuses a non-u32
/// *output* since ZKA-1; the input side needs the AIR.
///
/// What this checks, symbolically on rows of an honest trace: an `input` row and the cpu's
/// `SYS_READ` row with the word replaced by `2^32 + 5` still satisfy every constraint of their
/// tables, and no range bus carries the word. The next set's rule makes the first false.
#[test]
#[ignore = "ZKM-1/ZKH-2: input words are not range-checked in the AIR — closed only by the next constraint set (docs/05-roadmap.md)"]
fn a_non_u32_input_word_is_refused_by_the_air() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x2b_4d31);
    let mut a = Assembler::new(0);
    a.extend(read_input(0));
    a.push(mv(5, REG_A0));
    a.extend(halt());
    let p = a.assemble();
    let e = execute(&p, &[5], &[], 10_000).unwrap();
    let t = build_traces_salted(&p, &[5], &[], [0; 4], &e, Tier(10)).unwrap();

    // The input table's row 0, and its successor.
    let row = |m: &p3_matrix::dense::RowMajorMatrix<Val>, r: usize| m.values[(r % m.height()) * m.width()..(r % m.height()) * m.width() + m.width()].to_vec();
    let (in_int, in_con) = symbolic_air(&input::InputAir);
    let mut forged = Rows { cur: row(&t.input, 0), next: row(&t.input, 1), pre_cur: vec![], pre_next: vec![], public: vec![] };
    assert_eq!(forged.cur[input::col::WORD], Val::from_u32(5));
    forged.cur[input::col::WORD] = Val::from_u64(NOT_U32);
    let input_holds = in_con.iter().all(|c| eval_boundary(c, &forged, true, false) == Val::ZERO);
    let input_ranges_it = in_int.iter().any(|i| {
        (i.bus_name == bus::RANGE8.name() || i.bus_name == bus::AND4.name()) && i.fields.iter().any(|f| depends(f, &forged, Slot::Cur, input::col::WORD, &mut rng))
    });

    // The cpu's SYS_READ row, and its successor.
    let (wc, hc) = (cpu::col::WIDTH, t.cpu.height());
    let r = (0..hc).find(|r| t.cpu.values[r * wc + cpu::col::SYS_READ] == Val::ONE).expect("the program reads input 0");
    let mut cpu_forged = Rows { cur: row(&t.cpu, r), next: row(&t.cpu, r + 1), pre_cur: vec![], pre_next: vec![], public: t.public_values.clone() };
    let before = Rows { cur: row(&t.cpu, r - 1), next: cpu_forged.cur.clone(), pre_cur: vec![], pre_next: vec![], public: t.public_values.clone() };
    assert_eq!(cpu_forged.cur[cpu::col::C], Val::from_u32(5));
    cpu_forged.cur[cpu::col::C] = Val::from_u64(NOT_U32);
    let mut before_forged = before.clone();
    before_forged.next[cpu::col::C] = Val::from_u64(NOT_U32);
    let (cpu_int, cpu_con) = symbolic_air(&cpu::CpuAir);
    let cpu_holds = cpu_con.iter().all(|c| eval_rows(c, &cpu_forged) == Val::ZERO && eval_rows(c, &before_forged) == Val::ZERO);
    let cpu_ranges_it = cpu_int.iter().any(|i| {
        eval_rows(&i.count, &cpu_forged) != Val::ZERO
            && (i.bus_name == bus::RANGE8.name() || i.bus_name == bus::AND4.name())
            && i.fields.iter().any(|f| depends(f, &cpu_forged, Slot::Cur, cpu::col::C, &mut rng))
    });
    eprintln!(
        "input row with WORD = 2^32 + 5: constraints hold = {input_holds}, range-checked = {input_ranges_it}; \
         SYS_READ row with C = 2^32 + 5: constraints hold = {cpu_holds}, range-checked = {cpu_ranges_it}"
    );
    assert_eq!(Val::from_u64(NOT_U32).as_canonical_u64(), NOT_U32);
    assert!(
        !(input_holds && !input_ranges_it && cpu_holds && !cpu_ranges_it),
        "a non-u32 input word is accepted: the input table and the SYS_READ row both hold with WORD = C = 2^32 + 5, and no range bus carries it"
    );
}

/// The `POSEIDON2` syscall hashes `n` words as `n` field elements from the all-zero state, with no
/// length anywhere, so within the first rate block `[a]` and `[a, 0]` — and `[]`, whose digest is
/// the zero state unpermuted — are not told apart (HCS-4; ZKH-3 documented it and warned the guest
/// SDK). Every in-repo caller encodes its length itself, so nothing live is broken; but a guest
/// written against "hash these words" is. Checked here end to end on the emulator, i.e. the
/// semantics the chip proves: the two digests the guest gets back are equal.
#[test]
#[ignore = "HCS-4: POSEIDON2 does not bind the message length — closed only by a new syscall or the next constraint set (docs/05-roadmap.md)"]
fn poseidon2_binds_the_message_length() {
    const AT: i32 = 0x1000;
    let digest_of = |msg: &[u32]| -> Vec<u32> {
        let mut a = Assembler::new(0);
        a.extend(li(8, AT));
        for (k, w) in msg.iter().enumerate() {
            a.extend(li(5, *w as i32));
            a.push(sw(8, 5, 4 * k as i32));
        }
        a.extend(call_poseidon2(AT / 4, msg.len()));
        for k in 0..8 {
            a.push(lw(5, 8, 4 * k));
            a.extend(write_output(k as u32, 5));
        }
        a.extend(halt());
        execute(&a.assemble(), &[], &[], 100_000).unwrap().outputs.to_vec()
    };
    let a = 0x0dea_dbee;
    let (one, padded, empty) = (digest_of(&[a]), digest_of(&[a, 0]), digest_of(&[]));
    eprintln!("POSEIDON2([a]) = {one:08x?}\nPOSEIDON2([a, 0]) = {padded:08x?}\nPOSEIDON2([]) = {empty:08x?}");
    assert_ne!(one, padded, "[a] and [a, 0] hash to the same digest");
    assert_ne!(empty, vec![0; 8], "the empty message hashes to the zero digest");
}
