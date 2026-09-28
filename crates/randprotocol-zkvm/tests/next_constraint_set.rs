//! The gaps the next constraint set (the chain-16 cut) closes, written as the tests it has to pass.
//! Each began failing by design — `#[ignore]`d with the reason, failing under `--ignored`, the
//! finding pinned — and lost its `#[ignore]` in the commit that closed it (ZKM-1/ZKH-2, HCS-4,
//! ISA-4 on `feat/cs7-range-pad-isa`; each commit quotes the red). Closing a gap is a change to the
//! AIR (so to every verifier key) or to a syscall's semantics (so to every digest a guest computes
//! with it): a chain cut, never a same-chain release. `docs/05-roadmap.md`, "The next constraint
//! set", has the exact constraint each one needed.
mod common;
use common::*;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::isa::REG_A0;
use randprotocol_zkvm::machine::{build_traces_salted, Tier, Val};
use randprotocol_zkvm::tables::{bus, cpu, input, public};

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
/// tables, and no range bus carries the word. The next set's rule makes the first false: the
/// `input` table's `WL0..3` limbs, `RANGE8`-checked, with `WORD` pinned to their sum on a real row
/// (and `C` on the `SYS_READ` row is then a word too, since `INPUT_READ` ties it to `WORD`).
#[test]
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

/// ZKM-1's public-segment half: the `public` table is `input`'s twin (constraint set 6), and its
/// `WORD` was just as unchecked — a `SYS_READ_PUBLIC` row could hand a guest `2^32 + 5` for `5`,
/// and `H_PUB` absorb it. `Machine::verify_public` would catch the forged *digest* against the
/// words a chain publishes (it recomputes `H_PUB` from `u32`s), but a bare `verify` would not, and
/// the guest's register would hold a non-word either way. The same four-limb rule closes it.
#[test]
fn a_non_u32_public_word_is_refused_by_the_air() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x2b_4d32);
    let mut a = Assembler::new(0);
    a.extend(read_public(0));
    a.push(mv(5, REG_A0));
    a.extend(halt());
    let p = a.assemble();
    let e = execute(&p, &[], &[5], 10_000).unwrap();
    let t = build_traces_salted(&p, &[], &[5], [0; 4], &e, Tier(10)).unwrap();

    let row = |m: &p3_matrix::dense::RowMajorMatrix<Val>, r: usize| m.values[(r % m.height()) * m.width()..(r % m.height()) * m.width() + m.width()].to_vec();
    let (pub_int, pub_con) = symbolic_air(&public::PublicAir);
    let mut forged = Rows { cur: row(&t.public, 0), next: row(&t.public, 1), pre_cur: vec![], pre_next: vec![], public: vec![] };
    assert_eq!(forged.cur[public::col::WORD], Val::from_u32(5));
    forged.cur[public::col::WORD] = Val::from_u64(NOT_U32);
    let holds = pub_con.iter().all(|c| eval_boundary(c, &forged, true, false) == Val::ZERO);
    let ranges_it = pub_int.iter().any(|i| {
        (i.bus_name == bus::RANGE8.name() || i.bus_name == bus::AND4.name()) && i.fields.iter().any(|f| depends(f, &forged, Slot::Cur, public::col::WORD, &mut rng))
    });
    eprintln!("public row with WORD = 2^32 + 5: constraints hold = {holds}, range-checked = {ranges_it}");
    assert!(!(holds && !ranges_it), "a non-u32 public word is accepted: the public table holds with WORD = 2^32 + 5 and no range bus carries it");
}

/// The salt row's four lanes (`IS_SALT`, the first indigest row) are free witness words that `H_IN`
/// absorbs — `hash::input_digest` takes the salt as four `u32`s, but nothing in-circuit held the
/// row's `HV0..3` to that, so `H_IN` could commit to a salt no `u32` salt reproduces. Closed by the
/// write-back rows' own byte-limb columns (`HVL0_0..15`), reused on the salt row.
#[test]
fn a_non_u32_salt_lane_is_refused_by_the_air() {
    let mut a = Assembler::new(0);
    a.extend(read_input(0));
    a.extend(halt());
    let p = a.assemble();
    let e = execute(&p, &[5], &[], 10_000).unwrap();
    let t = build_traces_salted(&p, &[5], &[], [7, 8, 9, 10], &e, Tier(10)).unwrap();

    let row = |m: &p3_matrix::dense::RowMajorMatrix<Val>, r: usize| m.values[(r % m.height()) * m.width()..(r % m.height()) * m.width() + m.width()].to_vec();
    let (wc, hc) = (cpu::col::WIDTH, t.cpu.height());
    let r = (0..hc).find(|r| t.cpu.values[r * wc + cpu::col::IS_SALT] == Val::ONE).expect("every proof has a salt row");
    let (cpu_int, cpu_con) = symbolic_air(&cpu::CpuAir);
    let mut held = true;
    let mut ranged = false;
    for k in 0..4 {
        let mut forged = Rows { cur: row(&t.cpu, r), next: row(&t.cpu, r + 1), pre_cur: vec![], pre_next: vec![], public: t.public_values.clone() };
        let mut before = Rows { cur: row(&t.cpu, r - 1), next: forged.cur.clone(), pre_cur: vec![], pre_next: vec![], public: t.public_values.clone() };
        assert_eq!(forged.cur[cpu::col::HV0 + k], Val::from_u32(7 + k as u32));
        forged.cur[cpu::col::HV0 + k] = Val::from_u64(NOT_U32);
        before.next[cpu::col::HV0 + k] = Val::from_u64(NOT_U32);
        held &= cpu_con.iter().all(|c| eval_rows(c, &forged) == Val::ZERO && eval_rows(c, &before) == Val::ZERO);
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x2b_4d33 + k as u64);
        ranged |= cpu_int.iter().any(|i| {
            eval_rows(&i.count, &forged) != Val::ZERO
                && (i.bus_name == bus::RANGE8.name() || i.bus_name == bus::AND4.name())
                && i.fields.iter().any(|f| depends(f, &forged, Slot::Cur, cpu::col::HV0 + k, &mut rng))
        });
    }
    eprintln!("salt row with one lane = 2^32 + 5: constraints hold = {held}, range-checked = {ranged}");
    assert!(!(held && !ranged), "a non-u32 salt lane is accepted: the salt row holds with a lane = 2^32 + 5 and no range bus carries it");
}

/// The `POSEIDON2` syscall hashes `n` words as `n` field elements from the all-zero state, with no
/// length anywhere, so within the first rate block `[a]` and `[a, 0]` — and `[]`, whose digest is
/// the zero state unpermuted — are not told apart (HCS-4; ZKH-3 documented it and warned the guest
/// SDK). `POSEIDON2` stays exactly that — every note commitment, nullifier, Merkle root and `hc` is
/// built on it — and the next constraint set adds `POSEIDON2_LEN` (7) beside it, whose sponge
/// starts with the length in capacity lane 4 and always permutes at least once. Checked here end
/// to end on the emulator, i.e. the semantics the chip proves, for the new syscall: the digests of
/// `[a]` and `[a, 0]` differ, the empty message's is not zero, and each is `hash::sponge_hash_len`.
/// The old syscall's collision is kept as a pin (`POSEIDON2` must not change).
#[test]
fn poseidon2_binds_the_message_length() {
    const AT: i32 = 0x1000;
    let digest_of = |msg: &[u32], len_bound: bool| -> Vec<u32> {
        let mut a = Assembler::new(0);
        a.extend(li(8, AT));
        for (k, w) in msg.iter().enumerate() {
            a.extend(li(5, *w as i32));
            a.push(sw(8, 5, 4 * k as i32));
        }
        a.extend(if len_bound { call_poseidon2_len(AT / 4, msg.len()) } else { call_poseidon2(AT / 4, msg.len()) });
        for k in 0..8 {
            a.push(lw(5, 8, 4 * k));
            a.extend(write_output(k as u32, 5));
        }
        a.extend(halt());
        execute(&a.assemble(), &[], &[], 100_000).unwrap().outputs.to_vec()
    };
    let a = 0x0dea_dbee;
    // `POSEIDON2` itself is unchanged: the collision is its specified behaviour.
    assert_eq!(digest_of(&[a], false), digest_of(&[a, 0], false));
    assert_eq!(digest_of(&[], false), vec![0; 8]);
    let (one, padded, empty) = (digest_of(&[a], true), digest_of(&[a, 0], true), digest_of(&[], true));
    eprintln!("POSEIDON2_LEN([a]) = {one:08x?}\nPOSEIDON2_LEN([a, 0]) = {padded:08x?}\nPOSEIDON2_LEN([]) = {empty:08x?}");
    assert_ne!(one, padded, "[a] and [a, 0] hash to the same digest");
    assert_ne!(empty, vec![0; 8], "the empty message hashes to the zero digest");
    for msg in [&[a][..], &[a, 0], &[], &[1, 2, 3, 4], &[1, 2, 3, 4, 5]] {
        assert_eq!(digest_of(msg, true), randprotocol_zkvm::hash::sponge_hash_len(msg).to_vec(), "{msg:?}");
    }
}

/// The cpu rows of `guests::poseidon2_demo`/`poseidon2_len_demo(msg)` at tier 10, and the index of
/// the hash group's ecall row.
fn hash_group(msg: &[u32], len_bound: bool) -> (p3_matrix::dense::RowMajorMatrix<Val>, Vec<Val>, usize) {
    let p = if len_bound { randprotocol_zkvm::guests::poseidon2_len_demo(msg) } else { randprotocol_zkvm::guests::poseidon2_demo(msg) };
    let e = execute(&p, &[], &[], 10_000).unwrap();
    let t = build_traces_salted(&p, &[], &[], [0; 4], &e, Tier(10)).unwrap();
    let sel = if len_bound { cpu::col::SYS_HASH_LEN } else { cpu::col::SYS_HASH };
    let w = cpu::col::WIDTH;
    let r = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + sel] == Val::ONE).expect("the hash call's ecall row");
    (t.cpu, t.public_values, r)
}

fn cpu_row(m: &p3_matrix::dense::RowMajorMatrix<Val>, r: usize) -> Vec<Val> { m.values[r * m.width()..(r + 1) * m.width()].to_vec() }

/// Does every cpu constraint hold on the row pair `(cur, next)`?
fn cpu_pair_holds(cur: Vec<Val>, next: Vec<Val>, public: &[Val]) -> bool {
    let (_, con) = symbolic_air(&cpu::CpuAir);
    let rows = Rows { cur, next, pre_cur: vec![], pre_next: vec![], public: public.to_vec() };
    con.iter().all(|c| eval_rows(c, &rows) == Val::ZERO)
}

/// HCS-4, the AIR side: the honest `POSEIDON2_LEN` group's transitions hold, and each of its three
/// new rules refuses its forgery — the length seed (a first absorb row entering the zero state, as
/// a `POSEIDON2` group would), the mandatory empty block (an `n = 0` call routed straight to its
/// write-back rows, publishing the zero digest), and its converse on the old syscall (an `n = 0`
/// `POSEIDON2` call given an empty absorb row, which would publish `perm(0)` for the zero digest).
#[test]
fn the_poseidon2_len_group_rules_refuse_their_forgeries() {
    // Honest: every transition from the ecall row through the second write-back row holds.
    for n in [0usize, 1, 5] {
        let msg: Vec<u32> = (1..=n as u32).collect();
        let (cpu_t, pv, r) = hash_group(&msg, true);
        let rows = 1 + n.div_ceil(4).max(1) + 2;
        for k in r..r + rows { assert!(cpu_pair_holds(cpu_row(&cpu_t, k), cpu_row(&cpu_t, k + 1), &pv), "n={n}: honest row {k}"); }
        assert_eq!(cpu_row(&cpu_t, r + 1)[cpu::col::HS0 + 4], Val::from_u32(n as u32), "n={n}: the seed is the length");
    }

    // The seed: the first absorb row of `POSEIDON2_LEN([1..5])` entering with lane 4 = 0.
    let (cpu_t, pv, r) = hash_group(&[1, 2, 3, 4, 5], true);
    let mut next = cpu_row(&cpu_t, r + 1);
    next[cpu::col::HS0 + 4] = Val::ZERO;
    assert!(!cpu_pair_holds(cpu_row(&cpu_t, r), next, &pv), "a POSEIDON2_LEN group entered the unseeded state");

    // The empty block: `POSEIDON2_LEN([])` with its absorb row cut out, the ecall row followed
    // directly by the first write-back row (whose `HS` is then the unpermuted zero state).
    let (cpu_t, pv, r) = hash_group(&[], true);
    assert_eq!(cpu_row(&cpu_t, r + 1)[cpu::col::IS_HASH], Val::ONE);
    let mut next = cpu_row(&cpu_t, r + 2);
    for i in 0..8 { next[cpu::col::HS0 + i] = Val::ZERO; }
    next[cpu::col::CLK] = cpu_row(&cpu_t, r + 1)[cpu::col::CLK];
    assert!(!cpu_pair_holds(cpu_row(&cpu_t, r), next, &pv), "a POSEIDON2_LEN([]) call skipped its empty block");

    // The converse: `POSEIDON2([])`'s ecall row followed by an empty absorb row — the one
    // `POSEIDON2_LEN([])` has, identical at `n = 0` since the seed is then 0 too.
    let (len_t, _, lr) = hash_group(&[], true);
    let (cpu_t, pv, r) = hash_group(&[], false);
    assert_eq!(cpu_row(&cpu_t, r + 1)[cpu::col::IS_HASH_OUT], Val::ONE, "POSEIDON2([]) has no absorb row");
    let mut next = cpu_row(&len_t, lr + 1);
    next[cpu::col::CLK] = cpu_row(&cpu_t, r + 1)[cpu::col::CLK];
    next[cpu::col::PC] = cpu_row(&cpu_t, r + 1)[cpu::col::PC];
    next[cpu::col::NEXT_PC] = cpu_row(&cpu_t, r + 1)[cpu::col::PC];
    next[cpu::col::HASH_PTR] = cpu_row(&cpu_t, r)[cpu::col::HASH_PTR];
    assert!(!cpu_pair_holds(cpu_row(&cpu_t, r), next, &pv), "a POSEIDON2([]) call absorbed an empty block");
}

/// ISA-4, half one: `JALR` clears bit 0 of its target, as RV32I says — `(rs1 + imm) & !1`. The
/// machine used `rs1 + imm` as computed, so an odd target was an unfetchable `pc` (the emulator's
/// `BadPc`, the AIR's failed `PROGRAM` lookup) where an RV32I core jumps to the even address below
/// it. Checked on the emulator (the reference semantics) and then proved: the cpu's `JALR_B0`
/// column is the bit the target drops.
#[test]
fn a_jalr_to_an_odd_target_clears_bit_0() {
    let mut a = Assembler::new(0);
    // 0: t0 = 13 (the odd address one past the `li t1, 7` at 12); 4: jalr ra, t0, 0; 8: t1 = 1;
    // 12: t1 = 7 — RV32I lands at 12, so the output is 7, and `ra` holds 8.
    a.push(addi(5, 0, 13));
    a.push(jalr(1, 5, 0));
    a.push(addi(6, 0, 1));
    a.push(addi(6, 0, 7));
    a.extend(write_output(0, 6));
    a.extend(write_output(1, 1));
    a.extend(halt());
    let p = a.assemble();
    let e = execute(&p, &[], &[], 10_000).expect("an odd JALR target is RV32I's even one, not a bad pc");
    assert_eq!((e.outputs[0], e.outputs[1]), (7, 8));
    let m = randprotocol_zkvm::machine::Machine::new(randprotocol_zkvm::machine::FriProfile::Test);
    let (proof, _) = m.prove_salted(&p, &[], &[], [0; 4], Some(Tier(10))).expect("it proves");
    m.verify(&p.digest(), &proof).expect("and verifies");
}

/// ISA-4, half two: `JALR` is `funct3 = 0` only. RV32I reserves every other `funct3` under opcode
/// `0x67`; the decoder read the opcode and ignored the field, so eight words decoded to the same
/// `JALR`. Now both decoders refuse them — `Instr::decode` with `DecodeError::Funct`, and the
/// program table's in-circuit decoder by pinning the `JALR` flag to `funct3 = 0`: a row claiming
/// `VALID = 1` under that flag for a `funct3 = 1` word fails its constraints.
#[test]
fn a_jalr_with_a_nonzero_funct3_is_refused() {
    use randprotocol_zkvm::isa::{DecodeError, Instr};
    use randprotocol_zkvm::tables::program;
    let word = Instr::Jalr { rd: 1, rs1: 5, imm: 0 }.encode();
    assert!(Instr::decode(word).is_ok());
    for f3 in 1..8u32 {
        let odd = word | f3 << 12;
        assert_eq!(Instr::decode(odd), Err(DecodeError::Funct(f3)), "funct3 = {f3}");
    }
    // The in-circuit decoder: the honest `funct3 = 0` row, with bit 12 of the word flipped and every
    // decoded field left as a `JALR`'s.
    let (_, con) = symbolic_air(&program::ProgramAir);
    let w = program::col::WIDTH;
    let mut cur = vec![Val::ZERO; w];
    program::fill_word_row(&mut cur, 0, word);
    // `program_trace`'s own bookkeeping on a real row: every valid word is digested once.
    cur[program::col::MULT_WORD] = Val::ONE;
    let mut next = vec![Val::ZERO; w];
    program::fill_word_row(&mut next, 4, 0);
    let holds = |cur: &Vec<Val>| con.iter().all(|c| eval_rows(c, &Rows { cur: cur.clone(), next: next.clone(), pre_cur: vec![], pre_next: vec![], public: vec![] }) == Val::ZERO);
    assert!(holds(&cur), "the honest JALR row holds");
    cur[program::col::WORD] += Val::from_u32(1 << 12);
    cur[program::col::BIT0 + 12] = Val::ONE;
    assert!(!holds(&cur), "a funct3 = 1 JALR decodes as VALID in-circuit");
}
