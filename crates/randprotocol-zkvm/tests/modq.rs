//! `MODQ` (private multisig phase 3): the host reference semantics, the emulator syscall, the chip
//! standalone, and the machine wiring. Free of `dilithium-core` so the fullnode can vendor it.
use randprotocol_zkvm::modq::{self, Args, ModqError, Op, Poly, Q};

pub fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x }
}
pub fn poly(next: &mut impl FnMut() -> u64, bound: u32) -> Poly {
    core::array::from_fn(|_| (next() % bound as u64) as u32)
}
fn pow(b: u64, mut e: u64) -> u64 {
    let (mut r, mut b) = (1u64, b % Q as u64);
    while e > 0 { if e & 1 == 1 { r = r * b % Q as u64; } b = b * b % Q as u64; e >>= 1; }
    r
}
fn brv8(k: usize) -> u64 { (k as u8).reverse_bits() as u64 }

#[test]
fn zeta_is_1753_to_the_bit_reversed_index() {
    for k in 1..256 { assert_eq!(modq::zeta(k) as u64, pow(1753, brv8(k)), "k = {k}"); }
}

#[test]
fn ntt_evaluates_at_the_odd_powers_of_psi() {
    let mut next = rng(1);
    let a = poly(&mut next, Q);
    let mut hat = a;
    modq::ntt(&mut hat);
    for i in (0..256).step_by(17) {
        let r = pow(1753, 2 * brv8(i) + 1);
        let (mut acc, mut x) = (0u64, 1u64);
        for j in 0..256 { acc = (acc + a[j] as u64 * x) % Q as u64; x = x * r % Q as u64; }
        assert_eq!(hat[i] as u64, acc, "index {i}");
    }
}

#[test]
fn intt_inverts_ntt_and_every_output_is_canonical() {
    let mut next = rng(2);
    for _ in 0..50 {
        let a = poly(&mut next, Q);
        let mut x = a;
        modq::ntt(&mut x);
        assert!(x.iter().all(|&c| c < Q));
        modq::intt(&mut x);
        assert_eq!(x, a);
    }
}

#[test]
fn inputs_below_2_pow_24_are_read_mod_q() {
    let mut next = rng(3);
    let raw = poly(&mut next, modq::INPUT_BOUND);
    let reduced: Poly = core::array::from_fn(|i| raw[i] % Q);
    let (mut x, mut y) = (raw, reduced);
    modq::ntt(&mut x);
    modq::ntt(&mut y);
    assert_eq!(x, y);
    let (mut x, mut y) = (raw, reduced);
    modq::intt(&mut x);
    modq::intt(&mut y);
    assert_eq!(x, y);
}

#[test]
fn dot4_and_msub4_match_schoolbook_mod_q() {
    let mut next = rng(4);
    let a: [Poly; 4] = core::array::from_fn(|_| poly(&mut next, modq::INPUT_BOUND));
    let b: [Poly; 4] = core::array::from_fn(|_| poly(&mut next, modq::INPUT_BOUND));
    let c = poly(&mut next, modq::INPUT_BOUND);
    let d = modq::dot4(&a, &b);
    let mut w = a;
    modq::msub4(&mut w, &c, &b);
    let q = Q as u64;
    for i in 0..256 {
        let want: u64 = (0..4).map(|k| (a[k][i] as u64 % q) * (b[k][i] as u64 % q) % q).sum::<u64>() % q;
        assert_eq!(d[i] as u64, want);
        for k in 0..4 {
            let sub = (c[i] as u64 % q) * (b[k][i] as u64 % q) % q;
            assert_eq!(w[k][i] as u64, (a[k][i] as u64 % q + q - sub) % q);
        }
    }
}

#[test]
fn the_stages_start_at_the_input_and_end_at_the_transform() {
    let mut next = rng(5);
    let a = poly(&mut next, modq::INPUT_BOUND);
    let (s, t) = (modq::ntt_stages(&a), modq::intt_stages(&a));
    let (mut x, mut y) = (a, a);
    modq::ntt(&mut x);
    modq::intt(&mut y);
    assert_eq!((s[0], s[8], t[0], t[8]), (a, x, a, y));
    for p in 1..9 { assert!(s[p].iter().chain(t[p].iter()).all(|&c| c < Q), "stage {p} canonical"); }
}

#[test]
fn args_round_trip_and_reject_every_reserved_bit() {
    for (op, out, a, b) in [(Op::Ntt, 3, 0, 0), (Op::Intt, 31, 0, 0), (Op::Dot4, 8, 0, 4), (Op::Msub4, 0, 8, 4)] {
        let args = Args { op, out, a, b };
        assert_eq!(Args::decode(args.encode()), Some(args));
    }
    for bit in [2u32, 7, 13, 15, 21, 23, 29, 31] {
        assert_eq!(Args::decode(Args { op: Op::Dot4, out: 8, a: 0, b: 4 }.encode() | 1 << bit), None, "bit {bit}");
    }
    assert_eq!(Args::decode(Args { op: Op::Ntt, out: 0, a: 1, b: 0 }.encode()), None, "a transform names one poly");
}

#[test]
fn call_reads_each_input_once_and_refuses_what_the_air_cannot_prove() {
    let base = 0x1000;
    let ram = |a: u32| (a.wrapping_mul(2_654_435_761) >> 9) % modq::INPUT_BOUND;
    let io = modq::call(base, Args { op: Op::Dot4, out: 8, a: 0, b: 4 }.encode(), ram).unwrap();
    assert_eq!((io.inputs.len(), io.reads.len(), io.writes.len()), (8, 2048, 256));
    let mut addrs: Vec<u32> = io.reads.iter().map(|r| r.0).collect();
    addrs.sort();
    addrs.dedup();
    assert_eq!(addrs.len(), 2048, "no address is read twice at one timestamp");
    let dot = Args { op: Op::Dot4, out: 8, a: 0, b: 3 }.encode();
    assert_eq!(modq::call(base, dot, ram), Err(ModqError::Alias(dot)));
    let msub = Args { op: Op::Msub4, out: 0, a: 2, b: 4 }.encode();
    assert_eq!(modq::call(base, msub, ram), Err(ModqError::Alias(msub)));
    let big = |a: u32| if a == base + 7 { 1 << 24 } else { 0 };
    assert_eq!(modq::call(base, 0, big), Err(ModqError::Coefficient { addr: base + 7, value: 1 << 24 }));
    assert_eq!(modq::call(base, 1 << 2, ram), Err(ModqError::Args(1 << 2)));
}

#[test]
#[should_panic(expected = "poly index past 5 bits")]
fn encode_refuses_a_field_that_would_spill_into_another() {
    let _ = Args { op: Op::Ntt, out: 32, a: 0, b: 0 }.encode();
}

#[test]
#[should_panic(expected = "zeta index 256 out of range")]
fn zeta_refuses_an_index_past_255() {
    let _ = modq::zeta(256);
}

mod common;

mod emulator {
    use super::common::modq_program;
    use randprotocol_zkvm::asm::{ops::*, Assembler};
    use randprotocol_zkvm::emulator::{execute, ExecError, Syscall, MODQ_PTR_LIMIT, SPACE_RAM};
    use randprotocol_zkvm::modq::{self, Args, Op};

    pub const NTT0: u32 = 0;
    pub const INTT1: u32 = 1 | 1 << 8;
    pub const DOT_8_0_4: u32 = 2 | 8 << 8 | 4 << 24;
    pub const MSUB_0_8_4: u32 = 3 | 8 << 16 | 4 << 24;

    fn ram_after_fill(addr: u32) -> u32 {
        let i = addr - 0x1000;
        if i < 9 * 256 { 3 + 7001 * i } else { 0 }
    }

    #[test]
    fn every_op_in_the_emulator_matches_the_host_model() {
        for a1 in [NTT0, INTT1, DOT_8_0_4, MSUB_0_8_4] {
            let e = execute(&modq_program(&[a1]), &[], &[], 1 << 16).unwrap();
            let ev = e.events.iter().find(|e| e.modq.is_some()).expect("one MODQ row");
            assert_eq!(ev.sys, Some(Syscall::Modq { base: 0x1000, a1 }));
            let call = ev.modq.as_ref().unwrap();
            let io = modq::call(0x1000, a1, ram_after_fill).unwrap();
            assert_eq!(call.inputs, io.inputs, "a1 = {a1:#x}");
            let writes: Vec<(u32, u32)> = call.accesses.iter().filter(|a| a.is_write).map(|a| (a.addr, a.value)).collect();
            assert_eq!(writes, io.writes, "a1 = {a1:#x}");
        }
    }

    #[test]
    fn accesses_are_ram_reads_at_slot_0_then_writes_at_slot_1() {
        let e = execute(&modq_program(&[MSUB_0_8_4]), &[], &[], 1 << 16).unwrap();
        let call = e.events.iter().find_map(|e| e.modq.as_ref()).unwrap();
        let first_write = call.accesses.iter().position(|a| a.is_write).unwrap();
        assert_eq!((first_write, call.accesses.len()), (2304, 2304 + 1024));
        assert!(call.accesses.iter().all(|a| a.space == SPACE_RAM && a.slot == a.is_write as u32));
    }

    #[test]
    fn modq_refuses_reserved_bits() {
        let bad = DOT_8_0_4 | 1 << 5;
        assert_eq!(execute(&modq_program(&[bad]), &[], &[], 1 << 16).unwrap_err(), ExecError::ModqArgs(bad));
    }

    #[test]
    fn modq_refuses_overlapping_dot_operands() {
        let bad = Args { op: Op::Dot4, out: 8, a: 0, b: 2 }.encode();
        assert_eq!(execute(&modq_program(&[bad]), &[], &[], 1 << 16).unwrap_err(), ExecError::ModqAlias(bad));
    }

    #[test]
    fn modq_refuses_msub_aliasing() {
        let bad = Args { op: Op::Msub4, out: 0, a: 4, b: 4 }.encode();
        assert_eq!(execute(&modq_program(&[bad]), &[], &[], 1 << 16).unwrap_err(), ExecError::ModqAlias(bad));
    }

    #[test]
    fn modq_refuses_a_coefficient_of_2_pow_24() {
        let mut a = Assembler::new(0);
        a.extend(li(5, 0x4000));
        a.extend(li(8, 1 << 24));
        a.push(sw(5, 8, 12));
        a.extend(call_modq(0x1000, NTT0));
        a.extend(halt());
        let err = execute(&a.assemble(), &[], &[], 1 << 16).unwrap_err();
        assert_eq!(err, ExecError::ModqCoefficient { addr: 0x1003, value: 1 << 24 });
    }

    #[test]
    fn modq_refuses_a_base_past_the_limit() {
        let mut a = Assembler::new(0);
        a.extend(call_modq(MODQ_PTR_LIMIT + 1, NTT0));
        a.extend(halt());
        assert_eq!(execute(&a.assemble(), &[], &[], 1 << 16).unwrap_err(), ExecError::ModqPtrOutOfRange(MODQ_PTR_LIMIT + 1));
        let mut a = Assembler::new(0);
        a.extend(call_modq(MODQ_PTR_LIMIT, NTT0));
        a.extend(halt());
        assert!(execute(&a.assemble(), &[], &[], 1 << 16).is_ok(), "the limit itself is legal");
    }
}

mod harness {
    use super::common::rejects;
    use super::emulator::{DOT_8_0_4, INTT1, MSUB_0_8_4, NTT0};
    use super::common::modq_run::run_raw;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use randprotocol_zkvm::emulator::SPACE_RAM;
    use randprotocol_zkvm::machine::VerifyError;
    use randprotocol_zkvm::modq::{self, CallIo};
    use randprotocol_zkvm::tables::modq::{col, limbs_value, modq_log_height, modq_trace, pre, ModqAir, ModqEvent, BLOCK};
    use randprotocol_zkvm::tables::range::RangeCounts;
    use randprotocol_zkvm::tables::F;

    /// Four calls at clk 11..15 on one deterministic RAM (no call's outputs feed another here).
    pub fn calls() -> Vec<(ModqEvent, CallIo)> {
        let ram = |a: u32| (a.wrapping_mul(2_654_435_761) >> 9) % modq::INPUT_BOUND;
        [NTT0, INTT1, DOT_8_0_4, MSUB_0_8_4].iter().enumerate().map(|(i, &a1)| {
            let io = modq::call(0x1000, a1, ram).unwrap();
            (ModqEvent { clk: 11 + i as u32, base: 0x1000, a1, inputs: io.inputs.clone() }, io)
        }).collect()
    }

    pub fn twin(calls: &[(ModqEvent, CallIo)]) -> RowMajorMatrix<F> {
        let rows: Vec<(u32, u32, u32, bool)> = calls.iter().flat_map(|(ev, io)| {
            io.reads.iter().map(move |&(a, x)| (a, 4 * ev.clk, x, false))
                .chain(io.writes.iter().map(move |&(a, x)| (a, 4 * ev.clk + 1, x, true)))
        }).collect();
        let mut v = F::zero_vec(rows.len().next_power_of_two() * 6);
        for (i, &(addr, ts, val, w)) in rows.iter().enumerate() {
            v[i * 6..(i + 1) * 6].copy_from_slice(&[F::ONE, F::from_u32(SPACE_RAM), F::from_u32(addr), F::from_u32(ts), F::from_u32(val), F::from_bool(w)]);
        }
        RowMajorMatrix::new(v, 6)
    }

    pub fn run(trace: &RowMajorMatrix<F>, range: &RangeCounts, calls: &[(ModqEvent, CallIo)], twin: &RowMajorMatrix<F>) -> Result<(), VerifyError> {
        let asks: Vec<(u32, u32, u32)> = calls.iter().map(|(ev, _)| (ev.clk, ev.base, ev.a1)).collect();
        run_raw(trace, range, &asks, twin)
    }

    fn built() -> (Vec<(ModqEvent, CallIo)>, RowMajorMatrix<F>, RangeCounts) {
        let c = calls();
        let evs: Vec<ModqEvent> = c.iter().map(|x| x.0.clone()).collect();
        let mut range = RangeCounts::default();
        let t = modq_trace(&evs, modq_log_height(evs.len()), &mut range);
        (c, t, range)
    }

    #[test]
    fn modq_log_height_is_zero_without_calls_and_floors_at_one_block() {
        assert_eq!([0, 1, 2, 3, 18, 36, 54].map(modq_log_height), [0, 10, 11, 12, 15, 16, 16]);
    }

    #[test]
    fn the_trace_writes_exactly_what_the_host_model_computes() {
        let (c, t, _) = built();
        let p = ModqAir::preprocessed_trace_at::<F>(BLOCK);
        for (b, (_, io)) in c.iter().enumerate() {
            let mut got = Vec::new();
            for r in 0..BLOCK {
                let row = &t.values[(b * BLOCK + r) * col::WIDTH..(b * BLOCK + r + 1) * col::WIDTH];
                let pr = &p.values[r * pre::WIDTH..(r + 1) * pre::WIDTH];
                let is_t = row[col::IS_NTT] + row[col::IS_INTT] == F::ONE;
                let w0 = (is_t && pr[pre::S_LAST] == F::ONE) || (row[col::IS_DOT] == F::ONE && pr[pre::K_LAST] == F::ONE);
                let w1 = (is_t && pr[pre::S_LAST] == F::ONE) || row[col::IS_MSUB] == F::ONE;
                if w0 { got.push((limbs_value(row, col::ADDR_O0, 1) as u32, limbs_value(row, col::O0_L, 3) as u32)); }
                if w1 { got.push((limbs_value(row, col::ADDR_O1, 1) as u32, limbs_value(row, col::O1_L, 3) as u32)); }
            }
            got.sort();
            let mut want = io.writes.clone();
            want.sort();
            assert_eq!(got, want, "block {b}");
        }
    }

    /// The read side (Task 2 review minor): every `MEMORY` read the chip sends — address and value,
    /// at the rule-6 counts — is exactly one of `modq::call`'s reads, and every one of those is sent.
    #[test]
    fn the_trace_reads_exactly_what_the_host_model_reads() {
        let (c, t, _) = built();
        let p = ModqAir::preprocessed_trace_at::<F>(BLOCK);
        for (b, (_, io)) in c.iter().enumerate() {
            let mut got = Vec::new();
            for r in 0..BLOCK {
                let row = &t.values[(b * BLOCK + r) * col::WIDTH..(b * BLOCK + r + 1) * col::WIDTH];
                let pr = &p.values[r * pre::WIDTH..(r + 1) * pre::WIDTH];
                let is_t = row[col::IS_NTT] + row[col::IS_INTT] == F::ONE;
                let (dot, msub) = (row[col::IS_DOT] == F::ONE, row[col::IS_MSUB] == F::ONE);
                let s_first = pr[pre::S_FIRST] == F::ONE;
                let k_first = pr[pre::K_FIRST] == F::ONE;
                if (is_t && s_first) || msub { got.push((limbs_value(row, col::ADDR_U, 1) as u32, limbs_value(row, col::U_L, 3) as u32)); }
                if (is_t && s_first) || dot || msub { got.push((limbs_value(row, col::ADDR_V, 1) as u32, limbs_value(row, col::V_L, 3) as u32)); }
                if dot || (msub && k_first) { got.push((limbs_value(row, col::ADDR_W, 1) as u32, limbs_value(row, col::W_L, 3) as u32)); }
            }
            got.sort();
            let mut want = io.reads.clone();
            want.sort();
            assert_eq!(got, want, "block {b}");
        }
    }

    #[test]
    fn padding_blocks_are_all_zero_selectors() {
        let c = calls();
        let mut range = RangeCounts::default();
        let t = modq_trace(&[c[0].0.clone()], 11, &mut range);
        for r in BLOCK..2 * BLOCK {
            let row = &t.values[r * col::WIDTH..(r + 1) * col::WIDTH];
            assert!([col::IS_REAL, col::IS_NTT, col::IS_INTT, col::IS_DOT, col::IS_MSUB, col::A1].iter().all(|&i| row[i] == F::ZERO));
        }
    }

    #[test]
    fn the_modq_chip_proves_every_op_standalone() {
        let (c, t, range) = built();
        run(&t, &range, &c, &twin(&c)).unwrap();
    }

    #[test]
    fn a_tampered_output_limb_is_rejected_standalone() {
        let (c, mut t, range) = built();
        t.values[(3 * 128 + 5) * col::WIDTH + col::O0_L] += F::ONE;
        assert!(rejects(|| run(&t, &range, &c, &twin(&c))));
    }

    #[test]
    fn a_memory_value_the_chip_did_not_read_is_rejected_standalone() {
        let (c, t, range) = built();
        let mut tw = twin(&c);
        tw.values[4] += F::ONE;
        assert!(rejects(|| run(&t, &range, &c, &tw)));
    }
}

mod machine {
    use super::common::modq_program;
    use super::emulator::{DOT_8_0_4, INTT1, MSUB_0_8_4, NTT0};
    use randprotocol_zkvm::guests;
    use randprotocol_zkvm::machine::{FriProfile, Machine, ProveOptions, Tier};

    #[test]
    fn a_guest_calling_every_op_proves_and_verifies() {
        let m = Machine::new(FriProfile::Test);
        let p = modq_program(&[NTT0, INTT1, DOT_8_0_4, MSUB_0_8_4]);
        let (proof, exec) = m.prove(&p, &[], &[], Some(Tier(14))).unwrap();
        assert_eq!(exec.events.iter().filter(|e| e.modq.is_some()).count(), 4);
        assert_eq!(proof.modq_log_height, 12, "four 1024-row blocks");
        m.verify(&p.digest(), &proof).unwrap();
    }

    #[test]
    fn a_modq_free_proof_declares_no_modq_table() {
        let m = Machine::new(FriProfile::Test);
        let p = guests::fib(10);
        let (proof, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
        assert_eq!(proof.modq_log_height, 0);
        assert_eq!(proof.batch.degree_bits.len(), 9, "program, cpu, memory, alu, range, nibble, poseidon2, input, public");
        m.verify(&p.digest(), &proof).unwrap();
    }

    #[test]
    fn height_floors_pin_the_declared_shape() {
        let m = Machine::new(FriProfile::Test);
        let p = modq_program(&[NTT0]);
        let opts = ProveOptions { min_modq_log_height: 13, min_keccak_log_height: 9, min_mem_log_height: 18, ..Default::default() };
        let (proof, _) = m.prove_with_options(&p, &[], &[], Some(Tier(14)), opts).unwrap();
        assert_eq!(proof.modq_log_height, 13, "one call padded to eight blocks");
        assert_eq!(proof.keccak_log_height, 9, "a keccak-free run declares an idle table at the floor");
        assert_eq!(proof.mem_log_height, 18, "above the tier floor t + 2 = 16");
        m.verify(&p.digest(), &proof).unwrap();
    }

    #[test]
    fn the_old_key_api_is_the_modq_free_case_of_the_new_one() {
        let m = Machine::new(FriProfile::Test);
        let a = m.verifier_key(Tier(10), 7, 7, 0, 0, 7);
        let b = m.verifier_key_with_modq(Tier(10), 7, 7, 0, 0, 0, 7);
        assert!(std::sync::Arc::ptr_eq(&a, &b), "one cache slot");
        let c = m.verifier_key_with_modq(Tier(10), 7, 7, 0, 0, 10, 7);
        assert!(!std::sync::Arc::ptr_eq(&a, &c));
        assert_eq!(m.cached_keys(), 2);
        assert_eq!(randprotocol_zkvm::gas::gas_max(Tier(12), 5, 0), randprotocol_zkvm::gas::gas_max_with_modq(Tier(12), 5, 0, 0));
        assert_eq!(Tier(10).max_modq_log_height(), 20);
    }

    #[test]
    fn a_modq_row_costs_modq_gas() {
        let p = modq_program(&[NTT0]);
        let e = randprotocol_zkvm::emulator::execute(&p, &[], &[], 1 << 16).unwrap();
        let row = e.events.iter().find(|e| e.modq.is_some()).unwrap();
        assert_eq!(randprotocol_zkvm::gas::row_gas(row), randprotocol_zkvm::gas::MODQ_GAS);
        assert_eq!(randprotocol_zkvm::gas::gas_max_with_modq(Tier(10), 0, 0, 10) - randprotocol_zkvm::gas::gas_max(Tier(10), 0, 0), randprotocol_zkvm::gas::MODQ_GAS - 1);
    }

    /// The `MODQ` bus has no provider when the batch declares no modq table, so a cpu `SYS_MODQ`
    /// row's claim cannot balance: dropping the table from an honest trace set (with the gas limit
    /// set to the run's own gas, so the header's gas ceiling is not what refuses it) leaves a
    /// batch that either fails to prove or fails to verify.
    #[test]
    fn a_modq_row_without_a_modq_table_is_rejected() {
        use randprotocol_zkvm::machine::build_traces_salted_with;
        use p3_field::PrimeCharacteristicRing;
        use randprotocol_zkvm::tables::cpu::col;
        let m = Machine::new(FriProfile::Test);
        let p = modq_program(&[NTT0]);
        let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(14).max_cycles()).unwrap();
        let gas = randprotocol_zkvm::gas::gas_of(&p, &[], &[], &exec.events);
        let opts = ProveOptions { gas_limit: Some(gas), ..Default::default() };
        let mut t = build_traces_salted_with(&p, &[], &[], [0; 4], &exec, Tier(14), opts).unwrap();
        assert_eq!(t.modq_log_height, 10);
        let w = col::WIDTH;
        assert!((0..t.cpu.values.len() / w).any(|r| t.cpu.values[r * w + col::SYS_MODQ] == randprotocol_zkvm::tables::F::ONE), "the syscall row stays");
        // Non-vacuity: the same traces, untampered, prove and verify at this gas limit.
        m.verify(&p.digest(), &m.prove_traces(&p, &t, Tier(14))).expect("the honest traces verify");
        t.modq = None;
        t.modq_log_height = 0;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let pr = m.prove_traces(&p, &t, Tier(14));
            assert_eq!(pr.modq_log_height, 0);
            m.verify(&p.digest(), &pr)
        }));
        eprintln!("modq-less outcome: {:?}", outcome.as_ref().map(|r| r.as_ref().map_err(|e| format!("{e:?}").chars().take(200).collect::<String>())));
        assert!(!matches!(outcome, Ok(Ok(()))), "a SYS_MODQ row with no modq table must not verify");
    }

    /// `modq_log_height` is untrusted: a non-zero value outside `[MIN_LOG_HEIGHT,
    /// Tier::max_modq_log_height]` is `ModqHeight`, and `verify` refuses it before building a key.
    #[test]
    fn an_out_of_range_modq_height_is_rejected() {
        use randprotocol_zkvm::machine::{check_declared_heights_with_modq, VerifyError};
        use randprotocol_zkvm::tables::modq::{MAX_LOG_HEIGHT, MIN_LOG_HEIGHT};
        let c = |t: usize, mlh: u8| check_declared_heights_with_modq(Tier(t), 7, 7, 0, 0, mlh, 7, (t + 2) as u8);
        for t in [10, 20] {
            assert_eq!(c(t, 0), Ok(()), "0 is no modq table");
            assert_eq!(c(t, MIN_LOG_HEIGHT), Ok(()));
            assert_eq!(c(t, MAX_LOG_HEIGHT), Ok(()));
            for bad in [1, MIN_LOG_HEIGHT - 1, MAX_LOG_HEIGHT + 1, 40, 255] {
                assert_eq!(c(t, bad), Err(VerifyError::ModqHeight), "tier {t}, mlh {bad}");
            }
        }
        // Through `verify`, on a modq-free proof whose header (and degree bits) claim a 2^21 table.
        let prover = Machine::new(FriProfile::Test);
        let p = guests::fib(10);
        let (mut proof, _) = prover.prove(&p, &[], &[], Some(Tier(10))).unwrap();
        proof.modq_log_height = MAX_LOG_HEIGHT + 1;
        let public = proof.batch.degree_bits.pop().unwrap();
        proof.batch.degree_bits.push(MAX_LOG_HEIGHT as usize + 2);
        proof.batch.degree_bits.push(public);
        let verifier = Machine::new(FriProfile::Test);
        assert_eq!(verifier.verify(&p.digest(), &proof), Err(VerifyError::ModqHeight));
        assert_eq!(verifier.cached_keys(), 0, "the range check precedes the verifier key");
    }
}

/// Reads the docs at run time, not with `include_str!`: `deploy/sync-zkvm.sh` vendors this file into
/// the fullnode, where `docs/` does not exist, and the check is skipped there.
#[test]
fn the_docs_name_the_chip_where_the_isa_and_tables_are_documented() {
    let doc = |f: &str| std::fs::read_to_string(format!("{}/docs/{f}", env!("CARGO_MANIFEST_DIR")));
    let (Ok(isa), Ok(tables), Ok(roadmap)) = (doc("01-isa.md"), doc("02-tables-and-buses.md"), doc("05-roadmap.md")) else {
        eprintln!("docs/ not present (a vendored copy): skipped");
        return;
    };
    assert!(isa.contains("| 8 | `MODQ base a1`"), "01-isa.md syscall table row 8");
    assert!(tables.contains("## `modq` — main, `col::WIDTH = 59`"), "02-tables-and-buses.md modq section");
    assert!(tables.contains("`MODQ_WIRE`"), "the bus catalogue");
    let row8 = isa.lines().find(|l| l.starts_with("| 8 | `MODQ base a1`")).unwrap();
    assert!(row8.contains("| 168 |"), "row 8 carries MODQ_GAS");
    assert!(roadmap.contains("## Constraint set: the MODQ chip"), "05-roadmap.md MODQ section");
    assert_eq!(randprotocol_zkvm::tables::modq::col::WIDTH, 59);
    assert_eq!(randprotocol_zkvm::tables::cpu::col::WIDTH, 283);
}

/// Measurement (not a gate): tier-10 proof sizes for the roadmap's "Proof-size deltas (measured)"
/// table. Run with `-- --ignored --nocapture`; prints `MODQ-SIZE profile=<p> kind=<k> bytes=<n>`.
#[test]
#[ignore]
fn measure_modq_proof_sizes_at_tier_10() {
    use randprotocol_zkvm::asm::{ops::*, Assembler};
    use randprotocol_zkvm::guests;
    use randprotocol_zkvm::machine::{FriProfile, Machine, Tier};
    for (name, profile) in [("Test", FriProfile::Test), ("Production", FriProfile::Production)] {
        let m = Machine::new(profile);
        let p = guests::fib(10);
        let (proof, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
        assert_eq!(proof.modq_log_height, 0);
        m.verify(&p.digest(), &proof).unwrap();
        println!("MODQ-SIZE profile={name} kind=chip-free bytes={}", proof.size());

        // One NTT call over an all-zero arena: one cycle, one 1 024-row block, inside tier 10.
        let mut a = Assembler::new(0);
        a.extend(call_modq(0x1000, 0));
        a.extend(halt());
        let p = a.assemble();
        let (proof, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
        assert_eq!(proof.modq_log_height, 10, "one block");
        assert_eq!(proof.mem_log_height, 12, "tier 10 memory floor t + 2: the one call does not raise it");
        m.verify(&p.digest(), &proof).unwrap();
        println!("MODQ-SIZE profile={name} kind=one-block bytes={}", proof.size());
    }
}
