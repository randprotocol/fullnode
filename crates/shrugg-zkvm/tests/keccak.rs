use shrugg_zkvm::keccak::{keccak256, keccak_f, state_to_words, words_to_state, RC, ROT};

mod common;

#[test]
fn keccak256_matches_known_vectors() {
    assert_eq!(hex::encode(keccak256(b"")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    assert_eq!(hex::encode(keccak256(b"abc")), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    // exactly one rate block minus one byte, and exactly one rate block (two permutations)
    assert_eq!(keccak256(&[0u8; 135]).len(), 32);
    assert_ne!(keccak256(&[0u8; 135]), keccak256(&[0u8; 136]));
}

#[test]
fn keccak_f_matches_p3_keccak_and_words_roundtrip() {
    use p3_symmetric::Permutation;
    let mut s = [0u64; 25];
    for (i, l) in s.iter_mut().enumerate() { *l = 0x0123_4567_89ab_cdef_u64.rotate_left(i as u32 * 3) ^ i as u64; }
    let mut ours = s;
    keccak_f(&mut ours);
    let mut theirs = s;
    p3_keccak::KeccakF.permute_mut(&mut theirs);
    assert_eq!(ours, theirs);
    let w = state_to_words(&s);
    assert_eq!(w[0], s[0] as u32);
    assert_eq!(w[1], (s[0] >> 32) as u32);
    assert_eq!(words_to_state(&w), s);
    assert_eq!(RC[0], 1);
    assert_eq!(RC[23], 0x8000_0000_8000_8008);
    assert_eq!(ROT[0][0], 0);
    assert_eq!(ROT[1][0], 1);
    assert_eq!(ROT[0][1], 36);
}

/// The guest SDK's `keccak256` (`guest-sdk/src/lib.rs`) is a software sponge *over the syscall*:
/// a 50-word state permuted in place by `KECCAK`, a 34-word (136-byte) rate, and `0x01`/`0x80`
/// padding. `guest-sdk` only builds for `riscv32im-unknown-none-elf`, so its algorithm is
/// transcribed here — with `keccak_f` standing in for the syscall — and checked against the host
/// `keccak256` at every block-boundary case: empty, short, one byte shy of the rate, exactly the
/// rate (which needs a whole extra all-padding block), one byte past it, and two full blocks.
fn sdk_keccak256(msg: &[u8]) -> [u8; 32] {
    // stand-in for `keccak(state.as_mut_ptr())`
    let keccak = |state: &mut [u32; 50]| {
        let mut st = words_to_state(state);
        keccak_f(&mut st);
        *state = state_to_words(&st);
    };
    let mut state = [0u32; 50];
    let mut block = [0u8; 136];
    let mut off = 0;
    loop {
        let take = core::cmp::min(136, msg.len() - off);
        block.fill(0);
        block[..take].copy_from_slice(&msg[off..off + take]);
        let last = take < 136;
        if last { block[take] ^= 0x01; block[135] ^= 0x80; }
        for i in 0..34 { state[i] ^= u32::from_le_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]); }
        keccak(&mut state);
        off += take;
        if last { break; }
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes()); }
    out
}

#[test]
fn the_guest_sdk_sponge_matches_the_host_keccak256() {
    for len in [0usize, 1, 135, 136, 137, 272] {
        let msg: Vec<u8> = (0..len).map(|i| (7 * i + 1) as u8).collect();
        assert_eq!(sdk_keccak256(&msg), keccak256(&msg), "len {len}");
    }
}

mod chip {
    use p3_matrix::Matrix;
    use shrugg_zkvm::keccak::{keccak_f, state_to_words, words_to_state};
    use shrugg_zkvm::tables::keccak::{self, col, keccak_trace, KeccakEvent, BLOCK, ROUNDS};
    use shrugg_zkvm::tables::F;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::PrimeField64;

    fn random_words(seed: u64) -> [u32; 50] {
        let mut x = seed | 1;
        std::array::from_fn(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x as u32 })
    }

    fn limbs_to_words(row: &[F], base: usize) -> [u32; 50] {
        std::array::from_fn(|w| {
            let lane = w / 2;
            let lo = row[base + 4 * lane + 2 * (w % 2)].as_canonical_u64() as u32;
            let hi = row[base + 4 * lane + 2 * (w % 2) + 1].as_canonical_u64() as u32;
            lo | (hi << 16)
        })
    }

    #[test]
    fn keccak_trace_output_matches_p3_keccak_on_a_thousand_states() {
        for seed in 0..1000u64 {
            let input = random_words(seed);
            let t = keccak_trace(&[KeccakEvent { clk: 7, ptr: 0x100, input }], BLOCK);
            let idle = t.row_slice(ROUNDS).unwrap();  // first idle row carries the output in A
            let out = limbs_to_words(&idle, col::A0);
            let mut st = words_to_state(&input);
            keccak_f(&mut st);
            assert_eq!(out, state_to_words(&st), "seed {seed}");
            let first = t.row_slice(0).unwrap();
            assert_eq!(limbs_to_words(&first, col::IN0), input);
            assert_eq!(limbs_to_words(&first, col::A0), input);
        }
    }

    #[test]
    fn padding_blocks_are_honest_zero_permutations_with_zero_counts() {
        let t = keccak_trace(&[], 2 * BLOCK);
        assert_eq!(t.height(), 64);
        for r in 0..64 {
            let row = t.row_slice(r).unwrap();
            assert_eq!(row[col::IS_REAL], F::ZERO);
            assert_eq!(row[col::MULT], F::ZERO);
        }
        let mut zero = [0u64; 25];
        keccak_f(&mut zero);
        assert_eq!(limbs_to_words(&t.row_slice(ROUNDS).unwrap(), col::A0), state_to_words(&zero));
    }

    /// M4.2 (Task 6): no permutations means *no table*, not one padding block — `0` is the
    /// "absent" marker `machine::chips` reads to build an eight-chip batch. From one
    /// permutation on, the one-block floor is back.
    #[test]
    fn keccak_log_height_is_zero_without_events_and_floors_at_one_block() {
        assert_eq!(keccak::keccak_log_height(0), 0);
        assert_eq!(keccak::keccak_log_height(1), 5);
        assert_eq!(keccak::keccak_log_height(2), 6);
        assert_eq!(keccak::keccak_log_height(3), 7);
    }
}

/// M4.2 Task 3, Step 5 — the keccak chip alone under the real batch STARK, with a throwaway
/// consumer on each of its two buses: a `KeccakAsker` that looks up `(CLK, PTR)` on `KECCAK`,
/// and a `MemoryTwin` that receives the 100 `MEMORY` messages the chip sends for a real event.
/// This is the constraint-level counterpart to the trace tests above: those check the
/// arithmetic the filler computes, this checks the AIR the prover and verifier actually run
/// (and, in a debug build, `p3-batch-stark`'s per-row constraint checker walks every one of the
/// ~3,900 constraints on every row).
mod harness {
    use super::common::rejects;
    use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
    use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_lookup::{Count, InteractionBuilder};
    use p3_matrix::dense::RowMajorMatrix;
    use shrugg_zkvm::emulator::SPACE_RAM;
    use shrugg_zkvm::keccak::{keccak_f, state_to_words, words_to_state};
    use shrugg_zkvm::machine::{make_config, FriProfile, VerifyError};
    use shrugg_zkvm::tables::keccak::{col, keccak_trace, KeccakAir, KeccakEvent, BLOCK, ROUNDS};
    use shrugg_zkvm::tables::{bus, F};

    /// main = `[gate, clk, ptr]`: one weighted `KECCAK` lookup per row.
    #[derive(Clone)]
    struct KeccakAsker;
    impl<Fld> BaseAir<Fld> for KeccakAsker {
        fn width(&self) -> usize { 3 }
    }
    impl<AB: AirBuilder + InteractionBuilder> Air<AB> for KeccakAsker
    where
        AB::F: Field,
    {
        fn eval(&self, b: &mut AB) {
            let m = b.main();
            let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
            let gate = v(0);
            b.assert_bool(gate.clone());
            bus::KECCAK.lookup_key(b, [v(1), v(2)], Count::bounded(gate, 1));
        }
    }

    /// main = `[count, space, addr, ts, value, is_write]`: stands in for the memory table,
    /// receiving one `MEMORY` message per row. Enough to make the chip's 100 sends balance.
    #[derive(Clone)]
    struct MemoryTwin;
    impl<Fld> BaseAir<Fld> for MemoryTwin {
        fn width(&self) -> usize { 6 }
    }
    impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MemoryTwin
    where
        AB::F: Field,
    {
        fn eval(&self, b: &mut AB) {
            let m = b.main();
            let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
            let count = v(0);
            b.assert_bool(count.clone());
            bus::MEMORY.receive(b, [v(1), v(2), v(3), v(4), v(5)], Count::bounded(count, 1));
        }
    }

    #[derive(Clone)]
    enum T {
        K(KeccakAir, usize),
        A(KeccakAsker),
        M(MemoryTwin),
    }
    impl<Fld: Field> BaseAir<Fld> for T {
        fn width(&self) -> usize {
            match self {
                T::K(a, _) => <KeccakAir as BaseAir<Fld>>::width(a),
                T::A(a) => <KeccakAsker as BaseAir<Fld>>::width(a),
                T::M(a) => <MemoryTwin as BaseAir<Fld>>::width(a),
            }
        }
        fn preprocessed_width(&self) -> usize {
            match self {
                T::K(a, _) => <KeccakAir as BaseAir<Fld>>::preprocessed_width(a),
                _ => 0,
            }
        }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
            match self {
                T::K(_, h) => Some(KeccakAir::preprocessed_trace_at(*h)),
                _ => None,
            }
        }
    }
    impl<AB: AirBuilder + PermutationAirBuilder + InteractionBuilder> Air<AB> for T
    where
        AB::F: Field,
    {
        fn eval(&self, b: &mut AB) {
            match self {
                T::K(a, _) => a.eval(b),
                T::A(a) => a.eval(b),
                T::M(a) => a.eval(b),
            }
        }
    }

    /// The 100 `(space, addr, ts, value, is_write)` accesses one real permutation makes: 50
    /// reads of the input at `ts = 4·clk`, then 50 writes of the output at `ts = 4·clk + 1` —
    /// the same tuples `emulator::CycleEvent::keccak_accesses` records.
    fn twin_trace(ev: &KeccakEvent, height: usize) -> RowMajorMatrix<F> {
        let mut st = words_to_state(&ev.input);
        keccak_f(&mut st);
        let out = state_to_words(&st);
        let mut v = F::zero_vec(height * 6);
        let mut put = |i: usize, addr: u32, ts: u32, value: u32, is_write: bool| {
            let r = &mut v[i * 6..(i + 1) * 6];
            r[0] = F::ONE;
            r[1] = F::from_u32(SPACE_RAM);
            r[2] = F::from_u32(addr);
            r[3] = F::from_u32(ts);
            r[4] = F::from_u32(value);
            r[5] = F::from_bool(is_write);
        };
        for w in 0..50 {
            put(w, ev.ptr + w as u32, 4 * ev.clk, ev.input[w], false);
            put(50 + w, ev.ptr + w as u32, 4 * ev.clk + 1, out[w], true);
        }
        RowMajorMatrix::new(v, 6)
    }

    pub fn run(trace: &RowMajorMatrix<F>, ev: &KeccakEvent, height: usize) -> Result<(), VerifyError> {
        let mut asker = F::zero_vec(4 * 3);
        asker[0] = F::ONE;
        asker[1] = F::from_u32(ev.clk);
        asker[2] = F::from_u32(ev.ptr);
        let asker_trace = RowMajorMatrix::new(asker, 3);
        let twin = twin_trace(ev, 128);

        let airs = vec![T::K(KeccakAir, height), T::A(KeccakAsker), T::M(MemoryTwin)];
        let instances = vec![
            StarkInstance { air: &airs[0], trace, public_values: vec![] },
            StarkInstance { air: &airs[1], trace: &asker_trace, public_values: vec![] },
            StarkInstance { air: &airs[2], trace: &twin, public_values: vec![] },
        ];
        let config = make_config(FriProfile::Test);
        let pd = ProverData::from_instances(&config, &instances);
        let proof = prove_batch(&config, &instances, &pd);
        verify_batch(&config, &airs, &proof, &[vec![], vec![], vec![]], &pd.common)
            .map_err(|e| VerifyError::Batch(format!("{e:?}")))
    }

    pub fn event() -> KeccakEvent {
        let mut x = 0x243f_6a88_85a3_08d3u64;
        let input = std::array::from_fn(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u32
        });
        KeccakEvent { clk: 11, ptr: 0x2000, input }
    }

    #[test]
    fn keccak_table_answers_lookups_and_memory_under_a_constraint_check() {
        let ev = event();
        let height = BLOCK * 4; // one real block, three padding blocks
        let trace = keccak_trace(&[ev], height);
        run(&trace, &ev, height).unwrap();
    }

    #[test]
    fn a_tampered_theta_bit_is_rejected() {
        let ev = event();
        let height = BLOCK * 4;
        let mut trace = keccak_trace(&[ev], height);
        // Flip one A' bit on round row 3: A' is pinned three ways at once — rule 5 recomputes
        // the row's own `A` limb from it, rule 6 checks the column parity, rule 7 feeds it to χ.
        let cell = 3 * col::WIDTH + col::AP0 + 17;
        trace.values[cell] = F::ONE - trace.values[cell];
        assert!(rejects(|| run(&trace, &ev, height)));
    }

    /// Rule 9 (the round transition, `is_round · (n(A) − out)`): row 24, the first idle row,
    /// is where round 23's output lands — and it is the only `A` on the block whose value rule
    /// 5 does *not* also recompute from bits (rule 5 is gated off on idle rows), so a single
    /// flipped limb there isolates the transition pin itself. It is also exactly the limb that
    /// would otherwise let a prover write a word of its choosing back into guest RAM.
    #[test]
    fn a_flipped_round_transition_limb_is_rejected() {
        let ev = event();
        let height = BLOCK * 4;
        let mut trace = keccak_trace(&[ev], height);
        trace.values[ROUNDS * col::WIDTH + col::A0 + 7] += F::ONE;
        assert!(rejects(|| run(&trace, &ev, height)));
    }

    /// Rule 10 (the idle-row copy, `is_idle · same_block · (n(A) − v(A))`): rule 9 only fires
    /// on transitions *out of a round row*, so a limb flipped on a later idle row (27 here) is
    /// past its reach — rule 10's own idle-to-idle copy is what has to catch it, along with the
    /// write-back message that idle row carries.
    #[test]
    fn a_flipped_idle_row_limb_is_rejected() {
        let ev = event();
        let height = BLOCK * 4;
        let mut trace = keccak_trace(&[ev], height);
        trace.values[(ROUNDS + 3) * col::WIDTH + col::A0 + 11] += F::ONE;
        assert!(rejects(|| run(&trace, &ev, height)));
    }
}

/// The one place this chip's AIR is deliberately stricter than `poseidon2`'s: a real block must
/// be *claimed* on the `KECCAK` bus, not merely permitted to be. Because the chip sends its own
/// memory traffic on `IS_REAL` alone, a real block with `MULT = 0` would be a free Keccak-f
/// applied to guest RAM at a timestamp of the prover's choosing — so `MULT = IS_REAL` is
/// constrained on the last round row, and dropping the count here must be rejected.
mod unpaid {
    use super::common::rejects;
    use super::harness::{event, run};
    use shrugg_zkvm::tables::keccak::{col, keccak_trace, BLOCK, ROUNDS};
    use shrugg_zkvm::tables::F;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn a_real_block_that_provides_no_keccak_entry_is_rejected() {
        let ev = event();
        let height = BLOCK * 4;
        let mut trace = keccak_trace(&[ev], height);
        trace.values[(ROUNDS - 1) * col::WIDTH + col::MULT] = F::ZERO;
        assert!(rejects(|| run(&trace, &ev, height)));
    }

    /// The mirror image: a padding block flipped to `IS_REAL = 1` (still `MULT = 0`) is the
    /// forgery the constraint above actually exists to stop — it would otherwise permute
    /// whatever sits at `PTR` and write the result back into RAM with no syscall behind it.
    #[test]
    fn a_padding_block_flipped_to_real_is_rejected() {
        let ev = event();
        let height = BLOCK * 4;
        let mut trace = keccak_trace(&[ev], height);
        for r in BLOCK..2 * BLOCK {
            trace.values[r * col::WIDTH + col::IS_REAL] = F::ONE;
        }
        assert!(rejects(|| run(&trace, &ev, height)));
    }
}
