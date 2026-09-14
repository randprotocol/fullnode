use shrugg_zkvm::sha256::{bytes_to_words, compress, sha256, IV, K};
use sha2::Digest;

#[test]
fn sha256_matches_fips_vectors_and_the_sha2_crate() {
    assert_eq!(hex::encode(sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex::encode(sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hex::encode(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(48);
    for _ in 0..1_000 {
        let n = rand::RngExt::random_range(&mut rng, 0..300usize);
        let msg: Vec<u8> = (0..n).map(|_| rand::RngExt::random(&mut rng)).collect();
        assert_eq!(sha256(&msg), <[u8; 32]>::from(sha2::Sha256::digest(&msg)), "len {n}");
    }
    assert_eq!(K[0], 0x428a2f98); assert_eq!(K[63], 0xc67178f2); assert_eq!(IV[0], 0x6a09e667); assert_eq!(IV[7], 0x5be0cd19);
}

#[test]
fn compress_matches_sha2_compress256_on_a_thousand_blocks() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(49);
    for _ in 0..1_000 {
        let mut state: [u32; 8] = core::array::from_fn(|_| rand::RngExt::random(&mut rng));
        let bytes: [u8; 64] = core::array::from_fn(|_| rand::RngExt::random(&mut rng));
        let mut theirs = state;
        sha2::compress256(&mut theirs, &[bytes.into()]);
        compress(&mut state, &bytes_to_words(&bytes));
        assert_eq!(state, theirs);
    }
}

/// The guest SDK's `sha256` (`guest-sdk/src/lib.rs`) is a software Merkle–Damgård loop *over the
/// syscall*: a 24-word buffer whose words `16..24` hold the chaining state, the block packed
/// big-endian into words `0..16`, and `SHA256` compressing it in place. `guest-sdk` only builds
/// for `riscv32im-unknown-none-elf`, so its algorithm is transcribed here — with `compress`
/// standing in for the syscall — and checked against the host `sha256` at every block-boundary
/// case: empty, short, either side of the 56-byte length-field cutoff (56 is the first length
/// whose padding needs a whole extra block), either side of a full 64-byte block, and the same
/// three cases one block further along.
fn sdk_sha256(msg: &[u8]) -> [u8; 32] {
    // stand-in for `sha256_compress(buf.as_mut_ptr())`
    let compress_syscall = |buf: &mut [u32; 24]| {
        let block: [u32; 16] = buf[..16].try_into().unwrap();
        let mut h: [u32; 8] = buf[16..].try_into().unwrap();
        compress(&mut h, &block);
        buf[16..].copy_from_slice(&h);
    };
    let compress_block = |buf: &mut [u32; 24], block: &[u8; 64]| {
        for i in 0..16 {
            buf[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        compress_syscall(buf);
    };

    let mut buf = [0u32; 24];
    buf[16..].copy_from_slice(&IV);
    let mut block = [0u8; 64];
    let mut off = 0;
    while msg.len() - off >= 64 {
        block.copy_from_slice(&msg[off..off + 64]);
        compress_block(&mut buf, &block);
        off += 64;
    }
    let rest = msg.len() - off;
    block.fill(0);
    block[..rest].copy_from_slice(&msg[off..]);
    block[rest] = 0x80;
    if rest >= 56 {
        compress_block(&mut buf, &block);
        block.fill(0);
    }
    block[56..].copy_from_slice(&(msg.len() as u64).wrapping_mul(8).to_be_bytes());
    compress_block(&mut buf, &block);

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&buf[16 + i].to_be_bytes());
    }
    out
}

#[test]
fn the_guest_sdk_merkle_damgard_loop_matches_the_host_sha256() {
    for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 128] {
        let msg: Vec<u8> = (0..len).map(|i| (7 * i + 1) as u8).collect();
        assert_eq!(sdk_sha256(&msg), sha256(&msg), "len {len}");
    }
}

mod common;

/// M4.4 Task 3 — the `sha256` table's trace builder, checked against the host reference above.
mod chip {
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Matrix;
    use shrugg_zkvm::tables::sha256::{self, col, sha256_trace, Sha256Event, BLOCK};
    use shrugg_zkvm::tables::F;

    /// The equality contract (plan's global constraints): the table's write-back on any
    /// `(H, W)` is `sha256::compress`'s — which `compress_matches_sha2_compress256_on_a_thousand_blocks`
    /// above has already pinned to `sha2`'s `compress256`. 1 000 random blocks, one 64-row
    /// block each, in a 2^16-row table.
    #[test]
    fn sha256_trace_write_backs_match_the_reference_on_a_thousand_blocks() {
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(50);
        let events: Vec<Sha256Event> = (0..1000u32)
            .map(|i| Sha256Event {
                clk: i + 1,
                ptr: 0x100 + 32 * i,
                block: core::array::from_fn(|_| rand::RngExt::random(&mut rng)),
                h_in: core::array::from_fn(|_| rand::RngExt::random(&mut rng)),
            })
            .collect();
        let t = sha256_trace(&events, 16);
        assert_eq!(t.height(), 1 << 16);
        for (i, e) in events.iter().enumerate() {
            let last = t.row_slice((i + 1) * BLOCK - 1).unwrap();
            let mut want = e.h_in;
            shrugg_zkvm::sha256::compress(&mut want, &e.block);
            for k in 0..8 {
                assert_eq!(col::hout_word(&last, k), want[k], "block {i} word {k}");
            }
            assert_eq!(last[col::IS_REAL], F::ONE, "block {i} is real");
        }
    }

    /// AGENTS.md invariant 2, the keccak table's padding rule one algorithm over: a padding
    /// block is an *honest* compression of the all-zero state and all-zero block, marked only
    /// by `IS_REAL = 0` (which zeroes every bus count on the row).
    #[test]
    fn sha256_padding_blocks_are_honest_zero_compressions_with_zero_counts() {
        let t = sha256_trace(&[], 6);
        assert_eq!(t.height(), 64);
        let last = t.row_slice(BLOCK - 1).unwrap();
        let mut want = [0u32; 8];
        shrugg_zkvm::sha256::compress(&mut want, &[0u32; 16]);
        for k in 0..8 {
            assert_eq!(col::hout_word(&last, k), want[k], "word {k}");
        }
        for r in 0..BLOCK {
            assert_eq!(t.row_slice(r).unwrap()[col::IS_REAL], F::ZERO, "row {r}");
        }
    }

    /// The keccak table's rule, with 64-row blocks: `0` is the "this proof has no sha256
    /// table" marker, and from one compression on the floor is a single block.
    #[test]
    fn sha256_log_height_is_zero_without_events_and_floors_at_one_block() {
        assert_eq!(sha256::sha256_log_height(0), 0);
        assert_eq!(sha256::sha256_log_height(1), 6);
        assert_eq!(sha256::sha256_log_height(2), 7);
        assert_eq!(sha256::sha256_log_height(3), 8);
        assert_eq!(sha256::sha256_log_height(4), 8);
    }
}

/// M4.4 Task 3, Step 1 — the sha256 chip alone under the real batch STARK, with a throwaway
/// consumer on each of its two buses: a `Sha256Asker` that looks up `(CLK, PTR)` on `SHA256`,
/// and a `MemoryTwin` that receives the 32 `MEMORY` messages one real compression sends. The
/// shape is `tests/keccak.rs`'s harness; in a debug build `p3-batch-stark`'s per-row
/// constraint checker walks every constraint on every row of the table as well.
mod harness {
    use super::common::rejects;
    use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
    use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_lookup::{Count, InteractionBuilder};
    use p3_matrix::dense::RowMajorMatrix;
    use shrugg_zkvm::emulator::SPACE_RAM;
    use shrugg_zkvm::machine::{make_config, FriProfile, VerifyError};
    use shrugg_zkvm::tables::sha256::{col, sha256_trace, Sha256Air, Sha256Event, BLOCK};
    use shrugg_zkvm::tables::{bus, F};

    /// main = `[gate, clk, ptr]`: one weighted `SHA256` lookup per row.
    #[derive(Clone)]
    struct Sha256Asker;
    impl<Fld> BaseAir<Fld> for Sha256Asker {
        fn width(&self) -> usize { 3 }
    }
    impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Sha256Asker
    where
        AB::F: Field,
    {
        fn eval(&self, b: &mut AB) {
            let m = b.main();
            let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
            let gate = v(0);
            b.assert_bool(gate.clone());
            bus::SHA256.lookup_key(b, [v(1), v(2)], Count::bounded(gate, 1));
        }
    }

    /// main = `[count, space, addr, ts, value, is_write]`: stands in for the memory table,
    /// receiving one `MEMORY` message per row.
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
        S(Sha256Air, usize),
        A(Sha256Asker),
        M(MemoryTwin),
    }
    impl<Fld: Field> BaseAir<Fld> for T {
        fn width(&self) -> usize {
            match self {
                T::S(a, _) => <Sha256Air as BaseAir<Fld>>::width(a),
                T::A(a) => <Sha256Asker as BaseAir<Fld>>::width(a),
                T::M(a) => <MemoryTwin as BaseAir<Fld>>::width(a),
            }
        }
        fn preprocessed_width(&self) -> usize {
            match self {
                T::S(a, _) => <Sha256Air as BaseAir<Fld>>::preprocessed_width(a),
                _ => 0,
            }
        }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
            match self {
                T::S(_, h) => Some(Sha256Air::preprocessed_trace_at(*h)),
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
                T::S(a, _) => a.eval(b),
                T::A(a) => a.eval(b),
                T::M(a) => a.eval(b),
            }
        }
    }

    /// The 32 `(space, addr, ts, value, is_write)` accesses one real compression makes: the 24
    /// words of the buffer read at `ts = 4·clk`, the eight new state words written back at
    /// `ts = 4·clk + 1` — the same tuples `emulator::CycleEvent::sha256_accesses` records.
    fn twin_values(ev: &Sha256Event) -> Vec<F> {
        let mut h_out = ev.h_in;
        shrugg_zkvm::sha256::compress(&mut h_out, &ev.block);
        let mut v = F::zero_vec(32 * 6);
        let mut put = |i: usize, addr: u32, ts: u32, value: u32, is_write: bool| {
            let r = &mut v[i * 6..(i + 1) * 6];
            r[0] = F::ONE;
            r[1] = F::from_u32(SPACE_RAM);
            r[2] = F::from_u32(addr);
            r[3] = F::from_u32(ts);
            r[4] = F::from_u32(value);
            r[5] = F::from_bool(is_write);
        };
        for i in 0..16 {
            put(i, ev.ptr + i as u32, 4 * ev.clk, ev.block[i], false);
        }
        for i in 0..8 {
            put(16 + i, ev.ptr + 16 + i as u32, 4 * ev.clk, ev.h_in[i], false);
            put(24 + i, ev.ptr + 16 + i as u32, 4 * ev.clk + 1, h_out[i], true);
        }
        v
    }

    /// The `value` cell of the twin row that carries the read of state word `i` — the one a
    /// dishonest memory would have to lie in.
    const fn twin_state_read_value(i: usize) -> usize {
        (16 + i) * 6 + 4
    }

    pub fn run(trace: &RowMajorMatrix<F>, ev: &Sha256Event, height: usize) -> Result<(), VerifyError> {
        run_with_twin(trace, ev, &RowMajorMatrix::new(twin_values(ev), 6), height)
    }

    pub fn run_with_twin(
        trace: &RowMajorMatrix<F>,
        ev: &Sha256Event,
        twin: &RowMajorMatrix<F>,
        height: usize,
    ) -> Result<(), VerifyError> {
        let mut asker = F::zero_vec(4 * 3);
        asker[0] = F::ONE;
        asker[1] = F::from_u32(ev.clk);
        asker[2] = F::from_u32(ev.ptr);
        let asker_trace = RowMajorMatrix::new(asker, 3);

        let airs = vec![T::S(Sha256Air, height), T::A(Sha256Asker), T::M(MemoryTwin)];
        let instances = vec![
            StarkInstance { air: &airs[0], trace, public_values: vec![] },
            StarkInstance { air: &airs[1], trace: &asker_trace, public_values: vec![] },
            StarkInstance { air: &airs[2], trace: twin, public_values: vec![] },
        ];
        let config = make_config(FriProfile::Test);
        let pd = ProverData::from_instances(&config, &instances);
        let proof = prove_batch(&config, &instances, &pd);
        verify_batch(&config, &airs, &proof, &[vec![], vec![], vec![]], &pd.common)
            .map_err(|e| VerifyError::Batch(format!("{e:?}")))
    }

    pub fn event() -> Sha256Event {
        let mut x = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u32
        };
        let block = core::array::from_fn(|_| next());
        let h_in = core::array::from_fn(|_| next());
        Sha256Event { clk: 11, ptr: 0x2000, block, h_in }
    }

    /// The log-height the tamper tests share: one real block, three padding blocks.
    const LOG_HEIGHT: u8 = 8;

    #[test]
    fn sha256_chip_proves_standalone_against_the_asker_harness() {
        let ev = event();
        let trace = sha256_trace(&[ev], LOG_HEIGHT);
        run(&trace, &ev, 1 << LOG_HEIGHT).unwrap();
    }

    /// A flipped schedule bit on round row 20: `WM2_BITS` is pinned two ways at once — it
    /// composes to the `W[t−2]` the pipeline carries, and it feeds `σ1` into the row's `WNEW`.
    #[test]
    fn a_tampered_schedule_bit_is_rejected() {
        let ev = event();
        let mut trace = sha256_trace(&[ev], LOG_HEIGHT);
        let cell = 20 * col::WIDTH + col::WM2_BITS + 5;
        trace.values[cell] = F::ONE - trace.values[cell];
        assert!(rejects(|| run(&trace, &ev, 1 << LOG_HEIGHT)));
    }

    /// A flipped post-round bit on row 40: `ANEW_BITS` is the round's own output *and* the next
    /// row's `a`, so this must break both the round equation and the transition.
    #[test]
    fn a_tampered_round_output_bit_is_rejected() {
        let ev = event();
        let mut trace = sha256_trace(&[ev], LOG_HEIGHT);
        let cell = 40 * col::WIDTH + col::ANEW_BITS + 3;
        trace.values[cell] = F::ONE - trace.values[cell];
        assert!(rejects(|| run(&trace, &ev, 1 << LOG_HEIGHT)));
    }

    /// The forgery that matters most: a write-back value of the prover's choosing, landing in
    /// guest RAM for a later `lw` to pick up. The final add on the tail rows is what pins it.
    #[test]
    fn a_tampered_write_back_value_is_rejected() {
        let ev = event();
        let mut trace = sha256_trace(&[ev], LOG_HEIGHT);
        trace.values[(BLOCK - 1) * col::WIDTH + col::HOUT + 5] += F::ONE;
        assert!(rejects(|| run(&trace, &ev, 1 << LOG_HEIGHT)));
    }

    /// Rule 3's two *borrowed*-bank pins (`compose(WM15_BITS) = HIN[7]` and
    /// `compose(WM2_BITS) = HIN[3]`) are the only thing bounding `h` and `d` below 2^32 on row 0 —
    /// every other state word is bounded by the bit bank it composes into. Without them a
    /// dishonest memory could hand the chip a *field element* whose canonical value is `2^32` where
    /// the state word should be, and the round's carries would quietly absorb the extra `2^32`: the
    /// chip would prove an honest compression of `h = 0` while the memory bus says the word at
    /// `PTR + 23` is `2^32`. That is the machine-wide "every memory word is 32 bits" induction this
    /// chip declines to depend on (module doc, "Why there are no RANGE8 lookups").
    ///
    /// The forgery is built to satisfy *every other rule*, which is what makes these tests pin the
    /// borrow specifically rather than something else: `HIN[i]` is patched on all 64 rows (rule 1
    /// is block-constant), row 0's `D`/`H` follow it (rule 3), the round carries it feeds grow by
    /// one (rule 8) and the final add's carry bit for that word flips (rule 10) — and the twin
    /// serves the same value back on the `MEMORY` bus, so the bus balances too.
    fn non_word_state_forgery(slot: usize) -> (Sha256Event, RowMajorMatrix<F>, RowMajorMatrix<F>) {
        assert!(slot == 3 || slot == 7, "only D and H lack a bit bank of their own");
        let mut ev = event();
        // Zero in the slot under test, so its honest final-add carry is 0 and the patch below is a
        // clean 0 -> 1 flip.
        ev.h_in[3] = 0;
        ev.h_in[7] = 0;
        let mut trace = sha256_trace(&[ev], LOG_HEIGHT);
        let big = F::from_u64(1u64 << 32);

        for r in 0..BLOCK {
            trace.values[r * col::WIDTH + col::HIN + slot] = big;
        }
        // Row 0 is the trace's first row, so its cells are at `col::*` directly.
        let bump_carry = |trace: &mut RowMajorMatrix<F>, base: usize| {
            let mut c = 0u64;
            for i in 0..3 {
                if trace.values[base + i] == F::ONE {
                    c |= 1 << i;
                }
            }
            c += 1;
            assert!(c < 8, "the 3-bit carry cannot absorb the extra 2^32");
            for i in 0..3 {
                trace.values[base + i] = F::from_bool((c >> i) & 1 == 1);
            }
        };
        // `HOUT[slot]` is assembled on row 60 (`k = 0`): the a-side owns word 3, the e-side word 7.
        let carry_cell = (BLOCK - 4) * col::WIDTH
            + if slot == 3 { col::HOUTA_CARRY } else { col::HOUTE_CARRY };
        assert_eq!(trace.values[carry_cell], F::ZERO, "the honest final-add carry must be 0 here");
        trace.values[carry_cell] = F::ONE;
        if slot == 7 {
            trace.values[col::H] = big;
            bump_carry(&mut trace, col::A_CARRY); // h feeds T1, which feeds both a' and e'
            bump_carry(&mut trace, col::E_CARRY);
        } else {
            trace.values[col::D] = big;
            bump_carry(&mut trace, col::E_CARRY); // d feeds e' only
        }

        let mut twin = twin_values(&ev);
        twin[twin_state_read_value(slot)] = big;
        (ev, trace, RowMajorMatrix::new(twin, 6))
    }

    #[test]
    fn a_state_word_wider_than_thirty_two_bits_cannot_be_smuggled_in_as_h() {
        let (ev, trace, twin) = non_word_state_forgery(7);
        assert!(rejects(|| run_with_twin(&trace, &ev, &twin, 1 << LOG_HEIGHT)));
    }

    #[test]
    fn a_state_word_wider_than_thirty_two_bits_cannot_be_smuggled_in_as_d() {
        let (ev, trace, twin) = non_word_state_forgery(3);
        assert!(rejects(|| run_with_twin(&trace, &ev, &twin, 1 << LOG_HEIGHT)));
    }

    /// Controller ruling 2 spelled out as a test: the multiset the chip sends must be exactly the
    /// one Task 2's emulator recorded. Nothing here is hand-written — the event *and* the twin's
    /// 32 `MEMORY` messages both come out of `CycleEvent`, so a chip that read the wrong address,
    /// wrote at the wrong timestamp or sent a word twice would leave the bus unbalanced.
    #[test]
    fn the_chips_memory_sends_are_the_emulators_own_recorded_accesses() {
        use shrugg_zkvm::asm::{ops::*, Assembler};
        use shrugg_zkvm::emulator::{execute, Syscall};
        use shrugg_zkvm::isa::REG_ZERO;
        use shrugg_zkvm::sha256::IV;

        const BUF: i32 = 0x400; // byte address; word address 0x100
        const T0: u32 = 5;
        let ptr = (BUF / 4) as u32;
        let block: [u32; 16] = core::array::from_fn(|i| 0x0303_0303u32.wrapping_mul(i as u32 + 7));
        let mut a = Assembler::new(0);
        for (i, w) in block.iter().chain(IV.iter()).enumerate() {
            a.extend(li(T0, *w as i32));
            a.push(sw(REG_ZERO, T0, BUF + 4 * i as i32));
        }
        a.extend(call_sha256(ptr));
        a.extend(halt());
        let exec = execute(&a.assemble(), &[], &[], 1 << 16).unwrap();

        let cycle = exec
            .events
            .iter()
            .find(|e| matches!(e.sys, Some(Syscall::Sha256 { .. })))
            .expect("the run makes one SHA256 call");
        let r = cycle.sha256_row.expect("a SHA256 row");
        assert_eq!(r.block, block);
        assert_eq!(r.h_in, IV);
        assert_eq!(cycle.sha256_accesses.len(), 32);

        // The twin receives exactly what the emulator recorded, timestamps included
        // (`ts = 4*clk + slot`).
        let mut twin = F::zero_vec(32 * 6);
        for (i, m) in cycle.sha256_accesses.iter().enumerate() {
            let row = &mut twin[i * 6..(i + 1) * 6];
            row[0] = F::ONE;
            row[1] = F::from_u32(m.space);
            row[2] = F::from_u32(m.addr);
            row[3] = F::from_u32(4 * r.clk + m.slot);
            row[4] = F::from_u32(m.value);
            row[5] = F::from_bool(m.is_write);
        }
        let twin = RowMajorMatrix::new(twin, 6);

        let ev = Sha256Event { clk: r.clk, ptr: r.ptr, block: r.block, h_in: r.h_in };
        let height = 1usize << LOG_HEIGHT;
        let trace = sha256_trace(&[ev], LOG_HEIGHT);
        let mut asker = F::zero_vec(4 * 3);
        asker[0] = F::ONE;
        asker[1] = F::from_u32(ev.clk);
        asker[2] = F::from_u32(ev.ptr);
        let asker_trace = RowMajorMatrix::new(asker, 3);

        let airs = vec![T::S(Sha256Air, height), T::A(Sha256Asker), T::M(MemoryTwin)];
        let instances = vec![
            StarkInstance { air: &airs[0], trace: &trace, public_values: vec![] },
            StarkInstance { air: &airs[1], trace: &asker_trace, public_values: vec![] },
            StarkInstance { air: &airs[2], trace: &twin, public_values: vec![] },
        ];
        let config = make_config(FriProfile::Test);
        let pd = ProverData::from_instances(&config, &instances);
        let proof = prove_batch(&config, &instances, &pd);
        verify_batch(&config, &airs, &proof, &[vec![], vec![], vec![]], &pd.common).unwrap();
    }

    /// The mirror image of the keccak table's `MULT = IS_REAL` rule: here the `SHA256` count is
    /// `IS_REAL · IS_FIRST`, so a padding block flipped to real cannot be *unpaid* — it claims
    /// a `(CLK, PTR)` entry no asker looks up, and reads and writes RAM at a timestamp no
    /// syscall issued.
    #[test]
    fn a_padding_block_flipped_to_real_is_rejected() {
        let ev = event();
        let mut trace = sha256_trace(&[ev], LOG_HEIGHT);
        for r in BLOCK..2 * BLOCK {
            trace.values[r * col::WIDTH + col::IS_REAL] = F::ONE;
        }
        assert!(rejects(|| run(&trace, &ev, 1 << LOG_HEIGHT)));
    }
}
