use p3_matrix::Matrix;
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::guests;
use randprotocol_zkvm::machine::{FriProfile, Machine, Tier};

/// M3.4 (fix): the program table's height is proof-declared, not derived from the tier
/// (`tables::program::program_log_height`'s doc comment) — a program can be far longer than
/// `Tier::cpu_height()` while still executing briefly, since a digest row absorbs up to 4
/// `PROGRAM_WORD`s per *cycle* but a program's word count has no such per-cycle cap. Build one:
/// a trivial computation followed by a large block of never-executed instructions, long enough
/// that the program table alone would have overflowed a small tier's `cpu_height()`-sized table
/// under the pre-fix code (`Tier::program_height() = cpu_height()`, since deleted).
///
/// The tier this proves at is `Tier(14)`, not `Tier(10)` (whose `cpu_height` the program's
/// length is checked against): the program is 1 207 words, i.e. 302 digest-row permutations
/// plus 1 indigest-row one — 303 permutation blocks, past `Tier(10).poseidon2_height()`'s 128
/// (audit ZL4, 2026-09-12: the old wording's arithmetic was wrong; `Tier(12)`'s 512 would
/// actually suffice, and 14 is chosen only for margin). `Tier::poseidon2_height`'s scaling
/// relative to `cpu_height` is a separate concern — since the 2026-09-12 audit fix,
/// `build_traces_salted` rejects a tier whose permutation budget the workload exceeds with a
/// clean `ProveError::TooManyPoseidon2Permutations`, and the auto-tier pick
/// (`Tier::for_workload`) climbs past it instead of hitting `poseidon2_trace`'s old capacity
/// panic. What this test isolates is exactly the bug this fix closes: the *program table's own
/// height* — independently confirmed below via `traces.program.height()` — tracks the program's
/// length, not the tier, so it is not the thing that would have forced a larger tier here.
#[test]
fn a_program_much_longer_than_a_small_tiers_cpu_height_but_briefly_executed_proves() {
    use randprotocol_zkvm::machine::build_traces_salted;
    let m = Machine::new(FriProfile::Test);
    let mut a = Assembler::new(0);
    a.extend(li(5, 42)); // t0 = 42
    a.extend(write_output(0, 5));
    a.extend(halt());
    // Never executed (the guest already halted above) — padding to push `len` past
    // `Tier(10).cpu_height()` (1 024) without meaningfully touching the cycle count.
    for _ in 0..1200 {
        a.push(addi(0, 0, 0)); // a decodable no-op: x0 = x0 + 0
    }
    let p = a.assemble();
    assert_eq!(p.len(), 1_207, "the permutation arithmetic in this test's doc comment");
    assert!(p.len() > Tier(10).cpu_height(), "program must exceed a small tier's cpu height to exercise the fix");

    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], 1 << 20).unwrap();
    assert!(exec.cycles() < 20, "only the leading few instructions ever execute");
    let traces = build_traces_salted(&p, &[], &[], [0u32; 4], &exec, Tier(14)).unwrap();
    // The program table's own height is driven by the program's length (`program_log_height`),
    // not by `Tier(14).cpu_height()` (16 384) — it is far smaller, and in particular still
    // bigger than `Tier(10).cpu_height()` would have offered, confirming the fix actually sized
    // the table from `p.len()` rather than coincidentally inheriting a large tier's height.
    assert!(traces.program.height() > Tier(10).cpu_height());
    assert!(traces.program.height() < Tier(14).cpu_height());

    let proof = m.prove_traces(&p, &traces, Tier(14));
    assert_eq!(exec.outputs[0], 42);
    m.verify(&p.digest(), &proof).unwrap();
}

#[test]
fn every_guest_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    // M4.1 salted H_IN (controller ruling): `prove_salted` with a fixed salt, so the expected
    // H_IN below is reproducible — `prove`'s own OS-entropy salt would make it a different,
    // unpredictable value on every run.
    let salt = [11u32, 22, 33, 44];
    for (name, program, inputs) in guests::all() {
        let (proof, exec) = m.prove_salted(&program, &inputs, &[], salt, None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(proof.tier, Tier(10), "{name} should fit the smallest tier");
        assert_eq!(proof.public_values[2], exec.outputs[0] as u64);
        m.verify(&program.digest(), &proof).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(proof.size() > 0);

        use randprotocol_zkvm::tables::cpu::pv;
        let expected_hin = randprotocol_zkvm::hash::input_digest(salt, &inputs);
        for k in 0..8 {
            assert_eq!(proof.public_values[pv::IN0 + k], expected_hin[k] as u64, "{name}: H_IN word {k}");
        }
    }
}

/// M4.2: the end-to-end anchor for the whole `KECCAK` path — guest sponge, `SYS_KECCAK` cpu
/// row, the keccak chip's 24 rounds and its own `MEMORY` traffic, the proof-declared keccak
/// height — checked against the host `keccak::keccak256` for the same message.
#[test]
fn keccak_demo_proves_and_verifies_at_tier_10() {
    let m = Machine::new(FriProfile::Test);
    let msg: Vec<u8> = (0..64u8).collect();
    let p = guests::keccak_demo(&msg);
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(10).max_cycles()).unwrap();
    let want = randprotocol_zkvm::keccak::keccak256(&msg);
    for k in 0..8 {
        assert_eq!(exec.outputs[k], u32::from_le_bytes(want[4 * k..4 * k + 4].try_into().unwrap()), "digest word {k}");
    }
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove_salted(&p, &[], &[], [1, 2, 3, 4], Some(Tier(10))).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(proof.keccak_log_height, 5, "one permutation fits the minimum block");
    // M4.2 (Task 6): a proof that *does* call `KECCAK` carries the keccak instance — the ninth
    // of the ten this batch has since constraint set 6 appended the mandatory `public` one.
    assert_eq!(proof.batch.degree_bits.len(), 10, "ten tables when the keccak table is present");
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "keccak_demo(64 bytes): tier {:?}, {} cycles, proof {} bytes, prove {:?}, verify {:?}",
        proof.tier, exec.cycles(), proof.size(), prove_time, t1.elapsed()
    );
}

/// A keccak-free `guests::fib(10)` proof at `Tier(10)` and `FriProfile::Test`, measured.
///
/// **The current figure is constraint set 6's**, which is why the constant is no longer named for
/// M4.2 — it was `PRE_M4_2_TIER_10_TEST_PROFILE_BYTES` while it held the **pre**-M4.2 baseline, the
/// size of this proof on the last commit *before* the keccak table existed, and it kept that name
/// for one commit too long after it stopped holding that.
///
/// The history, since the point of the constant is the comparison: M4.2 measured 275 916 on the
/// branch base `b1d01d9` — the last commit before the keccak table — as the middle of three
/// consecutive proofs (274 156 / 275 916 / 276 684; the hiding PCS's fresh per-proof entropy moves
/// the postcard encoding by a few hundred bytes run to run). Constraint set 6 grew the same proof by
/// ~8% to **298 791**, the middle of four (297 223 / 298 791 / 299 143 / 299 783). The growth is the
/// public segment's structural cost and is expected — the cpu table gained 51 columns (the
/// `SYS_READ_PUB`/`IS_PUBDIGEST`/`PUBDIGEST_LAST` selectors, `IPOUT0..7`, and the
/// `PHVL0..31`/`PHIMAX0..3`/`PINV0..3` final-encoding block) and the batch gained a mandatory
/// ninth instance, the 4-column `public` table; every FRI query opens a leaf of the batch's
/// full width. `SIZE_BAND_PCT` is the tolerance around the current figure.
const TIER_10_TEST_PROFILE_BYTES: usize = 298_791;

/// Tolerance, in percent, on the size assertion in `a_keccak_free_proof_carries_no_keccak_table`.
///
/// Derived, not picked: the four measured proofs above span 297 223..299 783, i.e. ±0.6% around
/// the constant, so 5% is ~8x the per-proof entropy noise — room for the odd extra
/// declared-height byte or an upstream postcard tweak. The thing the assertion exists to detect
/// is an order of magnitude beyond it: a 2 612-column keccak table adds roughly +450 KB at this
/// profile (+1.91 MB at the production one), i.e. +160%, so the band would have to be ~32x wider
/// before the regression could hide inside it. The load-bearing check is the
/// `degree_bits.len() == 9` assertion; this one is the size corroboration.
const SIZE_BAND_PCT: usize = 5;

/// M4.2 (Task 6): the keccak table is **optional per proof**. A guest that never executes a
/// `KECCAK` syscall declares `keccak_log_height = 0`, the batch has eight instances rather than
/// nine, and the proof is back to its pre-M4.2 size — the padding block that used to cost every
/// proof ~1.91 MB at the production profile (~705 KB at the 27 queries M4.2 measured) is simply
/// not there.
///
/// The cpu table is unchanged by this: with no keccak table in the batch, the `KECCAK` bus has
/// no provider at all, so a cpu row claiming `SYS_KECCAK = 1` leaves that bus unbalanced (see
/// `tests/cheating.rs::a_keccak_syscall_without_a_keccak_table_is_rejected`).
#[test]
fn a_keccak_free_proof_carries_no_keccak_table() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove_salted(&p, &[], &[], [0; 4], Some(Tier(10))).unwrap();
    assert_eq!(proof.keccak_log_height, 0, "no KECCAK call, no keccak table");
    assert_eq!(proof.batch.degree_bits.len(), 9, "nine instances, not ten");
    m.verify(&p.digest(), &proof).unwrap();

    let size = proof.to_bytes().len();
    let lo = TIER_10_TEST_PROFILE_BYTES * (100 - SIZE_BAND_PCT) / 100;
    let hi = TIER_10_TEST_PROFILE_BYTES * (100 + SIZE_BAND_PCT) / 100;
    assert!(
        (lo..=hi).contains(&size),
        "keccak-free proof should be within {SIZE_BAND_PCT}% of the measured keccak-free size \
         ({TIER_10_TEST_PROFILE_BYTES} bytes): got {size}"
    );
    eprintln!("keccak-free fib(10) at tier 10, Test profile: {size} bytes (measured baseline: {TIER_10_TEST_PROFILE_BYTES})");
}

/// M4.2 (controller ruling 1): the memory table's height is **proof-declared**, floored at the
/// tier's own `2^(t+2)`. A keccak-free guest declares exactly that floor — the first cut of
/// M4.2 sized the table `log2_ceil(2^(t+2) + 100·2^(klh−5))`, and since `klh` floors at 5 the
/// `+100` term was never zero, so *every* proof in existence paid for a doubled memory table.
#[test]
fn a_keccak_free_proof_declares_the_tier_floor_memory_height() {
    use randprotocol_zkvm::machine::build_traces_salted;
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(10).max_cycles()).unwrap();
    let accesses: usize = exec.events.iter().map(|e| e.accesses.len() + e.keccak_accesses.len()).sum();
    assert!(accesses < 1 << 12, "fib(10) is nowhere near the tier-10 floor: {accesses} accesses");
    let t = build_traces_salted(&p, &[], &[], [0; 4], &exec, Tier(10)).unwrap();
    assert_eq!(t.mem_log_height, 12, "exactly `t + 2`");
    assert_eq!(t.memory.height(), 1 << 12);
    let proof = m.prove_traces(&p, &t, Tier(10));
    assert_eq!(proof.mem_log_height, 12);
    m.verify(&p.digest(), &proof).unwrap();
}

/// Three permutations are 300 memory accesses — real traffic the table has to hold, but still
/// two orders of magnitude below tier 10's 4 096-row floor, so the declared height does not
/// move. This is the regression the ruling exists for: under the old tier-derived formula this
/// same guest declared 13, doubling the table to buy 300 rows of room it already had.
#[test]
fn a_few_keccak_permutations_still_fit_under_the_tier_floor() {
    use randprotocol_zkvm::machine::build_traces_salted;
    const BUF: i32 = 0x1000;
    let m = Machine::new(FriProfile::Test);
    let mut a = Assembler::new(0);
    a.extend(li(8, BUF));
    a.extend(li(5, 0x1234_5678));
    a.push(sw(8, 5, 0));
    for _ in 0..3 {
        a.extend(call_keccak(BUF / 4));
    }
    a.push(lw(5, 8, 0));
    a.extend(write_output(0, 5));
    a.extend(halt());
    let p = a.assemble();
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(10).max_cycles()).unwrap();
    assert_eq!(exec.events.iter().filter(|e| e.keccak_row.is_some()).count(), 3);
    let t = build_traces_salted(&p, &[], &[], [0; 4], &exec, Tier(10)).unwrap();
    // Three permutations need three 32-row blocks -> 128 rows -> 2^7.
    assert_eq!(t.keccak_log_height, 7);
    let accesses: usize = exec.events.iter().map(|e| e.accesses.len() + e.keccak_accesses.len()).sum();
    assert!((300..1 << 12).contains(&accesses), "{accesses} accesses: real keccak traffic, still under the floor");
    assert_eq!(t.mem_log_height, 12, "the tier floor still wins");
    assert_eq!(t.memory.height(), 1 << 12);
    let proof = m.prove_traces(&p, &t, Tier(10));
    assert_eq!(proof.keccak_log_height, 7);
    assert_eq!(proof.mem_log_height, 12);
    m.verify(&p.digest(), &proof).unwrap();
}

/// And when the traffic genuinely outgrows the floor, the declaration follows it: 40
/// permutations are 4 000 chip-sent accesses on their own, past tier 10's 4 096-row floor once
/// the guest's own register traffic is added. The memory trace is sized by the declared value
/// and the verifier's degree-bits check agrees with it.
#[test]
fn enough_keccak_permutations_raise_the_declared_memory_height_past_the_floor() {
    use randprotocol_zkvm::machine::build_traces_salted;
    const BUF: i32 = 0x1000;
    let m = Machine::new(FriProfile::Test);
    let mut a = Assembler::new(0);
    for _ in 0..40 {
        a.extend(call_keccak(BUF / 4));
    }
    a.extend(halt());
    let p = a.assemble();
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(10).max_cycles()).unwrap();
    assert_eq!(exec.events.iter().filter(|e| e.keccak_row.is_some()).count(), 40);
    let t = build_traces_salted(&p, &[], &[], [0; 4], &exec, Tier(10)).unwrap();
    let accesses: usize = exec.events.iter().map(|e| e.accesses.len() + e.keccak_accesses.len()).sum();
    assert!(((1 << 12)..1 << 13).contains(&accesses), "{accesses} accesses: past the floor, inside one more bit");
    assert_eq!(t.mem_log_height, 13, "the access count now drives the height");
    assert_eq!(t.memory.height(), 1 << 13);
    // 40 permutations need 40 blocks -> 1 280 rows -> 2^11, comfortably inside tier 10's own
    // ceiling of `t + 5 = 15`.
    assert_eq!(t.keccak_log_height, 11);
    let proof = m.prove_traces(&p, &t, Tier(10));
    assert_eq!(proof.mem_log_height, 13);
    m.verify(&p.digest(), &proof).unwrap();
}

/// M4.4: the end-to-end anchor for the whole `SHA256` path — the guest's own padding, the
/// `SYS_SHA256` cpu row, the sha256 chip's 64 rounds and its own 32 `MEMORY` accesses, the
/// proof-declared sha256 height — checked against the host `sha256::sha256` for the same
/// message. One 55-byte message is one padded 512-bit block, i.e. exactly one compression, so
/// `sha256_log_height` sits at its floor of 6 (one 64-row block).
#[test]
fn sha256_demo_proves_and_verifies_with_one_sha256_block() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::sha256_demo();
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(10).max_cycles()).unwrap();
    // 55 bytes: the largest message whose `0x80 ‖ zeros ‖ be64(bitlen)` padding still fits one
    // 64-byte block. `guests::SHA256_DEMO_MSG` is the same literal the guest hashes; the length
    // assertion is what keeps the two from drifting into a two-block message, which
    // `sha256_demo` (a single `SHA256` call, no Merkle–Damgård loop) could not hash.
    let msg = b"The quick brown fox jumps over the lazy dog............";
    assert_eq!(msg.len(), 55, "one padded block");
    assert_eq!(msg, guests::SHA256_DEMO_MSG, "the test and the guest hash the same message");
    let want = randprotocol_zkvm::sha256::sha256(msg);
    for k in 0..8 {
        assert_eq!(
            exec.outputs[k],
            u32::from_be_bytes(want[4 * k..4 * k + 4].try_into().unwrap()),
            "digest word {k}",
        );
    }
    assert_eq!(exec.events.iter().filter(|e| e.sha256_row.is_some()).count(), 1, "one compression");
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove_salted(&p, &[], &[], [1, 2, 3, 4], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(proof.tier, Tier(10));
    assert_eq!(proof.sha256_log_height, 6, "one compression fills the minimum block exactly");
    assert_eq!(proof.keccak_log_height, 0, "and it calls no KECCAK, so that table is absent");
    // Ten instances: the nine every proof carries (constraint set 6's mandatory `public` table
    // included) plus the sha256 chip. The keccak chip is the one that is absent here — sha256
    // takes its slot in `chips()` order, so a batch can carry either, both or neither.
    assert_eq!(proof.batch.degree_bits.len(), 10, "nine mandatory tables plus sha256");
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "sha256_demo(55 bytes): tier {:?}, {} cycles, proof {} bytes, prove {:?}, verify {:?}",
        proof.tier, exec.cycles(), proof.size(), prove_time, t1.elapsed()
    );
}

/// The sha256 table is optional per proof exactly as the keccak table is (M4.2 Task 6's
/// pattern, applied to a 466-column chip): a guest that never executes `SHA256` declares
/// `sha256_log_height = 0` and the batch has no sha256 instance at all, which is what makes a
/// cpu row claiming `SYS_SHA256` unprovable there (`tests/cheating.rs::
/// sha256_row_without_a_sha256_table_is_rejected`).
#[test]
fn a_sha256_free_proof_carries_no_sha256_table() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove_salted(&p, &[], &[], [1, 2, 3, 4], Some(Tier(10))).unwrap();
    assert_eq!(proof.sha256_log_height, 0, "no SHA256 call, no sha256 table");
    assert_eq!(proof.keccak_log_height, 0, "and no KECCAK call either");
    assert_eq!(proof.batch.degree_bits.len(), 9, "the nine tables every proof carries");
    m.verify(&p.digest(), &proof).unwrap();
}

/// What one declared sha256 table costs a proof, measured the way M4.2 measured keccak's: the
/// **same guest**, the same tier, the same declared heights, differing only in whether the batch
/// carries the sha256 instance. `fib(10)` makes no `SHA256` call, so its honest sha256 table is a
/// single all-padding block — which is a perfectly provable witness (AGENTS.md invariant 2: with
/// `IS_REAL = 0` every bus count on every row is zero, so the block sends no memory traffic and
/// provides no `SHA256` entry), and that is exactly the shape a non-optional chip would have
/// forced on every proof in existence. Both proofs verify; the delta between them is the number
/// `docs/03-privacy.md` carries.
///
/// The assertions are deliberately loose (the hiding PCS moves each encoding ~1% run to run);
/// what they pin is the order of magnitude, i.e. that the instance is neither free nor
/// keccak-sized.
#[test]
fn a_declared_sha256_table_costs_about_a_hundred_kilobytes_at_the_test_profile() {
    use randprotocol_zkvm::machine::build_traces_salted;
    use randprotocol_zkvm::tables::sha256;
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(10).max_cycles()).unwrap();
    let mut t = build_traces_salted(&p, &[], &[], [1, 2, 3, 4], &exec, Tier(10)).unwrap();
    assert_eq!(t.sha256_log_height, 0, "fib makes no SHA256 call");
    let free = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p.digest(), &free).unwrap();

    t.sha256 = Some(sha256::sha256_trace(&[], sha256::MIN_LOG_HEIGHT));
    t.sha256_log_height = sha256::MIN_LOG_HEIGHT;
    let carried = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p.digest(), &carried).unwrap();

    let (a, b) = (free.size(), carried.size());
    eprintln!(
        "Test profile, tier 10, fib(10): sha256 table absent {a} bytes, one padding block {b} bytes, delta {} bytes",
        b as i64 - a as i64,
    );
    assert!(b > a + 50_000, "a 466 + 10-column instance is not free: {a} -> {b}");
    assert!(b < a + 200_000, "nor is it keccak-sized: {a} -> {b}");
}

/// The same comparison at the profile that actually ships (80 queries, blowup 8, 20 PoW bits) —
/// the number `docs/03-privacy.md`'s profile table needs, and the one that says whether a guest
/// calling `SHA256` still fits the node's proof cap. Ignored for the same reason
/// `measure_production_profile_at_tier_10_and_12` is: two production-profile proofs are ~13 s.
#[test]
#[ignore]
fn measure_the_sha256_table_cost_at_the_production_profile() {
    use randprotocol_zkvm::machine::build_traces_salted;
    use randprotocol_zkvm::tables::sha256;
    let m = Machine::new(FriProfile::Production);
    let p = guests::fib(10);
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(10).max_cycles()).unwrap();
    let mut t = build_traces_salted(&p, &[], &[], [1, 2, 3, 4], &exec, Tier(10)).unwrap();
    let t0 = std::time::Instant::now();
    let free = m.prove_traces(&p, &t, Tier(10));
    let free_prove = t0.elapsed();
    m.verify(&p.digest(), &free).unwrap();
    t.sha256 = Some(sha256::sha256_trace(&[], sha256::MIN_LOG_HEIGHT));
    t.sha256_log_height = sha256::MIN_LOG_HEIGHT;
    let t1 = std::time::Instant::now();
    let carried = m.prove_traces(&p, &t, Tier(10));
    let carried_prove = t1.elapsed();
    m.verify(&p.digest(), &carried).unwrap();
    println!(
        "Production profile, tier 10, fib(10): sha256 absent {} bytes ({:?} to prove), one block {} bytes ({:?}), delta {} bytes",
        free.size(), free_prove, carried.size(), carried_prove,
        carried.size() as i64 - free.size() as i64,
    );
    // And a guest that genuinely hashes, for the whole-proof number.
    let d = guests::sha256_demo();
    let t2 = std::time::Instant::now();
    let (proof, dexec) = m.prove_salted(&d, &[], &[], [1, 2, 3, 4], Some(Tier(10))).unwrap();
    let demo_prove = t2.elapsed();
    m.verify(&d.digest(), &proof).unwrap();
    println!(
        "Production profile, tier 10, sha256_demo: {} words, {} cycles, slh {}, mem 2^{}, {} bytes ({:?} to prove)",
        d.words.len(), dexec.cycles(), proof.sha256_log_height, proof.mem_log_height, proof.size(), demo_prove,
    );
}

#[test]
fn tier_padding_hides_cycle_count() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(5);
    let (p10, e) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
    let (p12, _) = m.prove(&p, &[], &[], Some(Tier(12))).unwrap();
    assert!(e.cycles() < 100);
    m.verify(&p.digest(), &p10).unwrap();
    m.verify(&p.digest(), &p12).unwrap();
    assert_ne!(p10.batch.degree_bits, p12.batch.degree_bits);
    assert_eq!(p10.public_values[1], 10);
    assert_eq!(p12.public_values[1], 12);
}

#[test]
fn a_fresh_verifier_accepts_the_proof() {
    let prover = Machine::new(FriProfile::Test);
    let verifier = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = prover.prove(&p, &[], &[], None).unwrap();
    // M3.4: the verifier never touches `p`'s words at all — only its digest, `hc`, which
    // both sides compute identically (`Program::digest` is a pure host-side function, no
    // `Machine` involved) and which the proof itself carries as a public value.
    verifier.verify(&p.digest(), &proof).unwrap();
    assert_eq!(p.code_hash(), p.digest().iter().map(|w| format!("{w:08x}")).collect::<String>());
    assert_ne!(p.code_hash(), guests::fib(11).code_hash());
}

#[test]
fn verifier_key_is_cached_after_first_verify() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove(&p, &[], &[], None).unwrap();
    let t0 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    let first = t0.elapsed();
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    let second = t1.elapsed();
    // Threshold retuned in M2.3: splitting the 2^16-row byte table into the 256-row range
    // and nibble tables made the uncached key build itself much cheaper, so the fixed
    // per-verify FRI-opening cost that caching can't remove is now a bigger share of
    // `first` — the measured ratio dropped from well under 10% to a consistent ~23-24%
    // (repeated locally), so 10% is no longer a safe bound. 40% keeps a comfortable margin
    // above that while still requiring a real, substantial caching win, not just noise.
    assert!(
        second < first * 2 / 5,
        "cached verify should be under 40% of the first: first={first:?} second={second:?}"
    );
    assert_eq!(m.cached_keys(), 1);

    // M4.2 (Task 6): `keccak_log_height` is part of the cache key, and `0` (no keccak table,
    // eight instances) is a *distinct* key from `5` (one block, nine instances) — they are
    // different chip sets, so they cannot share a `CommonData`. Everything else held equal
    // (same tier, same declared program/input heights), asking for both must miss the
    // cache separately and hand back two different keys.
    assert_eq!(proof.keccak_log_height, 0, "fib is keccak-free");
    assert_eq!(proof.sha256_log_height, 0, "and sha256-free");
    let (t, plh, ilh, plub) = (proof.tier, proof.program_log_height, proof.input_log_height, proof.public_log_height);
    let bare = m.verifier_key(t, plh, ilh, 0, 0, plub);
    assert_eq!(m.cached_keys(), 1, "the hash-table-free key is the one `verify` already cached");
    let with_keccak = m.verifier_key(t, plh, ilh, 5, 0, plub);
    assert_eq!(m.cached_keys(), 2, "`keccak_log_height = 5` is a different cache key from `0`");
    assert!(!std::sync::Arc::ptr_eq(&bare, &with_keccak));
    // M4.4: `sha256_log_height` is the key's fifth component, and independent of the fourth —
    // the four combinations of "declares a keccak table" x "declares a sha256 table" are four
    // different chip sets and therefore four different `CommonData`s.
    let with_sha256 = m.verifier_key(t, plh, ilh, 0, 6, plub);
    assert_eq!(m.cached_keys(), 3, "`sha256_log_height = 6` is a different cache key again");
    let with_both = m.verifier_key(t, plh, ilh, 5, 6, plub);
    assert_eq!(m.cached_keys(), 4, "and both together is a fourth");
    assert!(!std::sync::Arc::ptr_eq(&with_keccak, &with_sha256));
    assert_eq!(bare.lookups.len(), 9, "nine instances");
    assert_eq!(with_keccak.lookups.len(), 10, "ten instances");
    assert_eq!(with_sha256.lookups.len(), 10, "ten instances — sha256 in keccak's place");
    assert_eq!(with_both.lookups.len(), 11, "eleven instances");
}

#[test]
#[ignore]
fn measure_production_profile_at_tier_10_and_12() {
    let m = Machine::new(FriProfile::Production);
    // `fib(650)` runs 3910 cycles: past tier 10's max (1023) and within tier 12's max
    // (4095), so `prove(.., Some(Tier(12)))` actually exercises tier 12's padded height
    // rather than erroring `TooManyCycles` (as `fib(900)`, 5410 cycles, does).
    for (label, tier, n) in [("tier 10", Tier(10), 10u32), ("tier 12", Tier(12), 650u32)] {
        let p = guests::fib(n);
        let t0 = std::time::Instant::now();
        let (proof, _) = m.prove(&p, &[], &[], Some(tier)).unwrap();
        let prove_time = t0.elapsed();
        let t1 = std::time::Instant::now();
        m.verify(&p.digest(), &proof).unwrap();
        let verify_time = t1.elapsed();
        println!("{label}: proof size = {} bytes, prove = {:?}, verify = {:?}", proof.size(), prove_time, verify_time);
    }
    // Audit ZM1 (2026-09-12): what a proof that *does* carry the keccak table costs at the
    // restored 80-query profile — the same comparison `docs/03-privacy.md`'s M4.2 table makes,
    // re-measured because FRI leaf openings scale with the query count.
    let msg: Vec<u8> = (0..64u8).collect();
    let p = guests::keccak_demo(&msg);
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(proof.keccak_log_height, 5);
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    println!("tier 10 with a keccak table: proof size = {} bytes, prove = {:?}, verify = {:?}", proof.size(), prove_time, t1.elapsed());
}

#[test]
fn compiled_fib_matches_the_hand_written_guest() {
    use randprotocol_zkvm::emulator::execute;
    let compiled = guests::compiled::fib();
    let hand = guests::fib(20);
    let exec_c = execute(&compiled, &[20], &[], 50_000).unwrap();
    let exec_h = execute(&hand, &[], &[], 50_000).unwrap();
    assert_eq!(exec_c.outputs[0], exec_h.outputs[0]);
}

#[test]
fn compiled_fib_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::fib();
    let (proof, exec) = m.prove(&p, &[20], &[], None).unwrap();
    eprintln!("compiled fib(20): tier {:?}, {} cycles, proof {} bytes", proof.tier, exec.cycles(), proof.size());
    m.verify(&p.digest(), &proof).unwrap();
}

/// The M4.2 exit test: Keccak-256 of a 135-byte message (one byte shy of the 136-byte rate, so
/// the `0x01`/`0x80` padding still fits the same block) computed by a *compiled* guest —
/// `guest_sdk::keccak256`'s sponge over the `KECCAK` syscall, built by
/// `guests-compiled/keccak256`'s Makefile — matches the host `keccak::keccak256`, in exactly one
/// permutation, and the whole thing proves and verifies.
#[test]
fn compiled_keccak256_matches_the_host_in_one_permutation() {
    use randprotocol_zkvm::keccak;
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::keccak256();
    let msg: Vec<u8> = (0..135u8).map(|i| i.wrapping_mul(31)).collect();
    let mut inputs = vec![msg.len() as u32];
    for c in msg.chunks(4) {
        let mut w = [0u8; 4];
        w[..c.len()].copy_from_slice(c);
        inputs.push(u32::from_le_bytes(w));
    }
    let exec = randprotocol_zkvm::emulator::execute(&p, &inputs, &[], Tier(12).max_cycles()).unwrap();
    let want = keccak::keccak256(&msg);
    for k in 0..8 {
        assert_eq!(exec.outputs[k], u32::from_le_bytes(want[4 * k..4 * k + 4].try_into().unwrap()), "digest word {k}");
    }
    assert_eq!(exec.events.iter().filter(|e| e.keccak_row.is_some()).count(), 1, "one rate block, one permutation");
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove_salted(&p, &inputs, &[], [5, 6, 7, 8], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(proof.keccak_log_height, 5, "one permutation fits the minimum block");
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "keccak256 guest: {} words, {} cycles, tier {}, keccak_log_height {}, mem_log_height {}, proof {} bytes, prove {:?}, verify {:?}",
        p.words.len(), exec.cycles(), proof.tier.0, proof.keccak_log_height, proof.mem_log_height,
        proof.to_bytes().len(), prove_time, t1.elapsed()
    );
}

/// Audit ZM2 (2026-09-12), a *completeness* regression: the memory table's host-side sort key
/// packed `(space << 30) | addr` while the AIR recomputes `SPACE·2^30 + ADDR`. The two coincide
/// only below `addr < 2^30` — and `POSEIDON2`'s derived addresses legitimately reach past it
/// (`HASH_PTR < 2^30` is the AIR's bound, plus up to 4099 words). With `|`, an honest execution
/// whose hash addresses straddle `2^30` sorted its rows into an order whose in-circuit keys
/// *decrease* at the boundary, and the `dk` delta limbs then rejected the honest witness (and
/// `(1, x)` / `(1, 2^30 + x)` collided into one key outright). Latent only because every
/// current guest uses low memory; the hash syscall is exactly the feature that can reach there.
///
/// `ptr = 2^30 - 4` with `n = 4`: the absorb row reads `2^30-4 .. 2^30-1`, and the two
/// write-back rows write `2^30-4 .. 2^30+3` — straddling the boundary in one honest call.
#[test]
fn a_hash_call_whose_addresses_straddle_2_to_the_30_proves() {
    let m = Machine::new(FriProfile::Test);
    let mut a = Assembler::new(0);
    a.extend(call_poseidon2(((1u32 << 30) - 4) as i32, 4));
    a.extend(li(5, 7));
    a.extend(write_output(0, 5));
    a.extend(halt());
    let p = a.assemble();
    let (proof, exec) = m.prove(&p, &[], &[], None).unwrap();
    assert_eq!(exec.outputs[0], 7);
    m.verify(&p.digest(), &proof).unwrap();
}

/// **M4.3's exit test, part 1 — always run.** An ERC-20 `transfer` — Solidity's own runtime
/// bytecode, run by the compiled EVM interpreter guest with the contract's storage supplied as
/// depth-32 Poseidon2 Merkle witnesses — executes in the guest and its public output binds the
/// state-root transition; the workload's tier is pinned here too.
///
/// Part 2, the proof itself, is `compiled_evm_erc20_transfer_proves_at_tier_18`, which is
/// `#[ignore]`d: a tier-18 batch is 2^18 cpu rows, 2^20 memory and poseidon2 rows and a 2 612-column
/// keccak table, and three attempts on a quiet 48 GB machine were SIGKILLed at ≥ 28.5 GB resident
/// with the resident set still growing. The always-run proof of this same guest binary is
/// `compiled_evm_storage_read_write_and_return_proves_and_verifies` below, which fits tier 16.
///
/// The pre-state seeds `_balances[ALICE] = 1000` and `_totalSupply` through witnesses, so the
/// runtime bytecode alone executes (there is no constructor). The guest's eight outputs are
/// checked against a native run of the same `evm-core` code — a proof only says that *some*
/// consistent execution exists, so the semantics are pinned on the host — and the digest is then
/// recomputed from the host's own post-state root, which is what "the transition is bound" means:
/// a verifier holding `(codehash, pre_root, post_root, return data, logs)` gets these seven words
/// and no other post-root does.
#[test]
fn compiled_evm_erc20_transfer_binds_the_state_root_transition() {
    use evm_core::u256::U256;
    use randprotocol_zkvm::emulator::execute;
    use randprotocol_zkvm::evm::{erc20_transfer, ALICE, BOB};
    use randprotocol_zkvm::hash::input_digest_row_count;
    let p = guests::compiled::evm();
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let inputs = call.input_words();
    let (want, outcome, post) = call.expected();
    assert_eq!(outcome.status(), 1, "the native run must succeed");
    assert_eq!(outcome.n_logs, 1, "one Transfer event");
    assert_ne!(post.root(), call.tree.root(), "the transfer moved the storage root");

    // `Tier(18)` is the machine's next rung above 16: `machine::TIERS` is [10, 12, 14, 16, 18, 20],
    // even only, so a workload over tier 16's 65 535 cycles pays for 2^18 rows whatever it uses.
    let exec = execute(&p, &inputs, &[], Tier(18).max_cycles()).unwrap();
    assert_eq!(exec.outputs, want, "the guest's outputs disagree with the native run");

    // The tier the prover would pick, pinned as a number without paying for the proof: this is the
    // same arithmetic `Machine::prove` does with `tier: None` (`exec.cycles()` plus both digest
    // prefixes, against the cycle and Poseidon2-permutation budgets).
    let digest_rows = p.digest_rows();
    let indigest_rows = input_digest_row_count(inputs.len());
    let absorb = exec.events.iter().filter(|e| e.hash_row.is_some()).count();
    let cycles = exec.cycles() + digest_rows + indigest_rows;
    let perms = digest_rows + indigest_rows + absorb;
    eprintln!(
        "evm erc20 transfer: {} program words ({} of prologue), {} input words, {} cycles ({} executed + {} digest + {} indigest), {} poseidon2 permutations, {} keccak permutations, tier {:?}",
        p.words.len(), (0x1_0000 - p.base_pc) / 4, inputs.len(), cycles, exec.cycles(), digest_rows, indigest_rows,
        perms, exec.events.iter().filter(|e| e.keccak_row.is_some()).count(),
        Tier::for_workload(cycles, perms)
    );
    // The plan's exit criterion was tier ≤ 16 and the spec's estimate tier 14; the measured cost is
    // tier 18 — pinned so any change to the interpreter, the guest's program size or the input
    // layout that moves the cost fails a test rather than quietly growing a proof. Tier 16 would
    // need the whole call under 65 535 cycles, i.e. roughly half of what it costs
    // (`docs/05-roadmap.md`'s deviation 7 has the breakdown and the named follow-ups).
    assert_eq!(Tier::for_workload(cycles, perms), Some(Tier(18)), "M4.3 measures at tier 18");
    assert!(cycles > Tier(16).max_cycles(), "and not because of the permutation budget");

    // the post-tree the host derived agrees with what the guest bound: recompute the digest from
    // the host's post root, and check no *other* root gives these words.
    let mut h = randprotocol_zkvm::evm::HostRef;
    assert_eq!(
        evm_core::abi::public_output(&mut h, &call.code, &call.tree.root(), &post.root(), &outcome),
        want
    );
    assert_ne!(
        evm_core::abi::public_output(&mut h, &call.code, &call.tree.root(), &call.tree.root(), &outcome),
        want,
        "the pre-root must not produce the same digest as the post-root"
    );
}

/// **M4.3's exit test, part 2** — the ERC-20 `transfer` proof itself, `#[ignore]`d because of its
/// memory, not its correctness. The workload is tier 18 (2^18 cpu rows, 2^20 memory and poseidon2
/// rows, plus the 2 612-column keccak table), and **three attempts on an otherwise quiet 48 GB
/// machine were SIGKILLed with a maximum resident set of 28.5–28.9 GB** — still growing when the OS
/// stepped in, so the requirement is above that and a **≥ 64 GB** machine is the safe figure. Run it
/// there, explicitly:
///
/// ```text
/// cd research && cargo +1.98.1 test --release --test e2e \
///     compiled_evm_erc20_transfer_proves_at_tier_18 -- --ignored --nocapture
/// ```
///
/// Everything about the call that does *not* need that memory — the guest's outputs against a native
/// run, the digest binding, the tier arithmetic — is asserted by part 1, which always runs, and the
/// same guest binary, `hc` and output digest are proved at tier 16 by the test below. What this one
/// adds is the end-to-end fact in the milestone's own wording: this proof verifies. The other way to
/// get it is the storage `MERKLE_VERIFY`-syscall follow-up, which would put the transfer under tier
/// 16 and its proof within a laptop (`docs/04-guests.md`, `docs/05-roadmap.md`'s deviation 7).
#[test]
#[ignore]
fn compiled_evm_erc20_transfer_proves_at_tier_18() {
    use evm_core::u256::U256;
    use randprotocol_zkvm::evm::{erc20_transfer, ALICE, BOB};
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::evm();
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let inputs = call.input_words();
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove_salted(&p, &inputs, &[], [9, 10, 11, 12], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(exec.outputs, call.expected().0);
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "evm erc20 transfer proof: tier {}, keccak_log_height {}, mem_log_height {}, proof {} bytes, prove {:?}, verify {:?}",
        proof.tier.0, proof.keccak_log_height, proof.mem_log_height, proof.to_bytes().len(),
        prove_time, t1.elapsed()
    );
    assert_eq!(proof.tier.0, 18);
}

/// The compiled EVM guest proved and verified **inside the suite**: a call that reads a storage
/// slot, writes it back incremented and returns it — `SLOAD`, `SSTORE`, `MSTORE`, `RETURN`, one
/// witness verified and one Merkle path recomputed — through the same `evm.bin`, the same `hc` and
/// the same `EVM_OUT` output digest as the ERC-20 transfer, at tier 16 rather than 18 because 18
/// bytes of bytecode need neither the ERC-20's 1 296-byte `codehash` nor its second Merkle walk.
///
/// This is the test that says "the EVM interpreter guest is provable": the storage tree, the
/// 256-bit arithmetic, the `POSEIDON2` walk and the public output are all in-circuit here. The
/// ERC-20 transfer above is the same machinery on a bigger call.
#[test]
fn compiled_evm_storage_read_write_and_return_proves_and_verifies() {
    use evm_core::u256::U256;
    use randprotocol_zkvm::evm::{EvmCall, SparseTree};
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::evm();
    let mut tree = SparseTree::new();
    tree.insert(U256::from_u32(1), U256::from_u32(41));
    // PUSH1 1; SLOAD; PUSH1 1; ADD; PUSH1 1; SSTORE; PUSH1 1; SLOAD; PUSH0; MSTORE; PUSH1 32;
    // PUSH0; RETURN — reads slot 1 (41), writes 42 back and returns it.
    let call = EvmCall {
        code: vec![
            0x60, 0x01, 0x54, 0x60, 0x01, 0x01, 0x60, 0x01, 0x55, 0x60, 0x01, 0x54, 0x5f, 0x52,
            0x60, 0x20, 0x5f, 0xf3,
        ],
        calldata: vec![],
        address: U256::from_u32(0xaaaa),
        caller: U256::from_u32(0xcafe),
        callvalue: U256::ZERO,
        gas_limit: 100_000,
        tree,
        touched: vec![U256::from_u32(1)],
    };
    let inputs = call.input_words();
    let (want, outcome, post) = call.expected();
    assert_eq!(outcome.status(), 1);
    assert_eq!(&outcome.ret[..outcome.ret_len], &U256::from_u32(42).to_be_bytes());
    assert_ne!(post.root(), call.tree.root(), "the SSTORE moved the root");

    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove_salted(&p, &inputs, &[], [13, 14, 15, 16], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(exec.outputs, want, "the guest's outputs disagree with the native run");
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    eprintln!(
        "evm sload/sstore/return: {} program words, {} input words, {} cycles, {} poseidon2 permutations, {} keccak permutations, tier {}, keccak_log_height {}, mem_log_height {}, proof {} bytes, prove {:?}, verify {:?}",
        p.words.len(), inputs.len(), exec.cycles(),
        exec.events.iter().filter(|e| e.hash_row.is_some()).count(),
        exec.events.iter().filter(|e| e.keccak_row.is_some()).count(),
        proof.tier.0, proof.keccak_log_height, proof.mem_log_height, proof.to_bytes().len(),
        prove_time, t1.elapsed()
    );
    assert_eq!(proof.tier.0, 16, "one witness and 18 bytes of code fit tier 16");
}

/// `balanceOf`, `approve` and a `transfer` that exceeds the balance all run under the same guest
/// binary — one interpreter, four call shapes — and the revert carries the `require` message.
///
/// Executed, not proved: the proof in the exit test above is what shows the guest provable, and a
/// second (four-minute) proof of the same program with different private inputs would add nothing
/// to it. These run on the emulator, which is the same semantics the AIR enforces.
#[test]
fn compiled_evm_balance_of_approve_and_a_revert_execute_correctly() {
    use evm_core::u256::U256;
    use randprotocol_zkvm::emulator::execute;
    use randprotocol_zkvm::evm::*;
    let p = guests::compiled::evm();
    let cycles = Tier(18).max_cycles();

    // balanceOf(ALICE) returns the seeded balance and touches only that slot
    let mut bal = erc20_transfer(ALICE, BOB, U256::ZERO, &[(ALICE, U256::from_u32(1000))]);
    bal.calldata = abi_call("balanceOf(address)", &[ALICE]);
    bal.touched = vec![mapping_slot(&ALICE, SLOT_BALANCES)];
    let (want, o, bal_post) = bal.expected();
    assert_eq!(o.status(), 1);
    assert_eq!(U256::from_be_slice(&o.ret[..32]), U256::from_u32(1000));
    assert_eq!(bal_post.root(), bal.tree.root(), "a view call moves no storage");
    assert_eq!(execute(&p, &bal.input_words(), &[], cycles).unwrap().outputs, want);

    // approve(BOB, 5): writes _allowances[ALICE][BOB] — the *nested* mapping, whose key is
    // keccak(BOB ‖ keccak(ALICE ‖ 1)) — and emits one Approval
    let mut ap = erc20_transfer(ALICE, BOB, U256::ZERO, &[]);
    ap.calldata = abi_call("approve(address,uint256)", &[BOB, U256::from_u32(5)]);
    ap.touched = vec![mapping_slot2(&ALICE, &BOB, SLOT_ALLOWANCES)];
    let (want_ap, o_ap, ap_post) = ap.expected();
    assert_eq!(o_ap.status(), 1);
    assert_eq!(o_ap.n_logs, 1, "Approval");
    assert_eq!(o_ap.logs[0].n_topics, 3);
    assert_ne!(ap_post.root(), ap.tree.root(), "the allowance was written");
    assert_eq!(execute(&p, &ap.input_words(), &[], cycles).unwrap().outputs, want_ap);

    // transfer of 5000 against a balance of 1000 reverts with the require message
    let over = erc20_transfer(ALICE, BOB, U256::from_u32(5000), &[(ALICE, U256::from_u32(1000))]);
    let (want_r, o_r, over_post) = over.expected();
    assert_eq!(o_r.status(), 0);
    // The revert data is Solidity's ABI-encoded `Error(string)`, not the bare message: the
    // selector, the string's offset, its length, then the padded bytes. Decoding it is the point —
    // a `require` message reaches the chain only through the public output's return-data hash, so
    // the guest has to reproduce the encoding byte for byte, padding included.
    assert_eq!(&o_r.ret[..4], &selector("Error(string)"), "an ABI-encoded Error(string)");
    assert_eq!(U256::from_be_slice(&o_r.ret[4..36]), U256::from_u32(0x20), "the string's offset");
    let n = U256::from_be_slice(&o_r.ret[36..68]).low_u32() as usize;
    assert_eq!(
        core::str::from_utf8(&o_r.ret[68..68 + n]).unwrap(),
        "ERC20: transfer amount exceeds balance"
    );
    assert_eq!(o_r.ret_len, 68 + n.next_multiple_of(32), "the message is right-padded to a word");
    assert_eq!(over_post.root(), over.tree.root(), "a revert moves no storage");
    assert_eq!(execute(&p, &over.input_words(), &[], cycles).unwrap().outputs, want_r);

    // every one of the four calls is a different public output under one program digest
    let exit = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let outs = [want, want_ap, want_r, exit.expected().0];
    for (i, a) in outs.iter().enumerate() {
        for b in &outs[i + 1..] {
            assert_ne!(a, b, "two calls must not share a public output");
        }
    }
}

/// What an EVM-call proof costs at the profile a chain would use (80 queries, blowup 8, 20 PoW
/// bits), the figure `docs/03-privacy.md` and `docs/04-guests.md` quote: the keccak table is
/// present, so this is far above the keccak-free guests' ~1.25 MB. Ignored by default — one
/// production-profile tier-16 proof is minutes of wall time.
#[test]
#[ignore]
fn measure_production_profile_evm_erc20_transfer() {
    use evm_core::u256::U256;
    use randprotocol_zkvm::evm::{erc20_transfer, ALICE, BOB};
    let m = Machine::new(FriProfile::Production);
    let p = guests::compiled::evm();
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let inputs = call.input_words();
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove_salted(&p, &inputs, &[], [9, 10, 11, 12], None).unwrap();
    let prove_time = t0.elapsed();
    assert_eq!(exec.outputs, call.expected().0);
    let t1 = std::time::Instant::now();
    m.verify(&p.digest(), &proof).unwrap();
    println!(
        "evm erc20 transfer at the production profile: tier {}, keccak_log_height {}, proof {} bytes, prove {:?}, verify {:?}",
        proof.tier.0, proof.keccak_log_height, proof.to_bytes().len(), prove_time, t1.elapsed()
    );
}

// ---- M4.4's exit test: an SPL Token `Transfer` through the compiled sBPF guest ------------------
//
// **Superseded by the public input segment (constraint set 6), which took remedy (B) below.** The
// ELF is now the *public* input vector, so `H_PUB` binds it and the guest neither carries it on the
// private tape nor hashes it, and `input_hash` is over the canonical unpadded encoding rather than
// the aligned region: 1 753 945 cycles became **694 498** and 2 368 SHA-256 compressions became
// **30**, which fits `Tier(20)`. The proof itself, the tier it lands at and the fate of the
// `#[ignore]`d test below are the next task's measurement; everything from here down is M4.4's
// record of *why* the segment exists, kept because it is the decision record.
//
// **The proving half of this exit test does not pass, and is `#[ignore]`d with the measurement that
// says why.** The guest is correct — `compiled_sbpf_spl_token_transfer_executes_and_publishes_the_
// bound_digest` below runs it in the machine's own executor and gets the eight words `sbpf-core`
// produces natively, over the real SPL Token ELF fetched from mainnet — but it takes **1 753 945
// cycles**, and the largest tier this machine has is 20, whose budget is 1 048 575
// (`machine::TIERS`). The M4.4 plan requires tier ≤ 18 (262 143).
//
// Measured breakdown (`docs/04-guests.md`, from a pc histogram over the guest's symbols): SHA-256
// 1 066 950 cycles (60.8 %), the input tape plus the interpreter 600 725 (34.2 %), the stack/heap
// zeroing 51 535 (2.9 %), `elf::load` ~22 000 (1.3 %). The 2 368 compressions decompose exactly:
//
// * **1 698 for `program_hash` = sha256(elf bytes)** over all 108 600 committed bytes. The ELF is
//   also 27 151 of the 37 609 input words, so carrying it and hashing it is ~1.20 M of the 1.75 M —
//   spent on a program the run otherwise reads a few thousand bytes of and executes 143 instructions
//   from.
// * 654 for `input_hash` over the *aligned* region, of which 40 960 of 41 825 bytes are
//   `MAX_PERMITTED_DATA_INCREASE` realloc padding — 98 % zeros, so 640 of those compressions hash
//   nothing else.
// * 8 + 8 for the pre- and post-state account walks.
//
// **The obvious fix is unsound, so do not try it.** Declaring `program_hash` instead of recomputing
// it does not work: `H_IN` is salted and *hiding* (M4.1, `docs/03-privacy.md`), so a verifier cannot
// check a claimed digest of the input words against it, and a `program_hash` the guest does not
// recompute is bound to nothing at all — a prover could run any ELF under a fresh salt and declare
// the SPL Token hash. The in-circuit hashing *is* the binding.
//
// The two sound paths both reach past this file (design spec §5.1 item 8 is the decision record):
//
// * **(A)** bake the ELF into the guest's **data segment**, so `hc` binds it — the image container
//   `Program::from_flat_image` makes the data part of `Program::words`. Estimated ~72-76 K prologue
//   words for ~27 150 data words, minus the ELF's compressions and input words: ~0.6 M cycles, i.e.
//   **tier 20**, provable only on much larger hardware, and one committed binary per Solana program.
//   Note it is also ~20 % over the loaders' 65 535-word program cap (`HASH_LEFT` is 16 bits) until
//   the prologue's repeated `lui` half is deduped.
// * **(B)** a **public, unsalted** segment in the input commitment, so a declared digest becomes
//   checkable: the guest hashes nothing and the run reaches **tier 18** — a constraint-set change
//   with its own spec addendum and plan, whose price is that the ELF words become public.
//   [Measured 2026-09-13, after B was built as constraint set 6: **`Tier(20)`, 694 498 cycles**,
//   not tier 18. The estimate above omitted the cost of *reading* 27 151 ELF words off the tape,
//   which `READ_PUBLIC` pays at the same ~15.8 cycles/word `READ_INPUT` did (~430 K of the total).
//   Tier 18 needs a bulk public-read syscall — spec §9.5's open item. See
//   `compiled_sbpf_spl_token_transfer_proves_and_verifies` below and `docs/04-guests.md`.]
//
// `input_hash` over a canonical unpadded encoding (~290 K cycles) is legitimate and is deferred into
// the same follow-up, because it changes the same binding "Public output" ruling.

/// M4.4's exit test, the executor half — this one passes. The compiled sBPF guest runs an SPL Token
/// `Transfer` over the ELF fetched from the live program account, and the eight public output words
/// it publishes are exactly the ones `sbpf-core` produces natively: `out0 = 1` (the program returned
/// `r0 == 0`) and `out1..7` the Poseidon2 digest over the program, the instruction and the accounts'
/// post-state, all three bound through SHA-256 and therefore through the M4.4 chip.
///
/// Every number the M4.4 plan asks Task 6 to record is printed here and pinned below.
#[test]
fn compiled_sbpf_spl_token_transfer_executes_and_publishes_the_bound_digest() {
    use randprotocol_zkvm::sbpf::{deserialize_accounts, spl_transfer, TOKEN_AMOUNT_AT};
    let p = guests::compiled::sbpf();
    let call = spl_transfer(250);
    let inputs = call.input_words();
    // The ELF is the public segment now: the chain publishes it and `H_PUB` binds it, which is what
    // lets the guest stop hashing it (`sbpf_core::abi`).
    let public = call.public_words();
    let (want, r0, post) = call.expected();
    assert_eq!(r0, Ok(0));
    assert_eq!(want[0], 1);

    // The transfer really moved the balance, in the fixture's own terms.
    let pre = deserialize_accounts(&call.input);
    let bal =
        |d: &[u8]| u64::from_le_bytes(d[TOKEN_AMOUNT_AT..TOKEN_AMOUNT_AT + 8].try_into().unwrap());
    assert_eq!(bal(&pre[0].data) - 250, bal(&post[0].data));
    assert_eq!(bal(&pre[1].data) + 250, bal(&post[1].data));

    // The cap is not a tier's budget: see the comment above this test. It is a bound that fails
    // loudly if the guest ever runs away, rather than the tier the plan asked for.
    const CYCLE_CAP: usize = 4_000_000;
    let exec = randprotocol_zkvm::emulator::execute(&p, &inputs, &public, CYCLE_CAP).unwrap();
    assert_eq!(exec.outputs, want, "the in-circuit guest and the native run must agree");

    let compressions = exec.events.iter().filter(|e| e.sha256_row.is_some()).count();
    // A pure function of the *canonical* encoding's length, which is what the public segment bought:
    // 14 compressions over the 837-byte canonical `input_hash` preimage, plus the pre- and
    // post-state account walks (8 each). The 1 698 for `program_hash` are gone entirely — the ELF is
    // public, so `H_PUB` binds it — and the 654 over the aligned region (98 % realloc padding) are
    // the 14.
    assert_eq!(compressions, 30, "14 canonical input_hash + 2x8 accounts, was 2 368");
    assert_eq!(
        randprotocol_zkvm::tables::sha256::sha256_log_height(compressions),
        11,
        "30 blocks of 64 rows",
    );
    // Two bounds, in both directions, and neither is decoration. The upper one catches a runaway;
    // the lower one is the tripwire that says the next tier down has come into reach. M4.4 measured
    // 1 753 945 cycles here and the lower tripwire was `Tier(20)`; the public segment took the ELF
    // off the private tape and `program_hash` out of the digest, and the canonical `input_hash`
    // took the realloc padding out of the hashing, so the guest now **fits `Tier(20)`** and the
    // tripwire moves down a tier: the day it fits `Tier(18)`, re-measure and re-tier the proof.
    //
    // Of the 694 498, ~116 000 are `check_region`'s scan over the **40 988** bytes the canonical
    // encoding does not hash — pinned to zero there, along with the flag bytes pinned to {0, 1} —
    // at ~2.8 cycles a byte. That is the price of binding them by pinning rather than by hashing: a
    // sixth of what hashing them cost.
    //
    // 40 988 is exactly 41 825 (the aligned region) minus 837 (the canonical preimage), which is
    // the arithmetic check that every byte of an accepted region is either hashed or pinned. It
    // decomposes as 40 960 realloc headroom (4 accounts x MAX_PERMITTED_DATA_INCREASE), 16 bytes of
    // `original_data_len` slot (4 x 4), and 12 bytes of alignment padding before each entry's
    // `rent_epoch` (3 + 3 + 0 + 6 for this fixture's 165/165/0/82-byte account data). An earlier
    // note said 40 972: that figure counted the headroom and the padding but dropped the four
    // `original_data_len` slots.
    assert!(
        exec.cycles() <= 720_000,
        "{} cycles, was 694 498 when the public segment landed (1 753 945 before it)",
        exec.cycles()
    );
    assert!(
        exec.cycles() <= Tier(20).max_cycles(),
        "{} cycles no longer fits Tier(20)'s {} budget",
        exec.cycles(),
        Tier(20).max_cycles()
    );
    assert!(
        exec.cycles() > Tier(18).max_cycles(),
        "{} cycles now fits Tier(18): re-measure the proof and the docs' tier table",
        exec.cycles()
    );
    // The sBPF instruction count is the interpreter's own meter, which only the native run can
    // report — the executor counts RV32 cycles, not sBPF instructions.
    let native = randprotocol_zkvm::sbpf::run_elf(&mut call.elf.clone(), &mut call.input.clone());
    assert_eq!(native.result, Ok(0));
    eprintln!(
        "sbpf spl transfer: {} program words, {} input words, {} cycles, {} sBPF instructions, \
         frame high-water {}, {} sha256 compressions, sha256_log_height {}, {} public words, \
         fits Tier(20)'s {} budget (max {:?})",
        p.len(),
        inputs.len(),
        exec.cycles(),
        native.instructions,
        native.max_depth,
        compressions,
        randprotocol_zkvm::tables::sha256::sha256_log_height(compressions),
        public.len(),
        Tier(20).max_cycles(),
        Tier(20),
    );
}

/// A transfer exceeding the source balance returns `TokenError::InsufficientFunds` (`r0 != 0`):
/// status 0, and the pre-state bound as the post-state. The executor agrees with the native run, so
/// the failure path is in-circuit code too — and it is the rule that stops a partial effect being
/// published.
#[test]
fn compiled_sbpf_spl_token_transfer_of_too_much_fails_cleanly() {
    let p = guests::compiled::sbpf();
    let call = randprotocol_zkvm::sbpf::spl_transfer(u64::MAX / 2);
    let (want, r0, post) = call.expected();
    assert!(matches!(r0, Ok(code) if code != 0));
    assert_eq!(want[0], 0);
    assert_eq!(post, randprotocol_zkvm::sbpf::deserialize_accounts(&call.input));
    let exec =
        randprotocol_zkvm::emulator::execute(&p, &call.input_words(), &call.public_words(), 4_000_000)
            .unwrap();
    assert_eq!(exec.outputs, want);
    // Status 0 is not the only difference from the success case: the digest words differ too,
    // because a successful transfer's post-state is not its pre-state.
    let ok = randprotocol_zkvm::sbpf::spl_transfer(250).expected().0;
    assert_ne!(&want[1..], &ok[1..], "the two runs must not publish the same digest");
}

/// **M4.4's exit test, the proving half** — the SPL Token `Transfer` proves and verifies, and the
/// verifier recomputes `H_PUB` from the published ELF words (`verify_public`) rather than taking the
/// guest's word for which program ran. Constraint set 6 moved it from *unprovable at any tier* to
/// **`Tier(20)`**: 1 753 945 cycles became 694 498 once the ELF left the private tape and
/// `input_hash` became the canonical encoding (the executor half above measures all of it).
///
/// Still `#[ignore]`d, and now for M4.3's reason rather than M4.4's — **memory, not correctness**.
/// A tier-20 batch is 2^20 cpu rows, 2^22 memory and poseidon2 rows and a 466-column sha256 table:
/// **four times the cpu rows** of the tier-18 EVM proof
/// (`compiled_evm_erc20_transfer_proves_at_tier_18`), which was SIGKILLed on this same otherwise
/// quiet 48 GB machine three times over with a **maximum resident set of 28.5–28.9 GB and still
/// growing**. This one was not attempted here at all: macOS swaps rather than failing fast, so the
/// attempt costs hours and tells you nothing the EVM proof has not already. A **≥ 64 GB** machine is
/// the figure M4.3 arrived at for a tier-18 batch; a tier-20 batch wants more than that again. Run
/// it there, explicitly:
///
/// ```text
/// cd research && cargo +1.98.1 test --release --test e2e \
///     compiled_sbpf_spl_token_transfer_proves_and_verifies -- --ignored --nocapture
/// ```
///
/// Everything about the call that does *not* need that memory is asserted by
/// `compiled_sbpf_spl_token_transfer_executes_and_publishes_the_bound_digest`, which always runs:
/// the guest's eight output words against the native interpreter, the compression count, the
/// `sha256_log_height`, and the cycle count tripwired in both directions. What this one adds is the
/// end-to-end fact in the milestone's own wording — this proof verifies, at a tier the machine has.
/// Getting it under a laptop needs the tape cost itself addressed (a bulk public-read syscall, one
/// cpu row per four words: spec §9.5's open item, `docs/04-guests.md`).
#[test]
#[ignore = "Tier(20): 694 498 cycles against its 1 048 575 budget — provable, but not on this \
            48 GB machine. A tier-20 batch is 4x the cpu rows of the tier-18 EVM proof, which was \
            SIGKILLed here three times at >= 28.5 GB resident and still growing; run this on a \
            >= 64 GB machine with `-- --ignored`. Constraint set 6 got it here from 1 753 945 \
            cycles and 2 368 compressions (now 30, sha256_log_height 11): the ELF is the public \
            segment, so H_PUB binds it and the guest hashes nothing, and input_hash is over the \
            837-byte canonical encoding. Tier 18 needs a bulk public-read syscall: \
            docs/04-guests.md, design spec 9.5"]
fn compiled_sbpf_spl_token_transfer_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::compiled::sbpf();
    let call = randprotocol_zkvm::sbpf::spl_transfer(250);
    let private = call.input_words();
    let public = call.public_words();
    let (want, _r0, _post) = call.expected();
    let exec =
        randprotocol_zkvm::emulator::execute(&p, &private, &public, Tier(20).max_cycles()).unwrap();
    assert_eq!(exec.outputs, want);
    let t0 = std::time::Instant::now();
    let (proof, _) = m.prove_salted(&p, &private, &public, [13, 14, 15, 16], None).unwrap();
    let prove_time = t0.elapsed();
    eprintln!(
        "sbpf spl transfer: {} program words, {} private input words, {} public words, {} cycles, \
         {} sha256 compressions, tier {}, sha256_log_height {}, public_log_height {}, \
         mem_log_height {}, proof {} bytes, prove {:?}",
        p.len(),
        private.len(),
        public.len(),
        exec.cycles(),
        exec.events.iter().filter(|e| e.sha256_row.is_some()).count(),
        proof.tier.0,
        proof.sha256_log_height,
        proof.public_log_height,
        proof.mem_log_height,
        proof.size(),
        prove_time,
    );
    // `verify_public`, not `verify`: the whole point of constraint set 6 is that a verifier holding
    // the ELF words recomputes `H_PUB` and checks it against `pv::PUB0..7`, which is what binds the
    // program now that the guest no longer hashes it. `verify` alone would accept a proof of some
    // *other* program's run.
    m.verify_public(&p.digest(), &public, &proof).unwrap();
    assert!(proof.tier.0 <= 20, "the public segment buys Tier(20); above it, re-measure");
    assert!(proof.sha256_log_height >= 6);
}

/// Where the sBPF guest's cycles go, as a pc histogram mapped onto the guest binary's symbols — the
/// breakdown the M4.4 plan asks for whenever the exit test lands above tier 16, and the measurement
/// `docs/04-guests.md`'s cost table is built from. Writes `sbpf-pc-histogram.txt` into the
/// temporary directory; pair it with
/// `llvm-nm -n --defined-only guests-compiled/sbpf/target/riscv32im-unknown-none-elf/release/sbpf-guest`.
/// `#[ignore]`d because it is a measurement, not an assertion.
#[test]
#[ignore = "measurement: writes a pc histogram for docs/04-guests.md"]
fn sbpf_cycle_breakdown_by_pc() {
    use std::collections::BTreeMap;
    let p = guests::compiled::sbpf();
    let call = randprotocol_zkvm::sbpf::spl_transfer(250);
    let exec =
        randprotocol_zkvm::emulator::execute(&p, &call.input_words(), &call.public_words(), 4_000_000)
            .unwrap();
    let mut hist: BTreeMap<u32, usize> = BTreeMap::new();
    for e in &exec.events {
        *hist.entry(e.pc).or_default() += 1;
    }
    let path = std::env::temp_dir().join("sbpf-pc-histogram.txt");
    let mut out = String::new();
    for (pc, n) in &hist {
        out.push_str(&format!("{pc} {n}\n"));
    }
    std::fs::write(&path, out).unwrap();
    eprintln!("{} distinct pcs, {} cycles -> {}", hist.len(), exec.cycles(), path.display());
}

/// The public segment end to end: a guest reads it, `H_PUB` is pinned in the public values, and a
/// verifier who holds the words recomputes the digest and accepts — which is the whole point of an
/// unsalted segment, and exactly what `H_IN` cannot do.
#[test]
fn public_echo_proves_and_verify_public_checks_the_words() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::public_echo();
    let public = [11u32, 22, 33, 44];
    let (proof, exec) = m.prove(&p, &[], &public, None).unwrap();
    assert_eq!(exec.outputs[0], 11 + 22 + 33 + 44 + 22); // public[1] is read twice
    m.verify(&p.digest(), &proof).unwrap();
    m.verify_public(&p.digest(), &public, &proof).unwrap();
    // pv::PUB0..7 is the native digest of exactly these words.
    let want = randprotocol_zkvm::hash::public_digest(&public);
    for i in 0..8 {
        assert_eq!(proof.public_values[randprotocol_zkvm::tables::cpu::pv::PUB0 + i], want[i] as u64);
    }
    // A verifier handed different words rejects, while the STARK itself still verifies.
    assert!(m.verify_public(&p.digest(), &[11, 22, 33, 45], &proof).is_err());
    assert!(m.verify_public(&p.digest(), &[11, 22, 33], &proof).is_err());
    assert_eq!(proof.public_log_height, randprotocol_zkvm::tables::public::public_log_height(4));
}

/// Every pre-existing guest keeps proving with an empty segment, and `H_PUB` is then the fixed
/// digest of the empty vector — so `verify_public(hc, &[], proof)` accepts.
#[test]
fn an_empty_public_segment_still_has_a_digest_and_costs_four_rows() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove(&p, &[], &[], None).unwrap();
    m.verify_public(&p.digest(), &[], &proof).unwrap();
    assert_eq!(proof.public_log_height, randprotocol_zkvm::tables::public::MIN_LOG_HEIGHT);
    let want = randprotocol_zkvm::hash::public_digest(&[]);
    for i in 0..8 {
        assert_eq!(proof.public_values[randprotocol_zkvm::tables::cpu::pv::PUB0 + i], want[i] as u64);
    }
}
