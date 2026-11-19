//! The per-instance quotient layout and rate 1/4 on the RV32 machine — live since constraint set
//! 11 (monorepo issue 64, ZKVM-111; `docs/05-roadmap.md`). `machine::QUOTIENT_LAYOUT` is
//! `PerInstance` and both profiles are blowup 4. These tests show the live layout is the one
//! `verify` checks, that a proof committed under the other layout is refused, that tampering with
//! the per-instance quotient opening is refused, and that the degree-8 cpu and alu tables prove at
//! blowup 4 with no AIR change. `tests/quotient_layout_heap.rs` measures the heap.
use p3_batch_stark::QuotientLayout::{self, PerChunk, PerInstance};
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::guests;
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::{build_traces, FriProfile, Machine, Proof, Tier, VerifyError, LOG_BLOWUP, QUOTIENT_LAYOUT};

fn prove(m: &Machine, p: &Program, tier: Tier, layout: QuotientLayout) -> Proof {
    let exec = execute(p, &[], &[], tier.max_cycles()).unwrap();
    let traces = build_traces(p, &[], &[], &exec, tier).unwrap();
    m.prove_traces_with_layout(&traces, tier, layout)
}

#[test]
fn the_live_layout_is_per_instance() {
    assert_eq!(QUOTIENT_LAYOUT, PerInstance);
}

/// A proof under either layout verifies under that layout and is refused under the other — and
/// the live `verify`, which is `PerInstance`, refuses a `PerChunk` proof.
#[test]
fn each_layout_verifies_its_own_proofs_and_refuses_the_others() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let hc = p.digest();
    let per_chunk = prove(&m, &p, Tier(10), PerChunk);
    let per_instance = prove(&m, &p, Tier(10), PerInstance);

    m.verify(&hc, &per_instance).expect("a PerInstance proof is a live proof");
    m.verify_with_layout(&hc, &per_instance, PerInstance).unwrap();
    m.verify_with_layout(&hc, &per_chunk, PerChunk).unwrap();

    let refused = |r: Result<(), VerifyError>| matches!(r, Err(VerifyError::Batch(_)));
    assert!(refused(m.verify(&hc, &per_chunk)), "the live verifier refuses a PerChunk proof");
    assert!(refused(m.verify_with_layout(&hc, &per_instance, PerChunk)));
    assert!(refused(m.verify_with_layout(&hc, &per_chunk, PerInstance)));

    // A live proof (the ordinary `prove`) is a PerInstance proof.
    let (live, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
    m.verify_with_layout(&hc, &live, PerInstance).unwrap();
    assert!(refused(m.verify_with_layout(&hc, &live, PerChunk)));
}

/// The layout does not weaken what the quotient opening binds: one opened quotient value
/// changed, in any instance, and the PerInstance proof is refused. Likewise a public value.
#[test]
fn a_tampered_per_instance_proof_is_refused() {
    use p3_field::PrimeCharacteristicRing;
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let hc = p.digest();
    let proof = prove(&m, &p, Tier(10), PerInstance);
    m.verify(&hc, &proof).unwrap();
    let bytes = postcard::to_allocvec(&proof).unwrap();
    let n = proof.batch.opened_values.instances.len();
    for i in 0..n {
        let mut bad: Proof = postcard::from_bytes(&bytes).unwrap();
        let chunks = &mut bad.batch.opened_values.instances[i].base_opened_values.quotient_chunks;
        let last = chunks.len() - 1;
        chunks[last][0] += randprotocol_zkvm::machine::Challenge::ONE;
        assert!(m.verify(&hc, &bad).is_err(), "instance {i}");
    }
    let mut bad: Proof = postcard::from_bytes(&bytes).unwrap();
    bad.public_values[randprotocol_zkvm::tables::cpu::pv::OUT0] ^= 1;
    assert!(m.verify(&hc, &bad).is_err());
}

/// What the layout changes in the proof: the same opened values, fewer bytes (one set of
/// random-codeword openings and one Merkle path per instance for the quotient round, not one
/// per chunk). Sizes are printed; the assertion is only the direction.
#[test]
fn the_per_instance_proof_is_smaller_and_opens_the_same_shape() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    for tier in [Tier(10), Tier(12)] {
        let a = prove(&m, &p, tier, PerChunk);
        let b = prove(&m, &p, tier, PerInstance);
        let (la, lb) = (postcard::to_allocvec(&a).unwrap().len(), postcard::to_allocvec(&b).unwrap().len());
        let chunks = |pr: &Proof| -> Vec<usize> { pr.batch.opened_values.instances.iter().map(|i| i.base_opened_values.quotient_chunks.len()).collect() };
        assert_eq!(chunks(&a), chunks(&b), "the opened values keep upstream's per-chunk shape");
        assert_eq!(a.batch.degree_bits, b.batch.degree_bits);
        eprintln!(
            "tier {}: proof bytes PerChunk {la}, PerInstance {lb} ({:.1} % smaller); quotient chunks per instance {:?} (total {})",
            tier.0,
            100.0 * (la - lb) as f64 / la as f64,
            chunks(&a),
            chunks(&a).iter().sum::<usize>()
        );
        assert!(lb < la);
    }
}

/// The constraint degree of every table. Blowup 4 does not need every table at degree ≤ 5: the
/// cpu and alu tables are at 8 (8 quotient chunks) and the PCS re-extrapolates onto the larger
/// quotient domain, as the rVM's degree-8 chips do. Lowering them is the lever for the quotient
/// transient (ZKVM-111 item 5), not a precondition. Pinned so a change is deliberate.
#[test]
fn the_degree_8_tables_are_cpu_and_alu() {
    use randprotocol_zkvm::machine::max_constraint_degrees_with_modq;
    // Every chip: keccak, sha256 and modq declared at their floors.
    let degrees = max_constraint_degrees_with_modq(Tier(10), 7, 7, 7, 7, 10, 7, 12);
    let names = ["program", "cpu", "memory", "alu", "range", "nibble", "poseidon2", "input", "keccak", "sha256", "modq", "public"];
    assert_eq!(degrees.len(), names.len());
    let table: Vec<(&str, usize)> = names.iter().copied().zip(degrees.iter().copied()).collect();
    eprintln!("max constraint degree per table: {table:?}");
    let over: Vec<&str> = table.iter().filter(|(_, d)| *d > 5).map(|(n, _)| *n).collect();
    assert_eq!(over, vec!["cpu", "alu"], "the tables whose degree needs more than 4 quotient chunks");
    assert_eq!(*degrees.iter().max().unwrap(), 8);
}

/// Both profiles are rate 1/4 since constraint set 11, with the rVM's query and grinding numbers at
/// Production; their postcard encodings (0 and 1) did not move.
#[test]
fn the_live_profiles_are_rate_one_quarter() {
    assert_eq!(LOG_BLOWUP, 2);
    assert_eq!((FriProfile::Test.log_blowup(), FriProfile::Test.num_queries(), FriProfile::Test.pow_bits()), (2, 16, 4));
    assert_eq!((FriProfile::Production.log_blowup(), FriProfile::Production.num_queries(), FriProfile::Production.pow_bits()), (2, 92, 24));
    assert_eq!(postcard::to_allocvec(&FriProfile::Test).unwrap(), vec![0]);
    assert_eq!(postcard::to_allocvec(&FriProfile::Production).unwrap(), vec![1]);
}

/// Every guest in `guests::all()` that fits tier 10 proves and verifies at rate 1/4 under the live
/// layout with the degree-8 cpu and alu tables as they are.
#[test]
fn every_tier_10_guest_proves_and_verifies_at_rate_one_quarter() {
    let m = Machine::new(FriProfile::Test);
    let mut proved = 0;
    for (name, p, inputs) in guests::all() {
        let Ok(exec) = execute(&p, &inputs, &[], Tier(10).max_cycles()) else { continue };
        let Ok(traces) = build_traces(&p, &inputs, &[], &exec, Tier(10)) else { continue };
        let proof = m.prove_traces(&p, &traces, Tier(10));
        m.verify(&p.digest(), &proof).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        proved += 1;
    }
    eprintln!("rate 1/4, tier 10: {proved} guests proved and verified under the live layout");
    assert!(proved >= 5, "only {proved} guests fit tier 10");
}

/// One constraint violated, at rate 1/4: the cheating suite's simplest forgery (an output the
/// trace did not compute) is refused, so the larger quotient domain did not stop the quotient
/// from binding the constraints.
#[test]
fn a_rate_one_quarter_proof_with_a_forged_output_is_refused() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let mut proof = prove(&m, &p, Tier(10), PerInstance);
    m.verify(&p.digest(), &proof).unwrap();
    proof.public_values[randprotocol_zkvm::tables::cpu::pv::OUT0] += 1;
    assert!(m.verify(&p.digest(), &proof).is_err());
}
