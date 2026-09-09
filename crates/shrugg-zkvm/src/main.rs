//! `cargo run --release` — the Rand reference zkVM, narrated end to end.
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use shrugg_zkvm::emulator::execute;
use shrugg_zkvm::guests;
use shrugg_zkvm::isa::Instr;
use shrugg_zkvm::machine::{build_traces, FriProfile, Machine, Tier, TIERS};
use shrugg_zkvm::tables::{alu, byte, cpu, memory, program, F};
use std::time::Instant;

fn hr(title: &str) { println!("\n══ {title} {}", "═".repeat(70usize.saturating_sub(title.len()))); }

fn main() {
    hr("Part 1 · What R_exec proves");
    println!("A confidential call is: code hash hc (public), private inputs and state (witness),");
    println!("public outputs (8 words). The verifier learns only hc, the gas tier, and the outputs.");
    println!("Everything else — registers, memory, branches, the number of cycles — stays hidden.");

    hr("Part 2 · The guest: a confidential balance check");
    let threshold = 1000;
    let program = guests::balance_check(threshold);
    let inputs = [400u32, 250, 300, 75];
    println!("{} instructions at pc 0. It reads four private balances, sums them, and outputs", program.len());
    println!("1 if the sum ≥ {threshold}, else 0. Listing:");
    for (i, w) in program.words.iter().enumerate() {
        println!("  {:>4x}: {:08x}  {:?}", program.pc_of(i), w, Instr::decode(*w).unwrap());
    }

    hr("Part 3 · Execute (prover side; nothing here is visible to the chain)");
    let t = Instant::now();
    let exec = execute(&program, &inputs, 1 << 20).unwrap();
    println!("inputs {:?} → outputs {:?} in {} cycles ({:?})", inputs, &exec.outputs[..2], exec.cycles(), t.elapsed());

    hr("Part 4 · Arithmetize: five tables on eight buses");
    let tier = Tier::for_cycles(exec.cycles()).unwrap();
    let traces = build_traces(&program, &exec, tier).unwrap();
    println!("tier {} → cpu 2^{} rows (actual {} cycles), padding hides the rest", tier.0, tier.0, exec.cycles());
    println!("{:<10}{:>10}{:>8}   {}", "table", "rows", "cols", "role");
    for (name, h, w, role) in [
        ("program", traces.program.height(), program::col::WIDTH + program::pre::WIDTH, "preprocessed ROM; its commitment is hc"),
        ("cpu", traces.cpu.height(), cpu::col::WIDTH, "one row per cycle; fetch, decode selectors, pc"),
        ("memory", traces.memory.height(), memory::col::WIDTH, "registers + RAM sorted by (addr, ts)"),
        ("alu", traces.alu.height(), alu::col::WIDTH, "byte-limb arithmetic, shifts, compares"),
        ("byte", traces.byte.height(), byte::col::WIDTH + byte::pre::WIDTH, "2^16 byte pairs: range, and/or/xor, pow2"),
    ] { println!("{name:<10}{h:>10}{w:>8}   {role}"); }
    println!("buses: PROGRAM MEMORY ALU RANGE8 AND8 OR8 XOR8 POW2 (LogUp, verified globally)");

    hr("Part 5 · Prove and verify (production FRI: blowup 8, 80 queries, 20 PoW bits, ZK on)");
    let m = Machine::new(FriProfile::Production);
    let hc = m.code_hash(&program, tier);
    println!("hc = {hc}");
    let t = Instant::now();
    let proof = m.prove_traces(&program, &traces, tier);
    let prove_ms = t.elapsed().as_millis();
    println!("proof: {} bytes in {} ms", proof.size(), prove_ms);
    let t = Instant::now();
    m.verify(&program, &proof).unwrap();
    let verify_ms = t.elapsed().as_micros() as f64 / 1000.0;
    println!("verified in {verify_ms:.1} ms with public values {:?}", proof.public_values);

    hr("Part 6 · Cheating provers");
    let mut bad = build_traces(&program, &exec, tier).unwrap();
    bad.public_values[cpu::pv::OUT0] = F::from_u32(0);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let p = m.prove_traces(&program, &bad, tier); m.verify(&program, &p) }));
    println!("claim output 0 instead of 1        → {}", if matches!(r, Ok(Ok(()))) { "ACCEPTED (bug)" } else { "rejected" });
    let other = guests::balance_check(threshold + 1);
    println!("verify against a different program → {}", if m.verify(&other, &proof).is_ok() { "ACCEPTED (bug)" } else { "rejected" });

    hr("Part 7 · Zero knowledge and tier padding");
    let (p1, _) = m.prove(&program, &inputs, None).unwrap();
    let (p2, _) = m.prove(&program, &[1000, 0, 0, 0], None).unwrap();
    println!("same output, different private inputs: public values equal = {}, proof bytes equal = {}", p1.public_values == p2.public_values, p1.to_bytes() == p2.to_bytes());
    let (p3, _) = m.prove(&program, &inputs, Some(Tier(12))).unwrap();
    println!("same run at tier 12: {} bytes (tier 10: {} bytes) — size reveals the tier, never the cycle count", p3.size(), p1.size());

    hr("Part 8 · Summary");
    let mt = Machine::new(FriProfile::Test);
    let t = Instant::now(); let pt = mt.prove_traces(&program, &traces, tier); let test_ms = t.elapsed().as_millis();
    println!("{:<28}{:>14}{:>14}", "", "production", "test profile");
    println!("{:<28}{:>14}{:>14}", "FRI queries / PoW bits", "80 / 20", "16 / 4");
    println!("{:<28}{:>14}{:>14}", "prove (ms)", prove_ms, test_ms);
    println!("{:<28}{:>14}{:>14}", "proof size (bytes)", proof.size(), pt.size());
    println!("{:<28}{:>14.1}", "verify (ms)", verify_ms);
    println!("field Goldilocks · challenge F_p² · hash Poseidon2 · blowup 8 · ZK hiding FRI · tiers {TIERS:?}");
    println!("\nRead docs/02-tables-and-buses.md for the constraint list, docs/03-privacy.md for what leaks.");
    for (name, p, inp) in guests::all() {
        let (pr, ex) = m.prove(&p, &inp, None).unwrap();
        m.verify(&p, &pr).unwrap();
        println!("{name:<16} cycles {:>6} tier {:>2} proof {:>7} B", ex.cycles(), pr.tier.0, pr.size());
    }
}
