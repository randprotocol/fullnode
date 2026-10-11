//! Private multisig phase 4: the executor's msauth path. Node-local (the sync excludes `auth*.rs`).
//! The cheap tests run the guest in the emulator and check headers; the real-proof tests are
//! `#[ignore]`d (a tier-18 proof: minutes and tens of GB) and are run from a terminal outside the
//! agent harness, never inside it (its low-memory watchdog kills ~30 GB runs).

use crystals_dilithium::dilithium2::Keypair;
use randprotocol_core::confidential::{AuthShape, ConfidentialError, ConfidentialExecutor};
use randprotocol_zkvm::executor::{decode_canonical, non_canonical, prove_auth, prove_msauth, run_msauth, ZkExecutor, AUTH_TIER, MSAUTH_TIER};
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::msauth::{auth_commit, msauth_inputs, nk, pinned_options, policy, signer_tree, signing_message, Slot, M_MAX, MSAUTH_WORDS};
use randprotocol_zkvm::notes::{SpendKey, Word8};
use randprotocol_zkvm::tables::cpu::pv;

const BINDING: [u32; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
const MSK: Word8 = [5; 8];
const SALT: Word8 = [6; 8];

struct Fixture {
    kps: Vec<Keypair>,
    pks: Vec<[u8; 1312]>,
    root: Word8,
    paths: Vec<[Word8; 4]>,
}
fn fixture(n: usize) -> Fixture {
    let kps: Vec<Keypair> = (0..n).map(|i| Keypair::generate(Some(&[i as u8 + 1; 32])).unwrap()).collect();
    let pks: Vec<[u8; 1312]> = kps.iter().map(|k| k.public.to_bytes().try_into().unwrap()).collect();
    let (root, paths) = signer_tree(&pks);
    Fixture { kps, pks, root, paths }
}
fn slot(f: &Fixture, i: usize) -> Slot {
    Slot { index: i as u32, pk: f.pks[i], sig: f.kps[i].sign(&signing_message(&BINDING)), path: f.paths[i] }
}
fn expected(f: &Fixture, t: u32) -> Word8 {
    auth_commit(&nk(&MSK, &policy(t, &f.root)), &SALT)
}

#[test]
fn run_msauth_returns_c_for_two_of_three_and_refuses_one() {
    let f = fixture(3);
    let two = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0), slot(&f, 2)]);
    assert_eq!(two.len(), MSAUTH_WORDS);
    assert_eq!(run_msauth(&two, &BINDING), Ok(expected(&f, 2)));
    let one = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0)]);
    let e = run_msauth(&one, &BINDING).unwrap_err();
    assert!(e.contains("refused"), "{e}");
    assert!(run_msauth(&two, &[0; 8]).is_err(), "signatures over another binding");
    assert!(run_msauth(&two[..MSAUTH_WORDS - 1], &BINDING).is_err(), "a short witness");
}

#[test]
fn the_msauth_shape_is_the_vendored_pinned_one() {
    let s = ZkExecutor::msauth_heights();
    let o = pinned_options();
    assert_eq!(s.tier, MSAUTH_TIER);
    assert_eq!(
        (s.keccak_log_height, s.modq_log_height, s.mem_log_height),
        (o.min_keccak_log_height, o.min_modq_log_height, o.min_mem_log_height)
    );
    assert_eq!(s.sha256_log_height, 0);
    assert!(o.gas_limit.is_none(), "R-gas: the prover keeps the header ceiling");
    assert_eq!(s.public_log_height, ZkExecutor::auth_heights().2, "both bind the 8-word transaction binding");
    // The vendored literal pins, recomputed from the guest and the witness width.
    use randprotocol_zkvm::msauth::{PINNED_INPUT_LOG_HEIGHT, PINNED_PROGRAM_LOG_HEIGHT, PINNED_PUBLIC_LOG_HEIGHT};
    assert_eq!(
        (s.program_log_height, s.input_log_height, s.public_log_height),
        (PINNED_PROGRAM_LOG_HEIGHT, PINNED_INPUT_LOG_HEIGHT, PINNED_PUBLIC_LOG_HEIGHT)
    );
    assert_eq!(MSAUTH_TIER as u8, randprotocol_core::types::MSAUTH_PROOF_TIER);
    assert_eq!(s.keccak_log_height, randprotocol_core::types::MSAUTH_KECCAK_LOG_HEIGHT, "core's mirror");
    assert_eq!(s.modq_log_height, randprotocol_core::types::MSAUTH_MODQ_LOG_HEIGHT, "core's mirror");
    // R-gas: the header ceiling, a function of public header words only.
    assert_eq!(randprotocol_core::gas::msauth_gas_limit_pin(), 436_159);
    assert_eq!(
        randprotocol_core::gas::msauth_gas_limit_pin(),
        randprotocol_zkvm::gas::gas_max_with_modq(randprotocol_zkvm::machine::Tier(MSAUTH_TIER), s.keccak_log_height, 0, s.modq_log_height),
        "core's pin is the vendored machine's ceiling of the pinned header"
    );
}

#[test]
fn junk_and_a_single_key_proof_take_their_shape_or_none() {
    let ex = ZkExecutor::new(FriProfile::Test);
    ex.enable_auth_multisig(); // a chain naming hc_auth_multisig: the msauth path is reachable
    assert_eq!(ZkExecutor::auth_shape_of(b"junk"), Err(ConfidentialError::MalformedProof));
    let (single, c, tier) = prove_auth(FriProfile::Test, &SpendKey([7; 8]), &SALT, &BINDING, Backend::Cpu).unwrap();
    assert_eq!(tier as usize, AUTH_TIER);
    assert_eq!(ZkExecutor::auth_shape_of(&single), Ok(AuthShape::SingleKey));
    assert_eq!(ex.auth_proof_digest(&single), Ok(c), "the cheap read accepts either shape");
    let gas = ex.auth_gas_limit(&single).unwrap();
    assert_eq!(ex.auth_header_of(&single), Ok((AuthShape::SingleKey, c, gas)), "one decode, all three reads");
    // Dispatch on hc: the msauth hc sends a single-key proof to the msauth path, whose shape pin refuses it before a key is built.
    match ex.verify_auth(&ZkExecutor::hc_auth_multisig(), &single, &BINDING) {
        Err(ConfidentialError::InvalidProof(why)) => assert!(why.contains("not the multisig auth guest's shape"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(ex.cached_msauth_keys(), 0, "refused before any msauth key");
    assert!(!ex.msauth_key_ready());
    assert_eq!(ex.verify_auth(&ZkExecutor::hc_auth(), &single, &BINDING), Ok(c));
}

/// The per-field header comparison without the 4 GB key (spec §3.1, pre-flight finding 7): a
/// decoded Test-profile proof given the msauth header — all eight words `msauth_heights()`,
/// `degree_bits` the pinned shape's, its own `pv::NUM` public values — reads as `Multisig`
/// through the one decode; each word moved by one either way is refused by name by
/// `auth_header_of` and by `verify_auth` under `hc_auth_multisig`, and no key is ever built.
/// (`verify_auth` is never called on the all-matching proof: it would build the key.)
#[test]
fn every_msauth_header_word_off_by_one_is_refused_by_name_before_any_key() {
    use randprotocol_zkvm::machine::{Machine, Proof, Tier};
    let ex = ZkExecutor::new(FriProfile::Test);
    ex.enable_auth_multisig(); // a chain naming hc_auth_multisig: the msauth path is reachable
    let (single, c, _) = prove_auth(FriProfile::Test, &SpendKey([7; 8]), &SALT, &BINDING, Backend::Cpu).unwrap();
    let gas = decode_canonical(&single).unwrap().public_values[pv::GAS];
    let s = ZkExecutor::msauth_heights();
    let m = Machine::new(FriProfile::Test);
    let synth = |edit: &dyn Fn(&mut Proof)| -> Vec<u8> {
        let mut p = decode_canonical(&single).unwrap();
        p.tier = Tier(s.tier);
        p.program_log_height = s.program_log_height;
        p.input_log_height = s.input_log_height;
        p.keccak_log_height = s.keccak_log_height;
        p.sha256_log_height = s.sha256_log_height;
        p.modq_log_height = s.modq_log_height;
        p.public_log_height = s.public_log_height;
        p.mem_log_height = s.mem_log_height;
        p.batch.degree_bits = m.log_ext_degrees_with_modq(
            Tier(s.tier),
            s.program_log_height,
            s.input_log_height,
            s.keccak_log_height,
            s.sha256_log_height,
            s.modq_log_height,
            s.public_log_height,
            s.mem_log_height,
        );
        assert_eq!(p.public_values.len(), pv::NUM);
        edit(&mut p);
        p.to_bytes()
    };
    let matching = synth(&|_| {});
    assert_eq!(ZkExecutor::auth_shape_of(&matching), Ok(AuthShape::Multisig));
    assert_eq!(ex.auth_header_of(&matching), Ok((AuthShape::Multisig, c, Some(gas))));
    assert_eq!(ex.auth_proof_digest(&matching), Ok(c));
    assert_eq!(ex.auth_gas_limit(&matching), Ok(Some(gas)));
    type Edit = fn(&mut Proof, i8);
    let edits: [(&str, Edit); 8] = [
        ("tier", |p, d| p.tier.0 = (p.tier.0 as i64 + d as i64) as usize),
        ("program_log_height", |p, d| p.program_log_height = (p.program_log_height as i16 + d as i16) as u8),
        ("input_log_height", |p, d| p.input_log_height = (p.input_log_height as i16 + d as i16) as u8),
        ("keccak_log_height", |p, d| p.keccak_log_height = (p.keccak_log_height as i16 + d as i16) as u8),
        ("sha256_log_height", |p, d| p.sha256_log_height = (p.sha256_log_height as i16 + d as i16) as u8),
        ("modq_log_height", |p, d| p.modq_log_height = (p.modq_log_height as i16 + d as i16) as u8),
        ("public_log_height", |p, d| p.public_log_height = (p.public_log_height as i16 + d as i16) as u8),
        ("mem_log_height", |p, d| p.mem_log_height = (p.mem_log_height as i16 + d as i16) as u8),
    ];
    let mut refused = 0;
    for (field, edit) in edits {
        for d in [1i8, -1] {
            let bytes = synth(&|p| edit(p, d));
            let want = ConfidentialError::InvalidProof(format!("not the multisig auth guest's shape: {field}"));
            assert!(ZkExecutor::auth_shape_of(&bytes).is_err(), "{field} {d:+}");
            assert_eq!(ex.auth_header_of(&bytes), Err(want.clone()), "{field} {d:+}");
            assert_eq!(ex.verify_auth(&ZkExecutor::hc_auth_multisig(), &bytes, &BINDING), Err(want), "{field} {d:+}");
            refused += 1;
        }
    }
    assert_eq!(refused, 16);
    assert_eq!(ex.cached_msauth_keys(), 0, "no header built the msauth key");
    assert!(!ex.msauth_key_ready());

    // Task 3 (the Task 2b review's carried note): on a chain WITHOUT `hc_auth_multisig` the msauth
    // path is unreachable. The all-matching header — which on an enabled executor would go on to
    // build the ~4 GB tier-18 key — is refused before any decode, by name, and nothing is built.
    let plain = ZkExecutor::new(FriProfile::Test);
    assert!(!plain.auth_multisig_enabled(), "off until a genesis names hc_auth_multisig");
    match plain.verify_auth(&ZkExecutor::hc_auth_multisig(), &matching, &BINDING) {
        Err(ConfidentialError::InvalidProof(why)) => assert!(why.contains("without hc_auth_multisig"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(plain.cached_msauth_keys(), 0, "no msauth key touched");
    assert_eq!(plain.msauth_key_builds(), 0);
    assert_eq!(plain.msauth_machine_key_builds(), 0);
    // The single-key path is untouched by the gate.
    assert_eq!(plain.verify_auth(&ZkExecutor::hc_auth(), &single, &BINDING), Ok(c));
}

/// One real msauth proof at the Test profile, and every header rule checked on it.
/// Run from a terminal outside the agent harness:
/// `cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth -- --ignored --nocapture a_real_msauth_proof`
#[test]
#[ignore = "a tier-18 proof: minutes, >= 48 GB; run from a terminal outside the agent harness"]
fn a_real_msauth_proof_takes_the_pinned_shape_and_every_other_header_is_refused() {
    let f = fixture(3);
    let ex = ZkExecutor::new(FriProfile::Test);
    ex.enable_auth_multisig();
    let hc = ZkExecutor::hc_auth_multisig();
    let mut proofs = Vec::new();
    for active in [vec![0usize], vec![0, 2], (0..M_MAX).collect::<Vec<_>>()] {
        let t = active.len() as u32;
        let inputs = msauth_inputs(&MSK, &SALT, t, &active.iter().map(|&i| slot(&f, i)).collect::<Vec<_>>());
        let (bytes, c, tier) = prove_msauth(FriProfile::Test, &inputs, &BINDING).unwrap();
        assert_eq!((tier as usize, c), (MSAUTH_TIER, expected(&f, t)));
        proofs.push(bytes);
    }
    let s = ZkExecutor::msauth_heights();
    // Privacy: proofs at M = 1, 2, 3 differ in length only by the hiding noise.
    let (lo, hi) = (proofs.iter().map(Vec::len).min().unwrap(), proofs.iter().map(Vec::len).max().unwrap());
    assert!((hi - lo) * 100 <= lo, "M leaks through size: {lo}..{hi} bytes");
    for bytes in &proofs {
        let p = decode_canonical(bytes).unwrap();
        // R-hide: every M declares the same header.
        assert_eq!(
            (p.tier.0, p.program_log_height, p.input_log_height, p.keccak_log_height, p.sha256_log_height, p.modq_log_height, p.public_log_height, p.mem_log_height),
            (s.tier, s.program_log_height, s.input_log_height, s.keccak_log_height, s.sha256_log_height, s.modq_log_height, s.public_log_height, s.mem_log_height)
        );
        // R-gas: the header's ceiling, never the run's gas.
        assert_eq!(p.public_values[pv::GAS], randprotocol_core::gas::msauth_gas_limit_pin());
        assert_eq!(non_canonical(&p), None, "an honest msauth proof is canonical");
        assert_eq!(ZkExecutor::auth_shape_of(bytes), Ok(AuthShape::Multisig));
        assert_eq!(ex.auth_gas_limit(bytes), Ok(Some(randprotocol_core::gas::msauth_gas_limit_pin())));
    }
    let c = ex.verify_auth(&hc, &proofs[1], &BINDING).unwrap();
    assert_eq!(c, expected(&f, 2));
    assert_eq!(ex.cached_msauth_keys(), 1);
    assert!(ex.verify_auth(&hc, &proofs[1], &[0; 8]).is_err(), "another binding");
    // The single-key path refuses the multisig shape before building a key.
    assert!(matches!(ex.verify_auth(&ZkExecutor::hc_auth(), &proofs[1], &BINDING), Err(ConfidentialError::InvalidProof(_))));
    // Every header word (and the tier) moved by one, up and down, is refused by shape before a key is built.
    // `machine::Proof` is not `Clone`: re-decode the honest bytes for every mutation.
    let fresh = ZkExecutor::new(FriProfile::Test);
    fresh.enable_auth_multisig();
    type Edit = fn(&mut randprotocol_zkvm::machine::Proof, i8);
    let edits: [(&str, Edit); 8] = [
        ("tier", |p, d| p.tier.0 = (p.tier.0 as i64 + 2 * d as i64) as usize),
        ("program", |p, d| p.program_log_height = (p.program_log_height as i8 + d) as u8),
        ("input", |p, d| p.input_log_height = (p.input_log_height as i8 + d) as u8),
        ("keccak", |p, d| p.keccak_log_height = (p.keccak_log_height as i8 + d) as u8),
        ("sha256", |p, d| p.sha256_log_height = if d > 0 { 7 } else { 0 }),
        ("modq", |p, d| p.modq_log_height = (p.modq_log_height as i8 + d) as u8),
        ("public", |p, d| p.public_log_height = (p.public_log_height as i8 + d) as u8),
        ("mem", |p, d| p.mem_log_height = (p.mem_log_height as i8 + d) as u8),
    ];
    for (what, edit) in edits {
        for d in [1i8, -1] {
            if what == "sha256" && d < 0 {
                continue; // 0 is the pin; only "present" is a move
            }
            let mut p = decode_canonical(&proofs[1]).unwrap();
            edit(&mut p, d);
            let bytes = p.to_bytes();
            assert!(ZkExecutor::auth_shape_of(&bytes).is_err(), "{what} {d:+}");
            assert!(
                matches!(fresh.verify_auth(&hc, &bytes, &BINDING), Err(ConfidentialError::InvalidProof(_)) | Err(ConfidentialError::MalformedProof)),
                "{what} {d:+}"
            );
        }
    }
    assert_eq!(fresh.cached_msauth_keys(), 0, "no forged header built a key");
    // FRI arity is pinned for modq-bearing proofs too (VERIFIER-2): the field `honest_fri_arities` reads.
    let mut forged = decode_canonical(&proofs[1]).unwrap();
    forged.batch.opening_proof.1.commit_phase_openings[0].log_arity = 1;
    assert!(non_canonical(&forged).is_some(), "a finer FRI schedule on an msauth proof is non-canonical");
}

/// The Test-profile prove the e2e (Task 8) will pay three times. Record time and peak RSS before Task 8.
/// Run from a terminal outside the agent harness:
/// `/usr/bin/time -l cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth -- --ignored --nocapture measure_the_msauth_test_profile_prove`
#[test]
#[ignore = "one Test-profile tier-18 prove: record time and peak RSS; stop if the peak exceeds 40 GB; run from a terminal outside the agent harness"]
fn measure_the_msauth_test_profile_prove() {
    let f = fixture(3);
    let inputs = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0), slot(&f, 2)]);
    let t0 = std::time::Instant::now();
    let (bytes, _, _) = prove_msauth(FriProfile::Test, &inputs, &BINDING).unwrap();
    eprintln!("MSAUTH-TEST: proof {} B, prove {:?}", bytes.len(), t0.elapsed());
}

/// The cost a validator pays to warm the msauth key and verify one proof, at Production.
/// Run from a terminal outside the agent harness:
/// `/usr/bin/time -l cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth -- --ignored --nocapture measure_the_msauth_verifier_key_build_and_verify`
#[test]
#[ignore = "a Production tier-18 prove (tens of GB) then the ~4 GB key build and one verify: run from a terminal outside the agent harness; record in docs/node-hardware.md"]
fn measure_the_msauth_verifier_key_build_and_verify_at_the_production_profile() {
    let f = fixture(3);
    let inputs = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0), slot(&f, 2)]);
    let (bytes, _, _) = prove_msauth(FriProfile::Production, &inputs, &BINDING).unwrap();
    let ex = ZkExecutor::new(FriProfile::Production);
    ex.enable_auth_multisig();
    let t0 = std::time::Instant::now();
    ex.warm_auth_multisig();
    let warm = t0.elapsed();
    let t1 = std::time::Instant::now();
    ex.verify_auth(&ZkExecutor::hc_auth_multisig(), &bytes, &BINDING).unwrap();
    eprintln!("MSAUTH-PROD: proof {} B, key build {warm:?}, warm verify {:?}", bytes.len(), t1.elapsed());
}

/// The resident process size in bytes (`ps -o rss=`, KiB on macOS and Linux).
fn rss_bytes() -> u64 {
    let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse::<u64>().unwrap() * 1024
}

/// The key build alone (no prove): the spec §3.5 stop rule's two numbers, wall time and the
/// resident memory **after** the build (the key stays resident for the life of the process), over
/// this process's baseline; `/usr/bin/time -l` adds the peak. Eight threads warm at once, and
/// exactly one build happens (single flight). A key build, never a tier-18 prove, so it may run
/// inside the agent harness.
/// `/usr/bin/time -l cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth -- --ignored --nocapture measure_the_msauth_verifier_key_build_alone`
#[test]
#[ignore = "the Production tier-18 key build: measured 78.6 s and ~4.0 GB peak/resident on the 48 GB laptop"]
fn measure_the_msauth_verifier_key_build_alone() {
    let ex = std::sync::Arc::new(ZkExecutor::new(FriProfile::Production));
    let base = rss_bytes();
    let t0 = std::time::Instant::now();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let ex = ex.clone();
            std::thread::spawn(move || ex.warm_auth_multisig())
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let wall = t0.elapsed();
    let after = rss_bytes();
    assert!(ex.msauth_key_ready());
    assert_eq!(ex.cached_msauth_keys(), 1);
    assert_eq!(ex.msauth_key_builds(), 1, "eight concurrent warms, one build");
    eprintln!(
        "MSAUTH-KEY: profile=Production wall={wall:?} rss_before={:.1} MB rss_after={:.1} MB resident_delta={:.1} MB",
        base as f64 / 1e6,
        after as f64 / 1e6,
        after.saturating_sub(base) as f64 / 1e6
    );
}
