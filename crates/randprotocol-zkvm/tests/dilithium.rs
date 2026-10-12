use dilithium_core::{shake256, Shake};
use randprotocol_zkvm::dilithium_host::HostKeccak;

#[test]
fn shake256_matches_the_crate() {
    // crystals-dilithium exposes its fips202; compare against a fixed vector instead so the test
    // does not depend on a private module: SHAKE256("") first 32 bytes (FIPS 202 test vector).
    let mut out = [0u8; 32];
    shake256(&mut HostKeccak, &[b""], &mut out);
    assert_eq!(hex(&out), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

#[test]
fn shake128_streams_across_block_boundaries() {
    let mut a = Shake::new128(HostKeccak);
    a.absorb(&[7u8; 300]);
    a.finalize();
    let mut whole = [0u8; 400];
    a.squeeze(&mut whole);
    let mut b = Shake::new128(HostKeccak);
    b.absorb(&[7u8; 100]); b.absorb(&[7u8; 200]);
    b.finalize();
    let mut parts = [0u8; 400];
    b.squeeze(&mut parts[..168]); b.squeeze(&mut parts[168..]);
    assert_eq!(whole, parts);
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

#[test]
fn shake128_empty_known_answer() {
    let mut a = Shake::new128(HostKeccak);
    a.finalize();
    let mut out = [0u8; 32];
    a.squeeze(&mut out);
    assert_eq!(hex(&out), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
}

fn oracle(rate128: bool, input: &[u8], n: usize) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut out = vec![0u8; n];
    if rate128 {
        let mut h = sha3::Shake128::default();
        h.update(input);
        h.finalize_xof().read(&mut out);
    } else {
        let mut h = sha3::Shake256::default();
        h.update(input);
        h.finalize_xof().read(&mut out);
    }
    out
}

#[test]
fn shake_matches_sha3_across_rate_boundaries() {
    let data: Vec<u8> = (0..700u32).map(|i| (i * 31 + 7) as u8).collect();
    for rate128 in [true, false] {
        let rate = if rate128 { 168 } else { 136 };
        for len in [0, 1, 7, 8, 9, rate - 1, rate, rate + 1, 2 * rate, 2 * rate + 5, 700] {
            // squeeze longer than one rate, in odd-sized pieces
            let n = 3 * rate + 11;
            let want = oracle(rate128, &data[..len], n);
            let mut s = if rate128 { Shake::new128(HostKeccak) } else { Shake::new256(HostKeccak) };
            // absorb in ragged pieces so lane alignment varies
            let mut i = 0;
            let mut step = 3;
            while i < len {
                let j = (i + step).min(len);
                s.absorb(&data[i..j]);
                i = j;
                step = step * 2 + 1;
            }
            s.finalize();
            let mut got = vec![0u8; n];
            let (x, rest) = got.split_at_mut(5);
            let (y, z) = rest.split_at_mut(rate);
            s.squeeze(x);
            s.squeeze(y);
            s.squeeze(z);
            assert_eq!(got, want, "rate128={rate128} len={len}");
        }
    }
}

#[test]
fn shake256_one_shot_matches_sha3() {
    let mut out = [0u8; 200];
    shake256(&mut HostKeccak, &[&[1u8; 136], b"abc"], &mut out);
    let mut inp = vec![1u8; 136];
    inp.extend_from_slice(b"abc");
    assert_eq!(out.to_vec(), oracle(false, &inp, 200));
}

// ---------------------------------------------------------------------------------------------
// Task 2: round-3 Dilithium2 verify, agreeing with `crystals_dilithium::dilithium2`.
// ---------------------------------------------------------------------------------------------

use crystals_dilithium::dilithium2::{Keypair, PublicKey};

fn case(seed: u64, msg_len: usize) -> (Keypair, Vec<u8>) {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    let kp = Keypair::generate(Some(&s)).unwrap();
    let msg: Vec<u8> = (0..msg_len).map(|i| (i as u64 * 31 + seed) as u8).collect();
    (kp, msg)
}

fn ours(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use dilithium_core::ring::{Arena, SoftRing};
    use randprotocol_zkvm::dilithium_host::HostModq;
    let (pk, sig) = (pk.try_into().unwrap(), sig.try_into().unwrap());
    let reference = dilithium_core::verify_reference(&mut HostKeccak, pk, msg, sig);
    let soft = dilithium_core::verify_with(&mut HostKeccak, &mut SoftRing, &mut Box::new(Arena::new()), pk, msg, sig);
    let chip = dilithium_core::verify_with(&mut HostKeccak, &mut HostModq, &mut Box::new(Arena::new()), pk, msg, sig);
    assert_eq!((soft, chip), (reference, reference), "three backends disagree");
    assert_eq!(dilithium_core::verify(&mut HostKeccak, pk, msg, sig), reference);
    let wpk: [u32; 328] = core::array::from_fn(|i| u32::from_le_bytes(pk[4 * i..4 * i + 4].try_into().unwrap()));
    let wsig: [u32; 605] = core::array::from_fn(|i| u32::from_le_bytes(sig[4 * i..4 * i + 4].try_into().unwrap()));
    assert_eq!(dilithium_core::verify_words_with(&mut HostKeccak, &mut HostModq, &mut Box::new(Arena::new()), &wpk, msg, &wsig), reference, "word path");
    reference
}

#[test]
fn soft_ring_and_host_modq_agree_op_by_op() {
    use dilithium_core::ring::{modq_a1, slot, Arena, Ring, SoftRing};
    use randprotocol_zkvm::dilithium_host::HostModq;
    let mut s = 11u64;
    let mut next = move || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    let mut a = Box::new(Arena::new());
    for p in a.p.iter_mut() { for c in p.iter_mut() { *c = (next() % (1 << 24)) as u32; } }
    let mut b = Box::new(Arena { p: a.p });
    for (soft, host) in [
        (|r: &mut SoftRing, x: &mut Arena| r.ntt(x, slot::Z)) as fn(&mut SoftRing, &mut Arena),
        |r, x| r.intt(x, slot::W),
        |r, x| r.dot4(x, slot::W, slot::ROW, slot::Z),
        |r, x| r.msub4(x, slot::W, slot::C, slot::T1),
    ].into_iter().zip([
        (|r: &mut HostModq, x: &mut Arena| r.ntt(x, slot::Z)) as fn(&mut HostModq, &mut Arena),
        |r, x| r.intt(x, slot::W),
        |r, x| r.dot4(x, slot::W, slot::ROW, slot::Z),
        |r, x| r.msub4(x, slot::W, slot::C, slot::T1),
    ]) {
        soft(&mut SoftRing, &mut a);
        host(&mut HostModq, &mut b);
        assert_eq!(a.p, b.p);
    }
    assert_eq!(modq_a1(2, slot::W, slot::ROW, slot::Z), randprotocol_zkvm::modq::Args { op: randprotocol_zkvm::modq::Op::Dot4, out: 12, a: 4, b: 0 }.encode());
}

fn theirs(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    PublicKey::from_bytes(pk).unwrap().verify(msg, sig)
}

#[test]
fn sizes_match_the_crate() {
    assert_eq!(dilithium_core::PK_BYTES, crystals_dilithium::dilithium2::PUBLICKEYBYTES);
    assert_eq!(dilithium_core::SIG_BYTES, crystals_dilithium::dilithium2::SIGNBYTES);
}

#[test]
fn honest_signatures_verify_and_agree_with_the_crate() {
    for seed in 0..200u64 {
        let (kp, msg) = case(seed, (seed as usize * 7) % 300);
        let sig = kp.sign(&msg);
        let pkb = kp.public.to_bytes();
        assert!(PublicKey::from_bytes(&pkb).unwrap().verify(&msg, &sig));
        assert!(ours(&pkb, &msg, &sig), "seed {seed}");
    }
}

#[test]
fn tampering_with_any_part_is_rejected() {
    let (kp, msg) = case(1, 45);
    let sig = kp.sign(&msg);
    let pkb = kp.public.to_bytes();
    for i in (0..sig.len()).step_by(37) {
        let mut s = sig.to_vec(); s[i] ^= 1;
        let theirs = PublicKey::from_bytes(&pkb).unwrap().verify(&msg, &s);
        assert_eq!(ours(&pkb, &msg, &s), theirs, "sig byte {i}");
    }
    let mut m = msg.clone(); m[0] ^= 1;
    assert!(!ours(&pkb, &m, &sig));
    let mut p = pkb.to_vec(); p[40] ^= 1;
    assert!(!ours(&p, &msg, &sig));
}

const HINT: usize = 32 + 4 * 576; // the OMEGA + K hint bytes at the end of the signature
const OMEGA: usize = 80;

/// The hint section's K cumulative counts.
fn hint_counts(sig: &[u8]) -> [usize; 4] {
    core::array::from_fn(|i| sig[HINT + OMEGA + i] as usize)
}

/// Controller ruling R2: each class is built from the decoded hint section of the real signature,
/// so it is genuinely malformed for this signature (not just for some signatures).
#[test]
fn malformed_signatures_agree_with_the_crate() {
    let (kp, msg) = case(2, 45);
    let sig = kp.sign(&msg);
    let pkb = kp.public.to_bytes();
    let counts = hint_counts(&sig);
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    // count > OMEGA
    let mut s = sig.to_vec(); s[HINT + OMEGA] = OMEGA as u8 + 1; cases.push(("count > OMEGA", s));

    // non-monotone count: the first polynomial i with a hint gets a successor count one less
    let i = (0..3).find(|&i| counts[i] >= 1).expect("a hint in polys 0..3");
    let mut s = sig.to_vec(); s[HINT + OMEGA + i + 1] = (counts[i] - 1) as u8;
    cases.push(("non-monotone count", s));

    // nonzero tail: a nonzero byte right after the true total count
    let total = counts[3];
    assert!(total < OMEGA, "honest total {total} leaves no tail");
    let mut s = sig.to_vec(); s[HINT + total] = 1; cases.push(("nonzero tail", s));

    // indices not strictly increasing: a polynomial with >= 2 hints gets a repeated index
    let mut start = 0;
    let mut found = None;
    for &end in &counts {
        if end >= start + 2 { found = Some(start); break; }
        start = end;
    }
    let st = found.expect("a polynomial with >= 2 hints");
    let mut s = sig.to_vec(); s[HINT + st + 1] = s[HINT + st]; cases.push(("repeated index", s));
    // swapping two strictly increasing indices always yields a decreasing pair, for every seed
    let mut s = sig.to_vec(); s.swap(HINT + st, HINT + st + 1);
    assert!(s[HINT + st] > s[HINT + st + 1], "the decreasing-index case must be generated");
    cases.push(("decreasing index", s));

    // ‖z‖∞ too big
    let mut s = sig.to_vec(); for b in &mut s[32..32 + 18] { *b = 0xff; } cases.push(("‖z‖∞", s));

    // Non-canonical encodings of the *same* h: a lax parser would accept these as the honest
    // signature, so only the encoding checks reject them (the soundness-relevant malleability).
    // (a) a polynomial's first index written twice, later indices and counts shifted up by one
    let p = counts.iter().position(|&e| e >= 1).unwrap();
    let st0 = if p == 0 { 0 } else { counts[p - 1] };
    let mut s = sig.to_vec();
    s.copy_within(HINT + st0..HINT + total, HINT + st0 + 1);
    for q in p..4 { s[HINT + OMEGA + q] += 1; }
    cases.push(("duplicated index, same h", s));
    // (b) two indices of one polynomial swapped
    let mut s = sig.to_vec(); s.swap(HINT + st, HINT + st + 1); cases.push(("swapped indices, same h", s));

    for (name, s) in cases.iter() {
        let t = theirs(&pkb, &msg, s);
        assert_eq!(ours(&pkb, &msg, s), t, "case {name}");
        assert!(!t, "case {name} should be malformed");
    }
}

/// A deterministic splitmix64 stream, so the fuzz cases are reproducible without a dependency.
struct Mix(u64);
impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn fill(&mut self, b: &mut [u8]) { for x in b { *x = self.next() as u8; } }
}

#[test]
fn random_garbage_never_panics_and_agrees() {
    let mut r = Mix(0xd111_7401);
    let (kp, msg) = case(3, 64);
    let honest_sig = kp.sign(&msg);
    let honest_pk = kp.public.to_bytes();
    for n in 0..300 {
        let mut pk = [0u8; 1312];
        let mut sig = [0u8; 2420];
        r.fill(&mut pk);
        r.fill(&mut sig);
        match n % 3 {
            // fully random: almost always stops in the hint checks
            0 => {}
            // random c and z with an honest hint section and key: runs the whole pipeline
            1 => { pk = honest_pk; sig[HINT..].copy_from_slice(&honest_sig[HINT..]); }
            // honest signature and message under a random key
            _ => { sig = honest_sig; }
        }
        assert_eq!(ours(&pk, &msg, &sig), theirs(&pk, &msg, &sig), "garbage case {n}");
    }
}

#[test]
fn hint_section_mutations_agree_with_the_crate() {
    // Small perturbations of the honest hint section: counts and indices near their valid ranges.
    let mut r = Mix(0x4a17);
    let (kp, msg) = case(4, 10);
    let sig = kp.sign(&msg);
    let pkb = kp.public.to_bytes();
    let mut rejected = 0;
    for n in 0..400 {
        let mut s = sig;
        for _ in 0..1 + (r.next() % 3) {
            let pos = HINT + (r.next() as usize % (OMEGA + 4));
            let v = r.next();
            s[pos] = match v % 4 {
                0 => s[pos].wrapping_add(1),
                1 => s[pos].wrapping_sub(1),
                2 => (v >> 8) as u8 % (OMEGA as u8 + 2),
                _ => (v >> 8) as u8,
            };
        }
        let t = theirs(&pkb, &msg, &s);
        assert_eq!(ours(&pkb, &msg, &s), t, "mutation {n}");
        rejected += !t as usize;
    }
    assert!(rejected > 300, "only {rejected} mutations rejected");
}

/// The one encoding check the end-to-end tests cannot isolate: a non-monotone count list whose
/// lax decoding (skip the empty range, re-read earlier bytes) equals a canonical h. Pinned against
/// the reference's `unpack_sig` logic (sign/lvl2.rs via packing/lvl2.rs), which the crate keeps
/// private: canonical `[5, 5]` / counts `[1, 1, 2, 2]` is accepted; `[5]` / `[1, 0, 1, 1]` (same h
/// under a lax parser) is rejected.
#[test]
fn unpack_sig_encoding_checks_are_pinned() {
    use dilithium_core::packing::unpack_sig;
    use dilithium_core::poly::{Polyveck, Polyvecl};
    let run = |idx: &[u8], counts: [u8; 4]| {
        let mut sig = [0u8; 2420];
        sig[HINT..HINT + idx.len()].copy_from_slice(idx);
        sig[HINT + OMEGA..].copy_from_slice(&counts);
        let (mut c, mut z, mut h) = ([0u8; 32], Polyvecl::default(), Polyveck::default());
        let ok = unpack_sig(&mut c, &mut z, &mut h, &sig);
        let set: Vec<(usize, usize)> = (0..4)
            .flat_map(|i| (0..256).map(move |j| (i, j)))
            .filter(|&(i, j)| h.vec[i].coeffs[j] != 0)
            .collect();
        (ok, set)
    };
    assert_eq!(run(&[5, 5], [1, 1, 2, 2]), (true, vec![(0, 5), (2, 5)]));
    assert!(!run(&[5], [1, 0, 1, 1]).0);
    assert!(!run(&[5, 5], [2, 2, 2, 2]).0, "repeated index in one polynomial");
    assert!(!run(&[6, 5], [2, 2, 2, 2]).0, "decreasing indices in one polynomial");
    assert!(run(&[6, 5], [1, 2, 2, 2]).0, "the first index of a polynomial is unordered vs the last");
    assert!(!run(&[5, 0, 1], [1, 1, 1, 1]).0, "nonzero tail");
    assert!(!run(&[], [81, 81, 81, 81]).0, "count > OMEGA");
    // count > OMEGA that is otherwise consistent: indices 1..=80 then the count byte 81 itself
    // reads as an 81st increasing index, and the later counts are monotone.
    let idx: Vec<u8> = (1..=80).collect();
    assert!(!run(&idx, [81, 81, 81, 81]).0, "count > OMEGA, otherwise consistent");
    assert!(run(&idx, [80, 80, 80, 80]).0, "a full hint section at exactly OMEGA");
    assert!(run(&[], [0, 0, 0, 0]).0);
}

fn words(b: &[u8]) -> Vec<u32> {
    b.chunks(4).map(|c| { let mut w = [0u8; 4]; w[..c.len()].copy_from_slice(c); u32::from_le_bytes(w) }).collect()
}

#[test]
fn the_guest_verifies_like_the_host_and_reports_its_cycles() {
    use randprotocol_zkvm::emulator::Syscall;
    use randprotocol_zkvm::machine::Tier;
    let p = randprotocol_zkvm::guests::compiled::dilithium_verify();
    eprintln!("dilithium-verify: {} program words", p.words.len());
    for (seed, flip) in [(3u64, false), (4, true)] {
        let (kp, msg) = case(seed, 45);
        let mut sig = kp.sign(&msg).to_vec();
        if flip { sig[100] ^= 1; }
        let mut input = words(&kp.public.to_bytes());
        input.extend(words(&sig));
        input.push(msg.len() as u32);
        input.extend(words(&msg));
        let exec = randprotocol_zkvm::emulator::execute(&p, &input, &[], Tier(22).max_cycles()).unwrap();
        assert!(exec.halted);
        assert_eq!(exec.outputs[0], (!flip) as u32);
        let perms = exec.events.iter().filter(|e| matches!(e.sys, Some(Syscall::Keccak { .. }))).count();
        assert!(exec.cycles() < 110_000, "one verification with the MODQ chip and trims: {} cycles (spec §4.2 expects ≈ 79 k)", exec.cycles());
        assert!(perms > 0);
        let modq_calls = exec.events.iter().filter(|e| matches!(e.sys, Some(Syscall::Modq { .. }))).count();
        assert_eq!(modq_calls, 18, "9 NTT + 4 DOT4 + 1 MSUB4 + 4 INTT");
        eprintln!("dilithium2 verify in the rVM: {} cycles, {} keccak permutations (valid = {})", exec.cycles(), perms, !flip);
        for m in [1usize, 2, 3, 5] {
            eprintln!("  M = {m}: {} cycles -> {:?}", m * exec.cycles(), Tier::for_workload(m * exec.cycles(), 0));
        }
    }
}

// ---- Task 7: length, cross-key and guest differential hardening -------------------------------

#[test]
fn message_lengths_agree_with_the_crate() {
    for (k, len) in [0usize, 1, 63, 64, 65, 136, 137, 1000].into_iter().enumerate() {
        let (kp, mut msg) = case(100 + k as u64, len);
        let pk = kp.public.to_bytes();
        let sig = kp.sign(&msg);
        assert!(theirs(&pk, &msg, &sig), "crate accepts len {len}");
        assert!(ours(&pk, &msg, &sig), "ours accepts len {len}");
        if let Some(last) = msg.last_mut() {
            *last ^= 1;
            assert_eq!(ours(&pk, &msg, &sig), theirs(&pk, &msg, &sig), "flipped len {len}");
            assert!(!ours(&pk, &msg, &sig), "flipped len {len} rejected");
        }
    }
}

#[test]
fn a_signature_for_one_key_fails_under_every_other_key() {
    let cs: Vec<_> = (0..10u64).map(|s| case(200 + s, 40)).collect();
    let pks: Vec<_> = cs.iter().map(|(kp, _)| kp.public.to_bytes()).collect();
    let sigs: Vec<_> = cs.iter().map(|(kp, m)| kp.sign(m)).collect();
    for (i, (_, msg)) in cs.iter().enumerate() {
        for (j, pk) in pks.iter().enumerate() {
            let got = ours(pk, msg, &sigs[i]);
            assert_eq!(got, theirs(pk, msg, &sigs[i]), "agree ({i},{j})");
            assert_eq!(got, i == j, "matrix ({i},{j})");
        }
    }
}

fn guest_valid(p: &randprotocol_zkvm::isa::Program, pk: &[u8], sig: &[u8], msg: &[u8]) -> u32 {
    use randprotocol_zkvm::machine::Tier;
    let mut input = words(pk);
    input.extend(words(sig));
    input.push(msg.len() as u32);
    input.extend(words(msg));
    let exec = randprotocol_zkvm::emulator::execute(p, &input, &[], Tier(22).max_cycles()).unwrap();
    assert!(exec.halted);
    exec.outputs[0]
}

#[test]
fn the_guest_rejects_messages_over_64_bytes_and_accepts_64() {
    let p = randprotocol_zkvm::guests::compiled::dilithium_verify();
    let (kp, msg) = case(300, 64);
    let pk = kp.public.to_bytes();
    let sig = kp.sign(&msg);
    assert_eq!(guest_valid(&p, &pk, &sig, &msg), 1, "64 bytes accepted");
    let (kp, msg) = case(301, 65);
    let sig = kp.sign(&msg);
    assert!(ours(&kp.public.to_bytes(), &msg, &sig), "the host accepts 65 bytes");
    assert_eq!(guest_valid(&p, &kp.public.to_bytes(), &sig, &msg), 0, "65 bytes refused by the guest");
}

#[test]
fn guest_and_host_agree_over_seeds() {
    let p = randprotocol_zkvm::guests::compiled::dilithium_verify();
    for seed in 400..406u64 {
        let (kp, msg) = case(seed, 20 + (seed as usize % 40));
        let pk = kp.public.to_bytes();
        let sig = kp.sign(&msg);
        let off = (seed as usize * 397) % sig.len();
        let mut bad_sig = sig.to_vec();
        bad_sig[off] ^= 0x10;
        let mut bad_pk = pk.to_vec();
        bad_pk[(seed as usize * 211) % pk.len()] ^= 0x04;
        for (name, pk, sig) in [("valid", pk.to_vec(), sig.to_vec()), ("sig", pk.to_vec(), bad_sig), ("pk", bad_pk, sig.to_vec())] {
            let want = ours(&pk, &msg, &sig) as u32;
            assert_eq!(guest_valid(&p, &pk, &sig, &msg), want, "seed {seed} {name}");
            assert_eq!(want, (name == "valid") as u32, "seed {seed} {name} host");
        }
    }
}

// ---- Task 7: software trims ---------------------------------------------------------------------

#[test]
fn uniform_words_matches_the_reference_uniform() {
    use dilithium_core::poly::{uniform, uniform_words, Poly};
    for s in 0..200u16 {
        let rho: [u8; 32] = core::array::from_fn(|i| (i as u16 * 37 + s * 11) as u8);
        let mut want = Poly::default();
        uniform(&mut HostKeccak, &mut want, &rho, s);
        let mut got = [0u32; 256];
        uniform_words(&mut HostKeccak, &mut got, &rho, s);
        assert_eq!(got, core::array::from_fn(|i| want.coeffs[i] as u32), "nonce {s}");
    }
}

#[test]
fn permute_words_is_permute_in_the_syscall_layout() {
    use dilithium_core::Keccak;
    let mut s: [u64; 25] = core::array::from_fn(|i| 0x0123_4567_89ab_cdefu64.rotate_left(i as u32 * 7));
    let mut w = randprotocol_zkvm::keccak::state_to_words(&s);
    HostKeccak.permute(&mut s);
    HostKeccak.permute_words(&mut w);
    assert_eq!(w, randprotocol_zkvm::keccak::state_to_words(&s));
}

#[test]
fn fused_unpack_matches_the_reference_unpack_and_chknorm() {
    use dilithium_core::{packing, params, poly};
    for seed in 0..60u64 {
        let (kp, msg) = case(400 + seed, 33);
        let mut sig = kp.sign(&msg).to_vec();
        if seed % 3 == 0 { sig[32 + (seed as usize * 13) % 2304] ^= 0x40; }
        let pk: [u8; 1312] = kp.public.to_bytes().try_into().unwrap();
        let sig: [u8; 2420] = sig.try_into().unwrap();
        let (mut rho, mut t1) = ([0u8; 32], poly::Polyveck::default());
        packing::unpack_pk(&mut rho, &mut t1, &pk);
        let mut t1s = [[0u32; 256]; 4];
        packing::unpack_t1_shifted(&mut t1s, &pk);
        for k in 0..4 { for i in 0..256 { assert_eq!(t1s[k][i], (t1.vec[k].coeffs[i] << 13) as u32); } }
        let (mut c, mut z, mut h) = ([0u8; 32], poly::Polyvecl::default(), poly::Polyveck::default());
        let ok = packing::unpack_sig(&mut c, &mut z, &mut h, &sig);
        let mut zc = [[0u32; 256]; 4];
        let fused = packing::unpack_z_checked(&mut zc, &sig);
        assert_eq!(fused, poly::l_chknorm(&z, (params::GAMMA1 - params::BETA) as i32) == 0, "seed {seed}");
        if ok { for k in 0..4 { for i in 0..256 { assert_eq!(zc[k][i] as i64, (z.vec[k].coeffs[i] as i64).rem_euclid(randprotocol_zkvm::modq::Q as i64)); } } }
    }
}

fn reference_w1(w: &[[u32; 256]; 4], h: &[[u32; 256]; 4]) -> [u8; 768] {
    use dilithium_core::poly;
    let (mut rw, mut rh) = (poly::Polyveck::default(), poly::Polyveck::default());
    for k in 0..4 { for i in 0..256 { rw.vec[k].coeffs[i] = w[k][i] as i32; rh.vec[k].coeffs[i] = h[k][i] as i32; } }
    poly::k_use_hint(&mut rw, &rh);
    let mut out = [0u8; 768];
    poly::k_pack_w1(&mut out, &rw);
    out
}

#[test]
fn use_hint_pack_w1_matches_the_reference_on_random_values_and_every_decompose_edge() {
    use dilithium_core::rounding::use_hint_pack_w1;
    let q = randprotocol_zkvm::modq::Q;
    let mut s = 3u64;
    let mut next = move || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    for round in 0..40 {
        let w: [[u32; 256]; 4] = core::array::from_fn(|_| core::array::from_fn(|_| (next() % q as u64) as u32));
        let h: [[u32; 256]; 4] = core::array::from_fn(|_| core::array::from_fn(|_| (next() % 7 == 0) as u32));
        let mut got = [0u8; 768];
        use_hint_pack_w1(&mut got, &w, &h);
        assert_eq!(got, reference_w1(&w, &h), "round {round}");
    }
    let g2 = 2 * dilithium_core::params::GAMMA2 as u32;
    let edges: Vec<u32> = (0..=44u32).flat_map(|m| [m * g2, (m * g2).saturating_sub(1), m * g2 + 1]).filter(|&x| x < q).chain([0, q - 1]).collect();
    for hint in [0u32, 1] {
        let w: [[u32; 256]; 4] = core::array::from_fn(|k| core::array::from_fn(|i| edges[(k * 256 + i) % edges.len()]));
        let mut got = [0u8; 768];
        use_hint_pack_w1(&mut got, &w, &[[hint; 256]; 4]);
        assert_eq!(got, reference_w1(&w, &[[hint; 256]; 4]), "decompose edges, hint {hint}");
    }
}

// ---- Task 7 fix round 1: the bounds, hit on purpose ------------------------------------------------

/// A signature whose `z` fields are all `t = gamma1` (z = 0) except the given `(poly, coeff, t)`.
fn sig_with_z_fields(fields: &[(usize, usize, u32)]) -> [u8; 2420] {
    let mut sig = [0u8; 2420];
    let mut set = |p: usize, i: usize, t: u32| {
        let bit0 = 8 * (32 + 576 * p) + 18 * i;
        for b in 0..18 {
            let (byte, off) = ((bit0 + b) / 8, (bit0 + b) % 8);
            sig[byte] = (sig[byte] & !(1 << off)) | ((((t >> b) & 1) as u8) << off);
        }
    };
    for p in 0..4 { for i in 0..256 { set(p, i, 1 << 17); } }
    for &(p, i, t) in fields { set(p, i, t); }
    sig
}

#[test]
fn z_bound_is_hit_on_purpose_at_straddling_and_plain_positions() {
    use dilithium_core::{packing, params, poly};
    let b = (params::GAMMA1 - params::BETA) as i64; // 130 994
    let g1 = params::GAMMA1 as i64;
    // (t, z = gamma1 - t, accepted)
    let cases: [(u32, i64, bool); 6] = [
        (78, b, false), (79, b - 1, true), (262_065, -(b - 1), true), (262_066, -b, false),
        (0, g1, false), ((1 << 18) - 1, -g1 + 1, false),
    ];
    for &(t, z, _) in &cases { assert_eq!(g1 - t as i64, z); }
    // 0 and 2^18-1 are the extremes of the field: outside the bound (|z| >= B), so rejected.
    for n in [1usize, 3, 5, 7, 8, 10, 12, 14, 0, 2] {
        for p in [0usize, 3] {
            for &(t, z, accepted) in &cases {
                let sig = sig_with_z_fields(&[(p, 16 * 5 + n, t)]);
                let (mut c, mut zz, mut h) = ([0u8; 32], poly::Polyvecl::default(), poly::Polyveck::default());
                assert!(packing::unpack_sig(&mut c, &mut zz, &mut h, &sig));
                assert_eq!(zz.vec[p].coeffs[16 * 5 + n] as i64, z, "reference z, t={t} n={n}");
                let ref_ok = poly::l_chknorm(&zz, b as i32) == 0;
                let mut zc = [[0u32; 256]; 4];
                let got = packing::unpack_z_checked(&mut zc, &sig);
                assert_eq!(got, accepted, "accept/reject t={t} n={n} p={p}");
                assert_eq!(got, ref_ok, "against the reference chknorm t={t} n={n} p={p}");
                if accepted {
                    assert_eq!(zc[p][16 * 5 + n] as i64, z.rem_euclid(params::Q as i64), "centred value t={t} n={n}");
                }
            }
        }
    }
}

#[test]
fn use_hint_pack_w1_is_exhaustive_over_every_canonical_residue() {
    use dilithium_core::{params, rounding};
    let q = params::Q as u32;
    let g2 = params::GAMMA2 as u32;
    let field = |p: &[u32; 48], j: usize| -> i32 {
        let b = 6 * j;
        let lo = p[b >> 5] >> (b & 31);
        let v = if (b & 31) > 26 { lo | p[(b >> 5) + 1] << (32 - (b & 31)) } else { lo };
        (v & 63) as i32
    };
    // Named boundaries first, so a failure says which.
    let mut named: Vec<(String, u32)> = vec![];
    for m in 0..44u32 {
        for (d, name) in [(0u32, "(2m+1)g2"), (1, "(2m+1)g2+1")] {
            let a = (2 * m + 1) * g2 + d;
            if a < q { named.push((format!("{name} m={m}"), a)); }
        }
    }
    named.extend([("87g2+1".into(), 87 * g2 + 1), ("q-2".into(), q - 2), ("q-1".into(), q - 1)]);
    let check = |a0: u32, label: &str| {
        let w: [u32; 256] = core::array::from_fn(|i| (a0 + i as u32).min(q - 1));
        let mut p = [0u32; 48];
        rounding::w1_pack_words(&mut p, &w);
        for j in 0..256 {
            assert_eq!(field(&p, j), rounding::decompose(w[j] as i32).1, "high bits, {label}, a={}", w[j]);
            let mut ph = p;
            rounding::w1_apply_hint(&mut ph, &w, j);
            assert_eq!(field(&ph, j), rounding::use_hint(w[j] as i32, 1), "hint patch, {label}, a={}", w[j]);
        }
    };
    for (name, a) in &named { check(a.saturating_sub(128), name); check(*a, name); }
    let mut a0 = 0u32;
    while a0 < q { check(a0, "sweep"); a0 += 256; }
}
