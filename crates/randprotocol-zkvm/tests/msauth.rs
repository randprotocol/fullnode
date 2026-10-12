use randprotocol_zkvm::msauth::*;
use randprotocol_zkvm::notes::{domain, hash};

#[test]
fn tags_are_node_local_and_distinct() {
    let tags = [AUTH, MS_LEAF, MS_NODE, MS_POLICY, NK_MS];
    for t in tags { assert!(t >= 64 && t != 0xff && t != 64); }
    let mut s = tags.to_vec(); s.sort(); s.dedup(); assert_eq!(s.len(), 5);
    assert!(![domain::NK, domain::PK].iter().any(|d| tags.contains(d)));
}

#[test]
fn the_merkle_path_of_every_signer_reaches_the_root() {
    let pks: Vec<[u8; 1312]> = (0..3u8).map(|i| [i + 1; 1312]).collect();
    let (root, paths) = signer_tree(&pks);
    for (i, pk) in pks.iter().enumerate() {
        let mut cur = leaf(pk);
        for (lvl, sib) in paths[i].iter().enumerate() {
            let mut m = [0u32; 16];
            if (i >> lvl) & 1 == 0 { m[..8].copy_from_slice(&cur); m[8..].copy_from_slice(sib); }
            else { m[..8].copy_from_slice(sib); m[8..].copy_from_slice(&cur); }
            cur = hash(MS_NODE, &m);
        }
        assert_eq!(cur, root);
    }
}

#[test]
fn the_policy_binds_threshold_keys_and_msk() {
    let pks: Vec<[u8; 1312]> = (0..3u8).map(|i| [i + 1; 1312]).collect();
    let (root, _) = signer_tree(&pks);
    let msk = [9u32; 8];
    assert_ne!(nk(&msk, &policy(2, &root)), nk(&msk, &policy(3, &root)));
    assert_ne!(nk(&msk, &policy(2, &root)), nk(&[8u32; 8], &policy(2, &root)));
    let (root2, _) = signer_tree(&pks[..2]);
    assert_ne!(policy(2, &root), policy(2, &root2));
}

#[test]
fn the_witness_has_its_fixed_length_whatever_m() {
    let s = |i| Slot { index: i, pk: [1; 1312], sig: [2; 2420], path: [[0; 8]; DEPTH] };
    assert_eq!(msauth_inputs(&[0; 8], &[0; 8], 1, &[s(0)]).len(), MSAUTH_WORDS);
    assert_eq!(msauth_inputs(&[0; 8], &[0; 8], 2, &[s(0), s(2)]).len(), MSAUTH_WORDS);
}

#[test]
fn the_signing_message_is_prefix_then_binding() {
    let m = signing_message(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&m[..13], b"rand-msauth-1");
    assert_eq!(&m[13..17], &1u32.to_le_bytes());
}

#[test]
fn the_witness_offsets_are_pinned() {
    let s = |i| Slot { index: i, pk: [1; 1312], sig: [2; 2420], path: [[7; 8]; DEPTH] };
    let w = msauth_inputs(&[3; 8], &[4; 8], 2, &[s(5), s(9)]);
    assert_eq!(&w[0..8], &[3u32; 8]);
    assert_eq!(&w[8..16], &[4u32; 8]);
    assert_eq!(w[16], 2);
    assert_eq!(w[17], 1);
    assert_eq!(w[18], 5);
    assert_eq!(w[19], 0x01010101);
    assert_eq!(w[17 + 330], 0x02020202);
    assert_eq!(w[17 + 935], 7);
    assert_eq!(w[17 + 967], 1);
    assert_eq!(w[17 + 967 + 1], 9);
    assert!(w[17 + 2 * 967..].iter().all(|&x| x == 0));
}

#[test]
#[should_panic(expected = "assertion failed: s.index < N_MAX as u32")]
fn an_out_of_range_signer_index_is_refused() {
    let s = Slot { index: 16, pk: [1; 1312], sig: [2; 2420], path: [[0; 8]; DEPTH] };
    msauth_inputs(&[0; 8], &[0; 8], 1, &[s]);
}

// ---- Task 5: the compiled `msauth` guest and its cheating suite -------------------------------

use crystals_dilithium::dilithium2::Keypair;
use randprotocol_zkvm::{emulator::execute, guests::compiled, machine::Tier};

struct Fixture { kps: Vec<Keypair>, pks: Vec<[u8; 1312]>, root: Word8, paths: Vec<[Word8; DEPTH]> }
fn fixture(n: usize) -> Fixture {
    fixture_seeded(n, 0)
}
fn fixture_seeded(n: usize, tag: u8) -> Fixture {
    let kps: Vec<Keypair> = (0..n)
        .map(|i| {
            let mut seed = [i as u8 + 1; 32];
            seed[31] = tag;
            Keypair::generate(Some(&seed)).unwrap()
        })
        .collect();
    let pks: Vec<[u8; 1312]> = kps.iter().map(|k| k.public.to_bytes().try_into().unwrap()).collect();
    let (root, paths) = signer_tree(&pks);
    Fixture { kps, pks, root, paths }
}
type Word8 = randprotocol_zkvm::notes::Word8;
const BINDING: [u32; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
const MSK: Word8 = [5; 8];
const SALT: Word8 = [6; 8];

fn slot(f: &Fixture, i: usize, binding: &[u32; 8]) -> Slot {
    let sig = f.kps[i].sign(&signing_message(binding)); // `Signature = [u8; 2420]`
    Slot { index: i as u32, pk: f.pks[i], sig, path: f.paths[i] }
}
fn exec(input: &[u32], binding: &[u32; 8]) -> randprotocol_zkvm::emulator::Execution {
    let e = execute(&compiled::msauth(), input, binding, Tier(22).max_cycles()).unwrap();
    assert!(e.halted);
    e
}
fn run(input: &[u32], binding: &[u32; 8]) -> [u32; 8] {
    exec(input, binding).outputs[..8].try_into().unwrap()
}
fn expected(f: &Fixture, t: u32) -> Word8 { auth_commit(&nk(&MSK, &policy(t, &f.root)), &SALT) }

#[test]
fn two_of_three_publishes_the_hosts_commit() {
    let f = fixture(3);
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 2, &BINDING)]);
    assert_eq!(run(&input, &BINDING), expected(&f, 2));
}

#[test]
fn below_threshold_is_refused() {
    let f = fixture(3);
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING)]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn duplicate_index_is_refused() {
    let f = fixture(3);
    let s = slot(&f, 1, &BINDING);
    let input = msauth_inputs(&MSK, &SALT, 2, &[s.clone(), s]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn slots_from_two_policies_are_refused() {
    let (a, b) = (fixture(3), fixture(4));
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&a, 0, &BINDING), slot(&b, 3, &BINDING)]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn signature_over_another_binding_is_refused() {
    let f = fixture(3);
    let other = [0u32; 8];
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &other)]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn one_bad_signature_among_enough_good_ones_is_refused() {
    let f = fixture(3);
    let mut bad = slot(&f, 2, &BINDING);
    bad.sig[200] ^= 1;
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING), bad]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn threshold_zero_and_over_m_max_are_refused() {
    let f = fixture(3);
    for t in [0, M_MAX as u32 + 1] {
        let input = msauth_inputs(&MSK, &SALT, t, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
        assert_eq!(run(&input, &BINDING)[7], 0xdead_beef, "threshold {t}");
    }
}

#[test]
fn index_out_of_range_and_non_boolean_active_are_refused() {
    let f = fixture(3);
    // `msauth_inputs` itself refuses index 16 (Task 4), so the cheat is written into the
    // witness word directly: slot 0's `index` is word 18.
    let mut input = msauth_inputs(&MSK, &SALT, 1, &[slot(&f, 0, &BINDING)]);
    input[18] = 16;
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
    let mut input = msauth_inputs(&MSK, &SALT, 1, &[slot(&f, 0, &BINDING)]);
    input[17] = 2; // slot 0's `active`
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn a_wrong_msk_publishes_a_different_commit() {
    let f = fixture(3);
    let input = msauth_inputs(&[4; 8], &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
    assert_ne!(run(&input, &BINDING), expected(&f, 2));
}

/// Beyond the brief: the guest and the host model agree on random policies, and dropping one
/// signer from an exactly-at-threshold witness is refused.
#[test]
fn the_guest_matches_the_host_model_on_random_policies() {
    let mut x: u64 = 0x5eed_0f_75a7;
    let mut next = move || {
        // splitmix64
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    for case in 0..20u8 {
        let n = 1 + (next() % 16) as usize;
        let t = 1 + (next() % n.min(M_MAX) as u64) as u32;
        let count = t as usize + (next() % (n.min(M_MAX) - t as usize + 1) as u64) as usize;
        // `count` distinct indices of `0..n`, sorted increasing (partial Fisher-Yates).
        let mut pool: Vec<usize> = (0..n).collect();
        for i in 0..count {
            let j = i + (next() % (n - i) as u64) as usize;
            pool.swap(i, j);
        }
        let mut idx = pool[..count].to_vec();
        idx.sort();
        let msk: Word8 = core::array::from_fn(|_| next() as u32);
        let salt: Word8 = core::array::from_fn(|_| next() as u32);
        let binding: [u32; 8] = core::array::from_fn(|_| next() as u32);
        let f = fixture_seeded(n, case);
        let slots: Vec<Slot> = idx.iter().map(|&i| slot(&f, i, &binding)).collect();
        let want = auth_commit(&nk(&msk, &policy(t, &f.root)), &salt);
        let got = run(&msauth_inputs(&msk, &salt, t, &slots), &binding);
        assert_eq!(got, want, "case {case}: n {n} t {t} idx {idx:?}");
        if count == t as usize {
            let drop = (next() % count as u64) as usize;
            let mut fewer = slots.clone();
            fewer.remove(drop);
            let out = run(&msauth_inputs(&msk, &salt, t, &fewer), &binding);
            assert_eq!(out[7], 0xdead_beef, "case {case}: dropped slot {drop} of {count}");
        }
    }
}

/// Prints the cycle count at 1, 2 and 3 active slots and the lowest stack word touched
/// (`--nocapture`), and holds each run to the tier-22 cycle budget.
#[test]
fn cycles_at_one_two_and_three_signers() {
    let f = fixture(3);
    for k in 1..=3 {
        let slots: Vec<Slot> = (0..k).map(|i| slot(&f, i, &BINDING)).collect();
        let e = exec(&msauth_inputs(&MSK, &SALT, 1, &slots), &BINDING);
        assert_eq!(e.outputs[..8], expected(&f, 1));
        let top = e.events.iter().flat_map(|ev| ev.accesses.iter()).map(|a| a.addr).max().unwrap();
        let low = e
            .events
            .iter()
            .flat_map(|ev| ev.accesses.iter())
            .map(|a| a.addr)
            .filter(|&a| a + 0x4000 > top) // the 64 KiB stack is 0x4000 words below the top
            .min()
            .unwrap();
        eprintln!("msauth: {k} active slot(s): {} cycles; stack words {:#x}..={:#x} ({} B)", e.cycles(), low, top, 4 * (top - low + 1));
    }
}

// ---- Task 7: adversarial and edge-policy hardening ---------------------------------------------

const REFUSED: u32 = 0xdead_beef;
/// Witness word of slot `s`'s path, sibling `lvl`, word `w`.
fn path_word(s: usize, lvl: usize, w: usize) -> usize { 17 + SLOT_WORDS * s + (SLOT_WORDS - 8 * DEPTH) + 8 * lvl + w }
/// The commit the host model gives a lone slot at threshold 1, from the root its own pk, index
/// and path imply.
fn implied_commit(s: &Slot) -> Word8 {
    let mut cur = leaf(&s.pk);
    for (lvl, sib) in s.path.iter().enumerate() {
        let mut m = [0u32; 16];
        if (s.index >> lvl) & 1 == 0 { m[..8].copy_from_slice(&cur); m[8..].copy_from_slice(sib); }
        else { m[..8].copy_from_slice(sib); m[8..].copy_from_slice(&cur); }
        cur = hash(MS_NODE, &m);
    }
    auth_commit(&nk(&MSK, &policy(1, &cur)), &SALT)
}

#[test]
fn descending_indices_are_refused() {
    let f = fixture(3);
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 2, &BINDING), slot(&f, 1, &BINDING)]);
    assert_eq!(run(&input, &BINDING)[7], REFUSED);
}

#[test]
fn corrupted_sibling_within_one_policy_is_refused() {
    let f = fixture(3);
    let mut input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
    let at = path_word(1, 2, 3);
    let honest = input[at];
    input[at] ^= 1;
    assert_ne!(input[at], honest);
    assert_eq!(run(&input, &BINDING)[7], REFUSED);
}

#[test]
fn a_single_signer_with_a_corrupted_path_changes_the_commit() {
    let f = fixture(3);
    let mut input = msauth_inputs(&MSK, &SALT, 1, &[slot(&f, 1, &BINDING)]);
    let at = path_word(0, 1, 0);
    let honest = input[at];
    input[at] ^= 0x8000_0000;
    assert_ne!(input[at], honest);
    assert_ne!(run(&input, &BINDING), expected(&f, 1));
}

#[test]
fn pk_from_one_index_with_the_path_of_another_is_refused() {
    // Expectation corrected from the brief: a lone mismatched slot derives its own (bogus) root
    // and publishes the commit of that other policy, which never equals the honest commit; only
    // alongside an honest signer does the root disagree and the guest refuse.
    let f = fixture(3);
    let mut s = slot(&f, 0, &BINDING);
    s.index = 1;
    s.path = f.paths[1];
    let input = msauth_inputs(&MSK, &SALT, 1, &[s.clone()]);
    let out = run(&input, &BINDING);
    assert_ne!(out[7], REFUSED);
    assert_ne!(out, expected(&f, 1));
    assert_eq!(out, implied_commit(&s));
    // ascending (1 then 2), so the root mismatch is what refuses, not the ordering
    let input = msauth_inputs(&MSK, &SALT, 2, &[s, slot(&f, 2, &BINDING)]);
    assert_eq!(run(&input, &BINDING)[7], REFUSED);
}

#[test]
fn inactive_slots_are_ignored_even_with_garbage() {
    let f = fixture(3);
    let mut input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
    let base = 17 + 967 * 2;
    assert_eq!(input[base], 0);
    for w in &mut input[base + 1..base + 967] { *w = 0xABAB_ABAB; }
    assert_eq!(run(&input, &BINDING), expected(&f, 2));
}

#[test]
fn edge_policies_publish_the_hosts_commit() {
    // 1-of-1
    let f = fixture(1);
    let input = msauth_inputs(&MSK, &SALT, 1, &[slot(&f, 0, &BINDING)]);
    assert_eq!(run(&input, &BINDING), expected(&f, 1), "1-of-1");
    // 3-of-3
    let f = fixture(3);
    let all: Vec<Slot> = (0..3).map(|i| slot(&f, i, &BINDING)).collect();
    assert_eq!(run(&msauth_inputs(&MSK, &SALT, 3, &all), &BINDING), expected(&f, 3), "3-of-3");
    // 1-of-16 and 2-of-16 at the far end of the tree
    let f = fixture(16);
    let input = msauth_inputs(&MSK, &SALT, 1, &[slot(&f, 15, &BINDING)]);
    assert_eq!(run(&input, &BINDING), expected(&f, 1), "1-of-16 at index 15");
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 15, &BINDING)]);
    assert_eq!(run(&input, &BINDING), expected(&f, 2), "2-of-16 at 0 and 15");
}

#[test]
fn same_signatures_under_another_binding_are_refused() {
    let f = fixture(3);
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
    let other = [1u32, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(run(&input, &other)[7], REFUSED);
}

#[test]
fn msk_and_salt_each_change_the_commit() {
    let f = fixture(3);
    let s = [slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)];
    let honest = run(&msauth_inputs(&MSK, &SALT, 2, &s), &BINDING);
    let by_msk = run(&msauth_inputs(&[7; 8], &SALT, 2, &s), &BINDING);
    let by_salt = run(&msauth_inputs(&MSK, &[8; 8], 2, &s), &BINDING);
    assert_eq!(honest, expected(&f, 2));
    assert_ne!(by_msk, honest);
    assert_ne!(by_salt, honest);
    assert_ne!(by_msk, by_salt);
    assert_ne!(by_msk[7], REFUSED);
    assert_ne!(by_salt[7], REFUSED);
}

#[test]
fn more_active_than_threshold_is_accepted() {
    let f = fixture(3);
    let all: Vec<Slot> = (0..3).map(|i| slot(&f, i, &BINDING)).collect();
    assert_eq!(run(&msauth_inputs(&MSK, &SALT, 1, &all), &BINDING), expected(&f, 1));
}

#[test]
fn threshold_above_the_active_count_is_refused() {
    let f = fixture(3);
    let input = msauth_inputs(&MSK, &SALT, 3, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
    assert_eq!(run(&input, &BINDING)[7], REFUSED);
}

#[test]
fn a_signature_by_a_non_member_with_a_member_path_is_refused() {
    let f = fixture(3);
    let outsider = Keypair::generate(Some(&[0xEE; 32])).unwrap();
    let mut s = slot(&f, 1, &BINDING);
    s.sig = outsider.sign(&signing_message(&BINDING));
    // (a) the outsider's signature under the member's pk fails the signature check
    let input = msauth_inputs(&MSK, &SALT, 1, &[s.clone()]);
    assert_eq!(run(&input, &BINDING)[7], REFUSED);
    // (b) the outsider's own valid signature and pk with a member's path: alone it derives a
    // different root (a different policy's commit, never the honest one); next to an honest
    // signer the roots disagree and the guest refuses. (Brief expected the sentinel for the
    // lone case; the guest cannot know the true root, so the commit mismatch is the defence.)
    s.pk = outsider.public.to_bytes().try_into().unwrap();
    s.sig = outsider.sign(&signing_message(&BINDING));
    let input = msauth_inputs(&MSK, &SALT, 1, &[s.clone()]);
    let out = run(&input, &BINDING);
    assert_ne!(out[7], REFUSED);
    assert_ne!(out, expected(&f, 1));
    assert_eq!(out, implied_commit(&s));
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), s]);
    assert_eq!(run(&input, &BINDING)[7], REFUSED);
}

#[test]
fn public_multisig_message_format_is_not_accepted() {
    let f = fixture(3);
    let raw: Vec<u8> = BINDING.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert_eq!(raw.len(), 32);
    let mk = |i: usize| Slot { index: i as u32, pk: f.pks[i], sig: f.kps[i].sign(&raw), path: f.paths[i] };
    let input = msauth_inputs(&MSK, &SALT, 2, &[mk(0), mk(1)]);
    assert_eq!(run(&input, &BINDING)[7], REFUSED);
    // control: the same signers over the prefixed message are accepted
    let ok = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
    assert_eq!(run(&ok, &BINDING), expected(&f, 2));
}

// ---- MODQ phase 3, Task 8: the tier-18 gate and the pinned shape ----------------------------

fn full_run(k: usize) -> (randprotocol_zkvm::isa::Program, Vec<u32>, randprotocol_zkvm::emulator::Execution) { full_run_t(k, 1) }
fn full_run_t(k: usize, threshold: u32) -> (randprotocol_zkvm::isa::Program, Vec<u32>, randprotocol_zkvm::emulator::Execution) {
    let f = fixture(M_MAX);
    let slots: Vec<Slot> = (0..k).map(|i| slot(&f, i, &BINDING)).collect();
    let input = msauth_inputs(&MSK, &SALT, threshold, &slots);
    let e = exec(&input, &BINDING);
    (compiled::msauth(), input, e)
}

fn workload(k: usize) -> (usize, usize) {
    let (p, input, e) = full_run(k);
    let cycles = e.cycles() + p.digest_rows() + randprotocol_zkvm::hash::input_digest_row_count(input.len()) + randprotocol_zkvm::hash::public_digest_row_count(BINDING.len());
    (cycles, poseidon2_permutations(&p, input.len(), &e))
}

#[test]
fn m_max_fits_tier_18_counting_cycles_and_poseidon2_permutations() {
    use randprotocol_zkvm::emulator::Syscall;
    for k in 1..=3 {
        let (p, input, e) = full_run(k);
        let (cycles, perms) = workload(k);
        let keccak = e.events.iter().filter(|ev| matches!(ev.sys, Some(Syscall::Keccak { .. }))).count();
        let modq = e.events.iter().filter(|ev| matches!(ev.sys, Some(Syscall::Modq { .. }))).count();
        let accesses: usize = e.events.iter().map(|ev| ev.accesses.len()).sum();
        let modq_acc: usize = e.events.iter().filter_map(|ev| ev.modq.as_ref()).map(|m| m.accesses.len()).sum();
        let t = randprotocol_zkvm::machine::build_traces_salted_with(&p, &input, &BINDING, [0; 4], &e, Tier(18), Default::default());
        let heights = t.as_ref().map(|t| (t.keccak_log_height, t.modq_log_height, t.mem_log_height)).ok();
        eprintln!("GATE: M = {k}: {cycles} cycles, {perms} Poseidon2 permutations, {keccak} keccak, {modq} modq calls, {accesses} cpu mem accesses + {modq_acc} modq accesses, (keccak,modq,mem) log heights {heights:?} -> {:?}", Tier::for_workload(cycles, perms));
    }
    let (cycles, perms) = workload(M_MAX);
    assert_eq!(Tier::for_workload(cycles, perms), Some(MSAUTH_TIER), "ruling: M_MAX must fit tier 18 — if this fails at M_MAX = 3, set M_MAX = 2");
}

fn declared(k: usize, opts: randprotocol_zkvm::machine::ProveOptions) -> (Vec<u8>, String) { declared_t(k, 1, opts) }
fn declared_t(k: usize, threshold: u32, opts: randprotocol_zkvm::machine::ProveOptions) -> (Vec<u8>, String) {
    let (p, input, e) = full_run_t(k, threshold);
    let t = randprotocol_zkvm::machine::build_traces_salted_with(&p, &input, &BINDING, [0; 4], &e, MSAUTH_TIER, opts).unwrap();
    let h = vec![t.program_log_height, t.input_log_height, t.keccak_log_height, t.sha256_log_height, t.modq_log_height, t.public_log_height, t.mem_log_height];
    (h, format!("{:?}", t.public_values[randprotocol_zkvm::tables::cpu::pv::GAS]))
}

#[test]
fn pinned_heights_are_what_a_full_run_declares() {
    let (h, _) = declared(M_MAX, Default::default());
    let o = pinned_options();
    eprintln!("PINNED: keccak {} modq {} mem {} (all heights {h:?})", h[2], h[4], h[6]);
    assert_eq!((o.min_keccak_log_height, o.min_modq_log_height, o.min_mem_log_height), (h[2], h[4], h[6]));
    assert_eq!(o.gas_limit, None);
}

#[test]
fn proof_shape_is_the_same_for_every_m() {
    let mut shapes: Vec<_> = (1..=M_MAX).map(|k| declared(k, pinned_options())).collect();
    shapes.push(declared_t(M_MAX, 2, pinned_options())); // threshold 2 with all three signing
    assert!(shapes.windows(2).all(|w| w[0] == w[1]), "every M declares M_MAX's shape and the header-ceiling gas word: {shapes:?}");
    // and without the floors the shapes differ, so the test has teeth
    let loose: Vec<_> = (1..=M_MAX).map(|k| declared(k, Default::default()).0).collect();
    assert!(loose.windows(2).any(|w| w[0] != w[1]), "unfloored heights should differ across M: {loose:?}");
}

/// Where the one-M Production proofs write their JSON; `MSAUTH_PROOF_DIR` overrides the default.
fn proof_dir() -> String { std::env::var("MSAUTH_PROOF_DIR").unwrap_or_else(|_| "/private/tmp/claude-501".to_string()) }

/// One Production proof, ONE M per process (`MSAUTH_PROVE_M`=1 or 3, default 3), so no process holds
/// two proofs. Prints one parseable `PROOF` line and writes `msauth-proof-M<m>.json` (sha256, size,
/// tier, the seven heights, the GAS word) for `msauth_proof_headers_match_across_m`.
#[test]
#[ignore = "MODQ Task 8: Production proof of ONE M (env MSAUTH_PROVE_M, default 3) at the pinned shape — run under /usr/bin/time -l"]
fn msauth_proves_at_m_production() {
    use randprotocol_zkvm::machine::{FriProfile, Machine};
    use randprotocol_zkvm::tables::cpu::pv;
    use sha2::{Digest, Sha256};
    let k: usize = std::env::var("MSAUTH_PROVE_M").ok().map_or(M_MAX, |v| v.parse().expect("MSAUTH_PROVE_M"));
    assert!((1..=M_MAX).contains(&k));
    let (p, input) = { let (p, input, _exec) = full_run(k); (p, input) }; // the Execution is dropped here
    let profile = match std::env::var("MSAUTH_PROVE_PROFILE").as_deref() {
        Ok("test") => FriProfile::Test,
        Ok("production") | Err(_) => FriProfile::Production,
        Ok(o) => panic!("MSAUTH_PROVE_PROFILE={o}: test|production"),
    };
    let m = Machine::new(profile);
    let t0 = std::time::Instant::now();
    let proof = prove_msauth(&m, &p, &input, &BINDING).unwrap();
    let prove = t0.elapsed();
    m.verify_public(&p.digest(), &BINDING, &proof).unwrap();
    let bytes = proof.to_bytes();
    let heights = [proof.program_log_height, proof.input_log_height, proof.keccak_log_height, proof.sha256_log_height, proof.modq_log_height, proof.public_log_height, proof.mem_log_height];
    let gas = format!("{:?}", proof.public_values[pv::GAS]);
    let sha: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    let line = format!("{{\"m\":{k},\"size\":{},\"tier\":{},\"heights\":{heights:?},\"gas\":\"{gas}\",\"sha256\":\"{sha}\",\"profile\":\"{profile:?}\",\"prove_secs\":{:.1}}}", bytes.len(), proof.tier.0, prove.as_secs_f64());
    eprintln!("PROOF {line}");
    std::fs::write(format!("{}/msauth-proof-M{k}-{profile:?}.json", proof_dir()), format!("{line}\n")).unwrap();
}

/// Cheap: reads the two JSON files the one-M proves wrote and asserts the proofs are indistinguishable
/// by tier, heights and GAS word (exact) and by size (within varint noise).
#[test]
#[ignore = "MODQ Task 8: run after msauth_proves_at_m_production has run for M=1 and M=3"]
fn msauth_proof_headers_match_across_m() {
    let field = |s: &str, key: &str| -> String {
        let at = s.find(&format!("\"{key}\":")).unwrap_or_else(|| panic!("no {key} in {s}")) + key.len() + 3;
        let rest = &s[at..];
        let end = if rest.starts_with('[') { rest.find(']').unwrap() + 1 } else if rest.starts_with('"') { rest[1..].find('"').unwrap() + 2 } else { rest.find(|c| c == ',' || c == '}').unwrap() };
        rest[..end].to_string()
    };
    let read = |k: usize| std::fs::read_to_string(format!("{}/msauth-proof-M{k}-Production.json", proof_dir())).unwrap_or_else(|e| panic!("M{k}: {e}"));
    let (a, b) = (read(1), read(M_MAX));
    for key in ["tier", "heights", "gas"] {
        assert_eq!(field(&a, key), field(&b, key), "{key} must not leak M\n{a}{b}");
    }
    // Admission must never pin proof length: proof bytes are postcard varints, so the size jitters by
    // about 1% between witnesses. A 2% band still catches a gross M-dependent size.
    let size = |s: &str| field(s, "size").parse::<usize>().unwrap();
    let (s1, s3) = (size(&a), size(&b));
    assert!(s1.abs_diff(s3) <= s1.max(s3) / 50, "size must not leak M beyond varint noise: {s1} vs {s3}");
    eprintln!("HEADERS MATCH: size {} tier {} heights {} gas {}", field(&a, "size"), field(&a, "tier"), field(&a, "heights"), field(&a, "gas"));
}

#[test]
fn the_wrapper_refuses_a_shape_that_is_not_the_pinned_one() {
    let (p, input, _) = full_run(M_MAX);
    check_pinned_shape_with(&p, &input, &BINDING, pinned_options()).unwrap();
    // M = 1 with the modq floor lowered to 15: the declared modq height is 15, not the pinned 16.
    let (p1, in1, _) = full_run(1);
    let mut o = pinned_options();
    o.min_modq_log_height = 15;
    let err = check_pinned_shape_with(&p1, &in1, &BINDING, o).unwrap_err();
    assert!(err.contains("modq_log_height = 15, pinned 16"), "{err}");
    // no floors at all: M = 1 declares keccak 12
    let err = check_pinned_shape_with(&p1, &in1, &BINDING, Default::default()).unwrap_err();
    assert!(err.contains("keccak_log_height = 12, pinned 14"), "{err}");
}

/// The gate over five fixtures: different keys for all three signers, msk, salt and binding.
#[test]
fn the_gate_holds_over_random_fixtures() {
    let (mut cmin, mut cmax, mut pmin, mut pmax) = (usize::MAX, 0, usize::MAX, 0);
    for tag in 1u8..=5 {
        let f = fixture_seeded(M_MAX, tag.wrapping_mul(37));
        let binding: [u32; 8] = core::array::from_fn(|i| (tag as u32 + 1).wrapping_mul(0x9e37_79b9).wrapping_add(i as u32 * 7919));
        let msk: Word8 = core::array::from_fn(|i| tag as u32 * 1000 + i as u32);
        let salt: Word8 = core::array::from_fn(|i| tag as u32 * 77_777 + i as u32);
        let slots: Vec<Slot> = (0..M_MAX).map(|i| slot(&f, i, &binding)).collect();
        let input = msauth_inputs(&msk, &salt, 2, &slots);
        let e = exec(&input, &binding);
        let p = compiled::msauth();
        let cycles = e.cycles() + p.digest_rows() + randprotocol_zkvm::hash::input_digest_row_count(input.len()) + randprotocol_zkvm::hash::public_digest_row_count(binding.len());
        let perms = poseidon2_permutations(&p, input.len(), &e);
        eprintln!("FIXTURE {tag}: {cycles} cycles, {perms} perms");
        assert_eq!(Tier::for_workload(cycles, perms), Some(MSAUTH_TIER));
        check_pinned_shape_with(&p, &input, &binding, pinned_options()).unwrap();
        // natural heights equal the pinned ones at M_MAX
        let t = randprotocol_zkvm::machine::build_traces_salted_with(&p, &input, &binding, [0; 4], &e, MSAUTH_TIER, Default::default()).unwrap();
        assert_eq!((t.keccak_log_height, t.modq_log_height, t.mem_log_height), (PINNED_KECCAK_LOG_HEIGHT, PINNED_MODQ_LOG_HEIGHT, PINNED_MEM_LOG_HEIGHT), "fixture {tag}");
        cmin = cmin.min(cycles); cmax = cmax.max(cycles); pmin = pmin.min(perms); pmax = pmax.max(perms);
    }
    eprintln!("FIXTURES: M = 3 cycles min {cmin} max {cmax}; perms min {pmin} max {pmax}");
    assert!(cmax <= Tier(18).max_cycles());
}
