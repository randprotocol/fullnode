//! Emulation-only checks of the committed compiled guests and of the host-side input builders
//! (`notes::transfer_inputs`, `notes::bundle_inputs`) against their reference outputs.
//!
//! Nothing here proves: every test runs the guest in the emulator and compares its eight output
//! words with what the host computes natively. That keeps the file cheap (the suite that proves
//! lives in `e2e.rs`, `viewing.rs` and `bundle.rs`, which a hosted runner cannot hold) while still
//! pinning the guest/host agreement those files establish.
use evm_core::u256::U256;
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::evm::{abi_call, erc20_transfer, mapping_slot, ALICE, BOB, SLOT_BALANCES};
use randprotocol_zkvm::guests;
use randprotocol_zkvm::keccak::keccak256;
use randprotocol_zkvm::ledger::CommitmentTree;
use randprotocol_zkvm::notes::{self, bundle_input, input, Note, SpendKey, Word8, DEPTH};

// ---- the committed compiled guests ---------------------------------------------------------------

#[test]
fn compiled_fib_agrees_with_the_hand_written_guest_for_several_n() {
    let compiled = guests::compiled::fib();
    for n in [0u32, 1, 2, 3, 10, 20, 40] {
        let c = execute(&compiled, &[n], &[], 100_000).unwrap();
        let h = execute(&guests::fib(n), &[], &[], 100_000).unwrap();
        assert!(c.halted, "fib({n}) halts");
        assert_eq!(c.outputs[0], h.outputs[0], "fib({n})");
    }
}

#[test]
fn compiled_fib_has_a_stable_nonempty_image() {
    let p = guests::compiled::fib();
    assert!(!p.is_empty());
    assert_eq!(p.digest(), guests::compiled::fib().digest(), "loading is deterministic");
    assert_ne!(p.digest(), guests::compiled::keccak256().digest(), "distinct guests, distinct hc");
}

fn keccak_input(msg: &[u8]) -> Vec<u32> {
    let mut v = vec![msg.len() as u32];
    for c in msg.chunks(4) {
        let mut w = [0u8; 4];
        w[..c.len()].copy_from_slice(c);
        v.push(u32::from_le_bytes(w));
    }
    v
}

#[test]
fn compiled_keccak256_matches_the_host_at_every_block_boundary() {
    let p = guests::compiled::keccak256();
    // empty, sub-word, word-aligned, one byte shy of the 136-byte rate, exactly the rate (needs a
    // whole extra padding block), one past it, and two blocks plus a tail
    for len in [0usize, 1, 3, 4, 5, 63, 64, 131, 135, 136] {
        let msg: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(len as u8)).collect();
        let exec = execute(&p, &keccak_input(&msg), &[], 1 << 20).unwrap();
        let want = keccak256(&msg);
        for k in 0..8 {
            assert_eq!(exec.outputs[k], u32::from_le_bytes(want[4 * k..4 * k + 4].try_into().unwrap()), "len {len}, digest word {k}");
        }
        // up to 135 bytes the padding fits the one block; exactly 136 needs a second, all-padding one
        let permutations = if len == 136 { 2 } else { 1 };
        assert_eq!(exec.events.iter().filter(|e| e.keccak_row.is_some()).count(), permutations, "len {len}");
    }
}

/// The guest's buffer is one rate block (`guests-compiled/keccak256`'s header: `n <= 136`). A longer
/// message must not yield the digest of the whole message.
#[test]
fn compiled_keccak256_does_not_publish_a_digest_for_a_message_past_its_buffer() {
    let p = guests::compiled::keccak256();
    let msg = vec![0xabu8; 137];
    let want = keccak256(&msg);
    let want_words: Vec<u32> = (0..8).map(|k| u32::from_le_bytes(want[4 * k..4 * k + 4].try_into().unwrap())).collect();
    if let Ok(exec) = execute(&p, &keccak_input(&msg), &[], 1 << 20) {
        assert_ne!(exec.outputs[..8], want_words[..], "must not claim the digest of 137 bytes");
    }
}

#[test]
fn compiled_evm_guest_reproduces_the_native_interpreter_on_view_approve_and_revert() {
    use randprotocol_zkvm::evm::{mapping_slot2, SLOT_ALLOWANCES};
    let p = guests::compiled::evm();
    let cycles = randprotocol_zkvm::machine::Tier(18).max_cycles();

    // balanceOf is a view call: the seeded balance comes back and the storage root does not move
    let mut bal = erc20_transfer(ALICE, BOB, U256::ZERO, &[(ALICE, U256::from_u32(1000))]);
    bal.calldata = abi_call("balanceOf(address)", &[ALICE]);
    bal.touched = vec![mapping_slot(&ALICE, SLOT_BALANCES)];
    let (want, o, post) = bal.expected();
    assert_eq!(o.status(), 1);
    assert_eq!(U256::from_be_slice(&o.ret[..32]), U256::from_u32(1000));
    assert_eq!(post.root(), bal.tree.root());
    assert_eq!(execute(&p, &bal.input_words(), &[], cycles).unwrap().outputs, want);

    // approve writes the nested mapping slot and logs one Approval
    let mut ap = erc20_transfer(ALICE, BOB, U256::ZERO, &[]);
    ap.calldata = abi_call("approve(address,uint256)", &[BOB, U256::from_u32(5)]);
    ap.touched = vec![mapping_slot2(&ALICE, &BOB, SLOT_ALLOWANCES)];
    let (want_ap, o_ap, ap_post) = ap.expected();
    assert_eq!(o_ap.status(), 1);
    assert_eq!(o_ap.n_logs, 1);
    assert_ne!(ap_post.root(), ap.tree.root());
    assert_eq!(execute(&p, &ap.input_words(), &[], cycles).unwrap().outputs, want_ap);

    // an over-balance transfer reverts (status 0) and moves no storage
    let over = erc20_transfer(ALICE, BOB, U256::from_u32(5000), &[(ALICE, U256::from_u32(1000))]);
    let (want_r, o_r, over_post) = over.expected();
    assert_eq!(o_r.status(), 0);
    assert_eq!(over_post.root(), over.tree.root());
    assert_eq!(execute(&p, &over.input_words(), &[], cycles).unwrap().outputs, want_r);

    // three different calls, three different public outputs under one program digest
    assert_ne!(want, want_ap);
    assert_ne!(want, want_r);
    assert_ne!(want_ap, want_r);
}

#[test]
fn compiled_sbpf_guest_matches_the_native_run_on_success_and_on_insufficient_funds() {
    use randprotocol_zkvm::sbpf::{deserialize_accounts, spl_transfer, TOKEN_AMOUNT_AT};
    let p = guests::compiled::sbpf();
    const CAP: usize = 4_000_000;

    let ok = spl_transfer(250);
    let (want_ok, r0, post) = ok.expected();
    assert_eq!(r0, Ok(0));
    assert_eq!(want_ok[0], 1);
    let pre = deserialize_accounts(&ok.input);
    let bal = |d: &[u8]| u64::from_le_bytes(d[TOKEN_AMOUNT_AT..TOKEN_AMOUNT_AT + 8].try_into().unwrap());
    assert_eq!(bal(&pre[0].data) - 250, bal(&post[0].data));
    assert_eq!(bal(&pre[1].data) + 250, bal(&post[1].data));
    let exec = execute(&p, &ok.input_words(), &ok.public_words(), CAP).unwrap();
    assert_eq!(exec.outputs, want_ok);

    let bad = spl_transfer(u64::MAX / 2);
    let (want_bad, r0, post) = bad.expected();
    assert!(matches!(r0, Ok(code) if code != 0));
    assert_eq!(want_bad[0], 0);
    assert_eq!(post, deserialize_accounts(&bad.input), "a failed transfer publishes the pre-state");
    let exec = execute(&p, &bad.input_words(), &bad.public_words(), CAP).unwrap();
    assert_eq!(exec.outputs, want_bad);
    assert_ne!(&want_bad[1..], &want_ok[1..]);
}

// ---- notes: the input builders against the guests -------------------------------------------------

fn key() -> SpendKey {
    SpendKey::random()
}

#[test]
fn transfer_inputs_lays_every_field_at_its_documented_offset() {
    let sk = key();
    let vk = sk.viewing_key();
    let spent = Note::new(vk.pk(), key().viewing_key().pk(), 0x1_2345_6789, 7, 111);
    let created = Note::new(key().viewing_key().pk(), vk.pk(), 0x1_2345_6789, 7, 222);
    let mut tree = CommitmentTree::new();
    for i in 0..5u32 {
        tree.append(notes::hash(notes::domain::TEST, &[i]));
    }
    tree.append(spent.commitment());
    let (path, index) = tree.path_for(&spent.commitment()).unwrap();
    assert_eq!(index, 5);

    let v = notes::transfer_inputs(&sk, &spent, &created, &path, index);
    assert_eq!(v.len(), input::COUNT);
    assert_eq!(&v[input::SK..input::SK + 8], &sk.0);
    assert_eq!(&v[input::IN_FROM..input::IN_FROM + 8], &spent.from);
    assert_eq!(v[input::IN_AMOUNT_LO], 0x2345_6789);
    assert_eq!(v[input::IN_AMOUNT_HI], 1, "the amount is split low/high");
    assert_eq!(v[input::IN_ASSET], 7);
    assert_eq!(v[input::IN_TIME], 111);
    assert_eq!(&v[input::IN_R..input::IN_R + 8], &spent.r);
    assert_eq!(&v[input::OUT_PK..input::OUT_PK + 8], &created.pk);
    assert_eq!(v[input::OUT_TIME], 222);
    assert_eq!(&v[input::OUT_R..input::OUT_R + 8], &created.r);
    for (level, sib) in path.iter().enumerate() {
        assert_eq!(&v[input::PATH + 8 * level..input::PATH + 8 * level + 8], sib, "path level {level}");
    }
    assert_eq!(v[input::INDEX], 5);
    assert_eq!(v.len(), input::INDEX + 1, "the index is the last word");
}

#[test]
fn the_transfer_guest_publishes_expected_outputs_and_a_changed_anchor_changes_them() {
    let sk = key();
    let vk = sk.viewing_key();
    let spent = Note::new(vk.pk(), key().viewing_key().pk(), 500, 1, 100);
    let created = Note::new(key().viewing_key().pk(), vk.pk(), 500, 1, 160);
    let mut tree = CommitmentTree::new();
    tree.append(notes::hash(notes::domain::TEST, &[9]));
    tree.append(spent.commitment());
    let (path, index) = tree.path_for(&spent.commitment()).unwrap();
    let anchor = tree.root();

    let inputs = notes::transfer_inputs(&sk, &spent, &created, &path, index);
    let e = execute(&guests::transfer(), &inputs, &[], 1 << 22).unwrap();
    assert!(e.halted);
    assert_eq!(e.outputs, notes::expected_outputs(&sk, &spent, &created, anchor));

    // the digest binds the anchor: the same spend against another root is another digest
    let mut other = anchor;
    other[0] ^= 1;
    assert_ne!(notes::expected_outputs(&sk, &spent, &created, other), e.outputs);
    // and the nullifier: a different spender (same note) is another digest
    assert_ne!(notes::expected_outputs(&key(), &spent, &created, anchor), e.outputs);
}

fn two_inputs(owner: &SpendKey, amounts: [u64; 2], asset: u32, time: u32) -> (CommitmentTree, [(Note, [Word8; DEPTH], u32); 2]) {
    let pk = owner.viewing_key().pk();
    let mut tree = CommitmentTree::new();
    let ns: Vec<Note> = amounts.iter().map(|&a| Note::new(pk, key().viewing_key().pk(), a, asset, time)).collect();
    for n in &ns {
        tree.append(n.commitment());
    }
    let ins = std::array::from_fn(|i| {
        let (p, idx) = tree.path_for(&ns[i].commitment()).unwrap();
        (ns[i], p, idx)
    });
    (tree, ins)
}

#[test]
fn bundle_inputs_lays_both_inputs_both_outputs_and_the_scalars_at_their_offsets() {
    use bundle_input::*;
    let sk = key();
    let me = sk.viewing_key().pk();
    let (asset, time) = (3u32, 1_700_000_000u32);
    let (tree, ins) = two_inputs(&sk, [1_000, 2_000], asset, time);
    let outs = [Note::new(key().viewing_key().pk(), me, 2_400, asset, time), Note::new(me, me, 0x1_0000_0001, asset, time)];
    let (fee, burn) = (0x2_0000_0003u64, 0x4_0000_0005u64);
    let v = notes::bundle_inputs(&sk, &ins, &outs, tree.root(), fee, burn, asset, time);
    assert_eq!(v.len(), COUNT);
    assert_eq!(&v[SK..SK + 8], &sk.0);
    assert_eq!(&v[IN1_FROM..IN1_FROM + 8], &ins[0].0.from);
    assert_eq!((v[IN1_AMOUNT_LO], v[IN1_AMOUNT_HI]), (1_000, 0));
    assert_eq!(v[IN1_INDEX], 0);
    assert_eq!(&v[IN1_R..IN1_R + 8], &ins[0].0.r);
    assert_eq!(&v[IN1_PATH..IN1_PATH + 8], &ins[0].1[0]);
    assert_eq!(&v[IN2_FROM..IN2_FROM + 8], &ins[1].0.from);
    assert_eq!((v[IN2_AMOUNT_LO], v[IN2_AMOUNT_HI]), (2_000, 0));
    assert_eq!(v[IN2_INDEX], 1);
    assert_eq!(&v[ANCHOR..ANCHOR + 8], &tree.root());
    assert_eq!(&v[OUT1_PK..OUT1_PK + 8], &outs[0].pk);
    assert_eq!((v[OUT1_AMOUNT_LO], v[OUT1_AMOUNT_HI]), (2_400, 0));
    assert_eq!(&v[OUT2_PK..OUT2_PK + 8], &outs[1].pk);
    assert_eq!((v[OUT2_AMOUNT_LO], v[OUT2_AMOUNT_HI]), (1, 1), "a 64-bit amount is split low/high");
    assert_eq!(&v[OUT2_R..OUT2_R + 8], &outs[1].r);
    assert_eq!((v[FEE_LO], v[FEE_HI]), (3, 2));
    assert_eq!((v[BURN_LO], v[BURN_HI]), (5, 4));
    assert_eq!((v[ASSET], v[TIME]), (asset, time));
}

#[test]
fn the_bundle_guest_publishes_expected_bundle_outputs_for_two_real_inputs() {
    let sk = key();
    let me = sk.viewing_key().pk();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, ins) = two_inputs(&sk, [1_000, 2_000], asset, time);
    let anchor = tree.root();
    // 1_000 + 2_000 == 2_400 + 500 + 100 + 0
    let outs = [Note::new(key().viewing_key().pk(), me, 2_400, asset, time), Note::new(me, me, 500, asset, time)];
    let v = notes::bundle_inputs(&sk, &ins, &outs, anchor, 100, 0, asset, time);
    let e = execute(&guests::bundle(), &v, &[], 1 << 22).unwrap();
    assert!(e.halted);
    let want = notes::expected_bundle_outputs(&sk, &ins, &outs, anchor, 100, 0, asset, time);
    assert_eq!(e.outputs, want);
    // the fee is part of the digest
    assert_ne!(want, notes::expected_bundle_outputs(&sk, &ins, &outs, anchor, 101, 0, asset, time));
}

#[test]
fn the_bundle_guest_skips_membership_for_a_zero_amount_dummy_input() {
    let sk = key();
    let me = sk.viewing_key().pk();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, real) = two_inputs(&sk, [1_000, 0], asset, time);
    let dummy = (Note::new([0; 8], [0; 8], 0, asset, time), [[0u32; 8]; DEPTH], 0u32);
    let ins = [real[0], dummy];
    let anchor = tree.root();
    let outs = [Note::new(me, me, 900, asset, time), Note::new([0; 8], me, 0, asset, time)];
    let v = notes::bundle_inputs(&sk, &ins, &outs, anchor, 100, 0, asset, time);
    let e = execute(&guests::bundle(), &v, &[], 1 << 22).unwrap();
    assert_eq!(e.outputs, notes::expected_bundle_outputs(&sk, &ins, &outs, anchor, 100, 0, asset, time));
}

#[test]
fn the_bundle_guest_digest_diverges_from_the_honest_one_when_outputs_exceed_inputs() {
    let sk = key();
    let me = sk.viewing_key().pk();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let (tree, ins) = two_inputs(&sk, [1_000, 2_000], asset, time);
    let anchor = tree.root();
    // 3_001 out of 3_000 in: the guest taints the digest instead of refusing to run
    let outs = [Note::new(key().viewing_key().pk(), me, 3_001, asset, time), Note::new([0; 8], me, 0, asset, time)];
    let v = notes::bundle_inputs(&sk, &ins, &outs, anchor, 0, 0, asset, time);
    let e = execute(&guests::bundle(), &v, &[], 1 << 22).unwrap();
    assert_ne!(e.outputs, notes::expected_bundle_outputs(&sk, &ins, &outs, anchor, 0, 0, asset, time));
}
