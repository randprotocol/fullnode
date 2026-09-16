//! The EVM contract storage tree (M4.3 Task 2): the host builder (`randprotocol_zkvm::evm`) and the
//! guest's witness verifier (`evm_core::storage`) must agree bit for bit on every leaf, index
//! and root, including across the shared-path updates independent witnesses get wrong.
//!
//! Also pins the `Host`-generic hashes Task 1 could not test (nothing could implement `Host`
//! until `HostRef` existed): `evm_core::keccak256` and `evm_core::dhash` are byte-identical to
//! `keccak::keccak256` and `notes::hash`.

use evm_core::storage::{self as gs, StorageTree};
use evm_core::u256::U256;
use randprotocol_zkvm::evm::{empty_root, leaf_hash, slot_index, HostRef, SparseTree, Witness};
use randprotocol_zkvm::notes::domain;

fn s(v: u32) -> U256 { U256::from_u32(v) }

#[test]
fn domain_tags_agree_between_the_note_layer_and_the_guest_crate() {
    assert_eq!(domain::STORAGE_LEAF, gs::STORAGE_LEAF_DOMAIN);
    assert_eq!(domain::NODE, gs::NODE_DOMAIN);
    assert_eq!(domain::EVM_OUT, gs::EVM_OUT_DOMAIN);
    assert_eq!(domain::STORAGE_LEAF, 12);
    assert_eq!(domain::EVM_OUT, 13);
}

/// Task 1 left `evm_core::keccak256`/`dhash` (generic over `Host`) untested, because nothing
/// could implement `Host` before `HostRef`. Both are transcriptions of research's own
/// reference functions, so the assertion is byte-identity — across the Keccak block boundary
/// in both directions (135/136/137) and on the empty message, which still needs a whole
/// all-padding block.
#[test]
fn the_guest_crates_keccak256_and_dhash_match_the_research_reference() {
    let mut h = HostRef;
    for len in [0usize, 1, 135, 136, 137, 272] {
        let msg: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect();
        assert_eq!(evm_core::keccak256(&mut h, &msg), randprotocol_zkvm::keccak::keccak256(&msg), "keccak256 of {len} bytes");
    }
    for n in [0usize, 1, 8, 16, 40] {
        let msg: Vec<u32> = (0..n as u32).map(|i| i.wrapping_mul(2_654_435_761)).collect();
        assert_eq!(evm_core::dhash(&mut h, domain::STORAGE_LEAF, &msg), randprotocol_zkvm::notes::hash(domain::STORAGE_LEAF, &msg), "dhash of {n} words");
    }
}

#[test]
fn host_and_guest_hash_the_same_leaves_indices_and_roots() {
    let mut h = HostRef;
    for (slot, value) in [(s(0), s(0)), (s(1), s(1000)), (U256::MAX, s(7))] {
        assert_eq!(slot_index(&slot), gs::slot_index(&mut h, &slot));
        assert_eq!(leaf_hash(&slot, &value), gs::leaf_hash(&mut h, &slot, &value));
    }
    // the index is the top 32 bits of keccak256(slot) big-endian
    let k = randprotocol_zkvm::keccak::keccak256(&s(1).to_be_bytes());
    assert_eq!(slot_index(&s(1)), u32::from_be_bytes([k[0], k[1], k[2], k[3]]));
    let t = SparseTree::new();
    assert_eq!(t.root(), empty_root());
    let guest = StorageTree::new(empty_root());
    assert_eq!(guest.root(), empty_root());
}

/// The leaf is canonical in the value: a slot never written, a slot absent from the tree and a
/// slot written back to zero all hash to the one `EMPTY_LEAF`, so the root is
/// history-independent and the empty tree's root is the default subtree of depth 32.
#[test]
fn a_zero_value_leaf_is_the_empty_leaf_whatever_the_slot_is() {
    let mut h = HostRef;
    let empty = leaf_hash(&s(0), &U256::ZERO);
    for slot in [s(0), s(1), s(99), U256::MAX] {
        assert_eq!(leaf_hash(&slot, &U256::ZERO), empty);
        assert_eq!(gs::leaf_hash(&mut h, &slot, &U256::ZERO), empty);
    }
    // and writing a slot then writing it back to zero returns the tree to its empty root
    let mut t = SparseTree::new();
    t.insert(s(3), s(77));
    assert_ne!(t.root(), empty_root());
    t.insert(s(3), U256::ZERO);
    assert_eq!(t.root(), empty_root());
}

#[test]
fn a_witness_verifies_and_a_tampered_one_does_not() {
    let mut t = SparseTree::new();
    t.insert(s(0), s(500));
    t.insert(s(2), s(1_000_000));
    let root = t.root();
    let mut h = HostRef;
    let mut g = StorageTree::new(root);
    g.push(&mut h, into_guest(t.witness(&s(0)))).unwrap();
    g.push(&mut h, into_guest(t.witness(&s(5)))).unwrap();               // absent slot: value 0, still a valid witness
    assert_eq!(g.load(&mut h, &s(0)).unwrap(), s(500));
    assert_eq!(g.load(&mut h, &s(5)).unwrap(), U256::ZERO);
    assert!(matches!(g.load(&mut h, &s(2)), Err(gs::StorageError::NoWitness)));  // touched without a witness
    let mut bad = into_guest(t.witness(&s(2)));
    bad.value = s(1);
    let mut g2 = StorageTree::new(root);
    g2.push(&mut h, bad).unwrap();
    assert!(matches!(g2.load(&mut h, &s(2)), Err(gs::StorageError::BadWitness)));
}

#[test]
fn stores_recompute_the_root_the_host_tree_agrees_with_including_across_shared_paths() {
    // Two slots whose paths share a prefix are the case independent witnesses get wrong.
    let mut t = SparseTree::new();
    let slots: Vec<U256> = (0..6).map(s).collect();
    for (i, sl) in slots.iter().enumerate() { t.insert(*sl, s(100 * (i as u32 + 1))); }
    let pre = t.root();
    let mut h = HostRef;
    let mut g = StorageTree::new(pre);
    for sl in &slots { g.push(&mut h, into_guest(t.witness(sl))).unwrap(); }
    // update every slot, in an order that revisits already-updated paths
    for (i, sl) in slots.iter().enumerate().rev() {
        let prev = g.store(&mut h, sl, s(7 + i as u32)).unwrap();
        assert_eq!(prev, s(100 * (i as u32 + 1)));
        t.insert(*sl, s(7 + i as u32));
        assert_eq!(g.root(), t.root(), "root after updating slot {i}");
    }
    // a second store of the same slot, and a store to zero (deletion) both agree too
    assert_eq!(g.store(&mut h, &slots[3], s(0)).unwrap(), s(10));
    t.insert(slots[3], s(0));
    assert_eq!(g.root(), t.root());
    // reading back what we wrote needs no re-verification and returns the new values
    for (i, sl) in slots.iter().enumerate() { assert_eq!(g.load(&mut h, sl).unwrap(), if i == 3 { s(0) } else { s(7 + i as u32) }); }
}

/// A witness pushed but never loaded before a neighbouring store still verifies afterwards:
/// the refresh must fix its stale sibling whether or not it had already been verified.
#[test]
fn a_never_verified_witness_still_verifies_after_another_slots_store() {
    let mut t = SparseTree::new();
    for i in 0..4u32 { t.insert(s(i), s(10 * (i + 1))); }
    let mut h = HostRef;
    let mut g = StorageTree::new(t.root());
    for i in 0..4u32 { g.push(&mut h, into_guest(t.witness(&s(i)))).unwrap(); }
    g.store(&mut h, &s(0), s(999)).unwrap();
    t.insert(s(0), s(999));
    assert_eq!(g.root(), t.root());
    for i in 1..4u32 { assert_eq!(g.load(&mut h, &s(i)).unwrap(), s(10 * (i + 1)), "slot {i} after the store"); }
}

/// A witness is folded down the path of **its own slot**: `push` derives the leaf position from
/// `w.slot` and nothing else can supply one, so a witness carrying another slot's siblings fails
/// rather than verifying at a stale or borrowed index. (`StorageTree`'s fields are private for
/// exactly this reason — with `witnesses`/`n` writable, a tree built by assignment would keep the
/// index cache's initial zero and fold every witness down the path of index 0.)
#[test]
fn a_witness_is_verified_at_its_own_slots_index() {
    let mut t = SparseTree::new();
    t.insert(s(1), s(11));
    t.insert(s(2), s(22));
    let mut h = HostRef;
    // slot 1 and slot 2 are at different leaf positions, so one's siblings are not the other's
    assert_ne!(slot_index(&s(1)), slot_index(&s(2)));
    let mut g = StorageTree::new(t.root());
    g.push(&mut h, into_guest(t.witness(&s(1)))).unwrap();
    assert_eq!(g.load(&mut h, &s(1)).unwrap(), s(11));
    assert!(g.witness(0).verified);
    // the same value and siblings, relabelled with slot 2: now folded down slot 2's path, so it
    // cannot reach the root
    let mut relabelled = into_guest(t.witness(&s(1)));
    relabelled.slot = s(2);
    let mut g2 = StorageTree::new(t.root());
    g2.push(&mut h, relabelled).unwrap();
    assert!(matches!(g2.load(&mut h, &s(2)), Err(gs::StorageError::BadWitness)));
    assert!(!g2.witness(0).verified);
}

#[test]
fn pushing_more_than_max_witnesses_is_rejected() {
    let mut t = SparseTree::new();
    for i in 0..(gs::MAX_WITNESSES as u32 + 1) { t.insert(s(i), s(i + 1)); }
    let mut h = HostRef;
    let mut g = StorageTree::new(t.root());
    for i in 0..gs::MAX_WITNESSES as u32 { g.push(&mut h, into_guest(t.witness(&s(i)))).unwrap(); }
    assert_eq!(g.len(), gs::MAX_WITNESSES);
    let extra = into_guest(t.witness(&s(gs::MAX_WITNESSES as u32)));
    assert!(matches!(g.push(&mut h, extra), Err(gs::StorageError::TooMany)));
}

/// Two witnesses at one leaf position must be refused where they enter, not tolerated.
///
/// The leaf is canonical in the value, so a *ground* pair of distinct slots at one 32-bit position
/// both verify while the position is empty (identical `H(STORAGE_LEAF, [0; 16])` leaves, identical
/// siblings). A call that then read both and wrote both would bind a `post_root` carrying only the
/// second store — `store`'s refresh loop never touches a witness whose index equals the updated
/// one, and the second store folds its *original* siblings — while the interpreter ran on for the
/// rest of the call believing both writes happened. That is a divergence between the bound root and
/// the executed call, not the fail-closed griefing the docs claim, so `push` refuses the second
/// witness. 2^32 grinding is out of reach for a test; the same slot twice is the same defect
/// through the same `indices` check.
#[test]
fn two_witnesses_at_one_leaf_position_are_refused_at_push() {
    let mut t = SparseTree::new();
    t.insert(s(1), s(11));
    t.insert(s(2), s(22));
    let mut h = HostRef;
    let mut g = StorageTree::new(t.root());
    g.push(&mut h, into_guest(t.witness(&s(1)))).unwrap();
    // a second witness for the same slot: same index, refused, and nothing was taken
    let dup = into_guest(t.witness(&s(1)));
    assert!(matches!(g.push(&mut h, dup), Err(gs::StorageError::DuplicateIndex)));
    assert_eq!(g.len(), 1);
    // a different position still goes in, so the check is on the index and not on the count
    g.push(&mut h, into_guest(t.witness(&s(2)))).unwrap();
    assert_eq!(g.len(), 2);
    assert_eq!(g.load(&mut h, &s(1)).unwrap(), s(11));
    assert_eq!(g.load(&mut h, &s(2)).unwrap(), s(22));
}

/// The host mirror: `EvmCall::input_words` will not encode a vector the guest is bound to reject,
/// so a fixture cannot build the divergent call silently and have it look like a real one. (The
/// matching assert in `SparseTree::witness` — a leaf position held by a *different* slot — has no
/// test, because `insert`'s own assert makes that state unreachable through the type; it is there so
/// the property stays checked rather than argued.)
#[test]
#[should_panic(expected = "two touched slots share one leaf position")]
fn the_host_refuses_to_build_a_vector_with_two_witnesses_at_one_position() {
    let mut tree = SparseTree::new();
    tree.insert(s(1), s(11));
    let call = randprotocol_zkvm::evm::EvmCall {
        code: vec![0x00],
        calldata: vec![],
        address: U256::ZERO,
        caller: U256::ZERO,
        callvalue: U256::ZERO,
        gas_limit: 1_000,
        tree,
        touched: vec![s(1), s(1)],
    };
    let _ = call.input_words();
}

/// The guest's Merkle fold must be the note tree's, not just self-consistent with the host
/// builder: bit `i` of the index (LSB first) chooses left (0) or right (1) at level `i`, and the
/// node hash is `H(NODE, left, right)` — the convention `asm::emit_merkle_verify` implements
/// in-circuit and `ledger::CommitmentTree` builds its paths for. Folding a *commitment* tree's
/// own sibling path with `evm_core::storage::node_hash` therefore has to reproduce that tree's
/// root. (Host and guest sharing a wrong convention would be invisible to every other test here.)
#[test]
fn the_guest_fold_is_the_note_trees_index_convention() {
    let mut h = HostRef;
    let mut tree = randprotocol_zkvm::ledger::CommitmentTree::new();
    let leaves: Vec<[u32; 8]> = (0..5u32).map(|i| randprotocol_zkvm::notes::hash(domain::TEST, &[i])).collect();
    for cm in &leaves { tree.append(*cm); }
    for (index, cm) in leaves.iter().enumerate() {
        let path = tree.path(index);
        let mut cur = *cm;
        for (l, sib) in path.iter().enumerate() {
            cur = if (index >> l) & 1 == 0 { gs::node_hash(&mut h, &cur, sib) } else { gs::node_hash(&mut h, sib, &cur) };
        }
        assert_eq!(cur, tree.root(), "folding the commitment path of leaf {index}");
    }
}

#[test]
fn witness_words_are_272_and_round_trip() {
    let mut t = SparseTree::new();
    t.insert(s(9), s(9));
    let w = t.witness(&s(9));
    let words = w.words();
    assert_eq!(words.len(), 272);
    assert_eq!(&words[..8], &w.slot.0);
    assert_eq!(&words[8..16], &w.value.0);
    assert_eq!(&words[16..24], &w.siblings[0]);
    assert_eq!(&words[264..], &w.siblings[31]);
}

fn into_guest(w: Witness) -> gs::Witness { gs::Witness { slot: w.slot, value: w.value, siblings: w.siblings, verified: false } }
