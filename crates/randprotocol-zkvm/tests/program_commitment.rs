//! `program_commitment`: the salted program commitment and the admitted-programs tree, as host
//! arithmetic (monorepo issue 61, ZKVM-108). Nothing here is enforced by a proof — the current
//! constraint set publishes `hc` unsalted; `tests/next_constraint_set.rs::
//! two_proofs_of_one_program_publish_different_program_commitments` pins that gap. These tests
//! fix the definitions the next set's rows would prove.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_zkvm::guests;
use randprotocol_zkvm::hash::{permute_state, split_digest, sponge_hash, sponge_hash_len};
use randprotocol_zkvm::machine::Val;
use randprotocol_zkvm::notes;
use randprotocol_zkvm::program_commitment::*;

fn programs(n: u32) -> Vec<[u32; 8]> {
    (0..n).map(|i| guests::fib(i + 1).digest()).collect()
}

// ─────────────────────────── the salted commitment ───────────────────────────

#[test]
fn the_salted_commitment_is_the_documented_sponge() {
    let hc = guests::fib(10).digest();
    let salt = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
    let lanes = hc_lanes(&hc).unwrap();
    let mut s = [Val::ZERO; 8];
    s[4] = Val::from_u32(domain::HCC);
    s[7] = Val::ONE;
    for k in 0..4 {
        s[k] = Val::from_u32(salt[k]);
    }
    s = permute_state(s);
    s[..4].copy_from_slice(&lanes);
    s = permute_state(s);
    assert_eq!(salted(&hc, salt).unwrap(), split_digest([s[0], s[1], s[2], s[3]]));
}

/// The acceptance property, at the level of the function: two commitments to one program under
/// different salts differ, each opens with its own salt, and neither opens with the other's or
/// for another program.
#[test]
fn two_commitments_to_one_program_differ_and_both_open() {
    let hc = guests::fib(10).digest();
    let other = guests::fib(11).digest();
    let (s1, s2) = ([1, 2, 3, 4], [1, 2, 3, 5]);
    let (c1, c2) = (salted(&hc, s1).unwrap(), salted(&hc, s2).unwrap());
    assert_ne!(c1, c2);
    assert_ne!(c1, hc);
    assert!(opens(&c1, &hc, s1) && opens(&c2, &hc, s2));
    assert!(!opens(&c1, &hc, s2) && !opens(&c2, &hc, s1));
    assert!(!opens(&c1, &other, s1));
    // Every salt word matters.
    for k in 0..4 {
        let mut s = s1;
        s[k] ^= 1 << 31;
        assert_ne!(salted(&hc, s).unwrap(), c1, "salt word {k}");
    }
}

/// An observer who knows every candidate program but not the salt cannot test candidates the
/// way they can against today's `hc`: hashing a candidate without the salt, or with a guessed
/// one, gives something else. (That the commitment is *hiding* is the sponge's preimage
/// resistance over a 128-bit salt — an assumption, not something a test shows.)
#[test]
fn enumerating_candidates_without_the_salt_does_not_find_the_program() {
    let all = programs(64);
    let c = salted(&all[37], [0xdead_beef, 0x0bad_f00d, 0x1234_5678, 0x9abc_def0]).unwrap();
    for hc in &all {
        assert_ne!(*hc, c);
        assert_ne!(salted(hc, [0; 4]).unwrap(), c);
    }
}

#[test]
fn a_non_canonical_digest_has_no_lanes() {
    let hc = guests::fib(10).digest();
    assert_eq!(split_digest(hc_lanes(&hc).unwrap()), hc, "lanes round-trip");
    // p = 2^64 - 2^32 + 1: lo = 1, hi = 0xffff_ffff is p itself.
    let mut bad = hc;
    (bad[0], bad[1]) = (1, 0xffff_ffff);
    assert!(hc_lanes(&bad).is_none() && salted(&bad, [0; 4]).is_none() && !opens(&hc, &bad, [0; 4]));
    // p - 1 is the largest canonical lane.
    (bad[0], bad[1]) = (0, 0xffff_ffff);
    assert_eq!(hc_lanes(&bad).unwrap()[0].as_canonical_u64(), Val::ORDER_U64 - 1);
}

// ─────────────────────────── domains ───────────────────────────

#[test]
fn the_two_tags_are_new_and_distinct() {
    let note_layer = [
        notes::domain::NK, notes::domain::PK, notes::domain::NF, notes::domain::CM, notes::domain::OVK, notes::domain::KEM_SEED, notes::domain::NODE,
        notes::domain::HC, notes::domain::OUT, notes::domain::IN, notes::domain::BUNDLE, notes::domain::STORAGE_LEAF, notes::domain::EVM_OUT,
        notes::domain::SBPF_OUT, notes::domain::PUB, notes::domain::KEM_SEED_VERSION, notes::domain::TEST,
    ];
    assert_ne!(domain::HCC, domain::ADMIT_NODE);
    assert!(!note_layer.contains(&domain::HCC) && !note_layer.contains(&domain::ADMIT_NODE));
}

/// The same eight inputs under the two tags give different digests, and neither is a hash a
/// guest's `POSEIDON2` / `POSEIDON2_LEN` call over the same words computes (those start from a
/// state whose capacity lane 7 is zero).
#[test]
fn a_commitment_is_not_a_node_and_neither_is_a_guest_hash() {
    let a = [1u32, 2, 3, 4];
    let b = [5u32, 6, 7, 8];
    let (al, bl) = (a.map(Val::from_u32), b.map(Val::from_u32));
    let commitment = salted_lanes(bl, a);
    let tree_node = node(al, bl);
    assert_ne!(commitment, tree_node);
    let msg: Vec<u32> = a.iter().chain(b.iter()).copied().collect();
    for guest in [sponge_hash(&msg), sponge_hash_len(&msg)] {
        assert_ne!(split_digest(commitment), guest);
        assert_ne!(split_digest(tree_node), guest);
    }
    // And the order of a node's children matters.
    assert_ne!(node(al, bl), node(bl, al));
}

// ─────────────────────────── the admitted-programs tree ───────────────────────────

#[test]
fn every_admitted_program_has_a_path_to_the_root() {
    for (depth, n) in [(1usize, 1u32), (1, 2), (3, 5), (4, 16), (6, 37)] {
        let all = programs(n);
        let set = AdmittedSet::new(depth, &all).unwrap();
        assert_eq!((set.depth(), set.len()), (depth, n as usize));
        let root = set.root();
        assert_eq!(split_digest(root), set.root_words());
        for (i, hc) in all.iter().enumerate() {
            let path = set.path(i).unwrap();
            assert_eq!(path.siblings.len(), depth);
            assert_eq!(set.path_of(hc).unwrap(), path);
            assert!(is_admitted(&root, depth, hc, &path), "depth {depth}, n {n}, leaf {i}");
        }
        assert!(set.path(n as usize).is_none());
    }
}

/// The tree against a plain recursive definition, built without `AdmittedSet`.
#[test]
fn the_root_is_the_recursive_definition() {
    fn root(leaves: &[[Val; 4]], depth: usize) -> [Val; 4] {
        if depth == 0 {
            return leaves.first().copied().unwrap_or([Val::ZERO; 4]);
        }
        let half = 1usize << (depth - 1);
        let (l, r) = if leaves.len() > half { leaves.split_at(half) } else { (leaves, &[][..]) };
        node(root(l, depth - 1), root(r, depth - 1))
    }
    for n in [0u32, 1, 2, 3, 7, 8, 13] {
        let all = programs(n);
        let leaves: Vec<[Val; 4]> = all.iter().map(|h| hc_lanes(h).unwrap()).collect();
        assert_eq!(AdmittedSet::new(4, &all).unwrap().root(), root(&leaves, 4), "{n} programs");
    }
}

/// The second acceptance property, at the level of the function: a program that is not in the
/// set has no path — not its neighbour's, not an empty leaf's, not a forged one.
#[test]
fn a_program_that_is_not_admitted_is_refused() {
    let all = programs(11);
    let depth = 5;
    let set = AdmittedSet::new(depth, &all).unwrap();
    let root = set.root();
    let outsider = guests::fib(1000).digest();
    assert!(set.path_of(&outsider).is_none());
    // With each admitted program's path.
    for i in 0..all.len() {
        assert!(!is_admitted(&root, depth, &outsider, &set.path(i).unwrap()));
    }
    // At an empty leaf's position, with the siblings an honest tree has there.
    let grown = AdmittedSet::new(depth, &[all.clone(), vec![outsider]].concat()).unwrap();
    let path = grown.path(11).unwrap();
    assert!(is_admitted(&grown.root(), depth, &outsider, &path), "it is in the grown set");
    assert!(!is_admitted(&root, depth, &outsider, &path), "and not in the original");
}

#[test]
fn a_tampered_path_is_refused() {
    let all = programs(9);
    let depth = 4;
    let set = AdmittedSet::new(depth, &all).unwrap();
    let root = set.root();
    let hc = all[6];
    let path = set.path(6).unwrap();
    assert!(is_admitted(&root, depth, &hc, &path));
    // Another index.
    for index in (0..16).filter(|i| *i != 6) {
        assert!(!is_admitted(&root, depth, &hc, &AdmissionPath { index, ..path.clone() }), "index {index}");
    }
    // An index that does not fit the depth.
    assert!(!is_admitted(&root, depth, &hc, &AdmissionPath { index: 6 + 16, ..path.clone() }));
    // Any sibling lane changed.
    for level in 0..depth {
        for lane in 0..4 {
            let mut p = path.clone();
            p.siblings[level][lane] += Val::ONE;
            assert!(!is_admitted(&root, depth, &hc, &p), "level {level}, lane {lane}");
        }
    }
    // Another root.
    let mut r = root;
    r[0] += Val::ONE;
    assert!(!is_admitted(&r, depth, &hc, &path));
}

/// The verifier fixes the depth. A shorter path that reaches the root from an *inner node*
/// (passing the node off as a program digest) is refused, as is a longer one.
#[test]
fn a_path_of_the_wrong_depth_is_refused() {
    let all = programs(8);
    let depth = 3;
    let set = AdmittedSet::new(depth, &all).unwrap();
    let root = set.root();
    let path = set.path(2).unwrap();
    // The node above leaves 2 and 3, as if it were a digest, with the remaining two siblings.
    let inner = node(hc_lanes(&all[2]).unwrap(), hc_lanes(&all[3]).unwrap());
    let short = AdmissionPath { index: 1, siblings: path.siblings[1..].to_vec() };
    assert_eq!(root_from_path(inner, &short), Some(root), "the arithmetic does reach the root");
    assert!(!is_admitted(&root, depth, &split_digest(inner), &short), "but the depth check refuses it");
    let mut long = path.clone();
    long.siblings.push([Val::ZERO; 4]);
    assert!(!is_admitted(&root, depth, &all[2], &long));
}

#[test]
fn a_set_refuses_what_it_cannot_hold() {
    let all = programs(5);
    assert!(AdmittedSet::new(0, &all[..1]).is_none(), "depth 0");
    assert!(AdmittedSet::new(MAX_DEPTH + 1, &all).is_none(), "too deep");
    assert!(AdmittedSet::new(2, &all).is_none(), "five programs, four leaves");
    assert!(AdmittedSet::new(3, &[all[0], all[1], all[0]]).is_none(), "a repeat");
    let mut bad = all[0];
    (bad[0], bad[1]) = (1, 0xffff_ffff);
    assert!(AdmittedSet::new(3, &[bad]).is_none(), "a non-canonical digest");
    let empty = AdmittedSet::new(3, &[]).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.root(), node(node(node([Val::ZERO; 4], [Val::ZERO; 4]), node([Val::ZERO; 4], [Val::ZERO; 4])), node(node([Val::ZERO; 4], [Val::ZERO; 4]), node([Val::ZERO; 4], [Val::ZERO; 4]))));
}

#[test]
fn the_cost_is_two_permutations_and_two_per_level() {
    assert_eq!(permutations(0), 2);
    assert_eq!(permutations(16), 34);
    assert_eq!(permutations(20), 42);
}
