//! The note layer's properties, all host-side and proof-free: a note's wire layout and the
//! binding of its commitment to every field, nullifier uniqueness and key separation, envelope
//! tamper detection part by part, the commitment tree's paths against a hand-folded root, the
//! ledger's mint rules and anchor window, and a mint-only ledger's disclosure rows under every
//! `verify_row` refusal.
use randprotocol_zkvm::ledger::{CommitmentTree, Ledger, LedgerError};
use randprotocol_zkvm::notes::{self, domain, Note, SpendKey, ViewingKey, Word8, DEPTH};
use randprotocol_zkvm::viewing::{memo_field, scan, verify_row, Disclosure, Envelope, Role, RowError, RowSource, TxKey};

struct Party { vk: ViewingKey }
impl Party {
    fn new() -> Party { Party { vk: SpendKey::random().viewing_key() } }
}

fn w8(seed: u32) -> Word8 { notes::hash(domain::TEST, &[seed]) }

// ─────────────────────────── Note ───────────────────────────

#[test]
fn a_note_round_trips_through_words_and_bytes_with_the_documented_layout() {
    let n = Note { pk: w8(1), from: w8(2), amount: 0x1234_5678_9abc_def0, asset: 7, time: 9, r: w8(3) };
    let words = n.words();
    assert_eq!(&words[0..8], &n.pk);
    assert_eq!(&words[8..16], &n.from);
    assert_eq!((words[16], words[17]), (0x9abc_def0, 0x1234_5678), "amount is lo then hi");
    assert_eq!((words[18], words[19]), (7, 9));
    assert_eq!(&words[20..28], &n.r);
    assert_eq!(Note::from_words(words), n);
    assert_eq!(Note::WORDS, 28);
    assert_eq!(Note::BYTES, 112);
    let bytes = n.to_bytes();
    assert_eq!(bytes.len(), Note::BYTES);
    assert_eq!(&bytes[64..68], &0x9abc_def0u32.to_le_bytes());
    assert_eq!(Note::from_bytes(&bytes), Some(n));
    for len in [0usize, Note::BYTES - 1, Note::BYTES + 1, 2 * Note::BYTES] {
        assert_eq!(Note::from_bytes(&vec![0u8; len]), None, "{len} bytes");
    }
    let max = Note { amount: u64::MAX, ..n };
    assert_eq!((max.words()[16], max.words()[17]), (u32::MAX, u32::MAX));
    assert_eq!(Note::from_words(max.words()).amount, u64::MAX);
}

#[test]
fn the_commitment_is_bound_to_every_field_of_the_note() {
    let n = Note { pk: w8(1), from: w8(2), amount: 5, asset: 0, time: 1, r: w8(3) };
    let cm = n.commitment();
    assert_eq!(cm, notes::hash(domain::CM, &n.words()));
    let variants = [
        ("pk", Note { pk: w8(11), ..n }),
        ("from", Note { from: w8(12), ..n }),
        ("amount lo", Note { amount: 6, ..n }),
        ("amount hi", Note { amount: 5 | 1 << 32, ..n }),
        ("asset", Note { asset: 1, ..n }),
        ("time", Note { time: 2, ..n }),
        ("r", Note { r: w8(13), ..n }),
        ("pk/from swapped", Note { pk: n.from, from: n.pk, ..n }),
    ];
    for (what, v) in variants {
        assert_ne!(v.commitment(), cm, "{what}");
    }
}

#[test]
fn fresh_notes_with_the_same_fields_have_different_randomness_and_commitments() {
    let (a, b) = (Note::new(w8(1), w8(2), 5, 0, 1), Note::new(w8(1), w8(2), 5, 0, 1));
    assert_ne!(a.r, b.r);
    assert_ne!(a.commitment(), b.commitment());
    assert_eq!((a.pk, a.from, a.amount, a.asset, a.time), (b.pk, b.from, b.amount, b.asset, b.time));
}

// ─────────────────────────── keys and nullifiers ───────────────────────────

#[test]
fn nullifiers_are_unique_across_many_notes_of_one_owner_and_across_owners() {
    let alice = Party::new();
    let bob = Party::new();
    let mut seen = std::collections::HashSet::new();
    for i in 0..64u64 {
        let note = Note::new(alice.vk.pk(), alice.vk.pk(), i % 3, 0, (i / 3) as u32);
        let cm = note.commitment();
        let nf = alice.vk.nullifier(&cm);
        assert!(seen.insert(nf), "nullifier {i} repeats");
        assert_ne!(nf, cm, "a nullifier is not the commitment");
        assert_ne!(nf, bob.vk.nullifier(&cm), "another key gives another nullifier for the same note");
        assert_eq!(nf, notes::hash(domain::NF, &[&alice.vk.nk[..], &cm[..]].concat()));
    }
}

#[test]
fn the_key_hierarchy_is_deterministic_and_one_way_separated() {
    let sk = SpendKey([9, 8, 7, 6, 5, 4, 3, 2]);
    let vk = sk.viewing_key();
    assert_eq!(vk, sk.viewing_key());
    assert_eq!(vk.nk, notes::hash(domain::NK, &sk.0));
    assert_eq!(vk.pk(), notes::hash(domain::PK, &vk.nk));
    assert_ne!(vk.nk, vk.pk());
    assert_ne!(vk.nk, sk.0);
    // Two keys that differ in any single word derive different hierarchies all the way down.
    for i in 0..8 {
        let mut other = sk;
        other.0[i] ^= 0x8000_0000;
        let ovk = other.viewing_key();
        assert_ne!(ovk.nk, vk.nk, "word {i}");
        assert_ne!(ovk.pk(), vk.pk(), "word {i}");
        assert_ne!(ovk.ovk(), vk.ovk(), "word {i}");
        assert_ne!(ovk.address().kem_ek, vk.address().kem_ek, "word {i}");
    }
    assert_eq!(vk.address(), vk.address(), "the address is a pure function of the viewing key");
}

// ─────────────────────────── envelopes ───────────────────────────

fn sealed() -> (Party, Party, Note, TxKey, Envelope) {
    let alice = Party::new();
    let bob = Party::new();
    let note = Note::new(bob.vk.pk(), alice.vk.pk(), 5, 1, 10);
    let key = TxKey::random();
    let env = Envelope::seal(&alice.vk, &bob.vk.address(), &note, &key);
    (alice, bob, note, key, env)
}

#[test]
fn an_envelope_has_the_fixed_wire_size() {
    let (_, _, _, _, env) = sealed();
    assert_eq!(env.kem_ct.len(), 1088, "ML-KEM-768 ciphertext");
    assert_eq!(env.to_receiver.len(), 12 + 32 + 16, "nonce, key, tag");
    assert_eq!(env.to_sender.len(), 12 + 32 + 16);
    assert_eq!(env.body.len(), 12 + Note::BYTES + 16);
    assert_eq!(env.kem_ct.len() + env.to_receiver.len() + env.to_sender.len() + env.body.len(), 1348);
}

#[test]
fn flipping_any_byte_of_the_body_closes_it_to_every_key() {
    let (alice, bob, note, key, env) = sealed();
    let cm = note.commitment();
    for i in [0usize, 11, 12, 60, env.body.len() - 1] {
        let mut t = env.clone();
        t.body[i] ^= 1;
        assert_eq!(t.open_with_tx_key(cm, &key), None, "body byte {i}");
        assert_eq!(t.open_as_receiver(cm, &bob.vk), None, "body byte {i}");
        assert_eq!(t.open_as_sender(cm, &alice.vk), None, "body byte {i}");
    }
    let mut short = env.clone();
    short.body.truncate(11);
    assert_eq!(short.open_with_tx_key(cm, &key), None);
    short.body.clear();
    assert_eq!(short.open_with_tx_key(cm, &key), None);
}

#[test]
fn tampering_one_wrap_closes_only_that_party_s_path() {
    let (alice, bob, note, key, env) = sealed();
    let cm = note.commitment();
    let mut r = env.clone();
    r.to_receiver[20] ^= 1;
    assert_eq!(r.open_as_receiver(cm, &bob.vk), None, "the receiver wrap is broken");
    assert_eq!(r.open_as_sender(cm, &alice.vk), Some((key, note)), "the sender wrap is untouched");
    assert_eq!(r.open_with_tx_key(cm, &key), Some(note));
    let mut s = env.clone();
    s.to_sender[20] ^= 1;
    assert_eq!(s.open_as_sender(cm, &alice.vk), None);
    assert_eq!(s.open_as_receiver(cm, &bob.vk), Some((key, note)));
    let mut k = env.clone();
    k.kem_ct[100] ^= 1;
    assert_eq!(k.open_as_receiver(cm, &bob.vk), None, "a tampered KEM ciphertext decapsulates to another secret");
    assert_eq!(k.open_as_sender(cm, &alice.vk), Some((key, note)));
    let mut kt = env.clone();
    kt.kem_ct.truncate(1087);
    assert_eq!(kt.open_as_receiver(cm, &bob.vk), None, "a short KEM ciphertext is refused, not a panic");
}

#[test]
fn parts_of_two_envelopes_cannot_be_recombined() {
    let (alice, bob, note1, _key1, env1) = sealed();
    let note2 = Note::new(bob.vk.pk(), alice.vk.pk(), 6, 1, 10);
    let key2 = TxKey::random();
    let env2 = Envelope::seal(&alice.vk, &bob.vk.address(), &note2, &key2);
    let (cm1, cm2) = (note1.commitment(), note2.commitment());
    // The body of one under the other's commitment: the AAD binds it.
    let mut swapped = env1.clone();
    swapped.body = env2.body.clone();
    assert_eq!(swapped.open_with_tx_key(cm1, &key2), None, "body of 2 under cm 1");
    assert_eq!(swapped.open_with_tx_key(cm2, &key2), Some(note2), "the same body under its own cm still opens");
    assert_eq!(swapped.open_as_receiver(cm1, &bob.vk), None, "the key wrap opens but the body does not");
    // And a key wrap of one with the body of the other, under either commitment.
    let mut wraps = env2.clone();
    wraps.to_sender = env1.to_sender.clone();
    assert_eq!(wraps.open_as_sender(cm2, &alice.vk), None);
    assert_eq!(wraps.open_as_sender(cm1, &alice.vk), None);
}

#[test]
fn a_memo_is_authenticated_with_the_note() {
    let (_, bob, note, key, _) = sealed();
    let alice = Party::new();
    let note = Note { from: alice.vk.pk(), ..note };
    let env = Envelope::seal_with_memo(&alice.vk, &bob.vk.address(), &note, &key, &memo_field("hi").unwrap());
    let cm = note.commitment();
    assert_eq!(env.memo(cm, &key).as_deref(), Some("hi"));
    let mut t = env.clone();
    t.body[12 + Note::BYTES + 3] ^= 1; // a memo byte
    assert_eq!(t.memo(cm, &key), None);
    assert_eq!(t.open_with_tx_key(cm, &key), None, "the note goes with it: one AEAD over both");
    assert_eq!(env.memo(cm, &TxKey::random()), None);
    let other = Note { time: 11, ..note }.commitment();
    assert_eq!(env.memo(other, &key), None);
}

// ─────────────────────────── the commitment tree ───────────────────────────

fn fold(leaf: Word8, path: &[Word8; DEPTH], index: u32) -> Word8 {
    let mut node = leaf;
    for (level, sib) in path.iter().enumerate() {
        let (l, r) = if (index >> level) & 1 == 0 { (node, *sib) } else { (*sib, node) };
        node = notes::hash(domain::NODE, &[&l[..], &r[..]].concat());
    }
    node
}

#[test]
fn the_empty_tree_root_is_the_depth_32_chain_of_empty_nodes() {
    let tree = CommitmentTree::new();
    let mut empty = [0u32; 8];
    for _ in 0..DEPTH { empty = notes::hash(domain::NODE, &[&empty[..], &empty[..]].concat()); }
    assert_eq!(tree.root(), empty);
    assert_eq!(tree.path_for(&[0; 8]), None, "the zero leaf is not a commitment");
    // A single leaf: its path is the empty chain, and folding reproduces the root.
    let mut one = CommitmentTree::new();
    assert_eq!(one.append(w8(1)), 0);
    let (path, idx) = one.path_for(&w8(1)).unwrap();
    assert_eq!(idx, 0);
    assert_eq!(path[0], [0; 8]);
    assert_eq!(fold(w8(1), &path, 0), one.root());
    assert_ne!(one.root(), tree.root());
}

#[test]
fn every_leaf_s_path_folds_to_the_current_root_and_roots_never_repeat() {
    let mut tree = CommitmentTree::new();
    let mut roots = vec![tree.root()];
    let leaves: Vec<Word8> = (0..21).map(w8).collect();
    for (i, cm) in leaves.iter().enumerate() {
        assert_eq!(tree.append(*cm), i);
        let root = tree.root();
        assert!(!roots.contains(&root), "root after {} leaves repeats", i + 1);
        roots.push(root);
        for (j, earlier) in leaves[..=i].iter().enumerate() {
            let (path, idx) = tree.path_for(earlier).unwrap();
            assert_eq!(idx as usize, j);
            assert_eq!(fold(*earlier, &path, idx), root, "leaf {j} after {} leaves", i + 1);
            assert_eq!(tree.path(j), path);
        }
    }
    // A path is specific to its leaf and index: the wrong index does not fold to the root.
    let (path, _) = tree.path_for(&leaves[5]).unwrap();
    assert_ne!(fold(leaves[5], &path, 4), tree.root());
    assert_ne!(fold(leaves[6], &path, 5), tree.root());
}

// ─────────────────────────── the ledger without proofs ───────────────────────────

fn envelope_for(minter: &Party, to: &Party, note: &Note) -> Envelope {
    Envelope::seal(&minter.vk, &to.vk.address(), note, &TxKey::random())
}

#[test]
fn mint_enforces_the_amount_range_the_clock_and_uniqueness() {
    let mut ledger = Ledger::new(100);
    let (bridge, bob) = (Party::new(), Party::new());
    let too_big = Note::new(bob.vk.pk(), bridge.vk.pk(), 1 << 63, 0, 100);
    assert!(matches!(ledger.mint(&too_big, envelope_for(&bridge, &bob, &too_big)), Err(LedgerError::AmountOutOfRange(a)) if a == 1 << 63));
    let max = Note::new(bob.vk.pk(), bridge.vk.pk(), (1 << 63) - 1, 0, 100);
    assert_eq!(ledger.mint(&max, envelope_for(&bridge, &bob, &max)).unwrap(), 0);
    let late = Note::new(bob.vk.pk(), bridge.vk.pk(), 1, 0, 99);
    assert!(matches!(ledger.mint(&late, envelope_for(&bridge, &bob, &late)), Err(LedgerError::Time { claimed: 99, now: 100 })));
    let early = Note::new(bob.vk.pk(), bridge.vk.pk(), 1, 0, 101);
    assert!(matches!(ledger.mint(&early, envelope_for(&bridge, &bob, &early)), Err(LedgerError::Time { claimed: 101, now: 100 })));
    // The same note twice is a duplicate commitment; the tree is unchanged by the refusal.
    let root = ledger.root();
    assert!(matches!(ledger.mint(&max, envelope_for(&bridge, &bob, &max)), Err(LedgerError::Duplicate(cm)) if cm == max.commitment()));
    assert_eq!(ledger.root(), root);
    assert!(ledger.has_commitment(&max.commitment()));
    assert!(!ledger.has_nullifier(&bob.vk.nullifier(&max.commitment())), "a mint spends nothing");
    assert_eq!(ledger.txs.len(), 1);
    assert_eq!((ledger.txs[0].anchor, ledger.txs[0].nf, ledger.txs[0].cm_out), (None, None, max.commitment()));
    // The clock moves only by `advance`.
    ledger.advance(5);
    let now = Note::new(bob.vk.pk(), bridge.vk.pk(), 1, 0, 105);
    assert_eq!(ledger.mint(&now, envelope_for(&bridge, &bob, &now)).unwrap(), 1);
}

#[test]
fn a_mint_only_ledger_discloses_one_received_and_one_sent_row_that_verify() {
    let mut ledger = Ledger::new(7);
    let (alice, bob, carol) = (Party::new(), Party::new(), Party::new());
    let note = Note::new(bob.vk.pk(), alice.vk.pk(), 42, 3, 7);
    let key = TxKey::random();
    ledger.mint(&note, Envelope::seal(&alice.vk, &bob.vk.address(), &note, &key)).unwrap();
    let cm = note.commitment();

    let bob_d = Disclosure::Party(bob.vk);
    let rows = scan(&ledger, &bob_d);
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!((r.tx, r.source, r.slot, r.role), (0, RowSource::Transfer, 0, Role::Received));
    assert_eq!((r.sender, r.receiver, r.amount, r.asset, r.time), (alice.vk.pk(), bob.vk.pk(), 42, 3, 7));
    assert_eq!((r.cm_out, r.nf, r.note, r.spent), (cm, None, note, None));
    assert_eq!(verify_row(&ledger, &bob_d, r), Ok(()));

    let alice_d = Disclosure::Party(alice.vk);
    let sent = scan(&ledger, &alice_d);
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].role, sent[0].spent), (Role::Sent, None), "a mint has no spent note");
    assert_eq!(verify_row(&ledger, &alice_d, &sent[0]), Ok(()));

    let tx_d = Disclosure::Transaction { tx: 0, key };
    let one = scan(&ledger, &tx_d);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].role, Role::Transaction);
    assert_eq!(verify_row(&ledger, &tx_d, &one[0]), Ok(()));

    assert!(scan(&ledger, &Disclosure::Party(carol.vk)).is_empty(), "a third party sees nothing");
    assert!(scan(&ledger, &Disclosure::Transaction { tx: 0, key: TxKey::random() }).is_empty());
    assert!(scan(&ledger, &Disclosure::Transaction { tx: 1, key }).is_empty(), "no such transaction");
}

#[test]
fn verify_row_names_each_way_a_row_can_lie() {
    let mut ledger = Ledger::new(7);
    let (alice, bob) = (Party::new(), Party::new());
    let note = Note::new(bob.vk.pk(), alice.vk.pk(), 42, 3, 7);
    let key = TxKey::random();
    ledger.mint(&note, Envelope::seal(&alice.vk, &bob.vk.address(), &note, &key)).unwrap();
    let d = Disclosure::Party(bob.vk);
    let honest = scan(&ledger, &d).remove(0);
    let check = |edit: &dyn Fn(&mut randprotocol_zkvm::viewing::Row)| {
        let mut r = honest.clone();
        edit(&mut r);
        verify_row(&ledger, &d, &r)
    };
    assert_eq!(check(&|r| r.tx = 1), Err(RowError::UnknownTx));
    assert_eq!(check(&|r| r.slot = 1), Err(RowError::Slot));
    assert_eq!(check(&|r| r.cm_out[0] ^= 1), Err(RowError::Commitment));
    assert_eq!(check(&|r| r.note.amount = 43), Err(RowError::Commitment), "the note no longer opens the commitment");
    assert_eq!(check(&|r| r.amount = 43), Err(RowError::Fields));
    assert_eq!(check(&|r| r.sender = [0; 8]), Err(RowError::Fields));
    assert_eq!(check(&|r| r.time = 8), Err(RowError::Fields), "the note's own time is checked first");
    assert_eq!(check(&|r| r.nf = Some([1; 8])), Err(RowError::Nullifier));
    assert_eq!(check(&|r| r.role = Role::Transaction), Err(RowError::Scope));
    assert_eq!(check(&|r| r.role = Role::Sent), Err(RowError::Party), "bob did not create this note");
    assert_eq!(check(&|r| r.source = RowSource::Bundle), Err(RowError::UnknownTx), "there is no bundle 0");
    // Under a transaction disclosure the row must point at that transaction.
    let tx_d = Disclosure::Transaction { tx: 0, key };
    let mut r = honest.clone();
    r.role = Role::Transaction;
    assert_eq!(verify_row(&ledger, &tx_d, &r), Ok(()));
    assert_eq!(verify_row(&ledger, &Disclosure::Transaction { tx: 0, key: TxKey::random() }, &r), Err(RowError::Commitment), "the wrong key does not open it");
    assert_eq!(verify_row(&ledger, &d, &r), Err(RowError::Scope), "a party disclosure produces no Transaction rows");
}
