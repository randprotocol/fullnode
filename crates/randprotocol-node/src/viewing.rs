//! Node-side viewing-key imports: the Zcash `z_importviewingkey` analogue
//! (`docs/rpc-comparison.md` §4), and the per-transaction disclosure check behind
//! `rand_checkTransaction` (Monero's `check_tx_proof` analogue).
//!
//! This is the one deliberate exception to the chain's "the node never holds a key" property,
//! and it is worth stating exactly what changes and what does not. An operator may hand this
//! node a **viewing key** (`nk`) over RPC; the node then trial-decrypts leaves on that key's
//! behalf and serves the matches — which is what a block explorer (RandScan) runs a node *for*.
//! What the RPC layer has no type for is a *spend* key: nothing here can move value, and the
//! key that arrives is the one whose owning wallet can already see everything it discloses.
//! Imports live **in memory only** — no viewing key is ever written to this node's disk — so a
//! restart clears them and the explorer re-imports (see `docs/rpc.md`).
//!
//! The scan is lazy and incremental: import only records the key and where to start, and each
//! `rand_getViewingNotes` call advances the cursor by at most [`MAX_SCAN_ROWS`] leaves, so one
//! request can never make the node re-walk unbounded history. The trial decryption itself is the
//! wallet's own logic (`randprotocol_client::wallet::classify`) restated against a bare `ViewingKey`:
//! an envelope opens as *receiver* through the KEM decapsulation key, as *sender* through the
//! outgoing viewing key, and an opening whose note names another `pk` is garbage someone sealed
//! to a public address, not a note of this party's.

use crate::storage::{Storage, StorageError};
use randprotocol_core::notes::{Envelope, Word8};
use randprotocol_core::{Action, Transaction};
use randprotocol_zkvm::address::envelope_from_core;
use randprotocol_zkvm::notes::{Note, ViewingKey};
use randprotocol_zkvm::viewing::TxKey;
use std::collections::BTreeMap;

/// The most viewing keys one node holds at once. Every import costs a trial decryption per new
/// leaf for as long as it is held, so the cap is what keeps an unauthenticated RPC port from
/// turning the node into a scanning oracle for an unbounded set of keys. 64 is generous for an
/// explorer node watching the keys its operator cares about; a restart clears them all.
pub const MAX_VIEWING_KEYS: usize = 64;

/// The most leaves one `rand_getViewingNotes` call trial-decrypts. Each costs an ML-KEM-768
/// decapsulation plus up to two AEAD opens, so this bounds one request at well under a second of
/// work; a rescan longer than the cap completes over several calls, with the reply's
/// `scanned_index`/`complete` saying how far it got.
pub const MAX_SCAN_ROWS: u64 = 10_000;

/// What one leaf turned out to be for an imported key — the two rows of
/// `randprotocol_zkvm::viewing::Role` a party's own key can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A note this party owns: the envelope opened as receiver and the note names the party.
    Received,
    /// A note this party created for someone else — history only, opened through `ovk`.
    Sent,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Received => "received",
            Role::Sent => "sent",
        }
    }
}

/// One matched leaf, in tree order.
#[derive(Clone, Debug)]
pub struct ViewingNote {
    pub index: u64,
    pub cm: Word8,
    pub height: u64,
    pub role: Role,
    pub note: Note,
}

/// One imported viewing key and its scan state.
#[derive(Clone, Debug)]
pub struct Import {
    pub vk: ViewingKey,
    /// Leaves appended below this height are never tried: the cursor starts at
    /// `Storage::first_note_at_or_after` of it.
    pub rescan_from_height: u64,
    /// The next leaf index to trial-decrypt; every leaf at or below it has been tried.
    pub scanned_index: u64,
    /// Every leaf that matched, in tree order.
    pub notes: Vec<ViewingNote>,
}

/// Every key this node holds, keyed by the viewing key's `nk` words. In memory only, by design:
/// a viewing key on disk would be a new secret-at-rest this node has never had, and the
/// operator's orchestration already knows which keys to re-import after a restart.
#[derive(Default, Debug)]
pub struct Registry {
    keys: BTreeMap<Word8, Import>,
}

/// The registry is at [`MAX_VIEWING_KEYS`] and the key is not already in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("this node already holds the maximum of {MAX_VIEWING_KEYS} viewing keys")]
pub struct RegistryFull;

impl Registry {
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Record `nk` for scanning from `start_index` (the first leaf at or after
    /// `rescan_from_height`). Returns `true` when the key is new. Re-importing a key already
    /// held is a no-op — `false`, and the cursor is *not* reset: a rescan from an earlier
    /// height is a restart plus re-import, since imports are in-memory by design.
    pub fn import(&mut self, nk: Word8, rescan_from_height: u64, start_index: u64) -> Result<bool, RegistryFull> {
        if self.keys.contains_key(&nk) {
            return Ok(false);
        }
        if self.keys.len() >= MAX_VIEWING_KEYS {
            return Err(RegistryFull);
        }
        self.keys.insert(
            nk,
            Import { vk: ViewingKey { nk }, rescan_from_height, scanned_index: start_index, notes: Vec::new() },
        );
        Ok(true)
    }

    pub fn get_mut(&mut self, nk: &Word8) -> Option<&mut Import> {
        self.keys.get_mut(nk)
    }
}

/// What one leaf is for `vk`, with no I/O — the node-side restatement of
/// `randprotocol_client::wallet::classify`, which takes a whole wallet (a spend key) and so cannot be
/// reused here.
///
/// The ownership check matters exactly as it does for the wallet: an envelope opening is not
/// proof of ownership. Anyone can seal an envelope to a published `kem_ek` carrying a note owned
/// by some other `pk` — a shielded address is public by design — and such a row is garbage, not
/// a receipt: the bundle guest forces every input's owner to the derived `pk_self`, so no proof
/// can ever spend it.
pub fn classify(vk: &ViewingKey, cm: Word8, envelope: &Envelope) -> Option<(Role, Note)> {
    let env = envelope_from_core(envelope);
    if let Some((_, note)) = env.open_as_receiver(cm, vk) {
        if note.pk == vk.pk() {
            return Some((Role::Received, note));
        }
    }
    // Still worth the sender path: an envelope this party sealed for someone else opens through
    // `ovk`, not through the KEM, so the two openings are independent.
    if let Some((_, note)) = env.open_as_sender(cm, vk) {
        return Some((Role::Sent, note));
    }
    None
}

/// Trial-decrypt up to `max_rows` leaves past `import`'s cursor and record the matches. One
/// forward read of the (dense, gapless) notes family; leaves below the rescan floor are never
/// reached because the cursor started past them.
pub fn advance(storage: &Storage, import: &mut Import, max_rows: u64) -> Result<(), StorageError> {
    let next = storage.notes_count()?;
    // Defensive: `truncate_to` deletes a suffix of the family, so a chain rebuilt past the
    // cursor would otherwise leave it pointing past the end forever. (Truncation happens at
    // startup, before the RPC serves; this costs one compare.)
    if import.scanned_index > next {
        import.scanned_index = next;
    }
    let want = (next - import.scanned_index).min(max_rows);
    if want == 0 {
        return Ok(());
    }
    for (index, row) in storage.notes_from(import.scanned_index, want as usize)? {
        if let Some((role, note)) = classify(&import.vk, row.cm, &row.envelope) {
            import.notes.push(ViewingNote { index, cm: row.cm, height: row.height, role, note });
        }
        import.scanned_index = index + 1;
    }
    Ok(())
}

/// One envelope of a transaction that `key` opened, with the commitment it is bound to.
#[derive(Clone, Debug)]
pub struct Opening {
    /// Which of the transaction's envelope sets this came from: `"bundle"` (the transaction's
    /// own, the fee bundle of a `BridgeBurn`), `"asset_bundle"` (a `BridgeBurn`'s second
    /// bundle), `"deposit"` (a `BridgeAttest`'s deposit envelope), or `"mint"` (a faucet mint's
    /// one envelope).
    pub output: &'static str,
    /// The slot inside `output`; meaningless for `"deposit"`, which carries exactly one
    /// envelope.
    pub slot: u8,
    /// The on-chain commitment the opened note commits to — what makes the disclosure a proof
    /// rather than a claim: `open_with_tx_key` authenticates the note *and* checks it against
    /// this leaf, so a key that opens an envelope lifted from another transaction yields
    /// nothing.
    pub cm: Word8,
    pub note: Note,
}

/// Every envelope of `tx` that `key` opens — the whole of `rand_checkTransaction`'s
/// disclosure semantics. The envelopes tried are exactly the ones a living `TxKey` can exist
/// for: the bundle outputs (sealed by the sender, who may hand the key over) and a bridge
/// deposit (sealed by the depositor). A mint's, a withdraw's and a genesis alloc's envelopes are
/// sealed inside the node under keys that are dropped at once (`seal_deposit`,
/// `sealed_withdraw_note`, the faucet's mint), so no `TxKey` for them can ever be presented and
/// they are not tried.
///
/// `deposit_cm` is the chain-computed commitment of a `BridgeAttest`'s deposit note — the one
/// commitment the wire does not carry — which the caller computes from the registry the way
/// `tx_json` does; `None` for any other action, for a rotation (which deposits nothing), and on
/// a chain whose registry does not hold the asset.
pub fn disclosed(tx: &Transaction, deposit_cm: Option<Word8>, key: &TxKey) -> Vec<Opening> {
    let mut out = Vec::new();
    let mut try_env = |output: &'static str, slot: u8, cm: Word8, e: &Envelope| {
        if let Some(note) = envelope_from_core(e).open_with_tx_key(cm, key) {
            out.push(Opening { output, slot, cm, note });
        }
    };
    if let Some(b) = &tx.bundle {
        for (i, (cm, e)) in b.commitments.iter().zip(&b.envelopes).enumerate() {
            try_env("bundle", i as u8, *cm, e);
        }
    }
    match &tx.action {
        Action::BridgeBurn { asset_bundle, .. } => {
            for (i, (cm, e)) in asset_bundle.commitments.iter().zip(&asset_bundle.envelopes).enumerate() {
                try_env("asset_bundle", i as u8, *cm, e);
            }
        }
        Action::BridgeAttest { envelope, .. } => {
            if let Some(cm) = deposit_cm {
                try_env("deposit", 0, cm, envelope);
            }
        }
        // A faucet mint carries its one commitment and envelope on the wire.
        Action::Mint { cm, envelope, .. } => try_env("mint", 0, *cm, envelope),
        _ => {}
    }
    out
}

/// Test helpers shared with `rpc.rs`'s tests: real viewing keys, real notes, real sealed
/// envelopes — the fixtures in `storage` only carry placeholder envelopes, which open for
/// nobody.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use randprotocol_zkvm::address::{address_of, seal_note};
    use randprotocol_zkvm::notes::SpendKey;

    pub(crate) fn key_vk(n: u8) -> ViewingKey {
        SpendKey([n as u32; 8]).viewing_key()
    }

    /// A note owned by `owner`'s key, created by `sender`'s, worth `amount`.
    pub(crate) fn note_for(owner: &ViewingKey, sender: &ViewingKey, amount: u64) -> Note {
        Note::new(owner.pk(), sender.pk(), amount, 0, 0)
    }

    /// `sender` seals `note` to its owner's address under `key` — what a wallet does per output.
    pub(crate) fn sealed_to(sender: &ViewingKey, owner: &ViewingKey, note: &Note, key: &TxKey) -> Envelope {
        seal_note(sender, &address_of(owner), note, key).expect("a real encapsulation key seals")
    }

    /// The key's `nk` as the 64-hex parameter the RPC takes.
    pub(crate) fn nk_hex(vk: &ViewingKey) -> String {
        randprotocol_core::notes::word8_to_hex(&vk.nk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fixtures::{self, alloc_note, bundle_fee, genesis_with, key, make_block};
    use crate::storage::Storage;
    use testkit::{key_vk, note_for, sealed_to as sealed};
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_zkvm::address::{address_of, seal_note};
    use randprotocol_zkvm::notes::SpendKey;

    fn alice() -> ViewingKey {
        key_vk(1)
    }
    fn bob() -> ViewingKey {
        key_vk(2)
    }

    #[test]
    fn classify_tells_received_from_sent_from_strangers() {
        let carol = SpendKey([3; 8]).viewing_key();
        let note = note_for(&alice(), &bob(), 500);
        let cm = note.commitment();

        // Alice receives it: sealed to her, naming her pk.
        let env = sealed(&bob(), &alice(), &note, &TxKey([7; 32]));
        assert_eq!(classify(&alice(), cm, &env), Some((Role::Received, note)));
        // Bob sent it: his `ovk` opens the sender wrap even though it names Alice.
        assert_eq!(classify(&bob(), cm, &env), Some((Role::Sent, note)));
        // Carol has no key in it at all.
        assert_eq!(classify(&carol, cm, &env), None);
        // And the same envelope against a different commitment opens for nobody: the AEAD binds
        // it to its own leaf.
        assert_eq!(classify(&alice(), [9; 8], &env), None);
    }

    #[test]
    fn classify_rejects_a_note_sealed_to_us_but_owned_by_another_key() {
        // Anyone can encapsulate to a published kem_ek; the note inside names someone else.
        let stranger = SpendKey([9; 8]).viewing_key();
        let not_alices = note_for(&bob(), &stranger, 500);
        let env = seal_note(&stranger, &address_of(&alice()), &not_alices, &TxKey([8; 32])).unwrap();
        assert_eq!(classify(&alice(), not_alices.commitment(), &env), None);
    }

    #[test]
    fn the_registry_caps_imports_and_a_reimport_is_a_noop() {
        let mut reg = Registry::default();
        for i in 0..MAX_VIEWING_KEYS {
            let nk = [i as u32 + 1; 8];
            assert!(reg.import(nk, 0, 0).unwrap(), "import {i} is new");
        }
        assert_eq!(reg.len(), MAX_VIEWING_KEYS);
        // The 65th distinct key is refused...
        assert_eq!(reg.import([0xbeef; 8], 0, 0), Err(RegistryFull));
        // ...but a key already held is a no-op, even at the cap — and it does not reset the
        // cursor or the rescan floor.
        reg.get_mut(&[1; 8]).unwrap().scanned_index = 42;
        assert_eq!(reg.import([1; 8], 99, 7), Ok(false));
        let held = reg.get_mut(&[1; 8]).unwrap();
        assert_eq!((held.scanned_index, held.rescan_from_height), (42, 0));
        assert_eq!(reg.len(), MAX_VIEWING_KEYS);
    }

    /// A chain with two blocks: block 1 pays Alice 500 and Bob 700 (one bundle each, sealed by
    /// Bob and Alice respectively); block 2 pays Alice 900. Returns the pieces the assertions
    /// read.
    fn chain_with_sealed_notes() -> (tempfile::TempDir, Storage, Note, Note, Note) {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        storage.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();

        let alice_note_1 = note_for(&alice(), &bob(), 500);
        let bob_note = note_for(&bob(), &alice(), 700);
        let mut b1_bundle = fixtures::bundle(
            &ledger,
            [[31; 8], [32; 8]],
            [alice_note_1.commitment(), bob_note.commitment()],
            bundle_fee(),
        );
        b1_bundle.envelopes = [
            sealed(&bob(), &alice(), &alice_note_1, &TxKey([11; 32])),
            sealed(&alice(), &bob(), &bob_note, &TxKey([12; 32])),
        ];
        let tx1 = Transaction::shielded(gs.chain_id, b1_bundle, Action::None);
        let b1 = make_block(&gs.block, &mut ledger, vec![tx1], &key(1));
        storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

        let alice_note_2 = note_for(&alice(), &bob(), 900);
        let mut b2_bundle = fixtures::bundle(&ledger, [[33; 8], [34; 8]], [alice_note_2.commitment(), [44; 8]], bundle_fee());
        b2_bundle.envelopes = [sealed(&bob(), &alice(), &alice_note_2, &TxKey([13; 32])), fixtures::env(9)];
        let tx2 = Transaction::shielded(gs.chain_id, b2_bundle, Action::None);
        let b2 = make_block(&b1.block, &mut ledger, vec![tx2], &key(1));
        storage.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();

        (dir, storage, alice_note_1, bob_note, alice_note_2)
    }

    #[test]
    fn advance_finds_the_imported_keys_notes_and_nobody_elses() {
        let (_d, storage, alice_note_1, bob_note, alice_note_2) = chain_with_sealed_notes();

        // Alice: her two receipts, and the note she sent Bob — three rows, in tree order.
        let mut import = Import { vk: alice(), rescan_from_height: 0, scanned_index: 0, notes: Vec::new() };
        advance(&storage, &mut import, MAX_SCAN_ROWS).unwrap();
        assert_eq!(import.scanned_index, storage.notes_count().unwrap());
        let got: Vec<(u64, Role, Note)> = import.notes.iter().map(|n| (n.index, n.role, n.note)).collect();
        // Leaf 0 is the genesis alloc, whose placeholder envelope opens for nobody.
        assert_eq!(
            got,
            vec![(1, Role::Received, alice_note_1), (2, Role::Sent, bob_note), (3, Role::Received, alice_note_2)]
        );
        // Heights came from the rows.
        assert_eq!(import.notes[0].height, 1);
        assert_eq!(import.notes[2].height, 2);

        // Bob: the mirror image — he sent the 500 and the 900 and owns the 700.
        let mut bobs = Import { vk: bob(), rescan_from_height: 0, scanned_index: 0, notes: Vec::new() };
        advance(&storage, &mut bobs, MAX_SCAN_ROWS).unwrap();
        let got: Vec<(u64, Role, Note)> = bobs.notes.iter().map(|n| (n.index, n.role, n.note)).collect();
        assert_eq!(got, vec![(1, Role::Sent, alice_note_1), (2, Role::Received, bob_note), (3, Role::Sent, alice_note_2)]);
    }

    #[test]
    fn advance_respects_the_rescan_floor_and_is_bounded_per_call() {
        let (_d, storage, _n1, _n2, alice_note_2) = chain_with_sealed_notes();

        // From height 2 the block-1 notes are never tried: the cursor starts at the first leaf
        // of that height, and only the 900 shows.
        let start = storage.first_note_at_or_after(2).unwrap();
        assert_eq!(start, 3);
        let mut import = Import { vk: alice(), rescan_from_height: 2, scanned_index: start, notes: Vec::new() };
        advance(&storage, &mut import, MAX_SCAN_ROWS).unwrap();
        assert_eq!(import.notes.len(), 1);
        assert_eq!((import.notes[0].index, import.notes[0].note), (3, alice_note_2));

        // A per-call bound stops mid-tree and picks up where it stopped: one leaf per call here,
        // so the four leaves take four calls and the fifth finds nothing new.
        let mut slow = Import { vk: alice(), rescan_from_height: 0, scanned_index: 0, notes: Vec::new() };
        for calls in 1..=4 {
            advance(&storage, &mut slow, 1).unwrap();
            assert_eq!(slow.scanned_index, calls, "one leaf per call");
        }
        advance(&storage, &mut slow, 1).unwrap();
        assert_eq!(slow.notes.len(), 3, "the same three rows, gathered incrementally");
    }

    #[test]
    fn disclosed_opens_exactly_the_slots_the_key_sealed() {
        let ledger = genesis_with(7, vec![]).ledger;
        let alice_note = note_for(&alice(), &bob(), 500);
        let change = note_for(&bob(), &bob(), 9_500);
        let payment_key = TxKey([21; 32]);
        let change_key = TxKey([22; 32]);
        let mut bundle = fixtures::bundle(
            &ledger,
            [[31; 8], [32; 8]],
            [alice_note.commitment(), change.commitment()],
            bundle_fee(),
        );
        bundle.envelopes = [
            sealed(&bob(), &alice(), &alice_note, &payment_key),
            seal_note(&bob(), &address_of(&bob()), &change, &change_key).unwrap(),
        ];
        let tx = Transaction::shielded(7, bundle, Action::None);

        // The payment key discloses the payment and nothing else.
        let opened = disclosed(&tx, None, &payment_key);
        assert_eq!(opened.len(), 1);
        assert_eq!((opened[0].output, opened[0].slot), ("bundle", 0));
        assert_eq!((opened[0].cm, opened[0].note), (alice_note.commitment(), alice_note));
        // The change key discloses the change, and a wrong key nothing at all.
        assert_eq!(disclosed(&tx, None, &change_key).len(), 1);
        assert!(disclosed(&tx, None, &TxKey([99; 32])).is_empty());

        // A bridge attestation's deposit envelope opens against the chain-computed commitment —
        // and does not open against anything else, so a key lifted from another transaction
        // authenticates for nobody.
        let deposit = note_for(&alice(), &bob(), 1_000);
        let deposit_key = TxKey([23; 32]);
        let attest = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::BridgeAttest {
                attestation: vec![9; 64],
                recipient: address_of(&alice()),
                r: [5; 8],
                time: 4,
                asset: 1,
                envelope: sealed(&bob(), &alice(), &deposit, &deposit_key),
            },
        };
        let opened = disclosed(&attest, Some(deposit.commitment()), &deposit_key);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].output, "deposit");
        assert_eq!(opened[0].note, deposit);
        assert!(disclosed(&attest, None, &deposit_key).is_empty(), "no commitment, no opening");
        assert!(disclosed(&attest, Some([6; 8]), &deposit_key).is_empty(), "the AEAD binds the real one");
    }

    #[test]
    fn a_faucet_mint_discloses_its_one_note() {
        // A mint carries its commitment and envelope on the wire, like a bundle's outputs, so the
        // key its minter sealed under discloses it — the `rand tx-key` a recipient prints.
        let note = note_for(&alice(), &bob(), 100);
        let k = TxKey([31; 32]);
        let mint = Transaction::mint(7, note.commitment(), sealed(&bob(), &alice(), &note, &k), 100, &randprotocol_core::Keypair::generate());
        let opened = disclosed(&mint, None, &k);
        assert_eq!(opened.len(), 1);
        assert_eq!((opened[0].output, opened[0].slot, opened[0].cm), ("mint", 0, note.commitment()));
        assert_eq!(opened[0].note, note);
        assert!(disclosed(&mint, None, &TxKey([32; 32])).is_empty());
    }
}
