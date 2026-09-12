//! The vendored note layer (`notes`/`viewing`/`ledger`, synced from the research crate by
//! `deploy/sync-zkvm.sh`) against `shrugg-core`'s own pure data types, and one end-to-end
//! `bundle` proof.
//!
//! Node-local, not vendored: upstream's `tests/bundle.rs` and `tests/viewing.rs` are the
//! authority on the note layer's own behaviour and are deliberately left there (each proves
//! several tier-14 guests and takes minutes — see `deploy/sync-zkvm.sh`'s header). What this
//! file checks is the seam upstream cannot: that `shrugg_core`'s hash-free `CommitmentTree`/
//! `FullTree` reproduce `ledger::CommitmentTree` exactly, that the domain tags the sync script
//! inlines into `hash.rs` still equal the vendored `notes::domain` ones, and that a bundle proof
//! this crate produces is one `ZkExecutor` — the chain-side verifier — accepts.

use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::notes::{CommitmentTree, FullTree, Word8, DEPTH};
use shrugg_zkvm::address::{address_of, digest_input_of, seal_note};
use shrugg_zkvm::executor::{prove_bundle, ZkExecutor};
use shrugg_zkvm::machine::{Backend, FriProfile};
use shrugg_zkvm::notes::{self, Note, SpendKey};
use shrugg_zkvm::viewing::TxKey;

/// `hc`, the in-circuit Poseidon2 program digest of the vendored `guests::bundle()`, as the
/// research crate at commit `4086aa8` prints it — its own `guests::bundle().code_hash()`, over a
/// 3811-word program. A genesis pins this value as `hc_bundle`, and every bundle proof
/// on the chain is verified against it, so it must be the digest of *upstream's* guest and not
/// merely of whatever this crate happens to assemble: `guests.rs` and `asm.rs` are excluded from
/// `deploy/sync-zkvm.sh`'s rsync (they carry node-local additions) and so are the two files a
/// resync can silently leave behind. An assertion against a program object built on this side
/// could not catch that — both sides of it would drift together — so the reference is this
/// literal, transcribed by hand from the upstream checkout.
///
/// If a future resync changes it, that is a consensus-visible change to the bundle guest:
/// recompute it from the research checkout, update this constant, and update the genesis.
const RESEARCH_HC_BUNDLE_HEX: &str = "6f35274a03719537a8a425604b291c66b7c2de0ed6bf7fcf182b470bfb4abd6c";

fn leaf(i: u32) -> Word8 {
    [i, 7, 7, 7, 0, 0, 0, i]
}

#[test]
fn core_trees_agree_with_the_vendored_research_tree() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let mut research = shrugg_zkvm::ledger::CommitmentTree::new();
    let mut frontier = CommitmentTree::new(&ex);
    let mut leaves = Vec::new();
    for i in 0..21u32 {
        research.append(leaf(i));
        frontier.append(leaf(i), &ex);
        leaves.push(leaf(i));
        assert_eq!(frontier.root(), research.root(), "size {}", i + 1);
        let full = FullTree::new(leaves.clone(), &ex);
        assert_eq!(full.root(), research.root());
        for idx in 0..leaves.len() {
            assert_eq!(full.path(idx as u64).unwrap(), research.path(idx), "path {idx} at size {}", i + 1);
        }
    }
    assert_eq!(CommitmentTree::empty_root(&ex), shrugg_zkvm::ledger::CommitmentTree::new().root());
}

#[test]
fn hc_bundle_is_the_vendored_guest_digest_and_domains_agree() {
    assert_eq!(ZkExecutor::hc_bundle(), ZkExecutor::bundle_program().digest());
    // The upstream cross-check: `Program::code_hash` is `digest()` rendered as eight `{:08x}`
    // words, so this pins every word of `hc_bundle` to the research crate's own value.
    assert_eq!(ZkExecutor::bundle_program().code_hash(), RESEARCH_HC_BUNDLE_HEX);
    assert_eq!(ZkExecutor::bundle_program().words.len(), 3811);
    // `deploy/sync-zkvm.sh` rewrites `hash.rs`/`tables/cpu.rs`'s references to
    // `notes::domain::{HC, IN}` into local constants rather than reverting that patch now that
    // `notes.rs` is vendored; this is what keeps the two copies from drifting.
    assert_eq!(notes::domain::HC, shrugg_zkvm::hash::HC_DOMAIN);
    assert_eq!(notes::domain::IN, shrugg_zkvm::hash::IN_DOMAIN);
}

/// S2/S3 scaffold. `Withdraw` and `BridgeAttest` publish an amount and a blinding `r` and let
/// the chain compute the deposit note itself, so the executor's `note_commitment` must be the
/// vendored note's own commitment and nothing beside it — a note the chain computes that the
/// owner's wallet cannot recognise is a note that is simply lost.
#[test]
fn the_executors_note_commitment_is_the_vendored_notes_own() {
    let ex = ZkExecutor::new(FriProfile::Test);
    // `Note::new` draws `r` itself; the chain is handed one. Same note either way.
    let mut n = Note::new([1; 8], [0; 8], 5 * 1_000_000_000, 0, 17);
    assert_eq!(ex.note_commitment(&n.pk, &n.from, n.amount, n.asset, n.time, &n.r), n.commitment());
    // And the same for the hand-built note the ledger's own deposits look like.
    n = Note { pk: [9, 8, 7, 6, 5, 4, 3, 2], from: [0; 8], amount: u64::MAX, asset: 3, time: 0, r: [7; 8] };
    assert_eq!(ex.note_commitment(&n.pk, &n.from, n.amount, n.asset, n.time, &n.r), n.commitment());
    // Every field is bound — in particular `r`, which is what keeps a published withdrawal
    // amount from being a note anyone can recompute.
    let base = ex.note_commitment(&n.pk, &n.from, n.amount, n.asset, n.time, &n.r);
    assert_ne!(ex.note_commitment(&n.pk, &n.from, n.amount, n.asset, n.time, &[8; 8]), base);
    assert_ne!(ex.note_commitment(&n.pk, &n.from, n.amount - 1, n.asset, n.time, &n.r), base);
    assert_ne!(ex.note_commitment(&n.pk, &n.from, n.amount, n.asset + 1, n.time, &n.r), base);
    assert_ne!(ex.note_commitment(&n.pk, &n.from, n.amount, n.asset, n.time + 1, &n.r), base);
    assert_ne!(ex.note_commitment(&n.from, &n.pk, n.amount, n.asset, n.time, &n.r), base, "pk and from are not symmetric");
    // The stub is a different function on purpose (blake3, not Poseidon2): a test that passes
    // under the stub proves the ledger's *shape*, never the chain's actual commitments.
    assert_ne!(
        shrugg_core::confidential::StubExecutor.note_commitment(&n.pk, &n.from, n.amount, n.asset, n.time, &n.r),
        base
    );
}

/// A 1-in-1-out-with-dummies bundle proves, its digest matches the core-side recompute, and
/// the executor verifies it (about a minute at the test profile).
#[test]
fn a_bundle_proves_and_the_executor_verifies_it() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let sk = SpendKey::random();
    let vk = sk.viewing_key();
    let me = address_of(&vk);
    let time = 5u32;
    let spent = Note::new(vk.pk(), [0; 8], 1_000, 0, time);
    let mut tree = shrugg_zkvm::ledger::CommitmentTree::new();
    tree.append(spent.commitment());
    let (path, index) = tree.path_for(&spent.commitment()).unwrap();
    let anchor = tree.root();
    // A dummy input: amount 0, so the guest skips its `MERKLE_VERIFY`/anchor/asset checks and its
    // path/index are never dereferenced. Its OWNER must still be `pk_self` — the guest always
    // stages an input note with its own derived `pk_self` in the owner slot, never a witness word
    // (that is what makes "you can only spend notes committed to your own key" structural), so a
    // dummy owned by anyone else would have the guest commit to, and nullify, a different note
    // than the one built here. `r` is fresh (`Note::new`): two zero-`r` dummies would collide to
    // one nullifier and taint the proof.
    let dummy = (Note::new(vk.pk(), [0; 8], 0, 0, time), [[0; 8]; DEPTH], 0u32);
    let fee = 10u64;
    let out1 = Note::new(vk.pk(), vk.pk(), 600, 0, time);
    let out2 = Note::new(vk.pk(), vk.pk(), 390, 0, time);
    let inputs = notes::bundle_inputs(&sk, &[(spent, path, index), dummy], &[out1, out2], anchor, fee, 0, 0, time);
    let nf1 = vk.nullifier(&spent.commitment());
    let nf2 = vk.nullifier(&dummy.0.commitment());
    let di = digest_input_of(anchor, [nf1, nf2], [out1.commitment(), out2.commitment()], fee, 0, 0, time);
    // Emulate first, in milliseconds, and check the witness against the core-side recompute before
    // paying for a proof: a witness the guest taints (`bad != 0`) publishes a digest no plaintext
    // can reproduce, and finding that out after the prover has run costs minutes.
    let emulated = shrugg_zkvm::emulator::execute(ZkExecutor::bundle_program(), &inputs, 50_000_000).unwrap();
    assert_eq!(ex.bundle_digest(&di), emulated.outputs, "the witness is tainted or the digest preimage disagrees");
    let started = std::time::Instant::now();
    let (proof, digest, tier) = prove_bundle(FriProfile::Test, &inputs, Backend::Cpu).unwrap();
    println!("bundle proved at tier {tier} in {:.1?} ({} proof bytes)", started.elapsed(), proof.len());
    assert_eq!(tier, 14);
    assert_eq!(ex.bundle_digest(&di), digest);
    assert_eq!(ex.bundle_proof_digest(&proof).unwrap(), digest);
    ex.verify_bundle(&ZkExecutor::hc_bundle(), &proof).unwrap();
    assert!(ex.verify_bundle(&[1u32; 8], &proof).is_err());
    let e = seal_note(&vk, &me, &out1, &TxKey::random()).unwrap();
    assert!(e.len() <= shrugg_core::notes::MAX_ENVELOPE_BYTES);
}
