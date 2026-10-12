//! The seeded generator of `tests/fixtures/*.json`: a 2-of-3 policy and one proposal over a real v3
//! bundle (no proof), built from `randprotocol-zkvm` primitives only — no client — and six bad
//! proposals derived from it.
//!
//! Every random value comes from one `ChaCha20Rng::seed_from_u64(0x2026_1011)`, drawn in the
//! order the code below reads: `msk`, the three member seeds, the non-member seed, the recipient's
//! key, the spent note's `from` and `r`, the three dummy inputs' `r`, then per output slot its
//! owner (a throwaway key for each dummy), its `r`, its transaction key and its sealing randomness;
//! then the salt; then the tampered proposal's throwaway sender, transaction key and sealing
//! randomness. Nothing reads OS entropy: the envelopes are sealed by [`seal`], the vendored
//! `viewing::Envelope::seal` with its ML-KEM message and AEAD nonces taken from the stream.
//!
//! The binding is `BindingDomain::ChainId` on chain 7; the bundle's `time` is 1 000 and the
//! proposal's `expires_at` 2 024. `expected.json` is written from the crate's own `check_proposal`
//! and `sign` over the valid proposal, so the vectors pin the implementation's behaviour.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use randprotocol_core::notes::{word8_to_hex, Bundle, Envelope, ShieldedAddress, Word8, DEPTH};
use randprotocol_core::{gas, Action, Hash, Keypair, Transaction, UNITS_PER_RAND};
use randprotocol_msig::{check_proposal, informational_summary, parse_words, sign, words_hex, Policy, Proposal};
use randprotocol_zkvm::address::{address_of, envelope_from_core, envelope_to_core};
use randprotocol_zkvm::hidden::{self, hidden_input_v3 as hi, HiddenDigestInput, HiddenDigestInputV3, HiddenOutput, SLOTS};
use randprotocol_zkvm::notes::{Note, SpendKey, ViewingKey};
use randprotocol_zkvm::viewing::{self, TxKey};
use std::collections::BTreeMap;

const SEED: u64 = 0x2026_1011;
const CHAIN_ID: u64 = 7;
const TIME: u32 = 1_000;
const EXPIRES_AT: u64 = 2_024;
/// The one spent note: the payment, its change and the fee.
const SPENT: u64 = 25 * UNITS_PER_RAND;
const PAYMENT: u64 = 10 * UNITS_PER_RAND;

fn word(rng: &mut ChaCha20Rng) -> Word8 {
    std::array::from_fn(|_| rng.next_u32())
}

fn bytes32(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

/// The vendored `viewing.rs`'s AEAD: ChaCha20-Poly1305 with a 12-byte nonce prepended — here
/// drawn from `rng`.
fn aead(rng: &mut ChaCha20Rng, key: &[u8; 32], tag: &[u8], cm: &Word8, pt: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let aad = [tag, &randprotocol_zkvm::notes::words_to_bytes(cm)].concat();
    let ct = ChaCha20Poly1305::new(&Key::from(*key)).encrypt(&Nonce::from(nonce), Payload { msg: pt, aad: &aad }).expect("aead");
    [&nonce[..], &ct].concat()
}

/// `viewing::Envelope::seal(sender, to, note, tx_key)` (the legacy, memo-less body), byte for byte
/// in layout, with the ML-KEM encapsulation message and the three nonces drawn from `rng` rather
/// than `rand::rng()`. Checked to open as sender and as receiver through the vendored code.
fn seal(rng: &mut ChaCha20Rng, sender: &ViewingKey, to: &ShieldedAddress, to_vk: &ViewingKey, note: &Note, tx_key: &TxKey) -> Envelope {
    type Ek = ml_kem::ml_kem_768::EncapsulationKey;
    let cm = note.commitment();
    let ek = Ek::new(&ml_kem::kem::Key::<Ek>::try_from(&to.kem_ek[..]).expect("1184-byte key")).expect("valid key");
    let m = bytes32(rng);
    let (kem_ct, ss) = ek.encapsulate_deterministic(&m.into());
    let ss: [u8; 32] = ss.into();
    let e = viewing::Envelope {
        kem_ct: kem_ct.to_vec(),
        to_receiver: aead(rng, &ss, b"rand-envelope-receiver", &cm, &tx_key.0),
        to_sender: aead(rng, &sender.ovk(), b"rand-envelope-sender", &cm, &tx_key.0),
        body: aead(rng, &tx_key.0, b"rand-envelope-body", &cm, &note.to_bytes()),
    };
    assert_eq!(e.open_as_sender(cm, sender).map(|(_, n)| n), Some(*note), "opens as sender");
    assert_eq!(e.open_as_receiver(cm, to_vk).map(|(_, n)| n), Some(*note), "opens as receiver");
    envelope_to_core(&e)
}

fn pretty(v: &impl serde::Serialize) -> String {
    serde_json::to_string_pretty(v).unwrap() + "\n"
}

pub fn vectors() -> BTreeMap<&'static str, String> {
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);

    // ---- the policy: 2-of-3 over the first three seeds ----
    let msk = word(&mut rng);
    let members: Vec<[u8; 32]> = (0..3).map(|_| bytes32(&mut rng)).collect();
    let non_member = bytes32(&mut rng);
    let policy = Policy {
        version: 1,
        threshold: 2,
        signers: members.iter().map(|s| Keypair::from_seed(*s).unwrap().public_key().to_hex()).collect(),
        msk: word8_to_hex(&msk),
    };
    policy.check().expect("the fixture policy is valid");
    let vk = policy.viewing_key();
    let account = policy.address();
    let pk_self = vk.pk();

    // ---- the recipient, and the one spent note in a one-leaf tree ----
    let recipient_vk = SpendKey(word(&mut rng)).viewing_key();
    let recipient = address_of(&recipient_vk);
    let spent = Note { pk: pk_self, from: word(&mut rng), amount: SPENT, asset: 0, time: TIME - 500, r: word(&mut rng) };
    let mut tree = randprotocol_zkvm::ledger::CommitmentTree::new();
    tree.append(spent.commitment());
    let anchor = tree.root();
    let dummy_in = |k: usize, r: Word8| (Note { pk: pk_self, from: [0; 8], amount: 0, asset: hidden::slot_asset(k, 0), time: TIME, r }, [[0u32; 8]; DEPTH], 0u32);
    let (r0, r1, r3) = (word(&mut rng), word(&mut rng), word(&mut rng));
    let inputs = [dummy_in(0, r0), dummy_in(1, r1), (spent, tree.path(0), 0u32), dummy_in(3, r3)];

    // ---- the outputs: two dummies, the payment, the change — every one sealed by the account ----
    let fee = gas::BUNDLE_BASE;
    let mut outs = [HiddenOutput { pk: [0; 8], amount: 0, r: [0; 8] }; SLOTS];
    let mut envelopes = Vec::with_capacity(SLOTS);
    for (k, out) in outs.iter_mut().enumerate() {
        let (owner_vk, amount) = match k {
            2 => (recipient_vk, PAYMENT),
            3 => (vk, SPENT - PAYMENT - fee),
            _ => (SpendKey(word(&mut rng)).viewing_key(), 0),
        };
        *out = HiddenOutput { pk: owner_vk.pk(), amount, r: word(&mut rng) };
        let note = out.note(k, pk_self, 0, TIME);
        let tx_key = TxKey(bytes32(&mut rng));
        envelopes.push(seal(&mut rng, &vk, &address_of(&owner_vk), &owner_vk, &note, &tx_key));
    }
    let salt = word(&mut rng);
    let auth_commit = randprotocol_zkvm::msauth::auth_commit(&policy.nk(), &salt);
    let nullifiers: [Word8; SLOTS] = std::array::from_fn(|k| vk.nullifier(&inputs[k].0.commitment()));
    let commitments: [Word8; SLOTS] = std::array::from_fn(|k| outs[k].note(k, pk_self, 0, TIME).commitment());
    let words = hidden::hidden_bundle_inputs_v3(&vk, &salt, &inputs, &outs, anchor, fee, 0, 0, 0, TIME);
    let expected = hidden::hidden_bundle_digest_v3(&HiddenDigestInputV3 {
        base: HiddenDigestInput { anchor, nullifiers, commitments, fee, burn_a: 0, burn_r: 0, burn_asset: 0, time: TIME },
        auth_commit,
    });
    let bundle = Bundle {
        anchor,
        nullifiers,
        commitments,
        fee,
        burn_a: 0,
        burn_r: 0,
        burn_asset: 0,
        time: TIME,
        envelopes: envelopes.try_into().map_err(|_| "four envelopes").unwrap(),
        proof: Vec::new(),
        auth_commit,
        auth_proof: Vec::new(),
    };
    let tx = Transaction::shielded(CHAIN_ID, bundle, Action::None);
    let valid = Proposal::new(
        &policy,
        &tx,
        &Hash::ZERO,
        0,
        &words,
        &expected,
        &salt,
        EXPIRES_AT,
        informational_summary(Some((&recipient, PAYMENT)), 0, fee, ""),
    );

    // ---- the six bad proposals ----
    // Output slot 3 (the change) sealed again under a throwaway sender: the commitment stays, the
    // envelope moves, so the binding and signing message are re-made over it (a proposer hiding an
    // output would hand out a self-consistent file) and only "opens as sender" can refuse it.
    let throwaway = SpendKey(word(&mut rng)).viewing_key();
    let mut tampered_tx = tx.clone();
    {
        let b = tampered_tx.bundle.as_mut().unwrap();
        let (_, change) = envelope_from_core(&b.envelopes[3]).open_as_sender(b.commitments[3], &vk).expect("slot 3 opens before the edit");
        let tx_key = TxKey(bytes32(&mut rng));
        b.envelopes[3] = seal(&mut rng, &throwaway, &account, &vk, &change, &tx_key);
    }
    let tampered = Proposal::new(&policy, &tampered_tx, &Hash::ZERO, 0, &words, &expected, &salt, EXPIRES_AT, valid.summary.clone());
    // Input slot 2's witness amount raised by 1 (its 64-bit pair, with the carry): the binding is
    // unchanged, the witness no longer matches the transaction's value.
    let mut mismatch = valid.clone();
    let mut w = parse_words(&valid.bundle_words).unwrap();
    let (lo, hi_) = (hi::in_slot(2) + hi::S_AMOUNT_LO, hi::in_slot(2) + hi::S_AMOUNT_HI);
    let v = (w[lo] as u64 | (w[hi_] as u64) << 32) + 1;
    (w[lo], w[hi_]) = (v as u32, (v >> 32) as u32);
    mismatch.bundle_words = words_hex(&w);
    // The envelope edit above with the binding left as it was: refused at the binding.
    let mut unbound = valid.clone();
    unbound.tx = tampered.tx.clone();
    // An `expected` digest that is not the bundle's.
    let mut wrong_expected = valid.clone();
    let mut digest = randprotocol_msig::parse_word8(&valid.expected).unwrap();
    digest[0] ^= 1;
    wrong_expected.expected = word8_to_hex(&digest);
    // The fee raised by 1 in the bundle and the witness, the digest and binding re-made: every
    // check up to the balance passes, and the balance cannot (the outputs did not shrink).
    let mut fee_tx = tx.clone();
    fee_tx.bundle.as_mut().unwrap().fee += 1;
    let mut fee_words = words.clone();
    let f = (fee_words[hi::FEE_LO] as u64 | (fee_words[hi::FEE_HI] as u64) << 32) + 1;
    (fee_words[hi::FEE_LO], fee_words[hi::FEE_HI]) = (f as u32, (f >> 32) as u32);
    let fee_expected = hidden::hidden_bundle_digest_v3(&HiddenDigestInputV3 {
        base: HiddenDigestInput { anchor, nullifiers, commitments, fee: fee + 1, burn_a: 0, burn_r: 0, burn_asset: 0, time: TIME },
        auth_commit,
    });
    let fee_raised = Proposal::new(&policy, &fee_tx, &Hash::ZERO, 0, &fee_words, &fee_expected, &salt, EXPIRES_AT, valid.summary.clone());
    // One block past the longest window a chain may set.
    let mut expired = valid.clone();
    expired.expires_at = TIME as u64 + randprotocol_core::ledger::MAX_PROOF_WINDOW_BLOCKS + 1;

    // ---- what the valid proposal checks and signs to ----
    let (valid_json, policy_json) = (pretty(&valid), pretty(&policy));
    let summary = check_proposal(&valid_json, &policy_json).expect("the valid proposal checks");
    let share = |i: usize| {
        let (idx, sig) = sign(&valid_json, &policy_json, &members[i]).expect("a member signs");
        format!("{idx}:{}", hex::encode(sig))
    };
    let expected_json = serde_json::json!({
        "summary": summary,
        "signing_message": hex::encode(summary.signing_message),
        "share_0": share(0),
        "share_2": share(2),
    });
    let seeds = serde_json::json!({
        "members": members.iter().map(hex::encode).collect::<Vec<_>>(),
        "non_member": hex::encode(non_member),
    });

    BTreeMap::from([
        ("expected.json", pretty(&expected_json)),
        ("policy.json", policy_json),
        ("proposal-expired.json", pretty(&expired)),
        ("proposal-fee-raised.json", pretty(&fee_raised)),
        ("proposal-unbound.json", pretty(&unbound)),
        ("proposal-wrong-expected.json", pretty(&wrong_expected)),
        ("proposal-tampered-output.json", pretty(&tampered)),
        ("proposal-valid.json", valid_json),
        ("proposal-value-mismatch.json", pretty(&mismatch)),
        ("signer-seeds.json", pretty(&seeds)),
    ])
}
