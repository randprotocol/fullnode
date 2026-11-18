//! Issue #168: the wire form of an ordinary `Invoke` is pinned.
//!
//! `Action::InvokeAt` (tag 45) is a variant of its own so that nothing about an `Invoke` moves:
//! its bytes, its txid, both bindings and its version-1 context. The values below were taken on
//! the commit before `InvokeAt` existed (`609111b5`) and must never change on a live chain — a
//! change here is a wire change for chain 21.

use randprotocol_core::crypto::Hash;
use randprotocol_core::ledger::program_state::{Cell, Inflow, Payout, Transition};
use randprotocol_core::notes::{Bundle, Envelope, ShieldedAddress};
use randprotocol_core::types::{Action, BindingDomain, CallEnvelope, Transaction};

fn env() -> Envelope {
    Envelope { kem_ct: vec![1; 8], to_receiver: vec![9; 3], to_sender: vec![8; 2], body: vec![2; 8] }
}

fn bundle() -> Bundle {
    Bundle {
        anchor: [1; 8],
        nullifiers: [[2; 8], [3; 8], [4; 8], [5; 8]],
        commitments: [[6; 8], [7; 8], [8; 8], [9; 8]],
        fee: 1_234_567,
        burn_a: 55,
        burn_r: 0x1_0000_0002,
        burn_asset: 3,
        time: 41,
        envelopes: [env(), env(), env(), env()],
        proof: vec![0xaa; 16],
        auth_commit: [10; 8],
        auth_proof: vec![0xbb; 5],
    }
}

fn transition() -> Transition {
    let payout = |n: u32| Payout {
        asset: n,
        amount: 1_000 + n as u64,
        recipient: ShieldedAddress { pk: [n; 8], kem_ek: vec![6; 32] },
        r: [n + 100; 8],
        envelope: env(),
    };
    Transition {
        reads: vec![Cell { key: [1; 8], value: [2; 8] }],
        writes: vec![Cell { key: [1; 8], value: [3; 8] }, Cell { key: [4; 8], value: [5; 8] }],
        inflow: Inflow::Deposit,
        pays: vec![payout(0)],
        mints: vec![payout(2)],
    }
}

fn invoke() -> Transaction {
    Transaction::shielded(
        13,
        bundle(),
        Action::Invoke {
            program: Hash([7; 32]),
            proof: (0..=255u8).collect(),
            input_envelope: Some(CallEnvelope { kem_ct: vec![0xa1; 5], to_sender: vec![0xb2; 3], to_auditor: vec![0xc3; 2], body: vec![0xd4; 7] }),
            transition: transition(),
        },
    )
}

fn words_hex(w: &[u32]) -> String {
    let bytes: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// (blake3 of the encoding, txid, blake3 of `binding`, of `call_binding`, each under the chain-id
/// domain; then the two bindings under the genesis domain; then blake3 of the v1 context words).
const PINS: [&str; 7] = [
    "8d633abdf617524bbf04a2b145cc4feead7bc1e089713562e7df5b943713b395",
    "82ea17b675a4281d3fc68790f7dd416cdda52654c047f47d7831c31e7eae3bbf",
    "d0c62f927b32d998a21cf913ee456b52396d7a148b16368333c164213fd8bc6e",
    "38140184cb4ed1279bc274b7c5eed0af927b261479a4e04e88d56abad4603758",
    "428b42b53932b0872cd22adb31508113d98ef4e4aa3e9f9d7df4ce91f426fc68",
    "ca1d1573306d90df36c139906cde520b9f6cca043e96cf5be626f5c19db7519f",
    "d8f614228d38af182bb3a383b730f12c3fe4340f246f6b136b21329de521029c",
];

#[test]
fn an_ordinary_invoke_is_byte_for_byte_what_it_was() {
    let tx = invoke();
    let genesis = BindingDomain::Genesis(Hash([0x21; 32]));
    let b = tx.bundle.as_ref().unwrap();
    let Action::Invoke { transition, .. } = &tx.action else { unreachable!() };
    let got = [
        hex::encode(blake3::hash(&tx.encode()).as_bytes()),
        hex::encode(tx.hash().0),
        words_hex(&tx.binding(&BindingDomain::ChainId)),
        words_hex(&tx.call_binding(&BindingDomain::ChainId)),
        words_hex(&tx.binding(&genesis)),
        words_hex(&tx.call_binding(&genesis)),
        words_hex(&transition.context(b.burn_r, b.burn_asset, b.burn_a)),
    ];
    assert_eq!(got.to_vec(), PINS.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    assert_eq!(Transaction::decode(&tx.encode()).unwrap(), tx);
}

/// The new form is a different transaction in every respect an observer or the chain can see:
/// tag 45 on the wire (an `Invoke` is 33), its own txid and bindings, and both move with the
/// reference height.
#[test]
fn an_invoke_at_is_tag_45_and_never_an_invoke() {
    let plain = invoke();
    let at = |ref_height: u64| {
        let Action::Invoke { program, proof, input_envelope, transition } = plain.action.clone() else { unreachable!() };
        Transaction { chain_id: 13, bundle: None, action: Action::InvokeAt { program, proof, input_envelope, transition, ref_height } }
    };
    let bare = |a: &Transaction| Transaction { chain_id: 13, bundle: None, action: a.action.clone() };
    // Chain id (8 bytes), the bundle's `Option` tag (0), then the variant as a u32.
    assert_eq!(&bare(&plain).encode()[8..13], &[&[0u8][..], &33u32.to_le_bytes()[..]].concat()[..]);
    assert_eq!(&at(7).encode()[8..13], &[&[0u8][..], &45u32.to_le_bytes()[..]].concat()[..]);
    assert_eq!(Transaction::decode(&at(7).encode()).unwrap(), at(7));
    // The reference height is the last eight bytes, little-endian, after an `Invoke`'s fields.
    let (a, b) = (bare(&plain).encode(), at(0x0102_0304_0506_0708).encode());
    assert_eq!(b.len(), a.len() + 8);
    assert_eq!(&b[13..a.len()], &a[13..]);
    assert_eq!(&b[a.len()..], &0x0102_0304_0506_0708u64.to_le_bytes());
    let d = BindingDomain::ChainId;
    for (x, y) in [(bare(&plain), at(7)), (at(7), at(8))] {
        assert_ne!(x.hash(), y.hash());
        assert_ne!(x.binding(&d), y.binding(&d));
        assert_ne!(x.call_binding(&d), y.call_binding(&d), "the call proof is bound to the reference height");
    }
    // The call binding leaves the proof out and nothing else.
    let mut other_proof = at(7);
    if let Action::InvokeAt { proof, .. } = &mut other_proof.action {
        proof.push(1);
    }
    assert_eq!(other_proof.call_binding(&d), at(7).call_binding(&d));
    assert_ne!(other_proof.binding(&d), at(7).binding(&d));
    assert_eq!(at(7).action.invoke().unwrap().ref_height, Some(7));
    assert_eq!(plain.action.invoke().unwrap().ref_height, None);
}
