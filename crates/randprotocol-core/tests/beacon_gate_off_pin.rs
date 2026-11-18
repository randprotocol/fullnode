//! The randomness beacon is genesis-gated: a chain whose genesis has no `beacon` section is
//! byte for byte what it was.
//!
//! Every value below was taken on the commit before the beacon existed (`9d9e8473`) and must
//! never move: a block header's encoding and hash, the empty transaction root, and the wire form
//! of the two newest actions before the beacon's (tags 44 and 45). Chain 21's own genesis, header
//! and state roots are pinned the same way in the node crate, where the real executor is
//! (`node::tests::chain_21_is_byte_for_byte_what_it_was_before_the_beacon`). A change here is a
//! consensus change for chain 21.

use randprotocol_core::crypto::{Hash, Keypair, Signature};
use randprotocol_core::ledger::program_state::{Cell, Inflow, Transition};
use randprotocol_core::types::{Action, Block, BlockHeader, QuorumCertificate, Transaction};

fn digest(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

/// What the test computes, in order: blake3 of a header's bincode; the header's hash; the empty
/// transaction root; blake3 of a `SetRandPrice`'s encoding and its txid; blake3 of a bundle-less
/// `InvokeAt`'s encoding and its txid.
const PINS: [&str; 7] = [
    "4c0bbd7320fd568172ad0bbcf895a9b2c32eaa3532898f331fc6edb3e5e8fb2f",
    "072d035ba3dcf82bf1f29a5b1659e76ed2dd0e2c31c801fd5c8578e2914e56cb",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "7112c00c0d2c84c448c4419a907e9671c53fd140bc033de90ce49102faaec6c1",
    "d77469e56b23834cea4d0e8b35fdb26f60a2985603974d324f9749a2503f677f",
    "cb0497eb3a52c37a9498ad5a56f3fcdbec43b2b1e5d7b23abac028f85f2104b8",
    "a0ddfd0d8ae72d7da31cde95cf940a9a4abff8de8f232b2b4bd28853dea8b3cd",
];

#[test]
fn a_header_and_the_newest_actions_are_byte_for_byte_what_they_were() {
    let key = Keypair::from_seed([7; 32]).unwrap().public_key().clone();
    let header = BlockHeader {
        height: 1,
        view: 3,
        parent: Hash([0x21; 32]),
        proposer: key.clone(),
        timestamp_ms: 1_794_960_123_456,
        tx_root: Block::tx_root(&[]),
        state_root: Hash([0x5a; 32]),
        justify: QuorumCertificate { view: 0, block_hash: Hash([0x21; 32]), votes: Vec::new() },
    };
    let mut got = vec![digest(&bincode::serialize(&header).unwrap()), header.hash().to_hex(), Block::tx_root(&[]).to_hex()];
    let price = Transaction {
        chain_id: 21,
        bundle: None,
        action: Action::SetRandPrice { price_micros_per_rand: 150_000, nonce: 1, votes: vec![(key, Signature::empty())] },
    };
    let invoke_at = Transaction {
        chain_id: 21,
        bundle: None,
        action: Action::InvokeAt {
            program: Hash([7; 32]),
            proof: (0..=255u8).collect(),
            input_envelope: None,
            transition: Transition {
                reads: vec![Cell { key: [1; 8], value: [2; 8] }],
                writes: vec![Cell { key: [1; 8], value: [3; 8] }],
                inflow: Inflow::Deposit,
                pays: vec![],
                mints: vec![],
            },
            ref_height: 0x0102_0304_0506_0708,
        },
    };
    for tx in [&price, &invoke_at] {
        got.push(digest(&tx.encode()));
        got.push(tx.hash().to_hex());
        assert_eq!(&Transaction::decode(&tx.encode()).unwrap(), tx);
    }
    // Chain id (8 bytes), the bundle's `Option` tag (0), then the variant as a u32.
    assert_eq!(&price.encode()[9..13], &44u32.to_le_bytes());
    assert_eq!(&invoke_at.encode()[9..13], &45u32.to_le_bytes());
    assert_eq!(got, PINS.iter().map(|s| s.to_string()).collect::<Vec<_>>());
}
