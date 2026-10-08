//! RPL-3 (final fix wave, I8): the multi-chunk `perp_digest` pinned host-side with the real
//! Poseidon2. `randprotocol-core`'s `golden_vectors` owns `block_words` and `segment` in the
//! shared `perps-v1.json` but cannot name this crate's executor; this test owns the three digest
//! entries beside them, each `perp_digest(PERP_BLOCK, w)` over the deterministic sequence
//! `w[i] = (i as u32).wrapping_mul(2654435761)`:
//!
//! - `digest_4000` — exactly one chunk (`DIGEST_CHUNK_WORDS`);
//! - `digest_4001` — one word into the second chunk;
//! - `digest_8001` — three chunks, the third one word long: the three-chunk boundary, inside the guest's 8 192-word block buffer.
//!
//! durian.market's guest computes the same digest in echo mode; its check compares against these.
//! Regenerate with `PERPS_WRITE_VECTORS=1 cargo test -p randprotocol-zkvm --test perps_vectors`
//! (it rewrites only these three keys).

use randprotocol_core::ledger::perps::{domain, perp_digest, DIGEST_CHUNK_WORDS};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::FriProfile;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../randprotocol-core/tests/vectors/perps-v1.json");

/// The pinned word sequence: `i · 2654435761 mod 2^32` (Knuth's multiplicative hash constant),
/// so every word differs and none is zero past the first.
fn words(n: usize) -> Vec<u32> {
    (0..n).map(|i| (i as u32).wrapping_mul(2654435761)).collect()
}

fn digests() -> serde_json::Map<String, serde_json::Value> {
    let zk = ZkExecutor::new(FriProfile::Test);
    let mut m = serde_json::Map::new();
    for n in [4000usize, 4001, 8001] {
        m.insert(format!("digest_{n}"), serde_json::json!(perp_digest(&zk, domain::BLOCK, &words(n))));
    }
    m
}

#[test]
fn the_multi_chunk_digests_are_pinned_with_the_real_poseidon2() {
    assert_eq!(DIGEST_CHUNK_WORDS, 4000, "4000 and 4001 are the chunk boundary");
    let ours = digests();
    let read = || -> serde_json::Map<String, serde_json::Value> {
        serde_json::from_str(&std::fs::read_to_string(PATH).expect("perps-v1.json exists")).unwrap()
    };
    if std::env::var("PERPS_WRITE_VECTORS").is_ok() {
        let mut map = read();
        map.extend(ours.clone());
        std::fs::write(PATH, serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap()).unwrap();
    }
    let on_disk = read();
    for (k, v) in &ours {
        assert_eq!(on_disk.get(k), Some(v), "perps-v1.json's {k} is stale or missing");
    }
    // Three distinct digests: the length word and the chunking both move it.
    assert_ne!(ours["digest_4000"], ours["digest_4001"]);
    assert_ne!(ours["digest_4001"], ours["digest_8001"]);
}
