//! CPUV-1 residual (randprotocol/fullnode#54): `Machine::verifier_key`'s cache evicts the least
//! recently used key, not the oldest, and builds each key once however many callers miss it at
//! the same moment.
//!
//! A node verifies one bundle shape all day and call shapes now and then: under FIFO eviction a
//! burst of distinct admissible call shapes pushed the hot key out however often it was used, and
//! two first callers of one shape both paid the build (up to seconds and hundreds of MB at the
//! node's cap). The hooks used here (`with_key_cache_capacity`, `key_builds`, `has_cached_key`)
//! are `#[doc(hidden)]` test instruments; nothing else reads them.
use randprotocol_zkvm::machine::{FriProfile, Machine, Tier};
use randprotocol_zkvm::tables::{input, program, public};
use std::sync::{Arc, Barrier};

/// A tier-10, hash-chip-free key shape differing only in its declared program height.
fn key(m: &Machine, plh: u8) -> Arc<p3_batch_stark::CommonData<randprotocol_zkvm::machine::Config>> {
    m.verifier_key(Tier(10), plh, input::input_log_height(0), 0, 0, public::MIN_LOG_HEIGHT)
}
fn cached(m: &Machine, plh: u8) -> bool {
    m.has_cached_key(Tier(10), plh, input::input_log_height(0), 0, 0, public::MIN_LOG_HEIGHT)
}

#[test]
fn a_recently_used_key_survives_eviction_and_the_least_recently_used_one_goes() {
    let (a, b, c) = (program::MIN_LOG_HEIGHT, program::MIN_LOG_HEIGHT + 1, program::MIN_LOG_HEIGHT + 2);
    let m = Machine::with_key_cache_capacity(FriProfile::Test, 2);
    key(&m, a);
    key(&m, b);
    key(&m, a); // a hit: `a` is now the most recently used
    assert_eq!(m.key_builds(), 2, "the second `a` is a hit");
    key(&m, c); // full: one of `a`, `b` must go
    assert_eq!(m.key_builds(), 3);
    assert_eq!(m.cached_keys(), 2, "the capacity holds");
    assert!(cached(&m, c), "the new key is cached");
    assert!(
        cached(&m, a) && !cached(&m, b),
        "LRU: the key just used (`a`) stays and the least recently used (`b`) is evicted; \
         cached a = {}, b = {}",
        cached(&m, a),
        cached(&m, b)
    );
    key(&m, a);
    assert_eq!(m.key_builds(), 3, "and `a` is still a hit");
}

#[test]
fn concurrent_first_callers_of_one_key_share_one_build() {
    const CALLERS: usize = 8;
    let m = Arc::new(Machine::new(FriProfile::Test));
    let start = Arc::new(Barrier::new(CALLERS));
    let keys: Vec<_> = (0..CALLERS)
        .map(|_| {
            let (m, start) = (m.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                key(&m, program::MIN_LOG_HEIGHT)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert_eq!(m.key_builds(), 1, "{CALLERS} simultaneous first callers built the key {} times", m.key_builds());
    assert!(keys.iter().all(|k| Arc::ptr_eq(k, &keys[0])), "every caller holds the one built key");
    assert_eq!(m.cached_keys(), 1);
}
