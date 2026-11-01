//! The perps exchange's recorded block digests, cheap to clone and to commit to.
//!
//! A chain with a perps section records `D_h` for every closed block until a state proof covers
//! it. A chain nobody proves on holds one entry per block for ever, and every [`Ledger`] clone and
//! every state root used to walk all of them: on chain 21 at height 654 000 that was a 25 MB copy
//! and about 1.3 M BLAKE3 hashes per block, which pushed block apply past the view timeout.
//!
//! [`DigestLog`] holds the same ordered map in full chunks shared by `Arc`, each with its Merkle
//! root cached, plus a short unshared tail. A clone costs one pointer per chunk, and
//! [`DigestLog::merkle_root`] hashes only the tail and the chunk roots. Both its root and its
//! serialized form are byte for byte what `crypto::merkle_root` over the leaves and a
//! `BTreeMap<u64, Word8>` give, so the change is invisible to consensus and to stored rows.
//!
//! [`Ledger`]: super::Ledger

use crate::crypto::{merkle_node, merkle_root, Hash};
use crate::notes::{word8_to_bytes, Word8};
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::sync::Arc;

/// log2 of the leaves in a full chunk. A chunk is a perfect subtree of the tree `merkle_root`
/// builds over the whole log, because chunks are cut at multiples of this size from the first
/// leaf; [`DigestLog::rebuild`] restores that when the front of the log is dropped.
const CHUNK_BITS: u32 = 10;
const CHUNK_LEN: usize = 1 << CHUNK_BITS;

/// One recorded digest's Merkle leaf, under the domain `Perps::root` has always used.
fn leaf(height: u64, digest: &Word8) -> Hash {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&height.to_be_bytes());
    buf.extend_from_slice(&word8_to_bytes(digest));
    Hash::digest_domain(b"rand-perp-digest-1", &buf)
}

#[derive(Debug)]
struct Chunk {
    entries: Vec<(u64, Word8)>,
    /// `merkle_root` over the chunk's leaves.
    root: Hash,
}

impl Chunk {
    fn seal(entries: Vec<(u64, Word8)>) -> Chunk {
        let leaves: Vec<Hash> = entries.iter().map(|(h, d)| leaf(*h, d)).collect();
        Chunk { entries, root: merkle_root(&leaves) }
    }
}

/// An ordered `height -> digest` map; see the module documentation.
#[derive(Clone, Debug, Default)]
pub struct DigestLog {
    /// Full chunks, ascending: every height here is below every height in `tail`.
    chunks: Vec<Arc<Chunk>>,
    /// At most `CHUNK_LEN - 1` entries, ascending.
    tail: Vec<(u64, Word8)>,
}

impl DigestLog {
    pub fn new() -> DigestLog {
        DigestLog::default()
    }

    pub fn len(&self) -> usize {
        self.chunks.len() * CHUNK_LEN + self.tail.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty() && self.tail.is_empty()
    }

    /// Every entry in height order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (u64, &Word8)> + '_ {
        self.chunks.iter().flat_map(|c| c.entries.iter()).chain(self.tail.iter()).map(|(h, d)| (*h, d))
    }

    pub fn last_height(&self) -> Option<u64> {
        self.tail.last().or_else(|| self.chunks.last().and_then(|c| c.entries.last())).map(|(h, _)| *h)
    }

    pub fn get(&self, height: u64) -> Option<&Word8> {
        let find = |entries: &'_ [(u64, Word8)]| -> Option<usize> { entries.binary_search_by_key(&height, |(h, _)| *h).ok() };
        if let Some(i) = find(&self.tail) {
            return Some(&self.tail[i].1);
        }
        let at = self.chunks.partition_point(|c| c.entries[CHUNK_LEN - 1].0 < height);
        let chunk = self.chunks.get(at)?;
        find(&chunk.entries).map(|i| &chunk.entries[i].1)
    }

    pub fn contains(&self, height: u64) -> bool {
        self.get(height).is_some()
    }

    /// The entries with a height in `range`, ascending.
    pub fn range(&self, range: RangeInclusive<u64>) -> impl Iterator<Item = (u64, &Word8)> + '_ {
        let (from, to) = (*range.start(), *range.end());
        // The first chunk that can hold `from`: nothing before it is in range.
        let start = self.chunks.partition_point(|c| c.entries[CHUNK_LEN - 1].0 < from);
        self.chunks[start..]
            .iter()
            .flat_map(|c| c.entries.iter())
            .chain(self.tail.iter())
            .skip_while(move |(h, _)| *h < from)
            .take_while(move |(h, _)| *h <= to)
            .map(|(h, d)| (*h, d))
    }

    /// Record `digest` at `height`. A height above the last is the live path, O(1) amortized;
    /// any other rebuilds the log (the ledger never does it, only tests that plant an entry).
    pub fn insert(&mut self, height: u64, digest: Word8) {
        if self.last_height().is_some_and(|last| height <= last) {
            let mut all: BTreeMap<u64, Word8> = self.iter().map(|(h, d)| (h, *d)).collect();
            all.insert(height, digest);
            *self = all.into_iter().collect();
            return;
        }
        self.tail.push((height, digest));
        if self.tail.len() == CHUNK_LEN {
            let full = std::mem::take(&mut self.tail);
            self.chunks.push(Arc::new(Chunk::seal(full)));
        }
    }

    /// Drop every entry at or below `height`, as a state proof covering it does. Rebuilds: the
    /// surviving leaves sit at new positions, so no cached chunk root still applies.
    pub fn drop_through(&mut self, height: u64) {
        if self.last_height().is_some_and(|last| last > height) {
            *self = self.iter().filter(|(h, _)| *h > height).map(|(h, d)| (h, *d)).collect();
        } else {
            *self = DigestLog::new();
        }
    }

    /// `crypto::merkle_root` over every entry's leaf, in O(chunks + `CHUNK_LEN`) hashes.
    pub fn merkle_root(&self) -> Hash {
        let tail: Vec<Hash> = self.tail.iter().map(|(h, d)| leaf(*h, d)).collect();
        if self.chunks.is_empty() {
            return merkle_root(&tail);
        }
        let mut tops: Vec<Hash> = self.chunks.iter().map(|c| c.root).collect();
        if !tail.is_empty() {
            tops.push(tail_top(tail));
        }
        merkle_root(&tops)
    }
}

/// The tail's node at chunk height, as the whole-log tree computes it: `CHUNK_BITS` levels with
/// the last node of an odd level paired with itself. This is not `merkle_root(tail)`, which stops
/// as soon as one node is left. A level of the whole log has the tail's parity below chunk height,
/// since every full chunk contributes an even number of nodes there.
fn tail_top(mut level: Vec<Hash>) -> Hash {
    for _ in 0..CHUNK_BITS {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("the tail is not empty"));
        }
        level = level.chunks(2).map(|pair| merkle_node(&pair[0], &pair[1])).collect();
    }
    level[0]
}

impl FromIterator<(u64, Word8)> for DigestLog {
    /// From entries in ascending height order.
    fn from_iter<I: IntoIterator<Item = (u64, Word8)>>(entries: I) -> DigestLog {
        let mut log = DigestLog::new();
        for (height, digest) in entries {
            log.insert(height, digest);
        }
        log
    }
}

impl PartialEq for DigestLog {
    fn eq(&self, other: &DigestLog) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Eq for DigestLog {}

// The wire form is the map's, so every row, snapshot and JSON document keeps its bytes.
impl Serialize for DigestLog {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (height, digest) in self.iter() {
            map.serialize_entry(&height, digest)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for DigestLog {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<DigestLog, D::Error> {
        struct LogVisitor;
        impl<'de> Visitor<'de> for LogVisitor {
            type Value = DigestLog;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map of block heights to digests")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<DigestLog, A::Error> {
                let mut log = DigestLog::new();
                while let Some((height, digest)) = access.next_entry::<u64, Word8>()? {
                    log.insert(height, digest);
                }
                Ok(log)
            }
        }
        deserializer.deserialize_map(LogVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(h: u64) -> Word8 {
        [h as u32, (h >> 32) as u32, 3, 4, 5, 6, 7, 8]
    }

    fn map(heights: impl Iterator<Item = u64>) -> BTreeMap<u64, Word8> {
        heights.map(|h| (h, digest(h))).collect()
    }

    fn log_of(m: &BTreeMap<u64, Word8>) -> DigestLog {
        m.iter().map(|(h, d)| (*h, *d)).collect()
    }

    /// What `Perps::root` computed before this type: the oracle every root here must equal.
    fn full_root(m: &BTreeMap<u64, Word8>) -> Hash {
        merkle_root(&m.iter().map(|(h, d)| leaf(*h, d)).collect::<Vec<_>>())
    }

    /// Consensus: the root must be `merkle_root`'s at every length, above all around chunk and
    /// power-of-two boundaries, where duplicate-last pairing could diverge.
    #[test]
    fn the_root_equals_the_full_merkle_root_at_every_length() {
        let mut lengths: Vec<u64> = (0..2_200).collect();
        for k in 11..=15u32 {
            let p = 1u64 << k;
            lengths.extend([p - 1, p, p + 1, p + 1023, p + 1024, p + 1025]);
        }
        for n in lengths {
            let m = map(1..=n);
            assert_eq!(log_of(&m).merkle_root(), full_root(&m), "{n} entries");
        }
    }

    #[test]
    fn the_root_stays_correct_while_appending_one_at_a_time() {
        let mut m = BTreeMap::new();
        let mut log = DigestLog::new();
        for h in 1..=5_000 {
            m.insert(h, digest(h));
            log.insert(h, digest(h));
            assert_eq!(log.merkle_root(), full_root(&m), "after height {h}");
        }
    }

    /// A state proof drops the front, which moves every surviving leaf.
    #[test]
    fn the_root_is_right_after_the_front_is_dropped() {
        for (n, to) in [(5_000, 1), (5_000, 1024), (5_000, 1025), (5_000, 4_999), (5_000, 5_000), (5_000, 9_000), (10, 3)] {
            let mut log = log_of(&map(1..=n));
            log.drop_through(to);
            let m = map(to + 1..=n);
            assert_eq!(log.merkle_root(), full_root(&m), "{n} entries through {to}");
            assert_eq!(log, log_of(&m));
            // And appending goes on from there.
            let (mut log, mut m) = (log, m);
            for h in n.max(to) + 1..n.max(to) + 3_000 {
                log.insert(h, digest(h));
                m.insert(h, digest(h));
            }
            assert_eq!(log.merkle_root(), full_root(&m));
        }
    }

    #[test]
    fn sparse_heights_read_as_the_map_does() {
        let m = map((1..4_000).map(|i| i * 7));
        let log = log_of(&m);
        assert_eq!(log.len(), m.len());
        assert_eq!(log.last_height(), m.keys().next_back().copied());
        for h in [0, 1, 6, 7, 8, 7_161, 7_168, 7_175, 27_993, 28_000] {
            assert_eq!(log.get(h), m.get(&h), "get {h}");
            assert_eq!(log.contains(h), m.contains_key(&h));
        }
        for (from, to) in [(0, 0), (1, 6), (7, 7), (8, 13), (7_000, 7_400), (7_168, 14_336), (27_990, u64::MAX), (9, 3)] {
            let got: Vec<_> = if from <= to { log.range(from..=to).map(|(h, d)| (h, *d)).collect() } else { Vec::new() };
            let want: Vec<_> = if from <= to { m.range(from..=to).map(|(h, d)| (*h, *d)).collect() } else { Vec::new() };
            assert_eq!(got, want, "{from}..={to}");
        }
    }

    #[test]
    fn inserting_below_the_last_height_matches_the_map() {
        let mut m = map([2, 5, 9].into_iter());
        let mut log = log_of(&m);
        for (h, d) in [(5, [9; 8]), (3, [8; 8]), (1, [7; 8]), (12, [6; 8])] {
            m.insert(h, d);
            log.insert(h, d);
        }
        assert_eq!(log, log_of(&m));
        assert_eq!(log.merkle_root(), full_root(&m));
    }

    /// Stored rows and JSON must not change.
    #[test]
    fn the_wire_form_is_the_maps() {
        for n in [0, 1, 3, 1_023, 1_024, 1_025, 3_000] {
            let m = map(1..=n);
            let log = log_of(&m);
            let bytes = bincode::serialize(&m).unwrap();
            assert_eq!(bincode::serialize(&log).unwrap(), bytes, "{n} entries");
            let back: DigestLog = bincode::deserialize(&bytes).unwrap();
            assert_eq!(back, log);
            assert_eq!(back.merkle_root(), full_root(&m));
            assert_eq!(serde_json::to_string(&log).unwrap(), serde_json::to_string(&m).unwrap());
            assert_eq!(serde_json::from_str::<DigestLog>(&serde_json::to_string(&m).unwrap()).unwrap(), log);
        }
    }

    /// The bug itself: a clone of a long log must share its chunks, and appending to one clone
    /// must leave the other alone.
    #[test]
    fn a_clone_shares_the_chunks_and_diverges_cleanly() {
        let log = log_of(&map(1..=100_000));
        let mut fork = log.clone();
        assert_eq!(log.chunks.len(), 100_000 / CHUNK_LEN);
        for (a, b) in log.chunks.iter().zip(&fork.chunks) {
            assert!(Arc::ptr_eq(a, b), "a clone copies no chunk");
        }
        assert!(log.tail.len() < CHUNK_LEN, "what a clone does copy is bounded");
        let root = log.merkle_root();
        for h in 100_001..=102_000 {
            fork.insert(h, digest(h));
        }
        assert_eq!(log.merkle_root(), root);
        assert_eq!(log.len(), 100_000);
        assert_eq!(fork.merkle_root(), full_root(&map(1..=102_000)));
    }
}
