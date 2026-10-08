//! Compact blocks (spec 2026-10-08 §0, §5.2-5.4): the pieces of the proposal path that need no
//! node state, namely the cache of recently seen transaction bodies, the rebuild of a block
//! from a compact proposal, and a parked proposal waiting for the bodies it lacks. `node.rs`
//! wires them to gossip, the sync channel and the replica; HotStuff never sees a compact
//! proposal.

use crate::network::{CompactBlock, TX_FETCH_BATCH};
use libp2p::request_response::OutboundRequestId;
use libp2p::PeerId;
use randprotocol_core::{Block, Hash, Transaction};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// How many transaction bodies the node keeps beside its pool, by count. With the byte cap it
/// is the window between a transaction's arrival on gossip and its verdict, plus the bodies of
/// the blocks in flight (spec §5.2).
pub const RECENT_TXS_MAX: usize = 4_096;

/// The cache's byte cap: four blocks' worth on the chain's block-size cap.
pub fn recent_txs_bytes(max_block_bytes: usize) -> usize {
    max_block_bytes.saturating_mul(4)
}

/// Whether `tx` carries its bundle proof in the pruned marker form (`PRUNED_PROOF_MARKER` and the
/// proof's hash). [`Transaction::hash`] gives that form the same id as the transaction with its
/// proof, so a peer could gossip the marker copy of a transaction a leader is about to propose;
/// rebuilt into the block, it makes the block fail and this node not vote. A marker-form body
/// therefore never enters the compact path: not cached, not looked up, not accepted from a fetch.
pub fn is_marker_form(tx: &Transaction) -> bool {
    tx.bundle.as_ref().is_some_and(|b| randprotocol_core::notes::pruned_proof_hash(&b.proof).is_some())
}

/// FIFO of gossiped and proposed transactions by hash, capped by count and by serialized
/// bytes, so a compact proposal can usually be rebuilt without asking a peer.
pub struct RecentTxs {
    by_hash: HashMap<Hash, Transaction>,
    order: VecDeque<(Hash, usize)>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl RecentTxs {
    pub fn new(max_entries: usize, max_bytes: usize) -> RecentTxs {
        RecentTxs { by_hash: HashMap::new(), order: VecDeque::new(), bytes: 0, max_entries, max_bytes }
    }

    /// Remember a transaction; a held one is left where it is, and a marker-form one
    /// ([`is_marker_form`]) is not taken. Evicts the oldest entries past either cap (a single
    /// body larger than the byte cap is evicted at once).
    pub fn remember(&mut self, tx: Transaction) {
        if is_marker_form(&tx) {
            return;
        }
        let h = tx.hash();
        if self.by_hash.contains_key(&h) {
            return;
        }
        let len = bincode::serialized_size(&tx).map_or(0, |n| n as usize);
        self.by_hash.insert(h, tx);
        self.order.push_back((h, len));
        self.bytes = self.bytes.saturating_add(len);
        while self.order.len() > self.max_entries || self.bytes > self.max_bytes {
            let Some((old, old_len)) = self.order.pop_front() else { break };
            self.by_hash.remove(&old);
            self.bytes = self.bytes.saturating_sub(old_len);
        }
    }

    /// Remember every transaction of a block: the next leader's proposal often repeats them.
    pub fn remember_block(&mut self, block: &Block) {
        for tx in &block.transactions {
            self.remember(tx.clone());
        }
    }

    pub fn get(&self, h: &Hash) -> Option<&Transaction> {
        self.by_hash.get(h)
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// The answer to a transaction fetch (spec 2026-10-08 §3.2, §6): the bodies `lookup` finds for
/// `hashes`, in the order asked, stopping at the first that would take the answer's serialized
/// bytes past `limit` (final review I4). A cut answer is still an answer: the asker places what
/// came and asks the next peer for the rest.
pub fn bounded_answer<'a>(hashes: &[Hash], lookup: impl Fn(&Hash) -> Option<&'a Transaction>, limit: usize) -> Vec<Transaction> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for tx in hashes.iter().filter_map(lookup) {
        bytes = bytes.saturating_add(bincode::serialized_size(tx).map_or(usize::MAX, |n| n as usize));
        if bytes > limit {
            break;
        }
        out.push(tx.clone());
    }
    out
}

/// What a rebuild found: the block, or the hashes still missing in block order.
pub enum Rebuilt {
    Block(Block),
    Missing { compact: CompactBlock, have: Vec<Option<Transaction>>, missing: Vec<Hash> },
}

/// Rebuild the block a compact proposal elided from `lookup`, or say which hashes are missing,
/// in block order. The hash list was checked against the signed root before this is called, so
/// a complete rebuild is the block the leader signed.
pub fn rebuild(compact: CompactBlock, mut lookup: impl FnMut(&Hash) -> Option<Transaction>) -> Rebuilt {
    let have: Vec<Option<Transaction>> = compact.tx_hashes.iter().map(&mut lookup).collect();
    if have.iter().all(Option::is_some) {
        let txs = have.into_iter().flatten().collect();
        return Rebuilt::Block(compact.into_block(txs));
    }
    let missing = compact.tx_hashes.iter().zip(&have).filter(|(_, t)| t.is_none()).map(|(h, _)| *h).collect();
    Rebuilt::Missing { compact, have, missing }
}

/// One of a park's outstanding transaction fetches.
#[derive(Clone, Debug)]
pub struct InFlight {
    pub id: OutboundRequestId,
    /// The peer it went to.
    pub peer: PeerId,
    /// The hashes it asked for.
    pub hashes: Vec<Hash>,
    pub sent: Instant,
}

/// A compact proposal waiting for its bodies (spec §5.3; the node keeps up to two, by view).
pub struct Parked {
    /// Header, signature and hashes.
    pub compact: CompactBlock,
    /// The bodies found so far, by position.
    pub have: Vec<Option<Transaction>>,
    /// The forwarder.
    pub from: PeerId,
    /// The distinct peers asked so far, each counted once however many batches it was sent
    /// (final review I7); [`Parked::attempts`] is their number, bounded by the node's
    /// fetch-attempt limit.
    pub asked: Vec<PeerId>,
    /// Peers that answered `Busy` and have nothing else of this park's in flight: not counted
    /// as asked, and tried again only after every other candidate (final review I7).
    pub busy: Vec<PeerId>,
    /// Outstanding requests.
    pub inflight: Vec<InFlight>,
    pub since: Instant,
}

impl Parked {
    pub fn new(compact: CompactBlock, have: Vec<Option<Transaction>>, from: PeerId, now: Instant) -> Parked {
        Parked { compact, have, from, asked: Vec::new(), busy: Vec::new(), inflight: Vec::new(), since: now }
    }

    /// Fetch attempts so far: the distinct peers asked, a `Busy` answer not counted (final
    /// review I7).
    pub fn attempts(&self) -> usize {
        self.asked.len()
    }

    /// Count `peer` as asked: once, however many batches it is sent, and no longer busy.
    pub fn note_asked(&mut self, peer: PeerId) {
        self.busy.retain(|p| *p != peer);
        if !self.asked.contains(&peer) {
            self.asked.push(peer);
        }
    }

    /// `peer` answered a request `Busy` (final review I7): with nothing else of this park's
    /// out to it, it is no longer counted as asked and goes to the back of the line — tried
    /// again after every other candidate.
    pub fn note_busy(&mut self, peer: PeerId) {
        if self.inflight.iter().any(|f| f.peer == peer) {
            return;
        }
        self.asked.retain(|p| *p != peer);
        if !self.busy.contains(&peer) {
            self.busy.push(peer);
        }
    }

    /// Whether `h` names a position still empty.
    pub fn wants(&self, h: &Hash) -> bool {
        self.compact.tx_hashes.iter().zip(&self.have).any(|(x, t)| x == h && t.is_none())
    }

    pub fn view(&self) -> u64 {
        self.compact.header.view
    }

    /// Hashes whose position is still empty, in block order.
    pub fn missing(&self) -> Vec<Hash> {
        self.compact.tx_hashes.iter().zip(&self.have).filter(|(_, t)| t.is_none()).map(|(h, _)| *h).collect()
    }

    /// The hashes still to ask for, in block order, chunked by [`TX_FETCH_BATCH`], minus those
    /// a request in `inflight` already asked for.
    pub fn next_batches(&self) -> Vec<Vec<Hash>> {
        let pending: HashSet<Hash> = self.inflight.iter().flat_map(|f| f.hashes.iter()).copied().collect();
        let wanted: Vec<Hash> = self.missing().into_iter().filter(|h| !pending.contains(h)).collect();
        wanted.chunks(TX_FETCH_BATCH).map(<[Hash]>::to_vec).collect()
    }

    /// Place what a peer returned: a transaction goes in only at a position whose hash is still
    /// missing and equals `tx.hash()`; a stranger, a duplicate or a marker-form body
    /// ([`is_marker_form`]) is discarded (spec §5.3). The
    /// position index is built once, so the cost is linear at the proposal cap. Returns how many
    /// were placed.
    pub fn accept(&mut self, txs: Vec<Transaction>) -> usize {
        let at: HashMap<Hash, usize> = self.compact.tx_hashes.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        let mut placed = 0;
        for tx in txs.into_iter().filter(|t| !is_marker_form(t)) {
            if let Some(&i) = at.get(&tx.hash()) {
                if self.have[i].is_none() {
                    self.have[i] = Some(tx);
                    placed += 1;
                }
            }
        }
        placed
    }

    /// Drop the requests sent more than `timeout` ago (the wire's own sync timeout): libp2p has
    /// either failed them already or never will, and left in place their hashes would never be
    /// asked of another peer (spec §5.3; the by-hash fetch's rule, audit v5). Returns how many
    /// were dropped; each was counted as an attempt when sent, and its peer stays asked.
    pub fn expire(&mut self, timeout: Duration, now: Instant) -> usize {
        let before = self.inflight.len();
        self.inflight.retain(|f| now.saturating_duration_since(f.sent) <= timeout);
        before - self.inflight.len()
    }

    pub fn complete(&self) -> bool {
        self.have.iter().all(Option::is_some)
    }

    /// The full block, once every body is in.
    pub fn into_block(self) -> Option<Block> {
        if !self.complete() {
            return None;
        }
        let txs = self.have.into_iter().flatten().collect();
        Some(self.compact.into_block(txs))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::storage::fixtures::key;
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::consensus::SigningDomain;
    use randprotocol_core::types::block::{BlockHeader, QuorumCertificate};

    fn mint(i: u8) -> Transaction {
        let envelope = randprotocol_core::notes::Envelope { kem_ct: vec![i; 8], to_receiver: vec![], to_sender: vec![], body: vec![] };
        Transaction::mint(7, [1; 8], 0, [u32::from(i); 8], envelope, 1, &key(1), &StubExecutor)
    }

    fn block_of(txs: Vec<Transaction>) -> Block {
        let k = key(1);
        let header = BlockHeader {
            height: 1,
            view: 1,
            parent: Hash::ZERO,
            proposer: k.public_key().clone(),
            timestamp_ms: 1,
            tx_root: Block::tx_root(&txs),
            state_root: Hash::ZERO,
            justify: QuorumCertificate::genesis(Hash::ZERO),
        };
        Block::sign(&SigningDomain::v0(Hash::ZERO), header, txs, &k)
    }

    #[test]
    fn the_recent_cache_is_fifo_by_count_and_bytes() {
        let mut c = RecentTxs::new(3, usize::MAX);
        let txs: Vec<Transaction> = (1..=4u8).map(mint).collect();
        for t in &txs[..3] {
            c.remember(t.clone());
        }
        assert_eq!(c.len(), 3);
        c.remember(txs[3].clone());
        assert!(c.get(&txs[0].hash()).is_none(), "the oldest went");
        assert!(c.get(&txs[3].hash()).is_some());
        let one = bincode::serialized_size(&txs[0]).unwrap() as usize;
        let mut b = RecentTxs::new(usize::MAX, one * 2);
        for t in &txs[..3] {
            b.remember(t.clone());
        }
        assert_eq!(b.len(), 2, "two fit the byte cap");
        assert!(b.bytes() <= one * 2);
        b.remember(txs[1].clone());
        assert_eq!(b.len(), 2, "remembering a held transaction is a no-op");
    }

    #[test]
    fn remember_block_keeps_every_body() {
        let txs: Vec<Transaction> = (1..=3u8).map(mint).collect();
        let mut c = RecentTxs::new(10, usize::MAX);
        c.remember_block(&block_of(txs.clone()));
        assert!(txs.iter().all(|t| c.get(&t.hash()).is_some()));
        assert!(!c.is_empty());
    }

    #[test]
    fn rebuild_finds_what_it_can_and_lists_the_rest_in_order() {
        let txs: Vec<Transaction> = (1..=3u8).map(mint).collect();
        let block = block_of(txs.clone());
        let compact = CompactBlock::of(&block);
        let all = rebuild(compact.clone(), |h| txs.iter().find(|t| &t.hash() == h).cloned());
        let Rebuilt::Block(b) = all else { panic!("complete") };
        assert_eq!(b, block);
        let some = rebuild(compact, |h| if *h == txs[1].hash() { None } else { txs.iter().find(|t| &t.hash() == h).cloned() });
        let Rebuilt::Missing { have, missing, .. } = some else { panic!("incomplete") };
        assert_eq!(missing, vec![txs[1].hash()]);
        assert_eq!(have.iter().filter(|t| t.is_some()).count(), 2);
    }

    #[test]
    fn a_park_accepts_only_what_it_asked_for_and_completes() {
        let txs: Vec<Transaction> = (1..=3u8).map(mint).collect();
        let block = block_of(txs.clone());
        let compact = CompactBlock::of(&block);
        let have = vec![Some(txs[0].clone()), None, None];
        let mut p = Parked::new(compact, have, PeerId::random(), Instant::now());
        assert_eq!(p.missing(), vec![txs[1].hash(), txs[2].hash()]);
        assert_eq!(p.next_batches(), vec![vec![txs[1].hash(), txs[2].hash()]]);
        let stranger = mint(9);
        assert_eq!(p.accept(vec![stranger, txs[2].clone()]), 1, "the stranger is discarded");
        assert!(!p.complete());
        assert_eq!(p.accept(vec![txs[1].clone(), txs[1].clone()]), 1, "a duplicate is not placed twice");
        assert!(p.complete());
        assert_eq!(p.into_block().unwrap(), block);
    }

    #[test]
    fn batches_skip_what_is_in_flight() {
        let txs: Vec<Transaction> = (1..=5u8).map(mint).collect();
        let block = block_of(txs.clone());
        let compact = CompactBlock::of(&block);
        let mut p = Parked::new(compact, vec![None; 5], PeerId::random(), Instant::now());
        assert_eq!(p.next_batches().len(), 1, "five hashes are one batch of the real size");
        let id = test_request_ids(1)[0];
        p.inflight.push(InFlight { id, peer: PeerId::random(), hashes: vec![txs[0].hash(), txs[1].hash()], sent: Instant::now() });
        assert_eq!(p.next_batches(), vec![txs[2..].iter().map(|t| t.hash()).collect::<Vec<_>>()]);
    }

    #[test]
    fn a_long_miss_list_is_chunked_by_the_batch_size() {
        let n = TX_FETCH_BATCH + 3;
        let txs: Vec<Transaction> = (0..n).map(|i| mint_n(i as u32)).collect();
        let block = block_of(txs);
        let p = Parked::new(CompactBlock::of(&block), vec![None; n], PeerId::random(), Instant::now());
        let b = p.next_batches();
        assert_eq!(b.iter().map(Vec::len).collect::<Vec<_>>(), vec![TX_FETCH_BATCH, 3]);
    }

    /// A request older than the timeout is dropped; a fresh one stays.
    #[test]
    fn expire_drops_only_requests_past_the_timeout() {
        let txs: Vec<Transaction> = (1..=2u8).map(mint).collect();
        let block = block_of(txs.clone());
        let mut p = Parked::new(CompactBlock::of(&block), vec![None; 2], PeerId::random(), Instant::now());
        let ids = test_request_ids(2);
        let now = Instant::now() + Duration::from_secs(60);
        let peer = PeerId::random();
        p.inflight.push(InFlight { id: ids[0], peer, hashes: vec![txs[0].hash()], sent: now - Duration::from_secs(31) });
        p.inflight.push(InFlight { id: ids[1], peer, hashes: vec![txs[1].hash()], sent: now - Duration::from_secs(5) });
        assert_eq!(p.expire(Duration::from_secs(30), now), 1);
        assert_eq!(p.inflight.iter().map(|f| f.id).collect::<Vec<_>>(), vec![ids[1]]);
        assert_eq!(p.expire(Duration::from_secs(30), now), 0);
    }

    /// Final review I7: a peer counts once however many batches it is sent; a `Busy` peer with
    /// nothing else out is uncounted and queued behind the others; asked again, it counts once.
    #[test]
    fn attempts_count_distinct_peers_and_not_busy_answers() {
        let txs: Vec<Transaction> = (1..=2u8).map(mint).collect();
        let mut p = Parked::new(CompactBlock::of(&block_of(txs.clone())), vec![None; 2], PeerId::random(), Instant::now());
        let (a, b) = (PeerId::random(), PeerId::random());
        let ids = test_request_ids(2);
        p.note_asked(a);
        p.note_asked(a);
        assert_eq!(p.attempts(), 1, "two batches to one peer are one attempt");
        p.inflight.push(InFlight { id: ids[0], peer: a, hashes: vec![txs[0].hash()], sent: Instant::now() });
        p.inflight.push(InFlight { id: ids[1], peer: a, hashes: vec![txs[1].hash()], sent: Instant::now() });
        p.inflight.retain(|f| f.id != ids[0]);
        p.note_busy(a);
        assert_eq!((p.attempts(), p.busy.len()), (1, 0), "a busy answer with another request out to the peer changes nothing");
        p.inflight.clear();
        p.note_busy(a);
        assert_eq!((p.attempts(), p.busy.clone()), (0, vec![a]), "busy: not counted, queued");
        p.note_asked(b);
        p.note_asked(a);
        assert_eq!((p.attempts(), p.busy.len()), (2, 0), "asked again, it counts once");
        assert!(p.wants(&txs[0].hash()));
        p.accept(vec![txs[0].clone()]);
        assert!(!p.wants(&txs[0].hash()), "a filled position is not wanted");
    }

    /// Final review I4: an answer stops before the body that would take it past the bound, so
    /// it is a prefix of what was found, within the bound; under the bound it is everything.
    #[test]
    fn an_answer_is_a_prefix_within_the_byte_bound() {
        let txs: Vec<Transaction> = (1..=4u8).map(mint).collect();
        let hashes: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
        let lookup = |h: &Hash| txs.iter().find(|t| t.hash() == *h);
        let one = bincode::serialized_size(&txs[0]).unwrap() as usize;
        let cut = bounded_answer(&hashes, lookup, 2 * one + one / 2);
        assert_eq!(cut, txs[..2].to_vec(), "a prefix, cut before the third");
        assert!(cut.iter().map(|t| bincode::serialized_size(t).unwrap() as usize).sum::<usize>() <= 2 * one + one / 2);
        assert_eq!(bounded_answer(&hashes, lookup, usize::MAX), txs, "under the bound: all of it");
        assert!(bounded_answer(&hashes, lookup, one - 1).is_empty(), "not even the first fits");
    }

    /// `tx` with its bundle proof in the pruned marker form: the same id, different bytes.
    fn marker_copy(tx: &Transaction) -> Transaction {
        let mut m = tx.clone();
        let b = m.bundle.as_mut().expect("a bundle transaction");
        b.proof = [randprotocol_core::notes::PRUNED_PROOF_MARKER, Hash::digest(&b.proof).as_bytes().as_slice()].concat();
        assert!(is_marker_form(&m) && !is_marker_form(tx));
        assert_eq!(m.hash(), tx.hash(), "the marker form keeps the id");
        m
    }

    /// A shielded transfer: a mint carries no bundle, so no proof to put in marker form.
    fn bundled(i: u32) -> Transaction {
        use crate::storage::fixtures::{bundle_fee, bundle_tx, genesis_of};
        let gs = genesis_of(7, &[&key(1)], Vec::new(), 2);
        bundle_tx(&gs.ledger, [[i; 8], [i + 100; 8]], [[i + 200; 8], [i + 300; 8]], bundle_fee())
    }

    /// The cache never holds a marker-form body (review finding I1): the real body, remembered
    /// after it, is the one a rebuild finds.
    #[test]
    fn the_recent_cache_skips_a_marker_form_body() {
        let tx = bundled(1);
        let mut c = RecentTxs::new(10, usize::MAX);
        c.remember(marker_copy(&tx));
        assert!(c.is_empty(), "not taken");
        c.remember(tx.clone());
        assert_eq!(c.get(&tx.hash()), Some(&tx));
    }

    /// A fetch answer carrying the marker form of a missing transaction does not fill its slot
    /// (review finding I1); the real body still does.
    #[test]
    fn a_park_refuses_a_marker_form_body() {
        let txs: Vec<Transaction> = (1..=2).map(bundled).collect();
        let block = block_of(txs.clone());
        let mut p = Parked::new(CompactBlock::of(&block), vec![Some(txs[0].clone()), None], PeerId::random(), Instant::now());
        assert_eq!(p.accept(vec![marker_copy(&txs[1])]), 0, "refused");
        assert_eq!(p.missing(), vec![txs[1].hash()]);
        assert_eq!(p.accept(vec![txs[1].clone()]), 1);
        assert_eq!(p.into_block().unwrap(), block);
    }

    /// `n` distinct request ids, from a real request-response behaviour (they cannot be made
    /// otherwise).
    pub(crate) fn test_request_ids(n: usize) -> Vec<OutboundRequestId> {
        let mut b = test_sync_behaviour();
        let peer = PeerId::random();
        (0..n).map(|_| b.send_request(&peer, crate::network::SyncRequest::Transactions(vec![]))).collect()
    }

    /// A sync behaviour with no swarm behind it: `send_request` only queues, and hands back an id.
    pub(crate) fn test_sync_behaviour(
    ) -> libp2p::request_response::Behaviour<crate::network::codec::Codec<crate::network::SyncRequest, crate::network::SyncResponse>> {
        use libp2p::request_response::{Behaviour, Config, ProtocolSupport};
        let codec = crate::network::codec::Codec::new(1 << 16, 1 << 20);
        Behaviour::with_codec(codec, [(libp2p::StreamProtocol::new("/rand/test/sync/1"), ProtocolSupport::Full)], Config::default())
    }

    fn mint_n(i: u32) -> Transaction {
        let envelope = randprotocol_core::notes::Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![] };
        Transaction::mint(7, [1; 8], 0, [i; 8], envelope, 1, &key(1), &StubExecutor)
    }
}
