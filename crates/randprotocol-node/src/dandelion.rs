//! Dandelion++ stem relay for transactions (issue #145; Fanti et al., "Dandelion++: Lightweight
//! Cryptocurrency Networking with Formal Anonymity Guarantees", 2018).
//!
//! Before this, a node broadcast a transaction it verified at once, and gossipsub's
//! `flood_publish` sent it straight to every peer: the chain-21 experiment found the first node to
//! hold a transaction was the node it was submitted to in 27 of 27 traces. Dandelion++ moves the
//! broadcast away from the submitter:
//!
//! - **Stem.** A transaction this node's own RPC accepted, or one a peer stemmed to it, goes to
//!   ONE peer over a direct request-response send (`/rand/{chain}/stem/1`, [`crate::network`]),
//!   not gossip. Each node keeps [`STEM_SUCCESSORS`] successors per epoch ([`EPOCH`], a local
//!   timer), drawn at random from the connected peers that advertise the stem protocol, preferring
//!   trusted peers — validators by their signed binding, the bootstraps and the operator's
//!   reserved peers — and taking at most one peer per public host (audit v12, PRIV-602: whether
//!   this node dialled a peer is no trust signal, since every identify-advertised address is
//!   redialled). Each incoming edge (a predecessor, or this node's own RPC) is
//!   mapped to one successor for the epoch ([`Router::route`]), so the routes a node uses are
//!   consistent: an adversary sending many transactions through one node learns one edge, not a
//!   fresh random walk per transaction.
//! - **Fluff.** At each relay hop the node fluffs instead of stemming with probability
//!   [`DandelionConfig::fluff_prob`] (q, default 0.1): it pools the transaction and publishes it on
//!   the anonymous gossip lane. The submitting node itself never fluffs by the coin.
//! - **Embargo.** Every node holding a stem transaction runs a timer
//!   ([`Dandelion::embargo_for`], one distribution at the submitter and at every relay); if the
//!   transaction has not come back to it over gossip by then, it fluffs it itself. That is the
//!   fail-safe against a successor that drops it (a black hole). A successor that does not
//!   acknowledge a stem within [`crate::network::STEM_REQUEST_TIMEOUT`] — under the embargo — is
//!   dropped and the transaction rerouted to the edge's other successor.
//! - **Loops.** A stem that comes back to a node already holding it is treated as a fresh
//!   arrival on that edge — the q coin, then the edge's successor — without a second verification
//!   ([`Dandelion::on_loop`]). In a fleet of 25 the walk revisits a node within a handful of hops;
//!   ending the stem at the first loop left 41% of transactions to the embargo in the 25-node
//!   simulation (`a_25_node_fleet_stem_ends_on_the_coin`), against none now. A holder answers a
//!   stem copy as a node that never saw it would (the coin, then the edge's route), so a peer
//!   probing with copies cannot pick the holders out — except by the verification a holder skips,
//!   which only the successor it forwards to can time. A node
//!   forwards one transaction at most [`MAX_STEM_FORWARDS`] times; past that it waits for its
//!   embargo (only q = 0 gets there in practice). The submitter, when a walk comes back to it,
//!   fluffs on the coin like any relay: in the 25-node simulation it was the fluffer of 5.6% of
//!   its own transactions, against 4% for a node chosen at random.
//! - **Stempool.** A stem transaction is verified like any other but kept in the [`Stempool`],
//!   not the mempool: no RPC, no `SyncRequest::Transactions`, no block proposal sees it until it
//!   is fluffed. Otherwise the mempool-probing attack the experiment ran would still work.
//!
//! The type here is pure: no network, no clock and no randomness of its own (`now` and the RNG
//! come in), so every rule above is unit-tested. The node loop drives it (`node.rs`).

use crate::network::edge::Source;
use libp2p::PeerId;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use randprotocol_core::{Hash, Transaction};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// How many stem successors a node keeps per epoch: two, as in Dandelion++ (the 4-regular
/// approximation of a line graph).
pub const STEM_SUCCESSORS: usize = 2;
/// How long one epoch's successors and edge mapping last (Dandelion++'s ~10 minutes). A local
/// timer, unsynchronised across nodes, so an observer cannot line epochs up.
pub const EPOCH: Duration = Duration::from_secs(600);
/// q: the per-hop probability that a relay fluffs instead of stemming. Expected stem length is
/// 1/q relays when nothing else ends it.
pub const DEFAULT_FLUFF_PROB: f64 = 0.1;
/// The embargo's fixed part (`--dandelion-embargo-ms`); see [`Dandelion::embargo_for`].
pub const DEFAULT_EMBARGO: Duration = Duration::from_millis(3000);
/// The most times one node sends one stem transaction on: once when it first verifies it, then
/// once per return of a looping stem. Past it the node waits for the embargo. Routes are fixed per
/// edge, so a walk that closes a cycle goes round it until a coin lands: at q = 0.1, 32 laps of the
/// shortest cycle (three nodes) all missing is 0.9^96, about 4e-5. At q = 0 (tests) this is what
/// ends the walk.
pub const MAX_STEM_FORWARDS: usize = 32;
/// New stem transactions (not loops) one peer may send back to back, each costing a
/// verification (`node::Node::on_stem_tx`): its own allowance, beside the gossip one
/// (`admission::PEER_TX_BURST`). An honest peer sends a node at most one first-time stem per
/// transaction routed through that edge.
pub const STEM_PEER_BURST: u32 = 32;
/// And the rate they recover at: twice the gossip allowance's, since a busy edge carries a
/// transaction's stem and, later, its gossip.
pub const STEM_PEER_PER_SEC: f64 = 8.0;
/// The most stem transactions held at once. Past it a new one is fluffed at once rather than
/// held: the stempool is never a reason to drop a valid transaction. The node's own submission is
/// the exception: it makes room by fluffing the oldest entry held for a peer
/// ([`Stempool::evict_relayed_for`], audit v13 PRIV-605).
pub const STEMPOOL_MAX: usize = 1024;
/// The most bytes of stem transactions held at once, by `Transaction::encoded_len`.
pub const STEMPOOL_MAX_BYTES: usize = 64 << 20;

/// The operator's Dandelion++ settings (`--dandelion`, `--dandelion-fluff-prob`,
/// `--dandelion-embargo-ms`).
#[derive(Clone, Debug)]
pub struct DandelionConfig {
    /// Stem transactions at all. Off, the node advertises no stem protocol, so no peer stems to it,
    /// and it publishes every transaction it accepts on gossip at once, as before v0.8.3.
    pub enabled: bool,
    /// q, in `[0, 1]`.
    pub fluff_prob: f64,
    /// The embargo's fixed part, `b`: every holder, the submitter included, waits
    /// `b + min(Exp(mean b/4), b)` ([`Dandelion::embargo_for`]).
    pub embargo: Duration,
    /// How long one epoch lasts ([`EPOCH`]). Configurable for tests only.
    pub epoch: Duration,
    /// Seed the RNG instead of drawing it from the OS. Tests only: a predictable RNG is a
    /// predictable route.
    pub seed: Option<u64>,
}

impl Default for DandelionConfig {
    fn default() -> DandelionConfig {
        DandelionConfig { enabled: true, fluff_prob: DEFAULT_FLUFF_PROB, embargo: DEFAULT_EMBARGO, epoch: EPOCH, seed: None }
    }
}

impl DandelionConfig {
    /// Dandelion off: every accepted transaction is published at once.
    pub fn off() -> DandelionConfig {
        DandelionConfig { enabled: false, ..DandelionConfig::default() }
    }
}

/// Where a stem transaction came from: this node's own RPC, or the peer that stemmed it here.
/// The key of the per-edge mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Edge {
    Local,
    Peer(PeerId),
}

/// What to do with a transaction that just verified on a stem edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Pool it and publish it on gossip.
    Fluff(FluffReason),
    /// Hold it in the stempool and send it to this successor.
    Stem(PeerId),
}

/// Why a transaction was fluffed: the counters in [`DandelionStats`] and the debug log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FluffReason {
    /// The q coin at a relay.
    Coin,
    /// No stem-capable peer to send it to (a fleet of older nodes, or Dandelion off).
    NoRoute,
    /// The stempool is full.
    Full,
    /// Its embargo expired before it came back over gossip.
    Embargo,
}

/// One stem-capable peer, as the router weighs it (audit v12, PRIV-602).
#[derive(Clone, Copy, Debug)]
struct Candidate {
    /// A validator's peer by its signed binding, a bootstrap, or an operator-reserved peer:
    /// identities a stranger cannot take on. Not "this node dialled it": identify-advertised
    /// addresses are redialled every 30 s, so any peer that connects once becomes a dialled one.
    trusted: bool,
    /// The public host it is connected from. At most one successor per host, and a host is one
    /// candidate however many identities it runs. `None` (loopback, a private network, no IP):
    /// a candidate of its own.
    host: Option<Source>,
}

/// The successors and the per-edge mapping of one epoch.
pub struct Router {
    epoch_len: Duration,
    epoch_started: Option<Instant>,
    epoch: u64,
    /// Connected peers that advertise the stem protocol.
    capable: HashMap<PeerId, Candidate>,
    successors: Vec<PeerId>,
    routes: HashMap<Edge, PeerId>,
}

impl Router {
    pub fn new(epoch_len: Duration) -> Router {
        Router { epoch_len, epoch_started: None, epoch: 0, capable: HashMap::new(), successors: Vec::new(), routes: HashMap::new() }
    }

    /// A connected peer advertises the stem protocol. `trusted`: see [`Candidate::trusted`];
    /// `host`: the public host it is connected from ([`Candidate::host`]). A free successor slot
    /// is filled at once, so a node that starts with no capable peer stems as soon as one
    /// arrives. Repeated (identify runs again), it refreshes the peer's host and trust.
    pub fn add_peer(&mut self, peer: PeerId, trusted: bool, host: Option<Source>, rng: &mut StdRng) {
        self.capable.insert(peer, Candidate { trusted, host });
        self.fill(rng);
    }

    /// A peer's trust changed (its binding was recorded or superseded). Successors already drawn
    /// keep their slot until the epoch ends or they leave.
    pub fn set_trusted(&mut self, peer: &PeerId, trusted: bool) {
        if let Some(c) = self.capable.get_mut(peer) {
            c.trusted = trusted;
        }
    }

    /// A peer left (or failed a stem send): never a successor again until it is re-added. A
    /// successor it held is replaced, and every edge mapped to it is drawn again on next use.
    pub fn remove_peer(&mut self, peer: &PeerId, rng: &mut StdRng) {
        self.capable.remove(peer);
        if let Some(i) = self.successors.iter().position(|p| p == peer) {
            self.successors.remove(i);
            self.routes.retain(|_, s| s != peer);
            self.fill(rng);
        }
    }

    /// Top the successors up to [`STEM_SUCCESSORS`] from the capable peers that are not one
    /// already: trusted peers first, then the rest (audit v12, PRIV-602). Within each, the draw
    /// is over hosts, not identities — a host is picked uniformly, then one of its peers — and a
    /// host that already holds a successor slot is not drawn again, so identities an adversary
    /// runs on one address count once.
    /// The candidates are sorted before the draw, so a seeded RNG gives the same successors
    /// whatever order the map iterates in.
    fn fill(&mut self, rng: &mut StdRng) {
        for want_trusted in [true, false] {
            if self.successors.len() >= STEM_SUCCESSORS {
                return;
            }
            let taken: Vec<Source> = self.successors.iter().filter_map(|p| self.capable.get(p).and_then(|c| c.host)).collect();
            // Per host, its peers; a peer without a public host is a group of its own.
            let mut groups: Vec<(Option<Source>, Vec<PeerId>)> = Vec::new();
            let mut members: Vec<(PeerId, Option<Source>)> = self
                .capable
                .iter()
                .filter(|(p, c)| c.trusted == want_trusted && !self.successors.contains(p))
                .filter(|(_, c)| c.host.is_none_or(|h| !taken.contains(&h)))
                .map(|(p, c)| (*p, c.host))
                .collect();
            members.sort_by_key(|(p, _)| *p);
            for (p, h) in members {
                match h.and_then(|h| groups.iter_mut().find(|(g, _)| *g == Some(h))) {
                    Some((_, list)) => list.push(p),
                    None => groups.push((h, vec![p])),
                }
            }
            while self.successors.len() < STEM_SUCCESSORS && !groups.is_empty() {
                let (_, list) = groups.swap_remove(rng.gen_range(0..groups.len()));
                self.successors.push(list[rng.gen_range(0..list.len())]);
            }
        }
    }

    /// Start a new epoch when the current one is over (or none has started): fresh successors,
    /// an empty edge mapping.
    fn maybe_rotate(&mut self, now: Instant, rng: &mut StdRng) {
        let due = match self.epoch_started {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.epoch_len,
        };
        if due {
            self.epoch_started = Some(now);
            self.epoch += 1;
            self.successors.clear();
            self.routes.clear();
            self.fill(rng);
        }
    }

    /// The successor for a transaction that arrived on `from`, the same one for every
    /// transaction on that edge for the rest of the epoch. A predecessor is never sent its own
    /// transaction back: that is a loop at once. `None`: no stem-capable peer but the sender —
    /// the node then fluffs, which in a network that small hides nothing anyway.
    pub fn route(&mut self, from: Edge, now: Instant, rng: &mut StdRng) -> Option<PeerId> {
        self.maybe_rotate(now, rng);
        if let Some(s) = self.routes.get(&from) {
            return Some(*s);
        }
        let back = match from {
            Edge::Peer(p) => Some(p),
            Edge::Local => None,
        };
        let candidates: Vec<PeerId> = self.successors.iter().copied().filter(|s| Some(*s) != back).collect();
        let pick = candidates.choose(rng).copied()?;
        self.routes.insert(from, pick);
        Some(pick)
    }

    pub fn successors(&self) -> &[PeerId] {
        &self.successors
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn capable(&self) -> usize {
        self.capable.len()
    }
}

/// One held stem transaction.
struct StemEntry {
    tx: Transaction,
    bytes: usize,
    origin: Edge,
    deadline: Instant,
    /// The successors it was sent to, in order.
    sent_to: Vec<PeerId>,
    /// Its place in the order of holding ([`Stempool::evict_relayed_for`]'s "oldest").
    seq: u64,
}

/// Verified stem transactions, invisible to everything but the node loop until fluffed.
pub struct Stempool {
    entries: HashMap<Hash, StemEntry>,
    bytes: usize,
    max: usize,
    max_bytes: usize,
    next_seq: u64,
}

impl Stempool {
    pub fn new(max: usize, max_bytes: usize) -> Stempool {
        Stempool { entries: HashMap::new(), bytes: 0, max, max_bytes, next_seq: 0 }
    }

    /// Whether a `bytes`-long transaction fits under both caps now.
    fn fits(&self, bytes: usize) -> bool {
        self.entries.len() < self.max && self.bytes + bytes <= self.max_bytes
    }

    /// Audit v13, PRIV-605: room for a `bytes`-long transaction of this node's own — the oldest
    /// entries held for peers, taken out (for the caller to fluff) until both caps fit it. Before,
    /// a full stempool fluffed the node's own submission at once, so the submitter published it
    /// first. Entries of the node's own (`Edge::Local`) are never taken, and nothing is taken when
    /// taking every relayed entry would still not make room: the caller then fluffs as before.
    pub fn evict_relayed_for(&mut self, bytes: usize) -> Vec<(Hash, Transaction)> {
        let (own_len, own_bytes) = self
            .entries
            .values()
            .filter(|e| e.origin == Edge::Local)
            .fold((0usize, 0usize), |(n, b), e| (n + 1, b + e.bytes));
        if own_len >= self.max || own_bytes + bytes > self.max_bytes {
            return Vec::new();
        }
        let mut out = Vec::new();
        while !self.fits(bytes) {
            let Some(h) = self.entries.iter().filter(|(_, e)| e.origin != Edge::Local).min_by_key(|(_, e)| e.seq).map(|(h, _)| *h) else {
                break;
            };
            if let Some(tx) = self.take(&h) {
                out.push((h, tx));
            }
        }
        out
    }

    /// Hold `tx` until `deadline`; `false` (nothing held) when it would go over either cap.
    pub fn hold(&mut self, hash: Hash, tx: Transaction, origin: Edge, deadline: Instant) -> bool {
        if self.entries.contains_key(&hash) {
            return true;
        }
        let bytes = tx.encoded_len();
        if !self.fits(bytes) {
            return false;
        }
        self.bytes += bytes;
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(hash, StemEntry { tx, bytes, origin, deadline, sent_to: Vec::new(), seq });
        true
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.entries.contains_key(hash)
    }

    /// Record that `hash` went to `peer`.
    pub fn sent(&mut self, hash: &Hash, peer: PeerId) {
        if let Some(e) = self.entries.get_mut(hash) {
            e.sent_to.push(peer);
        }
    }

    /// Where `hash` came from and the successors it went to.
    pub fn route_of(&self, hash: &Hash) -> Option<(Edge, &[PeerId])> {
        self.entries.get(hash).map(|e| (e.origin, e.sent_to.as_slice()))
    }

    pub fn tx(&self, hash: &Hash) -> Option<&Transaction> {
        self.entries.get(hash).map(|e| &e.tx)
    }

    /// Remove `hash`: it was fluffed, here or by another node.
    pub fn take(&mut self, hash: &Hash) -> Option<Transaction> {
        let e = self.entries.remove(hash)?;
        self.bytes -= e.bytes;
        Some(e.tx)
    }

    /// Every transaction whose embargo has run out by `now`, removed.
    pub fn expired(&mut self, now: Instant) -> Vec<(Hash, Transaction)> {
        let due: Vec<Hash> = self.entries.iter().filter(|(_, e)| e.deadline <= now).map(|(h, _)| *h).collect();
        due.into_iter().filter_map(|h| self.take(&h).map(|tx| (h, tx))).collect()
    }

    /// The earliest embargo, for the node loop's timer.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries.values().map(|e| e.deadline).min()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What the node did with stem traffic, for tests and the debug log. Deliberately **not** in the
/// RPC status: a counter of stems received, polled, tells a prober the moment a node joins a
/// stem, which is what the stempool exists to hide.
#[derive(Debug, Default)]
pub struct DandelionStats {
    /// Stem-capable peers connected now.
    pub stem_peers: AtomicUsize,
    /// Stem transactions received from peers (before verification).
    pub stem_received: AtomicU64,
    /// Stem sends to a successor.
    pub stem_sent: AtomicU64,
    pub fluff_coin: AtomicU64,
    pub fluff_no_route: AtomicU64,
    pub fluff_full: AtomicU64,
    pub fluff_embargo: AtomicU64,
    /// A stem transaction that came back to a node holding it and was sent on.
    pub loop_restem: AtomicU64,
    /// One that came back past [`MAX_STEM_FORWARDS`] and was left to the embargo.
    pub loop_absorbed: AtomicU64,
}

impl DandelionStats {
    pub fn get(&self, field: impl Fn(&DandelionStats) -> &AtomicU64) -> u64 {
        field(self).load(Ordering::Relaxed)
    }

    pub(crate) fn bump(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_fluff(&self, why: FluffReason) {
        Self::bump(match why {
            FluffReason::Coin => &self.fluff_coin,
            FluffReason::NoRoute => &self.fluff_no_route,
            FluffReason::Full => &self.fluff_full,
            FluffReason::Embargo => &self.fluff_embargo,
        });
    }
}

/// What a stem transaction that is already in the stempool should do now (see
/// [`Dandelion::on_loop`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopAction {
    /// Send it on to this successor.
    Restem(PeerId),
    /// Take it out of the stempool, pool it and publish it.
    Fluff(FluffReason),
    /// Nothing: its embargo will fluff it.
    Absorb,
}

/// The node's Dandelion++ state: configuration, router, stempool and RNG.
pub struct Dandelion {
    pub cfg: DandelionConfig,
    pub router: Router,
    pub stempool: Stempool,
    pub rng: StdRng,
}

impl Dandelion {
    pub fn new(cfg: DandelionConfig) -> Dandelion {
        let rng = match cfg.seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };
        Dandelion { router: Router::new(cfg.epoch), stempool: Stempool::new(STEMPOOL_MAX, STEMPOOL_MAX_BYTES), rng, cfg }
    }

    /// Where a transaction that just verified on edge `from` goes. The submitter (`Local`) never
    /// fluffs by the coin; a relay does with probability q.
    pub fn decide(&mut self, from: Edge, now: Instant) -> Decision {
        if !self.cfg.enabled {
            return Decision::Fluff(FluffReason::NoRoute);
        }
        if self.stempool.len() >= self.stempool.max {
            return Decision::Fluff(FluffReason::Full);
        }
        if matches!(from, Edge::Peer(_)) && self.fluff_coin() {
            return Decision::Fluff(FluffReason::Coin);
        }
        match self.router.route(from, now, &mut self.rng) {
            Some(p) => Decision::Stem(p),
            None => Decision::Fluff(FluffReason::NoRoute),
        }
    }

    /// The q coin.
    pub fn fluff_coin(&mut self) -> bool {
        let q = self.cfg.fluff_prob.clamp(0.0, 1.0);
        self.rng.gen_bool(q)
    }

    /// How long a node holding a stem transaction waits before fluffing it itself, where `b` is
    /// [`DandelionConfig::embargo`]: `b + min(Exp(mean b/4), b)`, so in `[b, 2b]`, wherever the
    /// transaction came from (audit v12, PRIV-604).
    ///
    /// Random, so the holder whose timer fires first is a random node of the stem, not the one
    /// that started first. The submitter draws from the same distribution as every relay: before,
    /// its embargo was `2b + Exp(b/4)`, never under any relay's, so a successor that dropped the
    /// stem could tell from the delay alone whether the node that fluffed it was the origin. Now
    /// the windows coincide and the delay says nothing about it. `origin` is kept for the caller's
    /// bookkeeping; it no longer changes the draw.
    pub fn embargo_for(&mut self, _origin: Edge) -> Duration {
        let b = self.cfg.embargo;
        // Exp(1) by inversion; `gen::<f64>()` is in [0, 1), so `1 - u` is in (0, 1].
        let u: f64 = self.rng.gen();
        let exp = -(1.0 - u).ln() * (b.as_secs_f64() / 4.0);
        b + Duration::from_secs_f64(exp.min(b.as_secs_f64()))
    }

    /// Hold a verified stem transaction from `origin` under a fresh embargo. `false`: the
    /// stempool is full.
    pub fn hold(&mut self, hash: Hash, tx: Transaction, origin: Edge, now: Instant) -> bool {
        let wait = self.embargo_for(origin);
        self.stempool.hold(hash, tx, origin, now + wait)
    }

    /// A stem copy of `hash`, which this node already holds, arrived from `from`: the stem came
    /// back to it. Decided as a fresh arrival on that edge would be — the q coin, then the edge's
    /// successor — so the walk goes on to a fluff instead of stopping at the first loop, and the
    /// answer a holder gives is the answer a node that never saw it would give. Past
    /// [`MAX_STEM_FORWARDS`] sends of this transaction, its embargo fluffs it.
    pub fn on_loop(&mut self, hash: &Hash, from: PeerId, now: Instant) -> LoopAction {
        let Some((_, sent)) = self.stempool.route_of(hash) else { return LoopAction::Absorb };
        if sent.len() >= MAX_STEM_FORWARDS {
            return LoopAction::Absorb;
        }
        match self.decide(Edge::Peer(from), now) {
            Decision::Stem(p) => LoopAction::Restem(p),
            Decision::Fluff(why) => LoopAction::Fluff(why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    fn peers(n: usize) -> Vec<PeerId> {
        (0..n).map(|_| PeerId::random()).collect()
    }

    fn tx(n: u64) -> Transaction {
        Transaction { chain_id: n, bundle: None, action: randprotocol_core::Action::None }
    }

    fn router_with(ps: &[PeerId], trusted: bool, r: &mut StdRng) -> Router {
        let mut router = Router::new(EPOCH);
        for p in ps {
            router.add_peer(*p, trusted, None, r);
        }
        router
    }

    fn host(n: u8) -> Option<Source> {
        Some(Source::V4(std::net::Ipv4Addr::new(203, 0, 113, n)))
    }

    /// Within an epoch, every transaction on one edge goes to the same successor, the submitter's
    /// own included, and only two successors are ever used, whatever the number of edges.
    #[test]
    fn each_edge_keeps_one_successor_for_the_epoch() {
        let mut r = rng(1);
        let ps = peers(8);
        let mut router = router_with(&ps, true, &mut r);
        let t = Instant::now();
        let mut used = std::collections::HashSet::new();
        for (i, pred) in ps.iter().enumerate() {
            let first = router.route(Edge::Peer(*pred), t, &mut r).unwrap();
            assert_ne!(first, *pred, "a predecessor is not sent its own transaction back");
            for k in 0..20 {
                let again = router.route(Edge::Peer(*pred), t + Duration::from_secs(k), &mut r).unwrap();
                assert_eq!(again, first, "edge {i}: the same successor every time within the epoch");
            }
            used.insert(first);
        }
        let local = router.route(Edge::Local, t, &mut r).unwrap();
        for _ in 0..20 {
            assert_eq!(router.route(Edge::Local, t, &mut r), Some(local), "the submitter's own route is fixed too");
        }
        used.insert(local);
        assert_eq!(router.successors().len(), STEM_SUCCESSORS);
        assert!(used.len() <= STEM_SUCCESSORS, "only the epoch's two successors carry stems: {used:?}");
        assert!(used.iter().all(|u| router.successors().contains(u)));
        // Across edges both successors are used (the mapping is per edge, not one global route).
        assert_eq!(used.len(), 2, "eight predecessors and the submitter all mapped to one successor");
    }

    /// At an epoch boundary the successors and the edge mapping are drawn again; before it they
    /// are not.
    #[test]
    fn the_successors_and_routes_rotate_at_the_epoch() {
        let mut r = rng(2);
        let ps = peers(12);
        let mut router = Router::new(Duration::from_secs(600));
        for p in &ps {
            router.add_peer(*p, true, None, &mut r);
        }
        let t0 = Instant::now();
        let route0 = router.route(Edge::Local, t0, &mut r).unwrap();
        let epoch0 = router.epoch();
        let succ0 = router.successors().to_vec();
        assert_eq!(router.route(Edge::Local, t0 + Duration::from_secs(599), &mut r), Some(route0));
        assert_eq!(router.epoch(), epoch0, "no rotation inside the epoch");
        // Over many epochs the successor set changes (12 peers, 66 pairs): rotation is a real draw.
        let mut changed = false;
        let mut t = t0;
        for _ in 0..10 {
            t += Duration::from_secs(600);
            router.route(Edge::Local, t, &mut r).unwrap();
            let mut a = router.successors().to_vec();
            let mut b = succ0.clone();
            a.sort();
            b.sort();
            changed |= a != b;
        }
        assert_eq!(router.epoch(), epoch0 + 10, "one rotation per elapsed epoch");
        assert!(changed, "ten epochs drew the same two successors every time");
    }

    /// A successor that leaves is replaced at once, and the edges that mapped to it are drawn
    /// again; a peer that never advertised the stem is never a successor.
    #[test]
    fn a_departed_successor_is_replaced_and_its_edges_remapped() {
        let mut r = rng(3);
        let ps = peers(3);
        let mut router = router_with(&ps, true, &mut r);
        let t = Instant::now();
        let s = router.route(Edge::Local, t, &mut r).unwrap();
        router.remove_peer(&s, &mut r);
        assert_eq!(router.successors().len(), 2, "the third peer fills the slot");
        assert!(!router.successors().contains(&s));
        let s2 = router.route(Edge::Local, t, &mut r).unwrap();
        assert_ne!(s2, s);
        // With no capable peer left there is no route.
        for p in &ps {
            router.remove_peer(p, &mut r);
        }
        assert_eq!(router.route(Edge::Local, t, &mut r), None);
        assert_eq!(router.capable(), 0);
    }

    /// Audit v12, PRIV-602: trusted peers — validators by their signed binding, the bootstraps
    /// and the operator's reserved peers — are preferred, and nothing else is: with two of them
    /// among thirty-two (the rest connected, dialled or not, as identify-learned addresses are
    /// redialled), they are the successors in every epoch.
    #[test]
    fn trusted_peers_are_preferred_as_successors() {
        let mut r = rng(4);
        let others = peers(30);
        let trusted = peers(2);
        let mut router = Router::new(Duration::from_secs(1));
        for (i, p) in others.iter().enumerate() {
            router.add_peer(*p, false, host(i as u8 + 1), &mut r);
        }
        for (i, p) in trusted.iter().enumerate() {
            router.add_peer(*p, true, host(100 + i as u8), &mut r);
        }
        let t0 = Instant::now();
        for k in 0..20 {
            router.route(Edge::Local, t0 + Duration::from_secs(k), &mut r).unwrap();
            let mut s = router.successors().to_vec();
            s.sort();
            let mut d = trusted.clone();
            d.sort();
            assert_eq!(s, d, "epoch {k}: an untrusted peer took a successor slot");
        }
        // A peer's trust follows its binding: lost, it competes with the rest from the next epoch.
        router.set_trusted(&trusted[0], false);
        router.route(Edge::Local, t0 + Duration::from_secs(100), &mut r).unwrap();
        assert!(router.successors().contains(&trusted[1]));
    }

    /// Audit v12, PRIV-602: many identities on one host count as one candidate. Twenty-four
    /// identities behind one public address against twelve honest peers on hosts of their own,
    /// none trusted (the worst case: every one of them dialled by the 30 s redial): the crowd
    /// holds at most one successor slot, never both, and takes the submitter's own route in about
    /// 1/13 of epochs — one host among thirteen — not the 65% it took when every connected
    /// identity was a candidate. Peers with no global address (loopback, a LAN) are not grouped.
    #[test]
    fn a_crowd_of_identities_on_one_host_takes_at_most_its_hosts_share() {
        let mut r = rng(11);
        let crowd = peers(24);
        let honest = peers(12);
        let mut router = Router::new(Duration::from_secs(1));
        for p in &crowd {
            router.add_peer(*p, false, host(66), &mut r);
        }
        for (i, p) in honest.iter().enumerate() {
            router.add_peer(*p, false, host(i as u8 + 1), &mut r);
        }
        let t0 = Instant::now();
        let epochs = 4000;
        let mut taken = 0;
        for k in 0..epochs {
            let s = router.route(Edge::Local, t0 + Duration::from_secs(k), &mut r).unwrap();
            assert_eq!(router.successors().len(), 2);
            let in_crowd = router.successors().iter().filter(|p| crowd.contains(p)).count();
            assert!(in_crowd <= 1, "epoch {k}: one host held both successor slots");
            taken += usize::from(crowd.contains(&s));
        }
        let share = taken as f64 / epochs as f64;
        eprintln!("PRIV-602: 24 identities on one host vs 12 honest hosts: the crowd took the submitter's route in {:.1}% of epochs", 100.0 * share);
        assert!(share < 0.10, "the crowd took the submitter's route in {share} of epochs (one host in 13 is 0.077)");
        // A crowd that filled every slot before is still held to one when it is all there is.
        let mut alone = Router::new(Duration::from_secs(1));
        for p in &crowd {
            alone.add_peer(*p, false, host(66), &mut r);
        }
        alone.route(Edge::Local, t0, &mut r).unwrap();
        assert_eq!(alone.successors().len(), 1, "one host, one successor");
        // Peers without a global address are each their own candidate (a loopback test fleet, a LAN).
        let local = router_with(&peers(3), false, &mut r);
        assert_eq!(local.successors().len(), 2);
    }

    /// The fluff coin with a seeded RNG: q = 0 never, q = 1 always, q = 0.1 about one hop in ten,
    /// and the same seed the same sequence. The submitter never fluffs by the coin.
    #[test]
    fn the_fluff_decision_follows_q_and_the_seed() {
        let ps = peers(3);
        let make = |q: f64, seed: u64| {
            let mut d = Dandelion::new(DandelionConfig { fluff_prob: q, seed: Some(seed), ..Default::default() });
            for p in &ps {
                d.router.add_peer(*p, true, None, &mut rng(9));
            }
            d
        };
        let t = Instant::now();
        let pred = Edge::Peer(PeerId::random());
        let mut never = make(0.0, 1);
        assert!((0..1000).all(|_| matches!(never.decide(pred, t), Decision::Stem(_))));
        let mut always = make(1.0, 1);
        assert!((0..1000).all(|_| always.decide(pred, t) == Decision::Fluff(FluffReason::Coin)));
        assert!((0..1000).all(|_| matches!(always.decide(Edge::Local, t), Decision::Stem(_))), "the submitter always stems");
        let mut tenth = make(0.1, 7);
        let n = 20_000;
        let fluffs = (0..n).filter(|_| tenth.decide(pred, t) == Decision::Fluff(FluffReason::Coin)).count();
        let rate = fluffs as f64 / n as f64;
        assert!((0.09..0.11).contains(&rate), "q = 0.1 fluffed {rate}");
        let seq = |seed| {
            let mut d = make(0.5, seed);
            (0..64).map(|_| d.fluff_coin()).collect::<Vec<_>>()
        };
        assert_eq!(seq(42), seq(42), "one seed, one sequence");
        assert_ne!(seq(42), seq(43));
    }

    /// No stem-capable peer, or Dandelion off: fluff at once, as before v0.8.3.
    #[test]
    fn without_a_stem_peer_or_with_dandelion_off_the_node_fluffs_at_once() {
        let t = Instant::now();
        let mut lonely = Dandelion::new(DandelionConfig { seed: Some(1), ..Default::default() });
        assert_eq!(lonely.decide(Edge::Local, t), Decision::Fluff(FluffReason::NoRoute));
        // A relay whose only stem peer is the one that sent it the transaction does not send it
        // straight back; it fluffs. The submitter with that one peer stems to it.
        let only = PeerId::random();
        let mut pair = Dandelion::new(DandelionConfig { fluff_prob: 0.0, seed: Some(1), ..Default::default() });
        pair.router.add_peer(only, true, None, &mut rng(1));
        assert_eq!(pair.decide(Edge::Peer(only), t), Decision::Fluff(FluffReason::NoRoute));
        assert_eq!(pair.decide(Edge::Local, t), Decision::Stem(only));
        let mut off = Dandelion::new(DandelionConfig { seed: Some(1), ..DandelionConfig::off() });
        off.router.add_peer(PeerId::random(), true, None, &mut rng(1));
        assert_eq!(off.decide(Edge::Local, t), Decision::Fluff(FluffReason::NoRoute));
    }

    /// The embargo (audit v12, PRIV-604): one distribution at the submitter and at a relay,
    /// `b + min(Exp(b/4), b)`, so in `[b, 2b]` and about `1.25 b` on average at both;
    /// reproducible from the seed.
    #[test]
    fn the_embargo_is_base_plus_a_capped_exponential_everywhere() {
        let b = Duration::from_millis(2000);
        let mut d = Dandelion::new(DandelionConfig { embargo: b, seed: Some(5), ..Default::default() });
        let n = 20_000;
        let relay: Vec<Duration> = (0..n).map(|_| d.embargo_for(Edge::Peer(PeerId::random()))).collect();
        let local: Vec<Duration> = (0..n).map(|_| d.embargo_for(Edge::Local)).collect();
        assert!(relay.iter().all(|w| *w >= b && *w <= 2 * b), "a relay's embargo is in [b, 2b]");
        assert!(local.iter().all(|w| *w >= b && *w <= 2 * b), "the submitter's is in [b, 2b] too");
        let mean = |v: &[Duration]| v.iter().map(|w| w.as_secs_f64()).sum::<f64>() / v.len() as f64;
        // b + (b/4)(1 - e^-4) at both.
        assert!((2.46..2.52).contains(&mean(&relay)), "relay mean {}", mean(&relay));
        assert!((2.46..2.52).contains(&mean(&local)), "submitter mean {}", mean(&local));
        // P(Exp(b/4) < b/4) = 1 - 1/e: most fire in the first quarter of the window.
        assert!(relay.iter().filter(|w| **w < Duration::from_millis(2500)).count() > n / 2, "most relays fire early in the window");
        let mut a = Dandelion::new(DandelionConfig { embargo: b, seed: Some(5), ..Default::default() });
        let mut c = Dandelion::new(DandelionConfig { embargo: b, seed: Some(5), ..Default::default() });
        assert_eq!(a.embargo_for(Edge::Local), c.embargo_for(Edge::Local));
    }

    /// Audit v12, PRIV-604: the submitter's and a relay's embargo windows overlap entirely, so the
    /// time from a stem leaving a node to that node's own fluff does not say whether the node was
    /// the origin. Before, a relay fired in `[b, 2b]` and the submitter never under `2b`: a
    /// successor that dropped the stem could tell the two apart by the clock. Every decile of the
    /// two empirical distributions agrees to within 2% of `b`.
    #[test]
    fn the_submitter_and_relay_embargoes_overlap() {
        let b = Duration::from_millis(3000);
        let mut d = Dandelion::new(DandelionConfig { embargo: b, seed: Some(9), ..Default::default() });
        let n = 20_000;
        let mut relay: Vec<f64> = (0..n).map(|_| d.embargo_for(Edge::Peer(PeerId::random())).as_secs_f64()).collect();
        let mut local: Vec<f64> = (0..n).map(|_| d.embargo_for(Edge::Local).as_secs_f64()).collect();
        relay.sort_by(f64::total_cmp);
        local.sort_by(f64::total_cmp);
        for q in 1..10 {
            let i = n * q / 10;
            let gap = (relay[i] - local[i]).abs();
            assert!(gap < 0.02 * b.as_secs_f64(), "decile {q}: relay {:.3} s, submitter {:.3} s", relay[i], local[i]);
        }
        // Half the submitter's draws are under 1.25 b, where most relay draws also fall.
        let under = local.iter().filter(|w| **w < 1.25 * b.as_secs_f64()).count();
        assert!(under > n / 2, "only {under} of {n} submitter embargoes under 1.25 b");
    }

    /// Audit v12, PRIV-604: a stem send that is not acknowledged fails, and the node reroutes it
    /// to the edge's other successor, well before the shortest embargo (`b`) would have fluffed it:
    /// the acknowledgement timeout is under the default `b` with room for the second send.
    #[test]
    fn a_silent_successor_times_out_before_the_embargo() {
        assert!(
            crate::network::STEM_REQUEST_TIMEOUT * 2 <= DEFAULT_EMBARGO,
            "ack timeout {:?} leaves no time to reroute inside the {:?} embargo",
            crate::network::STEM_REQUEST_TIMEOUT,
            DEFAULT_EMBARGO
        );
    }

    /// The embargo fail-safe in the stempool: a held transaction comes out exactly when its timer
    /// runs out, the timer is what the loop sleeps to, and one fluffed early (it came back over
    /// gossip) is no longer held.
    #[test]
    fn the_stempool_releases_each_transaction_at_its_embargo() {
        let mut pool = Stempool::new(8, 1 << 20);
        let t = Instant::now();
        let (a, b, c) = (tx(1), tx(2), tx(3));
        assert!(pool.hold(a.hash(), a.clone(), Edge::Local, t + Duration::from_secs(5)));
        assert!(pool.hold(b.hash(), b.clone(), Edge::Peer(PeerId::random()), t + Duration::from_secs(2)));
        assert!(pool.hold(c.hash(), c.clone(), Edge::Peer(PeerId::random()), t + Duration::from_secs(3)));
        assert_eq!(pool.next_deadline(), Some(t + Duration::from_secs(2)));
        assert!(pool.expired(t + Duration::from_millis(1999)).is_empty(), "nothing before its embargo");
        assert_eq!(pool.expired(t + Duration::from_secs(2)), vec![(b.hash(), b.clone())]);
        assert_eq!(pool.take(&c.hash()), Some(c.clone()), "came back over gossip: taken early");
        assert!(pool.expired(t + Duration::from_secs(4)).is_empty(), "a taken one never fires");
        assert_eq!(pool.next_deadline(), Some(t + Duration::from_secs(5)));
        assert_eq!(pool.expired(t + Duration::from_secs(60)), vec![(a.hash(), a)]);
        assert!(pool.is_empty() && pool.next_deadline().is_none());
    }

    /// Both caps refuse rather than evict; the node then fluffs a relayed newcomer (its own
    /// submission makes room instead: PRIV-605, below).
    #[test]
    fn the_stempool_refuses_past_its_caps() {
        let t = Instant::now();
        let mut pool = Stempool::new(2, 1 << 20);
        assert!(pool.hold(tx(1).hash(), tx(1), Edge::Local, t));
        assert!(pool.hold(tx(2).hash(), tx(2), Edge::Local, t));
        assert!(!pool.hold(tx(3).hash(), tx(3), Edge::Local, t), "count cap");
        assert!(pool.hold(tx(1).hash(), tx(1), Edge::Local, t), "holding one again is not growth");
        let one = tx(1).encoded_len();
        let mut small = Stempool::new(8, one);
        assert!(small.hold(tx(1).hash(), tx(1), Edge::Local, t));
        assert!(!small.hold(tx(2).hash(), tx(2), Edge::Local, t), "byte cap");
        small.take(&tx(1).hash());
        assert!(small.hold(tx(2).hash(), tx(2), Edge::Local, t), "bytes come back when one leaves");
        let mut d = Dandelion::new(DandelionConfig { seed: Some(1), ..Default::default() });
        d.router.add_peer(PeerId::random(), true, None, &mut rng(1));
        d.stempool = Stempool::new(0, 0);
        assert_eq!(d.decide(Edge::Local, t), Decision::Fluff(FluffReason::Full));
    }

    /// Audit v13, PRIV-605: room for the node's own transaction comes from the oldest entries held
    /// for peers, never from its own, and only as many as the caps need; nothing is taken when
    /// taking every relayed entry would still not make room.
    #[test]
    fn room_for_an_own_submission_comes_from_the_oldest_relayed_entries() {
        let t = Instant::now();
        let peer = Edge::Peer(PeerId::random());
        let one = tx(1).encoded_len();
        let mut pool = Stempool::new(3, 1 << 20);
        assert!(pool.hold(tx(1).hash(), tx(1), Edge::Local, t));
        assert!(pool.hold(tx(2).hash(), tx(2), peer, t + Duration::from_secs(9)));
        assert!(pool.hold(tx(3).hash(), tx(3), peer, t));
        assert!(pool.evict_relayed_for(one).iter().map(|(h, _)| *h).eq([tx(2).hash()]), "the oldest held, not the earliest deadline");
        assert!(pool.hold(tx(4).hash(), tx(4), Edge::Local, t));
        assert!(pool.evict_relayed_for(one).iter().map(|(h, _)| *h).eq([tx(3).hash()]));
        assert!(pool.hold(tx(5).hash(), tx(5), Edge::Local, t));
        assert!(pool.evict_relayed_for(one).is_empty(), "every entry the node's own: nothing to take");
        assert_eq!(pool.len(), 3);
        // The byte cap: as many relayed entries as it takes, oldest first.
        let mut small = Stempool::new(8, 3 * one);
        for i in 1..=3 {
            assert!(small.hold(tx(i).hash(), tx(i), peer, t));
        }
        let big = 2 * one;
        assert!(small.evict_relayed_for(big).iter().map(|(h, _)| *h).eq([tx(1).hash(), tx(2).hash()]));
        assert!(small.evict_relayed_for(4 * one).is_empty(), "would never fit: nothing taken");
        assert_eq!(small.len(), 1);
        assert!(small.evict_relayed_for(one).is_empty(), "room already: nothing taken");
    }

    /// A stem that returns to a node holding it is decided like a fresh arrival on that edge —
    /// the coin, then the edge's successor, never back to the sender — at the submitter as at a
    /// relay; and after [`MAX_STEM_FORWARDS`] sends it waits for the embargo.
    #[test]
    fn a_loop_is_decided_like_a_fresh_arrival_until_the_forward_cap() {
        let t = Instant::now();
        for origin in [Edge::Local, Edge::Peer(PeerId::random())] {
            let mut d = Dandelion::new(DandelionConfig { fluff_prob: 0.0, seed: Some(3), ..Default::default() });
            let ps = peers(3);
            for p in &ps {
                d.router.add_peer(*p, true, None, &mut rng(1));
            }
            let x = tx(9);
            let Decision::Stem(first) = d.decide(origin, t) else { panic!("stems") };
            assert!(d.hold(x.hash(), x.clone(), origin, t));
            d.stempool.sent(&x.hash(), first);
            let back_from = ps[0];
            let fresh = d.decide(Edge::Peer(back_from), t);
            let LoopAction::Restem(next) = d.on_loop(&x.hash(), back_from, t) else { panic!("{origin:?}: sent on") };
            assert_eq!(Decision::Stem(next), fresh, "{origin:?}: the edge's own route, as for a fresh arrival");
            assert_ne!(next, back_from, "never straight back");
            for _ in 1..MAX_STEM_FORWARDS {
                d.stempool.sent(&x.hash(), next);
            }
            assert_eq!(d.on_loop(&x.hash(), back_from, t), LoopAction::Absorb, "{origin:?}: past the cap, the embargo");
        }
        // At q = 1 a return is fluffed by the coin, as a fresh arrival at a relay would be.
        let mut d = Dandelion::new(DandelionConfig { fluff_prob: 1.0, seed: Some(3), ..Default::default() });
        d.router.add_peer(PeerId::random(), true, None, &mut rng(1));
        let x = tx(10);
        assert!(d.hold(x.hash(), x.clone(), Edge::Local, t));
        assert_eq!(d.on_loop(&x.hash(), PeerId::random(), t), LoopAction::Fluff(FluffReason::Coin));
        // Not held (fluffed in the meantime): nothing to do.
        assert_eq!(d.on_loop(&tx(11).hash(), PeerId::random(), t), LoopAction::Absorb);
    }

    /// The stem in a fleet-sized network, simulated with the real router and coin: 25 nodes, each
    /// connected to every other, q = 0.1. Reports how a stem ends — fluffed by the coin, or left
    /// to the embargo after looping — and its length in hops, which with a measured per-hop time
    /// gives the latency cost (`cargo test -- --nocapture` prints it). A stem that loops goes on
    /// (`on_loop`), so nearly every stem ends on the coin after ~1/q hops; the submitter fluffs
    /// only when the walk comes back to it and its coin lands, like any other node's.
    #[test]
    fn a_25_node_fleet_stem_ends_on_the_coin() {
        let n = 25;
        // Fixed identities and seeds: the run is the same every time.
        let ids: Vec<PeerId> = (0..n)
            .map(|i| PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([i as u8 + 1; 32]).unwrap().public()))
            .collect();
        let t = Instant::now();
        let mut nodes: Vec<Dandelion> = (0..n)
            .map(|i| {
                let mut d = Dandelion::new(DandelionConfig { seed: Some(1000 + i as u64), ..Default::default() });
                let mut r = rng(i as u64);
                for (j, p) in ids.iter().enumerate() {
                    if j != i {
                        d.router.add_peer(*p, j % 2 == i % 2, None, &mut r);
                    }
                }
                d
            })
            .collect();
        let index: HashMap<PeerId, usize> = ids.iter().enumerate().map(|(i, p)| (*p, i)).collect();
        let trials = 4000;
        let (mut coin, mut embargo, mut hops_sum, mut submitter_fluffed) = (0usize, 0usize, 0usize, 0usize);
        let mut hops_hist = vec![0usize; 64];
        for k in 0..trials {
            let x = tx(100_000 + k as u64);
            let h = x.hash();
            let origin = k % n;
            // (node, edge it arrived on)
            let mut at = origin;
            let mut from = Edge::Local;
            let mut hops = 0usize;
            let ended_on_coin = loop {
                let node = &mut nodes[at];
                if node.stempool.contains(&h) {
                    let Edge::Peer(sender) = from else { unreachable!("only a peer stems") };
                    match node.on_loop(&h, sender, t) {
                        LoopAction::Restem(p) => {
                            node.stempool.sent(&h, p);
                            from = Edge::Peer(ids[at]);
                            at = index[&p];
                            hops += 1;
                            continue;
                        }
                        LoopAction::Fluff(FluffReason::Coin) => {
                            if at == origin {
                                submitter_fluffed += 1;
                            }
                            break true;
                        }
                        LoopAction::Fluff(other) => panic!("{other:?} in a fully connected fleet"),
                        LoopAction::Absorb => break false,
                    }
                }
                match node.decide(from, t) {
                    Decision::Fluff(FluffReason::Coin) => {
                        if at == origin {
                            submitter_fluffed += 1;
                        }
                        break true;
                    }
                    Decision::Fluff(other) => panic!("{other:?} in a fully connected fleet"),
                    Decision::Stem(p) => {
                        assert!(node.hold(h, x.clone(), from, t));
                        node.stempool.sent(&h, p);
                        from = Edge::Peer(ids[at]);
                        at = index[&p];
                        hops += 1;
                    }
                }
            };
            for node in nodes.iter_mut() {
                node.stempool.take(&h);
            }
            if ended_on_coin {
                coin += 1;
            } else {
                embargo += 1;
            }
            hops_sum += hops;
            hops_hist[hops.min(63)] += 1;
        }
        let coin_rate = coin as f64 / trials as f64;
        let mean_hops = hops_sum as f64 / trials as f64;
        let p90 = {
            let mut acc = 0;
            let mut out = 0;
            for (h, c) in hops_hist.iter().enumerate() {
                acc += c;
                if acc * 10 >= trials * 9 {
                    out = h;
                    break;
                }
            }
            out
        };
        eprintln!(
            "dandelion simulation, 25 nodes, q = 0.1: {:.1}% of stems end on the coin, {:.1}% on the embargo; mean {:.2} stem hops, p90 {p90}",
            100.0 * coin_rate,
            100.0 * embargo as f64 / trials as f64,
            mean_hops
        );
        eprintln!(
            "  the submitter itself fluffed {:.2}% (one node in 25 is {:.2}%)",
            100.0 * submitter_fluffed as f64 / trials as f64,
            100.0 / n as f64
        );
        assert!(coin_rate > 0.99, "only {coin_rate} of stems ended on the coin");
        assert!((7.0..13.0).contains(&mean_hops), "mean stem {mean_hops} hops at q = 0.1");
        assert!((submitter_fluffed as f64) < 0.1 * trials as f64, "the submitter fluffed {submitter_fluffed} of {trials}");
    }
}
