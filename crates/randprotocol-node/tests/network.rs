//! The network layer over real sockets: two or three swarms on loopback, driven through the
//! public `network::start` API and watched through their event streams — plus a bare gossipsub
//! swarm (the "observer") where a test has to see the topic a message rode on, which the node's
//! own events do not carry.
//!
//! Nothing here involves a `Node`: the network task alone, so what is pinned is the wire and the
//! swarm's policy — which topic, which id, which verdict forwards, which failure comes back and
//! how fast — and not the consensus logic above it (`cluster.rs` has that).

use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, TopicHash, ValidationMode};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, Swarm};
use randprotocol_core::consensus::{CommittedBlock, NotHeld, SigningDomain};
use randprotocol_core::types::block::{Block, BlockHeader, QuorumCertificate, Vote};
use randprotocol_core::{Hash, Keypair};
use randprotocol_node::network::{
    self, EdgeConfig, GossipId, GossipMessage, MessageAcceptance, NetworkConfig, NetworkEvent, NetworkHandle, PeerBinding, Status,
    SyncRequest, SyncResponse, WireLimits,
};
use std::time::Duration;
use tokio::sync::mpsc;

const CHAIN: u64 = 7;

fn cfg(chain_id: u64, bootstrap: Vec<Multiaddr>, limits: WireLimits) -> NetworkConfig {
    NetworkConfig { chain_id, listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()], bootstrap, enable_mdns: false, limits }
}

fn peer_of_seed(seed: u8) -> PeerId {
    PeerId::from(identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public())
}

async fn wait_for<T>(rx: &mut mpsc::Receiver<NetworkEvent>, timeout: Duration, mut f: impl FnMut(NetworkEvent) -> Option<T>) -> Option<T> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) => {
                if let Some(v) = f(ev) {
                    return Some(v);
                }
            }
            _ => return None,
        }
    }
}

/// A node, its events, and its full dialable address (`/ip4/127.0.0.1/tcp/<port>/p2p/<id>`).
struct Peer {
    h: NetworkHandle,
    rx: mpsc::Receiver<NetworkEvent>,
    full: Multiaddr,
    /// Events that arrived before the listen address did. The swarm task yields between its
    /// bootstrap dial and its first poll, and a handshake on loopback finishes in that window,
    /// so a dialer's `PeerConnected` can precede its own `Listening`. Consulted first by `wait`.
    early: Vec<NetworkEvent>,
}

impl Peer {
    /// The first event `f` accepts, the early ones first, within `timeout`. Events `f` declines
    /// are dropped, as the node loop would have consumed them.
    async fn wait<T>(&mut self, timeout: Duration, mut f: impl FnMut(NetworkEvent) -> Option<T>) -> Option<T> {
        let early = std::mem::take(&mut self.early);
        let mut early = early.into_iter();
        for ev in early.by_ref() {
            if let Some(v) = f(ev) {
                self.early = early.collect();
                return Some(v);
            }
        }
        wait_for(&mut self.rx, timeout, f).await
    }

    async fn connected(&mut self, peer: PeerId, timeout: Duration) -> bool {
        self.wait(timeout, |e| matches!(e, NetworkEvent::PeerConnected(p) if p == peer).then_some(())).await.is_some()
    }
}

async fn start(seed: u8, chain_id: u64, bootstrap: Vec<Multiaddr>, limits: WireLimits, edge: EdgeConfig) -> Peer {
    let (h, mut rx) = network::start_with(cfg(chain_id, bootstrap, limits), [seed; 32], edge).await.expect("starts");
    let mut early = Vec::new();
    let addr = wait_for(&mut rx, Duration::from_secs(5), |e| match e {
        NetworkEvent::Listening(a) => Some(a),
        other => {
            early.push(other);
            None
        }
    })
    .await
    .expect("listening");
    let full = addr.with(Protocol::P2p(h.local_peer_id));
    Peer { h, rx, full, early }
}

/// A listening node and a second one bootstrapped to it, connected both ways.
async fn pair(seed_a: u8, seed_b: u8) -> (Peer, Peer) {
    let mut a = start(seed_a, CHAIN, vec![], WireLimits::default(), EdgeConfig::default()).await;
    let mut b = start(seed_b, CHAIN, vec![a.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    assert!(a.connected(b.h.local_peer_id, Duration::from_secs(10)).await, "A never saw B");
    assert!(b.connected(a.h.local_peer_id, Duration::from_secs(10)).await, "B never saw A");
    (a, b)
}

fn status(height: u64) -> Status {
    Status { height, head_hash: Hash::digest(&height.to_be_bytes()), view: height, floor: 0 }
}

/// Publish `status` from `from` until `to` delivers a status of that height (the mesh takes a
/// heartbeat or two to form; a repeat of the same bytes is a duplicate at the publisher, so the
/// retries cost nothing on the wire). The author and the id the delivery must be reported with.
async fn gossip_until_delivered(from: &NetworkHandle, to: &mut Peer, status: Status) -> (PeerId, GossipId) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let height = status.height;
    while tokio::time::Instant::now() < deadline {
        from.broadcast(GossipMessage::Status(status.clone())).await;
        let got = to.wait(Duration::from_millis(400), |e| match e {
            NetworkEvent::Gossip { from, msg: GossipMessage::Status(s), id } if s.height == height => Some((from, id)),
            _ => None,
        })
        .await;
        if let Some(got) = got {
            return got;
        }
    }
    panic!("status {height} was never delivered");
}

// ------------------------------------------- an observer: a bare gossipsub swarm

/// A gossipsub swarm of its own, subscribed to the chain's four topics, with no node behind it:
/// it sees which topic a message arrives on and can publish raw bytes.
struct Observer {
    swarm: Swarm<gossipsub::Behaviour>,
    topics: Vec<IdentTopic>,
}

struct Seen {
    topic: TopicHash,
    source: Option<PeerId>,
    data: Vec<u8>,
}

impl Observer {
    fn new(chain_id: u64, authenticity: MessageAuthenticity) -> Observer {
        let gcfg = gossipsub::ConfigBuilder::default()
            .validation_mode(ValidationMode::Permissive)
            .heartbeat_interval(Duration::from_millis(200))
            .build()
            .unwrap();
        let gs = gossipsub::Behaviour::new(authenticity, gcfg).unwrap();
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity::Keypair::generate_ed25519())
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|_| gs)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let topics: Vec<IdentTopic> =
            ["consensus", "tx", "status", "peers"].iter().map(|t| IdentTopic::new(format!("rand/{chain_id}/{t}"))).collect();
        for t in &topics {
            swarm.behaviour_mut().subscribe(t).unwrap();
        }
        Observer { swarm, topics }
    }

    fn topic(&self, name: &str) -> IdentTopic {
        self.topics.iter().find(|t| t.to_string().ends_with(&format!("/{name}"))).cloned().unwrap()
    }

    /// Dial `target` and pump the swarm until the connection is up.
    async fn connect(&mut self, target: &Multiaddr) {
        self.swarm.dial(target.clone()).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            tokio::select! {
                ev = self.swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = ev { return; }
                }
                _ = tokio::time::sleep_until(deadline) => panic!("the observer never connected"),
            }
        }
    }

    /// Pump the swarm for `dur`, keeping the messages it delivered.
    async fn pump(&mut self, dur: Duration) -> Vec<Seen> {
        let deadline = tokio::time::Instant::now() + dur;
        let mut seen = Vec::new();
        loop {
            tokio::select! {
                ev = self.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) = ev {
                        seen.push(Seen { topic: message.topic, source: message.source, data: message.data });
                    }
                }
                _ = tokio::time::sleep_until(deadline) => return seen,
            }
        }
    }

    /// Publish `data` on `topic` (a duplicate or a mesh not yet formed is not an error here;
    /// the caller retries) and pump briefly so it goes out.
    async fn publish(&mut self, topic: &IdentTopic, data: Vec<u8>) {
        let _ = self.swarm.behaviour_mut().publish(topic.clone(), data);
        let _ = self.pump(Duration::from_millis(100)).await;
    }
}

// ------------------------------------------- blocks for the sync wire

fn domain() -> SigningDomain {
    SigningDomain::v0(Hash::digest(b"g"))
}

fn keys(n: u8) -> Vec<Keypair> {
    (1..=n).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect()
}

fn qc(ks: &[Keypair], view: u64, hash: Hash) -> QuorumCertificate {
    QuorumCertificate { view, block_hash: hash, votes: ks.iter().map(|k| Vote::sign(&domain(), view, hash, k)).collect() }
}

fn committed(height: u64, ks: &[Keypair]) -> CommittedBlock {
    let parent = Hash::digest(&height.to_be_bytes());
    let header = BlockHeader {
        height,
        view: height,
        parent,
        proposer: ks[0].public_key().clone(),
        timestamp_ms: height,
        tx_root: Hash::ZERO,
        state_root: parent,
        justify: qc(ks, height.saturating_sub(1), parent),
    };
    let block = Block::sign(&domain(), header, vec![], &ks[0]);
    let hash = block.hash();
    CommittedBlock { block, pruned: Vec::new(), qc: qc(ks, height, hash), receipts: Vec::new(), deposits: Vec::new(), aggregates: Vec::new(), perp_words: None }
}

/// `asker` sends `req` to `answerer`, which answers `resp`; what the asker received.
async fn exchange(asker: &mut Peer, answerer: &mut Peer, req: SyncRequest, resp: SyncResponse) -> SyncResponse {
    let req_id = asker.h.send_sync_request(answerer.h.local_peer_id, req.clone()).await.expect("a request id");
    let (asker_id, answerer_id) = (asker.h.local_peer_id, answerer.h.local_peer_id);
    let channel = answerer.wait(Duration::from_secs(10), |e| match e {
        NetworkEvent::SyncRequest { peer, request, channel } if peer == asker_id => {
            let same = match (&request, &req) {
                (SyncRequest::Blocks { from_height: a, max: b }, SyncRequest::Blocks { from_height: c, max: d }) => a == c && b == d,
                (SyncRequest::BlockByHash(a), SyncRequest::BlockByHash(b)) => a == b,
                _ => false,
            };
            same.then_some(channel)
        }
        _ => None,
    })
    .await
    .expect("the request arrived as sent");
    answerer.h.send_sync_response(channel, resp).await;
    asker.wait(Duration::from_secs(10), |e| match e {
        NetworkEvent::SyncResponse { peer, request_id, response } if peer == answerer_id && request_id == req_id => Some(response),
        NetworkEvent::SyncFailed { request_id, error, .. } if request_id == req_id => panic!("the request failed: {error}"),
        _ => None,
    })
    .await
    .expect("the response arrived")
}

// ------------------------------------------- discovery and connections

/// A bootstrap entry is dialed whether or not it names the peer: `/ip4/../tcp/..` alone connects
/// (the id is learned on the handshake), so an operator's list need not carry ids to work —
/// only to reserve.
#[tokio::test]
async fn a_bootstrap_address_without_a_peer_id_is_still_dialed() {
    let mut a = start(10, CHAIN, vec![], WireLimits::default(), EdgeConfig::default()).await;
    let mut plain = a.full.clone();
    assert!(matches!(plain.pop(), Some(Protocol::P2p(_))));
    let mut b = start(11, CHAIN, vec![plain], WireLimits::default(), EdgeConfig::default()).await;
    assert!(a.connected(b.h.local_peer_id, Duration::from_secs(10)).await, "A never saw B");
    assert!(b.connected(a.h.local_peer_id, Duration::from_secs(10)).await, "B never saw A");
    a.h.shutdown().await;
    b.h.shutdown().await;
}

/// `NetworkHandle::dial` connects two nodes that know nothing of each other, and `peers` on each
/// side then reports the other's id, a loopback TCP address and a fresh connection age.
#[tokio::test]
async fn a_runtime_dial_connects_and_peer_info_names_the_remote() {
    let mut a = start(12, CHAIN, vec![], WireLimits::default(), EdgeConfig::default()).await;
    let mut b = start(13, CHAIN, vec![], WireLimits::default(), EdgeConfig::default()).await;
    assert!(a.h.peers().await.is_empty());
    b.h.dial(a.full.clone()).await;
    assert!(a.connected(b.h.local_peer_id, Duration::from_secs(10)).await);
    assert!(b.connected(a.h.local_peer_id, Duration::from_secs(10)).await);

    let seen_by_a = a.h.peers().await;
    assert_eq!(seen_by_a.len(), 1);
    assert_eq!(seen_by_a[0].peer_id, b.h.local_peer_id.to_string());
    assert!(seen_by_a[0].addrs.iter().all(|x| x.starts_with("/ip4/127.0.0.1/tcp/")), "{:?}", seen_by_a[0].addrs);
    assert!(seen_by_a[0].connected_secs < 10);
    let seen_by_b = b.h.peers().await;
    assert_eq!(seen_by_b.len(), 1);
    assert_eq!(seen_by_b[0].peer_id, a.h.local_peer_id.to_string());
    // The dialer records the address exactly as it dialed it, `/p2p/<id>` included (the dial
    // table it redials from strips that; `peers` is the operator's view of what was dialed).
    assert_eq!(seen_by_b[0].addrs, vec![a.full.to_string()], "B dialed {}", a.full);
    a.h.shutdown().await;
    b.h.shutdown().await;
}

/// Shutting a node down closes its connections: the other side gets `PeerDisconnected`, and the
/// dead node's handle answers every query with nothing rather than hanging.
#[tokio::test]
async fn shutdown_disconnects_the_peer_and_the_handle_answers_empty_afterwards() {
    let (a, mut b) = pair(14, 15).await;
    let a_id = a.h.local_peer_id;
    a.h.shutdown().await;
    let gone = b.wait(Duration::from_secs(10), |e| matches!(e, NetworkEvent::PeerDisconnected(p) if p == a_id).then_some(())).await;
    assert!(gone.is_some(), "B never saw A go");
    assert!(b.h.peers().await.is_empty(), "B still lists A");
    assert!(a.h.peers().await.is_empty());
    assert!(a.h.send_sync_request(b.h.local_peer_id, SyncRequest::BlockByHash(Hash::ZERO)).await.is_none());
    b.h.shutdown().await;
}

/// Two nodes on different chain ids share a TCP connection — the transport is chain-agnostic —
/// but no topic (`rand/<chain>/…`) and no sync protocol (`/rand/<chain>/sync/1`): a sync request
/// across chains fails at protocol negotiation, at once, and gossip never crosses.
#[tokio::test]
async fn a_peer_on_another_chain_shares_a_connection_but_no_topic_and_no_sync_protocol() {
    let mut a = start(16, 7, vec![], WireLimits::default(), EdgeConfig::default()).await;
    let mut b = start(17, 8, vec![a.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    assert!(a.connected(b.h.local_peer_id, Duration::from_secs(10)).await);
    assert!(b.connected(a.h.local_peer_id, Duration::from_secs(10)).await);

    let started = tokio::time::Instant::now();
    let req_id = b.h.send_sync_request(a.h.local_peer_id, SyncRequest::Blocks { from_height: 0, max: 1 }).await.unwrap();
    let error = b.wait(Duration::from_secs(10), |e| match e {
        NetworkEvent::SyncFailed { request_id, error, .. } if request_id == req_id => Some(error),
        NetworkEvent::SyncResponse { request_id, .. } if request_id == req_id => panic!("answered across chains"),
        _ => None,
    })
    .await
    .expect("the request failed");
    assert!(error.contains("none of the requested protocols"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(5), "refused at negotiation, not at the timeout");
    // A never saw a request either.
    assert!(a.wait(Duration::from_millis(500), |e| matches!(e, NetworkEvent::SyncRequest { .. }).then_some(())).await.is_none());

    // Gossip: A publishes on chain 7's status topic for three seconds; B, on chain 8, hears nothing.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut h = 1;
    while tokio::time::Instant::now() < deadline {
        a.h.broadcast(GossipMessage::Status(status(h))).await;
        h += 1;
        let got = b.wait(Duration::from_millis(250), |e| matches!(e, NetworkEvent::Gossip { .. }).then_some(())).await;
        assert!(got.is_none(), "chain 7's status reached a chain 8 node");
    }
    a.h.shutdown().await;
    b.h.shutdown().await;
}

// ------------------------------------------- gossip: topics, ids, verdicts

/// A broadcast `Status` goes out on `rand/<chain>/status` and a `PeerBinding` on
/// `rand/<chain>/peers`, as exactly the bincode bytes of the `GossipMessage`, signed by (and so
/// sourced to) the publishing node — seen from a bare gossipsub swarm beside it.
#[tokio::test]
async fn each_message_rides_its_own_topic_as_the_bincode_of_the_gossip_message() {
    let a = start(20, CHAIN, vec![], WireLimits::default(), EdgeConfig::default()).await;
    let mut obs = Observer::new(CHAIN, MessageAuthenticity::Anonymous);
    obs.connect(&a.full).await;

    let key = Keypair::from_seed([9; 32]).unwrap();
    let binding = PeerBinding::sign(&key, &Hash::digest(b"genesis"), &a.h.local_peer_id, 1_000);
    let wanted = [
        (GossipMessage::Status(status(5)), obs.topic("status").hash()),
        (GossipMessage::PeerBinding(binding), obs.topic("peers").hash()),
    ];
    for (msg, topic) in wanted {
        let bytes = bincode::serialize(&msg).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut hit = None;
        while hit.is_none() && tokio::time::Instant::now() < deadline {
            a.h.broadcast(msg.clone()).await;
            hit = obs.pump(Duration::from_millis(400)).await.into_iter().find(|s| s.data == bytes);
        }
        let seen = hit.unwrap_or_else(|| panic!("never saw the message on any topic"));
        assert_eq!(seen.topic, topic, "wrong topic");
        assert_eq!(seen.source, Some(a.h.local_peer_id), "signed by the publisher");
    }
    a.h.shutdown().await;
}

/// The id a delivery is reported with is content-addressed: blake3 of the message bytes, which is
/// why two forwarders of one message produce one id. Checked from outside against the bytes the
/// publisher put on the wire.
#[tokio::test]
async fn a_delivered_messages_id_is_the_blake3_of_its_bytes() {
    let (mut a, b) = pair(21, 22).await;
    let s = status(9);
    let bytes = bincode::serialize(&GossipMessage::Status(s.clone())).unwrap();
    let (from, id) = gossip_until_delivered(&b.h, &mut a, s).await;
    assert_eq!(from, b.h.local_peer_id);
    assert_eq!(id.propagation_source, b.h.local_peer_id);
    assert_eq!(id.message_id.0, blake3::hash(&bytes).as_bytes().to_vec());
    a.h.report_validation(id, MessageAcceptance::Accept).await;
    a.h.shutdown().await;
    b.h.shutdown().await;
}

/// The same bytes published three times are delivered once: the content-addressed id makes the
/// repeats duplicates at the publisher and at the receiver alike.
#[tokio::test]
async fn the_same_bytes_published_again_are_delivered_once() {
    let (mut a, b) = pair(23, 24).await;
    // Warm the mesh with another message first, so the publishes below all go out.
    let (_, id) = gossip_until_delivered(&b.h, &mut a, status(1)).await;
    a.h.report_validation(id, MessageAcceptance::Accept).await;

    let s = status(2);
    for _ in 0..3 {
        b.h.broadcast(GossipMessage::Status(s.clone())).await;
    }
    let mut deliveries = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let got = a
            .wait(remaining, |e| match e {
                NetworkEvent::Gossip { msg: GossipMessage::Status(got), id, .. } if got.height == 2 => Some(id),
                _ => None,
            })
            .await;
        match got {
            Some(id) => {
                deliveries += 1;
                a.h.report_validation(id, MessageAcceptance::Accept).await;
            }
            None => break,
        }
    }
    assert_eq!(deliveries, 1);
    a.h.shutdown().await;
    b.h.shutdown().await;
}

/// B → A → C, with C reachable only through A. A message A's application rejects stops at A: C
/// never gets it. One A accepts goes on to C, from the author B, forwarded by A.
#[tokio::test]
async fn a_message_the_node_rejects_is_not_forwarded_to_a_third_node() {
    let mut a = start(25, CHAIN, vec![], WireLimits::default(), EdgeConfig::default()).await;
    let mut b = start(26, CHAIN, vec![a.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    let mut c = start(27, CHAIN, vec![a.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    for id in [b.h.local_peer_id, c.h.local_peer_id] {
        assert!(a.connected(id, Duration::from_secs(10)).await);
    }
    assert!(b.connected(a.h.local_peer_id, Duration::from_secs(10)).await);
    assert!(c.connected(a.h.local_peer_id, Duration::from_secs(10)).await);

    /// Publish `height` at B, have A report `verdict` on it, and say whether C got it within
    /// `c_window`.
    async fn relay(a: &mut Peer, b: &Peer, c: &mut Peer, height: u64, verdict: MessageAcceptance, c_window: Duration) -> bool {
        let (from, id) = gossip_until_delivered(&b.h, a, status(height)).await;
        assert_eq!(from, b.h.local_peer_id);
        a.h.report_validation(id, verdict).await;
        let a_id = a.h.local_peer_id;
        c.wait(c_window, |e| match e {
            NetworkEvent::Gossip { from, msg: GossipMessage::Status(s), id } if s.height == height => {
                assert_eq!(from, b.h.local_peer_id, "the author is B");
                assert_eq!(id.propagation_source, a_id, "forwarded by A");
                Some(())
            }
            _ => None,
        })
        .await
        .is_some()
    }

    // Warm-up: until the B → A → C path has carried an accepted message once.
    let mut height = 100;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !relay(&mut a, &b, &mut c, height, MessageAcceptance::Accept, Duration::from_secs(2)).await {
        height += 1;
        assert!(tokio::time::Instant::now() < deadline, "the mesh never carried an accepted message to C");
    }
    // Rejected at A: C does not get it.
    assert!(!relay(&mut a, &b, &mut c, 200, MessageAcceptance::Reject, Duration::from_secs(3)).await, "a rejected message was forwarded");
    // Ignored at A: not forwarded either.
    assert!(!relay(&mut a, &b, &mut c, 201, MessageAcceptance::Ignore, Duration::from_secs(3)).await, "an ignored message was forwarded");
    // Accepted at A: on it goes.
    assert!(relay(&mut a, &b, &mut c, 300, MessageAcceptance::Accept, Duration::from_secs(10)).await, "an accepted message was not forwarded");
    for p in [a, b, c] {
        p.h.shutdown().await;
    }
}

/// Bytes that are not a `GossipMessage` are rejected inside the network task: the node never
/// sees them as an event and a third node never receives them through this one — while an
/// unsigned but well-formed message from the same stranger is delivered (the permissive default).
#[tokio::test]
async fn undecodable_gossip_is_dropped_before_the_node_and_never_forwarded() {
    let mut a = start(28, CHAIN, vec![], WireLimits::default(), EdgeConfig::default()).await;
    let mut c = start(29, CHAIN, vec![a.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    assert!(a.connected(c.h.local_peer_id, Duration::from_secs(10)).await);
    let mut obs = Observer::new(CHAIN, MessageAuthenticity::Author(peer_of_seed(99)));
    obs.connect(&a.full).await;
    let topic = obs.topic("status");

    // Garbage, for three seconds: the mesh forms in that time, so some of it is sent.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut n = 0u64;
    while tokio::time::Instant::now() < deadline {
        obs.publish(&topic, [vec![0xff; 5], n.to_le_bytes().to_vec()].concat()).await;
        n += 1;
        for (name, p) in [("A", &mut a), ("C", &mut c)] {
            let got = p.wait(Duration::from_millis(50), |e| matches!(e, NetworkEvent::Gossip { .. }).then_some(())).await;
            assert!(got.is_none(), "{name} delivered undecodable bytes");
        }
    }
    // The same stranger, a decodable message: delivered at A, under the author it claims.
    let valid = bincode::serialize(&GossipMessage::Status(status(77))).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut got = None;
    while got.is_none() && tokio::time::Instant::now() < deadline {
        obs.publish(&topic, valid.clone()).await;
        got = a.wait(Duration::from_millis(300), |e| match e {
            NetworkEvent::Gossip { from, msg: GossipMessage::Status(s), .. } if s.height == 77 => Some(from),
            _ => None,
        })
        .await;
    }
    assert_eq!(got, Some(peer_of_seed(99)), "a decodable unsigned message is delivered under its claimed author");
    a.h.shutdown().await;
    c.h.shutdown().await;
}

// ------------------------------------------- sync: the request-response wire

/// Every answer a sync server gives crosses the wire intact: a batch of blocks with their QCs,
/// `Block(None)` for a hash nobody holds, a `NotHeld` that still verifies on arrival, and `Busy`
/// — each paired with the request that arrived as sent.
#[tokio::test]
async fn a_sync_exchange_carries_every_answer_intact() {
    let (mut a, mut b) = pair(30, 31).await;
    let ks = keys(2);
    let batch = vec![committed(1, &ks), committed(2, &ks), committed(3, &ks)];
    match exchange(&mut a, &mut b, SyncRequest::Blocks { from_height: 1, max: 3 }, SyncResponse::Blocks(batch.clone())).await {
        SyncResponse::Blocks(got) => {
            assert_eq!(got, batch);
            assert_eq!(got.iter().map(|cb| cb.block.header.height).collect::<Vec<_>>(), vec![1, 2, 3]);
        }
        other => panic!("{other:?}"),
    }
    let wanted = Hash::digest(b"nobody has this");
    assert!(matches!(exchange(&mut a, &mut b, SyncRequest::BlockByHash(wanted), SyncResponse::Block(None)).await, SyncResponse::Block(None)));
    let genesis = Hash::digest(b"genesis");
    let nh = NotHeld::sign(&ks[1], &genesis, &wanted, 4);
    match exchange(&mut a, &mut b, SyncRequest::BlockByHash(wanted), SyncResponse::NotHeld(nh.clone())).await {
        SyncResponse::NotHeld(got) => {
            assert_eq!(got, nh);
            assert!(got.verify(&genesis));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(exchange(&mut a, &mut b, SyncRequest::Blocks { from_height: 4, max: 100 }, SyncResponse::Busy).await, SyncResponse::Busy));
    // A single block by hash, whole.
    let one = committed(9, &ks).block;
    match exchange(&mut a, &mut b, SyncRequest::BlockByHash(one.hash()), SyncResponse::Block(Some(one.clone()))).await {
        SyncResponse::Block(Some(got)) => assert_eq!(got, one),
        other => panic!("{other:?}"),
    }
    a.h.shutdown().await;
    b.h.shutdown().await;
}

/// A response over the chain's reader limit never leaves the server: its writer refuses it, and
/// the asker gets `SyncFailed` within seconds — not an answer, and not the 20 s deadline that
/// would mean a silent truncation on the way.
#[tokio::test]
async fn a_response_over_the_chains_limit_fails_the_request_fast() {
    let limits = WireLimits { sync_response_wire_limit: 2048, sync_request_timeout: Duration::from_secs(20), ..WireLimits::default() };
    let mut a = start(32, CHAIN, vec![], limits, EdgeConfig::default()).await;
    let mut b = start(33, CHAIN, vec![a.full.clone()], limits, EdgeConfig::default()).await;
    assert!(a.connected(b.h.local_peer_id, Duration::from_secs(10)).await);
    let ks = keys(1);
    let fat = SyncResponse::Blocks(vec![committed(1, &ks)]);
    assert!(network::codec::cbor_size(&fat).unwrap() > 2048, "one block with two Dilithium2 QCs is well over 2 KiB");

    let started = tokio::time::Instant::now();
    let req_id = a.h.send_sync_request(b.h.local_peer_id, SyncRequest::Blocks { from_height: 1, max: 1 }).await.unwrap();
    let a_id = a.h.local_peer_id;
    let channel = b.wait(Duration::from_secs(10), |e| match e {
        NetworkEvent::SyncRequest { peer, channel, .. } if peer == a_id => Some(channel),
        _ => None,
    })
    .await
    .expect("B got the request");
    b.h.send_sync_response(channel, fat).await;
    let error = a.wait(Duration::from_secs(15), |e| match e {
        NetworkEvent::SyncFailed { request_id, error, .. } if request_id == req_id => Some(error),
        NetworkEvent::SyncResponse { request_id, .. } if request_id == req_id => panic!("an over-limit response was delivered"),
        _ => None,
    })
    .await
    .expect("the request failed");
    assert!(started.elapsed() < Duration::from_secs(15), "failed fast, not at the deadline: {error}");
    assert!(!error.contains("Timeout"), "{error}");

    // The wire is still usable: an answer within the limit goes through.
    assert!(matches!(exchange(&mut a, &mut b, SyncRequest::Blocks { from_height: 1, max: 1 }, SyncResponse::Blocks(vec![])).await, SyncResponse::Blocks(v) if v.is_empty()));
    a.h.shutdown().await;
    b.h.shutdown().await;
}

/// A request the responder never answers — it holds the channel and says nothing — fails with
/// the wire's own timeout, at the asker's `sync_request_timeout`, as `SyncFailed` naming it.
#[tokio::test]
async fn a_request_nobody_answers_fails_with_a_timeout_at_the_wire_deadline() {
    let short = WireLimits { sync_request_timeout: Duration::from_secs(2), ..WireLimits::default() };
    let mut a = start(34, CHAIN, vec![], short, EdgeConfig::default()).await;
    let mut b = start(35, CHAIN, vec![a.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    assert!(a.connected(b.h.local_peer_id, Duration::from_secs(10)).await);

    let started = tokio::time::Instant::now();
    let req_id = a.h.send_sync_request(b.h.local_peer_id, SyncRequest::Blocks { from_height: 0, max: 1 }).await.unwrap();
    let a_id = a.h.local_peer_id;
    let held = b.wait(Duration::from_secs(10), |e| match e {
        NetworkEvent::SyncRequest { peer, channel, .. } if peer == a_id => Some(channel),
        _ => None,
    })
    .await
    .expect("B got the request");
    let error = a.wait(Duration::from_secs(10), |e| match e {
        NetworkEvent::SyncFailed { peer, request_id, error } if request_id == req_id => {
            assert_eq!(peer, b.h.local_peer_id);
            Some(error)
        }
        _ => None,
    })
    .await
    .expect("the request failed");
    let took = started.elapsed();
    assert!(error.contains("Timeout"), "{error}");
    assert!(took >= Duration::from_secs(2) && took < Duration::from_secs(8), "took {took:?}");
    drop(held);
    a.h.shutdown().await;
    b.h.shutdown().await;
}

// ------------------------------------------- reserved peers: pinned versus bound

/// Audit v6, NET-1: an identity from `EdgeConfig::bound` (a binding learned before the restart)
/// is admitted past an inbound cap strangers have filled — and once unreserved it is a stranger
/// again, refused at that same cap.
#[tokio::test]
async fn a_bound_peer_is_admitted_past_the_cap_until_it_is_unreserved() {
    let (kept, dropped) = (40u8, 41u8);
    let capped = WireLimits { max_established_incoming: 1, ..WireLimits::default() };
    let edge = EdgeConfig { bound: vec![peer_of_seed(kept), peer_of_seed(dropped)], ..EdgeConfig::default() };
    let mut t = start(42, CHAIN, vec![], capped, edge).await;
    let stranger = start(43, CHAIN, vec![t.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    assert!(t.connected(stranger.h.local_peer_id, Duration::from_secs(10)).await, "the stranger fills the one slot");

    let k = start(kept, CHAIN, vec![t.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    assert!(t.connected(k.h.local_peer_id, Duration::from_secs(10)).await, "a bound peer is admitted past the full cap");

    t.h.unreserve_peer(peer_of_seed(dropped)).await;
    let d = start(dropped, CHAIN, vec![t.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    assert!(!t.connected(d.h.local_peer_id, Duration::from_secs(4)).await, "an unreserved bound peer got past the cap");
    let peers: Vec<String> = t.h.peers().await.into_iter().map(|p| p.peer_id).collect();
    assert!(!peers.contains(&d.h.local_peer_id.to_string()));
    assert_eq!(peers.len(), 2, "the stranger and the kept peer: {peers:?}");
    for p in [t, stranger, k, d] {
        p.h.shutdown().await;
    }
}

/// The operator's `--reserved-peer` identities (and the bootstraps') are pinned for the life of
/// the process: `unreserve_peer` on one is a no-op, and it is still admitted past a full cap.
#[tokio::test]
async fn an_operator_reserved_peer_survives_unreserve() {
    let reserved = 44u8;
    let capped = WireLimits { max_established_incoming: 1, ..WireLimits::default() };
    let edge = EdgeConfig { reserved: vec![peer_of_seed(reserved)], ..EdgeConfig::default() };
    let mut t = start(45, CHAIN, vec![], capped, edge).await;
    let stranger = start(46, CHAIN, vec![t.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    assert!(t.connected(stranger.h.local_peer_id, Duration::from_secs(10)).await);

    t.h.unreserve_peer(peer_of_seed(reserved)).await;
    let r = start(reserved, CHAIN, vec![t.full.clone()], WireLimits::default(), EdgeConfig::default()).await;
    assert!(t.connected(r.h.local_peer_id, Duration::from_secs(10)).await, "a pinned peer was unreserved");
    for p in [t, stranger, r] {
        p.h.shutdown().await;
    }
}
