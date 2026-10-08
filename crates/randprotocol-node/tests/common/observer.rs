//! An observer: a bare gossipsub swarm subscribed to a chain's four topics, with no node behind
//! it. It sees the raw frame a message rode on — its topic, its signed source and its bytes —
//! which a node's own events do not carry, and it can publish raw bytes.
//!
//! Moved here from `network.rs` unchanged so `cluster.rs` can watch a running chain's wire as
//! well (spec 2026-10-08 §1: a proposal's frame on the consensus topic carries hashes, not
//! bodies).

use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, TopicHash, ValidationMode};
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, Swarm};
use std::time::Duration;

/// A gossipsub swarm of its own, subscribed to the chain's four topics, with no node behind it:
/// it sees which topic a message arrives on and can publish raw bytes.
pub struct Observer {
    swarm: Swarm<gossipsub::Behaviour>,
    topics: Vec<IdentTopic>,
}

/// One message the observer was delivered, exactly as gossipsub handed it over.
pub struct Seen {
    pub topic: TopicHash,
    pub source: Option<PeerId>,
    pub data: Vec<u8>,
}

impl Observer {
    pub fn new(chain_id: u64, authenticity: MessageAuthenticity) -> Observer {
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

    /// An anonymous observer of `chain_id`, connected to every address in `bootstrap` — the
    /// shape a cluster test wants: it only listens.
    pub async fn start(chain_id: u64, bootstrap: Vec<Multiaddr>) -> Observer {
        let mut obs = Observer::new(chain_id, MessageAuthenticity::Anonymous);
        for addr in &bootstrap {
            obs.connect(addr).await;
        }
        obs
    }

    pub fn topic(&self, name: &str) -> IdentTopic {
        self.topics.iter().find(|t| t.to_string().ends_with(&format!("/{name}"))).cloned().unwrap()
    }

    /// Dial `target` and pump the swarm until the connection is up.
    pub async fn connect(&mut self, target: &Multiaddr) {
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
    pub async fn pump(&mut self, dur: Duration) -> Vec<Seen> {
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
    pub async fn publish(&mut self, topic: &IdentTopic, data: Vec<u8>) {
        let _ = self.swarm.behaviour_mut().publish(topic.clone(), data);
        let _ = self.pump(Duration::from_millis(100)).await;
    }
}
