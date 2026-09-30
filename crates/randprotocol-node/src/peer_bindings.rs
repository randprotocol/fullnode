//! Which libp2p identities belong to validators (audit v6, NET-1).
//!
//! A node's libp2p identity is derived from its validator's secret seed, so nothing public names
//! it; each validator signs a [`PeerBinding`] and gossips it, and every node that knows the
//! validator's key from a set it holds records the binding and reserves the peer
//! (`NetworkHandle::reserve_peer`): that peer is then admitted past the inbound connection cap
//! and served from the validators' share of the sync budget (SYNC-3). The record is persisted
//! (`Storage::put_peer_bindings`) and reserved again at the next start, so a restart — and every
//! node-by-node roll — finds its validators reserved before gossip has said anything. A freshly
//! cut chain starts with none: that is what the bootstrap reservation and `--reserved-peer` are
//! for.
//!
//! The decision is a function of its inputs ([`PeerBindings::offer`]) so every path is tested
//! without a swarm; the node loop does the I/O it asks for ([`BindingChange`]).

use crate::admission::{Acceptance, PeerLimiter, TokenBucket};
use crate::network::PeerBinding;
use crate::storage::PeerBindingRow;
use libp2p::PeerId;
use randprotocol_core::{Address, Hash};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

/// Validators whose bindings are held at once. The fleet runs 26; a set can grow, and bindings
/// of validators no longer in any known set are dropped first when this is reached.
pub const MAX_PEER_BINDINGS: usize = 1024;

/// Binding messages one forwarding peer may deliver back to back, and the rate it recovers them
/// at. Each validator announces once a minute and at most once every ten seconds on a new
/// connection, so a whole 26-validator fleet restarting together is ~2.6 a second through one
/// forwarder; a new binding costs one Dilithium2 verify.
pub const BINDING_GOSSIP_BURST: u32 = 64;
pub const BINDING_GOSSIP_PER_SEC: f64 = 8.0;

/// A validator re-announces its binding this often, so a node that missed it — or started after
/// it — learns it within the minute.
pub const BINDING_ANNOUNCE_EVERY: Duration = Duration::from_secs(60);
/// And when a peer connects, but not more often than this: a node reconnecting to many peers at
/// once announces once.
pub const BINDING_ANNOUNCE_MIN_GAP: Duration = Duration::from_secs(10);

/// How far past this node's clock a binding's `issued_ms` may be. The vote rule's drift bound
/// (15 s): a binding from further ahead would, once recorded, make the validator's own honest
/// announcements look stale until real time caught up.
pub const BINDING_MAX_AHEAD_MS: u64 = 15_000;

/// One validator's recorded binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound {
    pub peer: PeerId,
    pub issued_ms: u64,
}

/// What the node loop must do after an offer: reserve a newly bound peer, stop reserving the
/// ones no validator claims any more, and write the record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindingChange {
    pub reserve: Option<PeerId>,
    pub unreserve: Vec<PeerId>,
    pub persist: bool,
}

/// The binding gossip arm's decision: the one report gossipsub gets for the message, and the
/// change, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingVerdict {
    pub report: Acceptance,
    pub change: Option<BindingChange>,
}

impl BindingVerdict {
    fn report(report: Acceptance) -> BindingVerdict {
        BindingVerdict { report, change: None }
    }
}

pub struct PeerBindings {
    genesis: Hash,
    by_validator: BTreeMap<Address, Bound>,
    /// The bootstraps' identities and `--reserved-peer`'s: reserved for the life of the process
    /// whatever the bindings say, and validator peers for SYNC-3's budget.
    pinned: HashSet<PeerId>,
}

impl PeerBindings {
    pub fn new(genesis: Hash, pinned: HashSet<PeerId>) -> PeerBindings {
        PeerBindings { genesis, by_validator: BTreeMap::new(), pinned }
    }

    /// The record as persisted. A row that does not parse is skipped with a warning: a cache
    /// never stops a start, and the validator's next announcement puts it back.
    pub fn load(genesis: Hash, pinned: HashSet<PeerId>, rows: BTreeMap<String, PeerBindingRow>) -> PeerBindings {
        let mut b = PeerBindings::new(genesis, pinned);
        for (addr, row) in rows {
            match (Address::from_base58(&addr), row.peer.parse::<PeerId>()) {
                (Ok(a), Ok(peer)) if b.by_validator.len() < MAX_PEER_BINDINGS => {
                    b.by_validator.insert(a, Bound { peer, issued_ms: row.issued_ms });
                }
                (Ok(_), Ok(_)) => break,
                _ => tracing::warn!(%addr, peer = %row.peer, "skipping an unreadable persisted peer binding"),
            }
        }
        b
    }

    pub fn rows(&self) -> BTreeMap<String, PeerBindingRow> {
        self.by_validator
            .iter()
            .map(|(a, b)| (a.to_base58(), PeerBindingRow { peer: b.peer.to_base58(), issued_ms: b.issued_ms }))
            .collect()
    }

    pub fn get(&self, validator: &Address) -> Option<Bound> {
        self.by_validator.get(validator).copied()
    }

    pub fn len(&self) -> usize {
        self.by_validator.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_validator.is_empty()
    }

    /// Every peer a binding names, for reserving at start.
    pub fn bound_peers(&self) -> Vec<PeerId> {
        let mut v: Vec<PeerId> = self.by_validator.values().map(|b| b.peer).collect();
        v.sort();
        v.dedup();
        v
    }

    /// A validator's node, as far as this node can tell (SYNC-3): a peer some binding names, or
    /// one the operator reserved. A linear pass over at most [`MAX_PEER_BINDINGS`] entries, on a
    /// path already metered per peer.
    pub fn is_validator_peer(&self, peer: &PeerId) -> bool {
        self.pinned.contains(peer) || self.by_validator.values().any(|b| b.peer == *peer)
    }

    /// Peers reserved now: the pinned ones and every bound one, each once.
    pub fn reserved_count(&self) -> usize {
        let mut all: HashSet<&PeerId> = self.pinned.iter().collect();
        all.extend(self.by_validator.values().map(|b| &b.peer));
        all.len()
    }

    /// Whether no binding but `except`'s names `peer` and it is not pinned: then it may stop
    /// being reserved.
    fn unclaimed(&self, peer: &PeerId, except: &Address) -> bool {
        !self.pinned.contains(peer) && !self.by_validator.iter().any(|(a, b)| a != except && b.peer == *peer)
    }

    /// One delivered binding, in order, cheapest first:
    ///
    /// 1. Shape — a key or signature of the wrong length, an empty or oversized id, bytes that
    ///    are no peer id: `Reject`, the bytes are wrong whatever this node knows.
    /// 2. A signer in no validator set this replica knows: `Ignore` — it may be a validator of an
    ///    epoch this node has not reached, so the forwarder is not blamed.
    /// 3. `issued_ms` more than [`BINDING_MAX_AHEAD_MS`] past this node's clock, or not newer
    ///    than the one recorded for this validator: `Ignore`, and no signature is checked —
    ///    an old or repeated statement changes nothing and is not relayed. (gossipsub drops a
    ///    repeat of the same bytes itself for a minute; this is past that minute.)
    /// 4. At [`MAX_PEER_BINDINGS`] with no entry for this validator: entries of validators no
    ///    set knows any more make room first; with none, `Ignore`.
    /// 5. The signature, over this chain's genesis: fails, `Reject`.
    /// 6. Recorded: `Accept`, so relayed. A new or changed identity is reserved, the one it
    ///    replaces un-reserved unless another binding or the operator still claims it, and the
    ///    record persisted; the same identity only moves `issued_ms` forward.
    pub fn offer(&mut self, b: &PeerBinding, knows: impl Fn(&Address) -> bool, now_ms: u64) -> BindingVerdict {
        if !b.well_formed() {
            return BindingVerdict::report(Acceptance::Reject);
        }
        let Some(peer) = b.peer() else {
            return BindingVerdict::report(Acceptance::Reject);
        };
        let validator = b.validator.address();
        if !knows(&validator) {
            return BindingVerdict::report(Acceptance::Ignore);
        }
        if b.issued_ms > now_ms.saturating_add(BINDING_MAX_AHEAD_MS) {
            return BindingVerdict::report(Acceptance::Ignore);
        }
        let old = self.by_validator.get(&validator).copied();
        if old.is_some_and(|o| b.issued_ms <= o.issued_ms) {
            return BindingVerdict::report(Acceptance::Ignore);
        }
        let mut unreserve = Vec::new();
        let mut persist = false;
        if old.is_none() && self.by_validator.len() >= MAX_PEER_BINDINGS {
            let gone: Vec<Address> = self.by_validator.keys().filter(|a| !knows(a)).copied().collect();
            if gone.is_empty() {
                return BindingVerdict::report(Acceptance::Ignore);
            }
            for a in gone {
                if let Some(g) = self.by_validator.remove(&a) {
                    if self.unclaimed(&g.peer, &a) {
                        unreserve.push(g.peer);
                    }
                }
            }
            persist = true;
        }
        if !b.verify(&self.genesis) {
            // Nothing above changed the record unless room had to be made, and making room is
            // right whatever this message turns out to be.
            return BindingVerdict {
                report: Acceptance::Reject,
                change: persist.then_some(BindingChange { reserve: None, unreserve, persist }),
            };
        }
        let replaced = old.map(|o| o.peer).filter(|p| *p != peer);
        if let Some(p) = replaced {
            if self.unclaimed(&p, &validator) {
                unreserve.push(p);
            }
        }
        let is_new = old.is_none_or(|o| o.peer != peer);
        self.by_validator.insert(validator, Bound { peer, issued_ms: b.issued_ms });
        unreserve.retain(|p| *p != peer);
        let change = (is_new || persist).then(|| BindingChange {
            reserve: is_new.then_some(peer),
            unreserve,
            persist: true,
        });
        BindingVerdict { report: Acceptance::Accept, change }
    }
}

/// The binding gossip arm (audit v6, NET-1): metered against the forwarder's own bucket first —
/// over it, `Ignore`d, neither verified nor relayed, never `Reject`ed (an honest relay in a burst
/// looks the same) — then [`PeerBindings::offer`]. Every path is exactly one report.
#[allow(clippy::too_many_arguments)]
pub fn on_binding_gossip(
    bindings: &mut PeerBindings,
    bucket: &mut TokenBucket,
    limiter: &PeerLimiter,
    knows: impl Fn(&Address) -> bool,
    b: &PeerBinding,
    now: Instant,
    now_ms: u64,
) -> BindingVerdict {
    if !limiter.allow(bucket, now) {
        return BindingVerdict::report(Acceptance::Ignore);
    }
    bindings.offer(b, knows, now_ms)
}

/// Whether a validator announces its binding now: every [`BINDING_ANNOUNCE_EVERY`], and sooner
/// when a peer connected since the last one (`wanted`), but never twice within
/// [`BINDING_ANNOUNCE_MIN_GAP`]. `None` — never announced — is always due.
pub fn announce_due(last: Option<Instant>, wanted: bool, now: Instant) -> bool {
    match last {
        None => true,
        Some(at) => {
            let since = now.saturating_duration_since(at);
            since >= BINDING_ANNOUNCE_EVERY || (wanted && since >= BINDING_ANNOUNCE_MIN_GAP)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::Keypair;

    const NOW: u64 = 1_700_000_000_000;

    fn genesis() -> Hash {
        Hash::digest(b"chain 18")
    }

    fn validators() -> (Keypair, Keypair) {
        (Keypair::from_seed([1; 32]).unwrap(), Keypair::from_seed([2; 32]).unwrap())
    }

    fn knows_only(keys: &[&Keypair]) -> impl Fn(&Address) -> bool {
        let set: Vec<Address> = keys.iter().map(|k| k.address()).collect();
        move |a| set.contains(a)
    }

    fn accept_new(peer: PeerId) -> BindingVerdict {
        BindingVerdict { report: Acceptance::Accept, change: Some(BindingChange { reserve: Some(peer), unreserve: vec![], persist: true }) }
    }

    /// Audit v6, NET-1: a binding is recorded only when a known validator signed it for this
    /// chain and this identity. Another genesis, another peer id under the signature, a signer
    /// in no known set: nothing recorded, nothing reserved. The valid one is recorded, reserved
    /// and marked for persisting.
    #[test]
    fn only_a_known_validators_binding_for_this_chain_and_this_identity_is_recorded() {
        let (v, stranger) = validators();
        let peer = PeerId::random();
        let knows = knows_only(&[&v]);
        let mut b = PeerBindings::new(genesis(), HashSet::new());

        let foreign = PeerBinding::sign(&v, &Hash::digest(b"chain 17"), &peer, NOW);
        assert_eq!(b.offer(&foreign, &knows, NOW), BindingVerdict::report(Acceptance::Reject), "another chain's binding");
        let mut swapped = PeerBinding::sign(&v, &genesis(), &peer, NOW);
        swapped.peer_id = PeerId::random().to_bytes();
        assert_eq!(b.offer(&swapped, &knows, NOW), BindingVerdict::report(Acceptance::Reject), "another identity under the signature");
        let unknown = PeerBinding::sign(&stranger, &genesis(), &peer, NOW);
        assert_eq!(b.offer(&unknown, &knows, NOW), BindingVerdict::report(Acceptance::Ignore), "a key in no known set");
        assert!(b.is_empty() && !b.is_validator_peer(&peer), "nothing recorded");

        let good = PeerBinding::sign(&v, &genesis(), &peer, NOW);
        assert_eq!(b.offer(&good, &knows, NOW), accept_new(peer));
        assert_eq!(b.get(&v.address()), Some(Bound { peer, issued_ms: NOW }));
        assert!(b.is_validator_peer(&peer));
        assert_eq!(b.bound_peers(), vec![peer]);
    }

    /// Every path of the arm is exactly one report, and the paths that are not the peer's fault
    /// are `Ignore`, not `Reject`: over the forwarder's budget, a signer this node does not know
    /// yet, a statement from too far ahead, and a repeat or an older one — none of which is
    /// verified. `Reject` only for bytes that are wrong whatever this node knows.
    #[test]
    fn the_binding_arm_reports_every_message_once_and_blames_only_bad_bytes() {
        let (v, stranger) = validators();
        let knows = knows_only(&[&v]);
        let limiter = PeerLimiter::new(BINDING_GOSSIP_BURST, BINDING_GOSSIP_PER_SEC);
        let mut bucket = TokenBucket::default();
        let mut b = PeerBindings::new(genesis(), HashSet::new());
        let t = Instant::now();
        let peer = PeerId::random();
        let mut arm = |b: &mut PeerBindings, m: &PeerBinding| on_binding_gossip(b, &mut bucket, &limiter, &knows, m, t, NOW);

        let good = PeerBinding::sign(&v, &genesis(), &peer, NOW);
        let mut malformed = good.clone();
        malformed.signature = bincode::deserialize(&bincode::serialize(&vec![0u8; 3]).unwrap()).unwrap();
        let mut junk_id = good.clone();
        junk_id.peer_id = vec![0xff; 20];
        let mut bad_sig = PeerBinding::sign(&v, &genesis(), &peer, NOW + 1);
        bad_sig.signature = good.signature.clone();
        let cases: Vec<(&str, PeerBinding, Acceptance)> = vec![
            ("malformed", malformed, Acceptance::Reject),
            ("not a peer id", junk_id, Acceptance::Reject),
            ("unknown signer", PeerBinding::sign(&stranger, &genesis(), &peer, NOW), Acceptance::Ignore),
            ("from the future", PeerBinding::sign(&v, &genesis(), &peer, NOW + BINDING_MAX_AHEAD_MS + 1), Acceptance::Ignore),
            ("bad signature", bad_sig, Acceptance::Reject),
            ("valid", good.clone(), Acceptance::Accept),
            ("the same again", good.clone(), Acceptance::Ignore),
            ("older", PeerBinding::sign(&v, &genesis(), &peer, NOW - 1), Acceptance::Ignore),
            ("newer, same identity", PeerBinding::sign(&v, &genesis(), &peer, NOW + 5), Acceptance::Accept),
        ];
        for (what, m, want) in &cases {
            assert_eq!(arm(&mut b, m).report, *want, "{what}");
        }
        // The newer announcement of the same identity moved `issued_ms` and asked for nothing.
        assert_eq!(b.get(&v.address()), Some(Bound { peer, issued_ms: NOW + 5 }));
        assert_eq!(b.offer(&PeerBinding::sign(&v, &genesis(), &peer, NOW + 9), &knows, NOW).change, None);

        // Over the forwarder's budget: ignored, and the record does not move.
        let mut spent = TokenBucket::default();
        let tight = PeerLimiter::new(1, 0.0);
        assert!(tight.allow(&mut spent, t));
        let newer = PeerBinding::sign(&v, &genesis(), &PeerId::random(), NOW + 20);
        assert_eq!(on_binding_gossip(&mut b, &mut spent, &tight, &knows, &newer, t, NOW), BindingVerdict::report(Acceptance::Ignore));
        assert_eq!(b.get(&v.address()).unwrap().peer, peer);
    }

    /// A validator that moves to a new identity is reserved there and un-reserved at the old
    /// one — unless the operator pinned the old one, or another validator's binding names it.
    #[test]
    fn a_replaced_identity_is_unreserved_unless_something_else_claims_it() {
        let (v, w) = validators();
        let knows = knows_only(&[&v, &w]);
        let (p1, p2, pinned) = (PeerId::random(), PeerId::random(), PeerId::random());
        let mut b = PeerBindings::new(genesis(), [pinned].into_iter().collect());

        assert_eq!(b.offer(&PeerBinding::sign(&v, &genesis(), &p1, NOW), &knows, NOW), accept_new(p1));
        let moved = b.offer(&PeerBinding::sign(&v, &genesis(), &p2, NOW + 1), &knows, NOW);
        assert_eq!(moved.change, Some(BindingChange { reserve: Some(p2), unreserve: vec![p1], persist: true }));

        // Two validators claiming one identity: moving one leaves it reserved for the other.
        b.offer(&PeerBinding::sign(&w, &genesis(), &p2, NOW), &knows, NOW);
        let left = b.offer(&PeerBinding::sign(&v, &genesis(), &p1, NOW + 2), &knows, NOW);
        assert_eq!(left.change, Some(BindingChange { reserve: Some(p1), unreserve: vec![], persist: true }));

        // A pinned identity is never un-reserved.
        b.offer(&PeerBinding::sign(&w, &genesis(), &pinned, NOW + 1), &knows, NOW);
        let off_pinned = b.offer(&PeerBinding::sign(&w, &genesis(), &p2, NOW + 2), &knows, NOW);
        assert_eq!(off_pinned.change, Some(BindingChange { reserve: Some(p2), unreserve: vec![], persist: true }));
        assert!(b.is_validator_peer(&pinned), "pinned peers are validator peers whatever the bindings say");
        assert_eq!(b.reserved_count(), 3);
    }

    /// At the cap a newcomer is ignored while every entry is a known validator's; an entry whose
    /// validator no set knows any more makes room, and is un-reserved.
    #[test]
    fn the_record_is_capped_and_departed_validators_make_room() {
        let (v, _) = validators();
        let mut b = PeerBindings::new(genesis(), HashSet::new());
        let departed = Keypair::from_seed([9; 32]).unwrap().address();
        let departed_peer = PeerId::random();
        for i in 0..MAX_PEER_BINDINGS - 1 {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64 + 100).to_le_bytes());
            let a = Keypair::from_seed(seed).unwrap().address();
            b.by_validator.insert(a, Bound { peer: PeerId::random(), issued_ms: 1 });
        }
        b.by_validator.insert(departed, Bound { peer: departed_peer, issued_ms: 1 });
        assert_eq!(b.len(), MAX_PEER_BINDINGS);
        let peer = PeerId::random();
        let binding = PeerBinding::sign(&v, &genesis(), &peer, NOW);

        let everyone_known = |_: &Address| true;
        assert_eq!(b.offer(&binding, everyone_known, NOW), BindingVerdict::report(Acceptance::Ignore), "full of known validators");
        assert_eq!(b.len(), MAX_PEER_BINDINGS);

        let all_but_departed = |a: &Address| *a != departed;
        let v2 = b.offer(&binding, all_but_departed, NOW);
        assert_eq!(v2.report, Acceptance::Accept);
        assert_eq!(v2.change, Some(BindingChange { reserve: Some(peer), unreserve: vec![departed_peer], persist: true }));
        assert_eq!(b.len(), MAX_PEER_BINDINGS);
        assert!(b.get(&departed).is_none());
    }

    /// The record survives a restart: written through the storage row, read back from a reopened
    /// store, and the peers it names are what the next start reserves.
    #[test]
    fn a_recorded_binding_survives_a_storage_reopen() {
        let (v, w) = validators();
        let knows = knows_only(&[&v, &w]);
        let (p1, p2) = (PeerId::random(), PeerId::random());
        let dir = tempfile::tempdir().unwrap();
        let mut b = PeerBindings::new(genesis(), HashSet::new());
        for (k, p) in [(&v, p1), (&w, p2)] {
            let verdict = b.offer(&PeerBinding::sign(k, &genesis(), &p, NOW), &knows, NOW);
            assert!(verdict.change.is_some_and(|c| c.persist));
        }
        {
            let storage = crate::storage::Storage::open(dir.path()).unwrap();
            assert!(storage.peer_bindings().unwrap().is_empty(), "a fresh store holds none");
            storage.put_peer_bindings(&b.rows()).unwrap();
        }
        let storage = crate::storage::Storage::open(dir.path()).unwrap();
        let back = PeerBindings::load(genesis(), HashSet::new(), storage.peer_bindings().unwrap());
        assert_eq!(back.get(&v.address()), Some(Bound { peer: p1, issued_ms: NOW }));
        assert_eq!(back.get(&w.address()), Some(Bound { peer: p2, issued_ms: NOW }));
        let mut want = vec![p1, p2];
        want.sort();
        assert_eq!(back.bound_peers(), want);
        // The recorded `issued_ms` came back too: a replay of what was recorded is still stale.
        let mut reloaded = back;
        assert_eq!(reloaded.offer(&PeerBinding::sign(&v, &genesis(), &p2, NOW), &knows, NOW).report, Acceptance::Ignore);

        // An unreadable row is skipped, not fatal.
        let mut rows = storage.peer_bindings().unwrap();
        rows.insert("not an address".into(), PeerBindingRow { peer: "not a peer".into(), issued_ms: 0 });
        assert_eq!(PeerBindings::load(genesis(), HashSet::new(), rows).len(), 2);
    }

    #[test]
    fn a_validator_announces_every_minute_and_on_a_connect_at_most_every_ten_seconds() {
        let t = Instant::now();
        assert!(announce_due(None, false, t), "never announced");
        assert!(!announce_due(Some(t), true, t + Duration::from_secs(9)), "a connect inside the gap waits");
        assert!(announce_due(Some(t), true, t + BINDING_ANNOUNCE_MIN_GAP), "a connect after the gap announces");
        assert!(!announce_due(Some(t), false, t + Duration::from_secs(59)));
        assert!(announce_due(Some(t), false, t + BINDING_ANNOUNCE_EVERY));
    }
}
