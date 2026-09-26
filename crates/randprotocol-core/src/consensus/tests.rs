//! Deterministic multi-replica simulation of the HotStuff state machine.

use super::*;
use crate::confidential::{ConfidentialExecutor, StubExecutor};
use crate::genesis::{Genesis, GenesisValidator};
use crate::notes::{word8_to_hex, Envelope};
use crate::types::Transaction;
use std::collections::{BTreeMap, VecDeque};

struct Sim {
    nodes: Vec<HotStuff>,
    keys: Vec<Keypair>,
    addr_to_idx: BTreeMap<Address, usize>,
    /// The genesis every replica started from, as a node's config holds it.
    gs: crate::genesis::GenesisState,
    /// (to, msg). `None` = broadcast.
    queue: VecDeque<(Option<usize>, usize, ConsensusMessage)>,
    committed: Vec<Vec<CommittedBlock>>,
    /// `Action::RecordEpochSet`s each replica emitted, in order (the node persists these).
    recorded: Vec<Vec<(u64, crate::types::ValidatorSet)>>,
    /// The last `Action::PersistPending` each replica emitted — what storage holds under
    /// `META_PENDING_BLOCKS` (audit v5, CON-4) — and what `restart_durable` hands back.
    pending: Vec<Vec<Block>>,
    timers: Vec<Option<u64>>,
    pending_propose: Vec<Option<u64>>,
    fetches: Vec<(usize, Hash)>,
    now: u64,
    /// Node indices that are partitioned off (drop everything to/from them).
    down: Vec<bool>,
    /// `Action::SafetyViolation`s any replica emitted: a real node stops on one, and
    /// `assert_consistent` refuses to pass while one is recorded (audit v3).
    safety_violations: Vec<(usize, Hash, Hash)>,
}

/// A payout address for a test validator: phase S2 makes it a required genesis field, and
/// nothing in consensus reads it — it only has to parse.
fn payout(i: u8) -> String {
    crate::notes::ShieldedAddress { pk: [i as u32; 8], kem_ek: vec![i; crate::notes::KEM_EK_BYTES] }.to_string()
}

/// The genesis every simulation runs: no notes, faucet on, so a block body can be built out
/// of validator mints (the only transaction that needs no note to spend).
fn setup(n: u8, validators: u8) -> Sim {
    build(n, validators, crate::genesis::EPOCH_BLOCKS_DEFAULT, false)
}

/// A simulation with short epochs where every replica holds its signing key, including those
/// outside the genesis set: phase S2 lets such a replica observe until an epoch admits it.
fn setup_epochs(n: u8, validators: u8, epoch_blocks: u64) -> Sim {
    build(n, validators, epoch_blocks, true)
}

/// A simulation of a chain with a `bridge` section (and the `tokens` section it requires), where
/// B2's timestamp rules apply: block time is consensus input there.
fn setup_bridged(n: u8, validators: u8) -> Sim {
    build_with(n, validators, crate::genesis::EPOCH_BLOCKS_DEFAULT, false, true)
}

fn build(n: u8, validators: u8, epoch_blocks: u64, all_signers: bool) -> Sim {
    build_with(n, validators, epoch_blocks, all_signers, false)
}

thread_local! {
    /// The consensus domain version the fixtures below build their genesis with: 0 (chain 14's,
    /// the default) or 1. Set by [`with_domain`], so the same test bodies run under both.
    static DOMAIN_VERSION: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// The genesis field for the fixture's domain version: absent for 0, `Some(1)` for 1.
fn fixture_domain() -> Option<u32> {
    let v = DOMAIN_VERSION.with(|d| d.get());
    (v != 0).then_some(v)
}

fn with_domain<R>(version: u32, f: impl FnOnce() -> R) -> R {
    DOMAIN_VERSION.with(|d| d.set(version));
    let r = f();
    DOMAIN_VERSION.with(|d| d.set(0));
    r
}

fn build_with(n: u8, validators: u8, epoch_blocks: u64, all_signers: bool, bridged: bool) -> Sim {
    let keys: Vec<Keypair> = (1..=n).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect();
    let genesis = Genesis {
        chain_id: 1,
        timestamp_ms: 0,
        validators: keys[..validators as usize]
            .iter()
            .enumerate()
            .map(|(i, k)| GenesisValidator {
                public_key: k.public_key().clone(),
                // Genesis requires every validator to meet the staking minimum (S2).
                stake: crate::ledger::staking::MIN_STAKE as u128,
                payout: payout(i as u8 + 1),
            })
            .collect(),
        alloc: Vec::new(),
        faucet: true,
        confidential: true,
        // The admitted shape below is a Test-profile one, so the chain must say so too: a
        // mismatch is refused at genesis (audit v3, CHAIN9-1).
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&[3; 8]),
        epoch_blocks,
        max_program_words: None,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words: None,
        bridge: bridged.then(|| crate::bridge::BridgeConfig {
            emitter: [1; 32],
            guardians: vec![[2; 20]],
            emitters: BTreeMap::from([(2u16, [9u8; 32])]),
            pq_guardians: vec![Keypair::from_seed([0x70; 32]).unwrap().public_key().clone()],
            pause_key: Some(crate::crypto::Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
            rules_v2: None,
            guardian_set_index: None,
            burn_sequence: None,
        }),
        tokens: bridged.then(|| crate::genesis::TokensConfig {
            registration_fee: crate::genesis::MIN_REGISTRATION_FEE,
            tokens: vec![],
            mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None,
        }),
        aggregation: None,
        consensus_domain: fixture_domain(),
        staking: None,
    };
    let gs = genesis.build(&StubExecutor).unwrap();
    let mut cfg = ConsensusConfig::new(1, gs.validators.clone(), gs.hash());
    cfg.epoch_blocks = gs.epoch_blocks;
    cfg.domain = gs.signing_domain();
    let mut nodes = Vec::new();
    let mut addr_to_idx = BTreeMap::new();
    for (i, k) in keys.iter().enumerate() {
        let signer = if all_signers || i < validators as usize {
            Some(Keypair::from_seed(*k.seed()).unwrap())
        } else {
            None
        };
        nodes.push(HotStuff::new(cfg.clone(), signer, gs.block.clone(), gs.ledger.clone(), std::sync::Arc::new(StubExecutor)));
        addr_to_idx.insert(k.address(), i);
    }
    let mut sim = Sim {
        committed: vec![Vec::new(); n as usize],
        recorded: vec![Vec::new(); n as usize],
        pending: vec![Vec::new(); n as usize],
        timers: vec![None; n as usize],
        pending_propose: vec![None; n as usize],
        fetches: Vec::new(),
        down: vec![false; n as usize],
        safety_violations: Vec::new(),
        nodes,
        keys,
        gs,
        addr_to_idx,
        queue: VecDeque::new(),
        now: 0,
    };
    for i in 0..n as usize {
        let acts = sim.nodes[i].start();
        sim.handle(i, acts);
    }
    sim
}

impl Sim {
    /// What every replica in this simulation signs under: the fixture genesis's domain.
    fn domain(&self) -> SigningDomain {
        self.gs.signing_domain()
    }

    fn handle(&mut self, i: usize, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Broadcast(m) => self.queue.push_back((None, i, m)),
                Action::SendTo(addr, m) => {
                    let to = self.addr_to_idx[&addr];
                    self.queue.push_back((Some(to), i, m));
                }
                Action::Commit(blocks) => self.committed[i].extend(blocks),
                Action::RecordEpochSet(epoch, set) => self.recorded[i].push((epoch, set)),
                Action::ScheduleTimeout { view, .. } => self.timers[i] = Some(view),
                Action::ReadyToPropose { view } => self.pending_propose[i] = Some(view),
                Action::FetchBlock(h) => self.fetches.push((i, h)),
                Action::PersistSafety(..) => {}
                Action::PersistPending(blocks) => self.pending[i] = blocks,
                // A real node stops here; the simulator records it so a test can assert it, and
                // `assert_consistent` fails loudly if one ever appears unexpectedly.
                Action::SafetyViolation { committed, attempted } => {
                    self.safety_violations.push((i, committed, attempted))
                }
            }
        }
    }

    fn propose_all(&mut self, txs: Vec<Transaction>) {
        for i in 0..self.nodes.len() {
            if let Some(view) = self.pending_propose[i].take() {
                if self.down[i] {
                    continue;
                }
                self.now += 1;
                if let Ok(acts) = self.nodes[i].propose(view, txs.clone(), self.now) {
                    self.handle(i, acts);
                }
            }
        }
    }

    /// Serve block fetches from any alive node that has the block.
    fn serve_fetches(&mut self) {
        let fetches = std::mem::take(&mut self.fetches);
        for (who, h) in fetches {
            if self.down[who] {
                continue;
            }
            // Peers serve from their in-memory tree or, like the real node's
            // storage.block_by_hash, from their committed chain.
            let found = (0..self.nodes.len()).filter(|&j| j != who && !self.down[j]).find_map(|j| {
                self.nodes[j]
                    .block(&h)
                    .cloned()
                    .or_else(|| self.committed[j].iter().find(|cb| cb.block.hash() == h).map(|cb| cb.block.clone()))
            });
            if let Some(b) = found {
                match self.nodes[who].on_proposal(b, self.now) {
                    Ok(acts) => self.handle(who, acts),
                    Err(ConsensusError::UnknownParent(p)) => self.fetches.push((who, p)),
                    Err(_) => {}
                }
            }
        }
    }

    /// Deliver every queued message (FIFO). Returns number delivered.
    fn deliver_all(&mut self) -> usize {
        let mut n = 0;
        loop {
        let Some((to, from, msg)) = self.queue.pop_front() else {
            if self.fetches.is_empty() {
                break;
            }
            self.serve_fetches();
            continue;
        };
            if self.down[from] {
                continue;
            }
            let targets: Vec<usize> = match to {
                Some(t) => vec![t],
                None => (0..self.nodes.len()).filter(|&j| j != from).collect(),
            };
            for j in targets {
                if self.down[j] {
                    continue;
                }
                let r = self.nodes[j].on_message(msg.clone(), self.now);
                match r {
                    Ok(acts) => self.handle(j, acts),
                    // Like the real node: an unknown parent triggers a fetch.
                    Err(ConsensusError::UnknownParent(h)) => self.fetches.push((j, h)),
                    // Like the real node: a stale message, a vote we are not collecting, and a
                    // proposal past the view window (audit v4, CON-3) are dropped; the replica
                    // catches up through the QCs it assembles from gossiped votes.
                    Err(ConsensusError::Stale(_))
                    | Err(ConsensusError::NotLeader)
                    | Err(ConsensusError::ViewTooFarAhead { .. }) => {}
                    Err(e) => panic!("node {j} rejected message from {from}: {e}"),
                }
                n += 1;
            }
        }
        n
    }

    /// One round: leaders propose, messages flow. If nothing is pending
    /// afterwards the network has stalled, so time passes and timers fire.
    fn step(&mut self, txs: Vec<Transaction>) {
        self.propose_all(txs);
        self.deliver_all();
        let stalled = self.pending_propose.iter().enumerate().all(|(i, p)| p.is_none() || self.down[i]);
        if stalled {
            self.fire_timeouts();
        }
    }

    fn fire_timeouts(&mut self) {
        for i in 0..self.nodes.len() {
            if let Some(view) = self.timers[i].take() {
                if self.down[i] {
                    continue;
                }
                let acts = self.nodes[i].on_timeout(view);
                self.handle(i, acts);
            }
        }
        self.deliver_all();
    }

    fn assert_consistent(&self) {
        assert!(self.safety_violations.is_empty(), "safety violations reported: {:?}", self.safety_violations);
        let reference = &self.committed[0];
        for (i, c) in self.committed.iter().enumerate() {
            let n = reference.len().min(c.len());
            for k in 0..n {
                assert_eq!(c[k].block.hash(), reference[k].block.hash(), "node {i} diverges at {k}");
            }
            for (k, cb) in c.iter().enumerate() {
                assert_eq!(cb.block.height(), k as u64 + 1, "node {i} gap at {k}");
                assert_eq!(cb.qc.block_hash, cb.block.hash());
            }
        }
    }
}

fn env() -> Envelope {
    Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
}

/// A faucet mint of one unit to owner `[n; 8]` with blinding `[n; 8]`, signed by validator `key`.
fn mint(key: &Keypair, n: u32) -> Transaction {
    Transaction::mint(1, [n; 8], 0, [n; 8], env(), 1, key, &StubExecutor)
}

/// The node with a pending `ReadyToPropose`, and the view it is for.
fn pending_leader(sim: &Sim) -> (usize, u64) {
    (0..sim.nodes.len()).find_map(|i| sim.pending_propose[i].map(|v| (i, v))).expect("someone may propose")
}

fn proposal_of(actions: &[Action]) -> Block {
    actions
        .iter()
        .find_map(|a| match a {
            Action::Broadcast(ConsensusMessage::Proposal(b)) => Some(b.clone()),
            _ => None,
        })
        .expect("a proposal was broadcast")
}

/// Whether `actions` carry this replica's vote (a broadcast `Vote`).
fn votes(actions: &[Action]) -> bool {
    actions.iter().any(|a| matches!(a, Action::Broadcast(ConsensusMessage::Vote(_))))
}

/// A chain without a bridge reads no clock: `time` is bounded in block heights, so a replica
/// votes on a proposal however far ahead of its own clock the header's timestamp is — B2's drift
/// rule is gated on the bridge exactly like the rewind rule, so this chain is unchanged.
#[test]
fn a_bridgeless_proposal_far_ahead_of_the_local_clock_is_still_voted_for() {
    let mut sim = setup(2, 2);
    sim.now = 1_000_000;
    let (leader, view) = pending_leader(&sim);
    let follower = (leader + 1) % 2;
    let acts = sim.nodes[leader].propose(view, vec![], sim.now + 10_000_000).unwrap();
    let block = proposal_of(&acts);
    assert_eq!(block.header.timestamp_ms, sim.now + 10_000_000);
    let acts = sim.nodes[follower].on_proposal(block, sim.now).expect("no bridge, no clock rule");
    assert!(votes(&acts));
}

/// B2's vote rule (bridge hardening spec §3), inverting the test above for a bridged chain: a
/// validator does not vote for a block more than `MAX_CLOCK_DRIFT_MS` ahead of its own clock. The
/// block is still valid — it enters the tree, and a replica replaying committed history accepts
/// it — the rule only withholds this replica's vote. Exactly `+15 000` still gets the vote.
#[test]
fn a_bridged_proposal_far_ahead_of_the_local_clock_gets_no_vote_but_replays() {
    assert_eq!(MAX_CLOCK_DRIFT_MS, 15_000);
    // Every `setup_bridged` replica set is identical, so each case gets a fresh one.
    let fresh = || {
        let sim = setup_bridged(2, 2);
        let (leader, view) = pending_leader(&sim);
        (sim, leader, view)
    };
    // Within the step rule (the parent is genesis, at 0), and 30 s ahead of the follower.
    let (mut sim, leader, view) = fresh();
    let block = proposal_of(&sim.nodes[leader].propose(view, vec![], 30_000).unwrap());
    assert_eq!(block.header.timestamp_ms, 30_000);

    let (mut early, leader, _) = fresh();
    let follower = (leader + 1) % 2;
    let acts = early.nodes[follower].on_proposal(block.clone(), 30_000 - MAX_CLOCK_DRIFT_MS - 1).expect("a valid block");
    assert!(!votes(&acts), "a far-future timestamp withholds the vote");
    assert!(early.nodes[follower].has_block(&block.hash()), "but the block is valid and kept");

    let (mut edge, _, _) = fresh();
    let acts = edge.nodes[follower].on_proposal(block.clone(), 30_000 - MAX_CLOCK_DRIFT_MS).expect("a valid block");
    assert!(votes(&acts), "exactly the drift bound still votes");

    // Replay of committed history reads no local clock: the ledger path accepts it.
    let mut ledger = sim.gs.ledger.clone();
    ledger.apply_block(&block, &StubExecutor).expect("replay uses only the step rule");
}

/// A bridged leader's own proposal honours both B2 rules: after a stall its time is clamped to
/// `parent + MAX_TIMESTAMP_STEP_MS` (so its peers accept it), and a leader whose clock is ahead
/// of the parent stamps its own clock (never past its own drift bound). The chain then commits.
#[test]
fn a_bridged_leader_clamps_its_proposal_to_the_step_and_commits() {
    let mut sim = setup_bridged(4, 4);
    let (leader, view) = pending_leader(&sim);
    // Genesis is at 0 and the leader's clock is a day later: the block may only step 60 s.
    let now = 86_400_000;
    let acts = sim.nodes[leader].propose(view, vec![], now).unwrap();
    let block = proposal_of(&acts);
    assert_eq!(block.header.timestamp_ms, crate::ledger::MAX_TIMESTAMP_STEP_MS);
    assert!(votes(&acts), "the leader votes for its own block: it is behind, not ahead, of its clock");
    sim.handle(leader, acts);
    sim.now = now;
    sim.deliver_all();
    // A leader whose clock is inside the step stamps its own clock.
    sim.run_to_height(4, 40);
    sim.assert_consistent();
    for k in 1..sim.committed[0].len() {
        let (p, b) = (&sim.committed[0][k - 1].block.header, &sim.committed[0][k].block.header);
        assert!(b.timestamp_ms >= p.timestamp_ms && b.timestamp_ms <= p.timestamp_ms + crate::ledger::MAX_TIMESTAMP_STEP_MS);
    }
}

/// A leader whose clock lags its peers still never emits a block that moves
/// time backwards: the proposal time is `max(now, parent)`.
#[test]
fn proposal_timestamp_never_drops_below_the_parent() {
    let mut sim = setup(2, 2);
    sim.now = 50_000;
    sim.step(vec![]);
    let (leader, view) = pending_leader(&sim);
    let acts = sim.nodes[leader].propose(view, vec![], 0).unwrap();
    let block = proposal_of(&acts);
    let parent = sim.nodes[leader].block(&block.parent()).expect("parent is in the tree").clone();
    assert!(parent.header.timestamp_ms >= 50_000, "parent {}", parent.header.timestamp_ms);
    assert_eq!(block.header.timestamp_ms, parent.header.timestamp_ms);
}

#[test]
fn four_validators_commit_empty_blocks_in_lockstep() {
    let mut sim = setup(4, 4);
    for _ in 0..3 {
        sim.step(vec![]);
    }
    // Three proposals in: the third's votes just closed `high_qc`, certifying that block, but
    // the 3-chain commit rule hasn't closed on it yet (`committed_height` is still 0).
    let hs = &sim.nodes[0];
    let proposed_hash = hs.high_qc().block_hash;
    let qc_view = hs.high_qc().view;
    assert_eq!(hs.committed_height(), 0);
    assert_eq!(hs.certified(&proposed_hash), Some(qc_view));
    assert!(hs.has_block(&proposed_hash));
    assert_eq!(hs.certified(&Hash([7; 32])), None);
    for _ in 0..5 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
    // three-chain: after k proposals, k-3 blocks are committed
    assert!(sim.committed[0].len() >= 4, "committed {}", sim.committed[0].len());
    for c in &sim.committed {
        assert_eq!(c.len(), sim.committed[0].len());
    }
    assert!(sim.queue.is_empty());
}

#[test]
fn two_validators_need_both_signatures_and_commit() {
    let mut sim = setup(2, 2);
    for _ in 0..6 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
    assert!(sim.committed[0].len() >= 2);
    for cb in &sim.committed[0] {
        assert_eq!(cb.qc.votes.len(), 2);
    }
}

#[test]
fn single_validator_chain_advances_alone() {
    let mut sim = setup(1, 1);
    for _ in 0..5 {
        sim.step(vec![]);
    }
    assert!(sim.committed[0].len() >= 2);
}

#[test]
fn a_mint_is_included_and_applied_on_every_node() {
    let mut sim = setup(4, 4);
    let alice = Keypair::from_seed(*sim.keys[0].seed()).unwrap();
    let tx = mint(&alice, 5);
    sim.step(vec![tx.clone()]);
    for _ in 0..6 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
    let found = sim.committed[0].iter().find(|cb| cb.block.transactions.iter().any(|t| t.hash() == tx.hash()));
    assert!(found.is_some(), "mint committed");
    for node in &sim.nodes {
        let l = node.committed_ledger();
        assert!(l.has_commitment(&tx.commitments()[0]));
        assert_eq!(l.next_index(), 1);
    }
    // The same tx offered again is skipped by proposers (its commitment exists).
    sim.step(vec![tx.clone()]);
    sim.step(vec![]);
    let dup = sim.committed[0].iter().filter(|cb| cb.block.transactions.iter().any(|t| t.hash() == tx.hash())).count();
    assert_eq!(dup, 1);
}

#[test]
fn observer_full_node_commits_without_voting() {
    let mut sim = setup(5, 4);
    for _ in 0..8 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
    assert!(!sim.nodes[4].is_validator());
    assert!(sim.committed[4].len() >= 3);
    assert_eq!(sim.committed[4].len(), sim.committed[0].len());
}

#[test]
fn liveness_recovers_after_leader_timeout() {
    let mut sim = setup(4, 4);
    sim.step(vec![]);
    sim.step(vec![]);
    let before = sim.committed[0].len();
    // Take the leader of the current view offline so the view times out.
    let view = sim.nodes[0].view();
    let leader = sim.nodes[0].leader(view);
    let li = sim.addr_to_idx[&leader];
    sim.down[li] = true;
    sim.step(vec![]); // nothing happens: leader is down
    sim.fire_timeouts(); // everyone moves to view+1, next leader gets NewViews
    sim.step(vec![]);
    for _ in 0..8 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
    let alive: Vec<usize> = (0..4).filter(|&i| !sim.down[i]).collect();
    assert!(sim.committed[alive[0]].len() > before, "no progress after timeout");
    // Bring the leader back; it catches up via later proposals' QCs... only if it
    // learns the missing blocks. In the simulation it only sees new proposals, so it
    // asks for the parent (FetchBlock) and must not diverge.
    sim.down[li] = false;
    for _ in 0..4 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
}

#[test]
fn safety_under_partition_no_conflicting_commits() {
    // 4 validators, split 2/2: neither side has quorum, so nothing commits.
    let mut sim = setup(4, 4);
    for _ in 0..3 {
        sim.step(vec![]);
    }
    let base = sim.committed[0].len();
    let max_qc_before = sim.nodes.iter().map(|n| n.high_qc().view).max().unwrap();
    sim.down[2] = true;
    sim.down[3] = true;
    for _ in 0..6 {
        sim.step(vec![]);
        sim.fire_timeouts();
    }
    // No quorum on either side, so no new QC can form: high_qc never advances.
    for n in &sim.nodes {
        assert!(n.high_qc().view <= max_qc_before, "QC formed without quorum");
    }
    // Blocks certified before the split may still commit once their QC is
    // carried by a proposal, but never more than one such block.
    assert!(sim.committed[0].len() <= base + 1);
    assert!(sim.committed[1].len() <= base + 1);
    sim.assert_consistent();
    sim.down[2] = false;
    sim.down[3] = false;
    for _ in 0..3 {
        sim.fire_timeouts();
        sim.step(vec![]);
    }
    for _ in 0..8 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
    assert!(sim.committed[0].len() > base, "chain did not resume");
}

#[test]
fn rejects_proposal_from_wrong_leader_and_bad_signature() {
    let mut sim = setup(4, 4);
    sim.step(vec![]);
    let view = sim.nodes[1].view();
    let leader = sim.nodes[1].leader(view);
    let wrong = (0..4).find(|&i| sim.keys[i].address() != leader).unwrap();
    let tip = sim.nodes[wrong].high_qc().clone();
    let parent = sim.nodes[wrong].block(&tip.block_hash).unwrap().clone();
    let header = crate::types::BlockHeader {
        height: parent.height() + 1,
        view,
        parent: parent.hash(),
        proposer: sim.keys[wrong].public_key().clone(),
        timestamp_ms: 1,
        tx_root: Hash::ZERO,
        state_root: parent.header.state_root,
        justify: tip,
    };
    let block = Block::sign(&sim.domain(), header, vec![], &sim.keys[wrong]);
    let target = (0..4).find(|&i| i != wrong).unwrap();
    assert_eq!(sim.nodes[target].on_proposal(block.clone(), sim.now).unwrap_err(), ConsensusError::WrongLeader(view));

    let li = sim.addr_to_idx[&leader];
    let mut forged = block.clone();
    forged.header.proposer = sim.keys[li].public_key().clone();
    assert_eq!(sim.nodes[target].on_proposal(forged, sim.now).unwrap_err(), ConsensusError::BadSignature);
}

#[test]
fn timeout_backoff_is_exponential_and_capped() {
    let mut sim = setup(1, 1);
    let node = &mut sim.nodes[0];
    let mut durations = Vec::new();
    for _ in 0..6 {
        let v = node.view();
        let acts = node.on_timeout(v);
        for a in acts {
            if let Action::ScheduleTimeout { duration, .. } = a {
                durations.push(duration.as_millis());
            }
        }
    }
    assert_eq!(durations, vec![2000, 4000, 8000, 8000, 8000, 8000]);
}

#[test]
fn resume_from_persisted_head_continues_chain() {
    let mut sim = setup(2, 2);
    for _ in 0..6 {
        sim.step(vec![]);
    }
    let head = sim.committed[0].last().unwrap().clone();
    let cfg = config_of(&sim);
    let safety = sim.nodes[0].safety_state();
    let ledger = sim.nodes[0].committed_ledger().clone();
    let resumed = HotStuff::resume(
        cfg,
        Some(Keypair::from_seed(*sim.keys[0].seed()).unwrap()),
        head.block.clone(),
        head.qc.clone(),
        ledger,
        Some(safety.clone()),
        Vec::new(),
        sim.nodes[0].epoch_sets().clone(),
        std::sync::Arc::new(StubExecutor),
    );
    assert_eq!(resumed.committed_height(), head.block.height());
    assert!(resumed.view() >= safety.view);
    // The persisted `high_qc`/`locked_qc` come back when they are ahead of the head's QC (audit
    // v3, CON-1b); a node whose safety state is no newer than its head resumes on the head's QC.
    assert!(resumed.high_qc().view >= head.qc.view);
    assert_eq!(resumed.locked_qc().view, safety.locked_qc.view.max(head.qc.view));
}

/// The config a restarting node rebuilds from its genesis file.
fn config_of(sim: &Sim) -> ConsensusConfig {
    let mut cfg = ConsensusConfig::new(sim.gs.chain_id, sim.gs.validators.clone(), sim.gs.hash());
    cfg.epoch_blocks = sim.gs.epoch_blocks;
    // The signing domain comes from the genesis file too (audit v4): a restarted replica that
    // forgot it would sign under v0 on a v1 chain and every peer would refuse its proposals.
    cfg.domain = sim.gs.signing_domain();
    cfg
}

/// A restart hands `resume` a ledger rebuilt by `Storage::load_ledger`, which carries the state
/// families but no position: `Ledger::from_parts` starts at height 0. `resume` must move it to
/// the head block's height, or the mempool measures spec §7 step 5 against height 0 and refuses
/// every bundle with `time N is outside [0, 0]` until the second block after the restart.
#[test]
fn a_ledger_resumed_at_height_h_accepts_a_bundle_timed_at_h() {
    use crate::confidential::ConfidentialExecutor;
    use crate::gas;
    use crate::ledger::Ledger;
    use crate::types::Action;
    use crate::Bundle;

    let mut sim = setup(2, 2);
    for _ in 0..6 {
        sim.step(vec![]);
    }
    let head = sim.committed[0].last().unwrap().clone();
    let h = head.block.height();
    assert!(h >= 2, "the bug hides below height 2; committed head is {h}");

    // Exactly what a reload produces: the families, with no height and no timestamp.
    let mut reloaded: Ledger = sim.nodes[0].committed_ledger().clone();
    reloaded.set_height(0);
    reloaded.set_timestamp_ms(0);

    let cfg = config_of(&sim);
    let resumed = HotStuff::resume(
        cfg,
        Some(Keypair::from_seed(*sim.keys[0].seed()).unwrap()),
        head.block.clone(),
        head.qc.clone(),
        reloaded,
        Some(sim.nodes[0].safety_state()),
        Vec::new(),
        sim.nodes[0].epoch_sets().clone(),
        std::sync::Arc::new(StubExecutor),
    );
    let tip = resumed.tip_ledger();
    assert_eq!(tip.height(), h, "the resumed tip ledger must sit at the head block's height");
    assert_eq!(tip.timestamp_ms(), head.block.header.timestamp_ms);

    // A freshly built bundle stamps `time` with the head height; it must be admissible.
    let mut b = Bundle {
        anchor: tip.root(),
        nullifiers: [[9; 8], [10; 8], [19; 8], [20; 8]],
        commitments: [[11; 8], [12; 8], [21; 8], [22; 8]],
        fee: gas::BUNDLE_BASE,
        burn_a: 0,
        burn_r: 0,
        burn_asset: 0,
        time: h as u32,
        envelopes: [env(), env(), env(), env()],
        proof: vec![],
    };
    let d = StubExecutor.bundle_digest(&b.digest_input());
    b.proof = StubExecutor::make_bundle_proof(&tip.hc_bundle(), &d, &[0; 8]);
    let tx = StubExecutor::bound(Transaction::shielded(1, b, Action::None));
    tip.validate(&tx, &StubExecutor).expect("a bundle timed at the head height is admissible after a restart");
}

#[test]
fn late_starter_syncs_view_with_partner() {
    // Two validators: node 1 is offline while node 0 times out many views.
    let mut sim = setup(2, 2);
    sim.down[1] = true;
    for _ in 0..6 {
        sim.fire_timeouts();
    }
    assert!(sim.nodes[0].view() >= 6);
    assert_eq!(sim.nodes[1].view(), 1);
    // Node 1 comes online; node 0's next NewView pulls it forward.
    sim.down[1] = false;
    sim.fire_timeouts();
    assert_eq!(sim.nodes[1].view(), sim.nodes[0].view());
    for _ in 0..8 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
    assert!(sim.committed[0].len() >= 2, "no progress after view sync");
    assert_eq!(sim.committed[0].len(), sim.committed[1].len());
}

// ---------------------------------------------------------------------------
// Restart / persistence tests
// ---------------------------------------------------------------------------

impl Sim {
    /// Simulate a process restart of node `i`: everything in memory is lost except
    /// what a real node persists (committed head + QC, committed ledger, safety state).
    fn restart(&mut self, i: usize) {
        let old = &self.nodes[i];
        let safety = old.safety_state();
        let ledger = old.committed_ledger().clone();
        let (head, qc) = match self.committed[i].last() {
            Some(cb) => (cb.block.clone(), cb.qc.clone()),
            None => {
                let g = old.block(&old.committed_hash()).unwrap().clone();
                let gh = g.hash();
                (g, QuorumCertificate::genesis(gh))
            }
        };
        let cfg = config_of(self);
        let epoch_sets = old.epoch_sets().clone();
        let signer = if old.is_validator() { Some(Keypair::from_seed(*self.keys[i].seed()).unwrap()) } else { None };
        // No pending set: the restart this models is the one where a QC formed and the process
        // died before the certified blocks were written (audit v4, review focus 1; audit v5
        // CON-4) — `restart_durable` is the restart with what storage holds.
        self.nodes[i] =
            HotStuff::resume(cfg, signer, head, qc, ledger, Some(safety), Vec::new(), epoch_sets, std::sync::Arc::new(StubExecutor));
        self.timers[i] = None;
        self.pending_propose[i] = None;
        let acts = self.nodes[i].start();
        self.handle(i, acts);
    }

    /// `restart`, with the pending set the replica last persisted (`Action::PersistPending`)
    /// handed back to `resume` — the restart a real node makes (audit v5, CON-4).
    fn restart_durable(&mut self, i: usize) {
        let old = &self.nodes[i];
        let safety = old.safety_state();
        let ledger = old.committed_ledger().clone();
        let (head, qc) = match self.committed[i].last() {
            Some(cb) => (cb.block.clone(), cb.qc.clone()),
            None => {
                let g = old.block(&old.committed_hash()).unwrap().clone();
                let gh = g.hash();
                (g, QuorumCertificate::genesis(gh))
            }
        };
        let cfg = config_of(self);
        let epoch_sets = old.epoch_sets().clone();
        let signer = if old.is_validator() { Some(Keypair::from_seed(*self.keys[i].seed()).unwrap()) } else { None };
        let pending = self.pending[i].clone();
        self.nodes[i] =
            HotStuff::resume(cfg, signer, head, qc, ledger, Some(safety), pending, epoch_sets, std::sync::Arc::new(StubExecutor));
        self.timers[i] = None;
        self.pending_propose[i] = None;
        let acts = self.nodes[i].start();
        self.handle(i, acts);
    }

    fn assert_fully_equal(&self) {
        self.assert_consistent();
        let n = self.committed[0].len();
        for (i, c) in self.committed.iter().enumerate() {
            assert_eq!(c.len(), n, "node {i} has {} committed blocks, node 0 has {n}", c.len());
        }
        let root = self.nodes[0].committed_ledger().state_root();
        for (i, node) in self.nodes.iter().enumerate() {
            assert_eq!(node.committed_ledger().state_root(), root, "node {i} ledger differs");
        }
    }
}

/// Audit v3 (the CON-3 candidate): a three-chain that commits a block which does not descend from
/// this replica's committed head is conflicting finality — the set finalized a branch that
/// contradicts what this node already served as final. It used to be a log line and a `return`,
/// leaving the node answering `rand_getFinality` for a history it had just been shown was wrong.
/// It is now an `Action::SafetyViolation`, which stops the node.
#[test]
fn a_commit_that_skips_the_committed_head_is_reported_as_a_safety_violation() {
    let mut sim = setup(4, 4);
    for _ in 0..4 {
        sim.step(vec![]);
    }
    let victim = 0;
    // Rewrite this replica's committed head to a block nothing descends from: the same position a
    // node is in when the set commits a branch conflicting with its own committed history.
    sim.nodes[victim].force_committed_hash_for_testing(Hash::digest(b"a branch we never had"));
    let mut acts = Vec::new();
    for _ in 0..8 {
        sim.propose_all(vec![]);
        let proposals: Vec<Block> = sim
            .queue
            .iter()
            .filter_map(|(_, _, m)| match m {
                ConsensusMessage::Proposal(b) => Some(b.clone()),
                _ => None,
            })
            .collect();
        for b in proposals {
            if let Ok(a) = sim.nodes[victim].on_proposal(b, sim.now) {
                acts.extend(a);
            }
        }
        sim.step(vec![]);
    }
    assert!(
        acts.iter().any(|a| matches!(a, Action::SafetyViolation { .. })),
        "a commit off the committed head was not reported"
    );
}

/// Review I3: a resumed replica derives its current validator set from a block it holds.
///
/// `resume` restores a `high_qc` that is usually ahead of the committed head, and a fresh replica
/// holds only the head — so `refresh_current_set`'s old early return left `current` at the epoch-0
/// set after every restart and every sync batch. On a chain whose set never changes that is
/// invisible; after the first bond or unbond it means votes, new views and leaders are all judged
/// against a set the chain has left behind. The set a restarted node holds must be the one for the
/// epoch its head sits in.
#[test]
fn a_resumed_replica_holds_the_set_for_its_heads_epoch() {
    // Two-block epochs, so a handful of steps carries the chain past several boundaries.
    let mut sim = setup_epochs(4, 4, 2);
    for _ in 0..8 {
        sim.step(vec![]);
    }
    let victim = 0;
    let height = sim.nodes[victim].committed_height();
    assert!(height >= 4, "the chain crossed at least two epoch boundaries: height {height}");
    let want_epoch = (height + 1) / 2;
    assert!(want_epoch > 0, "the head is past epoch 0");

    sim.restart(victim);

    // The epoch, not the set: every epoch of this simulated chain derives the same four
    // validators, so comparing sets would pass whatever the replica believes. What goes stale is
    // which epoch it thinks it is in, and on a chain where a bond has changed the register that is
    // the difference between the right set and a retired one.
    assert_eq!(
        sim.nodes[victim].current_epoch(),
        want_epoch,
        "a resumed replica still holds epoch {}'s set at height {height}",
        sim.nodes[victim].current_epoch()
    );
}

/// Audit v3 CON-1b: the lock is a promise, and a restart must not break it. A validator locked on
/// a branch at view v, restarted, must still refuse a proposal on a conflicting branch whose
/// justify is older than its lock. Before the fix `resume` threw the persisted `locked_qc` away
/// and reset the lock to the committed head's QC, so the restarted node voted.
#[test]
fn a_resumed_validator_keeps_its_lock() {
    let mut sim = setup(4, 4);
    for _ in 0..4 {
        sim.step(vec![]);
    }
    // A node whose lock is ahead of its committed head: that is the promise a restart must keep.
    let victim = (0..4)
        .find(|&i| {
            let hs = &sim.nodes[i];
            hs.locked_qc().view > hs.committed_qc_view()
        })
        .expect("someone is locked past its committed head");
    let locked_before = sim.nodes[victim].locked_qc().clone();

    sim.restart(victim);

    assert_eq!(
        sim.nodes[victim].locked_qc().view,
        locked_before.view,
        "the lock must survive a restart"
    );
    assert_eq!(sim.nodes[victim].locked_qc().block_hash, locked_before.block_hash);

    // The field is not the point; the withheld vote is (review M5, and round 2's T1 — the first
    // version of this assertion could not fail, because its hand-built block justified with a
    // genesis QC that `on_proposal` refuses as BadJustify long before `try_vote` runs, and an
    // `unwrap_or_default` hid the refusal).
    //
    // So: a real, valid proposal on the committed head, justified by the head's own certificate —
    // which is *older* than this replica's lock. The replica holds the locked block no longer (a
    // restart drops the tree above the head), so it cannot check that this branch extends what it
    // promised, and it must withhold the vote and fetch the locked block instead.
    let head = sim.committed[victim].last().expect("the chain committed above").clone();
    let parent = head.block.clone();
    let height = parent.height() + 1;
    let view = sim.nodes[victim].view();
    let li = sim.addr_to_idx[&sim.nodes[victim].leader(view)];
    let proposer = sim.keys[li].public_key().clone();
    let proposer_addr = proposer.address();
    // The state the block must publish, built the way a proposer builds it.
    let mut after = sim.nodes[victim].committed_ledger().clone();
    after.set_height(height);
    after.set_timestamp_ms(sim.now);
    after.apply_transactions(&[], &proposer_addr, &StubExecutor).expect("an empty block applies");
    after.close_block(height, &proposer_addr);
    let header = crate::types::BlockHeader {
        height,
        view,
        parent: parent.hash(),
        proposer,
        timestamp_ms: sim.now,
        tx_root: Block::tx_root(&[]),
        state_root: after.state_root(),
        justify: head.qc.clone(),
    };
    let conflicting = Block::sign(&sim.domain(), header, vec![], &sim.keys[li]);
    let locked_hash = sim.nodes[victim].locked_qc().block_hash;
    assert!(!sim.nodes[victim].has_block(&locked_hash), "the restart dropped the locked block");
    let acts = sim.nodes[victim]
        .on_proposal(conflicting, sim.now)
        .expect("a well-formed proposal on the committed head is accepted");
    assert!(
        !acts.iter().any(|a| matches!(
            a,
            Action::Broadcast(ConsensusMessage::Vote(_)) | Action::SendTo(_, ConsensusMessage::Vote(_))
        )),
        "a restarted replica voted on a branch it cannot check against its own lock"
    );
    assert!(
        acts.iter().any(|a| matches!(a, Action::FetchBlock(h) if *h == locked_hash)),
        "the replica withheld the vote without asking for the block that would release it: {acts:?}"
    );
}

/// The same promise on the sync path: `apply_synced` rebuilds the replica through `resume` after
/// every batch, so a node that syncs must not forget its lock either.
#[test]
fn a_stale_safety_state_never_lowers_the_lock() {
    let mut sim = setup(4, 4);
    for _ in 0..4 {
        sim.step(vec![]);
    }
    let victim = 0;
    let head_qc_view = sim.nodes[victim].committed_qc_view();
    let mut safety = sim.nodes[victim].safety_state();
    // A safety state older than the committed head (what a node that fell behind persists) must
    // leave the lock at the head's QC, never below it.
    safety.locked_qc = QuorumCertificate::genesis(sim.nodes[victim].committed_hash());
    safety.high_qc = safety.locked_qc.clone();
    let cfg = config_of(&sim);
    let old = &sim.nodes[victim];
    let ledger = old.committed_ledger().clone();
    let (head, qc) = match sim.committed[victim].last() {
        Some(cb) => (cb.block.clone(), cb.qc.clone()),
        None => panic!("the chain committed above"),
    };
    let epoch_sets = old.epoch_sets().clone();
    let hs = HotStuff::resume(
        cfg,
        Some(Keypair::from_seed(*sim.keys[victim].seed()).unwrap()),
        head,
        qc,
        ledger,
        Some(safety),
        Vec::new(),
        epoch_sets,
        std::sync::Arc::new(StubExecutor),
    );
    assert_eq!(hs.locked_qc().view, head_qc_view, "a stale lock is raised to the head, never lowered");
}

#[test]
fn restart_does_not_double_vote_for_same_view() {
    // Safety across restart: a validator that voted in view v, crashed, and came
    // back must refuse to vote again in view v even for a different block.
    let mut sim = setup(4, 4);
    sim.step(vec![]);
    sim.step(vec![]);
    // Capture the next fresh proposal and pick a victim that is not its proposer.
    sim.propose_all(vec![]);
    let proposal = sim
        .queue
        .iter()
        .find_map(|(_, _, m)| match m {
            ConsensusMessage::Proposal(b) => Some(b.clone()),
            _ => None,
        })
        .expect("leader proposed");
    let view = proposal.view();
    let li = sim.addr_to_idx[&proposal.proposer()];
    // The next view's leader delivers its own vote internally (no network action), so skip it too.
    let next_leader = sim.addr_to_idx[&sim.nodes[0].leader(view + 1)];
    let victim = (0..4).find(|&i| i != li && i != next_leader).unwrap();
    // Votes are broadcast; a SendTo from an older scheme would count too.
    let has_vote = |acts: &[Action], view: u64| {
        acts.iter().any(|a| match a {
            Action::Broadcast(ConsensusMessage::Vote(v)) | Action::SendTo(_, ConsensusMessage::Vote(v)) if v.view == view => true,
            _ => false,
        })
    };
    let acts = sim.nodes[victim].on_proposal(proposal.clone(), sim.now).unwrap();
    let voted = has_vote(&acts, view);
    assert!(voted, "victim should vote the first time");
    assert!(acts.iter().any(|a| matches!(a, Action::PersistSafety(..))), "safety must be persisted before voting");
    assert_eq!(sim.nodes[victim].safety_state().last_voted_view, view);

    sim.restart(victim);
    assert_eq!(sim.nodes[victim].safety_state().last_voted_view, view, "last_voted_view survives restart");
    // Same proposal again: block is unknown to the fresh replica, but it must not vote.
    let acts = sim.nodes[victim].on_proposal(proposal, sim.now).unwrap_or_default();
    assert!(!has_vote(&acts, view), "restarted node voted twice in view {view}");
    // A conflicting block for the same view from the same leader must also get no vote.
    let mut conflicting = sim.nodes[li].block(&sim.nodes[li].high_qc().block_hash).cloned();
    if let Some(parent) = conflicting.take() {
        let header = crate::types::BlockHeader {
            height: parent.height() + 1,
            view,
            parent: parent.hash(),
            proposer: sim.keys[li].public_key().clone(),
            timestamp_ms: 99,
            tx_root: Hash::ZERO,
            state_root: parent.header.state_root,
            justify: sim.nodes[li].high_qc().clone(),
        };
        let b = Block::sign(&sim.domain(), header, vec![], &sim.keys[li]);
        let acts = sim.nodes[victim].on_proposal(b, sim.now).unwrap_or_default();
        assert!(!acts.iter().any(|a| match a {
            Action::Broadcast(ConsensusMessage::Vote(_)) | Action::SendTo(_, ConsensusMessage::Vote(_)) => true,
            _ => false,
        }));
    }
    sim.queue.clear();
}

#[test]
fn restart_mid_run_rejoins_and_stays_consistent() {
    let mut sim = setup(4, 4);
    for _ in 0..5 {
        sim.step(vec![]);
    }
    let before = sim.committed[2].len();
    sim.restart(2);
    assert_eq!(sim.committed[2].len(), before, "restart must not lose committed blocks");
    assert_eq!(sim.nodes[2].committed_height(), before as u64);
    for _ in 0..10 {
        sim.step(vec![]);
    }
    sim.assert_fully_equal();
    assert!(sim.committed[2].len() > before + 3, "restarted node stopped committing");
}

#[test]
fn every_node_restarted_in_turn_repeatedly() {
    let mut sim = setup(4, 4);
    sim.step(vec![]);
    for round in 0..3 {
        for i in 0..4 {
            sim.restart(i);
            for _ in 0..3 {
                sim.step(vec![]);
            }
            sim.assert_consistent();
        }
        let _ = round;
    }
    for _ in 0..6 {
        sim.step(vec![]);
    }
    sim.assert_fully_equal();
    assert!(sim.committed[0].len() >= 20, "only {} blocks after restarts", sim.committed[0].len());
}

#[test]
fn restart_with_mints_keeps_ledgers_identical() {
    let mut sim = setup(4, 4);
    let alice = Keypair::from_seed(*sim.keys[0].seed()).unwrap();
    for n in 0..3u32 {
        let tx = mint(&alice, n + 1);
        // The simulator has no mempool: keep offering the tx until a proposer includes it.
        let mut tries = 0;
        while !sim.nodes[0].tip_ledger().has_commitment(&tx.commitments()[0]) {
            sim.step(vec![tx.clone()]);
            tries += 1;
            assert!(tries < 20, "tx {n} never included");
        }
        sim.restart((n as usize + 1) % 4);
        sim.step(vec![]);
    }
    for _ in 0..8 {
        sim.step(vec![]);
    }
    sim.assert_fully_equal();
    for node in &sim.nodes {
        let l = node.committed_ledger();
        assert_eq!(l.next_index(), 3);
        for n in 1..=3u32 {
            assert!(l.has_commitment(&mint(&alice, n).commitments()[0]), "note {n} missing");
        }
    }
}

#[test]
fn offline_node_restarts_from_old_head_and_catches_up() {
    let mut sim = setup(4, 4);
    for _ in 0..4 {
        sim.step(vec![]);
    }
    sim.down[3] = true;
    for _ in 0..24 {
        sim.step(vec![]);
    }
    let others = sim.committed[0].len();
    assert!(others > sim.committed[3].len() + 5, "others did not advance: others {others}, node3 {}", sim.committed[3].len());
    // Comes back from disk with its stale head.
    sim.down[3] = false;
    sim.restart(3);
    for _ in 0..16 {
        sim.step(vec![]);
    }
    sim.assert_fully_equal();
}

#[test]
fn two_of_four_down_halts_then_recovers_without_fork() {
    let mut sim = setup(4, 4);
    for _ in 0..4 {
        sim.step(vec![]);
    }
    sim.down[1] = true;
    sim.down[2] = true;
    let max_qc = sim.nodes.iter().map(|n| n.high_qc().view).max().unwrap();
    for _ in 0..8 {
        sim.step(vec![]);
    }
    for n in &sim.nodes {
        assert!(n.high_qc().view <= max_qc, "QC formed with 2 of 4 validators");
    }
    // Both come back via restart (their memory is gone).
    sim.down[1] = false;
    sim.down[2] = false;
    sim.restart(1);
    sim.restart(2);
    for _ in 0..20 {
        sim.step(vec![]);
    }
    sim.assert_fully_equal();
    assert!(sim.nodes[0].high_qc().view > max_qc, "chain did not resume");
}

#[test]
fn a_ghost_high_qc_is_not_re_raised_by_a_new_view_once_it_proved_unobtainable() {
    // The 2026-09-24 mainnet stall, reduced: after a whole-fleet restart every replica's
    // persisted high QC certified a block above the head that no node held any more. Each fell
    // back to the head QC once its fetches failed — and every NewView from a peer re-announced
    // the ghost, raising the high QC again, so no leader ever proposed on the head: a livelock
    // that held chain 14 for hours. A QC on a block that proved unobtainable stays ignored until
    // the block itself arrives.
    let mut sim = setup(4, 4);
    for _ in 0..4 {
        sim.step(vec![]);
    }
    let ghost_qc = sim.nodes[0].high_qc().clone();
    let ghost = ghost_qc.block_hash;
    for i in 0..4 {
        sim.restart(i);
    }
    let key1 = Keypair::from_seed(*sim.keys[1].seed()).unwrap();
    let view = sim.nodes[0].view() + 1;
    let nv = NewView::sign(&sim.domain(), view, ghost_qc.clone(), &key1);
    let acts = sim.nodes[0].on_new_view(nv).unwrap();
    sim.handle(0, acts);
    assert_eq!(sim.nodes[0].high_qc().block_hash, ghost, "the first announcement is believed");
    let acts = sim.nodes[0].fallback_high_qc(&ghost);
    sim.handle(0, acts);
    let head_view = sim.nodes[0].committed_qc_view();
    assert_eq!(sim.nodes[0].high_qc().view, head_view, "fell back to the head");
    // The re-announcement, from another peer at a later view: what every NewView carried.
    let key2 = Keypair::from_seed(*sim.keys[2].seed()).unwrap();
    let nv2 = NewView::sign(&sim.domain(), view + 1, ghost_qc, &key2);
    let acts = sim.nodes[0].on_new_view(nv2).unwrap();
    sim.handle(0, acts);
    assert_eq!(sim.nodes[0].high_qc().view, head_view, "a QC on a block proven unobtainable is not raised again");
    assert_eq!(sim.nodes[0].high_qc().block_hash, sim.nodes[0].committed_hash(), "the head is what the next proposal extends");
}

#[test]
fn leader_falls_back_when_high_qc_block_is_unobtainable() {
    // A restarted validator learns (via NewView) of a QC for a block that no reachable peer
    // holds. Without the fallback it could never propose; with it, the chain continues.
    let mut sim = setup(4, 4);
    for _ in 0..4 {
        sim.step(vec![]);
    }
    // Take a QC for an uncommitted block from node 0's memory.
    let ghost_qc = sim.nodes[0].high_qc().clone();
    assert!(ghost_qc.view > 0);
    let ghost = ghost_qc.block_hash;
    // Every node restarts from disk: the block behind ghost_qc exists nowhere any more.
    for i in 0..4 {
        sim.restart(i);
        assert!(!sim.nodes[i].has_block(&ghost), "restart must drop uncommitted blocks");
    }
    // Node 1 re-announces the ghost QC, as a lagging peer would.
    let key1 = Keypair::from_seed(*sim.keys[1].seed()).unwrap();
    let view = sim.nodes[0].view() + 1;
    let nv = NewView::sign(&sim.domain(), view, ghost_qc.clone(), &key1);
    for i in 0..4 {
        let acts = sim.nodes[i].on_new_view(nv.clone()).unwrap();
        sim.handle(i, acts);
    }
    assert!(sim.nodes.iter().all(|n| n.high_qc().block_hash == ghost));
    // Fetches fail (no one has it); the node layer then calls the fallback on every replica, and
    // again on every later fetch of the ghost — the NewViews still queued re-announce it. The
    // fallback moves the high QC only (audit v4, CON-4): the lock waits for signed evidence.
    fn fallback_all(sim: &mut Sim) {
        for i in 0..4 {
            let h = sim.nodes[i].high_qc().block_hash;
            if sim.nodes[i].has_block(&h) {
                continue;
            }
            let locked_before = sim.nodes[i].locked_qc().clone();
            let acts = sim.nodes[i].fallback_high_qc(&h);
            sim.handle(i, acts);
            assert_eq!(sim.nodes[i].high_qc().view, sim.nodes[i].committed_qc_view(), "the high QC fell back to the head");
            assert_eq!(*sim.nodes[i].locked_qc(), locked_before, "an unsigned failure never touches the lock");
        }
    }
    sim.fetches.clear();
    fallback_all(&mut sim);
    // The signed evidence the node layer gathers: every other validator attests it does not hold
    // the block a replica is locked on — more than a third of the stake, so the lock releases.
    for i in 0..4 {
        let locked = sim.nodes[i].locked_qc().clone();
        if locked.view <= sim.nodes[i].committed_qc_view() || sim.nodes[i].has_block(&locked.block_hash) {
            continue;
        }
        for j in (0..4).filter(|&j| j != i) {
            let n = NotHeld::sign(&sim.keys[j], &sim.gs.hash(), &locked.block_hash);
            sim.nodes[i].record_not_held(&n);
        }
        assert_eq!(sim.nodes[i].locked_qc().view, sim.nodes[i].committed_qc_view(), "released on more than a third");
    }
    let before = sim.committed[0].len();
    for _ in 0..12 {
        fallback_all(&mut sim);
        sim.step(vec![]);
        sim.fetches.clear();
    }
    sim.assert_consistent();
    assert!(sim.committed[0].len() > before, "chain did not resume after fallback");
}

// ---------------------------------------------------------------------------
// Bounds and commit-rule regression tests
// ---------------------------------------------------------------------------

/// Drive a single-validator replica directly, proposing at chosen views.
struct OneNode {
    node: HotStuff,
    now: u64,
}

fn one_node_with(cfg: ConsensusConfig, gs_block: Block, gs_ledger: crate::ledger::Ledger, key: Keypair) -> OneNode {
    let node = HotStuff::new(cfg, Some(key), gs_block, gs_ledger, std::sync::Arc::new(StubExecutor));
    OneNode { node, now: 0 }
}

fn one_node() -> OneNode {
    let (cfg, gs, key) = one_node_parts();
    one_node_with(cfg, gs.block.clone(), gs.ledger.clone(), key)
}

fn one_node_parts() -> (ConsensusConfig, crate::genesis::GenesisState, Keypair) {
    let key = Keypair::from_seed([1; 32]).unwrap();
    let genesis = Genesis {
        chain_id: 1,
        timestamp_ms: 0,
        validators: vec![GenesisValidator { public_key: key.public_key().clone(), stake: crate::ledger::staking::MIN_STAKE as u128, payout: payout(1) }],
        alloc: Vec::new(),
        faucet: true,
        confidential: true,
        // The admitted shape below is a Test-profile one, so the chain must say so too: a
        // mismatch is refused at genesis (audit v3, CHAIN9-1).
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&[3; 8]),
        epoch_blocks: crate::genesis::EPOCH_BLOCKS_DEFAULT,
        max_program_words: None,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words: None,
        bridge: None,
        tokens: None,
        aggregation: None,
        consensus_domain: fixture_domain(),
        staking: None,
    };
    let gs = genesis.build(&StubExecutor).unwrap();
    let mut cfg = ConsensusConfig::new(1, gs.validators.clone(), gs.hash());
    cfg.domain = gs.signing_domain();
    (cfg, gs, key)
}

impl OneNode {
    fn propose(&mut self, view: u64) -> Vec<Action> {
        self.now += 1;
        self.node.propose(view, vec![], self.now).expect("propose")
    }
}

fn commits(acts: &[Action]) -> bool {
    acts.iter().any(|a| matches!(a, Action::Commit(_)))
}

#[test]
fn commit_rule_requires_three_consecutive_views() {
    let mut n = one_node();
    n.node.start();
    assert!(!commits(&n.propose(1))); // B1@1
    assert!(!commits(&n.propose(2))); // B2@2
    // Skip view 3: the replica times out into view 4, so the next QC chain has a gap.
    n.node.on_timeout(3);
    assert_eq!(n.node.view(), 4);
    assert!(!commits(&n.propose(4))); // B3@4
    // B4@5 closes a 3-chain over B1 with QCs at views 1, 2, 4: not consecutive,
    // so B1 must NOT commit (the old rule committed it here).
    assert!(!commits(&n.propose(5)), "non-consecutive three-chain committed");
    assert_eq!(n.node.committed_height(), 0);
    // B5@6: QCs at 2, 4, 5 over B2 — still a gap, no commit.
    assert!(!commits(&n.propose(6)));
    assert_eq!(n.node.committed_height(), 0);
    // B6@7: QCs at 4, 5, 6 over B3 — consecutive, so B1..B3 commit at once.
    assert!(commits(&n.propose(7)), "consecutive three-chain did not commit");
    assert_eq!(n.node.committed_height(), 3);
}

#[test]
fn messages_from_absurd_views_are_rejected() {
    let mut sim = setup(2, 2);
    sim.step(vec![]);
    let view_before = sim.nodes[0].view();
    // A NewView for u64::MAX carries a real signature and a real QC: it used to
    // drag the replica to u64::MAX, where the next `view + 1` overflowed.
    let nv = NewView::sign(&sim.domain(), u64::MAX, sim.nodes[0].high_qc().clone(), &sim.keys[1]);
    assert!(matches!(sim.nodes[0].on_new_view(nv), Err(ConsensusError::ViewOutOfRange { .. })));
    assert_eq!(sim.nodes[0].view(), view_before);
    // A vote for u64::MAX must be rejected before any `vote.view + 1` arithmetic.
    let v = Vote::sign(&sim.domain(), u64::MAX, Hash::digest(b"x"), &sim.keys[1]);
    assert!(matches!(sim.nodes[0].on_vote(v), Err(ConsensusError::ViewOutOfRange { .. })));
    // A sane NewView one view ahead is still accepted.
    let ok = NewView::sign(&sim.domain(), view_before + 1, sim.nodes[0].high_qc().clone(), &sim.keys[1]);
    assert!(sim.nodes[0].on_new_view(ok).is_ok());
}

#[test]
fn one_validator_down_keeps_committing() {
    // With votes relayed only to the next leader, a single down validator ate
    // two QCs per four-view cycle (its own proposal's, plus the previous
    // block's as vote collector), leaving QC runs of two that can never
    // satisfy the three-consecutive-views commit rule: finality stalled.
    // Broadcast votes form QCs at every live proposal, so commits proceed.
    let mut sim = setup(4, 4);
    for _ in 0..2 {
        sim.step(vec![]);
    }
    let base = sim.committed[0].len();
    sim.down[3] = true;
    for _ in 0..12 {
        sim.step(vec![]);
    }
    assert!(
        sim.committed[0].len() >= base + 4,
        "commits stalled with one validator down: base {base}, now {}",
        sim.committed[0].len()
    );
    sim.assert_consistent();
}

#[test]
fn consecutive_views_do_not_wrap_at_the_top_of_u64() {
    // Deep scan 2026-09-24: the live commit rule compared with `saturating_add`, so
    // (MAX-1, MAX, MAX) — two certificates for the same view — read as three consecutive views;
    // `commit_rule::committed_prefix` (the sync path) already uses `checked_add`.
    use super::hotstuff::consecutive_views;
    assert!(consecutive_views(5, 6, 7));
    assert!(!consecutive_views(5, 6, 8));
    assert!(!consecutive_views(u64::MAX - 1, u64::MAX, u64::MAX));
    assert!(!consecutive_views(u64::MAX, u64::MAX, u64::MAX));
}

#[test]
fn speculative_tree_is_capped() {
    let (mut cfg, gs, key) = one_node_parts();
    // Cap at genesis + two speculative blocks.
    cfg.max_tree_blocks = 3;
    let mut n = one_node_with(cfg, gs.block.clone(), gs.ledger.clone(), key);
    n.node.start();
    n.propose(1);
    n.propose(2);
    // The tree now holds genesis + B1 + B2 and is full: the next proposal is
    // refused before any execution or insertion.
    let err = n.node.propose(3, vec![], 3).unwrap_err();
    assert!(matches!(err, ConsensusError::TreeFull), "{err}");
}

// ---------------------------------------------------------------------------
// Epochs (phase S2)
// ---------------------------------------------------------------------------

use crate::ledger::staking::MIN_STAKE;
use crate::ledger::Ledger;
use crate::notes::ShieldedAddress;
use crate::types::actions::{registration_message, unbond_message, Registration};

fn payout_addr(i: u8) -> ShieldedAddress {
    ShieldedAddress { pk: [i as u32; 8], kem_ek: vec![i; crate::notes::KEM_EK_BYTES] }
}

/// A shielded bundle carrying `action`, anchored to `l`'s root and burning `burn`. The stub
/// proof publishes exactly the digest the ledger recomputes, so only the action's own rules
/// decide whether it is admissible.
fn staking_tx(l: &Ledger, n: u32, burn: u64, action: crate::types::Action) -> Transaction {
    use crate::confidential::ConfidentialExecutor;
    let mut b = crate::Bundle {
        anchor: l.root(),
        nullifiers: crate::notes::pad4([[n; 8], [n + 1; 8]]),
        commitments: crate::notes::pad4([[n + 2; 8], [n + 3; 8]]),
        fee: crate::gas::BUNDLE_BASE,
        burn_a: 0,
        burn_r: burn,
        burn_asset: 0,
        time: l.height() as u32,
        envelopes: [env(), env(), env(), env()],
        proof: vec![],
    };
    let d = StubExecutor.bundle_digest(&b.digest_input());
    b.proof = StubExecutor::make_bundle_proof(&l.hc_bundle(), &d, &[0; 8]);
    StubExecutor::bound(Transaction::shielded(1, b, action))
}

/// A `Bond` that registers `v` with `amount` of stake, burning the amount out of the pool.
fn bond_tx(l: &Ledger, n: u32, v: &Keypair, amount: u64, payout_index: u8) -> Transaction {
    let payout = payout_addr(payout_index);
    let signature = v.sign(registration_message(1, &payout).as_bytes());
    let registration = Registration { public_key: v.public_key().clone(), payout, signature };
    staking_tx(l, n, amount, crate::types::Action::Bond { validator: v.address(), amount, registration: Some(registration) })
}

/// An `Unbond` of `amount` signed by `v` at its current `nonce`. Bundle-less and free: a
/// validator key owns no notes to pay a fee with.
fn unbond_tx(v: &Keypair, amount: u64, nonce: u64) -> Transaction {
    let signature = v.sign(unbond_message(1, &v.address(), amount, nonce).as_bytes());
    Transaction {
        chain_id: 1,
        bundle: None,
        action: crate::types::Action::Unbond { validator: v.address(), amount, nonce, signature },
    }
}

impl Sim {
    /// The block at `height` on node `i`'s branch, committed or not.
    fn block_at(&self, i: usize, height: u64) -> Block {
        if let Some(cb) = self.committed[i].get(height as usize - 1) {
            return cb.block.clone();
        }
        let mut cur = self.nodes[i].high_qc().block_hash;
        loop {
            let b = self.nodes[i].block(&cur).expect("block is on the branch").clone();
            assert!(b.height() >= height, "height {height} is not on node {i}'s branch");
            if b.height() == height {
                return b;
            }
            cur = b.parent();
        }
    }

    /// Run until the chain has committed `height`, or fail.
    fn run_to_height(&mut self, height: u64, steps: usize) {
        for _ in 0..steps {
            if self.committed[0].len() as u64 >= height {
                return;
            }
            self.step(vec![]);
        }
        panic!("chain stalled at height {} (wanted {height})", self.committed[0].len());
    }
}

/// The set of epoch 1 is the register as it stood after the last block of epoch 0 — not the
/// genesis set, and not the register at any other height. A validator that bonds inside epoch 0
/// therefore leads, votes and counts towards quorum from the epoch's first block and not before.
#[test]
fn epoch_rollover_uses_the_register_after_the_last_block_of_the_previous_epoch() {
    let mut sim = setup_epochs(5, 4, 4);
    let newcomer = Keypair::from_seed(*sim.keys[4].seed()).unwrap();
    let fifth = newcomer.address();
    assert!(!sim.gs.validators.contains(&fifth), "the fifth key is outside the genesis set");

    sim.step(vec![]); // block 1
    // Ten times the minimum: from epoch 1 on the four genesis validators are a minority of the
    // stake, so no QC can form unless the rollover really admitted the fifth.
    let bond = bond_tx(sim.nodes[0].tip_ledger(), 10, &newcomer, 10 * MIN_STAKE, 5);
    sim.step(vec![bond.clone()]); // block 2

    // Epoch 0 does not know the fifth validator, whatever the register now says.
    let b2 = sim.block_at(0, 2);
    assert!(b2.transactions.iter().any(|t| t.hash() == bond.hash()), "the bond landed in block 2");
    let stray = Vote::sign(&sim.domain(), b2.view(), b2.hash(), &newcomer);
    assert_eq!(sim.nodes[0].on_vote(stray).unwrap_err(), ConsensusError::NotValidator);

    sim.run_to_height(9, 40);
    sim.assert_consistent();

    let b3 = sim.block_at(0, 3);
    let epoch0 = sim.nodes[0].set_for_height(3, &b3.parent()).expect("epoch 0 is the genesis set");
    let epoch1 = sim.nodes[0].set_for_height(4, &b3.hash()).expect("epoch 1 derives from block 3");
    assert_eq!(epoch0, sim.gs.validators);
    assert!(!epoch0.contains(&fifth));
    assert_eq!(epoch1.len(), 5, "the register after block 3 has five entries above the minimum");
    assert_eq!(epoch1.get(&fifth).unwrap().stake, 10 * MIN_STAKE as u128);

    // Every replica recorded the set of epoch 1 when its first block committed.
    for (i, rec) in sim.recorded.iter().enumerate() {
        assert!(rec.contains(&(1, epoch1.clone())), "node {i} did not record epoch 1: {:?}", rec.iter().map(|(e, _)| *e).collect::<Vec<_>>());
        assert!(rec.iter().all(|(e, _)| *e != 0), "epoch 0 is the genesis set, not a recorded rollover");
    }

    // From block 4 on, the leader schedule and the quorum are epoch 1's.
    let mut fifth_led = false;
    for cb in &sim.committed[0] {
        let h = cb.block.height();
        let set = sim.nodes[0].set_for_height(h, &cb.block.parent()).expect("the set of every committed block");
        assert_eq!(cb.block.proposer(), set.leader(cb.block.view()), "block {h} has the wrong leader");
        if h >= 4 {
            assert_eq!(set, epoch1);
            assert!(
                cb.qc.votes.iter().any(|v| v.voter_address() == fifth),
                "block {h} reached quorum without the fifth validator's stake"
            );
            fifth_led |= cb.block.proposer() == fifth;
        } else {
            assert_eq!(set, epoch0);
        }
    }
    assert!(fifth_led, "the fifth validator never took its turn as leader");
}

/// An unbond that drops a validator under the minimum takes it out of the next epoch's set; the
/// rest keep quorum and the chain does not stall at the boundary.
#[test]
fn an_unbond_below_min_stake_drops_a_validator_next_epoch_and_the_chain_keeps_quorum() {
    let mut sim = setup_epochs(5, 5, 4);
    let leaver = Keypair::from_seed(*sim.keys[4].seed()).unwrap();
    let gone = leaver.address();
    assert!(sim.gs.validators.contains(&gone));

    sim.step(vec![]); // block 1
    let unbond = unbond_tx(&leaver, 1, 0);
    sim.step(vec![unbond.clone()]); // block 2
    let b2 = sim.block_at(0, 2);
    assert!(b2.transactions.iter().any(|t| t.hash() == unbond.hash()), "the unbond landed in block 2");

    sim.run_to_height(9, 40);
    sim.assert_consistent();

    let b3 = sim.block_at(0, 3);
    let epoch1 = sim.nodes[0].set_for_height(4, &b3.hash()).expect("epoch 1 derives from block 3");
    assert_eq!(epoch1.len(), 4, "one unit below the minimum is below the minimum");
    assert!(!epoch1.contains(&gone));

    // The four that remain hold quorum, and the one that left neither leads nor votes.
    for cb in &sim.committed[0] {
        if cb.block.height() < 4 {
            continue;
        }
        assert_ne!(cb.block.proposer(), gone, "block {} was led by a dropped validator", cb.block.height());
        assert!(!cb.qc.votes.iter().any(|v| v.voter_address() == gone), "a dropped validator's vote was counted");
        assert!(cb.qc.votes.len() >= 3, "quorum in a four-validator set is three votes");
    }

    // And its vote on an epoch-1 block is refused outright.
    let tip = sim.block_at(0, sim.committed[0].len() as u64);
    assert!(tip.height() >= 4);
    let stray = Vote::sign(&sim.domain(), tip.view(), tip.hash(), &leaver);
    assert_eq!(sim.nodes[0].on_vote(stray).unwrap_err(), ConsensusError::NotValidator);
}

/// A QC is verified against the set of the epoch the block it certifies belonged to, so the two
/// QCs either side of a boundary are checked against different sets. A replica resumed from the
/// last block of epoch 0, holding only the persisted sets, accepts both.
#[test]
fn qcs_across_a_boundary_verify_against_their_own_epoch() {
    let mut sim = setup_epochs(5, 4, 4);
    let newcomer = Keypair::from_seed(*sim.keys[4].seed()).unwrap();
    sim.step(vec![]);
    let bond = bond_tx(sim.nodes[0].tip_ledger(), 10, &newcomer, 10 * MIN_STAKE, 5);
    sim.step(vec![bond]);
    sim.run_to_height(7, 40);
    sim.assert_consistent();

    let gh = sim.gs.hash();
    let b3 = sim.block_at(0, 3);
    let b4 = sim.block_at(0, 4);
    let b5 = sim.block_at(0, 5);
    let epoch0 = sim.gs.validators.clone();
    let epoch1 = sim.nodes[0].set_for_height(4, &b3.hash()).expect("epoch 1 derives from block 3");
    assert_ne!(epoch0, epoch1);

    // Block 4's justify certifies block 3, the last block of epoch 0.
    assert_eq!(b4.header.justify.block_hash, b3.hash());
    assert!(b4.header.justify.verify(&sim.domain(), &epoch0), "an epoch-0 QC verifies against epoch 0's set");
    assert!(!b4.header.justify.verify(&sim.domain(), &epoch1), "epoch 0's voters are a minority of epoch 1's stake");

    // Block 5's justify certifies block 4, the first block of epoch 1.
    assert_eq!(b5.header.justify.block_hash, b4.hash());
    assert!(b5.header.justify.verify(&sim.domain(), &epoch1), "an epoch-1 QC verifies against epoch 1's set");
    assert!(!b5.header.justify.verify(&sim.domain(), &epoch0), "epoch 0 does not know the fifth validator");

    // A replica resumed at committed height 3, with the sets storage kept, verifies each in turn.
    let head = sim.committed[0][2].clone();
    assert_eq!(head.block.hash(), b3.hash());
    let mut ledger = sim.gs.ledger.clone();
    for k in 0..3 {
        ledger.apply_block(&sim.committed[0][k].block, &StubExecutor).expect("replay");
    }
    let mut epoch_sets = EpochSets::new(epoch0.clone());
    epoch_sets.insert(1, epoch1.clone());
    let mut resumed = HotStuff::resume(
        config_of(&sim),
        None,
        head.block.clone(),
        head.qc.clone(),
        ledger,
        None,
        Vec::new(),
        epoch_sets,
        std::sync::Arc::new(StubExecutor),
    );
    assert_eq!(resumed.set_for_height(3, &b3.parent()).unwrap(), epoch0);
    assert_eq!(resumed.set_for_height(4, &b3.hash()).unwrap(), epoch1);
    resumed.on_proposal(b4.clone(), sim.now).expect("block 4's justify is an epoch-0 QC");
    resumed.on_proposal(b5.clone(), sim.now).expect("block 5's justify is an epoch-1 QC");
    assert!(resumed.has_block(&b5.hash()));
}

/// Every validator unbonding below the minimum inside one epoch empties the next epoch's
/// register. Consensus carries the previous epoch's set forward rather than switching to a set
/// with no leader: a halted chain has no block left in which to bond back in.
#[test]
fn an_epoch_whose_register_empties_carries_the_previous_set_forward() {
    let mut sim = setup_epochs(4, 4, 4);
    sim.step(vec![]); // block 1
    let leavers: Vec<Transaction> = (0..4)
        .map(|i| {
            let v = Keypair::from_seed(*sim.keys[i].seed()).unwrap();
            unbond_tx(&v, 1, 0)
        })
        .collect();
    sim.step(leavers); // block 2
    assert_eq!(sim.block_at(0, 2).transactions.len(), 4, "all four unbonded in one block");

    // Two more boundaries, so the fallback has to hold for an epoch derived from a fallback.
    sim.run_to_height(13, 60);
    sim.assert_consistent();

    let mut ledger = sim.gs.ledger.clone();
    for k in 0..3 {
        ledger.apply_block(&sim.committed[0][k].block, &StubExecutor).expect("replay");
    }
    assert!(ledger.derive_next_set(1).is_empty(), "the register after block 3 has nobody above the minimum");

    let b3 = sim.block_at(0, 3);
    let epoch1 = sim.nodes[0].set_for_height(4, &b3.hash()).expect("epoch 1 falls back to epoch 0");
    assert_eq!(epoch1, sim.gs.validators, "the empty derivation carries epoch 0's set forward");
    let tip = sim.committed[0].len() as u64;
    let last = sim.block_at(0, tip);
    assert!(last.height() >= 12, "the chain kept committing past two more boundaries");
    assert_eq!(sim.nodes[0].set_for_height(last.height(), &last.parent()).unwrap(), sim.gs.validators);
}

/// A block's height must be its parent's plus one before anything is derived from it. The epoch
/// of an unchecked height is the sender's to choose, and each choice would be a register walk and
/// a cached set keyed on a parent that never leaves the tree.
#[test]
fn a_block_whose_height_skips_its_parent_is_refused_before_its_epoch_is_derived() {
    let mut sim = setup_epochs(4, 4, 4);
    sim.step(vec![]);
    let parent = sim.block_at(0, 1);
    // Any key can sign its own block; the height, not the leader schedule, must be what refuses it.
    let liar = 1usize;
    let header = crate::types::BlockHeader {
        height: parent.height() + 1 + 4 * 1_000_000,
        view: sim.nodes[0].view() + 1,
        parent: parent.hash(),
        proposer: sim.keys[liar].public_key().clone(),
        timestamp_ms: 1,
        tx_root: Hash::ZERO,
        state_root: parent.header.state_root,
        justify: sim.nodes[0].high_qc().clone(),
    };
    let block = Block::sign(&sim.domain(), header, vec![], &sim.keys[liar]);
    assert_eq!(
        sim.nodes[0].on_proposal(block, sim.now).unwrap_err(),
        ConsensusError::BadHeight { block: parent.height() + 1 + 4_000_000, parent: parent.height() }
    );
}

// ── block aggregation: the covered source and the §3.4 selection ─────────────────────────────

/// A one-validator HotStuff with an aggregation-gated genesis, a registered aggregator, and a
/// covered source that answers every cover set with the same synthetic record.
fn aggregation_node() -> (HotStuff, Keypair, crate::ledger::aggregation::AggregationConfig) {
    aggregation_node_with(|_, _| {})
}

/// `aggregation_node`, with `prepare` run on the genesis ledger (after the aggregator's
/// registration) before the node is built on it.
fn aggregation_node_with(
    prepare: impl FnOnce(&mut crate::ledger::Ledger, &Keypair),
) -> (HotStuff, Keypair, crate::ledger::aggregation::AggregationConfig) {
    use crate::ledger::aggregation::{AdmittedShape, AggregationConfig};
    use crate::types::actions::{aggregator_register_message, AggregatorRegistration};
    use crate::types::{DeclaredShape, FriProfile};
    let key = Keypair::from_seed([1; 32]).unwrap();
    let shape = DeclaredShape {
        profile: FriProfile::Test,
        tier: 14,
        program_log_height: 13,
        input_log_height: 12,
        keccak_log_height: 0,
        sha256_log_height: 0,
        public_log_height: 2,
        mem_log_height: 18,
    };
    let cfg = AggregationConfig {
        bond: 100 * crate::types::UNITS_PER_RAND,
        max_covers: 3,
        subsidy_base: 100 * crate::types::UNITS_PER_RAND,
        halving_blocks: 210_000,
        window: 256,
        admitted_shapes: vec![AdmittedShape { shape, hc: Hash::digest(b"the bundle guest"), aggregate_program_digest: StubExecutor.aggregate_program_digest(&shape).unwrap() }],
    };
    let genesis = Genesis {
        chain_id: 1,
        timestamp_ms: 0,
        validators: vec![GenesisValidator {
            public_key: key.public_key().clone(),
            stake: crate::ledger::staking::MIN_STAKE as u128,
            payout: payout(1),
        }],
        alloc: Vec::new(),
        faucet: true,
        confidential: true,
        // The admitted shape below is a Test-profile one, so the chain must say so too: a
        // mismatch is refused at genesis (audit v3, CHAIN9-1).
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&[3; 8]),
        epoch_blocks: crate::genesis::EPOCH_BLOCKS_DEFAULT,
        max_program_words: None,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words: None,
        bridge: None,
        tokens: None,
        aggregation: Some(cfg.clone()),
        consensus_domain: None,
        staking: None,
    };
    let mut gs = genesis.build(&StubExecutor).unwrap();
    // Register the aggregator directly on the genesis ledger the node builds on (the register
    // move is what a first block would have done anyway; nothing here re-verifies genesis).
    let payout_addr = crate::notes::ShieldedAddress { pk: [7; 8], kem_ek: vec![8; crate::notes::KEM_EK_BYTES] };
    let registration = AggregatorRegistration {
        public_key: key.public_key().clone(),
        payout: payout_addr.clone(),
        signature: key.sign(aggregator_register_message(1, &payout_addr).as_bytes()),
    };
    let mut b = crate::notes::Bundle {
        anchor: gs.ledger.root(),
        nullifiers: crate::notes::pad4([[11; 8], [12; 8]]),
        commitments: crate::notes::pad4([[13; 8], [14; 8]]),
        fee: crate::gas::BUNDLE_BASE,
        burn_a: 0,
        burn_r: cfg.bond,
        burn_asset: 0,
        time: 0,
        envelopes: [
            crate::notes::Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] },
            crate::notes::Envelope { kem_ct: vec![5; 8], to_receiver: vec![6; 4], to_sender: vec![7; 4], body: vec![8; 16] },
            crate::notes::Envelope { kem_ct: vec![9; 8], to_receiver: vec![1; 4], to_sender: vec![2; 4], body: vec![3; 16] },
            crate::notes::Envelope { kem_ct: vec![4; 8], to_receiver: vec![5; 4], to_sender: vec![6; 4], body: vec![7; 16] },
        ],
        proof: vec![],
    };
    let d = StubExecutor.bundle_digest(&b.digest_input());
    b.proof = StubExecutor::make_bundle_proof(&[3; 8], &d, &[0; 8]);
    let register_tx = StubExecutor::bound(Transaction::shielded(1, b, crate::types::Action::RegisterAggregator { registration }));
    gs.ledger.apply_tx(&register_tx, &key.address(), &StubExecutor).unwrap();
    // The synthetic covers the tests name, in the ledger's coverable set (H1's block rule):
    // the single-byte digests 40.. and the two named ones, excess-free, never expiring.
    for c in (0..4u8).map(|i| Hash::digest(&[i + 40])).chain([Hash::digest(b"cover"), Hash::digest(b"cover a")]) {
        gs.ledger.bucket_excess(c, 0, key.address(), u64::MAX);
    }
    prepare(&mut gs.ledger, &key);
    let mut hs = HotStuff::new(
        ConsensusConfig::new(1, gs.validators.clone(), gs.hash()),
        Some(Keypair::from_seed(*key.seed()).unwrap()),
        gs.block.clone(),
        gs.ledger.clone(),
        std::sync::Arc::new(StubExecutor),
    );
    let hc_words: [u32; 8] = crate::notes::word8_from_bytes(Hash::digest(b"the bundle guest").as_bytes()).unwrap();
    let mut pv = [0u64; 34];
    pv[crate::types::pv::TIER] = shape.tier as u64;
    for k in 0..8 {
        pv[crate::types::pv::OUT0 + k] = 100 + k as u64;
        pv[crate::types::pv::HC0 + k] = hc_words[k] as u64;
    }
    let record = crate::types::CoveredBundle { public_values: pv, shape };
    struct TestCovered(crate::types::CoveredBundle);
    impl CoveredSource for TestCovered {
        fn covered(&self, covers: &[Hash]) -> Option<Vec<crate::types::CoveredBundle>> {
            Some(vec![self.0.clone(); covers.len()])
        }
    }
    hs.set_covered_source(std::sync::Arc::new(TestCovered(record)));
    (hs, key, cfg)
}

fn aggregate_tx(key: &Keypair, nonce: u64, time: u32, covers: Vec<Hash>, proof: Vec<u8>) -> Transaction {
    let aggregator = key.public_key().address();
    let r = [9; 8];
    let signature = key.sign(
        crate::types::actions::aggregate_signing_hash(1, nonce, time, &r, &covers, &Hash::digest(&proof)).as_bytes(),
    );
    Transaction {
        chain_id: 1,
        bundle: None,
        action: crate::types::Action::Aggregate {
            covers,
            proof,
            aggregator,
            nonce,
            time,
            r,
            envelope: crate::notes::Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] },
            signature,
        },
    }
}

/// Spec §3.4's selection, in the block the leader builds: at most one aggregate — the largest
/// cover set among the candidates that apply, ties to the lowest proof hash.
#[test]
fn a_proposal_carries_at_most_one_aggregate_the_largest_valid_cover_set() {
    let (mut hs, key, _cfg) = aggregation_node();
    hs.start();
    let covers = |n: usize| (0..n).map(|i| Hash::digest(&[i as u8 + 40])).collect::<Vec<_>>();
    let big = aggregate_tx(&key, 0, 1, covers(3), b"ok".to_vec());
    let small = aggregate_tx(&key, 0, 1, covers(1), b"ok-2".to_vec());
    let acts = hs.propose(1, vec![small.clone(), big.clone()], 1).expect("propose");
    let proposal = acts.iter().find_map(|a| match a {
        Action::Broadcast(ConsensusMessage::Proposal(b)) => Some(b),
        _ => None,
    });
    let block = proposal.expect("a proposal was built");
    let aggregates: Vec<_> = block
        .transactions
        .iter()
        .filter(|tx| matches!(tx.action, crate::types::Action::Aggregate { .. }))
        .collect();
    assert_eq!(aggregates.len(), 1, "at most one aggregate per block");
    assert_eq!(aggregates[0].hash(), big.hash(), "the largest cover set wins");

    // A tie on the count goes to the lowest proof hash.
    let mut hs2_state = aggregation_node();
    let hs2 = &mut hs2_state.0;
    hs2.start();
    let (p_low, p_high) = {
        let (a, b) = (vec![1u8; 4], vec![2u8; 4]);
        if Hash::digest(&a) < Hash::digest(&b) { (a, b) } else { (b, a) }
    };
    let a_high = aggregate_tx(&key, 0, 1, covers(2), p_high.clone());
    let a_low = aggregate_tx(&key, 0, 1, covers(2), p_low.clone());
    assert!(Hash::digest(&p_low) < Hash::digest(&p_high), "the fixture's own order");
    // Candidates in the losing order: the higher proof hash first.
    let acts = hs2.propose(1, vec![a_high.clone(), a_low.clone()], 1).expect("propose");
    let block = acts
        .iter()
        .find_map(|a| match a {
            Action::Broadcast(ConsensusMessage::Proposal(b)) => Some(b),
            _ => None,
        })
        .expect("a proposal was built");
    let aggregates: Vec<_> = block
        .transactions
        .iter()
        .filter(|tx| matches!(tx.action, crate::types::Action::Aggregate { .. }))
        .collect();
    assert_eq!(aggregates.len(), 1);
    assert_eq!(aggregates[0].hash(), a_low.hash(), "the lowest proof hash breaks the tie");
}

/// The capstone's own invariant, at HotStuff level: a leader builds a block carrying an
/// aggregate, its own `on_proposal` accepts it (no state-root mismatch), and a second replica
/// with the same covered source accepts it too.
#[test]
fn a_proposal_carrying_an_aggregate_applies_identically_on_proposer_and_peer() {
    let (mut leader, key, _cfg) = aggregation_node();
    let (mut peer, _, _) = aggregation_node();
    // The peer shares the leader's covered source (both are the same closure over the same
    // synthetic record — the test-double stands in for two nodes' identical stores).
    let covered_source = std::sync::Arc::new({
        struct SharedCovered;
        impl CoveredSource for SharedCovered {
            fn covered(&self, covers: &[Hash]) -> Option<Vec<crate::types::CoveredBundle>> {
                let hc_words: [u32; 8] = crate::notes::word8_from_bytes(Hash::digest(b"the bundle guest").as_bytes()).unwrap();
                let shape = crate::types::DeclaredShape {
                    profile: crate::types::FriProfile::Test,
                    tier: 14,
                    program_log_height: 13,
                    input_log_height: 12,
                    keccak_log_height: 0,
                    sha256_log_height: 0,
                    public_log_height: 2,
                    mem_log_height: 18,
                };
                Some(
                    covers
                        .iter()
                        .map(|_| {
                            let mut pv = [0u64; 34];
                            pv[crate::types::pv::TIER] = 14;
                            for k in 0..8 {
                                pv[crate::types::pv::OUT0 + k] = 100 + k as u64;
                                pv[crate::types::pv::HC0 + k] = hc_words[k] as u64;
                            }
                            crate::types::CoveredBundle { public_values: pv, shape }
                        })
                        .collect(),
                )
            }
        }
        SharedCovered
    });
    leader.set_covered_source(covered_source.clone());
    peer.set_covered_source(covered_source);
    leader.start();
    peer.start();
    let tx = aggregate_tx(&key, 0, 1, vec![Hash::digest(b"cover a")], b"ok".to_vec());
    let acts = leader.propose(1, vec![tx.clone()], 1).expect("the leader's own block must apply");
    let block = acts
        .iter()
        .find_map(|a| match a {
            Action::Broadcast(ConsensusMessage::Proposal(b)) => Some(b.clone()),
            _ => None,
        })
        .expect("a proposal was built");
    assert!(block.transactions.iter().any(|t| t.hash() == tx.hash()), "the aggregate is in the block");
    peer.on_proposal(block, 1).expect("the peer applies the same block to the same root");
}

/// The block-end sweep (spec §5.2) is part of the applied state: a bucketed excess whose window
/// passed at this height is credited to a validator's `rewards`, which the state root commits.
/// The leader's header root must therefore come from the same block-end steps every replica
/// runs — otherwise the first expired bucket makes every leader reject its own block, and the
/// chain halts (the pre-v0.1 review's L1).
#[test]
fn a_proposal_after_an_excess_window_passes_is_one_the_leader_itself_applies() {
    let (mut leader, _key, _cfg) = aggregation_node_with(|ledger, key| {
        // An excess bucketed at genesis whose window ends at height 1: the block this leader
        // builds is the one that sweeps it.
        ledger.bucket_excess(Hash::digest(b"an over-floor bundle"), 5, key.address(), 1);
    });
    leader.start();
    let acts = leader.propose(1, vec![], 1).expect("the leader accepts the block it built");
    assert!(
        acts.iter().any(|a| matches!(a, Action::Broadcast(ConsensusMessage::Proposal(_)))),
        "the proposal was broadcast"
    );
}

/// A candidate the covered source cannot cover is skipped — never the block.
#[test]
fn a_proposal_skips_an_aggregate_whose_covers_are_unavailable() {
    let (mut hs, key, _cfg) = aggregation_node();
    hs.set_covered_source(std::sync::Arc::new({
        struct NoneCovered;
        impl CoveredSource for NoneCovered {
            fn covered(&self, _covers: &[Hash]) -> Option<Vec<crate::types::CoveredBundle>> {
                None
            }
        }
        NoneCovered
    }));
    hs.start();
    let agg = aggregate_tx(&key, 0, 1, vec![Hash::digest(b"cover")], b"ok".to_vec());
    let acts = hs.propose(1, vec![agg], 1).expect("propose");
    let block = acts
        .iter()
        .find_map(|a| match a {
            Action::Broadcast(ConsensusMessage::Proposal(b)) => Some(b),
            _ => None,
        })
        .expect("a proposal was built");
    assert!(
        block.transactions.iter().all(|tx| !matches!(tx.action, crate::types::Action::Aggregate { .. })),
        "an uncoverable aggregate never enters the block"
    );
}

// ---------------------------------------------------------------------------
// Sibling proposals (audit v4, CON-3)
// ---------------------------------------------------------------------------

/// A valid block at `view` extending `node`'s committed head, signed by that view's leader and
/// stamped `timestamp_ms`: what the leader would propose — or, with a second timestamp beside
/// one it already proposed, the sibling a Byzantine leader proposes for the same view.
fn block_on_head(sim: &Sim, node: usize, view: u64, timestamp_ms: u64) -> Block {
    let hs = &sim.nodes[node];
    let parent_hash = hs.committed_hash();
    let parent = hs.block(&parent_hash).expect("the head is in the tree").clone();
    let height = parent.height() + 1;
    let li = sim.addr_to_idx[&hs.leader(view)];
    let proposer = sim.keys[li].public_key().clone();
    let proposer_addr = proposer.address();
    // The state the block must publish, built the way a proposer builds it.
    let mut after = hs.committed_ledger().clone();
    after.set_height(height);
    after.set_timestamp_ms(timestamp_ms);
    after.apply_transactions(&[], &proposer_addr, &StubExecutor).expect("an empty block applies");
    after.close_block(height, &proposer_addr);
    let justify = match sim.committed[node].last() {
        Some(cb) => cb.qc.clone(),
        None => QuorumCertificate::genesis(parent_hash),
    };
    let header = crate::types::BlockHeader {
        height,
        view,
        parent: parent_hash,
        proposer,
        timestamp_ms,
        tx_root: Block::tx_root(&[]),
        state_root: after.state_root(),
        justify,
    };
    Block::sign(&sim.domain(), header, vec![], &sim.keys[li])
}

/// A Byzantine validator (`attacker`) feeds `victim` `count` distinct blocks, one per view it
/// leads, every one a child of the committed head: it pulls the victim into each such view with
/// one signed NewView (all a validator needs today) and proposes there. Returns how many the
/// victim accepted into its tree.
fn fill_with_siblings(sim: &mut Sim, victim: usize, attacker: usize, count: usize) -> usize {
    let key = Keypair::from_seed(*sim.keys[attacker].seed()).unwrap();
    let attacker_addr = sim.keys[attacker].address();
    let mut accepted = 0;
    let mut sent = 0;
    let mut view = sim.nodes[victim].view();
    while sent < count {
        view += 1;
        if sim.nodes[victim].leader(view) != attacker_addr {
            continue;
        }
        let nv = NewView::sign(&sim.domain(), view, sim.nodes[victim].high_qc().clone(), &key);
        sim.nodes[victim].on_new_view(nv).expect("a validator's NewView is admitted");
        assert_eq!(sim.nodes[victim].view(), view);
        let now = 1_000 + view;
        let b = block_on_head(sim, victim, view, now);
        sent += 1;
        if sim.nodes[victim].on_proposal(b, now).is_ok() {
            accepted += 1;
        }
    }
    accepted
}

/// The next view above `victim`'s current one that a validator other than `attacker` leads.
fn next_honest_view(sim: &Sim, victim: usize, attacker: usize) -> u64 {
    let attacker_addr = sim.keys[attacker].address();
    (sim.nodes[victim].view() + 1..).find(|v| sim.nodes[victim].leader(*v) != attacker_addr).unwrap()
}

#[test]
fn six_hundred_siblings_do_not_stop_the_honest_leaders_proposal() {
    // Fails today with TreeFull: a Byzantine leader's junk fills the 512-block tree, and the
    // honest leader's proposal on the certified head is refused behind it.
    let mut sim = setup(4, 4);
    let (victim, attacker) = (1, 3);
    let accepted = fill_with_siblings(&mut sim, victim, attacker, 600);
    assert!(accepted >= 500, "the attacker's blocks are valid and were accepted: {accepted}");
    let view = next_honest_view(&sim, victim, attacker);
    let honest = block_on_head(&sim, victim, view, 10_000);
    let r = sim.nodes[victim].on_proposal(honest.clone(), 10_000);
    assert!(r.is_ok(), "the certified-branch proposal must always fit: {r:?}");
    assert!(sim.nodes[victim].has_block(&honest.hash()));
}

#[test]
fn equivocation_memory_outlives_the_trees_eviction() {
    // Deep scan 2026-09-24 (consensus): `evict_for_room` dropped the `proposed` entries of the
    // blocks it evicted, so a leader whose junk filled the tree could propose a *second* block
    // for any view whose first one had been evicted — the one-block-per-(view, leader) rule
    // (CON-3) was only as long as the tree's memory. The record must outlive the block.
    let mut sim = setup(4, 4);
    let (victim, attacker) = (1, 3);
    let attacker_addr = sim.keys[attacker].address();
    let first_view = (sim.nodes[victim].view() + 1..).find(|v| sim.nodes[victim].leader(*v) == attacker_addr).unwrap();
    let accepted = fill_with_siblings(&mut sim, victim, attacker, 600);
    assert!(accepted >= 500, "{accepted}");
    // The first sibling (view `first_view`, timestamp 1_000 + view) has been evicted, oldest first.
    let first = block_on_head(&sim, victim, first_view, 1_000 + first_view);
    assert!(!sim.nodes[victim].has_block(&first.hash()), "the oldest sibling was evicted");
    // A different block by the same leader for that same view: an equivocation, evicted or not.
    let second = block_on_head(&sim, victim, first_view, 1_000 + first_view + 1);
    assert_ne!(first.hash(), second.hash());
    let e = sim.nodes[victim].on_proposal(second.clone(), 1_000 + first_view + 1).unwrap_err();
    assert!(
        matches!(e, ConsensusError::Equivocation { view, first: f, .. } if view == first_view && f == first.hash()),
        "{e:?}"
    );
    assert!(!sim.nodes[victim].has_block(&second.hash()));
}

#[test]
fn a_leaders_second_block_for_one_view_is_refused_as_equivocation() {
    let mut sim = setup(4, 4);
    let (leader, view) = pending_leader(&sim);
    assert_eq!(view, 1);
    sim.now += 1;
    let acts = sim.nodes[leader].propose(view, vec![], sim.now).expect("the leader proposes");
    let a = proposal_of(&acts); // the block the leader really proposed
    // Same view, same parent, a different timestamp: a sibling the same leader signed.
    let b = block_on_head(&sim, 1, view, a.header.timestamp_ms + 1);
    assert_eq!(b.proposer(), a.proposer());
    assert_ne!(a.hash(), b.hash());
    assert!(sim.nodes[1].on_proposal(a.clone(), sim.now).is_ok());
    let e = sim.nodes[1].on_proposal(b.clone(), sim.now).unwrap_err();
    assert!(
        matches!(e, ConsensusError::Equivocation { view: 1, first, second } if first == a.hash() && second == b.hash()),
        "{e:?}"
    );
    assert!(sim.nodes[1].has_block(&a.hash()) && !sim.nodes[1].has_block(&b.hash()));
    // The same block again is not an equivocation: it is already held.
    assert!(sim.nodes[1].on_proposal(a, sim.now).is_ok());
}

#[test]
fn a_proposal_past_the_view_window_is_refused_not_stored() {
    let sim = setup(4, 4);
    let mut sim = sim;
    let current = sim.nodes[1].view();
    let far = block_on_head(&sim, 1, current + PROPOSAL_VIEW_WINDOW + 1, 5);
    let e = sim.nodes[1].on_proposal(far.clone(), 5).unwrap_err();
    assert!(matches!(e, ConsensusError::ViewTooFarAhead { view, current: c } if view == current + PROPOSAL_VIEW_WINDOW + 1 && c == current), "{e:?}");
    assert!(!sim.nodes[1].has_block(&far.hash()));
    assert_eq!(sim.nodes[1].view(), current, "a far-future proposal does not move the view");
    let edge = block_on_head(&sim, 1, current + PROPOSAL_VIEW_WINDOW, 5);
    let r = sim.nodes[1].on_proposal(edge, 5);
    assert!(!matches!(r, Err(ConsensusError::ViewTooFarAhead { .. })), "{r:?}");
}

// ---------------------------------------------------------------------------
// The lock is released only on signed evidence (audit v4, CON-4)
// ---------------------------------------------------------------------------

/// Run the simulation until some replica is locked above its committed head, and return it.
fn locked_above_head(sim: &mut Sim) -> usize {
    for _ in 0..24 {
        sim.step(vec![]);
        if let Some(i) = (0..sim.nodes.len()).find(|&i| sim.nodes[i].locked_qc().view > sim.nodes[i].committed_qc_view()) {
            return i;
        }
    }
    panic!("no replica locked past its committed head");
}

/// Drive `sim` to a replica locked on a block above its head that it no longer holds — the
/// position a restart leaves a validator in when the locked block was never persisted.
fn lock_on_unobtainable(sim: &mut Sim) -> usize {
    let victim = locked_above_head(sim);
    sim.restart(victim);
    let hs = &sim.nodes[victim];
    assert!(hs.locked_qc().view > hs.committed_qc_view(), "the lock survives the restart");
    assert!(!hs.has_block(&hs.locked_qc().block_hash), "the restart dropped the locked block");
    victim
}

#[test]
fn eight_unsigned_not_found_replies_no_longer_release_the_lock() {
    let mut sim = setup(4, 4);
    let victim = lock_on_unobtainable(&mut sim);
    let locked = sim.nodes[victim].locked_qc().clone();
    // Eight `Block(None)`s and timeouts are eight failed fetches: the node layer's give-up, which
    // used to take the lock back on nothing but unsigned answers from whoever it asked.
    for _ in 0..8 {
        sim.nodes[victim].fallback_high_qc(&locked.block_hash);
    }
    assert_eq!(*sim.nodes[victim].locked_qc(), locked, "no signed evidence, no release");
}

#[test]
fn not_held_releases_the_lock_only_on_a_quorum() {
    // Six equal stakes: a quorum is strictly more than two thirds (`ValidatorSet::has_quorum`,
    // `3·stake > 2·total`), so 5 signers; 4 is exactly two thirds and is not one. Audit v5,
    // CON-4: v0.5.4 released on more than a third (3 of 6), which is not sound — a third can be
    // exactly the Byzantine validators, so nobody honest need be among them.
    let mut sim = setup(6, 6);
    let victim = lock_on_unobtainable(&mut sim);
    let h = sim.nodes[victim].locked_qc().block_hash;
    let g = sim.gs.hash();
    let others: Vec<usize> = (0..6).filter(|&i| i != victim).collect();
    let sign = |i: usize| NotHeld::sign(&sim.keys[i], &g, &h);
    assert!(!sim.nodes[victim].record_not_held(&sign(others[0])));
    assert!(!sim.nodes[victim].record_not_held(&sign(others[1])));
    assert!(!sim.nodes[victim].record_not_held(&sign(others[2])), "three of six is not a quorum");
    assert!(!sim.nodes[victim].record_not_held(&sign(others[2])), "a repeat signer counts once");
    assert_eq!(sim.nodes[victim].not_held_stake(&h), 3 * MIN_STAKE as u128);
    assert_eq!(sim.nodes[victim].locked_qc().block_hash, h, "three of six is not more than two thirds");
    assert!(!sim.nodes[victim].record_not_held(&sign(others[3])), "four of six is exactly two thirds, not more");
    assert_eq!(sim.nodes[victim].locked_qc().block_hash, h);
    assert!(sim.nodes[victim].record_not_held(&sign(others[4])), "five of six is a quorum");
    assert_eq!(sim.nodes[victim].locked_qc().view, sim.nodes[victim].committed_qc_view());
    assert_eq!(sim.nodes[victim].not_held_stake(&h), 0, "the evidence is cleared with the release");
}

#[test]
fn a_not_held_from_outside_the_current_set_or_for_another_chain_counts_nothing() {
    let mut sim = setup(4, 4);
    let victim = lock_on_unobtainable(&mut sim);
    let h = sim.nodes[victim].locked_qc().block_hash;
    let g = sim.gs.hash();
    let stranger = Keypair::from_seed([9; 32]).unwrap(); // a key in no set
    assert!(!sim.nodes[victim].record_not_held(&NotHeld::sign(&stranger, &g, &h)));
    let other = (0..4).find(|&i| i != victim).unwrap();
    assert!(!sim.nodes[victim].record_not_held(&NotHeld::sign(&sim.keys[other], &Hash([7; 32]), &h)));
    // A tampered attestation: a real signer's signature moved onto another hash.
    let mut moved = NotHeld::sign(&sim.keys[other], &g, &Hash([8; 32]));
    moved.hash = h;
    assert!(!sim.nodes[victim].record_not_held(&moved));
    assert_eq!(sim.nodes[victim].not_held_stake(&h), 0);
    assert_eq!(sim.nodes[victim].locked_qc().block_hash, h);
}

#[test]
fn a_resumed_validator_finds_its_locked_block_without_a_fetch() {
    let mut sim = setup(4, 4);
    let victim = locked_above_head(&mut sim);
    let old = &sim.nodes[victim];
    let locked_hash = old.locked_qc().block_hash;
    let block = old.block(&locked_hash).expect("the running replica holds its locked block").clone();
    assert_eq!(block.parent(), old.committed_hash(), "the locked block sits on the head");
    let safety = old.safety_state();
    let ledger = old.committed_ledger().clone();
    // The head and its QC as storage holds them (`Sim::restart`'s recipe): the last commit, or
    // genesis when the lock got ahead of the head before anything committed.
    let (head, qc) = match sim.committed[victim].last() {
        Some(cb) => (cb.block.clone(), cb.qc.clone()),
        None => (old.block(&old.committed_hash()).unwrap().clone(), QuorumCertificate::genesis(old.committed_hash())),
    };
    let epoch_sets = old.epoch_sets().clone();
    let signer = || Some(Keypair::from_seed(*sim.keys[victim].seed()).unwrap());
    let mut resumed = HotStuff::resume(
        config_of(&sim),
        signer(),
        head.clone(),
        qc.clone(),
        ledger.clone(),
        Some(safety.clone()),
        vec![block.clone()],
        epoch_sets.clone(),
        std::sync::Arc::new(StubExecutor),
    );
    assert!(resumed.has_block(&block.hash()), "the persisted locked block is back in the tree");
    assert_eq!(resumed.locked_qc().block_hash, locked_hash);
    // A valid proposal on the head, justified by the head's own (older) certificate — the branch
    // `a_resumed_validator_keeps_its_lock` shows a blind replica must fetch on. Holding the
    // locked block, this one can check the branch itself: no fetch.
    resumed.start();
    let view = resumed.view();
    let li = sim.addr_to_idx[&resumed.leader(view)];
    let mut header = block.header.clone();
    header.view = view;
    header.proposer = sim.keys[li].public_key().clone();
    header.timestamp_ms += 1;
    let mut after = ledger.clone();
    after.set_height(header.height);
    after.set_timestamp_ms(header.timestamp_ms);
    after.apply_transactions(&[], &header.proposer.address(), &StubExecutor).unwrap();
    after.close_block(header.height, &header.proposer.address());
    header.state_root = after.state_root();
    header.tx_root = Block::tx_root(&[]);
    header.justify = qc.clone();
    let sibling = Block::sign(&sim.domain(), header, vec![], &sim.keys[li]);
    let acts = resumed.on_proposal(sibling.clone(), sim.now + 1).expect("a well-formed proposal on the head");
    assert!(!acts.iter().any(|a| matches!(a, Action::FetchBlock(_))), "no FetchBlock: {acts:?}");
    // Without the block it fetches, as before.
    let mut again = HotStuff::resume(
        config_of(&sim),
        signer(),
        head,
        qc,
        ledger,
        Some(safety),
        Vec::new(),
        epoch_sets,
        std::sync::Arc::new(StubExecutor),
    );
    again.start();
    let acts = again.on_proposal(sibling, sim.now + 1).expect("accepted");
    assert!(acts.iter().any(|a| matches!(a, Action::FetchBlock(h) if *h == locked_hash)), "{acts:?}");
}

/// Drive `sim` until some replica's high QC certifies a block above its head that it holds
/// with `depth` certified blocks between the head and it (inclusive); returns that replica.
fn certified_chain_of(sim: &mut Sim, depth: u64) -> usize {
    for _ in 0..32 {
        sim.step(vec![]);
        let found = (0..sim.nodes.len()).find(|&i| {
            let hs = &sim.nodes[i];
            let tip = hs.high_qc().block_hash;
            hs.high_qc().view > hs.committed_qc_view()
                && hs.block(&tip).is_some_and(|b| b.height() == hs.committed_height() + depth)
        });
        if let Some(i) = found {
            return i;
        }
    }
    panic!("no replica holds a certified chain of {depth} above its head");
}

/// The blocks from `hs`'s committed head (exclusive) up to its high QC's block, in height order.
fn certified_blocks(hs: &HotStuff) -> Vec<Block> {
    let mut out = Vec::new();
    let mut cur = hs.high_qc().block_hash;
    while cur != hs.committed_hash() {
        let b = hs.block(&cur).expect("the certified chain is held").clone();
        cur = b.parent();
        out.push(b);
    }
    out.reverse();
    out
}

/// Audit v5, CON-4: the blocks a QC certified are durable. A replica restarted with what it
/// persisted holds the block its high QC names — no fetch — and the chain goes on. Fails on
/// v0.5.4: the pending set is not persisted, so the restart drops the block, exactly the
/// whole-fleet-restart position that stalled chain 14 on 2026-09-24.
#[test]
fn a_restart_keeps_the_blocks_a_qc_certified() {
    let mut sim = setup(4, 4);
    let victim = certified_chain_of(&mut sim, 1);
    let high = sim.nodes[victim].high_qc().clone();
    let chain = certified_blocks(&sim.nodes[victim]);
    assert!(!chain.is_empty());
    assert_eq!(chain.last().unwrap().hash(), high.block_hash);
    assert_eq!(
        sim.pending[victim].iter().map(|b| b.hash()).collect::<Vec<_>>(),
        chain.iter().map(|b| b.hash()).collect::<Vec<_>>(),
        "what the replica last persisted is its certified chain, in order"
    );
    sim.fetches.clear();
    sim.restart_durable(victim);
    let hs = &sim.nodes[victim];
    assert_eq!(hs.high_qc(), &high, "the high QC survives the restart");
    assert!(hs.has_block(&high.block_hash), "the block the persisted high QC certifies is back in the tree");
    for b in &chain {
        assert!(hs.has_block(&b.hash()), "block {} of the certified chain is back", b.height());
    }
    assert!(!sim.fetches.iter().any(|(i, _)| *i == victim), "no FetchBlock at start: {:?}", sim.fetches);
    let before = sim.committed[victim].len();
    for _ in 0..8 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
    assert!(sim.committed[victim].len() > before, "the restarted replica keeps committing");
}

/// The pending set is our own persisted data, but it can be stale: a crash between a commit and
/// the rewrite that follows it leaves a set that starts at (or below) the new head, and a set
/// that does not reach the head at all must not be inserted (review focus 3). `resume` skips
/// what is at or under the head, inserts what extends what it holds, in order, and drops the
/// rest silently.
#[test]
fn a_stale_pending_set_is_dropped() {
    let mut sim = setup(4, 4);
    let victim = certified_chain_of(&mut sim, 2);
    let old = &sim.nodes[victim];
    let chain = certified_blocks(old);
    assert_eq!(chain.len(), 2, "two certified blocks above the head");
    let (mid, tip) = (chain[0].clone(), chain[1].clone());
    let head_hash = old.committed_hash();
    assert_eq!(mid.parent(), head_hash);
    let safety = old.safety_state();
    let ledger = old.committed_ledger().clone();
    let (head, qc) = match sim.committed[victim].last() {
        Some(cb) => (cb.block.clone(), cb.qc.clone()),
        None => (old.block(&head_hash).unwrap().clone(), QuorumCertificate::genesis(head_hash)),
    };
    let epoch_sets = old.epoch_sets().clone();
    let resume = |pending: Vec<Block>| {
        HotStuff::resume(
            config_of(&sim),
            Some(Keypair::from_seed(*sim.keys[victim].seed()).unwrap()),
            head.clone(),
            qc.clone(),
            ledger.clone(),
            Some(safety.clone()),
            pending,
            epoch_sets.clone(),
            std::sync::Arc::new(StubExecutor),
        )
    };
    // A set that does not extend the head: nothing is inserted.
    let stale = resume(vec![tip.clone()]);
    assert!(!stale.has_block(&tip.hash()), "a block whose parent is not held is dropped");
    assert_eq!(stale.pending_tip_height(), stale.committed_height(), "the tree holds only the head");
    // The whole certified chain, in order: both blocks are back.
    let whole = resume(vec![mid.clone(), tip.clone()]);
    assert!(whole.has_block(&mid.hash()) && whole.has_block(&tip.hash()), "two pending blocks restored in order");
    assert_eq!(whole.pending_tip_height(), whole.committed_height() + 2);
    // A set that starts at the head — the crash between the commit and the rewrite: the head is
    // skipped, not re-inserted, and what is above it is restored.
    let overlapping = resume(vec![head.clone(), mid.clone(), tip.clone()]);
    assert!(overlapping.has_block(&mid.hash()) && overlapping.has_block(&tip.hash()));
    assert_eq!(overlapping.pending_tip_height(), overlapping.committed_height() + 2);
    // Out of order, the child comes first and has no parent yet: it is dropped, the parent kept.
    let reversed = resume(vec![tip.clone(), mid.clone()]);
    assert!(reversed.has_block(&mid.hash()));
    assert!(!reversed.has_block(&tip.hash()), "order is the writer's promise, not something resume repairs");
}

/// A QC every validator of `sim` signed for `hash` at `view`: what a NewView can carry for a
/// block this replica never held — the ghost of the 2026-09-24 stall.
fn quorum_qc_for(sim: &Sim, view: u64, hash: Hash) -> QuorumCertificate {
    let votes = sim.keys.iter().map(|k| Vote::sign(&sim.domain(), view, hash, k)).collect();
    QuorumCertificate { view, block_hash: hash, votes }
}

/// With every certified block persisted, a persisted high QC whose block is not in the pending
/// set (and not the head) is a ghost by construction — every legitimately certified block above
/// the head is in the set — so `resume` drops it to the highest QC certifying a block it holds
/// instead of restoring it. The fleet on v0.5.4 had exactly this state on every node: a high
/// QC on a block nobody held, restored at every restart and re-announced by every NewView. The
/// lock is not touched: only the not-held quorum releases it.
#[test]
fn a_persisted_high_qc_on_a_block_the_pending_set_lacks_is_dropped_at_resume() {
    let mut sim = setup(4, 4);
    let victim = certified_chain_of(&mut sim, 2);
    let old = &sim.nodes[victim];
    let chain = certified_blocks(old);
    let (mid, tip) = (chain[0].clone(), chain[1].clone());
    let high = old.high_qc().clone();
    assert_eq!(high.block_hash, tip.hash());
    let safety = old.safety_state();
    let ledger = old.committed_ledger().clone();
    let head_hash = old.committed_hash();
    let (head, head_qc) = match sim.committed[victim].last() {
        Some(cb) => (cb.block.clone(), cb.qc.clone()),
        None => (old.block(&head_hash).unwrap().clone(), QuorumCertificate::genesis(head_hash)),
    };
    let epoch_sets = old.epoch_sets().clone();
    let resume = |pending: Vec<Block>| {
        let mut hs = HotStuff::resume(
            config_of(&sim),
            Some(Keypair::from_seed(*sim.keys[victim].seed()).unwrap()),
            head.clone(),
            head_qc.clone(),
            ledger.clone(),
            Some(safety.clone()),
            pending,
            epoch_sets.clone(),
            std::sync::Arc::new(StubExecutor),
        );
        let acts = hs.start();
        (hs, acts)
    };
    // The set holds the block: the QC is restored, as before.
    let (whole, acts) = resume(vec![mid.clone(), tip.clone()]);
    assert_eq!(whole.high_qc(), &high, "the high QC is restored when its block is held");
    assert!(!acts.iter().any(|a| matches!(a, Action::FetchBlock(_))), "{acts:?}");
    // The set lacks the block: the QC is a ghost, dropped to the highest held one — here the
    // head's — and nothing is fetched. The lock stays exactly as persisted.
    let (ghost, acts) = resume(Vec::new());
    assert_eq!(ghost.high_qc(), &head_qc, "a high QC on a block the pending set lacks is dropped to the head's");
    assert_eq!(ghost.high_qc().view, ghost.committed_qc_view());
    assert!(!acts.iter().any(|a| matches!(a, Action::FetchBlock(_))), "no fetch for a ghost: {acts:?}");
    let kept_lock = if safety.locked_qc.view > head_qc.view { safety.locked_qc.clone() } else { head_qc.clone() };
    assert_eq!(ghost.locked_qc(), &kept_lock, "the lock is kept");
    // The set holds the lower block only — not a state the node writes (the set is written
    // before the safety state that names the QC), but the rule is the same: the ghost is
    // dropped to the highest held certificate, and nothing is fetched.
    let (partial, acts) = resume(vec![mid.clone()]);
    assert!(partial.has_block(&mid.hash()));
    assert_ne!(partial.high_qc(), &high, "a ghost");
    assert!(partial.has_block(&partial.high_qc().block_hash), "the high QC names a held block");
    assert!(!acts.iter().any(|a| matches!(a, Action::FetchBlock(_))), "{acts:?}");
    // The reachable crash: the set is written, the safety state that names the tip's QC is
    // not. The older high QC's block is held, so it is restored — and the tip is in the tree
    // for the next NewView to certify.
    let mut older = safety.clone();
    older.high_qc = tip.header.justify.clone();
    let mut hs = HotStuff::resume(
        config_of(&sim),
        Some(Keypair::from_seed(*sim.keys[victim].seed()).unwrap()),
        head.clone(),
        head_qc.clone(),
        ledger.clone(),
        Some(older),
        vec![mid.clone(), tip.clone()],
        epoch_sets.clone(),
        std::sync::Arc::new(StubExecutor),
    );
    hs.start();
    assert_eq!(hs.high_qc(), &tip.header.justify);
    assert!(hs.has_block(&mid.hash()) && hs.has_block(&tip.hash()));
}

/// `fallback_high_qc` lands on the highest QC certifying a block the replica holds, not blindly
/// on the head's: a replica holding certified pending blocks above its head that fell back to
/// the head's QC proposed a sibling of the first pending block, which nobody could vote for
/// (chain 14, 2026-09-24: pending 248948..248952 above head 248947, fallback to view 261708).
#[test]
fn a_fallback_lands_on_the_highest_certified_block_held() {
    let mut sim = setup(4, 4);
    let victim = certified_chain_of(&mut sim, 2);
    let chain = certified_blocks(&sim.nodes[victim]);
    let tip = chain[1].clone();
    let high = sim.nodes[victim].high_qc().clone();
    assert_eq!(high.block_hash, tip.hash());
    // A quorum-signed QC on a block this replica never held, at a higher view, announced by a
    // peer's NewView: believed, as it must be.
    let ghost = Hash::digest(b"a block nobody holds");
    let ghost_qc = quorum_qc_for(&sim, high.view + 1, ghost);
    let view = sim.nodes[victim].view().max(high.view + 2);
    let announcer = (0..4).find(|&i| i != victim).unwrap();
    let nv = NewView::sign(&sim.domain(), view, ghost_qc.clone(), &sim.keys[announcer]);
    let acts = sim.nodes[victim].on_new_view(nv).expect("a well-formed new-view");
    sim.handle(victim, acts);
    assert_eq!(sim.nodes[victim].high_qc(), &ghost_qc);
    // Every fetch failed: the fallback lands on the QC certifying the higher pending block —
    // the certificate the replica holds — not on the head's.
    let acts = sim.nodes[victim].fallback_high_qc(&ghost);
    sim.handle(victim, acts);
    assert_eq!(sim.nodes[victim].high_qc(), &high, "back to the highest QC certifying a held block");
    assert!(sim.nodes[victim].has_block(&sim.nodes[victim].high_qc().block_hash));
    assert!(sim.nodes[victim].high_qc().view > sim.nodes[victim].committed_qc_view());
}

// ---------------------------------------------------------------------------
// Consensus domain v1 (audit v4): the genesis hash in every signed message
// ---------------------------------------------------------------------------

#[test]
fn a_v1_new_view_for_one_chain_does_not_verify_under_another() {
    let k = Keypair::from_seed([1; 32]).unwrap();
    let a = SigningDomain::v1(Hash([1; 32]));
    let b = SigningDomain::v1(Hash([2; 32]));
    let nv = NewView::sign(&a, 5, QuorumCertificate::genesis(Hash([1; 32])), &k);
    assert!(nv.verify(&a));
    assert!(!nv.verify(&b));
    assert!(!nv.verify(&SigningDomain::v0(Hash([1; 32]))), "a v1 new-view is not a v0 one");
}

/// The same simulation, the same test bodies, under `consensus_domain: 1`: every replica signs
/// and verifies with the genesis hash in the message, and nothing else about consensus changes.
/// A v0 vote from a set member is refused on a v1 chain.
#[test]
fn the_consensus_suite_holds_under_signing_domain_v1() {
    with_domain(1, || {
        let mut sim = setup(4, 4);
        assert_eq!(sim.gs.consensus_domain, 1);
        assert_eq!(sim.nodes[0].domain(), &SigningDomain::v1(sim.gs.hash()));
        sim.step(vec![]);
        let stale_domain = SigningDomain::v0(sim.gs.hash());
        let v = Vote::sign(&stale_domain, sim.nodes[0].view(), sim.nodes[0].high_qc().block_hash, &sim.keys[1]);
        assert_eq!(sim.nodes[0].on_vote(v), Err(ConsensusError::BadVote), "a v0 signature is not a v1 vote");
        drop(sim);

        four_validators_commit_empty_blocks_in_lockstep();
        two_validators_need_both_signatures_and_commit();
        liveness_recovers_after_leader_timeout();
        rejects_proposal_from_wrong_leader_and_bad_signature();
        restart_mid_run_rejoins_and_stays_consistent();
        a_resumed_validator_keeps_its_lock();
        a_resumed_validator_finds_its_locked_block_without_a_fetch();
        eight_unsigned_not_found_replies_no_longer_release_the_lock();
        not_held_releases_the_lock_only_on_a_quorum();
        a_restart_keeps_the_blocks_a_qc_certified();
        commit_rule_requires_three_consecutive_views();
        a_leaders_second_block_for_one_view_is_refused_as_equivocation();
        epoch_rollover_uses_the_register_after_the_last_block_of_the_previous_epoch();
    });
}

// ---------------------------------------------------------------------------
// Scan sweep 2026-09-26, SW-1: the orphan pool
// ---------------------------------------------------------------------------

/// The honest out-of-order pair every orphan test checks survives: B1 and B2 from the one
/// validator, and a fresh observer on the same genesis.
fn sw1_parts() -> (ConsensusConfig, crate::genesis::GenesisState, Keypair, Block, Block) {
    let (cfg, gs, key) = one_node_parts();
    let mut x = one_node_with(cfg.clone(), gs.block.clone(), gs.ledger.clone(), Keypair::from_seed(*key.seed()).unwrap());
    x.node.start();
    let b1 = proposal_of(&x.propose(1));
    let b2 = proposal_of(&x.propose(2));
    (cfg, gs, key, b1, b2)
}

fn sw1_observer(cfg: &ConsensusConfig, gs: &crate::genesis::GenesisState) -> HotStuff {
    let mut z = HotStuff::new(cfg.clone(), None, gs.block.clone(), gs.ledger.clone(), std::sync::Arc::new(StubExecutor));
    z.start();
    z
}

/// A block on a parent nobody holds, signed by `key`, carrying `txs` under a correct tx root.
fn sw1_orphan(cfg: &ConsensusConfig, key: &Keypair, height: u64, view: u64, salt: u64, txs: Vec<Transaction>) -> Block {
    let header = crate::types::BlockHeader {
        height,
        view,
        parent: Hash::digest(&salt.to_le_bytes()),
        proposer: key.public_key().clone(),
        timestamp_ms: 0,
        tx_root: Block::tx_root(&txs),
        state_root: Hash::ZERO,
        justify: QuorumCertificate::genesis(cfg.genesis_hash),
    };
    Block::sign(&cfg.domain, header, txs, key)
}

/// A mint whose envelope body is `bytes` long: payload for the size tests.
fn sw1_padded(key: &Keypair, bytes: usize) -> Transaction {
    let mut tx = mint(key, 9);
    if let crate::types::Action::Mint { envelope, .. } = &mut tx.action {
        envelope.body = vec![0xab; bytes];
    }
    tx
}

/// B2 before B1 at a replica holding `z`'s pool: B2 must come back out when B1 arrives.
fn sw1_honest_orphan_survives(z: &mut HotStuff, b1: &Block, b2: &Block) -> bool {
    assert!(matches!(z.on_proposal(b2.clone(), 0), Err(ConsensusError::UnknownParent(_))));
    let _ = z.on_proposal(b1.clone(), 0);
    z.has_block(&b2.hash())
}

/// A proposal signed by a key in no validator set, on a parent nobody holds, was kept as an
/// orphan after only its view and its own signature were checked; at a height past anything the
/// chain will commit, `prune` never dropped it. 256 of them pinned the pool for good (and held
/// 256 MiB here, ~4 GiB at the transport's 16 MiB): a legitimate out-of-order proposal was lost.
#[test]
fn an_outsiders_orphans_are_refused_and_never_pin_the_pool() {
    let (cfg, gs, _key, b1, b2) = sw1_parts();
    // Baseline: an observer that sees B2 before B1 recovers B2 from its orphan pool.
    let mut y = sw1_observer(&cfg, &gs);
    assert!(sw1_honest_orphan_survives(&mut y, &b1, &b2), "baseline: the orphan is replayed");

    let outsider = Keypair::from_seed([0xee; 32]).unwrap();
    let mut z = sw1_observer(&cfg, &gs);
    let junk = sw1_padded(&outsider, 1 << 20);
    for i in 0..256u64 {
        let r = z.on_proposal(sw1_orphan(&cfg, &outsider, u64::MAX - i, 1, i, vec![junk.clone()]), 0);
        assert!(r.is_err(), "an outsider's block with an unknown parent cannot apply: {r:?}");
    }
    assert!(
        sw1_honest_orphan_survives(&mut z, &b1, &b2),
        "the honest orphan was dropped: the pool is pinned by 256 outsider blocks"
    );
    assert_eq!(z.orphans_held().0, 0, "nothing of the outsider's is held");
}

/// Even the leader's own key cannot pin the pool: the count cap was first-come and never
/// evicted above the committed height, so 256 blocks on made-up parents at far heights shut out
/// the one out-of-order block that mattered. A full pool now gives way to a lower height.
#[test]
fn a_full_orphan_pool_gives_way_to_a_lower_height() {
    let (cfg, gs, key, b1, b2) = sw1_parts();
    let mut z = sw1_observer(&cfg, &gs);
    for i in 0..cfg.max_orphans as u64 {
        let r = z.on_proposal(sw1_orphan(&cfg, &key, 100 + i, 2, i, vec![]), 0);
        assert!(r.is_err(), "{r:?}");
    }
    assert_eq!(z.orphans_held().0, cfg.max_orphans);
    assert!(sw1_honest_orphan_survives(&mut z, &b1, &b2), "a full orphan pool refused the honest out-of-order block");
    assert!(z.orphans_held().0 <= cfg.max_orphans);
}

/// The orphan pool is bounded by bytes, not only by count: sixteen 1 MiB orphans against a
/// 4 MiB budget keep at most the budget, and the honest orphan still gets in.
#[test]
fn the_orphan_pool_is_bounded_in_bytes() {
    let (mut cfg, gs, key, b1, b2) = sw1_parts();
    cfg.max_orphan_bytes = 4 << 20;
    let mut z = sw1_observer(&cfg, &gs);
    let payload = sw1_padded(&key, 1 << 20);
    for i in 0..16u64 {
        let _ = z.on_proposal(sw1_orphan(&cfg, &key, 100 + i, 2, i, vec![payload.clone()]), 0);
    }
    let (_, bytes) = z.orphans_held();
    assert!(bytes <= cfg.max_orphan_bytes as u64, "the orphan pool holds {bytes} bytes against a budget of {}", cfg.max_orphan_bytes);
    assert!(sw1_honest_orphan_survives(&mut z, &b1, &b2));
}

/// What a block with an unknown parent must pass before it is kept: a height the tree could
/// ever reach, a view above the committed head's, the block byte cap, and its own tx root.
#[test]
fn an_orphan_is_checked_before_it_is_kept() {
    let (cfg, gs, key, b1, b2) = sw1_parts();
    let mut z = sw1_observer(&cfg, &gs);
    let too_high = cfg.max_tree_blocks as u64 + 1;
    let r = z.on_proposal(sw1_orphan(&cfg, &key, too_high, 2, 1, vec![]), 0);
    assert!(!matches!(r, Err(ConsensusError::UnknownParent(_))), "a height past the tree's reach was kept: {r:?}");
    let r = z.on_proposal(sw1_orphan(&cfg, &key, 5, 0, 2, vec![]), 0);
    assert!(!matches!(r, Err(ConsensusError::UnknownParent(_))), "a view at the committed head's was kept: {r:?}");
    let over = sw1_padded(&key, gs.ledger.max_block_bytes() + 1);
    let r = z.on_proposal(sw1_orphan(&cfg, &key, 5, 2, 3, vec![over]), 0);
    assert_eq!(r, Err(ConsensusError::Execution(crate::ledger::BlockError::TooLarge)));
    let mut bad_root = sw1_orphan(&cfg, &key, 5, 2, 4, vec![mint(&key, 4)]);
    bad_root.transactions.push(mint(&key, 5));
    let r = z.on_proposal(bad_root, 0);
    assert_eq!(r, Err(ConsensusError::Execution(crate::ledger::BlockError::TxRootMismatch)));
    // A justify carrying more votes than any set has validators is refused too.
    let mut fat = sw1_orphan(&cfg, &key, 5, 2, 6, vec![]);
    fat.header.justify = QuorumCertificate {
        view: 1,
        block_hash: fat.header.parent,
        votes: (0..2).map(|_| Vote::sign(&cfg.domain, 1, fat.header.parent, &key)).collect(),
    };
    let fat = Block::sign(&cfg.domain, fat.header, fat.transactions, &key);
    assert_eq!(z.on_proposal(fat, 0), Err(ConsensusError::BadJustify));
    assert_eq!(z.orphans_held().0, 0);
    assert!(sw1_honest_orphan_survives(&mut z, &b1, &b2));
}

// ---------------------------------------------------------------------------
// Scan 2026-09-26, CONS-1: the vote map
// ---------------------------------------------------------------------------

/// One validator's key filled `pending_votes`: `on_vote` took a signed vote from any set member
/// for any view up to `MAX_VIEW_AHEAD` and any block hash, and a full map (4096 keys) dropped the
/// votes for every new key — the honest ones included — so no QC formed again and the chain
/// stopped committing. The flood here tops up whatever slot a completed QC frees, far-future and
/// in-window views alike, from a validator that then goes silent: three of four is a quorum.
#[test]
fn one_validators_votes_cannot_fill_the_vote_map() {
    let mut sim = setup(4, 4);
    for _ in 0..6 {
        sim.step(vec![]);
    }
    let before = sim.committed[0].len();
    assert!(before >= 2);
    let attacker = Keypair::from_seed(*sim.keys[3].seed()).unwrap();
    sim.down[3] = true;
    let domain = sim.domain();
    let mut fresh = 0u32;
    let mut flood = |node: &mut HotStuff, budget: usize| {
        for _ in 0..budget.min(MAX_PENDING_VOTE_KEYS_FOR_TESTS.saturating_sub(node.vote_keys())) {
            fresh += 1;
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&fresh.to_be_bytes());
            // Mostly far-future views, which nothing prunes; one in eight inside the window.
            let ahead = if fresh % 8 != 0 { 900_000 } else { u64::from(fresh / 8 % 9) };
            let _ = node.on_vote(Vote::sign(&domain, node.view() + ahead, Hash(h), &attacker));
        }
    };
    for j in 0..3 {
        flood(&mut sim.nodes[j], MAX_PENDING_VOTE_KEYS_FOR_TESTS);
    }
    for _ in 0..40 {
        for j in 0..3 {
            flood(&mut sim.nodes[j], 512);
        }
        sim.step(vec![]);
    }
    sim.assert_consistent();
    let after = sim.committed[0].len();
    assert!(after > before + 5, "no QC formed once one validator's votes filled the vote map: committed {before} -> {after}");
    // One vote per (view, voter), inside the window: 4 voters × (window + the view before).
    let bound = 4 * (PROPOSAL_VIEW_WINDOW as usize + 2);
    for j in 0..3 {
        assert!(sim.nodes[j].vote_keys() <= bound, "node {j} holds {} vote keys", sim.nodes[j].vote_keys());
    }
}

/// `hotstuff::MAX_PENDING_VOTE_KEYS`, which the flood above aims at.
const MAX_PENDING_VOTE_KEYS_FOR_TESTS: usize = 4096;
