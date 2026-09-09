//! Deterministic multi-replica simulation of the HotStuff state machine.

use super::*;
use crate::confidential::StubExecutor;
use crate::genesis::{Genesis, GenesisValidator};
use crate::types::Transaction;
use std::collections::{BTreeMap, VecDeque};

struct Sim {
    nodes: Vec<HotStuff>,
    keys: Vec<Keypair>,
    addr_to_idx: BTreeMap<Address, usize>,
    /// (to, msg). `None` = broadcast.
    queue: VecDeque<(Option<usize>, usize, ConsensusMessage)>,
    committed: Vec<Vec<CommittedBlock>>,
    timers: Vec<Option<u64>>,
    pending_propose: Vec<Option<u64>>,
    fetches: Vec<(usize, Hash)>,
    now: u64,
    /// Node indices that are partitioned off (drop everything to/from them).
    down: Vec<bool>,
}

fn setup(n: u8, validators: u8) -> Sim {
    let keys: Vec<Keypair> = (1..=n).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect();
    let genesis = Genesis {
        chain_id: 1,
        timestamp_ms: 0,
        validators: keys[..validators as usize]
            .iter()
            .map(|k| GenesisValidator { public_key: k.public_key().clone(), stake: 10 })
            .collect(),
        alloc: keys.iter().map(|k| (k.address().to_base58(), 1_000)).collect(),
        faucet: false,
        confidential: true,
        fri_profile: "production".into(),
    };
    let gs = genesis.build().unwrap();
    let cfg = ConsensusConfig::new(1, gs.validators.clone(), gs.hash());
    let mut nodes = Vec::new();
    let mut addr_to_idx = BTreeMap::new();
    for (i, k) in keys.iter().enumerate() {
        let signer = if i < validators as usize { Some(Keypair::from_seed(*k.seed()).unwrap()) } else { None };
        nodes.push(HotStuff::new(cfg.clone(), signer, gs.block.clone(), gs.ledger.clone(), std::sync::Arc::new(StubExecutor)));
        addr_to_idx.insert(k.address(), i);
    }
    let mut sim = Sim {
        committed: vec![Vec::new(); n as usize],
        timers: vec![None; n as usize],
        pending_propose: vec![None; n as usize],
        fetches: Vec::new(),
        down: vec![false; n as usize],
        nodes,
        keys,
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
    fn handle(&mut self, i: usize, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Broadcast(m) => self.queue.push_back((None, i, m)),
                Action::SendTo(addr, m) => {
                    let to = self.addr_to_idx[&addr];
                    self.queue.push_back((Some(to), i, m));
                }
                Action::Commit(blocks) => self.committed[i].extend(blocks),
                Action::ScheduleTimeout { view, .. } => self.timers[i] = Some(view),
                Action::ReadyToPropose { view } => self.pending_propose[i] = Some(view),
                Action::FetchBlock(h) => self.fetches.push((i, h)),
                Action::PersistSafety(_) => {}
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
                match self.nodes[who].on_proposal(b) {
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
                let r = self.nodes[j].on_message(msg.clone());
                match r {
                    Ok(acts) => self.handle(j, acts),
                    // Like the real node: an unknown parent triggers a fetch.
                    Err(ConsensusError::UnknownParent(h)) => self.fetches.push((j, h)),
                    Err(ConsensusError::Stale(_)) | Err(ConsensusError::NotLeader) => {}
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

#[test]
fn four_validators_commit_empty_blocks_in_lockstep() {
    let mut sim = setup(4, 4);
    for _ in 0..8 {
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
fn transfer_is_included_and_applied_on_every_node() {
    let mut sim = setup(4, 4);
    let alice = Keypair::from_seed(*sim.keys[0].seed()).unwrap();
    let bob = sim.keys[1].address();
    let tx = Transaction::transfer(&alice, 1, 0, bob, 250, 5);
    sim.step(vec![tx.clone()]);
    for _ in 0..6 {
        sim.step(vec![]);
    }
    sim.assert_consistent();
    let found = sim.committed[0].iter().find(|cb| cb.block.transactions.iter().any(|t| t.hash() == tx.hash()));
    let block = found.expect("transfer committed").block.clone();
    let proposer = block.proposer();
    let fee_to = |a: Address| if a == proposer { 5 } else { 0 };
    for node in &sim.nodes {
        let l = node.committed_ledger();
        assert_eq!(l.balance(&alice.address()), 1_000 - 255 + fee_to(alice.address()));
        assert_eq!(l.balance(&bob), 1_250 + fee_to(bob));
        assert_eq!(l.nonce(&alice.address()), 1);
    }
    // The same tx offered again is skipped by proposers (nonce already used).
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
    let block = Block::sign(header, vec![], &sim.keys[wrong]);
    let target = (0..4).find(|&i| i != wrong).unwrap();
    assert_eq!(sim.nodes[target].on_proposal(block.clone()).unwrap_err(), ConsensusError::WrongLeader(view));

    let li = sim.addr_to_idx[&leader];
    let mut forged = block.clone();
    forged.header.proposer = sim.keys[li].public_key().clone();
    assert_eq!(sim.nodes[target].on_proposal(forged).unwrap_err(), ConsensusError::BadSignature);
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
    let cfg = ConsensusConfig::new(1, validators_of(&sim), genesis_hash_of(&sim));
    let safety = sim.nodes[0].safety_state();
    let ledger = sim.nodes[0].committed_ledger().clone();
    let resumed = HotStuff::resume(
        cfg,
        Some(Keypair::from_seed(*sim.keys[0].seed()).unwrap()),
        head.block.clone(),
        head.qc.clone(),
        ledger,
        Some(safety.clone()),
        std::sync::Arc::new(StubExecutor),
    );
    assert_eq!(resumed.committed_height(), head.block.height());
    assert!(resumed.view() >= safety.view);
    assert_eq!(resumed.high_qc().block_hash, head.block.hash());
}

fn validators_of(sim: &Sim) -> crate::types::ValidatorSet {
    crate::types::ValidatorSet::new(
        sim.keys
            .iter()
            .take(sim.nodes.iter().filter(|n| n.is_validator()).count())
            .map(|k| crate::types::Validator { public_key: k.public_key().clone(), stake: 10 })
            .collect(),
    )
}
fn genesis_hash_of(sim: &Sim) -> Hash {
    sim.committed[0][0].block.parent()
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
        let cfg = ConsensusConfig::new(1, validators_of(self), genesis_hash_of_any(self));
        let signer = if old.is_validator() { Some(Keypair::from_seed(*self.keys[i].seed()).unwrap()) } else { None };
        self.nodes[i] = HotStuff::resume(cfg, signer, head, qc, ledger, Some(safety), std::sync::Arc::new(StubExecutor));
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

fn genesis_hash_of_any(sim: &Sim) -> Hash {
    for c in &sim.committed {
        if let Some(first) = c.first() {
            return first.block.parent();
        }
    }
    sim.nodes[0].committed_hash()
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
    let acts = sim.nodes[victim].on_proposal(proposal.clone()).unwrap();
    let voted = acts.iter().any(|a| matches!(a, Action::SendTo(_, ConsensusMessage::Vote(v)) if v.view == view));
    assert!(voted, "victim should vote the first time");
    assert!(acts.iter().any(|a| matches!(a, Action::PersistSafety(_))), "safety must be persisted before voting");
    assert_eq!(sim.nodes[victim].safety_state().last_voted_view, view);

    sim.restart(victim);
    assert_eq!(sim.nodes[victim].safety_state().last_voted_view, view, "last_voted_view survives restart");
    // Same proposal again: block is unknown to the fresh replica, but it must not vote.
    let acts = sim.nodes[victim].on_proposal(proposal).unwrap_or_default();
    assert!(
        !acts.iter().any(|a| matches!(a, Action::SendTo(_, ConsensusMessage::Vote(v)) if v.view == view)),
        "restarted node voted twice in view {view}"
    );
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
        let b = Block::sign(header, vec![], &sim.keys[li]);
        let acts = sim.nodes[victim].on_proposal(b).unwrap_or_default();
        assert!(!acts.iter().any(|a| matches!(a, Action::SendTo(_, ConsensusMessage::Vote(_)))));
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
fn restart_with_transfers_keeps_ledgers_identical() {
    let mut sim = setup(4, 4);
    let alice = Keypair::from_seed(*sim.keys[0].seed()).unwrap();
    let bob = sim.keys[1].address();
    for n in 0..3u64 {
        let tx = Transaction::transfer(&alice, 1, n, bob, 100, 1);
        // The simulator has no mempool: keep offering the tx until a proposer includes it.
        let mut tries = 0;
        while sim.nodes[0].tip_ledger().nonce(&alice.address()) <= n {
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
        assert_eq!(node.committed_ledger().nonce(&alice.address()), 3);
        assert!(node.committed_ledger().balance(&bob) >= 1_300);
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
