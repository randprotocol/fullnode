//! The gossip-side precheck of a consensus message (scan 2026-09-27, CN-4).
//!
//! The node reports every delivered gossip message to gossipsub exactly once, and an `Accept` is
//! what makes gossipsub forward it to the rest of the mesh. Until CN-4 the consensus arm accepted
//! every decodable `Proposal`, `Vote` and `NewView` before this replica had looked at it, so a
//! vote from a key no set holds, a proposal self-signed by a non-leader, or a NewView whose
//! `high_qc` was a 16 MiB field went fleet-wide before `on_proposal`/`on_vote`/`on_new_view`
//! refused it — and every honest relay spent its downstream peers' per-forwarder budgets carrying
//! it, until honest consensus messages were the ones being `Ignore`d downstream.
//!
//! [`HotStuff::precheck_gossip`] is what the node now asks before it reports. It is cheap and
//! stateless-ish: lengths, counts, set membership in a set this replica already knows, and one
//! Dilithium2 verify (~0.1 ms) — never an execution, never a QC's worth of verifies, never a
//! parent lookup that a legitimate orphan could fail (SW-1's `check_orphan` owns orphans). The
//! replica path still verifies the same signature again (`on_vote`, `on_new_view`,
//! `on_proposal`): the second verify is ~0.1 ms per message, and threading a "verified" bit
//! through `ConsensusMessage` would change a type the wire, the simulator and storage share for
//! nothing measurable. So a message is verified twice, deliberately.
//!
//! **The Reject/Ignore line.** `Reject` is only for a message no honest node can have produced
//! and no honest node running this check would have forwarded — its bytes are wrong whatever
//! this replica's view, epoch or tree is: a key or signature of the wrong length, a proposal
//! over the genesis block cap (a consensus rule: `max_block_bytes` never changes after genesis),
//! a certificate whose votes disagree with it, or a signature that fails under a key this
//! replica knows as a validator's (the signing domain is the genesis's, the same on every node).
//! Everything that depends on how far along this replica is — a view it has left behind or not
//! reached, a signer in no set it knows (it may be behind an epoch boundary), a certificate
//! larger than any set it knows — is `Ignore`: not forwarded, nobody penalised, because a lagging
//! honest node must never mark an honest forwarder down. An `Ignore` here still hands the
//! message to the replica (the node decides that, see `node::classify_consensus_gossip`): the
//! replica is the authority, and a stale-looking message may still be the one it needs.
use super::{HotStuff, PROPOSAL_VIEW_WINDOW};
use crate::consensus::ConsensusMessage;
use crate::crypto::{Address, PublicKey, Signature, PUBLIC_KEY_LEN};
use crate::types::{QuorumCertificate, Vote};

/// What the gossip layer should do with a consensus message before the replica sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipPrecheck {
    /// Nothing cheap found against it: forward it.
    Accept,
    /// Not forwarded, nobody penalised — it may be fine for a node that is further along (or
    /// less far along) than this one. The reason is for the log.
    Ignore(&'static str),
    /// Provably malformed or forged, whatever this replica's state: not forwarded, and the
    /// forwarder wears it. The reason is for the log.
    Reject(&'static str),
}

/// A key or signature of the fixed Dilithium2 size. Both types deserialize from any length
/// (`serde_bytes_vec`), so a peer can hand us a 16 MiB "signature" that `verify` would only
/// refuse after this node had forwarded it.
fn well_formed(key: &PublicKey, sig: &Signature) -> bool {
    key.as_bytes().len() == PUBLIC_KEY_LEN && sig.is_well_formed()
}

impl HotStuff {
    /// Every validator set this replica knows: the current set, the recorded epoch sets and the
    /// sets derived for blocks in its tree — the same union `check_orphan` admits a proposer
    /// from. Calls `f` on each until it returns `true`.
    fn any_known_set(&self, mut f: impl FnMut(&crate::types::ValidatorSet) -> bool) -> bool {
        if f(&self.current) {
            return true;
        }
        if self.epoch_sets.known().any(|(_, s)| f(s)) {
            return true;
        }
        self.derived().values().any(|s| f(s))
    }

    /// The largest set this replica knows, in validators: no honest certificate carries more
    /// votes than its own epoch's set has members (each counted once, `QuorumCertificate::verify`).
    fn largest_known_set(&self) -> usize {
        let mut largest = 0;
        self.any_known_set(|s| {
            largest = largest.max(s.len());
            false
        });
        largest
    }

    fn known_validator(&self, addr: &Address) -> bool {
        self.any_known_set(|s| s.contains(addr))
    }

    /// A certificate's shape, before any of its signatures: every vote well-formed and naming
    /// the certificate's own (view, block) — `QuorumCertificate::verify` refuses anything else on
    /// every replica, so those are `Reject` — and no more votes than the largest set this replica
    /// knows, which is `Ignore` (a set it has not seen yet could be larger). The count bound is
    /// what caps a certificate's bytes: each vote is fixed-size once well-formed.
    fn precheck_qc(&self, qc: &QuorumCertificate) -> GossipPrecheck {
        if qc.votes.len() > self.largest_known_set() {
            return GossipPrecheck::Ignore("certificate carries more votes than any known set has validators");
        }
        for v in &qc.votes {
            if !well_formed(&v.voter, &v.signature) {
                return GossipPrecheck::Reject("certificate vote with a malformed key or signature");
            }
            if v.view != qc.view || v.block_hash != qc.block_hash {
                return GossipPrecheck::Reject("certificate vote for another view or block");
            }
        }
        GossipPrecheck::Accept
    }

    /// The gossip layer's cheap verdict on `msg` (CN-4; the policy is the module doc). Cheapest
    /// first, and the signature last: a message that is stale or from an unknown key never costs
    /// a verify.
    pub fn precheck_gossip(&self, msg: &ConsensusMessage) -> GossipPrecheck {
        match msg {
            ConsensusMessage::Vote(v) => self.precheck_vote(v),
            ConsensusMessage::NewView(nv) => {
                if !well_formed(&nv.sender, &nv.signature) {
                    return GossipPrecheck::Reject("new view with a malformed key or signature");
                }
                // `on_new_view`'s own staleness and range: it returns before counting either.
                if nv.view < self.view {
                    return GossipPrecheck::Ignore("new view for a view this replica has left");
                }
                if nv.view > self.view.saturating_add(super::MAX_VIEW_AHEAD) {
                    return GossipPrecheck::Ignore("new view too far ahead");
                }
                let qc = self.precheck_qc(&nv.high_qc);
                if qc != GossipPrecheck::Accept {
                    return qc;
                }
                if !self.known_validator(&nv.sender_address()) {
                    return GossipPrecheck::Ignore("new view from a key in no validator set this replica knows");
                }
                if !nv.verify(&self.cfg.domain) {
                    return GossipPrecheck::Reject("new view signature does not verify");
                }
                // The embedded certificate's signatures are left to `on_new_view`: up to a set's
                // worth of verifies per message is the cost this check exists to keep off the
                // relay path, and a validator signed this one — it is attributable.
                GossipPrecheck::Accept
            }
            ConsensusMessage::Proposal(block) => {
                if !well_formed(&block.header.proposer, &block.signature) {
                    return GossipPrecheck::Reject("proposal with a malformed key or signature");
                }
                // The block rules `apply_block_for_sync` refuses on without state, and that no
                // replica's progress changes: the transaction count and the genesis byte cap.
                if block.transactions.len() > crate::gas::MAX_BLOCK_TXS {
                    return GossipPrecheck::Reject("proposal over the block's transaction cap");
                }
                let max_bytes = self.committed_ledger.max_block_bytes();
                let mut tx_bytes = 0usize;
                for tx in &block.transactions {
                    tx_bytes = tx_bytes.saturating_add(bincode::serialized_size(tx).map_or(usize::MAX, |n| n as usize));
                    if tx_bytes > max_bytes {
                        return GossipPrecheck::Reject("proposal over the block byte cap");
                    }
                }
                let justify = &block.header.justify;
                if justify.block_hash != block.parent() {
                    return GossipPrecheck::Reject("proposal whose justify does not certify its parent");
                }
                let qc = self.precheck_qc(justify);
                if qc != GossipPrecheck::Accept {
                    return qc;
                }
                // `on_proposal`'s window: stale below the committed head, too far ahead past the
                // proposal window. Neither is forwarded; a far-behind replica catches up by sync.
                if block.height() <= self.committed_height {
                    return GossipPrecheck::Ignore("proposal at or under the committed head");
                }
                if block.view() > self.view.saturating_add(PROPOSAL_VIEW_WINDOW) {
                    return GossipPrecheck::Ignore("proposal too far ahead of this replica's view");
                }
                // The leader of its view in a set this replica knows — `check_orphan`'s rule, and
                // no parent needed. Which set is the block's is decided by its branch, which the
                // replica checks; a proposer that leads in none is `Ignore`, not `Reject`, since
                // this replica may not hold the epoch's set yet.
                let proposer = block.proposer();
                if !self.any_known_set(|s| s.leader(block.view()) == proposer) {
                    return GossipPrecheck::Ignore("proposer leads the view in no validator set this replica knows");
                }
                if !block.verify_signature(&self.cfg.domain) {
                    return GossipPrecheck::Reject("proposal signature does not verify");
                }
                // The list the signed header commits to, and no transaction twice (audit v6,
                // GOSSIP-2) — last, so only a header its leader really signed costs the hashing
                // (one pass over the transactions, bounded by the byte cap above). Without it a
                // relayer could repeat the last transaction of a leader's block, or swap the
                // list outright, and the variant went out under the leader's hash and signature.
                if let Some(fault) = block.transaction_list_fault() {
                    return GossipPrecheck::Reject(fault);
                }
                GossipPrecheck::Accept
            }
        }
    }

    fn precheck_vote(&self, v: &Vote) -> GossipPrecheck {
        if !well_formed(&v.voter, &v.signature) {
            return GossipPrecheck::Reject("vote with a malformed key or signature");
        }
        // `on_vote`'s own windows, which it answers with "ignored", not an error: a stale vote
        // (under the high QC, or two views back) and one past the proposal window (CONS-1).
        if v.view < self.high_qc.view || v.view.saturating_add(1) < self.view {
            return GossipPrecheck::Ignore("vote for a view this replica has left");
        }
        if v.view > self.view.saturating_add(PROPOSAL_VIEW_WINDOW) {
            return GossipPrecheck::Ignore("vote too far ahead of this replica's view");
        }
        // The set `on_vote` counts it in first (the block's epoch when the block is held), then
        // any set this replica knows.
        let voter = v.voter_address();
        if !self.set_for_vote(&v.block_hash).contains(&voter) && !self.known_validator(&voter) {
            return GossipPrecheck::Ignore("vote from a key in no validator set this replica knows");
        }
        if !v.verify(&self.cfg.domain) {
            return GossipPrecheck::Reject("vote signature does not verify");
        }
        GossipPrecheck::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::consensus::{ConsensusConfig, EpochSets, NewView, SafetyState};
    use crate::crypto::{Hash, Keypair};
    use crate::genesis::{Genesis, GenesisValidator};
    use crate::notes::word8_to_hex;
    use crate::types::{Block, BlockHeader};
    use std::sync::Arc;

    const VIEW: u64 = 20;

    fn key(i: u8) -> Keypair {
        Keypair::from_seed([i; 32]).unwrap()
    }

    /// A four-validator chain (keys 1..=4), resumed at view [`VIEW`] with the genesis head, so
    /// there is room below the view for a stale message.
    fn replica() -> HotStuff {
        let genesis = Genesis {
            chain_id: 1,
            timestamp_ms: 0,
            validators: (1..=4u8)
                .map(|i| GenesisValidator {
                    public_key: key(i).public_key().clone(),
                    stake: crate::ledger::staking::MIN_STAKE as u128,
                    payout: crate::notes::ShieldedAddress { pk: [i as u32; 8], kem_ek: vec![i; crate::notes::KEM_EK_BYTES] }
                        .to_string(),
                })
                .collect(),
            alloc: Vec::new(),
            faucet: true,
            confidential: true,
            fri_profile: "test".into(),
            hc_bundle: word8_to_hex(&[3; 8]),
            epoch_blocks: crate::genesis::EPOCH_BLOCKS_DEFAULT,
            max_program_words: None,
            max_proof_bytes: None,
            max_block_bytes: None,
            max_call_envelope_bytes: None,
            max_program_public_words: None,
            hardening_v6: None,
            hc_auth: None,
            bridge: None,
            tokens: None,
            aggregation: None,
            consensus_domain: Some(1),
            staking: None,
            envelope_bytes: None,
            vesting: None,
            gas: None,
        };
        let gs = genesis.build(&StubExecutor).unwrap();
        let mut cfg = ConsensusConfig::new(1, gs.validators.clone(), gs.hash());
        cfg.domain = gs.signing_domain();
        let qc = QuorumCertificate::genesis(gs.hash());
        let safety = SafetyState { view: VIEW, high_qc: qc.clone(), locked_qc: qc.clone(), last_voted_view: 0, voted: Vec::new() };
        HotStuff::resume(
            cfg.clone(),
            Some(key(1)),
            gs.block.clone(),
            qc,
            gs.ledger.clone(),
            Some(safety),
            Vec::new(),
            EpochSets::new(cfg.genesis_set.clone()),
            Arc::new(StubExecutor),
        )
    }

    fn leader_key(hs: &HotStuff, view: u64) -> Keypair {
        (1..=4u8).map(key).find(|k| k.address() == hs.leader(view)).unwrap()
    }

    /// An honest proposal for `view` by its leader, extending genesis.
    fn proposal(hs: &HotStuff, view: u64, signer: &Keypair) -> Block {
        let header = BlockHeader {
            height: 1,
            view,
            parent: hs.cfg.genesis_hash,
            proposer: signer.public_key().clone(),
            timestamp_ms: 0,
            tx_root: Block::tx_root(&[]),
            state_root: Hash::ZERO,
            justify: QuorumCertificate::genesis(hs.cfg.genesis_hash),
        };
        Block::sign(&hs.cfg.domain, header, Vec::new(), signer)
    }

    fn vote(hs: &HotStuff, view: u64, k: &Keypair) -> ConsensusMessage {
        ConsensusMessage::Vote(Vote::sign(&hs.cfg.domain, view, Hash([7; 32]), k))
    }

    fn is_reject(p: GossipPrecheck) -> bool {
        matches!(p, GossipPrecheck::Reject(_))
    }
    fn is_ignore(p: GossipPrecheck) -> bool {
        matches!(p, GossipPrecheck::Ignore(_))
    }

    #[test]
    fn honest_consensus_messages_are_accepted() {
        let hs = replica();
        assert_eq!(hs.precheck_gossip(&vote(&hs, VIEW, &key(2))), GossipPrecheck::Accept);
        let nv = NewView::sign(&hs.cfg.domain, VIEW, QuorumCertificate::genesis(hs.cfg.genesis_hash), &key(3));
        assert_eq!(hs.precheck_gossip(&ConsensusMessage::NewView(nv)), GossipPrecheck::Accept);
        let leader = leader_key(&hs, VIEW);
        let block = proposal(&hs, VIEW, &leader);
        assert_eq!(hs.precheck_gossip(&ConsensusMessage::Proposal(block)), GossipPrecheck::Accept);
    }

    /// Audit v6, GOSSIP-2. The transaction root duplicates the last leaf of an odd level
    /// (`crypto::merkle_root`), so a block and the same block with its last transaction repeated
    /// share a root — and so a header, a hash and the leader's signature. The relay precheck
    /// checked neither the root nor the list, so anyone could take a leader's honest proposal,
    /// repeat its last transaction (or swap the list for another), and have every node forward
    /// the variant under the leader's name; in the orphan pool, which keys on the header hash,
    /// it then held the place of the honest block.
    #[test]
    fn a_proposal_whose_transactions_are_not_the_ones_its_header_commits_to_is_not_forwarded() {
        use crate::confidential::StubExecutor;
        let hs = replica();
        let leader = leader_key(&hs, VIEW);
        let mint = |n: u32| crate::types::Transaction::mint(1, [n; 8], 0, [n; 8], crate::notes::Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }, 1, &leader, &StubExecutor);
        let with = |txs: Vec<crate::types::Transaction>, root_of: &[crate::types::Transaction]| {
            let mut header = proposal(&hs, VIEW, &leader).header;
            header.tx_root = Block::tx_root(root_of);
            Block::sign(&hs.cfg.domain, header, txs, &leader)
        };
        let honest = vec![mint(1), mint(2), mint(3)];
        let block = with(honest.clone(), &honest);
        assert_eq!(hs.precheck_gossip(&ConsensusMessage::Proposal(block.clone())), GossipPrecheck::Accept);
        // The same header and signature over the list with its last transaction repeated.
        let mut repeated = block.clone();
        repeated.transactions.push(honest[2].clone());
        assert_eq!(repeated.header, block.header);
        assert_eq!(repeated.hash(), block.hash(), "the finding: one hash, two blocks");
        assert!(repeated.verify_tx_root(), "the finding: the repeated list has the honest root");
        assert!(repeated.verify_signature(&hs.cfg.domain));
        assert!(is_reject(hs.precheck_gossip(&ConsensusMessage::Proposal(repeated.clone()))), "a repeated transaction");
        // The pair repeated one level up has the honest root too.
        let six: Vec<_> = (1..=6).map(mint).collect();
        let mut eight = with(six.clone(), &six);
        eight.transactions.extend([six[4].clone(), six[5].clone()]);
        assert!(eight.verify_tx_root());
        assert!(is_reject(hs.precheck_gossip(&ConsensusMessage::Proposal(eight))), "a repeated pair");
        // And a list the header does not commit to at all.
        let swapped = with(vec![mint(7)], &honest);
        assert!(is_reject(hs.precheck_gossip(&ConsensusMessage::Proposal(swapped))), "another list under the header");
        assert_eq!(repeated.transaction_list_fault(), Some("a transaction appears twice in the block"));
        assert_eq!(block.transaction_list_fault(), None);
    }

    #[test]
    fn a_vote_from_a_non_validator_is_not_forwarded_and_not_penalised() {
        let hs = replica();
        let p = hs.precheck_gossip(&vote(&hs, VIEW, &key(9)));
        assert!(is_ignore(p), "{p:?}");
    }

    #[test]
    fn a_vote_with_a_bad_signature_from_a_validator_key_is_rejected() {
        let hs = replica();
        let ConsensusMessage::Vote(mut v) = vote(&hs, VIEW, &key(2)) else { unreachable!() };
        v.block_hash = Hash([8; 32]);
        let p = hs.precheck_gossip(&ConsensusMessage::Vote(v));
        assert!(is_reject(p), "{p:?}");
    }

    #[test]
    fn a_vote_with_an_oversized_signature_is_rejected() {
        let hs = replica();
        let ConsensusMessage::Vote(mut v) = vote(&hs, VIEW, &key(2)) else { unreachable!() };
        // `Signature` deserializes from any length: this is the bytes a peer can put on the wire.
        v.signature = bincode::deserialize(&bincode::serialize(&vec![0u8; 16 << 20]).unwrap()).unwrap();
        let p = hs.precheck_gossip(&ConsensusMessage::Vote(v));
        assert!(is_reject(p), "{p:?}");
    }

    /// A lagging or leading honest node must not penalise its forwarder: a stale vote — even one
    /// whose signature would not verify here — is ignored, and never costs a verify.
    #[test]
    fn a_stale_honest_vote_is_ignored_not_rejected() {
        let hs = replica();
        let p = hs.precheck_gossip(&vote(&hs, VIEW - 5, &key(2)));
        assert!(is_ignore(p), "{p:?}");
        let p = hs.precheck_gossip(&vote(&hs, VIEW + PROPOSAL_VIEW_WINDOW + 1, &key(2)));
        assert!(is_ignore(p), "{p:?}");
        let nv = NewView::sign(&hs.cfg.domain, VIEW - 5, QuorumCertificate::genesis(hs.cfg.genesis_hash), &key(3));
        let p = hs.precheck_gossip(&ConsensusMessage::NewView(nv));
        assert!(is_ignore(p), "{p:?}");
    }

    #[test]
    fn a_new_view_with_a_bloated_high_qc_is_not_forwarded() {
        let hs = replica();
        // Ten thousand copies of one well-formed vote: ~38 MB of certificate, over any set.
        let v = Vote::sign(&hs.cfg.domain, 3, Hash([5; 32]), &key(2));
        let qc = QuorumCertificate { view: 3, block_hash: Hash([5; 32]), votes: vec![v; 10_000] };
        let nv = NewView::sign(&hs.cfg.domain, VIEW, qc, &key(3));
        let p = hs.precheck_gossip(&ConsensusMessage::NewView(nv));
        assert!(p != GossipPrecheck::Accept, "{p:?}");
        // And a certificate whose votes disagree with it is malformed on every replica.
        let odd = Vote::sign(&hs.cfg.domain, 4, Hash([5; 32]), &key(2));
        let qc = QuorumCertificate { view: 3, block_hash: Hash([5; 32]), votes: vec![odd] };
        let nv = NewView::sign(&hs.cfg.domain, VIEW, qc, &key(3));
        let p = hs.precheck_gossip(&ConsensusMessage::NewView(nv));
        assert!(is_reject(p), "{p:?}");
    }

    #[test]
    fn a_new_view_with_a_bad_signature_from_a_validator_key_is_rejected() {
        let hs = replica();
        let mut nv = NewView::sign(&hs.cfg.domain, VIEW, QuorumCertificate::genesis(hs.cfg.genesis_hash), &key(3));
        nv.view += 1;
        let p = hs.precheck_gossip(&ConsensusMessage::NewView(nv));
        assert!(is_reject(p), "{p:?}");
    }

    #[test]
    fn a_proposal_by_a_non_leader_or_forged_is_not_accepted() {
        let hs = replica();
        let leader = leader_key(&hs, VIEW);
        // Self-signed by a key that leads nothing (a non-validator).
        let p = hs.precheck_gossip(&ConsensusMessage::Proposal(proposal(&hs, VIEW, &key(9))));
        assert!(is_ignore(p), "{p:?}");
        // The leader's key, a signature over another header.
        let mut block = proposal(&hs, VIEW, &leader);
        block.header.timestamp_ms = 1;
        let p = hs.precheck_gossip(&ConsensusMessage::Proposal(block));
        assert!(is_reject(p), "{p:?}");
    }

    #[test]
    fn a_proposal_over_the_block_byte_cap_is_rejected() {
        let hs = replica();
        let leader = leader_key(&hs, VIEW);
        let max = hs.committed_ledger.max_block_bytes();
        // Faucet mints padded by their envelope: enough of them to pass the genesis byte cap.
        let mut txs = Vec::new();
        let mut bytes = 0usize;
        while bytes <= max {
            let envelope = crate::notes::Envelope {
                kem_ct: vec![0; 1 << 20],
                to_receiver: Vec::new(),
                to_sender: Vec::new(),
                body: Vec::new(),
            };
            let tx = crate::types::Transaction::mint(1, [1; 8], 0, [txs.len() as u32; 8], envelope, 1, &leader, &StubExecutor);
            bytes += tx.encoded_len();
            txs.push(tx);
        }
        let mut header = proposal(&hs, VIEW, &leader).header;
        header.tx_root = Block::tx_root(&txs);
        let block = Block::sign(&hs.cfg.domain, header, txs, &leader);
        let p = hs.precheck_gossip(&ConsensusMessage::Proposal(block));
        assert!(is_reject(p), "{p:?}");
    }

    /// An orphan is legitimate (SW-1): the precheck never asks for the parent.
    #[test]
    fn a_proposal_with_an_unknown_parent_is_still_accepted() {
        let hs = replica();
        let leader = leader_key(&hs, VIEW);
        let mut header = proposal(&hs, VIEW, &leader).header;
        header.parent = Hash([4; 32]);
        header.height = 3;
        header.justify = QuorumCertificate { view: VIEW - 1, block_hash: Hash([4; 32]), votes: Vec::new() };
        let block = Block::sign(&hs.cfg.domain, header, Vec::new(), &leader);
        assert_eq!(hs.precheck_gossip(&ConsensusMessage::Proposal(block)), GossipPrecheck::Accept);
    }
}
