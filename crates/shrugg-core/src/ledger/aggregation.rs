//! The aggregator register and the `Aggregate` action's home in the ledger (block aggregation,
//! spec §2–§4).
//!
//! Modelled on S2's validator register ([`super::staking`]): one public row per registered
//! aggregator, hashed into the state root as a component present exactly when
//! `genesis.aggregation` is `Some`. A chain without the section behaves byte-for-byte as
//! before — the register is empty, the component is absent, and the five actions are refused
//! with a named error rather than applied.

use crate::crypto::{merkle_root, Address, Hash, PublicKey};
use crate::notes::{word8_to_bytes, ShieldedAddress};
use crate::types::DeclaredShape;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The aggregation section of a genesis file (spec §2.3): present exactly on chains that
/// aggregate. Every field is part of the genesis hash, like the bridge section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationConfig {
    /// The bond an aggregator burns at registration (`RegisterAggregator`'s bundle burns
    /// exactly this).
    pub bond: u64,
    /// The most bundles one aggregate may cover.
    pub max_covers: u32,
    /// The subsidy at `n = 0` (`subsidy_base >> (n / halving_blocks)` thereafter, spec §5.1).
    pub subsidy_base: u64,
    /// The halving interval, in sealed blocks.
    pub halving_blocks: u64,
    /// How many finalised blocks an aggregate may lag (spec §3.3), and the pruning gate.
    pub window: u64,
    /// The registered inner shapes: at activation exactly one (the constraint-set-6 bundle
    /// guest at its production shape).
    pub admitted_shapes: Vec<AdmittedShape>,
}

/// One registered inner shape and its aggregate program digest (spec §2.3). The inner
/// verifier key's preprocessed cap is derived at startup, never stored here.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AdmittedShape {
    pub shape: DeclaredShape,
    /// The bundle guest's digest — what `pv::HC0..7` of every covered bundle must equal, so an
    /// aggregate cannot cover a proof of some other guest.
    pub hc: Hash,
    /// `aggregate_program_digest(shape, key)` for the shape, measured at activation.
    pub aggregate_program_digest: [u64; 4],
}

/// One row of the aggregator register (spec §2.1): the Dilithium2 key, the burned bond, the
/// shielded payout, the action nonce, and the unbonding release height when set. The validator
/// entry's twin, one role over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorEntry {
    pub public_key: PublicKey,
    pub bond: u64,
    pub payout: ShieldedAddress,
    pub nonce: u64,
    pub unbonding: Option<u64>,
}

/// The register's leaf (spec §2.1): `blake3("shrugg-aggregator-leaf-1", addr ‖ bond ‖ nonce ‖
/// presence+release ‖ payout pk ‖ payout kem_ek)`. The unbonding option is a presence byte plus
/// the height, so `None` and `Some(0)` can never collide.
pub fn aggregator_leaf(addr: &Address, entry: &AggregatorEntry) -> Hash {
    let mut buf = Vec::with_capacity(32 + 8 + 8 + 1 + 8 + 8 + entry.payout.kem_ek.len());
    buf.extend_from_slice(addr.as_bytes());
    buf.extend_from_slice(&entry.bond.to_be_bytes());
    buf.extend_from_slice(&entry.nonce.to_be_bytes());
    buf.push(entry.unbonding.is_some() as u8);
    buf.extend_from_slice(&entry.unbonding.unwrap_or(0).to_be_bytes());
    buf.extend_from_slice(&word8_to_bytes(&entry.payout.pk));
    buf.extend_from_slice(&entry.payout.kem_ek);
    Hash::digest_domain(b"shrugg-aggregator-leaf-1", &buf)
}

/// The register's component of the state root: the merkle root of every entry's leaf, empty at
/// chain-9 block 0. Joined into the root (under the `shrugg-state-3` domain) exactly when
/// `genesis.aggregation` is `Some`; a chain without the section keeps the state-2 root
/// byte-for-byte.
pub fn aggregators_root(register: &BTreeMap<Address, AggregatorEntry>) -> Hash {
    let leaves: Vec<Hash> = register.iter().map(|(addr, e)| aggregator_leaf(addr, e)).collect();
    merkle_root(&leaves)
}

/// What an aggregation action gets before the register's actions land (Task 2) — and always on
/// a chain without the section. Named, so a wallet hears which phase turns the actions on
/// rather than "invalid transaction" (`staking`'s `NOT_STAKING` pattern, mirrored).
pub(super) const NOT_AGGREGATION: crate::ledger::TxError = crate::ledger::TxError::UnsupportedAction("aggregation");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::{Keypair, Hash};
    use crate::gas;
    use crate::ledger::staking::ValidatorEntry;
    use crate::ledger::Ledger;
    use crate::types::{Action, AggregatorRegistration, SignedAggregateHeader, UNITS_PER_SHRUGG};
    use std::collections::BTreeMap;

    fn keys() -> (Keypair, Keypair) {
        (Keypair::from_seed([1; 32]).unwrap(), Keypair::from_seed([2; 32]).unwrap())
    }

    fn entry(k: &Keypair, stake: u64) -> (Address, ValidatorEntry) {
        (
            k.public_key().address(),
            ValidatorEntry {
                public_key: k.public_key().clone(),
                stake,
                pending: Vec::new(),
                rewards: 0,
                payout: crate::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
                nonce: 0,
            },
        )
    }

    fn ledger() -> Ledger {
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, [11; 8], register, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(1);
        l
    }

    fn cfg() -> AggregationConfig {
        AggregationConfig {
            bond: 100 * UNITS_PER_SHRUGG,
            max_covers: 3,
            subsidy_base: 100 * UNITS_PER_SHRUGG,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![],
        }
    }

    /// The manual state-root computation, written out per the documented construction: the
    /// state-2 root of `tree ‖ nullifiers ‖ validators ‖ programs [‖ bridge]`, the state-3 root
    /// with the aggregator component appended, each hashed with its own domain. Any drift in the
    /// implementation's construction fails against this, not against a hash pasted from it.
    fn manual_state_root(l: &Ledger, domain: &'static [u8], with_aggregators: bool) -> Hash {
        use crate::crypto::merkle_root;
        use crate::notes::word8_to_bytes;
        let nf_leaves: Vec<Hash> = l
            .nullifiers()
            .iter()
            .map(|nf| Hash::digest_domain(b"shrugg-nullifier-leaf", &word8_to_bytes(nf)))
            .collect();
        let val_leaves: Vec<Hash> = l
            .validators()
            .iter()
            .map(|(addr, v)| {
                let mut buf = Vec::new();
                buf.extend_from_slice(addr.as_bytes());
                buf.extend_from_slice(&v.stake.to_be_bytes());
                buf.extend_from_slice(&v.rewards.to_be_bytes());
                buf.extend_from_slice(&v.nonce.to_be_bytes());
                buf.extend_from_slice(&(v.pending.len() as u64).to_be_bytes());
                for (release_epoch, amount) in &v.pending {
                    buf.extend_from_slice(&release_epoch.to_be_bytes());
                    buf.extend_from_slice(&amount.to_be_bytes());
                }
                buf.extend_from_slice(&word8_to_bytes(&v.payout.pk));
                buf.extend_from_slice(&v.payout.kem_ek);
                Hash::digest_domain(b"shrugg-validator-leaf-2", &buf)
            })
            .collect();
        let prog_leaves: Vec<Hash> = l
            .programs()
            .keys()
            .map(|id| Hash::digest_domain(b"shrugg-program-leaf", id.as_bytes()))
            .collect();
        let mut buf = Vec::new();
        buf.extend_from_slice(&word8_to_bytes(&l.root()));
        buf.extend_from_slice(merkle_root(&nf_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&val_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&prog_leaves).as_bytes());
        if let Some(bridge) = l.bridge() {
            buf.extend_from_slice(bridge.root().as_bytes());
        }
        if with_aggregators {
            buf.extend_from_slice(aggregators_root(l.aggregators()).as_bytes());
        }
        Hash::digest_domain(domain, &buf)
    }

    /// The absolute gate: an aggregation-less chain's root is today's, computed exactly the way
    /// it is computed now — and a gated chain's is a different domain's, with the component in.
    #[test]
    fn a_chain_without_the_section_keeps_todays_state_root_byte_for_byte() {
        let l = ledger();
        assert_eq!(l.state_root(), manual_state_root(&l, b"shrugg-state-2", false));
        // The same ledger, gated, gets a different root — and the component is the empty
        // register's (so an empty register at chain-9 block 0 is well-defined).
        let mut gated = l.clone();
        gated.set_aggregation(Some(cfg()));
        assert_eq!(gated.state_root(), manual_state_root(&gated, b"shrugg-state-3", true));
        assert_ne!(gated.state_root(), l.state_root());
        // And taking the section back off is the identity, not a third value.
        let mut ungated = gated.clone();
        ungated.set_aggregation(None);
        assert_eq!(ungated.state_root(), l.state_root());
    }

    /// The register's leaf: every field of the entry is in the hash, in the documented order —
    /// addr ‖ bond ‖ nonce ‖ presence+release ‖ payout pk ‖ payout kem_ek.
    #[test]
    fn the_aggregator_leaf_hashes_every_field() {
        let payout = crate::notes::ShieldedAddress { pk: [7; 8], kem_ek: vec![8; 32] };
        let entry = AggregatorEntry {
            public_key: Keypair::from_seed([1; 32]).unwrap().public_key().clone(),
            bond: 42,
            payout: payout.clone(),
            nonce: 3,
            unbonding: Some(999),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(entry.public_key.address().as_bytes());
        buf.extend_from_slice(&42u64.to_be_bytes());
        buf.extend_from_slice(&3u64.to_be_bytes());
        buf.push(1u8);
        buf.extend_from_slice(&999u64.to_be_bytes());
        buf.extend_from_slice(&crate::notes::word8_to_bytes(&payout.pk));
        buf.extend_from_slice(&payout.kem_ek);
        assert_eq!(aggregator_leaf(&entry.public_key.address(), &entry), Hash::digest_domain(b"shrugg-aggregator-leaf-1", &buf));
        // A second entry with `unbonding: None` must not collide with `Some(0)`.
        let none_entry = AggregatorEntry { unbonding: None, ..entry.clone() };
        let zero_entry = AggregatorEntry { unbonding: Some(0), ..entry.clone() };
        assert_ne!(
            aggregator_leaf(&entry.public_key.address(), &none_entry),
            aggregator_leaf(&entry.public_key.address(), &zero_entry)
        );
    }

    /// The five actions on the wire: bincode round-trips, and `bundle_less` names the four
    /// bundle-less ones — `RegisterAggregator` is the one that rides a bundle (it burns the bond).
    #[test]
    fn the_five_actions_roundtrip_and_their_bundle_shape() {
        let kp = Keypair::from_seed([2; 32]).unwrap();
        let sig = kp.sign(b"test");
        let payout = crate::notes::ShieldedAddress { pk: [5; 8], kem_ek: vec![6; 32] };
        let registration = AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout,
            signature: sig.clone(),
        };
        let actions = vec![
            Action::RegisterAggregator { registration },
            Action::UnbondAggregator { aggregator: kp.public_key().address(), nonce: 1, signature: sig.clone() },
            Action::WithdrawAggregator {
                aggregator: kp.public_key().address(),
                nonce: 2,
                time: 9,
                r: [3; 8],
                envelope: env(),
                signature: sig.clone(),
            },
            Action::SlashAggregator {
                a: Box::new(signed_header(&kp, 1, &sig)),
                b: Box::new(signed_header(&kp, 1, &sig)),
            },
            Action::Aggregate {
                covers: vec![Hash::digest(b"one"), Hash::digest(b"two")],
                proof: vec![9; 64],
                aggregator: kp.public_key().address(),
                nonce: 3,
                time: 9,
                r: [4; 8],
                envelope: env(),
                signature: sig,
            },
        ];
        for a in &actions {
            let back: Action = bincode::deserialize(&bincode::serialize(a).unwrap()).unwrap();
            assert_eq!(*a, back);
        }
        assert_eq!(actions[0].bundle_less(), None, "RegisterAggregator burns the bond through its bundle");
        assert_eq!(actions[1].bundle_less(), Some("unbond_aggregator"));
        assert_eq!(actions[2].bundle_less(), Some("withdraw_aggregator"));
        assert_eq!(actions[3].bundle_less(), Some("slash_aggregator"));
        assert_eq!(actions[4].bundle_less(), Some("aggregate"));
    }

    fn signed_header(kp: &Keypair, nonce: u64, sig: &crate::crypto::Signature) -> SignedAggregateHeader {
        SignedAggregateHeader {
            aggregator: kp.public_key().address(),
            nonce,
            time: 9,
            r: [1; 8],
            covers: vec![Hash::digest(b"x")],
            proof_hash: Hash::digest(b"p"),
            signature: sig.clone(),
        }
    }

    fn env() -> crate::notes::Envelope {
        crate::notes::Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] }
    }

    /// The wire cap: the proof cap plus the covers and the interface-list bound and the fixed
    /// overhead — pinned as a derivation, not a magic number (spec §3.1).
    #[test]
    fn max_aggregate_bytes_is_the_proof_cap_plus_the_cover_and_list_bounds() {
        assert_eq!(
            gas::MAX_AGGREGATE_BYTES,
            gas::MAX_PROOF_BYTES + 3 * 32 + (4 + 1 + 34 * 3) * 8 + 4_400
        );
        // And it admits a 2 MiB proof with the three covers and the envelope.
        assert!(gas::MAX_AGGREGATE_BYTES > gas::MAX_PROOF_BYTES + 3 * 32 + 2_000);
    }

    /// The genesis section gates the ledger (spec §9): a genesis without it builds a ledger
    /// whose `aggregation` is `None`; with it, the section is installed, the register starts
    /// empty, and the state root is the gated one. And the activation placeholder — an admitted
    /// shape with an all-zero program digest — is refused at validation, so it can never reach
    /// a fleet.
    fn genesis() -> crate::genesis::Genesis {
        let k = Keypair::from_seed([9; 32]).unwrap();
        crate::genesis::Genesis {
            chain_id: 42,
            timestamp_ms: 1_700_000_000_000,
            validators: vec![crate::genesis::GenesisValidator {
                public_key: k.public_key().clone(),
                stake: crate::ledger::staking::MIN_STAKE as u128,
                payout: crate::notes::ShieldedAddress { pk: [4; 8], kem_ek: vec![5; crate::notes::KEM_EK_BYTES] }.to_string(),
            }],
            alloc: vec![],
            faucet: false,
            confidential: true,
            fri_profile: "production".into(),
            hc_bundle: crate::notes::word8_to_hex(&[3; 8]),
            bridge: None,
            aggregation: None,
            epoch_blocks: crate::genesis::EPOCH_BLOCKS_DEFAULT,
        }
    }

    #[test]
    fn the_genesis_section_gates_the_ledger_and_the_placeholder_is_refused() {
        let mut g = genesis();
        assert!(g.aggregation.is_none());
        let built = g.build(&StubExecutor).unwrap();
        assert!(built.ledger.aggregation().is_none());

        g.aggregation = Some(cfg());
        let built = g.build(&StubExecutor).unwrap();
        assert!(built.ledger.aggregation().is_some());
        assert!(built.ledger.aggregators().is_empty());
        assert_eq!(
            built.ledger.state_root(),
            manual_state_root(&built.ledger, b"shrugg-state-3", true)
        );

        let mut bad = genesis();
        let mut c = cfg();
        c.admitted_shapes = vec![AdmittedShape {
            shape: crate::types::DeclaredShape {
                profile: crate::types::FriProfile::Production,
                tier: 14,
                program_log_height: 13,
                input_log_height: 12,
                keccak_log_height: 0,
                sha256_log_height: 0,
                public_log_height: 2,
                mem_log_height: 18,
            },
            hc: crate::crypto::Hash::digest(b"bundle guest"),
            aggregate_program_digest: [0; 4],
        }];
        bad.aggregation = Some(c);
        assert!(matches!(
            bad.build(&StubExecutor),
            Err(crate::genesis::GenesisError::BadAggregationConfig(_))
        ));
    }

    /// The subsidy schedule: 100 SHRUGG per sealed block, halving every 210 000, zero from the
    /// 64th halving (spec §5.1).
    #[test]
    fn the_subsidy_halves_on_schedule_and_ends_at_the_64th() {
        let c = cfg();
        assert_eq!(gas::subsidy(0, &c), 100 * UNITS_PER_SHRUGG);
        assert_eq!(gas::subsidy(209_999, &c), 100 * UNITS_PER_SHRUGG);
        assert_eq!(gas::subsidy(210_000, &c), 50 * UNITS_PER_SHRUGG);
        assert_eq!(gas::subsidy(210_000 * 63, &c), c.subsidy_base >> 63);
        assert_eq!(gas::subsidy(210_000 * 64, &c), 0);
        assert_eq!(gas::subsidy(u64::MAX, &c), 0);
        // Monotone non-increasing across the whole schedule.
        let mut prev = u64::MAX;
        for k in 0..70u64 {
            let s = gas::subsidy(k * 210_000, &c);
            assert!(s <= prev, "subsidy increased at halving {k}");
            prev = s;
        }
    }
}
