//! BIND-1 (audit v6, issue #79): the ledger under genesis `binding_domain: 1`.
//!
//! Two ledgers with **one chain id** and two genesis hashes: every proof and every signed action
//! message made for the one is refused by the other, where before the flag both accepted both.
//! Without the flag nothing moves — a chain-id-bound transaction is what a `ChainId` ledger
//! accepts, and the golden values in `types::binding` pin the bytes.
//!
//! The token, aggregator and bridge-governance messages are tested beside their own fixtures
//! (`tokens.rs`, `aggregation.rs`, `bridge_gov.rs`); here are the two transaction bindings, the
//! auth proof, the faucet mint and the three staking messages.

use super::staking::{StakingError, ValidatorEntry, MIN_STAKE};
use super::*;
use crate::confidential::StubExecutor;
use crate::crypto::Keypair;
use crate::notes::{Envelope, ShieldedAddress};
use crate::program::program_id;
use crate::types::actions::{registration_message, Registration};
use crate::types::BindingDomain;

const HC: Word8 = [11; 8];
const HCA: Word8 = [21; 8];
const C: Word8 = [0xc0; 8];
/// The one chain id both chains share.
const CHAIN: u64 = 7;

fn env() -> Envelope {
    Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
}

fn validator() -> Keypair {
    Keypair::from_seed([1; 32]).unwrap()
}

fn payout() -> ShieldedAddress {
    ShieldedAddress { pk: [1; 8], kem_ek: vec![2; crate::notes::KEM_EK_BYTES] }
}

/// A ledger on chain [`CHAIN`] whose register holds one validator with twice the minimum stake.
fn plain() -> Ledger {
    let v = validator();
    let entry = ValidatorEntry {
        public_key: v.public_key().clone(),
        stake: 2 * MIN_STAKE,
        pending: Vec::new(),
        rewards: 0,
        payout: payout(),
        nonce: 0,
        activation_epoch: 0,
    };
    let mut l = Ledger::new(CHAIN, HC, [(v.address(), entry)].into_iter().collect(), &StubExecutor);
    l.set_faucet(true);
    l.set_confidential(true);
    l.set_height(1);
    l
}

/// [`plain`] on a chain whose genesis hash is `[genesis; 32]` and sets `binding_domain: 1`. The
/// state is identical across every `genesis` — same root, same anchors, same register — so the
/// genesis hash is the only thing two of them disagree about.
fn on(genesis: u8) -> Ledger {
    let mut l = plain();
    l.set_binding_domain(BindingDomain::Genesis(Hash([genesis; 32])));
    l
}

/// An unbound bundle: the stub proof publishes the digest the ledger recomputes; binding it is the
/// caller's (`StubExecutor::bound` / `bound_in`), as a wallet's is.
fn bundle(l: &Ledger, n: u32, fee: u64, burn: u64) -> Bundle {
    let mut b = Bundle {
        anchor: l.root(),
        nullifiers: crate::notes::pad4([[n; 8], [n + 1; 8]]),
        commitments: crate::notes::pad4([[n + 2; 8], [n + 3; 8]]),
        fee,
        burn_a: 0,
        burn_r: burn,
        burn_asset: 0,
        time: l.height as u32,
        envelopes: [env(), env(), env(), env()],
        proof: vec![],
        auth_commit: [0; 8],
        auth_proof: Vec::new(),
    };
    b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
    b
}

fn bad_bundle(r: &Result<(), TxError>) -> bool {
    matches!(r, Err(TxError::InvalidBundleProof(_)))
}

/// The bundle proof. A transfer proved for genesis A validates on A and is refused on B — one
/// chain id, another genesis — and a chain-id-bound proof (what every wallet made before the
/// flag) is refused on both; without the flag the chain-id-bound proof is the valid one.
#[test]
fn under_binding_domain_a_transfer_proved_for_another_genesis_is_refused() {
    let (la, lb, l0) = (on(0xa), on(0xb), plain());
    assert_eq!((la.chain_id(), la.root()), (lb.chain_id(), lb.root()), "one chain id, one state");
    let unbound = Transaction::shielded(CHAIN, bundle(&la, 1, gas::BUNDLE_BASE, 0), Action::None);
    let for_a = StubExecutor::bound_in(unbound.clone(), la.binding_domain());
    let for_chain_id = StubExecutor::bound(unbound);
    assert_eq!(la.validate(&for_a, &StubExecutor), Ok(()));
    assert!(bad_bundle(&lb.validate(&for_a, &StubExecutor)), "A's proof on B: {:?}", lb.validate(&for_a, &StubExecutor));
    assert!(bad_bundle(&la.validate(&for_chain_id, &StubExecutor)), "a chain-id proof on A");
    // Apply refuses what validate refuses: a block carrying it is invalid, not merely unpooled.
    let v = validator().address();
    assert!(lb.clone().apply_tx(&for_a, &v, &StubExecutor).is_err());
    assert!(la.clone().apply_tx(&for_a, &v, &StubExecutor).is_ok());
    // Without the flag: today's rule, both ways.
    assert_eq!(l0.binding_domain(), &BindingDomain::ChainId);
    assert_eq!(l0.validate(&for_chain_id, &StubExecutor), Ok(()));
    assert!(bad_bundle(&l0.validate(&for_a, &StubExecutor)), "a genesis-bound proof on a chain-id chain");
}

/// The auth proof (split authorisation) is verified against the same binding: a bundle proof
/// re-bound for B still carries an auth proof made for A, and B refuses it.
#[test]
fn under_binding_domain_an_auth_proof_made_for_another_genesis_is_refused() {
    let v3 = |genesis: u8| {
        let mut l = on(genesis);
        l.set_hc_auth(Some(HCA));
        l
    };
    let (la, lb) = (v3(0xa), v3(0xb));
    let mut b = bundle(&la, 1, gas::BUNDLE_BASE, 0);
    b.auth_commit = C;
    b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest_v3(&b.digest_input()), &[0; 8]);
    b.auth_proof = StubExecutor::make_auth_proof(&HCA, &C, &[0; 8]);
    let for_a = StubExecutor::bound_in(Transaction::shielded(CHAIN, b, Action::None), la.binding_domain());
    assert_eq!(la.validate(&for_a, &StubExecutor), Ok(()));
    assert!(bad_bundle(&lb.validate(&for_a, &StubExecutor)));
    // The bundle proof re-bound for B, the auth proof left as the key holder made it for A.
    let auth_for_a = for_a.bundle.as_ref().unwrap().auth_proof.clone();
    let mut mixed = StubExecutor::bound_in(for_a.clone(), lb.binding_domain());
    mixed.bundle.as_mut().unwrap().auth_proof = auth_for_a;
    assert!(
        matches!(lb.validate(&mixed, &StubExecutor), Err(TxError::InvalidAuthProof(_))),
        "{:?}",
        lb.validate(&mixed, &StubExecutor)
    );
}

/// The call proof (INT-4, `hardening_v6`): its public segment is the transaction's call binding,
/// and that binding carries the genesis hash — a call proved for A is refused on B even under a
/// fee bundle honestly proved for B.
#[test]
fn under_binding_domain_a_call_proved_for_another_genesis_is_refused() {
    let v = validator().address();
    let words = vec![0x13u32; 4];
    let id = program_id(0, &words);
    let with_program = |genesis: u8| {
        let mut l = on(genesis);
        l.set_hardening_v6(true);
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let d = StubExecutor::bound_in(
            Transaction::shielded(CHAIN, bundle(&l, 1, gas::fee_floor(&deploy), 0), deploy),
            l.binding_domain(),
        );
        l.apply_tx(&d, &v, &StubExecutor).unwrap();
        l.record_anchor(l.height());
        l
    };
    let (la, lb) = (with_program(0xa), with_program(0xb));
    assert_eq!(la.root(), lb.root());
    let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
    // A wallet's order on `call_for`'s chain: both proofs empty, the call over the call binding,
    // then the bundle over the whole — the bundle bound for `bundle_for`'s chain.
    let call = |call_for: &Ledger, bundle_for: &Ledger| {
        let mut t = Transaction::shielded(CHAIN, bundle(&la, 10, fee, 0), Action::Call { program: id, proof: vec![], input_envelope: None });
        let proof = StubExecutor::make_proof_with_public(&id, 12, [5; 8], &t.call_binding(call_for.binding_domain()));
        let Action::Call { proof: p, .. } = &mut t.action else { unreachable!() };
        *p = proof;
        StubExecutor::bound_in(t, bundle_for.binding_domain())
    };
    assert_eq!(la.validate(&call(&la, &la), &StubExecutor), Ok(()));
    assert_eq!(lb.validate(&call(&lb, &lb), &StubExecutor), Ok(()));
    assert!(bad_bundle(&lb.validate(&call(&la, &la), &StubExecutor)), "A's whole transaction on B");
    let lifted = lb.validate(&call(&la, &lb), &StubExecutor);
    assert!(matches!(lifted, Err(TxError::InvalidProof(_))), "A's call proof under a bundle proved for B: {lifted:?}");
}

/// The faucet mint: the minter's signature for genesis A is no signature on B, and today's
/// chain-id signature is none on either.
#[test]
fn under_binding_domain_a_mint_signed_for_another_genesis_is_refused() {
    let (la, lb, l0) = (on(0xa), on(0xb), plain());
    let mint = |d: &BindingDomain| Transaction::mint_in(d, CHAIN, [5; 8], 0, [6; 8], env(), 1, &validator(), &StubExecutor);
    let (for_a, for_chain_id) = (mint(la.binding_domain()), mint(&BindingDomain::ChainId));
    assert_eq!(for_chain_id, Transaction::mint(CHAIN, [5; 8], 0, [6; 8], env(), 1, &validator(), &StubExecutor));
    assert_eq!(la.validate(&for_a, &StubExecutor), Ok(()));
    assert_eq!(lb.validate(&for_a, &StubExecutor), Err(TxError::BadMintSignature));
    assert_eq!(la.validate(&for_chain_id, &StubExecutor), Err(TxError::BadMintSignature));
    assert_eq!(l0.validate(&for_chain_id, &StubExecutor), Ok(()));
    assert_eq!(l0.validate(&for_a, &StubExecutor), Err(TxError::BadMintSignature));
}

const BAD_SIGNATURE: Result<(), TxError> = Err(TxError::Staking(StakingError::BadSignature));

/// `Unbond` and `Withdraw`: a validator's signature for genesis A moves nothing on B. The verdict
/// for the right genesis is whatever the chain-id world gives the same action — the signature is
/// the only rule the domain touches.
#[test]
fn under_binding_domain_an_unbond_or_withdraw_signed_for_another_genesis_is_refused() {
    let (la, lb, l0) = (on(0xa), on(0xb), plain());
    let v = validator();
    let unbond = |d: &BindingDomain| {
        let signature = v.sign(d.unbond_message(CHAIN, &v.address(), MIN_STAKE, 0).as_bytes());
        Transaction { chain_id: CHAIN, bundle: None, action: Action::Unbond { validator: v.address(), amount: MIN_STAKE, nonce: 0, signature } }
    };
    let withdraw = |d: &BindingDomain| {
        let amount = 2 * gas::BUNDLE_BASE;
        let signature = v.sign(d.withdraw_message(CHAIN, &v.address(), amount, 0, 1, &[3; 8], &env()).as_bytes());
        let action = Action::Withdraw { validator: v.address(), amount, nonce: 0, time: 1, r: [3; 8], envelope: env(), signature };
        Transaction { chain_id: CHAIN, bundle: None, action }
    };
    assert_eq!(l0.validate(&unbond(&BindingDomain::ChainId), &StubExecutor), Ok(()));
    assert_eq!(la.validate(&unbond(la.binding_domain()), &StubExecutor), Ok(()));
    assert_eq!(lb.validate(&unbond(la.binding_domain()), &StubExecutor), BAD_SIGNATURE);
    assert_eq!(la.validate(&unbond(&BindingDomain::ChainId), &StubExecutor), BAD_SIGNATURE);
    assert_eq!(l0.validate(&unbond(la.binding_domain()), &StubExecutor), BAD_SIGNATURE);
    // Nothing is released, so the honest withdraw stops one rule after the signature — on both.
    let released = l0.validate(&withdraw(&BindingDomain::ChainId), &StubExecutor);
    assert!(matches!(released, Err(TxError::Staking(StakingError::NothingReleased { .. }))), "{released:?}");
    assert_eq!(la.validate(&withdraw(la.binding_domain()), &StubExecutor), released);
    assert_eq!(lb.validate(&withdraw(la.binding_domain()), &StubExecutor), BAD_SIGNATURE);
    assert_eq!(la.validate(&withdraw(&BindingDomain::ChainId), &StubExecutor), BAD_SIGNATURE);
}

/// A `Bond`'s registration: under the flag the chain-id-only v1 message is gone whether or not the
/// genesis also sets `staking.registration_v2` — a v1 registration bonds nothing, the genesis-bound
/// one does, and one signed for genesis A does not register on B.
#[test]
fn under_binding_domain_a_registration_binds_the_genesis() {
    let (la, lb, l0) = (on(0xa), on(0xb), plain());
    let newcomer = Keypair::from_seed([7; 32]).unwrap();
    let bond = |l: &Ledger, message: Hash| {
        let registration =
            Registration { public_key: newcomer.public_key().clone(), payout: payout(), signature: newcomer.sign(message.as_bytes()) };
        let action = Action::Bond { validator: newcomer.address(), amount: MIN_STAKE, registration: Some(registration) };
        StubExecutor::bound_in(Transaction::shielded(CHAIN, bundle(l, 30, gas::BUNDLE_BASE, MIN_STAKE), action), l.binding_domain())
    };
    let v1 = registration_message(CHAIN, &payout());
    let for_a = la.binding_domain().registration_message(CHAIN, &newcomer.address(), &payout());
    let for_b = lb.binding_domain().registration_message(CHAIN, &newcomer.address(), &payout());
    assert_eq!(l0.validate(&bond(&l0, v1), &StubExecutor), Ok(()), "today: the v1 message");
    assert_eq!(la.validate(&bond(&la, for_a), &StubExecutor), Ok(()));
    assert_eq!(la.validate(&bond(&la, v1), &StubExecutor), BAD_SIGNATURE, "no chain-id-only registration under the flag");
    assert_eq!(lb.validate(&bond(&lb, for_a), &StubExecutor), BAD_SIGNATURE, "A's registration under a bundle proved for B");
    assert_eq!(lb.validate(&bond(&lb, for_b), &StubExecutor), Ok(()));
}
