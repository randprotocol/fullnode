//! Private multisig accounts (spec `docs/superpowers/specs/2026-10-11-private-multisig-phase4-
//! design.md` §6): the policy file, proposals, signing, witness assembly and proving — the parts
//! that need a node, a file or a prover. The signer checks themselves are the pure crate
//! `randprotocol-msig` ([`crate::multisig_private`]), which every wallet app runs; [`sign`] here is
//! a thin wrapper over it.
//!
//! An account is a policy: `T` of `n` Dilithium2 signer keys and a secret `msk`. Its `nk` is
//! `msauth::nk(msk, policy)`, so it has a viewing key and an address like any wallet and no spend
//! key: a spend is a proposal ([`prepare`]) that `T` signers [`sign`], then a `msauth` proof over
//! their signatures ([`prove`]) beside the v3 bundle proof.
//!
//! **Secrets.** The policy file holds `msk` (viewing power over every note of the account) and a
//! proposal holds the witness words (`nk`, the salt, the spent notes' openings). Neither is ever
//! printed; both are written owner-only, never over an existing file, and refused on load when
//! group or other can read them.

use crate::wallet::{self, AuthWitness, DummySender, NoteStore, Plan, Prepared, Proving, Spend, Wallet};
use crate::RpcClient;
use anyhow::{anyhow, Context, Result};
use randprotocol_core::ledger::multisig::Account;
use randprotocol_core::notes::{word8_from_hex, word8_to_hex, ShieldedAddress, Word8};
use randprotocol_core::{Action, BindingDomain, Hash, Keypair, PublicKey, Signature, Transaction};
use randprotocol_msig::{self as pure, parse_words};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::FriProfile;
use randprotocol_zkvm::msauth::{self, Slot, M_MAX};
use randprotocol_zkvm::notes::ViewingKey;
use std::path::Path;

pub use randprotocol_msig::{parse_binding, parse_word8, Proposal};

/// A private multisig policy, typed (§6.1): `threshold` of `signers`, and the account's secret
/// `msk`. Its file is [`randprotocol_msig::Policy`]'s JSON.
#[derive(Clone)]
pub struct Policy {
    pub threshold: u32,
    /// Leaf order: part of the address.
    pub signers: Vec<PublicKey>,
    pub msk: Word8,
}

impl Policy {
    /// A policy over `signers` with a fresh `msk` (256 bits of OS entropy): a new account, even
    /// over the same keys and threshold. Refused where the guest could never spend it ([`Policy::check`]).
    pub fn new(signers: Vec<PublicKey>, threshold: u32) -> Result<Policy> {
        let p = Policy { threshold, signers, msk: wallet::fresh_word() };
        p.check()?;
        Ok(p)
    }

    /// The file form, which the pure checks take.
    pub fn pure(&self) -> pure::Policy {
        pure::Policy {
            version: pure::POLICY_VERSION,
            threshold: self.threshold,
            signers: self.signers.iter().map(PublicKey::to_hex).collect(),
            msk: word8_to_hex(&self.msk),
        }
    }

    fn from_pure(p: &pure::Policy) -> Result<Policy> {
        p.check()?;
        let signers = p.pks()?.iter().map(|k| PublicKey::from_bytes(k)).collect::<Result<Vec<_>, _>>()?;
        Ok(Policy { threshold: p.threshold, signers, msk: parse_word8(&p.msk)? })
    }

    /// §6.1: `1 ≤ n ≤ N_MAX`, `1 ≤ T ≤ min(n, M_MAX)`, every key 1 312 bytes and none repeated.
    pub fn check(&self) -> Result<()> {
        Ok(self.pure().check()?)
    }

    /// The signers' keys, leaf order. Panics on a policy that fails [`Policy::check`].
    pub fn pks(&self) -> Vec<[u8; 1312]> {
        self.pure().pks().expect("a checked policy's keys are 1 312 bytes")
    }

    pub fn signer_root(&self) -> Word8 {
        self.pure().signer_root()
    }

    /// `msauth::policy(T, signer_root)`, what a proposal names.
    pub fn policy_hash(&self) -> Word8 {
        self.pure().policy_hash()
    }

    /// `msauth::nk(msk, policy)`: the account's nullifier key.
    pub fn nk(&self) -> Word8 {
        self.pure().nk()
    }

    /// The account as a wallet that sees and never spends ([`Wallet::from_viewing_key`]): what
    /// scanning, balances and bundle building take.
    pub fn wallet(&self) -> Wallet {
        Wallet::from_viewing_key(ViewingKey { nk: self.nk() })
    }

    /// The address's fingerprint, which every signer compares out of band.
    pub fn fingerprint(&self) -> String {
        self.pure().fingerprint()
    }

    /// The indices of this policy's signers that also sign one of `accounts` (public multisig
    /// accounts, `rand_getMultisig`): anyone who knows both policies can link the two (parent spec
    /// §8 Q2), so the CLI warns.
    pub fn reused_in(&self, accounts: &[Account]) -> Vec<usize> {
        (0..self.signers.len()).filter(|&i| accounts.iter().any(|a| a.signers.contains(&self.signers[i]))).collect()
    }

    /// Writes the policy file: owner-only (0600) from the start, never over an existing file.
    pub fn save(&self, path: &Path) -> Result<()> {
        wallet::write_new_secret(path, &(serde_json::to_string_pretty(&self.pure())? + "\n"))
    }

    /// Reads a policy file, refusing one group or other can read (the key-file rule) and one the
    /// guest could never spend.
    pub fn load(path: &Path) -> Result<Policy> {
        wallet::refuse_loose_mode(path, "policy file", "a private multisig account's msk (its viewing power)")?;
        let text = std::fs::read_to_string(path).with_context(|| format!("reading policy file {}", path.display()))?;
        let p: pure::Policy = serde_json::from_str(&text).with_context(|| format!("{} is not a private multisig policy", path.display()))?;
        Policy::from_pure(&p).with_context(|| format!("policy file {}", path.display()))
    }
}

/// One signer's share: its index in the policy and its Dilithium2 signature over the proposal's
/// signing message. Written and read as `index:hex`.
#[derive(Clone, Debug)]
pub struct Share {
    pub index: u8,
    pub signature: Signature,
}

impl std::fmt::Display for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.index, hex::encode(self.signature.as_bytes()))
    }
}

impl std::str::FromStr for Share {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Share> {
        let (index, sig) = pure::parse_share(s)?;
        Ok(Share { index, signature: Signature::from_bytes(&sig)? })
    }
}

/// Building a [`Proposal`] from a bundle this wallet prepared.
pub(crate) trait ProposalExt {
    #[allow(clippy::too_many_arguments)]
    fn from_prepared(
        policy: &Policy,
        prepared: &Prepared,
        tx: &Transaction,
        binding: [u32; 8],
        chain_id: u64,
        genesis: &Hash,
        binding_domain: u32,
        expires_at: u64,
    ) -> Proposal;
}

impl ProposalExt for Proposal {
    /// Every field (§6.4): the derived ones by [`Proposal::new`], `summary` from the plan's payee,
    /// amount, fee and memo.
    fn from_prepared(
        policy: &Policy,
        prepared: &Prepared,
        tx: &Transaction,
        binding: [u32; 8],
        chain_id: u64,
        genesis: &Hash,
        binding_domain: u32,
        expires_at: u64,
    ) -> Proposal {
        let summary = pure::informational_summary(prepared.to.as_ref().map(|(a, n)| (a, *n)), prepared.asset, prepared.bundle.fee, &prepared.memo);
        let p = Proposal::new(&policy.pure(), tx, genesis, binding_domain, &prepared.words, &prepared.expected, &prepared.salt, expires_at, summary);
        debug_assert_eq!((p.chain_id, parse_binding(&p.binding).ok()), (chain_id, Some(binding)), "the binding the caller took");
        p
    }
}

/// The chain must run bundle guest v3 and this build's multisig auth guest, or no proposal made
/// here could ever be proved and admitted.
async fn require_multisig_chain(rpc: &RpcClient) -> Result<()> {
    multisig_chain_refusal(&rpc.status().await?).map_or(Ok(()), |e| Err(anyhow!(e)))?;
    wallet::check_bundle_gas_limit(rpc.limits().await?.and_then(|l| l.bundle_gas_limit))
}

/// Why `rand_status` rules this chain out for a private multisig spend, naming the condition:
/// no multisig auth guest at all, another build's guest, or a bundle guest other than v3.
fn multisig_chain_refusal(status: &serde_json::Value) -> Option<String> {
    let named = |field: &str| status[field].as_str().and_then(word8_from_hex);
    let (ours, bundle) = (ZkExecutor::hc_auth_multisig(), ZkExecutor::hc_hidden_bundle_v3());
    match status["hc_auth_multisig"].as_str() {
        None => return Some("this chain has no private multisig: rand_status names no hc_auth_multisig (null)".into()),
        Some(theirs) if named("hc_auth_multisig") != Some(ours) => {
            return Some(format!(
                "this chain's hc_auth_multisig is {theirs}, another build's guest; this build's is {}: upgrade (or downgrade) the wallet to the chain's release",
                word8_to_hex(&ours)
            ))
        }
        Some(_) => {}
    }
    if named("hc_bundle") != Some(bundle) {
        return Some(format!(
            "this chain's bundle guest (hc_bundle {}) is not this build's v3 ({}): a private multisig spend needs bundle guest v3",
            status["hc_bundle"].as_str().unwrap_or("null"),
            word8_to_hex(&bundle)
        ));
    }
    None
}

/// A proposal paying `amount` RAND to `to` from the account (§6.3 `prepare`): the chain checked,
/// the account scanned, its notes selected, the v3 bundle built with a fresh salt and every
/// output — dummies included — sealed with the account as sender, placed in
/// `Transaction::shielded(chain_id, bundle, Action::None)`, its binding taken. `expires_at` is the
/// bundle's time plus the chain's `proof_window_blocks` (the anchor window where unset).
///
/// The selected notes are **not** marked pending: nothing is spent until a transaction commits,
/// and an abandoned or refused proposal must not hide notes from the next one. A note in two live
/// proposals is harmless — the second to commit is refused as a double spend.
#[allow(clippy::too_many_arguments)]
pub async fn prepare(
    rpc: &RpcClient,
    policy: &Policy,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    amount: u64,
    memo: &str,
    fee: u64,
    chain_id: u64,
) -> Result<Proposal> {
    prepare_with(rpc, policy, store, to, Some(amount), memo, fee, chain_id).await
}

/// A proposal moving every spendable **RAND** note of the account to `to`, less the fee: how a
/// policy is rotated. Moves RAND only; token notes stay (send them with `--to … --asset`), and the
/// old address remains spendable by the old policy for any payment that arrives later. Refused
/// when the account holds more than two RAND notes — a bundle spends at most two: send to
/// yourself first to merge.
pub async fn prepare_sweep(rpc: &RpcClient, policy: &Policy, store: &mut NoteStore, to: &ShieldedAddress, fee: u64, chain_id: u64) -> Result<Proposal> {
    prepare_with(rpc, policy, store, to, None, "", fee, chain_id).await
}

/// [`prepare`], with `amount: None` for [`prepare_sweep`]'s whole RAND balance less the fee.
#[allow(clippy::too_many_arguments)]
async fn prepare_with(
    rpc: &RpcClient,
    policy: &Policy,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    amount: Option<u64>,
    memo: &str,
    fee: u64,
    chain_id: u64,
) -> Result<Proposal> {
    require_multisig_chain(rpc).await?;
    let w = policy.wallet();
    wallet::scan(rpc, &w, store).await?;
    let amount = match amount {
        Some(a) => a,
        None => {
            let notes = store.spendable_of(0).len();
            if notes > 2 {
                return Err(anyhow!("the account holds {notes} spendable RAND notes and a bundle spends at most two: send to yourself first to merge"));
            }
            let balance = store.balance_of(0);
            balance.checked_sub(fee).filter(|a| *a > 0).ok_or_else(|| {
                anyhow!("nothing to sweep: the account holds {} RAND and the fee is {}", randprotocol_core::format_amount(balance), randprotocol_core::format_amount(fee))
            })?
        }
    };
    let plan = Plan::select(store, Spend { asset: 0, to: Some((to, amount)), memo, fee, burn_a: 0, burn_r: 0, prover_fee: None })?;
    let format = rpc.envelope_format(chain_id).await?;
    let (prepared, time) = wallet::prepare_bundle(rpc, &w, store, &plan, format, &ZkExecutor::hc_hidden_bundle_v3(), DummySender::Account).await?;
    let tx = Transaction::shielded(chain_id, prepared.bundle.clone(), Action::None);
    let domain = wallet::scanned_binding_domain(rpc, store, chain_id).await?;
    let binding = tx.binding(&domain);
    let genesis = match domain {
        BindingDomain::Genesis(h) => h,
        BindingDomain::ChainId => store.genesis.unwrap_or(Hash::ZERO),
    };
    let window = rpc.limits().await?.and_then(|l| l.proof_window_blocks).unwrap_or(randprotocol_core::ledger::TIME_WINDOW);
    Ok(Proposal::from_prepared(policy, &prepared, &tx, binding, chain_id, &genesis, domain.version(), time as u64 + window))
}

fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("a proposal and a policy serialise")
}

/// `key`'s share of `proposal`: [`randprotocol_msig::sign_expecting_addresses`] over the two
/// files with the key's seed — every §6.5 check first (the binding recomputed, all four outputs
/// opened as the account, value conserved against the witness), and, when `expect_to` names the
/// payees, every value-moving non-change output paying one of them — and the summary lines it
/// checked, for the signer to read (with no `expect_to`, they say the payee was not checked).
/// Refused for a key outside the policy.
pub fn sign(proposal: &Proposal, policy: &Policy, key: &Keypair, expect_to: &[ShieldedAddress]) -> Result<(Share, Vec<String>)> {
    // The policy's JSON carries `msk`: wiped when dropped.
    let (proposal, policy) = (json(proposal), zeroize::Zeroizing::new(json(&policy.pure())));
    let shown = pure::check_proposal_expecting_addresses(&proposal, &policy, expect_to)?.lines();
    let (index, sig) = pure::sign_expecting_addresses(&proposal, &policy, key.seed(), expect_to)?;
    Ok((Share { index, signature: Signature::from_bytes(&sig)? }, shown))
}

/// One share's slot: its index in range, its signature verified natively over `msg`, its key and
/// signer-tree path.
fn slot(policy: &Policy, pks: &[[u8; 1312]], paths: &[[Word8; msauth::DEPTH]], share: &Share, msg: &[u8]) -> Result<Slot> {
    let i = share.index as usize;
    let pk = policy.signers.get(i).ok_or_else(|| anyhow!("signer {i} is not in this policy (it has {} signers)", policy.signers.len()))?;
    if !pk.verify(msg, &share.signature) {
        return Err(anyhow!("signer {i}'s signature does not verify over this proposal"));
    }
    let sig: [u8; 2420] = share.signature.as_bytes().try_into().map_err(|_| anyhow!("signer {i}'s signature is not 2 420 bytes"))?;
    Ok(Slot { index: i as u32, pk: pks[i], sig, path: paths[i] })
}

/// The `msauth` witness (§6.3 `prove`): the shares sorted by index, a repeated index refused, each
/// verified natively over the proposal's signing message (a failure names the share), at least `T`
/// of them (beyond `M_MAX`, the lowest indices are kept), then `msauth_inputs(msk, salt, T, slots)`
/// with each slot's key and signer-tree path. The `MSAUTH_WORDS` vector: it carries `msk`.
pub fn assemble_witness(proposal: &Proposal, policy: &Policy, shares: &[Share]) -> Result<Vec<u32>> {
    if proposal.policy != word8_to_hex(&policy.policy_hash()) {
        return Err(anyhow!("this proposal is for another policy"));
    }
    let binding = parse_binding(&proposal.binding)?;
    let msg = msauth::signing_message(&binding);
    if hex::decode(&proposal.signing_message).ok().as_deref() != Some(&msg[..]) {
        return Err(anyhow!("the proposal's signing_message is not its binding's"));
    }
    let mut sorted: Vec<&Share> = shares.iter().collect();
    sorted.sort_by_key(|s| s.index);
    if let Some(w) = sorted.windows(2).find(|w| w[0].index == w[1].index) {
        return Err(anyhow!("signer {} appears twice", w[0].index));
    }
    let pks = policy.pks();
    let (_, paths) = msauth::signer_tree(&pks);
    let mut slots = sorted.iter().map(|s| slot(policy, &pks, &paths, s, &msg)).collect::<Result<Vec<Slot>>>()?;
    if (slots.len() as u32) < policy.threshold {
        return Err(anyhow!("{} signature(s), the policy needs {}", slots.len(), policy.threshold));
    }
    slots.truncate(M_MAX);
    Ok(msauth::msauth_inputs(&policy.msk, &parse_word8(&proposal.salt)?, policy.threshold, &slots))
}

/// One share's `msauth` slot over `proposal` — its key, signature and signer-tree path, the
/// signature verified natively first: one iteration of [`assemble_witness`]'s slot loop, with no
/// threshold applied. Test-only (`tests/wallet_flow.rs`, the forced one-signature witness).
#[doc(hidden)]
pub fn slot_for(proposal: &Proposal, policy: &Policy, share: &Share) -> Result<Slot> {
    let msg = msauth::signing_message(&parse_binding(&proposal.binding)?);
    let pks = policy.pks();
    let (_, paths) = msauth::signer_tree(&pks);
    slot(policy, &pks, &paths, share, &msg)
}

/// The bundle as [`prepare`] built it, rebuilt from the proposal: its witness, digest, salt and
/// `auth_commit`, bundle guest v3.
fn prepared_of(proposal: &Proposal, tx: &Transaction) -> Result<Prepared> {
    Ok(Prepared {
        bundle: tx.bundle.clone().context("the proposal's transaction carries no bundle")?,
        words: parse_words(&proposal.bundle_words)?,
        expected: parse_word8(&proposal.expected)?,
        guest: ZkExecutor::hc_hidden_bundle_v3(),
        v3: true,
        salt: parse_word8(&proposal.salt)?,
        auth_commit: parse_word8(&proposal.auth_commit)?,
        to: None,
        asset: 0,
        memo: String::new(),
    })
}

/// The proved transaction (§6.3 `prove`): every §6.5 check, the shares assembled into the `msauth`
/// witness ([`assemble_witness`]), then both proofs against the binding taken at [`prepare`] — the
/// `msauth` proof on this machine (run in the emulator first; tier 18, minutes), the bundle by
/// `proving` (here or on a paired prover). The binding is required unchanged after.
///
/// No expiry check: this takes no node. The CLI reads the head and refuses at or past
/// `expires_at - 16` before calling it. `proof_cap` holds a paired prover's bundle reply: the
/// chain's `max_proof_bytes` ([`wallet::proof_cap`] of `rand_getLimits`), as `send` does.
pub async fn prove(proposal: &Proposal, policy: &Policy, shares: &[Share], proving: &Proving, profile: FriProfile, proof_cap: usize) -> Result<Transaction> {
    pure::check_proposal(&json(proposal), &zeroize::Zeroizing::new(json(&policy.pure())))?;
    let words = zeroize::Zeroizing::new(assemble_witness(proposal, policy, shares)?);
    let mut tx = Transaction::decode(&hex::decode(&proposal.tx)?)?;
    let binding = parse_binding(&proposal.binding)?;
    let domain = BindingDomain::for_version(proposal.binding_domain, Hash::from_hex(&proposal.genesis)?);
    let prepared = prepared_of(proposal, &tx)?;
    let (p, w) = (&prepared, &words[..]);
    wallet::prove_transaction_by(&mut tx, &domain, |b| async move { proving.prove(p, AuthWitness::Multisig(w), &b, profile, proof_cap).await }).await?;
    if tx.binding(&domain) != binding {
        return Err(anyhow!("the proved transaction no longer hashes to the proposal's binding (wallet bug)"));
    }
    Ok(tx)
}

/// Test-only (`tests/wallet_flow.rs`, the node-side `AuthMismatch` refusal): [`prove`] without the
/// auth half — the bundle proof alone, over the proposal's binding, on this machine, with
/// `auth_proof` left empty for the caller to fill. No share, no threshold and no §6.5 check is
/// applied. Never a wallet path: a transaction without its `msauth` proof is refused by every node.
#[doc(hidden)]
pub async fn prove_bundle_only(proposal: &Proposal, proving: &Proving, profile: FriProfile) -> Result<Transaction> {
    let Proving::Local(backend) = proving else {
        return Err(anyhow!("prove_bundle_only proves on this machine only"));
    };
    let mut tx = Transaction::decode(&hex::decode(&proposal.tx)?)?;
    let binding = parse_binding(&proposal.binding)?;
    let domain = BindingDomain::for_version(proposal.binding_domain, Hash::from_hex(&proposal.genesis)?);
    let prepared = prepared_of(proposal, &tx)?;
    let (p, backend) = (&prepared, *backend);
    wallet::prove_transaction_by(&mut tx, &domain, |b| async move { p.prove(&b, profile, backend) }).await?;
    if tx.binding(&domain) != binding {
        return Err(anyhow!("the proved transaction no longer hashes to the proposal's binding (wallet bug)"));
    }
    Ok(tx)
}

/// Writes a proposal: owner-only (0600) from the start, never over an existing file — it carries
/// the witness words.
pub fn save_proposal(p: &Proposal, path: &Path) -> Result<()> {
    wallet::write_new_secret(path, &(serde_json::to_string_pretty(p)? + "\n"))
}

/// Reads a proposal, refusing one group or other can read.
pub fn load_proposal(path: &Path) -> Result<Proposal> {
    wallet::refuse_loose_mode(path, "proposal", "a private multisig proposal's witness (nk and note openings)")?;
    let text = std::fs::read_to_string(path).with_context(|| format!("reading proposal {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("{} is not a private multisig proposal", path.display()))
}

/// What a signer reads before signing ([`randprotocol_msig::check_proposal_expecting_addresses`]
/// over the two typed files): every §6.5 check, the payees in `expect_to` when it is not empty,
/// and the summary, which `lines()` renders.
pub fn check(proposal: &Proposal, policy: &Policy, expect_to: &[ShieldedAddress]) -> Result<pure::ProposalSummary> {
    Ok(pure::check_proposal_expecting_addresses(&json(proposal), &zeroize::Zeroizing::new(json(&policy.pure())), expect_to)?)
}

/// Writes a proved transaction as bincode hex, owner-only and never over an existing file.
pub fn save_tx(tx: &Transaction, path: &Path) -> Result<()> {
    wallet::write_new_secret(path, &(hex::encode(tx.encode()) + "\n"))
}

/// Reads a transaction [`save_tx`] wrote.
pub fn load_tx(path: &Path) -> Result<Transaction> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading transaction {}", path.display()))?;
    let bytes = hex::decode(text.trim()).with_context(|| format!("{} is not hex", path.display()))?;
    Transaction::decode(&bytes).with_context(|| format!("{} is not a transaction", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::{gas, Keypair};

    fn keys(n: u8) -> Vec<Keypair> {
        (0..n).map(|i| Keypair::from_seed([0x40 + i; 32]).unwrap()).collect()
    }
    fn two_of_three() -> (Policy, Vec<Keypair>) {
        let k = keys(3);
        (Policy::new(k.iter().map(|k| k.public_key().clone()).collect(), 2).unwrap(), k)
    }

    #[test]
    fn a_policy_derives_the_guests_nk_and_a_viewing_only_wallet() {
        let (p, _) = two_of_three();
        let want = randprotocol_zkvm::msauth::nk(&p.msk, &randprotocol_zkvm::msauth::policy(2, &p.signer_root()));
        assert_eq!(p.nk(), want);
        let w = p.wallet();
        assert_eq!(w.vk.nk, want);
        assert!(w.sk.is_none() && w.spend_key().is_err(), "no spend key: spends go through multisig-private");
        assert_eq!(w.address, crate::wallet::Wallet::from_viewing_key(w.vk).address);
        assert_ne!(Policy::new(p.signers.clone(), 2).unwrap().nk(), p.nk(), "a fresh msk is another account");
    }

    #[test]
    fn a_policy_is_refused_when_the_guest_could_never_spend_it() {
        let k = keys(3);
        let pk = |i: usize| k[i].public_key().clone();
        assert!(Policy::new(vec![], 1).is_err(), "no signer");
        assert!(Policy::new(vec![pk(0), pk(1)], 0).is_err(), "threshold 0");
        assert!(Policy::new(vec![pk(0), pk(1)], 3).is_err(), "threshold above n");
        assert!(Policy::new(vec![pk(0), pk(0)], 1).is_err(), "a repeated key");
        assert!(Policy::new((0..17).map(|i| Keypair::from_seed([i; 32]).unwrap().public_key().clone()).collect(), 1).is_err(), "n > N_MAX");
        let m = randprotocol_zkvm::msauth::M_MAX as u32;
        let many: Vec<_> = (0..(m as u8 + 1)).map(|i| Keypair::from_seed([0x60 + i; 32]).unwrap().public_key().clone()).collect();
        assert!(Policy::new(many, m + 1).is_err(), "threshold above M_MAX");
    }

    #[test]
    fn the_policy_file_is_0600_and_round_trips() {
        let (p, _) = two_of_three();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        p.save(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Policy::load(&path).is_err(), "group/world readable is refused");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let back = Policy::load(&path).unwrap();
        assert_eq!((back.threshold, back.signers.clone(), back.msk), (p.threshold, p.signers.clone(), p.msk));
        assert!(p.save(&path).is_err(), "never overwrites");
    }

    /// A proposal over a real v3 bundle (no proof), built offline by the test helper below.
    fn proposal(p: &Policy) -> Proposal {
        tests_support::offline_proposal(p, 10 * randprotocol_core::UNITS_PER_RAND)
    }

    #[test]
    fn sign_recomputes_the_binding_and_opens_every_output_before_signing() {
        let (p, k) = two_of_three();
        let prop = proposal(&p);
        let (share, shown) = sign(&prop, &p, &k[2], &[]).unwrap();
        assert_eq!(share.index, 2);
        let msg = hex::decode(&prop.signing_message).unwrap();
        assert!(k[2].public_key().verify(&msg, &share.signature));
        assert!(shown.iter().any(|l| l.contains("10 RAND")), "{shown:?}");
        assert_eq!(share.to_string().parse::<Share>().unwrap().index, 2, "index:hex round-trips");
        // A key outside the policy is refused.
        assert!(sign(&prop, &p, &Keypair::from_seed([9; 32]).unwrap(), &[]).is_err());
        // A tampered transaction (its binding moves) is refused.
        let mut bad = prop.clone();
        let mut tx = Transaction::decode(&hex::decode(&bad.tx).unwrap()).unwrap();
        tx.bundle.as_mut().unwrap().fee += 1;
        bad.tx = hex::encode(tx.encode());
        assert!(sign(&bad, &p, &k[0], &[]).unwrap_err().to_string().contains("binding"));
        // A proposal from another policy's account is refused.
        let (other, _) = two_of_three();
        assert!(sign(&prop, &other, &k[0], &[]).unwrap_err().to_string().contains("auth_commit"));
        // Naming a payee the proposal does not pay refuses it; naming none says so in the lines.
        let stranger = crate::wallet::Wallet::from_spend_key(randprotocol_zkvm::notes::SpendKey([5; 8])).address;
        let e = sign(&prop, &p, &k[0], &[stranger]).unwrap_err().to_string();
        assert!(e.contains("not an expected recipient"), "{e}");
        assert!(shown.iter().any(|l| l.contains("the payee was NOT checked")), "{shown:?}");
    }

    /// `require_multisig_chain` names which condition failed: no multisig guest (null), another
    /// build's guest, or a bundle guest other than v3.
    #[test]
    fn the_multisig_chain_refusal_names_the_condition() {
        let (ours, v3) = (word8_to_hex(&ZkExecutor::hc_auth_multisig()), word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()));
        let other = "11".repeat(32);
        let status = |msauth: serde_json::Value, bundle: &str| serde_json::json!({ "hc_auth_multisig": msauth, "hc_bundle": bundle });
        assert_eq!(multisig_chain_refusal(&status(serde_json::json!(ours), &v3)), None);
        let null = multisig_chain_refusal(&status(serde_json::Value::Null, &v3)).unwrap();
        assert!(null.contains("names no hc_auth_multisig (null)"), "{null}");
        let theirs = multisig_chain_refusal(&status(serde_json::json!(other), &v3)).unwrap();
        assert!(theirs.contains(&format!("hc_auth_multisig is {other}, another build's guest")) && theirs.contains(&ours), "{theirs}");
        let bundle = multisig_chain_refusal(&status(serde_json::json!(ours), &other)).unwrap();
        assert!(bundle.contains("needs bundle guest v3") && bundle.contains(&other), "{bundle}");
    }

    /// Review finding 4: a single-key wallet seals dummy outputs under a throwaway key, so signers
    /// could not open them; a multisig proposal seals every output, dummies included, with the
    /// account's vk as sender, and `sign` refuses any output it cannot open.
    #[test]
    fn every_output_of_a_proposal_opens_as_sender_and_value_is_conserved() {
        let (p, k) = two_of_three();
        let prop = proposal(&p); // one real payment, change and two dummies
        let tx = Transaction::decode(&hex::decode(&prop.tx).unwrap()).unwrap();
        let w = p.wallet();
        let b = tx.bundle.as_ref().unwrap();
        for (slot, env) in b.envelopes.iter().enumerate() {
            let env = randprotocol_zkvm::address::envelope_from_core(env);
            assert!(env.open_as_sender_with(b.commitments[slot], &w.scan_key).is_some(), "slot {slot} opens as sender");
        }
        // A proposal whose witness spends more than the outputs + fee account for is refused.
        let mut skim = prop.clone();
        skim.bundle_words = tests_support::with_input_amount_raised(&prop.bundle_words, 1);
        assert!(sign(&skim, &p, &k[0], &[]).unwrap_err().to_string().contains("value"), "conservation");
        // An output sealed to a throwaway sender (the single-key dummy) is refused, not skipped —
        // in a proposal re-bound over the edited envelope, so only "opens as sender" can catch it.
        let mut hidden = prop.clone();
        hidden.tx = tests_support::with_a_throwaway_sealed_output(&prop.tx, &w);
        tests_support::rebind(&mut hidden);
        assert!(sign(&hidden, &p, &k[0], &[]).unwrap_err().to_string().contains("open"));
        // Burns are shown.
        let (_, shown) = sign(&prop, &p, &k[0], &[]).unwrap();
        assert!(shown.iter().any(|l| l.starts_with("burn")), "{shown:?}");
    }

    /// The real `prepare`, against the wallet tests' fake node: the store it was handed keeps no
    /// note pending (`OwnedNote::pending: Option<u32>`, what `clear_pending` and `Plan::select` read).
    #[tokio::test]
    async fn prepare_does_not_mark_notes_pending() {
        let (p, _) = two_of_three();
        let (rpc, mut store) = crate::wallet::tests::fake_multisig_chain(&p.wallet(), 20 * randprotocol_core::UNITS_PER_RAND).await;
        let to = crate::wallet::Wallet::from_spend_key(randprotocol_zkvm::notes::SpendKey([5; 8])).address;
        let prop = prepare(&rpc, &p, &mut store, &to, randprotocol_core::UNITS_PER_RAND, "", randprotocol_core::gas::BUNDLE_BASE, 7).await.unwrap();
        assert!(store.notes.iter().all(|n| n.pending.is_none()), "an abandoned proposal hides nothing from the next one");
        // A second proposal over the same notes is still possible.
        assert!(prepare(&rpc, &p, &mut store, &to, randprotocol_core::UNITS_PER_RAND, "", randprotocol_core::gas::BUNDLE_BASE, 7).await.is_ok());
        drop(prop);
    }

    /// `prepare_sweep`: every RAND note less the fee, to one output; more than two notes refused.
    #[tokio::test]
    async fn prepare_sweep_moves_the_whole_rand_balance_and_refuses_more_than_two_notes() {
        let (p, _) = two_of_three();
        let unit = randprotocol_core::UNITS_PER_RAND;
        let fee = randprotocol_core::gas::BUNDLE_BASE;
        let to = crate::wallet::Wallet::from_spend_key(randprotocol_zkvm::notes::SpendKey([6; 8])).address;
        let (rpc, mut store) = crate::wallet::tests::fake_multisig_chain_with(&p.wallet(), &[3 * unit, 4 * unit]).await;
        let sweep = prepare_sweep(&rpc, &p, &mut store, &to, fee, 7).await.unwrap();
        let s = crate::multisig_private::check_proposal(&json(&sweep), &json(&p.pure())).unwrap();
        let moved: Vec<u64> = s.outputs.iter().filter(|o| o.amount > 0).map(|o| o.amount).collect();
        assert_eq!(moved, vec![7 * unit - fee], "one output, the whole balance less the fee, no change");
        let (rpc, mut store) = crate::wallet::tests::fake_multisig_chain_with(&p.wallet(), &[unit, unit, unit]).await;
        let e = prepare_sweep(&rpc, &p, &mut store, &to, fee, 7).await.err().expect("three notes are refused").to_string();
        assert!(e.contains("send to yourself first to merge"), "{e}");
    }

    /// More shares than the threshold: all are verified, the lowest `M_MAX` indices are kept, and
    /// the guest still publishes `auth_commit`.
    #[test]
    fn assemble_witness_keeps_the_lowest_m_max_of_more_than_t_shares() {
        use randprotocol_zkvm::msauth::{M_MAX, SLOT_WORDS};
        let k = keys(4);
        let p = Policy::new(k.iter().map(|k| k.public_key().clone()).collect(), 2).unwrap();
        let prop = proposal(&p);
        let shares: Vec<Share> = [3usize, 1, 0, 2].iter().map(|&i| sign(&prop, &p, &k[i], &[]).unwrap().0).collect();
        let w = assemble_witness(&prop, &p, &shares).unwrap();
        let active: Vec<(u32, u32)> = (0..M_MAX).map(|s| (w[17 + s * SLOT_WORDS], w[17 + s * SLOT_WORDS + 1])).collect();
        assert_eq!(active, vec![(1, 0), (1, 1), (1, 2)], "the lowest M_MAX = 3 indices, in order");
        let binding = parse_binding(&prop.binding).unwrap();
        assert_eq!(randprotocol_zkvm::executor::run_msauth(&w, &binding).unwrap(), parse_word8(&prop.auth_commit).unwrap());
    }

    #[test]
    fn a_policy_names_its_signers_that_a_public_account_also_uses() {
        let (p, k) = two_of_three();
        let acct = randprotocol_core::ledger::multisig::Account { signers: vec![k[2].public_key().clone()], threshold: 1, nonce: 0, vault: Default::default() };
        assert_eq!(p.reused_in(&[acct]), vec![2]);
    }

    #[test]
    fn assemble_witness_needs_the_threshold_and_runs_like_the_guest() {
        let (p, k) = two_of_three();
        let prop = proposal(&p);
        let s0 = sign(&prop, &p, &k[0], &[]).unwrap().0;
        let s2 = sign(&prop, &p, &k[2], &[]).unwrap().0;
        let w = assemble_witness(&prop, &p, &[s2.clone(), s0.clone()]).unwrap();
        assert_eq!(w.len(), randprotocol_zkvm::msauth::MSAUTH_WORDS);
        let binding = parse_binding(&prop.binding).unwrap();
        assert_eq!(randprotocol_zkvm::executor::run_msauth(&w, &binding).unwrap(), parse_word8(&prop.auth_commit).unwrap(), "the guest publishes auth_commit");
        let e = assemble_witness(&prop, &p, std::slice::from_ref(&s0)).unwrap_err().to_string();
        assert!(e.contains("1 signature") && e.contains("needs 2"), "{e}");
        assert!(assemble_witness(&prop, &p, &[s0.clone(), s0.clone()]).is_err(), "a repeated index");
        let mut forged = s2.clone();
        forged.index = 1;
        assert!(assemble_witness(&prop, &p, &[s0, forged]).unwrap_err().to_string().contains("signer 1"), "names the bad share");
    }

    /// `prove` on the emulated path (the real tier-18 prove is Task 8's e2e): both proofs made over
    /// the binding taken at `prepare`, the auth proof the multisig shape publishing `auth_commit`,
    /// and nothing proved below the threshold.
    #[tokio::test]
    async fn prove_makes_both_proofs_over_the_proposals_binding() {
        use randprotocol_core::confidential::{AuthShape, ConfidentialExecutor, StubExecutor};
        let (p, k) = two_of_three();
        let prop = proposal(&p);
        let shares: Vec<Share> = [2usize, 0].iter().map(|&i| sign(&prop, &p, &k[i], &[]).unwrap().0).collect();
        let tx = prove(&prop, &p, &shares, &Proving::Emulated, FriProfile::Test, gas::MAX_PROOF_BYTES).await.unwrap();
        let b = tx.bundle.as_ref().unwrap();
        assert!(!b.proof.is_empty(), "the bundle proof");
        let binding = parse_binding(&prop.binding).unwrap();
        assert_eq!(tx.binding(&BindingDomain::ChainId), binding, "proved over the proposal's binding");
        let (shape, c, _) = StubExecutor.auth_header(&b.auth_proof).unwrap();
        assert_eq!((shape, c), (AuthShape::Multisig, parse_word8(&prop.auth_commit).unwrap()));
        let e = prove(&prop, &p, &shares[..1], &Proving::Emulated, FriProfile::Test, gas::MAX_PROOF_BYTES).await.unwrap_err().to_string();
        assert!(e.contains("needs 2"), "{e}");
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! An offline proposal: a v3 bundle spending one synthetic note of the policy's account to a
    //! fresh address, through the same `build_bundle` the online path calls.
    use super::*;
    pub(crate) fn offline_proposal(p: &Policy, amount: u64) -> Proposal {
        offline_proposal_with_store(p, amount).1
    }
    pub(crate) fn offline_proposal_with_store(p: &Policy, amount: u64) -> (NoteStore, Proposal) {
        crate::wallet::tests::offline_v3_proposal_for(&p.wallet(), amount, DummySender::Account, |prepared, tx, binding| {
            Proposal::from_prepared(p, prepared, tx, binding, 7, &randprotocol_core::Hash::ZERO, 0, 1_000)
        })
    }
    use randprotocol_zkvm::hidden::hidden_input_v3 as hi;
    /// `bundle_words` (hex of the v3 witness, each u32 little-endian) with input slot 2's amount
    /// raised by `by`: the 64-bit amount at words `in_slot(2) + S_AMOUNT_LO` / `+ S_AMOUNT_HI`, with the
    /// carry. Slot 2 is the first RAND input slot (slots 2–3 carry RAND), where the synthetic note sits.
    pub(crate) fn with_input_amount_raised(words_hex: &str, by: u64) -> String {
        let mut w = parse_words(words_hex).unwrap();
        let (lo, hi_) = (hi::in_slot(2) + hi::S_AMOUNT_LO, hi::in_slot(2) + hi::S_AMOUNT_HI);
        let v = (w[lo] as u64 | (w[hi_] as u64) << 32) + by;
        (w[lo], w[hi_]) = (v as u32, (v >> 32) as u32);
        randprotocol_msig::words_hex(&w)
    }
    /// The proposal's tx (hex of bincode) with output slot 3's envelope re-sealed: the note it holds
    /// (the change, opened as sender with the account's scan key) sealed again to the account by
    /// `randprotocol_zkvm::address::seal_note` under a fresh throwaway sender's `ovk`. The
    /// commitment is unchanged; the envelope, and so the binding, is not — [`rebind`] re-makes it.
    pub(crate) fn with_a_throwaway_sealed_output(tx_hex: &str, account: &crate::wallet::Wallet) -> String {
        let mut tx = Transaction::decode(&hex::decode(tx_hex).unwrap()).unwrap();
        let b = tx.bundle.as_mut().unwrap();
        let (_, note) = randprotocol_zkvm::address::envelope_from_core(&b.envelopes[3])
            .open_as_sender_with(b.commitments[3], &account.scan_key)
            .expect("slot 3 opens before the edit");
        assert_eq!(note.pk, account.vk.pk(), "slot 3 is the change, the account's own");
        let throwaway = randprotocol_zkvm::notes::SpendKey::random().viewing_key();
        b.envelopes[3] = randprotocol_zkvm::address::seal_note(&throwaway, &account.address, &note, &randprotocol_zkvm::viewing::TxKey::random()).unwrap();
        hex::encode(tx.encode())
    }
    /// `p`'s binding and signing message re-made over its (edited) transaction, as a proposer
    /// handing out a self-consistent file would.
    pub(crate) fn rebind(p: &mut Proposal) {
        let tx = Transaction::decode(&hex::decode(&p.tx).unwrap()).unwrap();
        let genesis = randprotocol_core::Hash::from_hex(&p.genesis).unwrap();
        let binding = tx.binding(&randprotocol_core::BindingDomain::for_version(p.binding_domain, genesis));
        p.binding = randprotocol_msig::words_hex(&binding);
        p.signing_message = hex::encode(randprotocol_zkvm::msauth::signing_message(&binding));
    }
}
