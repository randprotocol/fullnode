//! The private-multisig signer checks (spec `docs/superpowers/specs/2026-10-11-private-multisig-
//! phase4-design.md` §6.5), as a pure library.
//!
//! Every wallet app — the `rand` CLI, the clients' wasm and native cores — runs a signer's checks
//! through this crate, so it has no RPC, no filesystem, no OS entropy, and no prover, rocksdb or
//! tokio, and it compiles for `wasm32-unknown-unknown`. `randprotocol-client` re-exports it as
//! `randprotocol_client::multisig_private` and keeps everything that needs a node, a file or a
//! prover in its own `msig_private`.
//!
//! [`check_proposal`] never trusts the proposal's informational fields: it decodes the
//! transaction, recomputes its binding, opens every output as the account, and re-derives the
//! spent notes' nullifiers from the witness. [`sign`] signs only what checked.
//!
//! **What a signer can and cannot verify about delivery.** Each output is opened as sender with
//! the account's own outgoing key, so its owner key (`pk`), amount, asset and memo are checked
//! against the bundle's commitment. Who can *find* the note is not: the envelope's ML-KEM half is
//! sealed to some encapsulation key, and that key cannot be recovered or re-derived from the
//! envelope (encapsulation is randomised, and the vendored sealer draws its randomness from the
//! OS, so it cannot be re-run). A proposer could therefore pay the right `pk` while sealing to a
//! KEM key of its own choosing: nothing is stolen, but the payee never detects the note. So an
//! output is shown by a fingerprint of its owner key alone ([`owner_fingerprint`]), never by an
//! address, and every line says the delivery key is not verified; nothing from the proposal's
//! informational `summary` is shown or relied on. The follow-up is a deterministic seal API
//! upstream (the encapsulation message derived from the transaction key), which would let a
//! signer re-seal and compare.
//!
//! **Who is paid.** The coordinator holds the policy, so it can seal every output as the account
//! and pass every check above while paying a key of its own: the checks prove the outputs are
//! *some* owner keys, not the payee the signer meant. A signer closes that by naming the payee —
//! [`check_proposal_expecting`] / [`sign_expecting`] with the `rand1…` addresses the payees
//! handed over out of band: every output that moves value and is not change must then pay one
//! of their owner keys, or the proposal is refused. Without an expectation the summary says, once and loudly,
//! that the payee was not checked. (A zero-amount output — a bundle's dummy — moves nothing and
//! is not held to the expectation.)
//!
//! **Secrets.** A policy's JSON carries the account's `msk` (viewing power over every note of the
//! account) and a proposal's JSON carries the witness words (`nk`, the salt, the spent notes'
//! openings). This crate never logs either; callers must store both as secrets.

use randprotocol_core::ledger::MAX_PROOF_WINDOW_BLOCKS;
use randprotocol_core::notes::{word8_from_hex, word8_to_hex, ShieldedAddress, Word8};
use randprotocol_core::{format_amount, parse_amount, Action, BindingDomain, Hash, Keypair, PublicKey, Signature, Transaction};
use randprotocol_zkvm::address::{address_of, envelope_from_core};
use randprotocol_zkvm::hidden::{hidden_bundle_digest_v3, hidden_input_v3 as hi, HiddenDigestInput, HiddenDigestInputV3};
use randprotocol_zkvm::msauth::{self, M_MAX, N_MAX};
use randprotocol_zkvm::notes::{Note, ViewingKey};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeMap;

/// The policy file's `version` (§6.1).
pub const POLICY_VERSION: u32 = 1;
/// The proposal file's `version` (§6.4).
pub const PROPOSAL_VERSION: u32 = 1;
/// A Dilithium2 public key, the msauth guest's leaf preimage.
pub const PK_BYTES: usize = 1312;
/// A Dilithium2 signature.
pub const SIG_BYTES: usize = 2420;

const CHECKED: &str = "a checked policy (Policy::check)";

/// Why a check refused, or why an input did not parse.
#[derive(Debug, thiserror::Error)]
pub enum MsigError {
    /// A file or a share that does not parse.
    #[error("{0}")]
    Invalid(String),
    /// A well-formed proposal or share that fails a check.
    #[error("{0}")]
    Refused(String),
}

fn invalid(s: impl Into<String>) -> MsigError {
    MsigError::Invalid(s.into())
}

fn refused(s: impl Into<String>) -> MsigError {
    MsigError::Refused(s.into())
}

/// The policy file (§6.1): `{"version": 1, "threshold": T, "signers": [pk hex, …], "msk": hex}`.
/// The order of `signers` is the signer tree's leaf order, so it is part of the address.
#[derive(Serialize, Deserialize, Clone)]
pub struct Policy {
    pub version: u32,
    pub threshold: u32,
    /// Each a 1 312-byte Dilithium2 public key, as hex.
    pub signers: Vec<String>,
    /// The account's secret: 8 words, 64 hex.
    pub msk: String,
}

/// The proposal file (§6.4). `tx` is the transaction (bincode hex, both proofs empty);
/// `bundle_words` the v3 witness (hex, each word little-endian); `binding` the 8 binding words
/// (32 bytes LE, hex); `signing_message` 45 bytes hex; `summary` informational only.
#[derive(Serialize, Deserialize, Clone)]
pub struct Proposal {
    pub version: u32,
    pub chain_id: u64,
    pub genesis: String,
    pub binding_domain: u32,
    pub policy: String,
    pub tx: String,
    pub bundle_words: String,
    pub expected: String,
    pub salt: String,
    pub auth_commit: String,
    pub binding: String,
    pub signing_message: String,
    pub expires_at: u64,
    pub summary: Vec<String>,
}

/// One output as the account opened it: its owner key's [`owner_fingerprint`] (verified; the
/// delivery key is not — see the module doc), whether that owner is this account (change), the
/// amount, asset and memo the note carries, and — under an expectation — the fingerprint of the
/// expected address whose owner key it pays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutputSummary {
    pub owner_fingerprint: String,
    pub to_account: bool,
    pub amount: u64,
    pub asset: u32,
    pub memo: String,
    /// The matching expected address's fingerprint (`ShieldedAddress::fingerprint`); `None`
    /// without an expectation, for change, and for a zero-amount output.
    pub matches: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Burns {
    pub burn_a: u64,
    pub burn_asset: u32,
    pub burn_r: u64,
}

/// What [`check_proposal`] verified, for a signer to read before signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProposalSummary {
    /// The chain the transaction is for and the genesis its binding commits to (hex; all zeros
    /// under the chain-id-only binding domain), both checked.
    pub chain_id: u64,
    pub genesis: String,
    /// Whether the signer named the payees ([`check_proposal_expecting`]): every value-moving,
    /// non-change output then pays one of them.
    pub recipients_checked: bool,
    /// The four output slots, in order.
    pub outputs: Vec<OutputSummary>,
    pub fee: u64,
    pub burns: Burns,
    pub expires_at: u64,
    /// `b"rand-msauth-1" ‖ binding`: what every signer signs. Serialised as hex.
    #[serde(serialize_with = "hex_bytes")]
    pub signing_message: [u8; 45],
    pub policy_fingerprint: String,
}

fn hex_bytes<S: Serializer>(b: &[u8; 45], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(b))
}

impl ProposalSummary {
    /// The lines a signer is shown: the chain, the payee warning when no payee was named, each
    /// output, the fee and the burns.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![format!("chain {} · genesis {}", self.chain_id, self.genesis)];
        if !self.recipients_checked {
            lines.push(NO_EXPECTATION.to_string());
        }
        lines.extend(self.outputs.iter().enumerate().map(|(n, o)| {
            format!(
                "{n}: → {} to {}{}{} memo {:?} (owner key verified; delivery key NOT verifiable from this proposal)",
                amount_text(o.amount, o.asset),
                if o.to_account { "this account " } else { "" },
                o.owner_fingerprint,
                o.matches.as_ref().map(|f| format!(" matches {f}")).unwrap_or_default(),
                o.memo
            )
        }));
        lines.push(format!("fee {} RAND", format_amount(self.fee)));
        lines.push(format!(
            "burn {} of asset {}, {} RAND",
            self.burns.burn_a,
            self.burns.burn_asset,
            format_amount(self.burns.burn_r)
        ));
        lines
    }
}

/// The line a summary carries when the signer named no payee.
pub const NO_EXPECTATION: &str =
    "WARNING: no expected recipient given: the payee was NOT checked (the coordinator could be paying itself; pass the payee's address to check)";

/// `10 RAND`, or a token's raw units (this crate knows no token's decimals).
fn amount_text(amount: u64, asset: u32) -> String {
    match asset {
        0 => format!("{} RAND", format_amount(amount)),
        a => format!("{amount} units of asset {a}"),
    }
}

/// The fingerprint of an owner key alone: the first 16 hex digits (as many symbols as an address
/// fingerprint has) of `blake3("rand-msig-owner-1" ‖ pk)`. Unlike an address's fingerprint it
/// covers no KEM key, so it claims exactly what a signer verified.
pub fn owner_fingerprint(pk: &Word8) -> String {
    let bytes: Vec<u8> = pk.iter().flat_map(|w| w.to_le_bytes()).collect();
    Hash::digest_domain(b"rand-msig-owner-1", &bytes).to_hex()[..16].to_string()
}

/// [`owner_fingerprint`] of an address's owner key: what a payee hands a signer (`rand address`
/// prints it) to compare with the output line that pays them.
pub fn owner_fingerprint_of(addr: &ShieldedAddress) -> String {
    owner_fingerprint(&addr.pk)
}

/// [`owner_fingerprint_of`] a pasted `rand1…` address, parsed as the wallet parses one.
pub fn owner_fingerprint_of_text(addr: &str) -> Result<String, MsigError> {
    let a = ShieldedAddress::parse(addr.trim()).map_err(|e| invalid(format!("not a shielded address: {e}")))?;
    Ok(owner_fingerprint_of(&a))
}

/// A payee the signer expects: a `rand1…` address and, optionally, the exact RAND amount it must
/// be paid in total.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedRecipient {
    pub address: ShieldedAddress,
    /// Smallest units; `Some` pins the sum of every output paying `address` (RAND only).
    pub amount: Option<u64>,
}

impl ExpectedRecipient {
    /// An address with no amount pin.
    pub fn address(address: ShieldedAddress) -> Self {
        ExpectedRecipient { address, amount: None }
    }

    /// `rand1…` or `rand1…:AMOUNT`, the amount parsed as `rand send --amount` parses one
    /// (`randprotocol_core::parse_amount`: decimal RAND, up to the token's decimals).
    pub fn parse(text: &str) -> Result<Self, MsigError> {
        Self::parse_fragment(text).map_err(|f| invalid(format!("expected recipient {f}")))
    }

    fn parse_fragment(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (addr, amount) = match text.rsplit_once(':') {
            Some((a, amt)) => (a.trim(), Some(parse_amount(amt).map_err(|e| format!("has a malformed amount {amt:?}: {e}"))?)),
            None => (text, None),
        };
        let address = ShieldedAddress::parse(addr).map_err(|e| format!("is not a shielded address: {e}"))?;
        Ok(ExpectedRecipient { address, amount })
    }
}

/// Pasted `rand1…[:AMOUNT]` entries (see [`ExpectedRecipient::parse`]); a malformed one is
/// refused naming its index.
pub fn parse_expected_recipients<S: AsRef<str>>(texts: &[S]) -> Result<Vec<ExpectedRecipient>, MsigError> {
    texts
        .iter()
        .enumerate()
        .map(|(i, t)| ExpectedRecipient::parse_fragment(t.as_ref()).map_err(|f| invalid(format!("expected recipient {i} {f}"))))
        .collect()
}

/// The informational `summary` lines a proposal carries (§6.4): the payment, the fee, the memo.
/// [`check_proposal`] neither shows nor relies on them.
pub fn informational_summary(to: Option<(&ShieldedAddress, u64)>, asset: u32, fee: u64, memo: &str) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some((addr, amount)) = to {
        lines.push(format!("pay {} to {}", amount_text(amount, asset), addr.to_string()));
    }
    lines.push(format!("fee {} RAND", format_amount(fee)));
    if !memo.is_empty() {
        lines.push(format!("memo {memo:?}"));
    }
    lines
}

impl Policy {
    /// §6.1: version 1; `1 ≤ n ≤ N_MAX`; `1 ≤ T ≤ min(n, M_MAX)`; every key 1 312 bytes and none
    /// repeated; `msk` 64 hex. A policy outside these the guest could never spend.
    pub fn check(&self) -> Result<(), MsigError> {
        if self.version != POLICY_VERSION {
            return Err(invalid(format!("a version {} policy; this build reads version {POLICY_VERSION}", self.version)));
        }
        let n = self.signers.len();
        if n == 0 || n > N_MAX {
            return Err(invalid(format!("{n} signers; a private multisig policy has 1..={N_MAX}")));
        }
        let most = n.min(M_MAX) as u32;
        if self.threshold == 0 || self.threshold > most {
            return Err(invalid(format!(
                "threshold {} is outside 1..={most} (at most the {n} signers, and at most M_MAX = {M_MAX})",
                self.threshold
            )));
        }
        let pks = self.pks()?;
        for i in 0..n {
            if let Some(j) = (0..i).find(|&j| pks[j] == pks[i]) {
                return Err(invalid(format!("signer {i} repeats signer {j}")));
            }
        }
        parse_word8(&self.msk).map_err(|_| invalid("the policy's msk is not 64 hex characters"))?;
        Ok(())
    }

    /// The signers' keys, in leaf order.
    pub fn pks(&self) -> Result<Vec<[u8; PK_BYTES]>, MsigError> {
        self.signers
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let b = hex::decode(s).map_err(|_| invalid(format!("signer {i} is not hex")))?;
                let n = b.len();
                b.try_into().map_err(|_| invalid(format!("signer {i} is {n} bytes, a Dilithium2 key is {PK_BYTES}")))
            })
            .collect()
    }

    fn msk_word(&self) -> Word8 {
        parse_word8(&self.msk).expect(CHECKED)
    }

    /// `msauth::signer_tree(pks).0`. Panics on a policy that fails [`Policy::check`].
    pub fn signer_root(&self) -> Word8 {
        msauth::signer_tree(&self.pks().expect(CHECKED)).0
    }

    /// `msauth::policy(T, signer_root)`: what a proposal names as its `policy`.
    pub fn policy_hash(&self) -> Word8 {
        msauth::policy(self.threshold, &self.signer_root())
    }

    /// The account's nullifier key, `msauth::nk(msk, policy)`.
    pub fn nk(&self) -> Word8 {
        msauth::nk(&self.msk_word(), &self.policy_hash())
    }

    pub fn viewing_key(&self) -> ViewingKey {
        ViewingKey { nk: self.nk() }
    }

    /// The account's address, derived from [`Policy::viewing_key`] as a single-key wallet's is.
    pub fn address(&self) -> ShieldedAddress {
        address_of(&self.viewing_key())
    }

    /// The address's fingerprint, which every signer compares out of band.
    pub fn fingerprint(&self) -> String {
        self.address().fingerprint().to_string()
    }
}

impl Proposal {
    /// A proposal for `tx` (both proofs empty) under the binding domain of `binding_domain`
    /// (`BindingDomain::for_version`, over `genesis`): every derived field — `policy`, the binding,
    /// the signing message, `auth_commit` (the bundle's) — computed here, the rest as given.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: &Policy,
        tx: &Transaction,
        genesis: &Hash,
        binding_domain: u32,
        bundle_words: &[u32],
        expected: &Word8,
        salt: &Word8,
        expires_at: u64,
        summary: Vec<String>,
    ) -> Proposal {
        let binding = tx.binding(&BindingDomain::for_version(binding_domain, *genesis));
        let auth_commit = tx.bundle.as_ref().map_or([0; 8], |b| b.auth_commit);
        Proposal {
            version: PROPOSAL_VERSION,
            chain_id: tx.chain_id,
            genesis: genesis.to_hex(),
            binding_domain,
            policy: word8_to_hex(&policy.policy_hash()),
            tx: hex::encode(tx.encode()),
            bundle_words: words_hex(bundle_words),
            expected: word8_to_hex(expected),
            salt: word8_to_hex(salt),
            auth_commit: word8_to_hex(&auth_commit),
            binding: words_hex(&binding),
            signing_message: hex::encode(msauth::signing_message(&binding)),
            expires_at,
            summary,
        }
    }
}

/// 64 hex characters → 8 words (`word8_to_hex`'s inverse).
pub fn parse_word8(hex: &str) -> Result<Word8, MsigError> {
    // Never echo the value: a salt or an `msk` is parsed here.
    word8_from_hex(hex).ok_or_else(|| invalid(format!("a word is 64 hex characters; this one is {} characters or not hex", hex.len())))
}

/// The proposal's `binding`: 32 bytes, little-endian words, as hex.
pub fn parse_binding(hex: &str) -> Result<[u32; 8], MsigError> {
    parse_words(hex)?.try_into().map_err(|_| invalid("a binding is 8 words (64 hex characters)"))
}

/// Words as hex, each little-endian: `bundle_words` and `binding`.
pub fn words_hex(words: &[u32]) -> String {
    hex::encode(words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>())
}

/// [`words_hex`]'s inverse.
pub fn parse_words(text: &str) -> Result<Vec<u32>, MsigError> {
    let b = hex::decode(text).map_err(|_| invalid("words are hex"))?;
    if b.len() % 4 != 0 {
        return Err(invalid("words are a whole number of 4-byte words"));
    }
    Ok(b.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect())
}

fn parse_inputs(proposal_json: &str, policy_json: &str) -> Result<(Proposal, Policy), MsigError> {
    let policy: Policy = serde_json::from_str(policy_json).map_err(|e| invalid(format!("the policy does not parse: {e}")))?;
    policy.check()?;
    let proposal: Proposal = serde_json::from_str(proposal_json).map_err(|e| invalid(format!("the proposal does not parse: {e}")))?;
    if proposal.version != PROPOSAL_VERSION {
        return Err(invalid(format!("a version {} proposal; this build reads version {PROPOSAL_VERSION}", proposal.version)));
    }
    Ok((proposal, policy))
}

/// Every §6.5 check, in order; the summary of what was checked.
///
/// 1. Both files parse; [`Policy::check`].
/// 2. The proposal names this policy (`policy == hex(policy_hash)`).
/// 3. `tx` decodes, carries a bundle and no action, on the proposal's chain; its binding under the
///    proposal's domain is `binding`, and `signing_message` is that binding's.
/// 4. `auth_commit == msauth::auth_commit(nk, salt)`: the bundle spends from this account; and
///    `expected` is the bundle's v3 digest, recomputed.
/// 5. All four outputs open as sender under the account's scan key, each to the bundle's
///    commitment in its slot — an output that does not open is refused, never skipped.
/// 6. Value: the witness's input notes nullify (under the account's `nk`) to exactly the bundle's
///    four nullifiers, and per asset Σ inputs = Σ outputs + fee + `burn_a`/`burn_r`.
/// 7. Expiry, as far as a pure function can: `time < expires_at ≤ time + MAX_PROOF_WINDOW_BLOCKS`.
///    Comparing with the chain head is the caller's.
///
/// No payee is checked: [`check_proposal_expecting`] with an empty list, whose summary says so.
pub fn check_proposal(proposal_json: &str, policy_json: &str) -> Result<ProposalSummary, MsigError> {
    check_proposal_expecting_addresses(proposal_json, policy_json, &[])
}

/// [`check_proposal`], and then, when `expected_recipients` (pasted `rand1…[:AMOUNT]` entries,
/// parsed by [`parse_expected_recipients`]) is not empty, 8: every output that moves value
/// (amount > 0) and is not change pays the owner key of one of those addresses (otherwise refused,
/// naming the output and its owner fingerprint); every expected address is paid by at least one
/// such output (`expected recipient <fp> is not paid`); and an entry with an `:AMOUNT` is paid
/// exactly that in RAND, summed over its outputs (`… is paid <sum>, not <AMOUNT>`; a non-RAND
/// output to it is refused). The delivery key is still not verified (module doc). An
/// empty list checks no payee: the summary's `recipients_checked` is false and its lines say so.
pub fn check_proposal_expecting<S: AsRef<str>>(proposal_json: &str, policy_json: &str, expected_recipients: &[S]) -> Result<ProposalSummary, MsigError> {
    check_proposal_expecting_addresses(proposal_json, policy_json, &parse_expected_recipients(expected_recipients)?)
}

/// [`check_proposal_expecting`] over addresses already parsed.
pub fn check_proposal_expecting_addresses(proposal_json: &str, policy_json: &str, expected_recipients: &[ExpectedRecipient]) -> Result<ProposalSummary, MsigError> {
    let (proposal, policy) = parse_inputs(proposal_json, policy_json)?;
    check(&proposal, &policy, expected_recipients)
}

fn check(p: &Proposal, policy: &Policy, expected_recipients: &[ExpectedRecipient]) -> Result<ProposalSummary, MsigError> {
    // 2. The policy.
    let policy_hash = word8_to_hex(&policy.policy_hash());
    if p.policy != policy_hash {
        return Err(refused(format!("this proposal is for another policy: it names {}, this policy is {policy_hash}", p.policy)));
    }

    // 3. The transaction and its binding.
    let raw = hex::decode(&p.tx).map_err(|_| invalid("the proposal's tx is not hex"))?;
    let tx = Transaction::decode(&raw).map_err(|e| invalid(format!("the proposal's tx does not decode: {e}")))?;
    if tx.chain_id != p.chain_id {
        return Err(refused(format!("the transaction is for chain {}, the proposal says chain {}", tx.chain_id, p.chain_id)));
    }
    if !matches!(tx.action, Action::None) {
        return Err(refused("the transaction carries an action; a private multisig proposal is a payment from its bundle alone"));
    }
    let bundle = tx.bundle.as_ref().ok_or_else(|| refused("the transaction carries no bundle"))?;
    if p.binding_domain > BindingDomain::MAX_VERSION {
        return Err(invalid(format!("binding domain version {}; this build knows 0..={}", p.binding_domain, BindingDomain::MAX_VERSION)));
    }
    let genesis = Hash::from_hex(&p.genesis).map_err(|_| invalid("the proposal's genesis is not a 32-byte hash"))?;
    let binding = tx.binding(&BindingDomain::for_version(p.binding_domain, genesis));
    if parse_binding(&p.binding)? != binding {
        return Err(refused("the transaction does not hash to the proposal's binding"));
    }
    let signing_message = msauth::signing_message(&binding);
    if hex::decode(&p.signing_message).ok().as_deref() != Some(&signing_message[..]) {
        return Err(refused("the proposal's signing_message is not its binding's"));
    }

    // 4. The account.
    let nk = policy.nk();
    let salt = parse_word8(&p.salt)?;
    let c = msauth::auth_commit(&nk, &salt);
    if bundle.auth_commit != c || parse_word8(&p.auth_commit)? != c {
        return Err(refused("the proposal's auth_commit is not this policy's account"));
    }
    // The digest the bundle proof must publish, recomputed from the bundle, never trusted.
    let digest = hidden_bundle_digest_v3(&HiddenDigestInputV3 {
        base: HiddenDigestInput {
            anchor: bundle.anchor,
            nullifiers: bundle.nullifiers,
            commitments: bundle.commitments,
            fee: bundle.fee,
            burn_a: bundle.burn_a,
            burn_r: bundle.burn_r,
            burn_asset: bundle.burn_asset,
            time: bundle.time,
        },
        auth_commit: c,
    });
    if parse_word8(&p.expected)? != digest {
        return Err(refused("the proposal's expected digest is not its bundle's"));
    }

    // 5. Every output, as the account.
    let vk = ViewingKey { nk };
    let scan_key = vk.scan_key();
    let account = policy.address();
    let mut opened: Vec<(Note, String)> = Vec::with_capacity(bundle.envelopes.len());
    for (slot, (env, cm)) in bundle.envelopes.iter().zip(&bundle.commitments).enumerate() {
        let env = envelope_from_core(env);
        let refuse = || refused(format!("output {slot} does not open as this account's: refusing to sign value it cannot see"));
        let (key, note) = env.open_as_sender_with(*cm, &scan_key).ok_or_else(refuse)?;
        if note.commitment() != *cm {
            return Err(refuse());
        }
        opened.push((note, env.memo(*cm, &key).unwrap_or_default()));
    }

    // 6. Value, from the witness.
    let words = parse_words(&p.bundle_words)?;
    if words.len() != hi::COUNT {
        return Err(refused(format!("the witness's value cannot be checked: it is {} words, a v3 bundle's is {}", words.len(), hi::COUNT)));
    }
    if words[hi::NK..hi::NK + 8] != nk || words[hi::SALT..hi::SALT + 8] != salt {
        return Err(refused("the witness's value cannot be checked: its nk or salt is not this proposal's"));
    }
    let pk_self = vk.pk();
    let mut flow: BTreeMap<u32, (u128, u128)> = BTreeMap::new();
    for (k, nf) in bundle.nullifiers.iter().enumerate() {
        let b = hi::in_slot(k);
        let w8 = |at: usize| -> Word8 { words[at..at + 8].try_into().expect("8 words") };
        let note = Note {
            pk: pk_self,
            from: w8(b + hi::S_FROM),
            amount: words[b + hi::S_AMOUNT_LO] as u64 | (words[b + hi::S_AMOUNT_HI] as u64) << 32,
            asset: words[b + hi::S_ASSET],
            time: words[b + hi::S_TIME],
            r: w8(b + hi::S_R),
        };
        if vk.nullifier(&note.commitment()) != *nf {
            return Err(refused(format!("the witness's value does not match the transaction: input {k} does not nullify to the bundle's nullifier")));
        }
        flow.entry(note.asset).or_default().0 += note.amount as u128;
    }
    for (note, _) in &opened {
        flow.entry(note.asset).or_default().1 += note.amount as u128;
    }
    flow.entry(0).or_default().1 += bundle.fee as u128 + bundle.burn_r as u128;
    flow.entry(bundle.burn_asset).or_default().1 += bundle.burn_a as u128;
    if let Some((asset, (i, o))) = flow.iter().find(|(_, (i, o))| i != o) {
        return Err(refused(format!(
            "the witness's value does not match the outputs: asset {asset} has {i} in and {o} out with the fee and burns"
        )));
    }

    // 7. Expiry.
    let time = bundle.time as u64;
    if !(time < p.expires_at && p.expires_at <= time + MAX_PROOF_WINDOW_BLOCKS) {
        return Err(refused(format!(
            "the proposal expires at {}, outside its bundle's window ({time}, {}]",
            p.expires_at,
            time + MAX_PROOF_WINDOW_BLOCKS
        )));
    }

    // 8. The payees the signer named, if any.
    let mut outputs = Vec::with_capacity(opened.len());
    for (slot, (n, memo)) in opened.iter().enumerate() {
        let to_account = n.pk == account.pk;
        let matches = if expected_recipients.is_empty() || to_account || n.amount == 0 {
            None
        } else {
            let e = expected_recipients.iter().find(|e| e.address.pk == n.pk).ok_or_else(|| {
                refused(format!("output {slot} pays {}, not an expected recipient", owner_fingerprint(&n.pk)))
            })?;
            Some(format!("{} ({})", e.address.fingerprint(), amount_text(n.amount, n.asset)))
        };
        outputs.push(OutputSummary { owner_fingerprint: owner_fingerprint(&n.pk), to_account, amount: n.amount, asset: n.asset, memo: memo.clone(), matches });
    }

    // Every expected recipient is paid, and an amount pin is met exactly (asset 0 only).
    for e in expected_recipients {
        let paying: Vec<_> = opened.iter().filter(|(n, _)| n.pk == e.address.pk && n.pk != account.pk && n.amount > 0).map(|(n, _)| n).collect();
        let fp = e.address.fingerprint();
        if paying.is_empty() {
            return Err(refused(format!("expected recipient {fp} is not paid")));
        }
        if let Some(want) = e.amount {
            if paying.iter().any(|n| n.asset != 0) {
                return Err(refused(format!("expected recipient {fp}: amount pin on a non-RAND output")));
            }
            let sum = paying.iter().try_fold(0u64, |a, n| a.checked_add(n.amount));
            if sum != Some(want) {
                let got = sum.map(|v| format!("{} RAND", format_amount(v))).unwrap_or_else(|| "more than u64".to_string());
                return Err(refused(format!("expected recipient {fp} is paid {got}, not {} RAND", format_amount(want))));
            }
        }
    }

    Ok(ProposalSummary {
        chain_id: p.chain_id,
        genesis: genesis.to_hex(),
        recipients_checked: !expected_recipients.is_empty(),
        outputs,
        fee: bundle.fee,
        burns: Burns { burn_a: bundle.burn_a, burn_asset: bundle.burn_asset, burn_r: bundle.burn_r },
        expires_at: p.expires_at,
        signing_message,
        policy_fingerprint: account.fingerprint().to_string(),
    })
}

/// [`check_proposal`], then the signer's share: the Dilithium2 key derived from `signer_seed`
/// (`dilithium2::Keypair::generate(Some(seed))`, as `rand-node keygen` files hold it), refused
/// unless it is one of `policy.signers`, signing `signing_message` deterministically. Returns
/// `(index, 2 420-byte signature)`. Checks no payee: [`sign_expecting`] with an empty list.
pub fn sign(proposal_json: &str, policy_json: &str, signer_seed: &[u8; 32]) -> Result<(u8, Vec<u8>), MsigError> {
    sign_expecting_addresses(proposal_json, policy_json, signer_seed, &[])
}

/// [`sign`] after [`check_proposal_expecting`]: refused unless every value-moving, non-change
/// output pays one of `expected_recipients` (pasted `rand1…[:AMOUNT]`; when not empty).
pub fn sign_expecting<S: AsRef<str>>(proposal_json: &str, policy_json: &str, signer_seed: &[u8; 32], expected_recipients: &[S]) -> Result<(u8, Vec<u8>), MsigError> {
    sign_expecting_addresses(proposal_json, policy_json, signer_seed, &parse_expected_recipients(expected_recipients)?)
}

/// [`sign_expecting`] over addresses already parsed.
pub fn sign_expecting_addresses(proposal_json: &str, policy_json: &str, signer_seed: &[u8; 32], expected_recipients: &[ExpectedRecipient]) -> Result<(u8, Vec<u8>), MsigError> {
    let (proposal, policy) = parse_inputs(proposal_json, policy_json)?;
    let summary = check(&proposal, &policy, expected_recipients)?;
    let key = Keypair::from_seed(*signer_seed).map_err(|e| invalid(format!("the signer seed: {e}")))?;
    let index = policy
        .pks()?
        .iter()
        .position(|pk| pk[..] == key.public_key().as_bytes()[..])
        .ok_or_else(|| refused("this key is not one of the policy's signers"))?;
    let sig = key.sign(&summary.signing_message);
    Ok((index as u8, sig.as_bytes().to_vec()))
}

/// A share `"i:hex"` as `(i, signature bytes)`; the signature's length is checked.
pub fn parse_share(share: &str) -> Result<(u8, Vec<u8>), MsigError> {
    let (i, sig) = share.split_once(':').ok_or_else(|| invalid("a share is index:hex"))?;
    let i: u8 = i.trim().parse().map_err(|_| invalid(format!("share index {i:?} is not a small number")))?;
    let sig = hex::decode(sig.trim()).map_err(|_| invalid(format!("signer {i}'s share is not hex")))?;
    if sig.len() != SIG_BYTES {
        return Err(invalid(format!("signer {i}'s signature is {} bytes, a Dilithium2 signature is {SIG_BYTES}", sig.len())));
    }
    Ok((i, sig))
}

/// [`check_proposal`], then `share` (`"i:hex"`): `i` names one of the policy's signers and the
/// signature verifies under that key over the proposal's signing message.
pub fn verify_share(proposal_json: &str, policy_json: &str, share: &str) -> Result<(), MsigError> {
    let (proposal, policy) = parse_inputs(proposal_json, policy_json)?;
    let summary = check(&proposal, &policy, &[])?;
    let (i, sig) = parse_share(share)?;
    let pks = policy.pks()?;
    let pk = pks.get(i as usize).ok_or_else(|| refused(format!("signer {i} is not in this policy (it has {} signers)", pks.len())))?;
    let pk = PublicKey::from_bytes(pk).map_err(|e| invalid(e.to_string()))?;
    let sig = Signature::from_bytes(&sig).map_err(|e| invalid(e.to_string()))?;
    if !pk.verify(&summary.signing_message, &sig) {
        return Err(refused(format!("signer {i}'s signature does not verify over this proposal")));
    }
    Ok(())
}
