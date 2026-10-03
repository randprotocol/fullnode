//! RPL-3 perps from the wallet's side: what `rand perp …` builds, signs, checks and proves
//! (`docs/cli.md`, the `rand perp` section).
//!
//! - **Keys.** A trading key — and a validator's oracle key — is a Dilithium2 key file in
//!   `rand-node keygen`'s `{seed, address, public_key}` shape, read and written by the token
//!   authority's own loader and writer ([`wallet::load_authority_key`],
//!   [`wallet::write_authority_key`]). The account a key owns is [`account_id`] of its public key.
//! - **Signed actions.** An order, a cancel, a withdrawal request and an oracle submission are
//!   bundle-less: each is signed over [`Transaction::perp_sign_message`] ([`sign_perp`]) and sent
//!   as is ([`submit_perp_signed`]). Nonces come from the account the node serves
//!   ([`next_nonce`]); an oracle's is the wall clock in milliseconds.
//! - **Deposits** ride a bundle that burns the collateral ([`submit_perp_deposit`]).
//! - **Withdrawals** carry the note the chain will pay: this wallet's address, a fresh blinding
//!   `r`, the request's `time` (a chain height, as a bundle's `time` is) and an envelope sealed to
//!   this wallet ([`withdraw_action`]). The ledger pays it as
//!   `note_commitment(recipient.pk, PERP_FROM, amount, collateral, time, r)` and appends the
//!   request's envelope beside it, so the ordinary scan's trial decryption finds it. The engine
//!   pays a request in full or not at all, so the sealed amount is the paid amount.
//! - **State proofs** ([`prove_and_submit_state_proof`]): a `perp-prover` job is re-hashed here —
//!   roots, block digests, payouts digest — and held to the chain's proved root and recorded
//!   digests before a cycle is proved, then proved with the engine image and submitted.

use crate::wallet::{self, Burn, NoteStore, Proving, Submission, Wallet};
use crate::RpcClient;
use anyhow::{anyhow, bail, Context, Result};
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::ledger::perps::{
    account_id, domain, payouts_digest, perp_digest, state_proof_segment, PerpOrderBody,
    PerpPayout, PerpPrice, MAX_PERP_PAYOUTS, PERP_FROM,
};
use randprotocol_core::notes::{word8_from_hex, EnvelopeFormat, Word8};
use randprotocol_core::{Action, BindingDomain, Hash, Keypair, PublicKey, Signature, Transaction};
use randprotocol_zkvm::address::seal_note_as;
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::{FriProfile, Tier, TIERS};
use randprotocol_zkvm::notes::Note;
use randprotocol_zkvm::viewing::TxKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::time::Instant;

// ---------------------------------------------------------------- keys and signatures

/// A trading or oracle key: a Dilithium2 key file in `rand-node keygen`'s shape.
pub fn load_dilithium_key(path: &Path) -> Result<Keypair> {
    wallet::load_authority_key(path)
}

/// `rand perp keygen`: a fresh Dilithium2 key file at `path` (mode 0600, refusing to overwrite),
/// in the shape [`load_dilithium_key`] and `rand-node` read.
pub fn write_dilithium_key(path: &Path) -> Result<Keypair> {
    let kp = Keypair::generate();
    wallet::write_authority_key(&kp, path)?;
    Ok(kp)
}

/// `action` with its signature made by `kp` over [`Transaction::perp_sign_message`] — the
/// message the ledger verifies, over the chain's binding domain (BIND-1: `domain` is what
/// [`RpcClient::binding_domain`] answers for the chain). An action that is not one of the four
/// signed perp variants is returned unchanged.
pub fn sign_perp(
    domain: &BindingDomain,
    chain_id: u64,
    kp: &Keypair,
    mut action: Action,
) -> Action {
    let Some(msg) = Transaction::perp_sign_message(domain, chain_id, &action) else {
        return action;
    };
    // `perp_sign_message` answers `Some` for exactly these four variants (its own match is
    // exhaustive over `Action`), so the `else` is unreachable for a message that was made.
    let (Action::PerpOrder { signature, .. }
    | Action::PerpCancel { signature, .. }
    | Action::PerpWithdraw { signature, .. }
    | Action::PerpOracle { signature, .. }) = &mut action
    else {
        return action;
    };
    *signature = kp.sign(msg.as_bytes());
    action
}

// ---------------------------------------------------------------- the node's answers

/// A u64 off an RPC answer, a JSON number or a decimal string.
fn u64_of(v: &Value, what: &str) -> Result<u64> {
    crate::amount_field(v).ok_or_else(|| anyhow!("rand_getPerps: {what} is not a u64 ({v})"))
}

fn word8_of(v: &Value, what: &str) -> Result<Word8> {
    v.as_str()
        .and_then(word8_from_hex)
        .ok_or_else(|| anyhow!("{what} is not 64 hex characters ({v})"))
}

/// The fields of `rand_getPerps` the wallet acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerpsState {
    pub collateral_asset: u32,
    pub max_tier: u8,
    pub max_window_blocks: u64,
    pub proved_root: Word8,
    pub proved_height: u64,
}

impl PerpsState {
    /// Decode `rand_getPerps`; a chain without the `perps` section (`{"enabled": false}`) is an
    /// error, since every perp action is refused there.
    pub fn from_json(v: &Value) -> Result<PerpsState> {
        if v["enabled"] != Value::Bool(true) {
            bail!("this chain has no perps section (rand_getPerps: enabled is not true)");
        }
        Ok(PerpsState {
            collateral_asset: u32::try_from(u64_of(&v["collateral_asset"], "collateral_asset")?)?,
            max_tier: u8::try_from(u64_of(&v["max_tier"], "max_tier")?)?,
            max_window_blocks: u64_of(&v["max_window_blocks"], "max_window_blocks")?,
            proved_root: word8_of(&v["proved_root"], "rand_getPerps.proved_root")?,
            proved_height: u64_of(&v["proved_height"], "proved_height")?,
        })
    }

    pub async fn fetch(rpc: &RpcClient) -> Result<PerpsState> {
        PerpsState::from_json(&rpc.get_perps().await?)
    }
}

/// One trading account as `rand_getPerpAccount` serves it (the fields the wallet reads).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct PerpAccountJson {
    pub account: String,
    pub trading_key: String,
    #[serde(deserialize_with = "crate::u64_string_or_number")]
    pub nonce_high: u64,
}

/// The account `id` as the node holds it, `None` when it holds none.
pub async fn fetch_account(rpc: &RpcClient, id: &Word8) -> Result<Option<PerpAccountJson>> {
    rpc.get_perp_account(id)
        .await?
        .map(|v| serde_json::from_value(v).context("decoding rand_getPerpAccount"))
        .transpose()
}

/// The nonce the next signed action of an account takes: one past its highest used nonce, or
/// 1 for an account the exchange does not hold yet. Always free in the ledger's window.
pub fn next_nonce(account: Option<&PerpAccountJson>) -> u64 {
    account.map_or(1, |a| a.nonce_high.saturating_add(1))
}

/// `--nonce` when given, else [`next_nonce`] of the account as the node holds it now.
pub async fn resolve_nonce(rpc: &RpcClient, account: &Word8, explicit: Option<u64>) -> Result<u64> {
    match explicit {
        Some(n) => Ok(n),
        None => Ok(next_nonce(fetch_account(rpc, account).await?.as_ref())),
    }
}

// ---------------------------------------------------------------- building actions

/// An order body from the command line: `side` buy|sell, `kind` limit|market, `tif`
/// gtc|ioc|post. A limit order needs a price; a market order takes none (the ledger requires
/// its price be 0).
#[allow(clippy::too_many_arguments)]
pub fn order_body(
    nonce: u64,
    market: u32,
    side: &str,
    kind: &str,
    tif: &str,
    reduce_only: bool,
    price: Option<u64>,
    size: u64,
) -> Result<PerpOrderBody> {
    let side = match side {
        "buy" => 0,
        "sell" => 1,
        o => bail!("--side {o}: buy or sell"),
    };
    let kind_code = match kind {
        "limit" => 0,
        "market" => 1,
        o => bail!("--kind {o}: limit or market"),
    };
    let tif = match tif {
        "gtc" => 0,
        "ioc" => 1,
        "post" => 2,
        o => bail!("--tif {o}: gtc, ioc or post"),
    };
    let price = match (kind_code, price) {
        (0, Some(p)) if p > 0 => p,
        (0, _) => bail!("a limit order needs --price (in ticks' units, above 0)"),
        (_, None) => 0,
        (_, Some(_)) => bail!("a market order takes no --price"),
    };
    if size == 0 {
        bail!("--size 0 orders nothing");
    }
    Ok(PerpOrderBody {
        nonce,
        market,
        side,
        kind: kind_code,
        tif,
        reduce_only,
        price,
        size,
    })
}

/// A signed order of the account `kp` owns.
pub fn order_action(
    domain: &BindingDomain,
    chain_id: u64,
    kp: &Keypair,
    body: PerpOrderBody,
) -> Action {
    sign_perp(
        domain,
        chain_id,
        kp,
        Action::PerpOrder {
            account: account_id(kp.public_key()),
            body,
            signature: Signature::empty(),
        },
    )
}

/// A signed cancel of the order with nonce `target`, in the cancel's own slot `nonce`.
pub fn cancel_action(
    domain: &BindingDomain,
    chain_id: u64,
    kp: &Keypair,
    nonce: u64,
    target: u64,
) -> Action {
    sign_perp(
        domain,
        chain_id,
        kp,
        Action::PerpCancel {
            account: account_id(kp.public_key()),
            nonce,
            target,
            signature: Signature::empty(),
        },
    )
}

/// A signed withdrawal request of `amount` (collateral units) from the account `kp` owns, paid
/// to this wallet: the note the chain will append — `PERP_FROM`, `asset` (the collateral), `time`
/// (a chain height in the bundle time window, as `TokenMint`'s is) and a fresh blinding — and
/// the envelope sealed to this wallet that the ledger emits beside it. Returns the action and
/// that note.
#[allow(clippy::too_many_arguments)]
pub fn withdraw_action(
    w: &Wallet,
    kp: &Keypair,
    domain: &BindingDomain,
    chain_id: u64,
    nonce: u64,
    amount: u64,
    asset: u32,
    time: u32,
    format: EnvelopeFormat,
) -> Result<(Action, Note)> {
    if amount == 0 {
        bail!("a withdrawal of 0 moves nothing");
    }
    let recipient = w.address.clone();
    let note = Note::new(recipient.pk, PERP_FROM, amount, asset, time);
    let envelope = seal_note_as(format, &w.vk, &recipient, &note, &TxKey::random(), "")
        .map_err(|e| anyhow!("sealing the withdrawal envelope: {e}"))?;
    let action = Action::PerpWithdraw {
        account: account_id(kp.public_key()),
        nonce,
        amount,
        recipient,
        r: note.r,
        time,
        envelope,
        signature: Signature::empty(),
    };
    Ok((sign_perp(domain, chain_id, kp, action), note))
}

/// `--price <market>=<units>[,…]`: one price per market, positive, sorted ascending by market
/// (the ledger refuses an unordered or repeated list).
pub fn parse_prices(text: &str) -> Result<Vec<PerpPrice>> {
    let mut out = Vec::new();
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (m, p) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("--price {part}: expected <market>=<units>"))?;
        let market: u32 = m
            .trim()
            .parse()
            .with_context(|| format!("--price {part}: market is not a number"))?;
        let price: u64 = p
            .trim()
            .parse()
            .with_context(|| format!("--price {part}: price is not a number of units"))?;
        if price == 0 {
            bail!("--price {part}: a price of 0 reads as no price");
        }
        out.push(PerpPrice { market, price });
    }
    if out.is_empty() {
        bail!("--price: at least one <market>=<units>");
    }
    out.sort_by_key(|p| p.market);
    if out.windows(2).any(|w| w[0].market == w[1].market) {
        bail!("--price: a market is priced twice");
    }
    Ok(out)
}

/// A validator's signed oracle submission.
pub fn oracle_action(
    domain: &BindingDomain,
    chain_id: u64,
    kp: &Keypair,
    prices: Vec<PerpPrice>,
    nonce: u64,
) -> Action {
    sign_perp(
        domain,
        chain_id,
        kp,
        Action::PerpOracle {
            validator: kp.public_key().clone(),
            prices,
            nonce,
            signature: Signature::empty(),
        },
    )
}

// ---------------------------------------------------------------- submitting

/// A deposit of `amount` of the collateral into the account `trading_key` owns: one bundle that
/// pays the RAND fee and burns `amount` — through `burn_r` when the collateral is RAND (the
/// `Bond` shape, [`wallet::submit`]), through `burn_a`/`burn_asset` for a token (the
/// `TokenBurn` shape) — carrying `Action::PerpDeposit`.
#[allow(clippy::too_many_arguments)]
pub async fn submit_perp_deposit(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    trading_key: &PublicKey,
    amount: u64,
    collateral_asset: u32,
    fee: u64,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if amount == 0 {
        bail!("a deposit of 0 credits nothing");
    }
    let action = Action::PerpDeposit {
        trading_key: trading_key.clone(),
    };
    if collateral_asset == 0 {
        return wallet::submit(
            rpc,
            w,
            store,
            None,
            action,
            fee,
            Burn::rand(amount),
            profile,
            proving,
            chain_id,
            wait,
        )
        .await;
    }
    let spend = wallet::Spend {
        asset: collateral_asset,
        to: None,
        memo: "",
        fee,
        burn_a: amount,
        burn_r: 0,
        prover_fee: None,
    };
    let burn = Burn::Asset {
        index: collateral_asset,
        amount,
    };
    wallet::submit_spend(
        rpc, w, store, spend, action, burn, profile, proving, None, chain_id, wait,
    )
    .await
}

/// A signed perp action (order, cancel, withdrawal, oracle) or a state proof, sent bundle-less;
/// with `wait`, until it commits (a rejection is an error).
pub async fn submit_perp_signed(
    rpc: &RpcClient,
    chain_id: u64,
    action: Action,
    wait: bool,
) -> Result<Hash> {
    crate::governance::submit_bundle_less(rpc, chain_id, action, wait).await
}

// ---------------------------------------------------------------- state proofs

/// The block of a [`ProveJob`]: its height and its perp input words (`rand_getPerpInputs`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobBlock {
    pub height: u64,
    pub words: Vec<u32>,
}

/// `perp-prover`'s prove job (`crates/perp-prover/src/job.rs`), field for field: the window
/// `from_height + 1 ..= to_height`, the engine state words either side of it, the blocks' words,
/// the payouts (`request` as 64 hex) and the fees. Nothing in it is a hash; [`job_segment`]
/// computes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProveJob {
    pub from_height: u64,
    pub to_height: u64,
    pub state_before: Vec<u32>,
    pub state_after: Vec<u32>,
    pub blocks: Vec<JobBlock>,
    pub payouts: Vec<PerpPayout>,
    pub fees: u64,
}

impl ProveJob {
    pub fn load(path: &Path) -> Result<ProveJob> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("{} is not a perp prove job", path.display()))
    }

    /// The job's own consistency: a non-empty window of consecutive heights `from + 1 ..= to`,
    /// at most [`MAX_PERP_PAYOUTS`] payouts, each request at most once, in the engine's order (the
    /// ledger's rules for a state proof's list: the digest binds the order, nothing sorts it).
    pub fn check(&self) -> Result<()> {
        if self.to_height <= self.from_height || self.blocks.is_empty() {
            bail!(
                "the job covers no block ({}..={})",
                self.from_height.saturating_add(1),
                self.to_height
            );
        }
        let expected = self.from_height.saturating_add(1)..=self.to_height;
        if self.blocks.len() as u64 != self.to_height - self.from_height
            || self.blocks.iter().zip(expected).any(|(b, h)| b.height != h)
        {
            bail!(
                "the job's blocks are not the consecutive heights {}..={}",
                self.from_height.saturating_add(1),
                self.to_height
            );
        }
        if self.payouts.len() > MAX_PERP_PAYOUTS {
            bail!(
                "the job pays {} withdrawals; a state proof pays at most {MAX_PERP_PAYOUTS}",
                self.payouts.len()
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        if !self.payouts.iter().all(|p| seen.insert(p.request)) {
            bail!("the job's payouts name a request more than once");
        }
        Ok(())
    }
}

/// The public segment `job` proves over, `(segment, R_from, R_to)`: both roots and every block
/// digest recomputed from the job's words with `executor`'s Poseidon2 ([`perp_digest`], the
/// guest's chunking), then [`state_proof_segment`] — the segment the ledger builds from its own
/// proved root and recorded digests.
pub fn job_segment(
    job: &ProveJob,
    executor: &dyn ConfidentialExecutor,
) -> (Vec<u32>, Word8, Word8) {
    let r_from = perp_digest(executor, domain::STATE, &job.state_before);
    let r_to = perp_digest(executor, domain::STATE, &job.state_after);
    let digests: Vec<Word8> = job
        .blocks
        .iter()
        .map(|b| perp_digest(executor, domain::BLOCK, &b.words))
        .collect();
    let payouts = payouts_digest(executor, &job.payouts);
    let segment = state_proof_segment(
        job.from_height,
        job.to_height,
        &r_from,
        &r_to,
        &payouts,
        job.fees,
        &digests,
    );
    (segment, r_from, r_to)
}

/// The guest's private witness: `[n_state, state…, n_blocks, (n_words, block…)*]`.
pub fn job_witness(job: &ProveJob) -> Vec<u32> {
    let mut w = Vec::with_capacity(
        2 + job.state_before.len() + job.blocks.iter().map(|b| 1 + b.words.len()).sum::<usize>(),
    );
    w.push(job.state_before.len() as u32);
    w.extend_from_slice(&job.state_before);
    w.push(job.blocks.len() as u32);
    for b in &job.blocks {
        w.push(b.words.len() as u32);
        w.extend_from_slice(&b.words);
    }
    w
}

/// `rand perp prove`: check `job` against the chain, prove it with the engine at `image`, and
/// (unless `!submit`) submit the `PerpStateProof` — waiting for it to commit with `wait`.
/// Returns the transaction hash, the tier and the proof's size.
///
/// Refused, with nothing proved, when the job is not a consecutive window; when it does not
/// start at the chain's `proved_height` or its `R_from` is not the chain's `proved_root` (the
/// prover rolls back on this); when it spans more than `max_window_blocks`; when any block's
/// recomputed digest differs from the one `rand_getPerpInputs` serves, or the node serves none;
/// and when the engine's dry run does not report the window's block count. After proving,
/// refused when the tier is over the chain's `max_tier` or the proof over `max_proof_bytes`.
#[allow(clippy::too_many_arguments)]
pub async fn prove_and_submit_state_proof(
    rpc: &RpcClient,
    chain_id: u64,
    image: &Path,
    job: &ProveJob,
    tier: Option<u8>,
    profile: FriProfile,
    submit: bool,
    wait: bool,
) -> Result<(Hash, u8, usize)> {
    job.check()?;
    let executor = ZkExecutor::new(profile);
    let (segment, r_from, r_to) = job_segment(job, &executor);
    let state = PerpsState::fetch(rpc).await?;
    if job.from_height != state.proved_height {
        bail!(
            "the job starts at height {}; the chain's proved_height is {}",
            job.from_height,
            state.proved_height
        );
    }
    if r_from != state.proved_root {
        bail!(
            "the job's R_from {} is not the chain's proved_root {}",
            randprotocol_core::notes::word8_to_hex(&r_from),
            randprotocol_core::notes::word8_to_hex(&state.proved_root)
        );
    }
    let span = job.to_height - job.from_height;
    if span > state.max_window_blocks {
        bail!(
            "the job covers {span} blocks; this chain's max_window_blocks is {}",
            state.max_window_blocks
        );
    }
    for (b, block) in job.blocks.iter().enumerate() {
        let served = rpc.get_perp_inputs(block.height).await?.ok_or_else(|| {
            anyhow!(
                "block {}: the node serves no perp inputs for it",
                block.height
            )
        })?;
        let digest = word8_of(&served["digest"], "rand_getPerpInputs.digest")?;
        if segment[32 + 8 * b..40 + 8 * b] != digest {
            bail!(
                "block {}: the job's words digest differently from the chain's recorded D_h",
                block.height
            );
        }
    }
    if let Some(t) = tier {
        if !TIERS.contains(&usize::from(t)) || t > state.max_tier {
            bail!(
                "--tier {t}: one of {TIERS:?}, at most the chain's max_tier {}",
                state.max_tier
            );
        }
    }
    let bytes = std::fs::read(image)
        .with_context(|| format!("reading the engine image {}", image.display()))?;
    let program = randprotocol_zkvm::codec::program_from_bytes(&bytes)
        .map_err(|e| anyhow!("{} is not a program image: {e}", image.display()))?;
    let witness = job_witness(job);
    // A dry run first: seconds against a proof's minutes, and the engine's own verdict on the
    // window before anything is spent on it.
    let exec = randprotocol_zkvm::emulator::execute(
        &program,
        &witness,
        &segment,
        Tier(*TIERS.last().unwrap()).max_cycles(),
    )
    .map_err(|e| anyhow!("the engine does not run over this window: {e:?}"))?;
    if exec.outputs[0] != randprotocol_core::ledger::perps::PERP_VERSION
        || u64::from(exec.outputs[1]) != span
    {
        bail!(
            "the engine refused this window (outputs {:?})",
            exec.outputs
        );
    }
    eprintln!(
        "dry run: {} cycles, outputs {:?}",
        exec.cycles(),
        exec.outputs
    );
    drop(exec);
    // M2: the tier the run needs, from the dry run's workload (the prover's own choice), held to
    // the chain's max_tier before minutes are spent proving a window the chain would refuse.
    let needed = randprotocol_zkvm::executor::dry_run_call(&program, &witness, &segment)
        .map_err(|e| anyhow!("sizing the window: {e}"))?
        .tier;
    let tier = pick_tier(tier, needed, state.max_tier)?;
    let started = Instant::now();
    let (proof, _, proved_tier) =
        randprotocol_zkvm::executor::prove_perp(profile, &program, &witness, &segment, Some(tier))
            .map_err(|e| anyhow!("proving the window: {e}"))?;
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "proved {}..={} at tier {proved_tier}: {} bytes in {secs:.1} s",
        job.from_height + 1,
        job.to_height,
        proof.len()
    );
    if proved_tier > state.max_tier {
        bail!(
            "the proof is tier {proved_tier}, over this chain's max_tier {}: nothing submitted",
            state.max_tier
        );
    }
    let proof_bytes = proof.len();
    wallet::check_proof_size(proof_bytes, wallet::proof_cap(rpc.limits().await?.as_ref()))?;
    let action = Action::PerpStateProof {
        from_height: job.from_height,
        to_height: job.to_height,
        new_root: r_to,
        payouts: job.payouts.clone(),
        fees: job.fees,
        proof,
    };
    let hash = if submit {
        submit_perp_signed(rpc, chain_id, action, wait).await?
    } else {
        Transaction {
            chain_id,
            bundle: None,
            action,
        }
        .hash()
    };
    Ok((hash, proved_tier, proof_bytes))
}

/// The tier `rand perp prove` proves at: `--tier` when given, else `needed`, the smallest tier
/// the dry run fits. Refused, before anything is proved, when that is below `needed` (the run
/// does not fit it) or above the chain's `max_tier` (the chain would refuse the proof).
pub fn pick_tier(explicit: Option<u8>, needed: u8, max_tier: u8) -> Result<u8> {
    let tier = explicit.unwrap_or(needed);
    if tier < needed {
        bail!("--tier {tier}: the window needs tier {needed}");
    }
    if tier > max_tier {
        bail!(
            "the window needs tier {tier}, over this chain's max_tier {max_tier}: nothing proved \
             (prove a shorter window)"
        );
    }
    Ok(tier)
}

/// `rand perp genesis-root`: the engine state root of `words` (`perp_digest(STATE, words)`), the
/// genesis `perps.genesis_root` for a state `perp-prover genesis-state` wrote.
pub fn genesis_root(words: &[u32]) -> Word8 {
    perp_digest(&ZkExecutor::new(FriProfile::Test), domain::STATE, words)
}

/// A JSON array of u32 words from `path`.
pub fn read_words(path: &Path) -> Result<Vec<u32>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("{} is not a JSON array of u32 words", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rpc::{rpc_fn, Reply};
    use randprotocol_core::ledger::perps::{
        account_id, domain, payouts_digest, perp_digest, state_proof_segment, PerpOrderBody,
        PerpPrice, PERP_FROM,
    };
    use randprotocol_core::notes::{word8_from_hex, word8_to_hex, EnvelopeFormat};
    use randprotocol_core::{Signature, Transaction};
    use randprotocol_zkvm::executor::ZkExecutor;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn hasher() -> ZkExecutor {
        ZkExecutor::new(FriProfile::Test)
    }

    /// A window from proved height 5 over blocks 6 and 7, with one payout — the shape
    /// `perp-prover`'s `build_job` writes.
    fn job() -> ProveJob {
        ProveJob {
            from_height: 5,
            to_height: 7,
            state_before: vec![1, 2, 3, 4, 5],
            state_after: vec![1, 2, 3, 4, 6, 7],
            blocks: vec![
                JobBlock {
                    height: 6,
                    words: vec![5, 6, 0, 0, 0, 0, 0, 0, 0],
                },
                JobBlock {
                    height: 7,
                    words: vec![5, 7, 0, 9, 0, 0, 0, 0, 0, 1, 7, 0],
                },
            ],
            payouts: vec![PerpPayout {
                request: [3; 8],
                amount: 42,
            }],
            fees: 11,
        }
    }

    #[test]
    fn a_jobs_payouts_may_be_in_any_order_but_name_a_request_once() {
        let mut j = job();
        j.payouts = vec![
            PerpPayout {
                request: [5; 8],
                amount: 1,
            },
            PerpPayout {
                request: [3; 8],
                amount: 2,
            },
        ];
        j.check()
            .expect("descending request ids are the engine's order");
        j.payouts.push(PerpPayout {
            request: [5; 8],
            amount: 1,
        });
        let e = j.check().unwrap_err().to_string();
        assert!(e.contains("more than once"), "{e}");
    }

    /// A node serving `job`'s blocks the way `rand_getPerpInputs` does (the digest is the
    /// node's own `perp_digest(BLOCK, words)`), a `rand_getPerps` whose proved root and height
    /// are `root`/`height`, and a flag set if anything is ever submitted.
    async fn node(
        job: &ProveJob,
        root: Word8,
        height: u64,
        bad_digest_at: Option<u64>,
    ) -> (String, Arc<AtomicBool>) {
        let blocks = job.blocks.clone();
        let sent = Arc::new(AtomicBool::new(false));
        let flag = sent.clone();
        let url = rpc_fn(move |method, params| match method {
            "rand_getPerps" => Reply::Ok(json!({
                "enabled": true, "collateral_asset": 0, "max_tier": 20, "max_window_blocks": "64",
                "engine_hc": word8_to_hex(&[9; 8]), "genesis_root": word8_to_hex(&[0; 8]),
                "proved_root": word8_to_hex(&root), "proved_height": height.to_string(),
                "head_height": 9, "pending_heights": [6, 7], "markets": [], "medians": [],
                "accounts": 1, "pending_withdrawals": 1,
            })),
            "rand_getPerpInputs" => {
                let h = params[0].as_u64().unwrap();
                match blocks.iter().find(|b| b.height == h) {
                    Some(b) => {
                        let mut d = perp_digest(&hasher(), domain::BLOCK, &b.words);
                        if bad_digest_at == Some(h) {
                            d[0] ^= 1;
                        }
                        Reply::Ok(
                            json!({ "height": h, "digest": word8_to_hex(&d), "words": b.words }),
                        )
                    }
                    None => Reply::Ok(Value::Null),
                }
            }
            "rand_sendTransaction" => {
                flag.store(true, Ordering::SeqCst);
                Reply::Err(-32000, "not expected")
            }
            _ => Reply::Err(-32601, "unknown method"),
        })
        .await;
        (url, sent)
    }

    /// M2: the tier is the dry run's unless `--tier` raises it, and a window that needs more than
    /// the chain's `max_tier` is refused before proving.
    #[test]
    fn the_tier_comes_from_the_dry_run_and_is_held_to_max_tier() {
        assert_eq!(pick_tier(None, 14, 16).unwrap(), 14);
        assert_eq!(pick_tier(Some(16), 14, 16).unwrap(), 16);
        assert!(pick_tier(Some(12), 14, 16)
            .unwrap_err()
            .to_string()
            .contains("needs tier 14"));
        let e = pick_tier(None, 18, 16).unwrap_err().to_string();
        assert!(
            e.contains("max_tier 16") && e.contains("nothing proved"),
            "{e}"
        );
    }

    #[test]
    fn sign_perp_signs_exactly_the_perp_sign_message() {
        let kp = Keypair::generate();
        let account = account_id(kp.public_key());
        let body = PerpOrderBody {
            nonce: 3,
            market: 0,
            side: 1,
            kind: 0,
            tif: 0,
            reduce_only: false,
            price: 100,
            size: 2,
        };
        let unsigned = Action::PerpOrder {
            account,
            body,
            signature: Signature::empty(),
        };
        let d = BindingDomain::ChainId;
        let signed = sign_perp(&d, 7, &kp, unsigned.clone());
        assert_eq!(
            signed.perp_unsigned(),
            unsigned.perp_unsigned(),
            "only the signature is filled in"
        );
        let Action::PerpOrder { signature, .. } = &signed else {
            panic!("still an order")
        };
        let msg = Transaction::perp_sign_message(&d, 7, &signed).unwrap();
        assert!(
            kp.public_key().verify(msg.as_bytes(), signature),
            "verifies as the ledger checks it"
        );
        // BIND-1: on a chain whose genesis binds its hash the signature is over that domain, and
        // a chain-id signature is not one there.
        let g = BindingDomain::Genesis(Hash([0x5a; 32]));
        let bound = sign_perp(&g, 7, &kp, unsigned.clone());
        let Action::PerpOrder {
            signature: bound_sig,
            ..
        } = &bound
        else {
            panic!("still an order")
        };
        let bound_msg = Transaction::perp_sign_message(&g, 7, &bound).unwrap();
        assert!(kp.public_key().verify(bound_msg.as_bytes(), bound_sig));
        assert!(
            !kp.public_key().verify(bound_msg.as_bytes(), signature),
            "a domain-0 signature does not verify under domain 1"
        );
        // The two unsigned perp actions come back exactly as they went in.
        let deposit = Action::PerpDeposit {
            trading_key: kp.public_key().clone(),
        };
        assert_eq!(sign_perp(&d, 7, &kp, deposit.clone()), deposit);
        let proof = Action::PerpStateProof {
            from_height: 1,
            to_height: 2,
            new_root: [5; 8],
            payouts: vec![PerpPayout {
                request: [1; 8],
                amount: 2,
            }],
            fees: 3,
            proof: vec![1, 2, 3],
        };
        assert_eq!(sign_perp(&d, 7, &kp, proof.clone()), proof);
        let other = Transaction::perp_sign_message(&d, 8, &signed).unwrap();
        assert!(
            !kp.public_key().verify(other.as_bytes(), signature),
            "bound to the chain"
        );
    }

    #[tokio::test]
    async fn job_segment_recomputes_the_digests_the_node_serves() {
        let job = job();
        let h = hasher();
        let (segment, r_from, r_to) = job_segment(&job, &h);
        assert_eq!(r_from, perp_digest(&h, domain::STATE, &job.state_before));
        assert_eq!(r_to, perp_digest(&h, domain::STATE, &job.state_after));
        let (url, _) = node(&job, r_from, 5, None).await;
        let rpc = RpcClient::new(url);
        let mut served = Vec::new();
        for (b, block) in job.blocks.iter().enumerate() {
            let v = rpc.get_perp_inputs(block.height).await.unwrap().unwrap();
            let d = word8_from_hex(v["digest"].as_str().unwrap()).unwrap();
            assert_eq!(
                segment[32 + 8 * b..40 + 8 * b],
                d,
                "D_{} as the node records it",
                block.height
            );
            served.push(d);
        }
        let expected = state_proof_segment(
            5,
            7,
            &r_from,
            &r_to,
            &payouts_digest(&h, &job.payouts),
            11,
            &served,
        );
        assert_eq!(segment, expected, "the ledger's segment, word for word");
    }

    #[test]
    fn the_witness_is_the_guests_private_layout() {
        let job = job();
        let w = job_witness(&job);
        let mut expected = vec![5, 1, 2, 3, 4, 5, 2, 9];
        expected.extend_from_slice(&job.blocks[0].words);
        expected.push(12);
        expected.extend_from_slice(&job.blocks[1].words);
        assert_eq!(w, expected);
    }

    #[tokio::test]
    async fn a_proof_from_another_root_is_refused_before_any_proving() {
        let job = job();
        let (url, sent) = node(&job, [0xdead; 8], 5, None).await;
        // The image does not exist: a refusal that got as far as reading it would say so.
        let image = Path::new("/nonexistent/perp-engine.image.bin");
        let e = prove_and_submit_state_proof(
            &RpcClient::new(url),
            1,
            image,
            &job,
            None,
            FriProfile::Test,
            true,
            true,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("proved_root"), "{e:#}");
        assert!(!sent.load(Ordering::SeqCst), "nothing submitted");
    }

    #[tokio::test]
    async fn a_window_from_another_height_or_over_other_inputs_is_refused() {
        let job = job();
        let r_from = perp_digest(&hasher(), domain::STATE, &job.state_before);
        let image = Path::new("/nonexistent/perp-engine.image.bin");
        let (url, _) = node(&job, r_from, 4, None).await;
        let e = prove_and_submit_state_proof(
            &RpcClient::new(url),
            1,
            image,
            &job,
            None,
            FriProfile::Test,
            true,
            true,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("proved_height"), "{e:#}");
        let (url, sent) = node(&job, r_from, 5, Some(7)).await;
        let e = prove_and_submit_state_proof(
            &RpcClient::new(url),
            1,
            image,
            &job,
            None,
            FriProfile::Test,
            true,
            true,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("block 7"), "{e:#}");
        assert!(!sent.load(Ordering::SeqCst));
        // With every check passing, the next failure is the image itself.
        let (url, _) = node(&job, r_from, 5, None).await;
        let e = prove_and_submit_state_proof(
            &RpcClient::new(url),
            1,
            image,
            &job,
            None,
            FriProfile::Test,
            true,
            true,
        )
        .await
        .unwrap_err();
        assert!(format!("{e:#}").contains("perp-engine.image.bin"), "{e:#}");
    }

    #[test]
    fn a_job_in_the_provers_format_round_trips() {
        let text = r#"{"from_height":5,"to_height":7,"state_before":[1,2,3,4,5],"state_after":[1,2,3,4,6,7],
            "blocks":[{"height":6,"words":[5,6,0,0,0,0,0,0,0]},{"height":7,"words":[5,7,0,9,0,0,0,0,0,1,7,0]}],
            "payouts":[{"request":"0300000003000000030000000300000003000000030000000300000003000000","amount":42}],
            "fees":11}"#;
        let parsed: ProveJob = serde_json::from_str(text).unwrap();
        assert_eq!(parsed, job());
        let back = serde_json::to_value(&parsed).unwrap();
        assert_eq!(
            back,
            serde_json::from_str::<Value>(text).unwrap(),
            "serialized exactly as the prover writes it"
        );
    }

    #[test]
    fn the_next_nonce_is_one_past_the_high_water_mark() {
        assert_eq!(next_nonce(None), 1);
        let a: PerpAccountJson = serde_json::from_value(json!({
            "account": word8_to_hex(&[1; 8]), "trading_key": "00", "nonce_high": 7, "used": "1", "withdrawals": []
        }))
        .unwrap();
        assert_eq!(next_nonce(Some(&a)), 8);
        let s: PerpAccountJson = serde_json::from_value(json!({
            "account": word8_to_hex(&[1; 8]), "trading_key": "00", "nonce_high": "9", "used": "1", "withdrawals": []
        }))
        .unwrap();
        assert_eq!(next_nonce(Some(&s)), 10, "a decimal string too");
    }

    #[test]
    fn order_bodies_take_the_ledgers_codes_and_price_rules() {
        let b = order_body(4, 1, "sell", "limit", "post", true, Some(250), 3).unwrap();
        assert_eq!(
            b,
            PerpOrderBody {
                nonce: 4,
                market: 1,
                side: 1,
                kind: 0,
                tif: 2,
                reduce_only: true,
                price: 250,
                size: 3
            }
        );
        let m = order_body(5, 0, "buy", "market", "ioc", false, None, 1).unwrap();
        assert_eq!(
            (m.side, m.kind, m.tif, m.price),
            (0, 1, 1, 0),
            "a market order's price is 0"
        );
        assert!(
            order_body(1, 0, "buy", "limit", "gtc", false, None, 1).is_err(),
            "a limit order needs a price"
        );
        assert!(
            order_body(1, 0, "buy", "market", "gtc", false, Some(5), 1).is_err(),
            "a market order takes none"
        );
        assert!(order_body(1, 0, "long", "limit", "gtc", false, Some(5), 1).is_err());
        assert!(order_body(1, 0, "buy", "limit", "gtc", false, Some(5), 0).is_err());
    }

    #[test]
    fn prices_parse_sorted_and_refuse_duplicates_and_junk() {
        assert_eq!(
            parse_prices("1=200, 0=100").unwrap(),
            vec![
                PerpPrice {
                    market: 0,
                    price: 100
                },
                PerpPrice {
                    market: 1,
                    price: 200
                }
            ]
        );
        assert!(parse_prices("0=1,0=2").is_err());
        assert!(parse_prices("0=0").is_err());
        assert!(parse_prices("0").is_err());
        assert!(parse_prices("").is_err());
    }

    /// The withdrawal's note is the one the ledger computes at payout
    /// (`note_commitment(recipient.pk, PERP_FROM, amount, asset, time, r)`), and the envelope the
    /// request carries is emitted beside it — so the wallet's ordinary scan (`classify`, the
    /// trial-decryption every leaf goes through) finds it as received.
    #[test]
    fn a_paid_withdrawal_is_found_by_the_ordinary_scan() {
        let w = Wallet::generate();
        let kp = Keypair::generate();
        let (action, note) = withdraw_action(
            &w,
            &kp,
            &BindingDomain::ChainId,
            7,
            4,
            1_500,
            0,
            33,
            EnvelopeFormat::Legacy,
        )
        .unwrap();
        let Action::PerpWithdraw {
            account,
            nonce,
            amount,
            recipient,
            r,
            time,
            envelope,
            signature,
        } = &action
        else {
            panic!("a withdrawal")
        };
        assert_eq!(
            (*account, *nonce, *amount, *time, &recipient.pk),
            (account_id(kp.public_key()), 4, 1_500, 33, &w.address.pk)
        );
        let msg = Transaction::perp_sign_message(&BindingDomain::ChainId, 7, &action).unwrap();
        assert!(kp.public_key().verify(msg.as_bytes(), signature));
        let cm = hasher().note_commitment(&recipient.pk, &PERP_FROM, *amount, 0, *time, r);
        assert_eq!(cm, note.commitment());
        match crate::wallet::classify(&w, cm, envelope) {
            crate::wallet::Found::Received(n, _) => {
                assert_eq!((n.amount, n.from, n.r), (1_500, PERP_FROM, *r))
            }
            other => panic!("not found: {other:?}"),
        }
    }
}
