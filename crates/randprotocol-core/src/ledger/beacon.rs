//! The randomness beacon (genesis `beacon`; `docs/evm-block-context.md` §11): a hash-chain
//! commit–reveal beacon, post-quantum because it uses only the hash.
//!
//! Each validator holds a secret seed and registers the commitment `c = L^N(seed)`, where
//! `L(x) = blake3("rand-beacon-link-1" ‖ be64(chain_id) ‖ address ‖ x)` — the address inside the
//! link, so a commitment copied from another validator opens to nothing. Every block's proposer
//! reveals the preimage `r` of its current commitment (`L(r) == c`) as the block's **first
//! transaction**, an [`Action::BeaconReveal`](crate::types::Action::BeaconReveal); the ledger
//! then replaces the commitment by `r` and moves the chain's value:
//! `beacon(n) = blake3("rand-beacon-1" ‖ beacon(n−1) ‖ r ‖ be64(n))`. A reveal is determined by
//! the commitment, so it cannot be ground; a proposer's only influence is to withhold its block.
//!
//! `N` is not consensus: the chain checks one link per block and never counts them. A validator
//! whose chain runs out, who joins after genesis or who lost its seed registers a new commitment
//! with [`Action::BeaconCommit`](crate::types::Action::BeaconCommit), signed by its validator
//! key. A new commitment does **not** take effect at once: it waits `commit_delay_blocks` as
//! `pending` and is promoted at the validator's first block at or after that height. Without the
//! delay two colluding consecutive leaders, who know `beacon(h−1)` before anyone else, could
//! grind the fresh seed against it.
//!
//! The ledger keeps `Option<BeaconState>`: `None` on a chain without the section — where both
//! actions are refused by name before a byte of them is read, the state root is untouched byte
//! for byte and nothing is stored — and otherwise consensus state: folded into the state root as
//! `H("rand-state-beacon-1", root ‖ beacon_root)` around everything else, inside `Ledger`'s
//! equality, persisted by the node in one `meta` row.
//!
//! A validator with no usable commitment (none registered, one still pending, or a lost seed)
//! cannot build a valid block: it misses its slots — the view times out and the next leader
//! proposes — and keeps voting. Nothing is slashed for it.

use super::{Ledger, TxError};
use crate::crypto::{Address, Hash, Signature};
use crate::types::actions::beacon_commit_message;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Shortest and longest `beacon.commit_delay_blocks` a genesis may set. One block is the least
/// that keeps a commitment from opening in the block that registers it; the default
/// ([`DEFAULT_COMMIT_DELAY_BLOCKS`]) is what a chain should run.
pub const MIN_COMMIT_DELAY_BLOCKS: u64 = 1;
pub const MAX_COMMIT_DELAY_BLOCKS: u64 = 1 << 20;
/// What `rand-node genesis` writes when it is given commitments and no delay.
pub const DEFAULT_COMMIT_DELAY_BLOCKS: u64 = 256;
/// The seed-chain length the tools default to (not consensus): at 26 validators and 2 s blocks
/// one reveal per ~52 s, about 1.7 years.
pub const DEFAULT_SEED_LINKS: u64 = 1 << 20;

/// One link of `validator`'s hash chain on chain `chain_id`.
pub fn link(chain_id: u64, validator: &Address, x: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"rand-beacon-link-1");
    h.update(&chain_id.to_be_bytes());
    h.update(validator.as_bytes());
    h.update(x);
    *h.finalize().as_bytes()
}

/// The value the chain starts from: every genesis commitment, in address order. (Not the genesis
/// hash: the genesis header carries the state root, which commits to this value.)
pub fn genesis_value(chain_id: u64, commitments: &BTreeMap<Address, [u8; 32]>) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"rand-beacon-genesis-1");
    h.update(&chain_id.to_be_bytes());
    for (v, c) in commitments {
        h.update(v.as_bytes());
        h.update(c);
    }
    *h.finalize().as_bytes()
}

/// `beacon(n)` from `beacon(n−1)` and block `n`'s reveal.
pub fn mix(value: &[u8; 32], reveal: &[u8; 32], height: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"rand-beacon-1");
    h.update(value);
    h.update(reveal);
    h.update(&height.to_be_bytes());
    *h.finalize().as_bytes()
}

/// One genesis commitment, as the file writes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconCommitment {
    /// The validator's address, base58 (what `rand-node keygen` prints).
    pub validator: String,
    /// `L^N(seed)`, 64 hex characters (what `rand-node beacon init` prints).
    pub commitment: String,
}

/// The `beacon` genesis section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconConfig {
    /// Blocks a `BeaconCommit` waits before its commitment can be opened.
    pub commit_delay_blocks: u64,
    /// One commitment for every genesis validator, each exactly once.
    pub commitments: Vec<BeaconCommitment>,
}

impl BeaconConfig {
    /// The section's own rules, and its commitments parsed, in file order: the delay inside
    /// [`MIN_COMMIT_DELAY_BLOCKS`]`..=`[`MAX_COMMIT_DELAY_BLOCKS`]; every address base58, every
    /// commitment 64 hex characters; no validator and no commitment twice. That the list covers
    /// exactly the genesis validators is `Genesis::validate`'s to check.
    pub fn parsed(&self) -> Result<Vec<(Address, [u8; 32])>, String> {
        if !(MIN_COMMIT_DELAY_BLOCKS..=MAX_COMMIT_DELAY_BLOCKS).contains(&self.commit_delay_blocks) {
            return Err(format!(
                "beacon.commit_delay_blocks {} ({MIN_COMMIT_DELAY_BLOCKS}..={MAX_COMMIT_DELAY_BLOCKS})",
                self.commit_delay_blocks
            ));
        }
        let mut out: Vec<(Address, [u8; 32])> = Vec::with_capacity(self.commitments.len());
        for c in &self.commitments {
            let v = Address::from_base58(&c.validator).map_err(|_| format!("beacon commitment for `{}`: not an address", c.validator))?;
            let h = Hash::from_hex(&c.commitment).map_err(|_| format!("beacon commitment of {}: not 64 hex characters", c.validator))?;
            if out.iter().any(|(a, _)| *a == v) {
                return Err(format!("beacon: {} is listed twice", c.validator));
            }
            if out.iter().any(|(_, x)| *x == h.0) {
                return Err(format!("beacon: the commitment of {} is another validator's too", c.validator));
            }
            out.push((v, h.0));
        }
        Ok(out)
    }
}

/// One validator's place in the beacon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconEntry {
    /// The commitment the validator's next reveal must open; `None` for a validator that joined
    /// after genesis and whose first commitment is still pending.
    pub commitment: Option<[u8; 32]>,
    /// The nonce of its last `BeaconCommit` (0 before the first); the next carries `nonce + 1`.
    pub nonce: u64,
    /// A registered commitment that is not in force yet: `(height it may first be opened at,
    /// commitment)`. Promoted at the validator's first block at or after that height.
    pub pending: Option<(u64, [u8; 32])>,
}

impl BeaconEntry {
    /// The commitment a block at `height` by this validator must open: the pending one once it
    /// is due, the current one otherwise.
    pub fn due_commitment(&self, height: u64) -> Option<[u8; 32]> {
        match self.pending {
            Some((activate, c)) if height >= activate => Some(c),
            _ => self.commitment,
        }
    }
}

/// The beacon's consensus state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconState {
    /// Genesis `beacon.commit_delay_blocks`. A genesis parameter kept beside the state it rules;
    /// a reloading node sets it from the genesis file, and it is not in the root.
    pub commit_delay_blocks: u64,
    /// `beacon(n)` of the last block applied (the genesis value before block 1).
    pub value: [u8; 32],
    /// Every validator that ever registered a commitment, by address.
    pub entries: BTreeMap<Address, BeaconEntry>,
}

impl BeaconState {
    /// The state a chain starts with: every genesis commitment in force, nonce 0.
    pub fn genesis(chain_id: u64, commit_delay_blocks: u64, commitments: &[(Address, [u8; 32])]) -> BeaconState {
        let map: BTreeMap<Address, [u8; 32]> = commitments.iter().copied().collect();
        BeaconState {
            commit_delay_blocks,
            value: genesis_value(chain_id, &map),
            entries: map.into_iter().map(|(v, c)| (v, BeaconEntry { commitment: Some(c), nonce: 0, pending: None })).collect(),
        }
    }

    /// The state as one hash for the state root: the value, then every entry in address order —
    /// address, a presence byte and the commitment, the nonce, a presence byte and the pending
    /// pair — each field fixed-width, so no two states share bytes.
    pub fn root(&self) -> Hash {
        let mut buf = Vec::with_capacity(40 + self.entries.len() * 115);
        buf.extend_from_slice(&self.value);
        buf.extend_from_slice(&(self.entries.len() as u64).to_be_bytes());
        for (v, e) in &self.entries {
            buf.extend_from_slice(v.as_bytes());
            match &e.commitment {
                None => buf.push(0),
                Some(c) => {
                    buf.push(1);
                    buf.extend_from_slice(c);
                }
            }
            buf.extend_from_slice(&e.nonce.to_be_bytes());
            match &e.pending {
                None => buf.push(0),
                Some((at, c)) => {
                    buf.push(1);
                    buf.extend_from_slice(&at.to_be_bytes());
                    buf.extend_from_slice(c);
                }
            }
        }
        Hash::digest_domain(b"rand-beacon-root-1", &buf)
    }

    /// The commitment a block at `height` proposed by `validator` must open, if it has one.
    pub fn due_commitment(&self, validator: &Address, height: u64) -> Option<[u8; 32]> {
        self.entries.get(validator).and_then(|e| e.due_commitment(height))
    }
}

/// Why a beacon action was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BeaconError {
    /// A `BeaconReveal` anywhere but a block's first transaction — in the pool, over RPC, or
    /// later in a block. Only the block's proposer places one, and only there.
    #[error("a beacon reveal is valid only as a block's first transaction, placed by its proposer")]
    RevealOutsideBlockHead,
    /// The proposer has no commitment in force (none registered, or one still pending). State.
    #[error("proposer {0} has no beacon commitment in force")]
    NoBeaconCommitment(Address),
    /// The reveal is not the preimage of the proposer's commitment (a replayed old reveal is
    /// this too: the commitment has moved past it). State.
    #[error("the reveal does not open proposer {0}'s beacon commitment")]
    BadBeaconReveal(Address),
    /// A `BeaconCommit` for a key that is not in the validator register. State.
    #[error("{0} is not in the validator register")]
    NotInRegister(Address),
    /// Not the validator's next commit. State.
    #[error("beacon commit nonce {got}, expected {expected}")]
    BadNonce { expected: u64, got: u64 },
    /// The signature is not the validator's over this chain's message for this commitment and
    /// nonce.
    #[error("the beacon commit is not signed by validator {0}")]
    BadSignature(Address),
}

/// What either beacon action gets on a chain whose genesis has no `beacon` section: the gate,
/// before a byte of the action is read, as an old node refuses the unknown wire variant.
pub const NO_BEACON: TxError = TxError::UnsupportedAction("the randomness beacon is not enabled on this chain (genesis beacon)");

/// A `BeaconReveal` met by the generic transaction path — the pool, RPC, a proposer's candidate
/// list, any index of a block but the first: always refused. The one place a reveal applies is
/// [`apply_reveal`], which the block rule calls for `transactions[0]`.
pub fn refuse_reveal(ledger: &Ledger) -> Result<(), TxError> {
    if ledger.beacon.is_none() {
        return Err(NO_BEACON);
    }
    Err(BeaconError::RevealOutsideBlockHead.into())
}

/// Block `ledger.height()`'s reveal by `proposer`, in order: a pending commitment that is due is
/// promoted; the reveal must open the commitment in force (`L(r) == c`); the commitment becomes
/// `r` and the value moves. Nothing is written on a refusal.
pub fn apply_reveal(ledger: &mut Ledger, proposer: &Address, reveal: &[u8; 32]) -> Result<(), TxError> {
    let (chain_id, height) = (ledger.chain_id, ledger.height);
    let Some(state) = ledger.beacon.as_mut() else { return Err(NO_BEACON) };
    let entry = state.entries.get_mut(proposer).ok_or(BeaconError::NoBeaconCommitment(*proposer))?;
    let c = entry.due_commitment(height).ok_or(BeaconError::NoBeaconCommitment(*proposer))?;
    if link(chain_id, proposer, reveal) != c {
        return Err(BeaconError::BadBeaconReveal(*proposer).into());
    }
    if entry.pending.is_some_and(|(at, _)| height >= at) {
        entry.pending = None;
    }
    entry.commitment = Some(*reveal);
    state.value = mix(&state.value, reveal, height);
    Ok(())
}

/// The nonce `validator`'s next `BeaconCommit` must carry.
pub fn next_nonce(ledger: &Ledger, validator: &Address) -> u64 {
    ledger.beacon.as_ref().and_then(|b| b.entries.get(validator)).map_or(1, |e| e.nonce.saturating_add(1))
}

/// The state half of a commit, with no signature work: the gate, the register and the nonce.
/// What the mempool asks at every tip — once another commit has taken this nonce, or the
/// validator has left the register, this one can never apply.
pub fn check_commit_open(ledger: &Ledger, validator: &Address, nonce: u64) -> Result<(), TxError> {
    if ledger.beacon.is_none() {
        return Err(NO_BEACON);
    }
    if !ledger.validators.contains_key(validator) {
        return Err(BeaconError::NotInRegister(*validator).into());
    }
    let expected = next_nonce(ledger, validator);
    if nonce != expected {
        return Err(BeaconError::BadNonce { expected, got: nonce }.into());
    }
    Ok(())
}

/// Whether a pooled `BeaconCommit` can still apply on `ledger`, without the signature work. A
/// transaction carrying another action is not this function's and passes.
pub fn still_applies(ledger: &Ledger, tx: &crate::types::Transaction) -> Result<(), TxError> {
    let crate::types::Action::BeaconCommit { validator, nonce, .. } = &tx.action else {
        return Ok(());
    };
    check_commit_open(ledger, validator, *nonce)
}

/// `BeaconCommit`'s rules, cheap before expensive: the gate, the register, the nonce
/// ([`check_commit_open`]), then the validator's signature over [`beacon_commit_message`].
pub fn check_commit(ledger: &Ledger, validator: &Address, commitment: &[u8; 32], nonce: u64, signature: &Signature) -> Result<(), TxError> {
    check_commit_open(ledger, validator, nonce)?;
    let key = &ledger.validators.get(validator).ok_or(BeaconError::NotInRegister(*validator))?.public_key;
    let message = beacon_commit_message(&ledger.signing_domain.genesis, commitment, nonce);
    if !key.verify(message.as_bytes(), signature) {
        return Err(BeaconError::BadSignature(*validator).into());
    }
    Ok(())
}

/// The apply step, in lockstep with [`check_commit`]: re-checked against this very state, then
/// the write — the commitment goes to `pending`, openable from `height + commit_delay_blocks`
/// (replacing a pending one that had not been promoted), and the nonce moves.
pub(super) fn apply_commit(ledger: &mut Ledger, validator: &Address, commitment: &[u8; 32], nonce: u64, signature: &Signature) -> Result<(), TxError> {
    check_commit(ledger, validator, commitment, nonce, signature)?;
    let height = ledger.height;
    let Some(state) = ledger.beacon.as_mut() else { return Err(NO_BEACON) };
    let activate = height.saturating_add(state.commit_delay_blocks);
    let entry = state.entries.entry(*validator).or_insert(BeaconEntry { commitment: None, nonce: 0, pending: None });
    entry.pending = Some((activate, *commitment));
    entry.nonce = nonce;
    Ok(())
}

/// A validator's secret hash chain, walked from its seed: `x_0 = seed`, `x_{i+1} = L(x_i)`, the
/// commitment to register `x_links`. The reveal for a commitment `x_k` is `x_{k−1}`, and `k`
/// reveals remain. No position is stored anywhere: the chain's commitment says where the
/// validator is, which is crash-safe and right after an abandoned block.
///
/// Not consensus code — the node's reveal source and the CLI use it — but it lives beside the
/// link it must agree with. Checkpoints every [`SeedChain::STRIDE`] links make a lookup near the
/// last one cheap; a lookup with no hint walks the whole chain once.
pub struct SeedChain {
    chain_id: u64,
    validator: Address,
    links: u64,
    /// `x_{j · STRIDE}` for every `j` with `j · STRIDE ≤ links`.
    checkpoints: Vec<[u8; 32]>,
    tip: [u8; 32],
    /// The index of the last commitment found, where the next search starts.
    hint: std::sync::Mutex<Option<u64>>,
}

impl SeedChain {
    pub const STRIDE: u64 = 1024;

    /// Walk `links` links from `seed` (`links ≥ 1`).
    pub fn new(chain_id: u64, validator: Address, seed: [u8; 32], links: u64) -> SeedChain {
        let mut checkpoints = Vec::with_capacity((links / Self::STRIDE + 1) as usize);
        let mut x = seed;
        for i in 0..links {
            if i % Self::STRIDE == 0 {
                checkpoints.push(x);
            }
            x = link(chain_id, &validator, &x);
        }
        if links.is_multiple_of(Self::STRIDE) {
            checkpoints.push(x);
        }
        SeedChain { chain_id, validator, links, checkpoints, tip: x, hint: std::sync::Mutex::new(None) }
    }

    /// The commitment to register: `x_links`.
    pub fn commitment(&self) -> [u8; 32] {
        self.tip
    }

    pub fn links(&self) -> u64 {
        self.links
    }

    /// `x_k`, from the checkpoint below it.
    fn at(&self, k: u64) -> [u8; 32] {
        let mut x = self.checkpoints[(k / Self::STRIDE) as usize];
        for _ in 0..k % Self::STRIDE {
            x = link(self.chain_id, &self.validator, &x);
        }
        x
    }

    /// The index `k` with `x_k == commitment`, `1 ≤ k ≤ links`: next to the last one found
    /// first, then the whole chain.
    fn index_of(&self, commitment: &[u8; 32]) -> Option<u64> {
        let hint = *self.hint.lock().unwrap_or_else(|e| e.into_inner());
        let near = match hint {
            Some(h) => vec![h.saturating_sub(1), h],
            None => vec![self.links],
        };
        let mut found = near.into_iter().find(|k| (1..=self.links).contains(k) && self.at(*k) == *commitment);
        if found.is_none() {
            let mut x = self.checkpoints[0];
            for k in 1..=self.links {
                x = link(self.chain_id, &self.validator, &x);
                if x == *commitment {
                    found = Some(k);
                    break;
                }
            }
        }
        if let Some(k) = found {
            *self.hint.lock().unwrap_or_else(|e| e.into_inner()) = Some(k);
        }
        found
    }

    /// The reveal that opens `commitment` and how many reveals are left **before** it is used
    /// (`k`: this one included), or `None` when the commitment is not on this chain — another
    /// seed's, or the seed itself (`x_0`, which has no preimage here: the chain is spent).
    pub fn reveal_for(&self, commitment: &[u8; 32]) -> Option<([u8; 32], u64)> {
        let k = self.index_of(commitment)?;
        Some((self.at(k - 1), k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::Keypair;
    use crate::ledger::staking::MIN_STAKE;
    use crate::ledger::ValidatorEntry;
    use crate::notes::{ShieldedAddress, KEM_EK_BYTES};
    use crate::types::{Action, Transaction};

    const CHAIN: u64 = 7;
    const LINKS: u64 = 8;
    const DELAY: u64 = 3;

    fn key(i: u8) -> Keypair {
        Keypair::from_seed([i; 32]).unwrap()
    }

    fn this_chain() -> Hash {
        Hash::digest(b"this chain")
    }

    fn seeds(k: &Keypair, tag: u8) -> SeedChain {
        SeedChain::new(CHAIN, k.address(), [tag; 32], LINKS)
    }

    /// Four validators at height 5 signing under `this_chain()`; with the beacon, the first
    /// three hold a genesis commitment (seed `[i; 32]`, eight links) and the fourth has none.
    fn chain(section: bool) -> (Vec<Keypair>, Ledger) {
        let vals: Vec<Keypair> = (1..=4u8).map(key).collect();
        let register: BTreeMap<Address, ValidatorEntry> = vals
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let e = ValidatorEntry {
                    public_key: k.public_key().clone(),
                    stake: MIN_STAKE,
                    pending: Vec::new(),
                    rewards: 0,
                    payout: ShieldedAddress { pk: [i as u32; 8], kem_ek: vec![i as u8; KEM_EK_BYTES] },
                    nonce: 0,
                    activation_epoch: 0,
                };
                (k.address(), e)
            })
            .collect();
        let mut l = Ledger::new(CHAIN, [11; 8], register, &StubExecutor);
        l.set_height(5);
        l.set_signing_domain(crate::types::SigningDomain::v1(this_chain()));
        if section {
            let commitments: Vec<(Address, [u8; 32])> = (1..=3u8).map(|i| (key(i).address(), seeds(&key(i), i).commitment())).collect();
            l.set_beacon(Some(BeaconState::genesis(CHAIN, DELAY, &commitments)));
        }
        (vals, l)
    }

    fn commit_tx(k: &Keypair, commitment: [u8; 32], nonce: u64) -> Transaction {
        let m = beacon_commit_message(&this_chain(), &commitment, nonce);
        Transaction {
            chain_id: CHAIN,
            bundle: None,
            action: Action::BeaconCommit { validator: k.address(), commitment, nonce, signature: k.sign(m.as_bytes()) },
        }
    }

    fn reveal_tx(reveal: [u8; 32]) -> Transaction {
        Transaction { chain_id: CHAIN, bundle: None, action: Action::BeaconReveal { reveal } }
    }

    fn beacon_err(e: TxError) -> BeaconError {
        match e {
            TxError::Beacon(b) => b,
            other => panic!("not a beacon error: {other:?}"),
        }
    }

    /// The link, the genesis value and the mix are pinned: a change to any is a consensus change
    /// for every beacon chain, and breaks every validator's registered commitment.
    #[test]
    fn the_link_the_genesis_value_and_the_mix_are_pinned() {
        let v = Address([0x11; 32]);
        let x = [0x22; 32];
        // The link is the plain domain-separated hash of its four parts.
        let mut pre = b"rand-beacon-link-1".to_vec();
        pre.extend_from_slice(&7u64.to_be_bytes());
        pre.extend_from_slice(&v.0);
        pre.extend_from_slice(&x);
        assert_eq!(link(7, &v, &x), *blake3::hash(&pre).as_bytes());
        assert_eq!(hex::encode(link(7, &v, &x)), "25f53d7b5b993aeeea17f4fe9311b527339d5bcc5f8a51f4328660139116f9cf");
        assert_eq!(hex::encode(beacon_commit_message(&Hash([0x33; 32]), &x, 9).0), "7d59ca24a068cb662f7cfe38f489e08a696fe3258609043ad9b581f008423c44");
        // The chain id and the address are inside it: a copied commitment opens to nothing.
        assert_ne!(link(8, &v, &x), link(7, &v, &x));
        assert_ne!(link(7, &Address([0x12; 32]), &x), link(7, &v, &x));
        let map: BTreeMap<Address, [u8; 32]> = [(v, x), (Address([0x10; 32]), [0x33; 32])].into();
        let mut pre = b"rand-beacon-genesis-1".to_vec();
        pre.extend_from_slice(&7u64.to_be_bytes());
        pre.extend_from_slice(&[0x10; 32]);
        pre.extend_from_slice(&[0x33; 32]);
        pre.extend_from_slice(&v.0);
        pre.extend_from_slice(&x);
        assert_eq!(genesis_value(7, &map), *blake3::hash(&pre).as_bytes(), "address order, whatever the file's");
        let mut pre = b"rand-beacon-1".to_vec();
        pre.extend_from_slice(&[0x44; 32]);
        pre.extend_from_slice(&x);
        pre.extend_from_slice(&9u64.to_be_bytes());
        assert_eq!(mix(&[0x44; 32], &x, 9), *blake3::hash(&pre).as_bytes());
    }

    /// The seed chain: the commitment is `L^N(seed)`, each reveal opens the commitment before
    /// it, the count runs down to the seed, and a commitment from another chain is not found.
    #[test]
    fn a_seed_chain_reveals_link_by_link_down_to_its_seed() {
        let k = key(1);
        let s = SeedChain::new(CHAIN, k.address(), [9; 32], 2 * SeedChain::STRIDE + 5);
        let mut x = [9u8; 32];
        for _ in 0..s.links() {
            x = link(CHAIN, &k.address(), &x);
        }
        assert_eq!(s.commitment(), x);
        let mut c = s.commitment();
        for left in (1..=s.links()).rev() {
            let (r, remaining) = s.reveal_for(&c).expect("on the chain");
            assert_eq!(remaining, left);
            assert_eq!(link(CHAIN, &k.address(), &r), c);
            c = r;
        }
        assert_eq!(c, [9; 32], "the last reveal is the seed");
        assert_eq!(s.reveal_for(&c), None, "the seed has no preimage: the chain is spent");
        // A cold lookup anywhere on the chain (a restart), and the same one again (an abandoned
        // block: the chain's commitment did not move).
        let fresh = SeedChain::new(CHAIN, k.address(), [9; 32], 2 * SeedChain::STRIDE + 5);
        let mid = fresh.at(1500);
        assert_eq!(fresh.reveal_for(&mid), Some((fresh.at(1499), 1500)));
        assert_eq!(fresh.reveal_for(&mid), Some((fresh.at(1499), 1500)));
        assert_eq!(fresh.reveal_for(&fresh.at(1499)), Some((fresh.at(1498), 1499)));
        assert_eq!(fresh.reveal_for(&SeedChain::new(CHAIN, key(2).address(), [9; 32], 4).commitment()), None);
        // A chain of exactly one stride, and of one link.
        let one = SeedChain::new(CHAIN, k.address(), [9; 32], SeedChain::STRIDE);
        assert_eq!(one.reveal_for(&one.commitment()).unwrap().1, SeedChain::STRIDE);
        let tiny = SeedChain::new(CHAIN, k.address(), [9; 32], 1);
        assert_eq!(tiny.reveal_for(&tiny.commitment()), Some(([9; 32], 1)));
    }

    /// A valid reveal moves the proposer's commitment to the reveal and the value by the mix;
    /// the root moves with both; the next reveal opens the new commitment.
    #[test]
    fn a_reveal_opens_the_commitment_and_moves_the_value() {
        let (vals, mut l) = chain(true);
        let s = seeds(&vals[0], 1);
        let before = l.beacon().unwrap().clone();
        let root = l.state_root();
        let (r, left) = s.reveal_for(&s.commitment()).unwrap();
        assert_eq!(left, LINKS);
        apply_reveal(&mut l, &vals[0].address(), &r).unwrap();
        let after = l.beacon().unwrap();
        assert_eq!(after.value, mix(&before.value, &r, 5));
        assert_eq!(after.entries[&vals[0].address()], BeaconEntry { commitment: Some(r), nonce: 0, pending: None });
        assert_eq!(after.entries[&vals[1].address()], before.entries[&vals[1].address()], "nobody else's entry moves");
        assert_ne!(l.state_root(), root);
        l.set_height(6);
        let (r2, _) = s.reveal_for(&r).unwrap();
        apply_reveal(&mut l, &vals[0].address(), &r2).unwrap();
        assert_eq!(l.beacon().unwrap().value, mix(&mix(&before.value, &r, 5), &r2, 6), "the height is inside the mix");
    }

    /// Every refusal, and none of them writes: a wrong reveal, a replayed one, another
    /// validator's, a proposer with no commitment, and a reveal met anywhere but a block's head.
    #[test]
    fn a_wrong_replayed_or_stray_reveal_is_refused() {
        let (vals, mut l) = chain(true);
        let (a, b, d) = (vals[0].address(), vals[1].address(), vals[3].address());
        let s = seeds(&vals[0], 1);
        let (r, _) = s.reveal_for(&s.commitment()).unwrap();
        let untouched = l.clone();
        assert_eq!(beacon_err(apply_reveal(&mut l, &a, &[0; 32]).unwrap_err()), BeaconError::BadBeaconReveal(a));
        assert_eq!(beacon_err(apply_reveal(&mut l, &b, &r).unwrap_err()), BeaconError::BadBeaconReveal(b), "another validator's reveal");
        assert_eq!(beacon_err(apply_reveal(&mut l, &d, &r).unwrap_err()), BeaconError::NoBeaconCommitment(d));
        assert_eq!(l, untouched);
        apply_reveal(&mut l, &a, &r).unwrap();
        let once = l.clone();
        assert_eq!(beacon_err(apply_reveal(&mut l, &a, &r).unwrap_err()), BeaconError::BadBeaconReveal(a), "a replay");
        assert_eq!(l, once);
        // The generic path — the pool, RPC, a candidate, a later index — never takes one.
        for tx in [reveal_tx(r), reveal_tx(s.reveal_for(&r).unwrap().0)] {
            assert_eq!(beacon_err(l.validate(&tx, &StubExecutor).unwrap_err()), BeaconError::RevealOutsideBlockHead);
            assert_eq!(beacon_err(l.apply_tx(&tx, &a, &StubExecutor).unwrap_err()), BeaconError::RevealOutsideBlockHead);
        }
        assert_eq!(l, once);
    }

    /// The block rule: with the beacon on a block's first transaction is the proposer's reveal
    /// and no other transaction is one.
    #[test]
    fn a_block_must_open_with_its_proposers_reveal_and_carry_no_other() {
        use crate::ledger::BlockError;
        let (vals, l) = chain(true);
        let a = vals[0].address();
        let s = seeds(&vals[0], 1);
        let (r, _) = s.reveal_for(&s.commitment()).unwrap();
        let (r2, _) = s.reveal_for(&r).unwrap();
        let commit = commit_tx(&vals[3], [5; 32], 1);
        let run = |txs: &[Transaction]| {
            let mut t = l.clone();
            t.apply_transactions(txs, &a, &StubExecutor).map(|_| t)
        };
        assert_eq!(run(&[]).unwrap_err(), BlockError::MissingBeaconReveal);
        assert_eq!(run(std::slice::from_ref(&commit)).unwrap_err(), BlockError::MissingBeaconReveal);
        assert_eq!(run(&[commit.clone(), reveal_tx(r)]).unwrap_err(), BlockError::MissingBeaconReveal);
        assert_eq!(run(&[reveal_tx(r), reveal_tx(r2)]).unwrap_err(), BlockError::MisplacedBeaconReveal { index: 1 });
        assert_eq!(run(&[reveal_tx(r), commit.clone(), reveal_tx(r2)]).unwrap_err(), BlockError::MisplacedBeaconReveal { index: 2 });
        assert_eq!(
            run(&[reveal_tx(r2)]).unwrap_err(),
            BlockError::InvalidTx { index: 0, error: BeaconError::BadBeaconReveal(a).into() }
        );
        // A reveal for another chain id is not this chain's reveal.
        let foreign = Transaction { chain_id: CHAIN + 1, ..reveal_tx(r) };
        assert!(matches!(run(&[foreign]).unwrap_err(), BlockError::InvalidTx { index: 0, error: TxError::WrongChain { .. } }));
        let ok = run(&[reveal_tx(r), commit]).unwrap();
        assert_eq!(ok.beacon().unwrap().entries[&a].commitment, Some(r));
        assert_eq!(ok.beacon().unwrap().entries[&vals[3].address()].pending, Some((5 + DELAY, [5; 32])));
        assert_eq!(l.beacon().unwrap().entries[&a].commitment, Some(s.commitment()), "a refused block writes nothing");
    }

    /// A commit: the validator's signature over this chain's message, the next nonce, a key in
    /// the register. It lands in `pending` and moves the nonce and the root.
    #[test]
    fn a_commit_needs_the_validators_signature_and_the_next_nonce() {
        let (vals, mut l) = chain(true);
        let (a, d) = (vals[0].address(), vals[3].address());
        let root = l.state_root();
        let ok = commit_tx(&vals[3], [5; 32], 1);
        assert_eq!(l.validate(&ok, &StubExecutor), Ok(()));
        // The nonce: not zero, not two.
        for n in [0, 2] {
            assert_eq!(beacon_err(l.validate(&commit_tx(&vals[3], [5; 32], n), &StubExecutor).unwrap_err()), BeaconError::BadNonce { expected: 1, got: n });
        }
        // Signed by another validator, for another commitment, for another chain.
        let mut forged = ok.clone();
        let Action::BeaconCommit { validator, .. } = &mut forged.action else { unreachable!() };
        *validator = a;
        assert_eq!(beacon_err(l.validate(&forged, &StubExecutor).unwrap_err()), BeaconError::BadSignature(a));
        let mut moved = ok.clone();
        let Action::BeaconCommit { commitment, .. } = &mut moved.action else { unreachable!() };
        *commitment = [6; 32];
        assert_eq!(beacon_err(l.validate(&moved, &StubExecutor).unwrap_err()), BeaconError::BadSignature(d));
        let elsewhere = {
            let m = beacon_commit_message(&Hash::digest(b"another chain"), &[5; 32], 1);
            Transaction { chain_id: CHAIN, bundle: None, action: Action::BeaconCommit { validator: d, commitment: [5; 32], nonce: 1, signature: vals[3].sign(m.as_bytes()) } }
        };
        assert_eq!(beacon_err(l.validate(&elsewhere, &StubExecutor).unwrap_err()), BeaconError::BadSignature(d));
        // A key outside the register.
        let stranger = key(9);
        assert_eq!(
            beacon_err(l.validate(&commit_tx(&stranger, [5; 32], 1), &StubExecutor).unwrap_err()),
            BeaconError::NotInRegister(stranger.address())
        );
        // It rides without a bundle and pays nothing.
        assert_eq!(ok.action.bundle_less(), Some("beacon_commit"));
        assert_eq!(crate::gas::fee_floor(&ok.action), 0);
        l.apply_tx(&ok, &a, &StubExecutor).unwrap();
        assert_eq!(l.beacon().unwrap().entries[&d], BeaconEntry { commitment: None, nonce: 1, pending: Some((5 + DELAY, [5; 32])) });
        assert_ne!(l.state_root(), root);
        assert_eq!(beacon_err(l.validate(&ok, &StubExecutor).unwrap_err()), BeaconError::BadNonce { expected: 2, got: 1 }, "a replay");
        assert_eq!(beacon_err(still_applies(&l, &ok).unwrap_err()), BeaconError::BadNonce { expected: 2, got: 1 });
        assert_eq!(still_applies(&l, &commit_tx(&vals[3], [7; 32], 2)), Ok(()));
    }

    /// The delay: a new commitment cannot be opened before `height + delay`; until then the
    /// validator's old one stays in force (or, for a newcomer, it has none); at the first block
    /// at or after that height the new one is promoted and opened in one step.
    #[test]
    fn a_new_commitment_waits_out_the_delay_and_is_promoted_at_the_validators_next_block() {
        let (vals, mut l) = chain(true);
        let (a, d) = (vals[0].address(), vals[3].address());
        let (old, fresh, late) = (seeds(&vals[0], 1), seeds(&vals[0], 21), seeds(&vals[3], 24));
        l.apply_tx(&commit_tx(&vals[0], fresh.commitment(), 1), &a, &StubExecutor).unwrap();
        l.apply_tx(&commit_tx(&vals[3], late.commitment(), 1), &a, &StubExecutor).unwrap();
        let (new_r, _) = fresh.reveal_for(&fresh.commitment()).unwrap();
        let (old_r, _) = old.reveal_for(&old.commitment()).unwrap();
        let (late_r, _) = late.reveal_for(&late.commitment()).unwrap();
        // Before the delay has run: the new one does not open, the old one does, the newcomer
        // has nothing in force.
        l.set_height(5 + DELAY - 1);
        assert_eq!(l.beacon().unwrap().due_commitment(&a, l.height()), Some(old.commitment()));
        assert_eq!(l.beacon().unwrap().due_commitment(&d, l.height()), None);
        assert_eq!(beacon_err(apply_reveal(&mut l, &a, &new_r).unwrap_err()), BeaconError::BadBeaconReveal(a));
        assert_eq!(beacon_err(apply_reveal(&mut l, &d, &late_r).unwrap_err()), BeaconError::NoBeaconCommitment(d));
        apply_reveal(&mut l, &a, &old_r).unwrap();
        assert_eq!(l.beacon().unwrap().entries[&a], BeaconEntry { commitment: Some(old_r), nonce: 1, pending: Some((5 + DELAY, fresh.commitment())) });
        // At the delay: the new one is in force and the old chain no longer opens.
        l.set_height(5 + DELAY);
        assert_eq!(l.beacon().unwrap().due_commitment(&a, l.height()), Some(fresh.commitment()));
        let (older_r, _) = old.reveal_for(&old_r).unwrap();
        assert_eq!(beacon_err(apply_reveal(&mut l, &a, &older_r).unwrap_err()), BeaconError::BadBeaconReveal(a));
        apply_reveal(&mut l, &a, &new_r).unwrap();
        assert_eq!(l.beacon().unwrap().entries[&a], BeaconEntry { commitment: Some(new_r), nonce: 1, pending: None });
        // The newcomer proposes later still: promoted then.
        l.set_height(5 + DELAY + 7);
        apply_reveal(&mut l, &d, &late_r).unwrap();
        assert_eq!(l.beacon().unwrap().entries[&d], BeaconEntry { commitment: Some(late_r), nonce: 1, pending: None });
        // A second commit before promotion replaces the pending one and restarts the delay.
        l.apply_tx(&commit_tx(&vals[1], [1; 32], 1), &a, &StubExecutor).unwrap();
        l.set_height(l.height() + 1);
        l.apply_tx(&commit_tx(&vals[1], [2; 32], 2), &a, &StubExecutor).unwrap();
        assert_eq!(l.beacon().unwrap().entries[&vals[1].address()].pending, Some((l.height() + DELAY, [2; 32])));
    }

    /// Without the section: no state, both actions refused by name wherever they are met, the
    /// block rule asks for nothing, and the state root is what it is without the module.
    #[test]
    fn without_the_section_both_actions_are_refused_and_nothing_exists() {
        let (vals, mut l) = chain(false);
        let a = vals[0].address();
        assert!(l.beacon().is_none());
        let before = l.clone();
        for tx in [reveal_tx([1; 32]), commit_tx(&vals[0], [5; 32], 1)] {
            assert_eq!(l.validate(&tx, &StubExecutor).unwrap_err(), NO_BEACON);
            assert_eq!(l.apply_tx(&tx, &a, &StubExecutor).unwrap_err(), NO_BEACON);
            assert_eq!(
                l.apply_transactions(std::slice::from_ref(&tx), &a, &StubExecutor).unwrap_err(),
                crate::ledger::BlockError::InvalidTx { index: 0, error: NO_BEACON }
            );
        }
        assert_eq!(apply_reveal(&mut l, &a, &[1; 32]).unwrap_err(), NO_BEACON);
        assert_eq!(l.apply_transactions(&[], &a, &StubExecutor).map(|r| r.len()), Ok(0), "an empty block is a block");
        assert_eq!(l, before);
        // The wrapper is the outermost and only under the section.
        let (_, on) = chain(true);
        let mut buf = before.state_root().as_bytes().to_vec();
        buf.extend_from_slice(on.beacon().unwrap().root().as_bytes());
        assert_eq!(on.state_root(), Hash::digest_domain(b"rand-state-beacon-1", &buf));
    }

    /// The root commits to every field of the state but the genesis parameter.
    #[test]
    fn the_root_moves_with_every_field_but_the_delay() {
        let (vals, l) = chain(true);
        let base = l.beacon().unwrap().clone();
        let a = vals[0].address();
        let mut seen = vec![base.root()];
        let mut variant = |f: &dyn Fn(&mut BeaconState)| {
            let mut s = base.clone();
            f(&mut s);
            assert!(!seen.contains(&s.root()));
            seen.push(s.root());
        };
        variant(&|s| s.value[0] ^= 1);
        variant(&|s| s.entries.get_mut(&a).unwrap().commitment = Some([1; 32]));
        variant(&|s| s.entries.get_mut(&a).unwrap().commitment = None);
        variant(&|s| s.entries.get_mut(&a).unwrap().nonce = 1);
        variant(&|s| s.entries.get_mut(&a).unwrap().pending = Some((9, [1; 32])));
        variant(&|s| s.entries.get_mut(&a).unwrap().pending = Some((10, [1; 32])));
        variant(&|s| s.entries.get_mut(&a).unwrap().pending = Some((9, [2; 32])));
        variant(&|s| {
            s.entries.remove(&a);
        });
        let mut other_delay = base.clone();
        other_delay.commit_delay_blocks += 1;
        assert_eq!(other_delay.root(), base.root());
    }

    /// The section's own rules.
    #[test]
    fn the_genesis_section_is_checked() {
        let c = |v: &Keypair, h: [u8; 32]| BeaconCommitment { validator: v.address().to_base58(), commitment: hex::encode(h) };
        let good = BeaconConfig { commit_delay_blocks: 256, commitments: vec![c(&key(1), [1; 32]), c(&key(2), [2; 32])] };
        assert_eq!(good.parsed().unwrap(), vec![(key(1).address(), [1; 32]), (key(2).address(), [2; 32])]);
        let bad = |f: &dyn Fn(&mut BeaconConfig), want: &str| {
            let mut g = good.clone();
            f(&mut g);
            let why = g.parsed().unwrap_err();
            assert!(why.contains(want), "{why}");
        };
        bad(&|g| g.commit_delay_blocks = 0, "commit_delay_blocks");
        bad(&|g| g.commit_delay_blocks = MAX_COMMIT_DELAY_BLOCKS + 1, "commit_delay_blocks");
        bad(&|g| g.commitments[0].validator = "not base58 !".into(), "not an address");
        bad(&|g| g.commitments[0].commitment = "abcd".into(), "64 hex");
        bad(&|g| g.commitments[1].validator = g.commitments[0].validator.clone(), "twice");
        bad(&|g| g.commitments[1].commitment = g.commitments[0].commitment.clone(), "another validator's");
    }
}
