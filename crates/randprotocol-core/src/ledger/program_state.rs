//! RPL-2: program state, program vaults and the `Invoke` action
//! (`docs/superpowers/specs/2026-09-30-rpl2-program-state-design.md`).
//!
//! A `Call` is stateless: its outputs are data and nothing follows from them. An `Invoke` is a
//! call whose proof says the program accepts one **declared state transition** — the cells it
//! read and the values it read, the cells it writes, what the transaction's bundle burns into
//! the program's vault, and what the vault pays out or the program mints — and the ledger then
//! applies exactly that transition, provided every cell read still holds the value declared.
//!
//! Three things keep this small:
//!
//! - **State is public.** Cells and vault balances are plain maps in the ledger, committed in the
//!   state root. Nothing here touches the commitment tree except the payout notes, which the
//!   chain computes itself exactly as it computes a `TokenMint`'s note.
//! - **No circuit changes.** Value comes in through the bundle's existing public burn fields
//!   (`burn_r`, `burn_a`, `burn_asset`) and the call proof is an ordinary call proof, verified
//!   against a public segment the ledger builds from the transaction: the program's public input,
//!   the call binding, and the [`Transition::context`] words.
//! - **The proof never depends on ledger state.** The segment is built from what the transaction
//!   declares, so a proof verifies or fails on the transaction's bytes alone and the
//!   verified-proofs cache stays sound. What depends on state is the read check below, a
//!   comparison that always runs.
//!
//! The gate is the genesis `program_state` section. Without it every `Invoke` is refused before
//! anything else about it is looked at, `MintAuthority::Program` stays refused at registration,
//! and the chain is byte for byte what it was.

use super::tokens::{self, MintAuthority, TokenError};
use super::{Ledger, TxError};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{merkle_root, Hash};
use crate::notes::{word8_to_bytes, Envelope, ShieldedAddress, Word8, MAX_NOTE_VALUE};
use crate::program::ProgramId;
use crate::types::transaction::{Action, Transaction};
use crate::types::TX_BINDING_WORDS;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The most cells a transition may read, and the most it may write. The segment rule
/// ([`segment_fits`]) is the tighter bound for any program without a large public input.
pub const MAX_READS: usize = 8;
pub const MAX_WRITES: usize = 8;
/// The most notes a transition may create, pays and mints together.
pub const MAX_PAYOUTS: usize = 4;
/// Word 0 of the context. A program must refuse a version it was not written for.
pub const CONTEXT_VERSION: u32 = 1;
/// The fixed words before the cells: version, the four counts, `burn_r` (2), the inflow kind,
/// `burn_asset`, `burn_a` (2).
pub const CONTEXT_HEADER_WORDS: usize = 11;
/// The largest `cell_fee` a genesis may set: 1 000 RAND a cell.
pub const MAX_CELL_FEE: u64 = 1_000 * crate::types::UNITS_PER_RAND;

/// The `from` word of a note an `Invoke` pays out — `MINT_FROM`'s twin, one constant for every
/// program. Such a note has no sender, as a mint's has none; a fixed word keeps it apart from a
/// mint (`"rpl-mint"`), a bridge deposit and a faucet mint (both all-zero).
pub const PROGRAM_FROM: Word8 = [u32::from_le_bytes(*b"rpl2"), u32::from_le_bytes(*b"-pay"), 0, 0, 0, 0, 0, 0];

const ZERO: Word8 = [0; 8];

/// One storage cell: an eight-word key and an eight-word value. An absent cell reads as eight
/// zeros, and writing eight zeros removes the cell, so "absent" has exactly one encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    pub key: Word8,
    pub value: Word8,
}

/// What the bundle's `burn_a` of `burn_asset` is to the program. `burn_r`, the RAND burn, is
/// always a vault deposit and needs no word here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Inflow {
    /// The bundle burns no token (`burn_a == 0`).
    None,
    /// The token goes into the program's vault.
    Deposit,
    /// The token is destroyed; it must be one whose mint authority is this program.
    Burn,
}

impl Inflow {
    /// The context word: 0, 1, 2.
    pub fn word(self) -> u32 {
        match self {
            Inflow::None => 0,
            Inflow::Deposit => 1,
            Inflow::Burn => 2,
        }
    }
}

/// One note the transition creates. `asset` and `amount` are what the program decides and sees;
/// the recipient, the blinding and the envelope are the caller's, bound by the call binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payout {
    pub asset: u32,
    pub amount: u64,
    pub recipient: ShieldedAddress,
    pub r: Word8,
    pub envelope: Envelope,
}

/// The state transition an `Invoke` declares and its call proof vouches for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    /// Cells read, with the values read. Keys strictly ascending.
    pub reads: Vec<Cell>,
    /// Cells written. Keys strictly ascending.
    pub writes: Vec<Cell>,
    pub inflow: Inflow,
    /// Notes paid out of the program's vault.
    pub pays: Vec<Payout>,
    /// Notes of new units of a token whose mint authority is this program.
    pub mints: Vec<Payout>,
}

impl Transition {
    /// Every note this transition creates, in the order the ledger appends them: pays, then mints.
    pub fn payouts(&self) -> impl Iterator<Item = &Payout> {
        self.pays.iter().chain(self.mints.iter())
    }

    pub fn context_words(&self) -> usize {
        CONTEXT_HEADER_WORDS + 16 * (self.reads.len() + self.writes.len()) + 3 * (self.pays.len() + self.mints.len())
    }

    /// The words a program reads after the call binding (spec §5). The three burn fields are the
    /// transaction's bundle's; they are not part of the action, so they are passed in.
    pub fn context(&self, burn_r: u64, burn_asset: u32, burn_a: u64) -> Vec<u32> {
        let mut w = Vec::with_capacity(self.context_words());
        w.push(CONTEXT_VERSION);
        w.push(self.reads.len() as u32);
        w.push(self.writes.len() as u32);
        w.push(self.pays.len() as u32);
        w.push(self.mints.len() as u32);
        w.push(burn_r as u32);
        w.push((burn_r >> 32) as u32);
        w.push(self.inflow.word());
        w.push(burn_asset);
        w.push(burn_a as u32);
        w.push((burn_a >> 32) as u32);
        for c in self.reads.iter().chain(self.writes.iter()) {
            w.extend_from_slice(&c.key);
            w.extend_from_slice(&c.value);
        }
        for p in self.payouts() {
            w.push(p.asset);
            w.push(p.amount as u32);
            w.push((p.amount >> 32) as u32);
        }
        w
    }
}

/// Rows of the zkVM's public table for a segment of `len` words: `max(len + 1, 128)` rounded up
/// to a power of two (`tables::public::public_log_height`). Core cannot name a zkvm function, so
/// this is a mirror, like [`crate::program::program_table_rows`]; `randprotocol-zkvm`'s executor
/// tests pin it to the real one.
pub fn public_table_rows(len: usize) -> u64 {
    (len as u64).saturating_add(1).max(1 << crate::program::MIN_PRIVATE_TABLE_LOG_HEIGHT).next_power_of_two()
}

/// The segment rule (spec §5): an invoke's segment, `public ‖ call_binding ‖ context`, must sit in
/// the same public table as a hardened call's `public ‖ call_binding` — so an `Invoke` needs no
/// verifier key a `Call` to the same program does not already need.
pub fn segment_fits(public_len: usize, context_len: usize) -> bool {
    let call = public_len.saturating_add(TX_BINDING_WORDS);
    public_table_rows(call.saturating_add(context_len)) == public_table_rows(call)
}

/// `public ‖ call_binding ‖ context`.
pub fn invoke_segment(public: &[u32], binding: &[u32; TX_BINDING_WORDS], context: &[u32]) -> Vec<u32> {
    [public, binding.as_slice(), context].concat()
}

/// The commitment of a note an `Invoke` pays out, computed identically by [`validate`] and
/// [`apply`] and rebuilt from the transaction by anyone: every input is public on the wire.
/// `time` is the bundle's.
pub fn payout_commitment(p: &Payout, time: u32, executor: &dyn ConfidentialExecutor) -> Word8 {
    executor.note_commitment(&p.recipient.pk, &PROGRAM_FROM, p.amount, p.asset, time, &p.r)
}

/// The genesis `program_state` section.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramStateConfig {
    /// RAND units added to an invoke's fee floor for each cell it creates.
    #[serde(default)]
    pub cell_fee: u64,
}

impl ProgramStateConfig {
    pub fn check(&self) -> Result<(), String> {
        if self.cell_fee > MAX_CELL_FEE {
            return Err(format!("program_state.cell_fee {} exceeds {MAX_CELL_FEE}", self.cell_fee));
        }
        Ok(())
    }
}

/// Every program's cells and vault balances. Consensus state under the section: in the state
/// root ([`ProgramState::root`]) and persisted whole. `cell_fee` is the genesis parameter, and
/// the two RAND counters are audit state — derived, outside the root, like [`super::supply`]'s.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramState {
    pub cell_fee: u64,
    cells: BTreeMap<(ProgramId, Word8), Word8>,
    vaults: BTreeMap<(ProgramId, u32), u64>,
    /// Σ RAND ever deposited into a vault (a bundle's `burn_r` under an `Invoke`).
    pub rand_in: u64,
    /// Σ RAND ever paid out of a vault as a note.
    pub rand_out: u64,
}

impl ProgramState {
    pub fn from_config(c: &ProgramStateConfig) -> ProgramState {
        ProgramState { cell_fee: c.cell_fee, ..ProgramState::default() }
    }

    /// The cell's value; eight zeros if the program has never written it (or wrote zeros).
    pub fn cell(&self, program: &ProgramId, key: &Word8) -> Word8 {
        self.cells.get(&(*program, *key)).copied().unwrap_or(ZERO)
    }

    /// A page of `program`'s cells in key order, starting after `after`.
    pub fn cells_of(&self, program: &ProgramId, after: Option<&Word8>, limit: usize) -> Vec<Cell> {
        use std::ops::Bound;
        let start = match after {
            Some(k) => Bound::Excluded((*program, *k)),
            None => Bound::Included((*program, ZERO)),
        };
        self.cells
            .range((start, Bound::Unbounded))
            .take_while(|((p, _), _)| p == program)
            .take(limit)
            .map(|((_, key), value)| Cell { key: *key, value: *value })
            .collect()
    }

    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    pub fn vault(&self, program: &ProgramId, asset: u32) -> u64 {
        self.vaults.get(&(*program, asset)).copied().unwrap_or(0)
    }

    /// `program`'s vault, ascending by asset index. Asset 0 is RAND.
    pub fn vault_of(&self, program: &ProgramId) -> Vec<(u32, u64)> {
        self.vaults.range((*program, 0)..=(*program, u32::MAX)).map(|((_, asset), amount)| (*asset, *amount)).collect()
    }

    /// RAND the vaults hold: what went in less what came out.
    pub fn rand_held(&self) -> u64 {
        self.rand_in.saturating_sub(self.rand_out)
    }

    fn write(&mut self, program: &ProgramId, cell: &Cell) {
        if cell.value == ZERO {
            self.cells.remove(&(*program, cell.key));
        } else {
            self.cells.insert((*program, cell.key), cell.value);
        }
    }

    fn set_vault(&mut self, program: &ProgramId, asset: u32, amount: u64) {
        if amount == 0 {
            self.vaults.remove(&(*program, asset));
        } else {
            self.vaults.insert((*program, asset), amount);
        }
    }

    /// `blake3("rand-program-state-1", cells_root ‖ vaults_root)`, each a merkle root over its
    /// map's leaves in map order. Every leaf field is fixed-width.
    pub fn root(&self) -> Hash {
        let cells: Vec<Hash> = self
            .cells
            .iter()
            .map(|((program, key), value)| {
                let mut buf = Vec::with_capacity(96);
                buf.extend_from_slice(program.as_bytes());
                buf.extend_from_slice(&word8_to_bytes(key));
                buf.extend_from_slice(&word8_to_bytes(value));
                Hash::digest_domain(b"rand-program-cell-1", &buf)
            })
            .collect();
        let vaults: Vec<Hash> = self
            .vaults
            .iter()
            .map(|((program, asset), amount)| {
                let mut buf = Vec::with_capacity(44);
                buf.extend_from_slice(program.as_bytes());
                buf.extend_from_slice(&asset.to_be_bytes());
                buf.extend_from_slice(&amount.to_be_bytes());
                Hash::digest_domain(b"rand-program-vault-1", &buf)
            })
            .collect();
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(merkle_root(&cells).as_bytes());
        buf.extend_from_slice(merkle_root(&vaults).as_bytes());
        Hash::digest_domain(b"rand-program-state-1", &buf)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ProgramStateError {
    #[error("program state is disabled on this chain")]
    Disabled,
    #[error("a transition reads at most {MAX_READS} cells, this one reads {0}")]
    TooManyReads(usize),
    #[error("a transition writes at most {MAX_WRITES} cells, this one writes {0}")]
    TooManyWrites(usize),
    #[error("a transition creates at most {MAX_PAYOUTS} notes, this one creates {0}")]
    TooManyPayouts(usize),
    #[error("cell keys must be strictly ascending")]
    UnorderedKeys,
    /// The segment rule (spec §5): the context does not fit the public table a call to this
    /// program is proved over.
    #[error("the transition's context is {context} words; with this program's {public} public words at most {max} fit")]
    ContextTooLong { context: usize, public: usize, max: usize },
    #[error("the bundle burns no token, so the inflow must be none")]
    InflowWithoutBurn,
    #[error("the bundle burns {amount} of asset {asset}, so the inflow must say deposit or burn")]
    InflowMissing { asset: u32, amount: u64 },
    #[error("asset {0} is not a token this program may mint or burn")]
    NotProgramToken(u32),
    #[error("a payout must not be zero")]
    ZeroPayout,
    #[error("a payout of {0} is not a note value")]
    PayoutTooLarge(u64),
    /// A cell read no longer holds the value the transition was proved against. Not a permanent
    /// verdict: it says the state moved, not that the transaction's bytes are wrong.
    #[error("cell {key} is no longer what this transition read")]
    StaleRead { key: String },
    #[error("the vault holds {have} of asset {asset} and the transition pays {want}")]
    VaultShort { asset: u32, have: u64, want: u64 },
    #[error("arithmetic overflow")]
    Overflow,
}

/// What an action reaching this module that it does not own gets (see `tokens::NOT_TOKENS`).
const NOT_PROGRAM_STATE: TxError = TxError::UnsupportedAction("program state");

fn strictly_ascending(cells: &[Cell]) -> bool {
    cells.windows(2).all(|w| w[0].key < w[1].key)
}

fn key_hex(key: &Word8) -> String {
    word8_to_bytes(key).iter().map(|b| format!("{b:02x}")).collect()
}

/// The cells `writes` would create: written non-zero where nothing is stored. What the cell fee
/// is charged on.
pub fn created_cells(state: &ProgramState, program: &ProgramId, writes: &[Cell]) -> u64 {
    writes.iter().filter(|c| c.value != ZERO && state.cell(program, &c.key) == ZERO).count() as u64
}

/// The cell term of an invoke's fee floor, for the ledger's fee checks: `cell_fee` per cell
/// created. Zero for every other action and on a chain without the section.
pub fn cell_fee_of(ledger: &Ledger, action: &Action) -> u64 {
    match (ledger.program_state(), action) {
        (Some(state), Action::Invoke { program, transition, .. }) => {
            state.cell_fee.saturating_mul(created_cells(state, program, &transition.writes))
        }
        _ => 0,
    }
}

/// The byte-level rules of a transition: everything decidable from the action and the bundle's
/// burn fields alone, in the order spec §6 lists them. No state is read.
fn check_shape(tx: &Transaction, transition: &Transition) -> Result<(), TxError> {
    let t = transition;
    if t.reads.len() > MAX_READS {
        return Err(ProgramStateError::TooManyReads(t.reads.len()).into());
    }
    if t.writes.len() > MAX_WRITES {
        return Err(ProgramStateError::TooManyWrites(t.writes.len()).into());
    }
    let payouts = t.pays.len() + t.mints.len();
    if payouts > MAX_PAYOUTS {
        return Err(ProgramStateError::TooManyPayouts(payouts).into());
    }
    if !strictly_ascending(&t.reads) || !strictly_ascending(&t.writes) {
        return Err(ProgramStateError::UnorderedKeys.into());
    }
    let b = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?;
    match (b.burn_a, t.inflow) {
        (0, Inflow::None) => {}
        (0, _) => return Err(ProgramStateError::InflowWithoutBurn.into()),
        (amount, Inflow::None) => {
            return Err(ProgramStateError::InflowMissing { asset: b.burn_asset, amount }.into())
        }
        _ => {}
    }
    for p in t.payouts() {
        if p.amount == 0 {
            return Err(ProgramStateError::ZeroPayout.into());
        }
        // A note at or above 2^63 is unspendable by construction (the bundle guest range-checks
        // every amount), whatever the token registry's own bound says.
        if p.amount >= MAX_NOTE_VALUE {
            return Err(ProgramStateError::PayoutTooLarge(p.amount).into());
        }
        tokens::check_recipient(&p.recipient)?;
    }
    Ok(())
}

/// Whether `asset` is a token `program` may mint and burn.
fn program_token<'a>(
    registry: &'a tokens::TokenRegistry,
    program: &ProgramId,
    asset: u32,
) -> Result<&'a tokens::TokenInfo, TxError> {
    let info = registry.get(asset).ok_or(TokenError::UnknownToken(asset))?;
    match &info.authority {
        MintAuthority::Program(p) if p == program => Ok(info),
        _ => Err(ProgramStateError::NotProgramToken(asset).into()),
    }
}

/// The vault and supply moves a transition makes, decided once and used by both halves: what
/// each vault row ends at, and what each program token's supply moves by.
struct Moves {
    /// `(asset, balance after)`, one entry per asset the transition touches.
    vault: Vec<(u32, u64)>,
    /// A token burned through the bundle (`Inflow::Burn`).
    burned: Option<(u32, u64)>,
    /// `(asset, amount)` per mint, in order.
    minted: Vec<(u32, u64)>,
    rand_in: u64,
    rand_out: u64,
}

fn moves(ledger: &Ledger, tx: &Transaction, program: &ProgramId, t: &Transition) -> Result<Moves, TxError> {
    let state = ledger.program_state().ok_or(ProgramStateError::Disabled)?;
    let registry = ledger.tokens().ok_or(TokenError::Disabled)?;
    let b = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?;
    // Each vault row the transition touches, read once and then moved in place.
    let mut vault: BTreeMap<u32, u64> = BTreeMap::new();
    let row = |vault: &mut BTreeMap<u32, u64>, asset: u32| -> u64 {
        *vault.entry(asset).or_insert_with(|| state.vault(program, asset))
    };
    // What comes in first: a transition may pay out of what it deposits.
    if b.burn_r != 0 {
        let next = row(&mut vault, 0).checked_add(b.burn_r).ok_or(ProgramStateError::Overflow)?;
        vault.insert(0, next);
    }
    let mut burned = None;
    match t.inflow {
        Inflow::None => {}
        Inflow::Deposit => {
            // A registered token, of any authority: a bridged token may sit in a vault (its
            // supply and its backings do not move). RAND never arrives here — a RAND `burn_a` is
            // refused by `check_burn_shape`.
            registry.get(b.burn_asset).ok_or(TokenError::UnknownToken(b.burn_asset))?;
            let next = row(&mut vault, b.burn_asset).checked_add(b.burn_a).ok_or(ProgramStateError::Overflow)?;
            vault.insert(b.burn_asset, next);
        }
        Inflow::Burn => {
            let info = program_token(registry, program, b.burn_asset)?;
            info.total_supply.checked_sub(b.burn_a).ok_or(TokenError::SupplyUnderflow)?;
            burned = Some((b.burn_asset, b.burn_a));
        }
    }
    let mut rand_out = 0u64;
    for p in &t.pays {
        if p.asset != 0 {
            registry.get(p.asset).ok_or(TokenError::UnknownToken(p.asset))?;
        }
        let have = row(&mut vault, p.asset);
        let next =
            have.checked_sub(p.amount).ok_or(ProgramStateError::VaultShort { asset: p.asset, have, want: p.amount })?;
        vault.insert(p.asset, next);
        if p.asset == 0 {
            rand_out = rand_out.checked_add(p.amount).ok_or(ProgramStateError::Overflow)?;
        }
    }
    // Mints, against the supply the burn above (if any) and the earlier mints leave.
    let mut supply: BTreeMap<u32, u64> = BTreeMap::new();
    let mut minted = Vec::with_capacity(t.mints.len());
    for p in &t.mints {
        let info = program_token(registry, program, p.asset)?;
        let before = *supply.entry(p.asset).or_insert_with(|| match burned {
            Some((asset, amount)) if asset == p.asset => info.total_supply - amount,
            _ => info.total_supply,
        });
        let after = registry.check_note_bound(before, p.amount)?;
        supply.insert(p.asset, after);
        minted.push((p.asset, p.amount));
    }
    Ok(Moves { vault: vault.into_iter().collect(), burned, minted, rand_in: b.burn_r, rand_out })
}

/// The two rules of an `Invoke` that read this ledger's moving state (spec §6, steps 7–8 and
/// the registry half of 4–5): the vault can pay and the supplies can move, and every cell read
/// still holds the value the transition declares. Map lookups and compares, no hash.
fn check_state(
    ledger: &Ledger,
    state: &ProgramState,
    tx: &Transaction,
    program: &ProgramId,
    t: &Transition,
) -> Result<(), TxError> {
    moves(ledger, tx, program, t)?;
    for c in &t.reads {
        if state.cell(program, &c.key) != c.value {
            return Err(ProgramStateError::StaleRead { key: key_hex(&c.key) }.into());
        }
    }
    Ok(())
}

/// Whether `tx`, an `Invoke` that [`validate`] accepted on an earlier state, can still apply on
/// `ledger`: exactly the state-dependent half of [`validate`] (the vault, the supplies, the cells
/// read), with the verdict [`validate`] would give. For a node's pool, which asks at every tip:
/// another transaction writing a cell this one read, or draining the vault it pays from, makes it
/// inapplicable for good unless the state comes back, and it must leave the pool rather than be
/// offered to every block. Nothing here costs a hash or a proof. `Ok` for every other action.
pub fn still_applies(ledger: &Ledger, tx: &Transaction) -> Result<(), TxError> {
    let Action::Invoke { program, transition, .. } = &tx.action else {
        return Ok(());
    };
    let state = ledger.program_state().ok_or(ProgramStateError::Disabled)?;
    // The counts first, as `check_shape` has them: this may run before `validate` has (a pool's
    // pre-screen), and an oversized transition must not buy a lookup per entry.
    if transition.reads.len() > MAX_READS {
        return Err(ProgramStateError::TooManyReads(transition.reads.len()).into());
    }
    let payouts = transition.pays.len() + transition.mints.len();
    if payouts > MAX_PAYOUTS {
        return Err(ProgramStateError::TooManyPayouts(payouts).into());
    }
    check_state(ledger, state, tx, program, transition)
}

/// The action step of admission for an `Invoke` (spec §6, steps 2–8). The call proof, its fee
/// and the bundle's proof are the common path's, after this.
///
/// Nothing is written: every refusal [`apply`] could make is made here.
pub(super) fn validate(
    ledger: &Ledger,
    tx: &Transaction,
    action: &Action,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    let Action::Invoke { program, transition, .. } = action else {
        return Err(NOT_PROGRAM_STATE);
    };
    // The gate is absolute: on a chain without the section nothing about an invoke is looked at.
    let state = ledger.program_state().ok_or(ProgramStateError::Disabled)?;
    check_shape(tx, transition)?;
    // The program, and the segment rule against its public input's length.
    let record = ledger.program(program).ok_or(TxError::UnknownProgram(*program))?;
    let public = record.public_len as usize;
    let context = transition.context_words();
    if !segment_fits(public, context) {
        let max = (public_table_rows(public + TX_BINDING_WORDS) as usize - 1).saturating_sub(public + TX_BINDING_WORDS);
        return Err(ProgramStateError::ContextTooLong { context, public, max }.into());
    }
    // The vault and the supplies, then the reads: all map lookups.
    check_state(ledger, state, tx, program, transition)?;
    // Every note the transition creates is new: against the tree, the bundle's own four, and
    // each other. The hashes are the most expensive thing here, so they come last.
    let b = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?;
    let mut seen: Vec<Word8> = Vec::with_capacity(MAX_PAYOUTS);
    for p in transition.payouts() {
        let cm = payout_commitment(p, b.time, executor);
        if ledger.has_commitment(&cm) || b.commitments.contains(&cm) || seen.contains(&cm) {
            return Err(TxError::CommitmentExists(cm));
        }
        seen.push(cm);
    }
    Ok(())
}

/// The apply step, in lockstep with [`validate`]: credit what came in, debit what is paid, move
/// the supplies, write the cells, append the notes — pays, then mints.
pub(super) fn apply(
    ledger: &mut Ledger,
    tx: &Transaction,
    action: &Action,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    let Action::Invoke { program, transition, .. } = action else {
        return Err(NOT_PROGRAM_STATE);
    };
    // The gate again, before any write (see `tokens::apply`).
    if ledger.program_state().is_none() {
        return Err(ProgramStateError::Disabled.into());
    }
    let m = moves(ledger, tx, program, transition)?;
    let time = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?.time;
    {
        let registry = ledger.tokens_mut().ok_or(TokenError::Disabled)?;
        if let Some((asset, amount)) = m.burned {
            registry.sub_supply(asset, amount)?;
        }
        for (asset, amount) in &m.minted {
            registry.add_supply(*asset, *amount)?;
        }
    }
    {
        let state = ledger.program_state_mut().ok_or(ProgramStateError::Disabled)?;
        for (asset, amount) in &m.vault {
            state.set_vault(program, *asset, *amount);
        }
        state.rand_in = state.rand_in.checked_add(m.rand_in).ok_or(ProgramStateError::Overflow)?;
        state.rand_out = state.rand_out.checked_add(m.rand_out).ok_or(ProgramStateError::Overflow)?;
        for c in &transition.writes {
            state.write(program, c);
        }
    }
    for p in transition.payouts() {
        let cm = payout_commitment(p, time, executor);
        ledger.deposit(cm, executor)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::Keypair;
    use crate::gas;
    use crate::ledger::tokens::TokenRegistry;
    use crate::ledger::{BlockError, ValidatorEntry, VerifiedProofs};
    use crate::notes::{Bundle, KEM_EK_BYTES};
    use crate::program::program_id;

    const HC: Word8 = [11; 8];
    const CHAIN: u64 = 7;
    const REG_FEE: u64 = 1_000_000_000;
    const CELL_FEE: u64 = 10_000_000;
    /// Generous: covers the base, a call at any tier and a few cells.
    const FEE: u64 = 1_000_000_000;
    const WORDS: [u32; 4] = [0x13; 4];

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
    }

    fn proposer() -> Keypair {
        Keypair::from_seed([1; 32]).unwrap()
    }

    fn recipient(n: u32) -> ShieldedAddress {
        ShieldedAddress { pk: [n; 8], kem_ek: vec![6; KEM_EK_BYTES] }
    }

    fn pid() -> ProgramId {
        program_id(0, &WORDS)
    }

    fn key(n: u32) -> Word8 {
        [n, 0, 0, 0, 0, 0, 0, 0]
    }

    fn cell(k: u32, v: u32) -> Cell {
        Cell { key: key(k), value: if v == 0 { ZERO } else { [v, 0, 0, 0, 0, 0, 0, 1] } }
    }

    fn pay(asset: u32, amount: u64, n: u32) -> Payout {
        Payout { asset, amount, recipient: recipient(n), r: [n + 100; 8], envelope: env() }
    }

    fn bundle(l: &Ledger, seed: u32, fee: u64, burn_r: u64, burn_asset: u32, burn_a: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.anchors().back().expect("the genesis anchor").1,
            nullifiers: crate::notes::pad4([[seed; 8], [seed + 1; 8]]),
            commitments: crate::notes::pad4([[seed + 2; 8], [seed + 3; 8]]),
            fee,
            burn_a,
            burn_r,
            burn_asset,
            time: l.height() as u32,
            envelopes: [env(), env(), env(), env()],
            proof: vec![],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
        b
    }

    /// A ledger with `tokens`, optionally `program_state`, the test program deployed, token 1
    /// ("plain", a `Key` token) and — under the section — token 2 (the program's own).
    fn ledger_with(section: bool) -> Ledger {
        let k = proposer();
        let entry = ValidatorEntry {
            public_key: k.public_key().clone(),
            stake: 10,
            pending: Vec::new(),
            rewards: 0,
            payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
            nonce: 0,
            activation_epoch: 0,
        };
        let mut l = Ledger::new(CHAIN, HC, [(k.address(), entry)].into_iter().collect(), &StubExecutor);
        l.set_tokens(Some(TokenRegistry::new(REG_FEE)));
        if section {
            l.set_program_state(Some(ProgramState::from_config(&ProgramStateConfig { cell_fee: CELL_FEE })));
        }
        l.set_genesis_supply(1_000_000_000_000, 10);
        l.set_height(1);
        l.set_timestamp_ms(1_000_000);
        let deploy = Action::Deploy { base_pc: 0, words: WORDS.to_vec(), public: vec![] };
        let fee = gas::fee_floor(&deploy);
        let tx = StubExecutor::bound(Transaction::shielded(CHAIN, bundle(&l, 900, fee, 0, 0, 0), deploy));
        apply(&mut l, &tx).unwrap();
        let key_token = register(&l, MintAuthority::Key(Keypair::from_seed([21; 32]).unwrap().public_key().clone()), 910);
        apply(&mut l, &key_token).unwrap();
        if section {
            let own = register(&l, MintAuthority::Program(pid()), 920);
            apply(&mut l, &own).unwrap();
        }
        l
    }

    fn ledger() -> Ledger {
        ledger_with(true)
    }

    fn register(l: &Ledger, authority: MintAuthority, seed: u32) -> Transaction {
        StubExecutor::bound(Transaction::shielded(
            CHAIN,
            bundle(l, seed, gas::BUNDLE_BASE + REG_FEE, 0, 0, 0),
            Action::RegisterToken {
                name: "Test Coin".into(),
                symbol: "TST".into(),
                decimals: 6,
                authority,
                initial: None,
                salt: [seed as u8; 32],
                index: l.tokens().unwrap().next_index(),
            },
        ))
    }

    fn apply(l: &mut Ledger, tx: &Transaction) -> Result<Option<crate::ledger::CallReceiptData>, TxError> {
        l.apply_tx(tx, &proposer().address(), &StubExecutor)
    }

    fn empty() -> Transition {
        Transition { reads: vec![], writes: vec![], inflow: Inflow::None, pays: vec![], mints: vec![] }
    }

    /// An `Invoke` whose stub call proof is made over the segment the ledger will build, and
    /// whose bundle is bound — a wallet's order: the call proof first, then the bundle.
    fn invoke_with(l: &Ledger, seed: u32, fee: u64, burns: (u64, u32, u64), t: Transition) -> Transaction {
        let mut tx = Transaction::shielded(
            CHAIN,
            bundle(l, seed, fee, burns.0, burns.1, burns.2),
            Action::Invoke { program: pid(), proof: Vec::new(), input_envelope: None, transition: t },
        );
        reprove(l, &mut tx);
        tx
    }

    fn reprove(l: &Ledger, tx: &mut Transaction) {
        let record = l.program(&pid()).expect("deployed");
        let segment = l.invoke_segment(record, tx).expect("an invoke with a bundle");
        let call = StubExecutor::make_proof_with_public(&pid(), 10, [9, 8, 7, 6, 5, 4, 3, 2], &segment);
        let Action::Invoke { proof, .. } = &mut tx.action else { panic!("an invoke") };
        *proof = call;
        StubExecutor::bind(tx);
    }

    fn invoke(l: &Ledger, seed: u32, burns: (u64, u32, u64), t: Transition) -> Transaction {
        invoke_with(l, seed, FEE, burns, t)
    }

    fn refusal(l: &Ledger, tx: &Transaction) -> TxError {
        l.validate(tx, &StubExecutor).expect_err("refused")
    }

    fn ps(e: ProgramStateError) -> TxError {
        TxError::ProgramState(e)
    }

    #[test]
    fn without_the_section_an_invoke_is_refused_before_anything_else() {
        let l = ledger_with(false);
        // Malformed in every way the module checks — and the gate is still what it hears.
        let t = Transition { reads: vec![cell(2, 0), cell(1, 0)], ..empty() };
        let mut tx = Transaction::shielded(
            CHAIN,
            bundle(&l, 1, FEE, 0, 0, 0),
            Action::Invoke { program: Hash([9; 32]), proof: vec![1], input_envelope: None, transition: t },
        );
        StubExecutor::bind(&mut tx);
        assert_eq!(refusal(&l, &tx), ps(ProgramStateError::Disabled));
        // And a token cannot name a program as its authority there.
        assert_eq!(
            refusal(&l, &register(&l, MintAuthority::Program(pid()), 930)),
            TxError::Token(TokenError::AuthorityNotAllowed)
        );
        assert!(l.program_state().is_none());
    }

    #[test]
    fn a_program_token_registers_under_the_section_with_no_initial_supply() {
        let l = ledger();
        let info = l.tokens().unwrap().get(2).expect("token 2");
        assert_eq!(info.authority, MintAuthority::Program(pid()));
        assert_eq!(info.total_supply, 0);
        let mut tx = register(&l, MintAuthority::Program(pid()), 940);
        if let Action::RegisterToken { initial, .. } = &mut tx.action {
            *initial = Some(crate::types::InitialMint { amount: 5, recipient: recipient(4), r: [7; 8], time: 1, envelope: env() });
        }
        StubExecutor::bind(&mut tx);
        assert_eq!(refusal(&l, &tx), TxError::Token(TokenError::AuthorityNotAllowed));
    }

    #[test]
    fn an_invoke_deposits_writes_pays_and_mints() {
        let mut l = ledger();
        let root0 = l.state_root();
        let supply0 = l.audit().total_supply();
        assert!(l.audit().invariant_holds());
        // Deposit 1 000 RAND units and 500 of token 1; create cell 1; mint 40 of token 2.
        let t = Transition {
            reads: vec![cell(1, 0)],
            writes: vec![cell(1, 5)],
            inflow: Inflow::Deposit,
            pays: vec![],
            mints: vec![pay(2, 40, 1)],
        };
        let tx = invoke(&l, 10, (1_000, 1, 500), t.clone());
        l.validate(&tx, &StubExecutor).unwrap();
        let leaves0 = l.next_index();
        let receipt = apply(&mut l, &tx).unwrap().expect("an invoke has a call's receipt");
        assert_eq!((receipt.program, receipt.tier, receipt.outputs), (pid(), 10, [9, 8, 7, 6, 5, 4, 3, 2]));
        let state = l.program_state().unwrap();
        assert_eq!(state.vault_of(&pid()), vec![(0, 1_000), (1, 500)]);
        assert_eq!(state.cell(&pid(), &key(1)), cell(1, 5).value);
        assert_eq!(state.cells_of(&pid(), None, 10), vec![cell(1, 5)]);
        assert_eq!((state.rand_in, state.rand_out), (1_000, 0));
        assert_eq!(l.tokens().unwrap().get(2).unwrap().total_supply, 40);
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 0, "a deposit moves no supply");
        // The bundle's four leaves, then the one minted note, at the bundle's time.
        assert_eq!(l.next_index(), leaves0 + 5);
        assert!(l.has_commitment(&payout_commitment(&t.mints[0], 1, &StubExecutor)));
        assert_ne!(l.state_root(), root0);
        assert_eq!(l.audit().total_supply(), supply0, "RAND moved from the pool into a vault");
        assert!(l.audit().invariant_holds());

        // Pay 300 RAND and 200 of token 1 back out, burn 15 of token 2, rewrite the cell.
        let t = Transition {
            reads: vec![cell(1, 5)],
            writes: vec![cell(1, 6)],
            inflow: Inflow::Burn,
            pays: vec![pay(0, 300, 2), pay(1, 200, 3)],
            mints: vec![],
        };
        let tx = invoke(&l, 20, (0, 2, 15), t);
        apply(&mut l, &tx).unwrap();
        let state = l.program_state().unwrap();
        assert_eq!(state.vault_of(&pid()), vec![(0, 700), (1, 300)]);
        assert_eq!((state.rand_in, state.rand_out, state.rand_held()), (1_000, 300, 700));
        assert_eq!(l.tokens().unwrap().get(2).unwrap().total_supply, 25);
        assert_eq!(l.audit().total_supply(), supply0);
        assert!(l.audit().invariant_holds());
        assert_eq!((l.audit().program_rand_out, l.audit().program_rand_held), (300, 700));

        // Writing zeros removes the cell, and draining a vault row removes the row.
        let t = Transition { reads: vec![], writes: vec![cell(1, 0)], pays: vec![pay(1, 300, 4)], ..empty() };
        let tx = invoke(&l, 30, (0, 0, 0), t);
        apply(&mut l, &tx).unwrap();
        let state = l.program_state().unwrap();
        assert_eq!(state.cell_count(), 0);
        assert_eq!(state.vault_of(&pid()), vec![(0, 700)]);
    }

    #[test]
    fn a_transition_may_pay_out_of_what_it_deposits_and_no_more() {
        let l = ledger();
        let t = Transition { pays: vec![pay(0, 1_000, 1)], ..empty() };
        l.validate(&invoke(&l, 10, (1_000, 0, 0), t), &StubExecutor).unwrap();
        let t = Transition { pays: vec![pay(0, 1_001, 1)], ..empty() };
        assert_eq!(
            refusal(&l, &invoke(&l, 10, (1_000, 0, 0), t)),
            ps(ProgramStateError::VaultShort { asset: 0, have: 1_000, want: 1_001 })
        );
        // Two pays of one asset are judged together.
        let t = Transition { pays: vec![pay(0, 600, 1), pay(0, 600, 2)], ..empty() };
        assert_eq!(
            refusal(&l, &invoke(&l, 10, (1_000, 0, 0), t)),
            ps(ProgramStateError::VaultShort { asset: 0, have: 400, want: 600 })
        );
    }

    #[test]
    fn a_stale_read_is_refused_and_a_fresh_one_applies() {
        let mut l = ledger();
        let tx = invoke(&l, 10, (0, 0, 0), Transition { writes: vec![cell(1, 5)], ..empty() });
        apply(&mut l, &tx).unwrap();
        // Proved against the cell's old value (absent).
        let stale = invoke(&l, 20, (0, 0, 0), Transition { reads: vec![cell(1, 0)], writes: vec![cell(1, 7)], ..empty() });
        let TxError::ProgramState(ProgramStateError::StaleRead { key: k }) = refusal(&l, &stale) else { panic!("stale") };
        assert_eq!(k, key_hex(&key(1)));
        let fresh = invoke(&l, 20, (0, 0, 0), Transition { reads: vec![cell(1, 5)], writes: vec![cell(1, 7)], ..empty() });
        apply(&mut l, &fresh).unwrap();
        assert_eq!(l.program_state().unwrap().cell(&pid(), &key(1)), cell(1, 7).value);
    }

    /// The verified set vouches for a transaction's proofs, never for its reads: a transaction
    /// admitted at one state is refused at another on the comparison, with no proof looked at.
    #[test]
    fn the_verified_set_does_not_vouch_for_a_read() {
        struct All;
        impl VerifiedProofs for All {
            fn contains(&self, _: &Hash) -> bool {
                true
            }
            fn is_empty(&self) -> bool {
                false
            }
        }
        let mut l = ledger();
        let admitted = invoke(&l, 20, (0, 0, 0), Transition { reads: vec![cell(1, 0)], writes: vec![cell(1, 7)], ..empty() });
        l.validate(&admitted, &StubExecutor).unwrap();
        let tx = invoke(&l, 10, (0, 0, 0), Transition { writes: vec![cell(1, 5)], ..empty() });
        apply(&mut l, &tx).unwrap();
        let err = l.apply_tx_with(&admitted, &proposer().address(), &StubExecutor, &All).unwrap_err();
        assert!(matches!(err, TxError::ProgramState(ProgramStateError::StaleRead { .. })), "{err:?}");
    }

    #[test]
    fn two_invokes_in_a_block_apply_on_disjoint_cells_and_conflict_on_one() {
        let l = ledger();
        let a = invoke(&l, 10, (0, 0, 0), Transition { reads: vec![cell(1, 0)], writes: vec![cell(1, 5)], ..empty() });
        let b = invoke(&l, 20, (0, 0, 0), Transition { reads: vec![cell(2, 0)], writes: vec![cell(2, 5)], ..empty() });
        let c = invoke(&l, 30, (0, 0, 0), Transition { reads: vec![cell(1, 0)], writes: vec![cell(1, 9)], ..empty() });
        let mut both = l.clone();
        both.apply_transactions(&[a.clone(), b], &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(both.program_state().unwrap().cell_count(), 2);
        let mut clash = l.clone();
        let err = clash.apply_transactions(&[a, c], &proposer().address(), &StubExecutor).unwrap_err();
        assert!(
            matches!(&err, BlockError::InvalidTx { index: 1, error: TxError::ProgramState(ProgramStateError::StaleRead { .. }) }),
            "{err:?}"
        );
        assert_eq!(clash, l, "a refused block leaves the ledger as it was");
    }

    #[test]
    fn the_proof_is_bound_to_the_transition_the_burns_and_the_recipients() {
        let l = ledger();
        let t = Transition {
            reads: vec![cell(1, 0)],
            writes: vec![cell(1, 5)],
            inflow: Inflow::Deposit,
            pays: vec![pay(0, 10, 1)],
            mints: vec![pay(2, 40, 2)],
        };
        let good = invoke(&l, 10, (1_000, 1, 500), t);
        l.validate(&good, &StubExecutor).unwrap();
        type Change = fn(&mut Transaction);
        fn tr(t: &mut Transaction) -> &mut Transition {
            let Action::Invoke { transition, .. } = &mut t.action else { panic!("an invoke") };
            transition
        }
        let cases: Vec<(&str, Change)> = vec![
            ("a written value", |t| tr(t).writes[0].value[1] = 77),
            ("a written key", |t| tr(t).writes[0].key[7] = 1),
            ("a pay's amount", |t| tr(t).pays[0].amount = 11),
            ("a mint's amount", |t| tr(t).mints[0].amount = 41),
            ("a pay's recipient", |t| tr(t).pays[0].recipient.pk = [9; 8]),
            ("a mint's blinding", |t| tr(t).mints[0].r = [9; 8]),
            ("an envelope", |t| tr(t).mints[0].envelope.body[0] ^= 1),
            ("burn_r", |t| t.bundle.as_mut().unwrap().burn_r = 999),
            ("burn_a", |t| t.bundle.as_mut().unwrap().burn_a = 501),
        ];
        for (name, change) in cases {
            let mut tx = good.clone();
            change(&mut tx);
            // The copier re-makes the bundle's digest and binding but cannot re-make the call proof.
            let b = tx.bundle.as_mut().unwrap();
            let d = StubExecutor.bundle_digest(&b.digest_input());
            b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
            StubExecutor::bind(&mut tx);
            assert_eq!(
                refusal(&l, &tx),
                TxError::InvalidProof(crate::confidential::ConfidentialError::InvalidProof("PublicValues".into())),
                "{name}"
            );
        }
    }

    #[test]
    fn the_shape_rules() {
        let l = ledger();
        let many = |n: u32| (1..=n).map(|i| cell(i, 1)).collect::<Vec<_>>();
        let check = |t: Transition, burns: (u64, u32, u64)| refusal(&l, &invoke(&l, 10, burns, t));
        assert_eq!(check(Transition { reads: many(9), ..empty() }, (0, 0, 0)), ps(ProgramStateError::TooManyReads(9)));
        assert_eq!(check(Transition { writes: many(9), ..empty() }, (0, 0, 0)), ps(ProgramStateError::TooManyWrites(9)));
        let five = Transition { pays: (1..=3).map(|n| pay(0, 1, n)).collect(), mints: vec![pay(2, 1, 4), pay(2, 1, 5)], ..empty() };
        assert_eq!(check(five, (10, 0, 0)), ps(ProgramStateError::TooManyPayouts(5)));
        assert_eq!(
            check(Transition { reads: vec![cell(2, 0), cell(1, 0)], ..empty() }, (0, 0, 0)),
            ps(ProgramStateError::UnorderedKeys)
        );
        assert_eq!(
            check(Transition { writes: vec![cell(1, 1), cell(1, 2)], ..empty() }, (0, 0, 0)),
            ps(ProgramStateError::UnorderedKeys),
            "a key twice is not ascending"
        );
        assert_eq!(check(Transition { inflow: Inflow::Deposit, ..empty() }, (0, 0, 0)), ps(ProgramStateError::InflowWithoutBurn));
        assert_eq!(check(empty(), (0, 1, 5)), ps(ProgramStateError::InflowMissing { asset: 1, amount: 5 }));
        assert_eq!(check(Transition { pays: vec![pay(0, 0, 1)], ..empty() }, (5, 0, 0)), ps(ProgramStateError::ZeroPayout));
        assert_eq!(
            check(Transition { pays: vec![pay(0, 1 << 63, 1)], ..empty() }, (5, 0, 0)),
            ps(ProgramStateError::PayoutTooLarge(1 << 63))
        );
        let mut short = pay(0, 1, 1);
        short.recipient.kem_ek.pop();
        assert!(matches!(
            check(Transition { pays: vec![short], ..empty() }, (5, 0, 0)),
            TxError::Token(TokenError::BadRecipientKey { .. })
        ));
        // Four reads and four writes is 139 words of context: past the 119 that fit beside the
        // binding in a 128-row public table.
        assert_eq!(
            check(Transition { reads: many(4), writes: many(4), ..empty() }, (0, 0, 0)),
            ps(ProgramStateError::ContextTooLong { context: 139, public: 0, max: 119 })
        );
        // A RAND burn through `burn_a` stays refused for an invoke, as for everything.
        assert_eq!(check(Transition { inflow: Inflow::Deposit, ..empty() }, (0, 0, 5)), TxError::NonCanonicalRandBurn(5));
        assert_eq!(refusal(&l, &{
            let mut tx = invoke(&l, 10, (0, 0, 0), empty());
            if let Action::Invoke { program, .. } = &mut tx.action {
                *program = Hash([9; 32]);
            }
            StubExecutor::bind(&mut tx);
            tx
        }), TxError::UnknownProgram(Hash([9; 32])));
    }

    #[test]
    fn only_the_programs_own_token_is_minted_or_burned() {
        let l = ledger();
        let check = |t: Transition, burns: (u64, u32, u64)| refusal(&l, &invoke(&l, 10, burns, t));
        assert_eq!(check(Transition { mints: vec![pay(1, 5, 1)], ..empty() }, (0, 0, 0)), ps(ProgramStateError::NotProgramToken(1)));
        assert_eq!(check(Transition { mints: vec![pay(0, 5, 1)], ..empty() }, (0, 0, 0)), TxError::Token(TokenError::UnknownToken(0)));
        assert_eq!(check(Transition { mints: vec![pay(9, 5, 1)], ..empty() }, (0, 0, 0)), TxError::Token(TokenError::UnknownToken(9)));
        assert_eq!(check(Transition { inflow: Inflow::Burn, ..empty() }, (0, 1, 5)), ps(ProgramStateError::NotProgramToken(1)));
        assert_eq!(
            check(Transition { inflow: Inflow::Burn, ..empty() }, (0, 2, 5)),
            TxError::Token(TokenError::SupplyUnderflow),
            "nothing of token 2 exists yet"
        );
        assert_eq!(check(Transition { inflow: Inflow::Deposit, ..empty() }, (0, 9, 5)), TxError::Token(TokenError::UnknownToken(9)));
        assert_eq!(check(Transition { pays: vec![pay(9, 5, 1)], ..empty() }, (0, 0, 0)), TxError::Token(TokenError::UnknownToken(9)));
        // Another program's invoke cannot touch token 2 either: deploy a second program and try.
        let mut l2 = l.clone();
        let words = vec![0x13u32; 5];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let fee = gas::fee_floor(&deploy);
        let tx = StubExecutor::bound(Transaction::shielded(CHAIN, bundle(&l2, 950, fee, 0, 0, 0), deploy));
        apply(&mut l2, &tx).unwrap();
        let other = program_id(0, &words);
        let mut tx = Transaction::shielded(
            CHAIN,
            bundle(&l2, 10, FEE, 0, 0, 0),
            Action::Invoke {
                program: other,
                proof: Vec::new(),
                input_envelope: None,
                transition: Transition { mints: vec![pay(2, 5, 1)], ..empty() },
            },
        );
        StubExecutor::bind(&mut tx);
        assert_eq!(refusal(&l2, &tx), ps(ProgramStateError::NotProgramToken(2)));
    }

    #[test]
    fn a_created_cell_costs_the_cell_fee_and_a_rewrite_does_not() {
        let mut l = ledger();
        let floor = gas::BUNDLE_BASE + gas::call_fee(10, 0);
        let create = Transition { writes: vec![cell(1, 5), cell(2, 5)], ..empty() };
        let min = floor + 2 * CELL_FEE;
        assert_eq!(
            refusal(&l, &invoke_with(&l, 10, min - 1, (0, 0, 0), create.clone())),
            TxError::FeeTooLow { min, fee: min - 1 }
        );
        let tx = invoke_with(&l, 10, min, (0, 0, 0), create);
        apply(&mut l, &tx).unwrap();
        // Rewriting, deleting and writing zeros over nothing create no cell.
        let rewrite = Transition { writes: vec![cell(1, 6), cell(2, 0), cell(3, 0)], ..empty() };
        assert_eq!(created_cells(l.program_state().unwrap(), &pid(), &rewrite.writes), 0);
        let tx = invoke_with(&l, 20, floor, (0, 0, 0), rewrite);
        apply(&mut l, &tx).unwrap();
    }

    #[test]
    fn a_payout_note_must_be_new() {
        let mut l = ledger();
        let t = Transition { pays: vec![pay(0, 5, 1)], ..empty() };
        let tx = invoke(&l, 10, (100, 0, 0), t.clone());
        apply(&mut l, &tx).unwrap();
        // The same recipient, amount, blinding and time again is the same leaf.
        let cm = payout_commitment(&t.pays[0], 1, &StubExecutor);
        assert_eq!(refusal(&l, &invoke(&l, 20, (0, 0, 0), t.clone())), TxError::CommitmentExists(cm));
        // And twice inside one transition.
        let twice = Transition { pays: vec![pay(0, 6, 2), pay(0, 6, 2)], ..empty() };
        let cm = payout_commitment(&twice.pays[0], 1, &StubExecutor);
        assert_eq!(refusal(&l, &invoke(&l, 30, (0, 0, 0), twice)), TxError::CommitmentExists(cm));
    }

    /// `still_applies` is `validate`'s state-dependent half, with `validate`'s verdicts: what a
    /// pool asks of a transaction it already verified, at every tip.
    #[test]
    fn still_applies_answers_the_state_rules_alone() {
        let mut l = ledger();
        let fund = invoke(&l, 10, (1_000, 0, 0), empty());
        apply(&mut l, &fund).unwrap();
        let reader = invoke(&l, 20, (0, 0, 0), Transition { reads: vec![cell(1, 0)], writes: vec![cell(1, 7)], ..empty() });
        let payer = invoke(&l, 30, (0, 0, 0), Transition { pays: vec![pay(0, 600, 1)], ..empty() });
        let minter = invoke(&l, 40, (0, 0, 0), Transition { mints: vec![pay(2, 5, 3)], ..empty() });
        for tx in [&reader, &payer, &minter, &fund] {
            assert_eq!(still_applies(&l, tx), Ok(()));
            assert_eq!(still_applies(&l, tx), l.validate(tx, &StubExecutor).or_else(|e| match e {
                // `fund`'s own nullifiers are spent by now: not this function's question.
                TxError::Spent(_) => Ok(()),
                e => Err(e),
            }));
        }
        // Another invoke writes the cell `reader` read, and another drains the vault `payer` pays from.
        let writer = invoke(&l, 50, (0, 0, 0), Transition { writes: vec![cell(1, 5)], ..empty() });
        let drain = invoke(&l, 60, (0, 0, 0), Transition { pays: vec![pay(0, 600, 2)], ..empty() });
        l.apply_transactions(&[writer, drain], &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(still_applies(&l, &reader), Err(ps(ProgramStateError::StaleRead { key: key_hex(&key(1)) })));
        assert_eq!(still_applies(&l, &reader), Err(refusal(&l, &reader)), "validate's own verdict");
        assert_eq!(still_applies(&l, &payer), Err(ps(ProgramStateError::VaultShort { asset: 0, have: 400, want: 600 })));
        assert_eq!(still_applies(&l, &payer), Err(refusal(&l, &payer)));
        assert_eq!(still_applies(&l, &minter), Ok(()), "untouched by either");
        // Not an invoke: nothing to ask. Without the section: the gate.
        let deploy = Transaction::shielded(CHAIN, bundle(&l, 70, FEE, 0, 0, 0), Action::None);
        assert_eq!(still_applies(&l, &deploy), Ok(()));
        assert_eq!(still_applies(&ledger_with(false), &reader), Err(ps(ProgramStateError::Disabled)));
        // An oversized transition buys no lookups.
        let many = Transition { reads: (1..=9).map(|i| cell(i, 0)).collect(), ..empty() };
        assert_eq!(still_applies(&l, &invoke(&l, 80, (0, 0, 0), many)), Err(ps(ProgramStateError::TooManyReads(9))));
    }

    /// `Ledger::derived_commitments`: an invoke's payout notes, pays then mints, stamped with the
    /// bundle's time — what a pool claims and an indexer appends — and the singular form's one
    /// note for every other action.
    #[test]
    fn an_invokes_derived_commitments_are_its_payout_notes_in_order() {
        let mut l = ledger();
        let t = Transition { pays: vec![pay(0, 10, 1), pay(0, 20, 2)], mints: vec![pay(2, 40, 3)], ..empty() };
        let tx = invoke(&l, 10, (100, 0, 0), t.clone());
        let time = tx.bundle.as_ref().unwrap().time;
        let want: Vec<Word8> = t.payouts().map(|p| payout_commitment(p, time, &StubExecutor)).collect();
        assert_eq!(l.derived_commitments(&tx, &StubExecutor), want);
        assert_eq!(l.derived_commitment(&tx.action, &StubExecutor), None, "the singular form cannot see the bundle's time");
        let first = l.next_index();
        apply(&mut l, &tx).unwrap();
        assert_eq!(l.next_index(), first + 4 + 3, "the bundle's four, then the three payouts");
        assert!(want.iter().all(|cm| l.has_commitment(cm)));
        // No payouts, no notes; a transition over the cap derives nothing (and is refused).
        assert!(l.derived_commitments(&invoke(&l, 20, (0, 0, 0), empty()), &StubExecutor).is_empty());
        let five = Transition { pays: (1..=5).map(|n| pay(0, 1, n)).collect(), ..empty() };
        assert!(l.derived_commitments(&invoke(&l, 30, (10, 0, 0), five), &StubExecutor).is_empty());
        // Every other action answers as the singular form does.
        let reg = register(&l, MintAuthority::Program(pid()), 960);
        assert_eq!(l.derived_commitments(&reg, &StubExecutor), Vec::<Word8>::new());
    }

    /// The v0.6 canonical-proof rule (`hardening_v6`, which the section requires) reaches an
    /// invoke's call proof as it reaches a call's: a header field the verifier accepts at more
    /// than one value lets whoever relays the transaction re-encode the proof into a second
    /// transaction id, and the call binding blanks the proof, so both ids would verify.
    #[test]
    fn the_canonical_proof_rule_covers_an_invokes_call_proof() {
        let l = ledger();
        let tx = invoke(&l, 10, (0, 0, 0), Transition { writes: vec![cell(1, 5)], ..empty() });
        let Action::Invoke { proof, .. } = &tx.action else { panic!("an invoke") };
        let flagged = proof.clone();
        let check = |p: &[u8]| (p == flagged.as_slice()).then(|| "memory height 17".to_string());
        assert_eq!(
            crate::ledger::non_canonical_proofs(&tx, &check),
            Some(TxError::NonCanonicalProof("call proof: memory height 17".into()))
        );
    }

    /// The context layout is the program ABI: pinned word for word.
    #[test]
    fn the_context_words_are_pinned() {
        let t = Transition {
            reads: vec![Cell { key: [1, 2, 3, 4, 5, 6, 7, 8], value: [11, 12, 13, 14, 15, 16, 17, 18] }],
            writes: vec![Cell { key: [21, 22, 23, 24, 25, 26, 27, 28], value: [31, 32, 33, 34, 35, 36, 37, 38] }],
            inflow: Inflow::Burn,
            pays: vec![pay(3, (7 << 32) | 9, 1)],
            mints: vec![pay(4, 5, 2)],
        };
        let mut want = vec![1, 1, 1, 1, 1, 0xdddd_dddd, 0xcccc_cccc, 2, 6, 0xbbbb_bbbb, 0xaaaa_aaaa];
        want.extend([1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18]);
        want.extend([21, 22, 23, 24, 25, 26, 27, 28, 31, 32, 33, 34, 35, 36, 37, 38]);
        want.extend([3, 9, 7, 4, 5, 0]);
        let got = t.context(0xcccc_cccc_dddd_dddd, 6, 0xaaaa_aaaa_bbbb_bbbb);
        assert_eq!(got, want);
        assert_eq!(got.len(), t.context_words());
        assert_eq!(empty().context(0, 0, 0), vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(invoke_segment(&[5, 6], &[7; 8], &[8, 9]), vec![5, 6, 7, 7, 7, 7, 7, 7, 7, 7, 8, 9]);
        // The segment rule at its edges: 119 context words fit beside the binding, 120 do not;
        // a public input moves the edge with it.
        assert!(segment_fits(0, 119) && !segment_fits(0, 120));
        assert!(segment_fits(100, 19) && !segment_fits(100, 20));
        assert!(segment_fits(200, 47) && !segment_fits(200, 48), "a 256-row table");
        assert_eq!((public_table_rows(0), public_table_rows(127), public_table_rows(128)), (128, 128, 256));
        assert_eq!(PROGRAM_FROM[..2], [0x326c_7072, 0x7961_702d]);
    }

    /// The state-root component and its place in the root: pinned, and absent without the section.
    #[test]
    fn the_root_is_pinned_and_a_chain_without_the_section_keeps_its_root() {
        let bare = ledger_with(false);
        let mut with = bare.clone();
        with.set_program_state(Some(ProgramState::default()));
        let empty_root = ProgramState::default().root();
        let mut buf = Vec::new();
        buf.extend_from_slice(Hash::ZERO.as_bytes());
        buf.extend_from_slice(Hash::ZERO.as_bytes());
        assert_eq!(empty_root, Hash::digest_domain(b"rand-program-state-1", &buf));
        assert_ne!(with.state_root(), bare.state_root());
        // `cell_fee` and the two RAND counters are outside the root.
        let mut s = ProgramState { cell_fee: 9, rand_in: 5, rand_out: 2, ..ProgramState::default() };
        assert_eq!(s.root(), empty_root);
        s.write(&pid(), &cell(1, 5));
        s.set_vault(&pid(), 3, 77);
        let leaf = |domain: &[u8], parts: &[&[u8]]| Hash::digest_domain(domain, &parts.concat());
        let c = leaf(b"rand-program-cell-1", &[pid().as_bytes(), &word8_to_bytes(&key(1)), &word8_to_bytes(&cell(1, 5).value)]);
        let v = leaf(b"rand-program-vault-1", &[pid().as_bytes(), &3u32.to_be_bytes(), &77u64.to_be_bytes()]);
        let want = leaf(b"rand-program-state-1", &[merkle_root(&[c]).as_bytes(), merkle_root(&[v]).as_bytes()]);
        assert_eq!(s.root(), want);
        // Every field moves it.
        let mut t = s.clone();
        t.write(&pid(), &cell(1, 6));
        assert_ne!(t.root(), s.root());
        let mut t = s.clone();
        t.set_vault(&pid(), 3, 78);
        assert_ne!(t.root(), s.root());
        let mut t = s.clone();
        t.write(&Hash([1; 32]), &cell(1, 5));
        assert_ne!(t.root(), s.root());
    }

    #[test]
    fn cells_page_in_key_order_per_program() {
        let mut s = ProgramState::default();
        let other = Hash([0xff; 32]);
        for k in [3u32, 1, 2] {
            s.write(&pid(), &cell(k, k));
        }
        s.write(&other, &cell(1, 9));
        s.write(&Hash([0; 32]), &cell(9, 9));
        assert_eq!(s.cells_of(&pid(), None, 10), vec![cell(1, 1), cell(2, 2), cell(3, 3)]);
        assert_eq!(s.cells_of(&pid(), None, 2), vec![cell(1, 1), cell(2, 2)]);
        assert_eq!(s.cells_of(&pid(), Some(&key(2)), 10), vec![cell(3, 3)]);
        assert_eq!(s.cells_of(&pid(), Some(&key(3)), 10), vec![]);
        assert_eq!(s.cells_of(&other, None, 10), vec![cell(1, 9)]);
    }
}
