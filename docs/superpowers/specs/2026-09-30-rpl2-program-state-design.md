# RPL-2: program state, program vaults and the `Invoke` action

Status: decided 2026-09-30 in the durian.market session, under the user's standing instruction for
that session ("assume you always choose recommended decision"; "don't just write the specs, write
the implementation too … feel free to include it in chain 19 release and v0.6.8"). **Not reviewed
section by section by the user**, unlike the specs before it: read §2 before trusting the rest.
Target: a genesis-gated feature in v0.6.8. It is inert on every chain whose genesis has no
`program_state` section, so the build runs chain 18 (and a chain 19 cut as the pure re-genesis
`feat/chain19-cut` prepares) byte for byte.

First consumer: durian.market, a constant-product AMM (`../durian.market`, its own spec).

## 1. Problem

A `Call` is stateless: its proof is checked, its eight output words are stored in a receipt, and
nothing follows from them (`docs/confidential.md`, "Outputs"). The RPL spec records what that
rules out (§8: "tokens cannot be held by programs") and names the fix as future work (§11):
"RPL-2, program-owned notes … what lets a DEX or an escrow hold tokens. Needs a program-state
design", and "`Program` mint authority". The README's roadmap lists "persistent per-program state".

Three things are missing for a program to be an exchange, an escrow or a vault:

| gap | today |
|---|---|
| a program has nowhere to keep state | the state root commits program ids, never storage |
| a program cannot hold value | every note is owned by a spend key; `MintAuthority::Program` is refused at registration |
| a program's outputs cannot move value | effect kind 1 was deleted with the accounts |

## 2. Decisions

1. **State is public cells, not notes.** A program owns a map `key → value` of 8-word cells. An
   exchange's reserves are public by their nature (every trade moves the price), so hiding them
   buys nothing and would cost a program-state circuit. *Rejected: program-owned notes in the
   commitment tree* (the RPL spec's sketch) — spending one needs the bundle guest to accept a call
   proof in place of a spend key, a new `hc_bundle` and a soundness review, for state that is
   public anyway.
2. **Value a program holds is a public vault balance**, `(program, asset) → u64`, not a note.
   Value enters a vault through the bundle's existing public burn fields (`burn_r`, `burn_a`,
   `burn_asset`) and leaves as a chain-computed note, exactly as a `TokenMint`'s note is computed.
   **No circuit changes**: `hc_bundle`, `hc_auth` and every verifier-key shape are untouched.
3. **The caller proves; validators verify and never execute.** A state transition is declared in
   the clear in the transaction and the call proof shows the program accepts exactly that
   transition. *Rejected: validators executing the program at inclusion* (Aztec's public
   functions, and what an EVM does) — it has no write conflicts, but puts an interpreter and its
   semantics into consensus on a chain whose validators have only ever verified proofs.
4. **Optimistic concurrency, per cell.** A transition lists the cells it read with the values it
   read; the ledger refuses it unless each still holds that value. Two transitions that touch
   disjoint cells do not conflict. Two that touch the same cell do, and the loser re-proves. This
   is the known cost of decision 3 (§9).
5. **The ledger builds the proof's public segment from the transaction itself**, never from its
   own state: `public ‖ call_binding ‖ context`. So whether a call proof verifies is a function
   of the transaction's bytes alone, and the verified-proofs cache (audit v3, B5) stays sound.
   The state dependence is the read check of decision 4, a comparison that always runs.
6. **`MintAuthority::Program` is switched on** under the gate: a program may mint and burn a token
   registered to it (an exchange's liquidity shares).
7. **No program-to-program calls, no block context** (height, time) in v1.
8. **A new action, `Invoke`**, appended to the `Action` enum. `Call` is unchanged.
9. **The gate** is a genesis section `program_state`, which requires `tokens`, `gas`,
   `hardening_v6` and `hc_auth`. Absent, every `Invoke` and every `Program`-authority registration
   is refused before any other check and the chain is byte for byte what it was.

## 3. State

```rust
pub struct ProgramState {                                 // `Ledger::program_state: Option<_>`
    pub cell_fee: u64,                                    // genesis; RAND units per cell created
    cells: BTreeMap<(ProgramId, Word8), Word8>,           // an absent cell reads as eight zeros
    vaults: BTreeMap<(ProgramId, u32), u64>,              // asset index → units; 0 is RAND
    pub rand_in: u64,                                     // Σ RAND ever deposited into vaults
    pub rand_out: u64,                                    // Σ RAND ever paid out of vaults
}
```

- **A cell** is a `Word8` key and a `Word8` value. Writing eight zeros deletes the cell, so the
  encoding of "absent" is unique. There is no per-program cell limit: the cell fee prices growth.
- **A vault row** with balance 0 is removed, for the same reason.
- **State root.** One component appended last, after everything `rand-state-7` commits, and the
  whole re-domained `rand-state-8`:
  `blake3("rand-program-state-1", cells_root ‖ vaults_root)`, each a merkle root over leaves in
  map order — `blake3("rand-program-cell-1", program ‖ key ‖ value)` and
  `blake3("rand-program-vault-1", program ‖ asset_be ‖ amount_be)`. `cell_fee` is genesis-bound
  and the two RAND counters are audit state (§8), so neither is in the root.
- **Persistence.** One bincode blob, `META_PROGRAM_STATE`, in the block's atomic commit, restored
  by `load_ledger`/`reload_ledger`, rebuilt by replay in `truncate_to`.

## 4. The `Invoke` action

```rust
Action::Invoke {
    program: ProgramId,
    proof: Vec<u8>,                          // the call proof, as `Call`'s
    input_envelope: Option<CallEnvelope>,    // as `Call`'s
    transition: Transition,
}

pub struct Transition {
    pub reads: Vec<Cell>,        // cells read, with the values read; keys strictly ascending
    pub writes: Vec<Cell>,       // cells written; keys strictly ascending
    pub inflow: Inflow,          // what the bundle's `burn_a` of `burn_asset` is: see below
    pub pays: Vec<Payout>,       // out of the vault
    pub mints: Vec<Payout>,      // new units of a token whose authority is this program
}
pub struct Cell { pub key: Word8, pub value: Word8 }
pub enum Inflow { None, Deposit, Burn }
pub struct Payout { pub asset: u32, pub amount: u64, pub recipient: ShieldedAddress, pub r: Word8, pub envelope: Envelope }
```

**What comes in** is what the transaction's one bundle burns, and is not repeated in the action:

| bundle field | meaning under `Invoke` |
|---|---|
| `burn_r` | RAND deposited into the program's vault (asset 0) |
| `burn_a` of `burn_asset`, `inflow = Deposit` | that token deposited into the vault |
| `burn_a` of `burn_asset`, `inflow = Burn` | that token destroyed (`total_supply −= burn_a`); the token's authority must be `Program(program)` |
| `burn_a == 0` | `inflow` must be `None` |

`check_burn_shape` gains an `Invoke` arm that allows all three fields; a RAND `burn_a` stays
refused (`NonCanonicalRandBurn`), and a bridged token may be deposited but never burned this way.

**What goes out** is one chain-computed note per `Payout`, in order, `pays` then `mints`:
`note_commitment(recipient.pk, PROGRAM_FROM, amount, asset, bundle.time, r)`, with
`PROGRAM_FROM = ["rpl2", "-pay", 0, …]` — `MINT_FROM`'s twin. The amount and the recipient's `pk`
are public on the wire, as a mint's are. The note's `time` is the bundle's, which the common path
has already held to the window. At most `MAX_PAYOUTS = 4` payouts in all, so
`MAX_LEAVES_PER_TX` becomes 8.

**Limits.** `reads.len() ≤ 8`, `writes.len() ≤ 8`, and the segment rule of §5, which is the
binding one in practice.

## 5. What the program sees, and what the proof binds

The call proof's public segment is

```
segment = program.public ‖ tx.call_binding() ‖ context(tx)
```

`call_binding` is unchanged: it already covers the whole action with only the call proof blanked,
so it binds the transition, the recipients and the fee bundle. `context` is what the guest reads
with `read_public(public_len + 8 + i)`:

| words | field |
|---|---|
| 0 | `CONTEXT_VERSION` = 1 |
| 1..=4 | `n_reads`, `n_writes`, `n_pays`, `n_mints` |
| 5, 6 | `burn_r` (low, high) |
| 7 | inflow kind: 0 none, 1 deposit, 2 burn |
| 8 | `burn_asset` |
| 9, 10 | `burn_a` (low, high) |
| then | each read: key (8), value (8) |
| then | each write: key (8), value (8) |
| then | each pay: asset, amount low, amount high |
| then | each mint: asset, amount low, amount high |

Recipients are not in the context: a program decides amounts, not who is paid, and the binding
already fixes who.

**The segment rule.** `public_log_height(segment.len())` must equal
`public_log_height(public_len + TX_BINDING_WORDS)` — the height `warm_hardened` already builds
keys for. With the 2^7 floor that is 127 words for a program without a public input: 119 words of
context, e.g. three reads, three writes and four payouts. **An `Invoke` therefore needs no
verifier key a `Call` to the same program does not already need.** Every other pin of
`check_call` (tier ≤ 14, program height, input height, the hash-table caps) applies unchanged.

The executor gains one entry point, `verify_invoke(record, proof, segment)` (and its decode twin
for the verified-set path), which is `check_call` with the length pin relaxed from
`== public_len + 8` to the rule above.

A program is sound for `Invoke` only if it **checks the whole transition it is shown**: every
write, every payout and every mint must follow from the reads, the inflow and its private inputs.
A program that ignores a field lets a caller set it freely. `docs/guests.md` gains this rule.

## 6. Ledger rules

`ledger/program_state.rs`, `validate` and `apply` in lockstep like `tokens.rs`. In order, cheap
before expensive; everything before step 9 is a comparison or a map lookup.

1. **Sizes** (with the other step-1 caps): proof ≤ `max_proof_bytes`; every payout envelope is a
   note envelope (`check_note_envelope`); counts within §4's limits.
2. **The gate**: `ProgramStateError::Disabled` without the section; `ConfidentialDisabled` without
   the executor.
3. **Shape**: read keys strictly ascending, write keys strictly ascending; a write's value may
   equal what is stored (a no-op write is legal, and costs nothing).
4. **Inflow**: the table in §4. `Burn` of an unregistered token, a token of another authority, or
   more than `total_supply` is refused.
5. **Payouts**: `amount != 0`; the recipient is an address a note can be sealed to
   (`check_recipient`); `asset` is 0 or registered; a mint's asset has authority
   `Program(program)` and its supply stays within `check_note_bound`; every commitment is new,
   distinct from the bundle's four and from each other.
6. **The program** exists; the segment rule holds.
7. **Reads**: each `reads[i].value` equals the cell's current value (zeros if absent), else
   `ProgramStateError::StaleRead { key }`. Not a permanent admission verdict.
8. **Vault**: for each asset, `vault + deposited ≥ Σ pays`, checked arithmetic. A transition may
   pay out of what it deposits.
9. **Fee floor**, before the proof as `Call`'s pre-verify floor is, plus
   `cell_fee × (writes that create a cell)`; then the bundle's proof and auth proof against the
   binding (the common path); then the call proof against the segment; then the post-verify gas
   floor with the same cell term.

`apply`: credit the inflow (vault or supply), debit each pay, raise supply for each mint, write
the cells, append the payout notes in order, return the receipt (`Call`'s receipt shape; the
eight output words are the program's own event data).

**Registry change.** `RegisterToken { authority: Program(id), .. }` is accepted under the gate,
with `initial` required to be `None` (supply starts at zero; only the program mints). It is still
refused on a chain without the section. `SetAuthority` and `TokenMint` keep refusing a
non-`Key` token, so a program token's authority can never move.

## 7. Surface

- **RPC**: `rand_getProgramCell(program, key)`, `rand_getProgramCells(program, {after, limit})`,
  `rand_getProgramVault(program)`; `tx_json` renders `invoke` with its transition; the payout
  notes are indexed like mint notes; `rand_getLimits` reports `cell_fee` and the limits;
  `rand_estimateFee {"kind":"invoke"}`.
- **CLI**: `rand program invoke <id> --transition <file.json> [--input …]` builds the bundle
  (notes to burn, the RAND fee), proves the call against the segment, proves the bundle and the
  auth proof, submits and waits for the receipt. `rand program state <id>` and
  `rand program vault <id>` read. `rand token create --program <id>` registers a program token.
- **Wallets**: the client apps gain an `invoke` flow (clients repo, its own change).

## 8. The supply audit

RAND in a vault has left the pool and is not stake: `Supply::burned` already counts every
`burn_r`, so the audit's identity gains one term on the register side, `rand_in − rand_out`
(what vaults hold), and `rand_out` joins the pool's inflows. The two counters live in
`ProgramState`, not in `Supply`, so `META_SUPPLY`'s encoding does not move. A token in a vault is
still in its `total_supply`; zUSD's `total_supply == Σ locked` is untouched.

## 9. What this costs, stated plainly

- **Contention.** A transition is proved against the values it read. If another transaction
  changes one of those cells first, the proof is for a state that no longer exists and the wallet
  must rebuild and re-prove. For a pool with occasional trades this is invisible; for a busy one
  it is a queue where the fastest prover wins. The fix does not need another fork: because
  conflicts are per cell, a program can take deposits into per-user cells (no contention) and let
  anyone settle a batch against the pool cell in one proof. That is a program design, recorded as
  future work for durian.market, not a protocol change.
- **Amounts are public** at both ends of an `Invoke`, and the recipient's `pk` is, as with a
  mint. Who paid in is not: the bundle names nobody.
- **Every `Invoke` is two big proofs** (the bundle's and the call's) and the auth proof.

## 10. Testing

- Unit, per rule of §6: the accept path and every refusal, with the stub executor.
- The gate: a genesis without `program_state` hashes, roots and refuses exactly as before (pinned
  vectors unchanged); the section without `tokens`/`gas`/`hardening_v6`/`hc_auth` is a genesis
  error.
- State root and persistence: invoke, restart, same root; `truncate_to` replay.
- Two invokes in one block on disjoint cells both apply; on one cell the second is refused where
  it sits and the block without it applies.
- The verified-set path: a transaction admitted at state S is refused on its read check at S′
  without its proof being looked at.
- zkVM: a real guest proved against a real segment verifies; the same proof against a segment
  with one context word changed fails with `PublicValues`.
- End to end on a local test-profile chain: deploy, register a program token, invoke with a
  deposit, a payout and a mint; the recipient's wallet finds both notes.

## 11. Rollout

Hard fork for the chain that takes it: a new action, a new genesis section, `rand-state-8`, a
registry rule. v0.6.8 carries the code; **cutting a chain with the section is the user's separate
go**, as every cut has been. `rand-node genesis --program-state-cell-fee <units>` writes the
section.

## 12. Future work

Program-to-program calls; block context (height, time) in the context words; a batching
convention for contended programs; hiding the payout recipient (a chain-verified note-commitment
gadget a program may call); the multi-asset bundle, which would let one transaction deposit two
tokens.
