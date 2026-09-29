# Chain 18 — the bridge side of the cut (draft for the bridge session)

A draft of what `bridge/daemons/mainnet/cut-chain16.sh` did for chain 16 (`deploy/
chain16-bridge-steps.md`; read it first — this file mirrors its structure with the chain ids
moved), rewritten for chain 18. It is **not** a script and edits nothing in the bridge
repository; the bridge session turns it into `daemons/mainnet/cut-chain18.sh` (print every
command, run only with `--yes`, one step at a time).

**DERIVATION NOTE, same as the two fleet scripts this pairs with
(`deploy/cut-chain18-genesis.sh`, `deploy/cutover-fleet-chain18.sh`): chain 16 was not yet
live/cut when this was written, so every number in the "Values" table below is a placeholder,
not a re-derived fact.** Chain 16's own table was filled by actually reading chain 16's (then
chain 15's) live bridge state on the day of its cut; this file cannot do that yet. Every row
below is marked **TBD — read at the chain-18 snapshot** and must be filled from
`deploy/cut-chain18-genesis.sh snapshot <dir>`'s own output (which reads the live values
itself and asserts against them) before the bridge session's script is finalized, exactly as
chain 16's table was filled from chain 16's snapshot. If chain 17 is cut before chain 18, this
whole file should be re-derived from chain 17's bridge-steps doc instead (if one exists by
then) or from chain 16's, whichever is chain 18's actual immediate predecessor.

What is expected to differ from chain 16 (structural; the specifics are TBD, see above):

- **The guardian hosts are already validators.** This has been true since the chain-16 cut
  (they bonded on chain 15, 2026-09-27) and stays true for chain 18: `deploy/
  cutover-fleet-chain18.sh` stages, stops, switches (a `chain18.conf` drop-in, `--datadir
  /var/lib/randnode/data-18`, `chain16.conf` moved to `/root/chain16.conf.c16`) and starts
  them with the other twenty. The bridge steps only stop and restart the **daemons** and move
  their configuration and cursors — unchanged in shape from chain 16.
- **The guardian set, the PQ set and the pause key are assumed unchanged** (the user's
  2026-09-20 hold on guardian-set rotation, still in force as of chain 16 per project memory)
  — chain 18 starts at guardian set 1, the same eight PQ keys and the same pause key, *unless*
  the bridge session has rotated them between the chain-16 and chain-18 cuts, in which case
  every reference to `pq-guardians-chain16.json` / the set-1 pause key below must be updated
  to whatever set is live at chain-18 snapshot time. `GUARDIAN_PQ_SEED` stays whatever it was
  left at after chain 16's cut unless that also changed.
- **The genesis carries the same replay floor mechanism** (`min_inbound_sequence`, C15-1,
  unchanged since chain 15): chain 18 refuses every lock any earlier chain already minted.
  The floors themselves are TBD, read at the chain-18 snapshot (chain 16's own floors carry
  forward unless the fleet minted something new on chain 16 in the interim — check the
  snapshot's `next_sequence` against `done/<chain>/…` before trusting `{2,3,4,5}`
  unconditionally the way chain 16's table did for chain 15→16).
- **Constraint set 8 changes every verifier key, and the gas section changes the fee floor.**
  The relayer's `rand` must be the v0.6.6 (cs8/gas) build: a pre-cs8 `rand bridge-mint`
  proves a fee bundle chain 18 refuses outright (wrong verifier key), and even a cs8 build
  built without `--gas-price` awareness would compute too low a fee once chain 18's `gas`
  section is live (`docs/rpc.md`'s `rand_getLimits` serves the floor — the relayer's fee
  bundle must be priced from that, not a hardcoded constant).

## Values (TBD — read at the chain-18 snapshot; this table's shape follows chain 16's, not its numbers)

| | value | evidence |
|---|---|---|
| Rand burn sequence (next) | **TBD** | `rand_getBridgeState.burn_sequence` on chain 16 at snapshot time; relayer `cursors/rand.json` `next_sequence`; `done/16/…` |
| Ethereum endpoint next sequence | TBD | `sequence()` on the live Rand-side emitter, eth mainnet |
| BNB endpoint next sequence | TBD | `sequence()` on the live emitter, bsc |
| Tron endpoint next sequence | TBD | `sequence()` on the live Tron endpoint, TronGrid |
| Solana program next sequence | TBD | Config account `sequence` field, the live Solana program |
| Floors in the genesis | TBD (`{"2": …, "3": …, "4": …, "5": …}`) | one past the last sequence any earlier chain (14, 15, 16, and 17 if cut) already minted from each source — the cut script's own `MIN_INBOUND_<c>` derivation, not hand-computed here |
| Custody | TBD | EVM/Tron `balanceOf(endpoint) − accruedFees`; Solana TokenRegistry `custody`, at chain-18 snapshot time |

## Order at the cut (with the fleet runbook)

1. `stop` — before the snapshot, so no mint or release can move chain 16 after it is read:
   ```
   pkill -f 'rand-relayer --config mainnet/relayer.toml'
   pkill -f 'rand-guardian --config mainnet/guardian-[78].toml'
   for i in 1..6: ssh (guardian key) root@<host i> 'systemctl stop rand-guardian'
   ```
   Check first that nothing is in flight: the relayer log shows no pending lock or burn, every
   endpoint's `sequence()` equals the relayer's `next_sequence` per chain, and chain 16's
   `burn_sequence` equals `cursors/rand.json`'s `next_sequence`. If a lock is in flight, let it
   mint on chain 16 first (the cut script then refuses a floor at its old value — raise it).
2. Fleet: `deploy/cut-chain18-genesis.sh snapshot <dir>` → `cutover-fleet-chain18.sh stop` → the
   cut → `push` → `switch` (refuses a guardian host whose `rand-guardian` is still active) → `start`
   → `wait`.
3. `droplet <1..6>` — on each guardian host, once its node answers `rand_getGenesisHash` with the
   chain-18 hash and `rand_getHealth` ok (the fleet's `wait` phase):
   ```
   cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain16
   sed -i -E 's/^chain_id = 16 /chain_id = 18 /' /etc/rand-guardian.toml
   grep -q '^chain_id = 18 ' /etc/rand-guardian.toml
   cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain16
   echo '{"next_block": 0, "next_sequence": <TBD, next burn sequence>}' > /var/lib/rand-guardian/data/cursors/rand.json
   # source cursors (ethereum/bsc/tron/solana.json) are KEPT: they are past every earlier-chain lock
   systemctl start rand-guardian; sleep 5; journalctl -u rand-guardian -n 5 --no-pager
   ```
   `/etc/rand-guardian/env` is unchanged unless the bridge session rotated `GUARDIAN_PQ_SEED`
   since chain 16. The guardian `signed/` store is kept: nothing in it was signed for chain 18
   (the PQ co-signature binds the chain id), and chain 16 (assuming no burn since its own cut)
   minted no new lock.
4. `laptop`:
   ```
   for f in mainnet/relayer.toml mainnet/guardian-7.toml mainnet/guardian-8.toml:
     sed -i '' -E 's/^chain_id = 16 /chain_id = 18 /' $f
   for d in relayer guardian-7 guardian-8:
     cp -Rp data/mainnet/$d/cursors data/mainnet/$d/cursors.chain16
     echo '{"next_block": 0, "next_sequence": <TBD, next burn sequence>}' > data/mainnet/$d/cursors/rand.json
   # the relayer's rand CLI: a macOS build of the v0.6.6 tag (fullnode, cs8/gas)
   sed -i '' -E 's#^rand_cli = "[^"]*"#rand_cli = "'$HOME'/rand-node-a/bin-v065/rand"#' mainnet/relayer.toml
   ```
   The relayer wallet's note store is bound to chain 16 (or whichever chain it last scanned);
   the first scan against chain 18 empties and rescans it with a warning (expected, same as
   every earlier cut).
5. `fund-relayer` — the relayer wallet must still be in `faucet_recipients` (carried in the
   genesis's `staking` section, same as chain 16's), and the faucet mints only through a
   `faucet_minters` key (the operator validators; A, which the laptop's `127.0.0.1:8545` tunnel
   reaches, is one — the guardian hosts, obs1 and rand-archive-2 are not, same as chain 16):
   `rand --rpc http://127.0.0.1:8545 --key <relayer key path> faucet` as many times as needed,
   then `rand … balance`.
6. `start-laptop` — `GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh` (only if the PQ seed
   was in fact rotated for this cut — otherwise the guardians resume from where they left off),
   then `mainnet/run-relayer.sh`.
7. Audit — `rand-bridge-audit` against chain 18: `total_supply` == Σ `locked` == endpoint
   custody (carried forward from chain 16's own audited state); `rand_getBridgeState.
   min_inbound_sequence` shows the floors read at the chain-18 snapshot. Every zUSD holder
   opens their carried balance with a v0.6.6 wallet (`rand asset-balance 1`).

## If an endpoint redeploy lands BEFORE the cut

Chain 16's cut absorbed the 2026-09-29 R1/R3 endpoint redeploy (new Ethereum/BNB/Tron
emitters; Solana not redeployed) — see `deploy/chain16-bridge-steps.md`'s own section on it
for the mechanics (they are unchanged in shape). If a **further** redeploy lands before the
chain-18 cut, the same rules apply, moved up one chain:

- **Genesis**: the cut script takes `EMITTER_2/3/4` (32-byte wire forms of the new endpoints)
  and refuses a changed emitter unless `MIN_INBOUND_<c>` is given: `none` for a fresh endpoint
  (its `sequence` starts at 0, and the old endpoint's locks already fail `WrongEmitter`), or
  last minted + 1 if the new endpoint's locks were minted on chain 16 before the cut. Take the
  snapshot with the same `EMITTER_*` so custody is read at the new addresses.
- **Contracts**: construct the new endpoints with the live guardian addresses, and make the
  set index each new endpoint holds agree with what the relayer stamps on release attestations
  and with chain 18's `guardian_set_index` (whatever it inherits from chain 16). Registered
  tokens, caps and fees as chain 16's.
- **Daemons**: every `[[evm]]` `contract` in `relayer.toml`, `guardian-7/8.toml` and each
  droplet's `/etc/rand-guardian.toml` → the new address; `start_block` → the new deployment
  block; the source cursors of chains 2/3/4 reset to `{"next_block": <deploy block>,
  "next_sequence": 0}` on every guardian and the relayer (old cursors kept aside as
  `cursors.chain16`).
- If the redeploy lands AFTER the cut, chain 18's emitter table names the old endpoints and
  cannot be changed without a governance path — decide the order before cutting, same as
  chain 16's own note.

## Rollback (chain 16 again)

Stop the daemons; restore `rand-guardian.toml.chain16` and `cursors.chain16` on each droplet,
the three laptop tomls (`chain_id = 16`), the laptop cursors, and `rand_cli` back to the
chain-16 build; the fleet restores its units (`cutover-fleet-chain18.sh` header). Start as in
step 6.
