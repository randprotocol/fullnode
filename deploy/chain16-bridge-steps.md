# Chain 16 — the bridge side of the cut (draft for the bridge session)

A draft of what `bridge/daemons/mainnet/cut-chain15.sh` did for chain 15, rewritten for chain 16.
It is **not** a script and edits nothing in the bridge repository; the bridge session turns it into
`daemons/mainnet/cut-chain16.sh` (print every command, run only with `--yes`, one step at a time).

What is different from chain 15:

- **The guardian hosts' `rand-node` is now the fleet's job.** On chain 15 the bridge script
  installed the binary and wrote `chain15.conf` itself; the six guardian hosts are chain-15
  validators now (bonded 2026-09-27), so `deploy/cutover-fleet-chain16.sh` stages, stops,
  switches (a `chain16.conf` drop-in, `--datadir /var/lib/randnode/data-16`, `chain15.conf` moved to
  `/root/chain15.conf.c15`) and starts them with the other twenty. The bridge steps only stop and
  restart the **daemons** and move their configuration and cursors.
- **The guardian set, the PQ set and the pause key do not change.** Chain 16 starts at guardian set
  1, the same eight PQ keys (`pq-guardians-chain15.json`, sha256 `b1f6e878…7fb1`), the same pause
  key. `GUARDIAN_PQ_SEED` stays `pq-next.seed` on every droplet (chain 15 already switched it).
- **The genesis carries a replay floor** (`min_inbound_sequence`, C15-1): chain 16 itself refuses
  every lock chain 14 already minted, so a guardian store lost in the move can no longer mint twice.
  The cursors below are still set past those locks — the floor is the backstop, not the plan.
- **The relayer's `rand` must be v0.6.1.** Chain 16 pins the v2 bundle guest and v0.6.1's verifier
  keys (cs7); a v0.5.8/v0.6 `rand bridge-mint` proves a fee bundle chain 16 refuses.

## Values (read 2026-09-28 ~10:00 UTC; the cut script re-reads them in its snapshot)

| | value | evidence |
|---|---|---|
| Rand burn sequence (next) | **7** | `rand_getBridgeState.burn_sequence` on chain 15; relayer `cursors/rand.json` `next_sequence: 7`; `done/1/0…6` (chain 14's seven burns) |
| Ethereum endpoint next sequence | 2 | `sequence()` on `0xd6eb…4892`, eth mainnet |
| BNB endpoint next sequence | 2 | `sequence()` on `0xd6eb…4892`, bsc |
| Tron endpoint next sequence | 2 | `sequence()` on `TAqq2i8K…` (`0x0992…9700`), TronGrid |
| Solana program next sequence | 2 | Config account `B4EGs33g…` (program `FGA3kY3R…`), `sequence` field |
| Floors in the genesis | `{"2": 2, "3": 2, "4": 2, "5": 2}` | chain 14 minted seq 0 and 1 from each (relayer `done/<2..5>/{0,1}`, 2026-09-20); chain 15 minted nothing (zUSD supply and `locked` unchanged since its genesis, burn sequence unchanged) |
| Custody | Tron USDT 9 000 000 (9 USDT), Solana USDT 1 000 000 (1 USDT), every other backing 0 | EVM/Tron `balanceOf(endpoint) − accruedFees`; Solana TokenRegistry `custody` |

## Order at the cut (with the fleet runbook)

1. `stop` — before the snapshot, so no mint or release can move chain 15 after it is read:
   ```
   pkill -f 'rand-relayer --config mainnet/relayer.toml'
   pkill -f 'rand-guardian --config mainnet/guardian-[78].toml'
   for i in 1..6: ssh (guardian key) root@<host i> 'systemctl stop rand-guardian'
   ```
   Check first that nothing is in flight: the relayer log shows no pending lock or burn, every
   endpoint's `sequence()` equals the relayer's `next_sequence` per chain, and chain 15's
   `burn_sequence` equals `cursors/rand.json`'s `next_sequence`. If a lock is in flight, let it
   mint on chain 15 first (the cut script then refuses a floor at its old value — raise it).
2. Fleet: `deploy/cut-chain16-genesis.sh snapshot <dir>` → `cutover-fleet-chain16.sh stop` → the
   cut → `push` → `switch` (refuses a guardian host whose `rand-guardian` is still active) → `start`
   → `wait`.
3. `droplet <1..6>` — on each guardian host, once its node answers `rand_getGenesisHash` with the
   chain-16 hash and `rand_getHealth` ok (the fleet's `wait` phase):
   ```
   cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain15
   sed -i -E 's/^chain_id = 15 /chain_id = 16 /' /etc/rand-guardian.toml
   grep -q '^chain_id = 16 ' /etc/rand-guardian.toml
   cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain15
   echo '{"next_block": 0, "next_sequence": 7}' > /var/lib/rand-guardian/data/cursors/rand.json
   # source cursors (ethereum/bsc/tron/solana.json) are KEPT: they are past every chain-14/15 lock
   systemctl start rand-guardian; sleep 5; journalctl -u rand-guardian -n 5 --no-pager
   ```
   `/etc/rand-guardian/env` is unchanged (`GUARDIAN_PQ_SEED` = `pq-next.seed` since chain 15). The
   guardian `signed/` store is kept: nothing in it was signed for chain 16 (the PQ co-signature
   binds the chain id), and chain 15 minted no lock.
4. `laptop`:
   ```
   for f in mainnet/relayer.toml mainnet/guardian-7.toml mainnet/guardian-8.toml:
     sed -i '' -E 's/^chain_id = 15 /chain_id = 16 /' $f
   for d in relayer guardian-7 guardian-8:
     cp -Rp data/mainnet/$d/cursors data/mainnet/$d/cursors.chain15
     echo '{"next_block": 0, "next_sequence": 7}' > data/mainnet/$d/cursors/rand.json
   # the relayer's rand CLI: a macOS build of the v0.6.1 tag (fullnode), e.g. ~/rand-node-a/bin-v061/rand
   sed -i '' -E 's#^rand_cli = "[^"]*"#rand_cli = "'$HOME'/rand-node-a/bin-v061/rand"#' mainnet/relayer.toml
   ```
   The relayer wallet's note store (`~/.rand-chain14/wallets/relayer.key.json.notes.json`) is bound
   to chain 15; the first scan against chain 16 empties and rescans it with a warning (expected).
5. `fund-relayer` — the relayer wallet is in `faucet_recipients`, and the faucet mints only through
   a `faucet_minters` key (the 18 operator validators by default — A, which the laptop's
   `127.0.0.1:8545` tunnel reaches, is one; the guardian hosts, obs1 and rand-archive-2 are not):
   `rand --rpc http://127.0.0.1:8545 --key ~/.rand-chain14/wallets/relayer.key.json faucet` × 3
   (100 RAND each, as chain 15 did at blocks 32/36/40), then `rand … balance`.
6. `start-laptop` — `GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh`, then
   `mainnet/run-relayer.sh`.
7. Audit — `rand-bridge-audit` against chain 16: `total_supply` 10 zUSD == Σ `locked` (Tron USDT
   9, Solana USDT 1) == endpoint custody; `rand_getBridgeState.min_inbound_sequence` shows the floors.
   Anish opens his carried 10 zUSD with a v0.6.1 wallet (`rand asset-balance 1`).

## If the endpoint redeploy (2026-09-29 00:00 UTC, R1/R3) lands BEFORE the cut

The EVM/Tron contracts are not upgradeable: the redeploy creates new endpoints on Ethereum, BNB
and Tron, and moves the custody (9 USDT on Tron; the ETH/BSC endpoints hold only accrued fees).
Solana is not redeployed.

- **Genesis**: the cut script takes `EMITTER_2/3/4` (32-byte wire forms of the new endpoints) and
  refuses a changed emitter unless `MIN_INBOUND_<c>` is given: `none` for a fresh endpoint (its
  `sequence` starts at 0, and the old endpoint's locks already fail `WrongEmitter`), or last
  minted + 1 if the new endpoint's locks were minted on chain 15 before the cut. Take the snapshot
  with the same `EMITTER_*` so custody is read at the new addresses: the Tron custody must have
  moved (Σ locked == custody is asserted).
- **Contracts**: construct the new endpoints with the set-1 guardian addresses, and make the set
  index each new endpoint holds agree with what the relayer stamps on release attestations
  (`relayer.toml` `guardian_set_index = 1`) and with chain 16's `guardian_set_index: 1` — a fresh
  constructor likely starts at index 0 (bridge session to confirm against `RandBridgeBase`'s
  constructor). Registered tokens, caps and fees as today.
- **Daemons**: every `[[evm]]` `contract` in `relayer.toml`, `guardian-7/8.toml` and each droplet's
  `/etc/rand-guardian.toml` → the new address; `start_block` → the new deployment block; the source
  cursors of chains 2/3/4 reset to `{"next_block": <deploy block>, "next_sequence": 0}` on every
  guardian and the relayer (old cursors kept aside as `cursors.chain15`).
- If the redeploy lands AFTER the cut, chain 16's emitter table names the old endpoints and cannot
  be changed without a governance path — list the new ones after launch the B4 way only if the
  ledger supports replacing an emitter; otherwise the redeploy waits for chain 17. **Decide the
  order before cutting.**

## Rollback (chain 15 again)

Stop the daemons; restore `rand-guardian.toml.chain15` and `cursors.chain15` on each droplet, the
three laptop tomls (`chain_id = 15`), the laptop cursors, and `rand_cli` back to the chain-15
build; the fleet restores its units (`cutover-fleet-chain16.sh` header). Start as in step 6.
