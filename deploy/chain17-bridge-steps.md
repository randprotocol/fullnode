# Chain 17 — the bridge side of the cut (draft for the bridge session)

`deploy/chain16-bridge-steps.md` rewritten for chain 17. It is **not** a script and edits nothing in
the bridge repository; the bridge session turns it into `daemons/mainnet/cut-chain17.sh` (print
every command, run only with `--yes`, one step at a time).

What is different from chain 16:

- **The relayer's `rand` must be v0.6.3.** Chain 17 pins bundle guest v3 and `hc_auth` (split
  authorisation): every bundle carries an auth proof and its txid is `rand-txid-3`. A v0.6.1/v0.6.2
  `rand bridge-mint` proves a fee bundle chain 17 cannot even decode. The guardians' own `rand-node`
  (on the six guardian hosts) is the fleet's job, as on chain 16 (`deploy/cutover-fleet-chain17.sh`
  stages, switches — `chain17.conf`, `--datadir /var/lib/randnode/data-17`, `chain16.conf` moved to
  `/root/chain16.conf.c16` — and starts them with the other twenty).
- **The endpoint redeploy (R1/R3, planned 2026-09-29 00:00 UTC) is likely chain 17's to carry.**
  Chain 16's emitter table names the pre-redeploy endpoints and cannot be changed on chain 16, so
  new Ethereum/BNB/Tron endpoints become usable only through this genesis. Settle which endpoints
  chain 17 trusts before the snapshot — see "If the redeploy has landed" below.
- **The replay floor is re-derived, not copied.** `cut-chain17-genesis.sh` sets
  `min_inbound_sequence` per unchanged source to the endpoint's next outbound sequence at the
  snapshot (last minted + 1, given every emitted lock was minted on chain 14/15/16), never below
  chain 16's own floor, and cross-checks it against the relayer's `done/<chain>/` records when
  `RELAYER_DONE_DIR` is given. A lock emitted but not minted by the snapshot makes the cut refuse
  (custody ≠ locked) — let it mint on chain 16 first.
- **The guardian set, the PQ set and the pause key carry over unchanged** (the cut refuses a live
  rotation on chain 16 unless `BRIDGE_ROTATED=1`): guardian set 1, the same eight PQ keys, the same
  pause key; `GUARDIAN_PQ_SEED` stays `pq-next.seed`.

## Values (chain 16 at genesis; the cut script re-reads every one in its snapshot)

| | chain 16 genesis | chain 17 |
|---|---|---|
| Rand burn sequence (next) | 7 | chain 16's `rand_getBridgeState.burn_sequence` at the snapshot (7 unless chain 16 burned) |
| Guardian set index | 1 | chain 16's live value (1 unless rotated) |
| Floors `min_inbound_sequence` | `{"2": 2, "3": 2, "4": 2, "5": 2}` | per unchanged endpoint: its `sequence()` at the snapshot (≥ 2); per redeployed endpoint: explicit `MIN_INBOUND_<c>` (`none` for a fresh one) |
| zUSD locked | Tron USDT 9, Solana USDT 1 (10 zUSD, all Anish's) | chain 16's per-backing `locked` at the snapshot == source custody |
| zUSD carry | one note, 10 zUSD to Anish | `~/.rand-chain17/zusd-carry.txt`, Σ == Σ locked |

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
   mint on chain 16 first.
2. Fleet: `deploy/cut-chain17-genesis.sh snapshot <dir>` → `… balances <dir>` →
   (the user's go) → `cutover-fleet-chain17.sh stop` → the cut (with
   `RELAYER_DONE_DIR=<bridge>/data/mainnet/relayer/done` for the floor cross-check) → `push` →
   `switch` (refuses a guardian host whose `rand-guardian` is still active) → `start` → `wait`.
   Each phase alone, its `$?` read before the next.
3. `droplet <1..6>` — on each guardian host, once its node answers `rand_getGenesisHash` with the
   chain-17 hash and `rand_getHealth` ok (the fleet's `wait` phase):
   ```
   cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain16
   sed -i -E 's/^chain_id = 16 /chain_id = 17 /' /etc/rand-guardian.toml
   grep -q '^chain_id = 17 ' /etc/rand-guardian.toml
   cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain16
   echo '{"next_block": 0, "next_sequence": <chain 17 burn_sequence>}' > /var/lib/rand-guardian/data/cursors/rand.json
   # source cursors (ethereum/bsc/tron/solana.json) are KEPT for unchanged endpoints: they are past
   # every chain-14/15/16 lock. A redeployed endpoint's cursor is reset (below).
   systemctl start rand-guardian; sleep 5; journalctl -u rand-guardian -n 5 --no-pager
   ```
   The guardian `signed/` store is kept: nothing in it was signed for chain 17 (the PQ
   co-signature binds the chain id).
4. `laptop`:
   ```
   for f in mainnet/relayer.toml mainnet/guardian-7.toml mainnet/guardian-8.toml:
     sed -i '' -E 's/^chain_id = 16 /chain_id = 17 /' $f
   for d in relayer guardian-7 guardian-8:
     cp -Rp data/mainnet/$d/cursors data/mainnet/$d/cursors.chain16
     echo '{"next_block": 0, "next_sequence": <chain 17 burn_sequence>}' > data/mainnet/$d/cursors/rand.json
   # the relayer's rand CLI: a macOS build of the v0.6.3 tag (fullnode), e.g. ~/rand-node-a/bin-v063/rand
   sed -i '' -E 's#^rand_cli = "[^"]*"#rand_cli = "'$HOME'/rand-node-a/bin-v063/rand"#' mainnet/relayer.toml
   ```
   Check the relayer's `rand` first: `~/rand-node-a/bin-v063/rand --version` names 0.6.3. The
   relayer wallet's note store is bound to chain 16; the first scan against chain 17 empties and
   rescans it with a warning (expected). Its chain-16 RAND is carried only if its key file is
   under `WALLETS_DIRS` at the `balances` step — otherwise fund it as below.
5. `fund-relayer` — the relayer wallet is in `faucet_recipients`, and the faucet mints only through
   a `faucet_minters` key (the 18 operator validators — A, which the laptop's `127.0.0.1:8545`
   tunnel reaches, is one): `rand --rpc http://127.0.0.1:8545 --key <relayer key> faucet` × 3
   (100 RAND each, as chains 15 and 16 did), then `rand … balance` — skip if the carry already
   funded it.
6. `start-laptop` — `GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh`, then
   `mainnet/run-relayer.sh`.
7. Audit — `rand-bridge-audit` against chain 17: `total_supply` == Σ `locked` == endpoint custody;
   `rand_getBridgeState.min_inbound_sequence` shows the floors. Anish opens his carried zUSD with a
   v0.6.3 wallet (`rand asset-balance 1`) — a v0.6.2 wallet cannot spend on chain 17.

## If the redeploy has landed (new Ethereum/BNB/Tron endpoints)

- **Genesis**: `EMITTER_2/3/4` = the new endpoints' 32-byte wire forms (left-padded); the cut
  refuses a changed emitter unless `MIN_INBOUND_<c>` is given: `none` for a fresh endpoint (its
  `sequence` starts at 0; the old endpoint's locks fail `WrongEmitter` on chain 17), or last
  minted + 1 if anything from it was minted before the cut (it cannot have been on chain 16, whose
  table names the old endpoints). Take the snapshot with the same `EMITTER_*`, so custody is read
  at the new addresses — the Tron custody (9 USDT) must have MOVED to the new endpoint before the
  snapshot, or Σ locked == custody fails.
- **Contracts**: the new endpoints hold the set-1 guardian addresses, and the set index each holds
  agrees with the relayer's `guardian_set_index = 1` and chain 17's `guardian_set_index` (a fresh
  constructor may start at 0 — the bridge session confirms against `RandBridgeBase`).
- **Daemons**: every `[[evm]]` `contract` in `relayer.toml`, `guardian-7/8.toml` and each droplet's
  `/etc/rand-guardian.toml` → the new address; `start_block` → the deployment block; the source
  cursors of chains 2/3/4 reset to `{"next_block": <deploy block>, "next_sequence": 0}` on every
  guardian and the relayer (old ones kept as `cursors.chain16`).

## Rollback (chain 16 again)

Stop the daemons; restore `rand-guardian.toml.chain16` and `cursors.chain16` on each droplet, the
three laptop tomls (`chain_id = 16`), the laptop cursors, and `rand_cli` back to the v0.6.1 build
(`~/rand-node-a/bin-v061/rand`); the fleet restores its units (`cutover-fleet-chain17.sh` header).
Start as in step 6. A redeployed endpoint cannot be rolled back to chain 16 — chain 16 does not
trust it; custody moved to it stays unmintable there until chain 17 is back.
