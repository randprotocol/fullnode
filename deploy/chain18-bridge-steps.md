# Chain 18 — the bridge side of the cut (draft for the bridge session)

`deploy/chain17-bridge-steps.md` (read it first) rewritten for chain 18: chain 17 (v0.6.3, split
authorisation) is chain 18's predecessor, so every step below is chain 17's with the chain ids moved
up one and the gas build's differences added. It is **not** a script and edits nothing in
the bridge repository; the bridge session turns it into `daemons/mainnet/cut-chain18.sh` (print
every command, run only with `--yes`, one step at a time).

What is different from chain 17:

- **The relayer's `rand` must be v0.6.6 (constraint set 8, the gas section).** Chain 18 keeps chain
  17's bundle guest v3 and `hc_auth` (split authorisation: every bundle carries an auth proof, txid
  `rand-txid-3`) and adds cs8 — every verifier key changes — and the genesis `gas` section: every
  bundle proof must declare `gas_max(14, 0, 0)` = 20 479 and every auth proof `gas_max(10, 0, 0)` =
  1 279 (`TxError::BundleGasLimit` / `AuthGasLimit`), which only a v0.6.6 prover writes. A v0.6.3
  `rand bridge-mint` proves a fee bundle chain 18 refuses outright; its fee floor follows
  `rand_getLimits` (the chain's gas prices), never a hardcoded constant. The guardians' own `rand-node`
  (on the six guardian hosts) is the fleet's job, as on chain 17 (`deploy/cutover-fleet-chain18.sh`
  stages, switches — `chain18.conf`, `--datadir /var/lib/randnode/data-18`, `chain17.conf` moved to
  `/root/chain17.conf.c17` — and starts them with the other twenty).
- **The endpoint redeploy (R1/R3, planned 2026-09-29 00:00 UTC) was chain 17's to carry.** If chain
  17's genesis names the new endpoints, chain 18 inherits them unchanged (the default: `C17_EMITTER_*`
  in `cut-chain18-genesis.sh` must equal chain 17's genesis `bridge.emitters`, which the cut asserts
  — set them from `deploy/genesis-chain17.json` once it is committed). If chain 17 did NOT carry it,
  this genesis is the next chance — see "If the redeploy has landed" below.
- **The replay floor is re-derived, not copied.** `cut-chain18-genesis.sh` sets
  `min_inbound_sequence` per unchanged source to the endpoint's next outbound sequence at the
  snapshot (last minted + 1, given every emitted lock was minted on chain 14/15/16/17), never below
  chain 17's own floor, and cross-checks it against the relayer's `done/<chain>/` records when
  `RELAYER_DONE_DIR` is given. A lock emitted but not minted by the snapshot makes the cut refuse
  (custody ≠ locked) — let it mint on chain 17 first.
- **The guardian set, the PQ set and the pause key carry over unchanged** (the cut refuses a live
  rotation on chain 17 unless `BRIDGE_ROTATED=1`): guardian set 1, the same eight PQ keys, the same
  pause key; `GUARDIAN_PQ_SEED` stays `pq-next.seed`.

## Values (chain 17 at genesis; the cut script re-reads every one in its snapshot)

Chain 17 is not cut as this is written: its column is what its cut script aims for (chain 16's
values carried), to be replaced by `deploy/genesis-chain17.json`'s actual values once committed.

| | chain 17 genesis (expected) | chain 18 |
|---|---|---|
| Rand burn sequence (next) | 7 unless chain 16 burned | chain 17's `rand_getBridgeState.burn_sequence` at the snapshot |
| Guardian set index | 1 | chain 17's live value (1 unless rotated) |
| Floors `min_inbound_sequence` | per endpoint, `sequence()` at chain 17's snapshot (≥ 2) | per unchanged endpoint: its `sequence()` at the snapshot, never below chain 17's floor; per redeployed endpoint: explicit `MIN_INBOUND_<c>` (`none` for a fresh one) |
| zUSD locked | chain 16's per-backing `locked` (Tron USDT 9, Solana USDT 1 at chain 16's genesis) | chain 17's per-backing `locked` at the snapshot == source custody |
| zUSD carry | `~/.rand-chain17/zusd-carry.txt` | `~/.rand-chain18/zusd-carry.txt`, Σ == Σ locked |

## Order at the cut (with the fleet runbook)

1. `stop` — before the snapshot, so no mint or release can move chain 17 after it is read:
   ```
   pkill -f 'rand-relayer --config mainnet/relayer.toml'
   pkill -f 'rand-guardian --config mainnet/guardian-[78].toml'
   for i in 1..6: ssh (guardian key) root@<host i> 'systemctl stop rand-guardian'
   ```
   Check first that nothing is in flight: the relayer log shows no pending lock or burn, every
   endpoint's `sequence()` equals the relayer's `next_sequence` per chain, and chain 17's
   `burn_sequence` equals `cursors/rand.json`'s `next_sequence`. If a lock is in flight, let it
   mint on chain 17 first.
2. Fleet: `deploy/cut-chain18-genesis.sh snapshot <dir>` → `… balances <dir>` →
   (the user's go) → `cutover-fleet-chain18.sh stop` → the cut (with
   `RELAYER_DONE_DIR=<bridge>/data/mainnet/relayer/done` for the floor cross-check) → `push` →
   `switch` (refuses a guardian host whose `rand-guardian` is still active) → `start` → `wait`.
   Each phase alone, its `$?` read before the next.
3. `droplet <1..6>` — on each guardian host, once its node answers `rand_getGenesisHash` with the
   chain-18 hash and `rand_getHealth` ok (the fleet's `wait` phase):
   ```
   cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain17
   sed -i -E 's/^chain_id = 17 /chain_id = 18 /' /etc/rand-guardian.toml
   grep -q '^chain_id = 18 ' /etc/rand-guardian.toml
   cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain17
   echo '{"next_block": 0, "next_sequence": <chain 18 burn_sequence>}' > /var/lib/rand-guardian/data/cursors/rand.json
   # source cursors (ethereum/bsc/tron/solana.json) are KEPT for unchanged endpoints: they are past
   # every chain-14/15/16/17 lock. A redeployed endpoint's cursor is reset (below).
   systemctl start rand-guardian; sleep 5; journalctl -u rand-guardian -n 5 --no-pager
   ```
   The guardian `signed/` store is kept: nothing in it was signed for chain 18 (the PQ
   co-signature binds the chain id).
4. `laptop`:
   ```
   for f in mainnet/relayer.toml mainnet/guardian-7.toml mainnet/guardian-8.toml:
     sed -i '' -E 's/^chain_id = 17 /chain_id = 18 /' $f
   for d in relayer guardian-7 guardian-8:
     cp -Rp data/mainnet/$d/cursors data/mainnet/$d/cursors.chain17
     echo '{"next_block": 0, "next_sequence": <chain 18 burn_sequence>}' > data/mainnet/$d/cursors/rand.json
   # the relayer's rand CLI: a macOS build of the v0.6.6 tag (fullnode, cs8/gas), e.g. ~/rand-node-a/bin-v066/rand
   sed -i '' -E 's#^rand_cli = "[^"]*"#rand_cli = "'$HOME'/rand-node-a/bin-v066/rand"#' mainnet/relayer.toml
   ```
   Check the relayer's `rand` first: `~/rand-node-a/bin-v066/rand --version` names 0.6.6. The
   relayer wallet's note store is bound to chain 17; the first scan against chain 18 empties and
   rescans it with a warning (expected). Its chain-17 RAND is carried only if its key file is
   under `WALLETS_DIRS` at the `balances` step — otherwise fund it as below.
5. `fund-relayer` — the relayer wallet is in `faucet_recipients`, and the faucet mints only through
   a `faucet_minters` key (the 18 operator validators — A, which the laptop's `127.0.0.1:8545`
   tunnel reaches, is one): `rand --rpc http://127.0.0.1:8545 --key <relayer key> faucet` × 3
   (100 RAND each, as chains 15, 16 and 17 did), then `rand … balance` — skip if the carry already
   funded it.
6. `start-laptop` — `GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh`, then
   `mainnet/run-relayer.sh`.
7. Audit — `rand-bridge-audit` against chain 18: `total_supply` == Σ `locked` == endpoint custody;
   `rand_getBridgeState.min_inbound_sequence` shows the floors. Anish opens his carried zUSD with a
   v0.6.6 wallet (`rand asset-balance 1`) — a v0.6.3 (cs7) wallet cannot spend on chain 18.

## If the redeploy has landed (new Ethereum/BNB/Tron endpoints)

- **Genesis**: `EMITTER_2/3/4` = the new endpoints' 32-byte wire forms (left-padded); the cut
  refuses a changed emitter unless `MIN_INBOUND_<c>` is given: `none` for a fresh endpoint (its
  `sequence` starts at 0; the old endpoint's locks fail `WrongEmitter` on chain 18), or last
  minted + 1 if anything from it was minted before the cut (on chain 17, only if its table
  already names the new endpoint — then it is not a redeploy for chain 18 at all). Take the snapshot with the same `EMITTER_*`, so custody is read
  at the new addresses — the Tron custody (9 USDT) must have MOVED to the new endpoint before the
  snapshot, or Σ locked == custody fails.
- **Contracts**: the new endpoints hold the set-1 guardian addresses, and the set index each holds
  agrees with the relayer's `guardian_set_index = 1` and chain 18's `guardian_set_index` (a fresh
  constructor may start at 0 — the bridge session confirms against `RandBridgeBase`).
- **Daemons**: every `[[evm]]` `contract` in `relayer.toml`, `guardian-7/8.toml` and each droplet's
  `/etc/rand-guardian.toml` → the new address; `start_block` → the deployment block; the source
  cursors of chains 2/3/4 reset to `{"next_block": <deploy block>, "next_sequence": 0}` on every
  guardian and the relayer (old ones kept as `cursors.chain17`).

## Rollback (chain 17 again)

Stop the daemons; restore `rand-guardian.toml.chain17` and `cursors.chain17` on each droplet, the
three laptop tomls (`chain_id = 17`), the laptop cursors, and `rand_cli` back to the v0.6.3 build
(`~/rand-node-a/bin-v063/rand`); the fleet restores its units (`cutover-fleet-chain18.sh` header).
Start as in step 6. A redeployed endpoint cannot be rolled back to chain 17 — chain 17 does not
trust it; custody moved to it stays unmintable there until chain 18 is back.
