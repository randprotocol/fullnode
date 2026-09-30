# Chain 19 — the bridge side of the cut (draft for the bridge session)

`deploy/chain18-bridge-steps.md` (read it first) rewritten for chain 19: chain 18 (v0.6.7, the gas
model, the memo on) is chain 19's predecessor, so every step below is chain 18's with the chain ids
moved up one — **minus everything a new build needed, plus the endpoint redeploy**, which chain 18's
steps only described as an option ("If the redeploy has landed") and which is the whole reason for
this cut. It is **not** a script and edits nothing in the bridge repository; the bridge session owns
`daemons/mainnet/cut-chain19.sh` (bridge `721905c`: print every command, run only with `--yes`, one
step at a time), which already implements steps 1 and 3–6 below for the new endpoints.

What is different from chain 18:

- **No new build.** Chain 19 is a pure re-genesis of chain 18 on v0.6.7 (constraint set 8, bundle
  guest v3, `hc_auth`, the gas section, `envelope_bytes` 1860 — all asserted equal to chain 18's by
  the cut). The relayer's `rand` stays the build it runs chain 18 with (`rand_cli` is NOT changed);
  the guardians' own `rand-node` on the six guardian hosts stays v0.6.7 and is moved by the fleet
  (`deploy/cutover-fleet-chain19.sh`: `chain19.conf`, `--datadir /var/lib/randnode/data-19`,
  `chain18.conf` moved to `/root/chain18.conf.c18`; no binary is touched).
- **The 2026-09-30 endpoint redeploy (R1/R3) is what chain 19 carries.** Its genesis names the new
  Ethereum, BNB Chain and Tron endpoints as `bridge.emitters` 2, 3 and 4; Solana (5) and the
  Rand-side `bridge.emitter` are unchanged. These are the DEFAULTS of `cut-chain19-genesis.sh`,
  pinned: any other `EMITTER_<c>` is refused unless `EMITTERS_CHANGED=1`. Chain 18 never trusted
  the new endpoints, so nothing from them was ever minted.
- **The replay floor of a redeployed endpoint is explicit.** The cut refuses without
  `MIN_INBOUND_2`, `MIN_INBOUND_3` and `MIN_INBOUND_4`; the expected value is `1` for each: the
  endpoint's sequence 0 is the operator's consume-step lock (it re-locks exactly what the replayed
  old release then pays out — bridge `docs/mainnet-deployment.md`, "A fresh endpoint has an empty
  `consumed` map") and must never mint. If the consume step has NOT run by the snapshot the endpoint
  still reads `sequence() == 0` and a floor of 1 is *ahead* of it: the cut refuses unless
  `FLOOR_AHEAD_OK=1`. If MORE than one lock was emitted by a new endpoint (`sequence() > 1`) the cut
  refuses ("will mint on chain 19"): chain 18 cannot drain it, so decide by hand (raise the floor if
  the lock is the operator's and must never mint, or `ALLOW_UNMINTED_LOCKS=1` to let it mint).
- **Solana's floor is re-derived, not copied**: its program's next outbound sequence at the snapshot
  (4 expected: locks 2 and 3 were the 2026-09-30 rebalancing), never below chain 18's own floor (2),
  cross-checked against the relayer's `done/5/` records when `RELAYER_DONE_DIR` is given.
- **Custody is read at the NEW endpoints** for chains 2/3/4 (the snapshot uses the same `EMITTER_*`
  as the cut, and the cut refuses a snapshot read anywhere else) and must equal chain 18's
  per-backing `locked`: 0 for every Ethereum, BNB Chain and Tron backing, Solana USDT 10. A consume
  step leaves its endpoint at custody 0 (the release pays out what the lock brought in; the 10 bps
  stay in `accruedFees`, which the snapshot subtracts).
- **The guardian set, the PQ set and the pause key carry over unchanged** (the cut refuses a live
  rotation on chain 18 unless `BRIDGE_ROTATED=1`): guardian set 1, the same eight PQ keys, the same
  pause key; `GUARDIAN_PQ_SEED` stays `pq-next.seed`.

## Values (chain 18 at genesis, and live on 2026-09-30; the cut script re-reads every one in its snapshot)

| | chain 18 genesis (`deploy/genesis-chain18.json`) | chain 18 live, 2026-09-30 | chain 19 |
|---|---|---|---|
| `bridge.emitters` 2, 3 | `…d6ebd21c3df90c9175ebdc8d6b377a9361604892` | unchanged | `0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa` |
| `bridge.emitters` 4 | `…0992df85dcce77ded2c0387f1fa9cf98ac859700` | unchanged | `0000000000000000000000006410797df959987a5baf65b5fab97edeb34d5163` |
| `bridge.emitters` 5 | `d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a` | unchanged | unchanged |
| `bridge.emitter` (Rand side) | `c02df6ba…d15f` | unchanged | unchanged |
| Rand burn sequence (next) | 7 | 8 (burn 7 = the Tron rebalancing) | chain 18's `rand_getBridgeState.burn_sequence` at the snapshot (8 expected; another value is carried with a warning) |
| Guardian set index | 1 | 1 | chain 18's live value (1 unless rotated) |
| Floors `min_inbound_sequence` | `{2: 2, 3: 2, 4: 2, 5: 2}` | same | `{2: 1, 3: 1, 4: 1, 5: 4}` — 2/3/4 explicit (`MIN_INBOUND_<c>=1`), 5 = Solana's `sequence` at the snapshot |
| zUSD locked | Tron USDT 9, Solana USDT 1 | Solana USDT 10 | chain 18's per-backing `locked` at the snapshot == source custody (Solana USDT 10 expected) |
| zUSD carry | `~/.rand-chain18/zusd-carry.txt` | | `~/.rand-chain19/zusd-carry.txt` (the same one line: 10 zUSD to the same third-party address), Σ == Σ locked |

## Order at the cut (with the fleet runbook)

0. Before anything: the new endpoints are ready to carry value — past their set-0 windows
   (2026-10-01 12:23:40 UTC for the latest), `setToken` done, and the consume step run on each
   (Ethereum seq 4, BSC seq 5, Tron seq 7), so each reads `sequence() == 1` and custody 0. If the
   cut runs BEFORE the consume steps, `FLOOR_AHEAD_OK=1` (above) — and the bridge stays closed on
   chains 2/3/4 until they are done.
1. `stop` — before the snapshot, so no mint or release can move chain 18 after it is read:
   ```
   pkill -f 'rand-relayer --config mainnet/relayer.toml'
   pkill -f 'rand-guardian --config mainnet/guardian-[78].toml'
   for i in 1..6: ssh (guardian key) root@<host i> 'systemctl stop rand-guardian'
   ```
   Check first that nothing is in flight: the relayer log shows no pending lock or burn, the Solana
   program's `sequence` equals the relayer's `next_sequence` for chain 5, and chain 18's
   `burn_sequence` equals `cursors/rand.json`'s `next_sequence`. If a Solana lock is in flight, let
   it mint on chain 18 first. Pause the OLD Ethereum, BNB Chain and Tron endpoints (their admin
   keys can): chain 19 will not mint from them (`WrongEmitter`), so a lock there after the snapshot
   is stranded.
2. Fleet: `deploy/cutover-fleet-chain19.sh preflight` → `deploy/cut-chain19-genesis.sh snapshot
   <dir>` → `… balances <dir>` → (the user's go) → `cutover-fleet-chain19.sh stop` → the cut (with
   `MIN_INBOUND_2=1 MIN_INBOUND_3=1 MIN_INBOUND_4=1` and
   `RELAYER_DONE_DIR=<bridge>/data/mainnet/relayer/done` for Solana's floor cross-check) → `push` →
   `switch` (refuses a guardian host whose `rand-guardian` is still active) → `start` → `wait`.
   Each phase alone, its `$?` read before the next.
3. `droplet <1..6>` — on each guardian host, once its node answers `rand_getGenesisHash` with the
   chain-19 hash and `rand_getHealth` ok (the fleet's `wait` phase):
   ```
   cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain18
   sed -i -E 's/^chain_id = 18 /chain_id = 19 /' /etc/rand-guardian.toml
   grep -q '^chain_id = 19 ' /etc/rand-guardian.toml
   # every [[evm]] `contract` of chains 2/3/4 → the new endpoint, `start_block` → the block AFTER
   # its consume step (so the operator's sequence-0 lock is never observed)
   cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain18
   echo '{"next_block": 0, "next_sequence": <chain 19 burn_sequence>}' > /var/lib/rand-guardian/data/cursors/rand.json
   # chains 2/3/4: cursors reset to {"next_block": <start_block>, "next_sequence": 1}, and the
   # (chain, sequence)-keyed stores of those chains (signed/, refused/, observed/) moved aside —
   # a new endpoint restarts at sequence 0 and the old entries would read as equivocation.
   # Solana's cursor (solana.json) is KEPT: it is past every chain-14..18 lock.
   systemctl start rand-guardian; sleep 5; journalctl -u rand-guardian -n 5 --no-pager
   ```
   Nothing in a guardian's `signed/` store was signed for chain 19 (the PQ co-signature binds the
   chain id); the chain-5 entries stay, the chain-2/3/4 ones are archived as above.
4. `laptop`:
   ```
   for f in mainnet/relayer.toml mainnet/guardian-7.toml mainnet/guardian-8.toml:
     sed -i '' -E 's/^chain_id = 18 /chain_id = 19 /' $f        # + the three contracts and start blocks
   for d in relayer guardian-7 guardian-8:
     cp -Rp data/mainnet/$d/cursors data/mainnet/$d/cursors.chain18
     echo '{"next_block": 0, "next_sequence": <chain 19 burn_sequence>}' > data/mainnet/$d/cursors/rand.json
     # chains 2/3/4: stores (signed/ refused/ observed/ done/) archived, cursors at sequence 1
   ```
   `rand_cli` in `relayer.toml` is NOT changed: the v0.6.7-line `rand` that serves chain 18 serves
   chain 19. The relayer wallet's note store is bound to chain 18; the first scan against chain 19
   empties and rescans it with a warning (expected). Its chain-18 RAND is carried only if its key
   file is under `WALLETS_DIRS` at the `balances` step (`~/.rand-chain17/alloc-wallets/relayer.key.json`
   → `~/.rand-chain14/wallets/relayer.key.json`; check the symlink is there BEFORE the scan — it
   went missing once) — otherwise fund it as below.
5. `fund-relayer` — only if the carry did not fund it: the relayer wallet is in `faucet_recipients`,
   and the faucet mints only through a `faucet_minters` key (the 18 operator validators):
   `rand --rpc http://127.0.0.1:8545 --key <relayer key> faucet` × 3, then `rand … balance`.
6. `start-laptop` — `GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh`, then
   `mainnet/run-relayer.sh`.
7. Audit — `rand-bridge-audit` against chain 19 and the NEW endpoints: `total_supply` == Σ `locked`
   == endpoint custody (Solana USDT 10, everything else 0); `rand_getBridgeState` shows the new
   `emitters`, `min_inbound_sequence` `{2: 1, 3: 1, 4: 1, 5: 4}` and `burn_sequence` 8. The carried
   zUSD holder opens his note with any v0.6.7-line wallet (`rand asset-balance 1`).
8. Then, per the bridge repo: one 1 USDT round trip per new endpoint; the randbridge.org status
   service moved to a new database and the new contracts (`randbridge.org/DEPLOY.md` "Moving to
   redeployed bridge endpoints"); BR-3 (timelock handover) for the new Tron endpoint.

## Rollback (chain 18 again)

Stop the daemons; restore `rand-guardian.toml.chain18`, `cursors.chain18` and the archived
chain-2/3/4 stores on each droplet, the three laptop tomls (`chain_id = 18`, the OLD contracts and
start blocks), the laptop cursors and stores; the fleet restores its units
(`cutover-fleet-chain19.sh rollback`, then `start`). `rand_cli` was never changed. Start as in step
6. **Chain 18 does not trust the redeployed endpoints**: anything locked on a new endpoint stays
unmintable until chain 19 is back, and the old endpoints (paused in step 1) must be unpaused for
chain 18 to bridge again. Chain 18 resumes at the height it stopped at with `burn_sequence` and
`locked` as the snapshot read them — provided no release replayed onto an OLD endpoint in between.
