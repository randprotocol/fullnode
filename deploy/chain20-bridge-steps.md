# Chain 20 — the bridge side of the cut (draft for the bridge session)

`deploy/chain19-bridge-steps.md` (read it first) rewritten for chain 20: chain 19 (v0.6.7, the
2026-09-30 endpoints, live since 2026-10-01 03:43 UTC) is chain 20's predecessor. It is **not** a
script and edits nothing in the bridge repository. The bridge session owns the daemons; the
template for their stop / switch is the bridge repository's **`daemons/mainnet/cut-chain19.sh`**
(print every command, run only with `--yes`, one step at a time) — derive a `cut-chain20.sh` from
it with the differences below. Nothing here has run.

What is different from chain 19:

- **A new build: v0.6.8 (main + RPL-2), and every signer needs it.** Chain 20's genesis sets
  `binding_domain: 1` (BIND-1): the genesis hash goes into every transaction binding — the fee
  bundle of every `BridgeAttest` and `BridgeBurn`, so every proof the relayer makes — and into
  every bridge governance message (`rand-bridge-pause-2`, `-pq-unpause-2`, `-pq-list-2`,
  `-pq-register-2`, `-pq-rotate-pq-2`, `-pq-rotate-pause-2`; `docs/bridge.md` §21, "BIND-1"). A
  v0.6.7 `rand` builds the chain-id form, which a chain-20 node refuses. So:
  - **The relayer** now runs on droplet **`rand-relayer-1`** (systemd unit `rand-relayer`, CLI
    `/usr/local/bin/rand`, wallet `/var/lib/rand-relayer/wallet/`). It needs a **Linux v0.6.8
    `rand`** installed at `/usr/local/bin/rand` there, sha256-checked against the v0.6.8 release's
    `rand` (the fleet's `WANT_SHA_WALLET`), with the v0.6.7 one kept beside it for rollback
    (`/usr/local/bin/rand.pre-c20`). Install it while the relayer is stopped (step 1), not before:
    the v0.6.8 `rand` must not send to chain 19 in the meantime (chain 19 is pinned to the chain-id
    form, so a v0.6.8 wallet still speaks it there — but one build per chain keeps rollback simple).
  - **The guardian daemons** (hosts 1–6 and guardians 7/8 on the laptop): the mint PQ
    co-signature is **unchanged** — `rand-bridge-pq-cosign-1 ‖ chain_id ‖ mu` (`docs/bridge.md`
    §21, "Open, deliberately not done here") — so the co-signing code needs no change; any `rand`
    a daemon shells out to must be the v0.6.8 one, and each guardian host's own `rand-node` is moved
    to v0.6.8 by the fleet (`deploy/cutover-fleet-chain20.sh switch`).
  - **`rand-bridge-gov`** (bridge repository) must sign the `…-2` layouts before anyone pauses,
    unpauses, lists or rotates on chain 20; a pause file signed in the chain-id form is refused
    `BadPauseSignature`. Re-make the pre-signed pause file (if one is kept ready) for chain 20 after
    launch: it binds the genesis hash, which exists only once the cut is done.
  - **Wallets and clients need a v0.6.8 build for chain 20**: the `rand` CLI, the clients
    repository's apps (wasm core: the BIND-1 chain-id rule, `CHAIN_ID_BINDING_CHAIN_IDS` = 14–19,
    and `DEFAULT_CHAIN_ID` → 20), randscan (the new `rand_getLimits` fields, `rand_getAdmitted`,
    `invoke` transactions) and the website's WASM. A v0.6.7-line wallet signs nothing chain 20
    accepts. This is the cut record's `clients:` line.
- **The emitters do not change.** Chain 20 trusts exactly chain 19's `bridge.emitters` — the
  2026-09-30 Ethereum / BNB Chain / Tron endpoints and the unchanged Solana program — and the
  same Rand-side `bridge.emitter`. `cut-chain20-genesis.sh` defaults to them, checks them against
  `deploy/genesis-chain19.json` itself, refuses any other value without `EMITTERS_CHANGED=1`, and
  refuses the 2026-09-19 endpoints chains 14–18 trusted outright. So no contract, start block or
  cursor *address* changes in any daemon config — only `chain_id = 19` → `20` and the Rand cursor.
- **The replay floors are each endpoint's next sequence = last minted + 1.** On the three
  redeployed endpoints sequence 0 is the operator's consume-step lock and must never mint; the cut
  refuses any floor below 1 for chains 2, 3 and 4 (and `none` on every chain). By default each
  floor is `auto` — the endpoint's next outbound sequence at the snapshot, never below chain 19's
  own floor (`{2: 1, 3: 1, 4: 1, 5: 4}`) — which is last minted + 1 **only if every user lock has
  minted on chain 19** (the cut's custody == locked check fails otherwise). If one has not, give
  the floors explicitly — `MIN_INBOUND_<c>=<last minted + 1>`, or `MIN_INBOUND_FILE` with one
  `<chain> <floor>` line per chain (one source per chain; both is refused) — together with
  `ALLOW_UNMINTED_LOCKS=1`, which lets those locks mint on chain 20 (custody may then exceed
  `locked` on that chain only, and the cut warns). Cross-check with a copy of the relayer's
  `done/` from `rand-relayer-1` as `RELAYER_DONE_DIR`.
- **`bridge.rotation: {delay_secs: 86400, needs_possession: true}`** (BRG-14) is new in the
  genesis. Any PQ-set or pause-key rotation on chain 20 must carry each new key's own possession
  signature (the V2 actions) and pends 24 hours, during which the current pause key can cancel it
  (`docs/bridge.md` §21.5; the signer is `rand-node bridge-gov`). Run §21.5's rehearsal checklist
  on a private chain before the first real rotation. No rotation is planned at this cut.
- **`proof_window_blocks: 1024`** (issue #118): a mint's fee-bundle proof (and every bundle's
  anchor and `time`) now has **~20 minutes** at 1.17 s blocks between proving and inclusion — it
  was 256 roots, about 5 minutes, on chains 14–19. A relayer retry that used to expire on a slow
  prover now lands; a stale anchor still dies within the hour.
- **The relayer's RAND carries only if its key is scanned.** `balances` needs the key alone:
  `~/.rand-chain14/wallets/relayer.key.json` must be in the curated scan directory
  (`~/.rand-chain17/alloc-wallets/relayer.key.json` is the symlink; `REQUIRED_WALLETS=relayer`
  makes the scan refuse without it). The laptop copy's note store is stale — the live wallet is on
  `rand-relayer-1` — so `balances` rescans every wallet from leaf 0 (`rand sync --rescan`) and
  never relies on a note store. The relayer wallet on `rand-relayer-1` binds its note store to
  chain 19; its first scan against chain 20 empties and rescans it, with a warning (expected).
- The guardian set, the PQ set and the pause key carry over unchanged (the cut refuses a live
  rotation on chain 19 unless `BRIDGE_ROTATED=1`); `GUARDIAN_PQ_SEED` stays `pq-next.seed`.

## Values (chain 19 at genesis; the cut script re-reads every one in its snapshot)

| | chain 19 genesis (`deploy/genesis-chain19.json`) | chain 20 |
|---|---|---|
| `bridge.emitters` 2, 3 | `0000000000000000000000007af6b17047c1db6cb54347fdea45cf9179075bfa` | unchanged (asserted equal to chain 19's file) |
| `bridge.emitters` 4 | `0000000000000000000000006410797df959987a5baf65b5fab97edeb34d5163` | unchanged |
| `bridge.emitters` 5 | `d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a` | unchanged |
| `bridge.emitter` (Rand side) | `c02df6ba…d15f` | unchanged |
| Rand burn sequence (next) | 8 | chain 19's `rand_getBridgeState.burn_sequence` at the snapshot (8 expected; another value is carried with a warning) |
| Guardian set index | 1 | chain 19's live value (1 unless rotated) |
| Floors `min_inbound_sequence` | `{2: 1, 3: 1, 4: 1, 5: 4}` | each endpoint's next sequence at the snapshot (= last minted + 1), never below chain 19's, never below 1 on 2/3/4; `{2: 1, 3: 1, 4: 1, 5: 4}` expected if nothing was locked on chain 19 |
| `bridge.rotation` | absent | `{delay_secs: 86400, needs_possession: true}` |
| zUSD locked | Solana USDT 10 | chain 19's per-backing `locked` at the snapshot == source custody |
| zUSD carry | `~/.rand-chain19/zusd-carry.txt` | `~/.rand-chain20/zusd-carry.txt` (the same one line, 10 zUSD to the same third-party address, unless it moved), Σ == Σ locked |

## Order at the cut (with the fleet runbook)

0. Before anything: the v0.6.8 Linux `rand` is built and its sha256 known (the fleet's
   `WANT_SHA_WALLET`); `rand-bridge-gov` signs the `…-2` layouts; the clients' v0.6.8 builds are
   ready (the cut record's `clients:` line).
1. `stop` — before the snapshot, so no mint or release can move chain 19 after it is read (the
   template's stop step, with these hosts):
   ```
   ssh root@rand-relayer-1 'systemctl stop rand-relayer'
   pkill -f 'rand-guardian --config mainnet/guardian-[78].toml'          # laptop
   for i in 1..6: ssh (guardian key) root@<host i> 'systemctl stop rand-guardian'
   ```
   Check first that nothing is in flight: the relayer log on `rand-relayer-1` shows no pending lock
   or burn; each endpoint's `sequence()` equals the relayer's `next_sequence` for its chain (every
   user lock minted); chain 19's `burn_sequence` equals the relayer's `cursors/rand.json`
   `next_sequence`. If a lock is in flight, let it mint on chain 19 first (or plan the explicit
   floors above). Then, on `rand-relayer-1`, keep the v0.6.7 `rand` as
   `/usr/local/bin/rand.pre-c20` and install the v0.6.8 one (sha-checked).
2. Fleet: `deploy/cutover-fleet-chain20.sh preflight` → `stage` → `deploy/cut-chain20-genesis.sh
   snapshot <dir>` → `… balances <dir>` (relayer key linked; rescan) → (the user's go) →
   `cutover-fleet-chain20.sh stop` → the cut (`CUT_RECORD=…`, `RELAYER_DONE_DIR=<copy of
   rand-relayer-1's done/>`) → the second operator's `second-hash` → `push` → `switch` (refuses a
   guardian host whose `rand-guardian` is still active) → `start` → `wait` → `check-limits`. Each
   phase alone, its `$?` read before the next.
3. `droplet <1..6>` — on each guardian host, once its node answers `rand_getGenesisHash` with the
   chain-20 hash and `rand_getHealth` ok (the fleet's `wait` phase):
   ```
   cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain19
   sed -i -E 's/^chain_id = 19 /chain_id = 20 /' /etc/rand-guardian.toml
   grep -q '^chain_id = 20 ' /etc/rand-guardian.toml
   cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain19
   echo '{"next_block": 0, "next_sequence": <chain 20 burn_sequence>}' > /var/lib/rand-guardian/data/cursors/rand.json
   # source cursors (chains 2–5) are KEPT: the endpoints did not change and every lock below the
   # floors minted on chain 19. The (chain, sequence) stores stay too — no endpoint restarted.
   systemctl start rand-guardian; sleep 5; journalctl -u rand-guardian -n 5 --no-pager
   ```
4. `rand-relayer-1`:
   ```
   cp -p <relayer.toml> <relayer.toml>.chain19
   sed -i -E 's/^chain_id = 19 /chain_id = 20 /' <relayer.toml>      # rand_cli stays /usr/local/bin/rand (now v0.6.8)
   cp -Rp <data>/cursors <data>/cursors.chain19
   echo '{"next_block": 0, "next_sequence": <chain 20 burn_sequence>}' > <data>/cursors/rand.json
   /usr/local/bin/rand --version                                       # 0.6.8
   ```
   Laptop: the same for `mainnet/guardian-7.toml`, `mainnet/guardian-8.toml` and their cursors.
5. `fund-relayer` — only if the carry did not fund it: the relayer wallet is in
   `faucet_recipients`, and the faucet mints only through a `faucet_minters` key:
   `rand --rpc <chain-20 RPC> --key /var/lib/rand-relayer/wallet/<key> faucet` × 3, then `… balance`.
6. Start: `GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh` on the laptop, then
   `systemctl start rand-relayer` on `rand-relayer-1`.
7. Audit — `rand-bridge-audit` against chain 20 and the four endpoints: `total_supply` == Σ
   `locked` == endpoint custody; `rand_getBridgeState` shows chain 19's `emitters`, the floors the
   cut printed, `burn_sequence`, and `rotation_rules {delay_secs: 86400, needs_possession: true}`
   (`check-limits` reads the same). The carried zUSD holder opens his note with a **v0.6.8** wallet
   (`rand asset-balance 1`).
8. Then: one 1 USDT round trip on one endpoint (the first real proof under `binding_domain: 1`
   through the relayer); re-make the kept-ready pause file for chain 20 with `rand-bridge-gov`.

## Rollback (chain 19 again)

Stop the daemons; restore `rand-guardian.toml.chain19` and `cursors.chain19` on each guardian host,
the relayer's toml and cursors on `rand-relayer-1` **and its v0.6.7 `rand`**
(`/usr/local/bin/rand.pre-c20` → `/usr/local/bin/rand`, sha-checked), the laptop guardians' tomls
and cursors; the fleet restores its units and binaries (`cutover-fleet-chain20.sh rollback`, then
`start`). Start as in step 6. Chain 19 resumes at the height it stopped at with `burn_sequence` and
`locked` as the snapshot read them — provided nothing was minted or released on chain 20 in
between (a release paid out on a source chain for a chain-20 burn has no burn on chain 19).
