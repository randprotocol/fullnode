# DRAFT — the bridge session must review

# Chain 21 — the bridge side of the cut

Drafted 2026-10-12 by the cutover-prep session from `deploy/chain20-bridge-steps.md` (read it
first), chain 20 → chain 21. **The bridge session owns the daemons and this file**; nothing here has
run, and nothing here edits the bridge repository. The template for the daemons' stop / switch is
still the bridge repository's `daemons/mainnet/cut-chain19.sh` lineage (print every command, run only
with `--yes`, one step at a time) — derive a `cut-chain21.sh` with the differences below. The fleet
side is `deploy/cutover-fleet-chain21.sh` and `docs/chain21-cut-runbook.md`.

What is different from chain 20:

- **A new build: v0.8.0, and every prover-side `rand` needs it.** v0.8.0 carries constraint set 9:
  every verifier key and the proof encoding change, so a proof made by a v0.7.1 `rand` does not
  decode on chain 21, and a v0.8.0 `rand` does not prove for chain 20. So:
  - **The relayer** (droplet `rand-relayer-1`, unit `rand-relayer`, CLI `/usr/local/bin/rand`,
    wallet `/var/lib/rand-relayer/wallet/`) needs the **Linux v0.8.0 `rand`** from the signed
    release (the fleet's `rand`, sha256 as listed in v0.8.0's signed `SHA256SUMS`). **Keep the
    v0.7.1 one as `/usr/local/bin/rand.pre-c21`** (sha-checked against v0.7.1's signed
    `SHA256SUMS`) and install the new one while the relayer is stopped, after the fleet's `switch`,
    never before (a v0.8.0 `rand` cannot serve chain 20 in the meantime):
    ```
    systemctl is-active --quiet rand-relayer && { echo 'stop the relayer first'; exit 1; }
    [ "$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)" = '<v0.7.1 rand sha256>' ] || { echo 'installed rand is not v0.7.1'; exit 1; }
    [ -e /usr/local/bin/rand.pre-c21 ] || cp -a /usr/local/bin/rand /usr/local/bin/rand.pre-c21
    curl -fsSL -o /root/rand.c21 https://github.com/randprotocol/fullnode/releases/download/v0.8.0/rand
    [ "$(sha256sum /root/rand.c21 | cut -d' ' -f1)" = '<v0.8.0 rand sha256>' ] || { rm -f /root/rand.c21; echo 'SHA MISMATCH'; exit 1; }
    install -m 755 /root/rand.c21 /usr/local/bin/rand && /usr/local/bin/rand --version   # rand 0.8.0
    ```
  - **The guardian daemons** (hosts 1–6, and guardians 7/8 on the laptop): the mint PQ co-signature
    is unchanged; any `rand` a daemon shells out to must be the v0.8.0 one after the switch. Each
    guardian host's own `rand-node` is moved to v0.8.0 by the fleet (`cutover-fleet-chain21.sh
    switch`, which refuses a host whose `rand-guardian` is still active).
  - **`rand-bridge-gov`**: `binding_domain` stays 1, so the `…-2` layouts are unchanged; re-make the
    kept-ready pause file after launch — it binds chain 21's genesis hash.
- **The fees do not change.** Chain 20 already has `bridge.fees {mint_bps: 10, burn_bps: 10,
  recipient}` and the endpoints' own protocol fee is already 0; chain 21 carries the same section
  (the cut asserts it equal, recipient fingerprint `89DS-4Q4X-HXSX-MBYW`). Nothing for bridge-fa to
  change at this cut. Guardians still release the burn body's `release_amount`.
- **The emitters do not change.** Chain 21 trusts exactly chain 20's `bridge.emitters` (the
  2026-09-30 Ethereum / BNB Chain / Tron endpoints and the unchanged Solana program) and the same
  Rand-side `bridge.emitter`; `cut-chain21-genesis.sh` asserts them against
  `deploy/genesis-chain20.json`. Only `chain_id = 20` → `21` and the Rand cursor change in any
  daemon config.
- **The replay floors** are each endpoint's next sequence at the snapshot (`auto`, never below
  chain 20's own `{2: 3, 3: 3, 4: 3, 5: 7}`), which is last minted + 1 only if every user lock minted
  on chain 20. Same rules as chain 20 (explicit `MIN_INBOUND_<c>` + `ALLOW_UNMINTED_LOCKS=1` if one
  has not; cross-check with a copy of the relayer's `done/` as `RELAYER_DONE_DIR`).
- **The relayer's RAND carries only if its key is scanned** — unchanged: the
  `~/.rand-chain17/alloc-wallets/relayer.key.json` symlink must resolve before `balances`; the
  relayer wallet's first scan against chain 21 empties and rescans its note store (expected).

## Values (chain 20 at genesis; the cut re-reads every one in its snapshot)

| | chain 20 genesis (`deploy/genesis-chain20.json`) | chain 21 |
|---|---|---|
| `bridge.emitters` 2, 3, 4, 5 | the 2026-09-30 endpoints, Solana unchanged | unchanged (asserted) |
| Rand burn sequence (next) | 13 | chain 20's `rand_getBridgeState.burn_sequence` at the snapshot |
| Guardian set index | 1 | chain 20's live value (1 unless rotated) |
| Floors `min_inbound_sequence` | `{2: 3, 3: 3, 4: 3, 5: 7}` | each endpoint's next sequence at the snapshot, never below chain 20's |
| `bridge.rotation`, `bridge.fees` | `{86400, possession}`, `{10, 10, 89DS-…}` | unchanged (asserted) |
| endpoints' protocol fee | 0 | 0 (no change) |
| zUSD carry | `~/.rand-chain20/zusd-carry.txt` (anish 10, owner 89) | `~/.rand-chain21/zusd-carry.txt`, Σ == Σ locked at the snapshot |

## Order at the cut (with the fleet runbook)

0. Before anything: the v0.8.0 release is signed and its `rand` sha256 known; the clients' chain-21
   builds are ready (the record's `clients:` line); the pause key holder has `rand-bridge-gov`.
1. **`stop`** — before the snapshot, so nothing moves chain 20 after it is read:
   ```
   ssh root@rand-relayer-1 'systemctl stop rand-relayer'
   pkill -f 'rand-guardian --config mainnet/guardian-[78].toml'          # laptop
   for i in 1..6: ssh (guardian key) root@<host i> 'systemctl stop rand-guardian'
   ```
   Check first that nothing is in flight: each endpoint's `sequence()` equals the relayer's
   `next_sequence` for its chain; chain 20's `burn_sequence` equals the relayer's
   `cursors/rand.json` `next_sequence`. If a lock is in flight, let it mint on chain 20 first.
2. Fleet: snapshot → balances → the cut → the second operator's hash → `push` (chain 20 still
   running) → the user's go → `stop <genesis>` → `switch` → `start` → `wait` → `check-limits`.
3. **Relayer `rand`** — on `rand-relayer-1`, the v0.7.1 → v0.8.0 swap above (backup
   `rand.pre-c21` first).
4. **`droplet <1..6>`** — on each guardian host, once its node answers chain 21's genesis hash and
   `rand_getHealth` ok:
   ```
   cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain20
   sed -i -E 's/^chain_id = 20 /chain_id = 21 /' /etc/rand-guardian.toml
   grep -q '^chain_id = 21 ' /etc/rand-guardian.toml
   cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain20
   echo '{"next_block": 0, "next_sequence": <chain 21 burn_sequence>}' > /var/lib/rand-guardian/data/cursors/rand.json
   systemctl start rand-guardian; sleep 5; journalctl -u rand-guardian -n 5 --no-pager
   ```
5. **`rand-relayer-1`**: the relayer's toml → `chain_id = 21` (copy kept as `.chain20`), its
   `cursors` copied to `cursors.chain20` and `rand.json` reset to chain 21's `burn_sequence`;
   `/usr/local/bin/rand --version` says 0.8.0. Laptop: the same for guardians 7 and 8.
6. Start: `GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh` on the laptop, then
   `systemctl start rand-relayer` on `rand-relayer-1`.
7. Audit — `rand-bridge-audit` against chain 21 and the four endpoints: `total_supply` == Σ `locked`
   == custody; `rand_getBridgeState` shows chain 20's emitters, the cut's floors, `burn_sequence`,
   `rotation_rules`, `fees`. The carried zUSD holders open their notes with a v0.8.0 wallet.
8. One 1 USDT round trip on one endpoint, then the 50 zUSD treasury deposit (the runbook, §f).

## Rollback (chain 20 again) — the bridge stops FIRST

1. Stop the relayer and all eight guardians (step 1's commands). The fleet's `rollback` refuses a
   guardian host whose `rand-guardian` is active.
2. **Check that nothing happened on chain 21** while it ran — the fleet's
   `deploy/cutover-fleet-chain21.sh quiet deploy/genesis-chain21.json` (chain 21 still up):
   `rand_getBridgeState.burn_sequence` and every backing's `locked` must equal the genesis values;
   and the relayer's `done/` holds nothing newer than the snapshot. If anything was burned or
   minted on chain 21, a rollback loses it (a release paid for a chain-21 burn has no burn on chain
   20; a chain-21 mint is re-mintable on chain 20 only below its floor): the user decides.
3. Fleet: `halt` → `rollback` → `start` → `wait20` (all 26 on chain 20 and C's height moving).
4. Restore on each guardian host `rand-guardian.toml.chain20` and `cursors.chain20`; on
   `rand-relayer-1` the toml, the cursors **and the v0.7.1 `rand`**:
   ```
   [ "$(sha256sum /usr/local/bin/rand.pre-c21 | cut -d' ' -f1)" = '<v0.7.1 rand sha256>' ] || { echo 'rand.pre-c21 is NOT the v0.7.1 rand — nothing installed; stop here'; exit 1; }
   install -m 755 /usr/local/bin/rand.pre-c21 /usr/local/bin/rand
   /usr/local/bin/rand --version                                       # 0.7.1
   ```
   and the laptop guardians' tomls and cursors. Start as in step 6. No endpoint fee changes (chain
   20 and chain 21 have the same `bridge.fees`).
