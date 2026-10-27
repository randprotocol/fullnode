# Chain 21: the cut and the fleet cutover (runbook)

Written 2026-10-12 on `feat/chain21-cutover` (fullnode main c0878c3f merged in). **Nothing in this
runbook has run against a server.** Every step that touches a host, the public RPC, GitHub or a key
runs only on the user's go, typed in the executing session, one step at a time; each fleet phase
runs **alone**, never piped or chained, and its `echo $?` is read before the next (the chain-16
trap).

What is being cut (the user's decisions, 2026-10-08 to 2026-10-12): chain 21 from a snapshot of
chain 20, on fullnode **v0.8.0**, with the `fees` section (burn_base + burn_floor), the `perps`
section (BTC-PERP on zUSD), the `multisig` section (the treasury, 2 of 3, 100 000 RAND new
issuance), and **`hc_auth_multisig`** (private multisig, guest `9705f8e2…8247`) at **6 MiB proofs
/ 19 MiB blocks**. The fleet is the **current 26 droplets** (the DigitalOcean account is locked: no
host can be created, so there is no spare, no fresh archive and no big prover host to add).

The tools: `deploy/cut-chain21-genesis.sh` (snapshot, balances, the cut, check-limits),
`deploy/cutover-fleet-chain21.sh` (preflight, stage, push, stop, switch, start, wait, status; for
a rollback quiet, halt, rollback, wait20; `DRY_RUN=1` and `SELFTEST=1`),
`deploy/cut-records/chain21.record` (the draft cut record), `deploy/chain21-bridge-steps.md` (DRAFT,
the bridge session's to review).

**The order, end to end.** Chain 20 keeps running until everything chain 21 needs is on every host:
preflight → stage → bridge stop → snapshot → balances → the cut → the second operator's hash →
`push` → **the user's go** → `stop <genesis>` (refuses unless all 26 hosts hold the staged build,
the verified key and the pushed genesis) → `switch` → `start` → `wait` → check-limits → bridge
restart. A refused cut or an absent second operator therefore never leaves the fleet down. The
cut stamps the genesis time, so the second operator stands by before the cut runs, and the go
follows `push` within minutes.

## Known risk, stated plainly

**The msauth prove has never completed.** A Test-FRI prove of the multisig auth guest peaked at a
**76.4 GB** footprint and was killed on a 48 GB Mac. No multisig-private spend can be proven on any
hardware the operator has, and none can be bought while the DigitalOcean account is locked. So:

- `hc_auth_multisig` ships **untested end to end**, by the user's decision. The verifier side is in
  place (the pinned 23 754-byte key on every node, admission tells the two auth guests apart), but
  no real multisig-private proof has ever been verified by a node.
- The **6 MiB / 19 MiB limits are an estimate** (auth + bundle ≈ 4.8 MB at Production FRI, from
  table widths), not a measurement. If a real Production proof turns out larger than 6 MiB, no
  multisig-private spend can ever be admitted on chain 21: the limits are genesis values, and
  changing them is another cut.
- Funds sent to a private-multisig address on chain 21 cannot be spent until a host with ≥ 96 GB
  proves one. The treasury (the public `multisig` section) is **not** affected: it is the
  non-private multisig account, spent with plain signatures.
- The cutover's checks prove only that every node holds the pinned verifier key and starts with it
  (`rand_status.msauth_key = loaded`); they cannot prove that the key verifies a real proof.

Other standing caveats carried into this cut: the treasury's three signer keys were generated on
one machine and are exported in `~/.zshrc` (docs/multisig.md says "never two keys in one place");
zUSD collateral is outside the supply audit (perps M6); `deploy/key-separation` is `met: no`, so
the genesis is `testnet: true`.

## a. Pre-flight: the tag, the release, the signature, the local copies

Inputs: fullnode **c0878c3f** (origin/main = a1785c95 + version 0.8.0, doc memory corrections, a
dated CHANGELOG, and the CHANGELOG assets line naming msauth-vk-production.bin). Tag **v0.8.0** from
it once its push CI run, **38208645768**
(https://github.com/randprotocol/fullnode/actions/runs/38208645768), ends green. The tag happens
only if that run ends green; otherwise a new run's id replaces it in the annotation below.

1. **Tag** (the user; `docs/deploy.md` "Release rule": an annotated tag naming the green run):

   ```bash
   cd ~/Github/randprotocol/fullnode && git fetch origin
   gh run list -R randprotocol/fullnode -w ci.yml --commit c0878c3f --json databaseId,conclusion,headSha   # success
   gh run view 38208645768 -R randprotocol/fullnode --json conclusion,headSha
   git tag -a v0.8.0 c0878c3f -m "v0.8.0 — chain 21 onward (constraint set 9, private multisig)
   ci: run 38208645768 (success) at c0878c3f"
   git push origin v0.8.0
   ```

2. **release.yml** runs on the tag: it refuses unless CI was green at c0878c3f, builds on
   ubuntu-24.04, self-checks `keygen-msauth-vk --check` against `--print-pinned production`, attests
   provenance, and publishes **rand-node, rand, rand-prover, msauth-vk-production.bin, SHA256SUMS**.
   Watch it: `gh run watch -R randprotocol/fullnode $(gh run list -R randprotocol/fullnode -w release.yml -L1 --json databaseId -q '.[0].databaseId')`.

3. **The user signs SHA256SUMS** in a real Terminal (the key is passphrase-protected; a session
   cannot do this):

   ```bash
   mkdir -p ~/.rand-chain21/release-v0.8.0 && cd ~/.rand-chain21/release-v0.8.0
   gh release download v0.8.0 -R randprotocol/fullnode -p SHA256SUMS
   ssh-keygen -Y sign -n rand-release -f ~/.rand-release/release_ed25519 SHA256SUMS   # writes SHA256SUMS.sig
   gh release upload v0.8.0 SHA256SUMS.sig -R randprotocol/fullnode
   ```

   Before saying the signature is missing, re-list the assets with timestamps
   (`gh release view v0.8.0 -R randprotocol/fullnode --json assets`).

4. **Download and verify every asset locally** (run the library under `bash`, never sourced into
   zsh — it breaks word-splitting):

   ```bash
   REL=~/.rand-chain21/release-v0.8.0
   gh release download v0.8.0 -R randprotocol/fullnode -D "$REL" --clobber   # rand-node rand rand-prover msauth-vk-production.bin SHA256SUMS SHA256SUMS.sig
   cd ~/rand-worktrees/fullnode-chain21-cutover
   bash -c ". deploy/lib/verify-release.sh
     verify_release_sums $REL/SHA256SUMS $REL/SHA256SUMS.sig &&
     for f in rand-node rand rand-prover msauth-vk-production.bin; do verify_binary $REL/\$f $REL/SHA256SUMS \$f || exit 1; done && echo ALL VERIFIED"
   for f in rand-node rand rand-prover msauth-vk-production.bin; do gh attestation verify "$REL/$f" -R randprotocol/fullnode >/dev/null && echo "attested $f"; done
   shasum -a 256 "$REL/msauth-vk-production.bin"    # 68facb06c7f321aaf1d4d541acf6b5c0e9d7f17788ed1c9add6c5a8a8f7acd30
   wc -c < "$REL/msauth-vk-production.bin"           # 23754
   ```

5. **v0.7.0's signed sums** — what chain 20 runs. Chain 20 ran v0.6.8, then v0.7.0 from 2026-10-02;
   v0.7.0 was tagged but **never rolled** (a read-only `status` on 2026-10-12: all 26 hosts
   "0.7.0", git_sha 806ed349, healthy). They are the cutover's `OLD_RELEASE_SUMS` (default
   `OLD_VERSION` 0.7.0, `OLD_GIT_SHA` 806ed349…), read for preflight, the stop gate, the
   `*.pre-c21` backups and the rollback. **Confirm before the cut** with
   `deploy/cutover-fleet-chain21.sh status` (every host: version 0.7.0, git_sha 806ed349…) — and
   the relayer's own `rand`: on 2026-10-12 `rand-relayer-1` (203.0.113.28) ran rand 0.6.8, sha256
   155dfe66…ee2d — re-read it (`ssh -i ~/.ssh/rand_guardian_ed25519 root@203.0.113.28 'rand
   --version; sha256sum /usr/local/bin/rand'`; the alias `rand-relayer-1` is not in
   `~/.ssh/config`; on the first connect check the host key is ED25519
   <the host-key fingerprint from the operator's record>); see `deploy/chain21-bridge-steps.md`; if anything else answers, set `OLD_VERSION`/`OLD_GIT_SHA` and
   that release's sums instead:

   ```bash
   # already done 2026-10-12: ~/.rand-chain21/release-v0.7.0/SHA256SUMS (+ .sig) verified; it pins
   # rand-node fd7fa517…, rand 406e0108…, rand-prover 524c6e9b…. To redo it:
   OLDREL=~/.rand-chain21/release-v0.7.0; mkdir -p "$OLDREL"
   gh release download v0.7.0 -R randprotocol/fullnode -D "$OLDREL" -p SHA256SUMS -p SHA256SUMS.sig
   bash -c ". deploy/lib/verify-release.sh; verify_release_sums $OLDREL/SHA256SUMS $OLDREL/SHA256SUMS.sig"
   ```

6. **macOS builds on the laptop** (the release assets are Linux): the cut's `NODE`/`WALLET` and the
   cutover's `LOCAL_NODE` must be **v0.8.0 from the tag**; the `balances` scan needs chain 20's
   own `rand`, **v0.7.0** — a local input, macOS, built from tag v0.7.0 (806ed349), matching chain 20
   exactly (none is on the laptop: the chain-20 lesson — build it from the tag). Check
   free disk first (≥ 40 GiB; see the memory note on Time Machine snapshots).

   ```bash
   cd ~/Github/randprotocol/fullnode
   git worktree add ~/rand-worktrees/fullnode-v080 v0.8.0
   (cd ~/rand-worktrees/fullnode-v080 && RAND_BUILD_SHA=$(git rev-parse HEAD) cargo build --release --locked -p randprotocol-node -p randprotocol-client)
   ~/rand-worktrees/fullnode-v080/target/release/rand-node --version        # rand-node 0.8.0
   ~/rand-worktrees/fullnode-v080/target/release/rand-node keygen-msauth-vk --print-pinned production   # 68facb06…cd30
   git worktree add ~/rand-worktrees/fullnode-v070 v0.7.0
   (cd ~/rand-worktrees/fullnode-v070 && RAND_BUILD_SHA=$(git rev-parse HEAD) cargo build --release --locked -p randprotocol-client)
   ~/rand-worktrees/fullnode-v070/target/release/rand --version             # rand 0.7.0
   ```

7. **Dry runs on the release inputs** (local, no network):

   ```bash
   N=~/rand-worktrees/fullnode-v080/target/release
   RAND_MSAUTH_VK=$REL/msauth-vk-production.bin DRY_RUN=1 NODE=$N/rand-node WALLET=$N/rand \
     PERP_PROVER=~/.rand-chain21/bin/perp-prover TREASURY=~/.rand-chain21/treasury.txt \
     EXPECT_NODE_VERSION=0.8.0 deploy/cut-chain21-genesis.sh                 # ends "DRY RUN — …", nothing SKIPPED
   SELFTEST=1 NODE=$N/rand-node WALLET=$N/rand deploy/cutover-fleet-chain21.sh   # "fleet rehearsal (chain 21): N passed, 0 failed"
   SELFTEST=1 deploy/cut-chain21-genesis.sh
   ```

8. **The fleet's disk** (chain 20's lesson: syd1 came up `disk_low` and held the wait at 25/26).
   With the user's go, per host: `deploy/retire-chain-dirs.sh <ip> --dry-run`, then without
   `--dry-run` where chains ≤ 19 still sit. It keeps only the CURRENT dir — chain 20's, which is the
   rollback target, so run it **before** the cut, never in the first day after it.

## b. The chain-20 snapshot

As chain 20's cut did from chain 19 (`AGENTS.md`, "Chain 20 — LIVE"): the bridge stops first, then
the snapshot and the balances scan, with chain 20 still committing.

1. **Bridge stop** (the bridge session owns the daemons; `deploy/chain21-bridge-steps.md` is a
   DRAFT from chain 20's for it to review, step 1): relayer on
   `rand-relayer-1` (`ssh -i ~/.ssh/rand_guardian_ed25519 root@203.0.113.28`) and the six guardian daemons stopped, nothing in flight (each endpoint's
   `sequence()` = the relayer's `next_sequence`; chain 20's `burn_sequence` = the relayer's cursor).
   `cutover-fleet-chain21.sh switch` refuses a guardian host whose `rand-guardian` is still active.

2. **The tunnel** to an archive's RPC (the public RPC is Cloudflare and 403s urllib). obs1
   (`203.0.113.29`, validator+archive, no pruning) is the script's default:

   ```bash
   ssh -N -L 8545:127.0.0.1:8545 root@203.0.113.29        # in its own terminal; keep it open
   ```

   Fallback: rand-archive-2 (`203.0.113.38`, fra1, full history) — its tunnel timed out during
   chain 20's balances scan; node A (sgp1) worked then but now runs `--prune-history 24h`, so do not
   rely on it for a scan from leaf 0. The script refuses a dead tunnel or one that is not chain 20's.

3. **Snapshot** (local; reads chain 20 and the four endpoints' public RPCs — custody and sequences):

   ```bash
   cd ~/rand-worktrees/fullnode-chain21-cutover
   CHAIN20_RPC=http://127.0.0.1:8545 deploy/cut-chain21-genesis.sh snapshot ~/.rand-chain21/snapshot
   ```

   It writes `~/.rand-chain21/snapshot/chain20-state.json` (refuses if one is already there — a
   snapshot is taken once). Take it with the default `EMITTER_*` (chain 20's endpoints).

4. **Balances** (chain 20's own `rand`, v0.7.0 built from tag 806ed349; rescans every wallet from leaf 0):

   ```bash
   ls -l ~/.rand-chain17/alloc-wallets/relayer.key.json     # the link must resolve (it went missing once)
   CHAIN20_RPC=http://127.0.0.1:8545 WALLET=~/rand-worktrees/fullnode-v070/target/release/rand \
     deploy/cut-chain21-genesis.sh balances ~/.rand-chain21/snapshot
   ```

   It writes `~/.rand-chain21/snapshot/balances.json` and `~/.rand-chain21/alloc-rand.txt` (the RAND
   carry list), and lists any chain-20 genesis alloc no scanned wallet covers (the cut refuses while
   that list is non-empty). Then **write `~/.rand-chain21/zusd-carry.txt`** (`<label> rand1… <zUSD>`
   per line; Σ must equal the snapshot's locked total — chain 20 carried anish 10 and
   owner-89DS-4Q4X-HXSX-MBYW 89; check what moved since) and fill the record's `carries:` and
   `drops:` from the scan's output.

## c. The cut (the real invocation)

Chain 20 is **still running**: the cut reads only the snapshot directory and contacts nothing.
Then section d, then `push`, then the user's go and `stop`. The cut stamps the genesis time, so
have the second operator standing by first, and keep the gap from the cut to `start` to minutes.

```bash
cd ~/rand-worktrees/fullnode-chain21-cutover
N=~/rand-worktrees/fullnode-v080/target/release
REL=~/.rand-chain21/release-v0.8.0
CUT_RECORD=deploy/cut-records/chain21.record \
CHAIN20_SNAPSHOT=~/.rand-chain21/snapshot \
NODE=$N/rand-node \
WALLET=$N/rand \
EXPECT_NODE_VERSION=0.8.0 \
PERP_PROVER=~/.rand-chain21/bin/perp-prover \
PERP_IMAGE=~/Github/randprotocol/durian.market/artifacts/perp-engine.image.bin \
TREASURY=~/.rand-chain21/treasury.txt \
RAND_MSAUTH_VK=$REL/msauth-vk-production.bin \
MAX_PROOF_BYTES=6291456 MAX_BLOCK_BYTES=19922944 \
ALLOC_ADDRESSES=~/.rand-chain21/alloc-rand.txt \
ZUSD_CARRY=~/.rand-chain21/zusd-carry.txt \
FEE_RECIPIENT_FILE=~/.rand-chain20/fee-recipient-address.txt \
VALIDATORS_TSV=~/.rand-chain14/public/validators.tsv \
REGISTRATIONS=~/.rand-chain15/registrations \
  deploy/cut-chain21-genesis.sh
echo $?
```

| input | value | status |
|---|---|---|
| `CUT_RECORD` | `deploy/cut-records/chain21.record` | **needs the user**: `drops:`, `second-operator:` (and the TODOs inside `carries:`/`clients:`) are TODO(user); the cut refuses while a field starts with TODO. Before the cut `grep -n TODO deploy/cut-records/chain21.record` should print only the `genesis-hash`/`treasury-id`/`perps-genesis-root`/`second-hash` lines the cut and the second operator fill. Publish it before the cut. |
| `CHAIN20_SNAPSHOT` | `~/.rand-chain21/snapshot` | **needs the user**: made by `snapshot` + `balances` (section b), which contact obs1 and the endpoints |
| `NODE` | v0.8.0 `rand-node`, macOS build of the tag | local, to build (a.6) — the release asset is Linux |
| `WALLET` | v0.8.0 `rand`, same build | local, to build (a.6) |
| `EXPECT_NODE_VERSION` | `0.8.0` | local-known (the coordinator, 2026-10-12) |
| `PERP_PROVER` | `~/.rand-chain21/bin/perp-prover` | local-known: durian 310ae76, sha256 55ed4926…, provenance file beside it; genesis root da0e3a53…9846 |
| `PERP_IMAGE` | `~/Github/randprotocol/durian.market/artifacts/perp-engine.image.bin` (the script's default) | local-known; `rand perp image-hc` must print `f286a611…1573` (`EXPECT_ENGINE_HC`, the default) |
| `TREASURY` | `~/.rand-chain21/treasury.txt` | local-known: 3 signers, threshold 2, balance 100000 (public keys only) |
| `RAND_MSAUTH_VK` | `$REL/msauth-vk-production.bin` | local after a.4 (the verified release blob; 68facb06…cd30, 23 754 B). The real cut runs no loopback node, so it is for any `rand-node run` the session starts (a binary outside `target/` has no dev fallback) and for the dry run |
| `MAX_PROOF_BYTES` / `MAX_BLOCK_BYTES` | `6291456` / `19922944` | local-known: the script's defaults, asserted; set explicitly here only to make them visible. `GAS_DYNAMIC` follows at 9961472 |
| `ALLOC_ADDRESSES` | `~/.rand-chain21/alloc-rand.txt` | default; written by `balances` |
| `ZUSD_CARRY` | `~/.rand-chain21/zusd-carry.txt` | **needs the user**: the holders and amounts (not on disk yet) |
| `FEE_RECIPIENT_FILE` | `~/.rand-chain20/fee-recipient-address.txt` | local-known (default; fingerprint must be 89DS-4Q4X-HXSX-MBYW) |
| `VALIDATORS_TSV`, `REGISTRATIONS` | `~/.rand-chain14/public/validators.tsv`, `~/.rand-chain15/registrations` | local-known (defaults) |
| `EXPECT_ENGINE_HC`, `EXPECT_HC_AUTH_MULTISIG` | f286a611…, 9705f8e2…8247 | the script's decided defaults; any other value is refused |
| `CHAIN20_GENESIS` / `_HASH` / `_SHA256`, `EMITTER_2..5`, `BONDED`, `GENESIS_NAMES`, `STAKE_RAND` | the script's defaults (chain 20's) | local-known; leave them |
| `MIN_INBOUND_*` | `auto` (from the snapshot) | default; explicit floors only if a lock was in flight at the snapshot |
| `RELAYER_DONE_DIR` | a copy of `rand-relayer-1`'s `done/` | optional cross-check; **needs the user** (`scp -r -i ~/.ssh/rand_guardian_ed25519 root@203.0.113.28:<relayer data>/done …`) |
| `REWARDS_DROPPED_OK`, `PENDING_OK`, `UNCOVERED_ALLOCS_OK`, `NODE_VERSION_OK` | unset | set one only knowingly, after the cut refuses and says why; whatever it drops goes in `drops:` |

The cut prints the genesis file (`deploy/genesis-chain21.json`), its **genesis hash**, `TREASURY
ID <id>`, `PERPS GENESIS ROOT <hex>`, and the reminder that `push` refuses without `second-hash`.
Copy the three values into the record's `genesis-hash:`, `treasury-id:` and `perps-genesis-root:`.

## d. The second operator's hash check

**Getting the file to them.** The author sends `deploy/genesis-chain21.json` over a channel the
second operator already trusts for the author (an scp to their machine, a USB stick handed over,
or an attachment to a signed message), and reads the cut's printed sha256 to them over a second,
separate channel (a call, a chat) — the file and its hash never travel together. Nothing is
committed or pushed for this.

The second operator, on **their own machine**, with the v0.8.0 release `rand-node` (verified as in
a.4; a Linux host can use the release binary directly):

```bash
sha256sum genesis-chain21.json                     # the file they were given; equal to the cut's printed sha256
rand-node --version                                # rand-node 0.8.0
rand-node init --datadir "$(mktemp -d)/p" --genesis genesis-chain21.json | grep -o 'genesis [0-9a-f]*'
```

They send the hash they got back; it goes into `deploy/cut-records/chain21.record` as
`second-hash: <hash>` (with their name/machine in `second-operator:`), and **the record is
published again** with that line (it was first published before the cut, without it).
`cutover-fleet-chain21.sh push`, `stop` and `switch` each compare it with the hash this machine
derives (`require_second_rebuild`) and refuse on a blank or a mismatch. Chain 20 waived this
(one operator holds every key and host); `SECOND_REBUILD_WAIVED=1` still exists for that, prints
what it leaves unchecked and appends `second-rebuild-waived: …` to the record — **a user decision,
not a default**. Note what the check proves here: that the file's hash is what an independent build
derives; it does not re-cut the file (fresh randomness and a timestamp make every cut unique).

## e. The fleet and the roll order

**Hosts** (configuration/ snapshot of 2026-10-06, `fleet/inventory.tsv`; all 26 are validators,
quorum 18):

| group | hosts | shape |
|---|---|---|
| bootstraps, started first | C 203.0.113.23, D 203.0.113.25 | nodes.env, root unit, datadir `/root/data-rand-node-<x>-6210cf07` |
| nodes.env (18 more) | A 203.0.113.15, B 203.0.113.31, E 203.0.113.33, F 203.0.113.21, lon1 203.0.113.14, sfo3 203.0.113.10, tor1 203.0.113.18, blr1 203.0.113.27, syd1 203.0.113.32, atl1 203.0.113.24, ams3 203.0.113.17, nyc1 203.0.113.34, nyc2 203.0.113.12, sfo2 203.0.113.16, mkc1 203.0.113.37, mem1 203.0.113.30, obs1 203.0.113.29 (archive), archive2 203.0.113.38 (archive) | same; `-6210cf07` → `-<chain-21 prefix>` |
| guardian hosts | g1 203.0.113.11, g2 203.0.113.13, g3 203.0.113.26, g4 203.0.113.22, g5 203.0.113.40, g6 203.0.113.19 (`~/.rand-bridge/mainnet-set1/hosts.txt`, ssh key `~/.ssh/rand_guardian_ed25519`) | user `randnode`, drop-in `chain20.conf`/`data-20` → `chain21.conf`/`data-21` |

`deploy/nodes.env` in this tree matches `configuration/fleet/nodes.env`, and the guardian list
matches `configuration/fleet/guardian-hosts.txt`. Re-check against the live fleet in `preflight`
(the snapshot is from 2026-10-06; the fleet runs v0.7.0, git_sha 806ed349 — read with `status` on
2026-10-12; v0.7.0 was never rolled).

**Order.** The genesis goes to every host while chain 20 runs (`push`); then a cut is all-stop,
all-start: every host stops (only once all 26 pass the gate), every host switches, then C and D
start first and the other 24 after them. The compact-blocks rule "observers
and archives before validators" is for a same-chain flag-day roll; it does not apply here — there
is no observer-only node (obs1 and archive2 are validators too), nothing runs mixed, and v0.8.0
(which carries compact blocks) refuses chain 20 anyway. The compact-blocks flag day is therefore
absorbed by this cut. Non-validator nodes (the durian chain-20 RPC node `rand-chain20.service`, the
randbridge web/status/tunnel units on obs1, randscan on E, the provers on A and archive2) are NOT
handled by the cutover script: see section f.

**Invocation** (each line alone, `echo $?` after each; `R=…` lines are environment shorthand):

```bash
cd ~/rand-worktrees/fullnode-chain21-cutover
REL=~/.rand-chain21/release-v0.8.0; OLDREL=~/.rand-chain21/release-v0.7.0
LN=~/rand-worktrees/fullnode-v080/target/release/rand-node
G=deploy/genesis-chain21.json

# 0. a dry run of every phase (prints every remote command; contacts nothing)
DRY_RUN=1 RELEASE_SUMS=$REL/SHA256SUMS OLD_RELEASE_SUMS=$OLDREL/SHA256SUMS LOCAL_NODE=$LN deploy/cutover-fleet-chain21.sh switch $G
# 1. read-only, chain 20 running: v0.7.0 installed (sha256 and rand_getVersion 0.7.0/806ed349), chain 20 served, healthy, disk
OLD_RELEASE_SUMS=$OLDREL/SHA256SUMS deploy/cutover-fleet-chain21.sh preflight
# 2. chain 20 running: each host fetches rand-node, rand, msauth-vk-production.bin from the release,
#    checks all three against the SIGNED sums, and its staged rand-node verifies the staged key
RELEASE_SUMS=$REL/SHA256SUMS deploy/cutover-fleet-chain21.sh stage
# 3. section b: bridge stop, snapshot, balances; fill the record; publish it
# 4. section c: the cut (chain 20 still running);  5. section d: second-hash, record republished
# 6. chain 20 STILL RUNNING: the genesis to every host, checked by each staged v0.8.0 binary
LOCAL_NODE=$LN RELEASE_SUMS=$REL/SHA256SUMS deploy/cutover-fleet-chain21.sh push $G
# ── the user's go ──
# 7. gated: refuses (NOTHING STOPPED) unless every host holds the staged files, the verified key and
#    the pushed genesis and the record's second-hash matches; then stops all 26 (rc 1 if one stays up)
LOCAL_NODE=$LN RELEASE_SUMS=$REL/SHA256SUMS deploy/cutover-fleet-chain21.sh stop $G
# 8. key verified by the staged binary, then binaries + key installed, key re-verified, datadirs, units
LOCAL_NODE=$LN RELEASE_SUMS=$REL/SHA256SUMS OLD_RELEASE_SUMS=$OLDREL/SHA256SUMS deploy/cutover-fleet-chain21.sh switch $G
# 9. every host's installed key re-verified (refuses the whole start otherwise); C, D, then 24;
#    a host that does not come up is named, rc 1, and the marker is kept so start can be re-run
deploy/cutover-fleet-chain21.sh start
# 10. until 26/26 serve chain 21, healthy, msauth_key loaded, and C commits past height 2
LOCAL_NODE=$LN deploy/cutover-fleet-chain21.sh wait $G
deploy/cutover-fleet-chain21.sh status
```

The script refuses `stage`/`push`/`stop`/`switch` without the signed sums, a genesis that is not
chain 21's with `hc_auth_multisig` 9705f8e2… and 6/19 MiB, a `push`/`stop`/`switch` without the
matching `second-hash`, a `stop` before every host passes its gate, a `switch` on a running node or
an active `rand-guardian`, and a `start` without the marker a full `switch` writes.

**A failed switch** names the hosts; fix them and re-run `switch`, or roll the fleet back: the fleet
is already stopped (`halt` only if a node somehow runs), then `rollback` → `start` → `wait20`, then
restart the bridge on chain 20 (§g step 4). `rollback` restores the hosts that switched and leaves
the rest alone. **A re-cut after a switch** (a second genesis) needs the rollback first — `halt`,
`rollback`, `start`, `wait20` — and then `push`, `stop`, `switch` of the new file; `switch` refuses a
unit or drop-in that already names another chain-21 genesis.

## f. After launch

1. **check-limits against the first node**, before the first bundle and the first perps state
   proof (tunnel to C, D or obs1 as in b.2, on the chain-21 node):

   ```bash
   NODE=$N/rand-node deploy/cut-chain21-genesis.sh check-limits http://127.0.0.1:8545 deploy/genesis-chain21.json
   ```

   It reads back every carried value, `fee_rules` {burn_base, burn_floor}, `base_fees_burned` "0",
   `perps` and `rand_getPerps` (engine_hc, genesis_root, proved_height 0), `multisig` and the treasury
   (`rand_getMultisig <TREASURY ID>`), `hc_auth_multisig` (rand_getLimits and rand_status) and the
   6/19 MiB limits. If a bundle landed first: `BASE_FEES_BURNED_ANY=1`.

2. **The 50 zUSD treasury deposit** (the user's decision; zUSD cannot be seeded at genesis): from
   the wallet holding the user's zUSD, with the v0.8.0 `rand`, after a sync:

   ```bash
   rand --rpc <chain-21 RPC> --key <the user's wallet key> multisig deposit <TREASURY ID> 50 --asset 1
   curl -s -X POST <chain-21 RPC> -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"rand_getMultisig","params":["<TREASURY ID>"]}'   # 50 zUSD beside 100 000 RAND
   ```

3. **Perps checks** (docs/perps.md): `rand_getPerps` shows BTC-PERP, the pinned `engine_hc`,
   `proved_height` 0 → rising; start the perp-view service (`perp-prover serve`) and a prover
   (`perp-prover run`, ~22 GB of RAM a production proof — no new droplet can be made, so it runs on
   the 48 GB Mac or on an existing host with that much RAM; a withdrawal is paid only when proofs reach its
   block); NTP on every validator (`timedatectl show -p NTPSynchronized` = yes on all 26); a small
   zUSD deposit, open, close and withdraw on durian.market once the prover keeps up.

4. **The bridge** (the chain-21 bridge steps): guardians' `chain_id = 21` and `rand.json` cursor at
   the snapshot's `burn_sequence`, the relayer's 0.6.8 → v0.8.0 `rand` swap (rand.pre-c21 kept; the bridge session confirms the relayer works with v0.8.0 before the cut), start, `rand-bridge-audit`, one
   1 USDT round trip.

5. **Clients** — the apps' **default RPC host still points at chain 20**:
   - re-pin the clients repo to v0.8.0 and release the chain-21 wallets (the msauth-signing branch
     `feat/msauth-signing` vendors a1785c9; `release/chain20` stays for chain 20 until it is
     retired), switch each app's default RPC host to chain 21's at release;
   - deploy randscan main 60d5612 (migration 014) and randbridge.org 9b395f8 against chain 21;
   - randprotocol.org: the `/api/rpc` relay allowlist commits for v0.8.0 are not on the sale
     droplet yet; the public docs still say v0.6.8 (16 locales);
   - durian.market's chain RPC node (`rand-chain20.service`) and the `rand-prover-member` units on A
     and archive2 need the v0.8.0 `rand-node`/`rand-prover` and, for any `rand-node`, the msauth
     blob beside it — the cutover script installs neither;
   - refresh `~/Github/randprotocol/configuration/` (collect-live.sh, fetch-files.sh) and its
     encrypted archive: a stale snapshot respawns chain 20.

6. **One day later**: retire chain 20's dirs (`deploy/retire-chain-dirs.sh`), remove the
   `*.pre-c21` backups, record the launch in AGENTS.md and the CHANGELOG.

## g. Rollback

Possible only **before** anything is minted, released or paid out on chain 21 — after that, going
back loses it. v0.8.0 cannot run chain 20 and a chain-21 database cannot be rolled back across
constraint set 9, so rollback is "chain 20 again from where it stopped", never "chain 21 on v0.7.0".
In this order (each line alone, `echo $?`):

1. **The bridge stops FIRST** (`deploy/chain21-bridge-steps.md`, rollback step 1): the relayer on
   `rand-relayer-1` (`ssh -i ~/.ssh/rand_guardian_ed25519 root@203.0.113.28`) and all eight guardians. The fleet's `rollback` refuses a guardian host whose
   `rand-guardian` is still active.
2. **Nothing happened on chain 21?** With chain 21 still up (read-only):

   ```bash
   deploy/cutover-fleet-chain21.sh quiet deploy/genesis-chain21.json
   ```

   It reads `rand_getBridgeState` on C and D and refuses unless `burn_sequence` and Σ `locked` over
   every backing are still the genesis values (no burn emitted, no deposit minted). Also check the
   relayer's `done/` holds nothing newer than the snapshot, and the treasury: `rand_getMultisig
   <TREASURY ID>` still 100 000 RAND and no zUSD deposited. If anything moved, the rollback loses it
   — the user decides.

   **If chain 21 never answered** (no node came up, or none is up now), `quiet` cannot read it and
   refuses ("unreadable"). Then check `status` and the `wait` output: if no host ever reported a
   chain-21 height above 0, no block committed and nothing can have been minted or burned there;
   record that in the cut record and go on with step 3 on the user's word. If some host did report a
   height and none answers now, bring one up (`start` on C) and run `quiet` before halting again.
3. **The fleet:**

   ```bash
   deploy/cutover-fleet-chain21.sh halt                                       # stops chain 21 (refuses a host running chain 20)
   OLD_RELEASE_SUMS=$OLDREL/SHA256SUMS deploy/cutover-fleet-chain21.sh rollback    # units/drop-ins + v0.7.0 binaries, sha-checked
   deploy/cutover-fleet-chain21.sh start                                      # the rollback marker licenses it; no key check
   deploy/cutover-fleet-chain21.sh wait20                                     # all 26 serve chain 20, healthy, C's height MOVING
   ```

   `wait20` ends with "CHAIN 20 COMMITTING AGAIN" only when every host serves chain 20's genesis
   `6210cf07…` and C's height rises between two polls; `status` alone does not show that.
4. **The bridge back on chain 20** (`deploy/chain21-bridge-steps.md`, rollback step 4): the
   guardians' and the relayer's chain-20 config and cursors, the relayer's 0.6.8 `rand` from
   `rand.pre-c21` (sha-checked against 155dfe66…ee2d), then the daemons started; the cut record gets a line saying why.

Chain 20 resumes at the height it stopped at; its data dirs were never touched. The msauth blob
stays in `/usr/local/bin` (v0.7.0 ignores it). By hand, if `rollback` itself cannot run: the
script's header lists the files per host shape.

## What did not carry over cleanly from the chain-20 tooling

- The chain-20 cutover took the signed `SHA256SUMS` optionally (and staged on the operator's sha256
  word otherwise); chain 21's **requires** it and reads every pin from it, the blob's included.
- The old-side binary pins (`OLD_SHA`/`OLD_SHA_WALLET`) have no default: this tree has no v0.7.0
  `SHA256SUMS`; they come from v0.7.0's signed file (a.5). The old version is one variable,
  `OLD_VERSION` (0.7.0) with `OLD_GIT_SHA` (806ed349…). An earlier draft of this tooling assumed
  v0.7.1 (tagged, never rolled); the fleet's `status` corrected it.
- Chain 20's cutover had no SELFTEST and no DRY_RUN; its rehearsal was a separate script. Chain 21's
  has `DRY_RUN=1` built in and `SELFTEST=1` runs `deploy/rehearse-cutover-fleet-chain21.sh`.
- **The phase order changed.** Chain 20 stopped the fleet, then cut, then waited for the second
  hash and pushed, all during the downtime, and its `stop` checked nothing and ignored a host that
  failed to stop. Chain 21 cuts and pushes with chain 20 running, and `stop <genesis>` is gated.
  `halt` (an ungated stop that refuses a host running chain 20), `quiet` and `wait20` are new, for
  the rollback; `start` now fails and keeps its marker when a host does not come up; chain 20's
  `wait` exits silently on the first node that does not answer (left as is there; fixed here).
- `deploy/chain21-bridge-steps.md` is a DRAFT written here from chain 20's; the bridge session
  owns it and must review it.
- The cut script's default `CUT_RECORD` is `~/.rand-chain21/cut-record.txt`; the cutover's is the
  committed `deploy/cut-records/chain21.record`. Pass the same path to both (this runbook does).
- `deploy/roll-all.sh` and `configuration/scripts/respawn-*.sh` still describe chain 20 / v0.7.0
  hosts; a respawn after the cut needs the v0.8.0 pins and the blob.
