# Testnet: chain id 5 (SHRUGG, confidential computation, zkVM constraint set 4)

> **Constraint set 5 belongs to the next chain, not this one.** A build from `main` today vendors
> `circuits/research` at milestone 4.2: the production FRI profile is back to 80 queries, a proof
> declares a `keccak_log_height` and a `mem_log_height`, and the verifier key is four-keyed. None
> of that round-trips against a chain-5 proof in either direction, so such a build cannot join the
> fleet below and the fleet's blocks cannot be replayed by it — see `docs/confidential.md`'s
> "Constraint set 5" section. It arrives the same way every constraint set before it did: by
> cutting a new chain id. Note also that `MAX_PROOF_BYTES` is 2 MiB on constraint set 5 (1 MiB
> rejects every 80-query proof) while `MAX_BLOCK_BYTES` stays 4 MiB, which is about three shielded
> transfers per block (`docs/block-space.md` §5).

> **The fleet below is an account chain and is unchanged by the shielded pool.** Phase S1 (the
> note ledger, bundles, the shielded wallet) is a hard fork: a node built from this branch cannot
> join chain 5, and chain 5's blocks cannot be replayed by it. The fleet moves when the operator
> decides to, by cutting a new chain id from a shielded genesis — see "Cutting a shielded genesis"
> at the end of this file. Until then, run the shielded build on a separate chain id, or keep the
> pinned account build (`deploy/run-a-pinned.sh`, `.update-pin`) for the fleet.

Test keys only; all seeds are committed on purpose so any machine can pull and run.
Genesis hash `3a82b0c7b6c4eb1eb1e1ba8a54b4306a883a57d46ccebce1e7adb7b5fd9ffa86`, 100 SHRUGG per validator, **faucet enabled**, **confidential computation enabled** (production FRI profile, no bridge section; fleet build commit dbea18c, constraint set 4)
(`shrugg faucet [address]` mints up to 100 SHRUGG per call on any node). Quorum is 3 of 4 validators.

| node | role | where | address | peer id |
|---|---|---|---|---|
| A | validator | laptop, LAN 192.168.100.123 (NAT) | 2nRdFChBXRmKoe2sQE3ZYDzvdg53QmBZJJ9iweY7hk1v | 12D3KooWRbvv6T8iQz1jT5ijvPoo6CEGy3yRdiuxkUMJGUkTNq6P |
| B | validator | 192.168.100.79 (NAT) | ByDkxsEfDCR5DrmDufKftvcRsgvufypnZ4SgDQzJAQ7Z | 12D3KooWMUjpbd6U7c6KTjVXy3121aV6JLka47dh4ZPwGjyMV8Bf |
| C | validator | DigitalOcean 167.172.65.63 | F6rYLexPhyMmwPNqbEmyyp5FiTmtQqDgZyqScUqYY4F6 | 12D3KooWBKYD5bBRczEhzYQrN4jgfgaoGXb6PzbfdjtTjiy1SA5g |
| D | validator | DigitalOcean 178.128.91.236 | 5tMgLSzXL8keU1vg2wtGEXRJkmfBK6GzhjNjxrCFgCaj | 12D3KooWPrdUXsVXsD3RqaV4otq35awpJgMonSfdu3u8gtq5iUYq |
| E | observer | DigitalOcean 188.166.235.187 | CxeG7vJaxUoKBZZe8U8LGXohH2FvcCbE47AufK6Mp2jf | 12D3KooWR1nihpYk6vvdRYuq2WMGUtzDiwygytTXZJszdSnaVmDM |
| F | observer | DigitalOcean 157.245.156.41 | DcuuZrzDSJedhFnynLFchNfYmW4UKiZT2nEKbcs2ojmJ | 12D3KooWJwsFwi9CawJrPyA7ZBT5Q6mYWmctNvLRt3SuS7SdyU6j |

C and D have public IPs and act as bootstrap nodes; A and B are behind NAT and dial out to them
(`deploy/run-a.sh`, `deploy/run-b.sh`). Full multiaddrs are in `deploy/nodes.env`.

Droplets: `deploy/push-to-vps.sh <ip> <letter> "<bootstrap multiaddrs>" [validator|observer]` provisions from scratch;
`deploy/rebuild-vps.sh <ip>` rebuilds on new commits and restarts (data kept). Service name: `shrugg-node`.

On 192.168.100.79:
```bash
git pull && ./deploy/run-b.sh
shrugg --key deploy/node-b.key.json balance
shrugg faucet ByDkxsEfDCR5DrmDufKftvcRsgvufypnZ4SgDQzJAQ7Z        # 100 SHRUGG from the testnet faucet
shrugg --key deploy/node-b.key.json send 2nRdFChBXRmKoe2sQE3ZYDzvdg53QmBZJJ9iweY7hk1v 1.5
```

Live on chain 4 (2026-09-10): program `private_payment(1000)` deployed by A in block 10, id
`675adeea7e4242d8dc48bf56faedb7bea14a4f832d7c8a973f942fa7dd850065`; first confidential call in block 19
(tx `d4c75efbe141567eae72d5f639a1d444eb074d8b58a6592d95e01cd39a2364e3`), outputs `[1, 0, 25, 0, 0, 0, 0, 0]`,
25 units paid to B. Laptop proving 21 s; droplet verifier-key warm 7 s (one-time, background); receipt and
balance identical on A, C, D, E, F. Further calls the same evening: a below-threshold run (block 78, outputs all
zero, no effect, B unchanged) and a call proved and submitted entirely on observer E (79 s to prove on 2 vCPUs;
block 105, 200 units to B). `shrugg-node verify --mode full` on F re-verified all 109 blocks including the three
proofs in 6.9 s. B ends at 100.000000225 SHRUGG on every node.

Confidential call from the laptop (private inputs never leave it):
```bash
shrugg --key deploy/node-a.key.json program build --guest private_payment --arg 1000 --out pp.json
shrugg --key deploy/node-a.key.json program deploy pp.json
shrugg --key deploy/node-a.key.json call <program-id> --input 400 --input 250 --input 300 --input 75 --to <B address>
```

Chain 5 (2026-09-11, cut by the Air's session, fleet joined 09:04 UTC): first confidential call on the
constraint-set-4 zkVM committed in block 37 (prove 7.4 s on the laptop, proof 435 KB, down from 21 s / 878 KB).
Rule for this fleet: every node runs the pinned build commit (`dbea18c`); a zkVM constraint change is a fork,
announced by the zkVM session first, and moves the whole fleet at once with a fresh genesis. Observer E also
hosts the RandScan explorer, which re-indexes itself on a chain id change.

History: chain 1 (2 validators, SESH) and chain 2 (4 validators + 2 observers, SESH) ran on 2026-09-09;
chain 3 followed the SESH -> SHRUGG rename and added the faucet; chain 4 (2026-09-10) added confidential
computation on constraint set 2 and ended at 31,952 blocks when the fleet moved to constraint set 4.

## Cutting a shielded genesis

A shielded chain has no per-validator allocation: value exists only as a note someone holds the
spend key for, so `--alloc` takes a **shielded address** and creates one deposit note. The
addresses come from wallet keys, which are not node keys.

```bash
# one spend key per wallet that should start with funds (wallets/ is gitignored — never commit these)
for i in 1 2 3 4 5; do shrugg --key wallets/shielded-$i.key.json keygen; done
addr() { shrugg --key wallets/shielded-$1.key.json address; }

# the genesis: four validators, five 1000-SHRUGG deposit notes, faucet on, production FRI,
# 1000-block epochs. Phase S2 makes a --validator one register entry with all three of its fields
# at once — `<key file or hex public key>,<stake in SHRUGG>,<payout shrugg1…>` — so nothing can
# pair the wrong stake or payout with the wrong key. The payout is the shielded address that
# validator's rewards and unbonded stake are withdrawn to, and it is part of the genesis hash.
# The stake must be at least 1000 SHRUGG: below the staking minimum a validator is in the
# register but in no epoch's set, which genesis refuses outright.
args=()
for i in 1 2 3 4 5; do args+=(--alloc "$(addr $i)=1000"); done
shrugg-node genesis --chain-id 6 \
  --validator "deploy/node-a.key.json,1000,$(addr 1)" \
  --validator "deploy/node-b.key.json,1000,$(addr 2)" \
  --validator "deploy/node-c.key.json,1000,$(addr 3)" \
  --validator "deploy/node-d.key.json,1000,$(addr 4)" \
  "${args[@]}" --epoch-blocks 1000 --faucet --fri-profile production \
  --out deploy/genesis-shielded.example.json
```

Note that this command reuses four of the deposit wallets as payout addresses, which is convenient
for a testnet and wrong for anything else: a payout address is public in the register from the first
block on, so on a real chain give each validator a wallet that holds nothing else.

`deploy/genesis-shielded.example.json` in this repo is exactly that file, produced by that command
(chain id 6, genesis hash `386371c4f96405a3246b2402610b3499a5eb8aff1834a7d4ca6f1548f5d5bff7`,
`hc_bundle 4a27356f379571036025a4a8661c294b0edec2b7cf7fbfd60b472b186cbd4afb`). It is an **example**:
its five deposit notes belong to spend keys that live only on the machine that cut it, so re-cut
your own rather than adopting it. Two properties make that unavoidable:

- Every deposit note carries fresh commitment randomness, so the same `--alloc` list produces a
  different genesis hash every time. A deterministic `r` would let anyone confirm a guess at a
  genesis note's owner and amount by recomputing the commitment. Cut it once, distribute the file
  byte-identically, and keep it.
- `hc_bundle` pins the bundle guest every proof on the chain is checked against. A node whose build
  assembles a different guest refuses to start and names both digests, so a zkVM constraint change
  is a fork here exactly as it is for confidential calls.

Then, on each machine, as for any chain:

```bash
shrugg-node init --datadir ./data-6 --genesis genesis-shielded.json
shrugg-node run --datadir ./data-6 --key deploy/node-a.key.json --validator \
  --block-interval-ms 1000 --bootstrap /ip4/<ip>/tcp/30303/p2p/<peer id>
```

Keep `--block-interval-ms` at 1000 or slower: a bundle proof takes about 100 seconds and its
anchor is valid for 256 blocks, so a much faster chain rejects honest transfers whose anchor
expired mid-proof (`docs/shielded.md` §5).

The wallet side, on any machine with a key file:

```bash
shrugg --key wallets/shielded-1.key.json balance      # scans the tree; ~1000 SHRUGG at genesis
shrugg --key wallets/shielded-1.key.json send "$(shrugg --key wallets/shielded-2.key.json address)" 1.5
shrugg faucet "$(shrugg --key wallets/shielded-3.key.json address)"   # if --faucet was set
```

`shrugg-node status` on any node reports `notes`, `nullifiers`, `tree_root` and `hc_bundle`
alongside the usual height and peer counts, which is the quickest check that a fresh fleet agrees.
It also reports `is_validator` (this node holds a key) and `active_validator` (that key is in the
current epoch's set) — the two are different from phase S2 on, and the second is the one that says
whether a node is producing blocks.

Adding or removing a validator on a running chain needs no new genesis (`docs/staking.md`): its
operator runs `shrugg-node register --key node-e.key.json --payout <shrugg1…>`, a wallet with 1000
SHRUGG runs `shrugg bond <its address> 1000 --registration <hex>`, and the node — started with
`--validator` all along — begins proposing at the next epoch boundary. Leaving is
`shrugg-node unbond` and, two epochs later, `shrugg-node withdraw`, which pays the stake back into a
note at the payout address. Check the quorum arithmetic first: this fleet's four validators need
three online, and three need all three.
