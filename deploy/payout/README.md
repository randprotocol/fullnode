# Payout wallets for chains 8–13 (retired at the chain-14 cut)

> **Untracked since the chain-14 preparation, and burned.** These eighteen spend keys were
> committed to a PUBLIC repository for chains 8–13 — audit v3's OPS-1, critical. `git rm --cached`
> took all eighteen `*.key.json` out of the index and `.gitignore`'s `!deploy/payout/*.key.json`
> exception is gone, so the working copies below still run chains 8–13 locally and **nothing here
> may ever be committed again**. They are published seeds: treat every note they hold as spendable
> by anyone. Chain 14's eighteen payout wallets are generated off-repo by
> `deploy/gen-chain14-keys.sh` into `$KEYDIR` (default `~/.rand-chain14`), and
> `deploy/lib/key-guard.sh`'s `refuse_in_tree_key` refuses a cut that names a key inside the tree.
> The `*.record.json` files stay tracked: a signed `ReceiverRecord` is public by construction, and
> chain 11 — the only chain that read them — is reverted.

One shielded wallet per validator, 18 in all: `<node-name>.key.json` is the spend key whose
address is that validator's `payout` in `deploy/genesis-chain8.json`. A payout address is where
that validator's block rewards and released (unbonded) stake are paid, as a note. It is register
state, so it is part of the genesis hash and cannot be changed by editing a file — only by the
validator's own `rand-node register` on a running chain.

Short shielded addresses (chain 11) made a register's `payout` a receiver id rather than an
address, so this branch also added `<node-name>.record.json` beside each key: the signed
`ReceiverRecord` that same id resolves to (`rand address --record`'s output for that key), needed
so a chain-11 genesis can register these same 18 wallets with `rand-node genesis --receiver`.

**These were test keys committed on purpose**, the same convention the node keys in `deploy/`
followed: any machine could clone the repo and run the fleet. That convention ended with chain 13.
It was defensible while the chain carried nothing but test value and no bridge; it stopped being
defensible the moment chain 14 was going to hold bridged USDT and USDC, because a published
validator seed on a bridged chain lets anyone finalize conflicting blocks. On a real chain a payout
address is public in the register from the first block on, so give each validator a wallet that
holds nothing else and whose key nobody else has — which is exactly what
`deploy/gen-chain14-keys.sh` does, outside this tree.

Chain 7 had no payout addresses at all (its genesis validator entries are `public_key` + `stake`
only — it predates phase S2), so there is nothing to carry over; every one of these was generated
fresh for chain 8 with `rand --key deploy/payout/<name>.key.json keygen`.

## Which file belongs to which validator

`a`…`f` are certain: those six are named by the key files in `deploy/`, and each one's public key
was checked to be in chain 7's 18-entry validator list before the genesis was cut (positions 0–5,
in order).

`lon1`…`mem1` are the twelve regional DigitalOcean validators, and **their names are inferred, not
verified.** No key file for them exists in this repo — they were generated on the droplets — so
their public keys were taken from chain 7's validator list, positions 6–17, and paired with the
names from `deploy/nodes.env` in the order that file lists them (`lon1 sfo3 tor1 blr1 syd1 atl1
ams3 nyc1 nyc2 sfo2 mkc1 mem1`). Nothing in this checkout can confirm that pairing: a libp2p peer
id is derived from a *secret* subkey of the node key (`derive_subkey(b"rand-p2p-identity")`), so
the peer ids in `nodes.env` cannot be recomputed from the public keys in the genesis.

Only the labels are at stake, not the chain: every validator still gets its own distinct payout
wallet either way. A validator operator who wants certainty can run
`rand-node address --key <its node key>` on the droplet and match the `public_key` prefix
against the table in `deploy/README.md`. If a name turns out to be wrong, rename the file — the
genesis is unaffected, since it stores the address, not the path.
