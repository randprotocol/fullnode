# Chain-8 payout wallets

One shielded wallet per validator, 18 in all: `<node-name>.key.json` is the spend key whose
address is that validator's `payout` in `deploy/genesis-chain8.json`. A payout address is where
that validator's block rewards and released (unbonded) stake are paid, as a note. It is register
state, so it is part of the genesis hash and cannot be changed by editing a file — only by the
validator's own `shrugg-node register` on a running chain.

**These are test keys and they are committed on purpose**, the same convention the node keys in
`deploy/` follow: any machine can clone the repo and run the fleet. The seeds are public, so
anyone can spend what these wallets receive. That is acceptable here and wrong anywhere else:
on a real chain a payout address is public in the register from the first block on, so give each
validator a wallet that holds nothing else and whose key nobody else has.

Chain 7 had no payout addresses at all (its genesis validator entries are `public_key` + `stake`
only — it predates phase S2), so there is nothing to carry over; every one of these was generated
fresh for chain 8 with `shrugg --key deploy/payout/<name>.key.json keygen`.

## Which file belongs to which validator

`a`…`f` are certain: those six are named by the key files in `deploy/`, and each one's public key
was checked to be in chain 7's 18-entry validator list before the genesis was cut (positions 0–5,
in order).

`lon1`…`mem1` are the twelve regional DigitalOcean validators, and **their names are inferred, not
verified.** No key file for them exists in this repo — they were generated on the droplets — so
their public keys were taken from chain 7's validator list, positions 6–17, and paired with the
names from `deploy/nodes.env` in the order that file lists them (`lon1 sfo3 tor1 blr1 syd1 atl1
ams3 nyc1 nyc2 sfo2 mkc1 mem1`). Nothing in this checkout can confirm that pairing: a libp2p peer
id is derived from a *secret* subkey of the node key (`derive_subkey(b"shrugg-p2p-identity")`), so
the peer ids in `nodes.env` cannot be recomputed from the public keys in the genesis.

Only the labels are at stake, not the chain: every validator still gets its own distinct payout
wallet either way. A validator operator who wants certainty can run
`shrugg-node address --key <its node key>` on the droplet and match the `public_key` prefix
against the table in `deploy/README.md`. If a name turns out to be wrong, rename the file — the
genesis is unaffected, since it stores the address, not the path.
