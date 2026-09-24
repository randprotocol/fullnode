# The deep security-and-math scan (after v0.5.5): design

**Goal (user, 2026-09-24):** once the audit fixes are in, run another scan for deep security and
math issues and fix them. **Input:** the v0.5.5 tree, the whitepapers (`../whitepapers/`), the
v3–v5 audit findings tables, the two prior in-repo reviews (`../security/*.md`), and the four
chains' bridge contracts (`../bridge`). **Output:** one severity-ordered findings document
(`../security/fullnode-deep-scan-2026-09-2x.md`), each finding verified against source with a
concrete attack or failure witness, then fixed red-first on `feat/deep-scan`, tagged v0.5.6.

## Method

Independent adversarial reviewers, one per dimension, each producing candidate findings with
file:line and a witness; an adversarial verifier per candidate re-traces it and either confirms
with a reproduction (a failing test or a script) or rejects with the reason. Only confirmed
findings are fixed. Every fix ships with the reproduction as its regression test.

## Dimensions and the questions each must answer

1. **Consensus safety** (`crates/randprotocol-core/src/consensus/`): can two honest nodes commit
   conflicting blocks under f < n/3 Byzantine validators, with the v0.5.4/v0.5.5 rules (three-chain
   commit, the lock and its not-held quorum release, durable pending blocks, the ghost-QC memory,
   the sibling bound and eviction, epoch-set changes mid-view, the proposal window)? Model each
   rule as a state machine and search for a counterexample; check every `locked_qc =` and
   `high_qc =` write against the safety argument.
2. **Consensus liveness**: after a whole-fleet restart, a partition heal, a leader schedule with
   f dead leaders, and clock drift up to the vote rule's 15 s — does a commit happen within a
   bounded number of views? The pacemaker (CH-1/B3) is the known gap; quantify it and decide
   whether a minimal fix (NewView quorum of f+1 timeouts, timeout certificates) is safe to ship
   before the redesign.
3. **Ledger arithmetic and conservation** (`crates/randprotocol-core/src/ledger/`): for every
   action, is `pool_value` conserved (issued − burned − fees − slashed = notes outstanding)?
   Every `checked_*`/`saturating_*` site: which saturations silently create or destroy value?
   Faucet budget, registration burn, token mints and burns, bridge lock/release, staking
   rewards/unbonding/slashing, the aggregation fee bucket. Overflow at `u64` and the 2^63
   guest bound.
4. **The hidden-asset guest and the zkVM** (`crates/randprotocol-zkvm/`, vendored from
   `research`): the four-slot conservation with taint, the public-input segment binding, the
   transaction binding digest, Merkle membership, nullifier derivation; the Poseidon2 constants
   provenance (ZKV-2: are the constants an RNG draw with a recorded seed, and does anything
   about soundness rest on their structure?); FRI parameters against the paper (80/8/20) and
   the proof-size cap. Any finding here goes to `research` first (vendored code is never
   patched locally except `ZkExecutor` glue).
5. **The bridge** (`crates/randprotocol-core/src/bridge/`, `ledger/bridge_*.rs`, `bridge-codec`):
   ECDSA + PQ quorum checks, guardian-set rotation, replay across chains and sets, the deposit
   blinding derivation (F1), caps (daily and rolling windows, the global cap), pause/unpause
   nonces, burn sequencing and release proofs; the endpoint contracts' `setToken`/`release`
   authority and the relayer's trust in one RPC per chain (BR-4/BRG-15 in code terms).
6. **Node and RPC** (`crates/randprotocol-node/`): admission cheap-before-expensive ordering,
   the refused-hash cache's permanence rules, mempool claims and eviction, the witness build cap,
   viewing-key registry locks, sync batch acceptance (`batch_decision`, coverage closure),
   `verify_chain` versus `apply_synced` equivalence, storage migrations (`prune_committed_qcs`,
   `META_*` reads on an older database), the disk guard.
7. **Cryptography and key handling**: Dilithium2 signature domains (every domain string
   distinct; genesis hash inclusion under domain v1), ML-KEM envelope sealing and the
   `kem_seed_at` derivation, viewing-key derivation and what a viewing key can and cannot do,
   the wallet's note-store and witness tree, key-file permissions, the CLI's TLS defaults.
8. **The paper against the code** (`../whitepapers/randprotocol.tex`, the implementation
   draft): every theorem or parameter table entry mapped to the code that realises it
   (DOC-4/PA-7); mismatches are findings for whichever side is wrong.
9. **Operations as attack surface**: the fleet's single-operator keys, the public RPC, the
   explorer's `rand_importViewingKey` slots, disk growth versus the bridge's finality, the cut
   procedure, backups.

## Process

- Nine reviewer agents (one per dimension, the most capable model, read-only, with the spec and
  the audit tables), each returning ≤ 10 candidates with witnesses.
- One verifier agent per candidate (adversarial: its job is to reject), returning CONFIRMED with
  a reproduction or REJECTED with the reason.
- Findings document written from the confirmed set; fixes planned per the v0.5.4/v0.5.5 pattern
  (waves by crate, red-first, independent review, release suite, tag).

## Not in the scan

Re-reporting anything the v3–v5 tables already close, unless the verifier finds the fix wrong.
