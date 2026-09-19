# Chain-14 bridge hardening: mint caps, a mint pause, bounded timestamps, a post-quantum co-signature

Status: decided by the user 2026-09-19 (all three items of the 18 Sep bridging-architecture review
that bear on the Rand side, relayed by the bridge session: BRG-1, BRG-7 and the recommended option C).
Target: chain 14, before any custody exists — a `bridge` genesis section cannot be changed on a running
chain without carrying custody state across a re-cut. None of this changes the deployed source-chain
endpoints, the attestation wire format or `bridge-codec`.

## 1. Why

The user's invariant is that the USDT + USDC in custody is always at least the zUSD supply. Per-backing
`locked` and `InsufficientBacking` guarantee it for **redemption**. They do not guard **minting**: a
`BridgeAttest` with a valid 5-of-6 guardian quorum mints whatever it says. Today all six mainnet
guardian keys are on one laptop, so one compromise could mint zUSD with no custody behind it and
redeem it against real custody. Three layers close that, each independent of the others.

## 2. B1 — per-backing mint cap and mint pause

- **Cap.** Genesis `tokens` section, per bridged token: `mint_cap_per_day: u64` (8-decimal units),
  applied **per backing**. Chain 14: `100_000 × 10^8` (100 000 zUSD per backing per day; seven
  backings → at most 700 000 zUSD/day in total). A day is a UTC calendar day of the **block
  timestamp** (`timestamp_ms / 86_400_000`), which B2 makes trustworthy. Each backing records
  `minted_today: u64` and `mint_day: u32`; a deposit into a new day resets the counter.
  A `BridgeAttest` whose amount would take `minted_today` past the cap is refused
  `TokenError::MintCapExceeded { cap, minted_today, amount }` — **not** a permanent refusal (it becomes
  admissible the next day). Checked in validate, cheap, before the guardian signature work; apply is
  infallible on it, including two attestations in one block. The counters are consensus state (in
  the token leaf).
- **Pause.** Genesis `bridge.pause_key`: one Dilithium2 public key (`crypto::PublicKey`). Two new
  bundle-less actions:
  - `PauseMints { nonce, signature }` — signed by the pause key over
    `b"rand-bridge-pause-1" ‖ chain_id (u64 BE) ‖ nonce (u64 BE)`. It can only **pause**.
  - `UnpauseMints { nonce, pq_signatures: Vec<PqSignature> }` — needs a **PQ guardian quorum**
    (B3's set and rules) over `b"rand-bridge-pq-unpause-1" ‖ chain_id (u64 BE) ‖ nonce (u64 BE)`.
  - One ledger counter `pause_nonce`, bumped by both; a message's nonce must equal it (no replay).
  - While paused, every `BridgeAttest` carrying a transfer is refused `BridgeError::MintsPaused`
    (not permanent). **Burns stay open** — a pause must never trap redemption. Rotations (payload 2)
    stay admissible too.
  - The pause key must be held somewhere other than the machine that holds the guardian keys.
- **RPC.** `rand_getBridgeState` gains `paused`, `pause_nonce`, `pause_key` (hex); asset rows gain
  `mint_cap_per_day`, `minted_today`, `mint_day`.

## 3. B2 — a forward bound on block timestamps

A block is invalid if `timestamp_ms > parent.timestamp_ms + MAX_TIMESTAMP_STEP_MS` or
`timestamp_ms > local_now_ms + MAX_CLOCK_DRIFT_MS` (the second is a validator's vote rule, not a
replay rule — replay of committed history uses only the first). Values: `MAX_TIMESTAMP_STEP_MS =
60_000`, `MAX_CLOCK_DRIFT_MS = 15_000`. Monotonicity (`>= parent`) already holds. The test
`consensus/tests.rs:280` ("a far-future timestamp is not a validity rule") is inverted. Closes fullnode
issue #2 / review BRG-7: a leader can no longer jump the clock to expire a rotated guardian set's
86 400 s grace window or to skip B1's day.

## 4. B3 — the Dilithium2 co-signature on every mint

Implemented exactly as `docs/superpowers/specs/2026-09-19-pq-cosignature-bridge.md` (a verbatim copy
of the bridge repo's `spec/PQ-COSIGNATURE.md` at `297b662`), in summary:
- scheme: `crystals_dilithium::dilithium2` (crate 2.0, the one the node links), deterministic;
- message `M = b"rand-bridge-pq-cosign-1" ‖ rand_chain_id (u64 BE) ‖ mu` (63 bytes), `mu` the same
  keccak digest the ECDSA quorum signs;
- genesis `bridge.pq_guardians`: n hex public keys, index-aligned with `bridge.guardians`;
- `BridgeAttest` gains a LAST field `pq_signatures: Vec<PqSignature { index: u8, signature: Vec<u8> }>`
  (inside the transaction binding); quorum `n*2/3 + 1 ..= n`, strictly increasing indices `< n`,
  exact lengths, every listed signature must verify; independent of the ECDSA signer indices;
  structural checks before any signature work; errors `PqNoQuorum`, `PqIndexOrder`,
  `PqIndexOutOfRange`, `PqBadSignatureLength`, `PqBadSignature`;
- required on every `BridgeAttest`, rotations included; a payload-2 rotation does not change the PQ
  set;
- `rand_getBridgeState.pq_guardians`; `rand bridge-mint @att --pq @pq.json --to <rand1…>`;
- conformance: the bridge repo's `vectors/pq-cosignatures.json`.

Cost order in `check_attest`: structural (both quorums) → cap and pause → ECDSA recovery → Dilithium2
verification last (each ~0.1 ms, six per mint).

## 5. Tests

B1: cap exact-hit accepted, one unit over refused, reset at the next UTC day, two attestations in one
block that together exceed it (second refused), per-backing independence; pause by the key, a
replayed pause refused, attest refused while paused, burn accepted while paused, rotation accepted
while paused, unpause by a PQ quorum, unpause by the pause key alone refused, a short PQ quorum refused.
B2: the step and drift rules, the inverted consensus test, replay of history unaffected.
B3: every vector in `pq-cosignatures.json` (accept and each negative), a mint with a valid ECDSA quorum
and no PQ signatures refused, a PQ signature from another chain id refused, the binding covers
`pq_signatures`.

## 6. Genesis for chain 14

`bridge` = bridge-06's fixed section (handoff §6) **plus** `pq_guardians` (six keys generated on the
operators' hosts by the bridge session) and `pause_key`; `tokens` = zUSD with its seven backings and
`mint_cap_per_day = 100_000 × 10^8`.
