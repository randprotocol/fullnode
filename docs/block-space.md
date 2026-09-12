# Block space and the cost of an 80-query proof

Written 2026-09-12, when the production FRI profile went back to 80 queries / blowup 8 /
20 proof-of-work bits (`docs/zkvm.md` §5). The question this answers: a proof is now over a
megabyte, so what happens to block space, throughput and chain growth, and how does that sit
next to Bitcoin, Ethereum, Solana, Monero and Zcash.

## 1. The numbers

Measured on the research crate (`docs/03-privacy.md` there), `fib` guest, one machine:

| | 27 queries (M2.2) | 80 queries (production) |
|---|---|---|
| proof, tier 10 | 435 529 bytes | 1 202 416 bytes |
| proof, tier 12 | 460 441 bytes | 1 252 338 bytes |
| keccak table present | +705 KB | +1.91 MB |
| verify, uncached, tier 12 | 809 ms | 838 ms |
| verify, warm key | ~16 ms | ~16 ms |

A shielded bundle (`bundle` guest, tier 14) is not yet measured at 80 queries; each tier above
12 adds two FRI layers, so expect **about 1.3 MB**. Everything else in a transfer is small: two
nullifiers and two commitments (128 bytes), two envelopes (ML-KEM-768 ciphertext 1 088 bytes plus
the sealed note, about 1.4 KB each), the fee and burn fields, the 47-word digest preimage. Call
a transfer **1.3 MB, 99.7 % of it proof**.

The node's caps (`crates/shrugg-core/src/gas.rs`):

| cap | value | effect at 80 queries |
|---|---|---|
| `MAX_PROOF_BYTES` | 1 MiB today, **2 MiB at integration** | 1 MiB rejects every production proof |
| `MAX_BLOCK_BYTES` | 4 MiB | **3 transfers per block** (9 at 27 queries) |
| `MAX_BLOCK_TXS` | 2 000 | never reached |
| block interval (chain 5) | ~2 s | ~1.5 transfers/s |

So the answer to "does block space explode" is: no, the block cap is fixed, so a block cannot
grow; **throughput collapses instead**, to three shielded transfers per block, and a chain that
runs full grows by 4 MiB every 2 s, about 170 GB per day. That is the trade the 80-query ruling
bought: ~86 proven bits of soundness instead of ~42, at 2.75× the bytes.

## 2. Next to the other chains

Approximate, mid-2025 figures for the others; a "transfer" is the chain's ordinary payment,
which for the two privacy chains is a shielded 2-in-2-out.

| chain | block cap | block time | bytes per transfer | transfers per block | max growth per day | chain today |
|---|---|---|---|---|---|---|
| Bitcoin | 4 MB weight (1–2 MB typical) | 600 s | ~250 B (SegWit 2-in-2-out ~210 vB) | ~4 000–8 000 | ~0.6 GB | ~650 GB |
| Ethereum L1 | gas cap (45 M), no byte cap; ~100–150 KB typical + up to 9 × 128 KB blobs | 12 s | ~110 B (plain transfer) | ~200–800 | ~1–2 GB execution + ~5–8 GB blobs (pruned after 18 days) | ~1.2 TB pruned full node, ~20 TB archive |
| Solana | ~48 M compute units; a few MB of shreds | 0.4 s | ≤ 1 232 B (packet cap) | ~1 000–2 000 non-vote | multiple TB per year; validators keep a window, archives keep all | hundreds of TB unpruned |
| Monero | dynamic; 300 KB penalty-free floor, median × 2 | 120 s | ~2.2 KB (RingCT, 16-ring) | ~140 at the floor | ~0.2 GB at the floor | ~230 GB |
| Zcash | 2 MB | 75 s | ~2.7 KB Sapling, ~3–5 KB Orchard | ~400–700 | ~2.3 GB | ~300 GB |
| **SHRUGG, 27 queries** | 4 MiB | ~2 s | ~450 KB | ~9 | ~170 GB | testnet |
| **SHRUGG, 80 queries** | 4 MiB | ~2 s | **~1.3 MB** | **~3** | ~170 GB | testnet |

Two things stand out. Per transfer, a SHRUGG bundle is 300–600× a Zcash or Monero shielded
transaction and about 5 000× a Bitcoin payment. Per block, SHRUGG's 4 MiB every 2 s is already
the most bandwidth-hungry row in the table except Solana; only the tiny transfer count keeps it
from being obvious.

Why so large: Zcash Orchard and Monero use elliptic-curve proofs (Halo 2, CLSAG/Bulletproofs+)
that are a few hundred bytes to a few KB and take seconds to make. A STARK over a 26-column
public-value zkVM trace with 2 600-column tables is a different object: transparent, hash-based,
post-quantum, but its proof is dozens of Merkle paths per query. 80 queries × thousands of
columns × 8 bytes is where the megabyte comes from (`docs/03-privacy.md` in the research crate
works the arithmetic).

## 3. What the fee schedule does and does not price

Fees are flat floors (`docs/fees.md`): 0.001 SHRUGG per bundle regardless of size, because a
validator's cost is one nearly constant STARK verification. That was true at 27 queries and
remains true at 80: verification moved from 809 ms to 838 ms uncached, 16 ms warm. The floor
prices **verification**, not **bytes**.

Bytes are the scarce thing now. Three slots per block with a flat 0.001 SHRUGG floor and a
first-come mempool means demand above 1.5 transfers per second is rationed by arrival order,
not price. Before mainnet the mempool has to order candidates by fee above the floor. That is a
fee market without gas: the unit is a bundle, the price is whatever the sender attaches, and the
block picks the top three. Nothing in the proof system changes; `candidates_within` in
`crates/shrugg-node/src/node.rs` changes its sort key.

## 4. How the number comes down

In the order they are worth doing:

1. **Do not store proofs forever.** A proof is not part of the state root
   (`blake3("shrugg-state-2" || tree || nullifiers || validators || programs)`); only the
   commitments, nullifiers and anchors it authorised are. A node that has verified a block and
   seen it finalised can drop the proof bytes and keep the ~3 KB of public fields per transfer.
   Chain growth then falls from ~1.3 MB to ~3 KB per transfer, into Zcash's range, while
   bandwidth stays where it is. Syncing nodes then trust finality signatures for old blocks, as
   Ethereum light clients and Mina do; a node that wants to re-verify history keeps the proofs.
2. **Aggregate at the block.** One proof that verifies N bundle proofs (a recursion guest running
   the verifier in the zkVM) makes the block carry one ~1.3 MB proof instead of N. That is the
   standard STARK-chain answer and the largest piece of work on this list; it is what would move
   throughput from 3 to hundreds per block without touching the cap.
3. **Wrap the STARK in a small SNARK.** A Groth16 or Plonk wrapper over the STARK verifier gives a
   proof of a few hundred bytes per bundle at the cost of a trusted setup and a slower, less
   post-quantum final step. Zcash-sized transfers, but the sender proves for minutes, not
   100 s.
4. **Raise the block cap.** Cheapest, and only bandwidth pays: 16 MiB blocks at 2 s is 8 MB/s
   sustained on every validator link, which the droplet fleet can carry and a home node cannot.
   A cap is a ceiling, not a target; raising it changes nothing until blocks are full.

Not on the list: cutting queries back. 27 queries met the conjectured 100-bit target and left
~42 proven bits; the ruling on 2026-09-12 was that proven bits are what a value-bearing pool
runs on (`docs/zkvm.md` §5).

## 5. Practical consequences today

- Integration of the 80-query research crate raises `MAX_PROOF_BYTES` to 2 MiB; the 4 MiB
  block cap stays. Chain 6 will admit three transfers per block.
- The testnet fleet's links carry 4 MiB / 2 s comfortably. Disk is the constraint: a node that
  ran full blocks for a week would write ~1.2 TB. The fleet's ≥ 20 GB free-space rule is for
  builds, not for full blocks; proof pruning (item 1) is what makes full blocks survivable.
- The RandScan explorer shows bytes per block and per transaction; on the 80-query chain a block
  with three transfers will read as ~3.9 MB, which is correct, not a bug.

Related: `docs/fees.md` (why no gas), `docs/zkvm.md` §5 (the FRI profile), `docs/supply.md`
(the value-balance audit), `docs/rpc-comparison.md`.
