# Local versus delegated proving — the 2026-09-17 benchmark

The question asked was "which is better, HotStuff BFT or delegated proof generation". They are
not alternatives: HotStuff is the consensus every block on this chain commits under, in both
runs below, and delegated proving only moves *where a wallet's proof is made*. So the comparison
this page measures is the one that can differ — a wallet proving on its own machine against the
same wallet handing its witness to a `rand-prover` — on the same chain, through the same node,
with consensus, admission and the proof format held constant.

Spec: `docs/superpowers/specs/2026-09-17-delegated-proving-design.md` §11. Operator guide:
`docs/delegated-proving.md`. Loop: `scripts/proving-benchmark.sh`. Raw rows:
`docs/benchmarks/2026-09-17-local.csv` and `docs/benchmarks/2026-09-17-delegated.csv`.

## Setup

| | |
|---|---|
| chain | 12 (genesis `605eb783…`), 18 validators staked at 1000 RAND each, 13-of-18 quorum, production FRI profile (80 queries) |
| node | E (DigitalOcean sgp1, 188.166.235.187), reached from the laptop through an SSH tunnel, so the node side is identical in both runs |
| wallet machine | the laptop: 16 cores, 48 GB; `rand` from build `fb6e4a9` (this branch) in both runs — only `--prover` differs |
| fleet build | run 1 on the chain-12 pin `c66e6b8`; run 2 after the same-chain update of all 16 droplets and node A to the branch build (`rand-node` sha256 `1207e15a…`, compiled on E). The branch changes nothing in consensus, admission or the wire format, so this update cannot move the numbers by design; it was done because the user asked for the fleet to run the branch |
| prover (run 2) | `rand-prover` on the laptop itself, loopback, one slot, CPU backend. No droplet in the fleet can prove (1–2 GB of RAM against a tier-14 bundle), and no GPU host exists, so run 2 measures the delegated *topology* on the same silicon as run 1: the sealing, the transport, the queue, and the wallet's checks — not a faster prover |
| cycle | mint (faucet, no proof) → transfer of 1.5 RAND (one bundle proof) → bond of 1 RAND onto a validator (one bundle proof; the chain's only burn, since chain 12 has no bridge) → deploy of a fresh `private_payment` guest (one bundle proof for the fee) → a call of it with an input envelope (one program proof plus one bundle proof) |
| cadence | one cycle every 5 minutes for 2 hours; a cycle takes ~8 minutes with local proving, so cycles ran back to back |
| what is timed | per operation: wall clock from command start to the commit the wallet waits for; the wallet's own "proved in" (summed over the operation's proofs); the wallet's own verify of the proof it is about to submit, cold (verifier-key build plus verify) and warm (the per-proof cost every validator pays at admission); proof bytes; the committing height. Per run: transactions and blocks over the window, from `rand_getBlockByHeight` |

Verification time is measured on the wallet machine rather than on a validator because the node
does not expose per-proof timings; the warm figure is the same STARK verify every validator runs
at admission, on the same proof, so it transfers.

## Run 1 — local proving (the pinned fleet, `c66e6b8`)

Window: heights 23608–28843, 5236 blocks over 7400 s (0.708 blocks/s), 125 transactions,
16 cycles, 0 failures. 2026-09-17 16:27–18:45 UTC.

| operation | end-to-end (s) | proving (s) | verify cold (s) | verify warm (ms) | proof bytes | n |
|---|---|---|---|---|---|---|
| mint | 6.5 | — | — | — | — | 16 |
| transfer | 111.5 | 95.9 | 3.25 | 27 | 1 415 438 | 16 |
| bond | 111.4 | 95.8 | 3.24 | 27 | 1 417 519 | 16 |
| deploy | 111.0 | 95.9 | 3.23 | 27 | 1 417 742 | 16 |
| call (program + bundle) | 121.2 | 102.2 | 3.50 | 51 | 2 709 305 | 16 |

Chain throughput over the window: **0.0169 tx/s** — the loop's own submission rate, not a
ceiling. Consensus commits an already-proved transaction in about 10 s of the end-to-end
figure (end-to-end minus proving minus the wallet's two verifies), and a mint, which carries no
proof, commits in 6.5 s end to end including the RPC round trip.

## Run 2 — delegated proving (the fleet on the branch build)

Window: heights 30881–36215, 5335 blocks over 7623 s (0.700 blocks/s), 128 transactions,
17 cycles. 2026-09-17 19:19–21:41 UTC. The prover finished 78 jobs, refused none, expired none.

| operation | end-to-end (s) | proving (s) | verify cold (s) | verify warm (ms) | proof bytes | n |
|---|---|---|---|---|---|---|
| mint | 5.3 | — | — | — | — | 16 |
| transfer | 112.5 | 96.8 | 3.21 | 27 | 1 416 532 | 16 |
| bond | 112.3 | 97.1 | 3.21 | 27 | 1 415 618 | 16 |
| deploy | 112.5 | 97.1 | 3.21 | 27 | 1 417 294 | 15 |
| call (program + bundle) | 123.1 | 104.8 | 3.45 | 51 | 2 711 774 | 15 |

Chain throughput over the window: **0.0168 tx/s**.

Five rows failed, all from one cause outside the system under test: the SSH tunnel from the
laptop to E reset at 20:18 UTC (E closed the connection; the node itself never stopped), which
lost cycle 8's deploy and all of cycle 9. The tunnel was restarted with keepalives and cycle 10
onward ran clean. Those rows are `FAIL` in the CSV and excluded from the means; the prover saw
no failed job.

## Reading the two runs

| | local | delegated | difference |
|---|---|---|---|
| transfer, end to end | 111.5 s | 112.5 s | +1.0 s (+0.9 %) |
| bond, end to end | 111.4 s | 112.3 s | +0.9 s |
| deploy, end to end | 111.0 s | 112.5 s | +1.5 s |
| call, end to end | 121.2 s | 123.1 s | +1.9 s |
| bundle proof | 95.9 s | 96.8–97.1 s | +1 s: the job queue's 1–5 s poll granularity |
| verify, cold / warm | 3.25 s / 27 ms | 3.21 s / 27 ms | none |
| proof size | 1.415–1.418 MB | 1.416–1.417 MB | none |
| chain throughput | 0.0169 tx/s | 0.0168 tx/s | none (the loop's own rate) |
| block rate | 0.708 /s | 0.700 /s | none |
| consensus commit (end to end − proving − the two verifies) | ≈ 9–12 s | ≈ 9–12 s | none |

**What is better.** The question as asked has no winner, because HotStuff is not on one side
of it: both runs commit under the same three-chain HotStuff, and every row that consensus owns —
block rate, commit latency, verification cost, throughput — is identical to within noise. What
the runs do show is the cost of the delegated *topology* on equal hardware: about one second per
proof, from sealing the witness, one HTTP round trip each way, and the wallet polling a queue,
against ninety-six seconds of proving. That overhead is what a wallet pays to move its proving
somewhere else; it buys nothing here because "somewhere else" was the same laptop.

Delegation wins only when the prover is faster than the client. The spec's §11 target is a GPU
host (3–10 s per bundle against ~96 s here), which would turn the transfer's 112 s into roughly
15–20 s end to end with the same ~10 s of consensus underneath. No such host was available for
this run, so **the v0.3 switch stays open**: the plumbing is measured and costs ~1 %, the chain
side is unchanged, and the speed row of §11 still needs a GPU measurement. What delegation
already buys without a GPU is reach — a phone or a browser that cannot prove at all — at the
privacy and custody cost `docs/delegated-proving.md` states first.

Two facts about the chain itself fell out of the runs, unrelated to delegation: a mint, which
carries no proof, commits in 5–6 s end to end, which bounds the RPC-plus-consensus path; and a
proved transaction commits about 10 s after submission, consistent with the ~1 s block interval,
the three-chain rule and proof verification at admission.
