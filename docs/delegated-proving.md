# Delegated proof generation

**A prover you delegate to holds your spend key.** Every bundle a wallet delegates carries the
wallet's spend key as a private input — the bundle guest derives the viewing key from it in
the circuit — so the operator of a `rand-prover` can spend every note that wallet owns and
every note it will receive. Delegate only to a prover you would hand your key file to: one you
run yourself, or one run by someone who already has that trust. Splitting the key so a prover
can prove but not spend is the next design (spec §9); until it lands, this page describes a
*trusted* prover.

What delegation buys is time and reach: a proof that takes a hundred seconds on a laptop and
cannot be made on a phone at all is made where a GPU is. What it costs, besides custody, is
privacy toward the prover: it sees the notes being spent, the amounts, the recipient and the
client's IP. Toward everyone else — the chain, the network, the other prover's users —
nothing changes: the transaction the chain sees is indistinguishable from a locally proved one.

Spec: `docs/superpowers/specs/2026-09-17-delegated-proving-design.md`.

## Running a prover

```bash
rand-prover keygen --key prover.key.json           # an ordinary wallet key file
rand-prover address --key prover.key.json          # the rand1… address wallets pin
rand-prover run --key prover.key.json --listen 127.0.0.1:8600 --token "$(openssl rand -hex 16)"
```

| flag | default | meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8600` | off loopback needs `--token` or `--allow-open` |
| `--token` (`RAND_PROVER_TOKEN`) | none | the bearer wallets send; without it the service is free compute for anyone who finds it |
| `--cuda` | off | prove on the GPU; needs a build with `--features cuda` |
| `--slots` | 1 | concurrent proofs, one per GPU (zero is refused at startup) |
| `--max-queue` | 8 | jobs waiting beyond the slots |
| `--per-ip` | 2 | jobs one client address may have in flight — the *source* address of the connection, which behind a reverse proxy is the proxy itself, so every wallet shares one cap: raise it there, or terminate TLS on the prover. A forwarded-for header is not honoured in v1 |
| `--result-ttl-secs` | 600 | how long a finished result waits to be fetched |
| `--allow-open` | off | listen off loopback with no token — every job is then free compute for anyone who finds it |

It routes `POST /v1/jobs`, `GET /v1/jobs/{id}`, `GET /v1/jobs/{id}/result`, and `GET /v1/health`
(open, unauthenticated — it is how a wallet checks the address before it trusts the prover with
anything). Its queue estimate sums the per-kind running average of every job ahead of a new one;
a job that cannot start before its deadline is refused up front with 429 and that estimate,
rather than proving late. A queued job past its own deadline reports `expired` the moment
anyone polls it, and an expired job has no result to fetch.

Put TLS in front of it (any reverse proxy): the job itself is sealed to the prover's key, so
TLS protects the token and hides which wallet talks to which prover from the path.

The log carries job ids, kinds, states and timings. It never carries an input word, a note, or
an address; if you see one, that is a bug to report.

## Using one from the wallet

```bash
export RAND_PROVER=https://prover.example:8600
export RAND_PROVER_ADDRESS=rand1…        # what `rand-prover address` printed
export RAND_PROVER_TOKEN=…
rand send rand1… 1.5                     # proved there, submitted from here
rand bond <validator> 1000 …             # the same
rand call <program> 400 250 300 75       # a call, with its input envelope
```

Or `--prover`, `--prover-address`, `--prover-token`, `--prover-deadline` on any command
(`RAND_PROVER_DEADLINE` defaults to 120 s). `--cuda` and `--prover` together are an error: a
proof is made in one place. The first delegated command of a run prints the custody warning
above. The client's `reqwest` carries the `rustls-tls` feature, so an `https://` prover works
with no extra system dependency.

Before the first job the wallet reads the prover's `/v1/health` and refuses to continue if the
address there is not the one pinned. Then, per proof: the wallet builds the witness exactly as
it would locally, seals it to the prover's address under a fresh one-time reply key, posts it,
polls (surviving a dropped poll — up to five transport-error retries — and bounding the whole
wait at the deadline plus 900 s), fetches the sealed result, opens it, and — this is the part
that makes a *wrong* prover harmless short of custody — checks that the proof publishes the
digest the wallet computed from its own plaintext, and that the salt in the result is the one
it asked for *and the one the proof was made with* (it recomputes `H_IN` from the returned salt
and compares it to the commitment the proof publishes, so a salt that would make the wallet seal
a transcript the proof does not commit to is caught before submission). A proof of any other
bundle, an unrequested salt, or a salt that does not match the proof, is refused before the chain
sees it. Envelopes, transaction keys and submission are the same code as the local path.

**Deadline.** `--prover-deadline` (default 120 s) is how long the prover may take to *start*
the job. A bundle binds the chain height it was planned at, and admission accepts it for 256
blocks — about four minutes at chain 12's one-second interval — so a job that queues for
longer produces a proof the chain rejects. The prover refuses up front, with its estimate,
rather than proving late; the wallet then says so and stops. There is no automatic fallback to
local proving: a phone that delegated because it cannot prove would only hang.

## Errors you will see

| message | what happened | do |
|---|---|---|
| `the prover at … is unreachable` | connect, TLS or a 5xx | check the URL; or drop `--prover` |
| `refused the token (401)` | wrong or missing bearer | set `--prover-token` |
| `is busy (429): …; it estimates N s` | queue full or the deadline cannot be met | wait N s, raise `--prover-deadline`, or prove locally |
| `reports a different address than --prover-address pins` | wrong pin, or a different prover behind that URL | fix the pin; nothing was sent |
| `refusing to submit` | the returned proof is for some other bundle, or the salt is not the one the proof was made with | stop using that prover |
| `could not start the job within N s` | it queued past the deadline | run the command again |

## What the experiment measures

The 2026-09-17 comparison (spec §11): submit-to-commit wall clock of twenty `rand send`s,
local on a laptop versus delegated to a CPU droplet versus delegated to a GPU host. Chain
finality and throughput are expected unchanged — delegation moves proving off the client, it
does not shrink the 1.3 MB proof a block carries — so the only row that can move is the
client's latency, and only a GPU host can move it. `scripts/delegated-experiment.sh` runs the
loop and prints the table. The numbers go here when they exist.
