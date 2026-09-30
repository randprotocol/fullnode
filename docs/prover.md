# The delegated prover

A bundle proof is tier 14: about 100 s and 5.74 GB of memory on a laptop CPU
(`docs/node-hardware.md` §3). A browser gives WebAssembly 4 GiB and most phones have less than
8 GB, so a light wallet cannot make that proof itself. The delegated prover makes it on another
machine: a separate binary, `rand-prover`, or the same service inside a node, `rand-node run
--prover`. The wallet seals the proof's witness to the prover, collects the sealed proof, checks
it, and submits the transaction itself.

This page is the operator's and integrator's guide: the trust model, how to run a prover, how a
wallet pairs with it, and the wire protocol for other client authors. The design is
`docs/superpowers/specs/2026-09-28-delegated-proving-design.md`; the code is
`crates/randprotocol-prover` (the service and `rand-prover`), `crates/randprotocol-node/src/main.rs`
(`run --prover`) and `crates/randprotocol-client/src/prover.rs` (the wallet's side). Phase 1
(v0.6.2) changes no consensus rule and runs against any chain; its witness carries the spend key.
Phase 2 (v0.6.3, split authorisation — §8) is a hard fork selected at genesis: the witness carries
the viewing key `nk` instead, and the spend key stays on the wallet's machine.

## 1. What it is

The chain has three roles that prove or verify, and the delegated prover is the third
(spec §1):

| role | does | hardware | paid by | defined in |
|---|---|---|---|---|
| validator (proposer) | orders transactions, verifies proofs | CPU | the fee's verification share | `docs/staking.md` |
| aggregator | one recursive proof over many bundles | GPU | the fee's proving share + the block subsidy | `docs/aggregation.md` |
| **delegated prover** | one bundle proof for one sender | 8 GB+ CPU, or GPU | that sender, privately (spec §5) | this page |

A prover charges nothing unless its operator sets a fee (`--fee`, §3.5); then `prover_info.fee`
quotes it, and only a v3 job whose witness pays it is admitted. A prover holds no chain state,
reads no blocks and never sees a transaction — only the witness words and the eight binding words
of one bundle. The wallet builds the transaction, and the proof is bound to it through those
binding words.

## 2. The trust model

The bundle guest takes the spend key `sk` as a private input and derives `nk` and `pk_self` from
it. Knowledge of `sk` is the only thing that authorises a spend, so whoever receives a Phase 1
prove request can build any other transaction for that wallet. In the spec's words: **delegating a
proof is handing over custody.**

| | prover receives | prover can read | prover can spend | who may run it |
|---|---|---|---|---|
| Phase 1 (bundle guests v1/v2) | `sk` | the wallet's whole history | **yes** | the wallet's owner only |
| Phase 2 (bundle guest v3, genesis `hc_auth`) | `nk` and a fresh salt | the wallet's whole history | no | anyone |

A Phase 1 prover receives the spend key. It is for a machine the wallet's owner runs — a desktop
proving for the same person's phone, a home server proving for a laptop. The rule the design
starts from is that **someone who wants full privacy runs their own.**

A Phase 2 prover receives the viewing key `nk` instead. It cannot spend — a v3 bundle is admitted
only beside an auth proof over `sk`, which the wallet makes itself (§8) — but it can read the
wallet's whole history: `nk` derives the ML-KEM decapsulation key and `ovk`, so a prover that
proved one transaction can read everything that wallet ever received or sent, before and after.
Phase 2 does not make delegation private; it makes it non-custodial (§8).

Both ends enforce the Phase 1 rule for spend-key witnesses:

- `rand-prover run` refuses every `SpendKey` job unless it was started with `--accept-spend-key`
  (off by default). With the flag it prints, on stderr and in the log:
  `every SpendKey job holds the sending wallet's spend key: run this only for wallets you own`.
- A pairing link carries `own=1` only when the operator passed `--own` to `rand-prover pair`. The
  wallet sends a spend-key witness only to a prover paired with `own=1`; otherwise it refuses with
  `this build's witness carries the spend key; only a prover paired as your own (own=1) may
  receive it`. On a chain whose bundle guest is v1 or v2 every witness carries the spend key, so a
  prover paired without `--own` cannot be used there.

On a split-authorisation chain (genesis `hc_auth`, bundle guest v3 — §8) the job is a
`ViewingKey` job instead: the wallet sends `nk` and a fresh 256-bit salt, never the spend key, and
makes the tiny auth proof over `sk` itself. Every prover accepts viewing-key jobs, with or without
`--accept-spend-key`, and the wallet may send one to **any** paired prover, `own=1` or not — the
prover gates only by its flag and the job's kind; whether a pairing may receive a witness is the
wallet's rule, not the prover's. The history warning above is the whole cost: whoever proves one
v3 transaction for a wallet can read that wallet's entire history, past and future, so pair with a
prover you would show your history to. The wallet says so in two places: `rand prover pair` on a
link without `own=1`, and once per prover before the first viewing-key witness goes to one that is
not paired as your own (§5.2).

The kind follows the guest, whichever flags are set: a `ViewingKey` job is refused for guests v1
and v2 (they take a spend key), and a `SpendKey` job is refused for guest v3 (it takes `nk`).

The prover is not trusted for correctness either: the wallet checks every proof it gets back (§5).

## 3. Run your own

### 3.1 Key, pairing, run

```sh
rand-prover keygen
rand-prover pair --name phone --own --qr --url https://prover.example.net
rand-prover run --accept-spend-key
```

Every subcommand takes `--home <DIR>` (env `RAND_PROVER_HOME`, default `~/.rand-prover`), the
directory that holds `prover.key.json` and `pairings.json`. It is created at mode 0700 if missing.

- **`keygen`** writes `prover.key.json` at mode 0600 — a 64-byte seed from which the ML-KEM-768
  key pair is derived — and prints the key's fingerprint on stdout (`XXXX-XXXX-XXXX-XXXX`, 80 bits
  of `blake3("rand-prover-fingerprint-1" ‖ kem_ek)` in Crockford base32). It refuses to overwrite
  an existing key. `run` refuses a key file that group or other can read.
- **`pair --name <LABEL>`** mints a 32-byte token, stores only its hash
  (`blake3("rand-prover-token-1" ‖ token)`) under the label in `pairings.json` (mode 0600), and
  prints the pairing link on stdout. `--url` is the URL the wallet will reach this prover at
  (default `http://127.0.0.1:8600`); `--own` adds `own=1`; `--qr` also prints the link as a
  terminal QR code. A label must be unique; pairing it again needs `unpair` first.
- **`unpair --name <LABEL>`** removes a pairing. A running prover reads `pairings.json` at start,
  so the revocation takes effect when it restarts.
- **`pairings`** lists one line per pairing: label, `own` or `-`, and the creation date (UTC).
- **`run`** serves the `prover_*` JSON-RPC (§6) until ctrl-c or SIGTERM.

The token is printed once, inside the link, and never stored anywhere the prover can read it back.
A lost link cannot be recovered: `unpair --name <LABEL>` and `pair` again. The link is about
1,740 characters, most of it the base58 ML-KEM key, so the terminal QR code is tall; where the
wallet can take pasted text, paste the link instead.

`run` with no pairings still starts, but prints
``no pairings: every job will be refused — run `rand-prover pair` ``.

### 3.2 `rand-prover run` options

| option | default | meaning |
|---|---|---|
| `--listen <ADDR>` | `127.0.0.1:8600` | the listener, `ip:port` |
| `--accept-spend-key` | off | accept `SpendKey` witnesses (guests v1/v2); only for wallets you own (§2). `ViewingKey` witnesses (guest v3) are accepted either way |
| `--max-parallel <N>` | `1` | proofs run at once, one worker each; at least 1 |
| `--max-queue <N>` | `8` | jobs waiting beyond those proving |
| `--per-token <N>` | `2` | jobs one pairing may have queued or proving at once |
| `--cuda` | off | prove on the CUDA backend; needs a build with `--features cuda`, and there is no CPU fallback |
| `--skip-memory-check` | off | start even when the memory gate below would refuse |
| `--allow-origin <ORIGIN>` | extensions and loopback pages | a browser origin whose pages may read replies, repeatable; given once or more, the values are the whole list; `*` = every origin (opt-in, warned) — §6.1 |
| `--fee <RAND>` | none | the fee every job must pay, in RAND (display units, up to 9 decimals); needs `--fee-address` — §3.5 |
| `--fee-address <ADDRESS>` | none | the `rand1…` address the fee is paid to; needs `--fee` |

A job over the pairing's `--per-token` cap, or one that would push queued plus proving jobs past
`--max-queue` plus `--max-parallel`, is refused `busy` (§6.2).

### 3.3 Memory

Every proving slot needs one tier-14 bundle's peak, 5.74 GB (`PROVER_PEAK_BYTES`), and the
process keeps 1 GiB of headroom. At start, `run` compares `5.74 GB × --max-parallel + 1 GiB` with
the memory the OS reports available and refuses to serve if it does not fit:

```
1 proving slot(s) need 6.8 GB of available memory (5.74 GB each plus 1.1 GB headroom); this machine has 4.2 GB available — lower --max-parallel, or pass --skip-memory-check
```

`--skip-memory-check` is the escape for a machine whose available-memory figure understates what
it can give (a large page cache, say); a prover that swaps or is killed mid-proof serves no one.

### 3.4 Stopping

`run` shuts down on SIGINT (ctrl-c) or SIGTERM (systemd's default stop signal), the same way. A
proof already running on the blocking pool is not interrupted, so shutdown can wait up to one
proof, about 100 s, while it finishes. In a systemd unit, give the stop that long before systemd
escalates to SIGKILL:

```ini
[Service]
ExecStart=/usr/local/bin/rand-prover --home /root/prover run --accept-spend-key
TimeoutStopSec=180
```

On the stop the service stops admitting (a submit in the meantime is refused `bad job` with
`shutting down` — though over HTTP a client mostly sees a closed connection instead, since the
listener is aborted right after the service shuts down), drops every queued job with its witness
zeroized, lets the proof in flight finish but discards its reply (the job ends `failed`, `shutting
down`), and stops its workers; `rand-node run --prover` stops its hosted prover the same way when
the node stops, closing the prover's queue before it stops the node.

### 3.5 Charging a fee

```sh
rand-prover run --fee 0.05 --fee-address rand1…
```

Spec §5: the sender pays the prover inside the same bundle, as one more shielded RAND output — no
consensus change, no public field, and the prover is paid only if the transaction it proved
commits. `--fee` and `--fee-address` come together (each `requires` the other); `--fee 0` is
refused (`omit --fee and --fee-address instead`). At start `run` prints `charging <amount> RAND
per job to <fingerprint>`, the address's fingerprint. `prover_info.fee` then quotes
`{"amount": "<base units, decimal string>", "address": "rand1…"}` (§6.1).

Admission checks the fee after the witness length, on the opened witness (`service::check_fee`):
one of the four outputs must name the fee address's `pk`, sit in a RAND slot — slots 2–3 always,
slots 0–1 only when the bundle's asset is RAND — and carry at least the quoted amount, below 2^63
(the guest's range check would taint anything larger). A job that does not pay is refused `-32006
the prover fee is not paid`, with `data.reason` one of `no output pays this prover's fee address`,
`the output to this prover is not in RAND: the fee is paid in a RAND slot`, `the fee paid is below
the quoted <n> base units`, or the 2^63 refusal. Only a v3 witness can carry the fee: on a prover
that charges one, a spend-key job that passes the earlier checks (so `--accept-spend-key` is set)
is refused `-32006` too (`this prover charges a fee, which only a v3 witness can carry`).

The prover checks the fee **output** in the witness, not the **envelope** the wallet seals to it:
the envelope is not in the witness, so a wallet can pay the note and seal junk to it. That is
griefing only — the note is committed but neither side can open it, so the RAND is lost to both
and the wallet gains nothing. A follow-up is for the prover to keep the fee note's opening from
the witness, so it can spend the note without the envelope; this build does not.

## 4. In a node

A node can host the same service on its own listener:

```sh
rand-prover --home /root/prover keygen
rand-prover --home /root/prover pair --name laptop --own --url https://prover.example.net
rand-node run --datadir /root/data --key /root/keys/node.key.json \
  --prover 127.0.0.1:8600 --prover-home /root/prover --prover-accept-spend-key
```

| option | default | meaning |
|---|---|---|
| `--prover <ADDR>` | off | host the prover on this address |
| `--prover-home <DIR>` | `<datadir>/prover` | the directory holding `prover.key.json` and `pairings.json` |
| `--prover-accept-spend-key` | off | as `rand-prover run --accept-spend-key`, the same printed sentence |
| `--prover-max-parallel <N>` | `1` | as `--max-parallel` |
| `--prover-max-queue <N>` | `8` | as `--max-queue` |
| `--prover-cuda` | off | as `--cuda` (a `rand-node` built with `--features cuda`) |
| `--prover-skip-memory-check` | off | as `--skip-memory-check` |
| `--prover-allow-origin <ORIGIN>` | extensions and loopback pages | as `--allow-origin` (§6.1) |
| `--prover-fee <RAND>` | none | as `--fee` (§3.5); needs `--prover-fee-address` |
| `--prover-fee-address <ADDRESS>` | none | as `--fee-address`; needs `--prover-fee` |

The per-pairing cap is the default, 2 jobs; there is no node flag for it.

**The prover is never a method of the public RPC.** `rand-node`'s RPC authenticates nobody, by
design; the prover answers only paired tokens and holds spend keys while it proves. So `--prover`
must be a listener of its own: an address equal to `--rpc`, or a wildcard address on the same port
as `--rpc` (either side), is refused with `--prover <ADDR> is the --rpc address: the prover is
never a method of the public RPC; give it its own listener`.

**Every prover check runs, and the prover's address is bound, before the node key is read or the
database opened**, so a misconfigured prover — or a `--prover` port already in use — exits at once
instead of after a startup verify. The node never mints a
prover key: without one it refuses to start with
``no prover key at <home>/prover.key.json: run `rand-prover --home <home> keygen` and `pair` first``. The memory gate, the CUDA check and the
no-pairings warning are the same as `rand-prover run`'s, with the node's flag names. The prover
is served once the node's RPC is up (the bound port accepts no request before then) and stops
with the node; if the prover's listener exits, the node stops too. The node stops on ctrl-c or
SIGTERM, and stopping one with `--prover` can wait for a proof in flight in the same way (§3.4).

Never host the prover on a machine in the public RPC path (`docs/deploy.md`). Spec §8 Q3 also
records that a validator which holds witnesses while it proves is a larger target; an observer
or a machine of its own is the safer home.

## 5. The wallet

### 5.1 Pairing

```sh
rand prover pair 'randprover:…?url=https%3A%2F%2Fprover.example.net&token=…&own=1' --name home
rand prover show
rand prover forget
```

`pair <LINK>` parses the link, checks its URL (§7), then calls `prover_info` at that URL and
refuses unless the prover answers with the key fingerprint the link names — so the prover must be
running when the wallet pairs. Only then does it write `<key>.prover.json` beside the spend-key
file, at mode 0600 (the token is a bearer credential), replacing any earlier pairing, and print
`paired <fingerprint> at <url> (own: yes|no)`. A link without `own=1` is still saved, with this
warning on stderr (§2), printed as one line:

```text
warning: this link has no own=1: on a chain with split authorisation (bundle guest v3) this
prover can prove your bundles from a viewing-key witness — it learns this wallet's whole history,
never its spend key — and on a pre-v3 chain, whose witness carries the spend key, every --prover
use is refused; re-pair with a link from `rand-prover pair --own` only for a machine you run
```

`--name` is a label the wallet prints instead of the URL. A wallet keeps one pairing.

`show` prints the pairing's name, URL, fingerprint, `own` and the prover's key, never the token.
`forget` deletes `<key>.prover.json`.

### 5.2 Proving on the paired prover

The global flag `--prover` moves the bundle proof to the paired prover:

```sh
rand --prover send rand1… 1.5
```

It applies to every command that proves a bundle: `send`, `bond`, `program deploy`, `call`,
`bridge-mint`, `bridge-rotate`, `bridge-burn`, and `token create`, `mint`, `burn`,
`set-authority`, `register-bridged` and `list-backing`. For `call`, only the paying bundle moves;
the call proof is always made on the wallet's machine. `--prover` with `--cuda` is refused: the
bundle is proved on the paired prover or on this machine's GPU, not both — except `call`, whose
call proof takes `--cuda`; the paying bundle still goes to the prover. Without a pairing,
`--prover` refuses with `no prover paired for this wallet: rand prover pair <link>`.

On a split-authorisation chain (`rand_status` names bundle guest v3 and `hc_auth`) the wallet
draws a fresh 256-bit salt for each bundle, sends the prover the v3 witness — `nk` and the salt,
never the spend key — as a `ViewingKey` job, and makes the auth proof over the spend key and the
same binding on this machine (tier 10, about 7 s). The summary line reports both proving times.
To a prover not paired as your own, the first such job is preceded, once, by `warning: <name> —
this prover can read this wallet's whole history; it cannot spend`; `rand send` shows it in its
confirmation, before the y/N, so it can be declined.

**The prover's fee.** When `prover_info.fee` quotes one, the wallet adds the output that pays it
(spec §5): slot 2 of a token transfer, a burn, or a RAND bundle that pays nobody (a bond, a
deploy, a call, a bridge action), the RAND change moving to slot 3; slot 0 of a RAND transfer,
whose slots 2–3 already hold the payment and its change. That transfer spends one RAND note in
slots 0–1 for the fee (its change in slot 1) and another in slots 2–3, so a wallet holding one
spendable RAND note is told to split it first with a self-transfer proved without `--prover`.
`rand send` shows `prover fee: <amount> RAND to <fingerprint>` beside the recipient before its y/N;
the other commands print the same line on stderr. The global `--max-prover-fee <RAND>` (default
`1`) caps what the wallet pays: a quote above it is refused before any bundle is built, on every
command (`the prover quotes <q> RAND; the cap is <c> RAND (--max-prover-fee) — not building the
bundle`); `--max-prover-fee 0` refuses any fee. A fee on a chain whose bundle guest is v1 or v2 is
refused too — only a v3 witness can carry it. The wallet does not remember the fee it saw at
pairing: a prover may raise its price at any time, up to the cap.

While the job runs the wallet prints `queued on <name> at position <n>…` and `proving on <name>…`,
polling `prover_status` once a second. A poll that does not reach the prover (a reset, a timeout,
a proxy's error page) is retried, with one `prover <name> unreachable …, retrying…` line per
outage; the prover's own JSON-RPC error (`unknown job` after it restarted, say) or a `failed` or
`expired` job ends the wait. It gives up after 20 minutes, queue included, and cancels
the job. Any refusal of a proof also cancels the job, so it stops holding the prover's queue.

### 5.3 What the wallet checks

Before sealing anything:

- the prover's `prover_info.kem_fingerprint` equals the fingerprint the wallet paired with;
- the chain's own `rand_status`: a v3 `hc_bundle` must come with an `hc_auth` equal to this
  build's auth guest, and a v1/v2 `hc_bundle` with none — otherwise the wallet refuses before
  proving anything;
- the prover lists this chain's bundle guest in `hc_bundles`, the chain's FRI profile in
  `profiles`, and the job's kind in `witness_kinds` (`viewing_key` for guest v3, `spend_key` for
  v1/v2);
- for a spend-key witness only, the pairing has `own=1` (§2);
- a quoted fee is readable, at most `--max-prover-fee`, and on a v3 chain.

On the reply, in this order:

1. the proof is at most the chain's `max_proof_bytes`;
2. the digest the proof itself publishes — read out of the proof's public values, not taken from
   the reply's `digest` field, which is only the prover's word — equals the digest the wallet
   computed from its own plaintext;
3. the reply's `digest` field agrees with the proof;
4. the proof verifies on the wallet's machine against the bundle guest and the transaction's
   binding (`verify_bundle`), unless `RAND_PROVER_NO_VERIFY=1` is set.

On a v3 chain the digest in step 2 is the v3 digest, with the bundle's `auth_commit =
H(AUTH, nk, salt)` inside, and the wallet's own auth proof must publish the same `c`.

Step 2 is the check that matters and it runs whatever `RAND_PROVER_NO_VERIFY` says: a tainted
witness still proves (the guest sets its `bad` flag), so a valid proof of the wrong statement is
caught only by digest equality (spec §3.6). A reply that fails any step is not used.

## 6. The wire

### 6.1 Transport

JSON-RPC 2.0 over HTTP `POST /`, one request object per body. Batches and notifications are not
served (`-32600`); `params` must be an array. The request body is capped at 135 168 bytes
(twice `MAX_SEALED_JOB_BYTES` for the hex, plus 4 KiB); a larger body gets HTTP 413 with a
JSON-RPC error.

**Browser origins.** A browser page on another origin (a web or extension wallet) may call the
listener, but only from an origin on its allow-list. The reason is `prover_info`: its `kem_ek` and
`kem_fingerprint` are stable for the prover's life, and a desktop wallet serves this listener on
`127.0.0.1:8600`, so an `Access-Control-Allow-Origin: *` would let every website the user visits
read that key and recognise the same machine across sites — a cross-site identifier for a privacy
wallet. The pairing token protects submission, not enumeration. The default list is
wallet-shaped origins only:

```
chrome-extension://*   moz-extension://*   safari-web-extension://*
http://localhost:*     http://127.0.0.1:*  http://[::1]:*
```

A pattern is an exact origin (`https://wallet.example`, `http://host:8080`), `scheme://*` for a
`-extension` scheme only (any extension id under it: letters, digits, `-`, `_`, `.`, no port or
path; `https://*` or `http://*` is refused at start — to allow every origin, say `*`), or
`scheme://host:*` (that exact scheme and host on any port, or none). There is no other wildcard and
no substring match: `http://localhost.evil.example` is not `http://localhost:*`. A browser sends
origins in lowercase and so must the list. `Origin: null` — a `file://` page, a sandboxed iframe,
some redirects — matches no pattern and can never be allowed (only `*` answers it); serve a wallet
page from `http://localhost:<port>` instead. Per request, by its `Origin` header:

- **No `Origin`** (curl, the `rand` CLI, a same-origin page): served, with no CORS headers.
- **An allowed origin**: `OPTIONS /` answers 204 with `Access-Control-Allow-Origin: <that origin>`,
  `Vary: Origin`, `Access-Control-Allow-Methods: POST, OPTIONS`, `Access-Control-Allow-Headers:
  content-type` and `Access-Control-Max-Age: 86400`; every reply to a `POST` — results, JSON-RPC
  errors and the 413 alike — carries the same `Access-Control-Allow-Origin` and `Vary: Origin`.
- **Any other origin**: `OPTIONS /` answers 403 with no CORS headers, and every method, `prover_info`
  included, answers `-32007 origin not allowed` with no CORS headers, so the page can read neither.

`--allow-origin <ORIGIN>` (`rand-prover run`) or `--prover-allow-origin <ORIGIN>` (`rand-node run`)
replaces the list: repeat it, and the values given are the whole list (the default is not kept).
`--allow-origin '*'` allows every origin and answers `Access-Control-Allow-Origin: *`; it is opt-in
and prints a one-line warning, since any website can then read the prover's key. A malformed
pattern (a path, a trailing slash, a `*` elsewhere) refuses the start. `prover_info` serves the
effective list as `allowed_origins` (`["*"]` under `*`), so a wallet can tell why it was refused.

Nothing about a request is authorised by the browser either way: the only credential is the pairing
token inside the sealed job, never a cookie or other ambient credential another site could make the
browser send.

| method | params | result |
|---|---|---|
| `prover_info` | — | `{version, kem_fingerprint, kem_ek, hc_bundles[], profiles[], backend, witness_kinds[], queue: {depth, max, proving}, fee, allowed_origins[]}` |
| `prover_submit` | `[sealed_hex]` | `{job}` — 128 random bits, hex |
| `prover_status` | `[job]` | `{state, position?, reply?, error?}`; `state` ∈ `queued｜proving｜done｜failed｜expired` |
| `prover_cancel` | `[job]` | `{cancelled}` |

`prover_info`: `kem_ek` is the ML-KEM-768 encapsulation key in hex; `hc_bundles` are the bundle
guests this build proves, in the hex form `rand_status.hc_bundle` serves; `profiles` is
`["test", "production"]`; `backend` is `cpu` or `cuda`; `witness_kinds` is `["viewing_key",
"spend_key"]` with `--accept-spend-key` and `["viewing_key"]` without (a viewing-key job proves
bundle guest v3 only, §2); `fee` is `null`, or `{"amount": "<RAND base units, decimal string>",
"address": "rand1…"}` for a prover started with `--fee` (§3.5); `allowed_origins` is the origin
allow-list above, or `["*"]`.

`prover_status`: `position` (1-based) is present while `queued`; `reply` (hex of the sealed reply)
while `done`, on every poll; `error` while `failed` (a cancelled proving job ends `failed` with
`cancelled`). A finished job's reply is kept 10 minutes; after that the job reads `expired` and its
reply is gone, and a further 10 minutes later the job is forgotten (`unknown job`).

`prover_cancel`: a queued job is removed at once, its witness zeroized; a proving job is flagged
and its reply discarded when the proof returns. `cancelled` is `true` if the job was queued or
proving, `false` if it had already finished.

### 6.2 Errors

| code | message | when |
|---|---|---|
| `-32700` | `parse error` | the body is not JSON |
| `-32600` | varies | not a request object, a batch, a notification, `jsonrpc` not `"2.0"`, no method, or an unreadable/oversized body |
| `-32601` | `method not found` | |
| `-32602` | varies | `params` not an array, not one string, or the sealed job not hex |
| `-32000` | `bad job` | `data.reason`: too long, does not open under this key, malformed, wrong wire version, unknown bundle guest, unknown FRI profile, or a witness of the wrong length |
| `-32001` | `unknown job` | `prover_status`/`prover_cancel` on an id the prover does not hold |
| `-32003` | `the job's token is not paired with this prover` | |
| `-32004` | `witness kind not accepted` | `data.reason`: spend-key witnesses refused (no `--accept-spend-key`); a spend-key witness for guest v3 (`a v3 guest takes nk — send a viewing-key witness`); or a viewing-key witness for guest v1/v2 (`this build's v1/v2 guests take a spend key`) |
| `-32005` | `busy` | `data: {depth, max}` — the pairing's cap or the queue is full |
| `-32006` | `the prover fee is not paid` | `data.reason`: the witness does not pay this prover's quoted fee, or a spend-key job to a prover that charges one (§3.5) |
| `-32007` | `origin not allowed` | any method, from a request whose `Origin` header is not on the allow-list (§6.1); answered before the body is read as a request, without CORS headers |

Admission runs cheap before expensive — size, open, pairing, the spend-key flag, guest, the
witness kind against the guest, profile, witness length, the fee, the pairing's cap, the queue's
cap — and a refused job is zeroized before the answer goes out.

### 6.3 The sealed job and reply

The job and the reply are sealed end to end, so a TLS proxy in front of the prover reads nothing
(`crates/randprotocol-prover/src/wire.rs`):

```
sealed  = kem_ct (1 088 B) ‖ nonce (12 B) ‖ ChaCha20-Poly1305(key, postcard(ProveJob), aad = "rand-prover-job-1")
key     = blake3::derive_key("rand-prover-request-1", ml_kem_768_shared_secret)

ProveJob   { version: 1, token: [u8; 32], witness_kind: SpendKey | ViewingKey,
             hc_bundle: Word8, profile: String,            // "test" | "production"
             binding: [u32; TX_BINDING_WORDS], inputs: Vec<u32>, reply_key: [u8; 32] }

reply   = nonce (12 B) ‖ ChaCha20-Poly1305(reply_key, postcard(ProveReply), aad = "rand-prover-reply-1")
ProveReply { proof: Vec<u8>, digest: Word8, tier: u8 }
```

- The KEM is ML-KEM-768 to the prover's `kem_ek`; the primitives are the note envelope's
  (`randprotocol_zkvm::viewing`), at the same pinned versions.
- A sealed job is at most `MAX_SEALED_JOB_BYTES`, 64 KiB; an honest one is about 5 KB
  (1 100 bytes of KEM ciphertext and nonce plus 1 204 witness words for guests v1/v2, 1 212 for
  v3 — `nk` in the spend key's place, plus the eight salt words).
- `reply_key` is 32 fresh random bytes per job, so only the wallet that sent the job opens the
  proof. The prover's job ids are its own 128 random bits.
- A job sealed to another prover's key fails authentication (`does not open under this key`);
  ML-KEM's implicit rejection never errors on its own.
- `inputs` must be exactly the bundle guest's witness length (`hidden_input::COUNT` = 1 204 for
  v1/v2, `hidden_input_v3::COUNT` = 1 212 for v3); `binding` is the transaction's binding words,
  over which the proof is made.
- Nothing binds a sealed job to one submission: anyone who captures one can replay it verbatim.
  That costs the pairing's per-token slots and one proof of the prover's time, and the reply is
  useless to the replayer — it is sealed to the wallet's `reply_key`.

### 6.4 The pairing link

```
randprover:<base58(kem_ek)>?url=<percent-encoded URL>&token=<64 hex>[&own=1]
```

The URL is percent-encoded except for RFC 3986's unreserved characters. A parser must refuse a
key that is not 1 184 bytes, a repeated parameter, a missing or empty `url`, a token that is not 64
hex digits, and any `own` value other than `1`; unknown parameters are ignored. It must also refuse
a `url` that, once percent-decoded, holds anything but printable ASCII (U+0021–U+007E): the URL is
the prover's to choose and the wallet shows it to its owner, so it may carry no control character
(a terminal escape, a newline), no bidi or other format character, no space and no non-ASCII text —
an internationalised host name is written in its `xn--` form. `rand-prover pair --url` refuses to
mint such a link, and the wallet prints a pairing's URL and name only through its display
sanitiser, like every other string a prover supplies. The fingerprint a
wallet shows and checks is `blake3("rand-prover-fingerprint-1" ‖ kem_ek)[..10]` in Crockford
base32, grouped `XXXX-XXXX-XXXX-XXXX` — its own domain, so it never collides in meaning with an
address fingerprint.

## 7. TLS

The `rand` wallet accepts a prover URL that is `https://` to any host, or plain `http://` only to
this machine: `localhost`, `127.0.0.1` or `[::1]`. A URL with a user name or password is refused
outright (`http://localhost:80@evil.com/` names `evil.com`), and the host checked is the one the
URL resolves to. The job is sealed either way, but the pairing token travels inside it, and the
timing and size of the reply are visible to anyone on the path.

`rand-prover` itself speaks plain HTTP and listens on `127.0.0.1:8600` by default. To reach it
from another machine on a LAN, or from a phone, put a TLS-terminating proxy in front of it — Caddy,
for example — and pair with the proxy's `https://` URL:

```
prover.example.net {
    reverse_proxy 127.0.0.1:8600
}
```

A `--listen` (or `--prover`) address off loopback needs that fronting proxy to terminate TLS and
to meter requests: the prover itself caps only jobs per pairing and its queue, not requests, and `prover_info` is
unauthenticated — anyone who reaches it learns the prover's key, backend, queue depth and
`witness_kinds` (whether it takes spend keys).

The origin allow-list (§6.1) is a browser rule, not access control: it stops a website the user
visits from reading the prover's key through the user's own browser — the fingerprinting a
desktop wallet's loopback listener would otherwise allow — and it does nothing against a client
that sends no `Origin`, or a forged one, over the network. A proxy in front of the prover passes
the browser's `Origin` through unchanged (Caddy's `reverse_proxy` does), so the list keeps
working behind it; a web wallet served from its own `https://` origin needs that origin added with
`--allow-origin`, and `*` is never needed for it.

Known limitation: Chrome's Private Network Access sends a preflight with
`Access-Control-Request-Private-Network: true` when a public `https://` page calls a loopback
address, and blocks the call unless the reply carries `Access-Control-Allow-Private-Network: true`.
This build never sends that header, so a public web wallet cannot reach a prover on the user's own
`127.0.0.1` from Chrome even with its origin on the list; extension and `localhost` wallets are
unaffected, and a web wallet can reach a prover behind an `https://` proxy (above).

A certificate a browser or phone accepts on a LAN is the operator's to arrange; whether a desktop
app should carry a relay instead is spec §8 open question 4, unresolved.

## 8. What Phase 2 changes

Phase 2 (spec §4, v0.6.3) moves the spend key out of the bundle guest into a second, tiny proof the
light wallet makes itself: the auth guest reads `sk` and a fresh salt and publishes
`c = H(AUTH, nk, salt)`, proved against the transaction's binding; bundle guest v3 takes `nk` and
the same salt instead of `sk`, derives `pk_self` from `nk`, and folds the same `c` into its digest.
The bundle carries `c` as `auth_commit` and the auth proof as `auth_proof`, and the ledger admits
it only when the auth proof verifies against the pinned auth guest and the same binding and
publishes `auth_commit` (`docs/shielded.md` §2). A prover then holds `nk` — enough to prove the
bundle and to read the wallet's whole history, not enough to spend — so anyone may run one, and
`witness_kind: ViewingKey` is the normal job: every prover from v0.6.3 accepts it for guest v3 (§2,
§6.1). A wallet that proves for itself makes both proofs too, so a self-proved and a delegated
transaction look the same on chain.

It is a hard fork, selected at genesis by `rand-node genesis --bundle-guest v3 --auth-guest`:
`hc_bundle` `60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce` (v3) and `hc_auth`
`1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1` (both pinned in
`crates/randprotocol-zkvm/tests/guest_provenance.rs`); `rand_status` and `rand_getLimits` serve
`hc_auth`. The v0.6.3 build runs chain 17 on and refuses chains 14–16 (`docs/rpc.md`, changelog).

Measured (spec §4.2): the auth proof is tier 10, about 1.37 MB at Production FRI (313 KB at Test)
and about 7 s to prove on one laptop core; in the wallet-flow test (Test FRI profile) a v3 bundle
proof took 102 s on the wallet's machine and 108 s through a paired prover. A v3 transfer carries both proofs, about
2.85 MB at Production FRI (1.36 MB auth + 1.49 MB bundle in one measured run): one per block at the 4 MiB default and no `Call`, about seven at the 20 MiB `max_block_bytes` chains 15
and 16 set. A v3 transaction carries three proofs at most (bundle, auth, call), so the genesis block
cap must hold `3·max_proof_bytes + 1 MiB` (`Genesis::validate` refuses a `hc_auth` genesis below it,
the 4 MiB default included): a 4 MiB block admits transfers but no `Call` at Production FRI. The implementation plan is `docs/superpowers/plans/2026-09-28-delegated-proving-phase2.md`.
