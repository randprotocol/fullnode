#!/usr/bin/env python3
"""The trusted provers' router: one `prover_*` JSON-RPC endpoint in front of several provers.

`prover.randprotocol.org` names a pool, not a machine. Every prover in the pool runs with the SAME
prover key and pairing store (`rand-prover --home`), so a job sealed to the pool's key opens on any
of them; what a load balancer cannot know is where a job lives once it is submitted, and a bundle
proof has about 256 blocks to land (`ledger::TIME_WINDOW`), so a job that waits in one prover's
queue while another prover idles is a transaction that may expire. This router therefore reads each
request's method:

- `prover_submit` goes to the least loaded prover that answers; a prover that answers `busy`
  (-32005) or does not answer is skipped, and the job id it returns is remembered with its prover;
- `prover_status` / `prover_cancel` go to the prover that holds the job (asked around once if the
  router restarted in between);
- `prover_info` is any prover's answer with `queue` replaced by the pool's sums;
- anything else, and every `OPTIONS` preflight, goes to one prover unchanged.

Since the move to per-member keys (audit v7, VK-9) each member also has its own path,
`/m/<name>`, which a wallet that pinned the pool descriptor uses: a job sealed to one member's key
can only go to that member, so those requests are passed to it as they are. The root path above
serves the retiring shared key (wallet 0.6.8).

It opens nothing: jobs and replies are sealed end to end (docs/prover.md §6.3) and pass through as
bytes. It authorises nothing either — the provers check the pairing token and the origin
allow-list; the `Origin` header and the CORS reply headers are relayed untouched. nginx meters
every request per address; this router also meters `prover_submit` per address across the whole
pool (audit v7, VK-10): every token is public, so a slot is the only thing a flood can take, and a
wallet submits once per send.

Python 3 standard library only. Configuration, all environment:

  PROVER_BACKENDS   the shared-key backends behind `/`, comma-separated base URLs
  PROVER_MEMBERS    the members behind `/m/<name>`, comma-separated name=url
  SUBMIT_BURST      submits one address may make at once (default 6)
  SUBMIT_PER_MIN    and their refill per minute (default 3)
  ROUTER_LISTEN     ip:port to listen on (default 127.0.0.1:8650)

The client address is nginx's X-Real-IP (the router listens on loopback only).
"""

import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# `http.rs`'s MAX_BODY_BYTES: twice MAX_SEALED_JOB_BYTES (64 KiB) for the hex, plus 4 KiB.
MAX_BODY_BYTES = 2 * 65536 + 4096
BUSY = -32005
UNKNOWN_JOB = -32001
# A finished job is forgotten by its prover 20 minutes after it ends and a wallet waits at most
# 50 (30 queued + 20 proving); an hour covers both.
JOB_TTL_SECS = 3600
MAX_JOBS = 200_000
POLL_SECS = 2.0
BACKEND_TIMEOUT_SECS = 10.0
RELAYED_REPLY_HEADERS = (
    "content-type",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-max-age",
    "vary",
)
FORWARDED_REQUEST_HEADERS = (
    "content-type",
    "origin",
    "access-control-request-method",
    "access-control-request-headers",
)


class SubmitMeter:
    """A token bucket per client address for `prover_submit` (VK-10). Bounded: past MAX_CLIENTS
    addresses the stalest half is dropped, which can only ever be generous."""

    MAX_CLIENTS = 100_000

    def __init__(self, burst, per_min):
        self.burst = float(burst)
        self.rate = per_min / 60.0
        self.lock = threading.Lock()
        self.buckets = {}  # address -> (tokens, last)

    def allow(self, address, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            tokens, last = self.buckets.get(address, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self.buckets[address] = (tokens, now)
                return False
            self.buckets[address] = (tokens - 1.0, now)
            if len(self.buckets) > self.MAX_CLIENTS:
                for addr, _ in sorted(self.buckets.items(), key=lambda kv: kv[1][1])[: self.MAX_CLIENTS // 2]:
                    del self.buckets[addr]
            return True


def rate_limited(req_id):
    """The answer to a submit over its address's budget: `busy`, which a wallet reads as "try the
    next member" and, when every member says it, as "busy, try again later"."""
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": BUSY, "message": "busy", "data": {"reason": "too many submissions from this address; try again in a minute"}}}


class Backend:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.up = False
        self.depth = 0
        self.proving = 0
        self.max_queue = 0
        # Jobs this router sent since the last poll: the poll is two seconds stale, and two
        # submits inside one interval must not both pick the same "idle" prover.
        self.sent_since_poll = 0

    def load(self):
        return self.depth + self.proving + self.sent_since_poll


class Pool:
    def __init__(self, urls):
        self.backends = [Backend(u) for u in urls]
        self.lock = threading.Lock()
        self.jobs = {}  # job id -> (backend, expiry)

    # -- one HTTP exchange with one prover -------------------------------------------------

    def exchange(self, backend, method, body, headers):
        """Returns (status, reply headers, reply body), or None when the prover did not answer."""
        req = urllib.request.Request(backend.url + "/", data=body, method=method)
        for name in FORWARDED_REQUEST_HEADERS:
            if headers.get(name) is not None:
                req.add_header(name, headers.get(name))
        try:
            with urllib.request.urlopen(req, timeout=BACKEND_TIMEOUT_SECS) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:  # a 403 preflight, a 413: the prover's own answer
            return e.code, e.headers, e.read()
        except (urllib.error.URLError, OSError, ValueError):
            with self.lock:
                backend.up = False
            return None

    # -- the two-second poll ---------------------------------------------------------------

    def poll_once(self):
        body = b'{"jsonrpc":"2.0","id":0,"method":"prover_info","params":[]}'
        for b in self.backends:
            got = self.exchange(b, "POST", body, {"content-type": "application/json"})
            up, depth, proving, max_queue = False, 0, 0, 0
            if got is not None and got[0] == 200:
                try:
                    q = json.loads(got[2])["result"]["queue"]
                    up, depth, proving, max_queue = True, int(q["depth"]), int(q["proving"]), int(q["max"])
                except (ValueError, KeyError, TypeError):
                    pass
            with self.lock:
                b.up, b.depth, b.proving, b.max_queue, b.sent_since_poll = up, depth, proving, max_queue, 0
        now = time.monotonic()
        with self.lock:
            for job in [j for j, (_, exp) in self.jobs.items() if exp < now]:
                del self.jobs[job]

    def poll_forever(self):
        while True:
            try:
                self.poll_once()
            except Exception as e:  # never let the poller die
                print(f"poll: {e!r}", file=sys.stderr, flush=True)
            time.sleep(POLL_SECS)

    # -- routing ---------------------------------------------------------------------------

    def by_load(self):
        with self.lock:
            live = [b for b in self.backends if b.up]
            random.shuffle(live)  # ties go to a random prover, not always the first
            return sorted(live, key=lambda b: b.load())

    def by_load_all(self):
        """Every member, the ones the poll last saw up first: a member that just came back must
        still be asked for a job it may hold."""
        with self.lock:
            members = list(self.backends)
        return sorted(members, key=lambda b: (not b.up, b.load()))

    def remember(self, job, backend):
        with self.lock:
            if len(self.jobs) >= MAX_JOBS:
                oldest = min(self.jobs, key=lambda j: self.jobs[j][1])
                del self.jobs[oldest]
            self.jobs[job] = (backend, time.monotonic() + JOB_TTL_SECS)

    def holder(self, job):
        with self.lock:
            got = self.jobs.get(job)
        return got[0] if got else None

    def submit(self, body, headers):
        last = None
        for b in self.by_load():
            got = self.exchange(b, "POST", body, headers)
            if got is None:
                continue
            last = got
            reply = parse(got[2])
            if error_code(reply) == BUSY:
                continue
            job = reply.get("result", {}).get("job") if isinstance(reply, dict) and isinstance(reply.get("result"), dict) else None
            if isinstance(job, str):
                self.remember(job, b)
                with self.lock:
                    b.sent_since_poll += 1
            return got
        return last  # every prover busy: the last `busy` answer, or None when none answered

    def about_job(self, job, body, headers):
        b = self.holder(job)
        if b is not None:
            # Only the holder can answer for its job. If it does not answer, that is an outage the
            # wallet waits out and retries (docs/prover.md §5.2), never the other members' `unknown
            # job`, which a wallet reads as final (seen 2026-10-01: a member wedged mid-proof, and
            # the first status poll came back `unknown job`, so the send was abandoned).
            return self.exchange(b, "POST", body, headers)
        # The router restarted and forgot the job: ask every member. One that holds it answers for
        # it; `unknown job` is only the answer when every member answered and none holds it.
        silent = False
        last = None
        for b in self.by_load_all():
            got = self.exchange(b, "POST", body, headers)
            if got is None:
                silent = True
                continue
            last = got
            if error_code(parse(got[2])) != UNKNOWN_JOB:
                self.remember(job, b)
                return got
        return None if silent else last

    def info(self, body, headers):
        for b in self.by_load():
            got = self.exchange(b, "POST", body, headers)
            if got is None:
                continue
            reply = parse(got[2])
            if isinstance(reply, dict) and isinstance(reply.get("result"), dict) and "queue" in reply["result"]:
                with self.lock:
                    live = [x for x in self.backends if x.up]
                    reply["result"]["queue"] = {
                        "depth": sum(x.depth for x in live),
                        "max": sum(x.max_queue for x in live),
                        "proving": sum(x.proving for x in live),
                    }
                return got[0], got[1], json.dumps(reply).encode()
            return got
        return None

    def any(self, method, body, headers):
        for b in self.by_load():
            got = self.exchange(b, method, body, headers)
            if got is not None:
                return got
        return None

    def route(self, body, headers):
        req = parse(body)
        method = req.get("method") if isinstance(req, dict) else None
        params = req.get("params") if isinstance(req, dict) else None
        if method == "prover_submit":
            return self.submit(body, headers)
        if method in ("prover_status", "prover_cancel") and isinstance(params, list) and len(params) == 1 and isinstance(params[0], str):
            return self.about_job(params[0], body, headers)
        if method == "prover_info":
            return self.info(body, headers)
        return self.any("POST", body, headers)  # malformed or unknown: a prover's own error


def parse(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return None


def error_code(reply):
    if isinstance(reply, dict) and isinstance(reply.get("error"), dict):
        return reply["error"].get("code")
    return None


def make_handler(pool, members=None, meter=None):
    members = members or {}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "rand-prover-router"
        sys_version = ""
        timeout = 30  # a client that stops mid-request does not hold a thread for ever

        def log_message(self, fmt, *args):  # no per-request log: who proves when is not ours to keep
            pass

        def relay(self, got):
            if got is None:
                # A plain-text 503, like any proxy's error page, never a JSON-RPC error: a wallet
                # treats a JSON-RPC error as the prover's final word and abandons the job, and an
                # error page as an outage it waits out.
                body = b"no prover in the pool answered\n"
                self.send_response(503)
                self.send_header("content-type", "text/plain")
                self.send_header("retry-after", "2")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            status, headers, body = got
            self.send_response(status)
            for name in RELAYED_REPLY_HEADERS:
                for value in headers.get_all(name) or []:
                    self.send_header(name, value)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def plain(self, status, obj):
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def member(self):
            """The member a `/m/<name>` path names, `None` for the root path, or False when the
            path names no member."""
            path = self.path.split("?", 1)[0]
            if path in ("/", ""):
                return None
            if path.startswith("/m/") and path[3:] in members:
                return members[path[3:]]
            return False

        def do_OPTIONS(self):
            m = self.member()
            if m is False:
                return self.not_found()
            self.relay(pool.any("OPTIONS", None, self.headers) if m is None else pool.exchange(m, "OPTIONS", None, self.headers))

        def not_found(self):
            self.send_response(404)
            self.send_header("content-length", "0")
            self.end_headers()

        def do_POST(self):
            try:
                length = int(self.headers.get("content-length", ""))
            except ValueError:
                self.close_connection = True
                self.plain(411, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "content-length required"}})
                return
            if length < 0 or length > MAX_BODY_BYTES:
                self.close_connection = True
                self.plain(413, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": f"request body is larger than the {MAX_BODY_BYTES}-byte limit"}})
                return
            body = self.rfile.read(length)
            m = self.member()
            if m is False:
                return self.not_found()
            req = parse(body)
            if meter is not None and isinstance(req, dict) and req.get("method") == "prover_submit":
                address = self.headers.get("x-real-ip") or self.client_address[0]
                if not meter.allow(address):
                    return self.plain(200, rate_limited(req.get("id")))
            self.relay(pool.route(body, self.headers) if m is None else pool.exchange(m, "POST", body, self.headers))

        def do_GET(self):
            self.send_response(405)
            self.send_header("allow", "POST, OPTIONS")
            self.send_header("content-length", "0")
            self.end_headers()

    return Handler


def main():
    urls = [u.strip() for u in os.environ.get("PROVER_BACKENDS", "").split(",") if u.strip()]
    members = {}
    for item in os.environ.get("PROVER_MEMBERS", "").split(","):
        if "=" in item:
            name, url = item.split("=", 1)
            members[name.strip()] = Backend(url.strip())
    if not urls and not members:
        sys.exit("PROVER_BACKENDS and PROVER_MEMBERS are empty: name at least one prover")
    host, _, port = os.environ.get("ROUTER_LISTEN", "127.0.0.1:8650").rpartition(":")
    pool = Pool(urls)
    pool.poll_once()
    threading.Thread(target=pool.poll_forever, daemon=True).start()
    meter = SubmitMeter(int(os.environ.get("SUBMIT_BURST", "6")), float(os.environ.get("SUBMIT_PER_MIN", "3")))
    server = ThreadingHTTPServer((host, int(port)), make_handler(pool, members, meter))
    server.daemon_threads = True
    print(f"routing {len(urls)} shared-key prover(s) and {len(members)} member(s) on {host}:{port}", file=sys.stderr, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
