#!/usr/bin/env python3
"""Tests of router.py against fake provers. Run: python3 deploy/prover/test_router.py"""

import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import router  # noqa: E402


class FakeProver:
    """A prover that answers the four methods from a little state, like `http.rs` does."""

    def __init__(self, name, max_queue=8, allowed_origin="chrome-extension://abc"):
        self.name = name
        self.depth = 0
        self.proving = 0
        self.max_queue = max_queue
        self.busy = False
        self.jobs = {}
        self.submits = 0
        self.allowed_origin = allowed_origin
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def cors(self):
                origin = self.headers.get("origin")
                if origin is None:
                    return "absent"
                return "allowed" if origin == fake.allowed_origin else "refused"

            def do_OPTIONS(self):
                if self.cors() != "allowed":
                    self.send_response(403)
                    self.send_header("content-length", "0")
                    self.end_headers()
                    return
                self.send_response(204)
                self.send_header("access-control-allow-origin", self.headers.get("origin"))
                self.send_header("vary", "Origin")
                self.send_header("access-control-allow-methods", "POST, OPTIONS")
                self.send_header("access-control-allow-headers", "content-type")
                self.send_header("access-control-max-age", "86400")
                self.end_headers()

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                cors = self.cors()
                try:
                    req = json.loads(body)
                except ValueError:
                    return self.reply({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}, cors)
                if cors == "refused":
                    return self.reply({"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32007, "message": "origin not allowed"}}, cors)
                m, p = req.get("method"), req.get("params")
                if m == "prover_info":
                    out = {"result": {"kem_fingerprint": "POOL-KEY", "served_by": fake.name,
                                      "queue": {"depth": fake.depth, "max": fake.max_queue, "proving": fake.proving}}}
                elif m == "prover_submit":
                    fake.submits += 1
                    if fake.busy:
                        out = {"error": {"code": -32005, "message": "busy", "data": {"depth": fake.depth, "max": fake.max_queue}}}
                    else:
                        job = f"{fake.name}-job-{len(fake.jobs)}"
                        fake.jobs[job] = "queued"
                        fake.proving += 1
                        out = {"result": {"job": job}}
                elif m in ("prover_status", "prover_cancel"):
                    if p[0] in fake.jobs:
                        out = {"result": {"state": fake.jobs[p[0]], "held_by": fake.name}}
                    else:
                        out = {"error": {"code": -32001, "message": "unknown job"}}
                else:
                    out = {"error": {"code": -32601, "message": "method not found"}}
                out.update({"jsonrpc": "2.0", "id": req.get("id")})
                self.reply(out, cors)

            def reply(self, obj, cors):
                raw = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                if cors == "allowed":
                    self.send_header("access-control-allow-origin", self.headers.get("origin"))
                    self.send_header("vary", "Origin")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class RouterTest(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.c = FakeProver("a"), FakeProver("b"), FakeProver("c")
        self.pool = router.Pool([self.a.url, self.b.url, self.c.url])
        self.pool.poll_once()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), router.make_handler(self.pool))
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        for f in (self.a, self.b, self.c):
            try:
                f.stop()
            except Exception:
                pass

    def call(self, method, params=None, origin=None, raw=None):
        body = raw if raw is not None else json.dumps({"jsonrpc": "2.0", "id": 7, "method": method, "params": params or []}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={"content-type": "application/json"})
        if origin:
            req.add_header("origin", origin)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.headers, json.loads(r.read())
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, e.headers, json.loads(raw or b"null")
            except ValueError:
                return e.code, e.headers, None

    def test_a_submit_goes_to_the_least_loaded_prover(self):
        self.a.depth, self.b.depth, self.c.depth = 3, 0, 2
        self.pool.poll_once()
        _, _, r = self.call("prover_submit", ["00"])
        self.assertTrue(r["result"]["job"].startswith("b-"), r)

    def test_two_submits_inside_one_poll_interval_do_not_pile_on_one_prover(self):
        jobs = [self.call("prover_submit", ["00"])[2]["result"]["job"] for _ in range(3)]
        self.assertEqual(sorted(j[0] for j in jobs), ["a", "b", "c"], jobs)

    def test_a_busy_prover_is_skipped_and_the_job_lands_on_the_next(self):
        self.a.busy = self.b.busy = True
        _, _, r = self.call("prover_submit", ["00"])
        self.assertTrue(r["result"]["job"].startswith("c-"), r)

    def test_every_prover_busy_answers_busy(self):
        self.a.busy = self.b.busy = self.c.busy = True
        _, _, r = self.call("prover_submit", ["00"])
        self.assertEqual(r["error"]["code"], -32005, r)
        self.assertEqual(self.a.submits + self.b.submits + self.c.submits, 3)

    def test_status_and_cancel_go_to_the_prover_that_holds_the_job(self):
        self.a.busy = self.c.busy = True
        job = self.call("prover_submit", ["00"])[2]["result"]["job"]
        for m in ("prover_status", "prover_cancel"):
            _, _, r = self.call(m, [job])
            self.assertEqual(r["result"]["held_by"], "b", r)

    def test_a_job_the_router_forgot_is_found_by_asking_around(self):
        self.c.jobs["lost"] = "proving"
        _, _, r = self.call("prover_status", ["lost"])
        self.assertEqual(r["result"]["held_by"], "c", r)
        self.assertIs(self.pool.holder("lost").url, self.pool.backends[2].url)

    def test_a_job_nobody_holds_is_unknown(self):
        _, _, r = self.call("prover_status", ["nope"])
        self.assertEqual(r["error"]["code"], -32001, r)

    def test_a_dead_prover_is_skipped(self):
        self.a.stop()
        self.b.busy = True
        _, _, r = self.call("prover_submit", ["00"])
        self.assertTrue(r["result"]["job"].startswith("c-"), r)

    def test_no_prover_answering_is_a_plain_503(self):
        for f in (self.a, self.b, self.c):
            f.stop()
        status, h, r = self.call("prover_submit", ["00"])
        self.assertEqual(status, 503)
        self.assertEqual(h.get("content-type"), "text/plain")
        self.assertIsNone(r, "an error page, not a JSON-RPC error a wallet would take as final")

    def test_a_job_whose_holder_stops_answering_is_an_outage_not_unknown(self):
        # 2026-10-01: a member wedged mid-proof, the router asked the others, they answered
        # `unknown job`, and the wallet abandoned a job that was only waiting on its holder.
        self.a.busy = self.c.busy = True
        job = self.call("prover_submit", ["00"])[2]["result"]["job"]
        self.b.stop()
        status, _, r = self.call("prover_status", [job])
        self.assertEqual(status, 503)
        self.assertIsNone(r)

    def test_a_forgotten_job_with_a_member_silent_is_an_outage_not_unknown(self):
        self.c.stop()
        status, _, r = self.call("prover_status", ["held-by-the-silent-one"])
        self.assertEqual(status, 503)
        self.assertIsNone(r)

    def test_info_reports_the_pools_queue(self):
        self.a.depth, self.b.depth, self.b.proving, self.c.proving = 1, 2, 1, 1
        self.pool.poll_once()
        _, _, r = self.call("prover_info")
        self.assertEqual(r["result"]["queue"], {"depth": 3, "max": 24, "proving": 2}, r)
        self.assertEqual(r["result"]["kem_fingerprint"], "POOL-KEY")

    def test_the_origin_and_the_cors_headers_pass_through_both_ways(self):
        _, h, r = self.call("prover_info", origin="chrome-extension://abc")
        self.assertEqual(h.get("access-control-allow-origin"), "chrome-extension://abc")
        self.assertEqual(h.get("vary"), "Origin")
        self.assertIn("result", r)
        _, h, r = self.call("prover_info", origin="https://evil.example")
        self.assertIsNone(h.get("access-control-allow-origin"))
        self.assertEqual(r["error"]["code"], -32007, r)

    def test_a_preflight_is_the_provers_own_answer(self):
        def preflight(origin):
            req = urllib.request.Request(self.url, method="OPTIONS", headers={"origin": origin, "access-control-request-method": "POST"})
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status, r.headers
            except urllib.error.HTTPError as e:
                return e.code, e.headers
        status, h = preflight("chrome-extension://abc")
        self.assertEqual((status, h.get("access-control-allow-origin"), h.get("access-control-max-age")), (204, "chrome-extension://abc", "86400"))
        status, h = preflight("https://evil.example")
        self.assertEqual((status, h.get("access-control-allow-origin")), (403, None))

    def test_a_malformed_body_gets_a_provers_parse_error(self):
        _, _, r = self.call(None, raw=b"{not json")
        self.assertEqual(r["error"]["code"], -32700, r)

    def test_an_oversized_body_is_refused_before_any_prover_sees_it(self):
        status, _, r = self.call(None, raw=b"x" * (router.MAX_BODY_BYTES + 1))
        self.assertEqual(status, 413)
        self.assertEqual(self.a.submits + self.b.submits + self.c.submits, 0)
        self.assertIn("larger than", r["error"]["message"])


if __name__ == "__main__":
    unittest.main()
