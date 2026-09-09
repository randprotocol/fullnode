#!/usr/bin/env python3
"""One audit tick for the chain-4 testnet: send 10 SHRUGG to a fresh random
address, then verify every reachable validator node reports the same state
(state_root at a common height) and the same total balance over every address
ever touched, equal to genesis allocation + observed mints (fees are paid to
block proposers, so total supply is conserved).

State in audit-state.json, log in shrugg-audit.log (both repo-root, untracked).
Exit 0 on PASS, 1 on invariant FAILURE, 2 on stall/infra problems.
"""
import json, os, subprocess, sys, tempfile, time, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHRUGG = os.path.join(ROOT, "target/release/shrugg")
STATE = os.path.join(ROOT, "audit-state.json")
LOG = os.path.join(ROOT, "shrugg-audit.log")
WALLET = os.path.join(ROOT, "audit-wallet.key.json")
GENESIS = os.path.join(ROOT, "deploy/genesis.json")
SSH_KEY = os.path.expanduser("~/.ssh/id_ed25519")
UNITS = 10**9
SEND_SHRUGG = "10"
REMOTE_NODES = {"C": "167.172.65.63", "D": "178.128.91.236"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")


def rpc_local(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    out = subprocess.run(["curl", "-s", "-m", "10", "-X", "POST", "127.0.0.1:8545",
                          "-H", "content-type: application/json", "-d", body],
                         capture_output=True, text=True, timeout=20)
    r = json.loads(out.stdout)
    if "error" in r:
        raise RuntimeError(f"{method}: {r['error']}")
    return r["result"]


def rpc_batch_remote(ip, requests):
    """Run many JSON-RPC calls on a remote node's localhost RPC via one ssh."""
    payload = "\n".join(json.dumps({"jsonrpc": "2.0", "id": i, "method": m, "params": p})
                        for i, (m, p) in enumerate(requests))
    script = ("while IFS= read -r line; do curl -s -m 10 -X POST 127.0.0.1:8545 "
              "-H 'content-type: application/json' -d \"$line\"; echo; done")
    out = subprocess.run(["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=accept-new",
                          "-o", "ConnectTimeout=10", f"root@{ip}", script],
                         input=payload, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(f"ssh {ip}: {out.stderr.strip().splitlines()[-1] if out.stderr else 'failed'}")
    results = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if "error" in r:
            raise RuntimeError(f"{ip} rpc error: {r['error']}")
        results.append(r["result"])
    if len(results) != len(requests):
        raise RuntimeError(f"{ip}: expected {len(requests)} rpc results, got {len(results)}")
    return results


def wallet_cmd(*args, key=WALLET, timeout=90):
    out = subprocess.run([SHRUGG, "--key", key, *args], capture_output=True, text=True, timeout=timeout)
    return out.returncode, (out.stdout + out.stderr).strip()


def load_state():
    if os.path.exists(STATE):
        with open(STATE) as f:
            return json.load(f)
    gen = json.load(open(GENESIS))
    return {"last_scanned": 0, "mint_total": 0,
            "genesis_total": sum(gen["alloc"].values()),
            "addresses": sorted(gen["alloc"].keys()),
            "last_height": 0}


def save_state(st):
    with open(STATE, "w") as f:
        json.dump(st, f, indent=1)


def scan_blocks(st, head_height):
    addrs = set(st["addresses"])
    for h in range(st["last_scanned"] + 1, head_height + 1):
        blk = rpc_local("shrugg_getBlockByHeight", [h])
        if blk is None:
            break
        if blk.get("proposer"):
            addrs.add(blk["proposer"])
        for tx in blk.get("transactions", []):
            addrs.add(tx["from"])
            k = tx["kind"]
            if k["type"] in ("transfer", "mint"):
                addrs.add(k["to"])
                if k["type"] == "mint":
                    st["mint_total"] += int(k["amount"])
            for rec in k.get("recipients", []):
                addrs.add(rec)
        st["last_scanned"] = h
    st["addresses"] = sorted(addrs)


def audit_node(name, addrs, common_h, ip=None):
    reqs = [("shrugg_getBlockByHeight", [common_h])] + [("shrugg_getBalance", [a]) for a in addrs]
    if ip is None:
        res = [rpc_local(m, p) for m, p in reqs]
    else:
        res = rpc_batch_remote(ip, reqs)
    blk = res[0]
    total = sum(int(b) for b in res[1:])
    return {"node": name, "height_at": common_h,
            "block_hash": blk and blk["hash"], "state_root": blk and blk["state_root"],
            "total": total}


def main():
    record = {"ts": now(), "status": "PASS", "notes": []}
    st = load_state()

    head = rpc_local("shrugg_getHead", [])
    stalled = head["height"] <= st.get("last_height", 0) and head["view"] - head["height"] > 50
    record["head_before"] = head

    # 1. make sure the audit wallet exists and is funded
    if not os.path.exists(WALLET):
        wallet_cmd("keygen")
        record["notes"].append("created audit wallet")
    rc, out = wallet_cmd("balance")
    bal = 0
    for line in out.splitlines():
        if line.startswith("balance:"):
            bal = float(line.split()[1])
    if bal < 15 and not stalled:
        rc, out = wallet_cmd("faucet", timeout=120)
        record["notes"].append(f"faucet: rc={rc} {out.splitlines()[-1] if out else ''}")

    # 2. send 10 SHRUGG to a fresh random address
    if stalled:
        record["status"] = "STALLED"
        record["notes"].append(f"chain stalled: height {head['height']} view {head['view']}; skipping send")
    else:
        with tempfile.TemporaryDirectory() as td:
            tmp = os.path.join(td, "r.key.json")
            wallet_cmd("keygen", key=tmp)
            _, to_addr = wallet_cmd("address", key=tmp)
        rc, out = wallet_cmd("send", to_addr, SEND_SHRUGG, timeout=120)
        record["send"] = {"to": to_addr, "amount": SEND_SHRUGG, "rc": rc,
                          "result": out.splitlines()[-1] if out else ""}
        if rc != 0:
            record["status"] = "SEND_FAILED"

    # 3. balance audit across nodes
    head = rpc_local("shrugg_getHead", [])
    record["head_after"] = head
    st["last_height"] = head["height"]
    scan_blocks(st, head["height"])
    expected = st["genesis_total"] + st["mint_total"]
    record["expected_total"] = expected
    record["n_addresses"] = len(st["addresses"])

    for attempt in range(3):
        nodes = []
        heights = {"B": rpc_local("shrugg_getHead", [])["height"]}
        remote_ok = {}
        for name, ip in REMOTE_NODES.items():
            try:
                heights[name] = rpc_batch_remote(ip, [("shrugg_getHead", [])])[0]["height"]
                remote_ok[name] = ip
            except Exception as e:
                record["notes"].append(f"node {name} unreachable: {e}")
        common_h = min(heights.values())
        try:
            nodes.append(audit_node("B", st["addresses"], common_h))
            for name, ip in remote_ok.items():
                nodes.append(audit_node(name, st["addresses"], common_h, ip))
        except Exception as e:
            record["notes"].append(f"audit attempt {attempt}: {e}")
            time.sleep(3)
            continue
        record["nodes"] = nodes
        roots = {n["state_root"] for n in nodes}
        totals = {n["total"] for n in nodes}
        if len(roots) == 1 and len(totals) == 1 and totals == {expected}:
            break  # all nodes agree and supply is conserved
        # a commit may have landed mid-scan; rescan mints and retry
        newh = rpc_local("shrugg_getHead", [])["height"]
        scan_blocks(st, newh)
        expected = st["genesis_total"] + st["mint_total"]
        record["expected_total"] = expected
        time.sleep(3)
    else:
        pass

    if "nodes" in record:
        roots = {n["state_root"] for n in record["nodes"]}
        totals = {n["total"] for n in record["nodes"]}
        if len(roots) != 1:
            record["status"] = "FAIL_STATE_ROOT_MISMATCH"
        elif len(totals) != 1:
            record["status"] = "FAIL_TOTALS_DIFFER_ACROSS_NODES"
        elif totals != {expected}:
            record["status"] = "FAIL_SUPPLY_NOT_CONSERVED"
    elif record["status"] == "PASS":
        record["status"] = "AUDIT_INCOMPLETE"

    save_state(st)
    with open(LOG, "a") as f:
        f.write(json.dumps(record) + "\n")

    n_nodes = len(record.get("nodes", []))
    tot = record.get("nodes", [{}])[0].get("total") if n_nodes else None
    print(f"[{record['ts']}] {record['status']} height={head['height']} nodes_checked={n_nodes} "
          f"total={tot} expected={expected} addrs={record['n_addresses']}")
    for note in record["notes"]:
        print("  note:", note)
    if record["status"].startswith("FAIL"):
        sys.exit(1)
    if record["status"] in ("STALLED", "SEND_FAILED", "AUDIT_INCOMPLETE"):
        sys.exit(2)


if __name__ == "__main__":
    main()
