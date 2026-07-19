#!/usr/bin/env python3
"""E2E 抓包分析：验证 trafficgen 多场景下包序正确性。"""
import json
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error

IFACE = "enp135s0f0np0"
BASE = "http://localhost:8080"
TOKEN = None

def login():
    global TOKEN
    body = json.dumps({"username": "admin", "password": "admin"}).encode()
    req = urllib.request.Request(f"{BASE}/api/v1/auth/login", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        TOKEN = json.loads(r.read())["data"]["token"]

def api(method, path, body=None):
    url = f"{BASE}/api/v1{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {TOKEN}",
    })
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read().decode()}

def capture_start(pcap_path, filter_expr="tcp or udp"):
    proc = subprocess.Popen(
        ["tcpdump", "-i", IFACE, "-w", pcap_path, "-U", "-s", "0", "-Z", "root", filter_expr],
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)
    return proc

def capture_stop(proc):
    proc.send_signal(signal.SIGINT)
    proc.wait(timeout=5)

def parse_pcap(pcap_path):
    out = subprocess.run(
        ["tcpdump", "-r", pcap_path, "-nn", "-tttt", "-S", "-A"],
        capture_output=True, text=True, timeout=30,
    ).stdout
    packets = []
    cur = None
    for line in out.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line[0:4].isdigit() and "." in line[:30]:
            if cur:
                packets.append(cur)
            cur = {"ts": line[:23], "raw": line, "payload": "", "flags": "", "seq": "", "ack": "", "src_dst": ""}
            rest = line[24:]
            if " > " in rest:
                src_dst = rest.split(" > ", 1)[1]
                cur["src_dst"] = src_dst
                if "Flags [" in src_dst:
                    cur["flags"] = src_dst.split("Flags [", 1)[1].split("]", 1)[0]
                if "seq " in src_dst:
                    cur["seq"] = src_dst.split("seq ", 1)[1].split(",", 1)[0].strip()
                if "ack " in src_dst:
                    cur["ack"] = src_dst.split("ack ", 1)[1].split(",", 1)[0].strip()
        else:
            if cur is not None:
                cur["payload"] += line + "\n"
    if cur:
        packets.append(cur)
    return packets

def flow_key(p):
    # Use the full raw line which contains "src > dst: Flags..."
    raw = p.get("raw", "")
    if " > " not in raw:
        return None
    # Extract "IP src > dst:" segment
    parts = raw.split(" IP ", 1)
    if len(parts) != 2:
        return None
    after_ip = parts[1]
    # after_ip = "10.0.0.1.40000 > 10.0.0.2.80: Flags [S]..."
    src_dst_pair = after_ip.split(": ", 1)[0]  # "10.0.0.1.40000 > 10.0.0.2.80"
    if " > " not in src_dst_pair:
        return None
    s, d = src_dst_pair.split(" > ", 1)
    a = tuple(s.rsplit(".", 1))
    b = tuple(d.rsplit(".", 1))
    lo, hi = (a, b) if a < b else (b, a)
    return f"{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}"

def test_single_tcp():
    print("\n=== Scenario 1: Single TCP flow ===")
    r = api("POST", "/strategies", {
        "name": "e2e-tcp", "mode": "synth", "protocol": "tcp",
        "config": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                   "src_port": 11111, "dst_port": 80,
                   "tcp": {"handshake": True, "termination": True}},
    })
    sid = r["data"]["id"]
    r = api("POST", "/tasks", {
        "name": "e2e-tcp-task", "strategy_ids": [sid],
        "output_type": "port_group", "output_config": {"port_group_id": "33ddf949-b68a-456a-b32b-195690c29f93"},
    })
    tid = r["data"]["id"]
    cap = capture_start("/tmp/e2e-tcp-nic.pcap")
    api("POST", f"/tasks/{tid}/start")
    time.sleep(2)
    capture_stop(cap)
    pkts = parse_pcap("/tmp/e2e-tcp-nic.pcap")
    print(f"  captured {len(pkts)} packets")
    flows = {}
    for p in pkts:
        k = flow_key(p)
        if k:
            flows.setdefault(k, []).append(p)
    ok = True
    for k, plist in flows.items():
        flag_seq = [p.get("flags", "") for p in plist]
        print(f"  flow {k}: {flag_seq}")
        if not flag_seq:
            ok = False; continue
        if flag_seq[0] != "S":
            print(f"  FAIL: first packet not SYN, got {flag_seq[0]}")
            ok = False
        if "S." in flag_seq and "S" in flag_seq:
            if flag_seq.index("S") > flag_seq.index("S."):
                print(f"  FAIL: SYN after SYN-ACK")
                ok = False
        if "S." in flag_seq and "P." in flag_seq:
            if flag_seq.index("S.") > flag_seq.index("P."):
                print(f"  FAIL: SYN-ACK after data")
                ok = False
        if "P." in flag_seq and "F." in flag_seq:
            if flag_seq.index("P.") > flag_seq.index("F."):
                print(f"  FAIL: data after FIN")
                ok = False
    print(f"  result: {'PASS' if ok else 'FAIL'}")
    return ok

def test_http_host():
    print("\n=== Scenario 2: HTTP with Host: www.home.com ===")
    r = api("POST", "/strategies", {
        "name": "e2e-http", "mode": "synth", "protocol": "http",
        "config": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                   "src_port": 22222, "dst_port": 80,
                   "http": {"method": "GET", "uri": "/index.html", "version": "HTTP/1.1",
                            "request_headers": {"Host": "www.home.com"}, "transactions": 1}},
    })
    sid = r["data"]["id"]
    r = api("POST", "/tasks", {
        "name": "e2e-http-task", "strategy_ids": [sid],
        "output_type": "port_group", "output_config": {"port_group_id": "33ddf949-b68a-456a-b32b-195690c29f93"},
    })
    tid = r["data"]["id"]
    cap = capture_start("/tmp/e2e-http-nic.pcap")
    api("POST", f"/tasks/{tid}/start")
    time.sleep(2)
    capture_stop(cap)
    pkts = parse_pcap("/tmp/e2e-http-nic.pcap")
    print(f"  captured {len(pkts)} packets")
    http_get = None
    http_resp = None
    for p in pkts:
        if "GET /" in p.get("payload", ""):
            http_get = p
        if "HTTP/1.1 200" in p.get("payload", ""):
            http_resp = p
    ok = True
    if not http_get:
        print("  FAIL: no HTTP GET"); ok = False
    elif "Host: www.home.com" not in http_get["payload"]:
        print(f"  FAIL: Host header wrong"); ok = False
    else:
        print(f"  HTTP GET with Host: www.home.com ✓")
    if not http_resp:
        print("  FAIL: no HTTP 200 OK"); ok = False
    else:
        print(f"  HTTP 200 OK ✓")
    if http_get and http_resp:
        get_idx = pkts.index(http_get)
        resp_idx = pkts.index(http_resp)
        flag_seq = [p.get("flags", "") for p in pkts]
        syn_idx = flag_seq.index("S") if "S" in flag_seq else -1
        synack_idx = flag_seq.index("S.") if "S." in flag_seq else -1
        if syn_idx >= 0 and get_idx < syn_idx:
            print(f"  FAIL: GET before SYN"); ok = False
        if synack_idx >= 0 and get_idx < synack_idx:
            print(f"  FAIL: GET before SYN-ACK"); ok = False
        if resp_idx < get_idx:
            print(f"  FAIL: 200 OK before GET"); ok = False
        print(f"  SYN@{syn_idx} SYN-ACK@{synack_idx} GET@{get_idx} 200OK@{resp_idx}")
    print(f"  result: {'PASS' if ok else 'FAIL'}")
    return ok

def test_udp():
    print("\n=== Scenario 3: UDP request/response ===")
    r = api("POST", "/strategies", {
        "name": "e2e-udp", "mode": "synth", "protocol": "udp",
        "config": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                   "src_port": 33333, "dst_port": 53, "udp": {"response": True}},
    })
    sid = r["data"]["id"]
    r = api("POST", "/tasks", {
        "name": "e2e-udp-task", "strategy_ids": [sid],
        "output_type": "port_group", "output_config": {"port_group_id": "33ddf949-b68a-456a-b32b-195690c29f93"},
    })
    tid = r["data"]["id"]
    cap = capture_start("/tmp/e2e-udp-nic.pcap", "udp")
    api("POST", f"/tasks/{tid}/start")
    time.sleep(2)
    capture_stop(cap)
    pkts = parse_pcap("/tmp/e2e-udp-nic.pcap")
    print(f"  captured {len(pkts)} packets")
    ok = len(pkts) >= 2
    if ok and "10.0.0.1.33333 > 10.0.0.2.53" in pkts[0].get("raw", ""):
        print(f"  UDP request direction ✓")
    else:
        print(f"  FAIL: first UDP not request"); ok = False
    print(f"  result: {'PASS' if ok else 'FAIL'}")
    return ok

def test_multi_group_id():
    print("\n=== Scenario 4: Multiple group_id (5 flows, each own group_id) ===")
    classes = []
    for i in range(5):
        classes.append({
            "id": f"tcp-{i}", "type": "tcp", "flow_count": 1,
            "tuples": {
                "src_ip": {"strategy": "fixed", "value": "10.0.0.1"},
                "dst_ip": {"strategy": "fixed", "value": "10.0.0.2"},
                "src_port": {"strategy": "fixed", "value": 40000 + i},
                "dst_port": {"strategy": "fixed", "value": 80},
            },
            "config": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                       "src_port": 40000 + i, "dst_port": 80,
                       "tcp": {"handshake": True, "termination": True}},
            "group_id": {"strategy": "fixed", "value": f"call-{i}"},
        })
    # Batch tasks auto-start on creation; capture must wrap the create call
    cap = capture_start("/tmp/e2e-multi-nic.pcap")
    r = api("POST", "/tasks/batch", {
        "name": "e2e-multi-group",
        "batch": {"classes": classes},
        "output_type": "port_group",
        "output_config": {"port_group_id": "33ddf949-b68a-456a-b32b-195690c29f93"},
    })
    tid = r["data"]["id"]
    time.sleep(3)
    capture_stop(cap)
    pkts = parse_pcap("/tmp/e2e-multi-nic.pcap")
    print(f"  captured {len(pkts)} packets")
    flows = {}
    for p in pkts:
        k = flow_key(p)
        if k:
            flows.setdefault(k, []).append(p)
    print(f"  {len(flows)} distinct flows")
    ok = True
    for k, plist in flows.items():
        flag_seq = [p.get("flags", "") for p in plist]
        if "S" in flag_seq and "F." in flag_seq:
            if flag_seq.index("S") > flag_seq.index("F."):
                print(f"  FAIL: flow {k} SYN after FIN"); ok = False
            else:
                print(f"  flow {k}: {len(plist)} pkts, order ok")
    if len(flows) < 2:
        print(f"  WARN: expected 5 flows, got {len(flows)}")
    print(f"  result: {'PASS' if ok else 'FAIL'}")
    return ok

def test_bidirectional():
    print("\n=== Scenario 5: Bidirectional TCP (4-tuple hash, both directions same shard) ===")
    r = api("POST", "/strategies", {
        "name": "e2e-bidir", "mode": "synth", "protocol": "http",
        "config": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                   "src_port": 55555, "dst_port": 80,
                   "http": {"method": "POST", "uri": "/api", "version": "HTTP/1.1",
                            "request_headers": {"Host": "bidir.test"}, "body": "hello",
                            "transactions": 1}},
    })
    sid = r["data"]["id"]
    r = api("POST", "/tasks", {
        "name": "e2e-bidir-task", "strategy_ids": [sid],
        "output_type": "port_group", "output_config": {"port_group_id": "33ddf949-b68a-456a-b32b-195690c29f93"},
    })
    tid = r["data"]["id"]
    cap = capture_start("/tmp/e2e-bidir-nic.pcap")
    api("POST", f"/tasks/{tid}/start")
    time.sleep(2)
    capture_stop(cap)
    pkts = parse_pcap("/tmp/e2e-bidir-nic.pcap")
    print(f"  captured {len(pkts)} packets")
    flag_dir = [(p.get("flags", ""), "c2s" if "10.0.0.1.55555 > 10.0.0.2.80" in p.get("raw", "") else "s2c") for p in pkts]
    print(f"  flag/dir: {flag_dir[:10]}")
    ok = True
    if flag_dir and flag_dir[0] == ("S", "c2s"):
        print(f"  SYN c2s ✓")
    else:
        print(f"  FAIL: first not SYN c2s"); ok = False
    if any(f == "S." and d == "s2c" for f, d in flag_dir):
        print(f"  SYN-ACK s2c ✓")
    else:
        print(f"  FAIL: no SYN-ACK s2c"); ok = False
    print(f"  result: {'PASS' if ok else 'FAIL'}")
    return ok

if __name__ == "__main__":
    login()
    results = {}
    for name, fn in [
        ("single_tcp", test_single_tcp),
        ("http_host", test_http_host),
        ("udp", test_udp),
        ("multi_group_id", test_multi_group_id),
        ("bidirectional", test_bidirectional),
    ]:
        try:
            results[name] = fn()
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            results[name] = False
    print("\n" + "=" * 60)
    print("E2E Summary:")
    for name, ok in results.items():
        print(f"  {name}: {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if all(results.values()) else 1)
