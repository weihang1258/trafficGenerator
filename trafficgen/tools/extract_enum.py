import json, os

tasks_dir = "/tmp/claude-0/-home-weihang-trafficGenerator/e9caa689-495b-404d-a9ec-eb6df88e7167/tasks"
out_dir = "/home/weihang/trafficGenerator/trafficgen/tools/enum_results"

agents = {
    "afa4c69d0a7533a0b": "dns_icmp_arp",
    "acb090e89527be870": "tcp_extra_planners",
    "a32a0a736f70b8e17": "udp",
    "a122dc4ac38bb6c4f": "http",
    "ac5433dd9bf83c50f": "api",
    "ae2ecb7120347c11f": "engine_core",
    "a6cb79e5a8a5f674a": "output",
    "a6d646b980206f761": "pcapparser",
    "a9bfcafcc5c797458": "replay_storage",
}

for aid, label in agents.items():
    fp = os.path.join(tasks_dir, f"{aid}.output")
    if not os.path.exists(fp):
        print(f"SKIP {label} ({aid}) - file not found")
        continue
    with open(fp) as f:
        lines = f.readlines()

    last_text = ""
    for line in lines:
        try:
            obj = json.loads(line)
            if obj.get("type") == "assistant":
                msg = obj.get("message", {})
                for c in msg.get("content", []):
                    if c.get("type") == "text" and c.get("text", "").strip():
                        last_text = c["text"]
        except:
            pass

    if last_text:
        out = os.path.join(out_dir, f"{label}.md")
        with open(out, "w") as f:
            f.write(last_text)
        print(f"OK {label} ({aid}): {len(last_text)} chars -> {out}")
    else:
        print(f"EMPTY {label} ({aid})")

print("\n--- all enum results ---")
for f in sorted(os.listdir(out_dir)):
    sz = os.path.getsize(os.path.join(out_dir, f))
    print(f"  {f}: {sz} bytes")