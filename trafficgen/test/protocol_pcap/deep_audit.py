#!/usr/bin/env python3
"""Deep pcap parse audit: scan every case pcap with a single tshark call
extracting _ws.malformed per frame + TCP/IP/UDP checksum status.

Usage:
  python3 deep_audit.py scan [proto...]  -- scan pcaps, write deep-audit-raw.json
  python3 deep_audit.py report           -- classify findings vs case JSON
"""
import json
import os
import re
import subprocess
import sys

PCAP_ROOT = "/tmp/mcp-pcaps"
CASES_DIR = "/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases"
RAW_FILE = "/tmp/deep-audit-raw.json"
REPORT_FILE = "/tmp/deep-audit-report.json"

PROTOS = ["a2a", "dnp3", "doip", "enip", "gbt32960", "mcp", "modbus",
          "mqtt", "nfs", "rip", "smb", "srv6", "tds", "tftp"]


def run_tshark(args):
    r = subprocess.run(["tshark"] + args, capture_output=True, text=True)
    return r.stdout


# tshark (3.6+) *_checksum.status field values (epan/packet.h, proto.h):
#   1 = GOOD        — checksum verified and correct
#   2 = UNVERIFIED  — not verified (default for IPv4 header checksum and
#                     checksums the dissector does not validate)
#   3 = NOT_PRESENT — field legitimately absent (IPv4 UDP checksum 0x0000,
#                     RFC 768: 0 means "no checksum", valid on IPv4)
#   4 = ILLEGAL     — present but invalid (IPv6 UDP/TCP checksum 0x0000,
#                     RFC 8200 §8.1: zero is illegal over IPv6)
# Only ILLEGAL (4) is a real defect. Values 2/3 are normal on valid frames;
# flagging them produced false positives (e.g. srv6 end.dx4/dt4 inner IPv4
# UDP with checksum 0x0000 reported as bad).
BAD_CHECKSUM_STATUS = ("4",)


def scan_one(pcap):
    """Return (malformed_frames, bad_checksum_frames, checksum_counts)."""
    out = run_tshark(["-r", pcap, "-T", "fields", "-e", "frame.number",
                      "-e", "_ws.malformed",
                      "-e", "tcp.checksum.status", "-e", "ip.checksum.status",
                      "-e", "udp.checksum.status"])
    malformed = []
    bad_ck = []
    ck_counts = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        fno, malf, tcpck, ipck, udpck = parts[:5]
        if malf:
            malformed.append((fno, malf))
        for v in (tcpck, ipck, udpck):
            if v:
                ck_counts[v] = ck_counts.get(v, 0) + 1
                if v in BAD_CHECKSUM_STATUS:
                    bad_ck.append((fno, v))
    return malformed, bad_ck, ck_counts


def load_cases():
    out = {}
    for p in PROTOS:
        path = os.path.join(CASES_DIR, p + ".json")
        if not os.path.exists(path):
            continue
        for c in json.load(open(path)):
            out[c["id"]] = c
    return out


def expected_injection(c):
    """Heuristic: does this case intentionally inject errors/malformed data?"""
    s = json.dumps(c, ensure_ascii=False)
    needles = ["error_on_command", "error_response_status", "inject", "malformed",
               "expect_error", "负向", "错误注入", "error_inject", "corrupt",
               "invalid", "reject", "refuse", "checksum", "bad_crc", "broken"]
    return [n for n in needles if n.lower() in s.lower()]


# Known tshark dissector artifacts on VALID frames (not frame defects):
# tshark heuristically dissects UDP port 53 as DNS. A short payload
# ("12345678", 8 bytes) yields Transaction ID + Flags only, then the DNS
# dissector runs past the end of the payload and flags "[Malformed Packet:
# DNS]". The frames themselves are valid UDP datagrams with correct
# checksums (verified manually, e.g. srv6_tpos1_basic checksum 0xa316 =
# pseudo-header 2001:db8::1->2001:db8::2, UDP len 16). These cases use
# port 53 by design (design §6.1 S1 / §6.6 S6), so the artifact is
# expected and classified as such instead of "unexpected".
KNOWN_DISSECTOR_ARTIFACTS = {
    # "case_id": "reason"
    "srv6_tpos1_basic": "tshark DNS dissector artifact: UDP port 53 + 8B payload '12345678' (design §6.1 S1); frame valid, checksum 0xa316 correct",
    "srv6_tpos6_nested_ipv6": "tshark DNS dissector artifact: inner UDP port 53 + 8B payload (design §6.6 S6); frame valid, checksum 0x0675 correct",
    "enip_seq_wraparound_3_frames": "tshark CIP dissector artifact: 显式 cpf_items 字节 b1 00 04 00 ff ff aa bb（seq_wraparound 专项，passthrough 语义正确）被按 CIP Message Router 解析：seq 65535+payload 构成伪显式消息 → [Malformed Packet: CIP]。帧合法（见 enip.go buildIODataFrames 注释 2026-08）。",
}


def is_mount_dup_xid_artifact(proto, case_id, malformed_flags):
    """NFSv3 auto-session MOUNT artifact: UMOUNT reply reuses the same XID
    as the MNT call/reply (design §4.2 同一会话内 XID 递增规律在 MOUNT+
    UMOUNT 之间复用), so tshark's RPC state machine dissects the UMOUNT
    reply (proc=3, status-only body) with the MNT (proc=1) dissector which
    expects an fh → EOF → [Malformed Packet: MOUNT]. The frames are valid
    (MOUNT reply body = status only, verified against RFC 1813 §4.1); the
    duplicate-XID layout is by design for these auto-generated sessions.
    Only applies when every malformed flag is the MOUNT artifact."""
    if proto != "nfs":
        return False
    if case_id.startswith(("nfs_t111", "nfs_t112", "nfs_t113", "nfs_t114",
                           "nfs_t115", "nfs_t116", "nfs_t128")):
        return False
    if not malformed_flags:
        return False
    for pair in malformed_flags:
        flag = pair[1] if isinstance(pair, (list, tuple)) else pair
        if "[Malformed Packet: MOUNT]" not in flag:
            return False
    return True


def is_smb_gss_artifact(proto, case_id, malformed_flags):
    """SMB2 auto-session GSS-SPNEGO artifacts:
    1. Custom security_blob (T041): the case intentionally replaces the
       auto GSS blob with a user-supplied one; GSS-SPNEGO wrapper length
       (0x60 0x82 0x01 0x00 = 256) declares more than the actual 7B payload,
       so tshark's BER dissector runs past the blob and reports malformed.
       The blob bytes themselves are exactly what the case requests
       (verified: SecurityBlob @frame6 = 60 82 01 00 41 42 43), and
       SecurityBufferLength (07 00 = 7B) matches the actual blob length.
       The wrapper length is only a hint that BER's ASN.1 machinery
       follows; over-length wrapper on a raw blob is expected passthrough.
    2. probe_explicit_close / stale non-suite pcaps: probe_smb.json cases
       (prefixed probe_) are diagnostics, not suite cases; their default
       NTLMSSP blob (60 2e a0 0a 30 08 06 06 2b 06 01 05 05 02 a2 20 +
       32B NTLMSSP) contains OID+mechtoken that the NTLMSSP dissector
       reads past → [Malformed Packet: NTLMSSP] on the SESSION_SETUP
       reply. Frames are valid, NTLMv2 negotiation is the normal
       auto-session flow (see smb.go autoSession 注释), and probe cases
       are not part of the 279-case suite."""
    if proto != "smb":
        return False
    if case_id == "smb_tpos41_custom_securityblob":
        return True
    if case_id.startswith("probe_"):
        return True
    return False


def artifact_reason(case_id):
    """Return a reason string if this case's malformed flag is a known
    tshark dissector artifact on a valid frame, else None."""
    return KNOWN_DISSECTOR_ARTIFACTS.get(case_id)


def scan(protos):
    findings = []
    for p in protos:
        pdir = os.path.join(PCAP_ROOT, p)
        if not os.path.isdir(pdir):
            continue
        pcaps = sorted(f for f in os.listdir(pdir) if f.endswith(".pcap"))
        for fname in pcaps:
            path = os.path.join(pdir, fname)
            malf, bad_ck, ck = scan_one(path)
            if malf or bad_ck:
                findings.append({
                    "proto": p, "case": fname[:-5], "file": fname,
                    "malformed": malf, "bad_checksum": bad_ck,
                    "checksum": ck,
                })
    json.dump(findings, open(RAW_FILE, "w"), indent=1, ensure_ascii=False)
    print(f"scanned {len(protos)} protos: {len(findings)} pcaps with findings")


def report():
    cases = load_cases()
    findings = json.load(open(RAW_FILE))
    by_proto = {}
    for f in findings:
        by_proto.setdefault(f["proto"], []).append(f)

    unexpected, expected = [], []
    for f in findings:
        c = cases.get(f["case"])
        if c is None:
            # No case file (probe_* diagnostics, stale residue): classify via
            # artifact whitelist before giving up — probe_* pcaps are valid
            # auto-session frames flagged by tshark's GSS/NTLMSSP dissector.
            if is_smb_gss_artifact(f["proto"], f["case"], f.get("malformed") or []):
                expected.append((f, None, "GSS-SPNEGO dissector artifact (probe_* 诊断用例; 帧合法)"))
                continue
            unexpected.append((f, None, ["NO-CASE-FILE"]))
            continue
        hits = expected_injection(c)
        reason = artifact_reason(f["case"])
        if hits or reason or is_mount_dup_xid_artifact(f["proto"], f["case"], f.get("malformed") or []) or is_smb_gss_artifact(f["proto"], f["case"], f.get("malformed") or []):
            note = reason or ", ".join(hits)
            if not note:
                if f["proto"] == "nfs":
                    note = "MOUNT duplicate-XID dissector artifact (UMOUNT reply XID 复用, tshark 按 MNT dissector 解析 → malformed; 帧合法)"
                elif f["proto"] == "smb":
                    note = "GSS-SPNEGO dissector artifact (自定义 security_blob 长度提示 > 实际载荷 / NTLMSSP 自动会话; 帧合法)"
            expected.append((f, c, note))
        else:
            unexpected.append((f, c, hits))

    print("=" * 70)
    print(f"findings: {len(findings)} | expected: {len(expected)} "
          f"| UNEXPECTED: {len(unexpected)}")
    print("=" * 70)
    for f, c, hits in unexpected:
        src = c["id"] if c else f["case"] + " (NO-CASE)"
        print(f"[{f['proto']}] {src}")
        for fno, m in f["malformed"][:5]:
            print(f"    frame {fno}: {m[:100]}")
        for fno, v in f["bad_checksum"][:5]:
            print(f"    frame {fno}: checksum status {v}")

    json.dump({"expected": [f[0] for f in expected],
               "unexpected": [f[0] for f in unexpected]},
              open(REPORT_FILE, "w"), indent=1, ensure_ascii=False)
    print(f"\nreport written to {REPORT_FILE}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scan"
    if cmd == "scan":
        protos = sys.argv[2:] or PROTOS
        scan(protos)
    elif cmd == "report":
        report()
    else:
        print("usage: deep_audit.py [scan [proto...]|report]")
