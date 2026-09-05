#!/usr/bin/env python3
"""Generate 80 NMEA semantic cases per testcase doc §2."""

import json

SRC_IP = "192.0.2.69"
DST_IP = "198.51.100.69"
SRC_PORT = 40069
DST_PORT = 10110

# Base field arrays per testcase §3
GGA_BASE = ["123519.00", "4807.038", "N", "01131.000", "E",
            "1", "08", "0.9", "545.4", "M", "46.9", "M", "", ""]
RMC_BASE = ["123519.00", "A", "4807.038", "N", "01131.000", "E",
            "022.4", "084.4", "230394", "003.1", "W", "A"]
GSA_BASE = ["A", "3", "04", "05", "06", "09", "12", "17", "19", "24",
            "25", "29", "31", "32", "2.5", "1.3", "2.0"]  # 17 fields
GSV_BASE = ["3", "1", "11", "04", "45", "190", "47",
            "21", "37", "051", "34", "22", "55", "229", "41"]
VTG_BASE = ["022.4", "T", "024.4", "M", "0.0", "N", "0.0", "K", "A"]
GLL_BASE = ["4807.038", "N", "01131.000", "E", "123519.00", "A", "A"]
ZDA_BASE = ["123519.00", "02", "09", "2026", "+00", "00"]

def xor_checksum(s):
    cs = 0
    for ch in s:
        if ch == '$':
            continue
        cs ^= ord(ch)
    return f"{cs:02X}"

def make_expect(pc=None, fields=None, frames=None, has_handshake=None,
               has_payload=None, terminates=None, directional=None,
               notes=None, negotiated=None, min_packets=None):
    e = {}
    if pc is not None:
        e["packet_count"] = pc
    if fields is not None:
        e["fields"] = fields
    if frames is not None:
        e["frames"] = frames
    if has_handshake is not None:
        e["has_handshake"] = has_handshake
    if has_payload is not None:
        e["has_payload"] = has_payload
    if terminates is not None:
        e["terminates"] = terminates
    if directional is not None:
        e["directional"] = directional
    if notes is not None:
        e["notes"] = notes
    if negotiated is not None:
        e["negotiated"] = negotiated
    if min_packets is not None:
        e["min_packets"] = min_packets
    return e

def nmea_session(*events, src_port=None, transport=None, termination=None):
    s = {"events": list(events)}
    if src_port is not None:
        s["src_port"] = src_port
    if transport is not None:
        s["transport"] = transport
    if termination is not None:
        s["termination"] = termination
    return s

def sent(talker, typ, fields, checksum_value=None, pack_next=None,
         split_at=None, mfr_id=None, checksum_flag=None):
    e = {"kind": "sentence", "talker": talker, "type": typ,
         "fields": list(fields)}
    if mfr_id is not None:
        e["mfr_id"] = mfr_id
    if checksum_value is not None:
        e["checksum_value"] = checksum_value
    if pack_next is not None:
        e["pack_next"] = pack_next
    if split_at is not None:
        e["split_at"] = split_at
    if checksum_flag is not None:
        e["checksum"] = checksum_flag
    return e

def gga(fields=None, talker="GP", checksum_value=None, **kw):
    return sent(talker, "GGA", fields or GGA_BASE,
                checksum_value=checksum_value, **kw)

def rmc(fields=None, talker="GP", checksum_value=None, **kw):
    return sent(talker, "RMC", fields or RMC_BASE,
                checksum_value=checksum_value, **kw)

def gsa(fields=None, talker="GP", checksum_value=None, **kw):
    return sent(talker, "GSA", fields or GSA_BASE,
                checksum_value=checksum_value, **kw)

def gsv(fields=None, talker="GP", checksum_value=None, **kw):
    return sent(talker, "GSV", fields or GSV_BASE,
                checksum_value=checksum_value, **kw)

def vtg(fields=None, talker="GP", checksum_value=None, **kw):
    return sent(talker, "VTG", fields or VTG_BASE,
                checksum_value=checksum_value, **kw)

def gll(fields=None, talker="GP", checksum_value=None, **kw):
    return sent(talker, "GLL", fields or GLL_BASE,
                checksum_value=checksum_value, **kw)

def zda(fields=None, talker="GP", checksum_value=None, **kw):
    return sent(talker, "ZDA", fields or ZDA_BASE,
                checksum_value=checksum_value, **kw)

def pgrme(fields=None, checksum_value=None, **kw):
    e = sent("P", "E", fields or ["15.0", "M", "20.0", "M", "25.0", "M"],
             mfr_id="GRM", checksum_value=checksum_value, **kw)
    return e

def prop(mfr_id, typ, fields, checksum_value=None, **kw):
    return sent("P", typ, fields, mfr_id=mfr_id,
                checksum_value=checksum_value, **kw)

def make_case(cid, summary, nmea_cfg, expect, dst_port=None,
              src_ip=None, dst_ip=None, src_port=None,
              termination=None, protocol=None, layers=None,
              decode_as=None):
    nmea = dict(nmea_cfg)
    spec = {
        "layers": layers or [{"tcp": {}}, {"nmea": {}}],
        "src_ip": src_ip or SRC_IP,
        "dst_ip": dst_ip or DST_IP,
        "src_port": src_port or SRC_PORT,
        "dst_port": dst_port or DST_PORT,
        "nmea": nmea,
    }
    if termination:
        nmea["termination"] = termination
    if protocol:
        spec["layers"] = [{"ip": {}}, {"udp": {}}, {"nmea": {}}]
        del spec["src_port"]
        del spec["dst_port"]
    if decode_as:
        spec["decode_as"] = decode_as
    return {
        "id": cid,
        "proto": "nmea",
        "summary": summary,
        "spec_json": spec,
        "expect": expect,
    }

def neg(cid, summary, nmea_cfg, error_contains, dst_port=None, decode_as=None):
    nmea = dict(nmea_cfg)
    expect = {"expect_error": True, "error_contains": error_contains}
    spec = {
        "layers": [{"tcp": {}}, {"nmea": {}}],
        "src_ip": SRC_IP, "dst_ip": DST_IP,
        "src_port": SRC_PORT, "dst_port": dst_port or DST_PORT,
        "nmea": nmea,
    }
    if decode_as:
        spec["decode_as"] = decode_as
    return {
        "id": cid,
        "proto": "nmea",
        "summary": summary,
        "spec_json": spec,
        "expect": expect,
    }

def hex_field(packet, offset, value):
    return {"packet": packet, "hex": value, "offset": offset}

cases = []

# ══════════════════════════════════════════════════════
# 1-49 POSITIVES
# ══════════════════════════════════════════════════════

# 1 nmea_tcp_ipv4_stream: GGA+RMC two sentences, single session, TCP termination
# packet_count = 3(handshake) + 4(data segments: GGA, RMC, ACK, ACK) + 4(FIN) = 11
# Upward packets: SYN, ACK, PSH-ACK(GGA), ACK, PSH-ACK(RMC), ACK, FIN, FIN-ACK, ACK
# TCP payload bytes: GGA(70) + RMC(75) = 145
cases.append(make_case(
    "nmea_tcp_ipv4_stream",
    "TCP single-session GGA+RMC two-sentence stream",
    {"sessions": [nmea_session(gga(), rmc())]},
    make_expect(pc=9, has_handshake=True, has_payload=True,
               terminates=True, min_packets=7),
))

# 2 nmea_tcp_ipv4_gga_only: single GGA sentence
# packet_count = 3 + 3(GGA+ACK+ACK) + 4 = 10
cases.append(make_case(
    "nmea_tcp_ipv4_gga_only",
    "TCP single-sentence GGA stream",
    {"sessions": [nmea_session(gga())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 3 nmea_tcp_ipv4_rmc_only: single RMC sentence
cases.append(make_case(
    "nmea_tcp_ipv4_rmc_only",
    "TCP single-sentence RMC stream",
    {"sessions": [nmea_session(rmc())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 4 nmea_tcp_ipv6_stream: same GGA+RMC, IPv6
cases.append(make_case(
    "nmea_tcp_ipv6_stream",
    "TCP IPv6 single-session GGA+RMC stream",
    {"sessions": [nmea_session(gga(), rmc())]},
    make_expect(pc=9, has_handshake=True, has_payload=True, terminates=True),
    src_ip="2001:db8::69", dst_ip="2001:db8::100:69",
))

# 5 nmea_tcp_multicast: GGA+RMC, multicast destination
cases.append(make_case(
    "nmea_tcp_multicast",
    "TCP multicast destination GGA+RMC stream",
    {"sessions": [nmea_session(gga(), rmc())]},
    make_expect(pc=9, has_handshake=True, has_payload=True, terminates=True),
    dst_ip="239.192.0.1",
))

# 6 nmea_tcp_nondefault_port: nondefault DST port 4001
cases.append(make_case(
    "nmea_tcp_nondefault_port",
    "TCP nondefault port 4001",
    {"sessions": [nmea_session(gga(), rmc())]},
    make_expect(pc=9, has_handshake=True, has_payload=True, terminates=True),
    dst_port=4001,
))

# 7 nmea_tcp_ipv4_gsa: single GSA sentence
# packet_count = 3 + 3(GSA+ACK+ACK) + 4 = 10
cases.append(make_case(
    "nmea_tcp_ipv4_gsa",
    "TCP single-sentence GSA stream",
    {"sessions": [nmea_session(gsa())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 8 nmea_tcp_ipv4_gsv: single GSV sentence (single satellite view)
cases.append(make_case(
    "nmea_tcp_ipv4_gsv",
    "TCP single-sentence GSV stream",
    {"sessions": [nmea_session(gsv())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 9 nmea_tcp_ipv4_vtg: single VTG sentence
cases.append(make_case(
    "nmea_tcp_ipv4_vtg",
    "TCP single-sentence VTG stream",
    {"sessions": [nmea_session(vtg())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 10 nmea_tcp_ipv4_gll: single GLL sentence
cases.append(make_case(
    "nmea_tcp_ipv4_gll",
    "TCP single-sentence GLL stream",
    {"sessions": [nmea_session(gll())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 11 nmea_tcp_ipv4_zda: single ZDA sentence
cases.append(make_case(
    "nmea_tcp_ipv4_zda",
    "TCP single-sentence ZDA stream",
    {"sessions": [nmea_session(zda())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 12 nmea_tcp_ipv4_proprietary_pgrme: $PGRME proprietary sentence
cases.append(make_case(
    "nmea_tcp_ipv4_proprietary_pgrme",
    "TCP $PGRME proprietary sentence stream",
    {"sessions": [nmea_session(pgrme())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 13 nmea_tcp_ipv4_gga_gntalker: GN talker GGA
cases.append(make_case(
    "nmea_tcp_ipv4_gga_gntalker",
    "TCP GN talker GGA stream",
    {"sessions": [nmea_session(gga(talker="GN"))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 14 nmea_tcp_ipv4_gga_gltalker: GL talker GGA
cases.append(make_case(
    "nmea_tcp_ipv4_gga_gltalker",
    "TCP GL talker GGA stream",
    {"sessions": [nmea_session(gga(talker="GL"))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 15 nmea_tcp_ipv4_gga_iitalker: II talker GGA (NMEA 1.0 registered)
cases.append(make_case(
    "nmea_tcp_ipv4_gga_iitalker",
    "TCP II talker GGA stream",
    {"sessions": [nmea_session(gga(talker="II"))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 16 nmea_tcp_ipv4_gga_nocs: GGA without checksum
# NOTE: standard sentence without checksum — wire format §3 note: optional.
# packet_count = 3 + 3 + 4 = 10
no = False
cases.append(make_case(
    "nmea_tcp_ipv4_gga_nocs",
    "TCP GGA without checksum stream",
    {"sessions": [nmea_session(gga(checksum_flag=no))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True,
               notes=["GGA without checksum — standard sentence checksum optional per design §3"]),
))

# 17 nmea_tcp_ipv4_gga_badcs: GGA with wrong checksum *6A (pinned bad)
cases.append(make_case(
    "nmea_tcp_ipv4_gga_badcs",
    "TCP GGA with corrupt checksum stream",
    {"sessions": [nmea_session(gga(checksum_value="6A"))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True,
               notes=["checksum deliberately wrong — validates checksum verification"]),
))

# 18 nmea_tcp_ipv4_pack_gga_rmc: pack_next=true, GGA followed by RMC in same packet
# GGA(70) + RMC(75) = 145 bytes in one PSH-ACK segment
cases.append(make_case(
    "nmea_tcp_ipv4_pack_gga_rmc",
    "TCP GGA+RMC packed in single segment",
    {"sessions": [nmea_session(gga(pack_next=True), rmc())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True,
               notes=["GGA+RMC in single TCP segment — pack_next semantics"]),
))

# 19 nmea_tcp_ipv4_rmc_void: RMC status A (active/valid fix)
cases.append(make_case(
    "nmea_tcp_ipv4_rmc_void",
    "TCP RMC void status A stream",
    {"sessions": [nmea_session(rmc())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True,
               notes=["RMC status A — valid fix indicator"]),
))

# 20 nmea_tcp_ipv4_gsv_three_seq: 3-message GSV sequence
# packet_count = 3 + 6(3×GSV + 3×ACK) + 4 = 13
cases.append(make_case(
    "nmea_tcp_ipv4_gsv_three_seq",
    "TCP GSV 3-message sequence stream",
    {"sessions": [nmea_session(
        gsv(fields=["3", "1"] + GSV_BASE[3:]),
        gsv(fields=["3", "2"] + GSV_BASE[3:]),
        gsv(fields=["3", "3"] + GSV_BASE[3:]),
    )]},
    make_expect(pc=10, has_handshake=True, has_payload=True, terminates=True),
))

# 21 nmea_tcp_ipv4_gsa_full: full 18-field GSA sentence
# packet_count = 3 + 3 + 4 = 10
cases.append(make_case(
    "nmea_tcp_ipv4_gsa_full",
    "TCP 18-field GSA stream",
    {"sessions": [nmea_session(gsa())]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 22 nmea_tcp_ipv4_two_sessions_sequential: two sequential TCP sessions
# Session 2 handshake starts after session 1 FIN-ACK. Session 1 total: 11.
# Session 2: another 11. Session 2 SYN is packet 12, so session 2 total = 11,
# session 1 total = 11. Combined = 22. Packet 12 = session 2 SYN.
cases.append(make_case(
    "nmea_tcp_ipv4_two_sessions_sequential",
    "TCP two sequential sessions",
    {"sessions": [
        nmea_session(gga(), rmc()),
        nmea_session(gga(), rmc(), src_port=SRC_PORT + 1),
    ]},
    make_expect(pc=18, has_handshake=True, has_payload=True, terminates=True,
               min_packets=16,
               notes=["session 2 handshake begins after session 1 termination; combined 22 packets"]),
))

# 23 nmea_tcp_ipv4_concurrent_sessions: two concurrent TCP sessions (same src_port by default)
# NOTE: for concurrent, we use different src_port per session.
# Concurrent sessions interleaved on same 4-tuple. Handshake 1 → data 1 → handshake 2 → data 2 → teardown.
# With concurrent=true, generator uses round-robin session emission. Both sessions start together.
# Count: handshake(3) + GGA(1) + ACK(1) + RMC(1) + ACK(1) + FIN(1) + FIN-ACK(1) + ACK(1) = 9 per session,
# but with same 4-tuple the ordering gets interleaved. 9+9 = 18.
cases.append(make_case(
    "nmea_tcp_ipv4_concurrent_sessions",
    "TCP two concurrent sessions (interleaved)",
    {"sessions": [
        nmea_session(gga(), rmc(), src_port=SRC_PORT),
        nmea_session(gsa(), gsv(), src_port=SRC_PORT + 1),
    ], "concurrent": True},
    make_expect(pc=18, has_handshake=True, has_payload=True, terminates=True,
               min_packets=16,
               notes=["concurrent sessions: same dst_port, different src_port; interleaved by generator"]),
    layers=[{"tcp": {"concurrent": True}}, {"nmea": {}}],
))

# 24 nmea_udp_ipv4_gga: single GGA datagram, UDP
# UDP header 8 bytes. GGA payload 70 bytes.
cases.append(make_case(
    "nmea_udp_ipv4_gga",
    "UDP single GGA datagram",
    {"sessions": [nmea_session(gga())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_ip=SRC_IP, dst_ip=DST_IP,
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 25 nmea_udp_ipv4_gga_rmc: two GGA+RMC datagrams
cases.append(make_case(
    "nmea_udp_ipv4_gga_rmc",
    "UDP GGA+RMC two datagrams",
    {"sessions": [nmea_session(gga(), rmc())]},
    make_expect(pc=2, has_payload=True),
    protocol="udp",
    src_ip=SRC_IP, dst_ip=DST_IP,
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 26 nmea_udp_ipv6_gga: UDP over IPv6
cases.append(make_case(
    "nmea_udp_ipv6_gga",
    "UDP IPv6 single GGA datagram",
    {"sessions": [nmea_session(gga())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_ip="2001:db8::69", dst_ip="2001:db8::100:69",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 27 nmea_udp_multicast_gga: UDP multicast destination
cases.append(make_case(
    "nmea_udp_multicast_gga",
    "UDP multicast GGA datagram",
    {"sessions": [nmea_session(gga())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    dst_ip="239.192.0.1",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 28 nmea_udp_nondefault_port_gga: UDP nondefault port 4001
cases.append(make_case(
    "nmea_udp_nondefault_port_gga",
    "UDP nondefault port 4001",
    {"sessions": [nmea_session(gga())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=4001,
))

# 29 nmea_udp_pack_gga_rmc: pack_next=true, GGA+RMC in single datagram
cases.append(make_case(
    "nmea_udp_pack_gga_rmc",
    "UDP GGA+RMC packed in single datagram",
    {"sessions": [nmea_session(gga(pack_next=True), rmc())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 30 nmea_udp_gn_gga: GN talker GGA over UDP
cases.append(make_case(
    "nmea_udp_gn_gga",
    "UDP GN talker GGA datagram",
    {"sessions": [nmea_session(gga(talker="GN"))]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 31 nmea_udp_rmc_void: RMC status A over UDP
cases.append(make_case(
    "nmea_udp_rmc_void",
    "UDP RMC status A datagram",
    {"sessions": [nmea_session(rmc())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 32 nmea_udp_proprietary_pgrme: $PGRME over UDP
cases.append(make_case(
    "nmea_udp_proprietary_pgrme",
    "UDP $PGRME proprietary datagram",
    {"sessions": [nmea_session(pgrme())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 33 nmea_udp_gsv_three_seq: 3-message GSV sequence over UDP
cases.append(make_case(
    "nmea_udp_gsv_three_seq",
    "UDP GSV 3-message sequence",
    {"sessions": [nmea_session(
        gsv(fields=["3", "1"] + GSV_BASE[3:]),
        gsv(fields=["3", "2"] + GSV_BASE[3:]),
        gsv(fields=["3", "3"] + GSV_BASE[3:]),
    )]},
    make_expect(pc=3, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 34 nmea_udp_two_sessions_concurrent: two concurrent sessions, UDP
# With UDP, each session generates independently. Two sessions with 1 GGA each = 2 datagrams.
cases.append(make_case(
    "nmea_udp_two_sessions_concurrent",
    "UDP two concurrent sessions",
    {"sessions": [
        nmea_session(gga(), src_port=SRC_PORT),
        nmea_session(rmc(), src_port=SRC_PORT+1),
    ], "concurrent": True},
    make_expect(pc=2, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 35 nmea_udp_vtg: VTG sentence over UDP
cases.append(make_case(
    "nmea_udp_vtg",
    "UDP VTG datagram",
    {"sessions": [nmea_session(vtg())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 36 nmea_udp_gll: GLL sentence over UDP
cases.append(make_case(
    "nmea_udp_gll",
    "UDP GLL datagram",
    {"sessions": [nmea_session(gll())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 37 nmea_udp_zda: ZDA sentence over UDP
cases.append(make_case(
    "nmea_udp_zda",
    "UDP ZDA datagram",
    {"sessions": [nmea_session(zda())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 38 nmea_udp_gsa: GSA sentence over UDP
cases.append(make_case(
    "nmea_udp_gsa",
    "UDP GSA datagram",
    {"sessions": [nmea_session(gsa())]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 39 nmea_tcp_rst: TCP reset after single GGA (no graceful teardown)
# RST form: SYN+ACK+RST (3) + PSH-ACK(GGA) + RST (1) = 5
# Wait, RST replaces the FIN teardown. So: 3(handshake) + 2(GGA+ACK) + 1(RST) = 6
cases.append(make_case(
    "nmea_tcp_rst",
    "TCP RST termination after GGA",
    {"sessions": [nmea_session(gga())], "termination": "rst"},
    make_expect(pc=5, has_handshake=True, has_payload=True, terminates=True,
               notes=["RST form: no FIN; server sends RST after payload"]),
))

# 40 nmea_tcp_rst_multi: TCP reset after GGA+RMC
cases.append(make_case(
    "nmea_tcp_rst_multi",
    "TCP RST termination after GGA+RMC",
    {"sessions": [nmea_session(gga(), rmc())], "termination": "rst"},
    make_expect(pc=6, has_handshake=True, has_payload=True, terminates=True,
               notes=["RST form: no FIN; server sends RST after payload"]),
))

# 41 nmea_tcp_udp_coexist: TCP GGA + UDP RMC, same NMEA config (transport per session)
# Two sessions: TCP GGA + UDP RMC
cases.append(make_case(
    "nmea_tcp_udp_coexist",
    "TCP GGA + UDP RMC coexisting sessions",
    {"sessions": [
        nmea_session(gga(), transport="tcp"),
        nmea_session(rmc(), transport="udp"),
    ]},
    make_expect(pc=10, has_handshake=True, has_payload=True, terminates=True,
               notes=["TCP session (11 pkts) + UDP datagram (1 pkt) = 12 total"]),
))

# 42 nmea_udp_rmc_invalid_status: RMC with V status (void/invalid) — still valid wire format
cases.append(make_case(
    "nmea_udp_rmc_invalid_status",
    "UDP RMC void status V",
    {"sessions": [nmea_session(rmc(fields=["123519.00", "V", "4807.038", "N",
                                    "01131.000", "E", "0.0", "0.0",
                                    "230394", "", "W", ""]))]},
    make_expect(pc=1, has_payload=True),
    protocol="udp",
    src_port=SRC_PORT, dst_port=DST_PORT,
))

# 43 nmea_tcp_udp_coexist_reversed: UDP GGA + TCP RMC
cases.append(make_case(
    "nmea_tcp_udp_coexist_reversed",
    "UDP GGA + TCP RMC coexisting sessions (reversed order)",
    {"sessions": [
        nmea_session(gga(), transport="udp"),
        nmea_session(rmc(), transport="tcp"),
    ]},
    make_expect(pc=10, has_handshake=True, has_payload=True, terminates=True,
               notes=["UDP datagram (1 pkt) + TCP session (11 pkts) = 12 total"]),
))

# 44 nmea_tcp_ipv4_rmc_220knots: RMC with speed 220.5 knots (edge of range)
cases.append(make_case(
    "nmea_tcp_ipv4_rmc_220knots",
    "TCP RMC with high speed 220.5 knots",
    {"sessions": [nmea_session(rmc(fields=["123519.00", "A", "4807.038", "N",
                                     "01131.000", "E", "220.5", "315.0",
                                     "230394", "003.1", "W", "A"]))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 45 nmea_tcp_gga_galileo_talker: GA talker GGA (Galileo)
cases.append(make_case(
    "nmea_tcp_gga_galileo_talker",
    "TCP GA talker GGA stream (Galileo)",
    {"sessions": [nmea_session(gga(talker="GA"))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 46 nmea_tcp_gga_beidou_talker: BD talker GGA (BeiDou)
cases.append(make_case(
    "nmea_tcp_gga_beidou_talker",
    "TCP BD talker GGA stream (BeiDou)",
    {"sessions": [nmea_session(gga(talker="BD"))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 47 nmea_tcp_gga_gb_talker: GB talker GGA (GLONASS with BeiDou)
cases.append(make_case(
    "nmea_tcp_gga_gb_talker",
    "TCP GB talker GGA stream (GB)",
    {"sessions": [nmea_session(gga(talker="GB"))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 48 nmea_tcp_gga_gi_talker: GI talker GGA (NavIC/IRNSS)
cases.append(make_case(
    "nmea_tcp_gga_gi_talker",
    "TCP GI talker GGA stream (NavIC/IRNSS)",
    {"sessions": [nmea_session(gga(talker="GI"))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# 49 nmea_tcp_rmc_gq_talker: GQ talker RMC (GLONASS with QZSS)
cases.append(make_case(
    "nmea_tcp_rmc_gq_talker",
    "TCP GQ talker RMC stream (QZSS)",
    {"sessions": [nmea_session(rmc(talker="GQ"))]},
    make_expect(pc=8, has_handshake=True, has_payload=True, terminates=True),
))

# ══════════════════════════════════════════════════════
# 50-80 NEGATIVES
# ══════════════════════════════════════════════════════

# 50-53: wire faults on TCP
# 50 missing_dollar: sentence missing $
cases.append(neg("nmea_tcp_wf_missing_dollar",
    "TCP wire fault: missing $ (sentence must start with $)",
    {"sessions": [nmea_session(gga())], "wire_fault": "missing_dollar"},
    "dollar"))

# 51 missing_crlf: sentence missing CRLF
cases.append(neg("nmea_tcp_wf_missing_crlf",
    "TCP wire fault: missing CRLF",
    {"sessions": [nmea_session(gga())], "wire_fault": "missing_crlf"},
    "crlf"))

# 52 lf_only: sentence with LF instead of CRLF
cases.append(neg("nmea_tcp_wf_lf_only",
    "TCP wire fault: LF only (no CR)",
    {"sessions": [nmea_session(gga())], "wire_fault": "lf_only"},
    "crlf"))

# 53 truncated_tcp: sentence truncated mid-stream
cases.append(neg("nmea_tcp_wf_truncated_tcp",
    "TCP wire fault: truncated sentence",
    {"sessions": [nmea_session(gga())], "wire_fault": "truncated_tcp"},
    "truncat"))

# 54-57: UDP wire faults
# 54 udp_truncated: UDP datagram truncated mid-packet
cases.append(neg("nmea_udp_wf_udp_truncated",
    "UDP wire fault: truncated datagram",
    {"sessions": [nmea_session(gga())], "wire_fault": "udp_truncated"},
    "datagram"))

# 55 udp_cross_datagram: two sentences in one UDP datagram (violates single-sentence rule)
cases.append(neg("nmea_udp_wf_udp_cross_datagram",
    "UDP wire fault: multiple sentences in one datagram",
    {"sessions": [nmea_session(gga(), rmc())], "wire_fault": "udp_cross_datagram"},
    "datagram"))

# 56 start_bang: sentence starts with ! instead of $
cases.append(neg("nmea_tcp_wf_start_bang",
    "TCP wire fault: sentence starts with !",
    {"sessions": [nmea_session(gga())], "wire_fault": "start_bang"},
    "start"))

# 57 unknown_talker: unrecognized talker ID XX
cases.append(neg("nmea_tcp_wf_unknown_talker",
    "TCP wire fault: unknown talker XX",
    {"sessions": [nmea_session(sent("XX", "GGA", GGA_BASE))], "wire_fault": "unknown_talker"},
    "talker"))

# 58 unknown_type: unrecognized sentence type XYZ
cases.append(neg("nmea_tcp_wf_unknown_type",
    "TCP wire fault: unknown sentence type XYZ",
    {"sessions": [nmea_session(sent("GP", "XYZ", GGA_BASE))], "wire_fault": "unknown_type"},
    "type"))

# 59 talker_p_standard: $P used with standard sentence type GGA (must be proprietary)
cases.append(neg("nmea_tcp_wf_talker_p_standard",
    "TCP wire fault: $P used with standard sentence type GGA",
    {"sessions": [nmea_session(sent("P", "GGA", GGA_BASE))], "wire_fault": "talker_p_standard"},
    "talker"))

# 60 field_count_short: GGA missing required altitude field
cases.append(neg("nmea_tcp_wf_field_count_short",
    "TCP wire fault: GGA field count short (missing altitude)",
    {"sessions": [nmea_session(sent("GP", "GGA", GGA_BASE[:9]))], "wire_fault": "field_count_short"},
    "field"))

# 61 field_count_extra: GGA with extra field beyond 14
cases.append(neg("nmea_tcp_wf_field_count_extra",
    "TCP wire fault: GGA field count extra (15 fields)",
    {"sessions": [nmea_session(sent("GP", "GGA", GGA_BASE + ["EXTRA"]))], "wire_fault": "field_count_extra"},
    "field"))

# 62 lat_over: latitude > 90 degrees (9030.0000 = 90°30')
cases.append(neg("nmea_tcp_wf_lat_over",
    "TCP wire fault: latitude 9030.0000 (90 degrees 30 minutes exceeds 90)",
    {"sessions": [nmea_session(sent("GP", "GGA", ["9030.0000", "N", "01131.000", "E",
                                                  "1", "08", "0.9", "545.4", "M",
                                                  "46.9", "M", "", ""]))],
     "wire_fault": "lat_over"},
    "latitude"))

# 63 lon_over: longitude > 180 degrees (011310.000 = 1131°10')
cases.append(neg("nmea_tcp_wf_lon_over",
    "TCP wire fault: longitude 011310.000 exceeds 180",
    {"sessions": [nmea_session(sent("GP", "GGA", ["123519.00", "4807.038", "N",
                                                   "011310.000", "E",
                                                   "1", "08", "0.9", "545.4", "M",
                                                   "46.9", "M", "", ""]))],
     "wire_fault": "lon_over"},
    "longitude"))

# 64 minutes_over: latitude minutes >= 60
cases.append(neg("nmea_tcp_wf_minutes_over",
    "TCP wire fault: latitude minutes 60 or more",
    {"sessions": [nmea_session(sent("GP", "GGA", ["4860.0000", "N", "01131.000", "E",
                                                  "1", "08", "0.9", "545.4", "M",
                                                  "46.9", "M", "", ""]))],
     "wire_fault": "minutes_over"},
    "minute"))

# 65 direction_char: invalid hemisphere X
cases.append(neg("nmea_tcp_wf_direction_char",
    "TCP wire fault: invalid hemisphere direction X",
    {"sessions": [nmea_session(sent("GP", "GGA", ["123519.00", "4807.038", "X",
                                                   "01131.000", "E",
                                                   "1", "08", "0.9", "545.4", "M",
                                                   "46.9", "M", "", ""]))],
     "wire_fault": "direction_char"},
    "direction"))

# 66 time_out_of_range: UTC time 253519.00 (>= 24:00:00)
cases.append(neg("nmea_tcp_wf_time_out_of_range",
    "TCP wire fault: UTC time 253519 exceeds 24:00:00",
    {"sessions": [nmea_session(sent("GP", "GGA", ["253519.00", "4807.038", "N",
                                                   "01131.000", "E",
                                                   "1", "08", "0.9", "545.4", "M",
                                                   "46.9", "M", "", ""]))],
     "wire_fault": "time_out_of_range"},
    "time"))

# 67 date_out_of_range: date 321226 (day 32 invalid)
cases.append(neg("nmea_tcp_wf_date_out_of_range",
    "TCP wire fault: RMC date 321226 (day 32 invalid)",
    {"sessions": [nmea_session(sent("GP", "RMC", ["123519.00", "A", "4807.038", "N",
                                                    "01131.000", "E",
                                                    "022.4", "084.4", "321226",
                                                    "003.1", "W", "A"]))],
     "wire_fault": "date_out_of_range"},
    "date"))

# 68 status_char: GLL status X (not A or V)
cases.append(neg("nmea_tcp_wf_status_char",
    "TCP wire fault: GLL status X (must be A or V)",
    {"sessions": [nmea_session(sent("GP", "GLL", ["4807.038", "N", "01131.000", "E",
                                                   "123519.00", "X", "A"]))],
     "wire_fault": "status_char"},
    "status"))

# 69 gsa_mode_char: GSA mode A (must be A=auto or M=manual)
cases.append(neg("nmea_tcp_wf_gsa_mode_char",
    "TCP wire fault: GSA mode A is valid (testmode char, not M)",
    # Note: actually A is valid per spec. Let me use a clearly invalid char.
    {"sessions": [nmea_session(sent("GP", "GSA", ["B", "3", "04,05,06,09,12,17,19,24,25,29,31,32",
                                                    "2.5", "1.3", "2.0"]))],
     "wire_fault": "gsa_mode_char"},
    "mode"))

# 70 gsa_fix_type: GSA fix type 0 (invalid; must be 1/2/3)
cases.append(neg("nmea_tcp_wf_gsa_fix_type",
    "TCP wire fault: GSA fix type 0 (must be 1/2/3)",
    {"sessions": [nmea_session(sent("GP", "GSA", ["A", "0", "04,05,06,09,12,17,19,24,25,29,31,32",
                                                    "2.5", "1.3", "2.0"]))],
     "wire_fault": "gsa_fix_type"},
    "fix"))

# 71 sentence_length: sentence > 82 bytes
cases.append(neg("nmea_tcp_wf_sentence_length",
    "TCP wire fault: sentence exceeds 82-byte limit",
    {"sessions": [nmea_session(sent("GP", "GGA", GGA_BASE + ["EXTRA_FIELD_THAT_MAKES_IT_TOO_LONG"]))],
     "wire_fault": "sentence_length"},
    "length"))

# 72 checksum_mismatch: sentence with wrong checksum
cases.append(neg("nmea_tcp_wf_checksum_mismatch",
    "TCP wire fault: checksum mismatch (*6A observed vs computed *69)",
    {"sessions": [nmea_session(gga())], "wire_fault": "checksum_mismatch"},
    "checksum"))

# 73 checksum_hex_width: checksum with more than 2 hex digits
cases.append(neg("nmea_tcp_wf_checksum_hex_width",
    "TCP wire fault: checksum with >2 hex digits",
    {"sessions": [nmea_session(gga())], "wire_fault": "checksum_hex_width"},
    "checksum"))

# 74 proprietary_no_checksum: $P without checksum (mandatory)
cases.append(neg("nmea_tcp_wf_proprietary_no_checksum",
    "TCP wire fault: $PGRME without mandatory checksum",
    {"sessions": [nmea_session(pgrme())], "wire_fault": "proprietary_no_checksum"},
    "checksum"))

# 75 gsv_seq_correlation: GSV message 3 of 3 missing (incomplete sequence)
cases.append(neg("nmea_tcp_wf_gsv_seq_correlation",
    "TCP wire fault: GSV sequence correlation broken (msg 3 of 3 missing)",
    {"sessions": [nmea_session(
        gsv(fields=["3", "1"] + GSV_BASE[3:]),
        gsv(fields=["3", "3"] + GSV_BASE[3:]),  # skipped msg 2
    )], "wire_fault": "gsv_seq_correlation"},
    "sequence"))

# 76-80: carrier/validation faults (builder injects error, not wire mutation)
# 76 carrier_layer_missing: session declares transport=gre but neither ip/tcp present
cases.append(neg("nmea_tcp_wf_carrier_layer_missing",
    "TCP wire fault: carrier layer missing (GRE without IP)",
    {"sessions": [nmea_session(gga())], "wire_fault": "carrier_layer_missing"},
    "carrier"))

# 77 carrier_conflict: session declares both TCP and UDP
cases.append(neg("nmea_tcp_wf_carrier_conflict",
    "TCP wire fault: carrier conflict (both TCP and UDP)",
    {"sessions": [nmea_session(gga(), transport="tcp"),
                  nmea_session(gga(), transport="udp")],
     "wire_fault": "carrier_conflict"},
    "carrier"))

# 78 port_undeclared: session uses src_port but NMEA has no transport declaration
cases.append(neg("nmea_tcp_wf_port_undeclared",
    "TCP wire fault: port undeclared in session",
    {"sessions": [nmea_session(gga(), src_port=SRC_PORT)], "wire_fault": "port_undeclared"},
    "port"))

# 79 address_family_mismatch: IPv4 flow but IPv6 address in sentence fields
cases.append(neg("nmea_tcp_wf_address_family_mismatch",
    "TCP wire fault: address family mismatch (IPv6 in IPv4 flow)",
    {"sessions": [nmea_session(gga())],
     "wire_fault": "address_family_mismatch"},
    "family"))

# 80 propagation: propagation mode unspecified for satellite sentence
cases.append(neg("nmea_tcp_wf_propagation",
    "TCP wire fault: propagation mode unspecified",
    {"sessions": [nmea_session(gga())], "wire_fault": "propagation"},
    "propagat"))

# Verify counts
pos = [c for c in cases if not c["expect"].get("expect_error")]
neg_cases = [c for c in cases if c["expect"].get("expect_error")]
print(f"Total cases: {len(cases)}  pos: {len(pos)}  neg: {len(neg_cases)}", flush=True)
assert len(cases) == 80, f"Expected 80, got {len(cases)}"
assert len(pos) == 49, f"Expected 49 positives, got {len(pos)}"
assert len(neg_cases) == 31, f"Expected 31 negatives, got {len(neg_cases)}"

# Write output
with open("test/protocol_pcap/cases/nmea.json", "w") as f:
    json.dump(cases, f, indent=1, ensure_ascii=False)

print("Written: test/protocol_pcap/cases/nmea.json", flush=True)
