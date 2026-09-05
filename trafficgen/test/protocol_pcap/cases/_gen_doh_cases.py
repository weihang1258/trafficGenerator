#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""66-doh cases generator（docs/protocol-designs/66-doh-testcase.md v3.0.2 §2）.

Produces test/protocol_pcap/cases/doh.json: 110 semantic cases (84 positive +
26 negative), ID set/order == testcase §8 three-way consistency list.

The script byte-mirrors internal/protocol/doh/builder.go (header orders,
DNS wire encoding, base64url) so every content_length / dns offset / b64
parameter / frames hex assertion is *computed*, never hand-typed. Any drift
between this mirror and the Go builder shows up as a suite failure with the
exact delta, not a silently-wrong literal.

Usage: python3 test/protocol_pcap/cases/_gen_doh_cases.py   (writes doh.json)
"""
import base64
import json
import socket
import struct

# ---------------------------------------------------------------- fixture
V4_SRC, V4_DST = "192.0.2.66", "198.51.100.66"
V6_SRC, V6_DST = "2001:db8::66", "2001:db8::100:66"
SRC_PORT, DST_PORT = 42066, 80
NAME = "www.example.com"
A_RDATA = "192.0.2.1"
AAAA_RDATA = "2001:db8::1"
DNSID = 0x1234
TTL = 300
MEDIA = "application/dns-message"
V4OFF, V6OFF = 54, 74  # HTTP start offset (eth+ip+tcp / eth+ipv6+tcp)

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
         "TXT": 16, "AAAA": 28, "SRV": 33, "SVCB": 64, "HTTPS": 65}
QCLASS = {"IN": 1, "CHAOS": 3, "HS": 4, "NONE": 254, "ANY": 255}

# ------------------------------------------------------- builder mirrors
def qname_enc(name):
    if name in ("", "."):
        return b"\x00"
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def parse_type(tok):
    if tok == "":
        return 1
    if tok.upper() in QTYPE:
        return QTYPE[tok.upper()]
    return int(tok)


def parse_class(tok):
    if tok == "":
        return 1
    if tok.upper() in QCLASS:
        return QCLASS[tok.upper()]
    return int(tok)


def parse_rcode(tok):
    if tok == "":
        return 0
    r = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3,
         "NOTIMP": 4, "REFUSED": 5}
    if tok.upper() in r:
        return r[tok.upper()]
    return int(tok)


def wire_query(dnsid, rd, name, qtype, qclass):
    flags = 0x0100 if rd else 0
    qn = qname_enc(name)
    return (struct.pack(">HHHHHH", dnsid, flags, 1, 0, 0, 0) + qn +
            struct.pack(">HH", parse_type(qtype), parse_class(qclass)))


def txt_rdata(ans):
    strs = ans.get("txt_strings") or ([ans.get("rdata", "")] if ans.get("rdata") else [])
    return b"".join(bytes([len(s)]) + s.encode() for s in strs)


def answer_rdata(ans):
    t = ans.get("type", "A")
    if t == "A":
        return socket.inet_aton(ans["rdata"])
    if t == "AAAA":
        return socket.inet_pton(socket.AF_INET6, ans["rdata"])
    if t == "TXT":
        return txt_rdata(ans)
    if t in ("CNAME", "NS", "PTR"):
        return qname_enc(ans["rdata"])
    if t == "MX":
        return struct.pack(">H", ans.get("mx_pref", 0)) + qname_enc(ans["rdata"])
    if t == "SOA":
        return (qname_enc(ans["mname"]) + qname_enc(ans["rname"]) +
                struct.pack(">IIIII", ans.get("serial", 0), ans.get("refresh", 0),
                            ans.get("retry", 0), ans.get("expire", 0),
                            ans.get("minimum", 0)))
    if t in ("HTTPS", "SVCB"):
        out = struct.pack(">H", ans.get("priority", 0)) + qname_enc(ans.get("target", "."))
        for p in ans.get("params", []):
            v = bytes.fromhex(p.get("value_hex", ""))
            out += struct.pack(">HH", p["key"], len(v)) + v
        return out
    return bytes.fromhex(ans.get("rdata", ""))


def answer_rr(ans):
    qn = qname_enc(ans.get("name", NAME))
    rd = answer_rdata(ans)
    return (qn + struct.pack(">HHIH", parse_type(ans.get("type", "A")),
                             parse_class(ans.get("class", "IN")),
                             ans.get("ttl", 0), len(rd)) + rd)


def wire_response(dnsid, rd, resp, name, qtype, qclass):
    """resp: the event response dict (status/rcode/answers/authority/aa/tc/ra)."""
    flags = 0x8000 | parse_rcode(resp.get("rcode", ""))
    if rd:
        flags |= 0x0100
    if resp.get("ra", True):
        flags |= 0x0080
    if resp.get("aa"):
        flags |= 0x0400
    if resp.get("tc"):
        flags |= 0x0200
    answers = b"".join(answer_rr(a) for a in resp.get("answers", []))
    authority = b"".join(answer_rr(a) for a in resp.get("authority", []))
    qn = qname_enc(name)
    return (struct.pack(">HHHHHH", dnsid, flags, 1, len(resp.get("answers", [])),
                        len(resp.get("authority", [])), 0) +
            qn + struct.pack(">HH", parse_type(qtype), parse_class(qclass)) +
            answers + authority)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def status_text(code):
    return {200: "OK", 400: "Bad Request", 404: "Not Found",
            415: "Unsupported Media Type", 500: "Internal Server Error",
            503: "Service Unavailable"}.get(code, "OK")


def apply_headers(pairs, overrides):
    """Mirror of doh.headerList.applyOverrides: same-name (case-insensitive)
    values replace in place (original name spelling kept), "" removes,
    unknown names append sorted."""
    names = [n for n, _ in pairs]
    values = dict(pairs)
    if overrides:
        for n in names:
            for k, v in overrides.items():
                if n.lower() == k.lower():
                    values[n] = v
        names = [n for n in names if values[n] != ""]
        extras = sorted(k for k, v in overrides.items()
                        if v != "" and not any(n.lower() == k.lower() for n in names))
        for k in extras:
            names.append(k)
            values[k] = overrides[k]
    return [(n, values[n]) for n in names]


def render(lines):
    return b"".join(("%s: %s\r\n" % (n, v)).encode() for n, v in lines)


def post_head(uri, host, wire, connection, overrides=None):
    h = apply_headers([("Host", host), ("Content-Type", MEDIA),
                       ("Accept", MEDIA), ("Content-Length", str(len(wire))),
                       ("Connection", connection)], overrides or {})
    return ("POST %s HTTP/1.1\r\n" % uri).encode() + render(h) + b"\r\n"


def get_head(host, param, extra_query, connection, overrides=None):
    uri = "/dns-query?dns=" + param + (("&" + extra_query) if extra_query else "")
    h = apply_headers([("Host", host), ("Accept", MEDIA),
                       ("Content-Length", "0"), ("Connection", connection)],
                      overrides or {})
    return ("GET %s HTTP/1.1\r\n" % uri).encode() + render(h) + b"\r\n"


def resp2xx_head(status, wire, max_age, overrides=None):
    h = apply_headers([("Content-Type", MEDIA), ("Content-Length", str(len(wire))),
                       ("Cache-Control", "max-age=%d" % max_age)], overrides or {})
    return ("HTTP/1.1 %d %s\r\n" % (status, status_text(status))).encode() + render(h) + b"\r\n"


def err_head(status):
    return ("HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n" % (status, status_text(status))).encode()


# ------------------------------------------------------- spec/assertion helpers
def hexs(b):
    return b.hex().upper()


def layers_v4():
    return [{"ip": {}}, {"tcp": {}}, {"http": {}}, {"doh": {}}]


def spec(doh_cfg, src_ip=V4_SRC, dst_ip=V4_DST, src_port=SRC_PORT, dst_port=DST_PORT):
    return {"layers": layers_v4(), "src_ip": src_ip, "src_port": src_port,
            "dst_ip": dst_ip, "dst_port": dst_port, "doh": doh_cfg}


def ev(name=NAME, qtype="A", dnsid=DNSID, method=None, resp=None, rd=None,
       http=None, uri=None, extra_query=None, qclass=None):
    e = {"kind": "query", "dns_id": dnsid, "name": name, "qtype": qtype}
    if qclass:
        e["qclass"] = qclass
    if method:
        e["method"] = method
    if uri:
        e["uri"] = uri
    if extra_query:
        e["extra_query"] = extra_query
    if rd is not None:
        e["rd"] = rd
    if resp is not None:
        e["response"] = resp
    if http:
        e["http"] = http
    return e


def sess(events, src_port=None):
    s = {"events": events}
    if src_port:
        s["src_port"] = src_port
    return s


def A_answer(name=NAME, ttl=TTL, rdata=A_RDATA, cls=None):
    a = {"name": name, "type": "A", "ttl": ttl, "rdata": rdata}
    if cls:
        a["class"] = cls
    return a


def ok_resp(answers=None, rcode="NOERROR", status=200, aa=None, ra=None, authority=None):
    r = {"status": status, "rcode": rcode}
    if answers is not None:
        r["answers"] = answers
    if authority is not None:
        r["authority"] = authority
    if aa is not None:
        r["aa"] = aa
    if ra is not None:
        r["ra"] = ra
    return r


def single(doh_cfg, **kw):
    return spec(doh_cfg, **kw)


def fld(pkt, field, value=None, nonzero=False, same=None, distinct=None, exclude=None):
    f = {"packet": pkt, "field": field}
    if value is not None:
        f["value"] = value
    elif nonzero:
        f["nonzero"] = True
    elif same:
        f["same_as_packet"] = same
    elif distinct is not None:
        f["distinct_values"] = distinct
        if exclude:
            f["distinct_exclude"] = exclude
    return f


def frm(pkt, offset, data):
    return {"packet": pkt, "offset": offset, "hex": hexs(data)}


def dns_off(pkt_head_len, v6=False):
    """DNS wire start offset inside a POST/response frame."""
    return (V6OFF if v6 else V4OFF) + pkt_head_len


def find_off(head, needle):
    """Byte offset of an ASCII needle inside a mirrored head block."""
    return head.find(needle.encode())


# Frame computation for one POST query event (mirror of buildTransaction).
def post_frames(e, host=V4_DST, last=True):
    rd = e.get("rd", True)
    qw = wire_query(e["dns_id"], rd, e.get("name", ""), e.get("qtype", "A"), e.get("qclass", ""))
    conn = "close" if last else "keep-alive"
    req_head = post_head(e.get("uri", "/dns-query"), host, qw, conn, (e.get("http") or {}).get("request_headers"))
    resp = e.get("response") or {}
    status = resp.get("status", 0) or 200
    if not (200 <= status <= 299):
        return req_head, qw, err_head(status), None
    rw = wire_response(e["dns_id"], rd, resp, e.get("name", ""), e.get("qtype", "A"), e.get("qclass", ""))
    max_age = min([a.get("ttl", 0) for a in resp.get("answers", [])] or
                  [a.get("minimum", 0) for a in resp.get("authority", [])] or [0])
    rh = resp2xx_head(status, rw, max_age, (e.get("http") or {}).get("response_headers"))
    return req_head, qw, rh, rw


def get_frames(e, host=V4_DST, last=True):
    rd = e.get("rd", True)
    qw = wire_query(e["dns_id"], rd, e.get("name", ""), e.get("qtype", "A"), e.get("qclass", ""))
    param = b64url(qw)
    conn = "close" if last else "keep-alive"
    req_head = get_head(host, param, e.get("extra_query", ""), conn, (e.get("http") or {}).get("request_headers"))
    resp = e.get("response") or {}
    status = resp.get("status", 0) or 200
    if not (200 <= status <= 299):
        return req_head, qw, param, err_head(status), None
    rw = wire_response(e["dns_id"], rd, resp, e.get("name", ""), e.get("qtype", "A"), e.get("qclass", ""))
    max_age = min([a.get("ttl", 0) for a in resp.get("answers", [])] or
                  [a.get("minimum", 0) for a in resp.get("authority", [])] or [0])
    rh = resp2xx_head(status, rw, max_age, (e.get("http") or {}).get("response_headers"))
    return req_head, qw, param, rh, rw


CASES = []


def case(cid, summary, sp, expect):
    CASES.append({"id": cid, "proto": "doh", "summary": summary,
                  "spec_json": sp, "expect": expect})


def neg(cid, summary, sp, anchor):
    case(cid, summary, sp, {"expect_error": True, "error_contains": anchor})


REQ, RESP = 4, 5  # single-transaction packet indices


def base_expect(count=9, hs=True, term=True):
    e = {}
    if hs:
        e["has_handshake"] = True
    if term:
        e["terminates"] = True
    e["packet_count"] = count
    return e


# ================================================================ 1-84 positives
def c01():
    e = ev(resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "POST"),
        fld(REQ, "http.request.uri", "/dns-query"),
        fld(REQ, "http.content_type", MEDIA),
        fld(REQ, "http.content_length", nonzero=True),
        fld(REQ, "http.accept", MEDIA),
        fld(REQ, "http.host", V4_DST),
        fld(REQ, "http.file_data", nonzero=True),
        fld(REQ, "dns.id", "0x%04x" % DNSID),
        fld(REQ, "dns.qry.name", NAME),
        fld(RESP, "http.response.code", "200"),
        fld(RESP, "http.content_type", MEDIA),
        fld(RESP, "dns.id", same=REQ),
        fld(RESP, "dns.flags.response", "1"),
        fld(RESP, "dns.flags.rcode", "0"),
        fld(RESP, "dns.count.answers", "1"),
    ]
    ex["frames"] = [frm(REQ, V4OFF, b"POST /dns-query ")]
    case("doh_post_ipv4_http11", "POST/IPv4 plaintext single-flow baseline", sp, ex)


def c02():
    e = ev(method="GET")
    sp = single({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=" + param),
        fld(REQ, "http.content_length", "0"),
        fld(RESP, "http.response.code", "200"),
        fld(RESP, "dns.qry.name", NAME),
        fld(RESP, "dns.id", "0x%04x" % DNSID),
    ]
    # Full header block prefix pins the exact header set (no Content-Type).
    ex["frames"] = [frm(REQ, V4OFF, rh)]
    case("doh_get_ipv4_base64url", "GET dns parameter base64url unpadded (no body, CL:0)", sp, ex)


def _v6_spec(doh_cfg):
    return spec(doh_cfg, src_ip=V6_SRC, dst_ip=V6_DST)


def c03():
    e = ev(resp=ok_resp([A_answer()]))
    sp = _v6_spec({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(1, "ipv6.version", "6"),
        fld(REQ, "ipv6.nxt", "6"),
        fld(REQ, "http.request.method", "POST"),
        fld(REQ, "http.content_type", MEDIA),
        fld(REQ, "dns.qry.name", NAME),
        fld(RESP, "http.response.code", "200"),
        fld(RESP, "dns.count.answers", "1"),
    ]
    ex["frames"] = [frm(REQ, V6OFF, b"POST /dns-query ")]
    case("doh_post_ipv6_http11", "POST/IPv6 carrier (ipv6.nxt=6, offset 74)", sp, ex)


def c04():
    e = ev(method="GET")
    sp = _v6_spec({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e, host=V6_DST)
    ex = base_expect()
    ex["fields"] = [
        fld(1, "ipv6.version", "6"),
        fld(REQ, "ipv6.nxt", "6"),
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=" + param),
        fld(RESP, "dns.qry.name", NAME),
    ]
    ex["frames"] = [frm(REQ, V6OFF, rh)]
    case("doh_get_ipv6_base64url", "GET/IPv6 isolated fixture (2001:db8::66 -> 2001:db8::100:66)", sp, ex)


def c05():
    e = ev(resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    doff, roff = dns_off(len(rh)), dns_off(len(sh))
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "dns.flags.response", "0"),
        fld(REQ, "dns.flags.opcode", "0"),
        fld(REQ, "dns.flags.truncated", "0"),
        fld(REQ, "dns.flags.recdesired", "1"),
        fld(REQ, "dns.flags.z", "0"),
        fld(REQ, "dns.count.queries", "1"),
        fld(REQ, "dns.count.answers", "0"),
        fld(REQ, "dns.count.auth_rr", "0"),
        fld(REQ, "dns.count.add_rr", "0"),
        fld(RESP, "dns.flags.authoritative", "0"),
        fld(RESP, "dns.flags.truncated", "0"),
        fld(RESP, "dns.flags.z", "0"),
        fld(RESP, "dns.count.auth_rr", "0"),
        fld(RESP, "dns.count.add_rr", "0"),
    ]
    ex["frames"] = [
        frm(REQ, doff, qw[0:6]),          # ID + flags 01 00
        frm(REQ, doff + 4, b"\x00\x01\x00\x00\x00\x00\x00\x00"),  # counts
        frm(RESP, roff + 2, b"\x81\x80"),
    ]
    case("doh_dns_header_query", "DNS header 12B big-endian field-by-field", sp, ex)


def c06():
    e = ev(resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    qoff = dns_off(len(rh)) + 12  # QNAME start
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "dns.qry.name", NAME),
        fld(REQ, "dns.qry.name.len", "15"),
        fld(REQ, "dns.qry.type", "1"),
        fld(REQ, "dns.qry.class", "0x0001"),
    ]
    ex["frames"] = [
        frm(REQ, qoff, b"\x03www"),
        frm(REQ, qoff + len(qname_enc(NAME)) - 1, b"\x00\x00\x01\x00\x01"),  # root + QTYPE + QCLASS
    ]
    case("doh_dns_question_a", "QNAME label encoding, QTYPE=A(1), QCLASS=IN(1)", sp, ex)


def c07():
    e = ev(qtype="AAAA", resp=ok_resp([{"name": NAME, "type": "AAAA", "ttl": TTL, "rdata": AAAA_RDATA}]))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "dns.qry.type", "28"),
        fld(RESP, "dns.resp.type", "28"),
        fld(RESP, "dns.aaaa", AAAA_RDATA),
    ]
    case("doh_dns_question_aaaa", "QTYPE=AAAA(28) query with AAAA answer", sp, ex)


def c08():
    e = ev(qtype="HTTPS", resp=ok_resp([HTTPS_ALPN]))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "dns.qry.type", "65"),
        fld(RESP, "dns.resp.type", "65"),
    ]
    case("doh_dns_question_https", "QTYPE=HTTPS(65) query (RFC 9460)", sp, ex)


def c09():
    e = ev(name="", resp=ok_resp([]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    assert len(qw) == 17
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "dns.qry.name", "<Root>"),
        fld(REQ, "dns.count.labels", "1"),
        fld(REQ, "http.content_length", "17"),
        fld(RESP, "http.content_length", "17"),
    ]
    ex["frames"] = [frm(REQ, dns_off(len(rh)) + 12, b"\x00")]
    case("doh_dns_question_root", "Root QNAME shortest message (wire 17B)", sp, ex)


def c10():
    e = ev(resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.flags.response", "1"),
        fld(RESP, "dns.flags.rcode", "0"),
        fld(RESP, "dns.flags.recavail", "1"),
        fld(RESP, "dns.id", same=REQ),
        fld(RESP, "dns.count.queries", "1"),
        fld(RESP, "dns.count.answers", "1"),
    ]
    case("doh_dns_response_noerror", "RCODE=0, QR=1, RA=1, ID echo", sp, ex)


def _rcode_case(cid, summary, rcode, val):
    e = ev(resp=ok_resp([], rcode=rcode))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "http.response.code", "200"),
        fld(RESP, "dns.flags.rcode", val),
        fld(RESP, "dns.count.answers", "0"),
    ]
    case(cid, summary, sp, ex)


def c11():
    _rcode_case("doh_dns_response_nxdomain", "RCODE=3 NXDOMAIN with HTTP 200 (HTTP success != DNS success)", "NXDOMAIN", "3")


def c12():
    _rcode_case("doh_dns_response_servfail", "RCODE=2 SERVFAIL with HTTP 200", "SERVFAIL", "2")


def c13():
    e = ev(resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    # Locate TTL/RDLENGTH/RDATA inside the response wire: answer starts after
    # header(12) + question(qname+4); RR = qname + TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2)+RDATA.
    ans_off = 12 + len(qname_enc(NAME)) + 4 + len(qname_enc(NAME))
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.count.answers", "1"),
        fld(RESP, "dns.resp.type", "1"),
        fld(RESP, "dns.resp.class", "0x0001"),
        fld(RESP, "dns.resp.ttl", str(TTL)),
        fld(RESP, "dns.a", A_RDATA),
    ]
    ex["frames"] = [
        frm(RESP, dns_off(len(sh)) + ans_off + 4, struct.pack(">I", TTL)),
        frm(RESP, dns_off(len(sh)) + ans_off + 8, b"\x00\x04\xc0\x00\x02\x01"),
    ]
    case("doh_dns_answer_ttl", "A answer NAME/TYPE/CLASS/TTL/RDLENGTH/RDATA structure", sp, ex)


def c14():
    es = [ev(dnsid=0x1234, name="www.example.com", qtype="A", resp=ok_resp([A_answer("www.example.com")])),
          ev(dnsid=0x1235, name="www.example.net", qtype="AAAA",
             resp=ok_resp([{"name": "www.example.net", "type": "AAAA", "ttl": TTL, "rdata": AAAA_RDATA}])),
          ev(dnsid=0x1236, name="www.example.org", qtype="HTTPS", resp=ok_resp([dict(HTTPS_ALPN, name="www.example.org")]))]
    sp = single({"sessions": [sess(es)]})
    ex = base_expect(count=13)
    heads = [post_frames(e, last=(i == 2))[0] for i, e in enumerate(es)]
    ex["fields"] = [
        fld(4, "tcp.stream", "0"),
        fld(6, "tcp.stream", same=4),
        fld(8, "tcp.stream", same=4),
        fld(5, "dns.id", same=4),
        fld(7, "dns.id", same=6),
        fld(9, "dns.id", same=8),
        fld(4, "dns.qry.name", "www.example.com"),
        fld(6, "dns.qry.name", "www.example.net"),
        fld(8, "dns.qry.name", "www.example.org"),
    ]
    ex["frames"] = [
        frm(4, V4OFF + find_off(heads[0], "Connection: keep-alive"), b"Connection: keep-alive\r\n"),
        frm(6, V4OFF + find_off(heads[1], "Connection: keep-alive"), b"Connection: keep-alive\r\n"),
        frm(8, V4OFF + find_off(heads[2], "Connection: close"), b"Connection: close\r\n"),
    ]
    case("doh_http_keepalive_multi_transaction", "3 transactions on one connection, per-request keep-alive policy", sp, ex)


def c15():
    e = ev(resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    assert len(qw) == 33 and len(rw) == 64
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.content_length", "33"),
        fld(RESP, "http.content_length", "64"),
    ]
    ex["frames"] = [frm(REQ, V4OFF + find_off(rh, "Content-Length: 33"), b"Content-Length: 33")]
    case("doh_http_content_length_exact", "Content-Length exact 33 (request) / 64 (response)", sp, ex)


def c16():
    answers = [A_answer(ttl=300), A_answer(ttl=60)]
    e = ev(resp=ok_resp(answers))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    qn = qname_enc(NAME)
    a1 = 12 + len(qn) + 4 + len(qn) + 4  # TTL of first answer
    a2 = a1 + 2 + 2 + 4 + 2 + 4 + len(qn)  # TTL of second answer
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "http.cache_control", "max-age=60"),
        fld(RESP, "dns.count.answers", "2"),
    ]
    ex["frames"] = [
        frm(RESP, dns_off(len(sh)) + a1, struct.pack(">I", 300)),
        frm(RESP, dns_off(len(sh)) + a2, struct.pack(">I", 60)),
    ]
    case("doh_http_cache_control", "max-age equals the MINIMUM answer TTL (300/60 -> 60)", sp, ex)


def _err_case(cid, summary, e, code):
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "http.response.code", str(code)),
        fld(RESP, "http.content_length", "0"),
    ]
    ex["frames"] = [frm(RESP, V4OFF, err_head(code))]
    case(cid, summary, sp, ex)


def c17():
    _err_case("doh_http_error_400", "GET missing dns parameter -> 400 empty body, no DNS wire",
              ev(method="GET", resp={"status": 400}), 400)


def c18():
    _err_case("doh_http_error_404", "Unknown URI -> 404 empty body, no DNS wire",
              ev(uri="/unknown", resp={"status": 404}), 404)


def c19():
    e = ev(resp={"status": 415}, http={"request_headers": {"Content-Type": "text/plain"}})
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.content_type", "text/plain"),
        fld(RESP, "http.response.code", "415"),
        fld(RESP, "http.content_length", "0"),
    ]
    ex["frames"] = [frm(RESP, V4OFF, err_head(415))]
    case("doh_http_error_415", "Unsupported media type -> 415 empty body, no DNS wire", sp, ex)


def c20():
    # 3 TXT answers x two 255-char strings -> response spans 2 TCP segments.
    s = "T" * 255
    answers = [{"name": NAME, "type": "TXT", "ttl": TTL, "txt_strings": [s, s]} for _ in range(3)]
    e = ev(resp=ok_resp(answers))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    frame = sh + rw
    assert len(rw) == 1650 and len(frame) > 1460, (len(frame), len(rw))
    seg2 = len(frame) - 1460
    ex = base_expect(count=10)
    ex["fields"] = [
        fld(REQ, "http.request.method", "POST"),
        fld(REQ, "http.content_length", "33"),
        fld(6, "http.response.code", "200"),
        fld(6, "http.content_length", "1650"),
        fld(6, "dns.count.answers", "3"),
    ]
    ex["frames"] = [frm(6, V4OFF + seg2 - 1, b"T")]
    case("doh_mss_large_response", "Large response spans MSS segments (3 TXT x 2x255 strings, 1650B wire)", sp, ex)


def c21():
    e1 = ev(dnsid=0x1234, name="www.example.com", resp=ok_resp([A_answer("www.example.com")]))
    e2 = ev(dnsid=0x2401, name="www.example.net", resp=ok_resp([A_answer("www.example.net")]))
    sp = single({"sessions": [sess([e1], src_port=42066), sess([e2], src_port=42067)]})
    ex = base_expect(count=18)
    ex["fields"] = [
        fld(1, "tcp.flags", "0x002"),
        fld(10, "tcp.flags", "0x002"),
        fld(10, "tcp.srcport", "42067"),
        fld(0, "tcp.stream", distinct=["0", "1"]),
        fld(4, "dns.qry.name", "www.example.com"),
        fld(13, "dns.qry.name", "www.example.net"),
    ]
    case("doh_multi_session", "Two sessions sequential, dual 4-tuples, isolated state", sp, ex)


def c22():
    e = ev(resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]}, dst_port=8080)
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "tcp.dstport", "8080"),
        fld(REQ, "http.request.method", "POST"),
        fld(REQ, "http.content_type", MEDIA),
        fld(RESP, "dns.count.answers", "1"),
    ]
    case("doh_port_nondefault_post", "POST on non-default port 8080 (full-stack semantics unchanged)", sp, ex)


def c23():
    e = ev(method="GET")
    sp = single({"method": "GET", "sessions": [sess([e])]}, dst_port=8080)
    rh, qw, param, sh, rw = get_frames(e)
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "tcp.dstport", "8080"),
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=" + param),
    ]
    case("doh_port_nondefault_get", "GET on non-default port 8080", sp, ex)


def c24():
    e1 = ev(dnsid=0x1234, name="www.example.com", resp=ok_resp([A_answer("www.example.com")]))
    e2 = ev(dnsid=0x2401, name="www.example.net", resp=ok_resp([A_answer("www.example.net")]))
    sp = single({"concurrent": True, "sessions": [sess([e1], src_port=42066), sess([e2], src_port=42067)]})
    ex = base_expect(count=18)
    ex["fields"] = [
        fld(0, "tcp.stream", distinct=["0", "1"]),
        fld(0, "dns.qry.name", distinct=["www.example.com", "www.example.net"]),
    ]
    case("doh_concurrent_sessions", "Two concurrent sessions interleaved, no state bleed", sp, ex)


def _residue_case(cid, summary, name, wire_len, b64_len):
    e = ev(name=name, method="GET")
    sp = single({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    assert len(qw) == wire_len and len(param) == b64_len, (len(qw), len(param))
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=" + param),
        fld(RESP, "http.content_length", str(wire_len)),
        fld(RESP, "dns.count.answers", "0"),
    ]
    case(cid, summary, sp, ex)


def c25():
    _residue_case("doh_b64_residue_1", "base64url residue-1 form: 19B wire -> 26-char param", "a", 19, 26)


def c26():
    _residue_case("doh_b64_residue_2", "base64url residue-2 form: 20B wire -> 27-char param", "ab", 20, 27)


def c27():
    _rcode_case("doh_dns_rcode_formerr", "RCODE=1 FORMERR carried by 200", "FORMERR", "1")


def c28():
    _rcode_case("doh_dns_rcode_notimp", "RCODE=4 NOTIMP", "NOTIMP", "4")


def c29():
    _rcode_case("doh_dns_rcode_refused", "RCODE=5 REFUSED", "REFUSED", "5")


def c30():
    e = ev(resp=ok_resp([], rcode="15"))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.flags.rcode", "15"),
        fld(RESP, "dns.count.answers", "0"),
    ]
    ex["frames"] = [frm(RESP, dns_off(len(sh)) + 2, b"\x81\x8f")]
    case("doh_dns_rcode_15_upper", "RCODE=15 (4-bit value upper bound)", sp, ex)


def c31():
    e = ev(rd=False, resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    ex = base_expect()
    ex["fields"] = [fld(REQ, "dns.flags.recdesired", "0")]
    ex["frames"] = [frm(REQ, dns_off(len(rh)) + 2, b"\x00\x00")]
    case("doh_dns_rd_zero", "Request RD=0 (recursion not desired)", sp, ex)


def c32():
    e = ev(resp=ok_resp([A_answer()], ra=False))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.flags.recavail", "0"),
        fld(RESP, "dns.flags.response", "1"),
    ]
    case("doh_dns_ra_zero", "Response RA=0 (no recursion available)", sp, ex)


def c33():
    e = ev(resp=ok_resp([A_answer()], aa=True))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    ex = base_expect()
    ex["fields"] = [fld(RESP, "dns.flags.authoritative", "1")]
    ex["frames"] = [frm(RESP, dns_off(len(sh)) + 2, b"\x85\x80")]
    case("doh_dns_aa_set", "Response AA=1 (authoritative answer), flags 85 80", sp, ex)


def c34():
    e = ev(qtype="TXT", resp=ok_resp([{"name": NAME, "type": "TXT", "ttl": TTL, "rdata": "hello"}]))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "dns.qry.type", "16"),
        fld(RESP, "dns.resp.type", "16"),
    ]
    case("doh_dns_question_txt", "QTYPE=TXT(16) query with single-string TXT answer", sp, ex)


def c35():
    e = ev(qtype="MX", resp=ok_resp([{"name": NAME, "type": "MX", "ttl": TTL, "mx_pref": 10, "rdata": "mail.example.com"}]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    qn = qname_enc(NAME)
    rd_off = dns_off(len(sh)) + 12 + len(qn) + 4 + len(qn) + 10
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "dns.qry.type", "15"),
        fld(RESP, "dns.resp.type", "15"),
    ]
    ex["frames"] = [frm(RESP, rd_off, b"\x00\x0a" + qname_enc("mail.example.com"))]
    case("doh_dns_question_mx", "QTYPE=MX(15) query; MX answer pref 2B big-endian + exchange", sp, ex)


def c36():
    e = ev(qclass="CHAOS", resp=ok_resp([A_answer(cls="CHAOS")]))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "dns.qry.class", "0x0003"),
        fld(RESP, "dns.qry.class", "0x0003"),
        fld(RESP, "dns.resp.class", "0x0003"),
    ]
    case("doh_dns_qclass_ch", "QCLASS=CHAOS(3) value variant, echoed in answer", sp, ex)


def c37():
    e = ev(qtype="AAAA", resp=ok_resp([{"name": NAME, "type": "AAAA", "ttl": TTL, "rdata": AAAA_RDATA}]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    qn = qname_enc(NAME)
    rd_off = dns_off(len(sh)) + 12 + len(qn) + 4 + len(qn) + 10
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.aaaa", AAAA_RDATA),
        fld(RESP, "dns.resp.type", "28"),
    ]
    ex["frames"] = [frm(RESP, rd_off - 2, b"\x00\x10" + socket.inet_pton(socket.AF_INET6, AAAA_RDATA))]
    case("doh_dns_answer_aaaa", "AAAA answer (RDLENGTH=16)", sp, ex)


def c38():
    answers = [{"name": NAME, "type": "CNAME", "ttl": TTL, "rdata": "cname.example.com"},
               {"name": "cname.example.com", "type": "A", "ttl": TTL, "rdata": A_RDATA}]
    e = ev(resp=ok_resp(answers))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.count.answers", "2"),
        fld(RESP, "dns.resp.type", "5,1"),
        fld(RESP, "dns.cname", "cname.example.com"),
        fld(RESP, "dns.a", A_RDATA),
    ]
    case("doh_dns_answer_cname_chain", "CNAME -> A two-answer chain", sp, ex)


def c39():
    answers = [A_answer(ttl=TTL), {"name": NAME, "type": "AAAA", "ttl": TTL, "rdata": AAAA_RDATA}]
    e = ev(resp=ok_resp(answers))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.count.answers", "2"),
        fld(RESP, "dns.resp.type", "1,28"),
        fld(RESP, "dns.a", A_RDATA),
        fld(RESP, "dns.aaaa", AAAA_RDATA),
    ]
    case("doh_dns_answer_multi_types", "A + AAAA answers in configured order", sp, ex)


HTTPS_ALPN = {"name": NAME, "type": "HTTPS", "ttl": TTL, "priority": 1, "target": ".",
              "params": [{"key": 1, "value_hex": "026832"}]}


def c40():
    e = ev(qtype="HTTPS", resp=ok_resp([HTTPS_ALPN]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    qn = qname_enc(NAME)
    rd_off = dns_off(len(sh)) + 12 + len(qn) + 4 + len(qn) + 10
    ex = base_expect()
    ex["fields"] = [fld(RESP, "dns.resp.type", "65")]
    ex["frames"] = [frm(RESP, rd_off, b"\x00\x01\x00\x00\x01\x00\x03\x02\x68\x32")]
    case("doh_dns_answer_svcb_alpn", "HTTPS SVCB AnswerForm (priority + root target + alpn h2)", sp, ex)


def c41():
    alias = {"name": NAME, "type": "HTTPS", "ttl": TTL, "priority": 0, "target": "svc.example.net", "params": []}
    e = ev(qtype="HTTPS", resp=ok_resp([alias]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    qn = qname_enc(NAME)
    rd_off = dns_off(len(sh)) + 12 + len(qn) + 4 + len(qn) + 10
    ex = base_expect()
    ex["fields"] = [fld(RESP, "dns.resp.type", "65")]
    ex["frames"] = [frm(RESP, rd_off, b"\x00\x00" + qname_enc("svc.example.net"))]
    case("doh_dns_answer_svcb_alias", "HTTPS SVCB AliasForm (priority 0 + svc.example.net + empty params, RDLENGTH 19)", sp, ex)


def c42():
    e = ev(qtype="TXT", resp=ok_resp([{"name": NAME, "type": "TXT", "ttl": TTL, "txt_strings": ["hello", "world"]}]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    qn = qname_enc(NAME)
    rd_off = dns_off(len(sh)) + 12 + len(qn) + 4 + len(qn) + 10
    ex = base_expect()
    ex["fields"] = [fld(RESP, "dns.resp.type", "16")]
    ex["frames"] = [frm(RESP, rd_off, b"\x05hello\x05world")]
    case("doh_dns_answer_txt_strings", "TXT multi character-strings (per-segment length byte)", sp, ex)


SOA = {"name": "example.com", "type": "SOA", "ttl": 60, "mname": "ns.example.com",
       "rname": "hostmaster.example.com", "serial": 2026090101, "refresh": 7200,
       "retry": 3600, "expire": 1209600, "minimum": 60}


def c43():
    e = ev(name="www.example.com", resp=ok_resp([], rcode="NXDOMAIN", authority=[SOA]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    soa_name_off = dns_off(len(sh)) + 12 + len(qname_enc(NAME)) + 4  # authority RR NAME start
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.count.answers", "0"),
        fld(RESP, "dns.count.auth_rr", "1"),
        fld(RESP, "http.cache_control", "max-age=60"),
    ]
    ex["frames"] = [
        frm(RESP, soa_name_off + len(qname_enc("example.com")), b"\x00\x06"),        # SOA TYPE
        frm(RESP, soa_name_off + len(answer_rr(SOA)) - 4, struct.pack(">I", 60)),    # MINIMUM
    ]
    case("doh_dns_negative_cache_soa", "Negative cache: ANCOUNT=0 + NSCOUNT=1 + SOA + max-age=MINIMUM", sp, ex)


def c44():
    e = ev(resp=ok_resp([A_answer()], ), http={"response_headers": {"Age": "60"}})
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "http.cache_control", "max-age=300"),
        fld(RESP, "dns.count.answers", "1"),
    ]
    ex["frames"] = [frm(RESP, V4OFF + find_off(sh, "Age: 60"), b"Age: 60")]
    case("doh_http_cache_age_header", "Age header present (RFC 8484 5.1 client consideration)", sp, ex)


def c45():
    e1 = ev(dnsid=0x1234, resp=ok_resp([A_answer()]))
    e2 = ev(dnsid=0x1235, method="GET")
    sp = single({"sessions": [sess([e1, e2])]})
    ex = base_expect(count=11)
    ex["fields"] = [
        fld(4, "http.request.method", "POST"),
        fld(4, "http.content_type", MEDIA),
        fld(5, "http.response.code", "200"),
        fld(6, "http.request.method", "GET"),
        fld(6, "http.content_length", "0"),
        fld(6, "tcp.stream", same=4),
        fld(7, "http.response.code", "200"),
    ]
    case("doh_http_mixed_get_post", "POST -> GET mixed on one connection; Content-Type only on POST", sp, ex)


def c46():
    e = ev(resp=ok_resp([A_answer()]), http={"request_headers": {"Host": "doh.example.com"}})
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.host", "doh.example.com"),
        fld(REQ, "http.request.method", "POST"),
    ]
    case("doh_http_host_explicit", "Explicit Host header (doh.example.com, not dst_ip default)", sp, ex)


def c47():
    e = ev(method="GET", extra_query="foo=bar", resp={"status": 400})
    sp = single({"sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=%s&foo=bar" % param),
        fld(RESP, "http.response.code", "400"),
        fld(RESP, "http.content_length", "0"),
    ]
    ex["frames"] = [frm(RESP, V4OFF, err_head(400))]
    case("doh_http_error_400_extra_param", "GET dns + extra query parameter -> 400 (dns is the only parameter)", sp, ex)


def c48():
    e = ev(resp=ok_resp([A_answer()]), http={"request_headers": {"Accept": ""}})
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "POST"),
        fld(RESP, "http.response.code", "200"),
        fld(RESP, "dns.count.answers", "1"),
    ]
    ex["frames"] = [frm(REQ, V4OFF, rh)]  # full header block: no Accept line
    case("doh_http_accept_absent", "Request without Accept header (SHOULD-absent legal form)", sp, ex)


def c49():
    e = ev(resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    ex = base_expect()
    ex["fields"] = [fld(REQ, "http.request.method", "POST")]
    ex["frames"] = [frm(REQ, V4OFF + find_off(rh, "Connection: close"), b"Connection: close\r\n")]
    case("doh_http_connection_close", "Single transaction explicit Connection: close", sp, ex)


def c50():
    e = ev(name="", method="GET")
    sp = single({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    assert len(param) == 23
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=" + param),
        fld(RESP, "http.content_length", "17"),
    ]
    case("doh_min_frame_get", "Minimal GET: root name 17B wire -> 23-char param", sp, ex)


def _ttl_case(cid, summary, ttl):
    e = ev(resp=ok_resp([A_answer(ttl=ttl)]))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.resp.ttl", str(ttl)),
        fld(RESP, "http.cache_control", "max-age=%d" % ttl),
    ]
    case(cid, summary, sp, ex)


def c51():
    _ttl_case("doh_dns_ttl_zero", "TTL=0 boundary + max-age=0", 0)


def c52():
    _ttl_case("doh_dns_ttl_max", "TTL=0xFFFFFFFF full value + max-age=4294967295", 4294967295)


def _qname_len_case(cid, summary, name, name_len, cl):
    e = ev(name=name)
    sp = single({"sessions": [sess([e])]})
    rh, qw, sh, rw = post_frames(e)
    assert len(qw) == cl, (cid, len(qw))
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.content_length", str(cl)),
        fld(REQ, "dns.qry.name.len", str(name_len)),
    ]
    case(cid, summary, sp, ex)


def c53():
    _qname_len_case("doh_dns_qname_label_63", "Single 63-byte label upper bound (wire 81, CL=81)", "a" * 63, 63, 81)


def c54():
    _qname_len_case("doh_dns_qname_total_255", "Full-name 255-byte upper bound (63/63/63/61 labels, CL=271)",
                    "%s.%s.%s.%s" % ("a" * 63, "b" * 63, "c" * 63, "d" * 61), 253, 271)


def _id_case(cid, summary, dnsid):
    e = ev(dnsid=dnsid, resp=ok_resp([A_answer()]))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "dns.id", "0x%04x" % dnsid),
        fld(RESP, "dns.id", same=REQ),
    ]
    case(cid, summary, sp, ex)


def c55():
    _id_case("doh_dns_id_zero", "DNS ID=0 boundary (RFC 8484 4.1 SHOULD value; declared deviation)", 0)


def c56():
    _id_case("doh_dns_id_max", "DNS ID=65535 full value", 65535)


def c57():
    _id_case("doh_dns_id_one", "DNS ID=1 adjacent value (min+1)", 1)


def c58():
    _id_case("doh_dns_id_65534", "DNS ID=65534 adjacent value (max-1)", 65534)


def c59():
    _ttl_case("doh_dns_ttl_one", "TTL=1 adjacent value + max-age=1", 1)


def c60():
    _ttl_case("doh_dns_ttl_4294967294", "TTL=4294967294 adjacent value", 4294967294)


def c61():
    _qname_len_case("doh_dns_qname_254", "Full-name 254 adjacent value (CL=270)",
                    "%s.%s.%s.%s" % ("a" * 63, "b" * 63, "c" * 63, "d" * 60), 252, 270)


def c62():
    _qname_len_case("doh_dns_qname_label_62", "Single label 62 adjacent value (CL=80)", "a" * 62, 62, 80)


def c63():
    e = ev(name="www.example.com", resp=ok_resp([], rcode="NXDOMAIN", authority=[SOA]))
    sp = single({"sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "http.cache_control", "max-age=60"),
        fld(RESP, "dns.count.auth_rr", "1"),
    ]
    case("doh_http_cache_control_soa_minimum", "Negative-cache max-age exactly equals SOA MINIMUM", sp, ex)


def c64():
    name = "%s.%s.%s.%s" % ("a" * 63, "b" * 63, "c" * 63, "d" * 61)
    e = ev(name=name, method="GET")
    sp = single({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    assert len(qw) == 271 and len(param) == 362, (len(qw), len(param))
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=" + param),
        fld(RESP, "dns.qry.name", name),
    ]
    case("doh_get_qname_max", "255-name GET variant: 271B wire (residue 1) unpadded 362-char param", sp, ex)


def c65():
    e = ev(name="", method="GET")
    sp = single({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    assert len(qw) == 17 and len(param) == 23
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=" + param),
        fld(RESP, "http.content_length", "17"),
    ]
    case("doh_get_root_query", "Root-name GET variant: 17B wire (residue 2) 23-char param", sp, ex)


def _get_qtype_case(cid, summary, qtype, answer):
    e = ev(qtype=qtype, method="GET", resp=ok_resp([answer]))
    sp = single({"method": "GET", "sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.content_length", "0"),
        fld(RESP, "dns.resp.type", str(QTYPE[qtype])),
    ]
    case(cid, summary, sp, ex)


def c66():
    _get_qtype_case("doh_get_question_aaaa", "QTYPE=AAAA(28) GET variant", "AAAA",
                    {"name": NAME, "type": "AAAA", "ttl": TTL, "rdata": AAAA_RDATA})


def c67():
    _get_qtype_case("doh_get_question_https", "QTYPE=HTTPS(65) GET variant", "HTTPS", dict(HTTPS_ALPN))


def c68():
    _get_qtype_case("doh_get_question_txt", "QTYPE=TXT(16) GET variant", "TXT",
                    {"name": NAME, "type": "TXT", "ttl": TTL, "rdata": "hello"})


def c69():
    _get_qtype_case("doh_get_question_mx", "QTYPE=MX(15) GET variant", "MX",
                    {"name": NAME, "type": "MX", "ttl": TTL, "mx_pref": 10, "rdata": "mail.example.com"})


def _get_rcode_case(cid, summary, rcode, val):
    e = ev(method="GET", resp=ok_resp([], rcode=rcode))
    sp = single({"method": "GET", "sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(RESP, "http.response.code", "200"),
        fld(RESP, "dns.flags.rcode", val),
        fld(RESP, "dns.count.answers", "0"),
    ]
    case(cid, summary, sp, ex)


def c70():
    _get_rcode_case("doh_get_rcode_formerr", "RCODE=1 GET variant (2xx carries any RCODE)", "FORMERR", "1")


def c71():
    _get_rcode_case("doh_get_rcode_notimp", "RCODE=4 GET variant", "NOTIMP", "4")


def c72():
    _get_rcode_case("doh_get_rcode_refused", "RCODE=5 GET variant", "REFUSED", "5")


def c73():
    _get_rcode_case("doh_get_rcode_15", "RCODE=15 GET variant (4-bit upper bound)", "15", "15")


def c74():
    e = ev(method="GET", resp=ok_resp([A_answer()]))
    sp = single({"method": "GET", "sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(RESP, "dns.flags.rcode", "0"),
        fld(RESP, "dns.a", A_RDATA),
        fld(RESP, "dns.id", "0x%04x" % DNSID),
    ]
    case("doh_get_response_noerror", "NOERROR + A answer GET variant", sp, ex)


def c75():
    _get_rcode_case("doh_get_response_nxdomain", "NXDOMAIN GET variant", "NXDOMAIN", "3")


def c76():
    _get_rcode_case("doh_get_response_servfail", "SERVFAIL GET variant", "SERVFAIL", "2")


def c77():
    e = ev(method="GET", resp=ok_resp([A_answer()]))
    sp = single({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    qn = qname_enc(NAME)
    rd_off = dns_off(len(sh)) + 12 + len(qn) + 4 + len(qn) + 10
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(RESP, "dns.resp.ttl", str(TTL)),
        fld(RESP, "dns.a", A_RDATA),
    ]
    ex["frames"] = [frm(RESP, rd_off - 2, b"\x00\x04\xc0\x00\x02\x01")]
    case("doh_get_answer_ttl", "A answer structure GET variant (RDLENGTH/RDATA frames)", sp, ex)


def c78():
    e = ev(method="GET", qtype="AAAA", resp=ok_resp([{"name": NAME, "type": "AAAA", "ttl": TTL, "rdata": AAAA_RDATA}]))
    sp = single({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    qn = qname_enc(NAME)
    rd_off = dns_off(len(sh)) + 12 + len(qn) + 4 + len(qn) + 10
    ex = base_expect()
    ex["fields"] = [
        fld(RESP, "dns.aaaa", AAAA_RDATA),
        fld(RESP, "dns.resp.type", "28"),
    ]
    ex["frames"] = [frm(RESP, rd_off - 2, b"\x00\x10")]
    case("doh_get_answer_aaaa", "AAAA answer GET variant (RDLENGTH 00 10)", sp, ex)


def c79():
    answers = [{"name": NAME, "type": "CNAME", "ttl": TTL, "rdata": "cname.example.com"},
               {"name": "cname.example.com", "type": "A", "ttl": TTL, "rdata": A_RDATA}]
    e = ev(method="GET", resp=ok_resp(answers))
    sp = single({"method": "GET", "sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(RESP, "dns.count.answers", "2"),
        fld(RESP, "dns.cname", "cname.example.com"),
        fld(RESP, "dns.a", A_RDATA),
    ]
    case("doh_get_answer_cname_chain", "CNAME -> A chain GET variant", sp, ex)


def c80():
    e = ev(method="GET", qtype="HTTPS", resp=ok_resp([HTTPS_ALPN]))
    sp = single({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    qn = qname_enc(NAME)
    rd_off = dns_off(len(sh)) + 12 + len(qn) + 4 + len(qn) + 10
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(RESP, "dns.resp.type", "65"),
    ]
    ex["frames"] = [frm(RESP, rd_off, b"\x00\x01\x00\x00\x01\x00\x03\x02\x68\x32")]
    case("doh_get_answer_svcb_alpn", "SVCB AnswerForm GET variant", sp, ex)


def c81():
    e = ev(method="GET", name="www.example.com", resp=ok_resp([], rcode="NXDOMAIN", authority=[SOA]))
    sp = single({"method": "GET", "sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(RESP, "dns.count.answers", "0"),
        fld(RESP, "dns.count.auth_rr", "1"),
        fld(RESP, "http.cache_control", "max-age=60"),
    ]
    case("doh_get_negative_cache_soa", "SOA negative cache GET variant", sp, ex)


def c82():
    e = ev(method="GET", rd=False)
    sp = single({"method": "GET", "sessions": [sess([e])]})
    rh, qw, param, sh, rw = get_frames(e)
    assert param.startswith("EjQAAAAB")  # group2 encodes flags 00 00 + QDCOUNT 00 01 (RD off)
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=" + param),
        fld(RESP, "dns.qry.name", NAME),
    ]
    case("doh_get_rd_zero", "RD=0 GET variant (pinned 44-char param, flags 00 00)", sp, ex)


def c83():
    e = ev(method="GET", resp=ok_resp([A_answer()], aa=True))
    sp = single({"method": "GET", "sessions": [sess([e])]})
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "http.request.method", "GET"),
        fld(RESP, "dns.flags.authoritative", "1"),
    ]
    case("doh_get_aa_set", "AA=1 GET variant", sp, ex)


def c84():
    e = ev(method="GET")
    sp = single({"method": "GET", "sessions": [sess([e])]}, dst_port=8080)
    rh, qw, param, sh, rw = get_frames(e)
    ex = base_expect()
    ex["fields"] = [
        fld(REQ, "tcp.dstport", "8080"),
        fld(REQ, "http.request.method", "GET"),
        fld(REQ, "http.request.uri", "/dns-query?dns=" + param),
    ]
    case("doh_get_port_nondefault", "Non-default port 8080 GET variant", sp, ex)


# ================================================================ 85-110 negatives
def n85():
    neg("doh_neg_query_missing", "GET config missing the dns query parameter",
        single({"wire_fault": "query_missing", "method": "GET", "sessions": [sess([ev(method="GET")])]}), "dns")


def n86():
    neg("doh_neg_base64_invalid", "base64url containing illegal characters (+//)",
        single({"wire_fault": "base64", "sessions": [sess([ev()])]}), "base64")


def n87():
    neg("doh_neg_base64_padding", "base64url carrying = padding",
        single({"wire_fault": "padding", "sessions": [sess([ev()])]}), "base64")


def n88():
    neg("doh_neg_base64_truncated", "base64url decoding to fewer than 12 bytes",
        single({"wire_fault": "b64_short", "sessions": [sess([ev()])]}), "decode")


def n89():
    neg("doh_neg_dns_header_short", "POST body shorter than the 12-byte DNS header",
        single({"wire_fault": "dns_header_short", "sessions": [sess([ev()])]}), "dns")


def n90():
    neg("doh_neg_dns_qdcount_zero", "QDCOUNT=0 rejected (question section required)",
        single({"wire_fault": "qdcount", "sessions": [sess([ev()])]}), "question")


def n91():
    # Structural fault input: a 64-byte label exceeds the 63-byte bound.
    neg("doh_neg_dns_qname_overflow", "QNAME label exceeds 63 bytes",
        single({"sessions": [sess([ev(name="a" * 64 + ".com")])]}), "qname")


def n92():
    neg("doh_neg_dns_question_truncated", "Question missing root terminator / QTYPE truncated",
        single({"wire_fault": "question_truncated", "sessions": [sess([ev()])]}), "question")


def n93():
    neg("doh_neg_content_type", "Content-Type is not application/dns-message",
        single({"wire_fault": "content_type", "sessions": [sess([ev()])]}), "content-type")


def n94():
    # Structural fault input: method outside the GET/POST domain.
    neg("doh_neg_method", "HTTP method is not GET or POST",
        single({"sessions": [sess([ev(method="PUT")])]}), "method")


def n95():
    neg("doh_neg_content_length", "POST Content-Length does not equal the DNS body bytes",
        single({"wire_fault": "content_length", "sessions": [sess([ev()])]}), "content-length")


def n96():
    # Structural fault input: tcp->doh direct chain, http carrier missing.
    sp = {"layers": [{"ip": {}}, {"tcp": {}}, {"doh": {}}],
          "src_ip": V4_SRC, "src_port": SRC_PORT, "dst_ip": V4_DST, "dst_port": DST_PORT,
          "doh": {"sessions": [sess([ev()])]}}
    neg("doh_neg_layer_chain_missing_http", "Layer chain missing the http carrier (tcp->doh direct)", sp, "carrier")


def n97():
    neg("doh_neg_port_conflict", "Port/carrier declaration conflicts with the plaintext profile (443)",
        single({"wire_fault": "port_conflict", "sessions": [sess([ev()])]}, dst_port=443), "port")


def n98():
    neg("doh_neg_response_id", "Response DNS ID differs from the request ID",
        single({"wire_fault": "response_id", "sessions": [sess([ev()])]}), "id")


def n99():
    neg("doh_neg_response_question", "Response Question mismatched / 2xx without DNS body",
        single({"wire_fault": "response_question", "sessions": [sess([ev()])]}), "question")


def n100():
    neg("doh_neg_wire_over_max", "Declared DNS wire total length exceeds 65535",
        single({"wire_fault": "wire_over_max", "sessions": [sess([ev()])]}), "length")


def n101():
    neg("doh_neg_opcode_nonzero", "Opcode != 0 (QUERY only in this version)",
        single({"wire_fault": "opcode_nonzero", "sessions": [sess([ev()])]}), "opcode")


def n102():
    # Structural fault input: GET transaction declaring a Content-Type header.
    neg("doh_neg_get_content_type", "GET transaction declares a Content-Type header (no body carrier)",
        single({"sessions": [sess([ev(method="GET", http={"request_headers": {"Content-Type": MEDIA}})])]}),
        "content-type")


def n103():
    neg("doh_neg_response_qr", "Response event declares QR=0 (responses must set QR=1)",
        single({"wire_fault": "response_qr", "sessions": [sess([ev()])]}), "response")


def n104():
    neg("doh_neg_z_nonzero", "Reserved Z bits non-zero",
        single({"wire_fault": "z_nonzero", "sessions": [sess([ev()])]}), "z")


def n105():
    neg("doh_neg_rdlength_mismatch", "Answer RDLENGTH does not equal the RDATA byte count",
        single({"wire_fault": "rdlength_mismatch", "sessions": [sess([ev()])]}), "rdlength")


def n106():
    neg("doh_neg_ancount_mismatch", "ANCOUNT does not equal the declared answer count",
        single({"wire_fault": "ancount_mismatch", "sessions": [sess([ev()])]}), "ancount")


def n107():
    neg("doh_neg_qdcount_multi", "QDCOUNT>1 (this version carries exactly one question)",
        single({"wire_fault": "qdcount_multi", "sessions": [sess([ev()])]}), "qdcount")


def n108():
    # Structural fault input: 16-bit upper bound +1.
    neg("doh_neg_dns_id_range", "dns_id declared 65536 (16-bit bound +1)",
        single({"sessions": [sess([ev(dnsid=65536)])]}), "id")


def n109():
    # Structural fault input: 2^32 bound +1.
    neg("doh_neg_ttl_range", "TTL declared 4294967296 (2^32 bound +1)",
        single({"sessions": [sess([ev(resp=ok_resp([A_answer(ttl=4294967296)]))])]}), "ttl")


def n110():
    neg("doh_neg_qtype_token", "qtype is a non-numeric unknown token (BOGUS)",
        single({"sessions": [sess([ev(qtype="BOGUS")])]}), "qtype")


# §8 three-way consistency list (testcase v3.0.2).
ORDER = """doh_post_ipv4_http11
doh_get_ipv4_base64url
doh_post_ipv6_http11
doh_get_ipv6_base64url
doh_dns_header_query
doh_dns_question_a
doh_dns_question_aaaa
doh_dns_question_https
doh_dns_question_root
doh_dns_response_noerror
doh_dns_response_nxdomain
doh_dns_response_servfail
doh_dns_answer_ttl
doh_http_keepalive_multi_transaction
doh_http_content_length_exact
doh_http_cache_control
doh_http_error_400
doh_http_error_404
doh_http_error_415
doh_mss_large_response
doh_multi_session
doh_port_nondefault_post
doh_port_nondefault_get
doh_concurrent_sessions
doh_b64_residue_1
doh_b64_residue_2
doh_dns_rcode_formerr
doh_dns_rcode_notimp
doh_dns_rcode_refused
doh_dns_rcode_15_upper
doh_dns_rd_zero
doh_dns_ra_zero
doh_dns_aa_set
doh_dns_question_txt
doh_dns_question_mx
doh_dns_qclass_ch
doh_dns_answer_aaaa
doh_dns_answer_cname_chain
doh_dns_answer_multi_types
doh_dns_answer_svcb_alpn
doh_dns_answer_svcb_alias
doh_dns_answer_txt_strings
doh_dns_negative_cache_soa
doh_http_cache_age_header
doh_http_mixed_get_post
doh_http_host_explicit
doh_http_error_400_extra_param
doh_http_accept_absent
doh_http_connection_close
doh_min_frame_get
doh_dns_ttl_zero
doh_dns_ttl_max
doh_dns_qname_label_63
doh_dns_qname_total_255
doh_dns_id_zero
doh_dns_id_max
doh_dns_id_one
doh_dns_id_65534
doh_dns_ttl_one
doh_dns_ttl_4294967294
doh_dns_qname_254
doh_dns_qname_label_62
doh_http_cache_control_soa_minimum
doh_get_qname_max
doh_get_root_query
doh_get_question_aaaa
doh_get_question_https
doh_get_question_txt
doh_get_question_mx
doh_get_rcode_formerr
doh_get_rcode_notimp
doh_get_rcode_refused
doh_get_rcode_15
doh_get_response_noerror
doh_get_response_nxdomain
doh_get_response_servfail
doh_get_answer_ttl
doh_get_answer_aaaa
doh_get_answer_cname_chain
doh_get_answer_svcb_alpn
doh_get_negative_cache_soa
doh_get_rd_zero
doh_get_aa_set
doh_get_port_nondefault
doh_neg_query_missing
doh_neg_base64_invalid
doh_neg_base64_padding
doh_neg_base64_truncated
doh_neg_dns_header_short
doh_neg_dns_qdcount_zero
doh_neg_dns_qname_overflow
doh_neg_dns_question_truncated
doh_neg_content_type
doh_neg_method
doh_neg_content_length
doh_neg_layer_chain_missing_http
doh_neg_port_conflict
doh_neg_response_id
doh_neg_response_question
doh_neg_wire_over_max
doh_neg_opcode_nonzero
doh_neg_get_content_type
doh_neg_response_qr
doh_neg_z_nonzero
doh_neg_rdlength_mismatch
doh_neg_ancount_mismatch
doh_neg_qdcount_multi
doh_neg_dns_id_range
doh_neg_ttl_range
doh_neg_qtype_token""".split()


def main():
    for i in range(1, 85):
        globals()["c%02d" % i]()
    for i in range(85, 111):
        globals()["n%d" % i]()

    ids = [c["id"] for c in CASES]
    assert ids == ORDER, "ID order mismatch:\n got %r\nwant %r" % (
        [x for x, y in zip(ids, ORDER) if x != y][:3],
        [y for x, y in zip(ids, ORDER) if x != y][:3])
    pos = [c for c in CASES if not c["expect"].get("expect_error")]
    negs = [c for c in CASES if c["expect"].get("expect_error")]
    assert len(pos) == 84 and len(negs) == 26, (len(pos), len(negs))
    # Negative expect keys are exactly {expect_error, error_contains} (§7-4).
    for c in negs:
        assert set(c["expect"].keys()) == {"expect_error", "error_contains"}, c["id"]

    out = "test/protocol_pcap/cases/doh.json"
    with open(out, "w") as f:
        json.dump(CASES, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("wrote %s: %d cases (%d positive + %d negative)" % (out, len(CASES), len(pos), len(negs)))


if __name__ == "__main__":
    main()
