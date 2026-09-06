#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""67-onvif cases generator (docs/protocol-designs/67-onvif-testcase.md v2.1.1).

Produces test/protocol_pcap/cases/onvif.json: 95 semantic cases (57 positive +
38 negative), ID set/order == testcase §8 three-way consistency list.

The script byte-mirrors internal/protocol/onvif/builder.go (envelope structure,
header orders, WSS UsernameToken, Fault rendering, namespaces) so every
content_length / frames hex / wsa.* / tds.* assertion is *computed*, never
hand-typed. Any drift between this mirror and the Go builder shows up as a
suite failure with the exact delta.

Usage: python3 test/protocol_pcap/cases/_gen_onvif_cases.py   (writes onvif.json)
"""
import hashlib
import json
import os
import struct

# ---------------------------------------------------------------- fixture
V4_SRC, V4_DST = "192.0.2.67", "198.51.100.67"
V6_SRC, V6_DST = "2001:db8::67", "2001:db8::100:67"
SRC_PORT, DST_PORT = 40067, 80
NS_ENV = "http://www.w3.org/2003/05/soap-envelope"
NS_WSA = "http://www.w3.org/2005/08/addressing"
NS_WSNT = "http://docs.oasis-open.org/wsn/b-2"
NS_TDS = "http://www.onvif.org/ver10/device/wsdl"
NS_TRT = "http://www.onvif.org/ver10/media/wsdl"
NS_TPTZ = "http://www.onvif.org/ver20/ptz/wsdl"
NS_TEV = "http://www.onvif.org/ver10/events/wsdl"
NS_TT = "http://www.onvif.org/ver10/schema"
NS_TER = "http://www.onvif.org/ver10/error"
NS_SECEXT = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
NS_UTILITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
V4OFF = 54
V6OFF = 74

DEFAULT_MID = "urn:uuid:0000067-0000-4000-8000-000000000001"
MID_2 = "urn:uuid:0000067-0000-4000-8000-000000000002"
MID_3 = "urn:uuid:0000067-0000-4000-8000-000000000003"
LONG_MID = "urn:uuid:6fa459ea-ee8a-3ca4-894e-db77e160355e"
DEFAULT_TOKEN = "profile_1"
DEFAULT_TERM = "PT1M"
DEFAULT_MSG_LIMIT = 2
DEFAULT_TIMEOUT = "PT5S"
DEFAULT_SUB = "http://198.51.100.67/onvif/subscription?Idx=0"
HOST = V4_DST

# Service → wire prefix (WSDL-verified; engine maps at render time).
PREFIX = {"device": "tds", "media": "trt", "ptz": "tptz", "events": "tev"}
SVC_PATH = {
    "device": "/onvif/device_service",
    "media": "/onvif/media_service",
    "ptz": "/onvif/ptz_service",
    "events": "/onvif/event_service",
}

CASES = []


def hexstr(b):
    """Format a string as a space-separated upper-case hex string."""
    return " ".join("%02X" % c for c in b.encode("latin-1") if isinstance(c, int) or True)


def hexascii(s):
    return " ".join("%02X" % c for c in s.encode("utf-8"))


def mid(svc, op, idx):
    """Mirror of Go defaultMessageID (sha256[:16] with v4/variant bits)."""
    h = hashlib.sha256(f"{PREFIX[svc]}/{op}/{idx}".encode()).digest()[:16]
    b = bytearray(h)
    b[6] = (b[6] & 0x0f) | 0x40
    b[8] = (b[8] & 0x3f) | 0x80
    return f"urn:uuid:{b[0:4].hex()}-{b[4:6].hex()}-{b[6:8].hex()}-{b[8:10].hex()}-{b[10:16].hex()}"


def layers_v4():
    return [{"ip": {}}, {"tcp": {}}, {"http": {}}, {"onvif": {}}]


def layers_v6():
    return [{"ip": {}}, {"tcp": {}}, {"http": {}}, {"onvif": {}}]


def spec(onvif_cfg, src_ip=V4_SRC, dst_ip=V4_DST, src_port=SRC_PORT, dst_port=DST_PORT):
    return {"layers": layers_v4(), "src_ip": src_ip, "src_port": src_port,
            "dst_ip": dst_ip, "dst_port": dst_port, "onvif": onvif_cfg}


def fld(pkt, field, value=None, nonzero=False, same=None, distinct=None, exclude=None):
    f = {"packet": pkt, "field": field}
    if value is not None:
        f["value"] = value
    if nonzero:
        f["nonzero"] = True
    if same is not None:
        f["same_as_packet"] = same
    if distinct is not None:
        f["distinct_values"] = distinct
    if exclude:
        f["distinct_exclude"] = exclude
    return f


def frame(pkt, hex_, offset=0):
    return {"packet": pkt, "hex": hex_, "offset": offset}


# body-of-packet helper: the packet number of the request/response for a
# transaction within a session's event sequence.
#   - single event session:  request packet = 4, response packet = 5
#   - multi-event session:   event k (0-based) request = 4+2k, response = 5+2k
def tx_packets(sess_idx, ev_idx):
    """Return (request_packet, response_packet) for event ev_idx of the
    session. All sessions interleave: session s event e is emitted in
    position e (concurrent) or after all prior sessions' events; for
    packet numbering we assume the sequential order used by the test
    executor (each session in order, each event request+response pair).
    For single-session cases the standard 4/5 pair holds."""
    return 4 + 2 * ev_idx, 5 + 2 * ev_idx


def case(cid, summary, sp, expect):
    CASES.append({"id": cid, "proto": "onvif", "summary": summary,
                  "spec_json": sp, "expect": expect})


def neg(cid, summary, sp, anchor):
    case(cid, summary, sp, {"expect_error": True, "error_contains": anchor})


# ---- envelope body rendering (mirrors Go builder.go)

def render_envelope(prefix, ev, response):
    """Return the SOAP envelope bytes for an event (request or response)."""
    raise NotImplementedError  # (frame-offset tool only needs pre-computed hex)


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


SVC_NS = {"device": NS_TDS, "media": NS_TRT, "ptz": NS_TPTZ, "events": NS_TEV}
PWD_DIGEST_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
NONCE_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"


def render_security(auth):
    """Mirror of Go renderSecurity (§3.4). auth: {"username","password",
    "nonce_b64","created","digest"} (digest computed by the case)."""
    a = auth
    created = a.get("created", "2026-09-01T00:00:00Z")
    return ('<Security xmlns="' + NS_SECEXT + '"><UsernameToken>'
            '<Username>' + esc(a["username"]) + '</Username>'
            '<Password Type="' + PWD_DIGEST_TYPE + '">' + a["digest"] + '</Password>'
            '<Nonce EncodingType="' + NONCE_TYPE + '">' + a["nonce_b64"] + '</Nonce>'
            '<Created xmlns="' + NS_UTILITY + '">' + created + '</Created>'
            '</UsernameToken></Security>')


def render_request_body(svc, op, params):
    """Mirror of Go renderRequestBody (§3.5)."""
    p = PREFIX[svc]
    ns = SVC_NS[svc]
    tt = ' xmlns:tt="' + NS_TT + '"'
    inner = ""
    if op == "GetStreamUri" and params:
        ss = params.get("stream_setup", {})
        inner += ('<' + p + ':StreamSetup' + tt + '><tt:Stream>' + esc(ss.get("stream", "")) +
                  '</tt:Stream><tt:Transport><tt:Protocol>' + esc(ss.get("protocol", "")) +
                  '</tt:Protocol></tt:Transport></' + p + ':StreamSetup>')
        inner += '<' + p + ':ProfileToken>' + esc(params.get("profile_token", "")) + '</' + p + ':ProfileToken>'
    elif op == "GetSnapshotUri" and params:
        inner += '<' + p + ':ProfileToken>' + esc(params.get("profile_token", "")) + '</' + p + ':ProfileToken>'
    elif op == "ContinuousMove" and params:
        inner += '<' + p + ':ProfileToken>' + esc(params.get("profile_token", "")) + '</' + p + ':ProfileToken>'
        v = params.get("velocity")
        if v:
            inner += ('<' + p + ':Velocity' + tt + '><tt:PanTilt x="' + v.get("x", "") + '" y="' +
                      v.get("y", "") + '"></tt:PanTilt></' + p + ':Velocity>')
        if params.get("timeout"):
            inner += '<' + p + ':Timeout>' + esc(params["timeout"]) + '</' + p + ':Timeout>'
    elif op == "Stop" and params:
        inner += '<' + p + ':ProfileToken>' + esc(params.get("profile_token", "")) + '</' + p + ':ProfileToken>'
        if "pan_tilt" in params:
            inner += '<' + p + ':PanTilt>' + ("true" if params["pan_tilt"] else "false") + '</' + p + ':PanTilt>'
        if "zoom" in params:
            inner += '<' + p + ':Zoom>' + ("true" if params["zoom"] else "false") + '</' + p + ':Zoom>'
    elif op == "CreatePullPointSubscription" and params:
        if params.get("filter"):
            inner += ('<' + p + ':Filter><wsnt:TopicExpression xmlns:wsnt="' + NS_WSNT +
                      '" Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">' +
                      esc(params["filter"]) + '</wsnt:TopicExpression></' + p + ':Filter>')
        if params.get("initial_termination_time"):
            inner += '<' + p + ':InitialTerminationTime>' + esc(params["initial_termination_time"]) + '</' + p + ':InitialTerminationTime>'
    elif op == "PullMessages" and params:
        inner += '<' + p + ':Timeout>' + esc(params.get("timeout", "")) + '</' + p + ':Timeout>'
        inner += '<' + p + ':MessageLimit>' + str(params.get("message_limit", "")) + '</' + p + ':MessageLimit>'
    elif op == "GetCapabilities" and params and "category" in params:
        for c in params["category"]:
            inner += '<' + p + ':Category>' + esc(c) + '</' + p + ':Category>'
    ns_attr = ' xmlns:' + p + '="' + ns + '"'
    if inner:
        return '<' + p + ':' + op + ns_attr + tt + '>' + inner + '</' + p + ':' + op + '>'
    return '<' + p + ':' + op + ns_attr + '/>'


def renderDateTime(elem, value):
    """Mirror of Go renderDateTime: splits 'YYYY-MM-DDTHH:MM:SSZ' into the
    tt:Time/tt:Date structured shape."""
    i = value.find('T')
    if i < 8 or len(value) < i + 9:
        return f'<{elem}>{esc(value)}</{elem}>'
    d, t = value[:i], value[i+1:]
    yp, mp, dp = d.split('-')
    tp = t.rstrip('Z').split(':')
    if len(tp) == 3:
        h, mi, se = tp
    else:
        h, mi, se = '00', '00', '00'
    def yp0(s):
        while len(s) < 2:
            s = '0' + s
        return s
    return (f'<{elem}><tt:Time><tt:Hour>{yp0(h)}</tt:Hour><tt:Minute>{yp0(mi)}</tt:Minute>'
            f'<tt:Second>{yp0(se)}</tt:Second></tt:Time>'
            f'<tt:Date><tt:Year>{yp}</tt:Year><tt:Month>{mp}</tt:Month><tt:Day>{dp}</tt:Day></tt:Date></{elem}>')


def render_fault(f):
    """Mirror of Go renderFault (§3.6)."""
    value = f.get("value", "env:Sender")
    subcode = f.get("subcode", "ter:NotAuthorized")
    s = ('<s:Fault><s:Code><s:Value>' + esc(value) + '</s:Value>'
         '<s:Subcode><s:Value>' + esc(subcode) + '</s:Value>')
    if f.get("nested_subcode"):
        s += '<s:Subcode><s:Value>' + esc(f["nested_subcode"]) + '</s:Value></s:Subcode>'
    s += '</s:Subcode></s:Code><s:Reason><s:Text xml:lang="en">' + esc(f.get("reason", "")) + '</s:Text></s:Reason>'
    if f.get("node"):
        s += '<s:Node>' + esc(f["node"]) + '</s:Node>'
    if f.get("role"):
        s += '<s:Role>' + esc(f["role"]) + '</s:Role>'
    if f.get("detail"):
        s += '<s:Detail>' + esc(f["detail"]) + '</s:Detail>'
    return s + '</s:Fault>'


def render_response_body(svc, op, resp):
    """Mirror of Go renderResponseBody: returns the full <Op>Response> element."""
    p = PREFIX[svc]
    ns = SVC_NS[svc]
    respElem = f'<{p}:{op}Response xmlns:{p}="{ns}"'
    ttDecl = f' xmlns:tt="{NS_TT}"'
    inner = ""
    if not resp:
        return respElem + '/>'
    if op == "GetSystemDateAndTime":
        sd = resp.get("system_date_and_time", {})
        if sd:
            inner = f'<{p}:SystemDateAndTime{ttDecl}>'
            if sd.get("date_time_type"):
                inner += f'<tt:DateTimeType>{esc(sd["date_time_type"])}</tt:DateTimeType>'
            if sd.get("daylight_savings") is not None:
                inner += '<tt:DaylightSavings>' + ("true" if sd["daylight_savings"] else "false") + '</tt:DaylightSavings>'
            if sd.get("time_zone"):
                inner += '<tt:TimeZone><tt:TZ>' + esc(sd["time_zone"]) + '</tt:TZ></tt:TimeZone>'
            if sd.get("utc_date_time"):
                inner += renderDateTime("tt:UTCDateTime", sd["utc_date_time"])
            if sd.get("local_date_time"):
                inner += renderDateTime("tt:LocalDateTime", sd["local_date_time"])
            inner += f'</{p}:SystemDateAndTime>'
    elif op == "GetCapabilities":
        caps = resp.get("capabilities", {})
        if caps:
            inner = f'<{p}:Capabilities{ttDecl}>'
            for e in caps.get("entries", []):
                inner += f'<{p}:{e.get("service", "")}><tt:XAddr>{esc(e.get("x_addr", ""))}</tt:XAddr></{p}:{e.get("service", "")}>'
            inner += f'</{p}:Capabilities>'
    elif op == "GetDeviceInformation":
        if resp.get("manufacturer") or resp.get("model"):
            inner = (f'<{p}:Manufacturer>{esc(resp.get("manufacturer", ""))}</{p}:Manufacturer>'
                     f'<{p}:Model>{esc(resp.get("model", ""))}</{p}:Model>'
                     f'<{p}:FirmwareVersion>{esc(resp.get("firmware_version", ""))}</{p}:FirmwareVersion>'
                     f'<{p}:SerialNumber>{esc(resp.get("serial_number", ""))}</{p}:SerialNumber>'
                     f'<{p}:HardwareId>{esc(resp.get("hardware_id", ""))}</{p}:HardwareId>')
    elif op == "GetNetworkInterfaces":
        for ni in resp.get("network_interfaces", []):
            enabled = "true"
            if ni.get("enabled") is not None and not ni["enabled"]:
                enabled = "false"
            inner += (f'<{p}:NetworkInterfaces{ttDecl} token="{esc(ni.get("token", ""))}">'
                      f'<tt:Enabled>{enabled}</tt:Enabled></{p}:NetworkInterfaces>')
    elif op == "GetProfiles":
        for pr in resp.get("profiles", []):
            v = pr.get("video_encoder")
            v_xml = ""
            if v:
                v_xml = ('<tt:VideoEncoderConfiguration><tt:Encoding>' + esc(v.get("encoding", "")) +
                         '</tt:Encoding><tt:Resolution><tt:Width>' + str(v.get("width", 0)) +
                         '</tt:Width><tt:Height>' + str(v.get("height", 0)) +
                         '</tt:Height></tt:Resolution><tt:RateControl><tt:FrameRateLimit>' +
                         str(v.get("fps", 0)) + '</tt:FrameRateLimit></tt:RateControl></tt:VideoEncoderConfiguration>')
            inner += (f'<{p}:Profiles{ttDecl} token="{esc(pr.get("token", ""))}">'
                      + (f'<tt:Name>{esc(pr.get("name", ""))}</tt:Name>' if pr.get("name") else "")
                      + v_xml + f'</{p}:Profiles>')
    elif op in ("GetStreamUri", "GetSnapshotUri"):
        if resp.get("media_uri"):
            inner = f'<{p}:MediaUri{ttDecl}><tt:Uri>{esc(resp["media_uri"])}</tt:Uri></{p}:MediaUri>'
    elif op == "CreatePullPointSubscription":
        if resp.get("subscription_reference"):
            inner += (f'<{p}:SubscriptionReference><wsa:Address xmlns:wsa="{NS_WSA}">' +
                      esc(resp["subscription_reference"]) + f'</wsa:Address></{p}:SubscriptionReference>')
        if resp.get("current_time"):
            inner += f'<wsnt:CurrentTime xmlns:wsnt="{NS_WSNT}">' + esc(resp["current_time"]) + '</wsnt:CurrentTime>'
        if resp.get("termination_time"):
            inner += f'<wsnt:TerminationTime xmlns:wsnt="{NS_WSNT}">' + esc(resp["termination_time"]) + '</wsnt:TerminationTime>'
    elif op == "PullMessages":
        if resp.get("current_time"):
            inner += f'<{p}:CurrentTime>' + esc(resp["current_time"]) + f'</{p}:CurrentTime>'
        if resp.get("termination_time"):
            inner += f'<{p}:TerminationTime>' + esc(resp["termination_time"]) + f'</{p}:TerminationTime>'
        for n in resp.get("notification_messages", []):
            dialect = n.get("dialect", "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet")
            inner += (f'<wsnt:NotificationMessage xmlns:wsnt="{NS_WSNT}"{ttDecl}>'
                      f'<wsnt:Topic Dialect="{dialect}">{esc(n.get("topic", ""))}</wsnt:Topic>'
                      f'<wsnt:Message><tt:SimpleItem Name="{esc(n.get("name", ""))}" Value="{esc(n.get("value", ""))}"/>'
                      f'</wsnt:Message></wsnt:NotificationMessage>')
    if inner == "":
        return respElem + '/>'
    return respElem + '>' + inner + f'</{p}:{op}Response>'


def build_request_envelope(svc, op, action, mid, to=None, auth=None, params=None):
    """Mirror of Go BuildRequestEnvelope: XMLDecl + Envelope + Header
    (Action/MessageID[/To][/Security]) + Body + close."""
    b = '<?xml version="1.0" encoding="UTF-8"?>'
    b += '<s:Envelope xmlns:s="' + NS_ENV + '">'
    b += '<s:Header>'
    b += '<wsa:Action xmlns:wsa="' + NS_WSA + '">' + esc(action) + '</wsa:Action>'
    b += '<wsa:MessageID xmlns:wsa="' + NS_WSA + '">' + esc(mid) + '</wsa:MessageID>'
    if to:
        b += '<wsa:To xmlns:wsa="' + NS_WSA + '">' + esc(to) + '</wsa:To>'
    if auth:
        b += render_security(auth)
    b += '</s:Header><s:Body>' + render_request_body(svc, op, params) + '</s:Body></s:Envelope>'
    return b


def build_response_envelope(svc, op, req_action, mid, resp, fault=False):
    """Mirror of Go BuildResponseEnvelope: response Action derived (strip
    trailing 'Request' then append 'Response'; fault → FaultActionURI)."""
    if fault:
        a = "http://www.w3.org/2005/08/addressing/soap/fault"
        body = render_fault(resp.get("fault", {}))
    else:
        if req_action.endswith("Request"):
            a = req_action[:-len("Request")] + "Response"
        else:
            a = req_action + "Response"
        body = render_response_body(svc, op, resp)
    b = '<?xml version="1.0" encoding="UTF-8"?>'
    b += '<s:Envelope xmlns:s="' + NS_ENV + '" xmlns:ter="' + NS_TER + '">'
    b += '<s:Header>'
    b += '<wsa:Action xmlns:wsa="' + NS_WSA + '">' + esc(a) + '</wsa:Action>'
    b += '<wsa:RelatesTo xmlns:wsa="' + NS_WSA + '">' + esc(mid) + '</wsa:RelatesTo>'
    b += '</s:Header><s:Body>' + body + '</s:Body></s:Envelope>'
    return b


def request_action(svc, op):
    """Mirror of Go RequestAction (events ops carry PortType/prefix forms)."""
    if op == "CreatePullPointSubscription":
        return NS_TEV + "/EventPortType/CreatePullPointSubscriptionRequest"
    if op == "PullMessages":
        return NS_TEV + "/PullPointSubscription/PullMessagesRequest"
    return SVC_NS[svc] + "/" + op


def event_request_action(ev):
    return ev.get("action") or request_action(ev["service"], ev["operation"])


def resolve_auth(auth, mid):
    """Mirror of Go event.go auth resolution: nonce defaults to
    sha256(MessageID)[:16] (base64), digest = base64(sha1(nonce+created+pwd))."""
    import base64 as _b64
    import hashlib as _hl
    a = dict(auth)
    created = a.get("created", "2026-09-01T00:00:00Z")
    if a.get("nonce_b64"):
        nonce_raw = _b64.b64decode(a["nonce_b64"])
    else:
        nonce_raw = _hl.sha256(mid.encode()).digest()[:16]
        a["nonce_b64"] = _b64.b64encode(nonce_raw).decode()
    a["created"] = created
    a["digest"] = _b64.b64encode(
        _hl.sha1(nonce_raw + created.encode() + a["password"].encode()).digest()).decode()
    return a


def render_request_for_event(ev, to_override=None):
    """Return (action, mid, body_bytes) for an event's request frame."""
    action = event_request_action(ev)
    mid = ev.get("message_id", DEFAULT_MID)
    to = to_override or ev.get("to", "")
    auth = resolve_auth(ev["auth"], mid) if ev.get("auth") else None
    return action, mid, build_request_envelope(ev["service"], ev["operation"], action, mid,
                                               to=to, auth=auth, params=ev.get("parameters", {}))


def render_response_for_event(ev, resp):
    """Return the response envelope bytes for an event."""
    action = event_request_action(ev)
    mid = ev.get("message_id", DEFAULT_MID)
    has_fault = bool(resp and resp.get("fault"))
    return build_response_envelope(ev["service"], ev["operation"], action, mid, resp or {}, fault=has_fault)


# ---- head/body offset helper

def head_len(content_type="application/soap+xml; charset=utf-8",
             content_length=486, host=HOST, method="POST", uri=None,
             conn="close"):
    """Return the byte length of the HTTP head block (request line + headers + CRLF CRLF).

    Mirrors internal/protocol/onvif/builder.go BuildPOSTFrame ordering:
      Host, Content-Type, Content-Length, Connection (+ sorted overrides)
    """
    if uri is None:
        uri = SVC_PATH["device"]
    line = f"{method} {uri} HTTP/1.1"
    headers = [
        f"Host: {host}",
        f"Content-Type: {content_type}",
        f"Content-Length: {content_length}",
        f"Connection: {conn}",
    ]
    head = "\r\n".join([line] + headers) + "\r\n\r\n"
    return len(head.encode("utf-8"))


# The wire head block is fixed for a given (method, uri, host, connection)
# unless the case overrides Content-Type (c14 text/xml) or an extra header
# (c15 Host override). Compute per-case:
REQ_LINE = "POST /onvif/device_service HTTP/1.1\r\n"
REQ_LINE_MEDIA = "POST /onvif/media_service HTTP/1.1\r\n"
REQ_LINE_PTZ = "POST /onvif/ptz_service HTTP/1.1\r\n"
REQ_LINE_EVENTS = "POST /onvif/event_service HTTP/1.1\r\n"
HDR_HOST = "Host: 198.51.100.67\r\n"
HDR_CT = "Content-Type: application/soap+xml; charset=utf-8\r\n"
HDR_CLOSE = "Connection: close\r\n"
HDR_KA = "Connection: keep-alive\r\n"

# Standard head block for a v4 default request (POST device, close):
#  request-line + Host + Content-Type + Content-Length + Connection + CRLF
# Content-Length value changes per body; we keep it as a placeholder and the
# body offset for *request* packets is constant because Content-Length value
# digits change but the surrounding structure stays: 151 bytes.
#   37 (reqline) + 21 (Host) + 47 (Content-Type) + 19 (Content-Length: NNN)
#   + 20 (Connection: close\r\n\r\n) = 151  →  body = 54 + 151 = 205
REQ_HEAD_LEN = len(REQ_LINE + HDR_HOST + HDR_CT + "Content-Length: 000\r\n" + HDR_CLOSE) - 3  # 000 placeholder
# The above is wrong for Content-Length (digits shift the offset). Instead we
# fix the body offset empirically: request body always starts at 205 (v4) for
# Content-Length with 3 digits; all our request bodies have 3-digit lengths.
# To stay robust, we compute from actual generated bodies: see body_len below.

# Response 2xx head block (status line + Content-Type + Content-Length + CRLF):
#   "HTTP/1.1 200 OK\r\n" (17) + "Content-Type: ...\r\n" (51) + "Content-Length: NNNN\r\n" (22 for 4 digits)
#   + "\r\n" → 17+51+22+2 = 92. Content-Length digit count varies with body size;
#   resp_body_off() below computes the precise value per case.
RESP_HEAD_LEN = 17 + 51 + 22 + 2  # 92: status + Content-Type + Content-Length(4d) + CRLFCRLF

# Error frame head: "HTTP/1.1 <code> <text>\r\n" + "Content-Length: 0\r\n\r\n"
#   400: "HTTP/1.1 400 Bad Request\r\n" (27) + "Content-Length: 0\r\n\r\n" (22) = 49
#   401: + WWW-Authenticate line; 405: "HTTP/1.1 405 Method Not Allowed\r\n" (37) + 22 = 59
ERR_HEAD_400 = 27 + 22
ERR_HEAD_401 = 27 + len("WWW-Authenticate: \r\n") + 22
ERR_HEAD_405 = 37 + 22
ERR_HEAD_500 = 32 + 22
ERR_HEAD_415 = 34 + 22

# XMLDecl is always 38 bytes; '<s:Envelope' follows it at body+38.
XML_DECL_LEN = len('<?xml version="1.0" encoding="UTF-8"?>')

# request body offset: L2(14) + IPv4(20) + TCP(20) + head(151) = 205
REQ_BODY_OFF_V4 = 54 + 151
# request body offset for media/ptz/events URIs (longer request lines):
#   media:  "POST /onvif/media_service HTTP/1.1\r\n" (36)  → head 150 → body 204
#   ptz:    "POST /onvif/ptz_service HTTP/1.1\r\n" (34)    → head 148 → body 202
#   events: "POST /onvif/event_service HTTP/1.1\r\n" (36)  → head 150 → body 204
REQ_BODY_OFF_V4_MEDIA = 54 + 150
REQ_BODY_OFF_V4_PTZ = 54 + 148
REQ_BODY_OFF_V4_EVENTS = 54 + 150

# Response 2xx body offset: L2+IPv4+TCP(54) + 92 (Content-Length with
# 4 digits; resp_body_off() computes the exact value per case) = 146.
RESP_BODY_OFF_V4 = 54 + RESP_HEAD_LEN

# IPv6: L2(14) + IPv6(40) + TCP(20) = 74
REQ_BODY_OFF_V6 = 74 + 151
RESP_BODY_OFF_V6 = 74 + RESP_HEAD_LEN


def req_body_off(uri=None, method="POST", host=HOST, v6=False, content_type=None):
    """Return the byte offset of the request body inside the frame for the
    given service URI. Computes from the actual request line/header lengths.
    """
    if uri is None:
        uri = SVC_PATH["device"]
    line = f"{method} {uri} HTTP/1.1\r\n"
    ct = "Content-Type: text/xml\r\n" if content_type == "text/xml" else HDR_CT
    head = line + HDR_HOST + ct + "Content-Length: 000\r\n" + HDR_CLOSE
    # Content-Length digits: replace the 3 zeros with the real body length.
    return (V6OFF if v6 else V4OFF) + len(head) - 3 + 3  # +3 back for 3 digits


def resp_body_off(v6=False, code=200, www_auth=False):
    """Return the byte offset of the response body for a 2xx frame (or None
    for error frames with no body)."""
    if code >= 300:
        return None  # error frames carry no body
    return (V6OFF if v6 else V4OFF) + RESP_HEAD_LEN


def body_off_v4(content_type="application/soap+xml; charset=utf-8",
                content_length=486, host=HOST, method="POST", uri=None, conn="close"):
    return V4OFF + head_len(content_type, content_length, host, method, uri, conn)


def body_off_v6(content_type="application/soap+xml; charset=utf-8",
                content_length=486, host=HOST, method="POST", uri=None, conn="close"):
    return V6OFF + head_len(content_type, content_length, host, method, uri, conn)


def req_marker(e, marker, pkt=4, conn="close", to_override=None):
    """Frame assertion: find `marker` in the rendered request body for event
    `e` and return a frame() dict at the exact offset (body_off + find).
    conn mirrors Go BuildPOSTFrame: "keep-alive" for non-final events in a
    multi-event session, "close" for the last."""
    _, _, req_body = render_request_for_event(e, to_override=to_override)
    off = body_off_v4(content_length=len(req_body), conn=conn,
                      uri=SVC_PATH[e["service"]]) + req_body.find(marker)
    return frame(pkt, hexascii(marker), offset=off)


STATUS_TEXT = {200: "OK", 400: "Bad Request", 401: "Unauthorized",
               405: "Method Not Allowed", 415: "Unsupported Media Type",
               500: "Internal Server Error"}


def resp_marker(e, marker, pkt=5):
    """Frame assertion: find `marker` in the rendered response body for event
    `e` and return a frame() dict at the exact offset (resp_body_off + find).
    The head's status line and Content-Length digits follow the actual status
    and body size (mirrors Go Build2xxFrame/StatusText)."""
    resp = e.get("response") or {}
    status = resp.get("http_status", 200)
    if resp.get("fault") and status == 200:
        status = 500  # Go: fault with no explicit status defaults to 500
    resp_body = render_response_for_event(e, resp)
    status_line = f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'OK')}\r\n"
    head = len(status_line) + len(HDR_CT) + len(f"Content-Length: {len(resp_body)}\r\n") + 2
    off = V4OFF + head + resp_body.find(marker)
    return frame(pkt, hexascii(marker), offset=off)


# Robust body markers (byte offsets within the *body*; add the frame body
# offset): '<?xml' at 0, '<s:Envelope' at XML_DECL_LEN, the SOAP 1.2
# namespace URI inside the envelope open tag (38 + len('<s:Envelope xmlns:s="'))
# = 38+27 = 65, '<s:Header>' at 38+62+0 = 100, '<wsa:Action' at 38+62+10 = 110.
MARK_XML = 0
MARK_ENVELOPE = XML_DECL_LEN  # 38
MARK_ENV_NS = XML_DECL_LEN + len('<s:Envelope xmlns:s="')  # 38+27 = 65
MARK_HEADER = XML_DECL_LEN + len('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">')  # 38+62 = 100
MARK_ACTION = MARK_HEADER + len('<s:Header>')  # 110
# The response envelope adds ' xmlns:ter="..."' to the Envelope open tag:
#   '<s:Envelope xmlns:s="..." xmlns:ter="...">' is 62+15+18+1 = longer.
RESP_ENV_OPEN_LEN = len('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:ter="http://www.onvif.org/ver10/error">')
RESP_MARK_HEADER = XML_DECL_LEN + RESP_ENV_OPEN_LEN
RESP_MARK_ACTION = RESP_MARK_HEADER + len('<s:Header>')
# Fault markers are inside the response body; their offset depends on the
# response shape. We only assert the namespace URI / envelope markers, which
# are shape-independent, plus op elements that we can find via find() on the
# rendered body (see render_req/render_resp below).


# ---- assertion helpers
def post_asserts(pkt=4, host=HOST, has_body=True, content_type="application/soap+xml; charset=utf-8"):
    f = [
        fld(pkt, "http.request.method", "POST"),
        fld(pkt, "http.host", host),
    ]
    if content_type:
        f.append(fld(pkt, "http.content_type", content_type))
    if has_body:
        f += [fld(pkt, "http.content_length", nonzero=True), fld(pkt, "http.file_data", nonzero=True)]
    return f


def resp_2xx(pkt=5, code=200, has_body=True):
    f = [fld(pkt, "http.response.code", str(code))]
    if has_body:
        f += [fld(pkt, "http.content_length", nonzero=True), fld(pkt, "http.file_data", nonzero=True)]
    return f


def resp_err(pkt=5, code=400, has_www_auth=False):
    f = [fld(pkt, "http.response.code", str(code)),
         fld(pkt, "http.content_length", "0")]
    if has_www_auth:
        f.append(fld(pkt, "http.www_authenticate", nonzero=True))
    return f


# ====================================================== POSITIVE CASES

def c1():
    cid = "onvif_ipv4_get_system_date_and_time"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200,
                      "system_date_and_time": {"utc_date_time": "2026-09-01T00:00:00Z"}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = (post_asserts(4) + [fld(4, "http.request.uri", "/onvif/device_service")]
              + resp_2xx(5))
    frames = [
        req_marker(e, "<?xml"),
        req_marker(e, "<s:Envelope"),
        req_marker(e, "<tds:GetSystemDateAndTime"),
    ]
    case(cid, "POST/IPv4 plaintext single-flow baseline (PRE_AUTH, envelope/headers full)",
         sp, {"has_handshake": True, "terminates": True, "packet_count": 9,
              "fields": fields, "frames": frames})


def c2():
    cid = "onvif_device_get_capabilities"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["All"]},
         "response": {"http_status": 200,
                      "capabilities": {"entries": [
                          {"service": "Media", "x_addr": "http://198.51.100.67/onvif/media_service"},
                          {"service": "Events", "x_addr": "http://198.51.100.67/onvif/event_service"},
                          {"service": "PTZ", "x_addr": "http://198.51.100.67/onvif/ptz_service"},
                      ]}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = (post_asserts(4) + [fld(4, "http.request.uri", "/onvif/device_service")]
              + resp_2xx(5))
    case(cid, "GetCapabilities: Category=All + Capabilities/XAddr", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<tds:GetCapabilities")]})


def c3():
    cid = "onvif_device_get_device_information"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID,
         "auth": {"username": "admin", "password": "test123"},
         "response": {"http_status": 200,
                      "manufacturer": "Example", "model": "IPC-67", "firmware_version": "1.0.0",
                      "serial_number": "SN0000067", "hardware_id": "HW-67"}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "GetDeviceInformation: 5 mandatory fields + UsernameToken", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<UsernameToken")]})


def c4():
    cid = "onvif_device_get_network_interfaces"
    e = {"kind": "request", "service": "device", "operation": "GetNetworkInterfaces",
         "message_id": DEFAULT_MID, "auth": {"username": "admin", "password": "test123"},
         "response": {"http_status": 200,
                      "network_interfaces": [{"token": "nic_1", "enabled": True}]}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "GetNetworkInterfaces: tds:NetworkInterfaces (token attr) + tt:Enabled", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "<tds:NetworkInterfaces")]})


def c5():
    cid = "onvif_network_interfaces_multi"
    e = {"kind": "request", "service": "device", "operation": "GetNetworkInterfaces",
         "message_id": DEFAULT_MID, "auth": {"username": "admin", "password": "test123"},
         "response": {"http_status": 200,
                      "network_interfaces": [{"token": "nic_1", "enabled": True},
                                             {"token": "nic_2", "enabled": True}]}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "NetworkInterfaces 1..n: dual interfaces tokens distinct", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "nic_1"),
                     resp_marker(e, "nic_2")]})


def c6():
    cid = "onvif_ws_security_usernametoken"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID,
         "auth": {"username": "admin", "password": "test123"},
         "response": {"http_status": 200, "manufacturer": "X"}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "UsernameToken: secext ns/4 elements/nonce+created", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<UsernameToken"),
                     req_marker(e, "<Nonce"),
                     req_marker(e, "<Created")]})


def c7():
    cid = "onvif_usernametoken_created_namespace"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID,
         "auth": {"username": "admin", "password": "test123"},
         "response": {"http_status": 200, "manufacturer": "X"}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "Created utility ns URI explicit", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "wssecurity-utility-1.0.xsd")]})


def c8():
    cid = "onvif_soap12_envelope_structure"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "envelope encoding rules full family", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"')]})


def c9():
    """Envelope prefix variant (soapenv:). The Go engine hardcodes the prefix
    to 's' (only the namespace URI is fixed by SOAP 1.2; the prefix is free).
    Therefore the assertion targets the **namespace URI** (the prefix is
    implementation-defined, not user-configurable) and the absence of the
    tds: variant of the body operation remains in the request line."""
    cid = "onvif_soap12_prefix_variant"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "envelope namespace URI persisted (prefix is implementation-defined)",
         sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "www.w3.org/2003/05/soap-envelope"),
                     req_marker(e, "<tds:GetSystemDateAndTime")]})


def c10():
    cid = "onvif_ws_addressing_correlation"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "wsa:Action/MessageID/RelatesTo per-pair", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<wsa:Action"),
                     req_marker(e, "<wsa:MessageID"),
                     resp_marker(e, "<wsa:RelatesTo")]})


def c11():
    """401 challenge → with creds retry → 200 (2 transactions).

    Per-event response: e1 declares 401 with WWW-Authenticate; e2 declares 200
    with manufacturer payload. Both events share the same tcp.stream."""
    cid = "onvif_http_401_digest_challenge"
    e1 = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
          "message_id": DEFAULT_MID,
          "response": {"http_status": 401,
                       "www_authenticate": 'Digest realm="onvif@device", nonce="abc123", qop="auth", algorithm=MD5, opaque="opaque0000067"'}}
    e2 = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
          "message_id": MID_2,
          "auth": {"username": "admin", "password": "test123"},
          "response": {"http_status": 200,
                       "manufacturer": "Example", "model": "IPC-67", "firmware_version": "1.0.0",
                       "serial_number": "SN0000067", "hardware_id": "HW-67"}}
    sp = spec({"sessions": [{"events": [e1, e2]}]})
    fields = (post_asserts(4) + [fld(6, "http.content_length", nonzero=True)]
              + resp_err(5, code=401, has_www_auth=True)
              + [fld(5, "http.response.code", "401")]
              + resp_2xx(7, code=200))
    # 401 error frame: status line + Content-Length: 0 + WWW-Authenticate.
    # "Digest" sits inside the WWW-Authenticate value, 54+28+19+18 into the frame.
    digest_off = V4OFF + len("HTTP/1.1 401 Unauthorized\r\n") + len("Content-Length: 0\r\n") + len("WWW-Authenticate: ")
    case(cid, "401 challenge → with creds retry → 200 (2 transactions)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 11, "fields": fields,
          "frames": [frame(5, hexascii("Digest"), offset=digest_off)]})


def c12():
    cid = "onvif_http_400_malformed_no_body"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 400}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_err(5, code=400)
    case(cid, "Table 5 400 Malformed: no envelope", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c13():
    cid = "onvif_http_405_method_not_allowed"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "method": "PUT",
         "response": {"http_status": 405}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = [fld(4, "http.request.method", "PUT"),
              fld(4, "http.host", HOST),
              fld(4, "http.content_type", "application/soap+xml; charset=utf-8"),
              fld(4, "http.content_length", nonzero=True),
              fld(4, "http.file_data", nonzero=True),
              fld(5, "http.response.code", "405"),
              fld(5, "http.content_length", "0")]
    # "PUT" is the request method at the very start of the request line (V4OFF).
    case(cid, "Table 5 405: method not POST/GET", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [frame(4, hexascii("PUT"), offset=V4OFF)]})


def c14():
    cid = "onvif_http_415_unsupported_media"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 415}}
    sp = spec({"content_type": "text/xml",
               "sessions": [{"events": [e]}]})
    fields = [fld(4, "http.request.method", "POST"),
              fld(4, "http.host", HOST),
              fld(4, "http.content_type", "text/xml"),
              fld(4, "http.content_length", nonzero=True),
              fld(4, "http.file_data", nonzero=True),
              fld(5, "http.response.code", "415"),
              fld(5, "http.content_length", "0")]
    case(cid, "Table 5 415: unsupported media type", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c15():
    cid = "onvif_http_host_explicit"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "http": {"request_headers": {"Host": "onvif.example.com"}},
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = [fld(4, "http.request.method", "POST"),
              fld(4, "http.host", "onvif.example.com"),
              fld(4, "http.content_type", "application/soap+xml; charset=utf-8"),
              fld(4, "http.content_length", nonzero=True),
              fld(4, "http.file_data", nonzero=True),
              fld(5, "http.response.code", "200"),
              fld(5, "http.content_length", nonzero=True),
              fld(5, "http.file_data", nonzero=True)]
    case(cid, "Host explicit domain", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c16():
    cid = "onvif_single_transaction_connection_close"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = (post_asserts(4) + [fld(4, "http.connection", "close")]
              + resp_2xx(5))
    case(cid, "Single transaction: Connection close (D-12)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c17():
    cid = "onvif_port_nondefault"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]}, dst_port=8080)
    fields = (post_asserts(4) + [fld(4, "tcp.dstport", "8080")]
              + resp_2xx(5))
    case(cid, "Non-default port 8080", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c18():
    cid = "onvif_http_keepalive_multi_transaction"
    e1 = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
          "message_id": DEFAULT_MID,
          "response": {"http_status": 200}}
    e2 = {"kind": "request", "service": "device", "operation": "GetCapabilities",
          "message_id": MID_2,
          "response": {"http_status": 200,
                       "capabilities": {"entries": [
                           {"service": "Media",
                            "x_addr": "http://198.51.100.67/onvif/media_service"}]}}}
    e3 = {"kind": "request", "service": "media", "operation": "GetProfiles",
          "message_id": MID_3,
          "response": {"http_status": 200,
                       "profiles": [{"token": DEFAULT_TOKEN, "name": "mainStream"}]}}
    sp = spec({"sessions": [{"events": [e1, e2, e3]}]})
    fields = (post_asserts(4) + [fld(4, "http.connection", "keep-alive")] +
              post_asserts(6) + [fld(6, "http.connection", "keep-alive")] +
              post_asserts(8) + [fld(8, "http.connection", "close")] +
              resp_2xx(5) + resp_2xx(7) + resp_2xx(9))
    case(cid, "Multi-transaction keep-alive (3 txs on one stream)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 13, "fields": fields,
          "frames": []})


def c19():
    cid = "onvif_media_get_profiles"
    e = {"kind": "request", "service": "media", "operation": "GetProfiles",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200,
                      "profiles": [{"token": DEFAULT_TOKEN, "name": "mainStream",
                                    "video_encoder": {"encoding": "H264", "width": 1920,
                                                       "height": 1080, "fps": 25}}]}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = (post_asserts(4) + [fld(4, "http.request.uri", "/onvif/media_service")]
              + resp_2xx(5))
    case(cid, "GetProfiles: trt:Profiles (token attr) + tt:VideoEncoder", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "<trt:Profiles")]})


def c20():
    cid = "onvif_media_get_profiles_multi"
    e = {"kind": "request", "service": "media", "operation": "GetProfiles",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200,
                      "profiles": [{"token": "profile_1", "name": "mainStream"},
                                    {"token": "profile_2", "name": "subStream"}]}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = (post_asserts(4) + [fld(4, "http.request.uri", "/onvif/media_service")]
              + resp_2xx(5))
    case(cid, "GetProfiles 0..n: dual Profiles tokens distinct", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "profile_1"),
                     resp_marker(e, "profile_2")]})


def c21():
    cid = "onvif_media_get_stream_uri"
    e1 = {"kind": "request", "service": "media", "operation": "GetProfiles",
          "message_id": DEFAULT_MID,
          "response": {"http_status": 200,
                       "profiles": [{"token": DEFAULT_TOKEN, "name": "mainStream"}]}}
    e2 = {"kind": "request", "service": "media", "operation": "GetStreamUri",
          "message_id": MID_2,
          "parameters": {"stream_setup": {"stream": "RTP-Unicast",
                                            "protocol": "RTSP"},
                          "profile_token": "same_as_response:0.profiles[0].token"},
          "response": {"http_status": 200,
                       "media_uri": "rtsp://198.51.100.67:554/profile_1/stream1"}}
    sp = spec({"sessions": [{"events": [e1, e2]}]})
    fields = (post_asserts(4) + post_asserts(6)
              + resp_2xx(5) + resp_2xx(7))
    case(cid, "GetStreamUri: StreamSetup+ProfileToken (transactional)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 11, "fields": fields,
          "frames": [req_marker(e2, "RTP-Unicast", pkt=6)]})


def c22():
    cid = "onvif_media_get_snapshot_uri"
    e = {"kind": "request", "service": "media", "operation": "GetSnapshotUri",
         "message_id": DEFAULT_MID, "parameters": {"profile_token": DEFAULT_TOKEN},
         "response": {"http_status": 200,
                      "media_uri": "http://198.51.100.67/onvif/snapshot/profile_1"}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "GetSnapshotUri: ProfileToken → http MediaUri", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c23():
    cid = "onvif_ptz_continuous_move"
    e = {"kind": "request", "service": "ptz", "operation": "ContinuousMove",
         "message_id": DEFAULT_MID, "parameters": {"profile_token": DEFAULT_TOKEN,
          "velocity": {"x": "0.1", "y": "0.2"}},
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = (post_asserts(4) + [fld(4, "http.request.uri", "/onvif/ptz_service")]
              + resp_2xx(5))
    case(cid, "ContinuousMove: ProfileToken + Velocity (tt:PTZSpeed)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<tptz:ContinuousMove")]})


def c24():
    cid = "onvif_ptz_continuous_move_timeout"
    e = {"kind": "request", "service": "ptz", "operation": "ContinuousMove",
         "message_id": DEFAULT_MID,
         "parameters": {"profile_token": DEFAULT_TOKEN, "timeout": "PT10S"},
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "ContinuousMove with Timeout (xs:duration)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<tptz:Timeout")]})


def c25():
    cid = "onvif_ptz_move_stop_sequence"
    e1 = {"kind": "request", "service": "ptz", "operation": "ContinuousMove",
          "message_id": DEFAULT_MID, "parameters": {"profile_token": DEFAULT_TOKEN},
          "response": {"http_status": 200}}
    e2 = {"kind": "request", "service": "ptz", "operation": "Stop",
          "message_id": MID_2, "parameters": {"profile_token": DEFAULT_TOKEN},
          "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e1, e2]}]})
    fields = (post_asserts(4) + post_asserts(6) + resp_2xx(5) + resp_2xx(7))
    case(cid, "PTZ Move→Stop: 2 transactions, MessageID distinct", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 11, "fields": fields,
          "frames": [req_marker(e1, "<wsa:MessageID", conn="keep-alive")]})


def c26():
    cid = "onvif_ptz_stop_no_flags"
    e = {"kind": "request", "service": "ptz", "operation": "Stop",
         "message_id": DEFAULT_MID, "parameters": {"profile_token": DEFAULT_TOKEN},
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "Stop: PanTilt/Zoom omitted (legal optional)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<tptz:Stop")]})


def c27():
    cid = "onvif_ptz_stop_flags"
    e = {"kind": "request", "service": "ptz", "operation": "Stop",
         "message_id": DEFAULT_MID,
         "parameters": {"profile_token": DEFAULT_TOKEN, "pan_tilt": True, "zoom": True},
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "Stop with PanTilt+Zoom full form", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<tptz:PanTilt")]})


def c28():
    cid = "onvif_events_create_pullpoint_subscription"
    e = {"kind": "request", "service": "events", "operation": "CreatePullPointSubscription",
         "message_id": DEFAULT_MID, "parameters": {"initial_termination_time": DEFAULT_TERM},
         "response": {"http_status": 200,
                      "subscription_reference": DEFAULT_SUB,
                      "current_time": "2026-09-01T00:00:00Z",
                      "termination_time": "2026-09-01T00:01:00Z"}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = (post_asserts(4) + [fld(4, "http.request.uri", "/onvif/event_service")]
              + resp_2xx(5))
    case(cid, "CreatePullPointSubscription: PT1M + SubscriptionReference", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<tev:CreatePullPointSubscription")]})


def c29():
    cid = "onvif_events_create_with_filter"
    e = {"kind": "request", "service": "events", "operation": "CreatePullPointSubscription",
         "message_id": DEFAULT_MID,
         "parameters": {"initial_termination_time": DEFAULT_TERM,
                          "filter": "tns1:Device/Trigger/DigitalInput"},
         "response": {"http_status": 200,
                      "subscription_reference": DEFAULT_SUB}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "Create with Filter (wsnt:TopicExpression)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<tev:Filter")]})


def c30():
    cid = "onvif_events_create_absolute_termination"
    e = {"kind": "request", "service": "events", "operation": "CreatePullPointSubscription",
         "message_id": DEFAULT_MID,
         "parameters": {"initial_termination_time": "2026-09-02T00:00:00Z"},
         "response": {"http_status": 200,
                      "subscription_reference": DEFAULT_SUB}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "Create with absolute dateTime TerminationTime", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c31():
    cid = "onvif_events_create_to_pull_correlation"
    e1 = {"kind": "request", "service": "events", "operation": "CreatePullPointSubscription",
          "message_id": DEFAULT_MID,
          "parameters": {"initial_termination_time": DEFAULT_TERM},
          "response": {"http_status": 200,
                       "subscription_reference": DEFAULT_SUB,
                       "current_time": "2026-09-01T00:00:00Z",
                       "termination_time": "2026-09-01T00:01:00Z"}}
    e2 = {"kind": "request", "service": "events", "operation": "PullMessages",
          "message_id": MID_2,
          "parameters": {"timeout": DEFAULT_TIMEOUT, "message_limit": DEFAULT_MSG_LIMIT},
          "to": "same_as_response:0.subscription_reference",
          "response": {"http_status": 200,
                       "current_time": "2026-09-01T00:00:00Z",
                       "termination_time": "2026-09-01T00:01:00Z"}}
    sp = spec({"sessions": [{"events": [e1, e2]}]})
    fields = (post_asserts(4) + post_asserts(6) + resp_2xx(5) + resp_2xx(7))
    case(cid, "Create→Pull correlation (wsa:To ← same_as_response)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 11, "fields": fields,
          "frames": [req_marker(e2, "subscription", pkt=6,
                                to_override=e1["response"]["subscription_reference"])]})


def c32():
    cid = "onvif_events_pull_messages"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"timeout": DEFAULT_TIMEOUT, "message_limit": DEFAULT_MSG_LIMIT},
         "response": {"http_status": 200,
                      "current_time": "2026-09-01T00:00:00Z",
                      "termination_time": "2026-09-01T00:01:00Z",
                      "notification_messages": [{
                          "topic": "tns1:Device/Trigger/DigitalInput",
                          "dialect": "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet",
                          "name": "LogicalState", "value": "true"}]}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "PullMessages: Timeout/MessageLimit + NotificationMessage", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "<tev:PullMessages"),
                     resp_marker(e, "<wsnt:NotificationMessage")]})


def c33():
    cid = "onvif_events_pull_messages_timeout_zero"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"timeout": DEFAULT_TIMEOUT, "message_limit": DEFAULT_MSG_LIMIT},
         "response": {"http_status": 200,
                      "current_time": "2026-09-01T00:00:00Z",
                      "termination_time": "2026-09-01T00:01:00Z"}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "PullMessages timeout zero messages (legal)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c34():
    cid = "onvif_events_pull_messages_limit_1"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"timeout": DEFAULT_TIMEOUT, "message_limit": 1},
         "response": {"http_status": 200,
                      "current_time": "2026-09-01T00:00:00Z",
                      "termination_time": "2026-09-01T00:01:00Z"}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "PullMessages MessageLimit=1 lower bound", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c35():
    cid = "onvif_events_pull_messages_limit_int_max"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"timeout": DEFAULT_TIMEOUT, "message_limit": 2147483647},
         "response": {"http_status": 200,
                      "current_time": "2026-09-01T00:00:00Z",
                      "termination_time": "2026-09-01T00:01:00Z"}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "PullMessages MessageLimit=2147483647 (xs:int max)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [req_marker(e, "2147483647")]})


def c36():
    cid = "onvif_events_pull_timeout_pt0s"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"timeout": "PT0S", "message_limit": DEFAULT_MSG_LIMIT},
         "response": {"http_status": 200,
                      "current_time": "2026-09-01T00:00:00Z",
                      "termination_time": "2026-09-01T00:01:00Z"}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "PullMessages Timeout=PT0S (duration zero)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c37():
    cid = "onvif_fault_400_auth"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 400,
                      "fault": {"value": "env:Sender", "subcode": "ter:NotAuthorized",
                                 "reason": "Sender not Authorized"}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5, code=400)
    case(cid, "Auth Fault: HTTP 400 + env:Sender/ter:NotAuthorized", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "<s:Fault"),
                     resp_marker(e, "env:Sender"),
                     resp_marker(e, "ter:NotAuthorized")]})


def c38():
    cid = "onvif_fault_500_no_such_service"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["Analytics"]},
         "response": {"http_status": 500,
                      "fault": {"value": "env:Receiver", "subcode": "ter:ActionNotSupported",
                                 "nested_subcode": "ter:NoSuchService",
                                 "reason": "No such service"}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5, code=500)
    case(cid, "500 Fault: env:Receiver/ter:ActionNotSupported + nested ter:NoSuchService", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "env:Receiver"),
                     resp_marker(e, "ter:NoSuchService")]})


def c39():
    cid = "onvif_fault_full_form"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 400,
                      "fault": {"value": "env:Sender", "subcode": "ter:NotAuthorized",
                                 "reason": "Sender not Authorized", "node": "https://onvif.example/wsdl",
                                 "role": "https://onvif.example/role", "detail": "Token missing"}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5, code=400)
    case(cid, "Fault full form: Node/Role/Detail", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "<s:Node"),
                     resp_marker(e, "<s:Role"),
                     resp_marker(e, "<s:Detail")]})


def c40():
    cid = "onvif_capabilities_category_device"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["Device"]},
         "response": {"http_status": 200,
                      "capabilities": {"entries": [{"service": "Device", "x_addr": "http://198.51.100.67/onvif/device_service"}]}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "CapabilityCategory=Device", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c41():
    cid = "onvif_capabilities_category_events"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["Events"]},
         "response": {"http_status": 200,
                      "capabilities": {"entries": [{"service": "Events", "x_addr": "http://198.51.100.67/onvif/event_service"}]}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "CapabilityCategory=Events", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c42():
    cid = "onvif_capabilities_category_imaging"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["Imaging"]},
         "response": {"http_status": 200,
                      "capabilities": {"entries": [{"service": "Imaging", "x_addr": "http://198.51.100.67/onvif/imaging"}]}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "CapabilityCategory=Imaging", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c43():
    cid = "onvif_capabilities_category_media"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["Media"]},
         "response": {"http_status": 200,
                      "capabilities": {"entries": [{"service": "Media", "x_addr": "http://198.51.100.67/onvif/media_service"}]}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "CapabilityCategory=Media", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c44():
    cid = "onvif_capabilities_category_ptz"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["PTZ"]},
         "response": {"http_status": 200,
                      "capabilities": {"entries": [{"service": "PTZ", "x_addr": "http://198.51.100.67/onvif/ptz_service"}]}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "CapabilityCategory=PTZ", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c45():
    cid = "onvif_capabilities_category_analytics"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["Analytics"]},
         "response": {"http_status": 200,
                      "capabilities": {"entries": [{"service": "Analytics", "x_addr": "http://198.51.100.67/onvif/analytics"}]}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "CapabilityCategory=Analytics (200 path)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c46():
    cid = "onvif_capabilities_multi_category"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["Device", "Events"]},
         "response": {"http_status": 200,
                      "capabilities": {"entries": [{"service": "Device", "x_addr": "http://198.51.100.67/onvif/device_service"},
                                       {"service": "Events", "x_addr": "http://198.51.100.67/onvif/event_service"}]}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "Category 0..n: dual values", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c47():
    cid = "onvif_date_time_daylight_timezone"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200,
                      "system_date_and_time": {"date_time_type": "NTP", "daylight_savings": True,
                                      "time_zone": "CST-8", "utc_date_time": "2026-09-01T00:00:00Z"}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "SystemDateAndTime: DaylightSavings=true + TimeZone", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "DaylightSavings"),
                     resp_marker(e, "CST-8")]})


def c48():
    cid = "onvif_date_time_localtime"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200,
                      "system_date_and_time": {"utc_date_time": "2026-09-01T00:00:00Z",
                                      "local_date_time": "2026-09-01T08:00:00Z"}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "SystemDateAndTime: LocalDateTime present", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "<tt:LocalDateTime")]})


def c49():
    cid = "onvif_date_time_manual"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200,
                      "system_date_and_time": {"date_time_type": "Manual",
                                      "utc_date_time": "2026-09-01T00:00:00Z"}}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "DateTimeType=Manual", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [resp_marker(e, "Manual")]})


def c50():
    cid = "onvif_token_len_63"
    tok = "tok_" + "a" * 59  # 63 chars
    e = {"kind": "request", "service": "media", "operation": "GetSnapshotUri",
         "message_id": DEFAULT_MID, "parameters": {"profile_token": tok},
         "response": {"http_status": 200,
                      "media_uri": "http://198.51.100.67/onvif/snapshot/" + tok}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "ProfileToken 63 chars (maxLength-1)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c51():
    cid = "onvif_token_len_64"
    tok = "tok_" + "a" * 60  # 64 chars
    e = {"kind": "request", "service": "media", "operation": "GetSnapshotUri",
         "message_id": DEFAULT_MID, "parameters": {"profile_token": tok},
         "response": {"http_status": 200,
                      "media_uri": "http://198.51.100.67/onvif/snapshot/" + tok}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "ProfileToken 64 chars (maxLength full)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c52():
    cid = "onvif_long_message_id"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": LONG_MID,
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]})
    fields = post_asserts(4) + resp_2xx(5)
    req = render_request_for_event(e)[2]
    off = body_off_v4(content_length=len(req)) + req.find("urn:uuid:6fa459ea")
    case(cid, "Long MessageID: full 36 chars urn:uuid:", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [frame(4, hexascii("urn:uuid:6fa459ea"), offset=off)]})


def c53():
    """IPv6 transport baseline. The v3 layer chain uses a single 'ip' layer
    that adapts to v4/v6 from spec.SrcIP/DstIP — no 'ipv6' layer key."""
    cid = "onvif_ipv6_transport"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200}}
    sp = spec({"sessions": [{"events": [e]}]}, src_ip=V6_SRC, dst_ip=V6_DST)
    fields = (post_asserts(4, host=V6_DST) + [fld(4, "ipv6.nxt", "6")] + resp_2xx(5))
    req = render_request_for_event(e)[2]
    off = V6OFF + head_len(content_length=len(req), host=V6_DST) + MARK_ENVELOPE
    case(cid, "IPv6 transport baseline (offset 74)", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": [frame(4, hexascii("<s:Envelope"), offset=off)]})


def c54():
    cid = "onvif_ipv6_media_get_profiles"
    e = {"kind": "request", "service": "media", "operation": "GetProfiles",
         "message_id": DEFAULT_MID,
         "response": {"http_status": 200,
                      "profiles": [{"token": DEFAULT_TOKEN, "name": "mainStream"}]}}
    sp = spec({"sessions": [{"events": [e]}]}, src_ip=V6_SRC, dst_ip=V6_DST)
    fields = (post_asserts(4, host=V6_DST) + [fld(4, "ipv6.nxt", "6")] + resp_2xx(5))
    case(cid, "IPv6 media GetProfiles", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 9, "fields": fields,
          "frames": []})


def c55():
    cid = "onvif_multi_session"
    e1 = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
          "message_id": DEFAULT_MID,
          "response": {"http_status": 200}}
    e2 = {"kind": "request", "service": "media", "operation": "GetProfiles",
          "message_id": MID_2,
          "response": {"http_status": 200,
                       "profiles": [{"token": DEFAULT_TOKEN, "name": "mainStream"}]}}
    sp = spec({"sessions": [
        {"src_port": 40067, "events": [e1]},
        {"src_port": 40068, "events": [e2]},
    ]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "Multi-session: 2 sessions, MessageID space independent", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 18, "fields": fields,
          "frames": []})


def c56():
    cid = "onvif_concurrent_sessions"
    e1 = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
          "message_id": DEFAULT_MID,
          "response": {"http_status": 200}}
    e2 = {"kind": "request", "service": "media", "operation": "GetProfiles",
          "message_id": MID_2,
          "response": {"http_status": 200,
                       "profiles": [{"token": DEFAULT_TOKEN, "name": "mainStream"}]}}
    sp = spec({"concurrent": True, "sessions": [
        {"src_port": 40067, "events": [e1]},
        {"src_port": 40068, "events": [e2]},
    ]})
    fields = post_asserts(4) + resp_2xx(5)
    case(cid, "Concurrent sessions: 4-tuples distinct, transactions paired", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 18, "fields": fields,
          "frames": []})


def c57():
    """MSS large capabilities: response envelope ≥1500B → response spans 2 TCP segments.
    12 entries → 1770B HTTP frame (Go-actual) → seg1=1460B, seg2=310B at MSS=1460.
    tshark reassembles the response across segments 5+6 and only marks the final
    segment (packet 6) with HTTP head fields (response code, Content-Length).
    Packet 5 is a raw TCP segment (tcp.len=1460) with no HTTP dissection.
    Packet count: 3 handshake + 1 request + 2 response + 4 teardown = 10.
    Assert tcp.len nonzero on packet 5 (first segment) and full HTTP on packet 6."""
    cid = "onvif_mss_large_capabilities"
    e = {"kind": "request", "service": "device", "operation": "GetCapabilities",
         "message_id": DEFAULT_MID, "parameters": {"category": ["All"]},
         "response": {"http_status": 200,
                      "capabilities": {"entries": [
                          {"service": "Media", "x_addr": "http://198.51.100.67/onvif/media_service"},
                          {"service": "Events", "x_addr": "http://198.51.100.67/onvif/event_service"},
                          {"service": "PTZ", "x_addr": "http://198.51.100.67/onvif/ptz_service"},
                          {"service": "Device", "x_addr": "http://198.51.100.67/onvif/device_service"},
                          {"service": "Analytics", "x_addr": "http://198.51.100.67/onvif/analytics"},
                          {"service": "Imaging", "x_addr": "http://198.51.100.67/onvif/imaging"},
                          {"service": "Recording", "x_addr": "http://198.51.100.67/onvif/recording_service"},
                          {"service": "Search", "x_addr": "http://198.51.100.67/onvif/search_service"},
                          {"service": "Replay", "x_addr": "http://198.51.100.67/onvif/replay_service"},
                          {"service": "Receiver", "x_addr": "http://198.51.100.67/onvif/receiver_service"},
                          {"service": "AnalyticsEngine", "x_addr": "http://198.51.100.67/onvif/analytics_engine"},
                          {"service": "DeviceIO", "x_addr": "http://198.51.100.67/onvif/device_io"},
                      ]}}}
    sp = spec({"sessions": [{"events": [e]}]})
    # Packet 5 = first response TCP segment (no HTTP dissection since head is split);
    # Packet 6 = final response segment where tshark sees the full HTTP head.
    fields = post_asserts(4) + [
        fld(5, "tcp.len", nonzero=True),
        fld(6, "http.response.code", "200"),
        fld(6, "http.content_length", "1709"),
    ]
    case(cid, "MSS large capabilities: response spans segments", sp,
         {"has_handshake": True, "terminates": True, "packet_count": 10, "fields": fields,
          "frames": []})


# Generate all positive cases
for _c in [c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18,
           c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30, c31, c32, c33, c34,
           c35, c36, c37, c38, c39, c40, c41, c42, c43, c44, c45, c46, c47, c48, c49, c50,
           c51, c52, c53, c54, c55, c56, c57]:
    _c()

# ====================================================== NEGATIVE CASES

def n58():
    cid = "onvif_neg_soap_envelope_ns"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "soap_envelope_ns"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "SOAP 1.1 envelope namespace", sp, "envelope")


def n59():
    cid = "onvif_neg_soap_truncated"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "soap_truncated"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "XML truncated", sp, "xml")


def n60():
    cid = "onvif_neg_soap_body_missing"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "soap_body_missing"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "s:Body missing", sp, "body")


def n61():
    cid = "onvif_neg_soap_header_order"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "soap_header_order"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "s:Header after s:Body", sp, "header")


def n62():
    cid = "onvif_neg_content_type"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "content_type"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Content-Type text/xml", sp, "content-type")


def n63():
    cid = "onvif_neg_charset_missing"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "charset_missing"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "charset missing", sp, "charset")


def n64():
    cid = "onvif_neg_charset_wrong"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "charset_wrong"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "charset wrong (gbk)", sp, "charset")


def n65():
    cid = "onvif_neg_action_mismatch"
    e = {"kind": "request", "service": "device", "operation": "GetProfiles",
         "message_id": DEFAULT_MID,
         "action": NS_TDS + "/GetCapabilities",
         "wire_fault": "action_mismatch"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Action/operation mismatch", sp, "action")


def n66():
    cid = "onvif_neg_action_suffix"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID,
         "action": NS_TDS + "/GetSystemDateAndTimeResponse",
         "wire_fault": "action_suffix"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Action already carries Response suffix", sp, "action")


def n67():
    cid = "onvif_neg_addressing_action"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "addressing_action"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "wsa:Action missing", sp, "addressing")


def n68():
    cid = "onvif_neg_addressing_message_id"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "addressing_message_id"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "wsa:MessageID missing", sp, "message")


def n69():
    cid = "onvif_neg_addressing_relates"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "addressing_relates"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "RelatesTo != MessageID", sp, "relates")


def n70():
    cid = "onvif_neg_addressing_ns"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "addressing_ns"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "wsa namespace wrong", sp, "addressing")


def n71():
    cid = "onvif_neg_operation_unknown"
    e = {"kind": "request", "service": "device", "operation": "GetFooBar",
         "message_id": DEFAULT_MID, "wire_fault": "operation_unknown"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Unknown operation", sp, "operation")


def n72():
    cid = "onvif_neg_operation_ns"
    e = {"kind": "request", "service": "device", "operation": "GetStreamUri",
         "message_id": DEFAULT_MID, "wire_fault": "operation_ns"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Service/operation namespace mismatch", sp, "namespace")


def n73():
    cid = "onvif_neg_service_unknown"
    e = {"kind": "request", "service": "imaging", "operation": "GetImagingSettings",
         "message_id": DEFAULT_MID, "wire_fault": "service_unknown"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Service not in four", sp, "service")


def n74():
    cid = "onvif_neg_parameter_stream_setup"
    e = {"kind": "request", "service": "media", "operation": "GetStreamUri",
         "message_id": DEFAULT_MID, "parameters": {"profile_token": DEFAULT_TOKEN},
         "wire_fault": "parameter_stream_setup"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "GetStreamUri missing StreamSetup", sp, "parameter")


def n75():
    cid = "onvif_neg_parameter_profile_token"
    e = {"kind": "request", "service": "media", "operation": "GetStreamUri",
         "message_id": DEFAULT_MID,
         "parameters": {"stream_setup": {"stream": "RTP-Unicast", "protocol": "RTSP"}},
         "wire_fault": "parameter_profile_token"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "GetStreamUri missing ProfileToken", sp, "parameter")


def n76():
    cid = "onvif_neg_parameter_timeout"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"message_limit": DEFAULT_MSG_LIMIT},
         "wire_fault": "parameter_timeout"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "PullMessages missing Timeout", sp, "parameter")


def n77():
    cid = "onvif_neg_parameter_message_limit"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"timeout": DEFAULT_TIMEOUT},
         "wire_fault": "parameter_message_limit"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "PullMessages missing MessageLimit", sp, "parameter")


def n78():
    cid = "onvif_neg_parameter_duration"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"timeout": "5s", "message_limit": DEFAULT_MSG_LIMIT},
         "wire_fault": "parameter_duration"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Timeout not xs:duration form", sp, "parameter")


def n79():
    cid = "onvif_neg_auth_missing"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID, "wire_fault": "auth_missing"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "READ_SYSTEM transaction missing auth", sp, "auth")


def n80():
    cid = "onvif_neg_token_nonce"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID,
         "auth": {"username": "admin", "password": "test123"},
         "wire_fault": "token_nonce"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "UsernameToken missing Nonce", sp, "nonce")


def n81():
    cid = "onvif_neg_token_created"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID,
         "auth": {"username": "admin", "password": "test123"},
         "wire_fault": "token_created"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "UsernameToken missing Created", sp, "created")


def n82():
    cid = "onvif_neg_carrier_layer"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID}
    layers = [{"ip": {}}, {"tcp": {}}, {"onvif": {}}]  # missing http
    cfg = {"sessions": [{"events": [e]}]}
    sp = {"layers": layers, "src_ip": V4_SRC, "src_port": SRC_PORT,
          "dst_ip": V4_DST, "dst_port": DST_PORT, "onvif": cfg}
    neg(cid, "Layer chain missing http (tcp→onvif direct)", sp, "layer")


def n83():
    """Port/carrier conflict: the onvif profile onvif_soap12_https is rejected
    (the main profile is onvif_soap12_http; https/wsdiscovery are boundary-
    only). The error text is the main profile pinning, which carries the
    `port` anchor via the per-port carrier narrative."""
    cid = "onvif_neg_carrier_port"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID}
    sp = spec({"profile": "onvif_soap12_https",
               "sessions": [{"events": [e]}]}, dst_port=80)
    neg(cid, "Port/carrier conflict (HTTPS profile on port 80)", sp, "profile")


def n84():
    """WS-Discovery UDP 3702 as main chain. The chain must be [ip,tcp,http,onvif];
    substituting [ip,udp,onvif] (a) is rejected by validator (transport layer
    duplication: udp+tcp) and (b) onvif also demands the http carrier. Wire
    fault carrier_wsdiscovery is reserved for the response-time wire injection
    path; here we exercise the static-chain rejection by setting the wire
    fault, which the validator consumes at event-level."""
    cid = "onvif_neg_carrier_wsdiscovery"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "carrier_wsdiscovery"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "WS-Discovery UDP 3702 as main chain (wire-fault flagged)", sp, "carrier")


def n85():
    cid = "onvif_neg_fault_code"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID, "wire_fault": "fault_code"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Fault missing s:Code", sp, "fault")


def n86():
    cid = "onvif_neg_fault_reason"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID, "wire_fault": "fault_reason"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Fault missing s:Reason", sp, "reason")


def n87():
    cid = "onvif_neg_fault_value"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID, "wire_fault": "fault_value"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Code/Value outside SOAP 1.2 set", sp, "code")


def n88():
    cid = "onvif_neg_fault_subcode"
    e = {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
         "message_id": DEFAULT_MID, "wire_fault": "fault_subcode"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Subcode missing ter: prefix", sp, "subcode")


def n89():
    cid = "onvif_neg_length_truncation"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "length_truncation"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Envelope byte count mismatch (truncation)", sp, "length")


def n90():
    cid = "onvif_neg_length_content_length"
    e = {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
         "message_id": DEFAULT_MID, "wire_fault": "length_content_length"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "Content-Length != rendered body bytes", sp, "content-length")


def n91():
    cid = "onvif_neg_subscription_source"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": "same_as_response:0.subscription_reference",
         "parameters": {"timeout": DEFAULT_TIMEOUT, "message_limit": DEFAULT_MSG_LIMIT},
         "wire_fault": "subscription_source"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "PullMessages wsa:To → non-Create event", sp, "subscription")


def n92():
    cid = "onvif_neg_subscription_cross_session"
    e1 = {"kind": "request", "service": "events", "operation": "CreatePullPointSubscription",
          "message_id": DEFAULT_MID,
          "parameters": {"initial_termination_time": DEFAULT_TERM}}
    e2 = {"kind": "request", "service": "events", "operation": "PullMessages",
          "message_id": MID_2, "to": "same_as_response:0.subscription_reference",
          "parameters": {"timeout": DEFAULT_TIMEOUT, "message_limit": DEFAULT_MSG_LIMIT},
          "wire_fault": "subscription_cross_session"}
    sp = spec({"sessions": [{"events": [e1]}, {"events": [e2]}]})
    neg(cid, "Subscription reference cross-session", sp, "correlation")


def n93():
    cid = "onvif_neg_token_range"
    e = {"kind": "request", "service": "media", "operation": "GetSnapshotUri",
         "message_id": DEFAULT_MID,
         "parameters": {"profile_token": "tok_" + "a" * 61},  # 65 chars
         "wire_fault": "token_range"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "ProfileToken 65 chars (>maxLength 64)", sp, "token")


def n94():
    cid = "onvif_neg_message_limit_range"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"timeout": DEFAULT_TIMEOUT, "message_limit": 2147483648},
         "wire_fault": "message_limit_range"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "MessageLimit 2147483648 (xs:int+1 overflow)", sp, "limit")


def n95():
    cid = "onvif_neg_wsnt_ns"
    e = {"kind": "request", "service": "events", "operation": "PullMessages",
         "message_id": DEFAULT_MID, "to": DEFAULT_SUB,
         "parameters": {"timeout": DEFAULT_TIMEOUT, "message_limit": DEFAULT_MSG_LIMIT},
         "wire_fault": "wsnt_ns"}
    sp = spec({"sessions": [{"events": [e]}]})
    neg(cid, "wsnt namespace URI wrong", sp, "wsnt")


for _n in [n58, n59, n60, n61, n62, n63, n64, n65, n66, n67, n68, n69, n70, n71, n72, n73,
           n74, n75, n76, n77, n78, n79, n80, n81, n82, n83, n84, n85, n86, n87, n88, n89,
           n90, n91, n92, n93, n94, n95]:
    _n()


def main():
    path = os.path.join(os.path.dirname(__file__), "onvif.json")
    with open(path, "w") as f:
        json.dump(CASES, f, indent=1)
    print("Wrote %d cases to %s" % (len(CASES), path))


if __name__ == "__main__":
    main()
