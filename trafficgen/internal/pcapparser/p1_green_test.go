package pcapparser

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// T-PARSE-2 绿测试（D-PARSE-1 P1 批）：断言期望值全部测试内独立构造。

func dnsWrapUDP(t *testing.T, msg []byte, srcPort layers.UDPPort) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	ipv4 := &layers.IPv4{SrcIP: ipB, DstIP: ipA, Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: 40000}
	udp.SetNetworkLayerForChecksum(ipv4)
	if err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macB, DstMAC: macA, EthernetType: layers.EthernetTypeIPv4},
		ipv4, udp, gopacket.Payload(msg)); err != nil {
		t.Fatalf("serialize dns: %v", err)
	}
	return buf.Bytes()
}

// T-PARSE-2 DNS 响应面（需求三）：answers/flags/counts/ttl/rdata。
func TestP1_DNSResponseFields(t *testing.T) {
	msg := []byte{
		0xAB, 0xCD, 0x81, 0x80, // txid, response RD+RA
		0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // qd=1 an=2
	}
	msg = append(msg, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	msg = append(msg, 0, 1, 0, 1) // A IN
	for _, ip := range [][]byte{{10, 0, 0, 1}, {10, 0, 0, 2}} {
		ans := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
		ans = append(ans, ip...)
		msg = append(msg, ans...)
	}
	var dp dnsParser
	res, err := dp.Parse(msg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f := res.Detail.Messages[0].Fields
	if f["ancount"] != 2 {
		t.Errorf("ancount = %v, want 2", f["ancount"])
	}
	if f["ra"] != true || f["rd"] != true {
		t.Errorf("flags ra/rd = %v/%v, want true/true", f["ra"], f["rd"])
	}
	answers := f["answers"].([]map[string]any)
	if len(answers) != 2 {
		t.Fatalf("answers = %d, want 2", len(answers))
	}
	if answers[0]["rdata"] != "10.0.0.1" {
		t.Errorf("rdata = %v, want 10.0.0.1", answers[0]["rdata"])
	}
	if answers[0]["type_str"] != "A" || answers[0]["ttl"] != uint32(60) {
		t.Errorf("type_str/ttl = %v/%v", answers[0]["type_str"], answers[0]["ttl"])
	}
	if answers[0]["name"] != "www.example.com" {
		t.Errorf("压缩指针回解 name = %v, want www.example.com", answers[0]["name"])
	}
	if res.Metadata["response_ttl"] != uint32(60) {
		t.Errorf("response_ttl = %v, want 60", res.Metadata["response_ttl"])
	}
}

// T-PARSE-2 DNS TCP 双消息 + 配对（query→response 同流）。
func TestP1_DNSTCPQueryResponsePair(t *testing.T) {
	q := buildP1DNSQuery(0x1234, "pair.test")
	r := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	r = append(r, 4, 'p', 'a', 'i', 'r', 4, 't', 'e', 's', 't', 0)
	r = append(r, 0, 1, 0, 1)
	r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 192, 0, 2, 7)
	var stream []byte
	for _, m := range [][]byte{q, r} {
		stream = append(stream, byte(len(m)>>8), byte(len(m)))
		stream = append(stream, m...)
	}
	var dp dnsParser
	res, err := dp.ParseTCPStream(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res.Detail.Messages) != 2 {
		t.Fatalf("messages = %d, want 2（前缀逐消息）", len(res.Detail.Messages))
	}
	if res.Detail.Pair.State != "paired" || res.Detail.Pair.Requests != 1 || res.Detail.Pair.Responses != 1 {
		t.Errorf("pair = %+v, want 1/1 paired", res.Detail.Pair)
	}
}

// T-PARSE-2 HTTP 头 map/title/body_len/status_code int（需求二）。
func TestP1_HTTPDetailFields(t *testing.T) {
	body := "<html><head><title>测试页</title></head></html>"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	stream := []byte("GET /idx HTTP/1.1\r\nHost: t.test\r\nReferer: http://r/\r\n\r\n" + resp)
	var hp httpParser
	res, err := hp.Parse(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res.Detail.Messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(res.Detail.Messages))
	}
	req := res.Detail.Messages[0]
	if req.Kind != "request" || req.Fields["referer"] != "http://r/" {
		t.Errorf("request fields = %v", req.Fields)
	}
	rsp := res.Detail.Messages[1]
	if rsp.Fields["status_code"] != 200 {
		t.Errorf("status_code = %v, want int 200", rsp.Fields["status_code"])
	}
	if rsp.Fields["content_type"] != "text/html" {
		t.Errorf("content_type = %v", rsp.Fields["content_type"])
	}
	sc, ok := rsp.Fields["set_cookie"].([]string)
	if !ok || len(sc) != 2 || sc[0] != "a=1" {
		t.Errorf("set_cookie 多值 = %v", rsp.Fields["set_cookie"])
	}
	if rsp.Fields["body_len"] != len(body) {
		t.Errorf("body_len = %v, want %d", rsp.Fields["body_len"], len(body))
	}
	if res.Detail.Extra["html_title"] != "测试页" {
		t.Errorf("html_title = %v", res.Detail.Extra["html_title"])
	}
	if res.Detail.Pair.State != "paired" {
		t.Errorf("pair = %+v", res.Detail.Pair)
	}
}

// --- TLS 测试夹具（std x509 自签证书）---

func buildTLSHandshakeMsg(t *testing.T, hsType byte, body []byte) []byte {
	t.Helper()
	out := []byte{hsType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

func buildTLSRecord(t *testing.T, body []byte) []byte {
	t.Helper()
	out := []byte{0x16, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

func buildTLSStream(t *testing.T) []byte {
	t.Helper()
	// ClientHello: version+random+sid+cs+cm+SNI ext
	ch := []byte{0x03, 0x03}
	ch = append(ch, make([]byte, 32)...)
	ch = append(ch, 0)                                     // sid len
	ch = append(ch, 0x00, 0x02, 0xC0, 0x2F, 0x01, 0x00)    // 1 suite + 1 comp
	sniName := "tls.example.com"
	extData := []byte{0x00, byte(len(sniName) + 3), 0x00, 0x00, byte(len(sniName))}
	extData = append(extData, sniName...)
	// extensions 总长(2B, RFC 5246 §7.4.1.2：含每扩展 4B 头) + 扩展块
	total := len(extData) + 4
	ch = append(ch, byte(total>>8), byte(total))
	ch = append(ch, 0x00, 0x00, byte(len(extData)>>8), byte(len(extData)))
	ch = append(ch, extData...)
	// ServerHello: version+random+sid+suite+comp
	sh := []byte{0x03, 0x03}
	sh = append(sh, make([]byte, 32)...)
	sh = append(sh, 0, 0xC0, 0x2F, 0x00)
	// Certificate：std x509 自签
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xDEADBEEF),
		Subject:      pkix.Name{CommonName: "tls.example.com"},
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1800000000, 0),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certMsg := []byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}
	certMsg = append(certMsg, der...)
	certList := []byte{byte(len(certMsg) >> 16), byte(len(certMsg) >> 8), byte(len(certMsg))}
	certList = append(certList, certMsg...)

	var hs []byte
	hs = append(hs, buildTLSHandshakeMsg(t, 0x01, ch)...)
	hs = append(hs, buildTLSHandshakeMsg(t, 0x02, sh)...)
	hs = append(hs, buildTLSHandshakeMsg(t, 0x0B, certList)...)
	return buildTLSRecord(t, hs)
}

// T-PARSE-2 TLS：证书六件套/协商套件/握手序列/SNI。
func TestP1_TLSCertAndNegotiated(t *testing.T) {
	var tp tlsParser
	res, err := tp.Parse(buildTLSStream(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	extra := res.Detail.Extra
	if extra["sni"] != "tls.example.com" {
		t.Errorf("sni = %v", extra["sni"])
	}
	if extra["negotiated_cipher"] != "c02f" {
		t.Errorf("negotiated_cipher = %v, want c02f", extra["negotiated_cipher"])
	}
	seq, _ := extra["handshake_sequence"].([]string)
	if len(seq) != 3 || seq[0] != "client_hello" || seq[1] != "server_hello" || seq[2] != "certificate" {
		t.Errorf("handshake_sequence = %v", seq)
	}
	certs, _ := extra["certs"].([]map[string]any)
	if len(certs) != 1 {
		t.Fatalf("certs = %d, want 1", len(certs))
	}
	c := certs[0]
	if c["subject"] != "CN=tls.example.com" {
		t.Errorf("subject = %v", c["subject"])
	}
	if c["serial"] != "3735928559" {
		t.Errorf("serial = %v, want 3735928559 (0xDEADBEEF)", c["serial"])
	}
	if _, ok := c["signature_algorithm"]; !ok {
		t.Errorf("signature_algorithm 缺")
	}
	if _, ok := c["issuer"]; !ok {
		t.Errorf("issuer 缺")
	}
	nb, _ := c["not_before"].(string)
	if !strings.HasPrefix(nb, "2023-") {
		t.Errorf("not_before = %v, want 2023-* (1700000000)", c["not_before"])
	}
}

// T-PARSE-2 ICMP (id,seq) 配对三态（RFC 792 §4.1）。
func TestP1_ICMPPairing(t *testing.T) {
	mk := func(typ uint8, fromA bool) [][]byte {
		var src, dst net.IP
		var srcMAC, dstMAC net.HardwareAddr
		if fromA {
			src, dst, srcMAC, dstMAC = ipA, ipB, macA, macB
		} else {
			src, dst, srcMAC, dstMAC = ipB, ipA, macB, macA
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		ipv4 := &layers.IPv4{SrcIP: src, DstIP: dst, Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4}
		icmp := &layers.ICMPv4{TypeCode: layers.ICMPv4TypeCode(uint16(typ) << 8), Id: 7, Seq: 9}
		frame := []gopacket.SerializableLayer{
			&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4},
			ipv4, icmp,
		}
		if err := gopacket.SerializeLayers(buf, opts, frame...); err != nil {
			t.Fatalf("serialize: %v", err)
		}
		return [][]byte{buf.Bytes()}
	}
	var all [][]byte
	parse := func(frames ...[]byte) storage.FlowModel {
		all = append(all, frames...)
		path := writePcap(t, frames, nil)
		a, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return a.Flows[0]
	}
	paired := parse(mk(8, true)[0], mk(0, false)[0])
	if paired.PairState != "paired" || paired.RequestCount != 1 || paired.ResponseCount != 1 {
		t.Errorf("paired: %s %d/%d", paired.PairState, paired.RequestCount, paired.ResponseCount)
	}
	unmatchedReq := parse(mk(8, true)[0])
	if unmatchedReq.PairState != "unmatched_request" {
		t.Errorf("unmatched_request: %s", unmatchedReq.PairState)
	}
	unmatchedResp := parse(mk(0, true)[0])
	if unmatchedResp.PairState != "unmatched_response" {
		t.Errorf("unmatched_response: %s", unmatchedResp.PairState)
	}
}
