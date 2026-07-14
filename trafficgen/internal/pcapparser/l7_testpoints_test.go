package pcapparser

// Test points for l7_parsers.go, derived from tools/test_points/pcapparser.md
// (components L7.1-L7.12). REAL tests exercising httpParser/dnsParser/tlsParser
// directly (except L7-INTG which is SIMULATED via Parse).

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/storage"
)

// --- L7.1: httpParser.CanParse ---

func TestHTTPCanParse_WellKnownPort(t *testing.T) {
	var hp httpParser
	if !hp.CanParse(80, nil) {
		t.Error("CanParse(80, nil) = false, want true")
	}
	if !hp.CanParse(8080, nil) {
		t.Error("CanParse(8080, nil) = false, want true")
	}
	if !hp.CanParse(8000, nil) {
		t.Error("CanParse(8000, nil) = false, want true")
	}
	if !hp.CanParse(8081, nil) {
		t.Error("CanParse(8081, nil) = false, want true")
	}
}

func TestHTTPCanParse_MethodPrefix(t *testing.T) {
	var hp httpParser
	if !hp.CanParse(12345, []byte("GET / HTTP/1.1")) {
		t.Error("CanParse(12345, 'GET /...') = false, want true")
	}
	if !hp.CanParse(12345, []byte("POST /api")) {
		t.Error("CanParse(12345, 'POST /api') = false, want true")
	}
}

func TestHTTPCanParse_ResponseStatusLine(t *testing.T) {
	var hp httpParser
	if !hp.CanParse(12345, []byte("HTTP/1.1 200 OK")) {
		t.Error("CanParse(12345, 'HTTP/1.1 200 OK') = false, want true")
	}
}

func TestHTTPCanParse_NoMatch(t *testing.T) {
	var hp httpParser
	if hp.CanParse(12345, []byte{0x00, 0x01, 0x02}) {
		t.Error("CanParse(12345, binary) = true, want false")
	}
}

// --- L7.2: httpParser.Parse ---

func TestHTTPParse_NoHeaderBoundary(t *testing.T) {
	var hp httpParser
	res, err := hp.Parse([]byte("GET /"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Protocol != "http" {
		t.Errorf("Protocol = %q, want http", res.Protocol)
	}
	if res.BodyOffset != 0 || res.BodyLength != 0 {
		t.Errorf("BodyOffset/Length = %d/%d, want 0/0 (no \\r\\n\\r\\n)", res.BodyOffset, res.BodyLength)
	}
}

func TestHTTPParse_BodyPresent(t *testing.T) {
	var hp httpParser
	stream := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\nbody")
	res, err := hp.Parse(stream)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	headerEnd := bytes.Index(stream, []byte("\r\n\r\n")) + 4
	if res.BodyOffset != headerEnd {
		t.Errorf("BodyOffset = %d, want %d", res.BodyOffset, headerEnd)
	}
	if res.BodyLength != 4 {
		t.Errorf("BodyLength = %d, want 4", res.BodyLength)
	}
}

func TestHTTPParse_NoBodyEndsAtBlankLine(t *testing.T) {
	var hp httpParser
	stream := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	res, err := hp.Parse(stream)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.BodyOffset != len(stream) || res.BodyLength != 0 {
		t.Errorf("BodyOffset/Length = %d/%d, want %d/0", res.BodyOffset, res.BodyLength, len(stream))
	}
}

func TestHTTPParse_EmptyHeaderBlock(t *testing.T) {
	var hp httpParser
	res, err := hp.Parse([]byte(""))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Protocol != "http" {
		t.Errorf("Protocol = %q, want http", res.Protocol)
	}
}

func TestHTTPParse_ResponseStatusLine(t *testing.T) {
	var hp httpParser
	res, err := hp.Parse([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Metadata["status"] != "200" {
		t.Errorf("status = %v, want 200", res.Metadata["status"])
	}
	if res.Metadata["reason"] != "OK" {
		t.Errorf("reason = %v, want OK", res.Metadata["reason"])
	}
}

func TestHTTPParse_RequestLine(t *testing.T) {
	var hp httpParser
	res, err := hp.Parse([]byte("GET /a/b HTTP/1.1\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Metadata["method"] != "GET" {
		t.Errorf("method = %v, want GET", res.Metadata["method"])
	}
	if res.Metadata["uri"] != "/a/b" {
		t.Errorf("uri = %v, want /a/b", res.Metadata["uri"])
	}
}

func TestHTTPParse_HostHeader(t *testing.T) {
	var hp httpParser
	res, err := hp.Parse([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Metadata["host"] != "example.com" {
		t.Errorf("host = %v, want example.com", res.Metadata["host"])
	}
}

func TestHTTPParse_HeaderNoColon(t *testing.T) {
	// Header line without colon must not panic.
	var hp httpParser
	res, err := hp.Parse([]byte("GET / HTTP/1.1\r\nBadHeader\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Metadata["method"] != "GET" {
		t.Errorf("method = %v, want GET", res.Metadata["method"])
	}
}

func TestHTTPParse_RequestLineGarbage(t *testing.T) {
	var hp httpParser
	res, err := hp.Parse([]byte("GARBAGE\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Metadata["method"] != nil {
		t.Errorf("method = %v, want nil (garbage first line)", res.Metadata["method"])
	}
}

// --- L7.3: dnsParser.CanParse ---

func TestDNSCanParse_Port53(t *testing.T) {
	var dp dnsParser
	if !dp.CanParse(53, nil) {
		t.Error("CanParse(53, nil) = false, want true")
	}
	if !dp.CanParse(5353, nil) {
		t.Error("CanParse(5353, nil) = false, want true")
	}
}

func TestDNSCanParse_OtherPort(t *testing.T) {
	var dp dnsParser
	if dp.CanParse(1234, nil) {
		t.Error("CanParse(1234, nil) = true, want false")
	}
}

// --- L7.4: dnsParser.Parse ---

func TestDNSParse_ValidWithQuestions(t *testing.T) {
	// Build a minimal DNS query payload.
	var dp dnsParser
	dns := buildDNSQuery(t, "example.com", 1) // A record
	res, err := dp.Parse(dns)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Protocol != "dns" {
		t.Errorf("Protocol = %q, want dns", res.Protocol)
	}
	if !strings.Contains(res.Metadata["query_name"].(string), "example.com") {
		t.Errorf("query_name = %v, want example.com", res.Metadata["query_name"])
	}
	if res.Metadata["rcode"] != uint8(0) {
		t.Errorf("rcode = %v, want 0", res.Metadata["rcode"])
	}
}

func TestDNSParse_ValidNoQuestions(t *testing.T) {
	// DNS header with no questions (QDCount=0).
	var dp dnsParser
	dns := buildDNSQuery(t, "", 0) // no question
	res, err := dp.Parse(dns)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Metadata["query_name"] != nil {
		t.Errorf("query_name = %v, want nil (no questions)", res.Metadata["query_name"])
	}
}

func TestDNSParse_InvalidMessage(t *testing.T) {
	// Non-DNS payload (< 12 bytes).
	var dp dnsParser
	res, err := dp.Parse([]byte{0, 1, 2})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Protocol != "dns" {
		t.Errorf("Protocol = %q, want dns", res.Protocol)
	}
}

// buildDNSQuery constructs a minimal DNS query payload.
func buildDNSQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	var buf bytes.Buffer
	// Header: ID=0x1234, flags=0x0100 (standard query, RD=1), QDCount=1 if name non-empty else 0.
	binary.Write(&buf, binary.BigEndian, uint16(0x1234))
	binary.Write(&buf, binary.BigEndian, uint16(0x0100))
	qdCount := uint16(0)
	if name != "" {
		qdCount = 1
	}
	binary.Write(&buf, binary.BigEndian, qdCount)
	binary.Write(&buf, binary.BigEndian, uint16(0)) // ANCount
	binary.Write(&buf, binary.BigEndian, uint16(0)) // NSCount
	binary.Write(&buf, binary.BigEndian, uint16(0)) // ARCount
	// Question: encoded name.
	if name != "" {
		for _, part := range strings.Split(name, ".") {
			buf.WriteByte(byte(len(part)))
			buf.WriteString(part)
		}
		buf.WriteByte(0) // root label
		binary.Write(&buf, binary.BigEndian, qtype)
		binary.Write(&buf, binary.BigEndian, uint16(1)) // Class IN
	}
	return buf.Bytes()
}

// --- L7.5: tlsParser.CanParse ---

func TestTLSCanParse_Port443(t *testing.T) {
	var tp tlsParser
	if !tp.CanParse(443, nil) {
		t.Error("CanParse(443, nil) = false, want true")
	}
}

func TestTLSCanParse_SignatureNon443(t *testing.T) {
	var tp tlsParser
	sample := []byte{0x16, 0x03, 0x03, 0x00, 0x00} // TLS handshake, version 0x0303
	if !tp.CanParse(8443, sample) {
		t.Error("CanParse(8443, TLS signature) = false, want true")
	}
}

func TestTLSCanParse_NoMatch(t *testing.T) {
	var tp tlsParser
	if tp.CanParse(1234, []byte{0x00, 0x01, 0x02}) {
		t.Error("CanParse(1234, non-TLS) = true, want false")
	}
}

// --- L7.6: tlsParser.Parse (via buildTLSClientHello) ---

func TestTLSParse_SNI(t *testing.T) {
	var tp tlsParser
	ch := buildTLSClientHello(t, "example.com")
	res, err := tp.Parse(ch)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Metadata["sni"] != "example.com" {
		t.Errorf("sni = %v, want example.com", res.Metadata["sni"])
	}
}

func TestTLSParse_Version(t *testing.T) {
	var tp tlsParser
	ch := buildTLSClientHello(t, "example.com")
	res, err := tp.Parse(ch)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Metadata["version"] != "TLS 1.2" {
		t.Errorf("version = %v, want TLS 1.2", res.Metadata["version"])
	}
}

func TestTLSParse_CipherSuites(t *testing.T) {
	var tp tlsParser
	ch := buildTLSClientHello(t, "example.com")
	res, err := tp.Parse(ch)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	codes, ok := res.Metadata["cipher_suites"].([]string)
	if !ok || len(codes) == 0 {
		t.Errorf("cipher_suites = %v, want non-empty list", res.Metadata["cipher_suites"])
	}
}

// --- L7.7: extractTLSMetadata ---

func TestExtractTLSMetadata_ShortStream(t *testing.T) {
	meta := extractTLSMetadata([]byte{0x16, 0x03, 0x03, 0x00}) // only 4 bytes
	if meta.SNI != "" || meta.Version != "" {
		t.Errorf("short stream metadata = %+v, want empty", meta)
	}
}

func TestExtractTLSMetadata_NonHandshakeRecord(t *testing.T) {
	// Record type 0x17 (Application Data) -> skipped.
	meta := extractTLSMetadata([]byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00})
	if meta.SNI != "" {
		t.Errorf("non-handshake record SNI = %q, want empty", meta.SNI)
	}
}

func TestExtractTLSMetadata_MultipleRecords(t *testing.T) {
	// ClientHello + Certificate (using test helpers).
	ch := buildTLSClientHello(t, "example.com")
	meta := extractTLSMetadata(ch)
	if meta.SNI != "example.com" {
		t.Errorf("SNI = %q, want example.com", meta.SNI)
	}
	if meta.Version != "TLS 1.2" {
		t.Errorf("Version = %q, want TLS 1.2", meta.Version)
	}
}

// --- L7.8: parseTLSHandshake ---

func TestParseTLSHandshake_IncompleteHeader(t *testing.T) {
	meta := tlsMetadata{}
	parseTLSHandshake([]byte{0x01, 0x00, 0x00}, &meta) // only 3 bytes, need 4 for header
	if meta.SNI != "" {
		t.Errorf("after incomplete header SNI = %q, want empty", meta.SNI)
	}
}

func TestParseTLSHandshake_OtherType(t *testing.T) {
	meta := tlsMetadata{}
	// hsType 0x02 (ServerHello) -> skipped.
	parseTLSHandshake([]byte{0x02, 0x00, 0x00, 0x00}, &meta)
	if meta.Version != "" {
		t.Errorf("ServerHello should not set version: %q", meta.Version)
	}
}

// --- L7.11: tlsVersionString ---

func TestTLSVersionString_SSL3(t *testing.T) {
	if got := tlsVersionString(0x0300); got != "SSL 3.0" {
		t.Errorf("0x0300 = %q, want SSL 3.0", got)
	}
}

func TestTLSVersionString_TLS10(t *testing.T) {
	if got := tlsVersionString(0x0301); got != "TLS 1.0" {
		t.Errorf("0x0301 = %q, want TLS 1.0", got)
	}
}

func TestTLSVersionString_TLS11(t *testing.T) {
	if got := tlsVersionString(0x0302); got != "TLS 1.1" {
		t.Errorf("0x0302 = %q, want TLS 1.1", got)
	}
}

func TestTLSVersionString_TLS12(t *testing.T) {
	if got := tlsVersionString(0x0303); got != "TLS 1.2" {
		t.Errorf("0x0303 = %q, want TLS 1.2", got)
	}
}

func TestTLSVersionString_TLS13(t *testing.T) {
	if got := tlsVersionString(0x0304); got != "TLS 1.3" {
		t.Errorf("0x0304 = %q, want TLS 1.3", got)
	}
}

func TestTLSVersionString_Other(t *testing.T) {
	if got := tlsVersionString(0x1234); got != "0x1234" {
		t.Errorf("0x1234 = %q, want 0x1234", got)
	}
}

// --- L7.12: parseDNS ---

func TestParseDNS_TooShort(t *testing.T) {
	dns := parseDNS([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	if dns != nil {
		t.Errorf("parseDNS < 12 bytes = %v, want nil", dns)
	}
}

func TestParseDNS_Valid(t *testing.T) {
	dns := parseDNS(buildDNSQuery(t, "example.com", 1))
	if dns == nil {
		t.Fatal("parseDNS valid query = nil, want non-nil")
	}
	if len(dns.Questions) != 1 {
		t.Errorf("Questions = %d, want 1", len(dns.Questions))
	}
}

// --- L7-INTG: L7 metadata via Parse (SIMULATED) ---

func TestParse_L7MetadataViaParse(t *testing.T) {
	httpReq := []byte("GET / HTTP/1.1\r\nHost: ex.com\r\n\r\n")
	dnsQuery := buildDNSQuery(t, "ex.com", 1)
	tlsCH := buildTLSClientHello(t, "ex.com")

	frames := [][]byte{
		// TCP flow 1: HTTP GET to port 80
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, httpReq),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, uint32(101+len(httpReq)), 201, flagFIN|flagACK, nil),
		// UDP flow 2: DNS query to port 53
		buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, dnsQuery),
		// TCP flow 3: TLS ClientHello to port 443
		buildTCPFrame(t, macA, macB, ipA, ipB, 3000, 443, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 443, 3000, 500, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 3000, 443, 101, 501, flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 3000, 443, 101, 501, flagPSH|flagACK, tlsCH),
		buildTCPFrame(t, macA, macB, ipA, ipB, 3000, 443, uint32(101+len(tlsCH)), 501, flagFIN|flagACK, nil),
	}
	ts := make([]time.Time, len(frames))
	for i := range frames {
		ts[i] = time.UnixMicro(int64(1 + i))
	}
	path := writePcap(t, frames, ts)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if analysis.FlowCount != 3 {
		t.Fatalf("FlowCount = %d, want 3", analysis.FlowCount)
	}
	// Find flows by port.
	var httpFlow, dnsFlow, tlsFlow *storage.FlowModel
	for i := range analysis.Flows {
		switch analysis.Flows[i].DstPort {
		case 80:
			httpFlow = &analysis.Flows[i]
		case 53:
			dnsFlow = &analysis.Flows[i]
		case 443:
			tlsFlow = &analysis.Flows[i]
		}
	}
	if httpFlow == nil {
		t.Fatal("no HTTP flow (port 80)")
	}
	if httpFlow.L7Protocol != "http" {
		t.Errorf("HTTP L7Protocol = %q, want http", httpFlow.L7Protocol)
	}
	if httpFlow.L7Method != "GET" {
		t.Errorf("HTTP L7Method = %q, want GET", httpFlow.L7Method)
	}
	if httpFlow.L7Host != "ex.com" {
		t.Errorf("HTTP L7Host = %q, want ex.com", httpFlow.L7Host)
	}
	if dnsFlow == nil {
		t.Fatal("no DNS flow (port 53)")
	}
	if dnsFlow.L7Protocol != "dns" {
		t.Errorf("DNS L7Protocol = %q, want dns", dnsFlow.L7Protocol)
	}
	if !strings.Contains(dnsFlow.L7QueryName, "ex.com") {
		t.Errorf("DNS L7QueryName = %q, want ex.com", dnsFlow.L7QueryName)
	}
	if tlsFlow == nil {
		t.Fatal("no TLS flow (port 443)")
	}
	if tlsFlow.L7Protocol != "tls" {
		t.Errorf("TLS L7Protocol = %q, want tls", tlsFlow.L7Protocol)
	}
	if tlsFlow.L7Host != "ex.com" {
		t.Errorf("TLS L7Host = %q, want ex.com (SNI)", tlsFlow.L7Host)
	}
	if tlsFlow.L7Metadata == "" {
		t.Error("TLS L7Metadata empty, want non-empty JSON with version/cipher_suites")
	} else if !strings.Contains(tlsFlow.L7Metadata, "TLS 1.2") {
		t.Errorf("TLS L7Metadata = %q, want TLS 1.2 version", tlsFlow.L7Metadata)
	}
}