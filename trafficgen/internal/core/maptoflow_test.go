package core

import (
	"bytes"
	"net"
	"testing"
)

func TestMapToFlowSpec_TCP(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"src_port": float64(12345),
		"dst_port": float64(80),
		"ttl":      float64(128),
		"tcp": map[string]interface{}{
			"handshake":   true,
			"termination": false,
			"rst":         true,
			"mss":         float64(1460),
			"window_size": float64(65535),
		},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcIP != "10.0.0.1" || spec.DstIP != "10.0.0.2" {
		t.Errorf("IPs = %s/%s", spec.SrcIP, spec.DstIP)
	}
	if spec.SrcPort != 12345 || spec.DstPort != 80 {
		t.Errorf("ports = %d/%d", spec.SrcPort, spec.DstPort)
	}
	if spec.TTL != 128 {
		t.Errorf("TTL = %d, want 128", spec.TTL)
	}
	if spec.TCP == nil {
		t.Fatal("TCP nil")
	}
	if spec.TCP.MSS != 1460 || spec.TCP.WindowSize != 65535 {
		t.Errorf("TCP MSS=%d Win=%d", spec.TCP.MSS, spec.TCP.WindowSize)
	}
	if !spec.TCP.Handshake || spec.TCP.Termination || !spec.TCP.RST {
		t.Errorf("TCP flags handshake=%v termination=%v rst=%v", spec.TCP.Handshake, spec.TCP.Termination, spec.TCP.RST)
	}
}

func TestMapToFlowSpec_HTTPDefaultPort(t *testing.T) {
	cfg := map[string]interface{}{
		"http": map[string]interface{}{
			"method": "POST",
			"uri":    "/api",
		},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.HTTP == nil || spec.HTTP.Method != "POST" || spec.HTTP.URI != "/api" {
		t.Errorf("HTTP = %+v", spec.HTTP)
	}
	if spec.DstPort != 80 {
		t.Errorf("HTTP default DstPort = %d, want 80", spec.DstPort)
	}
}

func TestMapToFlowSpec_DNSDefaultPort(t *testing.T) {
	cfg := map[string]interface{}{
		"dns": map[string]interface{}{
			"domain": "example.com",
		},
	}
	spec := mapToFlowSpec(cfg, "dns")
	if spec.DNS == nil || spec.DNS.Domain != "example.com" {
		t.Errorf("DNS = %+v", spec.DNS)
	}
	// 端口默认已收敛至 ChainPlanner.ValidateSpec（统一架构 v3：
	// mapToFlowSpec 只产通用默认 80，协议级 53 由链规划器补齐）。
	if spec.DstPort != DefaultDstPort {
		t.Errorf("DNS default DstPort = %d, want %d (generic; 53 applied by chain planner)", spec.DstPort, DefaultDstPort)
	}
}

func TestMapToFlowSpec_VLAN(t *testing.T) {
	cfg := map[string]interface{}{
		"vlan_id":       float64(100),
		"vlan_priority": float64(3),
	}
	spec := mapToFlowSpec(cfg, "udp")
	if spec.VLAN == nil || spec.VLAN.ID != 100 || spec.VLAN.Priority != 3 {
		t.Errorf("VLAN = %+v", spec.VLAN)
	}
}

// TestMapToFlowSpec_HTTPFullSubmap verifies that every HTTP sub-map field
// lands in spec.HTTP after the rename + new-fields extension. Per CLAUDE.md
// testing policy §1 (spec-driven) and §3 (one test per code path), each
// field added in the unified-defaulting change needs a propagation check.
func TestMapToFlowSpec_HTTPFullSubmap(t *testing.T) {
	cfg := map[string]interface{}{
		"http": map[string]interface{}{
			"method":               "PUT",
			"uri":                  "/v1/x",
			"version":              "HTTP/1.0",
			"request_headers":      map[string]interface{}{"Host": "www.home.com", "X-Trace": "abc"},
			"body":                 `{"k":"v"}`,
			"keep_alive":           true,
			"transactions":         float64(3),
			"response_headers":     map[string]interface{}{"Content-Type": "application/json"},
			"response_body":        `{"ok":true}`,
			"response_status_code": float64(201),
			"response_status_text": "Created",
		},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.HTTP == nil {
		t.Fatalf("spec.HTTP is nil")
	}
	h := spec.HTTP
	if h.Method != "PUT" {
		t.Errorf("Method=%q, want PUT", h.Method)
	}
	if h.URI != "/v1/x" {
		t.Errorf("URI=%q, want /v1/x", h.URI)
	}
	if h.Version != "HTTP/1.0" {
		t.Errorf("Version=%q, want HTTP/1.0", h.Version)
	}
	if len(h.RequestHeaders) != 2 || h.RequestHeaders["Host"] != "www.home.com" || h.RequestHeaders["X-Trace"] != "abc" {
		t.Errorf("RequestHeaders=%+v, want {Host:www.home.com, X-Trace:abc}", h.RequestHeaders)
	}
	if h.Body != `{"k":"v"}` {
		t.Errorf("Body=%q, want {\"k\":\"v\"}", h.Body)
	}
	if !h.KeepAlive {
		t.Errorf("KeepAlive=false, want true")
	}
	if h.Transactions != 3 {
		t.Errorf("Transactions=%d, want 3", h.Transactions)
	}
	// T-HTTP-4: 旧配置带 think_time 键被忽略（不报错，其余字段正确）。
	legacy := mapToFlowSpec(map[string]interface{}{
		"http": map[string]interface{}{"method": "GET", "think_time": float64(200)},
	}, "http")
	if legacy.HTTP == nil || legacy.HTTP.Method != "GET" {
		t.Errorf("legacy think_time key: want ignored with Method=GET, got %+v", legacy.HTTP)
	}
	if len(h.ResponseHeaders) != 1 || h.ResponseHeaders["Content-Type"] != "application/json" {
		t.Errorf("ResponseHeaders=%+v, want {Content-Type:application/json}", h.ResponseHeaders)
	}
	if h.ResponseBody != `{"ok":true}` {
		t.Errorf("ResponseBody=%q, want {\"ok\":true}", h.ResponseBody)
	}
	if h.ResponseStatusCode != 201 {
		t.Errorf("ResponseStatusCode=%d, want 201", h.ResponseStatusCode)
	}
	if h.ResponseStatusText != "Created" {
		t.Errorf("ResponseStatusText=%q, want Created", h.ResponseStatusText)
	}
}

// TestMapToFlowSpec_HTTP_TCPSubConfig verifies that an HTTP strategy with a
// "tcp" sub-map gets spec.TCP populated (MSS, Handshake, Termination, etc.).
// This is the C1 regression test: before the fix, mapToFlowSpec's switch only
// read cfg["tcp"] in case "tcp", leaving spec.TCP nil for http/ftp/sip.
func TestMapToFlowSpec_HTTP_TCPSubConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"tcp": map[string]interface{}{
			"mss":         float64(1400),
			"initial_seq": float64(0x11111111),
			"handshake":   false,
		},
		"http": map[string]interface{}{
			"method": "GET",
			"uri":    "/",
		},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.TCP == nil {
		t.Fatal("TCP nil, want populated (C1: http must read tcp sub-config)")
	}
	if spec.TCP.MSS != 1400 {
		t.Errorf("TCP.MSS=%d, want 1400", spec.TCP.MSS)
	}
	if spec.TCP.InitialSeq != 0x11111111 {
		t.Errorf("TCP.InitialSeq=0x%x, want 0x11111111", spec.TCP.InitialSeq)
	}
	if spec.TCP.Handshake {
		t.Errorf("TCP.Handshake=true, want false (explicitly set)")
	}
	if !spec.TCP.Termination {
		t.Errorf("TCP.Termination=false, want true (default)")
	}
}

// TestMapToFlowSpec_InitialSeqLegacy_HandshakeDefault verifies that the
// top-level initial_seq backward compat creates a TCPConfig with
// Handshake=true and Termination=true (the defaults). Before the H3 fix,
// it created TCPConfig{InitialSeq: legacy} with zero-value Handshake/Termination
// (false), breaking HTTP/FTP/SIP flows that rely on the SYN handshake.
func TestMapToFlowSpec_InitialSeqLegacy_HandshakeDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":      "10.0.0.1",
		"dst_ip":      "10.0.0.2",
		"initial_seq": float64(0x22222222),
		"http": map[string]interface{}{
			"method": "GET",
			"uri":    "/",
		},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.TCP == nil {
		t.Fatal("TCP nil, want populated from top-level initial_seq")
	}
	if spec.TCP.InitialSeq != 0x22222222 {
		t.Errorf("TCP.InitialSeq=0x%x, want 0x22222222", spec.TCP.InitialSeq)
	}
	if !spec.TCP.Handshake {
		t.Errorf("TCP.Handshake=false, want true (H3: backward compat must default Handshake)")
	}
	if !spec.TCP.Termination {
		t.Errorf("TCP.Termination=false, want true (H3: backward compat must default Termination)")
	}
}

// TestMapToFlowSpec_LegacyHeadersKeyFallback verifies that strategies stored
// with the pre-rename "headers" JSON key still populate RequestHeaders after
// the rename to "request_headers". Without the fallback, existing DB rows
// would silently lose user-configured headers.
func TestMapToFlowSpec_LegacyHeadersKeyFallback(t *testing.T) {
	cfg := map[string]interface{}{
		"http": map[string]interface{}{
			"method":  "GET",
			"uri":     "/",
			"headers": map[string]interface{}{"Host": "legacy.example.com", "X-Old": "1"},
		},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.HTTP == nil {
		t.Fatalf("spec.HTTP is nil")
	}
	if len(spec.HTTP.RequestHeaders) != 2 {
		t.Errorf("RequestHeaders=%+v, want 2 entries from legacy 'headers' key", spec.HTTP.RequestHeaders)
	}
	if spec.HTTP.RequestHeaders["Host"] != "legacy.example.com" {
		t.Errorf("Host=%q, want legacy.example.com", spec.HTTP.RequestHeaders["Host"])
	}
	if spec.HTTP.RequestHeaders["X-Old"] != "1" {
		t.Errorf("X-Old=%q, want 1", spec.HTTP.RequestHeaders["X-Old"])
	}
}

// TestMapToFlowSpec_NewHeadersKeyPreferredOverLegacy verifies that when BOTH
// "request_headers" (new) and "headers" (legacy) are present, the new key
// wins and the legacy key is ignored. This prevents accidental merge of
// stale config with new config.
func TestMapToFlowSpec_NewHeadersKeyPreferredOverLegacy(t *testing.T) {
	cfg := map[string]interface{}{
		"http": map[string]interface{}{
			"method":          "GET",
			"uri":             "/",
			"request_headers": map[string]interface{}{"Host": "new.example.com"},
			"headers":         map[string]interface{}{"Host": "legacy.example.com", "X-Old": "1"},
		},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.HTTP == nil {
		t.Fatalf("spec.HTTP is nil")
	}
	if spec.HTTP.RequestHeaders["Host"] != "new.example.com" {
		t.Errorf("Host=%q, want new.example.com (new key should win)", spec.HTTP.RequestHeaders["Host"])
	}
	if _, exists := spec.HTTP.RequestHeaders["X-Old"]; exists {
		t.Errorf("X-Old leaked from legacy key when new key present: %+v", spec.HTTP.RequestHeaders)
	}
}

// --- L2/L3 field defaults (SrcMAC/DstMAC/DSCP/Flags) ---
//
// Per CLAUDE.md testing policy §1 (spec-driven): every default value is a
// spec row that needs a positive test (default applied when absent) AND a
// negative test (user value wins when present). Per §2 (failure paths): the
// "user explicitly set 0" path for numeric fields (DSCP=0 best-effort,
// Flags=0 no-DF) must be tested because 0 is a valid user choice that the
// naive getIntDefault helper would silently override.

// TestMapToFlowSpec_DefaultSrcMAC verifies that absent src_mac falls back to
// DefaultSrcMAC (02:00:00:00:00:01) so trafficgen packets are visually
// distinct on the wire. Before the fix, absent src_mac produced empty string,
// which the builder wrote as 00:00:00:00:00:00 -- indistinguishable from
// uninitialized traffic and not filterable in tcpdump.
func TestMapToFlowSpec_DefaultSrcMAC(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcMAC != DefaultSrcMAC {
		t.Errorf("SrcMAC=%q, want default %q", spec.SrcMAC, DefaultSrcMAC)
	}
}

// TestMapToFlowSpec_DefaultDstMAC verifies that absent dst_mac falls back to
// DefaultDstMAC (02:00:00:00:00:02).
func TestMapToFlowSpec_DefaultDstMAC(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DstMAC != DefaultDstMAC {
		t.Errorf("DstMAC=%q, want default %q", spec.DstMAC, DefaultDstMAC)
	}
}

// TestMapToFlowSpec_MACsUserOverride verifies that explicit src_mac/dst_mac
// in the config map win over the defaults. This is the user>default rule.
func TestMapToFlowSpec_MACsUserOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":  "10.0.0.1",
		"dst_ip":  "10.0.0.2",
		"src_mac": "aa:bb:cc:dd:ee:ff",
		"dst_mac": "11:22:33:44:55:66",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("SrcMAC=%q, want aa:bb:cc:dd:ee:ff (user override)", spec.SrcMAC)
	}
	if spec.DstMAC != "11:22:33:44:55:66" {
		t.Errorf("DstMAC=%q, want 11:22:33:44:55:66 (user override)", spec.DstMAC)
	}
}

// TestMapToFlowSpec_DefaultDSCP verifies that absent dscp falls back to
// DefaultDSCP (0x2E=46, EF). The IP TOS byte becomes 0xB8 (DSCP<<2 | ECN=0),
// which is the tcpdump filter marker for trafficgen packets.
func TestMapToFlowSpec_DefaultDSCP(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DSCP != DefaultDSCP {
		t.Errorf("DSCP=%d, want default %d", spec.DSCP, DefaultDSCP)
	}
}

// TestMapToFlowSpec_DSCPUserExplicitZero verifies that explicit dscp=0 in the
// config map is honored (best-effort traffic, no trafficgen marker). The
// naive getIntDefault helper would treat 0 as "absent" and override with
// DefaultDSCP -- the presence-check helper prevents this regression.
func TestMapToFlowSpec_DSCPUserExplicitZero(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"dscp":   float64(0),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DSCP != 0 {
		t.Errorf("DSCP=%d, want 0 (user explicit best-effort, not default)", spec.DSCP)
	}
}

// TestMapToFlowSpec_DSCPUserOverride verifies that a non-zero user-provided
// DSCP wins over the default.
func TestMapToFlowSpec_DSCPUserOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"dscp":   float64(8), // CS1
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DSCP != 8 {
		t.Errorf("DSCP=%d, want 8 (user override)", spec.DSCP)
	}
}

// TestMapToFlowSpec_DefaultIPFlags verifies that absent flags falls back to
// DefaultIPFlags (DF=1, 0x02). Matches modern OS TCP defaults (Linux/macOS/
// Windows all set DF=1 for TCP PMTU discovery).
func TestMapToFlowSpec_DefaultIPFlags(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.IPFlags != DefaultIPFlags {
		t.Errorf("IPFlags=%d, want default %d (DF=1)", spec.IPFlags, DefaultIPFlags)
	}
}

// TestMapToFlowSpec_FlagsUserExplicitZero verifies that explicit ip_flags=0
// in the config map is honored (allow fragmentation). Same presence-check
// rationale as TestMapToFlowSpec_DSCPUserExplicitZero.
func TestMapToFlowSpec_FlagsUserExplicitZero(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"ip_flags": float64(0),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.IPFlags != 0 {
		t.Errorf("IPFlags=%d, want 0 (user explicit no-DF, not default)", spec.IPFlags)
	}
}

// TestMapToFlowSpec_FlagsUserOverride verifies that a user-provided ip_flags
// value (e.g. MF=1 for fragmented traffic) wins over the default DF=1.
func TestMapToFlowSpec_FlagsUserOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"ip_flags": float64(1), // MF=1
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.IPFlags != 1 {
		t.Errorf("IPFlags=%d, want 1 (user override MF)", spec.IPFlags)
	}
}

// --- Edge cases: null / empty / JSON types ---

// TestMapToFlowSpec_DSCPNullFallsBackToDefault verifies that explicit JSON
// null for dscp is treated as "not set", not as "explicitly 0". Without the
// nil guard in defaultDSCP, cfg["dscp"]=nil passes the presence check and
// getInt returns 0, silently disabling the trafficgen marker.
func TestMapToFlowSpec_DSCPNullFallsBackToDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"dscp":   nil,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DSCP != DefaultDSCP {
		t.Errorf("DSCP=%d, want DefaultDSCP=%d (null should fall back to default)", spec.DSCP, DefaultDSCP)
	}
}

// TestMapToFlowSpec_FlagsNullFallsBackToDefault verifies that explicit JSON
// null for ip_flags is treated as "not set".
func TestMapToFlowSpec_FlagsNullFallsBackToDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"ip_flags": nil,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.IPFlags != DefaultIPFlags {
		t.Errorf("IPFlags=%d, want DefaultIPFlags=%d (null should fall back to default)", spec.IPFlags, DefaultIPFlags)
	}
}

// TestMapToFlowSpec_SrcMACExplicitEmpty verifies that explicit empty string
// for src_mac is honored (produces spec.SrcMAC=""), not replaced with the
// default. Use case: ARP probe with zero sender MAC. Pre-fix getStringDefault
// clobbered empty with DefaultSrcMAC.
func TestMapToFlowSpec_SrcMACExplicitEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":  "10.0.0.1",
		"dst_ip":  "10.0.0.2",
		"src_mac": "",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcMAC != "" {
		t.Errorf("SrcMAC=%q, want empty (user explicit empty should be honored)", spec.SrcMAC)
	}
}

// TestMapToFlowSpec_DstMACExplicitEmpty verifies the same for dst_mac.
func TestMapToFlowSpec_DstMACExplicitEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":  "10.0.0.1",
		"dst_ip":  "10.0.0.2",
		"dst_mac": "",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DstMAC != "" {
		t.Errorf("DstMAC=%q, want empty (user explicit empty should be honored)", spec.DstMAC)
	}
}

// TestMapToFlowSpec_SrcMACNullFallsBackToDefault verifies that JSON null for
// src_mac is treated as "not set" and falls back to DefaultSrcMAC.
func TestMapToFlowSpec_SrcMACNullFallsBackToDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":  "10.0.0.1",
		"dst_ip":  "10.0.0.2",
		"src_mac": nil,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcMAC != DefaultSrcMAC {
		t.Errorf("SrcMAC=%q, want DefaultSrcMAC=%q (null should fall back to default)", spec.SrcMAC, DefaultSrcMAC)
	}
}

// --- Missing spec-row coverage (per CLAUDE.md §1: every default is a spec row) ---

// TestMapToFlowSpec_DefaultTTL verifies that absent ttl falls back to 64.
// Pre-existing helper getIntDefault covers this, but it had no test.
func TestMapToFlowSpec_DefaultTTL(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.TTL != 64 {
		t.Errorf("TTL=%d, want 64 (default)", spec.TTL)
	}
}

// TestMapToFlowSpec_TOSPropagates verifies that the legacy tos field
// propagates to spec.TOS. L3Base later splits TOS into DSCP/ECN.
func TestMapToFlowSpec_TOSPropagates(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"tos":    float64(0xB8),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.TOS != 0xB8 {
		t.Errorf("TOS=0x%02x, want 0xB8", spec.TOS)
	}
}

// TestMapToFlowSpec_ECNPropagates verifies that user-provided ECN propagates.
func TestMapToFlowSpec_ECNPropagates(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"ecn":    float64(1),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.ECN != 1 {
		t.Errorf("ECN=%d, want 1", spec.ECN)
	}
}

// TestMapToFlowSpec_FragOffsetPropagates verifies that user-provided
// frag_offset propagates.
func TestMapToFlowSpec_FragOffsetPropagates(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":      "10.0.0.1",
		"dst_ip":      "10.0.0.2",
		"frag_offset": float64(185),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.FragOffset != 185 {
		t.Errorf("FragOffset=%d, want 185", spec.FragOffset)
	}
}

// TestMapToFlowSpec_DefaultsPropagateToWire is an integration test that drives
// the full path: config map -> mapToFlowSpec -> L3Base -> Builder.Build -> wire
// bytes, and asserts the on-wire packet actually carries the trafficgen
// markers (MAC 02:00:00:00:00:01, TOS byte 0xB8, DF bit set in bytes 6-7).
//
// Per CLAUDE.md testing policy §4: units passing in isolation does not prove
// the feature works end-to-end. The earlier unit tests verify mapToFlowSpec
// populates the FlowSpec correctly, but without this test, a regression in
// L3Base or Builder that loses the defaults would not be caught.
func TestMapToFlowSpec_DefaultsPropagateToWire(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"src_port": float64(12345),
		"dst_port": float64(80),
	}
	spec := mapToFlowSpec(cfg, "tcp")

	// Construct an L3Config via L3Base (as the protocol planners do) so the
	// integration path mirrors production.
	l3 := L3Base(spec.SrcIP, spec.DstIP, 6, spec.TTL, 1, spec)
	config := PacketConfig{
		L2: L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: 0x0800},
		L3: l3,
		L4: L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: spec.DstPort},
	}
	builder := NewBuilder()
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Ethernet header: bytes 0-5 dst MAC, 6-11 src MAC, 12-13 ethertype.
	wantDstMAC := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	if !bytes.Equal(packet[0:6], wantDstMAC) {
		t.Errorf("dst MAC bytes = %x, want %x (DefaultDstMAC)", packet[0:6], wantDstMAC)
	}
	wantSrcMAC := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(packet[6:12], wantSrcMAC) {
		t.Errorf("src MAC bytes = %x, want %x (DefaultSrcMAC)", packet[6:12], wantSrcMAC)
	}

	// IP header: byte 15 = TOS = (DSCP<<2)|(ECN&0x03).
	wantTOS := byte((DefaultDSCP << 2) | (spec.ECN & 0x03)) // 0x2E<<2 = 0xB8
	if packet[15] != wantTOS {
		t.Errorf("TOS byte = 0x%02x, want 0x%02x (DSCP=0x2E shifted)", packet[15], wantTOS)
	}

	// IP flags + frag offset: bytes 20-21 (L3 offset 6-7), DF bit is bit 1 of
	// the 16-bit value (0x4000 when set).
	flagsPlusOffset := uint16(packet[20])<<8 | uint16(packet[21])
	if flagsPlusOffset&0x4000 == 0 {
		t.Errorf("DF bit not set in IP header bytes 6-7 = 0x%04x, want DF=1 (default)", flagsPlusOffset)
	}
	if flagsPlusOffset&0x1FFF != 0 {
		t.Errorf("frag offset = %d, want 0", flagsPlusOffset&0x1FFF)
	}
}

// TestMapToFlowSpec_DefaultsPropagateToWire_FlagsZeroHonored is the inverse
// integration test: explicit flags=0 in config map -> on-wire IP header has
// DF bit cleared (bytes 6-7 bit 14 = 0). Before the L3Base fix, L3Base would
// silently rewrite flags=0 to DF=1, breaking the user>default rule end-to-end.
func TestMapToFlowSpec_DefaultsPropagateToWire_FlagsZeroHonored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"src_port": float64(12345),
		"dst_port": float64(80),
		"ip_flags": float64(0), // user explicitly wants no-DF
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.IPFlags != 0 {
		t.Fatalf("precondition: spec.IPFlags=%d, want 0", spec.IPFlags)
	}

	l3 := L3Base(spec.SrcIP, spec.DstIP, 6, spec.TTL, 1, spec)
	if l3.Flags != 0 {
		t.Fatalf("L3Base rewrote explicit flags=0 to 0x%02x -- user>default rule broken", l3.Flags)
	}
	config := PacketConfig{
		L2: L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: 0x0800},
		L3: l3,
		L4: L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: spec.DstPort},
	}
	packet, err := NewBuilder().Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	flagsPlusOffset := uint16(packet[20])<<8 | uint16(packet[21])
	if flagsPlusOffset&0x4000 != 0 {
		t.Errorf("DF bit set in IP header (0x%04x), want DF=0 (user explicit flags=0)", flagsPlusOffset)
	}
}

// --- L3/L4 address defaults (SrcIP/DstIP/SrcPort/DstPort) ---

// TestMapToFlowSpec_DefaultSrcIP verifies absent src_ip falls back to
// DefaultSrcIP (10.0.0.1). Without this default, src_ip was
// empty and the IP header had source 0.0.0.0, which is not a realistic
// client address and is dropped by many routers.
func TestMapToFlowSpec_DefaultSrcIP(t *testing.T) {
	cfg := map[string]interface{}{
		"dst_port": float64(80),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcIP != DefaultSrcIP {
		t.Errorf("SrcIP=%q, want default %q", spec.SrcIP, DefaultSrcIP)
	}
}

// TestMapToFlowSpec_DefaultDstIP verifies absent dst_ip falls back to
// DefaultDstIP (20.0.0.1).
func TestMapToFlowSpec_DefaultDstIP(t *testing.T) {
	cfg := map[string]interface{}{
		"src_port": float64(12345),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DstIP != DefaultDstIP {
		t.Errorf("DstIP=%q, want default %q", spec.DstIP, DefaultDstIP)
	}
}

// TestMapToFlowSpec_DefaultSrcPort verifies absent src_port falls back to
// DefaultSrcPort (12345). Without this default, src_port was 0 and the
// packet had an unrealistic source port.
func TestMapToFlowSpec_DefaultSrcPort(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcPort != DefaultSrcPort {
		t.Errorf("SrcPort=%d, want default %d", spec.SrcPort, DefaultSrcPort)
	}
}

// TestMapToFlowSpec_DefaultDstPort_TCP verifies absent dst_port falls back
// to DefaultDstPort (80) for TCP.
func TestMapToFlowSpec_DefaultDstPort_TCP(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DstPort != DefaultDstPort {
		t.Errorf("DstPort=%d, want default %d", spec.DstPort, DefaultDstPort)
	}
}

// TestMapToFlowSpec_DefaultDstPort_UDP verifies absent dst_port falls back
// to DefaultDstPort (80) for UDP (per the unified rule -- HTTP=80, DNS=53
// override in their own switch cases).
func TestMapToFlowSpec_DefaultDstPort_UDP(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "udp")
	if spec.DstPort != DefaultDstPort {
		t.Errorf("DstPort=%d, want default %d", spec.DstPort, DefaultDstPort)
	}
}

// TestMapToFlowSpec_DefaultDstPort_DNSOverridesTo53 verifies that DNS
// protocol overrides the generic 80 default with 53 (its well-known port).
func TestMapToFlowSpec_DefaultDstPort_DNSOverridesTo53(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"dns":    map[string]interface{}{"domain": "example.com"},
	}
	spec := mapToFlowSpec(cfg, "dns")
	// 端口默认已收敛至 ChainPlanner.ValidateSpec：mapToFlowSpec 产通用
	// 默认 80，DNS 53 由链规划器在 Plan 时补齐（不再有第二处 53 默认）。
	if spec.DstPort != DefaultDstPort {
		t.Errorf("DNS DstPort=%d, want %d (generic default; 53 applied by chain planner)", spec.DstPort, DefaultDstPort)
	}
}

// TestMapToFlowSpec_DefaultDstPort_HTTPMatchesGeneric80 verifies HTTP does
// NOT need to override since its well-known port is 80, same as the generic
// default. (Sanity check -- HTTP does not break the generic default.)
func TestMapToFlowSpec_DefaultDstPort_HTTPMatchesGeneric80(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"http":   map[string]interface{}{"method": "GET"},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.DstPort != 80 {
		t.Errorf("HTTP DstPort=%d, want 80", spec.DstPort)
	}
}

// TestMapToFlowSpec_SrcIPUserOverride verifies user-provided src_ip wins.
func TestMapToFlowSpec_SrcIPUserOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.1.2.3",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcIP != "10.1.2.3" {
		t.Errorf("SrcIP=%q, want 10.1.2.3 (user override)", spec.SrcIP)
	}
}

// TestMapToFlowSpec_DstIPUserOverride verifies user-provided dst_ip wins.
func TestMapToFlowSpec_DstIPUserOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "8.8.8.8",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DstIP != "8.8.8.8" {
		t.Errorf("DstIP=%q, want 8.8.8.8 (user override)", spec.DstIP)
	}
}

// TestMapToFlowSpec_SrcPortUserOverride verifies user-provided src_port wins.
func TestMapToFlowSpec_SrcPortUserOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"src_port": float64(54321),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcPort != 54321 {
		t.Errorf("SrcPort=%d, want 54321 (user override)", spec.SrcPort)
	}
}

// TestMapToFlowSpec_SrcPortExplicitZero verifies explicit src_port:0 is
// honored (port 0 is a valid user choice -- let OS pick ephemeral port).
// The defaultPort presence check prevents the 0 from being silently
// replaced with DefaultSrcPort.
func TestMapToFlowSpec_SrcPortExplicitZero(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"src_port": float64(0),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcPort != 0 {
		t.Errorf("SrcPort=%d, want 0 (user explicit zero, not default)", spec.SrcPort)
	}
}

// TestMapToFlowSpec_DstPortExplicitZero verifies explicit dst_port:0 is
// honored. Same presence-check rationale as src_port.
func TestMapToFlowSpec_DstPortExplicitZero(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(0),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DstPort != 0 {
		t.Errorf("DstPort=%d, want 0 (user explicit zero, not default)", spec.DstPort)
	}
}

// TestMapToFlowSpec_SrcIPNullFallsBackToDefault verifies JSON null for
// src_ip is treated as "not set" and falls back to DefaultSrcIP.
func TestMapToFlowSpec_SrcIPNullFallsBackToDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": nil,
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcIP != DefaultSrcIP {
		t.Errorf("SrcIP=%q, want DefaultSrcIP (null should fall back)", spec.SrcIP)
	}
}

// TestMapToFlowSpec_DstPortNullFallsBackToDefault verifies JSON null for
// dst_port is treated as "not set" and falls back to DefaultDstPort.
func TestMapToFlowSpec_DstPortNullFallsBackToDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": nil,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DstPort != DefaultDstPort {
		t.Errorf("DstPort=%d, want DefaultDstPort (null should fall back)", spec.DstPort)
	}
}

// TestMapToFlowSpec_AllDefaults_TCP verifies that a minimal cfg with only
// protocol produces a FlowSpec with every default filled in. This is the
// "trafficgen smoke test" -- user creates a strategy with just
// {protocol: "tcp"} and gets a complete, wire-valid spec.
func TestMapToFlowSpec_AllDefaults_TCP(t *testing.T) {
	cfg := map[string]interface{}{}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcIP != DefaultSrcIP {
		t.Errorf("SrcIP=%q, want %q", spec.SrcIP, DefaultSrcIP)
	}
	if spec.DstIP != DefaultDstIP {
		t.Errorf("DstIP=%q, want %q", spec.DstIP, DefaultDstIP)
	}
	if spec.SrcPort != DefaultSrcPort {
		t.Errorf("SrcPort=%d, want %d", spec.SrcPort, DefaultSrcPort)
	}
	if spec.DstPort != DefaultDstPort {
		t.Errorf("DstPort=%d, want %d", spec.DstPort, DefaultDstPort)
	}
	if spec.SrcMAC != DefaultSrcMAC {
		t.Errorf("SrcMAC=%q, want %q", spec.SrcMAC, DefaultSrcMAC)
	}
	if spec.DstMAC != DefaultDstMAC {
		t.Errorf("DstMAC=%q, want %q", spec.DstMAC, DefaultDstMAC)
	}
	if spec.DSCP != DefaultDSCP {
		t.Errorf("DSCP=%d, want %d", spec.DSCP, DefaultDSCP)
	}
	if spec.IPFlags != DefaultIPFlags {
		t.Errorf("IPFlags=%d, want %d", spec.IPFlags, DefaultIPFlags)
	}
	if spec.TTL != 64 {
		t.Errorf("TTL=%d, want 64", spec.TTL)
	}
}

// --- Edge-case coverage for IP/port defaults (per CLAUDE.md §1, §2) ---
//
// The following tests close the gaps identified in the post-merge test
// coverage audit: explicit empty/zero for IPs and ports, null fall-back
// for DstIP/SrcPort, DNS port-0 honored vs. overridden, HTTP port override,
// and a wire-level integration test for the IP/port defaults specifically
// (TestMapToFlowSpec_DefaultsPropagateToWire only covered MAC/DSCP/Flags).

// TestMapToFlowSpec_SrcIPExplicitEmpty verifies that explicit empty string
// for src_ip is honored (spec.SrcIP=""), not replaced with DefaultSrcIP.
// Use case: a planner that intentionally sends a 0.0.0.0 source (rare but
// valid for certain probe traffic). Per the user>default rule, "" is a
// legitimate user choice.
func TestMapToFlowSpec_SrcIPExplicitEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcIP != "" {
		t.Errorf("SrcIP=%q, want empty (user explicit empty should be honored)", spec.SrcIP)
	}
}

// TestMapToFlowSpec_DstIPExplicitEmpty verifies the same for dst_ip.
func TestMapToFlowSpec_DstIPExplicitEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DstIP != "" {
		t.Errorf("DstIP=%q, want empty (user explicit empty should be honored)", spec.DstIP)
	}
}

// TestMapToFlowSpec_DstIPNullFallsBackToDefault verifies JSON null for dst_ip
// is treated as "not set" and falls back to DefaultDstIP.
func TestMapToFlowSpec_DstIPNullFallsBackToDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": nil,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.DstIP != DefaultDstIP {
		t.Errorf("DstIP=%q, want DefaultDstIP=%q (null should fall back)", spec.DstIP, DefaultDstIP)
	}
}

// TestMapToFlowSpec_SrcPortNullFallsBackToDefault verifies JSON null for
// src_port is treated as "not set" and falls back to DefaultSrcPort.
func TestMapToFlowSpec_SrcPortNullFallsBackToDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"src_port": nil,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SrcPort != DefaultSrcPort {
		t.Errorf("SrcPort=%d, want DefaultSrcPort=%d (null should fall back)", spec.SrcPort, DefaultSrcPort)
	}
}

// TestMapToFlowSpec_DstPortExplicitZero_UDP verifies explicit dst_port:0 is
// honored for UDP (not overridden to 80). Per the user>default rule.
func TestMapToFlowSpec_DstPortExplicitZero_UDP(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(0),
	}
	spec := mapToFlowSpec(cfg, "udp")
	if spec.DstPort != 0 {
		t.Errorf("DstPort=%d, want 0 (user explicit zero honored for UDP)", spec.DstPort)
	}
}

// TestMapToFlowSpec_DNSDstPortExplicitZeroHonored verifies that explicit
// dst_port=0 for DNS is NOT overridden to 53. The presence check at
// strategy_convert.go:247 means "key present + non-nil" => user value wins.
// This is the load-bearing test for the DNS port override logic.
func TestMapToFlowSpec_DNSDstPortExplicitZeroHonored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(0),
		"dns":      map[string]interface{}{"domain": "example.com"},
	}
	spec := mapToFlowSpec(cfg, "dns")
	if spec.DstPort != 0 {
		t.Errorf("DNS DstPort=%d, want 0 (user explicit zero must NOT be overridden to 53)", spec.DstPort)
	}
}

// TestMapToFlowSpec_DNSDstPortUserOverride verifies DNS user-provided
// non-zero port (e.g., 5353 for mDNS) wins over the 53 default.
func TestMapToFlowSpec_DNSDstPortUserOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(5353),
		"dns":      map[string]interface{}{"domain": "example.com"},
	}
	spec := mapToFlowSpec(cfg, "dns")
	if spec.DstPort != 5353 {
		t.Errorf("DNS DstPort=%d, want 5353 (user override)", spec.DstPort)
	}
}

// TestMapToFlowSpec_DNSDstPortNullOverridesTo53 verifies JSON null for
// dst_port under DNS protocol falls back to 53 (not 80).
func TestMapToFlowSpec_DNSDstPortNullOverridesTo53(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": nil,
		"dns":      map[string]interface{}{"domain": "example.com"},
	}
	spec := mapToFlowSpec(cfg, "dns")
	// 端口默认已收敛至 ChainPlanner.ValidateSpec：mapToFlowSpec 产通用默认
	// 80（含 nil dst_port 走 defaultPort），DNS 53 由链规划器在 Plan 时补齐。
	if spec.DstPort != DefaultDstPort {
		t.Errorf("DNS DstPort=%d, want %d (generic default; 53 applied by chain planner)", spec.DstPort, DefaultDstPort)
	}
}

// TestMapToFlowSpec_HTTPDstPortExplicitZeroHonored verifies that explicit
// dst_port=0 for HTTP is honored (not overridden to 80). Since HTTP no
// longer has a port-override block (DefaultDstPort=80 covers it), this test
// guards against future regressions that might re-add an override.
func TestMapToFlowSpec_HTTPDstPortExplicitZeroHonored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(0),
		"http":     map[string]interface{}{"method": "GET"},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.DstPort != 0 {
		t.Errorf("HTTP DstPort=%d, want 0 (user explicit zero honored for HTTP)", spec.DstPort)
	}
}

// TestMapToFlowSpec_HTTPDstPortUserOverride verifies HTTP user-provided port
// (e.g., 8080) wins over the 80 default.
func TestMapToFlowSpec_HTTPDstPortUserOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(8080),
		"http":     map[string]interface{}{"method": "GET"},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.DstPort != 8080 {
		t.Errorf("HTTP DstPort=%d, want 8080 (user override)", spec.DstPort)
	}
}

// TestMapToFlowSpec_DefaultsPropagateToWire_IPPort is an integration test
// that drives an empty config map through the full path:
//
//	cfg -> mapToFlowSpec -> L3Base -> Builder.Build -> wire bytes
//
// and asserts the on-wire packet actually carries the default SrcIP/DstIP
// and src/dst port. Per CLAUDE.md testing policy §4: units passing in
// isolation does not prove the feature works end-to-end. The earlier
// TestMapToFlowSpec_DefaultsPropagateToWire only covered MAC/DSCP/Flags.
func TestMapToFlowSpec_DefaultsPropagateToWire_IPPort(t *testing.T) {
	cfg := map[string]interface{}{}
	spec := mapToFlowSpec(cfg, "tcp")

	l3 := L3Base(spec.SrcIP, spec.DstIP, 6, spec.TTL, 1, spec)
	config := PacketConfig{
		L2: L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: 0x0800},
		L3: l3,
		L4: L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: spec.DstPort},
	}
	packet, err := NewBuilder().Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// IP header: bytes 26-29 = src IP, 30-33 = dst IP (L3 offset 12-19).
	wantSrcIP := []byte{10, 0, 0, 1}
	if !bytes.Equal(packet[26:30], wantSrcIP) {
		t.Errorf("src IP bytes = %v, want %v (DefaultSrcIP 10.0.0.1)", packet[26:30], wantSrcIP)
	}
	wantDstIP := []byte{20, 0, 0, 1}
	if !bytes.Equal(packet[30:34], wantDstIP) {
		t.Errorf("dst IP bytes = %v, want %v (DefaultDstIP 20.0.0.1)", packet[30:34], wantDstIP)
	}

	// TCP header: bytes 34-35 = src port, 36-37 = dst port.
	wantSrcPort := []byte{0x30, 0x39} // 12345 = 0x3039
	if !bytes.Equal(packet[34:36], wantSrcPort) {
		t.Errorf("src port bytes = %x, want %x (DefaultSrcPort 12345)", packet[34:36], wantSrcPort)
	}
	wantDstPort := []byte{0x00, 0x50} // 80 = 0x0050
	if !bytes.Equal(packet[36:38], wantDstPort) {
		t.Errorf("dst port bytes = %x, want %x (DefaultDstPort 80)", packet[36:38], wantDstPort)
	}
}

// TestMapToFlowSpec_PadMinFrame_Absent verifies that absent pad_min_frame
// leaves PadMinFrame nil (default ON, handled by Builder.shouldPad). This
// is the default path — user doesn't specify the field, padding applies.
func TestMapToFlowSpec_PadMinFrame_Absent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.PadMinFrame != nil {
		t.Errorf("PadMinFrame=%v, want nil (absent -> default ON via builder)", *spec.PadMinFrame)
	}
}

// TestMapToFlowSpec_PadMinFrame_True verifies that explicit true is honored
// (not replaced with a default). Presence-checked so true wins.
func TestMapToFlowSpec_PadMinFrame_True(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":        "10.0.0.1",
		"dst_ip":        "10.0.0.2",
		"pad_min_frame": true,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.PadMinFrame == nil {
		t.Fatal("PadMinFrame=nil, want *true")
	}
	if !*spec.PadMinFrame {
		t.Errorf("PadMinFrame=false, want true (user explicit)")
	}
}

// TestMapToFlowSpec_PadMinFrame_False verifies that explicit false is honored
// (NOT replaced with the default true). This is the whole point of the
// presence-check: user "don't pad" must win, or the feature is useless.
// Matches the pattern of TestMapToFlowSpec_FlagsUserExplicitZero.
func TestMapToFlowSpec_PadMinFrame_False(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":        "10.0.0.1",
		"dst_ip":        "10.0.0.2",
		"pad_min_frame": false,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.PadMinFrame == nil {
		t.Fatal("PadMinFrame=nil, want *false (explicit false, not absent)")
	}
	if *spec.PadMinFrame {
		t.Errorf("PadMinFrame=true, want false (user explicit OFF)")
	}
}

// TestMapToFlowSpec_PadMinFrame_NullFallsBackToDefault verifies that explicit
// JSON null is treated as "not set", not as "explicitly false". Without the
// nil guard, cfg["pad_min_frame"]=nil passes the outer ok check but fails
// the inner bool type assertion, leaving PadMinFrame nil (correct here, but
// fragile — this test pins the behavior so a future refactor can't break it).
func TestMapToFlowSpec_PadMinFrame_NullFallsBackToDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":        "10.0.0.1",
		"dst_ip":        "10.0.0.2",
		"pad_min_frame": nil,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.PadMinFrame != nil {
		t.Errorf("PadMinFrame=%v, want nil (null -> default ON via builder)", *spec.PadMinFrame)
	}
}

// TestMapToFlowSpec_PadMinFrame_NonBoolIgnored verifies that a non-bool value
// (e.g. a string from misconfigured JSON) is ignored, leaving PadMinFrame nil.
// This matches the inner type-assertion guard's behavior.
func TestMapToFlowSpec_PadMinFrame_NonBoolIgnored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":        "10.0.0.1",
		"dst_ip":        "10.0.0.2",
		"pad_min_frame": "yes", // wrong type
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.PadMinFrame != nil {
		t.Errorf("PadMinFrame=%v, want nil (non-bool ignored)", *spec.PadMinFrame)
	}
}

// ============================================================================
// FTP branch (strategy_convert.go)
// ============================================================================
//
// Task 5（扁平删除）后 FTP 扁平形状判死（mapToFlowSpec → ValidationErrors，
// 见 ftp_flat_test.go）。本区只保留两类仍然合法的覆盖：
//   1. 层链形状经 mapToFlowSpec 的转换（无顶层扁平键 → 干净；
//      case "ftp" 的 21 默认口仍对链形 cfg 生效）
//   2. parse 函数行为（banner/commands/sessions/data_channel）经
//      ParseFTPConfigFromMap——层链路径 translateTerminalConfig 的同一
//      真相，扁平 cfg["ftp"] 分支已死。
// flat dst_port 的 guard-halves（显式 0 荣/nil 回退）由 DNS/SIP 同款测试
// 覆盖（TestMapToFlowSpec_DNSDstPort* / _SIP_），FTP 不再单独成测。

// TestMapToFlowSpec_FTP_ChainConfig converts a layers-chain ftp config and
// verifies: no ValidationErrors (flat keys absent), and the case "ftp"
// default dst_port 21 still applies when no flat dst_port exists.
func TestMapToFlowSpec_FTP_ChainConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": float64(21000)}},
			map[string]interface{}{"ftp": map[string]interface{}{"banner": "220 chain"}},
		},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("chain-shape ftp must convert clean, got %v", spec.ValidationErrors)
	}
	if spec.DstPort != 21 {
		t.Errorf("FTP DstPort=%d, want 21 (control-channel default for chain cfg without flat dst_port)", spec.DstPort)
	}
	if spec.SrcIP != "10.0.0.1" || spec.DstIP != "10.0.0.2" {
		t.Errorf("layer IP truth lost: src=%s dst=%s", spec.SrcIP, spec.DstIP)
	}
}

// TestParseFTPConfigFromMap_FullConfig verifies that a fully-populated ftp
// layer config parses into Banner + Commands verbatim (same parse functions
// the dead flat branch used; the chain path translates through this entry).
func TestParseFTPConfigFromMap_FullConfig(t *testing.T) {
	fc := ParseFTPConfigFromMap(map[string]interface{}{
		"banner": "220 Welcome",
		"commands": []interface{}{
			map[string]interface{}{
				"cmd":      "USER anonymous",
				"response": "331 Anonymous access allowed",
			},
			map[string]interface{}{
				"cmd":      "PASS guest@",
				"response": "230 Login successful",
			},
		},
	})
	if fc == nil {
		t.Fatal("FTP nil, want populated")
	}
	if fc.Banner != "220 Welcome" {
		t.Errorf("FTP.Banner=%q, want \"220 Welcome\"", fc.Banner)
	}
	if len(fc.Commands) != 2 {
		t.Fatalf("FTP.Commands len=%d, want 2", len(fc.Commands))
	}
	if fc.Commands[0].Cmd != "USER anonymous" || fc.Commands[0].Response != "331 Anonymous access allowed" {
		t.Errorf("FTP.Commands[0]=%+v", fc.Commands[0])
	}
	if fc.Commands[1].Cmd != "PASS guest@" || fc.Commands[1].Response != "230 Login successful" {
		t.Errorf("FTP.Commands[1]=%+v", fc.Commands[1])
	}
}

// TestParseFTPConfigFromMap_NilForEmpty verifies the empty-layer-config
// contract: no banner/commands/data_channel/sessions → nil config, the
// generator then runs the default empty session (legacy Plan treats nil
// Config the same way).
func TestParseFTPConfigFromMap_NilForEmpty(t *testing.T) {
	if fc := ParseFTPConfigFromMap(map[string]interface{}{}); fc != nil {
		t.Errorf("FTP=%+v, want nil (empty layer config)", fc)
	}
	if fc := ParseFTPConfigFromMap(nil); fc != nil {
		t.Errorf("FTP=%+v, want nil (nil input)", fc)
	}
}

// TestParseFTPConfigFromMap_CommandsEmpty verifies that an empty commands
// array leaves Commands nil (parseFTPCommands returns nil for len==0).
func TestParseFTPConfigFromMap_CommandsEmpty(t *testing.T) {
	fc := ParseFTPConfigFromMap(map[string]interface{}{
		"banner":   "220",
		"commands": []interface{}{},
	})
	if fc == nil {
		t.Fatal("FTP nil, want populated")
	}
	if fc.Commands != nil {
		t.Errorf("FTP.Commands=%v, want nil (empty array -> nil)", fc.Commands)
	}
}

// TestParseFTPConfigFromMap_CommandsAbsent verifies that an absent commands
// key leaves Commands nil. Same outcome as empty array, different path.
func TestParseFTPConfigFromMap_CommandsAbsent(t *testing.T) {
	fc := ParseFTPConfigFromMap(map[string]interface{}{"banner": "220"})
	if fc == nil {
		t.Fatal("FTP nil, want populated")
	}
	if fc.Commands != nil {
		t.Errorf("FTP.Commands=%v, want nil (absent key)", fc.Commands)
	}
}

// TestParseFTPConfigFromMap_CommandsNonArray verifies that a non-array
// commands value (e.g. a string) leaves Commands nil; with no other content
// the whole config collapses to nil (empty-config contract). parseFTPCommands's
// type assertion `v.([]interface{})` fails, returning nil.
func TestParseFTPConfigFromMap_CommandsNonArray(t *testing.T) {
	fc := ParseFTPConfigFromMap(map[string]interface{}{
		"commands": "USER anonymous",
	})
	if fc != nil {
		t.Errorf("FTP=%+v, want nil (non-array commands -> no content -> nil config)", fc)
	}
}

// TestParseFTPConfigFromMap_CommandsSkipNonMapItems verifies that non-map
// items in the commands array are silently skipped, while valid items are
// kept.
func TestParseFTPConfigFromMap_CommandsSkipNonMapItems(t *testing.T) {
	fc := ParseFTPConfigFromMap(map[string]interface{}{
		"commands": []interface{}{
			map[string]interface{}{
				"cmd":      "USER anonymous",
				"response": "331 ok",
			},
			"garbage-string", // skipped
			float64(42),      // skipped
			map[string]interface{}{
				"cmd":      "QUIT",
				"response": "221 bye",
			},
		},
	})
	if fc == nil {
		t.Fatal("FTP nil, want populated")
	}
	if len(fc.Commands) != 2 {
		t.Fatalf("FTP.Commands len=%d, want 2 (2 valid items, 2 skipped)", len(fc.Commands))
	}
	if fc.Commands[0].Cmd != "USER anonymous" {
		t.Errorf("FTP.Commands[0].Cmd=%q", fc.Commands[0].Cmd)
	}
	if fc.Commands[1].Cmd != "QUIT" {
		t.Errorf("FTP.Commands[1].Cmd=%q", fc.Commands[1].Cmd)
	}
}

// ============================================================================
// SIP branch (strategy_convert.go:287-298)
// ============================================================================
//
// Coverage goals:
//   1. sip sub-map present -> spec.SIP populated
//   2. sip sub-map absent -> spec.SIP nil
//   3. sip sub-map wrong type -> spec.SIP nil
//   4. dst_port absent -> default 5060 (SIP signaling override)
//   5. dst_port explicit user value -> user wins
//   6. dst_port=0 explicit -> 0 honored
//   7. dst_port=nil -> 5060
//   8. parseSIPDialog: empty/absent -> nil
//   9. parseSIPDialog: valid array with all field types (request, response,
//      headers, body, direction)
//  10. parseSIPDialog: non-array -> nil
//  11. parseSIPDialog: non-map items skipped
//  12. parseSIPDialog: headers list with non-string items skipped

// TestMapToFlowSpec_SIP_FullDialog verifies that a fully-populated SIP dialog
// produces spec.SIP with Method/URI/StatusCode/StatusText/Headers/Body/
// Direction all propagated verbatim from the config map.
func TestMapToFlowSpec_SIP_FullDialog(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"tcp": map[string]interface{}{
			"mss": float64(1400),
		},
		"sip": map[string]interface{}{
			"dialog": []interface{}{
				map[string]interface{}{
					"method":    "INVITE",
					"uri":       "sip:bob@example.com",
					"direction": "up",
					"headers":   []interface{}{"From: alice", "To: bob"},
					"body":      "v=0\r\no=alice 123 1 IN IP4 10.0.0.1",
				},
				map[string]interface{}{
					"status_code": float64(200),
					"status_text": "OK",
					"direction":   "down",
				},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP == nil {
		t.Fatal("SIP nil, want populated")
	}
	if spec.TCP == nil {
		t.Fatal("TCP nil, want populated (MSS lives under TCPConfig now)")
	}
	if spec.TCP.MSS != 1400 {
		t.Errorf("TCP.MSS=%d, want 1400 (MSS unified under TCPConfig)", spec.TCP.MSS)
	}
	if len(spec.SIP.Dialog) != 2 {
		t.Fatalf("SIP.Dialog len=%d, want 2", len(spec.SIP.Dialog))
	}
	req := spec.SIP.Dialog[0]
	if req.Method != "INVITE" || req.URI != "sip:bob@example.com" {
		t.Errorf("SIP.Dialog[0] Method=%q URI=%q", req.Method, req.URI)
	}
	if req.Direction != "up" {
		t.Errorf("SIP.Dialog[0].Direction=%q, want \"up\"", req.Direction)
	}
	if req.Body != "v=0\r\no=alice 123 1 IN IP4 10.0.0.1" {
		t.Errorf("SIP.Dialog[0].Body=%q", req.Body)
	}
	if len(req.Headers) != 2 || req.Headers[0] != "From: alice" || req.Headers[1] != "To: bob" {
		t.Errorf("SIP.Dialog[0].Headers=%v, want [From: alice, To: bob]", req.Headers)
	}
	resp := spec.SIP.Dialog[1]
	if resp.StatusCode != 200 || resp.StatusText != "OK" {
		t.Errorf("SIP.Dialog[1] Code=%d Text=%q", resp.StatusCode, resp.StatusText)
	}
	if resp.Direction != "down" {
		t.Errorf("SIP.Dialog[1].Direction=%q, want \"down\"", resp.Direction)
	}
}

// TestMapToFlowSpec_SIP_SubMapAbsent verifies that absent sip sub-map leaves
// spec.SIP nil. The planner then emits only TCP handshake + teardown.
func TestMapToFlowSpec_SIP_SubMapAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP != nil {
		t.Errorf("SIP=%+v, want nil (sub-map absent)", spec.SIP)
	}
}

// TestMapToFlowSpec_SIP_SubMapWrongType verifies that a non-map sip value
// leaves spec.SIP nil.
func TestMapToFlowSpec_SIP_SubMapWrongType(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sip":    []string{"INVITE", "200 OK"},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP != nil {
		t.Errorf("SIP=%+v, want nil (sub-map wrong type)", spec.SIP)
	}
}

// TestMapToFlowSpec_SIP_DefaultPort5060 verifies that absent dst_port falls
// back to 5060 (SIP signaling default). SIP is the third protocol (after
// DNS, FTP) to override the generic port-80 default.
func TestMapToFlowSpec_SIP_DefaultPort5060(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sip":    map[string]interface{}{"dialog": []interface{}{}},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.DstPort != 5060 {
		t.Errorf("SIP DstPort=%d, want 5060 (SIP signaling override)", spec.DstPort)
	}
}

// TestMapToFlowSpec_SIP_DefaultPort5060_NoSubMap verifies the port-5060
// override fires even when the sip sub-map is absent.
func TestMapToFlowSpec_SIP_DefaultPort5060_NoSubMap(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.DstPort != 5060 {
		t.Errorf("SIP DstPort=%d, want 5060 (override fires without sub-map)", spec.DstPort)
	}
}

// TestMapToFlowSpec_SIP_UserPortHonored verifies that explicit user dst_port
// wins over the 5060 default.
func TestMapToFlowSpec_SIP_UserPortHonored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(5061), // TLS-protected SIP
		"sip":      map[string]interface{}{"dialog": []interface{}{}},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.DstPort != 5061 {
		t.Errorf("SIP DstPort=%d, want 5061 (user override)", spec.DstPort)
	}
}

// TestMapToFlowSpec_SIP_DstPortExplicitZeroHonored verifies that explicit
// dst_port=0 for SIP is NOT overridden to 5060.
func TestMapToFlowSpec_SIP_DstPortExplicitZeroHonored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(0),
		"sip":      map[string]interface{}{"dialog": []interface{}{}},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.DstPort != 0 {
		t.Errorf("SIP DstPort=%d, want 0 (explicit zero must NOT be overridden to 5060)", spec.DstPort)
	}
}

// TestMapToFlowSpec_SIP_DstPortNilFallsBackTo5060 verifies that explicit
// JSON null dst_port is treated as "not set" and falls back to 5060.
func TestMapToFlowSpec_SIP_DstPortNilFallsBackTo5060(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": nil,
		"sip":      map[string]interface{}{"dialog": []interface{}{}},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.DstPort != 5060 {
		t.Errorf("SIP DstPort=%d, want 5060 (nil dst_port -> fallback)", spec.DstPort)
	}
}

// TestMapToFlowSpec_SIP_DialogEmpty verifies that an empty dialog array
// leaves spec.SIP.Dialog nil (parseSIPDialog returns nil for len==0).
func TestMapToFlowSpec_SIP_DialogEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sip": map[string]interface{}{
			"dialog": []interface{}{},
		},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP == nil {
		t.Fatal("SIP nil, want populated")
	}
	if spec.SIP.Dialog != nil {
		t.Errorf("SIP.Dialog=%v, want nil (empty array -> nil)", spec.SIP.Dialog)
	}
}

// TestMapToFlowSpec_SIP_DialogNonArray verifies that a non-array dialog
// value leaves spec.SIP.Dialog nil.
func TestMapToFlowSpec_SIP_DialogNonArray(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sip": map[string]interface{}{
			"dialog": "INVITE",
		},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP == nil {
		t.Fatal("SIP nil, want populated")
	}
	if spec.SIP.Dialog != nil {
		t.Errorf("SIP.Dialog=%v, want nil (non-array input)", spec.SIP.Dialog)
	}
}

// TestMapToFlowSpec_SIP_DialogSkipNonMapItems verifies that non-map items
// in the dialog array are silently skipped while valid items are kept.
func TestMapToFlowSpec_SIP_DialogSkipNonMapItems(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sip": map[string]interface{}{
			"dialog": []interface{}{
				map[string]interface{}{"method": "INVITE", "uri": "sip:bob@x"},
				"garbage", // skipped
				map[string]interface{}{"status_code": float64(200), "status_text": "OK"},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP == nil {
		t.Fatal("SIP nil, want populated")
	}
	if len(spec.SIP.Dialog) != 2 {
		t.Fatalf("SIP.Dialog len=%d, want 2 (1 skipped)", len(spec.SIP.Dialog))
	}
	if spec.SIP.Dialog[0].Method != "INVITE" {
		t.Errorf("SIP.Dialog[0].Method=%q", spec.SIP.Dialog[0].Method)
	}
	if spec.SIP.Dialog[1].StatusCode != 200 {
		t.Errorf("SIP.Dialog[1].StatusCode=%d", spec.SIP.Dialog[1].StatusCode)
	}
}

// TestMapToFlowSpec_SIP_DialogHeadersNonStringSkipped verifies that non-string
// items in the headers list of a dialog entry are silently skipped while
// valid string items are kept. parseSIPDialog's inner `h.(string)` assertion
// fails for numbers/arrays, but the loop continues.
func TestMapToFlowSpec_SIP_DialogHeadersNonStringSkipped(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sip": map[string]interface{}{
			"dialog": []interface{}{
				map[string]interface{}{
					"method":  "INVITE",
					"uri":     "sip:bob@x",
					"headers": []interface{}{"From: alice", float64(42), "To: bob"},
				},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP == nil {
		t.Fatal("SIP nil, want populated")
	}
	if len(spec.SIP.Dialog) != 1 {
		t.Fatalf("SIP.Dialog len=%d, want 1", len(spec.SIP.Dialog))
	}
	if len(spec.SIP.Dialog[0].Headers) != 2 {
		t.Errorf("SIP.Dialog[0].Headers=%v, want 2 strings (1 non-string skipped)", spec.SIP.Dialog[0].Headers)
	}
}

// TestMapToFlowSpec_SIP_MediaDirectionFromJSON locks in that the SIP media
// sub-map's "direction" field is propagated to SIPMedia.Direction. This is
// the JSON-config path; the F1 SDP-direction tests set media.Direction
// directly on the Go struct, so they do NOT exercise this code path.
//
// Pre-fix: parseSIPMedia omitted the Direction field, so a user who
// supplied {"media":{"direction":"down"}} in their strategy config had
// the value silently dropped, and the planner fell through to the
// SDP-derived default (which itself may not match the user's intent).
// The fix: parseSIPMedia must read the "direction" JSON key.
func TestMapToFlowSpec_SIP_MediaDirectionFromJSON(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sip": map[string]interface{}{
			"media": map[string]interface{}{
				"direction": "down",
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP == nil || spec.SIP.Media == nil {
		t.Fatal("SIP.Media nil, want populated")
	}
	if spec.SIP.Media.Direction != "down" {
		t.Errorf("SIP.Media.Direction=%q, want %q (JSON direction field lost in parseSIPMedia)",
			spec.SIP.Media.Direction, "down")
	}
}

// TestMapToFlowSpec_SIP_MediaDirectionEmptyStaysEmpty verifies that an absent
// "direction" key in the media sub-map leaves SIPMedia.Direction as the
// empty string (so the planner derives the direction from the SDP body or
// falls back to "up"). It must NOT default to a non-empty value here — the
// defaulting happens in the planner, not in parsing.
func TestMapToFlowSpec_SIP_MediaDirectionEmptyStaysEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sip": map[string]interface{}{
			"media": map[string]interface{}{
				"frames": float64(5),
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP == nil || spec.SIP.Media == nil {
		t.Fatal("SIP.Media nil, want populated")
	}
	if spec.SIP.Media.Direction != "" {
		t.Errorf("SIP.Media.Direction=%q, want \"\" (absent key must stay empty)", spec.SIP.Media.Direction)
	}
}

// TestMapToFlowSpec_SIP_MediaDirectionUpHonored verifies the "up" direction
// is propagated verbatim (the most common value).
func TestMapToFlowSpec_SIP_MediaDirectionUpHonored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sip": map[string]interface{}{
			"media": map[string]interface{}{
				"direction": "up",
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sip")
	if spec.SIP == nil || spec.SIP.Media == nil {
		t.Fatal("SIP.Media nil, want populated")
	}
	if spec.SIP.Media.Direction != "up" {
		t.Errorf("SIP.Media.Direction=%q, want %q", spec.SIP.Media.Direction, "up")
	}
}

// ============================================================================
// SCTP branch (strategy_convert.go:299-311)
// ============================================================================
//
// Coverage goals:
//   1. sctp sub-map present -> spec.SCTP populated (VerificationTag,
//      InitiateTag, Chunks)
//   2. sctp sub-map absent -> spec.SCTP nil
//   3. sctp sub-map wrong type -> spec.SCTP nil
//   4. dst_port NOT auto-overridden (SCTP has no universal default port;
//      unlike HTTP/FTP/SIP, the generic 80 stays — user must set dst_port)
//   5. parseSCTPChunks: empty/absent -> nil
//   6. parseSCTPChunks: valid array with all fields
//   7. parseSCTPChunks: Data as string
//   8. parseSCTPChunks: Data as number array
//   9. parseSCTPChunks: Data absent -> nil
//  10. parseSCTPChunks: non-array -> nil
//  11. parseSCTPChunks: non-map items skipped

// TestMapToFlowSpec_SCTP_FullConfig verifies that a fully-populated SCTP
// sub-map produces spec.SCTP with VerificationTag, InitiateTag, and Chunks
// propagated verbatim.
func TestMapToFlowSpec_SCTP_FullConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp": map[string]interface{}{
			"verification_tag": float64(0xDEADBEEF),
			"initiate_tag":     float64(0xCAFEBABE),
			"chunks": []interface{}{
				map[string]interface{}{
					"tsn":       float64(1),
					"sid":       float64(0),
					"ssn":       float64(0),
					"ppid":      float64(60),
					"data":      "NGAP payload",
					"direction": "up",
				},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatal("SCTP nil, want populated")
	}
	if spec.SCTP.VerificationTag != 0xDEADBEEF {
		t.Errorf("SCTP.VerificationTag=0x%x, want 0xDEADBEEF", spec.SCTP.VerificationTag)
	}
	if spec.SCTP.InitiateTag != 0xCAFEBABE {
		t.Errorf("SCTP.InitiateTag=0x%x, want 0xCAFEBABE", spec.SCTP.InitiateTag)
	}
	if len(spec.SCTP.Chunks) != 1 {
		t.Fatalf("SCTP.Chunks len=%d, want 1", len(spec.SCTP.Chunks))
	}
	c := spec.SCTP.Chunks[0]
	if c.TSN != 1 || c.SID != 0 || c.SSN != 0 || c.PPID != 60 {
		t.Errorf("SCTP.Chunk[0] TSN=%d SID=%d SSN=%d PPID=%d", c.TSN, c.SID, c.SSN, c.PPID)
	}
	if string(c.Data) != "NGAP payload" {
		t.Errorf("SCTP.Chunk[0].Data=%q, want \"NGAP payload\"", string(c.Data))
	}
	if c.Direction != "up" {
		t.Errorf("SCTP.Chunk[0].Direction=%q, want \"up\"", c.Direction)
	}
}

// TestMapToFlowSpec_SCTP_SubMapAbsent verifies that absent sctp sub-map
// leaves spec.SCTP nil.
func TestMapToFlowSpec_SCTP_SubMapAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP != nil {
		t.Errorf("SCTP=%+v, want nil (sub-map absent)", spec.SCTP)
	}
}

// TestMapToFlowSpec_SCTP_SubMapWrongType verifies that a non-map sctp value
// leaves spec.SCTP nil.
func TestMapToFlowSpec_SCTP_SubMapWrongType(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp":   "not-a-map",
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP != nil {
		t.Errorf("SCTP=%+v, want nil (sub-map wrong type)", spec.SCTP)
	}
}

// TestMapToFlowSpec_SCTP_NoPortOverride is the LOAD-BEARING test that SCTP
// does NOT auto-override the dst_port default. Unlike HTTP/FTP/SIP/DNS,
// SCTP has no universal default port (common: 38412 NGAP, 2905 M3UA, 9
// discard). The code explicitly does NOT override port 80 -> 38412; user
// must set dst_port. This test pins that design decision so a future
// refactor can't silently change it.
//
// strategy_convert.go:307-311 spells out the rationale.
func TestMapToFlowSpec_SCTP_NoPortOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp":   map[string]interface{}{},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.DstPort != DefaultDstPort {
		t.Errorf("SCTP DstPort=%d, want %d (generic default; SCTP does NOT override)", spec.DstPort, DefaultDstPort)
	}
}

// TestMapToFlowSpec_SCTP_UserPortHonored verifies that explicit user
// dst_port is preserved (no override to fight against).
func TestMapToFlowSpec_SCTP_UserPortHonored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(38412),
		"sctp":     map[string]interface{}{},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.DstPort != 38412 {
		t.Errorf("SCTP DstPort=%d, want 38412 (user override)", spec.DstPort)
	}
}

// TestMapToFlowSpec_SCTP_ChunksEmpty verifies that an empty chunks array
// leaves spec.SCTP.Chunks nil (parseSCTPChunks returns nil for len==0).
func TestMapToFlowSpec_SCTP_ChunksEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp": map[string]interface{}{
			"chunks": []interface{}{},
		},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatal("SCTP nil, want populated")
	}
	if spec.SCTP.Chunks != nil {
		t.Errorf("SCTP.Chunks=%v, want nil (empty array -> nil)", spec.SCTP.Chunks)
	}
}

// TestMapToFlowSpec_SCTP_ChunksAbsent verifies that absent chunks key leaves
// spec.SCTP.Chunks nil.
func TestMapToFlowSpec_SCTP_ChunksAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp":   map[string]interface{}{"verification_tag": float64(1)},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatal("SCTP nil, want populated")
	}
	if spec.SCTP.Chunks != nil {
		t.Errorf("SCTP.Chunks=%v, want nil (absent key)", spec.SCTP.Chunks)
	}
}

// TestMapToFlowSpec_SCTP_ChunksNonArray verifies that a non-array chunks
// value leaves spec.SCTP.Chunks nil.
func TestMapToFlowSpec_SCTP_ChunksNonArray(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp": map[string]interface{}{
			"chunks": "DATA",
		},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatal("SCTP nil, want populated")
	}
	if spec.SCTP.Chunks != nil {
		t.Errorf("SCTP.Chunks=%v, want nil (non-array input)", spec.SCTP.Chunks)
	}
}

// TestMapToFlowSpec_SCTP_ChunkDataAsNumberArray verifies that a chunk's Data
// field accepts a JSON number array (e.g. [0x4e, 0x47, 0x41, 0x50]) and is
// converted to a byte slice. This is the second of two supported Data input
// forms; the first (string) is covered by TestMapToFlowSpec_SCTP_FullConfig.
func TestMapToFlowSpec_SCTP_ChunkDataAsNumberArray(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp": map[string]interface{}{
			"chunks": []interface{}{
				map[string]interface{}{
					"tsn":  float64(1),
					"data": []interface{}{float64(0x4e), float64(0x47), float64(0x41), float64(0x50)}, // "NGAP"
				},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatal("SCTP nil, want populated")
	}
	if len(spec.SCTP.Chunks) != 1 {
		t.Fatalf("SCTP.Chunks len=%d, want 1", len(spec.SCTP.Chunks))
	}
	if string(spec.SCTP.Chunks[0].Data) != "NGAP" {
		t.Errorf("SCTP.Chunk[0].Data=%v, want \"NGAP\"", spec.SCTP.Chunks[0].Data)
	}
}

// TestMapToFlowSpec_SCTP_ChunkDataAbsent verifies that a chunk with no data
// field produces a nil Data slice (not an empty []byte). The switch in
// parseSCTPChunks leaves data nil when neither string nor []interface{}
// matches.
func TestMapToFlowSpec_SCTP_ChunkDataAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp": map[string]interface{}{
			"chunks": []interface{}{
				map[string]interface{}{
					"tsn": float64(1),
				},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatal("SCTP nil, want populated")
	}
	if len(spec.SCTP.Chunks) != 1 {
		t.Fatalf("SCTP.Chunks len=%d, want 1", len(spec.SCTP.Chunks))
	}
	if spec.SCTP.Chunks[0].Data != nil {
		t.Errorf("SCTP.Chunk[0].Data=%v, want nil (absent key)", spec.SCTP.Chunks[0].Data)
	}
}

// TestMapToFlowSpec_SCTP_ChunksSkipNonMapItems verifies that non-map items
// in the chunks array are silently skipped while valid items are kept.
func TestMapToFlowSpec_SCTP_ChunksSkipNonMapItems(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp": map[string]interface{}{
			"chunks": []interface{}{
				map[string]interface{}{"tsn": float64(1), "data": "first"},
				"garbage",  // skipped
				float64(7), // skipped
				map[string]interface{}{"tsn": float64(2), "data": "second"},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatal("SCTP nil, want populated")
	}
	if len(spec.SCTP.Chunks) != 2 {
		t.Fatalf("SCTP.Chunks len=%d, want 2 (2 non-map items skipped)", len(spec.SCTP.Chunks))
	}
	if string(spec.SCTP.Chunks[0].Data) != "first" {
		t.Errorf("SCTP.Chunk[0].Data=%q", string(spec.SCTP.Chunks[0].Data))
	}
	if string(spec.SCTP.Chunks[1].Data) != "second" {
		t.Errorf("SCTP.Chunk[1].Data=%q", string(spec.SCTP.Chunks[1].Data))
	}
}

// TestMapToFlowSpec_SCTP_AbortTrue verifies that sctp.abort=true in the raw
// config is propagated to SCTPConfig.Abort. Without this wiring, MCP/API
// submissions carrying abort=true silently drop the flag at the convert
// layer, and the planner always emits SHUTDOWN even when the user asked
// for an ABORT (C3.4 end-to-end regression).
func TestMapToFlowSpec_SCTP_AbortTrue(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp": map[string]interface{}{
			"abort": true,
		},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatal("SCTP nil, want populated")
	}
	if !spec.SCTP.Abort {
		t.Errorf("SCTP.Abort=false, want true (convert layer dropped sctp.abort)")
	}
}

// TestMapToFlowSpec_SCTP_AbortDefaultFalse verifies that sctp.abort absent
// leaves SCTPConfig.Abort at its zero value (false). This guards the
// default path so normal SCTP flows still emit SHUTDOWN.
func TestMapToFlowSpec_SCTP_AbortDefaultFalse(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"sctp":   map[string]interface{}{},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatal("SCTP nil, want populated")
	}
	if spec.SCTP.Abort {
		t.Errorf("SCTP.Abort=true, want false (abort key absent)")
	}
}

// ============================================================================
// ICMPv6 branch (strategy_convert.go:312-329)
// ============================================================================
//
// Coverage goals:
//   1. icmpv6 sub-map present -> spec.ICMPv6 populated (Type/Code/Identifier/
//      Sequence/Data/Pattern)
//   2. icmpv6 sub-map absent -> spec.ICMPv6 nil
//   3. icmpv6 sub-map wrong type -> spec.ICMPv6 nil
//   4. Type defaults to 128 (Echo Request) when absent
//   5. Code defaults to 0 when absent
//   6. Sequence defaults to 1 when absent
//   7. Data defaults to "ping" when absent
//   8. src_port/dst_port FORCED to 0 (ICMPv6 is L3 like ICMP, no L4 header)
//   9. parseICMPv6Pattern: empty/absent -> nil
//  10. parseICMPv6Pattern: valid array -> []ICMPv6Step with step-index+1
//      default Sequence
//  11. parseICMPv6Pattern: non-array -> nil

// TestMapToFlowSpec_ICMPv6_FullConfig verifies that a fully-populated ICMPv6
// sub-map produces spec.ICMPv6 with all fields propagated. Identifier has no
// default (0 means "fall back to Sequence" per the planner contract).
func TestMapToFlowSpec_ICMPv6_FullConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "::1",
		"dst_ip": "::2",
		"icmpv6": map[string]interface{}{
			"type":       float64(128),
			"code":       float64(0),
			"identifier": float64(0xBEEF),
			"sequence":   float64(7),
			"data":       "hello-ipv6",
		},
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatal("ICMPv6 nil, want populated")
	}
	if spec.ICMPv6.Type != 128 {
		t.Errorf("ICMPv6.Type=%d, want 128", spec.ICMPv6.Type)
	}
	if spec.ICMPv6.Code != 0 {
		t.Errorf("ICMPv6.Code=%d, want 0", spec.ICMPv6.Code)
	}
	if spec.ICMPv6.Identifier != 0xBEEF {
		t.Errorf("ICMPv6.Identifier=0x%x, want 0xBEEF", spec.ICMPv6.Identifier)
	}
	if spec.ICMPv6.Sequence != 7 {
		t.Errorf("ICMPv6.Sequence=%d, want 7", spec.ICMPv6.Sequence)
	}
	if string(spec.ICMPv6.Data) != "hello-ipv6" {
		t.Errorf("ICMPv6.Data=%q, want \"hello-ipv6\"", string(spec.ICMPv6.Data))
	}
}

// TestMapToFlowSpec_ICMPv6_Defaults verifies that when type/code/sequence/
// data are absent, the defaults (Type=128, Code=0, Sequence=1, Data="ping")
// are applied. Identifier has no default — 0 means "fall back to Sequence"
// in the planner, so we don't assert it here.
func TestMapToFlowSpec_ICMPv6_Defaults(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "::1",
		"dst_ip": "::2",
		"icmpv6": map[string]interface{}{},
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatal("ICMPv6 nil, want populated")
	}
	if spec.ICMPv6.Type != 128 {
		t.Errorf("ICMPv6.Type=%d, want 128 (default Echo Request)", spec.ICMPv6.Type)
	}
	if spec.ICMPv6.Code != 0 {
		t.Errorf("ICMPv6.Code=%d, want 0 (default)", spec.ICMPv6.Code)
	}
	if spec.ICMPv6.Sequence != 1 {
		t.Errorf("ICMPv6.Sequence=%d, want 1 (default)", spec.ICMPv6.Sequence)
	}
	if string(spec.ICMPv6.Data) != "ping" {
		t.Errorf("ICMPv6.Data=%q, want \"ping\" (default)", string(spec.ICMPv6.Data))
	}
}

// TestMapToFlowSpec_ICMPv6_SubMapAbsent verifies that absent icmpv6 sub-map
// leaves spec.ICMPv6 nil.
func TestMapToFlowSpec_ICMPv6_SubMapAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "::1",
		"dst_ip": "::2",
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.ICMPv6 != nil {
		t.Errorf("ICMPv6=%+v, want nil (sub-map absent)", spec.ICMPv6)
	}
}

// TestMapToFlowSpec_ICMPv6_SubMapWrongType verifies that a non-map icmpv6
// value leaves spec.ICMPv6 nil.
func TestMapToFlowSpec_ICMPv6_SubMapWrongType(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "::1",
		"dst_ip": "::2",
		"icmpv6": "not-a-map",
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.ICMPv6 != nil {
		t.Errorf("ICMPv6=%+v, want nil (sub-map wrong type)", spec.ICMPv6)
	}
}

// TestMapToFlowSpec_ICMPv6_PortsClearedToZero is the LOAD-BEARING test that
// ICMPv6 forces src_port and dst_port to 0. ICMPv6 is a Layer 3 protocol
// like ICMP — it has no L4 header, so any user-provided port values would
// be stale leftovers that confuse packet inspection. The force-clear at
// strategy_convert.go:327-328 zeroes them regardless of user input.
//
// We feed EXPLICIT port values to make the test strict: without the clear,
// these would survive into spec.SrcPort/DstPort and the test would catch it.
func TestMapToFlowSpec_ICMPv6_PortsClearedToZero(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "::1",
		"dst_ip":   "::2",
		"src_port": float64(12345),
		"dst_port": float64(80),
		"icmpv6":   map[string]interface{}{},
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.SrcPort != 0 {
		t.Errorf("ICMPv6 SrcPort=%d, want 0 (L3 protocol, no L4 header)", spec.SrcPort)
	}
	if spec.DstPort != 0 {
		t.Errorf("ICMPv6 DstPort=%d, want 0 (L3 protocol, no L4 header)", spec.DstPort)
	}
}

// TestMapToFlowSpec_ICMPv6_PortsClearedToZero_NoSubMap verifies the port
// clear fires even when the icmpv6 sub-map is absent. The clear is OUTSIDE
// the sub-map presence check (strategy_convert.go:327-328) so it applies
// whenever protocol="icmpv6" regardless of sub-map state.
func TestMapToFlowSpec_ICMPv6_PortsClearedToZero_NoSubMap(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "::1",
		"dst_ip":   "::2",
		"src_port": float64(12345),
		"dst_port": float64(80),
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.SrcPort != 0 {
		t.Errorf("ICMPv6 SrcPort=%d, want 0 (cleared even without sub-map)", spec.SrcPort)
	}
	if spec.DstPort != 0 {
		t.Errorf("ICMPv6 DstPort=%d, want 0 (cleared even without sub-map)", spec.DstPort)
	}
}

// TestMapToFlowSpec_ICMPv6_PatternValid verifies that a valid pattern array
// produces []ICMPv6Step with step-index+1 as default Sequence when sequence
// is 0. parseICMPv6Pattern mirrors parseICMPPattern's RFC 4443 ping session
// semantics: Identifier groups, Sequence increments per ping.
func TestMapToFlowSpec_ICMPv6_PatternValid(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "::1",
		"dst_ip": "::2",
		"icmpv6": map[string]interface{}{
			"identifier": float64(0xBEEF),
			"pattern": []interface{}{
				map[string]interface{}{"data": "first"},                          // sequence=0 -> 1
				map[string]interface{}{"data": "second"},                         // sequence=0 -> 2
				map[string]interface{}{"sequence": float64(99), "data": "third"}, // explicit
			},
		},
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatal("ICMPv6 nil, want populated")
	}
	if len(spec.ICMPv6.Pattern) != 3 {
		t.Fatalf("ICMPv6.Pattern len=%d, want 3", len(spec.ICMPv6.Pattern))
	}
	if spec.ICMPv6.Pattern[0].Sequence != 1 {
		t.Errorf("Pattern[0].Sequence=%d, want 1 (step+1 default)", spec.ICMPv6.Pattern[0].Sequence)
	}
	if spec.ICMPv6.Pattern[1].Sequence != 2 {
		t.Errorf("Pattern[1].Sequence=%d, want 2 (step+1 default)", spec.ICMPv6.Pattern[1].Sequence)
	}
	if spec.ICMPv6.Pattern[2].Sequence != 99 {
		t.Errorf("Pattern[2].Sequence=%d, want 99 (explicit)", spec.ICMPv6.Pattern[2].Sequence)
	}
	if spec.ICMPv6.Pattern[0].Type != 128 {
		t.Errorf("Pattern[0].Type=%d, want 128 (default Echo Request)", spec.ICMPv6.Pattern[0].Type)
	}
	if spec.ICMPv6.Pattern[0].Code != 0 {
		t.Errorf("Pattern[0].Code=%d, want 0 (default)", spec.ICMPv6.Pattern[0].Code)
	}
	if string(spec.ICMPv6.Pattern[0].Data) != "first" {
		t.Errorf("Pattern[0].Data=%q, want \"first\"", string(spec.ICMPv6.Pattern[0].Data))
	}
}

// TestMapToFlowSpec_ICMPv6_PatternEmpty verifies that an empty pattern
// array leaves spec.ICMPv6.Pattern nil (parseICMPv6Pattern returns nil for
// len==0). The planner then falls back to the single-ping path.
func TestMapToFlowSpec_ICMPv6_PatternEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "::1",
		"dst_ip": "::2",
		"icmpv6": map[string]interface{}{
			"pattern": []interface{}{},
		},
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatal("ICMPv6 nil, want populated")
	}
	if spec.ICMPv6.Pattern != nil {
		t.Errorf("ICMPv6.Pattern=%v, want nil (empty array -> nil)", spec.ICMPv6.Pattern)
	}
}

// TestMapToFlowSpec_ICMPv6_PatternAbsent verifies that absent pattern key
// leaves spec.ICMPv6.Pattern nil.
func TestMapToFlowSpec_ICMPv6_PatternAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "::1",
		"dst_ip": "::2",
		"icmpv6": map[string]interface{}{"type": float64(128)},
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatal("ICMPv6 nil, want populated")
	}
	if spec.ICMPv6.Pattern != nil {
		t.Errorf("ICMPv6.Pattern=%v, want nil (absent key)", spec.ICMPv6.Pattern)
	}
}

// TestMapToFlowSpec_ICMPv6_PatternNonArray verifies that a non-array
// pattern value leaves spec.ICMPv6.Pattern nil.
func TestMapToFlowSpec_ICMPv6_PatternNonArray(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "::1",
		"dst_ip": "::2",
		"icmpv6": map[string]interface{}{
			"pattern": "ping",
		},
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatal("ICMPv6 nil, want populated")
	}
	if spec.ICMPv6.Pattern != nil {
		t.Errorf("ICMPv6.Pattern=%v, want nil (non-array input)", spec.ICMPv6.Pattern)
	}
}

// TestMapToFlowSpec_ICMPv6_PatternSkipNonMapItems verifies that non-map
// items in the pattern array are silently skipped while valid items are
// kept. parseICMPv6Pattern's inner `item.(map[string]interface{})` fails
// for strings/numbers, but the loop continues.
func TestMapToFlowSpec_ICMPv6_PatternSkipNonMapItems(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "::1",
		"dst_ip": "::2",
		"icmpv6": map[string]interface{}{
			"pattern": []interface{}{
				map[string]interface{}{"data": "first"},
				"garbage",  // skipped
				float64(7), // skipped
				map[string]interface{}{"data": "fourth"},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatal("ICMPv6 nil, want populated")
	}
	if len(spec.ICMPv6.Pattern) != 2 {
		t.Fatalf("ICMPv6.Pattern len=%d, want 2 (2 non-map items skipped)", len(spec.ICMPv6.Pattern))
	}
	if string(spec.ICMPv6.Pattern[0].Data) != "first" {
		t.Errorf("Pattern[0].Data=%q", string(spec.ICMPv6.Pattern[0].Data))
	}
	if string(spec.ICMPv6.Pattern[1].Data) != "fourth" {
		t.Errorf("Pattern[1].Data=%q", string(spec.ICMPv6.Pattern[1].Data))
	}
}

// ============================================================================
// ICMP branch (strategy_convert.go:254-264) + parseICMPPattern (376-411)
// ============================================================================
//
// Coverage goals:
//   1. icmp sub-map present -> spec.ICMP populated (Type/Code/Identifier/
//      Sequence/Data/Pattern)
//   2. icmp sub-map absent -> spec.ICMP nil
//   3. icmp sub-map wrong type -> spec.ICMP nil
//   4. Type defaults to 8 (Echo Request) when absent
//   5. Code defaults to 0 when absent
//   6. Sequence defaults to 1 when absent
//   7. Data defaults to "ping" when absent
//   8. parseICMPPattern: empty array -> nil
//   9. parseICMPPattern: non-array -> nil
//  10. parseICMPPattern: valid array with step+1 default Sequence
//  11. parseICMPPattern: non-map items skipped
//  12. parseICMPPattern: empty result after skipping all -> nil

// TestMapToFlowSpec_ICMP_FullConfig verifies that a fully-populated ICMP
// sub-map produces spec.ICMP with all fields propagated.
func TestMapToFlowSpec_ICMP_FullConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"icmp": map[string]interface{}{
			"type":       float64(8),
			"code":       float64(0),
			"identifier": float64(0xCAFE),
			"sequence":   float64(5),
			"data":       "hello-ipv4",
		},
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP == nil {
		t.Fatal("ICMP nil, want populated")
	}
	if spec.ICMP.Type != 8 {
		t.Errorf("ICMP.Type=%d, want 8", spec.ICMP.Type)
	}
	if spec.ICMP.Code != 0 {
		t.Errorf("ICMP.Code=%d, want 0", spec.ICMP.Code)
	}
	if spec.ICMP.Identifier != 0xCAFE {
		t.Errorf("ICMP.Identifier=0x%x, want 0xCAFE", spec.ICMP.Identifier)
	}
	if spec.ICMP.Sequence != 5 {
		t.Errorf("ICMP.Sequence=%d, want 5", spec.ICMP.Sequence)
	}
	if string(spec.ICMP.Data) != "hello-ipv4" {
		t.Errorf("ICMP.Data=%q, want \"hello-ipv4\"", string(spec.ICMP.Data))
	}
}

// TestMapToFlowSpec_ICMP_Defaults verifies the ICMP defaults: Type=8
// (Echo Request), Code=0, Sequence=1, Data="ping". Identifier has no
// default — 0 means "fall back to Sequence" in the planner.
func TestMapToFlowSpec_ICMP_Defaults(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"icmp":   map[string]interface{}{},
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP == nil {
		t.Fatal("ICMP nil, want populated")
	}
	if spec.ICMP.Type != 8 {
		t.Errorf("ICMP.Type=%d, want 8 (default Echo Request)", spec.ICMP.Type)
	}
	if spec.ICMP.Code != 0 {
		t.Errorf("ICMP.Code=%d, want 0 (default)", spec.ICMP.Code)
	}
	if spec.ICMP.Sequence != 1 {
		t.Errorf("ICMP.Sequence=%d, want 1 (default)", spec.ICMP.Sequence)
	}
	if string(spec.ICMP.Data) != "ping" {
		t.Errorf("ICMP.Data=%q, want \"ping\" (default)", string(spec.ICMP.Data))
	}
}

// TestMapToFlowSpec_ICMP_SubMapAbsent verifies that absent icmp sub-map
// leaves spec.ICMP nil.
func TestMapToFlowSpec_ICMP_SubMapAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP != nil {
		t.Errorf("ICMP=%+v, want nil (sub-map absent)", spec.ICMP)
	}
}

// TestMapToFlowSpec_ICMP_SubMapWrongType verifies that a non-map icmp
// value leaves spec.ICMP nil.
func TestMapToFlowSpec_ICMP_SubMapWrongType(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"icmp":   "not-a-map",
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP != nil {
		t.Errorf("ICMP=%+v, want nil (sub-map wrong type)", spec.ICMP)
	}
}

// TestMapToFlowSpec_ICMP_PatternValid verifies that a valid pattern array
// produces []ICMPStep with step-index+1 default Sequence when sequence is 0.
// parseICMPPattern implements RFC 792 ping session semantics: Identifier
// groups, Sequence increments per ping.
func TestMapToFlowSpec_ICMP_PatternValid(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"icmp": map[string]interface{}{
			"identifier": float64(0xCAFE),
			"pattern": []interface{}{
				map[string]interface{}{"data": "first"},                          // sequence=0 -> 1
				map[string]interface{}{"data": "second"},                         // sequence=0 -> 2
				map[string]interface{}{"sequence": float64(99), "data": "third"}, // explicit
			},
		},
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP == nil {
		t.Fatal("ICMP nil, want populated")
	}
	if len(spec.ICMP.Pattern) != 3 {
		t.Fatalf("ICMP.Pattern len=%d, want 3", len(spec.ICMP.Pattern))
	}
	if spec.ICMP.Pattern[0].Sequence != 1 {
		t.Errorf("Pattern[0].Sequence=%d, want 1 (step+1 default)", spec.ICMP.Pattern[0].Sequence)
	}
	if spec.ICMP.Pattern[1].Sequence != 2 {
		t.Errorf("Pattern[1].Sequence=%d, want 2 (step+1 default)", spec.ICMP.Pattern[1].Sequence)
	}
	if spec.ICMP.Pattern[2].Sequence != 99 {
		t.Errorf("Pattern[2].Sequence=%d, want 99 (explicit)", spec.ICMP.Pattern[2].Sequence)
	}
	if spec.ICMP.Pattern[0].Type != 8 {
		t.Errorf("Pattern[0].Type=%d, want 8 (default Echo Request)", spec.ICMP.Pattern[0].Type)
	}
	if spec.ICMP.Pattern[0].Code != 0 {
		t.Errorf("Pattern[0].Code=%d, want 0 (default)", spec.ICMP.Pattern[0].Code)
	}
	if string(spec.ICMP.Pattern[0].Data) != "first" {
		t.Errorf("Pattern[0].Data=%q, want \"first\"", string(spec.ICMP.Pattern[0].Data))
	}
}

// TestMapToFlowSpec_ICMP_PatternEmpty verifies that an empty pattern array
// leaves spec.ICMP.Pattern nil (parseICMPPattern returns nil for len==0).
// The planner then falls back to the single-ping path.
func TestMapToFlowSpec_ICMP_PatternEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"icmp": map[string]interface{}{
			"pattern": []interface{}{},
		},
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP == nil {
		t.Fatal("ICMP nil, want populated")
	}
	if spec.ICMP.Pattern != nil {
		t.Errorf("ICMP.Pattern=%v, want nil (empty array -> nil)", spec.ICMP.Pattern)
	}
}

// TestMapToFlowSpec_ICMP_PatternAbsent verifies that absent pattern key
// leaves spec.ICMP.Pattern nil.
func TestMapToFlowSpec_ICMP_PatternAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"icmp":   map[string]interface{}{"type": float64(8)},
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP == nil {
		t.Fatal("ICMP nil, want populated")
	}
	if spec.ICMP.Pattern != nil {
		t.Errorf("ICMP.Pattern=%v, want nil (absent key)", spec.ICMP.Pattern)
	}
}

// TestMapToFlowSpec_ICMP_PatternNonArray verifies that a non-array pattern
// value leaves spec.ICMP.Pattern nil.
func TestMapToFlowSpec_ICMP_PatternNonArray(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"icmp": map[string]interface{}{
			"pattern": "ping",
		},
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP == nil {
		t.Fatal("ICMP nil, want populated")
	}
	if spec.ICMP.Pattern != nil {
		t.Errorf("ICMP.Pattern=%v, want nil (non-array input)", spec.ICMP.Pattern)
	}
}

// TestMapToFlowSpec_ICMP_PatternSkipNonMapItems verifies that non-map items
// in the pattern array are silently skipped while valid items are kept.
// parseICMPPattern's inner `item.(map[string]interface{})` fails for
// strings/numbers, but the loop continues.
func TestMapToFlowSpec_ICMP_PatternSkipNonMapItems(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"icmp": map[string]interface{}{
			"pattern": []interface{}{
				map[string]interface{}{"data": "first"},
				"garbage",  // skipped
				float64(7), // skipped
				map[string]interface{}{"data": "fourth"},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP == nil {
		t.Fatal("ICMP nil, want populated")
	}
	if len(spec.ICMP.Pattern) != 2 {
		t.Fatalf("ICMP.Pattern len=%d, want 2 (2 non-map items skipped)", len(spec.ICMP.Pattern))
	}
	if string(spec.ICMP.Pattern[0].Data) != "first" {
		t.Errorf("Pattern[0].Data=%q", string(spec.ICMP.Pattern[0].Data))
	}
	if string(spec.ICMP.Pattern[1].Data) != "fourth" {
		t.Errorf("Pattern[1].Data=%q", string(spec.ICMP.Pattern[1].Data))
	}
}

// TestParseICMPPattern_AllItemsNonMapReturnsNil verifies that an array
// containing ONLY non-map items returns nil (not an empty slice).
// parseICMPPattern's `if len(out) == 0 { return nil }` guard at the end
// catches this case — without it, callers would receive []ICMPStep{} and
// have to defensively nil-check, which is error-prone.
func TestParseICMPPattern_AllItemsNonMapReturnsNil(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"icmp": map[string]interface{}{
			"pattern": []interface{}{
				"garbage1",
				float64(7),
				[]string{"nested"},
			},
		},
	}
	spec := mapToFlowSpec(cfg, "icmp")
	if spec.ICMP == nil {
		t.Fatal("ICMP nil, want populated")
	}
	if spec.ICMP.Pattern != nil {
		t.Errorf("ICMP.Pattern=%v, want nil (all items non-map -> nil)", spec.ICMP.Pattern)
	}
}

// TestDefaultIPs_NotSameNetwork verifies the two default IPs are in
// DIFFERENT /24 networks. Same-network defaults (e.g. 192.0.2.1/192.0.2.2
// both in 192.0.2.0/24) cause DPI/firewall tests to mis-classify the
// flow as intra-subnet (switched) rather than inter-subnet (routed),
// defeating the purpose of synthesizing realistic cross-subnet traffic.
// The user explicitly asked for 10.0.0.x (src) and 20.0.0.x (dst) so
// src and dst DPI land in different subnets.
func TestDefaultIPs_NotSameNetwork(t *testing.T) {
	srcIP := net.ParseIP(DefaultSrcIP)
	dstIP := net.ParseIP(DefaultDstIP)
	if srcIP == nil {
		t.Fatalf("DefaultSrcIP %q is not a valid IP", DefaultSrcIP)
	}
	if dstIP == nil {
		t.Fatalf("DefaultDstIP %q is not a valid IP", DefaultDstIP)
	}
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		t.Fatalf("defaults must be IPv4 (got src=%v dst=%v)", srcIP, dstIP)
	}
	// Compare /24 prefix (first 3 octets).
	if src4[0] == dst4[0] && src4[1] == dst4[1] && src4[2] == dst4[2] {
		t.Errorf("DefaultSrcIP %s and DefaultDstIP %s are in the same /24 (%d.%d.%d.0/24) -- "+
			"DPI tests need src and dst in different subnets",
			DefaultSrcIP, DefaultDstIP, src4[0], src4[1], src4[2])
	}
}

// TestMapToFlowSpec_SubFlows_Absent verifies that when sub_flows is absent
// from the config, spec.SubFlows is nil (no sub-flows). This is the default
// for every protocol — sub-flows are opt-in.
func TestMapToFlowSpec_SubFlows_Absent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SubFlows != nil {
		t.Errorf("SubFlows=%v, want nil (absent in cfg)", spec.SubFlows)
	}
}

// TestMapToFlowSpec_SubFlows_EmptyArray verifies that sub_flows: [] yields a
// non-nil but empty slice. Planner iterates len(SubFlows), so empty is safe.
func TestMapToFlowSpec_SubFlows_EmptyArray(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":    "10.0.0.1",
		"dst_ip":    "20.0.0.1",
		"sub_flows": []interface{}{},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SubFlows == nil {
		t.Errorf("SubFlows=nil, want non-nil empty slice (cfg had empty array)")
	}
	if len(spec.SubFlows) != 0 {
		t.Errorf("len(SubFlows)=%d, want 0", len(spec.SubFlows))
	}
}

// TestMapToFlowSpec_SubFlows_TCPFull verifies that a TCP sub-flow with all
// fields populated parses correctly. This is the FTP-data-channel shape.
func TestMapToFlowSpec_SubFlows_TCPFull(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
		"sub_flows": []interface{}{
			map[string]interface{}{
				"protocol":    "tcp",
				"src_port":    float64(50000),
				"dst_port":    float64(44000),
				"direction":   "down",
				"payload":     "hello",
				"handshake":   true,
				"termination": true,
				"mss":         float64(1400),
			},
		},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if len(spec.SubFlows) != 1 {
		t.Fatalf("len(SubFlows)=%d, want 1", len(spec.SubFlows))
	}
	sub := spec.SubFlows[0]
	if sub.Protocol != "tcp" {
		t.Errorf("Protocol=%q, want \"tcp\"", sub.Protocol)
	}
	if sub.SrcPort != 50000 {
		t.Errorf("SrcPort=%d, want 50000", sub.SrcPort)
	}
	if sub.DstPort != 44000 {
		t.Errorf("DstPort=%d, want 44000", sub.DstPort)
	}
	if sub.Direction != "down" {
		t.Errorf("Direction=%q, want \"down\"", sub.Direction)
	}
	if string(sub.Payload) != "hello" {
		t.Errorf("Payload=%q, want \"hello\"", string(sub.Payload))
	}
	if !sub.Handshake {
		t.Errorf("Handshake=false, want true")
	}
	if !sub.Termination {
		t.Errorf("Termination=false, want true")
	}
	if sub.MSS != 1400 {
		t.Errorf("MSS=%d, want 1400", sub.MSS)
	}
}

// TestMapToFlowSpec_SubFlows_PayloadB64OverridesPayload verifies that
// PayloadB64 takes precedence over Payload when both are set. This mirrors
// the HTTP body_b64 / body precedence used elsewhere.
func TestMapToFlowSpec_SubFlows_PayloadB64OverridesPayload(t *testing.T) {
	// "ZmlsZSBib2R5" is base64 for "file body".
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
		"sub_flows": []interface{}{
			map[string]interface{}{
				"protocol":    "tcp",
				"payload":     "WRONG",
				"payload_b64": "ZmlsZSBib2R5",
			},
		},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if len(spec.SubFlows) != 1 {
		t.Fatalf("len(SubFlows)=%d, want 1", len(spec.SubFlows))
	}
	sub := spec.SubFlows[0]
	// Note: PayloadB64 is decoded by EmitSubFlow at emit time, not by
	// mapToFlowSpec. Here we just verify the field is parsed.
	if sub.PayloadB64 != "ZmlsZSBib2R5" {
		t.Errorf("PayloadB64=%q, want \"ZmlsZSBib2R5\"", sub.PayloadB64)
	}
	if string(sub.Payload) != "WRONG" {
		t.Errorf("Payload=%q, want \"WRONG\" (kept as fallback; decoding happens at emit)", string(sub.Payload))
	}
}

// TestMapToFlowSpec_SubFlows_AltIPsMultiHoming verifies that AltSrcIP/AltDstIP
// on a sub-flow parse correctly — this is the SCTP multi-homing shape where
// the sub-flow uses a different 4-tuple than the primary.
func TestMapToFlowSpec_SubFlows_AltIPsMultiHoming(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
		"sub_flows": []interface{}{
			map[string]interface{}{
				"protocol":    "sctp",
				"alt_src_ip":  "10.0.0.2",
				"alt_dst_ip":  "20.0.0.2",
				"alt_src_mac": "02:00:00:00:00:03",
				"alt_dst_mac": "02:00:00:00:00:04",
			},
		},
	}
	spec := mapToFlowSpec(cfg, "sctp")
	if len(spec.SubFlows) != 1 {
		t.Fatalf("len(SubFlows)=%d, want 1", len(spec.SubFlows))
	}
	sub := spec.SubFlows[0]
	if sub.AltSrcIP != "10.0.0.2" {
		t.Errorf("AltSrcIP=%q, want \"10.0.0.2\"", sub.AltSrcIP)
	}
	if sub.AltDstIP != "20.0.0.2" {
		t.Errorf("AltDstIP=%q, want \"20.0.0.2\"", sub.AltDstIP)
	}
	if sub.AltSrcMAC != "02:00:00:00:00:03" {
		t.Errorf("AltSrcMAC=%q, want \"02:00:00:00:00:03\"", sub.AltSrcMAC)
	}
	if sub.AltDstMAC != "02:00:00:00:00:04" {
		t.Errorf("AltDstMAC=%q, want \"02:00:00:00:00:04\"", sub.AltDstMAC)
	}
}

// TestMapToFlowSpec_SubFlows_WrongTypeIgnored verifies that a non-array
// sub_flows value is silently ignored (no panic, spec.SubFlows stays nil).
// This mirrors the FTP/SIP "wrong type -> nil" pattern used by other sub-maps.
func TestMapToFlowSpec_SubFlows_WrongTypeIgnored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":    "10.0.0.1",
		"dst_ip":    "20.0.0.1",
		"sub_flows": "not-an-array",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.SubFlows != nil {
		t.Errorf("SubFlows=%v, want nil (string is not a valid sub_flows value)", spec.SubFlows)
	}
}

// TestMapToFlowSpec_SubFlows_MultipleEntries verifies that multiple sub-flows
// parse into an ordered slice (order matters — planner emits them in order,
// and wire order = emit order).
func TestMapToFlowSpec_SubFlows_MultipleEntries(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
		"sub_flows": []interface{}{
			map[string]interface{}{"protocol": "tcp", "src_port": float64(50001)},
			map[string]interface{}{"protocol": "udp", "src_port": float64(50002)},
			map[string]interface{}{"protocol": "sctp", "src_port": float64(50003)},
		},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if len(spec.SubFlows) != 3 {
		t.Fatalf("len(SubFlows)=%d, want 3", len(spec.SubFlows))
	}
	if spec.SubFlows[0].Protocol != "tcp" || spec.SubFlows[0].SrcPort != 50001 {
		t.Errorf("SubFlows[0]=%+v, want tcp/50001", spec.SubFlows[0])
	}
	if spec.SubFlows[1].Protocol != "udp" || spec.SubFlows[1].SrcPort != 50002 {
		t.Errorf("SubFlows[1]=%+v, want udp/50002", spec.SubFlows[1])
	}
	if spec.SubFlows[2].Protocol != "sctp" || spec.SubFlows[2].SrcPort != 50003 {
		t.Errorf("SubFlows[2]=%+v, want sctp/50003", spec.SubFlows[2])
	}
}

// TestMapToFlowSpec_SubFlows_SkipsNonMapItems verifies that non-map items in
// the sub_flows array are skipped (json.Unmarshal leaves them zero-valued,
// but our encoding round-trip drops them). Specifically: a string item
// produces a zero-value SubFlowSpec (Protocol=""), which the planner must
// skip at emit time. We verify the slice contains the one valid entry only
// when the array is homogeneous.
func TestMapToFlowSpec_SubFlows_SkipsNonMapItems(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
		"sub_flows": []interface{}{
			"not-a-map",
			map[string]interface{}{"protocol": "tcp"},
		},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	// json.Unmarshal of a string into SubFlowSpec yields a zero-valued
	// entry (Protocol=""); the array length matches the input length but
	// the planner must skip entries with Protocol="".
	if len(spec.SubFlows) != 2 {
		t.Fatalf("len(SubFlows)=%d, want 2 (non-map item yields zero-valued entry)", len(spec.SubFlows))
	}
	if spec.SubFlows[0].Protocol != "" {
		t.Errorf("SubFlows[0].Protocol=%q, want \"\" (non-map item -> zero value)", spec.SubFlows[0].Protocol)
	}
	if spec.SubFlows[1].Protocol != "tcp" {
		t.Errorf("SubFlows[1].Protocol=%q, want \"tcp\"", spec.SubFlows[1].Protocol)
	}
}

// TestMapToFlowSpec_IKE_ESPDataPlane verifies the JSON -> FlowSpec parsing
// path for the ESP data-plane sub-config (strategy_convert.go).
func TestMapToFlowSpec_IKE_ESPDataPlane(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"ike": map[string]interface{}{
			"scenario":      "standard_v2",
			"initiator_spi": float64(0x0123456789ABCDEF),
			"esp_data_plane": map[string]interface{}{
				"spi":                float64(0xCAFEBABE),
				"count":              float64(3),
				"mode":               "tunnel",
				"direction":          "up",
				"iv_length":          float64(16),
				"icv_length":         float64(12),
				"inner_src_ip":       "192.168.1.1",
				"inner_dst_ip":       "192.168.2.1",
				"inner_proto":        float64(17),
				"inner_src_port":     float64(12345),
				"inner_dst_port":     float64(8080),
				"inner_payload_size": float64(64),
			},
		},
	}
	spec := mapToFlowSpec(cfg, "ike")
	if spec.IKE == nil {
		t.Fatal("IKE config nil")
	}
	if spec.IKE.ESPDataPlane == nil {
		t.Fatal("ESPDataPlane nil")
	}
	esp := spec.IKE.ESPDataPlane
	if esp.SPI != 0xCAFEBABE {
		t.Errorf("SPI = 0x%08X, want 0xCAFEBABE", esp.SPI)
	}
	if esp.Count != 3 {
		t.Errorf("Count = %d, want 3", esp.Count)
	}
	if esp.Mode != "tunnel" {
		t.Errorf("Mode = %q, want tunnel", esp.Mode)
	}
	if esp.InnerSrcIP != "192.168.1.1" || esp.InnerDstIP != "192.168.2.1" {
		t.Errorf("inner IPs = %s/%s", esp.InnerSrcIP, esp.InnerDstIP)
	}
	if esp.InnerProto != 17 {
		t.Errorf("InnerProto = %d, want 17", esp.InnerProto)
	}
	if esp.IVLength != 16 || esp.ICVLength != 12 {
		t.Errorf("IV/ICV = %d/%d, want 16/12", esp.IVLength, esp.ICVLength)
	}
}

// TestMapToFlowSpec_IKE_NoESPDataPlane verifies the ESPDataPlane field stays
// nil when not provided (backward compatibility).
func TestMapToFlowSpec_IKE_NoESPDataPlane(t *testing.T) {
	cfg := map[string]interface{}{
		"ike": map[string]interface{}{
			"scenario": "standard_v2",
		},
	}
	spec := mapToFlowSpec(cfg, "ike")
	if spec.IKE == nil {
		t.Fatal("IKE config nil")
	}
	if spec.IKE.ESPDataPlane != nil {
		t.Errorf("ESPDataPlane = %v, want nil (not provided)", spec.IKE.ESPDataPlane)
	}
}

// TestMapToFlowSpec_HTTP_ChunkedAndPipeline verifies the new HTTP fields
// (request_transfer_encoding, response_transfer_encoding, chunk_size,
// pipelined) are parsed from the http sub-map into HTTPConfig.
func TestMapToFlowSpec_HTTP_ChunkedAndPipeline(t *testing.T) {
	cfg := map[string]interface{}{
		"http": map[string]interface{}{
			"method":                     "POST",
			"uri":                        "/upload",
			"body":                       "data",
			"request_transfer_encoding":  "chunked",
			"response_transfer_encoding": "chunked",
			"chunk_size":                 float64(512),
			"pipelined":                  true,
			"transactions":               float64(3),
		},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.HTTP == nil {
		t.Fatalf("spec.HTTP is nil")
	}
	h := spec.HTTP
	if h.RequestTransferEncoding != "chunked" {
		t.Errorf("RequestTransferEncoding=%q, want chunked", h.RequestTransferEncoding)
	}
	if h.ResponseTransferEncoding != "chunked" {
		t.Errorf("ResponseTransferEncoding=%q, want chunked", h.ResponseTransferEncoding)
	}
	if h.ChunkSize != 512 {
		t.Errorf("ChunkSize=%d, want 512", h.ChunkSize)
	}
	if !h.Pipelined {
		t.Errorf("Pipelined=false, want true")
	}
}

// TestMapToFlowSpec_HTTP_NewFieldsAbsent verifies backward compatibility:
// when the new fields are absent, they default to zero values (no chunked,
// no pipeline), preserving existing behavior.
func TestMapToFlowSpec_HTTP_NewFieldsAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"http": map[string]interface{}{
			"method": "GET",
			"uri":    "/",
		},
	}
	spec := mapToFlowSpec(cfg, "http")
	if spec.HTTP == nil {
		t.Fatalf("spec.HTTP is nil")
	}
	h := spec.HTTP
	if h.RequestTransferEncoding != "" {
		t.Errorf("RequestTransferEncoding=%q, want empty (absent)", h.RequestTransferEncoding)
	}
	if h.ResponseTransferEncoding != "" {
		t.Errorf("ResponseTransferEncoding=%q, want empty (absent)", h.ResponseTransferEncoding)
	}
	if h.ChunkSize != 0 {
		t.Errorf("ChunkSize=%d, want 0 (absent)", h.ChunkSize)
	}
	if h.Pipelined {
		t.Errorf("Pipelined=true, want false (absent)")
	}
}

// VNC (RFC 6143) converter tests, derived from testcases_vnc.md §8.1-8.8.
func TestMapToFlowSpec_VNC(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"vnc": map[string]interface{}{
			"security_type":  float64(2),
			"width":          float64(800),
			"height":         float64(600),
			"server_name":    "test",
			"rounds":         float64(2),
			"pointer_x":      float64(100),
			"pointer_y":      float64(200),
			"key_events":     []interface{}{map[string]interface{}{"down": float64(1), "key": float64(97)}},
			"encodings":      []interface{}{float64(0), float64(5)},
			"initial_fbu":    []interface{}{map[string]interface{}{"x": float64(0), "y": float64(0), "width": float64(16), "height": float64(16), "encoding": "raw"}},
			"update_rects":   []interface{}{map[string]interface{}{"x": float64(0), "y": float64(0), "width": float64(2), "height": float64(2), "encoding": "raw"}},
			"challenge_seed": float64(42),
			"response_seed":  float64(7),
		},
	}
	spec := mapToFlowSpec(raw, "vnc")
	if spec.VNC == nil {
		t.Fatalf("spec.VNC is nil")
	}
	cfg := spec.VNC
	if cfg.SecurityType != 2 || cfg.Width != 800 || cfg.Height != 600 || cfg.ServerName != "test" {
		t.Errorf("base fields = sec %d %dx%d name %q, want 2 800x600 test",
			cfg.SecurityType, cfg.Width, cfg.Height, cfg.ServerName)
	}
	if cfg.Rounds != 2 || cfg.PointerX != 100 || cfg.PointerY != 200 {
		t.Errorf("interaction = rounds %d ptr %d,%d, want 2 100,200", cfg.Rounds, cfg.PointerX, cfg.PointerY)
	}
	if len(cfg.KeyEvents) != 1 || !cfg.KeyEvents[0].Down || cfg.KeyEvents[0].Key != 97 {
		t.Errorf("key_events = %+v, want [down key=97]", cfg.KeyEvents)
	}
	if len(cfg.Encodings) != 2 || cfg.Encodings[0] != 0 || cfg.Encodings[1] != 5 {
		t.Errorf("encodings = %v, want [0 5]", cfg.Encodings)
	}
	if len(cfg.InitialFBU) != 1 || cfg.InitialFBU[0].Width != 16 || cfg.InitialFBU[0].Encoding != "raw" {
		t.Errorf("initial_fbu = %+v, want 1 raw rect", cfg.InitialFBU)
	}
	if len(cfg.UpdateRects) != 1 || cfg.UpdateRects[0].Height != 2 {
		t.Errorf("update_rects = %+v, want 1 rect", cfg.UpdateRects)
	}
	if cfg.ChallengeSeed != 42 || cfg.ResponseSeed != 7 {
		t.Errorf("seeds = %d/%d, want 42/7", cfg.ChallengeSeed, cfg.ResponseSeed)
	}
	// 8.1 dst_port absent → 5900.
	if spec.DstPort != 5900 {
		t.Errorf("dst_port = %d, want 5900 default", spec.DstPort)
	}
}

// 8.2 explicit dst_port is honored (not clobbered by the 5900 default).
func TestMapToFlowSpec_VNC_ExplicitDstPort(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"dst_port": float64(5902),
		"vnc":      map[string]interface{}{"security_type": float64(16)},
	}
	spec := mapToFlowSpec(raw, "vnc")
	if spec.VNC == nil {
		t.Fatalf("spec.VNC is nil")
	}
	if spec.DstPort != 5902 {
		t.Errorf("dst_port = %d, want 5902", spec.DstPort)
	}
}

// 8.3 nil vnc sub-map → nil VNC config (planner's Validate rejects it).
func TestMapToFlowSpec_VNC_SubMapAbsent(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1"}, "vnc")
	if spec.VNC != nil {
		t.Fatalf("spec.VNC = %+v, want nil", spec.VNC)
	}
	// 8.1 default port still applies with no sub-map.
	if spec.DstPort != 5900 {
		t.Errorf("dst_port = %d, want 5900 default", spec.DstPort)
	}
}

// 8.4 explicit zero values are preserved (pointer at 0,0 is legal and must
// not be replaced by the 507/320 default).
func TestMapToFlowSpec_VNC_ExplicitZeroPreserved(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"vnc": map[string]interface{}{
			"pointer_x": float64(0), "pointer_y": float64(0),
			"rounds": float64(1), "fbu_update_interval": float64(1),
		},
	}
	spec := mapToFlowSpec(raw, "vnc")
	cfg := spec.VNC
	if cfg.PointerX != 0 || cfg.PointerY != 0 {
		t.Errorf("pointer = %d,%d, want 0,0 (explicit zero preserved)", cfg.PointerX, cfg.PointerY)
	}
}

// 8.5 security_type=3 → the parse layer preserves the illegal value (it is
// not a parse-level error); rejection happens in the planner's Validate,
// which fails the task in the worker (covered by vnc_test.go TestValidate and
// the worker's plan-error path).
func TestMapToFlowSpec_VNC_IllegalSecurityPreserved(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"vnc": map[string]interface{}{"security_type": float64(3)},
	}, "vnc")
	if spec.VNC == nil || spec.VNC.SecurityType != 3 {
		t.Fatalf("security_type = %+v, want 3 preserved for planner rejection", spec.VNC)
	}
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("ValidationErrors = %v, want empty (not a parse-level error)", spec.ValidationErrors)
	}
	task := Task{Name: "t", Protocol: "vnc", Spec: spec}
	if err := ValidateTask(task); err != nil {
		t.Fatalf("ValidateTask = %v, want nil (protocol is legal; rejection is the planner's job)", err)
	}
}

// 8.6 auth_result=5 → same as 8.5: preserved at parse, rejected by the
// planner's Validate (vnc_test.go TestValidate/auth_result=5).
func TestMapToFlowSpec_VNC_IllegalAuthResultPreserved(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"vnc": map[string]interface{}{"auth_result": float64(5)},
	}, "vnc")
	if spec.VNC == nil || spec.VNC.AuthResult != 5 {
		t.Fatalf("auth_result = %+v, want 5 preserved for planner rejection", spec.VNC)
	}
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("ValidationErrors = %v, want empty (not a parse-level error)", spec.ValidationErrors)
	}
}

// 8.7 encodings=["abc"] → parse-level error lands in ValidationErrors and the
// task fails (the planner surfaces them).
func TestMapToFlowSpec_VNC_InvalidEncodingParseError(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"vnc": map[string]interface{}{"encodings": []interface{}{"abc"}},
	}, "vnc")
	if len(spec.ValidationErrors) == 0 {
		t.Fatalf("expected ValidationErrors from non-numeric encoding, got none")
	}
	if !contains(spec.ValidationErrors[0], "invalid vnc encoding") {
		t.Errorf("ValidationErrors[0] = %q, want invalid-vnc-encoding", spec.ValidationErrors[0])
	}
}

// 8.8 unknown protocol name is rejected at task validation.
func TestValidateTask_VNCx_InvalidProtocol(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"vnc": map[string]interface{}{"security_type": float64(16)},
	}, "vncx")
	task := Task{Name: "t", Protocol: "vncx", Spec: spec}
	if err := ValidateTask(task); err == nil || !contains(err.Error(), "invalid protocol") {
		t.Fatalf("ValidateTask = %v, want invalid-protocol error", err)
	}
}

// PPTP (RFC 2637) converter tests, derived from testcases_pptp.md §8.1-8.5.

// 8.1 dst_port absent → 1723.
func TestMapToFlowSpec_PPTP_DefaultPort(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"pptp": map[string]interface{}{"role": "pac"},
	}
	spec := mapToFlowSpec(raw, "pptp")
	if spec.PPTP == nil {
		t.Fatalf("spec.PPTP is nil")
	}
	if spec.DstPort != 1723 {
		t.Errorf("dst_port = %d, want 1723 (RFC 2637 §1)", spec.DstPort)
	}
}

// 8.2 role/scenario/calls parse; explicit 0 frame counts survive (the
// planner emits 0 GRE frames then, unlike the defaults 3/2).
func TestMapToFlowSpec_PPTP_Fields(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"pptp": map[string]interface{}{
			"role":             "pac",
			"scenario":         "data_only",
			"calls":            float64(2),
			"data_frames":      float64(0),
			"down_data_frames": float64(0),
			"sub_address":      "aabbcc",
			"inner_ip": map[string]interface{}{
				"src_ip": "192.168.1.1", "dst_ip": "192.168.1.2",
				"proto": float64(6), "src_port": float64(1234), "dst_port": float64(80),
			},
		},
	}
	spec := mapToFlowSpec(raw, "pptp")
	cfg := spec.PPTP
	if cfg == nil {
		t.Fatalf("spec.PPTP is nil")
	}
	if cfg.Role != "pac" || cfg.Scenario != "data_only" || cfg.Calls != 2 {
		t.Errorf("role/scenario/calls = %q/%q/%d, want pac/data_only/2", cfg.Role, cfg.Scenario, cfg.Calls)
	}
	// Explicit zeros survive the parse (getIntPresence) and the planner
	// honors them (zero frames) — unlike the defaults 3/2.
	if cfg.DataFrames != 0 || cfg.DownDataFrames != 0 {
		t.Errorf("data_frames/down_data_frames = %d/%d, want 0/0 (explicit zero)", cfg.DataFrames, cfg.DownDataFrames)
	}
	if cfg.SubAddress != "aabbcc" {
		t.Errorf("sub_address = %q, want aabbcc", cfg.SubAddress)
	}
	if cfg.InnerIP == nil || cfg.InnerIP.SrcIP != "192.168.1.1" || cfg.InnerIP.Proto != 6 || cfg.InnerIP.SrcPort != 1234 {
		t.Errorf("inner_ip = %+v, want src 192.168.1.1 proto 6 port 1234", cfg.InnerIP)
	}
}

// 8.3 scenario="bad" → preserved at parse (not a parse-level error);
// rejection is the planner's Validate job (pptp_test.go TestValidate), which
// fails the task in the worker.
func TestMapToFlowSpec_PPTP_IllegalScenarioPreserved(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"pptp": map[string]interface{}{"scenario": "bad"},
	}, "pptp")
	if spec.PPTP == nil || spec.PPTP.Scenario != "bad" {
		t.Fatalf("scenario = %+v, want bad preserved for planner rejection", spec.PPTP)
	}
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("ValidationErrors = %v, want empty (not a parse-level error)", spec.ValidationErrors)
	}
	task := Task{Name: "t", Protocol: "pptp", Spec: spec}
	if err := ValidateTask(task); err != nil {
		t.Fatalf("ValidateTask = %v, want nil (protocol is legal; rejection is the planner's job)", err)
	}
}

// 8.4 sub_address="zz" (non-hex) → same as 8.3: preserved at parse,
// rejected by the planner's Validate (pptp_test.go TestValidate).
func TestMapToFlowSpec_PPTP_IllegalSubAddressPreserved(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"pptp": map[string]interface{}{"sub_address": "zz"},
	}, "pptp")
	if spec.PPTP == nil || spec.PPTP.SubAddress != "zz" {
		t.Fatalf("sub_address = %+v, want zz preserved for planner rejection", spec.PPTP)
	}
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("ValidationErrors = %v, want empty (not a parse-level error)", spec.ValidationErrors)
	}
}

// 8.5 unknown protocol name is rejected at task validation.
func TestValidateTask_PPTPx_InvalidProtocol(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"pptp": map[string]interface{}{"role": "pns"},
	}, "ppptx")
	task := Task{Name: "t", Protocol: "ppptx", Spec: spec}
	if err := ValidateTask(task); err == nil || !contains(err.Error(), "invalid protocol") {
		t.Fatalf("ValidateTask = %v, want invalid-protocol error", err)
	}
}

// 深度审计修复: DoIP AddressAndLength/TransferData/Data 以十六进制字符串输入
// (设计 §6.10/T041: "00 44 00 ..."), 此前按 ASCII 原样使用导致 0x34/0x36
// 报文长度错误。字符串值必须 hex 解码为字节。
func TestMapToFlowSpec_DoIP_HexStringFields(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"doip": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{
					"direction": "up",
					"uds": map[string]interface{}{
						"service_id":         float64(52),
						"address_and_length": "00 44 00 00 00 01 00 00 00 10",
						"transfer_data":      "aabbccdd",
					},
				},
			},
		},
	}, "doip")
	if spec.DoIP == nil || len(spec.DoIP.Messages) != 1 || spec.DoIP.Messages[0].UDS == nil {
		t.Fatalf("DoIP not parsed: %+v", spec.DoIP)
	}
	uds := spec.DoIP.Messages[0].UDS
	wantAddr := []byte{0x00, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10}
	if !bytes.Equal(uds.AddressAndLength, wantAddr) {
		t.Errorf("AddressAndLength = %x, want %x", uds.AddressAndLength, wantAddr)
	}
	if !bytes.Equal(uds.TransferData, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Errorf("TransferData = %x, want aabbccdd", uds.TransferData)
	}
}

// 数组形式的 Data/TransferData 保持逐字节语义 (hex 解码只作用于字符串)。
func TestMapToFlowSpec_DoIP_ByteArrayFields(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"doip": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{
					"direction": "up",
					"uds": map[string]interface{}{
						"service_id":    float64(39),
						"seed":          []interface{}{float64(17), float64(34), float64(51), float64(68)},
						"transfer_data": []interface{}{float64(1), float64(2), float64(3)},
					},
				},
			},
		},
	}, "doip")
	uds := spec.DoIP.Messages[0].UDS
	if !bytes.Equal(uds.Seed, []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Errorf("Seed = %x, want 11223344", uds.Seed)
	}
	if !bytes.Equal(uds.TransferData, []byte{1, 2, 3}) {
		t.Errorf("TransferData = %x, want 010203", uds.TransferData)
	}
}

// 非 hex 字符串回退为 ASCII (与既有 getByteSlice 语义一致, 不破坏其他协议)。
func TestMapToFlowSpec_DoIP_NonHexStringFallsBack(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"doip": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{
					"direction": "up",
					"uds": map[string]interface{}{
						"service_id": float64(52),
						"data":       "hello",
					},
				},
			},
		},
	}, "doip")
	uds := spec.DoIP.Messages[0].UDS
	if !bytes.Equal(uds.Data, []byte("hello")) {
		t.Errorf("Data = %x, want ASCII hello", uds.Data)
	}
}
