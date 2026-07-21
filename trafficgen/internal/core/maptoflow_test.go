package core

import (
	"bytes"
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
	if !spec.TCP.Handshake || spec.TCP.Termination {
		t.Errorf("TCP flags handshake=%v termination=%v", spec.TCP.Handshake, spec.TCP.Termination)
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
	if spec.DstPort != 53 {
		t.Errorf("DNS default DstPort = %d, want 53", spec.DstPort)
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
			"method":                "PUT",
			"uri":                   "/v1/x",
			"version":               "HTTP/1.0",
			"request_headers":       map[string]interface{}{"Host": "www.home.com", "X-Trace": "abc"},
			"body":                  `{"k":"v"}`,
			"keep_alive":            true,
			"transactions":          float64(3),
			"think_time":            float64(200),
			"response_headers":      map[string]interface{}{"Content-Type": "application/json"},
			"response_body":         `{"ok":true}`,
			"response_status_code":  float64(201),
			"response_status_text":  "Created",
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
	if h.ThinkTime != 200 {
		t.Errorf("ThinkTime=%d, want 200", h.ThinkTime)
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
	if spec.Flags != DefaultIPFlags {
		t.Errorf("Flags=%d, want default %d (DF=1)", spec.Flags, DefaultIPFlags)
	}
}

// TestMapToFlowSpec_FlagsUserExplicitZero verifies that explicit flags=0 in
// the config map is honored (allow fragmentation). Same presence-check
// rationale as TestMapToFlowSpec_DSCPUserExplicitZero.
func TestMapToFlowSpec_FlagsUserExplicitZero(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"flags":  float64(0),
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.Flags != 0 {
		t.Errorf("Flags=%d, want 0 (user explicit no-DF, not default)", spec.Flags)
	}
}

// TestMapToFlowSpec_FlagsUserOverride verifies that a user-provided flags
// value (e.g. MF=1 for fragmented traffic) wins over the default DF=1.
func TestMapToFlowSpec_FlagsUserOverride(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"flags":  float64(1), // MF=1
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.Flags != 1 {
		t.Errorf("Flags=%d, want 1 (user override MF)", spec.Flags)
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
// null for flags is treated as "not set".
func TestMapToFlowSpec_FlagsNullFallsBackToDefault(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"flags":  nil,
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.Flags != DefaultIPFlags {
		t.Errorf("Flags=%d, want DefaultIPFlags=%d (null should fall back to default)", spec.Flags, DefaultIPFlags)
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
		"flags":    float64(0), // user explicitly wants no-DF
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.Flags != 0 {
		t.Fatalf("precondition: spec.Flags=%d, want 0", spec.Flags)
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
// DefaultSrcIP (192.0.2.1, TEST-NET-1). Without this default, src_ip was
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
// DefaultDstIP (192.0.2.2, TEST-NET-1).
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
	if spec.DstPort != 53 {
		t.Errorf("DNS DstPort=%d, want 53 (protocol-specific override)", spec.DstPort)
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
	if spec.Flags != DefaultIPFlags {
		t.Errorf("Flags=%d, want %d", spec.Flags, DefaultIPFlags)
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
	if spec.DstPort != 53 {
		t.Errorf("DNS DstPort=%d, want 53 (null should fall back to DNS-specific default)", spec.DstPort)
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
//   cfg -> mapToFlowSpec -> L3Base -> Builder.Build -> wire bytes
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
	wantSrcIP := []byte{192, 0, 2, 1}
	if !bytes.Equal(packet[26:30], wantSrcIP) {
		t.Errorf("src IP bytes = %v, want %v (DefaultSrcIP 192.0.2.1)", packet[26:30], wantSrcIP)
	}
	wantDstIP := []byte{192, 0, 2, 2}
	if !bytes.Equal(packet[30:34], wantDstIP) {
		t.Errorf("dst IP bytes = %v, want %v (DefaultDstIP 192.0.2.2)", packet[30:34], wantDstIP)
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
// FTP branch (strategy_convert.go:273-286)
// ============================================================================
//
// Coverage goals (per CLAUDE.md Testing Policy §3 "one test per code path"):
//   1. ftp sub-map present -> spec.FTP populated, fields propagated
//   2. ftp sub-map absent -> spec.FTP nil (degenerate session path)
//   3. Banner/Commands/MSS fields each propagated
//   4. dst_port absent -> default 21 (FTP control channel override)
//   5. dst_port explicit user value -> user wins (NOT overridden to 21)
//   6. dst_port=0 explicit -> 0 honored (NOT overridden to 21)
//   7. dst_port=nil -> treated as absent -> 21 (matches DNS pattern)
//   8. parseFTPCommands: empty/absent array -> nil
//   9. parseFTPCommands: valid array -> []FTPCommand
//  10. parseFTPCommands: non-array -> nil
//  11. parseFTPCommands: array with non-map items -> skipped, rest kept

// TestMapToFlowSpec_FTP_FullConfig verifies that a fully-populated FTP sub-map
// produces spec.FTP with Banner, Commands, and MSS propagated verbatim.
func TestMapToFlowSpec_FTP_FullConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"ftp": map[string]interface{}{
			"banner": "220 Welcome",
			"mss":    float64(1400),
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
		},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.FTP == nil {
		t.Fatal("FTP nil, want populated")
	}
	if spec.FTP.Banner != "220 Welcome" {
		t.Errorf("FTP.Banner=%q, want \"220 Welcome\"", spec.FTP.Banner)
	}
	if spec.FTP.MSS != 1400 {
		t.Errorf("FTP.MSS=%d, want 1400", spec.FTP.MSS)
	}
	if len(spec.FTP.Commands) != 2 {
		t.Fatalf("FTP.Commands len=%d, want 2", len(spec.FTP.Commands))
	}
	if spec.FTP.Commands[0].Cmd != "USER anonymous" || spec.FTP.Commands[0].Response != "331 Anonymous access allowed" {
		t.Errorf("FTP.Commands[0]=%+v", spec.FTP.Commands[0])
	}
	if spec.FTP.Commands[1].Cmd != "PASS guest@" || spec.FTP.Commands[1].Response != "230 Login successful" {
		t.Errorf("FTP.Commands[1]=%+v", spec.FTP.Commands[1])
	}
}

// TestMapToFlowSpec_FTP_SubMapAbsent verifies that absent ftp sub-map leaves
// spec.FTP nil. The planner then emits only TCP handshake + teardown (an
// empty FTP session, which is a valid degenerate test).
func TestMapToFlowSpec_FTP_SubMapAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.FTP != nil {
		t.Errorf("FTP=%+v, want nil (sub-map absent)", spec.FTP)
	}
}

// TestMapToFlowSpec_FTP_SubMapWrongType verifies that a non-map ftp value
// (e.g. a string from misconfigured JSON) leaves spec.FTP nil. The type
// assertion `cfg["ftp"].(map[string]interface{})` fails silently.
func TestMapToFlowSpec_FTP_SubMapWrongType(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"ftp":    "not-a-map",
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.FTP != nil {
		t.Errorf("FTP=%+v, want nil (sub-map wrong type)", spec.FTP)
	}
}

// TestMapToFlowSpec_FTP_DefaultPort21 verifies that absent dst_port falls
// back to 21 (FTP control channel). FTP is the second protocol (after DNS)
// to override the generic port-80 default with its own well-known port.
func TestMapToFlowSpec_FTP_DefaultPort21(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"ftp":    map[string]interface{}{"banner": "220"},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.DstPort != 21 {
		t.Errorf("FTP DstPort=%d, want 21 (FTP control channel override)", spec.DstPort)
	}
}

// TestMapToFlowSpec_FTP_DefaultPort21_NoSubMap verifies the port-21 override
// fires even when the ftp sub-map is absent. The override is OUTSIDE the
// sub-map presence check (strategy_convert.go:284-286) so it applies whenever
// protocol="ftp" regardless of sub-map state.
func TestMapToFlowSpec_FTP_DefaultPort21_NoSubMap(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.DstPort != 21 {
		t.Errorf("FTP DstPort=%d, want 21 (override fires even without sub-map)", spec.DstPort)
	}
}

// TestMapToFlowSpec_FTP_UserPortHonored verifies that explicit user dst_port
// wins over the 21 default. Matches the DNS override pattern: presence check
// at strategy_convert.go:284 means "key present + non-nil" => user wins.
func TestMapToFlowSpec_FTP_UserPortHonored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(2121),
		"ftp":      map[string]interface{}{"banner": "220"},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.DstPort != 2121 {
		t.Errorf("FTP DstPort=%d, want 2121 (user override)", spec.DstPort)
	}
}

// TestMapToFlowSpec_FTP_DstPortExplicitZeroHonored verifies that explicit
// dst_port=0 for FTP is NOT overridden to 21. Without the `cfg["dst_port"]==nil`
// half of the guard, the presence-only check would treat 0 as "absent" and
// override it. This is the load-bearing test for that half of the guard.
func TestMapToFlowSpec_FTP_DstPortExplicitZeroHonored(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": float64(0),
		"ftp":      map[string]interface{}{"banner": "220"},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.DstPort != 0 {
		t.Errorf("FTP DstPort=%d, want 0 (explicit zero must NOT be overridden to 21)", spec.DstPort)
	}
}

// TestMapToFlowSpec_FTP_DstPortNilFallsBackTo21 verifies that explicit JSON
// null dst_port is treated as "not set" and falls back to 21. The `== nil`
// half of the guard catches this case; without it, a null dst_port would
// pass the outer `_, ok := cfg["dst_port"]` check and leave DstPort at 0.
func TestMapToFlowSpec_FTP_DstPortNilFallsBackTo21(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"dst_port": nil,
		"ftp":      map[string]interface{}{"banner": "220"},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.DstPort != 21 {
		t.Errorf("FTP DstPort=%d, want 21 (nil dst_port -> fallback)", spec.DstPort)
	}
}

// TestMapToFlowSpec_FTP_CommandsEmpty verifies that an empty commands array
// leaves spec.FTP.Commands nil (parseFTPCommands returns nil for len==0).
// The planner then emits a TCP handshake + Banner (if set) + teardown with
// no command/response pairs.
func TestMapToFlowSpec_FTP_CommandsEmpty(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"ftp": map[string]interface{}{
			"banner":   "220",
			"commands": []interface{}{},
		},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.FTP == nil {
		t.Fatal("FTP nil, want populated")
	}
	if spec.FTP.Commands != nil {
		t.Errorf("FTP.Commands=%v, want nil (empty array -> nil)", spec.FTP.Commands)
	}
}

// TestMapToFlowSpec_FTP_CommandsAbsent verifies that absent commands key
// leaves spec.FTP.Commands nil. Same outcome as empty array, different path
// (sub["commands"] returns nil interface, parseFTPCommands returns nil).
func TestMapToFlowSpec_FTP_CommandsAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"ftp":    map[string]interface{}{"banner": "220"},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.FTP == nil {
		t.Fatal("FTP nil, want populated")
	}
	if spec.FTP.Commands != nil {
		t.Errorf("FTP.Commands=%v, want nil (absent key)", spec.FTP.Commands)
	}
}

// TestMapToFlowSpec_FTP_CommandsNonArray verifies that a non-array commands
// value (e.g. a string) leaves spec.FTP.Commands nil. parseFTPCommands's
// type assertion `v.([]interface{})` fails, returning nil.
func TestMapToFlowSpec_FTP_CommandsNonArray(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"ftp": map[string]interface{}{
			"commands": "USER anonymous",
		},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.FTP == nil {
		t.Fatal("FTP nil, want populated")
	}
	if spec.FTP.Commands != nil {
		t.Errorf("FTP.Commands=%v, want nil (non-array input)", spec.FTP.Commands)
	}
}

// TestMapToFlowSpec_FTP_CommandsSkipNonMapItems verifies that non-map items
// in the commands array are silently skipped, while valid items are kept.
// parseFTPCommands's inner `item.(map[string]interface{})` assertion fails
// for strings/numbers, but the loop continues — the planner still gets the
// valid commands around the bad ones.
func TestMapToFlowSpec_FTP_CommandsSkipNonMapItems(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"ftp": map[string]interface{}{
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
		},
	}
	spec := mapToFlowSpec(cfg, "ftp")
	if spec.FTP == nil {
		t.Fatal("FTP nil, want populated")
	}
	if len(spec.FTP.Commands) != 2 {
		t.Fatalf("FTP.Commands len=%d, want 2 (2 valid items, 2 skipped)", len(spec.FTP.Commands))
	}
	if spec.FTP.Commands[0].Cmd != "USER anonymous" {
		t.Errorf("FTP.Commands[0].Cmd=%q", spec.FTP.Commands[0].Cmd)
	}
	if spec.FTP.Commands[1].Cmd != "QUIT" {
		t.Errorf("FTP.Commands[1].Cmd=%q", spec.FTP.Commands[1].Cmd)
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
		"sip": map[string]interface{}{
			"mss": float64(1400),
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
	if spec.SIP.MSS != 1400 {
		t.Errorf("SIP.MSS=%d, want 1400", spec.SIP.MSS)
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
				"garbage", // skipped
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
		"src_ip":  "::1",
		"dst_ip":  "::2",
		"icmpv6":  "not-a-map",
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
				map[string]interface{}{"data": "first"},  // sequence=0 -> 1
				map[string]interface{}{"data": "second"}, // sequence=0 -> 2
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
		"src_ip":  "::1",
		"dst_ip":  "::2",
		"icmpv6":  map[string]interface{}{"type": float64(128)},
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
				"garbage", // skipped
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
				map[string]interface{}{"data": "first"},  // sequence=0 -> 1
				map[string]interface{}{"data": "second"}, // sequence=0 -> 2
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
				"garbage", // skipped
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
