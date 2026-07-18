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
