package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

// ---------------------------------------------------------------------------
// hashToken (REAL) — HASH-POS, HASH-BR1, HASH-BR2
// ---------------------------------------------------------------------------

func TestHashToken_Deterministic(t *testing.T) {
	h1 := hashToken("secret-token")
	h2 := hashToken("secret-token")
	if h1 != h2 {
		t.Errorf("not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("len=%d, want 64", len(h1))
	}
	expected := sha256.Sum256([]byte("secret-token"))
	if h1 != hex.EncodeToString(expected[:]) {
		t.Errorf("unexpected hash: %s", h1)
	}
}

func TestHashToken_Empty(t *testing.T) {
	h := hashToken("")
	if h != hex.EncodeToString(sha256.New().Sum(nil)) {
		// sha256("") = e3b0c44298fc1c...
		expected := sha256.Sum256([]byte(""))
		if h != hex.EncodeToString(expected[:]) {
			t.Errorf("empty hash = %s, want %s", h, hex.EncodeToString(expected[:]))
		}
	}
}

func TestHashToken_Distinct(t *testing.T) {
	ha := hashToken("a")
	hb := hashToken("b")
	if ha == hb {
		t.Errorf("distinct inputs produced same hash: %s", ha)
	}
}

// ---------------------------------------------------------------------------
// validateIP (REAL) — VALIP-POS1/2, VALIP-NEG1-5
// ---------------------------------------------------------------------------

func TestValidateIP_Valid(t *testing.T) {
	if !validateIP("10.0.0.1") {
		t.Error("10.0.0.1 should be valid")
	}
}

func TestValidateIP_Broadcast(t *testing.T) {
	if !validateIP("255.255.255.255") {
		t.Error("255.255.255.255 should be valid")
	}
}

func TestValidateIP_IPv6(t *testing.T) {
	if validateIP("2001:db8::1") {
		t.Error("IPv6 should be rejected (design requires dotted-quad)")
	}
}

func TestValidateIP_OutOfRange(t *testing.T) {
	if validateIP("999.1.1.1") {
		t.Error("999.1.1.1 should be invalid")
	}
}

func TestValidateIP_ThreeOctets(t *testing.T) {
	if validateIP("10.0.0") {
		t.Error("10.0.0 should be invalid")
	}
}

func TestValidateIP_Empty(t *testing.T) {
	if validateIP("") {
		t.Error("empty string should be invalid")
	}
}

func TestValidateIP_FiveOctets(t *testing.T) {
	if validateIP("10.0.0.0.1") {
		t.Error("10.0.0.0.1 should be invalid")
	}
}

// ---------------------------------------------------------------------------
// validateMAC (REAL) — VALMAC-POS1/2, VALMAC-NEG1-4
// ---------------------------------------------------------------------------

func TestValidateMAC_Lower(t *testing.T) {
	if !validateMAC("aa:bb:cc:dd:ee:ff") {
		t.Error("aa:bb:cc:dd:ee:ff should be valid")
	}
}

func TestValidateMAC_Upper(t *testing.T) {
	if !validateMAC("AA:BB:CC:DD:EE:FF") {
		t.Error("AA:BB:CC:DD:EE:FF should be valid")
	}
}

func TestValidateMAC_Dash(t *testing.T) {
	if validateMAC("aa-bb-cc-dd-ee-ff") {
		t.Error("dash-separated MAC should be rejected")
	}
}

func TestValidateMAC_Short(t *testing.T) {
	if validateMAC("aa:bb:cc:dd:ee") {
		t.Error("5-octet MAC should be rejected")
	}
}

func TestValidateMAC_NonHex(t *testing.T) {
	if validateMAC("zz:bb:cc:dd:ee:ff") {
		t.Error("non-hex chars should be rejected")
	}
}

func TestValidateMAC_Empty(t *testing.T) {
	if validateMAC("") {
		t.Error("empty string should be rejected")
	}
}

// ---------------------------------------------------------------------------
// validateConfigNetwork (REAL) — VCN-POS1/2/3, VCN-NEG1-4, VCN-BR1/2
// ---------------------------------------------------------------------------

func TestValidateConfigNetwork_AllValid(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"src_mac": "aa:bb:cc:dd:ee:ff",
		"dst_mac": "11:22:33:44:55:66",
	}
	if msg := validateConfigNetwork(cfg); msg != "" {
		t.Errorf("expected empty, got %q", msg)
	}
}

func TestValidateConfigNetwork_Empty(t *testing.T) {
	if msg := validateConfigNetwork(map[string]interface{}{}); msg != "" {
		t.Errorf("expected empty, got %q", msg)
	}
}

func TestValidateConfigNetwork_EmptyFields(t *testing.T) {
	cfg := map[string]interface{}{"src_ip": ""}
	if msg := validateConfigNetwork(cfg); msg != "" {
		t.Errorf("expected empty, got %q", msg)
	}
}

func TestValidateConfigNetwork_BadSrcIP(t *testing.T) {
	cfg := map[string]interface{}{"src_ip": "not-ip"}
	msg := validateConfigNetwork(cfg)
	if !strings.Contains(msg, "invalid IP format: src_ip = not-ip") {
		t.Errorf("unexpected msg: %q", msg)
	}
}

func TestValidateConfigNetwork_BadDstIP(t *testing.T) {
	cfg := map[string]interface{}{"dst_ip": "999.0.0.1"}
	msg := validateConfigNetwork(cfg)
	if !strings.Contains(msg, "invalid IP format: dst_ip =") {
		t.Errorf("unexpected msg: %q", msg)
	}
}

func TestValidateConfigNetwork_BadSrcMAC(t *testing.T) {
	cfg := map[string]interface{}{"src_mac": "zz:zz:zz:zz:zz:zz"}
	msg := validateConfigNetwork(cfg)
	if !strings.Contains(msg, "invalid MAC format: src_mac =") {
		t.Errorf("unexpected msg: %q", msg)
	}
}

func TestValidateConfigNetwork_BadDstMAC(t *testing.T) {
	cfg := map[string]interface{}{"dst_mac": "aa"}
	msg := validateConfigNetwork(cfg)
	if !strings.Contains(msg, "invalid MAC format: dst_mac =") {
		t.Errorf("unexpected msg: %q", msg)
	}
}

func TestValidateConfigNetwork_NonStringIP(t *testing.T) {
	cfg := map[string]interface{}{"src_ip": 12345}
	if msg := validateConfigNetwork(cfg); msg != "" {
		t.Errorf("non-string IP should be skipped: %q", msg)
	}
}

func TestValidateConfigNetwork_IPv6(t *testing.T) {
	cfg := map[string]interface{}{"src_ip": "2001:db8::1"}
	msg := validateConfigNetwork(cfg)
	if !strings.Contains(msg, "invalid IP format: src_ip =") {
		t.Errorf("IPv6 should be rejected: %q", msg)
	}
}

// ---------------------------------------------------------------------------
// calculateConfigHash (REAL) — CCH-POS
// ---------------------------------------------------------------------------

func TestCalculateConfigHash_Deterministic(t *testing.T) {
	h1 := calculateConfigHash("synth", "tcp", `{"src_ip":"10.0.0.1"}`, `{"type":"flows","value":1}`)
	h2 := calculateConfigHash("synth", "tcp", `{"src_ip":"10.0.0.1"}`, `{"type":"flows","value":1}`)
	if h1 != h2 {
		t.Errorf("not deterministic: %s != %s", h1, h2)
	}
	h3 := calculateConfigHash("synth", "udp", `{"src_ip":"10.0.0.1"}`, `{"type":"flows","value":1}`)
	if h1 == h3 {
		t.Errorf("different protocol should produce different hash")
	}
}

// ---------------------------------------------------------------------------
// calculatePortsConfigHash (REAL) — CPCH-POS
// ---------------------------------------------------------------------------

func TestCalculatePortsConfigHash_Deterministic(t *testing.T) {
	json := `[{"interface":"eth0","weight":1}]`
	h1 := calculatePortsConfigHash(json)
	h2 := calculatePortsConfigHash(json)
	if h1 != h2 {
		t.Errorf("not deterministic: %s != %s", h1, h2)
	}
}

// ---------------------------------------------------------------------------
// calculateTaskHash (REAL) — CTH-POS
// ---------------------------------------------------------------------------

func TestCalculateTaskHash_OrderMatters(t *testing.T) {
	ab := calculateTaskHash([]string{"a", "b"}, `{"type":"pcap"}`)
	ba := calculateTaskHash([]string{"b", "a"}, `{"type":"pcap"}`)
	if ab == ba {
		t.Errorf("different order should produce different hash (function does not sort)")
	}
}

// ---------------------------------------------------------------------------
// layersLinkType (REAL) — LLT-POS
// ---------------------------------------------------------------------------

func TestLayersLinkType_Ethernet(t *testing.T) {
	lt := layersLinkType(1)
	if lt != layers.LinkTypeEthernet {
		t.Errorf("got %d, want %d", lt, layers.LinkTypeEthernet)
	}
}

// ---------------------------------------------------------------------------
// currentTime (REAL) — CT-POS
// ---------------------------------------------------------------------------

func TestCurrentTime_Now(t *testing.T) {
	before := time.Now()
	ct := currentTime()
	after := time.Now()
	if ct.Before(before.Add(-time.Second)) || ct.After(after.Add(time.Second)) {
		t.Errorf("currentTime out of range: %v (before=%v, after=%v)", ct, before, after)
	}
}

// ---------------------------------------------------------------------------
// resolvePcapPath (REAL/SIMULATED) — RPP-POS1/2/3, RPP-NEG1/2/3, RPP-BR1, RPP-NEG4
// ---------------------------------------------------------------------------

func TestResolvePcapPath_Absolute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.pcap")
	resolved, err := resolvePcapPath(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != path {
		t.Errorf("got %q, want %q", resolved, path)
	}
	// Verify parent directory was created
	if _, err := os.Stat(filepath.Dir(resolved)); err != nil {
		t.Errorf("parent dir not created: %v", err)
	}
}

func TestResolvePcapPath_Relative(t *testing.T) {
	resolved, err := resolvePcapPath("x.pcap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join("pcap", "x.pcap")
	if resolved != want {
		t.Errorf("got %q, want %q", resolved, want)
	}
}

func TestResolvePcapPath_AlreadyPrefixed(t *testing.T) {
	resolved, err := resolvePcapPath("pcap/x.pcap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != "pcap/x.pcap" {
		t.Errorf("got %q, want %q", resolved, "pcap/x.pcap")
	}
}

func TestResolvePcapPath_Empty(t *testing.T) {
	_, err := resolvePcapPath("")
	if err == nil || !strings.Contains(err.Error(), "pcap_path is required") {
		t.Errorf("expected error about required, got %v", err)
	}
}

func TestResolvePcapPath_Windows(t *testing.T) {
	_, err := resolvePcapPath("C:\\path\\x.pcap")
	if err == nil || !strings.Contains(err.Error(), "Windows-style path") {
		t.Errorf("expected Windows-style error, got %v", err)
	}
}

func TestResolvePcapPath_UNC(t *testing.T) {
	_, err := resolvePcapPath("\\\\srv\\share\\x.pcap")
	if err == nil || !strings.Contains(err.Error(), "UNC path") {
		t.Errorf("expected UNC error, got %v", err)
	}
}

func TestResolvePcapPath_MkdirAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "x.pcap")
	resolved, err := resolvePcapPath(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub", "dir")); err != nil {
		t.Errorf("sub dir not created: %v", err)
	}
	_ = resolved
}

func TestResolvePcapPath_MkdirFail(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("cannot test mkdir fail as root (root bypasses permission checks)")
	}
	// Create a read-only parent directory
	parent := t.TempDir()
	readonly := filepath.Join(parent, "readonly")
	if err := os.MkdirAll(readonly, 0500); err != nil {
		t.Fatalf("mkdir readonly: %v", err)
	}
	// Inside the read-only dir, try to create a subdir
	path := filepath.Join(readonly, "sub", "x.pcap")
	_, err := resolvePcapPath(path)
	if err == nil || !strings.Contains(err.Error(), "failed to create directory") {
		t.Errorf("expected mkdir error, got %v", err)
	}
}