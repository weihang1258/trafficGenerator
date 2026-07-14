package core

// Test points for validate.go (V1-V102) from tools/test_points/engine_core.md.
// Adds uncovered branches and exact-message assertions. Existing tests
// (validate_test.go, convert_test.go, audit_fixes_test.go) only assert err!=nil
// for most cases; these add exact error-message checks and the missing branches.

import (
	"encoding/json"
	"strings"
	"testing"
)

func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("err = %q, want substring %q", err.Error(), want)
	}
}

// --- ValidateConfigRanges (V1-V22) ---

func TestValidateConfigRanges_AllValid(t *testing.T) {
	cfg := map[string]interface{}{
		"dscp": float64(46), "ecn": float64(1), "vlan_id": float64(100),
		"vlan_priority": float64(3), "flags": float64(2), "frag_offset": float64(0),
		"ttl": float64(64), "tos": float64(0), "src_port": float64(1024), "dst_port": float64(80),
	}
	if err := ValidateConfigRanges(cfg); err != nil {
		t.Errorf("all-valid: unexpected err: %v", err)
	}
}

func TestValidateConfigRanges_Branches(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
		want string
	}{
		{"dscp neg", map[string]interface{}{"dscp": float64(-1)}, "dscp -1 invalid"},
		{"dscp over", map[string]interface{}{"dscp": float64(64)}, "dscp 64 invalid"},
		{"ecn neg", map[string]interface{}{"ecn": float64(-1)}, "ecn -1 invalid"},
		{"ecn over", map[string]interface{}{"ecn": float64(4)}, "ecn 4 invalid"},
		{"vlan_id neg", map[string]interface{}{"vlan_id": float64(-1)}, "vlan_id -1 invalid"},
		{"vlan_id over", map[string]interface{}{"vlan_id": float64(4096)}, "vlan_id 4096 invalid"},
		{"vlan_priority neg", map[string]interface{}{"vlan_priority": float64(-1)}, "vlan_priority -1 invalid"},
		{"vlan_priority over", map[string]interface{}{"vlan_priority": float64(8)}, "vlan_priority 8 invalid"},
		{"flags neg", map[string]interface{}{"flags": float64(-1)}, "flags -1 invalid"},
		{"flags over", map[string]interface{}{"flags": float64(8)}, "flags 8 invalid"},
		{"frag_offset neg", map[string]interface{}{"frag_offset": float64(-1)}, "frag_offset -1 invalid"},
		{"frag_offset over", map[string]interface{}{"frag_offset": float64(8192)}, "frag_offset 8192 invalid"},
		{"ttl neg", map[string]interface{}{"ttl": float64(-1)}, "ttl -1 invalid"},
		{"ttl over", map[string]interface{}{"ttl": float64(256)}, "ttl 256 invalid"},
		{"tos neg", map[string]interface{}{"tos": float64(-1)}, "tos -1 invalid"},
		{"tos over", map[string]interface{}{"tos": float64(256)}, "tos 256 invalid"},
		{"src_port neg", map[string]interface{}{"src_port": float64(-1)}, "src_port -1 invalid"},
		{"src_port over", map[string]interface{}{"src_port": float64(65536)}, "src_port 65536 invalid"},
		{"dst_port neg", map[string]interface{}{"dst_port": float64(-1)}, "dst_port -1 invalid"},
		{"dst_port over", map[string]interface{}{"dst_port": float64(65536)}, "dst_port 65536 invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertErrContains(t, ValidateConfigRanges(c.cfg), c.want)
		})
	}
}

// V22-BR1: empty map -> all getInt return 0 (in range) -> nil.
func TestValidateConfigRanges_MissingFields(t *testing.T) {
	if err := ValidateConfigRanges(map[string]interface{}{}); err != nil {
		t.Errorf("empty map: unexpected err: %v", err)
	}
}

// --- ValidateProtocolSubConfigs (V23-V40) ---

func TestValidateProtocolSubConfigs_TCPValid(t *testing.T) {
	cfg := map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(1460), "window_size": float64(65535)}}
	if err := ValidateProtocolSubConfigs(cfg, "tcp"); err != nil {
		t.Errorf("tcp valid: unexpected err: %v", err)
	}
}

func TestValidateProtocolSubConfigs_Branches(t *testing.T) {
	cases := []struct {
		name     string
		cfg      map[string]interface{}
		protocol string
		want     string
		wantErr  bool
	}{
		{"tcp.mss neg", map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(-1)}}, "tcp", "tcp.mss -1 invalid", true},
		{"tcp.mss over", map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(65536)}}, "tcp", "tcp.mss 65536 invalid", true},
		{"tcp.window_size neg", map[string]interface{}{"tcp": map[string]interface{}{"window_size": float64(-1)}}, "tcp", "tcp.window_size -1 invalid", true},
		{"dns.query_type neg", map[string]interface{}{"dns": map[string]interface{}{"query_type": float64(-1)}}, "dns", "dns.query_type -1 invalid", true},
		{"dns.query_type over", map[string]interface{}{"dns": map[string]interface{}{"query_type": float64(65536)}}, "dns", "dns.query_type 65536 invalid", true},
		{"icmp.type neg", map[string]interface{}{"icmp": map[string]interface{}{"type": float64(-1)}}, "icmp", "icmp.type -1 invalid", true},
		{"icmp.type over", map[string]interface{}{"icmp": map[string]interface{}{"type": float64(256)}}, "icmp", "icmp.type 256 invalid", true},
		{"icmp.code neg", map[string]interface{}{"icmp": map[string]interface{}{"code": float64(-1)}}, "icmp", "icmp.code -1 invalid", true},
		{"icmp.code over", map[string]interface{}{"icmp": map[string]interface{}{"code": float64(256)}}, "icmp", "icmp.code 256 invalid", true},
		{"icmp.sequence neg", map[string]interface{}{"icmp": map[string]interface{}{"sequence": float64(-1)}}, "icmp", "icmp.sequence -1 invalid", true},
		{"icmp.sequence over", map[string]interface{}{"icmp": map[string]interface{}{"sequence": float64(65536)}}, "icmp", "icmp.sequence 65536 invalid", true},
		{"arp.operation neg", map[string]interface{}{"arp": map[string]interface{}{"operation": float64(-1)}}, "arp", "arp.operation -1 invalid", true},
		{"arp.operation over", map[string]interface{}{"arp": map[string]interface{}{"operation": float64(65536)}}, "arp", "arp.operation 65536 invalid", true},
		{"tcp no sub", map[string]interface{}{}, "tcp", "", false},
		{"http", map[string]interface{}{"http": map[string]interface{}{"method": "GET"}}, "http", "", false},
		{"unknown", map[string]interface{}{}, "xyz", "", false},
		{"sub wrong type", map[string]interface{}{"tcp": "string"}, "tcp", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateProtocolSubConfigs(c.cfg, c.protocol)
			if c.wantErr {
				assertErrContains(t, err, c.want)
			} else if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
		})
	}
}

// --- ValidateFlowSpec (V41-V61) ---

func TestValidateFlowSpec_Branches(t *testing.T) {
	cases := []struct {
		name    string
		spec    FlowSpec
		wantErr string
	}{
		{"empty ok", FlowSpec{}, ""},
		{"src ip invalid", FlowSpec{SrcIP: "bad"}, "invalid src_ip"},
		{"src ip valid", FlowSpec{SrcIP: "1.1.1.1"}, ""},
		{"dst ip invalid", FlowSpec{DstIP: "bad"}, "invalid dst_ip"},
		{"dst ip valid", FlowSpec{DstIP: "1.1.1.1"}, ""},
		{"src mac invalid", FlowSpec{SrcMAC: "bad"}, "invalid src_mac"},
		{"src mac valid", FlowSpec{SrcMAC: "aa:bb:cc:dd:ee:ff"}, ""},
		{"dst mac invalid", FlowSpec{DstMAC: "bad"}, "invalid dst_mac"},
		{"dst mac valid", FlowSpec{DstMAC: "aa:bb:cc:dd:ee:ff"}, ""},
		{"vlan nil", FlowSpec{VLAN: nil}, ""},
		{"vlan id over", FlowSpec{VLAN: &VLAN{ID: 5000}}, "vlan_id 5000 invalid"},
		{"vlan id 4095", FlowSpec{VLAN: &VLAN{ID: 4095}}, ""},
		{"vlan priority over", FlowSpec{VLAN: &VLAN{ID: 100, Priority: 8}}, "vlan_priority 8 invalid"},
		{"dscp over", FlowSpec{DSCP: 64}, "dscp 64 invalid"},
		{"dscp zero", FlowSpec{DSCP: 0}, ""},
		{"ecn over", FlowSpec{ECN: 4}, "ecn 4 invalid"},
		{"tcp nil", FlowSpec{TCP: nil}, ""},
		{"tcp mss zero", FlowSpec{TCP: &TCPConfig{MSS: 0}}, ""},
		{"tcp mss too small", FlowSpec{TCP: &TCPConfig{MSS: 100}}, "mss 100 too small"},
		{"tcp mss min", FlowSpec{TCP: &TCPConfig{MSS: 536}}, ""},
		{"tcp mss valid", FlowSpec{TCP: &TCPConfig{MSS: 1460}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateFlowSpec(c.spec)
			if c.wantErr != "" {
				assertErrContains(t, err, c.wantErr)
			} else if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
		})
	}
}

// --- ValidateTask (V62-V67) ---

func TestValidateTask_ValidTCP(t *testing.T) {
	task := Task{Name: "t", Protocol: "tcp", Spec: FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}}
	if err := ValidateTask(task); err != nil {
		t.Errorf("valid tcp task: %v", err)
	}
}

func TestValidateTask_Branches(t *testing.T) {
	cases := []struct {
		name    string
		task    Task
		wantErr string
	}{
		{"name empty", Task{Protocol: "tcp"}, "task name is required"},
		{"invalid protocol", Task{Name: "t", Protocol: "xyz"}, "invalid protocol: xyz"},
		{"protocol empty", Task{Name: "t", Protocol: ""}, "invalid protocol:"},
		{"spec invalid", Task{Name: "t", Protocol: "tcp", Spec: FlowSpec{SrcIP: "bad"}}, "invalid spec:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertErrContains(t, ValidateTask(c.task), c.wantErr)
		})
	}
}

// V64-BR1: batch task delegates to ValidateBatchSpec.
func TestValidateTask_Batch(t *testing.T) {
	task := Task{Name: "t", Protocol: "batch", Batch: &BatchSpec{}}
	assertErrContains(t, ValidateTask(task), "batch must contain at least one traffic class")
}

// --- ValidateBatchSpec (V68-V81) ---

func validSynthClass(id, proto string) TrafficClass {
	return TrafficClass{
		ID: id, Type: proto, FlowCount: 1,
		Config: map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
	}
}

func TestValidateBatchSpec_Valid(t *testing.T) {
	batch := BatchSpec{Classes: []TrafficClass{validSynthClass("c1", "tcp")}}
	if err := ValidateBatchSpec(batch); err != nil {
		t.Errorf("valid batch: %v", err)
	}
}

func TestValidateBatchSpec_Branches(t *testing.T) {
	cases := []struct {
		name    string
		batch   BatchSpec
		wantErr string
	}{
		{"empty classes", BatchSpec{}, "batch must contain at least one traffic class"},
		{"duplicate class id", BatchSpec{Classes: []TrafficClass{validSynthClass("a", "tcp"), validSynthClass("a", "tcp")}}, "duplicate class id"},
		{"class id empty", BatchSpec{Classes: []TrafficClass{{ID: "", Type: "tcp", FlowCount: 1, Config: map[string]interface{}{}}}}, "id is required"},
		{"invalid type", BatchSpec{Classes: []TrafficClass{{ID: "c1", Type: "xyz", FlowCount: 1, Config: map[string]interface{}{}}}}, "invalid type xyz"},
		{"replay missing spec", BatchSpec{Classes: []TrafficClass{{ID: "c1", Type: "replay"}}}, "replay class missing 'replay' spec"},
		{"flow count zero", BatchSpec{Classes: []TrafficClass{{ID: "c1", Type: "tcp", FlowCount: 0, Config: map[string]interface{}{}}}}, "flow_count must be > 0"},
		{"flow count neg", BatchSpec{Classes: []TrafficClass{{ID: "c1", Type: "tcp", FlowCount: -1, Config: map[string]interface{}{}}}}, "flow_count must be > 0"},
		{"config ranges invalid", BatchSpec{Classes: []TrafficClass{{ID: "c1", Type: "tcp", FlowCount: 1, Config: map[string]interface{}{"dscp": float64(64)}}}}, "dscp 64 invalid"},
		{"sub config invalid", BatchSpec{Classes: []TrafficClass{{ID: "c1", Type: "tcp", FlowCount: 1, Config: map[string]interface{}{"tcp": map[string]interface{}{"mss": float64(65536)}}}}}, "tcp.mss 65536 invalid"},
		{"flow spec invalid", BatchSpec{Classes: []TrafficClass{{ID: "c1", Type: "tcp", FlowCount: 1, Config: map[string]interface{}{"src_ip": "bad"}}}}, "invalid src_ip"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertErrContains(t, ValidateBatchSpec(c.batch), c.wantErr)
		})
	}
}

// V73-POS: valid replay class.
func TestValidateBatchSpec_ReplayValid(t *testing.T) {
	batch := BatchSpec{Classes: []TrafficClass{{
		ID: "r1", Type: "replay",
		Replay: json.RawMessage(`{"pcap_asset_id":"a1","speed":{"mode":"max"},"direction":"single"}`),
	}}}
	if err := ValidateBatchSpec(batch); err != nil {
		t.Errorf("valid replay: %v", err)
	}
}

// V75-NEG: replay with invalid spec JSON wraps validateReplaySpec err.
func TestValidateBatchSpec_ReplayInvalidSpec(t *testing.T) {
	batch := BatchSpec{Classes: []TrafficClass{{
		ID: "r1", Type: "replay",
		Replay: json.RawMessage(`{"pcap_asset_id":"a1","speed":{"mode":"bogus"}}`),
	}}}
	assertErrContains(t, ValidateBatchSpec(batch), "invalid speed mode")
}

// V81-BR1: replay class ignores FlowCount (FlowCount=0 still ok).
func TestValidateBatchSpec_ReplayFlowCountIgnored(t *testing.T) {
	batch := BatchSpec{Classes: []TrafficClass{{
		ID: "r1", Type: "replay", FlowCount: 0,
		Replay: json.RawMessage(`{"pcap_asset_id":"a1","speed":{"mode":"max"}}`),
	}}}
	if err := ValidateBatchSpec(batch); err != nil {
		t.Errorf("replay should ignore flow_count: %v", err)
	}
}

// --- validateReplaySpec (V82-V102) ---

func TestValidateReplaySpec_Branches(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr string
	}{
		{"valid original", `{"pcap_asset_id":"a1","speed":{"mode":"original"},"direction":"single"}`, ""},
		{"valid multiplier", `{"pcap_asset_id":"a1","speed":{"mode":"multiplier","multiplier":2}}`, ""},
		{"valid bps", `{"pcap_asset_id":"a1","speed":{"mode":"bps","bps":"1M"}}`, ""},
		{"valid pps", `{"pcap_asset_id":"a1","speed":{"mode":"pps","pps":100}}`, ""},
		{"valid max", `{"pcap_asset_id":"a1","speed":{"mode":"max"}}`, ""},
		{"speed empty", `{"pcap_asset_id":"a1"}`, ""},
		{"direction dual", `{"pcap_asset_id":"a1","speed":{"mode":"max"},"direction":"dual"}`, ""},
		{"direction empty", `{"pcap_asset_id":"a1","speed":{"mode":"max"}}`, ""},
		{"checksum recompute", `{"pcap_asset_id":"a1","speed":{"mode":"max"},"checksum_mode":"recompute"}`, ""},
		{"checksum preserve", `{"pcap_asset_id":"a1","speed":{"mode":"max"},"checksum_mode":"preserve"}`, ""},
		{"checksum empty", `{"pcap_asset_id":"a1","speed":{"mode":"max"}}`, ""},
		{"invalid json", `{not json`, "invalid replay spec JSON"},
		{"no pcap asset id", `{"speed":{"mode":"max"}}`, "replay spec missing pcap_asset_id"},
		{"speed bogus", `{"pcap_asset_id":"a1","speed":{"mode":"bogus"}}`, "invalid speed mode"},
		{"bps no value", `{"pcap_asset_id":"a1","speed":{"mode":"bps"}}`, "bps mode requires a bps value"},
		{"pps zero", `{"pcap_asset_id":"a1","speed":{"mode":"pps","pps":0}}`, "pps mode requires pps > 0"},
		{"pps neg", `{"pcap_asset_id":"a1","speed":{"mode":"pps","pps":-1}}`, "pps mode requires pps > 0"},
		{"direction bogus", `{"pcap_asset_id":"a1","speed":{"mode":"max"},"direction":"triple"}`, "invalid direction"},
		{"checksum bogus", `{"pcap_asset_id":"a1","speed":{"mode":"max"},"checksum_mode":"magic"}`, "invalid checksum_mode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateReplaySpec(json.RawMessage(c.json))
			if c.wantErr != "" {
				assertErrContains(t, err, c.wantErr)
			} else if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
		})
	}
}
