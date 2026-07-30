package core

import (
	"encoding/json"
	"testing"
)

func TestValidateFlowSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    FlowSpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: false,
		},
		{
			name: "invalid src IP",
			spec: FlowSpec{
				SrcIP:   "invalid",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid dst IP",
			spec: FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "invalid",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid src MAC",
			spec: FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcMAC:  "invalid",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFlowSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFlowSpec() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTask(t *testing.T) {
	tests := []struct {
		name    string
		task    Task
		wantErr bool
	}{
		{
			name: "valid task",
			task: Task{
				Name:     "test task",
				Protocol: "tcp",
				Spec: FlowSpec{
					SrcIP:   "192.168.1.1",
					DstIP:   "192.168.1.2",
					SrcPort: 12345,
					DstPort: 80,
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			task: Task{
				Protocol: "tcp",
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			task: Task{
				Name:     "test",
				Protocol: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTask(tt.task)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTask() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateFlowSpec_VLANIDZeroWarns verifies that a VLAN ID of 0 does
// not fail validation (it is a valid 802.1Q priority-tag construct) but is
// surfaced as a warning so users learn that VID 0 is a priority tag, not a
// real VLAN. The test asserts only that Validate returns nil (warn, not
// error); the warning itself is observable via zap and is not asserted here.
func TestValidateFlowSpec_VLANIDZeroWarns(t *testing.T) {
	spec := FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
		VLAN:    &VLAN{ID: 0, Priority: 5},
	}
	if err := ValidateFlowSpec(spec); err != nil {
		t.Fatalf("ValidateFlowSpec() with vlan.id=0: expected no error (warn only), got %v", err)
	}
}

// TestValidateFlowSpec_VLANIDZeroNoPointer verifies that vlan.id==0 inside
// a nil VLAN pointer does not trigger the warning path. The 802.1Q warning
// is specific to an explicitly configured VLAN tag with VID 0.
func TestValidateFlowSpec_VLANNilNoWarn(t *testing.T) {
	spec := FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
		// VLAN is nil -- no warning path should execute.
	}
	if err := ValidateFlowSpec(spec); err != nil {
		t.Fatalf("ValidateFlowSpec() with nil VLAN: expected no error, got %v", err)
	}
}

func TestParseBPS(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"100", 100, false},
		{"1k", 1000, false},
		{"1K", 1000, false},
		{"1m", 1000000, false},
		{"1M", 1000000, false},
		{"1g", 1000000000, false},
		{"1G", 1000000000, false},
		{"200k", 200000, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseBPS(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseBPS() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseBPS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIRequestToTask(t *testing.T) {
	task := APIRequestToTask("test", "description", "tcp", FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
	}, "eth0")

	if task.Name != "test" {
		t.Errorf("Name = %s, want test", task.Name)
	}
	if task.Protocol != "tcp" {
		t.Errorf("Protocol = %s, want tcp", task.Protocol)
	}
	if task.Interface != "eth0" {
		t.Errorf("Interface = %s, want eth0", task.Interface)
	}
	if task.ID == "" {
		t.Error("ID should not be empty")
	}
}

// TestValidateBatchSpec_DuplicateClassID verifies duplicate class IDs are
// rejected (previously they collided on the rate-limiter key and config
// ClassID, breaking per-class rate isolation).
func TestValidateBatchSpec_DuplicateClassID(t *testing.T) {
	batch := BatchSpec{Classes: []TrafficClass{
		{ID: "a", Type: "tcp", FlowCount: 1,
			Config: map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}},
		{ID: "a", Type: "tcp", FlowCount: 1,
			Config: map[string]interface{}{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}},
	}}
	err := ValidateBatchSpec(batch)
	if err == nil {
		t.Fatal("expected error for duplicate class id, got nil")
	}
}

// TestValidateConfigRanges_TruncationBypass verifies out-of-range DSCP/ECN/VLAN
// values are rejected based on the raw int, not the truncated uint8/uint16.
// Previously dscp=256 silently wrapped to 0 (valid) via uint8(256).
func TestValidateConfigRanges_TruncationBypass(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
	}{
		{"dscp 256 wraps to 0", map[string]interface{}{"dscp": float64(256)}},
		{"ecn 4", map[string]interface{}{"ecn": float64(4)}},
		{"vlan_id 65536 wraps to 0", map[string]interface{}{"vlan_id": float64(65536)}},
		{"vlan_priority 8", map[string]interface{}{"vlan_priority": float64(8)}},
		{"flags 8 wraps", map[string]interface{}{"flags": float64(8)}},
		{"frag_offset 9000 out of 13-bit", map[string]interface{}{"frag_offset": float64(9000)}},
		{"ttl 256 wraps to 0", map[string]interface{}{"ttl": float64(256)}},
		{"tos 256 wraps to 0", map[string]interface{}{"tos": float64(256)}},
		{"dscp -1 wraps to 255", map[string]interface{}{"dscp": float64(-1)}},
		{"vlan_id -1", map[string]interface{}{"vlan_id": float64(-1)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateConfigRanges(c.cfg); err == nil {
				t.Fatalf("expected error for %s, got nil", c.name)
			}
		})
	}
	// Valid values must still pass (including 0 = default for ttl/flags/frag).
	valid := map[string]interface{}{"dscp": float64(46), "ecn": float64(0), "vlan_id": float64(100),
		"flags": float64(2), "frag_offset": float64(0), "ttl": float64(0), "tos": float64(0)}
	if err := ValidateConfigRanges(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// TestValidateBatchSpec_AllProtocols verifies the whitelist covers every
// protocol planner registered in internal/protocol/. Previously the whitelist
// in ValidateBatchSpec only listed 11 base protocols, so all 25 L7 planners
// (ssh, telnet, rdp, redis, ntp, snmp, syslog, smtp, pop3, imap, mysql,
// postgresql, ike, ike_nat_t, l2tp, tls, openvpn, shadowsocks, vmess,
// wireguard, dhcp, dhcpv6, mdns, ssdp, grpc) were rejected with
// "invalid type" despite having planners on disk and being registered with
// the engine.
func TestValidateBatchSpec_AllProtocols(t *testing.T) {
	// All 35 planners registered in cmd/server/main.go.
	allProtocols := []string{
		"tcp", "udp", "http", "dns", "icmp", "arp", "ftp", "sip", "sctp", "icmpv6",
		"replay",
		"ntp", "snmp", "syslog", "smtp", "pop3", "telnet", "imap", "grpc",
		"ssh", "ike", "ike_nat_t", "l2tp", "rdp", "redis", "mysql", "postgresql",
		"tls", "openvpn", "shadowsocks", "vmess", "wireguard", "dhcp", "dhcpv6",
		"mdns", "ssdp",
	}
	for _, proto := range allProtocols {
		t.Run(proto, func(t *testing.T) {
			class := TrafficClass{
				ID:        proto + "-1",
				Type:      proto,
				FlowCount: 1,
				Config:    map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1"},
			}
			// Replay classes need a non-empty Replay field (the planner
			// unmarshals this JSON into its ReplaySpec); all other classes
			// leave Replay nil.
			if proto == "replay" {
				class.Replay = json.RawMessage(`{"pcap_asset_id":"x","speed":{"mode":"original"},"direction":"single","checksum_mode":"recompute"}`)
				// Replay skips FlowSpec validation; reset the placeholder so
				// downstream asserts don't trip on a 0 FlowCount.
				class.FlowCount = 0
			}
			if err := ValidateBatchSpec(BatchSpec{Classes: []TrafficClass{class}}); err != nil {
				t.Fatalf("protocol %q rejected by ValidateBatchSpec: %v", proto, err)
			}
		})
	}
}

// TestMapToFlowSpec_SSDP_NextBootID_SearchPort verifies the SSDP converter
// (parseSSDPConfig) wires the next_boot_id and search_port JSON fields into
// the SSDPConfig struct. This is a regression guard for a real bug found via
// NIC testing: the planner emitted NEXTBOOTID.UPNP.ORG / SEARCHPORT.UPNP.ORG
// headers only when NextBootID>0 / SearchPort>0, but the converter never
// populated those fields (they stayed zero-valued), so the planner conditions
// were never true and the headers were silently dropped.
func TestMapToFlowSpec_SSDP_NextBootID_SearchPort(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"ssdp": map[string]interface{}{
			"message_type":  "update",
			"boot_id":       float64(2),
			"config_id":     float64(3),
			"next_boot_id":  float64(5),
			"search_port":   float64(49152),
		},
	}
	spec := mapToFlowSpec(raw, "ssdp")
	if spec.SSDP == nil {
		t.Fatalf("spec.SSDP is nil")
	}
	if spec.SSDP.NextBootID != 5 {
		t.Errorf("NextBootID = %d, want 5 (next_boot_id not wired)", spec.SSDP.NextBootID)
	}
	if spec.SSDP.SearchPort != 49152 {
		t.Errorf("SearchPort = %d, want 49152 (search_port not wired)", spec.SSDP.SearchPort)
	}
	// BootID/ConfigID were already wired; guard against regression.
	if spec.SSDP.BootID != 2 {
		t.Errorf("BootID = %d, want 2", spec.SSDP.BootID)
	}
	if spec.SSDP.ConfigID != 3 {
		t.Errorf("ConfigID = %d, want 3", spec.SSDP.ConfigID)
	}
}

// TestMapToFlowSpec_ICMPv6_FileSource verifies the ICMPv6 converter wires
// the file_source sub-map into ICMPv6Config.FileSource. This is a regression
// guard for a real bug found via NIC testing: the ICMPv6 planner was fixed to
// resolve FileSource (mirroring ICMPv4), but the converter never populated
// spec.ICMPv6.FileSource, so the FileSource was silently dropped — the task
// completed but echo data fell back to default/inline instead of the file
// bytes.
func TestMapToFlowSpec_ICMPv6_FileSource(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"icmpv6": map[string]interface{}{
			"type": float64(128),
			"file_source": map[string]interface{}{
				"literal": "FS-V6-LITERAL",
			},
		},
	}
	spec := mapToFlowSpec(raw, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatalf("spec.ICMPv6 is nil")
	}
	if spec.ICMPv6.FileSource == nil {
		t.Fatalf("ICMPv6.FileSource is nil (file_source not wired for icmpv6)")
	}
	if spec.ICMPv6.FileSource.Literal == "" {
		t.Fatalf("ICMPv6.FileSource.Literal is empty (file_source parsed but Literal dropped)")
	}
	if spec.ICMPv6.FileSource.Literal != "FS-V6-LITERAL" {
		t.Errorf("ICMPv6.FileSource.Literal = %q, want %q", spec.ICMPv6.FileSource.Literal, "FS-V6-LITERAL")
	}
}

// TestMapToFlowSpec_ICMPv6_FileSourcePrecedenceOverInline verifies that when
// both inline data and file_source are set, both are surfaced (the planner,
// not the converter, decides precedence — the planner lets FileSource win).
// The converter must populate BOTH so the planner has the choice.
func TestMapToFlowSpec_ICMPv6_FileSourcePrecedenceOverInline(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"icmpv6": map[string]interface{}{
			"data": "FROM-INLINE-DATA",
			"file_source": map[string]interface{}{
				"literal": "FROM-FILESOURCE",
			},
		},
	}
	spec := mapToFlowSpec(raw, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatalf("spec.ICMPv6 is nil")
	}
	if spec.ICMPv6.FileSource == nil {
		t.Fatalf("ICMPv6.FileSource is nil (file_source not wired when data also set)")
	}
	if spec.ICMPv6.FileSource.Literal != "FROM-FILESOURCE" {
		t.Errorf("FileSource.Literal = %q, want FROM-FILESOURCE", spec.ICMPv6.FileSource.Literal)
	}
	if string(spec.ICMPv6.Data) != "FROM-INLINE-DATA" {
		t.Errorf("Data = %q, want FROM-INLINE-DATA", string(spec.ICMPv6.Data))
	}
}
