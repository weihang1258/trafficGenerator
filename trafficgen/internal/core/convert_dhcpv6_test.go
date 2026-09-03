package core

import (
	"reflect"
	"testing"
)

// TestMapToFlowSpec_DHCPv6_Scenario_SARR verifies that the JSON-decoded
// "dhcpv6" sub-map with scenario="sarr" and all scenario-mode Default*
// fields is parsed into *DHCPv6Config with every field correctly wired.
// Regression guard: if the converter drops Scenario or any Default* field,
// the planner silently falls back to manual mode or emits zero-valued
// lifetimes/IAID, producing a malformed DHCPv6 dialog (RFC 8415).
func TestMapToFlowSpec_DHCPv6_Scenario_SARR(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "fe80::1", "dst_ip": "fe80::2",
		"dhcpv6": map[string]interface{}{
			"scenario":                   "sarr",
			"default_leased_addr":        "2001:db8::100",
			"default_iaid":               float64(7),
			"default_preferred_lifetime": float64(3600),
			"default_valid_lifetime":     float64(7200),
			"default_t1":                 float64(1800),
			"default_t2":                 float64(2880),
			"default_preference":         float64(10),
			"default_status_code":        float64(0),
			"default_status_message":     "Success",
			"default_oro":                []interface{}{float64(23), float64(24), float64(31)},
			"default_dns_servers":        []interface{}{"2001:db8::53", "2001:db8::54"},
			"default_dns_search":         []interface{}{"example.com", "test.example.com"},
			"default_sntp_servers":       []interface{}{"2001:db8::123"},
			"default_info_refresh_time":  float64(3600),
			"client_duid": map[string]interface{}{
				"type":            float64(1), // DUID-LLT
				"hardware_type":   float64(1),
				"time":            float64(100000),
				"link_layer_addr": "00:11:22:33:44:55",
			},
			"server_duid": map[string]interface{}{
				"type":            float64(2), // DUID-EN
				"enterprise_num":  float64(32473),
				"vendor_specific": []interface{}{float64(0xDE), float64(0xAD)},
			},
		},
	}
	spec := mapToFlowSpec(raw, "dhcpv6")
	if spec.DHCPv6 == nil {
		t.Fatalf("spec.DHCPv6 is nil")
	}
	c := spec.DHCPv6

	// Scenario must round-trip exactly.
	if c.Scenario != "sarr" {
		t.Errorf("Scenario = %q, want sarr", c.Scenario)
	}

	// Default* scalar fields.
	if c.DefaultLeasedAddr != "2001:db8::100" {
		t.Errorf("DefaultLeasedAddr = %q, want 2001:db8::100", c.DefaultLeasedAddr)
	}
	if c.DefaultIAID != 7 {
		t.Errorf("DefaultIAID = %d, want 7", c.DefaultIAID)
	}
	if c.DefaultPreferredLifetime != 3600 {
		t.Errorf("DefaultPreferredLifetime = %d, want 3600", c.DefaultPreferredLifetime)
	}
	if c.DefaultValidLifetime != 7200 {
		t.Errorf("DefaultValidLifetime = %d, want 7200", c.DefaultValidLifetime)
	}
	if c.DefaultT1 != 1800 {
		t.Errorf("DefaultT1 = %d, want 1800", c.DefaultT1)
	}
	if c.DefaultT2 != 2880 {
		t.Errorf("DefaultT2 = %d, want 2880", c.DefaultT2)
	}
	if c.DefaultPreference != 10 {
		t.Errorf("DefaultPreference = %d, want 10", c.DefaultPreference)
	}
	if c.DefaultStatusCode != 0 {
		t.Errorf("DefaultStatusCode = %d, want 0", c.DefaultStatusCode)
	}
	if c.DefaultStatusMessage != "Success" {
		t.Errorf("DefaultStatusMessage = %q, want Success", c.DefaultStatusMessage)
	}
	if c.DefaultInfoRefreshTime != 3600 {
		t.Errorf("DefaultInfoRefreshTime = %d, want 3600", c.DefaultInfoRefreshTime)
	}

	// Default* slice fields.
	wantORO := []uint16{23, 24, 31}
	if !reflect.DeepEqual(c.DefaultORO, wantORO) {
		t.Errorf("DefaultORO = %v, want %v", c.DefaultORO, wantORO)
	}
	wantDNS := []string{"2001:db8::53", "2001:db8::54"}
	if !reflect.DeepEqual(c.DefaultDNSServers, wantDNS) {
		t.Errorf("DefaultDNSServers = %v, want %v", c.DefaultDNSServers, wantDNS)
	}
	wantSearch := []string{"example.com", "test.example.com"}
	if !reflect.DeepEqual(c.DefaultDNSSearch, wantSearch) {
		t.Errorf("DefaultDNSSearch = %v, want %v", c.DefaultDNSSearch, wantSearch)
	}
	wantSNTP := []string{"2001:db8::123"}
	if !reflect.DeepEqual(c.DefaultSNTPServers, wantSNTP) {
		t.Errorf("DefaultSNTPServers = %v, want %v", c.DefaultSNTPServers, wantSNTP)
	}

	// ClientDUID (DUID-LLT).
	if c.ClientDUID == nil {
		t.Fatalf("ClientDUID is nil")
	}
	if c.ClientDUID.Type != 1 {
		t.Errorf("ClientDUID.Type = %d, want 1 (LLT)", c.ClientDUID.Type)
	}
	if c.ClientDUID.HardwareType != 1 {
		t.Errorf("ClientDUID.HardwareType = %d, want 1", c.ClientDUID.HardwareType)
	}
	if c.ClientDUID.Time != 100000 {
		t.Errorf("ClientDUID.Time = %d, want 100000", c.ClientDUID.Time)
	}
	if c.ClientDUID.LinkLayerAddr != "00:11:22:33:44:55" {
		t.Errorf("ClientDUID.LinkLayerAddr = %q, want 00:11:22:33:44:55", c.ClientDUID.LinkLayerAddr)
	}

	// ServerDUID (DUID-EN).
	if c.ServerDUID == nil {
		t.Fatalf("ServerDUID is nil")
	}
	if c.ServerDUID.Type != 2 {
		t.Errorf("ServerDUID.Type = %d, want 2 (EN)", c.ServerDUID.Type)
	}
	if c.ServerDUID.EnterpriseNum != 32473 {
		t.Errorf("ServerDUID.EnterpriseNum = %d, want 32473", c.ServerDUID.EnterpriseNum)
	}
	wantVS := []byte{0xDE, 0xAD}
	if !reflect.DeepEqual(c.ServerDUID.VendorSpecific, wantVS) {
		t.Errorf("ServerDUID.VendorSpecific = %v, want %v", c.ServerDUID.VendorSpecific, wantVS)
	}

	// Messages must be nil in scenario-only mode.
	if c.Messages != nil {
		t.Errorf("Messages should be nil in scenario-only mode, got %d messages", len(c.Messages))
	}

	// 端口默认已收敛至 ChainPlanner.ValidateSpec：mapToFlowSpec 产通用默认 80，
	// DHCPv6 547 由链规划器在 Plan 时补齐（统一架构 v3，不再有第二处默认）。
	if spec.DstPort != DefaultDstPort {
		t.Errorf("DstPort = %d, want %d (generic default; 547 applied by chain planner)", spec.DstPort, DefaultDstPort)
	}
}

// TestMapToFlowSpec_DHCPv6_Scenario_Relay verifies the relay scenario
// parses RelayConfig with all its fields. The relay scenario is special:
// it wraps the SARR dialog in RELAY-FORW/RELAY-REPL encapsulation (RFC 8415
// §20), so RelayConfig must be fully wired or the planner's validateScenario
// rejects it.
func TestMapToFlowSpec_DHCPv6_Scenario_Relay(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "fe80::1", "dst_ip": "fe80::2",
		"dhcpv6": map[string]interface{}{
			"scenario":            "relay",
			"default_leased_addr": "2001:db8::100",
			"relay_config": map[string]interface{}{
				"relay_ip":           "2001:db8::1",
				"relay_mac":          "00:aa:bb:cc:dd:ee",
				"hop_count":          float64(1),
				"interface_id":       []interface{}{float64(0x01), float64(0x02)},
				"include_client_mac": true,
			},
		},
	}
	spec := mapToFlowSpec(raw, "dhcpv6")
	if spec.DHCPv6 == nil {
		t.Fatalf("spec.DHCPv6 is nil")
	}
	c := spec.DHCPv6
	if c.Scenario != "relay" {
		t.Errorf("Scenario = %q, want relay", c.Scenario)
	}
	if c.RelayConfig == nil {
		t.Fatalf("RelayConfig is nil")
	}
	if c.RelayConfig.RelayIP != "2001:db8::1" {
		t.Errorf("RelayConfig.RelayIP = %q, want 2001:db8::1", c.RelayConfig.RelayIP)
	}
	if c.RelayConfig.RelayMAC != "00:aa:bb:cc:dd:ee" {
		t.Errorf("RelayConfig.RelayMAC = %q, want 00:aa:bb:cc:dd:ee", c.RelayConfig.RelayMAC)
	}
	if c.RelayConfig.HopCount != 1 {
		t.Errorf("RelayConfig.HopCount = %d, want 1", c.RelayConfig.HopCount)
	}
	wantIID := []byte{0x01, 0x02}
	if !reflect.DeepEqual(c.RelayConfig.InterfaceID, wantIID) {
		t.Errorf("RelayConfig.InterfaceID = %v, want %v", c.RelayConfig.InterfaceID, wantIID)
	}
	if !c.RelayConfig.IncludeClientMAC {
		t.Errorf("RelayConfig.IncludeClientMAC = false, want true")
	}
}

// TestMapToFlowSpec_DHCPv6_Scenario_AllValues verifies that all 10
// supported scenario values round-trip through the converter. Each value
// selects a different RFC 8415 state-machine dialog in the planner; if any
// value is silently dropped or mangled, the planner falls back to manual
// mode and emits nothing.
func TestMapToFlowSpec_DHCPv6_Scenario_AllValues(t *testing.T) {
	scenarios := []string{
		"sarr", "sarr_rapid", "renew", "rebind", "release",
		"decline", "confirm", "information_request", "reconfigure", "relay",
	}
	for _, sc := range scenarios {
		t.Run(sc, func(t *testing.T) {
			raw := map[string]interface{}{
				"src_ip": "fe80::1", "dst_ip": "fe80::2",
				"dhcpv6": map[string]interface{}{
					"scenario": sc,
				},
			}
			spec := mapToFlowSpec(raw, "dhcpv6")
			if spec.DHCPv6 == nil {
				t.Fatalf("spec.DHCPv6 is nil for scenario %q", sc)
			}
			if spec.DHCPv6.Scenario != sc {
				t.Errorf("Scenario = %q, want %q", spec.DHCPv6.Scenario, sc)
			}
		})
	}
}

// TestMapToFlowSpec_DHCPv6_NoScenario_ManualMode verifies that when
// scenario is absent, the converter produces an empty Scenario (manual mode)
// and correctly parses the Messages list. The convert layer does NOT enforce
// the Scenario/Messages mutual exclusion (that is the planner's job in
// validateScenario); it must parse both independently.
func TestMapToFlowSpec_DHCPv6_NoScenario_ManualMode(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "fe80::1", "dst_ip": "fe80::2",
		"dhcpv6": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{
					"msg_type":       float64(1), // SOLICIT
					"direction":      "up",
					"transaction_id": []interface{}{float64(0x01), float64(0x02), float64(0x03)},
					"options": []interface{}{
						map[string]interface{}{
							"code": float64(1), // ClientID
							"data": []interface{}{float64(0x00), float64(0x01)},
						},
					},
				},
				map[string]interface{}{
					"msg_type":  float64(7), // REPLY
					"direction": "down",
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "dhcpv6")
	if spec.DHCPv6 == nil {
		t.Fatalf("spec.DHCPv6 is nil")
	}
	c := spec.DHCPv6
	if c.Scenario != "" {
		t.Errorf("Scenario = %q, want empty (manual mode)", c.Scenario)
	}
	if len(c.Messages) != 2 {
		t.Fatalf("Messages = %d, want 2", len(c.Messages))
	}
	if c.Messages[0].MsgType != 1 {
		t.Errorf("Messages[0].MsgType = %d, want 1 (SOLICIT)", c.Messages[0].MsgType)
	}
	if c.Messages[0].Direction != "up" {
		t.Errorf("Messages[0].Direction = %q, want up", c.Messages[0].Direction)
	}
	wantXID := [3]byte{0x01, 0x02, 0x03}
	if c.Messages[0].TransactionID != wantXID {
		t.Errorf("Messages[0].TransactionID = %v, want %v", c.Messages[0].TransactionID, wantXID)
	}
	if len(c.Messages[0].Options) != 1 {
		t.Fatalf("Messages[0].Options = %d, want 1", len(c.Messages[0].Options))
	}
	if c.Messages[0].Options[0].Code != 1 {
		t.Errorf("Messages[0].Options[0].Code = %d, want 1 (ClientID)", c.Messages[0].Options[0].Code)
	}
	wantData := []byte{0x00, 0x01}
	if !reflect.DeepEqual(c.Messages[0].Options[0].Data, wantData) {
		t.Errorf("Messages[0].Options[0].Data = %v, want %v", c.Messages[0].Options[0].Data, wantData)
	}
	if c.Messages[1].MsgType != 7 {
		t.Errorf("Messages[1].MsgType = %d, want 7 (REPLY)", c.Messages[1].MsgType)
	}
}

// TestMapToFlowSpec_DHCPv6_NilSubMap verifies the failure path: when no
// "dhcpv6" key is present, spec.DHCPv6 is nil (not a zero-valued pointer),
// so the planner skips DHCPv6 entirely.
func TestMapToFlowSpec_DHCPv6_NilSubMap(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "fe80::1", "dst_ip": "fe80::2",
	}
	spec := mapToFlowSpec(raw, "dhcpv6")
	if spec.DHCPv6 != nil {
		t.Errorf("spec.DHCPv6 should be nil when no dhcpv6 sub-map, got %+v", spec.DHCPv6)
	}
	// 端口默认已收敛至 ChainPlanner.ValidateSpec：mapToFlowSpec 产通用默认 80，
	// DHCPv6 547 由链规划器在 Plan 时补齐。
	if spec.DstPort != DefaultDstPort {
		t.Errorf("DstPort = %d, want %d (generic default; 547 applied by chain planner)", spec.DstPort, DefaultDstPort)
	}
}

// TestMapToFlowSpec_DHCPv6_Scenario_DefaultsZero verifies that when scenario
// is set but no Default* fields are provided, all Default* fields are
// zero-valued. The planner applies its own defaults (IAID=1, T1=1800, etc.)
// at Plan time; the converter must not invent values. This guards against a
// field silently defaulting to a non-zero value that masks a missing user
// input.
func TestMapToFlowSpec_DHCPv6_Scenario_DefaultsZero(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "fe80::1", "dst_ip": "fe80::2",
		"dhcpv6": map[string]interface{}{
			"scenario": "information_request",
		},
	}
	spec := mapToFlowSpec(raw, "dhcpv6")
	if spec.DHCPv6 == nil {
		t.Fatalf("spec.DHCPv6 is nil")
	}
	c := spec.DHCPv6
	if c.Scenario != "information_request" {
		t.Errorf("Scenario = %q, want information_request", c.Scenario)
	}
	if c.DefaultLeasedAddr != "" {
		t.Errorf("DefaultLeasedAddr = %q, want empty", c.DefaultLeasedAddr)
	}
	if c.DefaultIAID != 0 {
		t.Errorf("DefaultIAID = %d, want 0", c.DefaultIAID)
	}
	if c.DefaultPreferredLifetime != 0 {
		t.Errorf("DefaultPreferredLifetime = %d, want 0", c.DefaultPreferredLifetime)
	}
	if c.DefaultValidLifetime != 0 {
		t.Errorf("DefaultValidLifetime = %d, want 0", c.DefaultValidLifetime)
	}
	if c.DefaultT1 != 0 {
		t.Errorf("DefaultT1 = %d, want 0", c.DefaultT1)
	}
	if c.DefaultT2 != 0 {
		t.Errorf("DefaultT2 = %d, want 0", c.DefaultT2)
	}
	if c.DefaultPreference != 0 {
		t.Errorf("DefaultPreference = %d, want 0", c.DefaultPreference)
	}
	if c.DefaultStatusCode != 0 {
		t.Errorf("DefaultStatusCode = %d, want 0", c.DefaultStatusCode)
	}
	if c.DefaultStatusMessage != "" {
		t.Errorf("DefaultStatusMessage = %q, want empty", c.DefaultStatusMessage)
	}
	if c.DefaultORO != nil {
		t.Errorf("DefaultORO = %v, want nil", c.DefaultORO)
	}
	if c.DefaultDNSServers != nil {
		t.Errorf("DefaultDNSServers = %v, want nil", c.DefaultDNSServers)
	}
	if c.DefaultDNSSearch != nil {
		t.Errorf("DefaultDNSSearch = %v, want nil", c.DefaultDNSSearch)
	}
	if c.DefaultSNTPServers != nil {
		t.Errorf("DefaultSNTPServers = %v, want nil", c.DefaultSNTPServers)
	}
	if c.DefaultInfoRefreshTime != 0 {
		t.Errorf("DefaultInfoRefreshTime = %d, want 0", c.DefaultInfoRefreshTime)
	}
	if c.ClientDUID != nil {
		t.Errorf("ClientDUID = %+v, want nil", c.ClientDUID)
	}
	if c.ServerDUID != nil {
		t.Errorf("ServerDUID = %+v, want nil", c.ServerDUID)
	}
	if c.RelayConfig != nil {
		t.Errorf("RelayConfig = %+v, want nil", c.RelayConfig)
	}
}

// TestMapToFlowSpec_DHCPv6_ExplicitDstPort verifies that an explicit
// dst_port in the top-level map overrides the DHCPv6 default of 547.
func TestMapToFlowSpec_DHCPv6_ExplicitDstPort(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "fe80::1", "dst_ip": "fe80::2",
		"dst_port": float64(1547),
		"dhcpv6": map[string]interface{}{
			"scenario": "sarr",
		},
	}
	spec := mapToFlowSpec(raw, "dhcpv6")
	if spec.DstPort != 1547 {
		t.Errorf("DstPort = %d, want 1547 (explicit override)", spec.DstPort)
	}
}
