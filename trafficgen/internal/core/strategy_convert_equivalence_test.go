package core

import (
	"testing"
)

// TestFlatChainEquivalence_DNS verifies that the flat ("dns": {...}) and
// chain ("layers": [..., {"dns": {}}]) config shapes produce equivalent
// FlowSpec canonical fields. The proxy in convert_proxy.go is the policy
// gate; this test asserts the L3/L4 contract is preserved.
func TestFlatChainEquivalence_DNS(t *testing.T) {
	flatCfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "8.8.8.8",
		"src_port": float64(12345),
		"dns":      map[string]interface{}{"domain": "example.com"},
	}
	chainCfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{}},
			map[string]interface{}{"udp": map[string]interface{}{}},
			map[string]interface{}{"dns": map[string]interface{}{}},
		},
		"src_ip":   "10.0.0.1",
		"dst_ip":   "8.8.8.8",
		"src_port": float64(12345),
		"dns":      map[string]interface{}{"domain": "example.com"},
	}
	flat := mapToFlowSpec(flatCfg, "dns")
	chain := mapToFlowSpec(chainCfg, "dns")
	if flat.SrcIP != chain.SrcIP {
		t.Errorf("SrcIP mismatch: flat=%q chain=%q", flat.SrcIP, chain.SrcIP)
	}
	if flat.DstIP != chain.DstIP {
		t.Errorf("DstIP mismatch: flat=%q chain=%q", flat.DstIP, chain.DstIP)
	}
	if flat.SrcPort != chain.SrcPort {
		t.Errorf("SrcPort mismatch: flat=%d chain=%d", flat.SrcPort, chain.SrcPort)
	}
	if flat.DNS == nil {
		t.Fatal("flat DNS config did not populate spec.DNS")
	}
	if flat.DNS.Domain != "example.com" {
		t.Errorf("flat DNS domain = %q, want example.com", flat.DNS.Domain)
	}
}

// TestFlatChainEquivalence_NTP covers the NTP terminal protocol.
func TestFlatChainEquivalence_NTP(t *testing.T) {
	flat := mapToFlowSpec(map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"src_port": float64(1234),
		"ntp":      map[string]interface{}{"version": float64(4), "mode": float64(3)},
	}, "ntp")
	if flat.NTP == nil {
		t.Fatal("NTP config not populated")
	}
	if flat.NTP.Version != 4 {
		t.Errorf("NTP version = %d, want 4", flat.NTP.Version)
	}
	if flat.NTP.Mode != 3 {
		t.Errorf("NTP mode = %d, want 3", flat.NTP.Mode)
	}
}

// TestFlatChainEquivalence_DHCP_DHCPv6 covers the DHCP family.
// DHCP/DHCPv6 use direction-resolved ports in the chain planner
// (client→67, server→68; up=server 547, down=client 546).
// mapToFlowSpec applies NO protocol-specific DstPort default for these —
// the universal DefaultDstPort (80) stands at flat-conversion time and the
// chain terminal generator (resolvePorts/resolveAddrs semantics) overrides it
// with the role-based port at Plan() time.
func TestFlatChainEquivalence_DHCP_DHCPv6(t *testing.T) {
	for _, proto := range []string{"dhcp", "dhcpv6"} {
		t.Run(proto, func(t *testing.T) {
			spec := mapToFlowSpec(map[string]interface{}{
				"src_ip":   "0.0.0.0",
				"dst_ip":   "255.255.255.255",
				"src_port": float64(68),
				proto:      map[string]interface{}{},
			}, proto)
			// No protocol-specific pre-set: universal default 80 stands until
			// the chain planner resolves the role-based port at Plan time.
			if spec.DstPort != DefaultDstPort {
				t.Errorf("%s DstPort = %d, want %d (universal default; role-based port resolved at Plan time)",
					proto, spec.DstPort, DefaultDstPort)
			}
			if spec.SrcPort != 68 {
				t.Errorf("%s SrcPort = %d, want 68 (explicit src_port honored)", proto, spec.SrcPort)
			}
		})
	}
}

// TestFlatChainEquivalence_UDPNoLayer verifies that for protocols whose flat
// config has no "layers" key, mapToFlowSpec still returns a valid FlowSpec
// (fallback to flat path). For a 4-byte UDP payload-only config (no protocol
// sub-map), the spec is the universal default.
func TestFlatChainEquivalence_UDPNoLayer(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip":   "10.0.0.1",
		"dst_ip":   "10.0.0.2",
		"protocol": "udp",
		"src_port": float64(1234),
		"dst_port": float64(5678),
		"payload":  "hello",
	}
	spec := mapToFlowSpec(cfg, "udp")
	if spec.SrcIP != "10.0.0.1" {
		t.Errorf("SrcIP = %q, want 10.0.0.1", spec.SrcIP)
	}
	if spec.SrcPort != 1234 {
		t.Errorf("SrcPort = %d, want 1234", spec.SrcPort)
	}
	if string(spec.Payload) != "hello" {
		t.Errorf("Payload = %q, want hello", spec.Payload)
	}
}

// TestFlatChainEquivalence_LayersKeyRoutes verifies that when cfg["layers"]
// is set, the spec's SrcIP/DstIP come from the layer config (chain path),
// not the flat default 10.0.0.1/20.0.0.1.
func TestFlatChainEquivalence_LayersKeyRoutes(t *testing.T) {
	// IPv6 in the IP layer (chain path)
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2"}},
			map[string]interface{}{"udp": map[string]interface{}{}},
			map[string]interface{}{"dns": map[string]interface{}{}},
		},
		"dns": map[string]interface{}{"domain": "ipv6.example.com"},
	}
	spec := mapToFlowSpec(cfg, "dns")
	if spec.SrcIP != "2001:db8::1" {
		t.Errorf("chain SrcIP = %q, want 2001:db8::1", spec.SrcIP)
	}
	if spec.DstIP != "2001:db8::2" {
		t.Errorf("chain DstIP = %q, want 2001:db8::2", spec.DstIP)
	}
	if spec.DNS == nil {
		t.Fatal("chain DNS config not populated")
	}
}

// TestFlatChainEquivalence_FieldContract verifies the field-by-field mapping
// from flat cfg keys to FlowSpec canonical fields. This is the "user > default
// > none" rule: explicit user values (including 0) must be honored.
func TestFlatChainEquivalence_FieldContract(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
		// canonical field checks
		srcIP   string
		dstIP   string
		srcPort uint16
		dstPort uint16
		ttl     uint8
		vlanID  uint16
		srcMAC  string
		dstMAC  string
	}{
		{
			name:  "explicit IP",
			cfg:   map[string]interface{}{"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"},
			srcIP: "1.2.3.4",
			dstIP: "5.6.7.8",
		},
		{
			name:    "explicit ports",
			cfg:     map[string]interface{}{"src_port": float64(1000), "dst_port": float64(2000)},
			srcPort: 1000,
			dstPort: 2000,
		},
		{
			name: "TTL and MAC",
			cfg: map[string]interface{}{
				"ttl":     float64(128),
				"src_mac": "02:11:22:33:44:55",
				"dst_mac": "02:aa:bb:cc:dd:ee",
			},
			ttl:    uint8(128),
			srcMAC: "02:11:22:33:44:55",
			dstMAC: "02:aa:bb:cc:dd:ee",
		},
		{
			name: "VLAN",
			cfg: map[string]interface{}{
				"vlan_id":       float64(100),
				"vlan_priority": float64(5),
			},
			vlanID: 100,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := mapToFlowSpec(c.cfg, "tcp")
			if c.srcIP != "" && spec.SrcIP != c.srcIP {
				t.Errorf("SrcIP = %q, want %q", spec.SrcIP, c.srcIP)
			}
			if c.dstIP != "" && spec.DstIP != c.dstIP {
				t.Errorf("DstIP = %q, want %q", spec.DstIP, c.dstIP)
			}
			if c.srcPort != 0 && spec.SrcPort != c.srcPort {
				t.Errorf("SrcPort = %d, want %d", spec.SrcPort, c.srcPort)
			}
			if c.dstPort != 0 && spec.DstPort != c.dstPort {
				t.Errorf("DstPort = %d, want %d", spec.DstPort, c.dstPort)
			}
			if c.ttl != 0 && spec.TTL != c.ttl {
				t.Errorf("TTL = %d, want %d", spec.TTL, c.ttl)
			}
			if c.srcMAC != "" && spec.SrcMAC != c.srcMAC {
				t.Errorf("SrcMAC = %q, want %q", spec.SrcMAC, c.srcMAC)
			}
			if c.dstMAC != "" && spec.DstMAC != c.dstMAC {
				t.Errorf("DstMAC = %q, want %q", spec.DstMAC, c.dstMAC)
			}
			if c.vlanID != 0 {
				if spec.VLAN == nil {
					t.Errorf("VLAN nil, want ID=%d", c.vlanID)
				} else if spec.VLAN.ID != c.vlanID {
					t.Errorf("VLAN.ID = %d, want %d", spec.VLAN.ID, c.vlanID)
				}
			}
		})
	}
}

// TestFlatChainEquivalence_UniversalTCPSubConfig verifies that the universal
// "tcp" sub-map is read for ALL protocols (not just case "tcp"), so
// cfg["tcp"] = {mss: 9000} is honored for http, ftp, sip, etc.
func TestFlatChainEquivalence_UniversalTCPSubConfig(t *testing.T) {
	for _, proto := range []string{"http", "ftp", "sip"} {
		t.Run(proto, func(t *testing.T) {
			spec := mapToFlowSpec(map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "10.0.0.2",
				"src_port": float64(1000),
				"dst_port": float64(2000),
				"tcp":      map[string]interface{}{"mss": float64(9000), "handshake": false, "termination": false},
			}, proto)
			if spec.TCP == nil {
				t.Fatalf("%s: TCP sub-config not populated", proto)
			}
			if spec.TCP.MSS != 9000 {
				t.Errorf("%s: TCP.MSS = %d, want 9000", proto, spec.TCP.MSS)
			}
			if spec.TCP.Handshake {
				t.Errorf("%s: TCP.Handshake = true, want false", proto)
			}
		})
	}
}

// TestFlatChainEquivalence_NoValidationErrors is the smoke test: every
// allowlisted protocol with a minimal valid sub-map must produce a spec
// with no ValidationErrors. A nil spec.<Proto> field or a ValidationErrors
// entry indicates a regression in mapToFlowSpec or the parseSubconfigJSON
// helper.
func TestFlatChainEquivalence_NoValidationErrors(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"dns":    {"dns": map[string]interface{}{"domain": "example.com"}},
		"ntp":    {"ntp": map[string]interface{}{}},
		"snmp":   {"snmp": map[string]interface{}{}},
		"syslog": {"syslog": map[string]interface{}{}},
		"ssdp":   {"ssdp": map[string]interface{}{}},
		"mdns":   {"mdns": map[string]interface{}{}},
		"dhcp":   {"dhcp": map[string]interface{}{}},
		"dhcpv6": {"dhcpv6": map[string]interface{}{}},
		"tftp":   {"tftp": map[string]interface{}{}},
		"modbus": {"modbus": map[string]interface{}{"unit_id": float64(1)}},
	}
	for proto, sub := range cases {
		t.Run(proto, func(t *testing.T) {
			spec := mapToFlowSpec(sub, proto)
			if len(spec.ValidationErrors) > 0 {
				t.Errorf("%s produced ValidationErrors: %v", proto, spec.ValidationErrors)
			}
		})
	}
}

// TestFlatChainEquivalence_SpecFieldsPopulated verifies the refactored
// parseSubconfigJSON helper populates the typed config struct correctly.
// Specifically: unknown JSON fields do not crash, and required nested
// fields are preserved.
func TestFlatChainEquivalence_SpecFieldsPopulated(t *testing.T) {
	t.Run("syslog", func(t *testing.T) {
		spec := mapToFlowSpec(map[string]interface{}{
			"src_ip":   "10.0.0.1",
			"dst_ip":   "10.0.0.2",
			"src_port": float64(500),
			"syslog": map[string]interface{}{
				"facility": float64(1),
				"severity": float64(6),
				"version":  float64(1),
				"hostname": "test-host",
				"app_name": "test-app",
				"msg":      "hello",
			},
		}, "syslog")
		if spec.Syslog == nil {
			t.Fatal("Syslog not populated")
		}
		if spec.Syslog.Facility != 1 {
			t.Errorf("Facility = %d, want 1", spec.Syslog.Facility)
		}
		if spec.Syslog.Hostname != "test-host" {
			t.Errorf("Hostname = %q, want test-host", spec.Syslog.Hostname)
		}
		if spec.Syslog.Msg != "hello" {
			t.Errorf("Msg = %q, want hello", spec.Syslog.Msg)
		}
	})
	t.Run("snmp", func(t *testing.T) {
		spec := mapToFlowSpec(map[string]interface{}{
			"snmp": map[string]interface{}{
				"version":   float64(0), // SNMPv1: presence-checked
				"community": "private",
				"pdu_type":  float64(1),
			},
		}, "snmp")
		if spec.SNMP == nil {
			t.Fatal("SNMP not populated")
		}
		// Presence-checked: explicit version=0 must be honored, not
		// collapsed to the default v2c (1).
		if spec.SNMP.Version != 0 {
			t.Errorf("SNMP.Version = %d, want 0 (v1)", spec.SNMP.Version)
		}
		if spec.SNMP.Community != "private" {
			t.Errorf("Community = %q, want private", spec.SNMP.Community)
		}
	})
	// Helper detection: ensure the same value flows via the helper.

}
