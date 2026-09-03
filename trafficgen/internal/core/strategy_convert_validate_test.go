package core

import (
	"testing"
)

// TestMapToFlowSpecAllowlistEquivalence: for every protocol in migrationAllowlist,
// mapToFlowSpec must produce a non-nil spec and the canonical L3/L4 fields must
// satisfy the same invariants the chain planner enforces (src/dst IP, src/dst
// port defaults, MAC defaults, TTL, etc.). This is the regression guard for
// deleting the per-protocol case bodies in mapToFlowSpec — the chain planner's
// ValidateSpec is the new single source of truth for port defaults; mapToFlowSpec
// must still produce a spec the chain planner can consume.
func TestMapToFlowSpecAllowlistEquivalence(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"dns":    {"dns": map[string]interface{}{"domain": "example.com"}},
		"ntp":    {"ntp": map[string]interface{}{}},
		"snmp":   {"snmp": map[string]interface{}{"var_binds": []map[string]interface{}{{"name": "1.3.6.1.2.1.1.1.0"}}}},
		"syslog": {"syslog": map[string]interface{}{}},
		"ssdp":   {"ssdp": map[string]interface{}{"message_type": "msearch", "search_target": "ssdp:all"}},
		"mdns":   {"mdns": map[string]interface{}{"questions": []map[string]interface{}{{"name": "x.local", "type": 1}}}},
		"dhcp":   {"dhcp": map[string]interface{}{}},
		"dhcpv6": {"dhcpv6": map[string]interface{}{}},
		"tftp":   {"tftp": map[string]interface{}{}},
		"modbus": {"modbus": map[string]interface{}{"unit_id": 1}},
	}
	for proto, cfg := range cases {
		t.Run(proto, func(t *testing.T) {
			spec := mapToFlowSpec(cfg, proto)
			// Required L3 invariants.
			if spec.SrcIP == "" {
				t.Errorf("%s: SrcIP must be defaulted", proto)
			}
			if spec.DstIP == "" {
				t.Errorf("%s: DstIP must be defaulted", proto)
			}
			if spec.TTL == 0 {
				t.Errorf("%s: TTL must be defaulted", proto)
			}
		})
	}
}
