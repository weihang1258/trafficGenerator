package core

import "encoding/json"

// parseSubconfigJSON decodes a protocol sub-map (e.g. cfg["snmp"]) into a
// typed config via json roundtrip (json.Marshal → json.Unmarshal). On decode
// error the message is appended to spec.ValidationErrors (the config field
// stays nil — same semantics as the inline boilerplate it replaces). On
// success *dst holds the decoded value.
//
// T is the pointer config type (e.g. *SNMPConfig), dst is the FlowSpec
// field's address (e.g. &spec.SNMP).
//
// This is the single shared helper for the protocols whose case bodies were
// pure json-roundtrip boilerplate (stun/rtmfp/amqp/http_flv/hls/hds/gbt/
// getwork/stratum/ethmining/igmp/ospf/pim/isis/vxlan/geneve/nvgre/openwire/
// ams/swarm/gnutella/mms/opcua/s7/iec104/bgp/moxa/someip/tns/mongodb/
// dameng/cql/ldp/pcep/drda/thrift/cflow). CLAUDE.md "no independent
// implementations": the marshal→unmarshal→ValidationErrors sequence lives
// here exactly once.
func parseSubconfigJSON[T any](spec *FlowSpec, sub map[string]interface{}, name string, dst *T) {
	raw, err := json.Marshal(sub)
	if err != nil {
		spec.ValidationErrors = append(spec.ValidationErrors, name+": marshal: "+err.Error())
		return
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		spec.ValidationErrors = append(spec.ValidationErrors, name+": "+err.Error())
	}
}

// setDefaultDstPort sets spec.DstPort to port only when the user has not
// specified one. This replaces the repeated boilerplate:
//
//	if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
//		spec.DstPort = <port>
//	}
//
// The pattern appears ~60 times in mapToFlowSpec. Keeping it in a named helper
// makes the intent explicit and avoids copy-paste errors.
func setDefaultDstPort(spec *FlowSpec, cfg map[string]interface{}, port uint16) {
	if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
		spec.DstPort = port
	}
}
