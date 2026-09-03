package core

// convert_proxy.go: the single dispatcher for converting a strategy config map to
// a FlowSpec. It documents and enforces the canonical config-architecture boundary:
//
//  1. cfg["layers"] present → use the chain path (engine routes to BuildLayersPlanner
//     which constructs a per-task ChainPlanner from the layers config; this is the
//     only sanctioned way to drive the chain-driven generation).
//
//  2. protocol is in migrationAllowlist (no "layers" key, legacy flat config) → fall
//     through to mapToFlowSpec, which still parses the flat protocol sub-configs
//     (cfg["dns"]/cfg["snmp"]/...) into spec.DNS/spec.SNMP/etc. Layer-chain
//     registration + ValidateSpec on ChainPlanner.Plan() takes care of all layer
//     defaults (port defaults, schema defaults) — mapToFlowSpec should NOT duplicate
//     those defaults.
//
//  3. protocol NOT in allowlist (e.g. ssh, mysql, mqtt) → legacy flat path. The
//     protocol keeps a legacy NewPlanner() registration in main.go until a future
//     migration brings it under the layer-chain architecture.
//
// The migration allowlist is the single source of truth for "which protocols are
// layer-chain driven" and is read by:
//   - the REST create-strategy whitelist (no — strategy creation accepts all
//     allowed protocols, allowlist is internal to the converter)
//   - the engine layer-planner factory (only invoked when cfg["layers"] is set)
//   - this proxy, to know whether a flat config for a migrated protocol is
//     still acceptable or should be rejected with a "use layers config" error.
//
// Per CLAUDE.md "no independent implementations": this is the only place in core
// that maps (protocol, config shape) → routing decision. Every other site
// (REST handler, MCP server, worker dispatch) defers to the engine + planner.
func isMigrationCandidate(protocol string) bool {
	return migrationAllowlist[protocol]
}

// migrationAllowlist lists protocols whose flat configs are still accepted by
// mapToFlowSpec (the chain planner is registered in main.go and the per-task
// ChainPlanner applies the layer-chain semantics at Plan() time). New flat
// keys for these protocols are accepted to preserve backward compatibility;
// new code should use the "layers" config shape documented in
// docs/protocol-designs/18-layer-config-design.md.
var migrationAllowlist = map[string]bool{
	// Batch 1: stateless UDP terminal protocols with no chain-edge cases.
	// radius 暂不在列：无 layer 生成器（仍走 legacy NewPlanner），
	// 其 DstPort 1812/1813 默认留在 mapToFlowSpec。
	"dns": true, "ntp": true, "snmp": true, "syslog": true,
	"ssdp": true, "mdns": true,
	// DHCP/dhcpv6: chain planner registered; per-direction port resolution
	// happens at Plan() time so mapToFlowSpec should NOT pre-set DstPort.
	"dhcp": true, "dhcpv6": true,
	// Batch 2: high-case-count terminal protocols.
	"tftp": true, "modbus": true,
}
