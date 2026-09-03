package core

import (
	"testing"
)

// TestProxyMigrationAllowlist ensures the conversion proxy's allowlist is the single
// authoritative source of "which protocols are migrated to layer-chain architecture".
// A protocol that lands in the allowlist but lacks a chain endpoint OR a flat fallback
// is a config-architecture drift (per CLAUDE.md "no independent implementations").
// This is the policy lock; concrete equivalence is covered by TestFlatChainEquivalence
// for each allowlisted protocol.
func TestProxyMigrationAllowlist(t *testing.T) {
	want := map[string]bool{
		"dns": true, "ntp": true, "snmp": true, "syslog": true,
		"ssdp": true, "mdns": true,
		"dhcp": true, "dhcpv6": true,
		// Batch-2 候选（高用例量，优先迁移）
		"tftp": true, "modbus": true,
	}
	// radius must NOT be in the allowlist: it has no layer generator yet
	// (legacy-only), so allowing it would claim a chain migration that
	// does not exist.
	if isMigrationCandidate("radius") {
		t.Errorf("radius must not be in migration allowlist (no layer generator; legacy-only path)")
	}
	for proto := range want {
		if !isMigrationCandidate(proto) {
			t.Errorf("protocol %q must be in migration allowlist (config-architecture rule)", proto)
		}
	}
}
