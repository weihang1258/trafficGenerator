package mcp

import (
	"reflect"
	"strings"
	"testing"
)

// fieldSchemaDescription extracts the `jsonschema:"..."` tag value for field `fieldName`
// from the struct named `typeName` in the mcp package. Returns "" if not found.
//
// We use reflect + struct tag lookup so the test asserts the literal text the
// LLM sees in the tool schema — if the description string changes, the test
// catches the change.
func fieldSchemaDescription(t *testing.T, typeName, fieldName string) string {
	t.Helper()
	switch typeName {
	case "generateTrafficInput":
		s := generateTrafficInput{}
		return extractSchemaTag(t, reflect.TypeOf(s), fieldName)
	case "replayPcapInput":
		s := replayPcapInput{}
		return extractSchemaTag(t, reflect.TypeOf(s), fieldName)
	case "manageStrategiesInput":
		s := manageStrategiesInput{}
		return extractSchemaTag(t, reflect.TypeOf(s), fieldName)
	case "managePcapsInput":
		s := managePcapsInput{}
		return extractSchemaTag(t, reflect.TypeOf(s), fieldName)
	}
	t.Fatalf("unknown type %s", typeName)
	return ""
}

func extractSchemaTag(t *testing.T, typ reflect.Type, fieldName string) string {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Name == fieldName {
			return f.Tag.Get("jsonschema")
		}
	}
	t.Fatalf("type %s has no field %s", typ.Name(), fieldName)
	return ""
}

// TestGenerateTraffic_ConfigSchemaMentionsSrcPort verifies that the
// Config field description on generateTrafficInput mentions src_port as
// required for tcp/udp. Without this hint, LLMs commonly omit src_port and
// the task fails with a confusing "source port is required" error.
//
// Pre-fix description: "strategy config (protocol-specific)"
// Post-fix description must mention src_port for tcp/udp.
func TestGenerateTraffic_ConfigSchemaMentionsSrcPort(t *testing.T) {
	got := fieldSchemaDescription(t, "generateTrafficInput", "Config")
	if !strings.Contains(got, "src_port") {
		t.Errorf("generateTrafficInput.Config jsonschema = %q; must mention 'src_port' for tcp/udp", got)
	}
	if !strings.Contains(got, "dst_port") {
		t.Errorf("generateTrafficInput.Config jsonschema = %q; must mention 'dst_port'", got)
	}
}

// TestManageStrategies_ConfigSchemaMentionsSrcPort verifies the same hint is
// present on the manageStrategies tool's Config field (for create/update).
func TestManageStrategies_ConfigSchemaMentionsSrcPort(t *testing.T) {
	got := fieldSchemaDescription(t, "manageStrategiesInput", "Config")
	if !strings.Contains(got, "src_port") {
		t.Errorf("manageStrategiesInput.Config jsonschema = %q; must mention 'src_port' for tcp/udp", got)
	}
}

// TestReplayPcap_SpeedSchemaMentionsStringBPS verifies that the Speed field
// on replayPcapInput mentions that bps must be a string like "1000" or "1g",
// NOT a number. Without this hint, LLMs pass bps:1000 (number) and the backend
// rejects with "cannot unmarshal number into Go struct field .speed.bps of type string".
func TestReplayPcap_SpeedSchemaMentionsStringBPS(t *testing.T) {
	got := fieldSchemaDescription(t, "replayPcapInput", "Speed")
	if !strings.Contains(got, "string") {
		t.Errorf("replayPcapInput.Speed jsonschema = %q; must mention 'string' for bps", got)
	}
	if !strings.Contains(got, "bps") {
		t.Errorf("replayPcapInput.Speed jsonschema = %q; must mention 'bps'", got)
	}
	// Must specifically warn against numbers.
	lower := strings.ToLower(got)
	if !strings.Contains(lower, "not a number") {
		t.Errorf("replayPcapInput.Speed jsonschema = %q; must warn that bps is NOT a number", got)
	}
}

// TestManagePcaps_ExtractRulesSchemaMentionsLayerFields verifies that the
// ExtractRules field on managePcapsInput mentions layer field names
// (src_ip, dst_port, seq, etc.), not model field names (SrcIP, DstPort).
func TestManagePcaps_ExtractRulesSchemaMentionsLayerFields(t *testing.T) {
	got := fieldSchemaDescription(t, "managePcapsInput", "ExtractRules")
	if !strings.Contains(got, "src_ip") {
		t.Errorf("managePcapsInput.ExtractRules jsonschema = %q; must mention 'src_ip' (layer field)", got)
	}
	if !strings.Contains(got, "dst_port") {
		t.Errorf("managePcapsInput.ExtractRules jsonschema = %q; must mention 'dst_port' (layer field)", got)
	}
	if !strings.Contains(got, "layer field") {
		t.Errorf("managePcapsInput.ExtractRules jsonschema = %q; must mention 'layer field'", got)
	}
}

// TestManageStrategies_ConfigSchemaMentionsL2L3Defaults verifies the Config
// description mentions the L2/L3 field defaults so LLMs know:
//   - packets carry trafficgen markers (02:00:00:00:00:0x MAC, 0xb8 TOS)
//   - defaults are overridable; explicit 0 is honored
//   - the tcpdump filter expression for finding trafficgen packets
//
// Per CLAUDE.md testing policy §1: every default is a spec row needing a
// schema-level test so LLM calls don't regress to sending zero-valued MACs.
func TestManageStrategies_ConfigSchemaMentionsL2L3Defaults(t *testing.T) {
	got := fieldSchemaDescription(t, "manageStrategiesInput", "Config")
	if !strings.Contains(got, "02:00:00:00:00:01") {
		t.Errorf("manageStrategiesInput.Config jsonschema = %q; must mention default src_mac '02:00:00:00:00:01'", got)
	}
	if !strings.Contains(got, "0x2E") {
		t.Errorf("manageStrategiesInput.Config jsonschema = %q; must mention default dscp '0x2E'", got)
	}
	if !strings.Contains(got, "DF") {
		t.Errorf("manageStrategiesInput.Config jsonschema = %q; must mention default flags=DF", got)
	}
	if !strings.Contains(got, "0xb8") {
		t.Errorf("manageStrategiesInput.Config jsonschema = %q; must mention TOS byte 0xb8 (for tcpdump filter)", got)
	}
	if !strings.Contains(got, "tcpdump") {
		t.Errorf("manageStrategiesInput.Config jsonschema = %q; must mention tcpdump filter", got)
	}
}

// TestGenerateTraffic_ConfigSchemaMentionsL2L3Defaults verifies the same
// hint is present on the workflow tool's Config field.
func TestGenerateTraffic_ConfigSchemaMentionsL2L3Defaults(t *testing.T) {
	got := fieldSchemaDescription(t, "generateTrafficInput", "Config")
	if !strings.Contains(got, "02:00:00:00:00:01") {
		t.Errorf("generateTrafficInput.Config jsonschema = %q; must mention default src_mac '02:00:00:00:00:01'", got)
	}
	if !strings.Contains(got, "0x2E") {
		t.Errorf("generateTrafficInput.Config jsonschema = %q; must mention default dscp '0x2E'", got)
	}
	if !strings.Contains(got, "DF") {
		t.Errorf("generateTrafficInput.Config jsonschema = %q; must mention default flags=DF", got)
	}
}

