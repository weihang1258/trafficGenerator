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
	case "outputConfigInput":
		s := outputConfigInput{}
		return extractSchemaTag(t, reflect.TypeOf(s), fieldName)
	case "portGroupPort":
		s := portGroupPort{}
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

// TestManageStrategies_ConfigSchema_PointsToLayerSchemaForDefaults verifies
// the Config description routes default discovery to flowb_query_layers.
// The old text inlined flat-era defaults (src_mac=02:00:00:00:00:01,
// dscp=0x08, ip_flags=DF, tcpdump filter) — flat syntax the engine now
// rejects, so repeating it taught LLMs a format that fails by construction.
// Defaults still exist and remain discoverable via action=schema (ip layer
// mac/dscp fields carry the same engine defaults); the test asserts both the
// pointer and the absence of flat advertisement.
func TestManageStrategies_ConfigSchema_PointsToLayerSchemaForDefaults(t *testing.T) {
	got := fieldSchemaDescription(t, "manageStrategiesInput", "Config")
	if !strings.Contains(got, "action=schema lists fields/types/defaults/depends_on") {
		t.Errorf("manageStrategiesInput.Config jsonschema = %q; must point defaults discovery at flowb_query_layers action=schema", got)
	}
	for _, banned := range []string{"(2) flat", "src_mac=02:00:00:00:00:01", "dscp=0x08", "ip_flags=DF"} {
		if strings.Contains(got, banned) {
			t.Errorf("manageStrategiesInput.Config jsonschema advertises rejected flat syntax %q: %s", banned, got)
		}
	}
}

// TestGenerateTraffic_ConfigSchema_PointsToLayerSchemaForDefaults verifies
// the same contract on the workflow tool's Config field (see the strategy
// variant above for rationale).
func TestGenerateTraffic_ConfigSchema_PointsToLayerSchemaForDefaults(t *testing.T) {
	got := fieldSchemaDescription(t, "generateTrafficInput", "Config")
	if !strings.Contains(got, "action=schema lists fields/types/defaults/depends_on") {
		t.Errorf("generateTrafficInput.Config jsonschema = %q; must point defaults discovery at flowb_query_layers action=schema", got)
	}
	for _, banned := range []string{"(2) flat", "src_mac=02:00:00:00:00:01", "ip_flags=DF"} {
		if strings.Contains(got, banned) {
			t.Errorf("generateTrafficInput.Config jsonschema advertises rejected flat syntax %q: %s", banned, got)
		}
	}
}

// TestManageStrategies_ConfigSchemaMentionsLayerChainFormat verifies the
// Config description teaches the layer-chain format (P6). Pre-fix the
// description covered only the legacy flat format, so LLMs never discovered
// the layers key that triggers backend layer-chain validation.
func TestManageStrategies_ConfigSchemaMentionsLayerChainFormat(t *testing.T) {
	got := fieldSchemaDescription(t, "manageStrategiesInput", "Config")
	for _, want := range []string{"\"layers\"", "layer-chain", "flowb_query_layers", "auto-completed", "depends_on"} {
		if !strings.Contains(got, want) {
			t.Errorf("manageStrategiesInput.Config jsonschema = %q; must mention %q (layer-chain format)", got, want)
		}
	}
}

// TestManageStrategies_ConfigSchema_NoFlatAdvertisement inverts the former
// "keeps legacy flat defaults" guard: the engine rejects top-level flat
// fields (core.CheckProtoFlat), so the description must never advertise
// them. group_id remains a legal top-level key and stays documented.
func TestManageStrategies_ConfigSchema_NoFlatAdvertisement(t *testing.T) {
	got := fieldSchemaDescription(t, "manageStrategiesInput", "Config")
	for _, banned := range []string{"(2) flat", "src_ip=10.0.0.1", "dst_ip=20.0.0.1", "src_port=12345", "dst_port=80 (DNS 53)"} {
		if strings.Contains(got, banned) {
			t.Errorf("manageStrategiesInput.Config jsonschema advertises rejected flat syntax %q: %s", banned, got)
		}
	}
	if !strings.Contains(got, "group_id") {
		t.Errorf("manageStrategiesInput.Config jsonschema = %q; must keep group_id hint (legal top-level key)", got)
	}
	if !strings.Contains(got, "are rejected") {
		t.Errorf("manageStrategiesInput.Config jsonschema = %q; must state flat fields are rejected", got)
	}
}


// TestOutputConfig_PortsDocumented 锁住客户端反馈的三项文档缺口（缺口重现
// 即红）：① output_config 必须出现 ports 键名及互斥说明（generate 描述
// 只写 port_group_id/pcap_path/interface2 的时代已结束）；② weight 缺省
// 语义（省略=0）及"不同 weight = 不同组"必须写进 port 描述；③ interface
// 名必须先查 interfaces（建组是软校验，错名只在 Start 才败）。
func TestOutputConfig_PortsDocumented(t *testing.T) {
	// ① output_config 入口描述必须提到 'ports' 键及互斥（客户端原话：
	// 只写了 port_group_id/pcap_path/interface2 三键名）。
	gen := fieldSchemaDescription(t, "generateTrafficInput", "OutputConfig")
	for _, want := range []string{"'ports'", "mutually exclusive with port_group_id"} {
		if !strings.Contains(gen, want) {
			t.Errorf("generateTrafficInput.OutputConfig jsonschema = %q; must mention %q", gen, want)
		}
	}
	oc := fieldSchemaDescription(t, "outputConfigInput", "Ports")
	for _, want := range []string{"Mutually exclusive with port_group_id", "weight", "idempotent", "port_group or both"} {
		if !strings.Contains(oc, want) {
			t.Errorf("outputConfigInput.Ports jsonschema = %q; must mention %q", oc, want)
		}
	}
	pg := fieldSchemaDescription(t, "outputConfigInput", "PortGroupID")
	if !strings.Contains(pg, "Mutually exclusive with ports") {
		t.Errorf("outputConfigInput.PortGroupID jsonschema = %q; must mirror the mutual-exclusion rule", pg)
	}
	wt := fieldSchemaDescription(t, "portGroupPort", "Weight")
	for _, want := range []string{"default 0", "DIFFERENT group"} {
		if !strings.Contains(wt, want) {
			t.Errorf("portGroupPort.Weight jsonschema = %q; must mention %q", wt, want)
		}
	}
	iface := fieldSchemaDescription(t, "portGroupPort", "Interface")
	if !strings.Contains(iface, "action=interfaces") {
		t.Errorf("portGroupPort.Interface jsonschema = %q; must point at flowb_query_system action=interfaces", iface)
	}
	i2 := fieldSchemaDescription(t, "outputConfigInput", "Interface2")
	if !strings.Contains(i2, "may combine with port_group_id or ports") {
		t.Errorf("outputConfigInput.Interface2 jsonschema = %q; must state the combinable set (port_group_id/ports/pcap, not both)", i2)
	}
}
