package mcp

import (
	"strings"
	"testing"
)

// TestConfigTagsMatchSchemaBlurb guards the derivation chain schemas/v1 ->
// schemagen -> schemaConfigBlurb -> hand-written Config jsonschema tags.
// Struct tags must be string literals (Go reflect does not evaluate `+`
// concat), so the tags cannot reference the generated constant directly.
// Instead this test fails whenever the tag text drifts from the generated
// blurb: copy the new blurb text into both tags (tools_strategy.go,
// tools_workflow.go) and keep every tools_schema_test.go substring.
func TestConfigTagsMatchSchemaBlurb(t *testing.T) {
	for _, tc := range []struct{ typeName, field string }{
		{"manageStrategiesInput", "Config"},
		{"generateTrafficInput", "Config"},
	} {
		got := fieldSchemaDescription(t, tc.typeName, tc.field)
		if !strings.Contains(got, schemaConfigBlurb) {
			t.Errorf("%s.Config tag drifted from schemaConfigBlurb (generated from schemas/v1).\nGot tag len %d, blurb len %d. Copy the blurb text into the tag.", tc.typeName, len(got), len(schemaConfigBlurb))
		}
	}
}

// TestSchemaDocsTablesNonEmpty ensures the generated per-file doc tables are
// present and populated (derivation did not silently emit empty maps).
func TestSchemaDocsTablesNonEmpty(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"schemaDocsStrategy": schemaDocsStrategy,
		"schemaDocsTask":     schemaDocsTask,
		"schemaDocsBatch":    schemaDocsBatch,
		"schemaDocsDefs":     schemaDocsDefs,
	} {
		if len(m) == 0 {
			t.Errorf("%s is empty; regenerate via go run ./internal/mcp/schemagen", name)
		}
	}
}

// TestSmallInputsMatchSchemaDefs guards the remaining hand-written input
// structs against defs.json drift. These structs are small enough that the
// test asserts key phrases directly; a mismatch means the schema changed and
// the tag (or the schema) needs a deliberate update.
func TestSmallInputsMatchSchemaDefs(t *testing.T) {
	fc := fieldSchemaDescription(t, "manageStrategiesInput", "FlowControl")
	for _, want := range []string{"strategy-level flow control"} {
		if !strings.Contains(fc, want) {
			t.Errorf("manageStrategiesInput.FlowControl tag = %q; must mention %q", fc, want)
		}
	}
	_ = schemaDocsDefs["/$defs/flow_control"]
	_ = schemaDocsDefs["/$defs/output_config"]
	if got := schemaDocsDefs["/$defs/flow_control/properties/type"]; !strings.Contains(got, "flows") {
		t.Errorf("defs flow_control.type doc = %q; must mention flows", got)
	}
	if got := schemaDocsDefs["/$defs/output_config/properties/interface2"]; !strings.Contains(got, "dual") {
		t.Errorf("defs output_config.interface2 doc = %q; must mention dual", got)
	}
}
