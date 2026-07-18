package core

import (
	"encoding/json"
	"testing"
)

func TestFlowSpecGroupIDJSONRoundTrip(t *testing.T) {
	raw := `{"group_id":{"strategy":"pattern","pattern":"call-{n}","range":[1,100]}}`
	var spec FlowSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if spec.GroupID == nil {
		t.Fatal("GroupID is nil")
	}
	if spec.GroupID.Strategy != "pattern" {
		t.Fatalf("strategy = %q, want pattern", spec.GroupID.Strategy)
	}
	if spec.GroupID.Pattern != "call-{n}" {
		t.Fatalf("pattern = %q, want call-{n}", spec.GroupID.Pattern)
	}
	if len(spec.GroupID.Range) != 2 {
		t.Fatalf("range len = %d, want 2", len(spec.GroupID.Range))
	}
}

func TestTrafficClassGroupIDJSONRoundTrip(t *testing.T) {
	raw := `{"id":"sip","type":"tcp","flow_count":1,"group_id":{"strategy":"fixed","value":"call-A"}}`
	var c TrafficClass
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.GroupID == nil {
		t.Fatal("GroupID is nil")
	}
	if c.GroupID.Strategy != "fixed" {
		t.Fatalf("strategy = %q, want fixed", c.GroupID.Strategy)
	}
	if v, ok := c.GroupID.Value.(string); !ok || v != "call-A" {
		t.Fatalf("value = %v, want call-A", c.GroupID.Value)
	}
}

func TestGroupIDOmitempty(t *testing.T) {
	spec := FlowSpec{}
	out, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if _, exists := got["group_id"]; exists {
		t.Fatalf("group_id should be omitted when nil, got %s", out)
	}
}

func TestMapToFlowSpecPreservesGroupID(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"group_id": map[string]interface{}{
			"strategy": "fixed",
			"value":    "call-A",
		},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.GroupID == nil {
		t.Fatal("GroupID is nil")
	}
	if spec.GroupID.Strategy != "fixed" {
		t.Fatalf("strategy = %q, want fixed", spec.GroupID.Strategy)
	}
	if v, ok := spec.GroupID.Value.(string); !ok || v != "call-A" {
		t.Fatalf("value = %v, want call-A", spec.GroupID.Value)
	}
}

func TestMapToFlowSpecGroupIDAbsent(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.GroupID != nil {
		t.Fatalf("GroupID = %v, want nil (no group_id)", spec.GroupID)
	}
}
