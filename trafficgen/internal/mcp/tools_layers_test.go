package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// flowb_query_layers 两种 action 的契约：
//   - schema（默认）：层字段表（回归保护——原行为不变，且新字段可见）
//   - examples：cases 语料派生的已验证配置——LLM 复制即用，免试错
func TestQueryLayersSchemaAction(t *testing.T) {
	action, data, err := queryLayersPayload(queryLayersInput{})
	if err != nil || action != "schema" {
		t.Fatalf("default action = %s, err %v", action, err)
	}
	views, ok := data.([]layerSchemaView)
	if !ok || len(views) < 100 {
		t.Fatalf("schema views = %T len %d, want >=100 layers", data, len(views))
	}
	// 新字段可见性标记：a2a 层必须含 tasks（125 协议收口字段）。
	_, a2aData, err := queryLayersPayload(queryLayersInput{Layer: "a2a"})
	if err != nil {
		t.Fatalf("a2a schema: %v", err)
	}
	b, _ := json.Marshal(a2aData)
	if !strings.Contains(string(b), `"tasks"`) {
		t.Errorf("a2a schema missing tasks field")
	}
}

func TestQueryLayersExamplesForProtocol(t *testing.T) {
	action, data, err := queryLayersPayload(queryLayersInput{Action: "examples", Proto: "modbus"})
	if err != nil || action != "examples" {
		t.Fatalf("examples modbus: action=%s err=%v", action, err)
	}
	m, _ := json.Marshal(data)
	var out struct {
		Envelope configEnvelopeDoc `json:"envelope"`
		Examples []struct {
			CaseID string          `json:"case_id"`
			Config json.RawMessage `json:"config"`
		} `json:"examples"`
	}
	if err := json.Unmarshal(m, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Examples) == 0 {
		t.Fatal("modbus examples empty")
	}
	if out.Envelope.FlowControl == "" || len(out.Envelope.TopLevelKeys) != 2 {
		t.Errorf("envelope incomplete: %+v", out.Envelope)
	}
	// 示例必须是可执行层链（layers 数组 + 非空）
	var cfg struct {
		Layers []map[string]json.RawMessage `json:"layers"`
	}
	if err := json.Unmarshal(out.Examples[0].Config, &cfg); err != nil || len(cfg.Layers) == 0 {
		t.Errorf("example config not a layer chain: err=%v layers=%d", err, len(cfg.Layers))
	}
}

func TestQueryLayersExamplesAllProtocols(t *testing.T) {
	_, data, err := queryLayersPayload(queryLayersInput{Action: "examples"})
	if err != nil {
		t.Fatalf("examples all: %v", err)
	}
	b, _ := json.Marshal(data)
	var out struct {
		Generated int `json:"generated"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// cases 语料 123 协议；允许 ±2 的边界协议（如 kingbase 收敛进
	// postgresql 后无独立正例），低于 120 说明生成器漏面。
	if out.Generated < 120 {
		t.Errorf("embedded examples cover %d protocols, want >=120", out.Generated)
	}
}

func TestQueryLayersExamplesUnknownProtoAndAction(t *testing.T) {
	if _, _, err := queryLayersPayload(queryLayersInput{Action: "examples", Proto: "no-such-proto"}); err == nil {
		t.Error("unknown protocol must error")
	}
	if _, _, err := queryLayersPayload(queryLayersInput{Action: "bogus"}); err == nil {
		t.Error("invalid action must error")
	}
	// layers.DefaultRegistry 冒烟：示例工具与 registry 同源。
	if reg := layers.DefaultRegistry(); reg == nil {
		t.Error("nil default registry")
	}
}
