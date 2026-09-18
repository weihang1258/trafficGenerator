package layers_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mcp" // init 注册 mcp 终结层生成器 + 校验器
)

// D-MCP-1 步骤 0 红例族（failing 先行，P-PIPE #9 P4）。
// 实现前预期：①红（presence 未判死，放行）；②红（registry mcp 零 Fields，
// 层内业务键 V9 全拒 unknown field）；③红（无 translateTerminalConfig
// case "mcp"——②修后层值仍进不了 spec.MCP，Plan 报 mcp config is required）；
// ④红（MCPConfig.ThinkTime 仍在——M1-E1 删除前反射可见）。

func mcpMigrateChain(t *testing.T, mcpCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 13000, "dst_port": 8081}},
		map[string]interface{}{"mcp": mcpCfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func mcpMigrateSpec() core.FlowSpec {
	return core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 13000, DstPort: 8081}
}

// mcpUpPayloads 收集 Plan 输出全部上行数据帧载荷拼接（stdio 行分隔 JSON）。
func mcpUpPayloads(t *testing.T, p core.ProtocolPlanner, spec core.FlowSpec) []byte {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var b []byte
	for pkt := range ch {
		if pkt.Direction == "up" && len(pkt.Payload) > 0 && pkt.L4.Flags == 0x18 {
			b = append(b, pkt.Payload...)
		}
	}
	return b
}

// 红例1【D-MCP-1 §1/§5】：顶层 mcp 子映射 presence 判死——空 map 也死
// （dns/mqtt/smtp/pop3/imap 先例）。现状：放行。
func TestMCPChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"mcp": map[string]interface{}{}},
		},
		"mcp": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("mcp", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(mcp, {layers, mcp:{}}) = \"\", want top-level mcp presence rejection")
	}
	if msg := core.CheckProtoFlat("mcp", cfg); !strings.Contains(msg, "no longer accepts a top-level mcp sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `no longer accepts a top-level mcp sub-config`", msg)
	}
}

// 红例2【D-MCP-1 §1/§13】：层 mcp 业务键收录进注册表——transport/requests
// 不再 V9 unknown field。现状：registry mcp 零 Fields，全拒。
func TestMCPChain_LayerFieldsAccepted(t *testing.T) {
	raw := mcpMigrateChain(t, map[string]interface{}{
		"transport": "stdio",
		"requests":  []interface{}{map[string]interface{}{"method": "tools/list"}},
	})
	if _, err := layers.BuildLayersPlanner("mcp", raw); err != nil {
		t.Fatalf("BuildLayersPlanner: %v (mcp 层业务键应放行，现状 unknown field)", err)
	}
}

// 红例3【D-MCP-1 §1】：层 requests 翻译进 spec.MCP——线上出现用户方法
// tools/list。现状：无 case "mcp"，spec.MCP 保持 nil，Plan 报
// "mcp config is required"（默认序列不断言，显式 requests 是真相证据）。
func TestMCPChain_LayerRequestsTranslate(t *testing.T) {
	raw := mcpMigrateChain(t, map[string]interface{}{
		"transport": "stdio",
		"requests":  []interface{}{map[string]interface{}{"method": "tools/list"}},
	})
	p, err := layers.BuildLayersPlanner("mcp", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	wire := mcpUpPayloads(t, p, mcpMigrateSpec())
	if !strings.Contains(string(wire), "tools/list") {
		t.Fatalf("layer mcp requests dropped (want tools/list on wire), up=%q", wire)
	}
}

// 红例4【D-MCP-1 M1-E1】：MCPConfig.ThinkTime 已删（死字段，生成器零消费；
// http E1 删除先例）。反射锁：删前可见即红。
func TestMCPChain_ThinkTimeDeleted(t *testing.T) {
	if _, ok := reflect.TypeOf(core.MCPConfig{}).FieldByName("ThinkTime"); ok {
		t.Fatal("core.MCPConfig still has ThinkTime field, want deleted (M1-E1: dead field, zero consumers)")
	}
}
