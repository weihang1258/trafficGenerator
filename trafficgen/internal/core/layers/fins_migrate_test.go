package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/fins" // init 注册 fins 层生成器 + 校验器
)

// D-FINS-1 §4 红例①②③（failing 先行，P-PIPE #11 P4）。
// 实现前预期：①红（CheckProtoFlat 无 fins presence 分支，放行）；②红
// （registry fins 零 Fields，层内业务键 V9 全拒 unknown field）；③红
// （translate 无 case "fins" → Metadata 空 → 生成器回退默认 DM 读 0101，
// 层内 clock 命令 0701 不上线）。

func finsChain(t *testing.T, finsCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 1234, "dst_port": 9600}},
		map[string]interface{}{"fins": finsCfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-FINS-1 §2】：顶层 fins 子映射 presence 判死——空 map 也死
// （mcp/srv6 先例）。现状：CheckProtoFlat("fins", ...) 返回空。
func TestFINSChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]interface{}{"udp": map[string]interface{}{}},
			map[string]interface{}{"fins": map[string]interface{}{}},
		},
		"fins": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("fins", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(fins, {layers, fins:{}}) = \"\", want top-level fins presence rejection")
	} else if !strings.Contains(msg, "top-level fins sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-FINS-1 §1】：fins 层 16 业务键 V9 放行（一律无 Default）。
// 现状：registry fins 零 Fields → 任意键 unknown field。
func TestFINSChain_LayerFieldsAccepted(t *testing.T) {
	raw := finsChain(t, map[string]interface{}{
		"transport":   "udp",
		"commands":    []interface{}{map[string]interface{}{"command": 257, "memory_area": "dm", "address": 100, "items": 2}},
		"sessions":    2,
		"sid":         7,
		"sid_auto":    false,
		"icf":         129,
		"gct":         2,
		"dna":         0,
		"da1":         1,
		"da2":         0,
		"sna":         0,
		"sa1":         2,
		"sa2":         0,
		"handshake":   true,
		"termination": false,
		"read_areas":  []interface{}{map[string]interface{}{"memory_area": "dm", "address": 100, "items": 1}},
	})
	if _, err := layers.ValidateLayers(raw, "fins"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-FINS-1 §3】：translate 上线——层 config 命令进生成器。现状：
// translateTerminalConfig 无 case "fins" → Metadata 空 → configFromMeta(nil)
// 默认 DM 读（payload 01 01），层内 clock 读 0701 不上线。
func TestFINSChain_LayerTranslateClockCommand(t *testing.T) {
	p := layers.NewChainPlannerFromChain("fins", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "udp", Config: map[string]interface{}{"src_port": 1234, "dst_port": 9600}},
		{Name: "fins", Config: map[string]interface{}{
			"transport": "udp",
			"commands":  []interface{}{map[string]interface{}{"command": 0x0701}},
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: 9600}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	clockSeen := false
	for pkt := range ch {
		n++
		// FINS 帧 = 10B 头 + 命令码 2B：offset 10..11 = 07 01（clock read）。
		if len(pkt.Payload) >= 12 && pkt.Payload[10] == 0x07 && pkt.Payload[11] == 0x01 {
			clockSeen = true
		}
	}
	if n == 0 {
		t.Fatal("no packets")
	}
	if !clockSeen {
		t.Fatalf("clock command 0701 not in wire (translate missing? got default DM read 0101)")
	}
}
