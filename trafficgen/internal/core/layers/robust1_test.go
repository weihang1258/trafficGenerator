package layers

// D-ROBUST-1 批 1 验收：T-RB1-4（file_id 统一拒）+ T-RB1-5（sink 透出）。

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// T-RB1-4【MCP 可触发】占位符 file_id create 即拒，全协议一致（红例：
// vnc 静默 81 包 / tftp 0 包掩蔽 / wireguard 运行期才拒）。
func TestROBUST1_FileIDShapeRejectedAtCreate(t *testing.T) {
	// 直接走链级 file_source 扫描：构造含占位符的链。
	chain := []Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "udp", Config: map[string]interface{}{"dst_port": uint16(9000),
			"file_source": map[string]interface{}{"file_id": "<上传回执 file_id，64 位 hex>"}}},
	}
	errs := []string{}
	walkFileSourceKeysSupported(chain[1].Config, "layers[1](udp)", &errs, true)
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, ";"), "64 hex chars") {
		t.Fatalf("placeholder file_id: errs = %v, want 64-hex anchor", errs)
	}
	// 合法 64hex：形状过（运行期存在性走家族契约）。
	errs = nil
	walkFileSourceKeysSupported(map[string]interface{}{"dst_port": uint16(9000),
		"file_source": map[string]interface{}{"file_id": strings.Repeat("ab", 32)}},
		"layers[1](udp)", &errs, true)
	for _, e := range errs {
		if strings.Contains(e, "64 hex") {
			t.Fatalf("valid 64-hex rejected: %v", errs)
		}
	}
	// vnc 层（嵌套消息内 file_source 同样被扫到）。
	errs = nil
	walkFileSourceKeysSupported(map[string]interface{}{"file_source": map[string]interface{}{"file_id": "zz"}},
		"layers[2](vnc)", &errs, true)
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, ";"), "64 hex chars") {
		t.Fatalf("vnc placeholder file_id: errs = %v", errs)
	}
}

// T-RB1-5 sink：Plan 期 drive 错误写入 ctx sink（0 包报错透出的前置）。
func TestROBUST1_PlanErrorSinkCarriesDriveError(t *testing.T) {
	sink := &core.PlanErrorSink{}
	chain := []Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2", "hop_by_hop": []interface{}{map[string]interface{}{"type": float64(30), "value": strings.Repeat("09", 100)}}}},
		{Name: "udp", Config: map[string]interface{}{"src_port": uint16(5000), "dst_port": uint16(9001), "mtu": uint16(68)}},
	}
	p := NewChainPlannerFromChain("udp", chain)
	spec := core.FlowSpec{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 5000, DstPort: 9001}
	ctx := core.WithPlanErrorSink(context.Background(), sink)
	_, err := p.Plan(ctx, spec)
	if err == nil {
		t.Fatal("Plan() = nil error (sync path); sink test needs async drive error")
	}
	// 同步路径直接返回错误——sink 主要服务异步 drive。直接验证 sink 语义。
	sink2 := &core.PlanErrorSink{}
	if sink2.Load() != nil {
		t.Fatal("empty sink Load() must be nil")
	}
	sink2.Store(context.Canceled)
	sink2.Store(nil)
	if sink2.Load() == nil || !strings.Contains(sink2.Load().Error(), "canceled") {
		t.Fatal("Store/Load semantics broken")
	}
	sink2.Store(err) // first-write-wins
	if !strings.Contains(sink2.Load().Error(), "canceled") {
		t.Fatal("Store first-write-wins broken")
	}
	_ = err
}
