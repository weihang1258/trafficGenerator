// D-TLS-1 步骤 2 locking（drive 层）：tls 层 sni 动态对象经 applySpecToChain
// 注入解析值后，生成器读到的必须是标量——对象不得进生成器（tcp :406 同款
// 纪律）。本测试直接调 applySpecToChain 的可观测等价面：Plan 整链出包
// （drive 内 applySpecToChain 已执行），不断言内部 cfg，只断言"对象链
// 出包数与标量链一致且不报错"。
package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tls"
)

// 动态 sni 对象链（spec.TLS.SNI 已由 translateTLSSNI/ resolveLayerTuple 注入
// 解析值——模拟 worker 逐流后的 spec 形态）必须出完整 16 包，且与标量链包数一致。
func TestChainPlanner_TLS_DynSNIObjectStrippedBeforeGenerate(t *testing.T) {
	mkPlanner := func() *layers.ChainPlanner {
		return layers.NewChainPlannerFromChain("tls", []layers.Layer{
			{Name: "ip"},
			{Name: "tcp"},
			{Name: "tls", Config: map[string]interface{}{
				"sni": map[string]interface{}{
					"strategy": "list",
					"list":     []interface{}{"a.com", "b.com"},
				},
			}},
			{Name: "http", Config: map[string]interface{}{}},
		})
	}
	base := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 443, FlowIndex: 1,
		// 模拟 worker 逐流后：解析值已进 spec.TLS.SNI（b.com）。
		TLS: &core.TLSConfig{SNI: "b.com"},
	}
	ch, err := mkPlanner().Plan(context.Background(), base)
	if err != nil {
		t.Fatalf("Plan(dyn obj + resolved spec): %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 16 {
		t.Fatalf("packets = %d, want 16 (object must be replaced by resolved sni, not fed to generator)", n)
	}

	// 对象 + 空 spec（直接 Plan 未逐流解析）→ 剥离回默认，不报错，包数仍 16。
	bare := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 443, FlowIndex: 1,
	}
	ch, err = mkPlanner().Plan(context.Background(), bare)
	if err != nil {
		t.Fatalf("Plan(dyn obj + bare spec): %v", err)
	}
	n = 0
	for range ch {
		n++
	}
	if n != 16 {
		t.Fatalf("packets = %d, want 16 (bare spec must strip object to default, not fail)", n)
	}
}
