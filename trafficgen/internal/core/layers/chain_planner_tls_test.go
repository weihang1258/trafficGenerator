// 外部测试包：显式 import tls/http 触发注册（内层 package layers 测试无法
// import——layer_gen.go 的反向注册依赖会造成测试导入环）。
package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 tls/http 包 init 注册隧道层生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tls"
)

// D-TLS-1 步骤 2 locking：层内 sni 动态对象经 translateTLSSNI 按 FlowIndex
// 直解进 spec.TLS.SNI——Plan 内 ValidateSpec→translate 读到当流序号（与
// http TestChainPlanner_HTTP_LayerDynURIResolvesPerFlow 同构：翻译读 p.chain
// 用户原始链含动态对象，不读 term 补全链）。
func TestChainPlanner_TLS_LayerDynSNIResolvesPerFlow(t *testing.T) {
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
	for i, want := range []string{"a.com", "b.com"} {
		p := mkPlanner()
		spec := core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 40000, DstPort: 443, FlowIndex: i,
		}
		validated, err := p.ValidateSpec(spec)
		if err != nil {
			t.Fatalf("flow %d ValidateSpec: %v", i, err)
		}
		if validated.TLS == nil {
			t.Fatalf("flow %d: spec.TLS nil after layer translation", i)
		}
		if validated.TLS.SNI != want {
			t.Fatalf("flow %d: SNI = %q, want %q (translateTLSSNI must resolve at FlowIndex)", i, validated.TLS.SNI, want)
		}
	}
}

// D-TLS-1 步骤 2 locking：标量 sni 直写 spec.TLS.SNI；spec.TLS 非 nil 空壳
// （worker 防御性补建产物）不挡路；有内容的 spec.TLS 走 flat 权威。
func TestChainPlanner_TLS_ScalarSNIAndEmptyShell(t *testing.T) {
	mkPlanner := func() *layers.ChainPlanner {
		return layers.NewChainPlannerFromChain("tls", []layers.Layer{
			{Name: "ip"},
			{Name: "tcp"},
			{Name: "tls", Config: map[string]interface{}{
				"sni": "example.com",
			}},
			{Name: "http", Config: map[string]interface{}{}},
		})
	}
	base := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 443,
	}
	// 标量直写。
	validated, err := mkPlanner().ValidateSpec(base)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.TLS == nil || validated.TLS.SNI != "example.com" {
		t.Fatalf("SNI = %+v, want example.com", validated.TLS)
	}
	// 空壳不挡路。
	shell := base
	shell.TLS = &core.TLSConfig{}
	validated, err = mkPlanner().ValidateSpec(shell)
	if err != nil {
		t.Fatalf("empty-shell ValidateSpec: %v", err)
	}
	if validated.TLS == nil || validated.TLS.SNI != "example.com" {
		t.Fatalf("empty-shell SNI = %+v, want example.com", validated.TLS)
	}
	// flat 有内容优先。
	flat := base
	flat.TLS = &core.TLSConfig{SNI: "flat.com"}
	validated, err = mkPlanner().ValidateSpec(flat)
	if err != nil {
		t.Fatalf("flat ValidateSpec: %v", err)
	}
	if validated.TLS.SNI != "flat.com" {
		t.Fatalf("flat SNI = %q, want flat.com", validated.TLS.SNI)
	}
}

// D-TLS-1 步骤 2 locking：动态 sni 不改变包数（只换 ClientHello 扩展字节）。
func TestChainPlanner_TLS_DynSNIDoesNotChangePacketCount(t *testing.T) {
	p := layers.NewChainPlannerFromChain("tls", []layers.Layer{
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
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 443, FlowIndex: 0,
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 16 {
		t.Fatalf("packets = %d, want 16 (dyn sni must not change count; T13 baseline)", n)
	}
}
