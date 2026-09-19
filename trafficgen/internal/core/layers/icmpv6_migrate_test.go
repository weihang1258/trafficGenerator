package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/icmpv6" // init 注册 icmpv6 层生成器 + 校验器
)

// D-ICMPV6-1 §4 红例①②③④（failing 先行，P-PIPE #14 P4）。
// 实现前预期：①红（CheckProtoFlat 无 icmpv6 presence 分支，放行）；②红
// （registry icmpv6 无行，层内业务键 V9 全拒 unknown field）；③红
// （translate case "icmpv6" 为 no-op → spec.ICMPv6 恒 nil；validateLayer
// 未注册 → "icmpv6 config is required" 不可达，Plan 走 raw-IP 但生成器
// 缺位）；④红（链上无 validator，v4 地址静默放行——legacy Validate 的
// v6 强制（icmpv6.go:60-79）不经层链路径）。

func icmpv6Chain(t *testing.T, icmpv6Cfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2"}},
		map[string]interface{}{"icmpv6": icmpv6Cfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-ICMPV6-1 §2】：顶层 icmpv6 子映射 presence 判死——空 map 也死。
func TestICMPv6Chain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2"}},
			map[string]interface{}{"icmpv6": map[string]interface{}{}},
		},
		"icmpv6": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("icmpv6", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(icmpv6, {layers, icmpv6:{}}) = \"\", want top-level icmpv6 presence rejection")
	} else if !strings.Contains(msg, "top-level icmpv6 sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-ICMPV6-1 §1】：icmpv6 层 6 业务键 V9 放行（一律无 Default）。
func TestICMPv6Chain_LayerFieldsAccepted(t *testing.T) {
	raw := icmpv6Chain(t, map[string]interface{}{
		"type":       128,
		"code":       0,
		"identifier": 1,
		"sequence":   1,
		"data":       "ping",
		"pattern":    []interface{}{map[string]interface{}{"type": 128, "sequence": 1, "data": "aa"}},
	})
	if _, err := layers.ValidateLayers(raw, "icmpv6"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-ICMPV6-1 §3】：translate 上线——空层缺省 type 128，Echo 对
// 2 包（request up + auto-reply down，payload[0]=type）。
func TestICMPv6Chain_LayerTranslateEchoPair(t *testing.T) {
	p := layers.NewChainPlannerFromChain("icmpv6", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2"}},
		{Name: "icmpv6", Config: map[string]interface{}{
			"identifier": 1,
			"sequence":   1,
		}},
	})
	spec := core.FlowSpec{SrcIP: "2001:db8::1", DstIP: "2001:db8::2"}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	var types []uint8
	for pkt := range ch {
		n++
		if len(pkt.Payload) > 0 {
			types = append(types, pkt.Payload[0])
		}
	}
	if n != 2 {
		t.Fatalf("packets=%d want 2 (translate missing? Echo pair not emitted)", n)
	}
	if len(types) != 2 || types[0] != 128 || types[1] != 129 {
		t.Fatalf("Echo pair types=%v want [128 129]", types)
	}
}

// 红例⑤【D-ICMPV6-1 决策 D1】：pattern step 缺省镜像 parse
// （strategy_convert.go parseICMPv6Pattern）：type 缺省 128、code 缺省 0、
// sequence==0（含显式 0）自动补 index+1、data 缺省 "ping"。
// 实现偏差时：step type=0 会被 validator 误杀 / seq=0 上线发出 seq=0 包。
func TestICMPv6Chain_PatternStepDefaultsMirrorParse(t *testing.T) {
	p := layers.NewChainPlannerFromChain("icmpv6", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2"}},
		{Name: "icmpv6", Config: map[string]interface{}{
			"pattern": []interface{}{
				map[string]interface{}{}, // 全缺省：type 128 / code 0 / seq 1 / data "ping"
				map[string]interface{}{"sequence": 0, "data": "probe"}, // 显式 0 也自动补序 → 2
			},
		}},
	})
	spec := core.FlowSpec{SrcIP: "2001:db8::1", DstIP: "2001:db8::2"}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// legacy 语义：每个 type=128 的步发请求+自动回包（icmpv6.go:160-191），
	// 2 请求步 → 4 包 [128 129 128 129]。
	n := 0
	var seqs []uint16
	var datas []string
	for pkt := range ch {
		n++
		if len(pkt.Payload) >= 8 {
			seqs = append(seqs, uint16(pkt.Payload[6])<<8|uint16(pkt.Payload[7]))
			datas = append(datas, string(pkt.Payload[8:]))
		}
	}
	if n != 4 {
		t.Fatalf("packets=%d want 4 (each request step auto-replies)", n)
	}
	// 步1全缺省 seq=1（请求+回包同 seq），步2显式 0 自动补序 → 2。
	if len(seqs) != 4 || seqs[0] != 1 || seqs[1] != 1 || seqs[2] != 2 || seqs[3] != 2 {
		t.Fatalf("step seqs=%v want [1 1 2 2] (seq==0 must auto-number index+1 like parse)", seqs)
	}
	if len(datas) != 4 || datas[0] != "ping" || datas[1] != "ping" || datas[2] != "probe" || datas[3] != "probe" {
		t.Fatalf("step datas=%v want [ping ping probe probe] (missing data must default to \"ping\")", datas)
	}
}

// 红例⑥【D-FTP-4 豁免对齐】：ip.src 层动态对象 + icmpv6 → Validate 必须
// 放行（解析前 spec 仍带 flat 缺省 10.0.0.1，另一族；validateSpecBase
// chain_planner.go:587 已豁免同族静态检查，validateLayer 裸委托 legacy
// Validate 缺豁免 → 误杀动态多流）。
func TestICMPv6Chain_DynamicIPFamilyExempt(t *testing.T) {
	p := layers.NewChainPlannerFromChain("icmpv6", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{
			"src": map[string]interface{}{"strategy": "inc", "range": []interface{}{"2001:db8::1", "2001:db8::2"}, "step": 1},
			"dst": "2001:db8::9",
		}},
		{Name: "icmpv6", Config: map[string]interface{}{}},
	})
	spec := core.FlowSpec{
		SrcIP:         "10.0.0.1", // flat 缺省（动态对象未解析时的占位）
		DstIP:         "20.0.0.1",
		HasLayerDynIP: true,
	}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("dynamic ip.src must escape static v6 family check (D-FTP-4 exemption): %v", err)
	}
}

// 红例④【D-ICMPV6-1 依赖链②】：v4 地址经链路径必须拒（legacy Validate 的
// v6 强制复用进 layer validator）。实现前链上无 validator=静默放行。
func TestICMPv6Chain_V4Rejected(t *testing.T) {
	p := layers.NewChainPlannerFromChain("icmpv6", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "icmpv6", Config: map[string]interface{}{}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("v4 addresses must be rejected (legacy v6 enforcement icmpv6.go:60-79 must be wired into the layer validator)")
	}
	if !strings.Contains(err.Error(), "must be IPv6") {
		t.Fatalf("anchor mismatch: %v", err)
	}
}
