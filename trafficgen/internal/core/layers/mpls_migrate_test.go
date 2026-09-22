package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mpls" // init 注册 mpls 层生成器 + 校验器
)

// D-MPLS-1 §4 红例①②③④（failing 先行，P-PIPE #16 P4）。
// 实现前预期：①红（CheckProtoFlat 无 mpls presence 分支）；②红
// （registry 占位行无 Fields，层内业务键 V9 全拒 unknown field）；③红
// （translate 无 case → spec.MPLS 恒 nil → "MPLS config is required"）；④红
// （translate 不落端口 → spec.DstPort=0 上帧）。

func mplsChain(t *testing.T, mplsCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"mpls": mplsCfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-MPLS-1 §2】：顶层 mpls 子映射 presence 判死——空 map 也死。
func TestMPLSChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]interface{}{"mpls": map[string]interface{}{}},
		},
		"mpls": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("mpls", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(mpls, {layers, mpls:{}}) = \"\", want top-level mpls presence rejection")
	} else if !strings.Contains(msg, "top-level mpls sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-MPLS-1 §1】：mpls 层 8 业务键 V9 放行（占位行无 Fields →
// 实现前全拒 unknown field）。
func TestMPLSChain_LayerFieldsAccepted(t *testing.T) {
	raw := mplsChain(t, map[string]interface{}{
		"labels": []interface{}{
			map[string]interface{}{"label": 100, "tc": 0, "ttl": 64},
			map[string]interface{}{"label": 200, "s": true},
		},
		"multicast":     false,
		"inner_proto":   17,
		"src_port":      12345,
		"dst_port":      80,
		"frames":        1,
		"direction":     "up",
		"inner_payload": "abc",
	})
	if _, err := layers.ValidateLayers(raw, "mpls"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-MPLS-1 §3】：translate 上线——[ip,mpls] 链 1 帧，标签栈字节
// 与存量扁平路径等价（label 100 << 12 | S=1 << 8 | TTL 64 = 0x00064140，
// 对探针 pcap 验证过的合同值）。
func TestMPLSChain_LayerTranslateLabelFrame(t *testing.T) {
	p := layers.NewChainPlannerFromChain("mpls", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "mpls", Config: map[string]interface{}{
			"src_port": 12345, "dst_port": 80,
			"labels": []interface{}{map[string]interface{}{"label": 100}},
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for pkt := range ch {
		n++
		if pkt.L4.DstPort != 80 {
			t.Fatalf("inner udp dstPort=%d want 80 (translate must carry ports)", pkt.L4.DstPort)
		}
		if pkt.L2.MPLS == nil || len(pkt.L2.MPLS.Labels) != 1 || pkt.L2.MPLS.Labels[0].Label != 100 {
			t.Fatalf("label stack not carried: %+v", pkt.L2.MPLS)
		}
		if pkt.L2.MPLS.Labels[0].TTL != 64 {
			t.Fatalf("label TTL=%d want 64 (Plan resolves 0→64)", pkt.L2.MPLS.Labels[0].TTL)
		}
	}
	if n != 1 {
		t.Fatalf("packets=%d want 1 (frames default)", n)
	}
}

// 红例④【D-MPLS-1 决策 C】：translate 把层 config 填进 spec.MPLS——经
// ValidateSpec 后 spec.MPLS 非 nil 且 labels 逐槽映射（实现前恒 nil =
// legacy "MPLS config is required"）。空栈拒绝由 legacy Validate 承担
// （planner.go:61-63），此处证翻译通路本身。
func TestMPLSChain_PresenceFilled(t *testing.T) {
	p := layers.NewChainPlannerFromChain("mpls", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "mpls", Config: map[string]interface{}{
			"labels":      []interface{}{map[string]interface{}{"label": 1, "tc": 5, "ttl": 63}},
			"multicast":   true,
			"frames":      3,
			"direction":   "down",
			"inner_proto": 6,
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	out, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if out.MPLS == nil {
		t.Fatal("spec.MPLS must be translated from the layer config")
	}
	if len(out.MPLS.Labels) != 1 || out.MPLS.Labels[0].Label != 1 || out.MPLS.Labels[0].TC != 5 || out.MPLS.Labels[0].TTL != 63 {
		t.Fatalf("labels not mapped per-slot: %+v", out.MPLS.Labels)
	}
	if !out.MPLS.Multicast || out.MPLS.Frames != 3 || out.MPLS.Direction != "down" || out.MPLS.InnerProto != 6 {
		t.Fatalf("business keys not mapped: %+v", out.MPLS)
	}
}
