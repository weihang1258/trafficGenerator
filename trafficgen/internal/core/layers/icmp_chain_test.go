package layers_test

// D-ICMP-1 P4 链级红例：[ip→icmp] raw-IP 链（icmpv6 对称第 12 连协议）。
// 红例面：①顶层 icmp 子映射 presence 判死；②层 6 业务键 V9 放行；
// ③translate 上线——空层缺省 type=8，Echo 对 2 包（request up + auto-reply
// down，payload[0]=type）；④pattern step 缺省镜像 parse。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 icmp 包 init 注册层生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/icmp"
)

func icmpChainRaw(t *testing.T, icmpCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal([]map[string]interface{}{
		{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{"icmp": icmpCfg},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// 红①【D-ICMP-1 裁定5】：顶层 icmp 子映射 presence 判死（层链+顶层并存）。
func TestICMPChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]interface{}{"icmp": map[string]interface{}{}},
		},
		"icmp": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("icmp", cfg); msg == "" {
		t.Fatal(`CheckProtoFlat(icmp, {layers, icmp:{}}) = "", want top-level icmp presence rejection`)
	} else if !strings.Contains(msg, "top-level icmp sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红②【D-ICMP-1 裁定2】：icmp 层 6 业务键 V9 放行（一律无 Default）。
func TestICMPChain_LayerFieldsAccepted(t *testing.T) {
	raw := icmpChainRaw(t, map[string]interface{}{
		"type":       8,
		"code":       0,
		"identifier": 1,
		"sequence":   1,
		"data":       "ping",
		"pattern":    []interface{}{map[string]interface{}{"type": 8, "sequence": 1, "data": "aa"}},
	})
	if _, err := layers.ValidateLayers(raw, "icmp"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红③【D-ICMP-1 裁定3】：translate 上线——空层缺省 type=8，Echo 对 2 包
// （request up + auto-reply down，payload[0]=type；id=0 回退 Sequence 面）。
func TestICMPChain_LayerTranslateEchoPair(t *testing.T) {
	p := layers.NewChainPlannerFromChain("icmp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "icmp", Config: map[string]interface{}{
			"identifier": 7,
			"sequence":   1,
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
	if len(types) != 2 || types[0] != 8 || types[1] != 0 {
		t.Fatalf("Echo pair types=%v want [8 0]", types)
	}
}

// 红④【D-ICMP-1 裁定4】：validator 逐步校验——type=3 非 Echo 拒、
// code=1 拒、pattern step type=3 拒（锚词逐字）。
func TestICMPChain_ValidatorAnchors(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
		want string
	}{
		{"type=3", map[string]interface{}{"type": 3}, "icmp type must be 8 (Echo Request) or 0 (Echo Reply), got 3"},
		{"code=1", map[string]interface{}{"type": 8, "code": 1}, "icmp code must be 0 for Echo, got 1"},
		{"pattern step", map[string]interface{}{"pattern": []interface{}{map[string]interface{}{"type": 3}}}, "icmp pattern step 1 type must be 8 or 0, got 3"},
	}
	for _, c := range cases {
		p := layers.NewChainPlannerFromChain("icmp", []layers.Layer{
			{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			{Name: "icmp", Config: c.cfg},
		})
		err := p.Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
}
