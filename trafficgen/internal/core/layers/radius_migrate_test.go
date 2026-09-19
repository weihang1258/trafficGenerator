package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/radius" // init 注册 radius 层生成器 + 校验器
)

// D-RADIUS-1 §4 红例①②③④+1813 专项（failing 先行，P-PIPE #20 P4）。
// 实现前预期：①红（CheckProtoFlat 无 radius presence 分支）；②红
// （registry 无 radius 行，V9 拒 unknown layer）；③红（translate 无 case
// + 生成器未注册）；④红（translate 不落 spec.Radius → 恒 nil）；⑤红
// （:770 预写拿不到 code 恒 1812，顺序修正缺失 → acct dstport 错 1812）。

func radiusChain(t *testing.T, radiusCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"radius": radiusCfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-RADIUS-1 §2】：顶层 radius 子映射 presence 判死——空 map 也死。
func TestRadiusChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]interface{}{"radius": map[string]interface{}{}},
		},
		"radius": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("radius", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(radius, {layers, radius:{}}) = \"\", want top-level radius presence rejection")
	} else if !strings.Contains(msg, "top-level radius sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-RADIUS-1 §1】：radius 层 9 键 V9 放行（registry 无行 → 实现
// 前整层 unknown）。业务 7 键（含 attributes/response_attributes 列表）
// + 端口 2 键（七度已批 E1）。
func TestRadiusChain_LayerFieldsAccepted(t *testing.T) {
	raw := radiusChain(t, map[string]interface{}{
		"src_port": 12345, "dst_port": 1812,
		"code": 1, "identifier": 0, "rounds": 1,
		"authenticator": "000102030405060708090a0b0c0d0e0f",
		"attributes": []interface{}{
			map[string]interface{}{"type": 1, "value": "user"},
			map[string]interface{}{"type": 8, "format": "ipv4", "value": "10.0.0.1"},
		},
		"response_code":      2,
		"response_attributes": []interface{}{
			map[string]interface{}{"type": 26, "vendor_id": 9, "value": "vs"},
		},
	})
	if _, err := layers.ValidateLayers(raw, "radius"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-RADIUS-1 §3】：translate + 生成器上线——[ip,radius] 链最小
// 2 包（req up/rsp down）。legacy 输出 L4.Protocol="udp"、RADIUS 报文在
// Payload（radius.go:320-368 emit 合同），auth code 1→2 auto、id 复刻。
func TestRadiusChain_LayerTranslateMinimalExchange(t *testing.T) {
	p := layers.NewChainPlannerFromChain("radius", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "radius", Config: map[string]interface{}{
			"src_port": 12345, "dst_port": 1812, "code": 1,
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
	wantCode := []byte{1, 2}
	wantDst := []uint16{1812, 12345}
	n := 0
	for pkt := range ch {
		if n >= 2 {
			t.Fatalf("packet overflow: got >2 packets")
		}
		if pkt.L4.Protocol != "udp" {
			t.Fatalf("packet %d: L4.Protocol=%q want udp", n+1, pkt.L4.Protocol)
		}
		if pkt.L4.DstPort != wantDst[n] {
			t.Fatalf("packet %d: dstPort=%d want %d", n+1, pkt.L4.DstPort, wantDst[n])
		}
		if len(pkt.Payload) < 20 || pkt.Payload[0] != wantCode[n] {
			t.Fatalf("packet %d: code=%d want %d (RADIUS header byte 0)", n+1, pkt.Payload[0], wantCode[n])
		}
		n++
	}
	if n != 2 {
		t.Fatalf("packets=%d want 2 (one round = req+resp)", n)
	}
}

// 红例④【D-RADIUS-1 决策 C】：translate 把层 config 填进 spec.Radius——
// 经 ValidateSpec 后 spec.Radius 非 nil 且 7 键逐槽+attributes round-trip
// +VSA vendor_id（实现前恒 nil = "radius config is required"）。
func TestRadiusChain_PresenceFilled(t *testing.T) {
	p := layers.NewChainPlannerFromChain("radius", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "radius", Config: map[string]interface{}{
			"code": 4, "identifier": 7, "rounds": 2,
			"authenticator": "000102030405060708090a0b0c0d0e0f",
			"attributes": []interface{}{
				map[string]interface{}{"type": 40, "format": "uint32", "value": "1"},
			},
			"response_code": 5,
			"response_attributes": []interface{}{
				map[string]interface{}{"type": 26, "vendor_id": 9, "value": "vs"},
			},
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	out, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if out.Radius == nil {
		t.Fatal("spec.Radius must be translated from the layer config")
	}
	g := out.Radius
	if g.Code != 4 || g.Identifier != 7 || g.Rounds != 2 || g.ResponseCode != 5 ||
		g.Authenticator != "000102030405060708090a0b0c0d0e0f" {
		t.Fatalf("business keys not mapped: %+v", g)
	}
	if len(g.Attributes) != 1 || g.Attributes[0].Type != 40 || g.Attributes[0].Format != "uint32" || g.Attributes[0].Value != "1" {
		t.Fatalf("attributes not drilled: %+v", g.Attributes)
	}
	if len(g.ResponseAttributes) != 1 || g.ResponseAttributes[0].VendorID != 9 || g.ResponseAttributes[0].Type != 26 {
		t.Fatalf("response_attributes not drilled: %+v", g.ResponseAttributes)
	}
	// 顺序修正专项：acct(code=4) 且 dst_port 层键缺席 → translate 自补
	// 1813（覆盖 validateSpecBase :770 预写的 1812）。
	if out.DstPort != 1813 {
		t.Fatalf("acct dstPort=%d want 1813 (:770 prewrite wins-over fix)", out.DstPort)
	}
}

// 红例⑤（专项补例）：auth(code=1) dst 缺席 → 1812。
func TestRadiusChain_AuthPort1812(t *testing.T) {
	p := layers.NewChainPlannerFromChain("radius", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "radius", Config: map[string]interface{}{"code": 1}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	out, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if out.DstPort != 1812 {
		t.Fatalf("auth dstPort=%d want 1812", out.DstPort)
	}
}
