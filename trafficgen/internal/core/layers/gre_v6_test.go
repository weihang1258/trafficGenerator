package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dns"  // init 注册 dns 终结层生成器
	_ "github.com/trafficgen/trafficgen/internal/protocol/gre"  // init 注册 gre 隧道层生成器
	_ "github.com/trafficgen/trafficgen/internal/protocol/http" // init 注册 http 层生成器
)

// D-GRE-2 步骤 0 红例族（failing 先行，2026-09-15 探针转正）。
// 实现前全红：内层地址被 spec 广播顶掉 / v6 被结构段拒 / TTL 硬编码。
// 红例走 BuildLayersPlanner 全链口径（P2c 真实入口），不是直调内部函数。

func greChain(outerSrc, outerDst, innerSrc, innerDst string, gre map[string]interface{}, innerExtra map[string]interface{}) json.RawMessage {
	inner := map[string]interface{}{"src": innerSrc, "dst": innerDst}
	for k, v := range innerExtra {
		inner[k] = v
	}
	chain := []map[string]map[string]interface{}{
		{"ip": {"src": outerSrc, "dst": outerDst}},
		{"gre": gre},
		{"ip": inner},
		{"udp": {"src_port": float64(12345), "dst_port": float64(80)}},
		// query_only：本组测试断言单包 GRE 封装形状（D-DNS-2 后空 dns 层
		// 默认一问一答 2 包）。
		{"dns": {"query_only": true}},
	}
	raw, _ := json.Marshal(chain)
	return raw
}

func planGre(t *testing.T, layersJSON json.RawMessage, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	p, err := layers.BuildLayersPlanner("gre", layersJSON)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	out, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for pkt := range out {
		pkts = append(pkts, pkt)
	}
	return pkts
}

// 红例1【§1 A1 决策】：内层 ip 层显式标量必须保留——外 v4 内 v6 时出包
// 内层是 v6（现状：被 spec 广播静默换成 v4，探针 A）。
func TestGREChain_InnerScalarRespected(t *testing.T) {
	raw := greChain("10.0.0.1", "20.0.0.1", "fd00::1", "fd00::2", map[string]interface{}{}, nil)
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80}
	pkts := planGre(t, raw, spec)
	if len(pkts) == 0 {
		t.Fatal("0 packets")
	}
	inner := pkts[0].Payload
	if inner[0]>>4 != 6 {
		t.Errorf("inner IP version = %d, want 6 (fd00::1/fd00::2 were written in the inner ip layer; spec-broadcast must not override)", inner[0]>>4)
	}
	// fd00::1 前 2 字节 = fd 00（v6 内层源前缀；::1 在后半 8 字节）。
	if inner[8] != 0xfd || inner[9] != 0x00 {
		t.Errorf("inner src bytes [8:16] = % x, want fd00::1 prefix (fd 00 ...)", inner[8:16])
	}
}

// 红例2【§4 v6-in-v6 格】：纯 v6 隧道放行且 GRE proto=0x86DD（现状：结构段拒）。
func TestGREChain_V6InV6(t *testing.T) {
	raw := greChain("fd00::1", "fd00::2", "fd00::1", "fd00::2", map[string]interface{}{}, nil)
	spec := core.FlowSpec{SrcIP: "fd00::1", DstIP: "fd00::2", SrcPort: 12345, DstPort: 80}
	pkts := planGre(t, raw, spec)
	if len(pkts) != 1 {
		t.Fatalf("packets = %d, want 1", len(pkts))
	}
	pkt := pkts[0]
	if pkt.L2.GRE == nil || pkt.L2.GRE.ProtocolType != core.EtherTypeIPv6 {
		t.Errorf("GRE proto = %+v, want 0x86dd", pkt.L2.GRE)
	}
	if pkt.L3.Protocol != core.ProtocolGRE {
		t.Errorf("outer IP proto = %d, want 47", pkt.L3.Protocol)
	}
	if pkt.Payload[0]>>4 != 6 {
		t.Errorf("inner IP version = %d, want 6", pkt.Payload[0]>>4)
	}
}

// 红例3【§5 锚词】：内层两地址混族拒绝（v4 源 + v6 目的）。
func TestGREChain_InnerMixedFamilyRejected(t *testing.T) {
	raw := greChain("10.0.0.1", "20.0.0.1", "10.0.0.1", "fd00::2", map[string]interface{}{}, nil)
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80}
	p, err := layers.BuildLayersPlanner("gre", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	err = p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "must be the same IP version") {
		t.Fatalf("Validate err = %v, want inner same-IP-version rejection", err)
	}
}

// 红例4【§1 inner_ttl 决策 C1】：内层 ip 层 ttl=60 生效（现状：生成器硬编码 64）。
func TestGREChain_InnerTTLOverride(t *testing.T) {
	raw := greChain("10.0.0.1", "20.0.0.1", "10.0.0.1", "20.0.0.1", map[string]interface{}{},
		map[string]interface{}{"ttl": float64(60)})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80}
	pkts := planGre(t, raw, spec)
	if len(pkts) != 1 {
		t.Fatalf("packets = %d, want 1", len(pkts))
	}
	inner := pkts[0].Payload
	if inner[8] != 60 {
		t.Errorf("inner TTL byte = %d, want 60 (inner ip layer ttl)", inner[8])
	}
}

// 红例5【§12 双侧拒绝·ValidateLayers 侧】：内层 ip 层动态对象拒绝。
func TestGREChain_InnerDynRejected(t *testing.T) {
	chain := []map[string]interface{}{
		{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{"gre": map[string]interface{}{}},
		{"ip": map[string]interface{}{"src": map[string]interface{}{"strategy": "list", "list": []interface{}{"30.0.0.1", "30.0.0.2"}}}},
		{"udp": map[string]interface{}{"src_port": float64(12345), "dst_port": float64(80)}},
		{"dns": map[string]interface{}{}},
	}
	raw, _ := json.Marshal(chain)
	_, err := layers.ValidateLayers(raw, "gre")
	if err == nil || !strings.Contains(err.Error(), "inner ip layer does not support dynamic") {
		t.Fatalf("ValidateLayers err = %v, want inner-ip-dynamic rejection", err)
	}
}

// 红例6【§4 外层 v6 格 + §5 外层锚词】：外层 v6 + 内层 v4（4in6）放行；
// 顺带钉外层空地址锚词（独立子断言）。
func TestGREChain_V4InV6(t *testing.T) {
	raw := greChain("fd00::1", "fd00::2", "10.0.0.1", "20.0.0.1", map[string]interface{}{}, nil)
	spec := core.FlowSpec{SrcIP: "fd00::1", DstIP: "fd00::2", SrcPort: 12345, DstPort: 80}
	pkts := planGre(t, raw, spec)
	if len(pkts) != 1 {
		t.Fatalf("packets = %d, want 1", len(pkts))
	}
	pkt := pkts[0]
	if pkt.L2.GRE == nil || pkt.L2.GRE.ProtocolType != core.EtherTypeIPv4 {
		t.Errorf("GRE proto = %+v, want 0x0800 (v4 inner)", pkt.L2.GRE)
	}
	if pkt.L3.Protocol != core.ProtocolGRE {
		t.Errorf("outer IP proto = %d, want 47", pkt.L3.Protocol)
	}
	if pkt.Payload[0]>>4 != 4 {
		t.Errorf("inner IP version = %d, want 4", pkt.Payload[0]>>4)
	}
	// 外层 L3 地址是 spec 的 v6（finalEmit 交换语义下 up 帧保持 spec 序）。
	if pkt.L3.SrcIP != "fd00::1" || pkt.L3.DstIP != "fd00::2" {
		t.Errorf("outer IPs = %s->%s, want fd00::1->fd00::2", pkt.L3.SrcIP, pkt.L3.DstIP)
	}
}
