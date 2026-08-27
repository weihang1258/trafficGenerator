// 外部测试包：rip 链的字节级对比需要 legacy rip.NewPlanner 与 chain
// （internal/protocol/rip + internal/core/layers）。测试贴近真实调用方
// （main.go 的 layers.NewChainPlanner("rip")）。
package layers_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/rip"
)

// ripSpec builds a minimal RIP v2 response spec（与 legacy rip_test.go ripSpec
// 同构：显式 4-tuple + SrcMAC）。DstMAC 留空——多播/广播事件由链层按 DstIP
// 推导（multicastDstMAC：224.0.0.9→01:00:5e:00:00:09、255.255.255.255→
// ff:ff:ff:ff:ff:ff、FF02::9→33:33:00:00:00:09）。注意：legacy rip 无
// resolveMulticastMAC——它恒落 spec.DstMAC（rip.go:657-659），链层推导是
// 本波的声明分歧，详见 maskRIPVolatile 注释与
// TestChainPlanner_RIP_MulticastMACDerivation。
func ripSpec(cfg *core.RIPConfig) core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 52001,
		DstPort: 520,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		RIP:     cfg,
	}
}

// assertRIPIdentical builds both packets and compares wire bytes after
// masking the volatile IPID/checksum fields. rip payload 确定性（固定头）。
func assertRIPIdentical(t *testing.T, chain, legacy core.PacketConfig, idx int) {
	t.Helper()
	b := core.NewBuilder()
	cb, err := b.Build(chain)
	if err != nil {
		t.Fatalf("Build(chain[%d]): %v", idx, err)
	}
	lb, err := b.Build(legacy)
	if err != nil {
		t.Fatalf("Build(legacy[%d]): %v", idx, err)
	}
	if !bytes.Equal(maskRIPVolatile(cb), maskRIPVolatile(lb)) {
		t.Errorf("packet %d bytes differ:\nchain  %x\nlegacy %x", idx, cb, lb)
	}
}

// maskRIPVolatile zeroes the fields that legitimately differ between chain
// and legacy builders: IPID (18-19) and IP checksum (24-25) are volatile
// per-build, and the L2 DstMAC (0-5) when the destination is multicast or
// broadcast (IPv4 224-239 / 255.255.255.255; IPv6 FF00::/8). For such
// destinations the chain derives the MAC from the DstIP (multicastDstMAC,
// RFC 1112 §6.4), while legacy rip emits spec.DstMAC unconditionally
// (rip.go:657-659, empty → zero-filled) — a documented structural deviation
// (see TestChainPlanner_RIP_MulticastMACDerivation). For unicast the DstMAC
// must match byte-for-byte (chain l2For vs legacy spec.DstMAC), so it is NOT
// masked — a mismatch there is a real divergence
// (see TestChainPlanner_RIP_UnicastDstMACNotMasked).
func maskRIPVolatile(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	if len(out) > 38 {
		out[18], out[19] = 0, 0
		out[24], out[25] = 0, 0
		etherType := uint16(out[12])<<8 | uint16(out[13])
		switch etherType {
		case 0x0800: // IPv4：dst IP @30-33
			if (out[30] >= 224 && out[30] <= 239) ||
				(out[30] == 255 && out[31] == 255 && out[32] == 255 && out[33] == 255) {
				for i := 0; i < 6; i++ {
					out[i] = 0
				}
			}
		case 0x86DD: // IPv6：dst IP @38-53
			if out[38] == 0xff {
				for i := 0; i < 6; i++ {
					out[i] = 0
				}
			}
		}
	}
	return out
}

// TestChainPlanner_RIP_V2MulticastUpdate verifies the [ip→udp→rip] chain
// emits one multicast datagram to 224.0.0.9 with TTL=1, src=520 (well-known),
// DSCP=0 (legacy dead-param: emitRIPPacket 的 L3Base 用 spec.DSCP 直配，CS6
// 默认从不达线), byte-identical to legacy (legacy TestTPOS6_MulticastUpdate 同款)。
func TestChainPlanner_RIP_V2MulticastUpdate(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "v2",
		Command:   "response",
		Multicast: true,
		Routes:    []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.SrcPort = 0 // 单 router Response → src=520（resolveSrcPort）
	spec.DstPort = 0 // 未设 → 版本默认 520
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Direction != "up" {
		t.Errorf("direction = %s, want up", chain[0].Direction)
	}
	if chain[0].L3.DstIP != "224.0.0.9" {
		t.Errorf("L3.DstIP = %q, want 224.0.0.9 (v2 multicast group)", chain[0].L3.DstIP)
	}
	if chain[0].L3.TTL != 1 {
		t.Errorf("L3.TTL = %d, want 1 (multicast)", chain[0].L3.TTL)
	}
	// 多播 MAC 推导（RFC 1112 §6.4）：224.0.0.9 → 01:00:5e:00:00:09。
	if chain[0].L2.DstMAC != "01:00:5e:00:00:09" {
		t.Errorf("L2.DstMAC = %q, want 01:00:5e:00:00:09", chain[0].L2.DstMAC)
	}
	if chain[0].L2.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("L2.SrcMAC = %q, want aa:bb:cc:dd:ee:ff (spec.SrcMAC)", chain[0].L2.SrcMAC)
	}
	// Response 从 well-known 520 发出（RFC 2453 §3.6）。
	if chain[0].L4.SrcPort != 520 || chain[0].L4.DstPort != 520 {
		t.Errorf("L4 ports = %d/%d, want 520/520", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	// DSCP = 0：legacy 的 dscp 计算（默认 CS6）是死参数——emitRIPPacket 用
	// L3Base(..., spec)，DSCP 恒等于 spec.DSCP（此处 0），字节一致即证。
	if chain[0].L3.DSCP != 0 {
		t.Errorf("L3.DSCP = %d, want 0 (legacy dead-param semantics: spec.DSCP passthrough)", chain[0].L3.DSCP)
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_RIP_MulticastMACDerivation documents the deliberate
// structural deviation behind maskRIPVolatile's DstMAC masking: with a
// NON-EMPTY spec.DstMAC (real API flows default to 02:00:00:00:00:02,
// strategy_convert.go), legacy rip emits spec.DstMAC unconditionally
// (rip.go:657-659) even for multicast groups, while the chain derives the
// RFC 1112 §6.4 multicast MAC from the DstIP. The chain's derivation is the
// wire-correct behavior (01:00:5e + low 23 bits of 224.0.0.9); the test
// asserts it explicitly so the divergence is provably intentional, not
// masked. mdns legacy derives the multicast MAC itself, so this deviation
// is rip-specific.
func TestChainPlanner_RIP_MulticastMACDerivation(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "v2",
		Command:   "response",
		Multicast: true,
		Routes:    []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.DstMAC = "02:00:00:00:00:02" // 真实 API flow 默认（strategy_convert.go:224）
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	// 链：RFC 1112 §6.4 从 224.0.0.9 推导多播 MAC，spec.DstMAC 被忽略。
	if chain[0].L2.DstMAC != "01:00:5e:00:00:09" {
		t.Errorf("chain L2.DstMAC = %q, want 01:00:5e:00:00:09 (derived from 224.0.0.9)", chain[0].L2.DstMAC)
	}
	// legacy：spec.DstMAC 无条件落（02:00:00:00:00:02）——结构分歧即在此。
	if legacy[0].L2.DstMAC != "02:00:00:00:00:02" {
		t.Errorf("legacy L2.DstMAC = %q, want 02:00:00:00:00:02 (spec.DstMAC unconditional)", legacy[0].L2.DstMAC)
	}
	// 字节对比仍通过（maskRIPVolatile 只掩派生 MAC 段，链的推导值被掩后
	// 与 legacy 的空值对齐——派生是唯一差异）。
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_RIP_UnicastDstMACNotMasked proves the mask does NOT hide
// unicast DstMAC differences: chain l2For and legacy emitRIPPacket both
// produce spec.DstMAC, so the bytes must match unmasked. If the mask ever
// grew to swallow this, the test fails the byte comparison and catches it.
func TestChainPlanner_RIP_UnicastDstMACNotMasked(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routes:  []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.DstMAC = "02:00:00:00:00:02"
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L2.DstMAC != spec.DstMAC {
		t.Errorf("chain unicast L2.DstMAC = %q, want %q (l2For)", chain[0].L2.DstMAC, spec.DstMAC)
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}
// 255.255.255.255 + ff:ff:ff:ff:ff:ff MAC + TTL=1, byte-identical to legacy
// (legacy TestTPOS1 同款：v1 即使 multicast=false 也广播)。
func TestChainPlanner_RIP_V1Broadcast(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "v1",
		Command:   "response",
		Multicast: true,
		Routes:    []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L3.DstIP != "255.255.255.255" {
		t.Errorf("L3.DstIP = %q, want 255.255.255.255 (v1 broadcast)", chain[0].L3.DstIP)
	}
	if chain[0].L3.TTL != 1 {
		t.Errorf("L3.TTL = %d, want 1 (broadcast)", chain[0].L3.TTL)
	}
	if chain[0].L2.DstMAC != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("L2.DstMAC = %q, want ff:ff:ff:ff:ff:ff (broadcast)", chain[0].L2.DstMAC)
	}
	// v1 固定 4 字节头 + 20 字节 RTE = 24。
	if len(chain[0].Payload) != 24 {
		t.Errorf("payload = %d bytes, want 24", len(chain[0].Payload))
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_RIP_SimpleAuth verifies the auth entry lands in the payload
// (AFI=0xFFFF), byte-identical to legacy (legacy TestTPOS8_SimpleAuth 同款)。
func TestChainPlanner_RIP_SimpleAuth(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Auth: &core.RIPAuth{
			Type:     "simple",
			Password: "secret123",
		},
		Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.DstIP = "192.168.1.2" // unicast：保留用户 DstIP
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	// 4 头 + 20 auth + 20 route = 44。
	if len(chain[0].Payload) != 44 {
		t.Errorf("payload = %d bytes, want 44", len(chain[0].Payload))
	}
	if chain[0].Payload[4] != 0xFF || chain[0].Payload[5] != 0xFF {
		t.Errorf("auth AFI = %02x%02x, want FFFF", chain[0].Payload[4], chain[0].Payload[5])
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_RIP_RequestFull verifies request_full yields Request +
// auto-Response on the same 4-tuple, src=52001 (ephemeral, requesting host),
// byte-identical to legacy (legacy TestTPOS1_RequestFull 同款)。
func TestChainPlanner_RIP_RequestFull(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:  "v2",
		Command:  "request",
		Scenario: "request_full",
	}
	spec := ripSpec(cfg)
	spec.SrcPort = 0
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2 (request + auto-response)", len(chain))
	}
	// Request：AFI=0 特殊 entry（RFC 2453 §3.9.1），src=52001。
	reqPkt := chain[0]
	if reqPkt.L4.SrcPort != 52001 {
		t.Errorf("request SrcPort = %d, want 52001 (ephemeral)", reqPkt.L4.SrcPort)
	}
	if reqPkt.L4.DstPort != 520 {
		t.Errorf("request DstPort = %d, want 520", reqPkt.L4.DstPort)
	}
	// 4 头 + 20 特殊 entry = 24。
	if len(reqPkt.Payload) != 24 {
		t.Errorf("request payload = %d bytes, want 24", len(reqPkt.Payload))
	}
	// 同 4-tuple、同 FlowID（事件级覆盖，链层回填尊重之——legacy
	// rip.go:517-520 的 "src-dst-srcPort-dstPort" 含已解析端口 52001/520）。
	respPkt := chain[1]
	if respPkt.L4.SrcPort != 52001 || respPkt.L4.DstPort != 520 {
		t.Errorf("response ports = %d/%d, want 52001/520 (same tuple)",
			respPkt.L4.SrcPort, respPkt.L4.DstPort)
	}
	wantFlowID := fmt.Sprintf("%s-%s-%d-%d", "192.168.1.1", "192.168.1.2", 52001, 520)
	if respPkt.FlowID != wantFlowID {
		t.Errorf("response FlowID = %q, want %q", respPkt.FlowID, wantFlowID)
	}
	if respPkt.FlowID != reqPkt.FlowID {
		t.Errorf("FlowID differ: %q vs %q", respPkt.FlowID, reqPkt.FlowID)
	}
	// request_full 共享 per-flow 索引 0/1（legacy rip.go:535-550 同款：
	// Request index 0、auto-Response index 1），非全局递增。
	if reqPkt.PacketIndex != 0 || respPkt.PacketIndex != 1 {
		t.Errorf("PacketIndex = %d/%d, want 0/1 (shared per-4-tuple)", reqPkt.PacketIndex, respPkt.PacketIndex)
	}
	for i := 0; i < 2; i++ {
		assertRIPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_RIP_MultiRouter verifies each router gets its own 4-tuple
// with src=52001+idx (design §6.13), byte-identical to legacy
// (legacy TestTPOS16b_MultiRouterDefaultPorts 同款)。
func TestChainPlanner_RIP_MultiRouter(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routers: []core.RIPRouter{
			{SrcIP: "192.168.1.1"},
			{SrcIP: "192.168.1.2"},
			{SrcIP: "192.168.2.1"},
		},
		Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.SrcPort = 0
	spec.SrcIP = "192.168.1.1"
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 3 {
		t.Fatalf("chain produced %d packets, want 3", len(chain))
	}
	for i, c := range chain {
		if c.L4.SrcPort != uint16(52001+i) {
			t.Errorf("router %d SrcPort = %d, want %d", i, c.L4.SrcPort, 52001+i)
		}
		// 每 router 独立源 IP（legacy rip.go:461-464：router.SrcIP 回退
		// spec.SrcIP——事件级 SrcIP 覆盖，ip 层注入的 spec.SrcIP 不适用）。
		if c.L3.SrcIP != cfg.Routers[i].SrcIP {
			t.Errorf("router %d SrcIP = %q, want %q", i, c.L3.SrcIP, cfg.Routers[i].SrcIP)
		}
		// 每 router 独立 flowID（legacy rip.go:517-520：router%d- 前缀 +
		// 已解析端口 + 有效目标），事件级覆盖后链层回填尊重之——不再是
		// spec 级 "192.168.1.1-192.168.1.2-0-520"。
		wantFlowID := fmt.Sprintf("router%d-%s-%s-%d-%d", i,
			cfg.Routers[i].SrcIP, "192.168.1.2", 52001+i, 520)
		if c.FlowID != wantFlowID {
			t.Errorf("router %d FlowID = %q, want %q", i, c.FlowID, wantFlowID)
		}
		// 每 router 独立 per-flow 索引（从 0 起）。
		if c.PacketIndex != 0 {
			t.Errorf("router %d PacketIndex = %d, want 0 (per-router)", i, c.PacketIndex)
		}
		assertRIPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_RIP_Rounds verifies rounds=2 emits 2 independent Response
// messages (each a fresh message; auth first-packet per round), byte-identical
// to legacy (legacy T-POS-7 同款)。
func TestChainPlanner_RIP_Rounds(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Rounds:  2,
		Routes:  []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// 每 round 独立消息：Payload 相同（确定性），PacketIndex 递增。
	if !bytes.Equal(chain[0].Payload, chain[1].Payload) {
		t.Errorf("round payloads differ")
	}
	// 单 router：事件级 per-flow 索引从 0 起（round 0 = 0, round 1 = 1）。
	if chain[0].PacketIndex != 0 || chain[1].PacketIndex != 1 {
		t.Errorf("PacketIndex = %d/%d, want 0/1 (per-router from 0)", chain[0].PacketIndex, chain[1].PacketIndex)
	}
	for i := 0; i < 2; i++ {
		assertRIPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_RIP_SplitHorizonPoisonReverse verifies unicast filtering:
// next-hop route toward the receiver is skipped (split horizon) or metric=16
// (poison reverse), byte-identical to legacy. 多播跳过过滤（无具体接收者）。
func TestChainPlanner_RIP_SplitHorizonPoisonReverse(t *testing.T) {
	routes := []core.RIPRoute{
		{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1},
		{IPAddr: "192.168.5.0", SubnetMask: "255.255.255.0", Metric: 1, NextHop: "192.168.1.2"},
	}
	cfg := &core.RIPConfig{
		Version:      "v2",
		Command:      "response",
		Routes:       routes,
		SplitHorizon: true,
	}
	spec := ripSpec(cfg)
	spec.DstIP = "192.168.1.2" // unicast receiver == NextHop → route filtered
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	// 过滤后仅剩 1 条路由：4 头 + 20 = 24。
	if len(chain[0].Payload) != 24 {
		t.Errorf("split-horizon payload = %d bytes, want 24 (1 route after filter)", len(chain[0].Payload))
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)

	// Poison reverse：同一路由 metric=16 保留。
	cfg2 := &core.RIPConfig{
		Version:       "v2",
		Command:       "response",
		Routes:        routes,
		PoisonReverse: true,
	}
	spec2 := ripSpec(cfg2)
	spec2.DstIP = "192.168.1.2"
	chain2 := collectPlanner(t, layers.NewChainPlanner("rip"), spec2)
	legacy2 := collectPlanner(t, rip.NewPlanner(), spec2)
	if len(chain2) != 1 {
		t.Fatalf("poison chain produced %d packets, want 1", len(chain2))
	}
	if len(chain2[0].Payload) != 44 {
		t.Errorf("poison payload = %d bytes, want 44 (2 routes, one poisoned)", len(chain2[0].Payload))
	}
	assertRIPIdentical(t, chain2[0], legacy2[0], 0)
}

// TestChainPlanner_RIP_UnicastTTLSpec verifies unicast honors spec.TTL
// (legacy rip.go:486-492：multicast→1、unicast→spec.TTL 或 64)。
func TestChainPlanner_RIP_UnicastTTLSpec(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routes:  []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	spec := ripSpec(cfg)
	spec.DstIP = "192.168.1.2"
	spec.TTL = 128
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if chain[0].L3.TTL != 128 {
		t.Errorf("L3.TTL = %d, want 128 (spec.TTL honored for unicast)", chain[0].L3.TTL)
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)

	// spec.TTL=0 → 默认 64。
	spec2 := ripSpec(cfg)
	spec2.DstIP = "192.168.1.2"
	chain2 := collectPlanner(t, layers.NewChainPlanner("rip"), spec2)
	if chain2[0].L3.TTL != 64 {
		t.Errorf("L3.TTL = %d, want 64 (default)", chain2[0].L3.TTL)
	}
}

// TestChainPlanner_RIP_RIPng verifies the ng path: port 521, FF02::9 group,
// 33:33:00:00:00:09 MAC, byte-identical to legacy。
func TestChainPlanner_RIP_RIPng(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:   "ng",
		Command:   "response",
		Multicast: true,
		Routes:    []core.RIPRoute{{IPAddr: "2001:db8::", PrefixLen: 64, Metric: 1}},
	}
	spec := core.FlowSpec{
		SrcIP:  "fe80::1",
		DstIP:  "ff02::9",
		SrcMAC: "02:00:00:00:00:01",
		RIP:    cfg,
	}
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L3.DstIP != "FF02::9" {
		t.Errorf("L3.DstIP = %q, want FF02::9", chain[0].L3.DstIP)
	}
	if chain[0].L2.DstMAC != "33:33:00:00:00:09" {
		t.Errorf("L2.DstMAC = %q, want 33:33:00:00:00:09", chain[0].L2.DstMAC)
	}
	if chain[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType = %04x, want 86DD (IPv6)", chain[0].L2.EtherType)
	}
	if chain[0].L4.SrcPort != 521 || chain[0].L4.DstPort != 521 {
		t.Errorf("L4 ports = %d/%d, want 521/521 (RIPng)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	if chain[0].L3.TTL != 1 {
		t.Errorf("L3.TTL = %d, want 1 (multicast)", chain[0].L3.TTL)
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_RIP_ValidateNegative mirrors legacy Validate: RIP config
// required, invalid version, v1+auth rejected, bad metric, bad IP。
func TestChainPlanner_RIP_ValidateNegative(t *testing.T) {
	p := layers.NewChainPlanner("rip")

	// nil config → 默认化产默认流（P0b-2）。
	spec := ripSpec(nil)
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate(nil RIP) = %v, want nil (default flow, P0b-2)", err)
	}

	// 非法版本。
	spec = ripSpec(&core.RIPConfig{Version: "v3", Command: "response"})
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(version v3) = nil, want error")
	}

	// v1 + auth → error。
	spec = ripSpec(&core.RIPConfig{Version: "v1", Command: "response",
		Auth: &core.RIPAuth{Type: "simple", Password: "secret"}})
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(v1+auth) = nil, want error")
	}

	// 非法 metric。
	spec = ripSpec(&core.RIPConfig{Version: "v2", Command: "response",
		Routes: []core.RIPRoute{{IPAddr: "10.0.0.0", Metric: 255}}})
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(metric 255) = nil, want error")
	}

	// 非法 IP（unicast）。
	spec = ripSpec(&core.RIPConfig{Version: "v2", Command: "response"})
	spec.DstIP = "nope"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(invalid DstIP) = nil, want error")
	}
}

// TestChainPlanner_RIP_DefaultRoutes verifies response_default scenario fills
// the 5 default routes when Routes is nil, byte-identical to legacy。
func TestChainPlanner_RIP_DefaultRoutes(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
	}
	spec := ripSpec(cfg) // Routes nil → 默认 5 条
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	// 4 头 + 5×20 RTE = 104。
	if len(chain[0].Payload) != 104 {
		t.Errorf("payload = %d bytes, want 104 (5 default routes)", len(chain[0].Payload))
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_RIP_TriggeredUpdate verifies TriggeredUpdate forces
// command=response even for an explicit request (legacy rip.go:415-421:
// Scenario > Command > TriggeredUpdate; R-3-HIGH-3), and scenario derivation
// still fills response_default routes, byte-identical to legacy。
func TestChainPlanner_RIP_TriggeredUpdate(t *testing.T) {
	cfg := &core.RIPConfig{
		Version:         "v2",
		Command:         "request",
		TriggeredUpdate: true,
	}
	spec := ripSpec(cfg)
	spec.SrcPort = 0 // 单 router Response → 520
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Payload[0] != 2 {
		t.Errorf("command byte = %d, want 2 (response, triggered override)", chain[0].Payload[0])
	}
	// request → 触发更新覆写为 response → response_default 场景填默认 5 条路由。
	if len(chain[0].Payload) != 104 {
		t.Errorf("payload = %d bytes, want 104 (5 default routes)", len(chain[0].Payload))
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_RIP_ExplicitEmptyRoutes verifies an explicit empty Routes
// slice (non-nil) yields a bare 4-byte header — scenario derivation does NOT
// re-fill defaultRoutes (legacy T-EDGE-6/T-POS-19 语义：nil 字段缺省 vs 显式
// 空 slice 是零路由), byte-identical to legacy。
func TestChainPlanner_RIP_ExplicitEmptyRoutes(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routes:  []core.RIPRoute{}, // 显式空 slice，非 nil
	}
	spec := ripSpec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if len(chain[0].Payload) != 4 {
		t.Errorf("payload = %d bytes, want 4 (bare header, explicit empty routes)", len(chain[0].Payload))
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_RIP_DSCPSpec verifies spec.DSCP passthrough on the wire
// for both multicast and unicast — the dead-param claim's positive proof:
// legacy emitRIPPacket 的 L3Base 恒用 spec.DSCP 直配（CS6 默认从不达线），
// 链层事件 DSCP=spec.DSCP 透传，字节一致。DSCP 落在 IP TOS 字节（帧偏移
// 15），maskRIPVolatile 不遮罩，字节比较直接验证。
func TestChainPlanner_RIP_DSCPSpec(t *testing.T) {
	for _, tc := range []struct {
		name      string
		multicast bool
	}{
		{"multicast", true},
		{"unicast", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &core.RIPConfig{
				Version:   "v2",
				Command:   "response",
				Multicast: tc.multicast,
				Routes:    []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
			}
			spec := ripSpec(cfg)
			spec.DSCP = 0x2E // AF11
			if !tc.multicast {
				spec.DstIP = "192.168.1.2"
			}
			chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
			legacy := collectPlanner(t, rip.NewPlanner(), spec)

			if len(chain) != 1 {
				t.Fatalf("chain produced %d packets, want 1", len(chain))
			}
			if chain[0].L3.DSCP != 0x2E {
				t.Errorf("L3.DSCP = %d, want 46 (0x2E, spec.DSCP passthrough)", chain[0].L3.DSCP)
			}
			assertRIPIdentical(t, chain[0], legacy[0], 0)
		})
	}
}

// TestChainPlanner_RIP_ValidateIPFamily verifies family consistency checks
// (legacy rip.go:212-222)：v1/v2 拒绝 IPv6 字面量、ng 拒绝 IPv4。
// 注：legacy 对 multicast 豁免 DstIP 家族检查（T-ERR-14），但链层的通用
// same-family 检查（chain_planner.go:130-135，防 L3 builder 混淆）仍拒绝
// v6-src + v4-dst 混合——对 ng multicast + 混合家族 spec 链层更严格，属
// 设计内差异（多播覆盖下 DstIP 本就是死值，混合家族是用户错误）。
func TestChainPlanner_RIP_ValidateIPFamily(t *testing.T) {
	p := layers.NewChainPlanner("rip")

	spec := ripSpec(&core.RIPConfig{Version: "v2", Command: "response"})
	spec.SrcIP = "fe80::1"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(v2 + IPv6 src) = nil, want family error")
	}

	spec = ripSpec(&core.RIPConfig{Version: "ng", Command: "response"})
	spec.SrcIP = "192.168.1.1"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(ng + IPv4 src) = nil, want family error")
	}

	// 链层更严格：ng multicast + v6-src/v4-dst 混合家族 → 拒绝（legacy 因
	// multicast 豁免 DstIP 家族检查而接受，链层 same-family 检查拦截）。
	spec = ripSpec(&core.RIPConfig{Version: "ng", Command: "response", Multicast: true})
	spec.SrcIP = "fe80::1"
	spec.DstIP = "192.168.1.2"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(ng multicast + mixed family) = nil, want same-family error (chain stricter than legacy)")
	}
}

// TestChainPlanner_RIP_SplitHorizonMulticast verifies split horizon / poison
// reverse filtering is skipped for multicast (无具体接收者，legacy rip.go:
// 500-505 同款)：指向接收者的 next-hop 路由在多播下保留。
func TestChainPlanner_RIP_SplitHorizonMulticast(t *testing.T) {
	routes := []core.RIPRoute{
		{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1},
		{IPAddr: "192.168.5.0", SubnetMask: "255.255.255.0", Metric: 1, NextHop: "192.168.1.2"},
	}
	cfg := &core.RIPConfig{
		Version:      "v2",
		Command:      "response",
		Multicast:    true,
		Routes:       routes,
		SplitHorizon: true,
	}
	spec := ripSpec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("rip"), spec)
	legacy := collectPlanner(t, rip.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	// 多播不过滤：2 条路由全部保留（4 头 + 40）。
	if len(chain[0].Payload) != 44 {
		t.Errorf("multicast payload = %d bytes, want 44 (2 routes kept, no filter)", len(chain[0].Payload))
	}
	assertRIPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_RIP_ContextCancel verifies ctx cancellation during the
// router loop aborts generation without hanging。
func TestChainPlanner_RIP_ContextCancel(t *testing.T) {
	cfg := &core.RIPConfig{
		Version: "v2",
		Command: "response",
		Routers: make([]core.RIPRouter, 50),
		Routes:  []core.RIPRoute{{IPAddr: "10.0.0.0", SubnetMask: "255.0.0.0", Metric: 1}},
	}
	for i := range cfg.Routers {
		cfg.Routers[i].SrcIP = fmt.Sprintf("192.168.1.%d", i+1)
	}
	spec := ripSpec(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := layers.NewChainPlanner("rip").Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	count := 0
	for range ch {
		count++
		if count == 5 {
			cancel()
		}
	}
	if count == 0 {
		t.Error("cancel-mid-rip yielded 0 packets; expected at least 5 before cancel")
	}
}
