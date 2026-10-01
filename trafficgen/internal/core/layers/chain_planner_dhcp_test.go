// 外部测试包：dhcp 链的字节级对比需要 legacy dhcp.NewPlanner 与 chain
// （internal/protocol/dhcp + internal/core/layers）。测试贴近真实调用方
// （main.go 的 layers.NewChainPlanner("dhcp")）。
package layers_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/dhcp"
)

// dhcpSpec builds a minimal DHCP spec（与 legacy dhcp_test.go 用例同构）。
// 端口留 0——dhcp 链 validateSpecBase 不默认化端口，生成器按角色解析
// （client 68→67、server 67→68、relay 67→67）。DstMAC 留空——广播目标由
// 事件显式覆盖为 ff:ff:ff:ff:ff:ff（legacy resolveMACs BroadcastMAC 语义）。
func dhcpSpec(cfg *core.DHCPConfig) core.FlowSpec {
	return core.FlowSpec{
		SrcIP:  "0.0.0.0",
		DstIP:  "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		DHCP:   cfg,
	}
}

func TestChainPlanner_DHCP_LayerConfigTranslates(t *testing.T) {
	p := layers.NewChainPlannerFromChain("dhcp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "0.0.0.0", "dst": "255.255.255.255"}},
		{Name: "udp", Config: map[string]interface{}{}},
		{Name: "dhcp", Config: map[string]interface{}{
			"role": "client", "xid": uint32(0x12345678),
			"messages": []interface{}{map[string]interface{}{"type": float64(dhcp.MsgTypeDiscover)}},
		}},
	})
	spec, err := p.ValidateSpec(core.FlowSpec{SrcIP: "0.0.0.0", DstIP: "255.255.255.255", SrcMAC: "aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if spec.DHCP == nil || spec.DHCP.Xid != 0x12345678 || len(spec.DHCP.Messages) != 1 {
		t.Fatalf("layer config was not translated: %+v", spec.DHCP)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	count := 0
	for pkt := range ch {
		count++
		if len(pkt.Payload) == 0 || pkt.L4.Protocol != "udp" {
			t.Fatalf("unexpected DHCP packet: %+v", pkt)
		}
	}
	if count != 1 {
		t.Fatalf("packets=%d, want 1", count)
	}
}

func assertDHCPIdentical(t *testing.T, chain, legacy core.PacketConfig, idx int) {
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
	if !bytes.Equal(maskDHCPVolatile(cb), maskDHCPVolatile(lb)) {
		t.Errorf("packet %d bytes differ:\nchain  %x\nlegacy %x", idx, cb, lb)
	}
}

// maskDHCPVolatile zeroes the fields that legitimately differ between chain
// and legacy builders: IPID (18-19) and IP checksum (24-25) are volatile
// per-build. DHCP 帧最小 46 字节（14 eth + 20 ip + 8 udp + 4 pad），38 字节
// 保护与 rip 同款。
func maskDHCPVolatile(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	if len(out) > 38 {
		out[18], out[19] = 0, 0
		out[24], out[25] = 0, 0
	}
	return out
}

// TestChainPlanner_DHCP_ClientDiscover verifies the [ip→udp→dhcp] chain
// emits one DISCOVER: 0.0.0.0:68 → spec.DstIP:67, TTL=64, byte-identical
// to legacy (legacy TestDHCPClientDiscover 同款，unicast spec 目标)。
func TestChainPlanner_DHCP_ClientDiscover(t *testing.T) {
	cfg := &core.DHCPConfig{
		Role:     "client",
		Xid:      0x12345678,
		Messages: []core.DHCPMessage{{Type: dhcp.MsgTypeDiscover}},
	}
	spec := dhcpSpec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Direction != "up" {
		t.Errorf("direction = %s, want up", chain[0].Direction)
	}
	// spec 值直落（resolveIPs/resolveMACs 仅在 spec 为空时填缺省——DHCP 无
	// 广播标志时不做广播覆盖，legacy 语义）。
	if chain[0].L3.SrcIP != "0.0.0.0" || chain[0].L3.DstIP != "255.255.255.255" {
		t.Errorf("L3 IPs = %s/%s, want 0.0.0.0/255.255.255.255 (spec values)", chain[0].L3.SrcIP, chain[0].L3.DstIP)
	}
	if chain[0].L3.TTL != 64 {
		t.Errorf("L3.TTL = %d, want 64 (legacy DefaultTTL)", chain[0].L3.TTL)
	}
	if chain[0].L2.DstMAC != "11:22:33:44:55:66" {
		t.Errorf("L2.DstMAC = %q, want 11:22:33:44:55:66 (spec.DstMAC)", chain[0].L2.DstMAC)
	}
	if chain[0].L2.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("L2.SrcMAC = %q, want aa:bb:cc:dd:ee:ff (spec.SrcMAC)", chain[0].L2.SrcMAC)
	}
	if chain[0].L4.SrcPort != 68 || chain[0].L4.DstPort != 67 {
		t.Errorf("L4 ports = %d/%d, want 68/67 (client role)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	// BOOTP 头 236 + magic 4 + option53(3) + END(1) = 244。
	if len(chain[0].Payload) != 244 {
		t.Errorf("payload = %d bytes, want 244", len(chain[0].Payload))
	}
	if chain[0].Payload[0] != dhcp.OpBootrequest {
		t.Errorf("op = %d, want 1 (BOOTREQUEST)", chain[0].Payload[0])
	}
	assertDHCPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_DHCP_DORA verifies a 4-message DORA dialog (scenario 模式，
// 合成消息) with down-direction OFFER/ACK replies: down 包源 IP 交换为
// spec.DstIP、源 MAC 交换/回退、端口保持 67→68，byte-identical to legacy
// (legacy TestDHCPScenarioDora 同款)。
func TestChainPlanner_DHCP_DORA(t *testing.T) {
	cfg := &core.DHCPConfig{
		Role:                    "client",
		Xid:                     0xDEADBEEF,
		Scenario:                "dora",
		DefaultYourIP:           "192.168.1.100",
		DefaultServerIdentifier: "192.168.1.1",
		DefaultLeaseTime:        3600,
	}
	spec := dhcpSpec(cfg)
	spec.DstIP = "192.168.1.1" // 服务器 IP（down 包源）
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 4 {
		t.Fatalf("chain produced %d packets, want 4 (DORA)", len(chain))
	}
	// 与 legacy 逐字段核对（dump 实证）：scenario 消息无 Broadcast → 无广播
	// 覆盖；up 包目标=spec.DstIP/spec.DstMAC（服务器），down 包源=spec.DstIP/
	// 交换 MAC——spec.DstMAC 非空时不做 DefaultServerMAC 回退（回退仅当源
	// MAC 为空或广播，planner.go:569-571）；端口对每条消息恒为角色解析值
	// 68/67，方向无关（legacy planner.go:629-633，字节实证 down 包 68→67）。
	want := []struct {
		direction string
		srcIP     string
		dstIP     string
		srcMAC    string
		dstMAC    string
		op        byte
		msgType   byte
	}{
		{"up", "0.0.0.0", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 1, 1},   // DISCOVER
		{"down", "192.168.1.1", "0.0.0.0", "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff", 2, 2}, // OFFER
		{"up", "0.0.0.0", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 1, 3},   // REQUEST
		{"down", "192.168.1.1", "0.0.0.0", "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff", 2, 5}, // ACK
	}
	for i, w := range want {
		p := chain[i]
		if p.Direction != w.direction {
			t.Errorf("packet %d direction = %s, want %s", i, p.Direction, w.direction)
		}
		if p.L3.SrcIP != w.srcIP || p.L3.DstIP != w.dstIP {
			t.Errorf("packet %d L3 IPs = %s/%s, want %s/%s", i, p.L3.SrcIP, p.L3.DstIP, w.srcIP, w.dstIP)
		}
		// down 包源 MAC：交换 + DefaultServerMAC 回退（legacy 语义）。
		if p.L2.SrcMAC != w.srcMAC || p.L2.DstMAC != w.dstMAC {
			t.Errorf("packet %d L2 MACs = %s/%s, want %s/%s", i, p.L2.SrcMAC, p.L2.DstMAC, w.srcMAC, w.dstMAC)
		}
		// 端口恒为角色解析值（legacy 方向无关写，链层 L4PortOverride 直落）。
		if p.L4.SrcPort != 68 || p.L4.DstPort != 67 {
			t.Errorf("packet %d L4 ports = %d/%d, want 68/67 (role ports, direction-independent)", i, p.L4.SrcPort, p.L4.DstPort)
		}
		if p.L3.TTL != 64 {
			t.Errorf("packet %d L3.TTL = %d, want 64", i, p.L3.TTL)
		}
		if p.Payload[0] != w.op {
			t.Errorf("packet %d op = %d, want %d", i, p.Payload[0], w.op)
		}
		// option 53 = msg type（BOOTP 头 236 后 magic 4，选项首字节）。
		if p.Payload[240] != 53 || p.Payload[242] != w.msgType {
			t.Errorf("packet %d option 53 = %d/%d, want 53/%d", i, p.Payload[240], p.Payload[242], w.msgType)
		}
		// 同 4-tuple 共享 flowID + 消息序 PacketIndex（legacy 语义）。格式
		// 用已解析端口（68/67）——与链层默认回填的 spec 级 flowID
		// （0.0.0.0-192.168.1.1-0-0）可区分，证明事件覆盖生效。
		if p.FlowID != "0.0.0.0-192.168.1.1-68-67" {
			t.Errorf("packet %d FlowID = %q, want 0.0.0.0-192.168.1.1-68-67 (resolved, event-carried)", i, p.FlowID)
		}
		if p.PacketIndex != uint64(i) {
			t.Errorf("packet %d PacketIndex = %d, want %d", i, p.PacketIndex, i)
		}
		assertDHCPIdentical(t, p, legacy[i], i)
	}
}

// TestChainPlanner_DHCP_ServerRole verifies role=server: src=67/dst=68 端口、
// down 方向不交换 MAC（server 视角），up 包源 MAC = spec.DstMAC（客户端）。
func TestChainPlanner_DHCP_ServerRole(t *testing.T) {
	cfg := &core.DHCPConfig{
		Role: "server",
		Xid:  0xABCDEF01,
		Messages: []core.DHCPMessage{
			{Type: dhcp.MsgTypeDiscover},
			{Type: dhcp.MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		},
	}
	spec := dhcpSpec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// 端口 server 视角：resolvePorts = 67/68，方向无关（两条消息恒写）。
	if chain[0].L4.SrcPort != 67 || chain[0].L4.DstPort != 68 {
		t.Errorf("packet 0 L4 ports = %d/%d, want 67/68 (server role)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	if chain[1].L4.SrcPort != 67 || chain[1].L4.DstPort != 68 {
		t.Errorf("packet 1 L4 ports = %d/%d, want 67/68 (server role)", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	// server 视角 down：src=server MAC（spec.SrcMAC，无交换）、dst=client MAC。
	if chain[1].L2.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("packet 1 L2.SrcMAC = %q, want aa:bb:cc:dd:ee:ff (server src, no swap)", chain[1].L2.SrcMAC)
	}
	if chain[1].L2.DstMAC != "11:22:33:44:55:66" {
		t.Errorf("packet 1 L2.DstMAC = %q, want 11:22:33:44:55:66 (client dst)", chain[1].L2.DstMAC)
	}
	assertDHCPIdentical(t, chain[0], legacy[0], 0)
	assertDHCPIdentical(t, chain[1], legacy[1], 1)
}

// TestChainPlanner_DHCP_ExplicitUnicastReply verifies per-message Broadcast
// override: client role + Broadcast=false → OFFER 单播到 spec.SrcIP/SrcMAC
// （legacy planner.go:575-577 仅广播时覆盖 DstMAC，unicast 用 resolveMACs
// 结果）。DstMAC 显式落（事件 OverrideDstMAC=true + 解析值），非推导。
func TestChainPlanner_DHCP_ExplicitUnicastReply(t *testing.T) {
	f := false
	cfg := &core.DHCPConfig{
		Role: "client",
		Xid:  0x11223344,
		Messages: []core.DHCPMessage{
			{Type: dhcp.MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
			{Type: dhcp.MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1", Broadcast: &f},
		},
	}
	spec := dhcpSpec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// unicast down：目标 = 客户端 spec.SrcIP/SrcMAC（client 角色交换）。
	if chain[1].L3.DstIP != "0.0.0.0" {
		t.Errorf("packet 1 L3.DstIP = %q, want 0.0.0.0 (client src)", chain[1].L3.DstIP)
	}
	if chain[1].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("packet 1 L2.DstMAC = %q, want aa:bb:cc:dd:ee:ff (unicast to client)", chain[1].L2.DstMAC)
	}
	assertDHCPIdentical(t, chain[0], legacy[0], 0)
	assertDHCPIdentical(t, chain[1], legacy[1], 1)
}

// TestChainPlanner_DHCP_BroadcastDiscover verifies the real broadcast path:
// per-message Broadcast:true + 空 spec.DstMAC → resolveMACs 回退 BroadcastMAC
// （planner.go:723-725），消息级广播覆盖 DstMAC=ff:ff:ff:ff:ff:ff
// （planner.go:576-578），up 方向 DstIP 覆盖为 255.255.255.255
// （planner.go:604-605），BOOTP flags=0x8000（planner.go:505-507）。
func TestChainPlanner_DHCP_BroadcastDiscover(t *testing.T) {
	bcast := true
	cfg := &core.DHCPConfig{
		Role:     "client",
		Xid:      0x0BADF00D,
		Messages: []core.DHCPMessage{{Type: dhcp.MsgTypeDiscover, Broadcast: &bcast}},
	}
	spec := dhcpSpec(cfg)
	spec.DstMAC = "" // 空目标 → 广播回退路径（dhcpSpec 默认非空，须显式清空）
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L3.SrcIP != "0.0.0.0" {
		t.Errorf("L3.SrcIP = %q, want 0.0.0.0 (client has no IP)", chain[0].L3.SrcIP)
	}
	if chain[0].L3.DstIP != dhcp.BroadcastIP {
		t.Errorf("L3.DstIP = %q, want %q (broadcast override)", chain[0].L3.DstIP, dhcp.BroadcastIP)
	}
	if chain[0].L2.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("L2.SrcMAC = %q, want aa:bb:cc:dd:ee:ff", chain[0].L2.SrcMAC)
	}
	if chain[0].L2.DstMAC != dhcp.BroadcastMAC {
		t.Errorf("L2.DstMAC = %q, want %q (broadcast MAC)", chain[0].L2.DstMAC, dhcp.BroadcastMAC)
	}
	if chain[0].L4.SrcPort != 68 || chain[0].L4.DstPort != 67 {
		t.Errorf("L4 ports = %d/%d, want 68/67 (client role)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	// BOOTP 头 flags 字段 = payload[10:12]（op1+htype1+hlen1+hops1+xid4+secs2）。
	if got := binary.BigEndian.Uint16(chain[0].Payload[10:12]); got != dhcp.BroadcastFlag {
		t.Errorf("BOOTP flags = 0x%x, want 0x%x (broadcast flag)", got, dhcp.BroadcastFlag)
	}
	assertDHCPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_DHCP_BroadcastFlagCfgLevel verifies the spec-level
// broadcast path (M1): cfg.BroadcastFlag=true 无 per-message Broadcast →
// 所有消息广播（layer_gen.go:122-129 msgBroadcast 取 cfg 级标志），广播覆盖
// 优先于显式单播 spec.DstMAC/DstIP（planner.go:576-578/604-605 语义）。
func TestChainPlanner_DHCP_BroadcastFlagCfgLevel(t *testing.T) {
	cfg := &core.DHCPConfig{
		Role:          "client",
		Xid:           0x0BADF00D,
		BroadcastFlag: true, // cfg 级广播标志（spec-level）
		Messages:      []core.DHCPMessage{{Type: dhcp.MsgTypeDiscover}},
	}
	spec := dhcpSpec(cfg) // 显式非空 DstMAC/DstIP——广播覆盖必须压过它们
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L3.DstIP != dhcp.BroadcastIP {
		t.Errorf("L3.DstIP = %q, want %q (cfg-level broadcast overrides spec.DstIP)", chain[0].L3.DstIP, dhcp.BroadcastIP)
	}
	if chain[0].L2.DstMAC != dhcp.BroadcastMAC {
		t.Errorf("L2.DstMAC = %q, want %q (cfg-level broadcast overrides spec.DstMAC)", chain[0].L2.DstMAC, dhcp.BroadcastMAC)
	}
	if got := binary.BigEndian.Uint16(chain[0].Payload[10:12]); got != dhcp.BroadcastFlag {
		t.Errorf("BOOTP flags = 0x%x, want 0x%x (cfg-level broadcast flag)", got, dhcp.BroadcastFlag)
	}
	if chain[0].L3.TTL != 64 {
		t.Errorf("L3.TTL = %d, want 64 (event TTL, marker-guarded)", chain[0].L3.TTL)
	}
	assertDHCPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_DHCP_DefaultServerMACFallback verifies the down-reply
// source-MAC fallback (M2): role=client + 空 spec.DstMAC → resolveMACs 回退
// BroadcastMAC，down 分支再回退 DefaultServerMAC=02:00:00:00:00:02
// （layer_gen.go:160-162 / planner.go:569-571 同款：广播 MAC 不能作源）。
func TestChainPlanner_DHCP_DefaultServerMACFallback(t *testing.T) {
	cfg := &core.DHCPConfig{
		Role: "client",
		Xid:  0xFEEDFACE,
		Messages: []core.DHCPMessage{
			{Type: dhcp.MsgTypeDiscover},
			{Type: dhcp.MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		},
	}
	spec := dhcpSpec(cfg)
	spec.DstMAC = ""           // 触发 BroadcastMAC→DefaultServerMAC 两级回退
	spec.DstIP = "192.168.1.1" // down 包源 IP（默认 255.255.255.255 无意义）
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// down OFFER：源 = DefaultServerMAC（非 ff:ff:ff:ff:ff:ff）、目标 = 客户端。
	if chain[1].L2.SrcMAC != dhcp.DefaultServerMAC {
		t.Errorf("packet 1 L2.SrcMAC = %q, want %q (DefaultServerMAC fallback)", chain[1].L2.SrcMAC, dhcp.DefaultServerMAC)
	}
	if chain[1].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("packet 1 L2.DstMAC = %q, want aa:bb:cc:dd:ee:ff (client)", chain[1].L2.DstMAC)
	}
	if chain[1].L3.SrcIP != "192.168.1.1" || chain[1].L3.DstIP != "0.0.0.0" {
		t.Errorf("packet 1 L3 IPs = %s/%s, want 192.168.1.1/0.0.0.0", chain[1].L3.SrcIP, chain[1].L3.DstIP)
	}
	assertDHCPIdentical(t, chain[0], legacy[0], 0)
	assertDHCPIdentical(t, chain[1], legacy[1], 1)
}

// TestChainPlanner_DHCP_ServerRoleEmptyMACs verifies the server-role
// empty-MAC branch (review M2 服务端变体，layer_gen.go:153-156）：server 角色
// down 不交换 MAC，源 MAC 为空时回退 DefaultServerMAC（legacy planner.go:
// 556-561 同款）；空 spec.DstMAC 时 resolveMACs 回退 BroadcastMAC 作客户端
// 目标。up 包（client 视角 DISCOVER）源 MAC = spec.DstMAC（客户端 MAC）。
func TestChainPlanner_DHCP_ServerRoleEmptyMACs(t *testing.T) {
	cfg := &core.DHCPConfig{
		Role: "server",
		Xid:  0xCAFEBABE,
		Messages: []core.DHCPMessage{
			{Type: dhcp.MsgTypeDiscover},
			{Type: dhcp.MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		},
	}
	spec := dhcpSpec(cfg)
	spec.SrcMAC = "" // 服务端 MAC 留空 → down 分支 DefaultServerMAC 回退
	spec.DstMAC = "" // 客户端 MAC 留空 → resolveMACs BroadcastMAC
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// down OFFER：源 = DefaultServerMAC（server 分支不做交换）、目标 = 广播 MAC。
	if chain[1].L2.SrcMAC != dhcp.DefaultServerMAC {
		t.Errorf("packet 1 L2.SrcMAC = %q, want %q (server-role fallback)", chain[1].L2.SrcMAC, dhcp.DefaultServerMAC)
	}
	if chain[1].L2.DstMAC != dhcp.BroadcastMAC {
		t.Errorf("packet 1 L2.DstMAC = %q, want %q (client via BroadcastMAC)", chain[1].L2.DstMAC, dhcp.BroadcastMAC)
	}
	// up DISCOVER：src = 客户端 MAC（role=server 时 clientMAC 取 spec.DstMAC）。
	if chain[0].L2.SrcMAC != "" {
		t.Errorf("packet 0 L2.SrcMAC = %q, want empty (client MAC unresolved)", chain[0].L2.SrcMAC)
	}
	assertDHCPIdentical(t, chain[0], legacy[0], 0)
	assertDHCPIdentical(t, chain[1], legacy[1], 1)
}

// TestChainPlanner_DHCP_ExplicitSpecPorts verifies explicit non-zero spec
// ports survive resolvePorts to the wire (review M3)：链层 validateSpecBase
// 不默认化端口，生成器 resolvePorts 保留显式值（planner.go:646-651 语义）。
func TestChainPlanner_DHCP_ExplicitSpecPorts(t *testing.T) {
	cfg := &core.DHCPConfig{
		Role:     "client",
		Xid:      0xABCDEF01,
		Messages: []core.DHCPMessage{{Type: dhcp.MsgTypeDiscover}},
	}
	spec := dhcpSpec(cfg)
	spec.SrcPort = 1068
	spec.DstPort = 1067
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L4.SrcPort != 1068 || chain[0].L4.DstPort != 1067 {
		t.Errorf("L4 ports = %d/%d, want 1068/1067 (explicit spec ports)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	assertDHCPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_DHCP_ManualMessagesOrder verifies manual (non-scenario)
// multi-message order + 显式 direction 覆盖（用户 direction 优先于类型推断）。
func TestChainPlanner_DHCP_ManualMessagesOrder(t *testing.T) {
	cfg := &core.DHCPConfig{
		Role: "client",
		Xid:  0x55667788,
		Messages: []core.DHCPMessage{
			{Type: dhcp.MsgTypeInform, ClientIP: "192.168.1.100", Direction: "up"},
			{Type: dhcp.MsgTypeAck, ServerIdentifier: "192.168.1.1", Direction: "down"},
		},
	}
	spec := dhcpSpec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)
	legacy := collectPlanner(t, dhcp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// INFORM 用 ciaddr 作源 IP（legacy planner.go:611-616 语义）。
	if chain[0].L3.SrcIP != "192.168.1.100" {
		t.Errorf("packet 0 L3.SrcIP = %q, want 192.168.1.100 (ciaddr as src)", chain[0].L3.SrcIP)
	}
	assertDHCPIdentical(t, chain[0], legacy[0], 0)
	assertDHCPIdentical(t, chain[1], legacy[1], 1)
}
