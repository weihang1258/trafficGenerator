// 外部测试包：dhcpv6 链的字节级对比需要 legacy dhcpv6.NewPlanner 与 chain
// （internal/protocol/dhcpv6 + internal/core/layers）。测试贴近真实调用方
// （main.go 的 layers.NewChainPlanner("dhcpv6")）。
package layers_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/dhcpv6"
)

// dhcpv6Spec builds a minimal DHCPv6 spec（与 legacy dhcpv6_test.go validSpec
// 同构）。端口留 0——dhcpv6 链 validateSpecBase 不默认化端口，生成器按方向
// 解析（up=client 546→547、down=server 547→546，legacy resolveAddrs 语义）。
// DstMAC 显式 33:33:00:01:00:02——legacy 从不推导 MAC（TestMulticast_DstMAC
// 语义），事件 OverrideDstMAC=true 原样落。DUID 显式（autoClientDUID 含
// time.Now() 非确定性，字节对比必须固定）。
func dhcpv6Spec(cfg *core.DHCPv6Config) core.FlowSpec {
	return core.FlowSpec{
		SrcIP:  "fe80::1",
		DstIP:  "ff02::1:2",
		SrcMAC: "00:11:22:33:44:55",
		DstMAC: "33:33:00:01:00:02",
		DHCPv6: cfg,
	}
}

// dhcpv6ExplicitDUIDs returns the deterministic DUID pair used by the tests
// （autoClientDUID 用 time.Now() 非确定性，autoServerDUID 是确定性 DUID-EN）。
func dhcpv6ExplicitDUIDs() (*core.DUID, *core.DUID) {
	return &core.DUID{
			Type:          dhcpv6.DUIDTypeLLT,
			HardwareType:  dhcpv6.HardwareTypeEthernet,
			Time:          0,
			LinkLayerAddr: "00:11:22:33:44:55",
		}, &core.DUID{
			Type:           dhcpv6.DUIDTypeEN,
			EnterpriseNum:  9,
			VendorSpecific: []byte("trafficgen"),
		}
}

// dhcpv6BaseCfg builds the shared manual-message config（显式 XID + DUID）。
func dhcpv6BaseCfg(messages []core.DHCPv6Message) *core.DHCPv6Config {
	clientDUID, serverDUID := dhcpv6ExplicitDUIDs()
	return &core.DHCPv6Config{
		ClientDUID: clientDUID,
		ServerDUID: serverDUID,
		Messages:   messages,
	}
}

// dhcpv6SARR builds the manual SARR message list（legacy TestScenario1_ 同构：
// 显式共享 XID、ClientID/ServerID 自动前置、IA_NA 直配）。
func dhcpv6SARR(xid [3]byte) []core.DHCPv6Message {
	return []core.DHCPv6Message{
		{
			MsgType:       dhcpv6.MsgTypeSolicit,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptORO, Data: buildORO()},
				{Code: dhcpv6.OptIANA, Data: buildIANAEmpty(1)},
			},
		},
		{
			MsgType:       dhcpv6.MsgTypeAdvertise,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptPreference, Data: []byte{0}},
				{Code: dhcpv6.OptIANA, Data: buildIANAWithAddr(1)},
			},
		},
		{
			MsgType:       dhcpv6.MsgTypeRequest,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptIANA, Data: buildIANAEmpty(1)},
			},
		},
		{
			MsgType:       dhcpv6.MsgTypeReply,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptIANA, Data: buildIANAWithAddr(1)},
			},
		},
	}
}

// ---- option builders（与 legacy test_helpers 同款字节布局）----

// buildORO builds option 6 data: requested option codes (2B each).
func buildORO() []byte {
	out := make([]byte, 0, 6)
	out = appendUint16(out, dhcpv6.OptRDNSS)
	out = appendUint16(out, dhcpv6.OptDNSSL)
	out = appendUint16(out, dhcpv6.OptSNTP)
	return out
}

// buildIANAEmpty builds option 3 data: IAID(4) + T1(4) + T2(4) + 0 sub-options.
func buildIANAEmpty(iaid uint32) []byte {
	out := make([]byte, 0, 12)
	out = appendUint32(out, iaid)
	out = appendUint32(out, 0)
	out = appendUint32(out, 0)
	return out
}

// buildIANAWithAddr builds option 3 data with one IAADDR sub-option
// （2001:db8::100, preferred=3600, valid=7200, no sub-options）。
func buildIANAWithAddr(iaid uint32) []byte {
	sub := make([]byte, 0, 24)
	sub = appendIP16(sub, "2001:db8::100")
	sub = appendUint32(sub, 3600)
	sub = appendUint32(sub, 7200)
	sub = appendUint16(sub, 0) // sub-option count
	iana := make([]byte, 0, 12)
	iana = appendUint32(iana, iaid)
	iana = appendUint32(iana, 1800)
	iana = appendUint32(iana, 2880)
	// 子选项包装进 option 5（IAADDR）TLV：code 5 + len 24 + data。
	out := make([]byte, 0, 12+4+2+len(sub))
	out = append(out, iana...)
	out = appendUint16(out, dhcpv6.OptIAAddr)
	out = appendUint16(out, uint16(len(sub)))
	out = append(out, sub...)
	return out
}

// buildRelayMsgOpt wraps inner bytes in option 9 (Relay Message) TLV.
func buildRelayMsgOpt(inner []byte) []byte {
	out := make([]byte, 0, 4+len(inner))
	out = appendUint16(out, dhcpv6.OptRelayMsg)
	out = appendUint16(out, uint16(len(inner)))
	out = append(out, inner...)
	return out
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendIP16(b []byte, s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		panic("appendIP16: not an IPv6 address: " + s)
	}
	return append(b, ip.To16()...)
}

// ---- 断言辅助 ----

// assertDHCPv6Identical builds both packets and compares wire bytes.
// IPv6 帧无掩码：IPv6 头无 IPID/header checksum（writeL3v6），UDP checksum
// 用最终 L3 SrcIP/DstIP 计算（calculateUDPChecksum），对固定地址/端口
// 确定性——legacy 与 chain 字节完全可比。
func assertDHCPv6Identical(t *testing.T, chain, legacy core.PacketConfig, idx int) {
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
	if !bytes.Equal(cb, lb) {
		t.Errorf("packet %d bytes differ (chain %d vs legacy %d bytes):\nchain  %x\nlegacy %x", idx, len(cb), len(lb), cb, lb)
	}
}

// TestChainPlanner_DHCPv6_SARR verifies the manual SARR 4-message dialog:
// 方向 up/down/up/down、端口 546/547 ↔ 547/546（resolveAddrs 按方向交换 +
// L4PortOverride 透传事件最终端口）、MAC/IP 交换、EtherType 0x86DD、
// 共享 XID、ClientID/ServerID 自动前置、flowID=spec 值拼接、PacketIndex
// 消息序——byte-identical to legacy (legacy TestScenario1_Standard4WayExchange
// 同款)。
func TestChainPlanner_DHCPv6_SARR(t *testing.T) {
	xid := [3]byte{0x12, 0x34, 0x56}
	cfg := dhcpv6BaseCfg(dhcpv6SARR(xid))
	spec := dhcpv6Spec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)
	legacy := collectPlanner(t, dhcpv6.NewPlanner(), spec)

	if len(chain) != 4 {
		t.Fatalf("chain produced %d packets, want 4 (SARR)", len(chain))
	}
	// 与 legacy 逐字段核对：up=client fe80::1→服务器 ff02::1:2、546/547；
	// down=服务器→client 交换 IP/MAC/端口 547/546；MAC 恒事件携带值
	// （OverrideDstMAC=true 阻止链层对 ff02:: 多播目标推导 33:33——legacy
	// 从不推导，TestMulticast_DstMAC 语义）。
	want := []struct {
		direction string
		srcIP     string
		dstIP     string
		srcMAC    string
		dstMAC    string
		srcPort   uint16
		dstPort   uint16
		msgType   byte
	}{
		{"up", "fe80::1", "ff02::1:2", "00:11:22:33:44:55", "33:33:00:01:00:02", dhcpv6.ClientPort, dhcpv6.ServerPort, 1},   // SOLICIT
		{"down", "ff02::1:2", "fe80::1", "33:33:00:01:00:02", "00:11:22:33:44:55", dhcpv6.ServerPort, dhcpv6.ClientPort, 2}, // ADVERTISE
		{"up", "fe80::1", "ff02::1:2", "00:11:22:33:44:55", "33:33:00:01:00:02", dhcpv6.ClientPort, dhcpv6.ServerPort, 3},   // REQUEST
		{"down", "ff02::1:2", "fe80::1", "33:33:00:01:00:02", "00:11:22:33:44:55", dhcpv6.ServerPort, dhcpv6.ClientPort, 7}, // REPLY
	}
	for i, w := range want {
		p := chain[i]
		if p.Direction != w.direction {
			t.Errorf("packet %d direction = %s, want %s", i, p.Direction, w.direction)
		}
		if p.L3.SrcIP != w.srcIP || p.L3.DstIP != w.dstIP {
			t.Errorf("packet %d L3 IPs = %s/%s, want %s/%s (resolveAddrs swap)", i, p.L3.SrcIP, p.L3.DstIP, w.srcIP, w.dstIP)
		}
		if p.L2.SrcMAC != w.srcMAC || p.L2.DstMAC != w.dstMAC {
			t.Errorf("packet %d L2 MACs = %s/%s, want %s/%s (no multicast derivation)", i, p.L2.SrcMAC, p.L2.DstMAC, w.srcMAC, w.dstMAC)
		}
		if p.L4.SrcPort != w.srcPort || p.L4.DstPort != w.dstPort {
			t.Errorf("packet %d L4 ports = %d/%d, want %d/%d (%s direction)", i, p.L4.SrcPort, p.L4.DstPort, w.srcPort, w.dstPort, w.direction)
		}
		if p.L2.EtherType != core.EtherTypeIPv6 {
			t.Errorf("packet %d EtherType = 0x%04x, want 0x86DD", i, p.L2.EtherType)
		}
		if p.L3.TTL != dhcpv6.DefaultTTL {
			t.Errorf("packet %d L3.TTL = %d, want 64 (event TTL)", i, p.L3.TTL)
		}
		if p.Payload[0] != w.msgType {
			t.Errorf("packet %d msg-type = %d, want %d", i, p.Payload[0], w.msgType)
		}
		if p.FlowID != "fe80::1-ff02::1:2-0-0" {
			t.Errorf("packet %d FlowID = %q, want fe80::1-ff02::1:2-0-0 (chain default from spec)", i, p.FlowID)
		}
		if p.PacketIndex != uint64(i) {
			t.Errorf("packet %d PacketIndex = %d, want %d", i, p.PacketIndex, i)
		}
		assertDHCPv6Identical(t, p, legacy[i], i)
	}
}

// TestChainPlanner_DHCPv6_ExplicitSpecPorts verifies explicit non-zero spec
// ports survive resolveAddrs to the wire: chain validateSpecBase 不默认化
// 端口，生成器保留显式值；down 交换仍 1068/1067 ↔ 1067/1068。
func TestChainPlanner_DHCPv6_ExplicitSpecPorts(t *testing.T) {
	xid := [3]byte{0xAB, 0xCD, 0xEF}
	cfg := dhcpv6BaseCfg([]core.DHCPv6Message{
		{MsgType: dhcpv6.MsgTypeSolicit, TransactionID: xid},
		{MsgType: dhcpv6.MsgTypeAdvertise, TransactionID: xid},
	})
	spec := dhcpv6Spec(cfg)
	spec.SrcPort = 1068
	spec.DstPort = 1067
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)
	legacy := collectPlanner(t, dhcpv6.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	if chain[0].L4.SrcPort != 1068 || chain[0].L4.DstPort != 1067 {
		t.Errorf("SOLICIT ports = %d/%d, want 1068/1067 (explicit spec ports)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	if chain[1].L4.SrcPort != 1067 || chain[1].L4.DstPort != 1068 {
		t.Errorf("ADVERTISE ports = %d/%d, want 1067/1068 (down swap)", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	assertDHCPv6Identical(t, chain[0], legacy[0], 0)
	assertDHCPv6Identical(t, chain[1], legacy[1], 1)
}

// TestChainPlanner_DHCPv6_RelayForwRepl verifies relay messages: RELAY-FORW
// 端点 = RelayConfig.RelayMAC/RelayIP（源）、端口 547/547；RELAY-REPL 目标
// = relay、547/547；34 字节中继头 + option 9 内层消息（legacy
// TestScenario9_RelayForwRepl 同构）。
func TestChainPlanner_DHCPv6_RelayForwRepl(t *testing.T) {
	cfg := dhcpv6BaseCfg(nil)
	cfg.RelayConfig = &core.RelayConfig{
		RelayIP:  "2001:db8::1",
		RelayMAC: "00:aa:bb:cc:dd:ee",
	}
	// 内层 SOLICIT/REPLY 字节（与 legacy 测试同构：inner 经独立 Plan 构建）。
	innerSolicit := innerMessage(t, dhcpv6.MsgTypeSolicit, [3]byte{0x12, 0x34, 0x56})
	innerReply := innerMessage(t, dhcpv6.MsgTypeReply, [3]byte{0x12, 0x34, 0x56})

	cfg.Messages = []core.DHCPv6Message{
		{
			MsgType: dhcpv6.MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount:    1,
				LinkAddress: "2001:db8::1",
				PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptRelayMsg, Data: innerSolicit},
			},
		},
		{
			MsgType: dhcpv6.MsgTypeRelayRepl,
			RelayFields: &core.RelayFields{
				HopCount:    1,
				LinkAddress: "2001:db8::1",
				PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptRelayMsg, Data: innerReply},
			},
		},
	}
	spec := dhcpv6Spec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)
	legacy := collectPlanner(t, dhcpv6.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// RELAY-FORW：源 = relay 端点（MAC/IP）、目标 = spec 服务器、547/547。
	if chain[0].L3.SrcIP != "2001:db8::1" || chain[0].L3.DstIP != "ff02::1:2" {
		t.Errorf("FORW L3 IPs = %s/%s, want 2001:db8::1/ff02::1:2", chain[0].L3.SrcIP, chain[0].L3.DstIP)
	}
	if chain[0].L2.SrcMAC != "00:aa:bb:cc:dd:ee" {
		t.Errorf("FORW L2.SrcMAC = %q, want relay MAC", chain[0].L2.SrcMAC)
	}
	if chain[0].L4.SrcPort != dhcpv6.ServerPort || chain[0].L4.DstPort != dhcpv6.ServerPort {
		t.Errorf("FORW ports = %d/%d, want 547/547", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	// RELAY-REPL：目标 = relay MAC/IP、547/547。
	if chain[1].L3.SrcIP != "ff02::1:2" || chain[1].L3.DstIP != "2001:db8::1" {
		t.Errorf("REPL L3 IPs = %s/%s, want ff02::1:2/2001:db8::1", chain[1].L3.SrcIP, chain[1].L3.DstIP)
	}
	if chain[1].L2.DstMAC != "00:aa:bb:cc:dd:ee" {
		t.Errorf("REPL L2.DstMAC = %q, want relay MAC", chain[1].L2.DstMAC)
	}
	if chain[1].L4.SrcPort != dhcpv6.ServerPort || chain[1].L4.DstPort != dhcpv6.ServerPort {
		t.Errorf("REPL ports = %d/%d, want 547/547", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	// 34 字节中继头 + option 9 内层消息。
	if chain[0].Payload[0] != dhcpv6.MsgTypeRelayForw || chain[1].Payload[0] != dhcpv6.MsgTypeRelayRepl {
		t.Errorf("msg-types = %d/%d, want 12/13", chain[0].Payload[0], chain[1].Payload[0])
	}
	if chain[0].Payload[1] != 1 {
		t.Errorf("FORW hop-count = %d, want 1", chain[0].Payload[1])
	}
	if !bytes.Equal(chain[0].Payload[34:38], buildRelayMsgOpt(innerSolicit)[0:4]) {
		t.Errorf("FORW option 9 header at 34 mismatch")
	}
	assertDHCPv6Identical(t, chain[0], legacy[0], 0)
	assertDHCPv6Identical(t, chain[1], legacy[1], 1)
}

// innerMessage builds inner DHCPv6 message bytes via the legacy planner
// （relay 测试的 option 9 内层载荷，与 legacy TestScenario9_ 同构）。
func innerMessage(t *testing.T, msgType uint8, xid [3]byte) []byte {
	t.Helper()
	cfg := dhcpv6BaseCfg([]core.DHCPv6Message{
		{
			MsgType:       msgType,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptIANA, Data: buildIANAEmpty(1)},
			},
		},
	})
	spec := dhcpv6Spec(cfg)
	legacy := collectPlanner(t, dhcpv6.NewPlanner(), spec)
	if len(legacy) != 1 {
		t.Fatalf("inner %d produced %d packets, want 1", msgType, len(legacy))
	}
	return legacy[0].Payload
}

// TestChainPlanner_DHCPv6_EmptyDstMAC_DerivesMulticastMAC verifies the
// empty-event-DstMAC fallback: spec.DstMAC 空 → 事件 DstMAC 空 →
// finalEmit 覆盖分支用 multicastDstMAC(ff02::1:2) 推导 33:33:00:01:00:02
// （与 mdns/ssdp 链同款推导路径；legacy dhcpv6 永不推导——本测试只验证
// 链层 fallback，不对比 legacy）。
func TestChainPlanner_DHCPv6_EmptyDstMAC_DerivesMulticastMAC(t *testing.T) {
	xid := [3]byte{0x11, 0x22, 0x33}
	cfg := dhcpv6BaseCfg([]core.DHCPv6Message{
		{MsgType: dhcpv6.MsgTypeSolicit, TransactionID: xid},
	})
	spec := dhcpv6Spec(cfg)
	spec.DstMAC = "" // 空目标 → 链层 multicastDstMAC 推导（dhcpv6Spec 默认非空）
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L2.DstMAC != "33:33:00:01:00:02" {
		t.Errorf("L2.DstMAC = %q, want 33:33:00:01:00:02 (derived from ff02::1:2)", chain[0].L2.DstMAC)
	}
	if chain[0].L2.SrcMAC != "00:11:22:33:44:55" {
		t.Errorf("L2.SrcMAC = %q, want 00:11:22:33:44:55 (事件 SrcMAC，resolveAddrs 直配 spec.SrcMAC)", chain[0].L2.SrcMAC)
	}
	if chain[0].L2.EtherType != core.EtherTypeIPv6 {
		t.Errorf("EtherType = 0x%04x, want 0x86DD", chain[0].L2.EtherType)
	}
}

// TestChainPlanner_DHCPv6_EmptyDstIP 覆盖空 spec.DstIP 负路径（RFC 8415 §11
// client 可留目标未指定；dhcpv6 Validate 允许空 IP）：up SOLICIT 事件
// DstIP=""（resolveAddrs 直配空值），链层不得注入多余目标（isDHCPv6Chain
// 豁免 ip 层 dst 默认）——字节与 legacy 完全一致（全零 :: 目标 + 确定性
// checksum）。down ADVERTISE 是显式文档化的结构分歧（波 5 mdns 先例）：
// resolveAddrs 把空 spec.DstIP 交换进 down srcIP，ip 层 srcSet 注入
// spec.SrcIP（"fe80::1"），链层产出 fe80::1→fe80::1 的 IPv6 帧；legacy 在
// 该路径产出 IPv4 帧（EtherTypeFor("")→0x0800，0.0.0.0/0.0.0.0 全零 +
// checksum）——legacy 边缘 bug（IPv6 场景落 IPv4 帧）不复制，链层保持有效
// IPv6 帧。防回归：空 DstIP 时链层若注入 schema 默认 dst（20.0.0.1）会
// 破坏 up 字节一致性。
func TestChainPlanner_DHCPv6_EmptyDstIP(t *testing.T) {
	xid := [3]byte{0x21, 0x43, 0x65}
	cfg := dhcpv6BaseCfg([]core.DHCPv6Message{
		{MsgType: dhcpv6.MsgTypeSolicit, TransactionID: xid},
		{MsgType: dhcpv6.MsgTypeAdvertise, TransactionID: xid},
	})
	spec := dhcpv6Spec(cfg)
	spec.DstIP = "" // 空目标 → up 事件 DstIP=""（resolveAddrs 直配）
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)
	legacy := collectPlanner(t, dhcpv6.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// up SOLICIT：目标为空（链层不得注入 schema 默认），字节与 legacy 一致。
	if chain[0].L3.DstIP != "" {
		t.Errorf("SOLICIT L3.DstIP = %q, want empty (spec.DstIP 空直配)", chain[0].L3.DstIP)
	}
	assertDHCPv6Identical(t, chain[0], legacy[0], 0)
	// down ADVERTISE：结构分歧文档化——空 spec.DstIP 交换进 srcIP 后由 ip 层
	// srcSet 注入 spec.SrcIP，帧类型保持 IPv6（legacy 在此产出 IPv4 垃圾帧）。
	if chain[1].L3.SrcIP != "fe80::1" || chain[1].L3.DstIP != "fe80::1" {
		t.Errorf("ADVERTISE L3 IPs = %q/%q, want fe80::1/fe80::1 (srcSet 注入 + down swap)", chain[1].L3.SrcIP, chain[1].L3.DstIP)
	}
	if chain[1].L2.EtherType != core.EtherTypeIPv6 {
		t.Errorf("ADVERTISE EtherType = 0x%04x, want 0x86DD IPv6 (legacy 落 IPv4 帧的边缘 bug 不复制)", chain[1].L2.EtherType)
	}
	if chain[1].L4.SrcPort != dhcpv6.ServerPort || chain[1].L4.DstPort != dhcpv6.ClientPort {
		t.Errorf("ADVERTISE ports = %d/%d, want 547/546 (resolveAddrs down 交换)", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
}

// TestChainPlanner_DHCPv6_ScenarioSARR verifies scenario 模式结构：4 条消息
// 共享同一 XID（scenario 生成器内部 randomXID()——只做结构断言，不做字节
// 对比；SOLICIT/ADVERTISE 端口 546/547 ↔ 547/546）。
func TestChainPlanner_DHCPv6_ScenarioSARR(t *testing.T) {
	clientDUID, serverDUID := dhcpv6ExplicitDUIDs()
	cfg := &core.DHCPv6Config{
		ClientDUID:        clientDUID,
		ServerDUID:        serverDUID,
		Scenario:          "sarr",
		DefaultLeasedAddr: "2001:db8::100",
		DefaultIAID:       1,
	}
	spec := dhcpv6Spec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)

	if len(chain) != 4 {
		t.Fatalf("chain produced %d packets, want 4 (scenario sarr)", len(chain))
	}
	// 同组共享 XID（scenario 强制，buildScenarioMessages randomXID 语义）。
	var first [3]byte
	copy(first[:], chain[0].Payload[1:4])
	for i := 1; i < 4; i++ {
		if got := [3]byte{chain[i].Payload[1], chain[i].Payload[2], chain[i].Payload[3]}; got != first {
			t.Errorf("packet %d XID = %x, want %x (scenario shared XID)", i, got, first)
		}
	}
	if chain[0].L4.SrcPort != dhcpv6.ClientPort || chain[0].L4.DstPort != dhcpv6.ServerPort {
		t.Errorf("SOLICIT ports = %d/%d, want 546/547", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	if chain[1].L4.SrcPort != dhcpv6.ServerPort || chain[1].L4.DstPort != dhcpv6.ClientPort {
		t.Errorf("ADVERTISE ports = %d/%d, want 547/546", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	if chain[0].Payload[0] != dhcpv6.MsgTypeSolicit || chain[2].Payload[0] != dhcpv6.MsgTypeRequest {
		t.Errorf("scenario msg-types = %d/%d/%d/%d, want 1/2/3/7", chain[0].Payload[0], chain[1].Payload[0], chain[2].Payload[0], chain[3].Payload[0])
	}
}

// TestChainPlanner_DHCPv6_AutoXID verifies the zero-XID state machine: down
// 非 RECONFIGURE 复制 lastXID（ADVERTISE=SOLICIT、REPLY=REQUEST），up 新
// 事务 random（SOLICIT≠REQUEST），RECONFIGURE 新 XID（≠ REPLY）。随机 XID
// 只做结构断言，不做字节对比（legacy TestAutoXID_* 同款）。
func TestChainPlanner_DHCPv6_AutoXID(t *testing.T) {
	cfg := dhcpv6BaseCfg([]core.DHCPv6Message{
		{MsgType: dhcpv6.MsgTypeSolicit},
		{MsgType: dhcpv6.MsgTypeAdvertise},
		{MsgType: dhcpv6.MsgTypeRequest},
		{MsgType: dhcpv6.MsgTypeReply},
		{MsgType: dhcpv6.MsgTypeReconfigure},
	})
	spec := dhcpv6Spec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)

	if len(chain) != 5 {
		t.Fatalf("chain produced %d packets, want 5", len(chain))
	}
	xid := func(p []byte) [3]byte {
		return [3]byte{p[1], p[2], p[3]}
	}
	solicit, advertise := xid(chain[0].Payload), xid(chain[1].Payload)
	request, reply := xid(chain[2].Payload), xid(chain[3].Payload)
	reconfigure := xid(chain[4].Payload)
	if advertise != solicit {
		t.Errorf("ADVERTISE XID %x != SOLICIT XID %x (down copies lastXID)", advertise, solicit)
	}
	if reply != request {
		t.Errorf("REPLY XID %x != REQUEST XID %x (down copies lastXID)", reply, request)
	}
	if solicit == request {
		t.Errorf("SOLICIT/REQUEST share XID %x (up generates new random)", solicit)
	}
	if reconfigure == reply {
		t.Errorf("RECONFIGURE XID %x == REPLY XID %x (new transaction)", reconfigure, reply)
	}
}

// TestChainPlanner_DHCPv6_RelaySkipsXID verifies relay messages bypass the
// XID state machine entirely: relay 消息的 header 无 XID 字段（34 字节头
// hop-count 在 offset 1），lastXID 不被 relay 更新（planner.go:365-378
// isRelay 跳过语义）——relay 之后追加一条 down ADVERTISE（零 XID），断言
// 其 XID 复制 relay 前的 SOLICIT XID（0x112233）：若实现错误地在 relay
// 上执行 lastXID=xid（零值清零），ADVERTISE 会复制全零而非 0x112233。
func TestChainPlanner_DHCPv6_RelaySkipsXID(t *testing.T) {
	cfg := dhcpv6BaseCfg(nil)
	cfg.RelayConfig = &core.RelayConfig{
		RelayIP:  "2001:db8::1",
		RelayMAC: "00:aa:bb:cc:dd:ee",
	}
	innerSolicit := innerMessage(t, dhcpv6.MsgTypeSolicit, [3]byte{0x12, 0x34, 0x56})
	cfg.Messages = []core.DHCPv6Message{
		{
			MsgType:       dhcpv6.MsgTypeSolicit,     // 先一条普通消息（更新 lastXID）
			TransactionID: [3]byte{0x11, 0x22, 0x33}, // 显式 XID——up 消息零值会 randomXID，字节对比不稳定
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptIANA, Data: buildIANAEmpty(1)},
			},
		},
		{
			MsgType: dhcpv6.MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount:    1,
				LinkAddress: "2001:db8::1",
				PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptRelayMsg, Data: innerSolicit},
			},
		},
		{
			MsgType: dhcpv6.MsgTypeAdvertise, // down 零 XID → 复制 lastXID；若 relay 清零则复制全零
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptIANA, Data: buildIANAWithAddr(1)},
			},
		},
	}
	spec := dhcpv6Spec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)

	if len(chain) != 3 {
		t.Fatalf("chain produced %d packets, want 3", len(chain))
	}
	// relay 消息 34 字节头：offset 1 = hop-count（非 XID），XID 状态机被跳过。
	if chain[1].Payload[0] != dhcpv6.MsgTypeRelayForw || chain[1].Payload[1] != 1 {
		t.Errorf("relay header = %d/%d, want 12/1 (msg-type/hop-count)", chain[1].Payload[0], chain[1].Payload[1])
	}
	// ADVERTISE（relay 之后）XID 必须仍复制 SOLICIT 的 0x112233。
	if got := [3]byte{chain[2].Payload[1], chain[2].Payload[2], chain[2].Payload[3]}; got != [3]byte{0x11, 0x22, 0x33} {
		t.Errorf("ADVERTISE XID = %x, want 112233 (relay 不更新 lastXID，复制 SOLICIT)", got)
	}
	legacy := collectPlanner(t, dhcpv6.NewPlanner(), spec)
	assertDHCPv6Identical(t, chain[0], legacy[0], 0)
	assertDHCPv6Identical(t, chain[1], legacy[1], 1)
	assertDHCPv6Identical(t, chain[2], legacy[2], 2)
}

// TestChainPlanner_DHCPv6_ScenarioRelay verifies the relay scenario variant
// (review 发现：10 个场景变体中仅 sarr 有链层测试，relay 是唯一独立的
// resolveAddrs 分支风险路径)：4 条内层 SARR 消息各自包成 RELAY-FORW/
// RELAY-REPL（option 9），方向 up/down/up/down；端点地址为 relay 的
// MAC/IP（2001:db8::1/00:aa:bb:cc:dd:ee）+ spec 服务器（ff02::1:2）——
// resolveAddrs relay 分支（planner.go:462-477）：RELAY-FORW 只改 src（relay
// →server 模型），RELAY-REPL 只改 dst（server→relay 模型）；端口恒 547/547
// （RFC 8415：relay↔server 用 server 端口）；hop-count 默认 0（RFC 8415
// §19.1.1 单跳 relay 语义）；link-address=RelayIP、peer-address=leased
// （fe80::1）。不做 legacy 字节对比：内层 XID 随机（scenario randomXID()，
// 且 UDP checksum 覆盖 payload，掩码无法恢复）——legacy 与 chain 均使用
// 显式 cfg.ClientDUID（Time:0 确定性，实验验证），内层 ClientID TLV 是
// 确定性字节，可断言（含 DUID Time=0）。
func TestChainPlanner_DHCPv6_ScenarioRelay(t *testing.T) {
	clientDUID, serverDUID := dhcpv6ExplicitDUIDs()
	cfg := &core.DHCPv6Config{
		ClientDUID:        clientDUID,
		ServerDUID:        serverDUID,
		Scenario:          "relay",
		DefaultLeasedAddr: "fe80::1",
		DefaultIAID:       1,
		RelayConfig: &core.RelayConfig{
			RelayIP:  "2001:db8::1",
			RelayMAC: "00:aa:bb:cc:dd:ee",
		},
	}
	spec := dhcpv6Spec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)

	if len(chain) != 4 {
		t.Fatalf("chain produced %d packets, want 4 (relay-wrapped SARR)", len(chain))
	}
	wantTypes := []uint8{dhcpv6.MsgTypeRelayForw, dhcpv6.MsgTypeRelayRepl, dhcpv6.MsgTypeRelayForw, dhcpv6.MsgTypeRelayRepl}
	wantInner := []uint8{dhcpv6.MsgTypeSolicit, dhcpv6.MsgTypeAdvertise, dhcpv6.MsgTypeRequest, dhcpv6.MsgTypeReply}
	for i := 0; i < 4; i++ {
		p := chain[i].Payload
		if p[0] != wantTypes[i] {
			t.Errorf("packet %d msg-type = %d, want %d (relay wrap)", i, p[0], wantTypes[i])
		}
		if p[1] != 0 {
			t.Errorf("packet %d hop-count = %d, want 0 (RFC 8415 §19.1.1 单跳)", i, p[1])
		}
		// 34 字节中继头：offset 2-18 link-address=RelayIP、18-34
		// peer-address=leased（fe80::1）。
		if !bytes.Equal(p[2:18], []byte(net.ParseIP("2001:db8::1").To16())) {
			t.Errorf("packet %d link-address = %x, want 2001:db8::1 (RelayIP)", i, p[2:18])
		}
		if !bytes.Equal(p[18:34], []byte(net.ParseIP("fe80::1").To16())) {
			t.Errorf("packet %d peer-address = %x, want fe80::1 (DefaultLeasedAddr)", i, p[18:34])
		}
		// option 9（Relay Message）TLV：p[34:36]=code 0009、p[36:38]=len，
		// 内层消息从 p[38] 起（自身 4 字节头 msg-type + XID）。
		if p[34] != 0 || uint16(p[35]) != dhcpv6.OptRelayMsg {
			t.Errorf("packet %d option at 34 = %x, want 0009 (Relay Message)", i, p[34:36])
		}
		if p[38] != wantInner[i] {
			t.Errorf("packet %d inner msg-type = %d, want %d", i, p[38], wantInner[i])
		}
		// 内层 ClientID TLV 定位（p[38] + 4 字节内层头）：client 消息
		// （SOLICIT/REQUEST）ClientID 紧接；server 消息（ADVERTISE/REPLY）
		// buildClientServerMessage 先前置 ServerID TLV（code 2, len 16,
		// DUID-EN = 20 字节）再 ClientID。显式 cfg.ClientDUID（DUID-LLT
		// Time:0）→ 确定性字节——与 legacy 的唯一分歧是 DUID Time
		// （autoClientDUID time.Now()），结构一致。
		inner := p[38:]
		clientIDOffset := 4
		if wantInner[i] == dhcpv6.MsgTypeAdvertise || wantInner[i] == dhcpv6.MsgTypeReply {
			if inner[4] != 0 || uint16(inner[5]) != dhcpv6.OptServerID ||
				inner[6] != 0 || inner[7] != 16 {
				t.Errorf("packet %d inner ServerID TLV = %x, want code=2 len=16 (前置 ServerID)", i, inner[4:8])
			}
			clientIDOffset = 24
		}
		clientOpt := inner[clientIDOffset:]
		if clientOpt[0] != 0 || uint16(clientOpt[1]) != dhcpv6.OptClientID ||
			clientOpt[2] != 0 || clientOpt[3] != 14 {
			t.Errorf("packet %d inner ClientID TLV = %x, want code=1 len=14", i, clientOpt[:4])
		}
		if clientOpt[4] != 0 || uint16(clientOpt[5]) != dhcpv6.DUIDTypeLLT ||
			clientOpt[6] != 0 || uint16(clientOpt[7]) != dhcpv6.HardwareTypeEthernet {
			t.Errorf("packet %d inner DUID header = %x, want DUID-LLT hw=1", i, clientOpt[4:8])
		}
		if clientOpt[8] != 0 || clientOpt[9] != 0 || clientOpt[10] != 0 || clientOpt[11] != 0 {
			t.Errorf("packet %d inner DUID time = %x, want 00000000 (显式 cfg.ClientDUID Time:0)", i, clientOpt[8:12])
		}
		if !bytes.Equal(clientOpt[12:18], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
			t.Errorf("packet %d inner DUID MAC = %x, want 001122334455", i, clientOpt[12:18])
		}
		// 端点：RELAY-FORW（up 索引 0/2）源=relay、目标=spec 服务器；
		// RELAY-REPL（down 索引 1/3）源=服务器、目标=relay——resolveAddrs
		// relay 分支只改 src（FORW）/只改 dst（REPL），MAC 同理。
		if i%2 == 0 {
			if chain[i].L3.SrcIP != "2001:db8::1" || chain[i].L3.DstIP != "ff02::1:2" {
				t.Errorf("packet %d (FORW) L3 IPs = %q/%q, want 2001:db8::1/ff02::1:2 (relay→server)", i, chain[i].L3.SrcIP, chain[i].L3.DstIP)
			}
			if chain[i].L2.SrcMAC != "00:aa:bb:cc:dd:ee" {
				t.Errorf("packet %d (FORW) L2.SrcMAC = %q, want relay MAC", i, chain[i].L2.SrcMAC)
			}
		} else {
			if chain[i].L3.SrcIP != "ff02::1:2" || chain[i].L3.DstIP != "2001:db8::1" {
				t.Errorf("packet %d (REPL) L3 IPs = %q/%q, want ff02::1:2/2001:db8::1 (server→relay)", i, chain[i].L3.SrcIP, chain[i].L3.DstIP)
			}
			if chain[i].L2.DstMAC != "00:aa:bb:cc:dd:ee" {
				t.Errorf("packet %d (REPL) L2.DstMAC = %q, want relay MAC", i, chain[i].L2.DstMAC)
			}
		}
		if chain[i].L4.SrcPort != dhcpv6.ServerPort || chain[i].L4.DstPort != dhcpv6.ServerPort {
			t.Errorf("packet %d ports = %d/%d, want 547/547 (relay 用 server 端口)", i, chain[i].L4.SrcPort, chain[i].L4.DstPort)
		}
	}
}

// TestChainPlanner_DHCPv6_ScenarioRelay_HopAndInterfaceID covers the relay
// scenario 可配置项：显式 hop-count 原样写入（RFC 8415 §19.2.1 多跳语义）、
// InterfaceID 仅出现在 RELAY-FORW（option 18，RELAY-REPL 不带）。不做
// legacy 字节对比（同 TestChainPlanner_DHCPv6_ScenarioRelay：内层 XID 随机，
// UDP checksum 覆盖 payload 掩码不可恢复）。
func TestChainPlanner_DHCPv6_ScenarioRelay_HopAndInterfaceID(t *testing.T) {
	clientDUID, serverDUID := dhcpv6ExplicitDUIDs()
	cfg := &core.DHCPv6Config{
		ClientDUID:        clientDUID,
		ServerDUID:        serverDUID,
		Scenario:          "relay",
		DefaultLeasedAddr: "fe80::1",
		DefaultIAID:       1,
		RelayConfig: &core.RelayConfig{
			RelayIP:     "2001:db8::1",
			RelayMAC:    "00:aa:bb:cc:dd:ee",
			HopCount:    2,
			InterfaceID: []byte{0x01, 0x02},
		},
	}
	spec := dhcpv6Spec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)

	if len(chain) != 4 {
		t.Fatalf("chain produced %d packets, want 4", len(chain))
	}
	// hop-count=2 原样（legacy 语义）。
	for i := 0; i < 4; i++ {
		if chain[i].Payload[1] != 2 {
			t.Errorf("packet %d hop-count = %d, want 2 (显式 hop_count)", i, chain[i].Payload[1])
		}
	}
	// option 18 只在 RELAY-FORW（up 索引 0/2）出现；RELAY-REPL（1/3）没有。
	// 确定性数据断言：option 18 紧跟 option 9（scenario.go:449-457 opts
	// 顺序：RelayMsg 先、InterfaceID 后）之后——位置 = 38 + option 9 的
	// len（内层消息字节数），code 18/len 2/data 0102。
	for i := 0; i < 4; i++ {
		p := chain[i].Payload
		if i%2 == 0 {
			innerLen := int(binary.BigEndian.Uint16(p[36:38]))
			off := 38 + innerLen
			if p[off] != 0 || uint16(p[off+1]) != dhcpv6.OptInterfaceID ||
				p[off+2] != 0 || p[off+3] != 2 || p[off+4] != 0x01 || p[off+5] != 0x02 {
				t.Errorf("packet %d option 18 = %x, want 001200020102 (紧随 option 9)", i, p[off:off+6])
			}
		} else if bytes.Contains(p, []byte{0x00, 0x12, 0x00, 0x02, 0x01, 0x02}) {
			t.Errorf("packet %d (REPL) option 18 present, want absent (InterfaceID 仅 RELAY-FORW)", i)
		}
	}
}

// TestChainPlanner_DHCPv6_AutoDUIDs verifies the nil-DUID fallback
// （review 发现：autoClientDUID/autoServerDUID 链层零覆盖）：ClientDUID=nil →
// autoClientDUID(req.Meta.SrcMAC) 生成 DUID-LLT（hw-type=1、time=epoch2000、
// link-layer=spec.SrcMAC——事件 SrcMAC 注入）；ServerDUID=nil → autoServerDUID
// DUID-EN（enterprise=0、vendor=trafficgen）。autoClientDUID 含 time.Now()
// 非确定性，与 legacy 同款（planner.go:701-712），只做结构断言；autoServerDUID
// 完全确定性，可断言完整字节（SOLICIT 不携带 ServerID，需 ADVERTISE 触发
// 前置——buildClientServerMessage isServerMsg 语义）。ADVERTISE 零 XID →
// 复制 SOLICIT 的显式 XID（0x112233），字节对比成立。
func TestChainPlanner_DHCPv6_AutoDUIDs(t *testing.T) {
	cfg := dhcpv6BaseCfg([]core.DHCPv6Message{
		{MsgType: dhcpv6.MsgTypeSolicit, TransactionID: [3]byte{0x11, 0x22, 0x33}},
		{MsgType: dhcpv6.MsgTypeAdvertise},
	})
	cfg.ClientDUID = nil // → autoClientDUID(Meta.SrcMAC)
	cfg.ServerDUID = nil // → autoServerDUID()
	spec := dhcpv6Spec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// 布局：msg-type(1) + XID(3) + ClientID TLV（code 1, len 14, DUID-LLT
	// type 1/hw 1/time 4/MAC 6 = 18 字节）= 22 字节。autoClientDUID 的
	// time=time.Now()（epoch 2000）非确定性——只做结构断言。SOLICIT 不是
	// server 消息，buildClientServerMessage 不前置 ServerID——payload 到
	// ClientID 即止。
	p := chain[0].Payload
	if len(p) != 22 {
		t.Fatalf("payload len = %d, want 22 (header 4 + ClientID TLV 18, SOLICIT 无 ServerID)", len(p))
	}
	clientOpt := p[4:]
	if clientOpt[0] != 0 || uint16(clientOpt[1]) != dhcpv6.OptClientID ||
		clientOpt[2] != 0 || clientOpt[3] != 14 {
		t.Errorf("ClientID TLV = %x, want code=1 len=14", clientOpt[:4])
	}
	if clientOpt[4] != 0 || uint16(clientOpt[5]) != dhcpv6.DUIDTypeLLT ||
		clientOpt[6] != 0 || uint16(clientOpt[7]) != dhcpv6.HardwareTypeEthernet {
		t.Errorf("client DUID header = %x, want DUID-LLT hw=1", clientOpt[4:8])
	}
	if !bytes.Equal(clientOpt[12:18], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("client DUID link-layer = %x, want 001122334455 (autoClientDUID(Meta.SrcMAC))", clientOpt[12:18])
	}
	// ADVERTISE（server 消息）前置 ServerID TLV（code 2, len 16, DUID-EN：
	// type 2 + enterprise 4B=0 + vendor 10B="trafficgen" = 20 字节）再 ClientID。
	// autoServerDUID 完全确定性——断言完整字节。
	ap := chain[1].Payload
	if got := [3]byte{ap[1], ap[2], ap[3]}; got != [3]byte{0x11, 0x22, 0x33} {
		t.Errorf("ADVERTISE XID = %x, want 112233 (down 复制 SOLICIT lastXID)", got)
	}
	if ap[4] != 0 || uint16(ap[5]) != dhcpv6.OptServerID ||
		ap[6] != 0 || ap[7] != 16 {
		t.Errorf("ServerID TLV = %x, want code=2 len=16", ap[4:8])
	}
	serverOpt := ap[8:]
	if serverOpt[0] != 0 || uint16(serverOpt[1]) != dhcpv6.DUIDTypeEN {
		t.Errorf("server DUID type = %x, want DUID-EN", serverOpt[0:2])
	}
	if serverOpt[2] != 0 || serverOpt[3] != 0 || serverOpt[4] != 0 || serverOpt[5] != 0 {
		t.Errorf("server DUID enterprise = %x, want 0 (autoServerDUID)", serverOpt[2:6])
	}
	if !bytes.Equal(serverOpt[6:16], []byte("trafficgen")) {
		t.Errorf("server DUID vendor = %q, want trafficgen", serverOpt[6:16])
	}
	// ServerID 之后是 autoClientDUID 的 ClientID TLV（code 1, len 14）：
	// server 消息 buildClientServerMessage 先 ServerID 再 ClientID。
	clientTLV := serverOpt[16:]
	if clientTLV[0] != 0 || uint16(clientTLV[1]) != dhcpv6.OptClientID ||
		clientTLV[2] != 0 || clientTLV[3] != 14 {
		t.Errorf("ServerID 后 ClientID TLV = %x, want code=1 len=14", clientTLV[:4])
	}
	if !bytes.Equal(clientTLV[12:18], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("ServerID 后 client DUID MAC = %x, want 001122334455", clientTLV[12:18])
	}
}

// TestChainPlanner_DHCPv6_ExplicitDirection verifies per-message Direction
// override（review 发现：planner.go:216-218 校验行 + 覆盖路径未测）：显式
// direction="down" 的 SOLICIT 走 resolveAddrs down 分支（MAC/IP/端口全交换）。
// 事件字节与 legacy 一致（L4PortOverride 直落最终端口）。
func TestChainPlanner_DHCPv6_ExplicitDirection(t *testing.T) {
	cfg := dhcpv6BaseCfg([]core.DHCPv6Message{
		{
			MsgType:       dhcpv6.MsgTypeSolicit,
			TransactionID: [3]byte{0x11, 0x22, 0x33},
			Direction:     "down",
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptIANA, Data: buildIANAEmpty(1)},
			},
		},
	})
	spec := dhcpv6Spec(cfg)
	chain := collectPlanner(t, layers.NewChainPlanner("dhcpv6"), spec)
	legacy := collectPlanner(t, dhcpv6.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	// down：源=server（spec.DstIP/DstMAC），目标=client（spec.SrcIP/SrcMAC），
	// 端口 547→546（resolveAddrs down 交换）。
	if chain[0].L3.SrcIP != "ff02::1:2" || chain[0].L3.DstIP != "fe80::1" {
		t.Errorf("L3 IPs = %q/%q, want ff02::1:2/fe80::1 (down swap)", chain[0].L3.SrcIP, chain[0].L3.DstIP)
	}
	if chain[0].L2.SrcMAC != "33:33:00:01:00:02" || chain[0].L2.DstMAC != "00:11:22:33:44:55" {
		t.Errorf("L2 MACs = %q/%q, want 33:33:00:01:00:02/001122334455 (down swap)", chain[0].L2.SrcMAC, chain[0].L2.DstMAC)
	}
	if chain[0].L4.SrcPort != dhcpv6.ServerPort || chain[0].L4.DstPort != dhcpv6.ClientPort {
		t.Errorf("ports = %d/%d, want 547/546 (down swap)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	assertDHCPv6Identical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_DHCPv6_ExplicitDirection_Invalid verifies the direction
// validation 负路径（planner.go:216-218）：非 up/down 值被 Validate 拒绝，
// 经 chain 校验器同样传播（validateSpecBase → RegisterLayerValidator）。
func TestChainPlanner_DHCPv6_ExplicitDirection_Invalid(t *testing.T) {
	cfg := dhcpv6BaseCfg([]core.DHCPv6Message{
		{
			MsgType:       dhcpv6.MsgTypeSolicit,
			TransactionID: [3]byte{0x11, 0x22, 0x33},
			Direction:     "sideways",
			Options: []core.DHCPv6Option{
				{Code: dhcpv6.OptIANA, Data: buildIANAEmpty(1)},
			},
		},
	})
	spec := dhcpv6Spec(cfg)
	if err := layers.NewChainPlanner("dhcpv6").Validate(spec); err == nil {
		t.Fatal("Validate: invalid direction accepted, want error")
	}
}
