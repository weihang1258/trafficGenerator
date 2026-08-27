// 外部测试包：ssdp 链的字节级对比需要 legacy ssdp.NewPlanner 与 chain
// （internal/protocol/ssdp + internal/core/layers）。测试贴近真实调用方
// （main.go 的 layers.NewChainPlanner("ssdp")）。
package layers_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/ssdp"
)

// ssdpSpec builds a minimal NOTIFY alive spec. DstMAC 留空——legacy 与链层
// 都按多播 IP 推导 01:00:5e:7f:ff:fa（resolveMulticastMAC / multicastDstMAC
// 同款）。端口省略 0 → 双路默认 1900（validateSpecBase 默认 + udp 层读取）。
func ssdpSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:  "192.168.1.50",
		DstIP:  "239.255.255.250",
		SrcMAC: "02:00:00:00:00:01",
		SSDP: &core.SSDPConfig{
			MessageType:  "alive",
			SearchTarget: "upnp:rootdevice",
			USN:          "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
			MaxAge:       1800,
			Location:     "http://192.168.1.50:80/description.xml",
			Server:       "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0",
			BootID:       1,
			RepeatCount:  1,
		},
	}
}

// ssdpMSearchSpec builds a minimal M-SEARCH spec (1 response, fast MX).
// DstMAC 留空：legacy M-SEARCH 走 resolveMulticastMAC 推导 01:00:5e:7f:ff:fa
// （spec.DstMAC 非零会被 honor——链层恒推导，字节不一致，故留空）；响应
// 回程 DstMAC 恒字面 ""（legacy planner.go:479 写死，帧全零），留空时链层
// 单播不推导 → "" → 全零，两路一致。
func ssdpMSearchSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:  "192.168.1.50",
		DstIP:  "239.255.255.250",
		SrcMAC: "02:00:00:00:00:01",
		SSDP: &core.SSDPConfig{
			MessageType:   "msearch",
			SearchTarget:  "ssdp:all",
			MX:            1,
			Server:        "Linux/3.2.40 UPnP/1.1 TestClient/1.0",
			ResponseCount: 1,
		},
	}
}

// assertSSDPIdentical builds both packets and compares wire bytes after
// masking the volatile IPID/checksum fields. ssdp payload 确定性（固定头）。
func assertSSDPIdentical(t *testing.T, chain, legacy core.PacketConfig, idx int) {
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
	if !bytes.Equal(maskSSDPVolatile(cb), maskSSDPVolatile(lb)) {
		t.Errorf("packet %d bytes differ:\nchain  %x\nlegacy %x", idx, cb, lb)
	}
}

// maskSSDPVolatile zeroes IPID (18-19) and IP checksum (24-25)。
func maskSSDPVolatile(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	if len(out) > 25 {
		out[18], out[19] = 0, 0
		out[24], out[25] = 0, 0
	}
	return out
}

// TestChainPlanner_SSDP_Alive verifies the [ip→udp→ssdp] chain emits one up
// datagram to the multicast group with TTL=4 (RFC draft-cai-ssdp-v1-03 §6.2),
// byte-identical to legacy ssdp.NewPlanner.
func TestChainPlanner_SSDP_Alive(t *testing.T) {
	spec := ssdpSpec()
	chain := collectPlanner(t, layers.NewChainPlanner("ssdp"), spec)
	legacy := collectPlanner(t, ssdp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Direction != "up" {
		t.Errorf("direction = %s, want up", chain[0].Direction)
	}
	if chain[0].L3.DstIP != ssdp.IPv4MulticastGroup {
		t.Errorf("L3.DstIP = %q, want %q", chain[0].L3.DstIP, ssdp.IPv4MulticastGroup)
	}
	if chain[0].L3.SrcIP != "192.168.1.50" {
		t.Errorf("L3.SrcIP = %q, want 192.168.1.50", chain[0].L3.SrcIP)
	}
	// 多播 MAC 推导（RFC 1112 §6.4）：239.255.255.250 → 01:00:5e:7f:ff:fa。
	if chain[0].L2.DstMAC != "01:00:5e:7f:ff:fa" {
		t.Errorf("L2.DstMAC = %q, want 01:00:5e:7f:ff:fa", chain[0].L2.DstMAC)
	}
	if chain[0].L2.SrcMAC != "02:00:00:00:00:01" {
		t.Errorf("L2.SrcMAC = %q, want 02:00:00:00:00:01", chain[0].L2.SrcMAC)
	}
	// ssdp 强制 TTL=4（spec.TTL 无效，legacy 无条件 4）。
	if chain[0].L3.TTL != 4 {
		t.Errorf("L3.TTL = %d, want 4", chain[0].L3.TTL)
	}
	if chain[0].L4.Protocol != "udp" || chain[0].L4.SrcPort != 1900 || chain[0].L4.DstPort != 1900 {
		t.Errorf("L4 = %s %d/%d, want udp 1900/1900", chain[0].L4.Protocol, chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	payload := string(chain[0].Payload)
	if !strings.HasPrefix(payload, "NOTIFY * HTTP/1.1\r\n") {
		t.Errorf("payload prefix = %q, want NOTIFY * HTTP/1.1\\r\\n", payload[:30])
	}
	if !strings.Contains(payload, "HOST: 239.255.255.250:1900\r\n") {
		t.Errorf("payload missing HOST")
	}
	assertSSDPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_SSDP_DefaultPorts verifies the chain defaults src/dst ports
// to 1900 (validateSpecBase) when the spec omits them.
func TestChainPlanner_SSDP_DefaultPorts(t *testing.T) {
	spec := ssdpSpec()
	spec.SrcPort, spec.DstPort = 0, 0
	chain := collectPlanner(t, layers.NewChainPlanner("ssdp"), spec)
	if chain[0].L4.SrcPort != 1900 || chain[0].L4.DstPort != 1900 {
		t.Errorf("ports = %d/%d, want 1900/1900 (ssdp default)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
}

// TestChainPlanner_SSDP_Byebye verifies byebye emits the minimal 4-header
// NOTIFY, byte-identical to legacy.
func TestChainPlanner_SSDP_Byebye(t *testing.T) {
	spec := ssdpSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType:  "byebye",
		SearchTarget: "upnp:rootdevice",
		USN:          "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
	}
	chain := collectPlanner(t, layers.NewChainPlanner("ssdp"), spec)
	legacy := collectPlanner(t, ssdp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	payload := string(chain[0].Payload)
	if !strings.HasPrefix(payload, "NOTIFY * HTTP/1.1\r\n") {
		t.Errorf("payload prefix = %q, want NOTIFY * HTTP/1.1\\r\\n", payload[:30])
	}
	if strings.Contains(payload, "CACHE-CONTROL") {
		t.Errorf("byebye should not contain CACHE-CONTROL")
	}
	if strings.Contains(payload, "LOCATION:") {
		t.Errorf("byebye should not contain LOCATION")
	}
	assertSSDPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_SSDP_MSearch verifies M-SEARCH + 1 unicast 200 OK response:
// response goes back to spec.SrcIP (控制点) with DstMAC = spec.DstMAC (unicast
// 不推导), both TTL=4, byte-identical to legacy.
func TestChainPlanner_SSDP_MSearch(t *testing.T) {
	spec := ssdpMSearchSpec()
	chain := collectPlanner(t, layers.NewChainPlanner("ssdp"), spec)
	legacy := collectPlanner(t, ssdp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2 (1 msearch + 1 response)", len(chain))
	}

	// Packet 0: M-SEARCH → multicast group + derived multicast MAC.
	ms := chain[0]
	if ms.L3.DstIP != ssdp.IPv4MulticastGroup {
		t.Errorf("ms L3.DstIP = %q, want %q", ms.L3.DstIP, ssdp.IPv4MulticastGroup)
	}
	if ms.L2.DstMAC != "01:00:5e:7f:ff:fa" {
		t.Errorf("ms L2.DstMAC = %q, want 01:00:5e:7f:ff:fa", ms.L2.DstMAC)
	}
	if ms.L3.TTL != 4 {
		t.Errorf("ms L3.TTL = %d, want 4", ms.L3.TTL)
	}
	if !strings.HasPrefix(string(ms.Payload), "M-SEARCH * HTTP/1.1\r\n") {
		t.Errorf("ms payload prefix = %q, want M-SEARCH", string(ms.Payload[:30]))
	}

	// Packet 1: 200 OK → unicast back to control point (spec.SrcIP), DstMAC
	// 空（legacy planner.go:479 响应 DstMAC 恒字面 ""，帧全零），up direction。
	resp := chain[1]
	if resp.Direction != "up" {
		t.Errorf("resp direction = %s, want up", resp.Direction)
	}
	if resp.L3.DstIP != "192.168.1.50" {
		t.Errorf("resp L3.DstIP = %q, want 192.168.1.50 (back to control point)", resp.L3.DstIP)
	}
	if resp.L3.SrcIP != "192.168.1.50" {
		t.Errorf("resp L3.SrcIP = %q, want 192.168.1.50", resp.L3.SrcIP)
	}
	if resp.L2.DstMAC != "" {
		t.Errorf("resp L2.DstMAC = %q, want empty (legacy 响应 DstMAC 恒字面空 → 帧全零)", resp.L2.DstMAC)
	}
	if resp.L3.TTL != 4 {
		t.Errorf("resp L3.TTL = %d, want 4 (unicast 回程也强制 4)", resp.L3.TTL)
	}
	if resp.L4.SrcPort != 1900 || resp.L4.DstPort != 1900 {
		t.Errorf("resp ports = %d/%d, want 1900/1900", resp.L4.SrcPort, resp.L4.DstPort)
	}
	if !strings.HasPrefix(string(resp.Payload), "HTTP/1.1 200 OK\r\n") {
		t.Errorf("resp payload prefix = %q, want HTTP/1.1 200 OK", string(resp.Payload[:30]))
	}

	for i := 0; i < 2; i++ {
		assertSSDPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_SSDP_MSearchMultiResponse verifies ResponseCount=3 yields
// 4 packets (1 M-SEARCH + 3 responses), all byte-identical to legacy.
// 响应延迟随机（rand.Intn），但延迟不影响字节；MX=1 上限 1000ms 防慢。
func TestChainPlanner_SSDP_MSearchMultiResponse(t *testing.T) {
	spec := ssdpMSearchSpec()
	spec.SSDP.ResponseCount = 3
	chain := collectPlanner(t, layers.NewChainPlanner("ssdp"), spec)
	legacy := collectPlanner(t, ssdp.NewPlanner(), spec)

	if len(chain) != 4 {
		t.Fatalf("chain produced %d packets, want 4 (1 msearch + 3 responses)", len(chain))
	}
	for i := 0; i < 4; i++ {
		if chain[i].L3.TTL != 4 {
			t.Errorf("packet %d TTL = %d, want 4", i, chain[i].L3.TTL)
		}
		assertSSDPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_SSDP_Response verifies the standalone response goes to
// spec.DstIP with TTL=4, byte-identical to legacy. DstIP 用单播（legacy
// TestSSDP_Integration_Response 同款）：legacy 独立 response 的 DstMAC 恒
// 字面 ""（planner.go:503，帧全零）；链层对多播 DstIP 会推导多播 MAC——
// 单播 IP 下 multicastDstMAC 返回 "" → 回退 l2For（spec.DstMAC 空 → 全零），
// 两路一致。
func TestChainPlanner_SSDP_Response(t *testing.T) {
	spec := ssdpSpec()
	spec.DstIP = "192.168.1.100"
	spec.SSDP = &core.SSDPConfig{
		MessageType:  "response",
		SearchTarget: "upnp:rootdevice",
		USN:          "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
		Location:     "http://192.168.1.50:80/description.xml",
		Server:       "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0",
		MaxAge:       1800,
		Date:         "Sun, 28 Jul 2026 12:34:56 GMT",
	}
	chain := collectPlanner(t, layers.NewChainPlanner("ssdp"), spec)
	legacy := collectPlanner(t, ssdp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L3.DstIP != "192.168.1.100" {
		t.Errorf("L3.DstIP = %q, want 192.168.1.100 (spec.DstIP)", chain[0].L3.DstIP)
	}
	if chain[0].L2.DstMAC != "" {
		t.Errorf("L2.DstMAC = %q, want empty (legacy 独立 response DstMAC 恒空)", chain[0].L2.DstMAC)
	}
	if chain[0].L3.TTL != 4 {
		t.Errorf("L3.TTL = %d, want 4", chain[0].L3.TTL)
	}
	payload := string(chain[0].Payload)
	if !strings.HasPrefix(payload, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("payload prefix = %q, want HTTP/1.1 200 OK", payload[:30])
	}
	if !strings.Contains(payload, "DATE: Sun, 28 Jul 2026 12:34:56 GMT\r\n") {
		t.Errorf("payload missing DATE")
	}
	assertSSDPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_SSDP_Repeat verifies RepeatCount=3 with a fixed interval
// emits 3 packets at wall-clock pacing (per-packet Timestamp 被 Plan 覆写，
// 见 chain_planner_mdns_test.go Probe 注释), byte-identical to legacy.
func TestChainPlanner_SSDP_Repeat(t *testing.T) {
	spec := ssdpSpec()
	spec.SSDP.RepeatCount = 3
	spec.SSDP.RepeatIntervalMs = 50
	start := time.Now()
	chain := collectPlanner(t, layers.NewChainPlanner("ssdp"), spec)
	elapsed := time.Since(start)
	legacy := collectPlanner(t, ssdp.NewPlanner(), spec)

	if len(chain) != 3 {
		t.Fatalf("chain produced %d packets, want 3", len(chain))
	}
	if elapsed < 2*50*time.Millisecond {
		t.Errorf("3 repeat packets finished in %v, want >= 100ms (2 x 50ms gaps)", elapsed)
	}
	for i := 0; i < 3; i++ {
		if chain[i].L3.TTL != 4 {
			t.Errorf("packet %d TTL = %d, want 4", i, chain[i].L3.TTL)
		}
		assertSSDPIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_SSDP_IPv6 verifies the IPv6 path: ff02::c group +
// 33:33:00:00:00:0c MAC + bracketed HOST header, byte-identical to legacy.
func TestChainPlanner_SSDP_IPv6(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "fe80::1234",
		DstIP:  "ff02::c",
		SrcMAC: "02:00:00:00:00:01",
		SSDP: &core.SSDPConfig{
			MessageType:  "alive",
			SearchTarget: "upnp:rootdevice",
			USN:          "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
			MaxAge:       1800,
		},
	}
	chain := collectPlanner(t, layers.NewChainPlanner("ssdp"), spec)
	legacy := collectPlanner(t, ssdp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L3.DstIP != ssdp.IPv6MulticastGroup {
		t.Errorf("L3.DstIP = %q, want %q", chain[0].L3.DstIP, ssdp.IPv6MulticastGroup)
	}
	if chain[0].L2.DstMAC != "33:33:00:00:00:0c" {
		t.Errorf("L2.DstMAC = %q, want 33:33:00:00:00:0c", chain[0].L2.DstMAC)
	}
	if chain[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType = %04x, want 86DD (IPv6)", chain[0].L2.EtherType)
	}
	if chain[0].L3.TTL != 4 {
		t.Errorf("L3.TTL = %d, want 4", chain[0].L3.TTL)
	}
	if !strings.Contains(string(chain[0].Payload), "HOST: [ff02::c]:1900\r\n") {
		t.Errorf("payload missing bracketed IPv6 HOST")
	}
	assertSSDPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_SSDP_ValidateNegative mirrors legacy Validate: SSDP config
// required, unknown message_type, missing search_target, missing USN for
// alive, non-1900 ports, max-age > 1800, mx > 5.
func TestChainPlanner_SSDP_ValidateNegative(t *testing.T) {
	p := layers.NewChainPlanner("ssdp")

	// nil config → 默认化产默认流（P0b-2；与 mdns 对齐）。
	spec := ssdpSpec()
	spec.SSDP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate(nil SSDP) = %v, want nil (default flow, P0b-2)", err)
	}

	spec = ssdpSpec()
	spec.SSDP.MessageType = "bogus"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(unknown message_type) = nil, want error")
	}

	spec = ssdpSpec()
	spec.SSDP.SearchTarget = ""
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(empty search_target) = nil, want error")
	}

	spec = ssdpSpec()
	spec.SSDP.USN = ""
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(empty USN for alive) = nil, want error")
	}

	spec = ssdpSpec()
	spec.SrcPort = 53
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(src port 53) = nil, want error")
	}

	spec = ssdpSpec()
	spec.DstPort = 53
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(dst port 53) = nil, want error")
	}

	spec = ssdpSpec()
	spec.SSDP.MaxAge = 1801
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(max-age 1801) = nil, want error")
	}

	spec = ssdpSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.MX = 6
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(mx 6) = nil, want error")
	}
}

// TestChainPlanner_SSDP_SpecTTL verifies a non-zero spec.TTL is honored
// (legacy planner.go:282-285: effectiveTTL = spec.TTL; 0 → DefaultTTL=4),
// byte-identical to legacy.
func TestChainPlanner_SSDP_SpecTTL(t *testing.T) {
	spec := ssdpSpec()
	spec.TTL = 128
	chain := collectPlanner(t, layers.NewChainPlanner("ssdp"), spec)
	legacy := collectPlanner(t, ssdp.NewPlanner(), spec)

	if chain[0].L3.TTL != 128 {
		t.Errorf("L3.TTL = %d, want 128 (spec.TTL honored)", chain[0].L3.TTL)
	}
	assertSSDPIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_SSDP_ContextCancel verifies ctx cancellation during a
// response delay aborts generation without hanging (msearch ResponseCount>1
// 在延迟 select 中监听 ctx.Done)。
func TestChainPlanner_SSDP_ContextCancel(t *testing.T) {
	spec := ssdpMSearchSpec()
	spec.SSDP.ResponseCount = 2
	spec.SSDP.ResponseDelayMinMs = 5000
	spec.SSDP.ResponseDelayMaxMs = 5000

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := layers.NewChainPlanner("ssdp").Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// M-SEARCH 立即发出；cancel 后响应延迟 select 必须快速退出并关闭通道。
	cancel()
	deadline := time.After(2 * time.Second)
	count := 0
	for range ch {
		count++
		select {
		case <-deadline:
			t.Fatalf("channel did not close after cancel (got %d packets)", count)
		default:
		}
	}
}
