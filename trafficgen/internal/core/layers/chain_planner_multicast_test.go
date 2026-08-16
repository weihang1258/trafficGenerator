// 外部测试包：验证 MessageEvent 的 L2/L3 目标覆盖（波 5 多播基础设施）。
// mdns/dhcp/dhcpv6/ssdp/rip 等多播协议需要把数据报目标覆盖为多播组
// （224.0.0.251/239.255.255.250/224.0.0.9/ff02::fb...）+ 多播 MAC
// （01:00:5e:xx/33:33:xx）或广播（255.255.255.255/ff:ff:ff:ff:ff:ff），
// 而链层默认只支持 spec.DstIP→spec.DstMAC 单播目标。本测试直接驱动
// [ip→udp→mdns] 链 + 事件级覆盖，验证覆盖值正确落到 L2/L3。
package layers_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/mdns"
)

// TestChainPlanner_Multicast_DstIPOverride verifies an event carrying
// DstIP=224.0.0.251 reaches L3.DstIP without down-swap (multicast target is
// absolute), and the derived multicast MAC lands on L2.DstMAC.
func TestChainPlanner_Multicast_DstIPOverride(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		DstPort: 5353,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		MDNS: &core.MDNSConfig{
			Mode:           "query",
			MulticastGroup: mdns.MulticastIPv4,
			// query 模式须带 Question（legacy Validate 同款要求）。
			Questions: []core.MDNSQuestion{
				{Name: "MyServer._http._tcp.local", Type: mdns.TypePTR},
			},
		},
	}
	chain := collectPlanner(t, layers.NewChainPlanner("mdns"), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L3.DstIP != mdns.MulticastIPv4 {
		t.Errorf("L3.DstIP = %q, want %q (multicast override)", chain[0].L3.DstIP, mdns.MulticastIPv4)
	}
	if chain[0].L3.SrcIP != "10.0.0.1" {
		t.Errorf("L3.SrcIP = %q, want 10.0.0.1 (src untouched)", chain[0].L3.SrcIP)
	}
	if chain[0].L2.DstMAC != "01:00:5e:00:00:fb" {
		t.Errorf("L2.DstMAC = %q, want 01:00:5e:00:00:fb (derived from 224.0.0.251)", chain[0].L2.DstMAC)
	}
	if chain[0].L2.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("L2.SrcMAC = %q, want aa:bb:cc:dd:ee:ff", chain[0].L2.SrcMAC)
	}
	if chain[0].L4.SrcPort != 5353 || chain[0].L4.DstPort != 5353 {
		t.Errorf("L4 ports = %d/%d, want 5353/5353 (mdns both-port default)", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
}

// TestChainPlanner_Multicast_ExplicitDstMAC verifies an event carrying an
// explicit DstMAC (e.g. dhcp broadcast ff:ff:ff:ff:ff:ff) lands on L2.DstMAC
// verbatim, bypassing multicast-IP derivation.
func TestChainPlanner_Multicast_ExplicitDstMAC(t *testing.T) {
	bcast := true
	spec := core.FlowSpec{
		SrcIP:   "0.0.0.0",
		DstIP:   "255.255.255.255",
		SrcPort: 68,
		DstPort: 67,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		// DstMAC 留空：client 角色 + 广播标志 → resolveMACs 回退
		// BroadcastMAC（legacy planner.go:723-725 语义），事件显式覆盖落 L2。
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{Type: 1, Broadcast: &bcast}, // DISCOVER with 广播标志
			},
		},
	}
	chain := collectPlanner(t, layers.NewChainPlanner("dhcp"), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L3.DstIP != "255.255.255.255" {
		t.Errorf("L3.DstIP = %q, want 255.255.255.255 (broadcast override)", chain[0].L3.DstIP)
	}
	// dhcp 事件显式带 BroadcastMAC → 不推导，原样落 L2。
	if chain[0].L2.DstMAC != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("L2.DstMAC = %q, want ff:ff:ff:ff:ff:ff (explicit broadcast MAC)", chain[0].L2.DstMAC)
	}
}
