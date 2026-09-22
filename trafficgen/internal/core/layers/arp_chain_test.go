package layers_test

// D-ARP-1 P4 链级红例：[eth→arp] L2-only 链（goose/sv/isis 族对称）。
// 协议特有：①op=1 自动配对 request(up, 广播)+reply(down, 单播)；
// ②op=2 单发宣告形（legacy 广播错位勘误，裁定3）；③28B 载荷 RFC 826
// 字段序逐字节钉；④体首=帧偏移 14（无 IP/TCP 头）。

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 arp 包 init 注册层生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/arp"
)

func arpChainPlanner(t *testing.T, arpCfg string) (*layers.ChainPlanner, core.FlowSpec) {
	t.Helper()
	p := layers.NewChainPlannerFromChain("arp", []layers.Layer{
		{Name: "eth", Config: map[string]interface{}{"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02"}},
		{Name: "arp", Config: mustJSONMap(t, arpCfg)},
	})
	spec := core.FlowSpec{}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	return p, validated
}

// 红1：op=1（缺省 {}）自动配对——2 帧，广播请求+单播应答，28B RFC 826
// 字段序全钉（裁定1/2/3）。
func TestChainPlanner_ARPPair(t *testing.T) {
	p, spec := arpChainPlanner(t, `{}`)
	if spec.ARP == nil {
		t.Fatalf("translate must populate spec.ARP from the arp layer config")
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for pkt := range ch {
		pkts = append(pkts, pkt)
	}
	if len(pkts) != 2 {
		t.Fatalf("packets %d, want 2 (request+reply 配对)", len(pkts))
	}
	// 帧1 request(up)：广播，oper=1，tha 全零。
	p1 := pkts[0]
	if p1.Direction != "up" || p1.L4.Protocol != "arp" {
		t.Fatalf("frame1 dir=%s proto=%s", p1.Direction, p1.L4.Protocol)
	}
	if p1.L2.EtherType != core.EtherTypeARP {
		t.Fatalf("frame1 ethertype %#x, want 0x0806", p1.L2.EtherType)
	}
	if p1.L2.SrcMAC != "aa:bb:cc:dd:ee:01" || p1.L2.DstMAC != "ff:ff:ff:ff:ff:ff" {
		t.Fatalf("frame1 macs %s->%s", p1.L2.SrcMAC, p1.L2.DstMAC)
	}
	if len(p1.Payload) != 28 {
		t.Fatalf("frame1 payload %d bytes, want 28", len(p1.Payload))
	}
	b := p1.Payload
	if binary.BigEndian.Uint16(b[0:2]) != 1 || binary.BigEndian.Uint16(b[2:4]) != 0x0800 ||
		b[4] != 6 || b[5] != 4 {
		t.Fatalf("frame1 htype/ptype/hlen/plen: % x", b[0:6])
	}
	if op := binary.BigEndian.Uint16(b[6:8]); op != 1 {
		t.Fatalf("frame1 oper %d, want 1", op)
	}
	sha, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	if string(b[8:14]) != string(sha) {
		t.Fatalf("frame1 sha=% x", b[8:14])
	}
	if string(b[14:18]) != string([]byte{10, 0, 0, 1}) {
		t.Fatalf("frame1 spa=% x, want 10.0.0.1（缺省）", b[14:18])
	}
	if string(b[18:24]) != string([]byte{0, 0, 0, 0, 0, 0}) {
		t.Fatalf("frame1 tha=% x, want 全零（RFC 826 请求）", b[18:24])
	}
	if string(b[24:28]) != string([]byte{10, 0, 0, 2}) {
		t.Fatalf("frame1 tpa=% x, want 10.0.0.2（缺省）", b[24:28])
	}
	// 帧2 reply(down)：单播，角色互换。
	p2 := pkts[1]
	if p2.Direction != "down" {
		t.Fatalf("frame2 dir=%s, want down", p2.Direction)
	}
	if p2.L2.SrcMAC != "aa:bb:cc:dd:ee:02" || p2.L2.DstMAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("frame2 macs %s->%s, want 单播互换", p2.L2.SrcMAC, p2.L2.DstMAC)
	}
	b2 := p2.Payload
	if op := binary.BigEndian.Uint16(b2[6:8]); op != 2 {
		t.Fatalf("frame2 oper %d, want 2", op)
	}
	sha2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	if string(b2[8:14]) != string(sha2) || string(b2[14:18]) != string([]byte{10, 0, 0, 2}) {
		t.Fatalf("frame2 sha/spa 互换错: sha=% x spa=% x", b2[8:14], b2[14:18])
	}
	if string(b2[18:24]) != string(sha) || string(b2[24:28]) != string([]byte{10, 0, 0, 1}) {
		t.Fatalf("frame2 tha/tpa 互换错: tha=% x tpa=% x", b2[18:24], b2[24:28])
	}
}

// 红2：op=2 单发宣告形——1 帧，单播（legacy 广播错位勘误实证）。
func TestChainPlanner_ARPReplySingle(t *testing.T) {
	p, spec := arpChainPlanner(t, `{"operation": 2}`)
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for pkt := range ch {
		pkts = append(pkts, pkt)
	}
	if len(pkts) != 1 {
		t.Fatalf("packets %d, want 1（op=2 单发）", len(pkts))
	}
	p1 := pkts[0]
	if p1.L2.DstMAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("op=2 ether dst %s, want 单播 sender_mac（勘误：legacy 此处广播）", p1.L2.DstMAC)
	}
	b := p1.Payload
	if op := binary.BigEndian.Uint16(b[6:8]); op != 2 {
		t.Fatalf("oper %d, want 2", op)
	}
	sha, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	if string(b[8:14]) != string(sha) || string(b[14:18]) != string([]byte{10, 0, 0, 2}) {
		t.Fatalf("op=2 sha/spa 须为对端角色: % x/% x", b[8:14], b[14:18])
	}
}

// 红3：显式地址覆盖 + translate 面。
func TestChainPlanner_ARPExplicitAddrs(t *testing.T) {
	p, spec := arpChainPlanner(t, `{"sender_ip": "192.168.10.5", "target_ip": "192.168.10.1"}`)
	if spec.ARP.SenderIP != "192.168.10.5" || spec.ARP.TargetIP != "192.168.10.1" {
		t.Fatalf("translate explicit addrs lost: %+v", spec.ARP)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for pkt := range ch {
		n++
		b := pkt.Payload
		if n == 1 && (string(b[14:18]) != string([]byte{192, 168, 10, 5}) || string(b[24:28]) != string([]byte{192, 168, 10, 1})) {
			t.Fatalf("explicit spa/tpa 错: % x/% x", b[14:18], b[24:28])
		}
	}
	if n != 2 {
		t.Fatalf("packets %d, want 2", n)
	}
}

// 红4：validator 锚直测——operation 出 [1,2] 由 registry V9 先拦（此处测
// validator 层 IP 格式锚）。
func TestChainPlanner_ARPValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("arp", []layers.Layer{
		{Name: "eth", Config: map[string]interface{}{"src_mac": "aa:bb:cc:dd:ee:01"}},
		{Name: "arp", Config: mustJSONMap(t, `{"sender_ip": "999.1.1.1"}`)},
	})
	if _, err := p.ValidateSpec(core.FlowSpec{}); err == nil || !contains(err.Error(), "invalid sender_ip") {
		t.Fatalf("want invalid sender_ip anchor, got %v", err)
	}
}
