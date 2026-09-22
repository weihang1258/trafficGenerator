package arp

// D-ARP-1 P4：arp 层生成器（L2-only 终结层，[eth,arp] 链——goose Generator
// 型：Generate+req.Emit，GenEvents=nil，链 finalEmit 补 EtherType/清 L3）。
// 线面复用 legacy 28B 构造语义（RFC 826 字段序，裁定1），编排/校验重建
//（裁定2/3）：op=1 自动配对 request(up, 广播)+reply(down, 单播)；op=2 单发
// 对端宣告形（legacy 广播错位勘误）。

import (
	"context"
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

const (
	defaultSenderIP = "10.0.0.1"
	defaultTargetIP = "10.0.0.2"
	// MAC 兜底缺省（eth 层未给时；goose DefaultDstMAC 同款手法）。
	defaultSenderMAC = "aa:bb:cc:dd:ee:01"
	defaultTargetMAC = "aa:bb:cc:dd:ee:02"
	broadcastMAC     = "ff:ff:ff:ff:ff:ff"
)

type Generator struct{}

func (*Generator) Name() string                     { return "arp" }
func (*Generator) GenEvents() layers.EventGenerator { return nil }

func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("arp generator: invalid request")
	}
	c := req.Meta.ARP
	if c == nil {
		c = &core.ARPConfig{}
	}
	op := c.Operation
	if op == 0 {
		op = OperationRequest
	}
	senderMAC := firstNonEmpty(c.SenderMAC, req.Meta.SrcMAC, defaultSenderMAC)
	targetMAC := firstNonEmpty(c.TargetMAC, req.Meta.DstMAC, defaultTargetMAC)
	senderIP := firstNonEmpty(c.SenderIP, defaultSenderIP)
	targetIP := firstNonEmpty(c.TargetIP, defaultTargetIP)

	if op == OperationRequest {
		// 帧1 request(up)：广播问，tha 全零（RFC 826）。
		if err := emitARP(ctx, req, "up", senderMAC, broadcastMAC,
			OperationRequest, senderMAC, senderIP, zeroMAC, targetIP); err != nil {
			return err
		}
		// 帧2 reply(down)：对端单播答，角色互换。
		return emitARP(ctx, req, "down", targetMAC, senderMAC,
			OperationReply, targetMAC, targetIP, senderMAC, senderIP)
	}
	// op=2 单发宣告(down)：对端角色（裁定3 勘误——legacy 此形发广播错位帧）。
	return emitARP(ctx, req, "down", targetMAC, senderMAC,
		op, targetMAC, targetIP, senderMAC, senderIP)
}

const zeroMAC = "00:00:00:00:00:00"

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func emitARP(ctx context.Context, req *layers.GenRequest, direction, ethSrc, ethDst string, oper uint16, sha, spa, tha, tpa string) error {
	b, err := BuildARPBody(oper, sha, spa, tha, tpa)
	if err != nil {
		return err
	}
	p := core.PacketConfig{
		Direction: direction,
		L2:        core.L2Config{SrcMAC: ethSrc, DstMAC: ethDst, EtherType: core.EtherTypeARP},
		L4:        core.L4Config{Protocol: "arp"},
		Payload:   b,
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return req.Emit(p)
}

// BuildARPBody 构造 28B ARP 载荷（RFC 826 字段序，legacy buildARPPacket
// 字节面复用）：htype2(0001)+ptype2(0800)+hlen1(06)+plen1(04)+oper2+
// sha6+spa4+tha6+tpa4。
func BuildARPBody(oper uint16, sha, spa, tha, tpa string) ([]byte, error) {
	packet := make([]byte, 28)
	packet[0], packet[1] = 0x00, 0x01 // htype: Ethernet
	packet[2], packet[3] = 0x08, 0x00 // ptype: IPv4
	packet[4] = 0x06                  // hlen: MAC
	packet[5] = 0x04                  // plen: IPv4
	packet[6] = byte(oper >> 8)
	packet[7] = byte(oper)
	if err := putMAC(packet[8:14], sha); err != nil {
		return nil, fmt.Errorf("arp: invalid sender_mac %q: %w", sha, err)
	}
	if err := putIP(packet[14:18], spa); err != nil {
		return nil, fmt.Errorf("arp: invalid sender_ip %q: %w", spa, err)
	}
	if err := putMAC(packet[18:24], tha); err != nil {
		return nil, fmt.Errorf("arp: invalid target_mac %q: %w", tha, err)
	}
	if err := putIP(packet[24:28], tpa); err != nil {
		return nil, fmt.Errorf("arp: invalid target_ip %q: %w", tpa, err)
	}
	return packet, nil
}

func putMAC(dst []byte, s string) error {
	m, err := net.ParseMAC(s)
	if err != nil || len(m) != 6 {
		return fmt.Errorf("want 6-byte MAC")
	}
	copy(dst, m)
	return nil
}

func putIP(dst []byte, s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("want IPv4")
	}
	ip4 := ip.To4()
	if ip4 == nil || len(ip4) != 4 {
		return fmt.Errorf("want IPv4")
	}
	copy(dst, ip4)
	return nil
}

// ValidateARPSpec 校验 arp 层配置（D-ARP-1 裁定4）：IP/MAC 格式非法拒；
// operation 语义域由 registry V9 [1,2] create-time 先火，此处只兜 0（缺省
// 合法）；IP 承载混入由 V-carrier 通用门拒（complete.go，锚词带 "carrier"）。
func ValidateARPSpec(s core.FlowSpec) error {
	c := s.ARP
	if c == nil {
		return nil // 空层零值缺省合法（P0b 默认流口径）
	}
	if c.SenderIP != "" && net.ParseIP(c.SenderIP) == nil {
		return fmt.Errorf("arp: invalid sender_ip %q", c.SenderIP)
	}
	if c.TargetIP != "" && net.ParseIP(c.TargetIP) == nil {
		return fmt.Errorf("arp: invalid target_ip %q", c.TargetIP)
	}
	if c.SenderMAC != "" {
		if _, err := net.ParseMAC(c.SenderMAC); err != nil {
			return fmt.Errorf("arp: invalid sender_mac %q", c.SenderMAC)
		}
	}
	if c.TargetMAC != "" {
		if _, err := net.ParseMAC(c.TargetMAC); err != nil {
			return fmt.Errorf("arp: invalid target_mac %q", c.TargetMAC)
		}
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("arp", func() (layers.LayerGenerator, error) { return &Generator{}, nil })
	layers.RegisterLayerValidator("arp", func(s *core.FlowSpec) error { return ValidateARPSpec(*s) })
}
