package layers_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/smtp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/smtp"
)

// 冒烟：smtp 层链接线（main.go 空导入 + 注册后 init 反向注册生成器/校验器，
// NewChainPlanner("smtp") 能实例化并产包）。[ip→tcp→smtp] 链：tcp 层生成器
// 负责握手/seq-ack/挥手/MSS 分段，smtp 终结层产 banner + Dialog 命令/响应对
// 报文事件。
func TestChainPlannerSMTPSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 50000, DstPort: 25,
		SMTP: &core.SMTPConfig{
			Banner: "220 mail.example.org ESMTP",
			Dialog: []core.SMTPCommand{
				{Cmd: "HELO client.example.org", Response: "250 mail.example.org"},
				{Cmd: "QUIT", Response: "221 2.0.0 Bye"},
			},
		},
	}
	ch, err := layers.NewChainPlanner("smtp").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	var n int
	var upData, downData int
	for p := range ch {
		if p.L4.Protocol != "tcp" {
			t.Fatalf("packet %d: L4.Protocol=%q, want tcp", n, p.L4.Protocol)
		}
		if len(p.Payload) > 0 {
			if p.Direction == "up" {
				upData++
			} else {
				downData++
			}
		}
		n++
	}
	// 3 握手 + 2 数据对（HELO 请求/响应 + QUIT 请求/响应）+ 1 banner + 4 挥手
	if n == 0 {
		t.Fatalf("smtp chain produced 0 packets")
	}
	if upData < 2 || downData < 3 {
		t.Fatalf("smtp chain: up data=%d down data=%d, want >=2/>=3 (banner+2 responses)", upData, downData)
	}
	t.Logf("smtp chain produced %d packets (%d up data, %d down data)", n, upData, downData)
}

// TestChainPlannerSMTPEmptyConfigDefaultDialog：空 SMTPConfig（无 Dialog）走
// 默认会话（banner 自动生成 + HELO/MAIL/RCPT/DATA/QUIT），且 tcp.dst_port=25
// FieldContract 补齐端口。
func TestChainPlannerSMTPEmptyConfigDefaultDialog(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	ch, err := layers.NewChainPlanner("smtp").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	var n, upOK int
	for p := range ch {
		if p.Direction == "up" && p.L4.DstPort == 25 {
			upOK++
		}
		n++
	}
	if n == 0 {
		t.Fatalf("smtp chain produced 0 packets")
	}
	if upOK == 0 {
		t.Fatalf("smtp chain: no up packet with default DstPort 25")
	}
	t.Logf("smtp chain produced %d packets (%d up@25)", n, upOK)
}

// TestChainPlannerSMTPCustomPort：用户显式写非标准端口（submission 587），
// FieldContract 不强制 25（用户显式优先）。
func TestChainPlannerSMTPCustomPort(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", DstPort: 587}
	ch, err := layers.NewChainPlanner("smtp").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	var n, up587 int
	for p := range ch {
		if p.Direction == "up" && p.L4.DstPort == 587 {
			up587++
		}
		n++
	}
	if n == 0 || up587 == 0 {
		t.Fatalf("smtp chain custom port: packets=%d up@587=%d, want >0/ >0", n, up587)
	}
}

// smtpMaskTCPSeqAck zeroes the volatile bytes that differ between two
// independent runs of the SMTP flow: IPv4 ID (18-19), IP checksum (24-25),
// and the TCP seq/ack (TCP header offsets 4-11 = frame offset 38-45 given
// 14-byte Ethernet + 20-byte IPv4 header). The TCP checksum (TCP offset 16 =
// frame offset 50-51) covers seq/ack and is masked too. Both planners draw a
// random ISN, so seq/ack never match byte-for-byte; the payload bytes and
// their lengths must match.
func smtpMaskTCPSeqAck(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	if len(out) > 51 {
		out[18], out[19] = 0, 0                         // IPID
		out[24], out[25] = 0, 0                         // IP header checksum
		out[38], out[39], out[40], out[41] = 0, 0, 0, 0 // TCP seq
		out[42], out[43], out[44], out[45] = 0, 0, 0, 0 // TCP ack
		out[50], out[51] = 0, 0                         // TCP checksum
	}
	return out
}

// TestChainPlannerSMTPDataFramesByteIdentical 验证 [ip→tcp→smtp] 链与 legacy
// smtp.NewPlanner 的数据帧字节一致（banner + Dialog 命令/响应对 payload 与
// 方向逐帧对应；TCP seq/ack/IPID/校验和屏蔽后）。握手/挥手帧由 tcp 层生成器
// 负责，与 legacy 自产的握手存在 MSS 选项/挥手包数差异（文档化 divergence），
// 只对比数据帧。
func TestChainPlannerSMTPDataFramesByteIdentical(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 mail.example.org ESMTP",
			Dialog: []core.SMTPCommand{
				{Cmd: "HELO client.example.org", Response: "250 mail.example.org"},
				{Cmd: "QUIT", Response: "221 2.0.0 Bye"},
			},
		},
	}
	chain := collectPlanner(t, layers.NewChainPlanner("smtp"), spec)
	legacy := collectPlanner(t, smtp.NewPlanner(), spec)
	if len(chain) != len(legacy) {
		t.Fatalf("chain=%d packets, legacy=%d, want equal", len(chain), len(legacy))
	}
	b := core.NewBuilder()
	for i := range chain {
		// 只对比数据帧（payload 非空）：握手/挥手帧的 seq 语义由 tcp 层生成器
		// 与 legacy 各自持有（随机 ISN），且链上挥手是 4 包 vs legacy 4 包——
		// 数据帧 payload 与方向逐帧对应才是本测试的核心断言。
		if len(chain[i].Payload) == 0 {
			continue
		}
		if chain[i].Direction != legacy[i].Direction {
			t.Fatalf("packet %d direction: chain=%s legacy=%s", i, chain[i].Direction, legacy[i].Direction)
		}
		if !bytes.Equal(chain[i].Payload, legacy[i].Payload) {
			t.Fatalf("packet %d payload differ:\nchain  %q\nlegacy %q", i, chain[i].Payload, legacy[i].Payload)
		}
		cb, err := b.Build(chain[i])
		if err != nil {
			t.Fatalf("Build(chain[%d]): %v", i, err)
		}
		lb, err := b.Build(legacy[i])
		if err != nil {
			t.Fatalf("Build(legacy[%d]): %v", i, err)
		}
		if !bytes.Equal(smtpMaskTCPSeqAck(cb), smtpMaskTCPSeqAck(lb)) {
			t.Errorf("packet %d frame bytes differ:\nchain  %x\nlegacy %x", i, cb, lb)
		}
	}
}
