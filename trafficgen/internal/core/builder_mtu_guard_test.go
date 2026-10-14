package core

// D-UDP-MTU：builder 16 位长度域守卫。超限以前静默回绕成畸形包
// （实测 70042B 帧 ip.len 回绕 4492），改为显式报错——任务失败报失败。
// 测试登记 T-UDP-MTU-9（仅单测：全层守卫齐全后 MCP 面无自然触发点）。

import (
	"strings"
	"testing"
)

func TestBuilder_UDPLengthOverflowErrors(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{
		Direction: "up",
		L3:        L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17},
		L4:        L4Config{Protocol: "udp", SrcPort: 5000, DstPort: 9001},
		Payload:   make([]byte, 70000),
	}
	_, err := b.Build(cfg)
	if err == nil {
		t.Fatal("udp 70000B payload: Build() = nil error, want length-field guard error (previously silent uint16 wrap)")
	}
	if !strings.Contains(err.Error(), "65535") {
		t.Fatalf("err = %v, want anchor 65535", err)
	}
}

func TestBuilder_IPv4TotalLengthOverflowErrors(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{
		Direction: "up",
		L3:        L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6},
		L4:        L4Config{Protocol: "tcp", SrcPort: 5000, DstPort: 80},
		Payload:   make([]byte, 70000),
	}
	_, err := b.Build(cfg)
	if err == nil || !strings.Contains(err.Error(), "65535") {
		t.Fatalf("IPv4 total 70030: err = %v, want 65535 anchor", err)
	}
}

func TestBuilder_IPv6PayloadLengthOverflowErrors(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{
		Direction: "up",
		L2:        L2Config{EtherType: EtherTypeIPv6},
		L3:        L3Config{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", Protocol: 17},
		L4:        L4Config{Protocol: "udp", SrcPort: 5000, DstPort: 9001},
		Payload:   make([]byte, 70000),
	}
	_, err := b.Build(cfg)
	if err == nil || !strings.Contains(err.Error(), "65535") {
		t.Fatalf("IPv6 payload 70008: err = %v, want 65535 anchor", err)
	}
}

// 上限恰好合法：65507B udp 包（mtu=65535 预算上限）必须能组出。
func TestBuilder_UDPMaxLegalLengthBuilds(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{
		Direction: "up",
		L3:        L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17},
		L4:        L4Config{Protocol: "udp", SrcPort: 5000, DstPort: 9001},
		Payload:   make([]byte, 65507),
	}
	frame, err := b.Build(cfg)
	if err != nil {
		t.Fatalf("65507B legal max: Build() error = %v", err)
	}
	if len(frame) != 14+20+8+65507 {
		t.Fatalf("frame = %d bytes, want %d", len(frame), 14+20+8+65507)
	}
}
