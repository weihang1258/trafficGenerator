package moxa

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (p Planner) Name() string { return "moxa" }

func (p Planner) Validate(spec core.FlowSpec) error {
	if spec.MOXA == nil {
		// P0b-2：空配置不再报错——Generate/Plan 已默认化并产默认流
		// （stream "hello"）。允许 nil。
		return nil
	}
	cfg := spec.MOXA
	if cfg.Sessions > 1 {
		return fmt.Errorf("moxa: sessions=%d>1 not supported (multi-sessions: use strategy flow_control flows)", cfg.Sessions)
	}
	if spec.TCP != nil && !spec.TCP.Handshake {
		return fmt.Errorf("moxa: tcp.handshake must be true (serial passthrough needs a TCP connection)")
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("moxa: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("moxa: invalid destination IP")
	}
	if spec.SrcIP != "" && spec.DstIP != "" {
		src, dst := net.ParseIP(spec.SrcIP), net.ParseIP(spec.DstIP)
		if (src.To4() != nil) != (dst.To4() != nil) {
			return fmt.Errorf("moxa: SrcIP and DstIP must be same IP version")
		}
	}
	stream := cfg.Stream
	if len(stream) == 0 {
		return fmt.Errorf("moxa: empty stream block or payload required")
	}
	for i, b := range stream {
		if b.Direction != "" && b.Direction != "up" && b.Direction != "down" {
			return fmt.Errorf("moxa: invalid direction %q, want up|down", b.Direction)
		}
		var data []byte
		if b.PayloadB64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(b.PayloadB64)
			if err != nil {
				return fmt.Errorf("moxa: invalid payload_b64: %v", err)
			}
			data = decoded
		} else if b.Payload != "" {
			data = []byte(b.Payload)
		} else {
			return fmt.Errorf("moxa: empty stream block or payload required")
		}
		if len(data) == 0 {
			return fmt.Errorf("moxa: empty stream block or payload required")
		}
		if len(data) > MaxBlockBytes {
			return fmt.Errorf("moxa: block %d payload %d exceeds max %d", i, len(data), MaxBlockBytes)
		}
		if len(data) >= 3 && data[0] == 0x5a && data[1] == 0x5a && data[2] == 0x5a {
			return fmt.Errorf("moxa: config-packet bytes in stream are not supported (see §3.2)")
		}
	}
	return nil
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 4800
	}
	cfg := spec.MOXA
	if cfg == nil {
		// P0b-2：空配置默认化（Generate 同款：stream "hello"）。
		cfg = &MOXAConfig{Stream: []MOXAStreamBlock{{Payload: "hello"}}}
	}
	if len(cfg.Stream) == 0 {
		cpy := *cfg
		cpy.Stream = []MOXAStreamBlock{{Payload: "hello"}}
		cfg = &cpy
	}
	mss := 1460
	if spec.TCP != nil && spec.TCP.MSS != 0 {
		mss = int(spec.TCP.MSS)
	}
	out := make(chan core.PacketConfig, 32)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort
			dir := "up"
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
				dir = "down"
			}
			select {
			case out <- core.PacketConfig{FlowID: "moxa", PacketIndex: idx, Direction: dir, L2: core.L2Config{EtherType: core.EtherTypeFor(sip)}, L3: core.L3Base(sip, dip, 6, 64, uint16(idx), spec), L4: core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535}, Payload: payload, Timestamp: time.Now()}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		if !emit(true, nil, 2) || !emit(false, nil, 0x12) || !emit(true, nil, 0x10) {
			return
		}
		for _, blk := range cfg.Stream {
			var data []byte
			if blk.PayloadB64 != "" {
				decoded, _ := base64.StdEncoding.DecodeString(blk.PayloadB64)
				data = decoded
			} else {
				data = []byte(blk.Payload)
			}
			up := blk.Direction == "" || blk.Direction == "up"
			for off := 0; off < len(data); off += mss {
				end := off + mss
				if end > len(data) {
					end = len(data)
				}
				if !emit(up, data[off:end], 0x18) {
					return
				}
			}
		}
		emit(true, nil, 0x11)
		emit(false, nil, 0x10)
		emit(false, nil, 0x11)
		emit(true, nil, 0x10)
	}()
	return out, nil
}
