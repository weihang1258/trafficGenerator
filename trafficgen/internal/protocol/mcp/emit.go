package mcp

import (
	"context"
	"sync/atomic"

	"github.com/trafficgen/trafficgen/internal/core"
)

// globalPacketCounter is a process-wide atomic counter used to guarantee
// unique PacketIndex values across all flows and sessions (design §8.10
// T44: packet_index globally unique, no duplicates across multi-session).
var globalPacketCounter uint64

// nextPacketIndex atomically returns a unique packet index for this Plan
// session (and across all Plan calls in the process).
func nextPacketIndex() uint64 {
	return atomic.AddUint64(&globalPacketCounter, 1)
}

// emitHandshake pushes 3 SYN/SYN-ACK/ACK packets to out (design §6.2).
//
// v1.1.x M-2 修复：所有 emit 函数接受 ctx，并在 pushPkt 内部对 ctx.Done()
// 做 select，避免 ctx 已取消时 goroutine 在阻塞发送上挂死。
func emitHandshake(ctx context.Context, out chan<- core.PacketConfig, spec core.FlowSpec, dstPort uint16, flowID string, ttl uint8, ps *planState) {
	now := ps.now
	pushPkt(ctx, out, core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: nextPacketIndex(),
		Direction:   "up",
		Timestamp:   now,
		L2:          makeL2(spec, "up"),
		L3:          makeL3(spec, "up", ttl, ps),
		L4:          core.L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: dstPort, Flags: 0x02}, // SYN
		Payload:     nil,
	})
	pushPkt(ctx, out, core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: nextPacketIndex(),
		Direction:   "down",
		Timestamp:   now,
		L2:          makeL2(spec, "down"),
		L3:          makeL3(spec, "down", ttl, ps),
		L4:          core.L4Config{Protocol: "tcp", SrcPort: dstPort, DstPort: spec.SrcPort, Flags: 0x12}, // SYN-ACK
		Payload:     nil,
	})
	pushPkt(ctx, out, core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: nextPacketIndex(),
		Direction:   "up",
		Timestamp:   now,
		L2:          makeL2(spec, "up"),
		L3:          makeL3(spec, "up", ttl, ps),
		L4:          core.L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: dstPort, Flags: 0x10}, // ACK
		Payload:     nil,
	})
}

// emitAppData pushes one TCP PSH-ACK packet carrying the given payload.
// L4 src/dst ports are swapped for the down direction so server→client
// replies carry the server's port as source (matching handshake/teardown
// behavior and TCP semantics).
func emitAppData(ctx context.Context, out chan<- core.PacketConfig, spec core.FlowSpec, dstPort uint16, flowID, dir string, ttl uint8, ps *planState, payload []byte) {
	srcPort, dstPort2 := spec.SrcPort, dstPort
	if dir == "down" {
		srcPort, dstPort2 = dstPort, spec.SrcPort
	}
	pushPkt(ctx, out, core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: nextPacketIndex(),
		Direction:   dir,
		Timestamp:   ps.now,
		L2:          makeL2(spec, dir),
		L3:          makeL3(spec, dir, ttl, ps),
		L4: core.L4Config{
			Protocol: "tcp",
			SrcPort:  srcPort,
			DstPort:  dstPort2,
			Flags:    0x18, // PSH-ACK
		},
		Payload: payload,
	})
}

// emitTeardown pushes 3 teardown packets per socks5 template (§6.2):
// FIN-ACK(up) -> FIN-ACK(down) -> ACK(up).
func emitTeardown(ctx context.Context, out chan<- core.PacketConfig, spec core.FlowSpec, dstPort uint16, flowID string, ttl uint8, ps *planState) {
	now := ps.now
	pushPkt(ctx, out, core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: nextPacketIndex(),
		Direction:   "up",
		Timestamp:   now,
		L2:          makeL2(spec, "up"),
		L3:          makeL3(spec, "up", ttl, ps),
		L4:          core.L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: dstPort, Flags: 0x11}, // FIN-ACK
		Payload:     nil,
	})
	pushPkt(ctx, out, core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: nextPacketIndex(),
		Direction:   "down",
		Timestamp:   now,
		L2:          makeL2(spec, "down"),
		L3:          makeL3(spec, "down", ttl, ps),
		L4:          core.L4Config{Protocol: "tcp", SrcPort: dstPort, DstPort: spec.SrcPort, Flags: 0x11}, // FIN-ACK
		Payload:     nil,
	})
	pushPkt(ctx, out, core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: nextPacketIndex(),
		Direction:   "up",
		Timestamp:   now,
		L2:          makeL2(spec, "up"),
		L3:          makeL3(spec, "up", ttl, ps),
		L4:          core.L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: dstPort, Flags: 0x10}, // ACK
		Payload:     nil,
	})
}

// makeL2 builds an L2Config for the given direction.
func makeL2(spec core.FlowSpec, dir string) core.L2Config {
	if dir == "up" {
		return core.L2Config{
			SrcMAC:    spec.SrcMAC,
			DstMAC:    spec.DstMAC,
			EtherType: core.EtherTypeFor(spec.SrcIP),
		}
	}
	return core.L2Config{
		SrcMAC:    spec.DstMAC,
		DstMAC:    spec.SrcMAC,
		EtherType: core.EtherTypeFor(spec.DstIP),
	}
}

// makeL3 builds an L3Config for the given direction.
func makeL3(spec core.FlowSpec, dir string, ttl uint8, ps *planState) core.L3Config {
	if dir == "up" {
		return core.L3Base(spec.SrcIP, spec.DstIP, 6, ttl, ps.nextIPID(), spec)
	}
	return core.L3Base(spec.DstIP, spec.SrcIP, 6, ttl, ps.nextIPID(), spec)
}

// pushPkt pushes one packet to out. 当 ctx 已取消时立即返回（不发送），
// 避免 goroutine 在阻塞 channel 发送上挂死（v1.1.x M-2 修复）。
//
// 注意：select 同时监听 out<-pkt 和 ctx.Done()。当 ctx 取消时，已构造
// 但未发送的 packet 被丢弃；调用方（goroutine）应在 pushPkt 返回后
// 检查 ctx 并退出。emit 系列函数不返回错误，因此 ctx 取消是静默的
// （符合 Plan() 的语义：ctx 取消后 channel 被 close，调用方 drain 时
// 会看到提前关闭）。
func pushPkt(ctx context.Context, out chan<- core.PacketConfig, pkt core.PacketConfig) {
	select {
	case out <- pkt:
	case <-ctx.Done():
	}
}
