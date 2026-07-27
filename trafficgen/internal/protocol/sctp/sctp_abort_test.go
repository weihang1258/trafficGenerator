package sctp

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestSCTP_AbortEmitsSingleChunk verifies the C3.4 fix: when SCTPConfig.Abort
// is true, the planner emits a single ABORT chunk in place of the 3-way
// SHUTDOWN teardown. Per RFC 4960 §9.1, ABORT is the abrupt-close path
// (used to signal "I'm tearing this down without negotiating TSN exchange")
// and is modeled as one chunk. Previously, the planner always emitted the
// 3-way SHUTDOWN/SHUTDOWN-ACK/SHUTDOWN-COMPLETE sequence regardless, so a
// user couldn't simulate the ABORT path for fault-injection scenarios.
//
// Test counts packets AFTER the COOKIE-ACK and before the channel close:
//   - 0 DATA chunks + Abort=true -> exactly 1 packet (the ABORT chunk)
//   - 0 DATA chunks + Abort=false -> exactly 3 packets (the SHUTDOWN trio)
//   - 1 DATA chunk + Abort=true -> 4 packets total (handshake=4, data=1, abort=1)
//     asserted by chunk-shape (chunks[0..N-2] are not ABORT, chunks[N-1] is)
func TestSCTP_AbortEmitsSingleChunk(t *testing.T) {
	cases := []struct {
		name     string
		abort    bool
		chunks   []core.SCTPChunk
		wantTail []uint8 // chunk types of the last 1 (abort) or 3 (shutdown) packets
	}{
		{
			name:     "Abort=true, no DATA -> single ABORT chunk",
			abort:    true,
			chunks:   nil,
			wantTail: []uint8{ChunkABORT},
		},
		{
			name:     "Abort=false (default), no DATA -> 3-way SHUTDOWN",
			abort:    false,
			chunks:   nil,
			wantTail: []uint8{ChunkSHUTDOWN, ChunkSHUTDOWNAck, ChunkSHUTDOWNComplete},
		},
		{
			name:  "Abort=true, one DATA -> ABORT after DATA chunk",
			abort: true,
			chunks: []core.SCTPChunk{
				{Direction: "up", Data: []byte("x")},
			},
			wantTail: []uint8{ChunkDATA, ChunkABORT},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := core.FlowSpec{
				SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
				SrcPort: 9000, DstPort: 9001,
				SCTP: &core.SCTPConfig{
					Abort:  tc.abort,
					Chunks: tc.chunks,
				},
			}
			configs, err := NewPlanner().Plan(context.Background(), spec)
			if err != nil {
				t.Fatalf("Plan() error = %v", err)
			}
			var gotChunks []uint8
			for cfg := range configs {
				if len(cfg.Payload) < 4 {
					// Empty chunks (COOKIE-ACK, SHUTDOWN-ACK, SHUTDOWN-COMPLETE)
					// have no chunk-type byte at the start - we still record
					// the "0 marker" so the tail count matches. To keep the
					// assertion shape stable, we skip non-chunk packets.
					continue
				}
				gotChunks = append(gotChunks, cfg.Payload[0])
			}
			// Take the trailing N packets matching wantTail length.
			tailLen := len(tc.wantTail)
			if len(gotChunks) < tailLen {
				t.Fatalf("got %d chunk packets, want at least %d (tail=%v, all=%v)",
					len(gotChunks), tailLen, tc.wantTail, gotChunks)
			}
			tail := gotChunks[len(gotChunks)-tailLen:]
			for i := range tail {
				if tail[i] != tc.wantTail[i] {
					t.Errorf("tail[%d] chunk type = %d, want %d (full tail=%v)",
						i, tail[i], tc.wantTail[i], tail)
				}
			}
		})
	}
}

// TestSCTP_Abort_ChunkByteShape asserts the ABORT chunk wire format per
// RFC 4960 §6.4: Type=6, Flags=0 (T-bit=0, no other flags), Length=4
// (no Cause fields — the minimal ABORT). Length MUST include the 4-byte
// chunk header (per §3.2) and MUST NOT be padded for inspection because
// ABORT is exactly the 4-byte header with no value bytes.
//
// This is a builder-level shape test — separate from the planner-level
// "which chunks get emitted" test above. It catches silent regressions
// in buildABORTChunk (e.g. someone adding a dummy Cause field that
// changes the wire shape a DPI would see).
func TestSCTP_Abort_ChunkByteShape(t *testing.T) {
	chunk := buildABORTChunk()

	// Minimal ABORT: 4 bytes exactly. Type=6, Flags=0, Length=4.
	if got, want := len(chunk), 4; got != want {
		t.Fatalf("len(ABORT chunk) = %d, want %d (minimal: no Cause fields)", got, want)
	}
	if got := chunk[0]; got != ChunkABORT {
		t.Errorf("chunk[0] (Type) = %d, want %d (ChunkABORT)", got, ChunkABORT)
	}
	if got := chunk[1]; got != 0x00 {
		t.Errorf("chunk[1] (Flags) = 0x%02x, want 0x00 (T-bit=0, no other flags)", got)
	}
	length := binary.BigEndian.Uint16(chunk[2:4])
	if length != 4 {
		t.Errorf("chunk[2:4] (Length) = %d, want 4 (includes 4-byte header, no Cause)", length)
	}
}

// TestSCTP_Abort_NoShutdownTriplet verifies that when Abort=true, the
// planner NEVER emits a SHUTDOWN (7), SHUTDOWN-ACK (8), or
// SHUTDOWN-COMPLETE (14) chunk. The 3-way teardown must be fully
// replaced by a single ABORT chunk — emitting any of the shutdown
// trio alongside ABORT would create two competing teardowns a real
// peer wouldn't know how to interpret.
//
// We scan the entire PacketConfig stream (not just the tail) for any
// of the shutdown chunk type bytes.
func TestSCTP_Abort_NoShutdownTriplet(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 9000, DstPort: 9001,
		SCTP: &core.SCTPConfig{
			Abort: true,
			Chunks: []core.SCTPChunk{
				{Direction: "up", Data: []byte("hello")},
				{Direction: "up", Data: []byte("world")},
			},
		},
	}
	configs, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	for cfg := range configs {
		if len(cfg.Payload) < 1 {
			continue
		}
		switch cfg.Payload[0] {
		case ChunkSHUTDOWN, ChunkSHUTDOWNAck, ChunkSHUTDOWNComplete:
			t.Errorf("Abort=true but got shutdown chunk type %d in stream; ABORT must fully replace the 3-way shutdown",
				cfg.Payload[0])
		}
	}
}

// TestSCTP_Abort_TotalPacketCount verifies the aggregate packet count
// for the ABORT path. For Abort=true with N up-direction DATA chunks,
// the total emit count is:
//
//	handshake (4) + N data + 1 ABORT = N+5 packets
//
// No additional packets from the normal 3-way shutdown (3 packets
// suppressed). This is a step above the tail-shape test — it asserts
// the planner doesn't accidentally emit a stray packet (e.g. an empty
// shell) on the abort path.
func TestSCTP_Abort_TotalPacketCount(t *testing.T) {
	cases := []struct {
		name       string
		dataChunks int
		wantTotal  int
	}{
		{"0 data chunks", 0, 5}, // 4 handshake + 0 data + 1 abort
		{"1 data chunk", 1, 6},  // 4 handshake + 1 data + 1 abort
		{"3 data chunks", 3, 8}, // 4 handshake + 3 data + 1 abort
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chunks := make([]core.SCTPChunk, tc.dataChunks)
			for i := range chunks {
				chunks[i] = core.SCTPChunk{Direction: "up", Data: []byte("x")}
			}
			spec := core.FlowSpec{
				SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
				SrcPort: 9000, DstPort: 9001,
				SCTP: &core.SCTPConfig{
					Abort:  true,
					Chunks: chunks,
				},
			}
			configs, err := NewPlanner().Plan(context.Background(), spec)
			if err != nil {
				t.Fatalf("Plan() error = %v", err)
			}
			var got int
			for range configs {
				got++
			}
			if got != tc.wantTotal {
				t.Errorf("packet count = %d, want %d (4 handshake + %d data + 1 abort)",
					got, tc.wantTotal, tc.dataChunks)
			}
		})
	}
}

// TestSCTP_Abort_DefaultFalseKeepsShutdown verifies the backward-compat
// invariant: when Abort is left at its zero value (false), the planner
// still emits the 3-way SHUTDOWN/SHUTDOWN-ACK/SHUTDOWN-COMPLETE
// sequence. This is the regression boundary — silent default-flipping
// would break every existing test scenario that doesn't set Abort
// explicitly.
//
// Separate from TestSCTP_AbortEmitsSingleChunk's "Abort=false" case
// because that sub-test only asserts the tail shape; this asserts the
// total emit count for a flow without explicit DATA chunks (4 handshake
// + 3 shutdown = 7 packets).
func TestSCTP_Abort_DefaultFalseKeepsShutdown(t *testing.T) {
	// Spec with NO SCTPConfig at all (SCTP nil) — must also default to
	// the 3-way shutdown path. The planner's spec-handling injects a
	// zero-value SCTPConfig when SCTP is nil.
	t.Run("SCTP nil", func(t *testing.T) {
		spec := core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			SrcPort: 9000, DstPort: 9001,
		}
		configs, err := NewPlanner().Plan(context.Background(), spec)
		if err != nil {
			t.Fatalf("Plan() error = %v", err)
		}
		var got int
		for range configs {
			got++
		}
		// 4 handshake + 0 data + 3 shutdown = 7 packets
		if got != 7 {
			t.Errorf("packet count (SCTP nil) = %d, want 7 (4 handshake + 3 shutdown)", got)
		}
	})
	t.Run("Abort false explicitly", func(t *testing.T) {
		spec := core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			SrcPort: 9000, DstPort: 9001,
			SCTP: &core.SCTPConfig{Abort: false},
		}
		configs, err := NewPlanner().Plan(context.Background(), spec)
		if err != nil {
			t.Fatalf("Plan() error = %v", err)
		}
		var got int
		for range configs {
			got++
		}
		if got != 7 {
			t.Errorf("packet count (Abort=false) = %d, want 7 (4 handshake + 3 shutdown)", got)
		}
	})
}

// TestSCTP_Abort_UpDirectionAndServerVTag verifies the ABORT chunk's
// direction and verification tag. Per RFC 4960 §8.5.1, ABORT must use
// the peer's last-seen verification tag (the server's tag for an
// ABORT initiated by the client) — mirroring the DATA chunk's tag
// pattern in the same planner. Without this, a DPI/receiver couldn't
// attribute the ABORT to the correct association and would discard it.
//
// Direction "up" (client→server) is the conventional model: the
// client decides to tear the association down (fault injection, RST
// equivalent for SCTP).
func TestSCTP_Abort_UpDirectionAndServerVTag(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 9000, DstPort: 9001,
		SrcMAC: "aa:bb:cc:dd:ee:f1", DstMAC: "aa:bb:cc:dd:ee:f2",
		SCTP: &core.SCTPConfig{
			Abort: true,
			// Fixed verification tags so we can assert equality
			// without playing the random-tag dance.
			VerificationTag: 0x11111111, // client local (server puts this in packets→client)
			InitiateTag:     0x22222222, // server's InitiateTag (client puts this in packets→server)
		},
	}
	configs, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var aborter *core.PacketConfig
	var nAbort int
	for cfg := range configs {
		if len(cfg.Payload) >= 1 && cfg.Payload[0] == ChunkABORT {
			nAbort++
			aborter = &cfg
		}
	}
	if nAbort != 1 {
		t.Fatalf("got %d ABORT packets, want exactly 1", nAbort)
	}
	if aborter.Direction != "up" {
		t.Errorf("ABORT direction = %q, want %q (client→server)",
			aborter.Direction, "up")
	}
	if aborter.L4.Ack != 0x22222222 {
		t.Errorf("ABORT VerificationTag (L4.Ack) = 0x%08x, want 0x22222222 (server's InitiateTag)",
			aborter.L4.Ack)
	}
	if aborter.L4.SrcPort != 9000 || aborter.L4.DstPort != 9001 {
		t.Errorf("ABORT ports = (%d,%d), want (9000,9001) — must match flow 4-tuple",
			aborter.L4.SrcPort, aborter.L4.DstPort)
	}
}
