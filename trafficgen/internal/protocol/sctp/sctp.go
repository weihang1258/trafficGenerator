// Package sctp implements the SCTP protocol planner.
//
// SCTP (Stream Control Transmission Protocol, RFC 4960) is a session-level,
// message-oriented transport carrying IP protocol 132. Unlike TCP's 3-way
// handshake, SCTP uses a 4-way handshake:
//
//	INIT       (client -> server, VerificationTag=0 per RFC 4960 §5.1.1)
//	INIT-ACK   (server -> client, carries server's InitiateTag + Cookie)
//	COOKIE-ECHO (client -> server, echoes the Cookie from INIT-ACK)
//	COOKIE-ACK (server -> client, association established)
//
// DATA chunks carry TSN (transmission sequence number, per-direction),
// SID (stream id), SSN (per-stream sequence), and PPID (payload protocol
// id). Teardown is a 3-way SHUTDOWN:
//
//	SHUTDOWN         (client -> server, highest cumulative TSN ack)
//	SHUTDOWN-ACK     (server -> client)
//	SHUTDOWN-COMPLETE (client -> server, final packet)
//
// The planner emits the 4-way handshake, each SCTPChunk in Chunks as a
// DATA chunk, then the 3-way SHUTDOWN — all within one 4-tuple (one flow)
// with one continuous TSN space per direction.
//
// Verification Tag handling: the client picks the server's InitiateTag
// (from INIT-ACK) as the destination Verification Tag for all subsequent
// packets it sends to the server, and vice versa. For test purposes,
// when the user leaves these at 0, the planner auto-generates random
// non-zero tags for each side. INIT carries VerificationTag=0 per RFC.
//
// This planner does NOT implement HEARTBEAT chunks, multi-homing, or
// SCTP authentication (RFC 4895). It models the minimal session-level
// structure needed to test SCTP-aware packet processing: handshake +
// DATA + teardown, with proper TSN/SID/SSN/PPID in DATA chunks.
package sctp

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64

	// SCTP chunk types per RFC 4960 §3.2.
	ChunkDATA              = 0
	ChunkINIT              = 1
	ChunkINITAck           = 2
	ChunkCOOKIEEcho        = 10
	ChunkCOOKIEAck         = 11
	ChunkHEARTBEAT         = 4
	ChunkHEARTBEATAck      = 5
	ChunkABORT             = 6
	ChunkSHUTDOWN          = 7
	ChunkSHUTDOWNAck       = 8
	ChunkSHUTDOWNComplete  = 14

	// Chunk flags.
	ChunkFlagBeginEnd = 0x03 // DATA chunk B+E (beginning+end of message)
)

// Planner implements the SCTP protocol planner.
type Planner struct{}

// NewPlanner creates a new SCTP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "sctp" }

// Validate validates an SCTP flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
	}
	return nil
}

// Plan generates packet configs for an SCTP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		sctpConfig := spec.SCTP
		if sctpConfig == nil {
			sctpConfig = &core.SCTPConfig{}
		}

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// Verification tags. The client's VerificationTag is the tag the
		// SERVER learns from INIT and puts in packets to the client. The
		// server's InitiateTag (sent in INIT-ACK) is what the CLIENT puts
		// in packets to the server. Per RFC 4960 §5.1.1, INIT carries
		// VerificationTag=0; the value is learned from INIT-ACK. When the
		// user leaves these at 0, the planner picks random non-zero tags.
		clientVerTag := sctpConfig.VerificationTag
		if clientVerTag == 0 {
			clientVerTag = randNonZeroTag()
		}
		serverVerTag := sctpConfig.InitiateTag
		if serverVerTag == 0 {
			serverVerTag = randNonZeroTag()
		}

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// TSN starts at a random value per RFC 6525 (§5.1). User-supplied
		// TSN in SCTPChunk overrides this; otherwise we auto-increment per
		// direction.
		clientTSN := rand.Uint32()
		serverTSN := rand.Uint32()

		// emit builds and sends one SCTP packet. The VerificationTag field
		// goes in the SCTP common header (reuses L4.Ack for storage). The
		// chunks (serialized by the caller) go in Payload.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, verTag uint32, chunks []byte) {
			l3 := core.L3Base(srcIP, dstIP, core.ProtocolSCTP, effectiveTTL, nextIPID(), spec)
			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: l3,
				L4: core.L4Config{
					Protocol: "sctp",
					SrcPort:  srcPort,
					DstPort:  dstPort,
					Ack:      verTag, // VerificationTag stored in Ack slot
				},
				Payload: chunks,
			}
			configChan <- cfg
			packetIndex++
		}

		// --- SCTP 4-way handshake ---

		// INIT (client -> server, VerificationTag=0 per RFC 4960 §5.1.1).
		// The INIT chunk carries the client's InitiateTag (VerificationTag),
		// initial TSN, and other params. We model the minimum: InitiateTag,
		// aRwnd, OS, MIS, initial TSN. Cookie is generated by the server.
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, 0,
			buildINITChunk(clientVerTag, clientTSN))

		// INIT-ACK (server -> client, VerificationTag=client's tag from INIT).
		// Carries the server's InitiateTag, aRwnd, OS, MIS, initial TSN,
		// and a Cookie that the client echoes back unchanged.
		cookie := make([]byte, 32) // arbitrary cookie; just needs to be non-empty
		rand.Read(cookie)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, clientVerTag,
			buildINITAckChunk(serverVerTag, serverTSN, cookie))

		// COOKIE-ECHO (client -> server, VerificationTag=server's tag from INIT-ACK).
		// Echoes the Cookie from INIT-ACK.
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, serverVerTag,
			buildCOOKIEEchoChunk(cookie))

		// COOKIE-ACK (server -> client, VerificationTag=client's tag).
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, clientVerTag,
			buildCOOKIEAckChunk())

		// --- DATA chunks ---
		for _, ch := range sctpConfig.Chunks {
			direction := ch.Direction
			if direction == "" {
				direction = "up"
			}
			if direction != "up" && direction != "down" {
				continue
			}
			var tsn uint32
			if ch.TSN != 0 {
				tsn = ch.TSN
			} else {
				tsn = clientTSN
				clientTSN++
			}
			if direction == "up" {
				dataChunk := buildDATAChunk(tsn, ch.SID, ch.SSN, ch.PPID, ch.Data)
				emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
					spec.SrcPort, spec.DstPort, serverVerTag, dataChunk)
			} else {
				// For down-direction DATA chunks, use the server's TSN
				// space if the user didn't supply a TSN. Note: this branch
				// only triggers when the user explicitly sets Direction="down"
				// on a chunk — the common test case is up-only.
				if ch.TSN != 0 {
					tsn = ch.TSN
				} else {
					tsn = serverTSN
					serverTSN++
				}
				dataChunk := buildDATAChunk(tsn, ch.SID, ch.SSN, ch.PPID, ch.Data)
				emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
					spec.DstPort, spec.SrcPort, clientVerTag, dataChunk)
			}
		}

		// --- SCTP 3-way SHUTDOWN teardown ---

		// SHUTDOWN (client -> server). Carries the highest cumulative TSN
		// ack the client has received. For test purposes, we send the
		// latest serverTSN-1 (the last TSN the server would have sent).
		shutdownTSN := serverTSN
		if shutdownTSN > 0 {
			shutdownTSN-- // last TSN acked = highest received - 1
		}
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, serverVerTag,
			buildSHUTDOWNChunk(shutdownTSN))

		// SHUTDOWN-ACK (server -> client).
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, clientVerTag,
			buildSHUTDOWNAckChunk())

		// SHUTDOWN-COMPLETE (client -> server).
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, serverVerTag,
			buildSHUTDOWNCompleteChunk())
	}()

	return configChan, nil
}

// randNonZeroTag returns a random non-zero 32-bit verification tag. RFC 4960
// §5.1.1 requires the tag to be non-zero (a tag of 0 in a non-INIT packet
// means the sender doesn't have an association yet, which would be a
// protocol violation after the handshake).
func randNonZeroTag() uint32 {
	for {
		t := rand.Uint32()
		if t != 0 {
			return t
		}
	}
}

// buildChunk writes a generic SCTP chunk header (Type + Flags + Length) and
// pads the value to a 4-byte boundary per RFC 4960 §3.2. The Length field
// includes the 4-byte header but NOT the padding.
func buildChunk(chunkType uint8, flags uint8, value []byte) []byte {
	length := uint16(4 + len(value))
	padded := (length + 3) &^ 3
	buf := make([]byte, padded)
	buf[0] = chunkType
	buf[1] = flags
	binary.BigEndian.PutUint16(buf[2:4], length)
	copy(buf[4:], value)
	return buf
}

// buildINITChunk builds an INIT chunk (type 1). Value layout per RFC 4960
// §3.3.1: InitiateTag(4) + aRwnd(4) + OS(2) + MIS(2) + InitialTSN(4) = 16
// bytes of fixed fields, followed by optional params (we omit them).
func buildINITChunk(initiateTag, initialTSN uint32) []byte {
	value := make([]byte, 16)
	binary.BigEndian.PutUint32(value[0:4], initiateTag)
	binary.BigEndian.PutUint32(value[4:8], 65535) // aRwnd
	binary.BigEndian.PutUint16(value[8:10], 10)   // OS (outbound streams)
	binary.BigEndian.PutUint16(value[10:12], 10)  // MIS (inbound streams)
	binary.BigEndian.PutUint32(value[12:16], initialTSN)
	return buildChunk(ChunkINIT, 0, value)
}

// buildINITAckChunk builds an INIT-ACK chunk (type 2). Same layout as INIT
// plus a State Cookie param (type 7). The cookie is what the client echoes
// in COOKIE-ECHO; we just emit the bytes the user passed in.
func buildINITAckChunk(initiateTag, initialTSN uint32, cookie []byte) []byte {
	value := make([]byte, 16+4+len(cookie))
	binary.BigEndian.PutUint32(value[0:4], initiateTag)
	binary.BigEndian.PutUint32(value[4:8], 65535)
	binary.BigEndian.PutUint16(value[8:10], 10)
	binary.BigEndian.PutUint16(value[10:12], 10)
	binary.BigEndian.PutUint32(value[12:16], initialTSN)
	// State Cookie param: Type=7, Length=4+len(cookie), Value=cookie
	binary.BigEndian.PutUint16(value[16:18], 7)
	binary.BigEndian.PutUint16(value[18:20], uint16(4+len(cookie)))
	copy(value[20:], cookie)
	return buildChunk(ChunkINITAck, 0, value)
}

// buildCOOKIEEchoChunk builds a COOKIE-ECHO chunk (type 10). Value is the
// cookie bytes from INIT-ACK, echoed unchanged.
func buildCOOKIEEchoChunk(cookie []byte) []byte {
	return buildChunk(ChunkCOOKIEEcho, 0, cookie)
}

// buildCOOKIEAckChunk builds a COOKIE-ACK chunk (type 11). No value.
func buildCOOKIEAckChunk() []byte {
	return buildChunk(ChunkCOOKIEAck, 0, nil)
}

// buildDATAChunk builds a DATA chunk (type 0) per RFC 4960 §3.3.1. Value
// layout: TSN(4) + SID(2) + SSN(2) + PPID(4) + user data. Flags B+E
// (0x03) indicate the chunk carries a complete message (beginning and
// end) — the common case when a user payload fits in one chunk.
func buildDATAChunk(tsn uint32, sid, ssn uint16, ppid uint32, data []byte) []byte {
	value := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(value[0:4], tsn)
	binary.BigEndian.PutUint16(value[4:6], sid)
	binary.BigEndian.PutUint16(value[6:8], ssn)
	binary.BigEndian.PutUint32(value[8:12], ppid)
	copy(value[12:], data)
	return buildChunk(ChunkDATA, ChunkFlagBeginEnd, value)
}

// buildSHUTDOWNChunk builds a SHUTDOWN chunk (type 7). Value is the highest
// cumulative TSN Ack the sender has received (4 bytes).
func buildSHUTDOWNChunk(highestTSN uint32) []byte {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value[0:4], highestTSN)
	return buildChunk(ChunkSHUTDOWN, 0, value)
}

// buildSHUTDOWNAckChunk builds a SHUTDOWN-ACK chunk (type 8). No value.
func buildSHUTDOWNAckChunk() []byte {
	return buildChunk(ChunkSHUTDOWNAck, 0, nil)
}

// buildSHUTDOWNCompleteChunk builds a SHUTDOWN-COMPLETE chunk (type 14).
// No value. The T-bit (bit 0 of flags) is 0, meaning the sender had a TCB
// (transmission control block) — the normal case for the side that
// initiated shutdown.
func buildSHUTDOWNCompleteChunk() []byte {
	return buildChunk(ChunkSHUTDOWNComplete, 0, nil)
}
