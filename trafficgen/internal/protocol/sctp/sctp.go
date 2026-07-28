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
// Optional HEARTBEAT chunks (RFC 4960 §3.5.1) are emitted between
// COOKIE-ACK and the first DATA chunk, or — when the user supplies no
// DATA chunks — between COOKIE-ACK and SHUTDOWN. When Heartbeats.AltPath
// is set, heartbeats carry the alternate IP/MAC tuple (multi-homing,
// RFC 4960 §6/C5), giving the planner a sub-flow with a different 4-tuple
// but the same GroupID as the parent so both paths route to one
// PacketWorker (wire order = emit order).
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
	ChunkSACK              = 3
	ChunkHEARTBEAT         = 4
	ChunkHEARTBEATAck      = 5
	ChunkABORT             = 6
	ChunkSHUTDOWN          = 7
	ChunkSHUTDOWNAck       = 8
	ChunkERROR             = 9
	ChunkCOOKIEEcho        = 10
	ChunkCOOKIEAck         = 11
	ChunkSHUTDOWNComplete  = 14

	// Chunk flags.
	ChunkFlagBeginEnd = 0x03 // DATA chunk B+E (beginning+end of message)

	// ERROR Cause Code constants (RFC 4960 §3.3.10).
	ECInvalidStreamID       = 1
	ECMissingMandatoryParam = 2
	ECStaleCookieError      = 3
	ECOutOfResource         = 4
	ECUnresolvableAddress   = 5
	ECUnrecognizedChunkType = 6
	ECInvalidMandatoryParam = 7
	ECUnrecognizedParams    = 8
	ECNoUserData            = 9
)

// Planner implements the SCTP protocol planner.
type Planner struct{}

// NewPlanner creates a new SCTP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "sctp" }

// Validate validates an SCTP flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	parentSrcIsV6 := false
	if spec.SrcIP != "" {
		ip := net.ParseIP(spec.SrcIP)
		if ip == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
		parentSrcIsV6 = ip.To4() == nil
	}
	parentDstIsV6 := false
	if spec.DstIP != "" {
		ip := net.ParseIP(spec.DstIP)
		if ip == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
		parentDstIsV6 = ip.To4() == nil
	}
	// AltPath multi-homing addresses must be valid IPv4. buildIPv4AddrParam
	// only emits IPv4 Address params (RFC 4960 §3.3.2.1 type 5); an IPv6 or
	// garbage alt IP would silently produce no INIT param while HEARTBEATs
	// still originate from that address - a DPI sees two unrelated flows.
	// Reject here so the user sees the misconfiguration.
	//
	// Additionally, per RFC 4960 §6.4 multi-homing addresses must be in the
	// same address family as the primary path. An IPv4 AltPath on an IPv6
	// association (or vice versa) would emit IPv4 Address params inside an
	// IPv6 SCTP packet — semantically broken and invisible to DPI.
	if spec.SCTP != nil && spec.SCTP.Heartbeats != nil && spec.SCTP.Heartbeats.AltPath != nil {
		ap := spec.SCTP.Heartbeats.AltPath
		if ap.SrcIP != "" {
			ip := net.ParseIP(ap.SrcIP)
			if ip == nil {
				return fmt.Errorf("invalid AltPath.SrcIP: %s", ap.SrcIP)
			}
			if ip.To4() == nil {
				return fmt.Errorf("AltPath.SrcIP %s is IPv6; only IPv4 multi-homing is supported (RFC 4960 §3.3.2.1 type 5)", ap.SrcIP)
			}
			if parentSrcIsV6 {
				return fmt.Errorf("AltPath.SrcIP %s is IPv4 but parent SrcIP is IPv6; multi-homing requires same address family (RFC 4960 §6.4)", ap.SrcIP)
			}
		}
		if ap.DstIP != "" {
			ip := net.ParseIP(ap.DstIP)
			if ip == nil {
				return fmt.Errorf("invalid AltPath.DstIP: %s", ap.DstIP)
			}
			if ip.To4() == nil {
				return fmt.Errorf("AltPath.DstIP %s is IPv6; only IPv4 multi-homing is supported (RFC 4960 §3.3.2.1 type 5)", ap.DstIP)
			}
			if parentDstIsV6 {
				return fmt.Errorf("AltPath.DstIP %s is IPv4 but parent DstIP is IPv6; multi-homing requires same address family (RFC 4960 §6.4)", ap.DstIP)
			}
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
		// When AltPath is set, INIT carries an IPv4 Address parameter (type 5)
		// declaring the client's alternate local address (AltPath.SrcIP) per
		// RFC 4960 §3.3.2 — without it, a DPI can't associate the alt-path
		// HEARTBEAT with this association. INIT carries only the SENDER's
		// (client's) local addresses; the server's alt address goes in INIT-ACK.
		var clientAltIPs, serverAltIPs []string
		if sctpConfig.Heartbeats != nil && sctpConfig.Heartbeats.AltPath != nil {
			if sctpConfig.Heartbeats.AltPath.SrcIP != "" {
				clientAltIPs = append(clientAltIPs, sctpConfig.Heartbeats.AltPath.SrcIP)
			}
			if sctpConfig.Heartbeats.AltPath.DstIP != "" {
				serverAltIPs = append(serverAltIPs, sctpConfig.Heartbeats.AltPath.DstIP)
			}
		}
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, 0,
			buildINITChunk(clientVerTag, clientTSN, clientAltIPs))

		// INIT-ACK (server -> client, VerificationTag=client's tag from INIT).
		// Carries the server's InitiateTag, aRwnd, OS, MIS, initial TSN,
		// and a Cookie that the client echoes back unchanged. Also carries
		// an IPv4 Address parameter declaring the server's alternate local
		// address (AltPath.DstIP) per RFC 4960 §3.3.2.
		cookie := make([]byte, 32) // arbitrary cookie; just needs to be non-empty
		rand.Read(cookie)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, clientVerTag,
			buildINITAckChunk(serverVerTag, serverTSN, cookie, serverAltIPs))

		// COOKIE-ECHO (client -> server, VerificationTag=server's tag from INIT-ACK).
		// Echoes the Cookie from INIT-ACK.
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, serverVerTag,
			buildCOOKIEEchoChunk(cookie))

		// COOKIE-ACK (server -> client, VerificationTag=client's tag).
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, clientVerTag,
			buildCOOKIEAckChunk())

			// --- Optional HEARTBEAT chunks (RFC 4960 §3.5.1) ---
		// Emitted between COOKIE-ACK and the first DATA chunk (or before
		// SHUTDOWN when there are no DATA chunks). Each pair is a
		// HEARTBEAT (client → server) + HEARTBEAT-ACK (server → client).
		// When AltPath is set, heartbeats carry the alternate 4-tuple
		// (multi-homing); otherwise they ride the primary path.
		if sctpConfig.Heartbeats != nil {
			emitSCTPHeartbeats(configChan, sctpConfig.Heartbeats,
				spec, flowID, now, &packetIndex, nextIPID,
				clientVerTag, serverVerTag, effectiveTTL)
		}

		// --- DATA chunks ---
		for _, ch := range sctpConfig.Chunks {
			direction := ch.Direction
			if direction == "" {
				direction = "up"
			}
			if direction != "up" && direction != "down" {
				continue
			}
			// Resolve the DATA chunk payload bytes per the FileSource
			// precedence contract (mirrors FTP Task 11):
			//  1. ch.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *ch.FileSource)
			//  2. else ch.Data (inline)
			//
			// SCTPChunk has no PayloadB64 field — only inline Data.
			//
			// When FileSource is set but no cache is injected, skip this
			// chunk (do NOT fall through to inline Data). Falling through
			// would violate the FileSource > inline precedence contract.
			// Production engine (Task 13) always injects the cache.
			dataBytes, skipChunk := resolveSCTPChunkData(ctx, ch)
			if skipChunk {
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
				dataChunk := buildDATAChunk(tsn, ch.SID, ch.SSN, ch.PPID, dataBytes)
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
				dataChunk := buildDATAChunk(tsn, ch.SID, ch.SSN, ch.PPID, dataBytes)
				emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
					spec.DstPort, spec.SrcPort, clientVerTag, dataChunk)
			}
		}

		// --- SCTP teardown: 3-way SHUTDOWN or abrupt ABORT ---
		//
		// Default path is the 3-way SHUTDOWN/SHUTDOWN-ACK/SHUTDOWN-COMPLETE
		// handshake (graceful close, RFC 4960 §9.2). When SCTPConfig.Abort
		// is true, the planner instead emits a single ABORT chunk
		// (RFC 4960 §9.1) — the abrupt-close path used for fault-injection
		// scenarios where the side tears the association down without
		// negotiating TSN exchange. ABORT replaces the 3-way shutdown
		// entirely; we do NOT emit SHUTDOWN first and then ABORT.
		if sctpConfig.Abort {
			// ABORT (client -> server). No Cause fields — the minimal
			// 4-byte ABORT chunk. VerificationTag is the server's tag
			// per RFC 4960 §8.5.1 (ABORT must use the peer's last-seen
			// verification tag, mirroring the DATA chunk's tag pattern).
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
				spec.SrcPort, spec.DstPort, serverVerTag,
				buildABORTChunk())
		} else {
			// SHUTDOWN (client -> server). Carries the highest cumulative
			// TSN ack the client has received. For test purposes, we
			// send the latest serverTSN-1 (the last TSN the server would
			// have sent).
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
		}
	}()

	return configChan, nil
}

// resolveSCTPChunkData resolves a DATA chunk's payload bytes per the
// FileSource precedence contract (mirrors FTP Task 11):
//
//  1. ch.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *ch.FileSource)
//  2. else ch.Data (inline)
//
// SCTPChunk has no PayloadB64 field — only inline Data. If a future
// enhancement adds PayloadB64, insert it as step 2 and demote Data to
// step 3.
//
// When FileSource is set but no cache is injected (e.g. a unit test that
// forgot core.WithPayloadCache, or a controller path that doesn't wire the
// cache yet), the function returns skipChunk=true so the caller skips
// emitting this chunk (matching FTP's "return without emitting" behavior
// on the same precedence-violation condition). Falling through to inline
// Data would silently violate the FileSource > inline precedence contract.
// Production engine (Task 13) always injects the cache.
//
// Returns (bytes, skip). When skip is true, bytes is nil.
func resolveSCTPChunkData(ctx context.Context, ch core.SCTPChunk) ([]byte, bool) {
	if ch.FileSource == nil {
		return ch.Data, false
	}
	pc := core.PayloadCacheFrom(ctx)
	if pc == nil {
		return nil, true
	}
	bytes, _ := pc.GetOrLoad(ctx, *ch.FileSource)
	return bytes, false
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
// bytes of fixed fields, followed by optional params.
//
// When altIPs is non-empty, the planner appends one IPv4 Address parameter
// (type 5) per address per RFC 4960 §3.3.2 / §C.2. This declares the
// multi-homing addresses the peer should use for HEARTBEATs — without it,
// a pcap showing an INIT without address params followed by a HEARTBEAT
// from an unannounced IP looks like two unrelated flows to a DPI.
func buildINITChunk(initiateTag, initialTSN uint32, altIPs []string) []byte {
	value := make([]byte, 16)
	binary.BigEndian.PutUint32(value[0:4], initiateTag)
	binary.BigEndian.PutUint32(value[4:8], 65535) // aRwnd
	binary.BigEndian.PutUint16(value[8:10], 10)   // OS (outbound streams)
	binary.BigEndian.PutUint16(value[10:12], 10)  // MIS (inbound streams)
	binary.BigEndian.PutUint32(value[12:16], initialTSN)
	for _, ip := range altIPs {
		value = append(value, buildIPv4AddrParam(ip)...)
	}
	return buildChunk(ChunkINIT, 0, value)
}

// buildINITAckChunk builds an INIT-ACK chunk (type 2). Same fixed layout as
// INIT, followed by a State Cookie parameter (type 7) and optional IPv4
// Address parameters (type 5) for multi-homing per RFC 4960 §3.3.2 / §C.2.
// altIPs declares the server's multi-homing addresses; the cookie is what
// the client echoes in COOKIE-ECHO.
func buildINITAckChunk(initiateTag, initialTSN uint32, cookie []byte, altIPs []string) []byte {
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
	for _, ip := range altIPs {
		value = append(value, buildIPv4AddrParam(ip)...)
	}
	return buildChunk(ChunkINITAck, 0, value)
}

// buildIPv4AddrParam builds an IPv4 Address parameter (type 5) per RFC 4960
// §3.3.2.1. Layout: Type(2) + Length(2) + IPv4(4) = 8 bytes total. Length=8
// (includes Type+Length). No reserved field. Returns nil if ip is not a
// valid IPv4 address - caller should Validate alt-path IPs to surface this.
func buildIPv4AddrParam(ip string) []byte {
	ipBytes := net.ParseIP(ip).To4()
	if ipBytes == nil {
		return nil
	}
	p := make([]byte, 8)
	binary.BigEndian.PutUint16(p[0:2], 5) // Parameter Type: IPv4 Address
	binary.BigEndian.PutUint16(p[2:4], 8) // Length (includes Type+Length)
	copy(p[4:8], ipBytes)
	return p
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

// buildABORTChunk builds an ABORT chunk (type 6) per RFC 4960 §6.4 and
// §9.1. Used for the abrupt-close path (fault-injection scenarios where
// the side tears the association down without negotiating TSN exchange).
//
// Layout: Type(1)=6 + Flags(1) + Length(2)=4 + (optional Cause fields).
// We emit a minimal ABORT with no Cause — the chunk is exactly 4 bytes.
// The T-bit (bit 0 of flags) is left 0, which per RFC 4960 §6.4 means
// "the sender had a TCB" (normal ABORT on a known association). T=1
// ("TCB was discarded") is reserved for scenarios where the sender
// never had state — e.g. an ABORT sent in response to a packet that
// doesn't match any existing association — and is NOT what we emit
// here. For tests/fault-injection T=0 is the conventional shape.
func buildABORTChunk() []byte {
	return buildChunk(ChunkABORT, 0, nil)
}

// buildHEARTBEATChunk builds a HEARTBEAT chunk (type 4) per RFC 4960
// §3.5.1. The value is the Heartbeat Information TLV (type 1) carrying
// a sender-defined opaque token (typically the sender's IP + timestamp).
// We use a 16-byte token (4-byte magic + 12-byte filler) so a peer
// (or DPI) can identify the chunk shape.
func buildHEARTBEATChunk(info []byte) []byte {
	value := make([]byte, 4+len(info))
	binary.BigEndian.PutUint16(value[0:2], 1)                   // HB-Info param type
	binary.BigEndian.PutUint16(value[2:4], uint16(4+len(info))) // length
	copy(value[4:], info)
	return buildChunk(ChunkHEARTBEAT, 0, value)
}

// buildHEARTBEATAckChunk builds a HEARTBEAT-ACK chunk (type 5). The value
// echoes the Heartbeat Information TLV from the corresponding HEARTBEAT
// per RFC 4960 §3.5.2.
func buildHEARTBEATAckChunk(info []byte) []byte {
	value := make([]byte, 4+len(info))
	binary.BigEndian.PutUint16(value[0:2], 1)
	binary.BigEndian.PutUint16(value[2:4], uint16(4+len(info)))
	copy(value[4:], info)
	return buildChunk(ChunkHEARTBEATAck, 0, value)
}

// buildSACKChunk builds a SACK (Selective ACK) chunk (type 3) per RFC 4960
// §3.3.4. Value layout:
//
//	Cumulative TSN Ack(4) + a_rwnd(4) + Num Gap Ack Blocks(2) +
//	Num Duplicate TSNs(2) + [Gap Ack Block(4) × N] + [Duplicate TSN(4) × M]
//
// When gapBlocks and dupTSNs are nil/empty, the chunk carries a bare
// acknowledgment with no gap blocks and no duplicates — the minimal SACK.
func buildSACKChunk(cumTSNAck, aRwnd uint32, gapBlocks []struct{ Start, End uint16 }, dupTSNs []uint32) []byte {
	nGap := len(gapBlocks)
	nDup := len(dupTSNs)
	value := make([]byte, 12+nGap*4+nDup*4)
	binary.BigEndian.PutUint32(value[0:4], cumTSNAck)
	binary.BigEndian.PutUint32(value[4:8], aRwnd)
	binary.BigEndian.PutUint16(value[8:10], uint16(nGap))
	binary.BigEndian.PutUint16(value[10:12], uint16(nDup))
	off := 12
	for _, g := range gapBlocks {
		binary.BigEndian.PutUint16(value[off:off+2], g.Start)
		binary.BigEndian.PutUint16(value[off+2:off+4], g.End)
		off += 4
	}
	for _, d := range dupTSNs {
		binary.BigEndian.PutUint32(value[off:off+4], d)
		off += 4
	}
	return buildChunk(ChunkSACK, 0, value)
}

// buildERRORChunk builds an ERROR chunk (type 9) per RFC 4960 §3.3.10.
// Value is one or more Error Cause TLV entries. Each Error Cause has:
//
//	Cause Code(2) + Cause Length(2) + Cause-Specific Info(variable)
//
// When causes is nil/empty, the chunk carries a single "No User Data"
// cause (code 9) as the default — the minimal ERROR a sender can emit
// to signal a generic protocol error.
func buildERRORChunk(causes []struct {
	Code uint16
	Info []byte
}) []byte {
	if len(causes) == 0 {
		// Default: "No User Data" cause (code 9), 4 bytes total (no info).
		value := make([]byte, 4)
		binary.BigEndian.PutUint16(value[0:2], 9) // Cause Code: No User Data
		binary.BigEndian.PutUint16(value[2:4], 4) // Length (includes Type+Length)
		return buildChunk(ChunkERROR, 0, value)
	}
	totalLen := 0
	for _, c := range causes {
		totalLen += 4 + len(c.Info) // 4-byte header + info
	}
	value := make([]byte, totalLen)
	off := 0
	for _, c := range causes {
		clen := uint16(4 + len(c.Info))
		binary.BigEndian.PutUint16(value[off:off+2], c.Code)
		binary.BigEndian.PutUint16(value[off+2:off+4], clen)
		copy(value[off+4:], c.Info)
		off += int(clen)
	}
	return buildChunk(ChunkERROR, 0, value)
}

// emitSCTPHeartbeats emits Count heartbeat pairs between COOKIE-ACK and
// the first DATA chunk. Each pair is HEARTBEAT (up) + HEARTBEAT-ACK (down).
// When AltPath is set, heartbeats use the alternate IP/MAC tuple (multi-
// homing) and the FlowID carries the ":hb" suffix so the sub-flow is
// distinguishable from the primary path; the GroupID is inherited from
// the parent so both paths route to one PacketWorker.
func emitSCTPHeartbeats(
	configChan chan<- core.PacketConfig,
	hb *core.SCTPHeartbeatConfig,
	spec core.FlowSpec,
	parentFlowID string,
	now time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	clientVerTag, serverVerTag uint32,
	effectiveTTL uint8,
) {
	count := hb.Count
	if count <= 0 {
		count = 1
	}

	// Resolve alternate path addresses (multi-homing). When AltPath is
	// nil or a field is empty, fall back to the parent's value so the
	// heartbeat still goes somewhere.
	srcIP := spec.SrcIP
	dstIP := spec.DstIP
	srcMAC := spec.SrcMAC
	dstMAC := spec.DstMAC
	flowID := parentFlowID
	if hb.AltPath != nil {
		if hb.AltPath.SrcIP != "" {
			srcIP = hb.AltPath.SrcIP
		}
		if hb.AltPath.DstIP != "" {
			dstIP = hb.AltPath.DstIP
		}
		if hb.AltPath.SrcMAC != "" {
			srcMAC = hb.AltPath.SrcMAC
		}
		if hb.AltPath.DstMAC != "" {
			dstMAC = hb.AltPath.DstMAC
		}
		flowID = parentFlowID + ":hb"
	}

	emitHB := func(direction, sMAC, dMAC, sIP, dIP string, srcPort, dstPort uint16, verTag uint32, payload []byte) {
		l3 := core.L3Base(sIP, dIP, core.ProtocolSCTP, effectiveTTL, nextIPID(), spec)
		cfg := core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: *packetIndex,
			Direction:   direction,
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    sMAC,
				DstMAC:    dMAC,
				EtherType: core.EtherTypeFor(sIP),
			},
			L3: l3,
			L4: core.L4Config{
				Protocol: "sctp",
				SrcPort:  srcPort,
				DstPort:  dstPort,
				Ack:      verTag,
			},
			Payload: payload,
		}
		configChan <- cfg
		*packetIndex++
	}

	for i := 0; i < count; i++ {
		// Per-iteration Heartbeat Info token: 4-byte magic + 4-byte counter
		// + 8-byte random nonce = 16 bytes. Lets DPI identify the heartbeat
		// shape and lets tests assert uniqueness across iterations.
		info := make([]byte, 16)
		binary.BigEndian.PutUint32(info[0:4], 0x48425443) // "HBTC"
		binary.BigEndian.PutUint32(info[4:8], uint32(i))
		rand.Read(info[8:16])

		// HEARTBEAT (client -> server, VerificationTag = serverVerTag).
		emitHB("up", srcMAC, dstMAC, srcIP, dstIP, spec.SrcPort, spec.DstPort, serverVerTag,
			buildHEARTBEATChunk(info))
		// HEARTBEAT-ACK (server -> client, VerificationTag = clientVerTag).
		// Per RFC 4960 §3.5.2, the ack echoes the Heartbeat Info unchanged.
		// Swap ports so the server's source port is spec.DstPort (echoing the
		// client's destination), matching INIT-ACK's port-swap pattern.
		emitHB("down", dstMAC, srcMAC, dstIP, srcIP, spec.DstPort, spec.SrcPort, clientVerTag,
			buildHEARTBEATAckChunk(info))
	}
}
