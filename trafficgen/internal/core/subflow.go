// Package core provides core functionality.
package core

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// EmitSubFlow emits packets for a single sub-flow into configChan. It is the
// generic entry point used by any planner that supports sub-flows (FTP data
// channel, SIP RTP media, SCTP multi-homing) — the planner calls this with
// the parent's FlowSpec, parent flow ID, and the sub-flow spec.
//
// Wire order is emit order: the planner emits the parent's signaling packets
// (which negotiate the sub-flow, e.g. FTP PASV response), then calls
// EmitSubFlow for the data plane, then continues with the parent's signaling
// (e.g. FTP "226 Transfer complete"). Because the planner is a single
// goroutine writing to one configChan, the wire order matches.
//
// The sub-flow's FlowID is "{parentFlowID}:sub-{subIdx}" so receivers can
// distinguish primary vs. secondary packets. The GroupID is inherited from
// the parent (callers must set it on every emitted PacketConfig — see the
// worker's computeHashKey, which uses GroupID to route same-GroupID packets
// to one PacketWorker, preserving cross-flow timing).
//
// Parameters:
//   - configChan: the parent planner's output channel (EmitSubFlow writes
//     into it directly — no intermediate channel).
//   - subIdx: 0-based index into spec.SubFlows (used for FlowID suffix).
//   - sub: the SubFlowSpec describing the data flow.
//   - parent: the parent FlowSpec (for SrcIP/DstIP/MACs/TTL/DSCP inheritance).
//   - parentFlowID: the parent's FlowID (for FlowID suffixing).
//   - now: the timestamp to stamp on every emitted packet.
//   - packetIndex: pointer to the parent's packet counter (EmitSubFlow
//     increments it for each packet emitted, so the parent's numbering
//     stays continuous).
//   - nextIPID: the parent's IPID generator (so the sub-flow's IPIDs don't
//     collide with the parent's).
//
// EmitSubFlow does NOT close configChan — the parent planner owns the
// channel lifecycle.
func EmitSubFlow(
	configChan chan<- PacketConfig,
	subIdx int,
	sub SubFlowSpec,
	parent FlowSpec,
	parentFlowID string,
	now time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
) {
	subFlowID := fmt.Sprintf("%s:sub-%d", parentFlowID, subIdx)

	// Resolve effective 4-tuple: sub-flow can override IPs/MACs (multi-homing),
	// ports, and direction. Empty -> inherit parent.
	srcIP := parent.SrcIP
	dstIP := parent.DstIP
	srcMAC := parent.SrcMAC
	dstMAC := parent.DstMAC
	if sub.AltSrcIP != "" {
		srcIP = sub.AltSrcIP
	}
	if sub.AltDstIP != "" {
		dstIP = sub.AltDstIP
	}
	if sub.AltSrcMAC != "" {
		srcMAC = sub.AltSrcMAC
	}
	if sub.AltDstMAC != "" {
		dstMAC = sub.AltDstMAC
	}

	// Resolve payload (PayloadB64 overrides Payload, matching HTTP behavior).
	var payload []byte
	if b64 := sub.PayloadB64; b64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
			payload = decoded
		}
	}
	if len(payload) == 0 && sub.Payload != "" {
		payload = []byte(sub.Payload)
	}

	// Effective TTL and DSCP inherit from parent.
	effectiveTTL := parent.TTL
	if effectiveTTL == 0 {
		effectiveTTL = DefaultTTL
	}

	// Build a synthetic FlowSpec for the sub-flow so L3Base / EtherTypeFor
	// pick up the (possibly alternate) IPs and parent's DSCP/ECN/Flags.
	subSpec := FlowSpec{
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcMAC:      srcMAC,
		DstMAC:      dstMAC,
		TTL:         effectiveTTL,
		DSCP:        parent.DSCP,
		ECN:         parent.ECN,
		IPFlags:     parent.IPFlags,
		FragOffset:  parent.FragOffset,
		HopByHop:    parent.HopByHop,
		PadMinFrame: parent.PadMinFrame,
		VLAN:        parent.VLAN,
	}

	// Direction: which side's payload bytes flow. "up" = client→server
	// (client opens); "down" = server→client (server opens, e.g. FTP active
	// mode). ServerInitiated controls who sends SYN — see emitTCPSubFlow.
	dir := sub.Direction
	if dir == "" {
		dir = "up"
	}

	// Pre-write Metadata["group_id"] for downstream consumers (parsers,
	// replays, custom harnesses) that read PacketConfig before the engine's
	// worker stamps the authoritative value. The worker's computeHashKey
	// (worker.go:325) overwrites this with the flowIdx-resolved gID, so
	// routing is unaffected by what we write here.
	//
	// LIMITATION: the pre-write evaluates the strategy at flowIdx=0 because
	// the planner does not know the per-flow index at emit time (the worker
	// drives the loop and computes flowIdx outside the planner). For
	// "fixed"/"list" strategies this is correct (index-invariant). For
	// "inc"/"pattern"/"rand" strategies with flow_count > 1, the pre-write
	// value diverges from the worker's authoritative value (e.g. inc range
	// [1,10]: pre-write always "1", worker emits "1".."10"). Downstream
	// consumers that need the authoritative group_id must read it AFTER the
	// worker stamp, not from the pre-write. See TestEmitSubFlow_GroupIDIncStrategy_Limitation
	// which demonstrates the divergence.
	gID := resolveSubFlowGroupID(sub.GroupID, parent.GroupID)

	switch sub.Protocol {
	case "tcp":
		emitTCPSubFlow(configChan, sub, subSpec, subFlowID, now, packetIndex, nextIPID, payload, dir, gID)
	case "udp":
		emitUDPSubFlow(configChan, sub, subSpec, subFlowID, now, packetIndex, nextIPID, payload, dir, gID)
	case "sctp":
		emitSCTPSubFlow(configChan, sub, subSpec, subFlowID, now, packetIndex, nextIPID, payload, dir, gID)
	}
}

// resolveSubFlowGroupID evaluates the sub-flow's group_id per the
// priority documented on EmitSubFlow. Returns "" when both sub.GroupID and
// parent.GroupID are nil (worker falls back to 4-tuple hash in that case).
func resolveSubFlowGroupID(subGID, parentGID *StrategyConfig) string {
	if g := FlowGroupIDValue(subGID, 0); g != "" {
		return g
	}
	if g := FlowGroupIDValue(parentGID, 0); g != "" {
		return g
	}
	return ""
}

// emitTCPSubFlow emits a full TCP sub-flow: 3-way handshake (if Handshake),
// MSS-segmented payload in the requested direction with peer ACKs, then
// 4-way teardown (if Termination).
//
// Sequence space is independent from the parent flow — real TCP sub-flows
// (e.g. FTP data channel) are separate connections with their own ISN.
//
// ServerInitiated controls who sends SYN. When true (FTP active mode), the
// server opens the connection — SYN goes server→client with SrcPort=sub.DstPort
// (server's port, e.g. 20). When false (FTP passive, SIP RTP), the client
// opens — SYN goes client→server with SrcPort=sub.SrcPort.
//
// Direction controls which way the PAYLOAD flows: "up"=client→server (STOR
// upload), "down"=server→client (RETR download). Direction is orthogonal to
// ServerInitiated: an active-mode RETR has the server open the connection
// AND send file bytes (server→client); a passive-mode RETR has the client
// open but the server still sends.
func emitTCPSubFlow(
	configChan chan<- PacketConfig,
	sub SubFlowSpec,
	spec FlowSpec,
	flowID string,
	now time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	payload []byte,
	dir string,
	gID string,
) {
	mss := uint16(sub.MSS)
	if mss == 0 {
		mss = 1460
	}

	clientSeq := rand.Uint32()
	serverSeq := rand.Uint32()
	winSize := uint16(65535)

	// Port pair: SrcPort=client's port, DstPort=server's port (always,
	// regardless of who opens the connection).
	clientPort := sub.SrcPort
	serverPort := sub.DstPort

	// Pre-allocate Metadata so each emitPacket can write gID without
	// re-allocating. Only allocated when gID is non-empty (skips the
	// map alloc on the common 4-tuple-hash fallback path).
	var meta map[string]interface{}
	if gID != "" {
		meta = map[string]interface{}{"group_id": gID}
	}

	// emitPacket builds and sends one TCP packet in the given direction.
	// "up" = client→server (SrcMAC=spec.SrcMAC, ports client→server);
	// "down" = server→client (swapped).
	emitPacket := func(direction string, seq, ack uint32, flags uint8, pay []byte) {
		var srcMAC, dstMAC, srcIP, dstIP string
		var srcPort, dstPort uint16
		if direction == "down" {
			srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
			srcIP, dstIP = spec.DstIP, spec.SrcIP
			srcPort, dstPort = serverPort, clientPort
		} else {
			srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
			srcIP, dstIP = spec.SrcIP, spec.DstIP
			srcPort, dstPort = clientPort, serverPort
		}
		l4 := L4Config{
			Protocol:   "tcp",
			SrcPort:    srcPort,
			DstPort:    dstPort,
			Seq:        seq,
			Ack:        ack,
			Flags:      flags,
			WindowSize: winSize,
		}
		if flags == 0x02 || flags == 0x12 {
			l4.TCPOptions = synMSSOptions(mss)
		}
		var pktMeta map[string]interface{}
		if meta != nil {
			// Copy so each emitted PacketConfig has its own Metadata
			// (the engine may mutate it downstream).
			pktMeta = make(map[string]interface{}, len(meta))
			for k, v := range meta {
				pktMeta[k] = v
			}
		}
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: direction, Timestamp: now,
			L2:      L2Config{SrcMAC: srcMAC, DstMAC: dstMAC, EtherType: EtherTypeFor(srcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:      L3Base(srcIP, dstIP, 6, spec.TTL, nextIPID(), spec),
			L4:      l4,
			Payload: pay,
			Metadata: pktMeta,
		}
		*packetIndex++
	}

	// 3-way handshake. The initiator sends SYN first.
	if sub.Handshake {
		if sub.ServerInitiated {
			// SYN (server -> client)
			emitPacket("down", serverSeq, 0, 0x02, nil)
			serverSeq++
			// SYN-ACK (client -> server)
			emitPacket("up", clientSeq, serverSeq, 0x12, nil)
			clientSeq++
			// ACK (server -> client)
			emitPacket("down", serverSeq, clientSeq, 0x10, nil)
		} else {
			// SYN (client -> server)
			emitPacket("up", clientSeq, 0, 0x02, nil)
			clientSeq++
			// SYN-ACK (server -> client)
			emitPacket("down", serverSeq, clientSeq, 0x12, nil)
			serverSeq++
			// ACK (client -> server)
			emitPacket("up", clientSeq, serverSeq, 0x10, nil)
		}
	}

	// Data segments in the requested direction. "up" = client sends; "down"
	// = server sends (e.g. FTP RETR download — server pushes file bytes).
	for len(payload) > 0 {
		segSize := len(payload)
		if segSize > int(mss) {
			segSize = int(mss)
		}

		if dir == "down" {
			// server -> client PSH|ACK
			emitPacket("down", serverSeq, clientSeq, 0x18, payload[:segSize])
			serverSeq += uint32(segSize)
			// client -> server ACK
			emitPacket("up", clientSeq, serverSeq, 0x10, nil)
		} else {
			// client -> server PSH|ACK
			emitPacket("up", clientSeq, serverSeq, 0x18, payload[:segSize])
			clientSeq += uint32(segSize)
			// server -> client ACK
			emitPacket("down", serverSeq, clientSeq, 0x10, nil)
		}
		payload = payload[segSize:]
	}

	// 4-way teardown.
	if sub.Termination {
		// FIN (client -> server)
		emitPacket("up", clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		// ACK (server -> client)
		emitPacket("down", serverSeq, clientSeq, 0x10, nil)
		// FIN (server -> client)
		emitPacket("down", serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		// ACK (client -> server)
		emitPacket("up", clientSeq, serverSeq, 0x10, nil)
	}
}

// emitUDPSubFlow emits a single UDP packet carrying payload in the requested
// direction. UDP has no handshake or teardown — the sub-flow is one datagram.
// (For RTP-style multi-frame sub-flows, the planner splits the payload into
// N frames before calling EmitSubFlow, or we can add a FrameCount field
// later. For now, one datagram per sub-flow matches the FTP/RTP-as-one-burst
// pattern; SIP RTP support will follow with a Frames field on SubFlowSpec
// when needed.)
func emitUDPSubFlow(
	configChan chan<- PacketConfig,
	sub SubFlowSpec,
	spec FlowSpec,
	flowID string,
	now time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	payload []byte,
	dir string,
	gID string,
) {
	var meta map[string]interface{}
	if gID != "" {
		meta = map[string]interface{}{"group_id": gID}
	}
	if dir == "down" {
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: "down", Timestamp: now,
			L2:      L2Config{SrcMAC: spec.DstMAC, DstMAC: spec.SrcMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:      L3Base(spec.DstIP, spec.SrcIP, 17, spec.TTL, nextIPID(), spec),
			L4:      L4Config{Protocol: "udp", SrcPort: sub.DstPort, DstPort: sub.SrcPort},
			Payload: payload,
			Metadata: meta,
		}
	} else {
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: "up", Timestamp: now,
			L2:      L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:      L3Base(spec.SrcIP, spec.DstIP, 17, spec.TTL, nextIPID(), spec),
			L4:      L4Config{Protocol: "udp", SrcPort: sub.SrcPort, DstPort: sub.DstPort},
			Payload: payload,
			Metadata: meta,
		}
	}
	*packetIndex++
}

// emitSCTPSubFlow emits a minimal SCTP sub-flow: INIT/INIT-ACK/COOKIE-ECHO/
// COOKIE-ACK handshake (if Handshake), one DATA chunk carrying payload, then
// SHUTDOWN/SHUTDOWN-ACK/SHUTDOWN-COMPLETE teardown (if Termination).
//
// SCTP sub-flows share the parent's Verification Tag space — real SCTP
// multi-homing uses ONE association across multiple paths, not separate
// associations. So this helper writes HEARTBEAT chunks (not a full
// association) on alternate paths. For a full SCTP sub-flow (rare in
// practice), we still emit the 4-way handshake with new tags.
func emitSCTPSubFlow(
	configChan chan<- PacketConfig,
	sub SubFlowSpec,
	spec FlowSpec,
	flowID string,
	now time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	payload []byte,
	dir string,
	gID string,
) {
	clientTag := rand.Uint32()
	serverTag := rand.Uint32()
	clientTSN := rand.Uint32()
	serverTSN := clientTSN + 1

	// Pre-build the Metadata template. Only allocated when gID is non-empty
	// (skips the map alloc on the 4-tuple-hash fallback path). Each emitted
	// PacketConfig gets its OWN copy so downstream mutations don't bleed
	// between packets.
	var metaTemplate map[string]interface{}
	if gID != "" {
		metaTemplate = map[string]interface{}{"group_id": gID}
	}
	metaFor := func() map[string]interface{} {
		if metaTemplate == nil {
			return nil
		}
		m := make(map[string]interface{}, len(metaTemplate))
		for k, v := range metaTemplate {
			m[k] = v
		}
		return m
	}

	// 4-way handshake.
	if sub.Handshake {
		// INIT (client -> server, Verificationtag=0)
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: "up", Timestamp: now,
			L2:       L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:       L3Base(spec.SrcIP, spec.DstIP, 132, spec.TTL, nextIPID(), spec),
			L4:       L4Config{Protocol: "sctp", SrcPort: sub.SrcPort, DstPort: sub.DstPort, Ack: 0},
			Payload:  buildSCTPINITChunk(clientTag),
			Metadata: metaFor(),
		}
		*packetIndex++

		// INIT-ACK (server -> client)
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: "down", Timestamp: now,
			L2:       L2Config{SrcMAC: spec.DstMAC, DstMAC: spec.SrcMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:       L3Base(spec.DstIP, spec.SrcIP, 132, spec.TTL, nextIPID(), spec),
			L4:       L4Config{Protocol: "sctp", SrcPort: sub.DstPort, DstPort: sub.SrcPort, Ack: clientTag},
			Payload:  buildSCTPINITChunk(serverTag),
			Metadata: metaFor(),
		}
		*packetIndex++

		// COOKIE-ECHO (client -> server)
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: "up", Timestamp: now,
			L2:       L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:       L3Base(spec.SrcIP, spec.DstIP, 132, spec.TTL, nextIPID(), spec),
			L4:       L4Config{Protocol: "sctp", SrcPort: sub.SrcPort, DstPort: sub.DstPort, Ack: serverTag},
			Payload:  buildSCTPCookieEchoChunk(),
			Metadata: metaFor(),
		}
		*packetIndex++

		// COOKIE-ACK (server -> client)
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: "down", Timestamp: now,
			L2:       L2Config{SrcMAC: spec.DstMAC, DstMAC: spec.SrcMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:       L3Base(spec.DstIP, spec.SrcIP, 132, spec.TTL, nextIPID(), spec),
			L4:       L4Config{Protocol: "sctp", SrcPort: sub.DstPort, DstPort: sub.SrcPort, Ack: clientTag},
			Payload:  buildSCTPCookieAckChunk(),
			Metadata: metaFor(),
		}
		*packetIndex++
	}

	// DATA chunk.
	if len(payload) > 0 {
		if dir == "down" {
			configChan <- PacketConfig{
				FlowID: flowID, PacketIndex: *packetIndex, Direction: "down", Timestamp: now,
				L2:       L2Config{SrcMAC: spec.DstMAC, DstMAC: spec.SrcMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
				L3:       L3Base(spec.DstIP, spec.SrcIP, 132, spec.TTL, nextIPID(), spec),
				L4:       L4Config{Protocol: "sctp", SrcPort: sub.DstPort, DstPort: sub.SrcPort, Ack: clientTag},
				Payload:  buildSCTPDATAChunk(serverTSN, payload),
				Metadata: metaFor(),
			}
		} else {
			configChan <- PacketConfig{
				FlowID: flowID, PacketIndex: *packetIndex, Direction: "up", Timestamp: now,
				L2:       L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
				L3:       L3Base(spec.SrcIP, spec.DstIP, 132, spec.TTL, nextIPID(), spec),
				L4:       L4Config{Protocol: "sctp", SrcPort: sub.SrcPort, DstPort: sub.DstPort, Ack: serverTag},
				Payload:  buildSCTPDATAChunk(clientTSN, payload),
				Metadata: metaFor(),
			}
		}
		*packetIndex++
	}

	// 3-way shutdown.
	if sub.Termination {
		// SHUTDOWN (client -> server)
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: "up", Timestamp: now,
			L2:       L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:       L3Base(spec.SrcIP, spec.DstIP, 132, spec.TTL, nextIPID(), spec),
			L4:       L4Config{Protocol: "sctp", SrcPort: sub.SrcPort, DstPort: sub.DstPort, Ack: serverTag},
			Payload:  buildSCTPShutdownChunk(clientTSN),
			Metadata: metaFor(),
		}
		*packetIndex++

		// SHUTDOWN-ACK (server -> client)
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: "down", Timestamp: now,
			L2:       L2Config{SrcMAC: spec.DstMAC, DstMAC: spec.SrcMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:       L3Base(spec.DstIP, spec.SrcIP, 132, spec.TTL, nextIPID(), spec),
			L4:       L4Config{Protocol: "sctp", SrcPort: sub.DstPort, DstPort: sub.SrcPort, Ack: clientTag},
			Payload:  buildSCTPShutdownAckChunk(),
			Metadata: metaFor(),
		}
		*packetIndex++

		// SHUTDOWN-COMPLETE (client -> server)
		configChan <- PacketConfig{
			FlowID: flowID, PacketIndex: *packetIndex, Direction: "up", Timestamp: now,
			L2:       L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: EtherTypeFor(spec.SrcIP), VLAN: spec.VLAN, Pad: spec.PadMinFrame},
			L3:       L3Base(spec.SrcIP, spec.DstIP, 132, spec.TTL, nextIPID(), spec),
			L4:       L4Config{Protocol: "sctp", SrcPort: sub.SrcPort, DstPort: sub.DstPort, Ack: serverTag},
			Payload:  buildSCTPShutdownCompleteChunk(),
			Metadata: metaFor(),
		}
		*packetIndex++
	}
}

// synMSSOptions builds TCP options for SYN packets: MSS + Window Scale +
// SACK-Permitted. Kept here so the subflow helper doesn't depend on the tcp
// planner package (which would create an import cycle).
func synMSSOptions(mss uint16) []TCPOption {
	if mss == 0 {
		mss = 1460
	}
	return []TCPOption{
		{Kind: TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}},
		{Kind: TCPOptWinScale, Data: []byte{0x07}},
		{Kind: TCPOptSACKPermit},
	}
}

// SCTP chunk builders. Layout per RFC 4960 §3.2:
//   Type(1) + Flags(1) + Length(2) + value(padded to 4-byte boundary)

func buildSCTPINITChunk(initiateTag uint32) []byte {
	// INIT chunk: Type=1, Flags=0, Length=20 (4-byte chunk header + 16-byte INIT value).
	// INIT value: InitiateTag(4) + A-RWND(4) + OutboundStreams(2) + InboundStreams(2) + InitialTSN(4).
	buf := make([]byte, 20)
	buf[0] = 1 // Type=INIT
	buf[1] = 0
	buf[2] = 0
	buf[3] = 20
	// InitiateTag
	buf[4] = byte(initiateTag >> 24)
	buf[5] = byte(initiateTag >> 16)
	buf[6] = byte(initiateTag >> 8)
	buf[7] = byte(initiateTag)
	// A-RWND = 65535
	buf[8] = 0
	buf[9] = 0
	buf[10] = 0xFF
	buf[11] = 0xFF
	// OutboundStreams = 1
	buf[12] = 0
	buf[13] = 1
	// InboundStreams = 1
	buf[14] = 0
	buf[15] = 1
	// InitialTSN = 0
	buf[16] = 0
	buf[17] = 0
	buf[18] = 0
	buf[19] = 0
	return buf
}

func buildSCTPCookieEchoChunk() []byte {
	// COOKIE-ECHO: Type=10, Flags=0, Length=4 (empty cookie for test).
	return []byte{10, 0, 0, 4}
}

func buildSCTPCookieAckChunk() []byte {
	// COOKIE-ACK: Type=11, Flags=0, Length=4.
	return []byte{11, 0, 0, 4}
}

func buildSCTPDATAChunk(tsn uint32, data []byte) []byte {
	// DATA chunk: Type=0, Flags=0x03 (Begin+End), Length=16+len(data) (padded).
	dataLen := len(data)
	totalLen := 16 + dataLen
	paddedLen := totalLen
	if paddedLen%4 != 0 {
		paddedLen += 4 - (paddedLen % 4)
	}
	buf := make([]byte, paddedLen)
	buf[0] = 0    // Type=DATA
	buf[1] = 0x03 // Flags: B=1, E=1 (single-message chunk)
	buf[2] = byte(totalLen >> 8)
	buf[3] = byte(totalLen)
	// TSN
	buf[4] = byte(tsn >> 24)
	buf[5] = byte(tsn >> 16)
	buf[6] = byte(tsn >> 8)
	buf[7] = byte(tsn)
	// SID = 0
	buf[8] = 0
	buf[9] = 0
	// SSN = 0
	buf[10] = 0
	buf[11] = 0
	// PPID = 0
	buf[12] = 0
	buf[13] = 0
	buf[14] = 0
	buf[15] = 0
	// Data
	copy(buf[16:], data)
	return buf
}

func buildSCTPShutdownChunk(cumTSN uint32) []byte {
	// SHUTDOWN: Type=7, Flags=0, Length=8 (4-byte header + 4-byte CumulativeTSN).
	buf := make([]byte, 8)
	buf[0] = 7
	buf[1] = 0
	buf[2] = 0
	buf[3] = 8
	buf[4] = byte(cumTSN >> 24)
	buf[5] = byte(cumTSN >> 16)
	buf[6] = byte(cumTSN >> 8)
	buf[7] = byte(cumTSN)
	return buf
}

func buildSCTPShutdownAckChunk() []byte {
	// SHUTDOWN-ACK: Type=8, Flags=0, Length=4.
	return []byte{8, 0, 0, 4}
}

func buildSCTPShutdownCompleteChunk() []byte {
	// SHUTDOWN-COMPLETE: Type=14, Flags=0, Length=4.
	return []byte{14, 0, 0, 4}
}

// DefaultTTL mirrors the protocol planners' default. Kept here (not in
// types.go) because it's only consumed by the subflow helper.
const DefaultTTL = 64

// withSubflowIPs is a small helper for tests that want to construct a
// SubFlowSpec with explicit IPs without writing struct literals. Not used
// by production code.
func withSubflowIPs(sub SubFlowSpec, srcIP, dstIP string) SubFlowSpec {
	sub.AltSrcIP = srcIP
	sub.AltDstIP = dstIP
	return sub
}

var _ = withSubflowIPs // keep helper alive even if unused by production
var _ = net.ParseIP     // keep net import alive
