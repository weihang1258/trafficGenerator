// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// emit.go: Low-level packet emission helpers (TCP/SMB2/segmentation).
package smb

import (
	"context"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// emitTCPPacket emits a single TCP packet config (SYN/ACK/FIN/PSH).
// 阻塞发送：channel 满时等待（而非静默丢弃 PDU），并尊重 ctx 取消
// （C-2 修复：原 select+default 在 channel 满时静默丢包且 packetIndex
// 仍递增，导致包序列空洞）。
func emitTCPPacket(
	ctx context.Context,
	spec core.FlowSpec,
	direction string,
	seq, ack uint32,
	flags uint8,
	payload []byte,
	tcpOpts []core.TCPOption,
	ttl uint8,
	ipID uint16,
	packetIndex *uint64,
	flowID string,
	now time.Time,
	configChan chan<- core.PacketConfig,
) {
	if payload == nil {
		payload = []byte{}
	}

	srcMAC, dstMAC := spec.SrcMAC, spec.DstMAC
	srcIP, dstIP := spec.SrcIP, spec.DstIP
	srcPort, dstPort := spec.SrcPort, spec.DstPort
	if direction == "down" {
		srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
		srcIP, dstIP = spec.DstIP, spec.SrcIP
		srcPort, dstPort = spec.DstPort, spec.SrcPort
	}

	l3 := core.L3Base(srcIP, dstIP, 6, ttl, ipID, spec)
	l4 := core.L4Config{
		Protocol:   "tcp",
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Seq:        seq,
		Ack:        ack,
		Flags:      flags,
		WindowSize: 65535,
	}
	if flags == 0x02 || flags == 0x12 {
		l4.TCPOptions = tcpOpts
	}

	cfg := core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: *packetIndex,
		Direction:   direction,
		Timestamp:   now,
		L2: core.L2Config{
			SrcMAC:    srcMAC,
			DstMAC:    dstMAC,
			EtherType: core.EtherTypeFor(srcIP),
		},
		L3:      l3,
		L4:      l4,
		Payload: payload,
	}

	select {
	case configChan <- cfg:
		(*packetIndex)++
	case <-ctx.Done():
		// 尊重外部 context 取消（M-4）：取消时不再阻塞，结束会话。
		return
	}
}

// emitSMB2PDU builds an SMB2 PDU (header + body + NBSS) and emits it as a
// PSH-ACK.
func emitSMB2PDU(
	ctx context.Context,
	spec core.FlowSpec,
	session *smbSessionState,
	direction string,
	cmd uint16,
	status uint32,
	flags uint32,
	body []byte,
	useNBSS bool,
	clientSeq, serverSeq *uint32,
	mss uint16,
	ttl uint8,
	now *time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	flowID string,
	configChan chan<- core.PacketConfig,
	isResponse bool,
) {
	creditCharge := creditChargeFor(session.dialectRev)

	hdr := buildSMB2Header(cmd, creditCharge, status, flags,
		session.messageID, session.treeID, session.sessionID)

	// H-3 修复: EncryptionRequired=true 且 dialect > 0x0300 时，认证完成后
	// 的信令 PDU 用 52B TRANSFORM_HEADER 包裹（设计 §3.27/S14/T178-182）：
	// 层叠顺序 = NBSS(4) + TRANSFORM_HEADER(52) + 原 SMB2 头+体（密文占位）。
	// 原 SMB2 头+体字节原样保留（trafficgen 不做真实加密），OriginalMessageSize
	// 记录其长度。
	pdu := make([]byte, 0, len(hdr)+len(body))
	pdu = append(pdu, hdr...)
	pdu = append(pdu, body...)

	if session.encryptRequired {
		th := buildTransformHeader(uint32(len(pdu)), session.sessionID)
		pdu = append(th, pdu...)
	}

	if useNBSS {
		nbss := buildNBSSHeader(len(pdu))
		pdu = append(nbss, pdu...)
	}

	var senderSeq, peerSeq *uint32
	if isResponse {
		senderSeq = serverSeq
		peerSeq = clientSeq
	} else {
		senderSeq = clientSeq
		peerSeq = serverSeq
	}

	emitPayloadMSS(ctx, spec, direction, senderSeq, peerSeq, pdu, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan)
}

// emitPayloadMSS segments payload by MSS and emits each chunk as PSH-ACK.
func emitPayloadMSS(
	ctx context.Context,
	spec core.FlowSpec,
	direction string,
	senderSeq, peerSeq *uint32,
	payload []byte,
	mss uint16,
	ttl uint8,
	now *time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	flowID string,
	configChan chan<- core.PacketConfig,
) {
	for _, seg := range segmentByMSS(payload, int(mss)) {
		emitTCPPacket(ctx, spec, direction, *senderSeq, *peerSeq, 0x18, seg, nil, ttl,
			nextIPID(), packetIndex, flowID, *now, configChan)
		*senderSeq += uint32(len(seg))
	}
}

// segmentByMSS splits payload into chunks of at most mss bytes.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if len(payload) <= mss {
		return [][]byte{payload}
	}
	var segs [][]byte
	for i := 0; i < len(payload); i += mss {
		end := i + mss
		if end > len(payload) {
			end = len(payload)
		}
		segs = append(segs, payload[i:end])
	}
	return segs
}

// buildNegotiateErrorResponseBody returns a 4-byte minimal error body.
func buildNegotiateErrorResponseBody() []byte {
	body := make([]byte, 4)
	body[0] = 0x41 // StructureSize = 65
	body[1] = 0x00
	body[2] = 0x00
	body[3] = 0x00
	return body
}
