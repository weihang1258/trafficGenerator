// Package pcapparser reads pcap files and produces structured flow/packet
// models for asset viewing (§15) and replay (§16). The pcap file on disk is
// the source of truth; this package produces pointers + aggregates (§17).
package pcapparser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// endpoint is an (ip, port) pair used for bidirectional flow normalization.
type endpoint struct {
	IP   string
	Port uint16
}

// String renders an endpoint as "ip:port".
func (e endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.IP, e.Port)
}

// compareEndpoints orders endpoints by IP then port so the two directions of a
// connection normalize to the same flow key.
func compareEndpoints(a, b endpoint) int {
	if c := strings.Compare(a.IP, b.IP); c != 0 {
		return c
	}
	switch {
	case a.Port < b.Port:
		return -1
	case a.Port > b.Port:
		return 1
	default:
		return 0
	}
}

// flowKeyTCPUDP computes the bidirectional-normalized 5-tuple flow key for a
// TCP/UDP flow: the (ip,port) endpoints are sorted so both directions of one
// connection map to the same key (§16.7).
func flowKeyTCPUDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) string {
	a := endpoint{srcIP.String(), srcPort}
	b := endpoint{dstIP.String(), dstPort}
	if compareEndpoints(a, b) > 0 {
		a, b = b, a
	}
	return fmt.Sprintf("%d|%s|%s", proto, a, b)
}

// flowKeyICMP normalizes an ICMP flow as (proto, min(ip), max(ip), id).
// Echo requests/replies share a flow by id (type 是方向语义不是流身份——
// req=8/reply=0 必须同流才能 (id,seq) 配对，D-PARSE-1 P0 行为变更：key 去
// type，原 type 入 key 致 req/reply 分家)。Directions normalize via IP order.
func flowKeyICMP(srcIP, dstIP net.IP, id uint16) string {
	a, b := srcIP.String(), dstIP.String()
	if strings.Compare(a, b) > 0 {
		a, b = b, a
	}
	return fmt.Sprintf("1|%s|%s|%d", a, b, id)
}

// flowKeyARP normalizes an ARP exchange as (op, min(sender,target), max(...)).
func flowKeyARP(senderIP, targetIP net.IP, op uint16) string {
	a, b := senderIP.String(), targetIP.String()
	if strings.Compare(a, b) > 0 {
		a, b = b, a
	}
	return fmt.Sprintf("arp|%d|%s|%s", op, a, b)
}

// FlowState accumulates per-flow state during a single-pass parse. A flow is
// active while packets arrive; on termination (FIN/RST/timeout/end-of-file) it
// is finalized into a FlowModel.
type FlowState struct {
	storage.FlowModel

	packets []storage.PacketModel // batched; flushed when len >= batchSize

	// Direction tracking (§16.7). firstSrcIP/firstSrcPort identify the first
	// packet's source -- the initial client candidate. R2's direction.go
	// refines this with SYN/SYN-ACK calibration; P2 uses the first-packet guess.
	firstSrcIP   string
	firstSrcPort uint16
	// serverPort is the server-side port, used as the L7 parser hint (§6/§7).
	// Seeded from the first packet's dst port, then corrected by setClient when
	// direction calibration fires (so a capture starting at the SYN-ACK still
	// hands the L7 parser the real server port, not the client's ephemeral one).
	serverPort uint16
	dirLocked    bool // once calibration locks, direction is fixed

	// Offset layout (§9), extracted from the first packet (encapsulation-
	// constant across the flow). Serialized to FlowModel.OffsetLayout at
	// finalize for the replay rewriter to consume.
	layout OffsetLayout

	// Reassembly streams (§7): one per direction. Set by the reassemblyFactory
	// when the assembler first sees each direction. The parser flushes their
	// buffers to .payloads at finalize.
	c2sStream *reassemblyStream
	s2cStream *reassemblyStream

	// TCP handshake + flag tracking (packet-level, finalized at end).
	sawSYN, sawSYNACK, sawACKAfterSYN bool
	flagsCount                       map[string]int64
	seqMin, seqMax                   uint32
	seqSeen                          bool
	// Per-direction next-expected-seq for retransmit/out-of-order detection
	// (§7): nextSeq = highest (seq + payloadLen) seen so far. A packet whose
	// data overlaps already-seen bytes is a retransmission; a packet arriving
	// ahead of the expected seq leaves a gap (out-of-order). Wraparound-aware
	// via seqLess (signed delta, 2GB window tolerance).
	c2sNextSeq, s2cNextSeq uint32
	c2sSeqSeen, s2cSeqSeen bool
	// Window range (§7): min/max TCP window across all packets.
	winMin, winMax uint16
	winSeen        bool
	// MSS/WindowScale/SACK advertised in SYN/SYN-ACK (§7). Recorded on the
	// first SYN-bearing packet that carries them.
	tcpOptionsRecorded bool

	// flowKey caches the normalized key (also stored in FlowModel.FlowKey).
	flowKey string

	// l7Parsed tracks whether UDP L7 metadata has been set (from the first
	// packet with a payload). TCP L7 is parsed once after reassembly.
	l7Parsed bool

	// counters for finalize
	indexInFlow int

	// P0 载荷完整性（D-PARSE-1）：UDP 双向增量摘要与预览（TCP 在 finalize 从
	// 重组流缓冲计算）；udpPayloadBytes 供 unknown 兜底判定。
	c2sHasher, s2cHasher hash.Hash
	c2sPrev, s2cPrev     []byte
	udpPayloadBytes      int64

	// P0 SCTP 聚合：chunk 类型集合 + 关联状态机输入
	sctpChunkSeen                                                                                  map[uint8]bool
	sctpHasInit, sctpHasInitAck, sctpHasCookieEcho, sctpHasCookieAck, sctpHasData, sctpHasAbort bool
}

// payloadPreviewCap is the preview cap in bytes (D-PARSE-1 裁定：128B 常量，
// hex+ascii 双视图足够比对且防超长).
const payloadPreviewCap = 128

// newFlowState creates a FlowState for the first packet of a flow.
func newFlowState(flowID, pcapAssetID, userID, flowKey string, pkt firstPacketInfo) *FlowState {
	fs := &FlowState{
		flowKey:      flowKey,
		firstSrcIP:   pkt.SrcIP,
		firstSrcPort: pkt.SrcPort,
		serverPort:   pkt.DstPort, // first packet: dst is the server candidate
	}
	fs.FlowModel = storage.FlowModel{
		ID:          flowID,
		PcapAssetID: pcapAssetID,
		UserID:      userID,
		FlowKey:     flowKey,
		L4Protocol:  pkt.L4Proto,
		IPVersion:   pkt.IPVersion,
		SrcIP:       pkt.SrcIP,
		SrcPort:     pkt.SrcPort,
		DstIP:       pkt.DstIP,
		DstPort:     pkt.DstPort,
		FirstTsUs:   pkt.TsUs,
		LastTsUs:    pkt.TsUs,
		// First-packet direction guess: src of the first packet is the client
		// candidate. DirStatus stays "uncertain" until R2 calibrates.
		Client:    fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort),
		Server:    fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort),
		DirMethod: "first_packet",
		DirStatus: "uncertain",
		// 封装承载 + ICMP 聚合缺省（D-PARSE-1 P0）：无 VLAN/封装 -1，ICMP 首包
		// 覆写（type 0 是合法 echo reply，必须 -1 哨兵）。
		VlanIDOuter: pkt.VlanOuter,
		VlanIDInner: pkt.VlanInner,
		EncapType:   pkt.EncapType,
		EncapID:     pkt.EncapID,
		ICMPType:    -1,
		ICMPCode:    -1,
		ICMPID:      -1,
		ICMPSeq:     -1,
	}
	return fs
}

// firstPacketInfo carries the fields needed to seed a FlowState from the first
// packet of a flow.
type firstPacketInfo struct {
	SrcIP, DstIP string
	SrcPort, DstPort uint16
	L4Proto   string
	IPVersion int
	TsUs      int64
	// 封装承载（D-PARSE-1 P0）：取自首包（封装恒定原则）
	VlanOuter, VlanInner int
	EncapType            string
	EncapID              int64
}

// classifyDirection returns "c2s" if the packet's src matches the flow's
// first-packet src (the client candidate), else "s2c".
func (fs *FlowState) classifyDirection(srcIP string, srcPort uint16) string {
	if srcIP == fs.firstSrcIP && srcPort == fs.firstSrcPort {
		return "c2s"
	}
	return "s2c"
}

// addPacket accumulates a packet into the flow state: stats, direction counts,
// timestamp range, and the PacketModel (batched). The caller must set
// pkt.Direction (via classifyDirection, using the parsed src fields) before
// calling, since PacketModel does not carry src/dst IP/port.
func (fs *FlowState) addPacket(pkt storage.PacketModel) {
	fs.indexInFlow++
	pkt.IndexInFlow = fs.indexInFlow

	fs.FlowModel.PacketCount++
	fs.FlowModel.ByteCount += int64(pkt.Length)
	if pkt.Direction == "c2s" {
		fs.FlowModel.C2SPackets++
		fs.FlowModel.C2SBytes += int64(pkt.Length)
	} else {
		fs.FlowModel.S2CPackets++
		fs.FlowModel.S2CBytes += int64(pkt.Length)
	}
	// FirstTsUs is seeded in newFlowState from the first packet's timestamp, so
	// no "unset" sentinel is needed here.  The previous `== 0` check was a bug:
	// 0 is a valid timestamp, so a first packet at ts=0 would let any later
	// packet overwrite FirstTsUs.  Compare strictly against the seeded minimum.
	if pkt.TimestampUs < fs.FlowModel.FirstTsUs {
		fs.FlowModel.FirstTsUs = pkt.TimestampUs
	}
	if pkt.TimestampUs > fs.FlowModel.LastTsUs {
		fs.FlowModel.LastTsUs = pkt.TimestampUs
	}
	fs.packets = append(fs.packets, pkt)
}

// drainPackets returns the buffered packet batch and clears it. Called when the
// batch reaches BatchSize or the flow finalizes.
func (fs *FlowState) drainPackets() []storage.PacketModel {
	out := fs.packets
	fs.packets = nil
	return out
}

// pendingPacketCount returns the number of buffered packets not yet drained.
func (fs *FlowState) pendingPacketCount() int { return len(fs.packets) }

// setL7 populates FlowModel L7 fields + body offsets from an L7 parse result.
// dir is "c2s" or "s2c" (for body offsets); for UDP it's the packet direction.
func (fs *FlowState) setL7(res *L7Result, dir string) {
	if res == nil {
		return
	}
	oldProto := fs.FlowModel.L7Protocol
	fs.FlowModel.L7Protocol = res.Protocol
	if oldProto != "" && oldProto != res.Protocol {
		// 解析器换判：整体覆盖 + 清旧协议索引列（L7Host 不能残留 TLS SNI
		// 之类，复审 F4）。
		fs.FlowModel.L7Method = ""
		fs.FlowModel.L7Host = ""
		fs.FlowModel.L7QueryName = ""
	}
	// c2s/s2c 各解析一次；同协议第二次调用合并 metadata 而非整体覆盖
	//（c2s 的 client_id/topic 不被 s2c 的 msg_types 冲掉）。列表键拼接成
	// 完整会话序，标量键新值胜；协议不同（解析器换判）仍整体覆盖。
	merged := res.Metadata
	if oldProto == res.Protocol && fs.FlowModel.L7Metadata != "" {
		var old map[string]any
		if json.Unmarshal([]byte(fs.FlowModel.L7Metadata), &old) == nil && len(old) > 0 {
			for k, v := range merged {
				if nl, ok := v.([]string); ok {
					if ol, ok2 := old[k].([]any); ok2 {
						comb := make([]any, 0, len(ol)+len(nl))
						comb = append(comb, ol...)
						for _, s := range nl {
							comb = append(comb, s)
						}
						old[k] = comb
						continue
					}
				}
				old[k] = v
			}
			merged = old
		}
	}
	if data, err := json.Marshal(merged); err == nil {
		fs.FlowModel.L7Metadata = string(data)
	}
	// Denormalized filter columns (§17.3): method/host/queryname as indexed
	// columns for fast L7 filtering, full detail in L7Metadata JSON.
	if v, ok := res.Metadata["method"]; ok {
		fs.FlowModel.L7Method = fmt.Sprintf("%v", v)
	}
	if v, ok := res.Metadata["host"]; ok {
		fs.FlowModel.L7Host = fmt.Sprintf("%v", v)
	}
	if v, ok := res.Metadata["sni"]; ok {
		fs.FlowModel.L7Host = fmt.Sprintf("%v", v) // TLS SNI indexes as L7Host
	}
	if v, ok := res.Metadata["query_name"]; ok {
		fs.FlowModel.L7QueryName = fmt.Sprintf("%v", v)
	}
	// Body offsets (§10): where the L7 body starts within the reassembled stream.
	if dir == "c2s" {
		fs.FlowModel.C2SBodyOffset = int64(res.BodyOffset)
		fs.FlowModel.C2SBodyLength = int64(res.BodyLength)
	} else if dir == "s2c" {
		fs.FlowModel.S2CBodyOffset = int64(res.BodyOffset)
		fs.FlowModel.S2CBodyLength = int64(res.BodyLength)
	}
}

// setLayout records the offset layout extracted from the first packet. Called
// once per flow (encapsulation-constant principle).
func (fs *FlowState) setLayout(layout OffsetLayout) {
	fs.layout = layout
}

// setStream registers a reassembly stream for the given direction. Called by
// the reassemblyFactory when the assembler first sees a direction.
func (fs *FlowState) setStream(dir string, s *reassemblyStream) {
	if dir == "c2s" {
		fs.c2sStream = s
	} else {
		fs.s2cStream = s
	}
}

// seqLess reports whether a < b with TCP wraparound awareness (§7). A signed
// 32-bit delta works for offsets up to 2GB (the common case); larger gaps
// are treated as wraparound and compared directly.
func seqLess(a, b uint32) bool {
	delta := int32(b - a)
	return delta > 0
}

// seqInRange reports whether a is within [min, max] with wraparound awareness.
func seqInRange(a, min, max uint32) bool {
	return !seqLess(a, min) && !seqLess(max, a)
}

// recordTCPStats accumulates TCP-specific FlowModel fields from each packet:
// flag counts, handshake status, initial seq, seq range, retransmission count,
// out-of-order count, window range, MSS/WindowScale/SACK from SYN options.
// Called per TCP packet.
func (fs *FlowState) recordTCPStats(f packetFields, dir string) {
	if fs.flagsCount == nil {
		fs.flagsCount = map[string]int64{}
	}
	if f.tcpSYN {
		fs.flagsCount["syn"]++
		if f.tcpACK {
			fs.sawSYNACK = true
			fs.FlowModel.S2CInitSeq = f.tcpSeq // SYN-ACK seq = server init seq
		} else {
			fs.sawSYN = true
			fs.FlowModel.C2SInitSeq = f.tcpSeq // SYN seq = client init seq
		}
		// Record SYN-carried TCP options (§7): MSS, WindowScale, SACK.
		// Only record once (the first SYN in each direction carries them).
		if !fs.tcpOptionsRecorded && f.tcpOptionKinds != nil {
			fs.tcpOptionsRecorded = true
			fs.FlowModel.MSS = f.tcpMSS
			fs.FlowModel.WindowScale = f.tcpWindowScale
			// Serialize option kinds for TCPOptions.
			fs.FlowModel.TCPOptions = formatTCPOptions(f.tcpOptionKinds)
		}
	} else if f.tcpACK && fs.sawSYNACK {
		// Third handshake step: a pure/data ACK after the SYN-ACK (typically
		// from the client) completes the 3-way handshake.
		fs.sawACKAfterSYN = true
	}
	if f.tcpACK {
		fs.flagsCount["ack"]++
	}
	if f.tcpFIN {
		fs.flagsCount["fin"]++
	}
	if f.tcpRST {
		fs.flagsCount["rst"]++
	}
	if f.tcpPSH {
		fs.flagsCount["psh"]++
	}
	// Seq range over all TCP packets.
	if !fs.seqSeen || f.tcpSeq < fs.seqMin {
		fs.seqMin = f.tcpSeq
	}
	if !fs.seqSeen || f.tcpSeq > fs.seqMax {
		fs.seqMax = f.tcpSeq
	}
	fs.seqSeen = true

	// Retransmission / out-of-order detection (§7): track per-direction
	// next-expected seq. A packet whose seq is below the expected position
	// and whose data overlaps already-seen bytes is a retransmission. A
	// packet whose seq is past the expected position is out-of-order.
	// P1-11：SYN 与 FIN 各占 1 个序号——nextSeq 只加 payloadLen 会把干净流
	// 判出 3 次假乱序（两方向握手 ACK + 挥手末 ACK），必须计入占位。
	payloadLen := uint32(len(f.payload))
	if f.tcpSYN {
		payloadLen++
	}
	if f.tcpFIN {
		payloadLen++
	}
	nextSeq := &fs.c2sNextSeq
	seen := &fs.c2sSeqSeen
	if dir == "s2c" {
		nextSeq = &fs.s2cNextSeq
		seen = &fs.s2cSeqSeen
	}
	if !*seen {
		// First packet in this direction: set the expected seq.
		*nextSeq = f.tcpSeq + payloadLen
		*seen = true
	} else if f.tcpSeq < *nextSeq {
		// Seq is below the next expected seq — this is a retransmission
		// or out-of-order segment. If the data overlaps (seq+payloadLen
		// > nextSeq), bytes overlap; classify as retransmission.
		fs.FlowModel.RetransCount++
	} else if f.tcpSeq > *nextSeq {
		// Seq is ahead of the expected position — a gap; out-of-order.
		fs.FlowModel.OutOfOrderCount++
		*nextSeq = f.tcpSeq + payloadLen
	} else {
		// Exactly at the expected position — normal in-order delivery.
		*nextSeq = f.tcpSeq + payloadLen
	}

	// Window range (§7).
	if !fs.winSeen || f.tcpWindow < fs.winMin {
		fs.winMin = f.tcpWindow
	}
	if !fs.winSeen || f.tcpWindow > fs.winMax {
		fs.winMax = f.tcpWindow
	}
	fs.winSeen = true
}

// formatTCPOptions serializes the set of TCP option kinds as a JSON array
// string, e.g. `[2,3,4]` for MSS+WindowScale+SACK.
func formatTCPOptions(kinds []uint8) string {
	// Deduplicate while preserving order.
	seen := make(map[uint8]bool)
	var out []uint8
	for _, k := range kinds {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	var s string
	for i, k := range out {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("%d", k)
	}
	return "[" + s + "]"
}

// recordICMPStats captures the first packet's type/code/id/seq into the flow
// aggregate (D-PARSE-1 P0：首包值；混杂面 L7Detail 标记随 P1 批).
func (fs *FlowState) recordICMPStats(f packetFields) {
	switch f.l4Proto {
	case "icmp":
		if fs.FlowModel.ICMPType == -1 {
			fs.FlowModel.ICMPType = int(f.icmpType)
			fs.FlowModel.ICMPCode = int(f.icmpCode)
			fs.FlowModel.ICMPID = int(f.icmpID)
			fs.FlowModel.ICMPSeq = int(f.icmpSeq)
		}
	case "icmpv6":
		if fs.FlowModel.ICMPType == -1 {
			fs.FlowModel.ICMPType = int(f.icmp6Type)
			fs.FlowModel.ICMPCode = int(f.icmp6Code)
			fs.FlowModel.ICMPID = int(f.icmp6ID)
			fs.FlowModel.ICMPSeq = int(f.icmp6Seq)
		}
	}
}

// sctpChunkWalk iterates SCTP chunks per RFC 4960 §3.1 (4B chunk header:
// type/flags/length; length includes padding). Returns the chunk type list,
// DATA payload byte total (chunk length - 16B DATA chunk header), and the
// handshake/abort flags feeding the association state machine.
func sctpChunkWalk(data []byte) (typesList []uint8, dataBytes int64,
	hasInit, hasInitAck, hasCookieEcho, hasCookieAck, hasData, hasAbort bool) {
	for len(data) >= 4 {
		ct := data[0]
		cl := int(data[2])<<8 | int(data[3])
		if cl < 4 || cl > len(data) {
			break // 截断/非法：停（负例断言锚点）
		}
		typesList = append(typesList, ct)
		switch ct {
		case 1:
			hasInit = true
		case 2:
			hasInitAck = true
		case 10:
			hasCookieEcho = true
		case 11:
			hasCookieAck = true
		case 0:
			hasData = true
			if cl >= 16 {
				dataBytes += int64(cl - 16) // DATA: 4B 块头 + TSN(4)+SID(2)+SSN(2)+PPID(4)
			}
		case 6:
			hasAbort = true
		}
		data = data[cl:]
	}
	return
}

// recordSCTPStats accumulates chunk-type set, DATA byte count and association
// state inputs per SCTP packet (D-PARSE-1 P0).
func (fs *FlowState) recordSCTPStats(payload []byte) {
	typesList, dataBytes, hasInit, hasInitAck, hasCookieEcho, hasCookieAck, hasData, hasAbort := sctpChunkWalk(payload)
	if fs.sctpChunkSeen == nil {
		fs.sctpChunkSeen = map[uint8]bool{}
	}
	seen := []uint8{}
	for _, ct := range typesList {
		if !fs.sctpChunkSeen[ct] {
			fs.sctpChunkSeen[ct] = true
			seen = append(seen, ct)
		}
	}
	if len(seen) > 0 {
		// 追加进 JSON 数组字符串（简单拼装，类型集合是小面）
		cur := strings.TrimSuffix(strings.TrimPrefix(fs.FlowModel.SctpChunkTypes, "["), "]")
		parts := []string{}
		if cur != "" {
			parts = append(parts, cur)
		}
		for _, ct := range seen {
			parts = append(parts, fmt.Sprintf("%d", ct))
		}
		fs.FlowModel.SctpChunkTypes = "[" + strings.Join(parts, ",") + "]"
	}
	fs.FlowModel.SctpDataBytes += dataBytes
	fs.sctpHasInit = fs.sctpHasInit || hasInit
	fs.sctpHasInitAck = fs.sctpHasInitAck || hasInitAck
	fs.sctpHasCookieEcho = fs.sctpHasCookieEcho || hasCookieEcho
	fs.sctpHasCookieAck = fs.sctpHasCookieAck || hasCookieAck
	fs.sctpHasData = fs.sctpHasData || hasData
	fs.sctpHasAbort = fs.sctpHasAbort || hasAbort
}

// finalizeSCTPState derives the association state (D-PARSE-1 P0：
// established|aborted|incomplete) from accumulated chunk flags.
func (fs *FlowState) finalizeSCTPState() {
	if fs.FlowModel.L4Protocol != "sctp" || fs.sctpChunkSeen == nil {
		return
	}
	handshake := (fs.sctpHasInit && fs.sctpHasInitAck) || fs.sctpHasCookieEcho
	switch {
	case fs.sctpHasAbort:
		fs.FlowModel.SctpAssocState = "aborted"
	case handshake || fs.sctpHasData || fs.sctpHasCookieAck:
		fs.FlowModel.SctpAssocState = "established"
	default:
		fs.FlowModel.SctpAssocState = "incomplete"
	}
}

// feedUDPPayload accumulates a UDP payload into its direction's incremental
// digest and preview (D-PARSE-1 P0：载荷域按序聚合).
func (fs *FlowState) feedUDPPayload(dir string, b []byte) {
	if len(b) == 0 {
		return
	}
	fs.udpPayloadBytes += int64(len(b))
	if fs.c2sHasher == nil {
		fs.c2sHasher = sha256.New()
	}
	if fs.s2cHasher == nil {
		fs.s2cHasher = sha256.New()
	}
	if dir == "c2s" {
		fs.c2sHasher.Write(b)
		fs.c2sPrev = appendPreview(fs.c2sPrev, b)
	} else {
		fs.s2cHasher.Write(b)
		fs.s2cPrev = appendPreview(fs.s2cPrev, b)
	}
}

// appendPreview appends up to the preview cap bytes.
func appendPreview(cur, b []byte) []byte {
	if len(cur) >= payloadPreviewCap {
		return cur
	}
	n := payloadPreviewCap - len(cur)
	if n > len(b) {
		n = len(b)
	}
	return append(cur, b[:n]...)
}

// formatPreview renders bytes as hex+" | "+ascii 双视图 (printable ASCII kept,
// others '.').
func formatPreview(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2+3+len(b))
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	out = append(out, ' ', '|', ' ')
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, '.')
		}
	}
	return string(out)
}

// sha256Hex returns the hex-encoded sha256 of b, "" when empty (payloadHash 同
// 口径：空载荷与零字节摘要可区分).
func sha256Hex(b []byte) string {
	return payloadHash(b)
}

// fillPayloadDigests writes the P0 payload/body digest columns at finalize:
// TCP from reassembled stream buffers (honoring L7 body boundaries when a
// parser set them, else body=stream), UDP from the incremental direction
// digest (body=payload for UDP). Must run after flushStreams + L7 parse.
func (fs *FlowState) fillPayloadDigests() {
	if fs.FlowModel.L4Protocol == "udp" {
		if fs.c2sHasher != nil {
			fs.FlowModel.C2SPayloadHash = hex.EncodeToString(fs.c2sHasher.Sum(nil))
		}
		if fs.s2cHasher != nil {
			fs.FlowModel.S2CPayloadHash = hex.EncodeToString(fs.s2cHasher.Sum(nil))
		}
		fs.FlowModel.C2SPayloadPreview = formatPreview(fs.c2sPrev)
		fs.FlowModel.S2CPayloadPreview = formatPreview(fs.s2cPrev)
		// UDP 无独立 body 段：body=载荷
		fs.FlowModel.C2SBodyHash = fs.FlowModel.C2SPayloadHash
		fs.FlowModel.S2CBodyHash = fs.FlowModel.S2CPayloadHash
		fs.FlowModel.C2SBodyPreview = fs.FlowModel.C2SPayloadPreview
		fs.FlowModel.S2CBodyPreview = fs.FlowModel.S2CPayloadPreview
		return
	}
	if fs.FlowModel.L4Protocol != "tcp" {
		return
	}
	digestStream := func(buf []byte, bodyOff, bodyLen int64, payHash, payPrev, bodyHash, bodyPrev *string) {
		if buf == nil {
			return
		}
		*payHash = sha256Hex(buf)
		*payPrev = formatPreview(buf)
		// body：解析器给出边界用边界段；无/越界回落 body=stream（错误表第 4 行）
		off, ln := int(bodyOff), int(bodyLen)
		if ln <= 0 || off < 0 || off+ln > len(buf) {
			off, ln = 0, len(buf)
		}
		*bodyHash = sha256Hex(buf[off : off+ln])
		*bodyPrev = formatPreview(buf[off : off+ln])
	}
	if fs.c2sStream != nil {
		digestStream(fs.c2sStream.buf, fs.FlowModel.C2SBodyOffset, fs.FlowModel.C2SBodyLength,
			&fs.FlowModel.C2SPayloadHash, &fs.FlowModel.C2SPayloadPreview,
			&fs.FlowModel.C2SBodyHash, &fs.FlowModel.C2SBodyPreview)
	}
	if fs.s2cStream != nil {
		digestStream(fs.s2cStream.buf, fs.FlowModel.S2CBodyOffset, fs.FlowModel.S2CBodyLength,
			&fs.FlowModel.S2CPayloadHash, &fs.FlowModel.S2CPayloadPreview,
			&fs.FlowModel.S2CBodyHash, &fs.FlowModel.S2CBodyPreview)
	}
}

// finalizeL7Fallback sets the unknown/handshake_only fallback (D-PARSE-1 H 规
// 则)：有载荷但无解析器命中 → unknown；TCP 纯握手零载荷 → handshake_only。
// 解析器命中但解析失败的流已带解析器名（识别≠解析成功），不走本兜底。
func (fs *FlowState) finalizeL7Fallback() {
	if fs.FlowModel.L7Protocol != "" {
		return
	}
	hasPayload := fs.udpPayloadBytes > 0
	if fs.FlowModel.L4Protocol == "tcp" {
		hasPayload = fs.FlowModel.C2SLength+fs.FlowModel.S2CLength > 0
	}
	switch {
	case hasPayload:
		fs.FlowModel.L7Protocol = "unknown"
	case fs.FlowModel.L4Protocol == "tcp":
		fs.FlowModel.L7Protocol = "handshake_only"
	}
}

// flushStreams writes the c2s/s2c reassembly buffers to the .payloads file and
// records offsets/lengths/completeness in FlowModel. Called by the parser after
// assembler.FlushAll (single-threaded). payloadsPath is stored in
// FlowModel.StreamFile so consumers can locate the reassembled bytes.
func (fs *FlowState) flushStreams(w *payloadsWriter, payloadsPath string) {
	if fs.FlowModel.L4Protocol != "tcp" {
		return
	}
	fs.FlowModel.StreamFile = payloadsPath
	fs.FlowModel.ReassemblyComplete = true // true unless a gap is detected
	c2sGap, s2cGap := false, false
	if fs.c2sStream != nil {
		off, length, err := w.appendStream(fs.c2sStream.buf)
		if err != nil {
			return
		}
		fs.FlowModel.C2SOffset = off
		fs.FlowModel.C2SLength = length
		c2sGap = fs.c2sStream.gapDetected
	}
	if fs.s2cStream != nil {
		off, length, err := w.appendStream(fs.s2cStream.buf)
		if err != nil {
			return
		}
		fs.FlowModel.S2COffset = off
		fs.FlowModel.S2CLength = length
		s2cGap = fs.s2cStream.gapDetected
	}
	if c2sGap || s2cGap {
		fs.FlowModel.ReassemblyComplete = false
		var gaps []string
		if c2sGap {
			gaps = append(gaps, "c2s")
		}
		if s2cGap {
			gaps = append(gaps, "s2c")
		}
		fs.FlowModel.GapInfo = "seq gap in " + joinStr(gaps, ", ")
	}
}

// joinStr joins strings with sep (small helper to avoid importing strings here).
func joinStr(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

// uint32FromSeq is a no-op cast kept for readability (seq values are already uint32).
func uint32FromSeq(s uint32) uint32 { return s }

// finalize completes the FlowModel: duration, offset-layout serialization,
// TCP stats (handshake/flags/seq-range), and flushes remaining buffered
// packets. Reassembly (.payloads) fields are filled by the parser after
// assembler.FlushAll. Returns the model and the remaining packet batch.
func (fs *FlowState) finalize() (storage.FlowModel, []storage.PacketModel) {
	fs.FlowModel.DurationUs = fs.FlowModel.LastTsUs - fs.FlowModel.FirstTsUs
	if data, err := json.Marshal(fs.layout); err == nil {
		fs.FlowModel.OffsetLayout = string(data)
	} else {
		fs.FlowModel.OffsetLayout = "{}"
	}
	fs.finalizeTCPStats()
	fs.finalizeSCTPState()
	fs.fillPayloadDigests()
	fs.finalizeL7Fallback()
	rem := fs.drainPackets()
	return fs.FlowModel, rem
}

// finalizeTCPStats derives the TCP-specific FlowModel fields from accumulated
// packet-level state.
func (fs *FlowState) finalizeTCPStats() {
	if fs.FlowModel.L4Protocol != "tcp" {
		return
	}
	switch {
	case fs.sawSYN && fs.sawSYNACK && fs.sawACKAfterSYN:
		fs.FlowModel.HandshakeStatus = "complete"
	case fs.sawSYN || fs.sawSYNACK:
		fs.FlowModel.HandshakeStatus = "partial"
	default:
		fs.FlowModel.HandshakeStatus = "none"
	}
	if fs.flagsCount != nil {
		if data, err := json.Marshal(fs.flagsCount); err == nil {
			fs.FlowModel.FlagsSummary = string(data)
		}
	}
	if fs.seqSeen {
		rng := []uint32{fs.seqMin, fs.seqMax}
		if data, err := json.Marshal(rng); err == nil {
			fs.FlowModel.SeqRange = string(data)
		}
	}
	// Window range (§7): JSON [min,max].
	if fs.winSeen {
		rng := []uint16{fs.winMin, fs.winMax}
		if data, err := json.Marshal(rng); err == nil {
			fs.FlowModel.WindowRange = string(data)
		}
	}
}

// packetFields holds the parsed fields used to build a PacketModel and update
// the FlowState, extracted from a gopacket.Packet.
type packetFields struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	l4Proto          string
	ipVersion        int
	payload          []byte // L4 payload (for PayloadHash)
	anomaly          string // truncated|oversize|undersize|""
	fragGroupID      string
	fragOffset       int
	// IP fragmentation details (§8): ipID + moreFragments flag for reassembly.
	ipID uint16
	ipMF bool
	// fragFirst is true when this is the first fragment (offset 0), which
	// carries the L4 header (ports) needed for flow key computation.
	fragFirst bool
	// TCP flags for direction calibration (§16.7) and handshake analysis.
	tcpSYN, tcpACK, tcpFIN, tcpRST, tcpPSH bool
	tcpSeq, tcpAckValue uint32
	// TCP window + SYN-carried options (§7). Window is tracked per packet for
	// WindowRange; MSS/WindowScale/SACK/option-kinds come from SYN/SYN-ACK only.
	tcpWindow      uint16
	tcpMSS         uint16 // 0 if not advertised
	tcpWindowScale int    // -1 if not advertised
	tcpSACK        bool
	tcpOptionKinds []uint8
	// ICMP echo flow key members (§5): type + id distinguish echo flows.
	icmpType uint8
	icmpCode uint8
	icmpID   uint16
	icmpSeq  uint16
	// ICMPv6 (D-PARSE-1 P0)：镜像 v4 面
	icmp6Type, icmp6Code uint8
	icmp6ID, icmp6Seq    uint16
	// ARP flow key members (§5): sender/target protocol address + operation.
	arpSenderIP net.IP
	arpTargetIP net.IP
	arpOp       uint16
	// P0 新传输面：ttl/dscp/ecn、udp len、igmp/ospf/pim type、L2 身份
	ttl, dscp, ecn uint8
	udpLen         uint16
	igmpType       uint8
	ospfType       uint8
	pimType        uint8
	l2EtherType    uint16
	l2SrcMAC       string
	l2DstMAC       string
	// VLAN/封装（D-PARSE-1 P0）：-1=无
	vlanOuter, vlanInner int
	encapType            string
	encapID              int64
	// TCP flags 位组装（包级列 TCPFlagsRaw/Str 用）
	tcpFlagsRaw uint8
	tcpFlagsStr string
}

// extractFields walks a gopacket.Packet's layers to pull the fields the parser
// needs. It is permissive: unknown/missing layers yield zero values rather than
// errors, so malformed packets are still indexed (byte-patch preserves them).
func extractFields(pkt gopacket.Packet) packetFields {
	f := packetFields{fragOffset: -1, vlanOuter: -1, vlanInner: -1, encapID: -1}
	if nl := pkt.NetworkLayer(); nl != nil {
		switch v := nl.(type) {
		case *layers.IPv4:
			f.srcIP = v.SrcIP
			f.dstIP = v.DstIP
			f.ipVersion = 4
			f.ipID = v.Id
			f.ipMF = v.Flags&layers.IPv4MoreFragments != 0
			f.ttl = v.TTL
			f.dscp = v.TOS >> 2
			f.ecn = v.TOS & 0x03
			if f.ipMF || v.FragOffset != 0 {
				f.fragGroupID = fmt.Sprintf("%d|%s|%s|%d", v.Id, v.SrcIP, v.DstIP, v.Protocol)
				f.fragOffset = int(v.FragOffset) // 8-byte units (§17.4)
				// gopacket returns nil TransportLayer for ANY fragment (it sets
				// NextLayerType=LayerTypeFragment), so f.l4Proto would stay "" and
				// the fragment would land in a synthetic raw|N flow. For a fully-
				// fragmented flow this loses all reassembled data (§8). Recover the
				// L4 protocol from the IP header, and for the FIRST fragment
				// (offset 0) parse the L4 ports from the IP payload so the fragment
				// groups into the real flow.
				switch v.Protocol {
				case layers.IPProtocolTCP:
					f.l4Proto = "tcp"
				case layers.IPProtocolUDP:
					f.l4Proto = "udp"
				}
				f.fragFirst = v.FragOffset == 0
				if f.fragFirst && len(v.Payload) >= 4 {
					f.srcPort = uint16(v.Payload[0])<<8 | uint16(v.Payload[1])
					f.dstPort = uint16(v.Payload[2])<<8 | uint16(v.Payload[3])
				}
			}
		case *layers.IPv6:
			f.srcIP = v.SrcIP
			f.dstIP = v.DstIP
			f.ipVersion = 6
			f.ttl = v.HopLimit
			f.dscp = v.TrafficClass >> 2
			f.ecn = v.TrafficClass & 0x03
		}
	}
	if tl := pkt.TransportLayer(); tl != nil {
		switch v := tl.(type) {
		case *layers.TCP:
			f.srcPort = uint16(v.SrcPort)
			f.dstPort = uint16(v.DstPort)
			f.l4Proto = "tcp"
			f.payload = v.Payload
			f.tcpSYN = v.SYN
			f.tcpACK = v.ACK
			f.tcpFIN = v.FIN
			f.tcpRST = v.RST
			f.tcpPSH = v.PSH
			f.tcpSeq = v.Seq
			f.tcpAckValue = v.Ack
			f.tcpWindow = v.Window
			f.tcpFlagsRaw, f.tcpFlagsStr = tcpFlagsPack(v)
			// SYN/SYN-ACK carry the options that matter for FlowModel (MSS,
			// WindowScale, SACK). Parse them here so recordTCPStats can record
			// them on the handshake packets (§7).
			if v.SYN {
				f.tcpOptionKinds = make([]uint8, 0, len(v.Options))
				for _, opt := range v.Options {
					f.tcpOptionKinds = append(f.tcpOptionKinds, uint8(opt.OptionType))
					switch opt.OptionType {
					case 2: // MSS (kind 2): 2-byte value
						if len(opt.OptionData) == 2 {
							f.tcpMSS = uint16(opt.OptionData[0])<<8 | uint16(opt.OptionData[1])
						}
					case 3: // Window Scale (kind 3): 1-byte shift count
						if len(opt.OptionData) == 1 {
							f.tcpWindowScale = int(int8(opt.OptionData[0]))
						}
					case 4: // SACK Permitted (kind 4)
						f.tcpSACK = true
					}
				}
			}
		case *layers.UDP:
			f.srcPort = uint16(v.SrcPort)
			f.dstPort = uint16(v.DstPort)
			f.l4Proto = "udp"
			f.payload = v.Payload
			f.udpLen = v.Length
		case *layers.SCTP:
			// SCTP（D-PARSE-1 P0 收口：此前 l4Proto="" 逐包 raw 化）
			f.srcPort = uint16(v.SrcPort)
			f.dstPort = uint16(v.DstPort)
			f.l4Proto = "sctp"
			f.payload = v.Payload
		}
	}
	// ICMPv4/v6 and ARP don't expose a TransportLayer/NetworkLayer; detect
	// directly so their flow keys use the right fields.
	if icmp := pkt.Layer(layers.LayerTypeICMPv4); icmp != nil {
		f.l4Proto = "icmp"
		if v, ok := icmp.(*layers.ICMPv4); ok {
			f.icmpType = v.TypeCode.Type()
			f.icmpCode = v.TypeCode.Code()
			f.icmpID = v.Id
			f.icmpSeq = v.Seq
			f.payload = v.Payload
		}
	}
	// ICMPv6（D-PARSE-1 P0 收口：镜像 v4 面；echo id/seq 在 ICMPv6Echo 层）
	if icmp6 := pkt.Layer(layers.LayerTypeICMPv6); icmp6 != nil {
		f.l4Proto = "icmpv6"
		if v, ok := icmp6.(*layers.ICMPv6); ok {
			f.icmp6Type = v.TypeCode.Type()
			f.icmp6Code = v.TypeCode.Code()
			f.payload = v.Payload
			if echo, ok := pkt.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo); ok {
				f.icmp6ID = echo.Identifier
				f.icmp6Seq = echo.SeqNumber
				f.payload = echo.Payload // echo data（4B id/seq 之后）
			}
		}
	}
	// IGMP/OSPF（IP proto 直载，NetworkLayer 之后 gopacket 解出专属层）
	if igmp := pkt.Layer(layers.LayerTypeIGMP); igmp != nil {
		f.l4Proto = "igmp"
		if v, ok := igmp.(*layers.IGMP); ok {
			f.igmpType = uint8(v.Type)
			f.payload = v.Payload
		}
	}
	// OSPF/PIM（gopacket v1.1.19 均无可断言解码层）：IP proto 原始分支。
	// OSPF type=payload[1]（version(1)+type(1)，RFC 2328 §4.1）；
	// PIM type=首字节低 4 位（高 4 位版本，RFC 7761 §4）。
	if f.l4Proto == "" {
		if v4, ok := pkt.NetworkLayer().(*layers.IPv4); ok {
			switch v4.Protocol {
			case layers.IPProtocol(89):
				f.l4Proto = "ospf"
				f.payload = v4.Payload
				if len(v4.Payload) > 1 {
					f.ospfType = v4.Payload[1]
				}
			case layers.IPProtocol(103):
				f.l4Proto = "pim"
				f.payload = v4.Payload
				if len(v4.Payload) > 0 {
					f.pimType = v4.Payload[0] & 0x0F
				}
			}
		}
	}
	if arp := pkt.Layer(layers.LayerTypeARP); arp != nil {
		f.l4Proto = "arp"
		if v, ok := arp.(*layers.ARP); ok {
			f.arpOp = v.Operation
			// SourceProtAddress/DstProtAddress are raw bytes (4 for IPv4 ARP).
			if len(v.SourceProtAddress) == 4 {
				f.arpSenderIP = net.IP(v.SourceProtAddress)
			}
			if len(v.DstProtAddress) == 4 {
				f.arpTargetIP = net.IP(v.DstProtAddress)
			}
			f.payload = v.Payload // L2 载荷（通常零长；hash 口径统一）
		}
	}
	// L2-only（goose 0x88B5/sv 0x88BA/isis LLC，D-PARSE-1 P0 收口）：无 IP 层，
	// 按 EtherType+MAC 对分组；payload=L2 载荷（hash 口径统一）
	if f.l4Proto == "" {
		if eth, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
			// 0x88B5=goose(IEC 61850 GOOSE)/0x88BA=sv(采样值) gopacket 未命名，
			// 用原始值；LLC=isis（IEEE 802.3 长度字段，gopacket 标 EthernetTypeLLC=0）
			switch eth.EthernetType {
			case layers.EthernetType(0x88B5), layers.EthernetType(0x88BA), layers.EthernetTypeLLC:
				f.l4Proto = "l2"
				f.l2EtherType = uint16(eth.EthernetType)
				f.l2SrcMAC = eth.SrcMAC.String()
				f.l2DstMAC = eth.DstMAC.String()
				f.payload = eth.Payload
			}
		}
	}
	// IPv6 分片分组（D-PARSE-1 P0：v4 既有/v6 本批补；重组进 assembler 随
	// P1 批，本批只修流身份）。gopacket 对分片头 NextDecoder(DecodeFragment)
	// 停止链式解码——首片 L4 端口从分片头后手工取（与 v4 首片同口径）。
	if frag6, ok := pkt.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment); ok {
		f.fragGroupID = fmt.Sprintf("v6|%d|%s|%s", frag6.Identification, f.srcIP, f.dstIP)
		f.fragOffset = int(frag6.FragmentOffset) // 8 字节单位，与 v4 同口径
		f.fragFirst = frag6.FragmentOffset == 0
		if f.fragFirst && f.l4Proto == "" {
			rest := frag6.Payload
			if len(rest) >= 4 {
				ports := func() (uint16, uint16) {
					return uint16(rest[0])<<8 | uint16(rest[1]), uint16(rest[2])<<8 | uint16(rest[3])
				}
				switch frag6.NextHeader {
				case layers.IPProtocolTCP:
					f.l4Proto = "tcp"
					f.srcPort, f.dstPort = ports()
				case layers.IPProtocolUDP:
					f.l4Proto = "udp"
					f.srcPort, f.dstPort = ports()
				}
			}
		}
	}
	// VLAN/封装检测（D-PARSE-1 P0）：Dot1Q 单层/QinQ 双层取值 + 封装标记
	dot1qSeen := 0
	for _, ly := range pkt.Layers() {
		switch v := ly.(type) {
		case *layers.Dot1Q:
			dot1qSeen++
			if dot1qSeen == 1 {
				f.vlanOuter = int(v.VLANIdentifier)
			} else if dot1qSeen == 2 {
				f.vlanInner = int(v.VLANIdentifier)
			}
		case *layers.MPLS:
			f.encapType = "mpls"
		case *layers.PPPoE:
			f.encapType = "pppoe"
			f.encapID = int64(v.SessionId)
		case *layers.VXLAN:
			f.encapType = "vxlan"
			f.encapID = int64(v.VNI & 0xFFFFFF)
		case *layers.GTPv1U:
			f.encapType = "gtp"
			f.encapID = int64(v.TEID)
		case *layers.Geneve:
			f.encapType = "geneve"
			f.encapID = int64(v.VNI & 0xFFFFFF)
		case *layers.GRE:
			f.encapType = "gre"
		}
	}
	return f
}

// tcpFlagsPack assembles the wire flags byte and the "SYN,ACK" style string
// (包级列 TCPFlagsRaw/Str 用).
func tcpFlagsPack(v *layers.TCP) (uint8, string) {
	var raw uint8
	var s string
	add := func(set bool, bit uint8, name string) {
		if set {
			raw |= bit
			if s != "" {
				s += ","
			}
			s += name
		}
	}
	add(v.FIN, 0x01, "FIN")
	add(v.SYN, 0x02, "SYN")
	add(v.RST, 0x04, "RST")
	add(v.PSH, 0x08, "PSH")
	add(v.ACK, 0x10, "ACK")
	add(v.URG, 0x20, "URG")
	add(v.ECE, 0x40, "ECE")
	add(v.CWR, 0x80, "CWR")
	return raw, s
}

// computeFlowKey derives the bidirectional-normalized flow key from parsed
// fields. Returns "" for protocols we don't group (e.g. unknown L2).
func computeFlowKey(f packetFields) string {
	switch f.l4Proto {
	case "tcp":
		return flowKeyTCPUDP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 6)
	case "udp":
		return flowKeyTCPUDP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 17)
	case "icmp":
		return flowKeyICMP(f.srcIP, f.dstIP, f.icmpID)
	case "arp":
		return flowKeyARP(f.arpSenderIP, f.arpTargetIP, f.arpOp)
	case "icmpv6":
		return flowKeyICMPProto(f.srcIP, f.dstIP, 58, f.icmp6ID)
	case "sctp":
		return flowKeyTCPUDP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 132)
	case "igmp", "ospf", "pim":
		// 无端口直载协议：proto|端点序|type 分组（RFC 3376/2328/7761 面）
		t := f.igmpType
		proto := 2
		if f.l4Proto == "ospf" {
			t, proto = f.ospfType, 89
		} else if f.l4Proto == "pim" {
			t, proto = f.pimType, 103
		}
		a, b := f.srcIP.String(), f.dstIP.String()
		if strings.Compare(a, b) > 0 {
			a, b = b, a
		}
		return fmt.Sprintf("%d|%s|%s|%d", proto, a, b, t)
	case "l2":
		a, b := f.l2SrcMAC, f.l2DstMAC
		if strings.Compare(a, b) > 0 {
			a, b = b, a
		}
		return fmt.Sprintf("l2|%d|%s|%s", f.l2EtherType, a, b)
	default:
		return ""
	}
}

// flowKeyICMPProto generalizes the ICMP flow key to any IP protocol carrying
// echo id semantics (icmp=1 / icmpv6=58; D-PARSE-1 P0). Type 不入 key（见
// flowKeyICMP 注）。
func flowKeyICMPProto(srcIP, dstIP net.IP, proto uint8, id uint16) string {
	a, b := srcIP.String(), dstIP.String()
	if strings.Compare(a, b) > 0 {
		a, b = b, a
	}
	return fmt.Sprintf("%d|%s|%s|%d", proto, a, b, id)
}

// payloadHash returns the hex-encoded sha256 of the L4 payload, or "" when the
// payload is empty (so pure-ACK packets have an empty hash, distinct from the
// hash of zero bytes).
func payloadHash(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// detectAnomaly classifies a packet's size anomalies (§8). frameLen is the
// ORIGINAL wire length (ci.Length) for jumbo/runt detection -- a frame truncated
// by snaplen to <64 bytes but padded on the wire to 64 is NOT a runt.
// capturedLen < originalLen means snaplen truncation.
func detectAnomaly(frameLen, capturedLen, originalLen int) string {
	switch {
	case capturedLen < originalLen:
		return "truncated"
	case frameLen > 1518:
		return "oversize"
	case frameLen < 64:
		return "undersize"
	default:
		return ""
	}
}
