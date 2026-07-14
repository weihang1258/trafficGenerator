// Package pcapparser reads pcap files and produces structured flow/packet
// models for asset viewing (§15) and replay (§16). The pcap file on disk is
// the source of truth; this package produces pointers + aggregates (§17).
package pcapparser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// flowKeyICMP normalizes an ICMP flow as (proto, min(ip), max(ip), type, id).
// Echo requests/replies share a flow by id; the two directions normalize via
// IP ordering.
func flowKeyICMP(srcIP, dstIP net.IP, icmpType uint8, id uint16) string {
	a, b := srcIP.String(), dstIP.String()
	if strings.Compare(a, b) > 0 {
		a, b = b, a
	}
	return fmt.Sprintf("1|%s|%s|%d|%d", a, b, icmpType, id)
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
}

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
	fs.FlowModel.L7Protocol = res.Protocol
	if data, err := json.Marshal(res.Metadata); err == nil {
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
	payloadLen := uint32(len(f.payload))
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
	tcpSeq uint32
	// TCP window + SYN-carried options (§7). Window is tracked per packet for
	// WindowRange; MSS/WindowScale/SACK/option-kinds come from SYN/SYN-ACK only.
	tcpWindow      uint16
	tcpMSS         uint16 // 0 if not advertised
	tcpWindowScale int    // -1 if not advertised
	tcpSACK        bool
	tcpOptionKinds []uint8
	// ICMP echo flow key members (§5): type + id distinguish echo flows.
	icmpType uint8
	icmpID   uint16
	// ARP flow key members (§5): sender/target protocol address + operation.
	arpSenderIP net.IP
	arpTargetIP net.IP
	arpOp       uint16
}

// extractFields walks a gopacket.Packet's layers to pull the fields the parser
// needs. It is permissive: unknown/missing layers yield zero values rather than
// errors, so malformed packets are still indexed (byte-patch preserves them).
func extractFields(pkt gopacket.Packet) packetFields {
	f := packetFields{fragOffset: -1}
	if nl := pkt.NetworkLayer(); nl != nil {
		switch v := nl.(type) {
		case *layers.IPv4:
			f.srcIP = v.SrcIP
			f.dstIP = v.DstIP
			f.ipVersion = 4
			f.ipID = v.Id
			f.ipMF = v.Flags&layers.IPv4MoreFragments != 0
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
			f.tcpWindow = v.Window
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
		}
	}
	// ICMPv4/v6 and ARP don't expose a TransportLayer/NetworkLayer; detect
	// directly so their flow keys use the right fields.
	if icmp := pkt.Layer(layers.LayerTypeICMPv4); icmp != nil {
		f.l4Proto = "icmp"
		if v, ok := icmp.(*layers.ICMPv4); ok {
			f.icmpType = v.TypeCode.Type()
			f.icmpID = v.Id
			f.payload = v.Payload
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
		}
	}
	return f
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
		return flowKeyICMP(f.srcIP, f.dstIP, f.icmpType, f.icmpID)
	case "arp":
		return flowKeyARP(f.arpSenderIP, f.arpTargetIP, f.arpOp)
	default:
		return ""
	}
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
