package pcapparser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// P0 公共面测试（D-PARSE-1 / T-PARSE-1e…1j）。断言口径：流级列与包级列的
// 期望值全部来自测试内独立计算（sha256 逐帧现算），不抄实现内部状态。

func buildVLANFrame(t *testing.T, outer, inner uint16, ipv4ThenTCP bool) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, Window: 1000, PSH: true, ACK: true}
	tcp.SetNetworkLayerForChecksum(ipv4)
	frame := []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeDot1Q},
		&layers.Dot1Q{Priority: 3, VLANIdentifier: outer, Type: layers.EthernetTypeDot1Q},
	}
	if inner > 0 {
		frame = append(frame, &layers.Dot1Q{Priority: 0, VLANIdentifier: inner, Type: layers.EthernetTypeIPv4})
	} else {
		frame[len(frame)-1] = &layers.Dot1Q{Priority: 3, VLANIdentifier: outer, Type: layers.EthernetTypeIPv4}
	}
	frame = append(frame, ipv4, tcp)
	if err := gopacket.SerializeLayers(buf, opts, frame...); err != nil {
		t.Fatalf("serialize vlan: %v", err)
	}
	return buf.Bytes()
}

// T-PARSE-1e：单层/QinQ VLAN 值流级落列 + OffsetLayout 双槽（QinQ 双层此前
// 互相覆盖只剩内层，D-PARSE-1 P0 修复面）。
func parseOne(t *testing.T, frame []byte) []storage.FlowModel {
	t.Helper()
	path := writePcap(t, [][]byte{frame}, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return analysis.Flows
}

func TestParse_VLANValues(t *testing.T) {
	// vlan 是流级常量（封装恒定原则）：单层/QinQ 各自独立 pcap 验证
	singleFlow, qinqFlow := &parseOne(t, buildVLANFrame(t, 100, 0, true))[0],
		&parseOne(t, buildVLANFrame(t, 100, 200, true))[0]
	if singleFlow.VlanIDOuter != 100 || singleFlow.VlanIDInner != -1 {
		t.Errorf("single: outer=%d inner=%d, want 100/-1", singleFlow.VlanIDOuter, singleFlow.VlanIDInner)
	}
	if qinqFlow.VlanIDOuter != 100 || qinqFlow.VlanIDInner != 200 {
		t.Errorf("qinq: outer=%d inner=%d, want 100/200", qinqFlow.VlanIDOuter, qinqFlow.VlanIDInner)
	}
	// 包级 vlan 无列（流级语义，封装恒定）；校验 layout 双槽
	var layout OffsetLayout
	if err := json.Unmarshal([]byte(qinqFlow.OffsetLayout), &layout); err != nil {
		t.Fatalf("layout: %v", err)
	}
	if layout.VlanTCO == -1 || layout.VlanTCOInner == -1 {
		t.Errorf("qinq layout tco/inner = %d/%d, want 两槽", layout.VlanTCO, layout.VlanTCOInner)
	}
	if err := json.Unmarshal([]byte(singleFlow.OffsetLayout), &layout); err != nil {
		t.Fatalf("layout: %v", err)
	}
	if layout.VlanTCO == -1 || layout.VlanTCOInner != -1 {
		t.Errorf("single layout tco/inner = %d/%d, want inner=-1", layout.VlanTCO, layout.VlanTCOInner)
	}
}

// buildSCTPChunks serializes INIT + DATA chunks (RFC 4960 §3.1 wire format).
func buildSCTPChunks() []byte {
	// INIT chunk: type=1, flags=0, len=20 (含 4B 头 + InitiateTag4+a_rwnd4+OS2+MIS2+TSN4)
	init := []byte{1, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0x20, 0x00, 0, 10, 0, 65535 >> 8 & 0xff, 0, 1, 0, 2}
	// DATA chunk: type=0, flags=3 (UB+E), len=16+len(data), TSN4+SID2+SSN2+PPID4
	data := []byte("hello sctp")
	dc := append([]byte{0, 3, 0, byte(16 + len(data)), 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0}, data...)
	out := append(init, dc...)
	return out
}

func buildSCTPFrame(t *testing.T, chunks []byte) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolSCTP}
	sctp := &layers.SCTP{SrcPort: 3000, DstPort: 38412}
	frame := []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4,
		sctp,
		gopacket.Payload(chunks),
	}
	if err := gopacket.SerializeLayers(buf, opts, frame...); err != nil {
		t.Fatalf("serialize sctp: %v", err)
	}
	return buf.Bytes()
}

// T-PARSE-1 SCTP：分组收口（此前逐包 raw 化）+ chunk 面聚合 + 关联状态。
func TestParse_SCTPFlowChunks(t *testing.T) {
	chunks := buildSCTPChunks()
	path := writePcap(t, [][]byte{buildSCTPFrame(t, chunks)}, []time.Time{time.UnixMicro(1)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if analysis.FlowCount != 1 {
		t.Fatalf("sctp must group into 1 flow, got %d (raw 化 bug)", analysis.FlowCount)
	}
	f := analysis.Flows[0]
	if f.L4Protocol != "sctp" {
		t.Fatalf("L4Protocol = %q, want sctp", f.L4Protocol)
	}
	if f.SctpChunkTypes != "[1,0]" {
		t.Errorf("SctpChunkTypes = %q, want [1,0]", f.SctpChunkTypes)
	}
	if f.SctpAssocState != "established" {
		t.Errorf("SctpAssocState = %q, want established (INIT+DATA)", f.SctpAssocState)
	}
	// DATA bytes = (16+len(data)) - 16 = len(data)
	if f.SctpDataBytes != int64(len("hello sctp")) {
		t.Errorf("SctpDataBytes = %d, want %d", f.SctpDataBytes, len("hello sctp"))
	}
}

// T-PARSE-1f：双向载荷 hash/预览（TCP=重组流，UDP=载荷聚合）+ 包级 PayloadHash。
func TestParse_PayloadHashPreview(t *testing.T) {
	c2sPayload := []byte("client request body bytes")
	s2cPayload := []byte("server response body bytes, longer for preview fill")
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 1, flagPSH|flagACK, c2sPayload),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 102, flagPSH|flagACK, s2cPayload),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(analysis.Flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(analysis.Flows))
	}
	f := analysis.Flows[0]
	sum := sha256.Sum256(c2sPayload)
	if f.C2SPayloadHash != hex.EncodeToString(sum[:]) {
		t.Errorf("C2SPayloadHash mismatch")
	}
	sum = sha256.Sum256(s2cPayload)
	if f.S2CPayloadHash != hex.EncodeToString(sum[:]) {
		t.Errorf("S2CPayloadHash mismatch")
	}
	// 预览：hex 前缀 + " | " + ascii 视图，内容以载荷开头
	if !strings.HasPrefix(f.C2SPayloadPreview, hex.EncodeToString(c2sPayload)) {
		t.Errorf("C2SPayloadPreview = %q, want hex prefix of payload", f.C2SPayloadPreview)
	}
	if !strings.HasSuffix(f.C2SPayloadPreview, string(c2sPayload)) {
		t.Errorf("C2SPayloadPreview ascii tail mismatch: %q", f.C2SPayloadPreview)
	}
	// body 无解析器边界 → body=stream（错误表回落规则）
	if f.C2SBodyHash != f.C2SPayloadHash {
		t.Errorf("C2SBodyHash must equal payload hash when no parser boundary")
	}
	// 包级 PayloadHash
	sum = sha256.Sum256(c2sPayload)
	for _, p := range analysis.Packets {
		if p.PayloadLen == len(c2sPayload) && p.PayloadHash != hex.EncodeToString(sum[:]) {
			t.Errorf("packet PayloadHash mismatch for data packet")
		}
	}

	// UDP：载荷域聚合（两包同向拼接摘要）
	u1 := []byte("udp-one-")
	u2 := []byte("udp-two!")
	uf := [][]byte{
		buildUDPFrame(t, macA, macB, ipA, ipB, 5353, 40000, u1),
		buildUDPFrame(t, macA, macB, ipA, ipB, 5353, 40000, u2),
	}
	path = writePcap(t, uf, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	analysis, err = Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse udp: %v", err)
	}
	sum = sha256.Sum256(append(append([]byte{}, u1...), u2...))
	if analysis.Flows[0].C2SPayloadHash != hex.EncodeToString(sum[:]) {
		t.Errorf("UDP C2SPayloadHash = aggregated-payload digest mismatch")
	}
	if analysis.Flows[0].C2SBodyHash != analysis.Flows[0].C2SPayloadHash {
		t.Errorf("UDP body=payload 口径不一致")
	}
}

// T-PARSE-1h：包级常用头字段列。
func TestParse_PacketHeaderColumns(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildUDPFrame(t, macA, macB, ipA, ipB, 5353, 40000, []byte("x")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	syn, udp := analysis.Packets[0], analysis.Packets[1]
	if syn.TCPSeq != 100 || syn.TCPAck != 0 || syn.TCPWindow != 65535 {
		t.Errorf("tcp seq/ack/window = %d/%d/%d, want 100/0/65535", syn.TCPSeq, syn.TCPAck, syn.TCPWindow)
	}
	if syn.TCPFlagsRaw != flagSYN || syn.TCPFlagsStr != "SYN" {
		t.Errorf("tcp flags raw/str = %#x/%q, want 0x02/SYN", syn.TCPFlagsRaw, syn.TCPFlagsStr)
	}
	if syn.TTL != 64 || syn.PayloadLen != 0 {
		t.Errorf("ttl/payload_len = %d/%d, want 64/0", syn.TTL, syn.PayloadLen)
	}
	if udp.UDPLen != 8+1 {
		t.Errorf("udp len = %d, want 9", udp.UDPLen)
	}
	if udp.TCPFlagsStr != "" || udp.TCPSeq != 0 {
		t.Errorf("udp 包 tcp 面必须零值: flags=%q seq=%d", udp.TCPFlagsStr, udp.TCPSeq)
	}
}

// T-PARSE-1i：TCP 纯握手（零载荷）→ handshake_only；载荷 hash 空串口径。
func TestParse_HandshakeOnlyTCP(t *testing.T) {
	frames := [][]byte{
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 100, 0, flagSYN, nil),
		buildTCPFrame(t, macB, macA, ipB, ipA, 80, 1234, 200, 101, flagSYN|flagACK, nil),
		buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagACK, nil),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2), time.UnixMicro(3)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f := analysis.Flows[0]
	if f.L7Protocol != "handshake_only" {
		t.Errorf("L7Protocol = %q, want handshake_only", f.L7Protocol)
	}
	if f.C2SPayloadHash != "" || f.S2CPayloadHash != "" {
		t.Errorf("零载荷 hash 必须为空串: %q/%q", f.C2SPayloadHash, f.S2CPayloadHash)
	}
	if f.HandshakeStatus != "complete" {
		t.Errorf("HandshakeStatus = %q, want complete", f.HandshakeStatus)
	}
}

// T-PARSE-1 ICMP 族流级聚合：echo req/reply (id,seq) + 包级 icmp 列。
func TestParse_ICMPAggregateAndPacketColumns(t *testing.T) {
	echoReq := buildICMPv4Frame(t, 8, 0, 0x42, 7, []byte("data"))
	echoReply := buildICMPv4Frame(t, 0, 0, 0x42, 7, []byte("data"))
	path := writePcap(t, [][]byte{echoReq, echoReply}, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f := analysis.Flows[0]
	if f.L4Protocol != "icmp" || analysis.FlowCount != 1 {
		t.Fatalf("icmp grouping broken: %d flows / %s", analysis.FlowCount, f.L4Protocol)
	}
	if f.ICMPType != 8 || f.ICMPCode != 0 || f.ICMPID != 0x42 || f.ICMPSeq != 7 {
		t.Errorf("icmp aggregate = %d/%d/%d/%d, want 8/0/0x42/7", f.ICMPType, f.ICMPCode, f.ICMPID, f.ICMPSeq)
	}
	sum := sha256.Sum256([]byte("data"))
	for _, p := range analysis.Packets {
		if p.ICMPType == 8 || p.ICMPType == 0 {
			if p.ICMPID != 0x42 || p.ICMPSeq != 7 {
				t.Errorf("packet icmp id/seq = %#x/%d, want 0x42/7", p.ICMPID, p.ICMPSeq)
			}
			if p.PayloadHash != hex.EncodeToString(sum[:]) {
				t.Errorf("icmp echo data hash mismatch")
			}
		}
	}
}

func buildICMPv4Frame(t *testing.T, icmpType, icmpCode uint8, ident, seq uint16, data []byte) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4}
	icmp := &layers.ICMPv4{TypeCode: layers.ICMPv4TypeCode(uint16(icmpType)<<8 | uint16(icmpCode)), Id: ident, Seq: seq}
	frame := []gopacket.SerializableLayer{
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4,
		icmp,
	}
	if len(data) > 0 {
		frame = append(frame, gopacket.Payload(data))
	}
	if err := gopacket.SerializeLayers(buf, opts, frame...); err != nil {
		t.Fatalf("serialize icmp: %v", err)
	}
	return buf.Bytes()
}

// T-PARSE-1 IPv6 分片分组：首片带端口建流，非首片经 fragFlowMap 归并同流
// （v6| 前缀与 v4 ipID 空间隔离）。重组进 assembler 随 P1 批（D-PARSE-1
// 矩阵②如实注记），本批断言流身份唯一。
func TestParse_IPv6FragmentFlowGrouping(t *testing.T) {
	buildFrag := func(offset8, ident uint32, more bool, after []byte) []byte {
		t.Helper()
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true}
		// IPv6Fragment 无 SerializeTo：分片头 8B 手工拼（RFC 8200 §4.5：
		// nextHeader(1)+reserved(1)+offset13|r2|M 位域+ident(4)）
		frag := make([]byte, 8)
		frag[0] = 17 // nextHeader=UDP
		f16v := uint16(offset8) << 3
		if more {
			f16v |= 1 // M 位（RFC 8200 §4.5 bit 0）
		}
		frag[2], frag[3] = byte(f16v>>8), byte(f16v)
		frag[4], frag[5], frag[6], frag[7] = byte(ident>>24), byte(ident>>16), byte(ident>>8), byte(ident)
		if offset8 == 0 {
			// 首片：分片头后是 UDP 头(8B)+载荷
			udp := make([]byte, 8)
			udp[0], udp[1] = 0x30, 0x39 // src 12345
			udp[2], udp[3] = 0x30, 0x30 // dst 12336
			after = append(udp, after...)
		}
		frame := []gopacket.SerializableLayer{
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv6},
			&layers.IPv6{SrcIP: net.ParseIP("fd00::a"), DstIP: net.ParseIP("fd00::b"),
				Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: 64},
			gopacket.Payload(append(frag, after...)),
		}
		if err := gopacket.SerializeLayers(buf, opts, frame...); err != nil {
			t.Fatalf("serialize frag: %v", err)
		}
		return buf.Bytes()
	}
	frames := [][]byte{
		buildFrag(0, 0x77, true, []byte("first-fragment-payload")),
		buildFrag(16, 0x77, false, []byte("last-fragment-payload")),
	}
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if analysis.FlowCount != 1 {
		t.Fatalf("v6 分片两包必须归同流, got %d flows", analysis.FlowCount)
	}
	f := analysis.Flows[0]
	if f.L4Protocol != "udp" || f.SrcPort != 12345 {
		t.Errorf("首片端口提取: l4=%s sport=%d, want udp/12345", f.L4Protocol, f.SrcPort)
	}
}
