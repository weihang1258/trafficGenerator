package core

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestWriteSRH_PadNLengthByteConversion 验证 H2 修复：writeSRH 中
// `pad - 2` 的 int→byte 类型转换。当 pad 为 8 时，`pad - 2 = 6`，必须
// 正确写入字节 6 而非因类型问题导致编译错误或错误值。
//
// 构造场景：1 段 + 自定义 TLV(Type=200, Value=2 字节) → SRH base = 8+16+4 = 28，
// 尾部需 4 字节 PadN 对齐到 32。PadN Length 字段应为 4-2 = 2。
func TestWriteSRH_PadNLengthByteConversion(t *testing.T) {
	srh := &SRHConfig{
		NextHeader:   17,
		HdrExtLen:    3, // 32/8 - 1
		SegmentsLeft: 0,
		LastEntry:    0,
		Flags:        0,
		Tag:          0,
		SegmentList:  [][16]byte{parseIPv6Bytes(t, "fc00::1")},
		TLV: []SRv6TLV{
			{Type: 200, Value: []byte{0xab, 0xcd}},
		},
	}
	dst := make([]byte, srhHeaderLen(srh))
	b := NewBuilder()
	b.writeSRH(dst, srh)

	// SRH 布局：[0..8] 固定头, [8..24] 段, [24..28] 自定义 TLV (type=200,len=2,val=ab cd),
	// [28..32] PadN (type=4, len=2, val=00 00)。
	if dst[28] != 0x04 {
		t.Errorf("PadN type = 0x%02x, want 0x04", dst[28])
	}
	if dst[29] != 0x02 {
		t.Errorf("PadN length = 0x%02x, want 0x02 (pad=4, pad-2=2)", dst[29])
	}
}

// TestWriteSRH_HMACPad1Alignment 验证 C2 修复：HMAC TLV 前 1 字节空缺
// 必须用 Pad1（0x00）填充，而非 PadN。原代码 `if pad < 2 { pad = 8 }`
// 会插入 8 字节 PadN 且根本不对齐（offset 从 7 变到 15 仍 mod 8 = 7）。
//
// 构造场景：1 段 + 自定义 TLV(Type=200, Value=1 字节) → TLV 前 offset = 24+3 = 27，
// HMAC 前需对齐到 8n → pad = 1 → 必须用 Pad1（0x00 单字节）。
func TestWriteSRH_HMACPad1Alignment(t *testing.T) {
	srh := &SRHConfig{
		NextHeader:   17,
		SegmentsLeft: 0,
		LastEntry:    0,
		Flags:        0,
		Tag:          0,
		SegmentList:  [][16]byte{parseIPv6Bytes(t, "fc00::1")},
		TLV: []SRv6TLV{
			// 自定义 TLV 占 3 字节，让后续 HMAC 前偏移 = 24+3 = 27 (mod 8 = 3, pad = 5)
			// 改为 2 字节让 HMAC 前偏移 = 24+4 = 28 (mod 8 = 4, pad = 4)
			// 用 5 字节让 HMAC 前偏移 = 24+7 = 31 (mod 8 = 7, pad = 1) → Pad1
			{Type: 200, Value: []byte{0xab, 0xcd, 0xef, 0x12, 0x34}},
			{Type: 5, Value: make([]byte, 32)}, // HMAC TLV
		},
	}
	// 验证 srhHeaderLen 与 writeSRH 一致：HMAC 前 pad=1 应加 1 字节 Pad1
	expectLen := 8 + 16 + 7 + 1 + 2 + 32 // base + seg + customTLV + Pad1 + HMAC(T+L) + HMAC(V)
	// tail alignment: expectLen = 66, mod 8 = 2, pad = 6 (PadN)
	expectLen += 6
	if got := srhHeaderLen(srh); got != expectLen {
		t.Fatalf("srhHeaderLen = %d, want %d", got, expectLen)
	}

	dst := make([]byte, srhHeaderLen(srh))
	b := NewBuilder()
	b.writeSRH(dst, srh)

	// 偏移：8(base) + 16(seg) = 24；customTLV 7 字节 → offset = 31
	// Pad1 在 offset 31（单字节 0x00）
	if dst[31] != 0x00 {
		t.Errorf("Pad1 byte at offset 31 = 0x%02x, want 0x00 (Pad1 for 1-byte gap)", dst[31])
	}
	// HMAC TLV 在 offset 32（8n 对齐）
	if dst[32] != 0x05 {
		t.Errorf("HMAC TLV type at offset 32 = 0x%02x, want 0x05 (must be 8n-aligned)", dst[32])
	}
}

// TestBuild_HopByHopAndSRH_Offset 验证 H1 修复：当 HopByHop + SRH 同时存在时，
// SRH 必须紧跟 HopByHop 之后（offset = l2End + 40 + hbhoLen），而非 l2End+ipLen
// （ipLen 包含 srhLen 自身，会指向 SRH 末尾之后，导致越界或写到 L4 区域）。
func TestBuild_HopByHopAndSRH_Offset(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: EtherTypeIPv6,
		},
		L3: L3Config{
			SrcIP:    "fc00:1::1",
			DstIP:    "fc00:11::1",
			Protocol: 43, // Routing (SRH)
			TTL:      64,
			HopByHop: []IPv6Option{
				{Type: 5, Value: []byte{0x00, 0x00}}, // Router Alert
			},
			SRH: &SRHConfig{
				NextHeader:   17,
				HdrExtLen:    2,
				SegmentsLeft: 0,
				LastEntry:    0,
				Flags:        0,
				Tag:          0,
				SegmentList:  [][16]byte{parseIPv6Bytes(t, "fc00:11::1")},
			},
		},
		L4: L4Config{
			Protocol: "udp",
			SrcPort:  12345,
			DstPort:  53,
		},
		Payload: []byte("ping"),
	}

	pkt, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// 帧长 = 14 (Eth) + 40 (IPv6 fixed) + 8 (HBH) + 24 (SRH) + 8 (UDP) + 4 (payload) = 98
	if len(pkt) != 98 {
		t.Errorf("frame length = %d, want 98", len(pkt))
	}

	// IPv6 NextHeader at offset 20 = 0 (HopByHop)
	if pkt[20] != 0x00 {
		t.Errorf("IPv6 NextHeader = 0x%02x, want 0x00 (HopByHop)", pkt[20])
	}

	// HopByHop at offset 54 (14+40). HBH NextHeader = 43 (Routing/SRH).
	if pkt[54] != 43 {
		t.Errorf("HopByHop NextHeader = %d, want 43 (Routing)", pkt[54])
	}

	// SRH at offset 62 (14+40+8). SRH NextHeader = 17 (UDP).
	// H1 bug: 修复前 srhStart = l2End+ipLen = 14+72 = 86，写到 UDP 区域。
	if pkt[62] != 17 {
		t.Errorf("SRH NextHeader at offset 62 = %d, want 17 (UDP)", pkt[62])
	}
	// SRH RoutingType at offset 64 = 4
	if pkt[64] != 4 {
		t.Errorf("SRH RoutingType at offset 64 = %d, want 4", pkt[64])
	}

	// UDP at offset 86 (14+40+8+24). UDP SrcPort = 12345.
	// H1 bug: 修复前 SRH 写到 offset 86 覆盖了 UDP 头部。
	if got := binary.BigEndian.Uint16(pkt[86:88]); got != 12345 {
		t.Errorf("UDP SrcPort at offset 86 = %d, want 12345 (H1: SRH must not overwrite UDP)", got)
	}
}

// TestBuild_SRH_PseudoHeaderDstIsFinalDestination 验证 C1 修复：当 SRH 存在时，
// L4 (UDP/TCP) 伪头 DstIP 必须为最终目的地（wire SegmentList[0]），而非外层
// IPv6 DstIP。reduced SRH 下外层 DstIP 是首段，不是最终目的地，伪头用错地址
// 会导致校验和错误被 IPv6 栈丢弃。
func TestBuild_SRH_PseudoHeaderDstIsFinalDestination(t *testing.T) {
	builder := NewBuilder()

	// Reduced SRH：外层 DstIP = S1（首段），wire SegmentList[0] = S2（最终目的地）。
	// 伪头必须用 S2，不是 S1。
	finalDst := parseIPv6Bytes(t, "fc00:22::1") // wire SegmentList[0] = 最终目的地
	srh := &SRHConfig{
		NextHeader:   17,
		HdrExtLen:    2,
		SegmentsLeft: 1,
		LastEntry:    0,
		Flags:        0,
		Tag:          0,
		SegmentList:  [][16]byte{finalDst},
	}

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: EtherTypeIPv6,
		},
		L3: L3Config{
			SrcIP:    "fc00:1::1",
			DstIP:    "fc00:11::1", // 外层 DstIP = 首段（reduced）
			Protocol: 43,
			TTL:      64,
			SRH:      srh,
		},
		L4: L4Config{
			Protocol: "udp",
			SrcPort:  12345,
			DstPort:  53,
		},
		Payload: []byte("ping"),
	}

	pkt, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// UDP 在 offset 14+40+24 = 78。UDP checksum 在 offset 78+6 = 84。
	udpChecksum := binary.BigEndian.Uint16(pkt[84:86])
	if udpChecksum == 0 {
		t.Fatal("UDP checksum = 0 on IPv6 (RFC 6936 forbids this)")
	}

	// 用最终目的地 S2 手动重算伪头校验和，必须与帧中一致。
	// 用 S1（外层 DstIP）重算则必须不一致——证明伪头用的是 S2。
	sumWithFinal := computeUDPChecksumManual(t,
		net.ParseIP("fc00:1::1"), net.ParseIP("fc00:22::1"),
		12345, 53, 8+4, []byte("ping"))
	sumWithOuter := computeUDPChecksumManual(t,
		net.ParseIP("fc00:1::1"), net.ParseIP("fc00:11::1"),
		12345, 53, 8+4, []byte("ping"))

	if sumWithFinal != udpChecksum {
		t.Errorf("UDP checksum = 0x%04x, pseudo-header with final dst (S2) = 0x%04x, want match (C1: pseudo DstIP must be SegmentList[0])",
			udpChecksum, sumWithFinal)
	}
	if sumWithOuter == udpChecksum {
		t.Errorf("UDP checksum = 0x%04x matches pseudo-header with outer DstIP (S1) — C1 NOT fixed: pseudo DstIP should be SegmentList[0] (final), not outer",
			udpChecksum)
	}
}

// parseIPv6Bytes 解析 IPv6 字符串为 16 字节 [16]byte。
func parseIPv6Bytes(t *testing.T, s string) [16]byte {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid IPv6: %s", s)
	}
	ip = ip.To16()
	var out [16]byte
	copy(out[:], ip)
	return out
}

// computeUDPChecksumManual 手动计算 IPv6 UDP 校验和（伪头 + UDP 头 + payload），
// 用于交叉验证 builder 写入的校验和。
func computeUDPChecksumManual(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort int, udpLen int, payload []byte) uint16 {
	t.Helper()
	ph := make([]byte, 40)
	copy(ph[0:16], srcIP.To16())
	copy(ph[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(ph[32:36], uint32(udpLen))
	ph[36] = 0
	ph[37] = 0
	ph[38] = 0
	ph[39] = 17 // UDP

	// UDP header: srcPort(2) + dstPort(2) + length(2) + checksum(2)=0
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// udp[6:8] = 0 (checksum placeholder)

	all := append(ph, udp...)
	all = append(all, payload...)

	sum := uint32(0)
	for i := 0; i+1 < len(all); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(all[i : i+2]))
	}
	if len(all)%2 == 1 {
		sum += uint32(all[len(all)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	result := ^uint16(sum)
	if result == 0 {
		result = 0xFFFF
	}
	return result
}
