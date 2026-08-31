package core

import (
	"encoding/binary"
	"fmt"
	"net"
)

// B4 封装类（VXLAN / NVGRE / GENEVE）的层链配置结构（RFC 7348 / 7637 / 8926）。
// 配置从 spec_json 顶层协议键（"vxlan"/"nvgre"/"geneve"）经 strategy_convert
// 的 json 往返解析（stun/gtp 同款），经 FlowMeta 直传终结层生成器。内层
// Ethernet fixture 三协议共用（EncapEthernetFixture）：生成器据 fixture 构造
// 完整内层帧字节（MAC + 可选 802.1Q + EtherType + 内层 IP 头（校验和正确）
// + payload）。

// 内层帧构造常量（三封装协议共用）：内层 IP 用不可深度解析的协议号，避免
// tshark 把 payload dissect 成 spurious malformed 伪影。
const (
	// EncapInnerProtoIPv4 is the inner IPv4 protocol number (253,
	// RFC 3692 experimentation) used in encapsulated inner headers.
	EncapInnerProtoIPv4 = 253
	// EncapInnerIPv6NoNextHdr is IPv6 No Next Header (59) for inner IPv6.
	EncapInnerIPv6NoNextHdr = 59
	// encapVLANTPID is the 802.1Q TPID.
	encapVLANTPID = 0x8100
)

// BuildEncapEthernetFrame assembles a complete inner Ethernet frame from the
// shared fixture: DstMAC(6) | SrcMAC(6) | [802.1Q(4)] | EtherType(2) |
// inner L3 | payload（三封装协议共用的内层帧构造器；逻辑与 nvgre 包内已
// 提交实现一致）。内层 IPv4 头带正确校验和（tshark 对错误校验和报
// expert info，会导致用例失败）；内层 IPv6 Next Header = 59。
func BuildEncapEthernetFrame(fix *EncapEthernetFixture) ([]byte, error) {
	if err := ValidateEncapFixture(fix, "encap"); err != nil {
		return nil, err
	}
	dstMAC, _ := net.ParseMAC(fix.DstMAC)
	srcMAC, _ := net.ParseMAC(fix.SrcMAC)

	isV6 := fix.EtherType == "ipv6" || fix.EtherType == "vlan_ipv6"
	payloadLen := len(fix.Payload)

	var l3 []byte
	if isV6 {
		l3 = make([]byte, 40)
		l3[0] = 6 << 4
		binary.BigEndian.PutUint16(l3[4:6], uint16(payloadLen))
		l3[6] = EncapInnerIPv6NoNextHdr
		l3[7] = 64
		copy(l3[8:24], net.ParseIP(fix.SrcIP).To16())
		copy(l3[24:40], net.ParseIP(fix.DstIP).To16())
	} else {
		l3 = make([]byte, 20)
		l3[0] = 0x45
		binary.BigEndian.PutUint16(l3[2:4], uint16(20+payloadLen))
		l3[8] = 64
		l3[9] = EncapInnerProtoIPv4
		copy(l3[12:16], net.ParseIP(fix.SrcIP).To4())
		copy(l3[16:20], net.ParseIP(fix.DstIP).To4())
		binary.BigEndian.PutUint16(l3[10:12], EncapIPv4HeaderChecksum(l3))
	}

	frame := make([]byte, 0, len(dstMAC)+len(srcMAC)+4+2+len(l3)+payloadLen)
	frame = append(frame, dstMAC...)
	frame = append(frame, srcMAC...)
	if fix.EtherType == "vlan_ipv4" || fix.EtherType == "vlan_ipv6" {
		tci := uint16(fix.VLANPriority&0x7)<<13 | fix.VLANID&0x0fff
		frame = append(frame, byte(encapVLANTPID>>8), byte(encapVLANTPID&0xff))
		frame = append(frame, byte(tci>>8), byte(tci))
	}
	if isV6 {
		frame = append(frame, 0x86, 0xdd)
	} else {
		frame = append(frame, 0x08, 0x00)
	}
	frame = append(frame, l3...)
	frame = append(frame, fix.Payload...)
	return frame, nil
}

// EncapIPv4HeaderChecksum computes the RFC 1071 header checksum over a
// 20-byte IPv4 header with a zeroed checksum field（调用方写回）。
func EncapIPv4HeaderChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// ValidateEncapFixture rejects inner Ethernet fixture faults shared by the
// three encapsulation layers: unparseable MACs, an unknown ether_type, a VID
// beyond 12 bits, a PCP beyond 3 bits, an inner IP family mismatching the
// ether_type, and an unparseable inner IP. Boundary values (VID=0/4095,
// PCP=0/7, broadcast/multicast MACs, empty payload) are legal and must NOT
// be rejected. errPrefix（如 "vxlan"/"nvgre"/"geneve"）进错误消息开头。
func ValidateEncapFixture(fix *EncapEthernetFixture, errPrefix string) error {
	if fix == nil {
		return nil
	}
	srcMAC, err := net.ParseMAC(fix.SrcMAC)
	if err != nil || len(srcMAC) != 6 {
		return fmt.Errorf("%s: inner src_mac %q is not a valid 6-byte MAC", errPrefix, fix.SrcMAC)
	}
	dstMAC, err := net.ParseMAC(fix.DstMAC)
	if err != nil || len(dstMAC) != 6 {
		return fmt.Errorf("%s: inner dst_mac %q is not a valid 6-byte MAC", errPrefix, fix.DstMAC)
	}
	isV6 := false
	switch fix.EtherType {
	case "ipv4":
	case "ipv6":
		isV6 = true
	case "vlan_ipv4":
	case "vlan_ipv6":
		isV6 = true
	default:
		return fmt.Errorf("%s: inner ether_type %q not in {ipv4, ipv6, vlan_ipv4, vlan_ipv6}", errPrefix, fix.EtherType)
	}
	if fix.VLANID > 0x0fff {
		return fmt.Errorf("%s: inner vlan_id %d exceeds the 12-bit VID range 0..4095 (IEEE 802.1Q)", errPrefix, fix.VLANID)
	}
	if fix.VLANPriority > 7 {
		return fmt.Errorf("%s: inner vlan_priority %d exceeds the 3-bit PCP range 0..7 (IEEE 802.1Q)", errPrefix, fix.VLANPriority)
	}
	checkFamily := func(kind, addr string) error {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("%s: inner %s %q is not a valid IP address", errPrefix, kind, addr)
		}
		if (ip.To4() != nil) == isV6 {
			want := "IPv4"
			if isV6 {
				want = "IPv6"
			}
			return fmt.Errorf("%s: inner address family mismatch: ether_type %q requires %s %s, got %q", errPrefix, fix.EtherType, want, kind, addr)
		}
		return nil
	}
	if err := checkFamily("src_ip", fix.SrcIP); err != nil {
		return err
	}
	if err := checkFamily("dst_ip", fix.DstIP); err != nil {
		return err
	}
	// 外层 IPv4 total length 16-bit 不回绕的上界。开销取 UDP 载体最坏值：
	// 14 eth + 20 outer ip + 8 UDP + 8 隧道基础头（vxlan/geneve）；nvgre 的
	// GRE 载体（4+4 Key）实际 42——按 50 校验只是略保守，不会误拒真实用例。
	overhead := 14 + 20 + 8 + 8
	l3Len := 20
	if isV6 {
		l3Len = 40
	}
	if max := 0xffff - overhead - l3Len; len(fix.Payload) > max {
		return fmt.Errorf("%s: inner payload length %d exceeds the encapsulation limit %d (outer IPv4 total length must not wrap around)", errPrefix, len(fix.Payload), max)
	}
	return nil
}

// EncapEthernetFixture is the inner Ethernet frame fixture shared by the
// VXLAN / NVGRE / GENEVE terminal layers（内层以太网帧 fixture，三封装协议
// 共用）。生成器把 fixture 编码为完整内层帧字节；ether_type 决定内层 IP 头
// 版本（ipv4→0x0800 + 20B IPv4 头，ipv6→0x86DD + 40B IPv6 头），vlan_* 变体
// 先插 802.1Q tag（TPID 0x8100 + TCI）。内层 IP 的 checksum 由生成器计算
// （builder 不解释 tunnel payload）。
type EncapEthernetFixture struct {
	// SrcMAC / DstMAC are the inner frame MACs（内层 MAC 原样保留，不换
	// outer MAC）。空值非法（validator 拒绝）。
	SrcMAC string `json:"src_mac,omitempty"`
	DstMAC string `json:"dst_mac,omitempty"`
	// EtherType selects the inner L3 payload encoding: "ipv4" | "ipv6" |
	// "vlan_ipv4" | "vlan_ipv6"（0x0800 / 0x86DD，vlan_* 先插 802.1Q）。
	EtherType string `json:"ether_type,omitempty"`
	// VLANID is the 802.1Q VID (0–4095) for the vlan_* ether types；
	// VLANPriority is the 3-bit PCP（可选，0 默认）。
	VLANID       uint16 `json:"vlan_id,omitempty"`
	VLANPriority uint8  `json:"vlan_priority,omitempty"`
	// SrcIP / DstIP are the inner IP addresses（与 EtherType 版本必须一致，
	// validator 拒绝混族）。
	SrcIP string `json:"src_ip,omitempty"`
	DstIP string `json:"dst_ip,omitempty"`
	// Payload is the inner L4 payload after the inner IP header（JSON 端为
	// base64 字符串，encoding/json 自动转 []byte）。
	Payload []byte `json:"payload_b64,omitempty"`
}

// EncapWireFault is the negative-case fault injection handle（负例故障注入口，
// 仅 validator/planner 消费——注入即拒绝并传播 task error，不是线上字段）。
// Kind 协议各自定义（如 header_truncated / reserved_flags / checksum），
// Value 是可选故障参数（如越界的 VNI 值）。
type EncapWireFault struct {
	Kind  string `json:"kind"`
	Value int    `json:"value,omitempty"`
}

// VXLANDatagram is one explicit datagram in a multi-VNI / multi-flow fixture
// （多数据报 fixture 的单个数据报：独立 VNI / I flag / 内层 fixture / 事件级
// 源端口与方向）。空 Datagrams 列表时生成器按顶层 VNI/IFlag/Inner 发单数据报。
type VXLANDatagram struct {
	VNI     uint32                `json:"vni"`
	IFlag   *bool                 `json:"i_flag,omitempty"`
	SrcPort uint16                `json:"src_port,omitempty"`
	Up      *bool                 `json:"up,omitempty"`
	Inner   *EncapEthernetFixture `json:"inner,omitempty"`
	// UDPSumZero makes this datagram's IPv4 UDP checksum 0x0000（RFC 768
	// 合法零校验和档位，udp_checksum_profiles 用例；事件级
	// udp_disable_checksum 元数据）。
	UDPSumZero bool `json:"udp_checksum_zero,omitempty"`
}

// VXLANConfig is the vxlan terminal-layer config（RFC 7348）：外层 ip+udp
// 载体由链上层生成，本层发 8-byte VXLAN 头（I flag bit3 = 0x08，VNI 24-bit
// big-endian）+ 内层 Ethernet 帧。
type VXLANConfig struct {
	// VNI is the 24-bit VXLAN Network Identifier（0–0xffffff；validator
	// 拒绝越界）。0 是合法边界值。
	VNI uint32 `json:"vni,omitempty"`
	// IFlag selects the I bit（0x08）。nil → true（RFC 7348 数据面正例
	// 要求 I 置位）；显式 false 进负例（reserved_flags 锚词）。
	IFlag *bool `json:"i_flag,omitempty"`
	// Inner is the inner Ethernet fixture（必填，validator 拒绝缺失）。
	Inner *EncapEthernetFixture `json:"inner,omitempty"`
	// Datagrams 多数据报 fixture（multi_vni / multi_flow 用例）：每项发
	// 一个数据报事件。Inner/VNI 为单项缺省回退。
	Datagrams []VXLANDatagram `json:"datagrams,omitempty"`
	// WireFault 负例故障注入口（validator 消费）。
	WireFault *EncapWireFault `json:"wire_fault,omitempty"`
}

// GeneveOption is one RFC 8926 option（option 头 4B = Class(2) + Type(1) +
// Rsvd(3 bits) + Length(5 bits, 单位 4B）+ Data。Length 由 len(Data)/4 推导；
// Data 必须是 4 的倍数字节，Rsvd 必须 0（非零进负例 option 锚词）。
type GeneveOption struct {
	Class uint16 `json:"class,omitempty"`
	Type  uint8  `json:"type,omitempty"`
	Rsvd  uint8  `json:"rsvd,omitempty"`
	Data  []byte `json:"data_b64,omitempty"`
}

// GeneveDatagram is one explicit datagram in a multi-VNI / multi-flow
// fixture（同 VXLANDatagram：独立 VNI / flags / options / fixture / 端口）。
type GeneveDatagram struct {
	VNI      uint32                `json:"vni"`
	Version  *uint8                `json:"version,omitempty"`
	OAM      *bool                 `json:"oam,omitempty"`
	Critical *bool                 `json:"critical,omitempty"`
	SrcPort  uint16                `json:"src_port,omitempty"`
	Up       *bool                 `json:"up,omitempty"`
	Options  []GeneveOption        `json:"options,omitempty"`
	Inner    *EncapEthernetFixture `json:"inner,omitempty"`
}

// GeneveConfig is the geneve terminal-layer config（RFC 8926）：外层 ip+udp
// 载体由链上层生成，本层发 8-byte GENEVE 基础头（Ver(2)+OptLen(6)、OAM bit7/
// Critical bit6、Protocol Type 2B、VNI 3B + reserved）+ options + 内层帧。
type GeneveConfig struct {
	// VNI is the 24-bit Virtual Network Identifier（0–0xffffff）。
	VNI uint32 `json:"vni,omitempty"`
	// Version is the 2-bit GENEVE version（RFC 8926 当前恒 0；非零拒绝）。
	Version uint8 `json:"version,omitempty"`
	// OAM / Critical select flags bit 7 / bit 6（其余保留位必须 0）。
	OAM      bool `json:"oam,omitempty"`
	Critical bool `json:"critical,omitempty"`
	// ProtocolType is the 2-byte protocol type；0 → 0x6558（TEB，本版正例
	// 主档——Ethernet inner payload）。
	ProtocolType uint16 `json:"protocol_type,omitempty"`
	// Options 按线上顺序编码（不排序不合并）；基础头 OptLen = 总 option
	// 字节/4。
	Options []GeneveOption `json:"options,omitempty"`
	// Inner is the inner Ethernet fixture（protocol_type=0x6558 时必填）。
	Inner *EncapEthernetFixture `json:"inner,omitempty"`
	// Datagrams 多数据报 fixture（multi_vni / multi_flow / version_flags
	// 用例）。
	Datagrams []GeneveDatagram `json:"datagrams,omitempty"`
	// WireFault 负例故障注入口（validator 消费）。
	WireFault *EncapWireFault `json:"wire_fault,omitempty"`
}

// NVGREDatagram is one explicit packet in a multi-VSID / multi-flow fixture
// （独立 VSID / Flow ID / 内层 fixture / 方向）。
type NVGREDatagram struct {
	VSID   uint32                `json:"vsid"`
	FlowID uint8                 `json:"flow_id,omitempty"`
	Up     *bool                 `json:"up,omitempty"`
	Inner  *EncapEthernetFixture `json:"inner,omitempty"`
}

// NVGREConfig is the nvgre terminal-layer config（RFC 7637）：链 [ip, nvgre]
// 无传输层，生成器自产完整包——外层 IP（proto 47）+ GRE 头（FlagsAndVersion
// 0x2000 K=1、ProtocolType 0x6558 TEB、Key=VSID(24)<<8|FlowID(8) 网络字节序，
// 经 L2Config.GRE 由 builder writeGRE 序列化）+ 内层 Ethernet 帧 payload。
type NVGREConfig struct {
	// VSID is the 24-bit Virtual Subnet ID（Key 高 24 位，0–0xffffff）。
	VSID uint32 `json:"vsid,omitempty"`
	// FlowID is the 8-bit Flow ID（Key 低 8 位，0–0xff）。
	FlowID uint8 `json:"flow_id,omitempty"`
	// TTL is the outer IPv4 TTL（nil → 64；显式 0/1/255 是设计边界值，
	// 用指针区分"未提供"与显式 0）。
	TTL *uint8 `json:"ttl,omitempty"`
	// Inner is the inner Ethernet fixture（必填）。
	Inner *EncapEthernetFixture `json:"inner,omitempty"`
	// Datagrams 多数据报 fixture（multi_vsid / multi_flow 用例）。
	Datagrams []NVGREDatagram `json:"datagrams,omitempty"`
	// WireFault 负例故障注入口（validator 消费）。
	WireFault *EncapWireFault `json:"wire_fault,omitempty"`
}
