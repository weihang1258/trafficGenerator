package core

// B4 封装类（VXLAN / NVGRE / GENEVE）的层链配置结构（RFC 7348 / 7637 / 8926）。
// 配置从 spec_json 顶层协议键（"vxlan"/"nvgre"/"geneve"）经 strategy_convert
// 的 json 往返解析（stun/gtp 同款），经 FlowMeta 直传终结层生成器。内层
// Ethernet fixture 三协议共用（EncapEthernetFixture）：生成器据 fixture 构造
// 完整内层帧字节（MAC + 可选 802.1Q + EtherType + 内层 IP 头（校验和正确）
// + payload）。

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
