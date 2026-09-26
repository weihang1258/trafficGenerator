package layers

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TCP flag values (replicated from internal/protocol/tcp/tcp.go so the
// layers package has no dependency on the protocol package).
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
)

// Default values aligned with internal/protocol/tcp/tcp.go.
const (
	DefaultMSS        = 1460
	MinMSS            = 536 // RFC 879: minimum MSS
	DefaultWindowSize = 65535
	DefaultTTL        = 64
	// dropTailSegments is the simulated packet loss for retransmit mode
	// (T3.3): the LAST N data segments' peer ACKs are withheld from the SM
	// (模拟丢包), so those segments stay in the retransmission queue and are
	// re-emitted once the data phase completes (one RTO round). N=1 keeps
	// the deterministic loss minimal — enough to exercise the retransmit
	// path (dup segment + recovery ACK) without perturbing other behavior.
	dropTailSegments = 1
)

// LayerGenerator generates packet configs for one layer of a chain
// (层生成器)。Each generator reads its own completed layer config, wraps the
// inner generator's packets (tunnel layers), and hands the wrapped packet to
// the ChainPlanner via Emit. State shared across layers of one flow lives in
// SessionState; per-flow baseline values live in GenRequest.Meta.
type LayerGenerator interface {
	// Name returns the layer name this generator implements ("ip", "tcp", ...).
	Name() string
	// Generate drives this layer's packet sequence. req.Sess carries the
	// per-flow state across layer boundaries; req.Emit delivers each
	// wrapped packet to the ChainPlanner.
	Generate(ctx context.Context, req *GenRequest) error
	// GenEvents optionally marks a terminal generator that produces message
	// events (报文事件) for the transport layer instead of raw packets.
	// HTTPGenerator and future terminal generators (dns/ntp/...) implement
	// it; the ChainPlanner type-asserts and wires the event channel. A nil
	// return means the generator does not produce events (falls back to the
	// plain packet path).
	GenEvents() EventGenerator
}

// GenRequest carries one layer's generation context (一层生成上下文)。
type GenRequest struct {
	// Chain is the completed layer chain for this flow (已补全的层链, 各层名
	// 从外到内 ip→udp→stun）。Generators inspect it to determine the carrier
	// transport (stun 生成器据此加 TCP 帧头)。
	Chain []Layer
	// Layer is this layer's config, already completed with schema defaults
	// (已补全、已应用 schema 默认值)。Generators read values from here, never
	// from the raw FlowSpec.
	Layer Layer
	// Inner is the inner generator's packet stream (内层包流, 内→外递归)。
	// Tunnel layers consume it; the terminal/transport/network layers ignore it.
	Inner <-chan core.PacketConfig
	// Emit delivers this layer's wrapped packet to the ChainPlanner.
	// Returning an error aborts the whole chain drive.
	Emit func(core.PacketConfig) error
	// Sess is the per-flow session state shared across layers.
	Sess *SessionState
	// Meta carries the flow baseline (FlowID/ClassID/Timestamp/Direction
	// source). Payload carries the flow-level application payload for
	// transport layers.
	Meta FlowMeta
	// EmitMsg delivers a terminal-layer message event (报文事件) to the
	// transport layer. Terminal generators (http, future dns/ntp/...) emit
	// message byte events here; the transport generator (TCPGenerator/UDPGenerator
	// Inner mode) consumes them from Meta.Events when present. The
	// ChainPlanner wires the two.
	EmitMsg func(MessageEvent) error
}

// MessageEvent is one terminal-layer message in the transport stream
// (一个报文事件：方向 + 完整报文字节)。The transport layer owns
// segmentation and seq/ack; the event only carries the direction and the
// fully-built message bytes.
type MessageEvent struct {
	// Up is true for the client→server direction (request), false for
	// server→client (response).
	Up bool
	// Bytes is the complete protocol message (e.g. full HTTP request/response).
	Bytes []byte
	// Metadata carries per-message packet metadata for the transport layer
	// to merge into the emitted PacketConfig (波 4：syslog 的
	// syslog_priority/syslog_transport 事件元数据)。The UDPGenerator merges
	// these entries into the datagram's Metadata; the TCPGenerator ignores
	// them (legacy tcp 载体不设事件元数据)。
	Metadata map[string]interface{}
	// DstIP overrides the datagram's L3 destination (波 5 多播基础设施)。
	// OverrideDstIP 必须同时为 true 才生效：false → 走链层默认（spec.DstIP，
	// down 时交换）。true → DstIP 为绝对目标（多播组 224.0.0.251 / 广播
	// 255.255.255.255），finalEmit 原样落并跳过 down 交换——legacy 多播/
	// 广播 planner 从不交换组地址。
	OverrideDstIP bool
	DstIP         string
	// DstMAC overrides the datagram's L2 destination (波 5 多播基础设施)。
	// OverrideDstMAC 必须同时为 true 才生效：false → 链层推导（多播 IP →
	// 01:00:5e/33:33，否则 l2For 的 spec.DstMAC 并按方向交换）。true →
	// DstMAC 原样落（如 dhcp 广播 ff:ff:ff:ff:ff:ff）。
	OverrideDstMAC bool
	DstMAC         string
	// TTL overrides the datagram's IP TTL (波 5b)。Zero (0) = chain default
	// (ipTTL 的 schema 默认 64，或 spec.TTL)。Non-zero = 覆盖事件的目标 TTL
	// （如 ssdp 恒 4，RFC draft-cai-ssdp-v1-03 §6.2；mdns 恒 255）。
	// udp 层覆盖分支（OverrideDstIP/MAC 事件）写入后，ip 层与 finalEmit 的
	// TTL 覆写被覆盖标记跳过，本值保留。
	TTL uint8
	// SrcPort overrides the datagram's UDP source port (波 5c：rip 多 router /
	// well-known 端口语义)。Zero (0) = 传输层 cfg 值（validateSpecBase 默认化）。
	// Non-zero = 事件的目标源端口（legacy rip.go resolveSrcPort：单 router
	// Response=520 well-known、multi-router=52001+idx、request_full=52001——
	// 每 router 独立事件携带各自端口）。up/down 交换以覆盖值为准。
	SrcPort uint16
	// L4PortOverride marks the event's SrcPort/DstPort as absolute for the
	// direction (波 5d：dhcp 端口方向无关——legacy planner.go:629-633 对每条
	// 消息恒写角色解析端口，role=client 的 down reply 线上是 67→68）。设置时
	// udp 层 down 方向不做交换，直落事件值；否则按既有语义（覆盖值参与
	// up/down 交换，rip 波 5c 契约）。
	L4PortOverride bool
	// SrcIP overrides the datagram's L3 source IP (波 5c：rip 每 router 独立
	// srcIP——legacy rip.go:461-464 router.SrcIP 回退 spec.SrcIP，多 router
	// 时各包源 IP 不同，链层 ip 注入的 spec.SrcIP 不适用)。空串 = 链层默认
	// （ip 层 cfg src 注入 spec.SrcIP）。与 DstIP 覆盖不同：本值仅源 IP，
	// 不设覆盖标记（无交换语义，udp 层直落 L3.SrcIP）。
	SrcIP string
	// SrcMAC overrides the datagram's L2 source MAC (波 5d：dhcp down 方向
	// 的 reply 源 MAC 按角色交换——role!=server 时 src=spec.DstMAC，空或
	// 广播回退 DefaultServerMAC=02:00:00:00:00:02，legacy planner.go:552-573
	// 语义；finalEmit 覆盖分支恒写 spec.SrcMAC，事件值优先)。空串 = 链层
	// 默认（finalEmit 的 spec.SrcMAC）。仅覆盖标记（OverrideDstIP/MAC/TTL）
	// 事件生效。
	SrcMAC string
	// DstPort overrides the datagram's UDP destination port (波 5c：rip 版本
	// 默认端口——ng→521、其余→520，legacy getDstPort；validateSpecBase 对
	// rip 链不默认化端口，生成器经本字段传递）。Zero (0) = 传输层 cfg 值。
	DstPort uint16
	// DSCP overrides the datagram's IP DSCP (波 5c：rip 透传 spec.DSCP——
	// legacy emitRIPPacket 的 dscp 参数是死参数，实际恒用 spec.DSCP 直配，
	// 无 CS6 默认；本字段仅为链路完整性，rip 事件恒等于 spec.DSCP)。Zero (0)
	// = ip 层 schema 默认。事件携带 DSCP 时（OverrideDstIP/MAC 标记包），ip
	// 层的 dscp 覆写被覆盖标记跳过（与 TTL 对称），本值保留。
	DSCP uint8
	// FlowID overrides the packet's flow ID (波 5c：legacy rip 每 router 独立
	// flowID——"router%d-%s-%s-%d-%d" 含已解析端口与有效目标，rip.go:517-520；
	// 链层默认回填 flowID(spec) 是 spec 级值，无法表达 per-router 分割与
	// 已解析端口。空串 = 链层默认。设置时须同时设置 PacketIndex。
	FlowID string
	// PacketIndex overrides the packet's per-flow index (波 5c：legacy rip
	// 每 router 从 0 起、request_full 同 4-tuple 共享 0/1；链层默认回填
	// 全局递增索引)。nil = 链层默认。设置时须同时设置 FlowID。
	PacketIndex *uint64
	// CloseConn signals the transport layer that the event is the last on
	// its connection four-tuple: the (波 6) generalized TCPGenerator tears
	// the matching connKey state down before processing the next event so
	// the next event on a different {src,dstIP,dst} port starts a fresh
	// connection (flow-correlation side connections: a side GET/PUT
	// completes and the next main-session transaction must not re-handshake
	// the side's port). False (default) preserves the legacy behavior —
	// the connection stays up until the stream's natural teardown.
	CloseConn bool
	// ServerFirst marks a data-connection event whose SYN is sent by the
	// server, not the client (FTP active mode: server connects 20 →
	// client's PORT-advertised port, legacy EmitSubFlow ServerInitiated).
	// The TCP event loop's handshake closure is client-first only; when set,
	// the loop emits the down-direction SYN/SYN-ACK/ACK triple mirroring
	// emitTCPSubFlow's ServerInitiated branch. Default false (client-first).
	ServerFirst bool
}

// EventGenerator produces the message-event stream for a terminal
// layer (终结层报文事件生成器)。Implemented by terminal-layer generators
// (e.g. the http generator in the protocol package); the ChainPlanner calls
// EmitEvent for each built message and closes the stream when generation is
// done.
type EventGenerator interface {
	// EmitEvent delivers one message event. The ChainPlanner wires
	// it to the transport layer's event channel.
	EmitEvent(ev MessageEvent) error
}

// EventTransformer marks a tunnel-layer generator that transforms the
// terminal message-event stream instead of producing packets (事件变换器标记，
// T13：transport 之内、终结层之外的 CategoryTunnel 层——tls 把终结层事件
// 字节包成 TLS record 后仍以 MessageEvent 形态转发，不产 PacketConfig)。
// Such layers are driven via the ordinary Generate entry: they read the
// inner event stream from req.Meta.Events and forward transformed events
// via req.EmitMsg. assertEventWiring rejects any layer in that position
// that does not implement this marker.
type EventTransformer interface {
	// TransformEvents reports whether this generator consumes and
	// transforms the terminal event stream (恒 true for transformers;
	// the method exists so a plain generator can't satisfy the marker
	// accidentally).
	TransformEvents() bool
}

// FlowMeta is the per-flow baseline the ChainPlanner passes to every layer
// (每 flow 基线元数据)。
type FlowMeta struct {
	FlowID  string
	ClassID string
	// FlowIndex is the zero-based per-flow sequence number (worker 策略/
	// 批量循环写入 spec.FlowIndex，drive 经 flowMetaFor 透传；终结层动态
	// 解析用，D-FTP-2 索引域）。Direct callers default 0.
	FlowIndex int
	// Timestamp is the per-packet timestamp source; zero = time.Now() per
	// packet (包时间戳，零值 = 每包取当前时间)。
	Timestamp time.Time
	// Payload is the flow-level application payload (spec.Payload)。
	Payload []byte
	// HTTP is the flow's HTTP config (注入到 http 层生成器，绕过 schema
	// 字段表——HTTPConfig 全量字段不落层 config，避免 ValidateLayerConfig
	// 的未知字段拒绝)。Only set for http chains.
	HTTP *core.HTTPConfig
	// DstIP is the flow destination IP (供终结层生成器构造 Host 头等，
	// legacy http.go:270 传 spec.DstIP 给 buildHTTPRequestBody)。
	DstIP string
	// SrcIP is the flow source IP (波 5：终结层生成器按源 IP 版本选择
	// 多播组，legacy mdns planner.go:400-405 同款；http 等其它链不使用)。
	SrcIP string
	// CoAP is the flow's CoAP config (注入到 coap 层生成器)。
	// Only set for coap chains.
	CoAP *core.CoAPConfig
	// Events is the transport layer's view of the terminal stream
	// (传输层 Inner 模式消费的报文事件流)。The ChainPlanner creates it,
	// the terminal generator writes via req.EmitMsg, the transport
	// generator reads it. When nil, the transport generator keeps the
	// legacy single-payload mode.
	Events <-chan MessageEvent
	// UDP is the flow's UDP config (注入到 udp 层生成器：IsResponse /
	// DisableChecksum，legacy udp.go 语义)。Only set for udp chains.
	UDP *core.UDPConfig
	// DNS is the flow's DNS config (注入到 dns 层生成器，波 4)。
	// Only set for dns chains.
	DNS *core.DNSConfig
	// NTP is the flow's NTP config (注入到 ntp 层生成器，波 4)。
	// Only set for ntp chains.
	NTP *core.NTPConfig
	// SNMP is the flow's SNMP config (注入到 snmp 层生成器，波 4)。
	// Only set for snmp chains.
	SNMP *core.SNMPConfig
	// Syslog is the flow's syslog config (注入到 syslog 层生成器，波 4)。
	// Only set for syslog chains.
	Syslog *core.SyslogConfig
	// MDNS is the flow's mdns config (注入到 mdns 层生成器，波 5)。
	// Only set for mdns chains.
	MDNS *core.MDNSConfig
	// SSDP is the flow's ssdp config (注入到 ssdp 层生成器，波 5b)。
	// Only set for ssdp chains.
	SSDP *core.SSDPConfig
	// RIP is the flow's RIP config (注入到 rip 层生成器，波 5c)。
	// Only set for rip chains.
	RIP *core.RIPConfig
	// DHCP is the flow's DHCP config (注入到 dhcp 层生成器，波 5d)。
	// Only set for dhcp chains.
	DHCP *core.DHCPConfig
	// DHCPv6 is the flow's DHCPv6 config (注入到 dhcpv6 层生成器，波 5e)。
	// Only set for dhcpv6 chains.
	DHCPv6 *core.DHCPv6Config
	// GRE is the flow's GRE tunnel config (注入到 gre 隧道层生成器，P2e T12)。
	// Flat 权威（与终结层配置翻译同款 flat-wins）：spec.GRE 非 nil 时全量
	// 采用（InnerSrcIP/InnerDstIP/InnerTTL/InnerIPID/Sequence 基值...），
	// 层 config 的 key/checksum/sequence 仅在其为 nil 时生效。Only set for
	// gre chains.
	GRE *core.GREConfig
	// SrcPort is the flow source port (波 5b：ssdp 生成器默认 src 端口
	// 1900，legacy planner.go:236-239 同款；波 5c：rip 生成器事件级覆盖
	// 端口，spec.SrcPort 为 0 时走 legacy resolveSrcPort；其余链不使用)。
	SrcPort uint16
	// DstPort is the flow destination port (波 5b：ssdp 生成器默认 dst
	// 端口 1900，legacy planner.go:230-233 同款；波 5c：rip 生成器按版本
	// 默认 520/521；其余链不使用)。
	DstPort uint16
	// TTL is the flow TTL (波 5b：ssdp 生成器默认 TTL=4，legacy
	// planner.go:205-208 同款；波 5c：rip 生成器 multicast→1、unicast→
	// spec.TTL 或 64，legacy rip.go:486-492 同款；零值 = 链层默认 ipTTL)。
	TTL uint8
	// DSCP is the flow DSCP (波 5c：rip 生成器透传 spec.DSCP——legacy
	// rip.go:494-498 的 CS6 默认是死参数，emitRIPPacket 恒用 spec.DSCP 直配；
	// 零值 = 链层默认 0)。
	DSCP uint8
	// SrcMAC is the flow source MAC (波 5c：rip 生成器写入 L2 覆盖事件，
	// legacy rip.go emitRIPPacket L2Base 的 spec.SrcMAC；其余链不使用)。
	SrcMAC string
	// DstMAC is the flow destination MAC (波 5d：dhcp 生成器角色解析的
	// resolveMACs 与 role!=client 的 chaddr 回退读 spec.DstMAC，legacy
	// planner.go:441-455/716-742 语义；其余链不使用)。
	DstMAC string
	// TFTP is the flow's TFTP config (注入到 tftp 层生成器，P4a)。Only set
	// for tftp chains.
	TFTP *core.TFTPConfig
	// ENIP is the flow's ENIP config (注入到 enip 层生成器，P4a)。Only set
	// for enip chains.
	ENIP *core.ENIPConfig
	// DNP3 is the flow's DNP3 config (注入到 dnp3 层生成器，P4a)。Only set
	// for dnp3 chains。
	DNP3 *core.DNP3Config
	// DoIP is the flow's DoIP config (注入到 doip 层生成器，P4a)。Only set
	// for doip chains。
	DoIP *core.DoIPConfig
	// GBT32960 is the flow's GBT32960 config (注入到 gbt32960 层生成器，
	// P4a)。Only set for gbt32960 chains。
	GBT32960 *core.GBT32960Config
	// MCP is the flow's MCP config (注入到 mcp 层生成器，P4a)。Only set for
	// mcp chains。
	MCP *core.MCPConfig
	// MODBUS is the flow's MODBUS config (注入到 modbus 层生成器，P4a)。
	// Only set for modbus chains。
	MODBUS *core.MODBUSConfig
	// MQTT is the flow's MQTT config (注入到 mqtt 层生成器，P4a：会话序列
	// CONNECT/CONNACK/SUBSCRIBE/消息/Will/DISCONNECT 逐帧事件，build* 纯
	// 函数复用)。Only set for mqtt chains。
	MQTT *core.MQTTConfig
	// NFS is the flow's NFS config (注入到 nfs 层生成器，P4a：RPC 调用/回复
	// 逐事件产出，buildCall/buildReply 纯函数复用)。Only set for nfs chains。
	// core 无法 import protocol/nfs（protocol 包反向依赖 core），故为
	// interface{}——经 spec.Metadata["nfs"] 原样传递（strategy_convert.go
	// mapToFlowSpec 的 nfs case 存 JSON 解码子 map），生成器侧解析。
	NFS interface{}
	// FINS is the flow's FINS config (注入到 fins 层生成器)。
	FINS    interface{}
	S7      *core.S7Config
	IEC104  *core.IEC104Config
	BGP     *core.BGPConfig
	OPCUA   *core.OPCUAConfig
	MMS     *core.MMSConfig
	GOOSE   *core.GOOSEConfig
	SV      *core.SVConfig
	ARP     *core.ARPConfig
	STUN    *core.STUNConfig
	HTTPFLV *core.HTTPFLVConfig
	HLS     *core.HLSConfig
	HDS     *core.HDSConfig
	MOXA    *core.MOXAConfig
	SOMEIP  *core.SOMEIPConfig
	DRDA    *core.DRDAConfig
	Thrift  *core.ThriftConfig
	// OpenWire is the flow's OpenWire config (注入到 openwire 终结层生成器：
	// ActiveMQ loose 命令序列逐事件产出；连接级显式地址时走自驱完整包分支，
	// B5)。Only set for openwire chains.
	OpenWire *core.OpenWireConfig
	// AMS is the flow's AMS config (注入到 ams 终结层生成器：管理帧序列逐
	// 事件产出；连接级显式地址时走自驱完整包分支，B5)。Only set for ams chains.
	AMS *core.AMSConfig
	// Swarm is the flow's Swarm config (注入到 swarm 终结层生成器：discovery
	// datagram 或 storage frame 逐事件产出，B5)。Only set for swarm chains.
	Swarm *core.SwarmConfig
	// Gnutella is the flow's Gnutella config (注入到 gnutella 终结层生成器：
	// 握手+消息逐事件产出；连接级显式地址时走自驱完整包分支，B5)。
	Gnutella *core.GnutellaConfig
	TNS      *core.TNSConfig
	MongoDB  *core.MongoDBConfig
	Dameng   *core.DamengConfig
	// PostgreSQL is the flow's PostgreSQL config (注入到 postgresql 终结层生成器，
	// P0a：共享 PG v3 wire 层，kingbase 是其 dialect 变体——共享层读
	// req.Meta.PostgreSQL 的 Events/Sessions，dialect 决定端口 5432/54321）。
	PostgreSQL *core.PostgreSQLConfig
	Megaco     *core.MegacoConfig   // D-MEGACO-1：megaco 终结层（RFC 3525 文本编码，udp/tcp 双载体）
	HL7        *core.HL7Config      // D-HL7-1：hl7 终结层（HL7 v2.x MLLP，TCP/2575 单载体）
	MMSE       *core.MMSEConfig     // D-MMSE-1：mmse 终结层（WAP-209，http 族第 5 协议）
	EDP        *core.EDPConfig      // D-EDP-1：edp 终结层（OneNET Enhanced Device Protocol，TCP 单载体）
	XMR        *core.XMRConfig      // D-XMR-1：xmrmining 终结层（Monero stratum 行式 JSON，TCP 单载体）
	BACNET     *core.BACNETConfig   // D-BACNET-1：bacnet 终结层（BACnet/IP Annex J，UDP/47808 单载体）
	DCERPC     *core.DCERPCConfig   // D-DCERPC-1：dcerpc 终结层（DCE/RPC v5 over TCP，EPM 135+动态端口）
	DTLS       *core.DTLSConfig     // D-DTLS-1：dtls 终结层（DTLS 1.0/1.2 records over UDP，4433 单载体）
	Kerberos   *core.KerberosConfig // D-KERBEROS-1：kerberos 终结层（Kerberos V5 DER，UDP/TCP 88 双载体）
	NTLM       *core.NTLMConfig     // D-NTLM-1：ntlm 终结层（NTLMv2 三消息，SMB2/HTTP Negotiate 双 profile 自封帧，TCP 单载体）
	SSTP       *core.SSTPConfig     // D-SSTP-1：sstp 终结层（MS-SSTP over TLS/TCP 443，tls 变换器透传）
	OCSP       *core.OCSPConfig     // D-OCSP-1：ocsp 终结层（RFC 6960/8954 OCSP，tcp 载体 + 可选 http 层双 profile）
	SPNEGO     *core.SPNEGOConfig   // D-SPNEGO-1：spnego 终结层（RFC 4178 DER，裸 TCP/HTTP Negotiate 双 profile 自封帧，TCP 单载体）
	CQL        *core.CQLConfig
	LDP        *core.LDPConfig
	PCEP       *core.PCEPConfig
	CFlow      *core.CFlowConfig
	RTMFP      *core.RTMFPConfig
	AMQP       *core.AMQPConfig
	// SMB is the flow's SMB config (注入到 smb 层生成器，P4a：SMB2 会话
	// NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE/Operations/CLOSE/
	// TREE_DISCONNECT/LOGOFF 逐 PDU 事件，build* 纯函数复用)。Only set for
	// smb chains。
	SMB *core.SMBConfig
	// SMTP is the flow's SMTP config (注入到 smtp 终结层生成器，P3：banner +
	// Dialog 命令/响应对逐事件产出，字节与 legacy Plan 数据帧一致)。Only set
	// for smtp chains。
	SMTP *core.SMTPConfig
	// TCP is the flow's TCP config (注入到 tcp 载体终结层生成器，P4a：
	// doip 0x36 TransferData 分段读 spec.TCP.MSS，legacy doip.go:677-701
	// 同款)。Only set for tcp-carrier chains。
	TCP *core.TCPConfig
	// Redis is the flow's Redis config (注入到 redis 终结层生成器：RESP
	// 2/3 会话逐帧事件，encodeRESPArray/encodeSubConfirm/resolveReply 纯
	// 函数复用)。Only set for redis chains。
	Redis *core.RedisConfig
	// FTP is the flow's FTP config (注入到 ftp 终结层生成器：banner +
	// 会话/命令/响应对/数据通道逐事件产出，resolveTx/端口推导复用
	// legacy planner)。Only set for ftp chains。
	FTP *core.FTPConfig
	// POP3 is the flow's POP3 config (注入到 pop3 终结层生成器：banner +
	// 命令/响应对逐事件产出，buildMailDropResponse/buildTopResponse 纯函数
	// 复用)。Only set for pop3 chains。
	POP3 *core.POP3Config
	// IMAP is the flow's IMAP config (注入到 imap 终结层生成器：greeting +
	// 命令/literal/IDLE 逐事件产出，formatCommandLine/constructMIMEBody 纯
	// 函数复用)。Only set for imap chains。
	IMAP *core.IMAPConfig
	// MySQL is the flow's MySQL config (注入到 mysql 终结层生成器：Greeting →
	// auth → 命令/回复逐事件产出，encode* 纯函数复用)。Only set for mysql
	// chains。
	MySQL *core.MySQLConfig
	// WireGuard is the flow's WireGuard config (注入到 wireguard 终结层生成器：
	// UDP 数据报序列，build* 纯函数复用)。Only set for wireguard chains。
	WireGuard *core.WireGuardConfig
	// L2TP is the flow's L2TP config (注入到 l2tp 终结层生成器：UDP 隧道控制/
	// PPP 数据报文列，buildControlMessage/buildDataMessage 纯函数复用)。
	// Only set for l2tp chains。
	L2TP *core.L2TPConfig
	// GTP is the flow's GTP config (注入到 gtp 终结层生成器：GTP-U/C 隧道
	// 报文序列，buildGTPMessage/buildInnerIPv4Packet 纯函数复用)。Only set
	// for gtp chains。
	GTP *core.GTPConfig
	// IKE is the flow's IKE config (注入到 ike 终结层生成器：IKE 消息序列 +
	// ESP 数据面，buildIKEMessageBytes/buildESPPacket 纯函数复用)。Only set
	// for ike chains。
	IKE *core.IKEConfig
	// IKENATT is the flow's IKE-NAT-T config (注入到 ike_nat_t 终结层生成器：
	// 端口浮动 + Non-ESP Marker 的 NAT 穿透 IKE 消息序列，buildIKENATTMessage
	// 纯函数复用)。Only set for ike_nat_t chains。
	IKENATT *core.IKENATTConfig
	// GRPC is the flow's gRPC config (注入到 grpc 终结层生成器：HTTP/2
	// preface + SETTINGS + 逐 call HEADERS/DATA/trailers 逐帧事件，buildFrame/
	// buildDataFrameStream 纯函数复用)。Only set for grpc chains。
	GRPC *core.GRPCConfig
	// SSH is the flow's SSH config (注入到 ssh 终结层生成器：version exchange
	// + KEXINIT/KEXDH + NEWKEYS + userauth + channel 逐 BPP 帧事件，
	// encode*/buildBPP 纯函数复用)。Only set for ssh chains。
	SSH *core.SSHConfig
	// RDP is the flow's RDP config (注入到 rdp 终结层生成器：X.224/MCS/security
	// PDU 序列逐帧事件，encode* 纯函数复用)。Only set for rdp chains。
	RDP *core.RDPConfig
	// OpenVPN is the flow's OpenVPN config (注入到 openvpn 终结层生成器：UDP
	// 数据报序列 P_CONTROL/P_DATA，build* 纯函数复用)。Only set for openvpn
	// chains。
	OpenVPN *core.OpenVPNConfig
	// Vmess is the flow's VMess config (注入到 vmess 终结层生成器：TCP-mode
	// request/response AEAD 帧序列，build* 纯函数复用)。Only set for vmess
	// chains。
	Vmess *core.VmessConfig
	// Shadowsocks is the flow's Shadowsocks config (注入到 shadowsocks 终结层
	// 生成器：TCP-mode AEAD 帧序列 + 可选 SOCKS5/HTTP 混淆，build* 纯函数复用)。
	// Only set for shadowsocks chains。
	Shadowsocks *core.ShadowsocksConfig
	// Socks is the flow's SOCKS proxy config (注入到 socks5 终结层生成器：
	// greeting/method/auth/request/reply 信令 + 隧道数据面，build* 纯函数
	// 复用)。Only set for socks5 chains.
	Socks *core.SocksConfig
	// VXLAN is the flow's VXLAN config (注入到 vxlan 终结层生成器：8-byte
	// VXLAN 头 + 内层 Ethernet 帧逐数据报事件，B4 封装类)。Only set for
	// vxlan chains.
	VXLAN *core.VXLANConfig
	// Geneve is the flow's GENEVE config (注入到 geneve 终结层生成器：
	// 8-byte 基础头 + options + 内层帧逐数据报事件，B4 封装类)。Only set
	// for geneve chains.
	Geneve *core.GeneveConfig
	// NVGRE is the flow's NVGRE config (注入到 nvgre 终结层生成器：自产
	// 完整包——外层 IP proto 47 + L2.GRE TEB(0x6558) + 内层帧 payload，
	// B4 封装类)。Only set for nvgre chains.
	NVGRE *core.NVGREConfig
	// SRv6 is the flow's SRv6 config (注入到 srv6 终结层生成器：raw-IP
	// 链 [ip,srv6]，D-SRV6-1——生成器包装 legacy Planner.Plan 自产完整
	// IPv6+SRH 包)。Only set for srv6 chains.
	SRv6 *core.SRv6Config
	// IGMP/OSPF/PIM/ISIS is the flow's routing config (注入到各自终结层生成器，
	// P3 T5：igmp/ospf/pim 是 raw-IP [ip,<proto>] 链，isis 是 L2-only
	// [eth,isis] 链；生成器经 req.Meta.<XXX> 读协议配置逐事件产包)。Only set
	// for the corresponding routing chains。
	IGMP *core.IGMPConfig
	OSPF *core.OSPFConfig
	PIM  *core.PIMConfig
	ISIS *core.ISISConfig
	// ICMPv6 is the flow's ICMPv6 config（D-ICMPV6-1：raw-IP 终结层生成器直传）。Only set for icmpv6 chains.
	ICMPv6 *core.ICMPv6Config
	// ICMP is the flow's ICMP config（D-ICMP-1：raw-IP 终结层生成器直传）。Only set for icmp chains.
	ICMP *core.ICMPConfig
	// H323 is the flow's h323 config（D-H323-1：raw 自驱终层生成器直传）。Only set for h323 chains.
	H323 *core.H323Config
	// MPLS is the flow's mpls config（D-MPLS-1：raw 自驱终层生成器直传）。Only set for mpls chains.
	MPLS *core.MPLSConfig
	// NGAP is the flow's ngap config（D-NGAP-1：raw 自驱终层生成器直传）。Only set for ngap chains.
	NGAP *core.NGAPConfig
	// Telnet is the flow's telnet config（D-TELNET-1：raw 自驱终层生成器直传）。Only set for telnet chains.
	Telnet *core.TelnetConfig
	// SIP is the flow's sip config（D-SIP-1：raw 自驱终层生成器直传，含 RTP 子流）。Only set for sip chains.
	SIP *core.SIPConfig
	// D-PPPOE-1：pppoe raw 链同款（配置经 Meta 直传终结层生成器，
	// srv6 Meta.SRv6 先例）。
	PPPoE *core.PPPoEConfig
	// D-LDAP-1：ldap raw 链同款。
	LDAP *core.LDAPConfig
	// D-RTMP-1：rtmp raw 链同款。
	RTMP *core.RTMPConfig
	// D-RTSP-1：rtsp raw 链同款。
	RTSP *core.RTSPConfig
	// D-PPTP-1：pptp raw 链同款。
	PPTP *core.PPTPConfig
	// D-VNC-1：vnc raw 链同款。
	VNC *core.VNCConfig
	// D-XMPP-1：xmpp raw 链同款。
	Xmpp *core.XmppConfig
	// D-SCTP-1：sctp raw 链同款。
	SCTP *core.SCTPConfig
	// D-JT808-1：jt808 raw 链同款。
	JT808 *core.JT808Config
	// D-JT809-1：jt809 raw 链同款。
	JT809 *core.JT809Config
	// D-JTT905-1：jtt905 raw 链同款。
	JTT905 *core.JTT905Config
	// Radius is the flow's radius config（D-RADIUS-1：raw 自驱终层生成器直传）。Only set for radius chains.
	Radius *core.RadiusConfig
	// GBT is the flow's gbt config (注入到 gbt 终结层生成器，B6：BIP 22/23
	// JSON-RPC over HTTP；sessions[]/events[] 逐事件产完整 HTTP 帧，http 层
	// 透传转发)。Only set for gbt chains。
	GBT *core.GBTConfig
	// GetWork is the flow's getwork config (注入到 getwork 终结层生成器，
	// B6：Bitcoin legacy getwork JSON-RPC over HTTP；同款透传转发)。
	GetWork *core.GetWorkConfig
	// Stratum is the flow's stratum config (注入到 stratum 终结层生成器，
	// B6：比特币 Stratum v1 行式 JSON over TCP；每事件一条行/一对请求响应)。
	Stratum *core.StratumConfig
	// ETHMining is the flow's ethmining config (注入到 ethmining 终结层生成器，
	// 73-ethmining v2.0.2：以太坊挖矿 stratum 行式 JSON over TCP；每事件
	// 一条行/一对请求响应，[tcp→ethmining] 直连)。
	ETHMining *core.ETHMiningConfig
	// NMEA is the flow's nmea config （注入到 nmea 终结层生成器，
	// 69-nmea v2.0.0：NMEA 0183 sentence 明文 over TCP/UDP；每事件一句，
	// [tcp→nmea]/[udp→nmea] 双载体）。
	NMEA *core.NMEAConfig
	// CWMP is the flow's cwmp config （注入到 cwmp 终结层生成器，
	// 64-cwmp v2.2.2：TR-069 SOAP 1.1 over HTTP；每事件一笔事务一侧的完整
	// HTTP 帧，http 层透传转发；sessions[]/events[] + flows[] 流关联副连接）。
	CWMP *core.CWMPConfig
	// DOH is the flow's doh config （注入到 doh 终结层生成器，
	// 66-doh v2.2.1：DNS over HTTPS / RFC 8484；每事件一笔查询事务的完整
	// HTTP 请求/响应帧对（POST body / GET base64url），http 层透传转发）。
	DOH *core.DOHConfig
	// ONVIF is the flow's onvif config （注入到 onvif 终结层生成器，
	// 67-onvif v2.1.1：ONVIF Core Spec Ver. 26.06 四服务 SOAP 1.2 over HTTP；
	// 每事件一笔 SOAP 请求/响应帧对，http 层透传转发）。
	ONVIF *core.ONVIFConfig
	// TCPState is the flow's TCP retransmission state machine (T3.3：tcp 层
	// config retransmit=true 时由 TCPGenerator 构建并驱动——SendSegment/
	// OnACK/OnDupACK/OnRTO 随正常数据段/ACK 发射同步喂数)。nil = 关闭
	// 重传模拟（默认；字节流与 legacy 完全一致，不多不少）。
	//
	// DEPRECATED carrier: FlowMeta is copied by value at every layer
	// boundary, so a pointer written here by an inner layer does NOT
	// propagate upstream. The live handle is SessionState.TCPRetrans
	// (shared pointer). This field is kept for the plan's named surface
	// (tests may set it pre-Plan to force a specific SM instance); the
	// TCPGenerator itself writes SessionState.TCPRetrans.
	TCPState *TCPRetransmissionStateMachine
	// CksumEngine is the flow's IP checksum engine (T3.3：端到端校验/验证
	// 用——AssembleAndVerify 重组分片后验证 IPv4 头校验和，伪头求和供
	// TCP/UDP 校验复算)。生成路径本身仍在 builder.go 内联计算（字节级
	// 兼容约束），此句柄供集成测试/验证器复算对拍。nil = 未启用。
	CksumEngine *IPCksumComputer
}

// SessionState is the per-flow state shared by all layer generators
// (每 flow 会话状态)。
type SessionState struct {
	ClientSeq, ServerSeq uint32 // tcp 层持有
	ClientAck, ServerAck uint32
	HandshakeDone        bool
	IPID                 uint16 // ip 层持有，每 Emit 前写入并自增
	// PacketIndex is the per-flow packet sequence number, advanced by the
	// ChainPlanner for every packet that leaves the chain (ChainPlanner 统一推进)。
	PacketIndex uint64
	// TCPRetrans is the retransmission state machine for retransmit=true
	// flows (T3.3)。SessionState 是链上共享指针（req.Sess），tcp 层构建的
	// SM 写在这里可被 ChainPlanner/集成测试观察（FlowMeta 是逐层值拷贝，
	// 指针字段写入不回传——SM 挂 Sess 而非 Meta）。nil = 未开启。
	TCPRetrans *TCPRetransmissionStateMachine
}

// flowConfigField reads a completed layer config field with a schema-type
// conversion. Returns (value, present). Values may arrive as the schema
// default's native type (uint8/uint16/uint32/bool/string) or as a raw JSON
// number/string when the config came from user input.
func flowConfigField(cfg map[string]interface{}, key string) (interface{}, bool) {
	if cfg == nil {
		return nil, false
	}
	v, ok := cfg[key]
	return v, ok && v != nil
}

// configUint64 converts a config value to uint64 (schema-typed defaults
// and raw numeric strings). ok=false when absent or unparseable.
// ngapByteSlice mirrors core getByteSlice (strategy_convert.go:6226): NAS
// keys take a raw string (bytes as-is, NOT hex) or a []interface{} of
// numbers. D-NGAP-1 decision C1 parity requirement.
func ngapByteSlice(v interface{}) []byte {
	switch b := v.(type) {
	case string:
		return []byte(b)
	case []interface{}:
		out := make([]byte, 0, len(b))
		for _, n := range b {
			if u, ok := configUint64(n); ok {
				out = append(out, byte(u))
			}
		}
		return out
	}
	return nil
}

func configUint64(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case uint8:
		return uint64(n), true
	case uint16:
		return uint64(n), true
	case uint32:
		return uint64(n), true
	case uint64:
		return n, true
	case int:
		return uint64(n), true
	case int64:
		return uint64(n), n >= 0
	case float64:
		if n < 0 || n != float64(uint64(n)) {
			return 0, false
		}
		return uint64(n), true
	case string:
		u, err := strconv.ParseUint(n, 0, 64)
		return u, err == nil
	}
	return 0, false
}

func configUint16(v interface{}) (uint16, bool) {
	u, ok := configUint64(v)
	if !ok || u > 65535 {
		return 0, false
	}
	return uint16(u), true
}

func configUint8(v interface{}) (uint8, bool) {
	u, ok := configUint64(v)
	if !ok || u > 255 {
		return 0, false
	}
	return uint8(u), true
}

func configUint32(v interface{}) (uint32, bool) {
	u, ok := configUint64(v)
	if !ok || u > 4294967295 {
		return 0, false
	}
	return uint32(u), true
}

func configString(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func configBool(v interface{}) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		if b == "true" {
			return true, true
		}
		if b == "false" {
			return false, true
		}
	}
	return false, false
}

// synOptions builds the SYN TCP options: MSS + Window Scale + SACK-Permitted
// (字节复刻 internal/protocol/tcp/tcp.go:85-96)。MSS=0 归一为 DefaultMSS。
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}

// effectiveMSS resolves the effective MSS: 0 → DefaultMSS, below MinMSS →
// MinMSS (schema min 536, RFC 879).
func effectiveMSS(mss uint16) uint16 {
	if mss == 0 {
		return DefaultMSS
	}
	if mss < MinMSS {
		return MinMSS
	}
	return mss
}

// segmentByMSS splits payload into chunks of at most mss bytes. An empty
// payload returns a single empty chunk so the caller still emits one
// PSH-ACK segment (matching the legacy http.go:469-489 semantics — an
// empty HTTP body still produces one data packet).
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		// Defensive: caller resolves 0 → DefaultMSS before invoking.
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	chunks := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	return chunks
}

// ---- ip 层生成器 ----

// IPGenerator fills the L3 config for every packet it wraps (ip 层生成器)。
// It reads src/dst/ttl/dscp/ecn/frag_offset from its own completed layer
// config, writes Sess.IPID into L3Config.IPID and increments it before each
// Emit. It does NOT re-implement L3Base — the caller (ChainPlanner) already
// fills flow-level fields; this generator is the chain-level owner of IPID.
type IPGenerator struct{}

// Name returns "ip".
func (g *IPGenerator) Name() string { return "ip" }

// GenEvents is unimplemented for the ip layer (ip 层不是终结层，无报文事件)。
func (g *IPGenerator) GenEvents() EventGenerator { return nil }

// Generate wraps every packet from Inner with this layer's L3 config.
// Without Inner (standalone ip? never — ip is never a terminal layer) it
// emits nothing.
// 空串不覆盖（review LOW-1 修复）：src/dst 值为空字符串且非用户显式写入时
// （applySpecToChain 的 schema 默认只填 10.0.0.1/20.0.0.1 当 spec.SrcIP 为空
// ——review 实测）不得覆盖已填好的 IP（legacy 语义：spec IP 空 → L3 空）。
// 本层 Config 里 src/dst 是"用户写的层配置"或"applySpecToChain 注入的
// spec 值"，两者都是显式意图；空串表示"未指定"→ 保留已有值。
func (g *IPGenerator) Generate(ctx context.Context, req *GenRequest) error {
	cfg := req.Layer.Config
	src, srcSet := cfgValueString(cfg, "src")
	dst, dstSet := cfgValueString(cfg, "dst")
	v, _ := flowConfigField(cfg, "ttl")
	ttl, _ := configUint8(v)
	v, _ = flowConfigField(cfg, "dscp")
	dscp, _ := configUint8(v)
	v, _ = flowConfigField(cfg, "ecn")
	ecn, _ := configUint8(v)
	v, _ = flowConfigField(cfg, "frag_offset")
	fragOffset, _ := configUint16(v)
	if req.Sess == nil {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pkt, ok := <-req.Inner:
			if !ok {
				return nil
			}
			// 只在用户显式写了 src/dst 时覆盖（LOW-1：空串/未写 → 保留已有值）。
			// 多播覆盖事件（波 5）：udp 层已写入绝对 DstIP（多播组/广播）、
			// SrcIP（波 5c：rip 多 router 独立源，事件级覆盖）、TTL=255
			// （RFC 6762 §11 等）与 dscp，ip 层不得再覆盖成链层配置的
			// spec 值——检查事件覆盖标记（finalEmit 消费前一直存在），标记包
			// 跳过 dst、ttl 与 dscp 覆盖。src 例外：mdns/ssdp 事件只设标记不
			// 带 SrcIP（udp 层仅当 ev.SrcIP != "" 才写 L3.SrcIP），若按标记
			// 一律跳过会导致这些事件源 IP 恒空；空串判别即 MessageEvent.SrcIP
			// 的契约（"空串 = 链层默认"）——事件已覆盖 src 时 L3.SrcIP 非空，
			// 保留事件值；否则写链层配置的 spec 源。
			_, overrideDst := pkt.Metadata[eventDstOverrideKey]
			if srcSet && pkt.L3.SrcIP == "" {
				pkt.L3.SrcIP = src
			}
			if dstSet && !overrideDst {
				pkt.L3.DstIP = dst
			}
			if ttl != 0 && !overrideDst {
				pkt.L3.TTL = ttl
			}
			if !overrideDst {
				pkt.L3.DSCP = dscp
			}
			pkt.L3.ECN = ecn
			pkt.L3.FragOffset = fragOffset
			// IPID 每次 Emit 前写入并自增（tcp.go:137-141 语义）。
			pkt.L3.IPID = req.Sess.IPID
			req.Sess.IPID++
			if err := req.Emit(pkt); err != nil {
				return err
			}
		}
	}
}

// cfgValueString reads a config field's string value; present=false when the
// field is absent, nil, or not a string（字段是否存在且为字符串）。
func cfgValueString(cfg map[string]interface{}, key string) (string, bool) {
	v, ok := flowConfigField(cfg, key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// ---- tcp 层生成器 ----

// TCPGenerator drives the TCP packet sequence for one flow: handshake
// (SYN/SYN-ACK/ACK), MSS-segmented data segments with peer ACKs, and either
// an abortive RST or the four-way FIN teardown (tcp 层生成器, 字节级复刻
// internal/protocol/tcp/tcp.go:98-432 的包序列与 seq/ack 推进)。
type TCPGenerator struct{}

// Name returns "tcp".
func (g *TCPGenerator) Name() string { return "tcp" }

// GenEvents is unimplemented for the tcp layer (tcp 是传输层，消费事件流，
// 不产出报文事件)。
func (g *TCPGenerator) GenEvents() EventGenerator { return nil }

// tcpConnKey 标识一条 TCP 连接：客户端源端口 + 服务端 L3 目标 + 目标端口
// （原 Generate 内 connKey 闭包类型上移到包级，供 handshake/teardown
// 闭包签名使用；注释见事件循环处 connKey 抽象说明）。
type tcpConnKey struct {
	src   uint16
	dstIP string
	dst   uint16
}

// tcpCfg is the resolved TCP layer configuration.
type tcpCfg struct {
	srcPort, dstPort uint16
	handshake        bool
	termination      bool
	rst              bool
	mss              uint16
	windowSize       uint16
	initialSeq       uint32
	// concurrent enables per-SrcPort connection state in event mode: each
	// distinct event SrcPort gets its own handshake on first use and its
	// seq state is restored on return (mms 并发会话；drda 默认语义仍是
	// 挥旧握新，concurrent=false).
	concurrent bool
	// retransmit enables the TCP retransmission state machine (T3.3): data
	// segments and ACKs also drive TCPRetransmissionStateMachine, and after
	// the data phase unacked segments (queue tail the simulated peer never
	// acked) are re-emitted as duplicate PSH-ACK retransmissions.
	retransmit bool
}

// resolveCfg resolves the TCP layer configuration from the completed layer
// config. 存在但不可转换的值（review MEDIUM-1 修复）：显式报错返回，绝不
// 静默丢配置（configUint16/32/8 判"不可转换"时，字段存在 → 用户写了
// 一个我们读不了的值 → 必须拒绝，而不是退回默认/随机）。
func (g *TCPGenerator) resolveCfg(req *GenRequest) (tcpCfg, error) {
	cfg := tcpCfg{
		handshake:   true, // schema 默认 true——不能读 TCPConfig 零值
		termination: true,
		windowSize:  DefaultWindowSize,
		mss:         DefaultMSS,
	}
	// 不可转换值报错；不存在（或 nil）字段跳过（走 schema 默认）。
	errInvalid := func(field string, v interface{}) error {
		return fmt.Errorf("tcp layer: field %q = %v invalid: cannot convert to %s",
			field, v, fieldType(field))
	}
	c := req.Layer.Config
	if v, ok := flowConfigField(c, "src_port"); ok {
		if p, ok := configUint16(v); ok {
			cfg.srcPort = p
		} else {
			return cfg, errInvalid("src_port", v)
		}
	}
	if v, ok := flowConfigField(c, "dst_port"); ok {
		if p, ok := configUint16(v); ok {
			cfg.dstPort = p
		} else {
			return cfg, errInvalid("dst_port", v)
		}
	}
	if v, ok := flowConfigField(c, "handshake"); ok {
		if b, ok := configBool(v); ok {
			cfg.handshake = b
		} else {
			return cfg, errInvalid("handshake", v)
		}
	}
	if v, ok := flowConfigField(c, "termination"); ok {
		if b, ok := configBool(v); ok {
			cfg.termination = b
		} else {
			return cfg, errInvalid("termination", v)
		}
	}
	if v, ok := flowConfigField(c, "rst"); ok {
		if b, ok := configBool(v); ok {
			cfg.rst = b
		} else {
			return cfg, errInvalid("rst", v)
		}
	}
	if v, ok := flowConfigField(c, "mss"); ok {
		if m, ok := configUint16(v); ok {
			cfg.mss = m
		} else {
			return cfg, errInvalid("mss", v)
		}
	}
	if v, ok := flowConfigField(c, "window_size"); ok {
		if w, ok := configUint16(v); ok {
			cfg.windowSize = w
		} else {
			return cfg, errInvalid("window_size", v)
		}
	}
	if v, ok := flowConfigField(c, "initial_seq"); ok {
		if s, ok := configUint32(v); ok {
			cfg.initialSeq = s
		} else {
			return cfg, errInvalid("initial_seq", v)
		}
	}
	if v, ok := flowConfigField(c, "concurrent"); ok {
		if b, ok := configBool(v); ok {
			cfg.concurrent = b
		} else {
			return cfg, errInvalid("concurrent", v)
		}
	}
	if v, ok := flowConfigField(c, "retransmit"); ok {
		if b, ok := configBool(v); ok {
			cfg.retransmit = b
		} else {
			return cfg, errInvalid("retransmit", v)
		}
	}
	cfg.mss = effectiveMSS(cfg.mss)
	return cfg, nil
}

// fieldType names the numeric type a field maps to, for error messages.
func fieldType(field string) string {
	switch field {
	case "initial_seq":
		return "uint32"
	case "handshake", "termination", "rst", "concurrent", "retransmit":
		return "bool"
	default:
		return "uint16"
	}
}

// Generate drives the TCP sequence for one flow. The flow-level payload
// comes from req.Meta.Payload; per-packet direction/L2/L3 assembly is
// delegated to the ChainPlanner via the wrapping layer chain (ip 层在上层
// 包装)。This generator emits L4-only packets through req.Emit.
func (g *TCPGenerator) Generate(ctx context.Context, req *GenRequest) error {
	cfg, err := g.resolveCfg(req)
	if err != nil {
		return err
	}
	sess := req.Sess
	if sess == nil {
		sess = &SessionState{}
		req.Sess = sess
	}
	// seq 初始化：clientSeq = InitialSeq（schema，0 则随机），serverSeq = 随机。
	// 多会话（P0a postgresql/kingbase）支持每条独立 TCP 连接：每条连接的 seq
	// 由 handshake 闭包重新初始化（独立连接 seq 互不共享）；单连接路径字节级不变。
	clientSeq := cfg.initialSeq
	if clientSeq == 0 {
		clientSeq = rand.Uint32()
	}
	serverSeq := rand.Uint32()
	winSize := cfg.windowSize
	if winSize == 0 {
		winSize = DefaultWindowSize
	}
	synOpts := synOptions(cfg.mss)
	mss := int(cfg.mss)

	emit := func(pkt core.PacketConfig) error {
		if req.Emit == nil {
			return nil
		}
		return req.Emit(pkt)
	}

	// handshake 闭包：为一条连接发出 SYN(up,0x02)→SYN-ACK(down,0x12)→ACK(up,0x10)
	// （schema 默认 true）。key 是该连接的 connKey（单连接 = 配置默认；
	// 多会话 = 每个 session/数据通道的独立 key，含各自目标端口）。
	// 每次调用重新初始化该连接 seq，字节序列
	// 与 legacy 单连接握手完全一致（P0a 多会话边界复用于新连接握手）。
	// serverFirst=true 时发出 server 首 SYN 的 down/up/down 三元组（FTP
	// active 数据通道，legacy emitTCPSubFlow ServerInitiated 分支）。
	handshake := func(key tcpConnKey, serverFirst bool) error {
		// defaultKey 回退：key.dst==0 的事件（无 DstPort 覆盖）走配置默认端口，
		// 与旧 byte-key 单连接行为逐字节一致。
		if key.dst == 0 {
			key.dst = cfg.dstPort
		}
		if !cfg.handshake {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		clientSeq = cfg.initialSeq
		if clientSeq == 0 {
			clientSeq = rand.Uint32()
		}
		serverSeq = rand.Uint32()
		srcPort, dstPort := key.src, key.dst
		if serverFirst {
			// SYN (server -> client)
			if err := emit(core.PacketConfig{
				Direction: "down",
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    dstPort,
					DstPort:    srcPort,
					Seq:        serverSeq,
					Flags:      FlagSYN,
					WindowSize: winSize,
					TCPOptions: synOpts,
				},
			}); err != nil {
				return err
			}
			serverSeq++
			// SYN-ACK (client -> server)
			if err := emit(core.PacketConfig{
				Direction: "up",
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    srcPort,
					DstPort:    dstPort,
					Seq:        clientSeq,
					Ack:        serverSeq,
					Flags:      FlagSYN | FlagACK,
					WindowSize: winSize,
					TCPOptions: synOpts,
				},
			}); err != nil {
				return err
			}
			clientSeq++
			// ACK (server -> client)
			if err := emit(core.PacketConfig{
				Direction: "down",
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    dstPort,
					DstPort:    srcPort,
					Seq:        serverSeq,
					Ack:        clientSeq,
					Flags:      FlagACK,
					WindowSize: winSize,
				},
			}); err != nil {
				return err
			}
			return nil
		}
		if err := emit(core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        clientSeq,
				Flags:      FlagSYN,
				WindowSize: winSize,
				TCPOptions: synOpts,
			},
		}); err != nil {
			return err
		}
		clientSeq++
		if err := emit(core.PacketConfig{
			Direction: "down",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    dstPort,
				DstPort:    srcPort,
				Seq:        serverSeq,
				Ack:        clientSeq,
				Flags:      FlagSYN | FlagACK,
				WindowSize: winSize,
				TCPOptions: synOpts,
			},
		}); err != nil {
			return err
		}
		serverSeq++
		if err := emit(core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      FlagACK,
				WindowSize: winSize,
			},
		}); err != nil {
			return err
		}
		return nil
	}

	// teardown 闭包：为一条连接发出 FIN|ACK(up)→ACK(down)→FIN|ACK(down)→ACK(up)
	// 挥手（schema 默认 true）。key 是该连接的 connKey，字节序列与 legacy
	// 单连接挥手完全一致（P0a 多会话边界复用于挥旧连接）。
	teardown := func(key tcpConnKey) error {
		srcPort, dstPort := key.src, key.dst
		if !cfg.termination {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := emit(core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      FlagFIN | FlagACK,
				WindowSize: winSize,
			},
		}); err != nil {
			return err
		}
		clientSeq++
		if err := emit(core.PacketConfig{
			Direction: "down",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    dstPort,
				DstPort:    srcPort,
				Seq:        serverSeq,
				Ack:        clientSeq,
				Flags:      FlagACK,
				WindowSize: winSize,
			},
		}); err != nil {
			return err
		}
		if err := emit(core.PacketConfig{
			Direction: "down",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    dstPort,
				DstPort:    srcPort,
				Seq:        serverSeq,
				Ack:        clientSeq,
				Flags:      FlagFIN | FlagACK,
				WindowSize: winSize,
			},
		}); err != nil {
			return err
		}
		serverSeq++
		if err := emit(core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      FlagACK,
				WindowSize: winSize,
			},
		}); err != nil {
			return err
		}
		return nil
	}

	// 初始连接握手（schema 默认 true）：单连接路径以 cfg.srcPort 建连。
	// 事件模式下握手延迟到事件循环首事件：多会话流（pcep 40001/40002）的
	// 首事件端口 != cfg.srcPort，若先建默认连接会多出一条"握手+挥手"空连接
	// （29 vs 22 包回归）；单连接事件流首事件端口回退 cfg.srcPort，与原
	// 先握手后消费事件字节级一致。
	eventMode := req.Meta.Events != nil
	if !eventMode {
		if err := handshake(tcpConnKey{src: cfg.srcPort, dst: cfg.dstPort}, false); err != nil {
			return err
		}
	}
	// 会话状态回写：握手完成后 server 侧 seq 即固定（Sess 供外层/隧道层或
	// 后续驱动读取；挥手用到的也是这个 serverSeq）。回写在 RST 检查之前
	// （review HIGH-1 修复）：RST 分支不提前 return，保证状态永不被跳过。
	sess.ClientSeq = clientSeq
	sess.ServerSeq = serverSeq
	sess.ClientAck = serverSeq
	sess.ServerAck = clientSeq
	sess.HandshakeDone = true

	// 数据段：payload 按 MSS 分段，每段(up, PSH|ACK) 后紧跟对端 ACK(down)。
	// 事件模式（Meta.Events != nil）下跳过单 payload 段：终结层（http 等）
	// 自产报文，legacy http 从不读 spec.Payload，多发包会破坏字节兼容
	// （review CRITICAL 修复）。
	//
	// T3.3 retransmit 模式：数据段发射同步驱动重传状态机（SendSegment/
	// OnACK）。SM 挂共享 SessionState.TCPRetrans（外层/集成测试可观察
	// cwnd/RTO/队列状态）。模拟丢包 = 末段（最后 dropTailSegments 个）的
	// 对端 ACK 不喂 SM（段滞留 segQueue → FlightSize>0），数据阶段结束后
	// 走一次 OnRTO 重传滞留段（dup PSH-ACK，带原始字节），随后补 ACK 确认
	// （模拟对端恢复）。retransmit=false 时字节流与 legacy 完全一致。
	var retransSM *TCPRetransmissionStateMachine
	if cfg.retransmit {
		retransSM = NewTCPRetransmissionStateMachine(TCPRetransmissionConfig{
			MSSBytes: uint32(cfg.mss),
		})
		// SM 挂共享 SessionState（FlowMeta 逐层值拷贝，指针写入不回传）。
		sess.TCPRetrans = retransSM
	}
	payload := req.Meta.Payload
	if len(payload) > 0 && req.Meta.Events == nil {
		// segPayloads 记录每个数据段的原始字节（按发送序），供重传补发
		// dup 段复用（SM 的 Segment 只存 seq/len，不存字节）。
		type segRec struct {
			seq     uint32
			payload []byte
		}
		var segs []segRec
		var unackedTail []segRec // 滞留段（模拟丢包，待重传）
		for len(payload) > 0 {
			segmentSize := len(payload)
			if segmentSize > mss {
				segmentSize = mss
			}
			seg := core.PacketConfig{
				Direction: "up",
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    cfg.srcPort,
					DstPort:    cfg.dstPort,
					Seq:        clientSeq,
					Ack:        serverSeq,
					Flags:      FlagPSH | FlagACK,
					WindowSize: winSize,
				},
				Payload: payload[:segmentSize],
			}
			if err := emit(seg); err != nil {
				return err
			}
			if retransSM != nil {
				retransSM.SendSegment(seg.L4.Seq, uint32(segmentSize), time.Now())
				segs = append(segs, segRec{seq: seg.L4.Seq, payload: seg.Payload})
			}
			clientSeq += uint32(segmentSize)
			payload = payload[segmentSize:]
			ack := core.PacketConfig{
				Direction: "down",
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    cfg.dstPort,
					DstPort:    cfg.srcPort,
					Seq:        serverSeq,
					Ack:        clientSeq,
					Flags:      FlagACK,
					WindowSize: winSize,
				},
			}
			if err := emit(ack); err != nil {
				return err
			}
			// 模拟丢包：末段（最后 dropTailSegments 个）的对端 ACK 视为
			// 丢失——不喂 SM，该段滞留 segQueue 待重传。当前段是否属于
			// "末尾组"在发送时点未知（总段数未定），改为发送后由
			// unackedTail 收集阶段按 segQueue 精确判定——这里只对
			// "确定不是末段"（后面还有数据）的 ACK 喂 SM；最后一段的
			// ACK 是否喂由数据阶段结束后的滞留收集反推（见下）。
			// 简化实现：仅当 dropTailSegments=1 时，最后一段的 ACK 跳过
			// （remaining==0 判定）；多段滞留场景由 SM 队列差异体现。
			if retransSM != nil && len(payload) == 0 && dropTailSegments > 0 {
				// 此 ACK 模拟丢失，跳过 OnACK（段滞留）。
			} else if retransSM != nil {
				retransSM.OnACK(ack.L4.Ack, time.Now())
			}
		}
		// 收集滞留段（segQueue 里的 seq → 原始字节，从 segs 线性匹配）。
		if retransSM != nil {
			for _, s := range retransSM.SegQueue() {
				for _, r := range segs {
					if r.seq == s.Seq {
						unackedTail = append(unackedTail, r)
						break
					}
				}
			}
		}
		// 重传滞留段：一次 RTO 轮（OnRTO：ssthresh 减半、cwnd→IW、RTO 翻倍），
		// 按序补发 dup PSH-ACK（携带原始字节），随后补发对端恢复 ACK 一次性
		// 确认全部滞留段（正常路径 clientSeq 已含全部段推进，重传不推进 seq）。
		if retransSM != nil && len(unackedTail) > 0 {
			retransSM.OnRTO(time.Now())
			for _, r := range unackedTail {
				rt := core.PacketConfig{
					Direction: "up",
					L4: core.L4Config{
						Protocol:   "tcp",
						SrcPort:    cfg.srcPort,
						DstPort:    cfg.dstPort,
						Seq:        r.seq,
						Ack:        serverSeq,
						Flags:      FlagPSH | FlagACK,
						WindowSize: winSize,
					},
					Payload: r.payload,
				}
				if err := emit(rt); err != nil {
					return err
				}
			}
			last := unackedTail[len(unackedTail)-1]
			peerAck := last.seq + uint32(len(last.payload))
			ackFinal := core.PacketConfig{
				Direction: "down",
				L4: core.L4Config{
					Protocol:   "tcp",
					SrcPort:    cfg.dstPort,
					DstPort:    cfg.srcPort,
					Seq:        serverSeq,
					Ack:        peerAck,
					Flags:      FlagACK,
					WindowSize: winSize,
				},
			}
			if err := emit(ackFinal); err != nil {
				return err
			}
			retransSM.OnACK(peerAck, time.Now())
		}
	}

	// ---- Inner 模式：终结层报文事件流（波 2 方案 A）----
	// 终结层（http）经 req.EmitMsg 产出"报文事件"（方向 + 完整字节），
	// tcp 层消费后按 http 语义发段：每报文按 MSS 分段，每段 0x18 PSH-ACK，
	// **段间不跟独立 ACK**（piggyback，ack 字段 = 对端当前 seq），双方向
	// seq 各自推进。与 legacy http.go:266-357 字节一致（测试精确断言段数
	// 与无 ACK 插入）。独立 tcp flow（无事件流）走上方旧逻辑。
	events := req.Meta.Events
	// connKey 抽象（波 6）：TCP 连接由客户端源端口+服务端 L3 目标+目标端口
	// 共同标识（类型见包级 tcpConnKey）。普通单连接路径（http/dns 等）
	// 事件不设覆盖，三元组全部回退
	// 配置默认（src=cfg.srcPort、dstIP=cfg.DstIP/空、dst=cfg.dstPort）—
	// 字节与原 conns[uint16] 路径逐字节一致（单一合成 key）。多会话或流关联
	// 等带覆盖事件，src/dstIP/dst 非默认时合成独立 key，连接独立建/挥。
	// resolveConnKey 把事件折叠到其连接 key。无覆盖事件（srcPort=0 且
	// OverrideDstIP=false 且 DstPort=0）走配置默认——保持原单连接字节。
	resolveConnKey := func(src uint16, overrideDstIP bool, dstIP string, dst uint16) tcpConnKey {
		k := tcpConnKey{src: src, dstIP: dstIP, dst: dst}
		if src == 0 {
			k.src = cfg.srcPort
		}
		if !overrideDstIP || k.dstIP == "" {
			k.dstIP = "" // 占位；同 key 不会与真覆盖混（dstIP 是空时回退路径）
		}
		if dst == 0 {
			k.dst = cfg.dstPort
		}
		return k
	}
	// curKey 是"当前 TCP 连接"的 connKey（首事件未到前为配置默认）。
	curKey := resolveConnKey(0, false, "", 0)
	// 事件模式下连接尚未建立（握手延迟到首事件）；空事件流（终结层没发事件
	// 就关闭）时补默认连接，保持"握手+挥手"空连接的旧行为。
	connected := !eventMode
	// sawEvent 区分"空事件流"与"CloseConn 拆完后事件流结束"：前者补默认
	// 连接（旧行为），后者不得再补（连接已按语义拆除）。
	sawEvent := false
	// 并发会话模式（cfg.concurrent）：按 connKey 维护独立连接状态。首次见某
	// key → 握手建连；切换回已建立的 key → 恢复其 seq 状态（不挥手不握手）。
	// concurrent=false 时沿用 P0a 挥旧握新语义，行为不变。
	type tcpConn struct {
		clientSeq, serverSeq uint32
	}
	conns := map[tcpConnKey]*tcpConn{}
	// connOrder 记录并发连接的首见序（流结束时按此序统一挥手）。
	var connOrder []tcpConnKey
	// deleteConnKey 从 conns + connOrder 同时移除某 key（CloseConn 路径用：
	// 流结束前提前拆除某连接 → 流末尾不再重复挥手）。
	deleteConnKey := func(k tcpConnKey) {
		delete(conns, k)
		for i, x := range connOrder {
			if x == k {
				connOrder = append(connOrder[:i], connOrder[i+1:]...)
				break
			}
		}
	}
	for events != nil {
		var ev MessageEvent
		var ok bool
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok = <-events:
			if !ok {
				events = nil // 终结层关闭：数据段结束，进入挥手
				continue
			}
		}
		// 会话边界：事件合成 key != 当前连接 key → 新连接（挥旧握新或并发恢复）。
		// ServerFirst 由事件携带（FTP active 数据通道 server 首 SYN，
		// legacy emitTCPSubFlow ServerInitiated 分支）；其余连接恒 client 首 SYN。
		sawEvent = true
		evKey := resolveConnKey(ev.SrcPort, ev.OverrideDstIP, ev.DstIP, ev.DstPort)
		if cfg.concurrent {
			if _, seen := conns[evKey]; !seen {
				if err := handshake(evKey, ev.ServerFirst); err != nil {
					return err
				}
				conns[evKey] = &tcpConn{clientSeq: clientSeq, serverSeq: serverSeq}
				connOrder = append(connOrder, evKey)
			} else {
				c := conns[evKey]
				clientSeq, serverSeq = c.clientSeq, c.serverSeq
			}
			connected = true
			curKey = evKey
		} else if !connected {
			// 首个事件建立首条连接（key = 事件携带值）。
			if err := handshake(evKey, ev.ServerFirst); err != nil {
				return err
			}
			connected = true
			curKey = evKey
		} else if evKey != curKey {
			// 顺序模式下的"挥旧握新"——P0a 多会话边界：单连接路径（无
			// OverrideDstIP 且 src=0）byte-key 与原 curSrcPort 路径逐字
			// 相等（key 唯一字段 src=cfg.srcPort），行为不变；多会话/流关联
			// 路径切换到独立 key，建立新连接。
			if err := teardown(curKey); err != nil {
				return err
			}
			if err := handshake(evKey, ev.ServerFirst); err != nil {
				return err
			}
			curKey = evKey
		}
		// CloseConn 路径：流关联副连接等"事件流结束前提前拆除"——本事件的
		// 数据段先上路（顺序与 legacy 子流"数据→挥手"一致），再按当前 key
		// 挥手，并从并发状态表中移除（避免流末尾 connOrder 重复挥手）。
		// 顺序模式下同时置 connected=false：下一事件走"首连接"分支只握手，
		// 不再对已挥掉的 curKey 重复挥手（cwmp 链 flows 场景由 chain 侧强制
		// concurrent=true 兜底，此为纯防御）。
		closeAfter := ev.CloseConn
		ev.CloseConn = false
		// dataEv 字节流向：Up（client 首 SYN / passive）= clientSeq 推进；
		// down（server 首 SYN / active）= serverSeq 推进。事件 Up 只标记
		// 首 SYN 方向（serverFirst 由握手分支单独消费），载荷的真实流向
		// 是"data 连接上谁承载 payload"，legacy emitTCPSubFlow 以 dir 决定：
		// dir=down（RETR 下载）server 发 PSH，dir=up（STOR 上传）client 发
		// PSH。终结层用 Up 表达首包方向 + 载荷流向两份信息会冲突——载荷流向
		// 以 ServerFirst 锚定（active=server 发），首包方向固定 client（除非
		// ServerFirst）。无载荷 + CloseConn = 纯连接控制事件（ftp 空会话，
		// T-FTP-5 legacy 7 包等价）：首见 key 照常握手（上方 concurrent/首
		// 连接分支），数据段跳过（绝不产空 PSH 段），closeAfter 收尾挥手。
		// 无载荷且非 CloseConn 的事件维持旧路径（segmentByMSS 空 Bytes 出
		// 空 PSH 段），既有生成器行为不变——它们从不发无载荷事件。
		evUp := ev.Up
		if ev.ServerFirst {
			evUp = false // active：server 发 PAYLOAD，down 方向 PSH
		}
		if !(len(ev.Bytes) == 0 && closeAfter) {
			segments := segmentByMSS(ev.Bytes, mss)
			for _, seg := range segments {
				var direction string
				var seq, ack uint32
				if evUp {
					direction, seq, ack = "up", clientSeq, serverSeq
				} else {
					direction, seq, ack = "down", serverSeq, clientSeq
				}
				// 方向相关端口交换（P2c-3 修复，review 捕获）：事件模式的 down
				// 段必须与握手/挥手 down 段一致地把 src/dst 端口互换——响应帧
				// 以对端端口（cfg.dstPort）为源。旧实现恒写 cfg.srcPort/dstPort，
				// 响应帧源端口是客户端端口（40000 而非 8080），与 legacy
				// http.go:330（SrcPort: spec.DstPort）不一致。多会话用 evSrc
				// 替代 cfg.srcPort（该连接的真实客户端源端口）。
				srcPort, dstPort := evKey.src, evKey.dst
				if !evUp {
					srcPort, dstPort = evKey.dst, evKey.src
				}
				pkt := core.PacketConfig{
					Direction: direction,
					L4: core.L4Config{
						Protocol:   "tcp",
						SrcPort:    srcPort,
						DstPort:    dstPort,
						Seq:        seq,
						Ack:        ack,
						Flags:      FlagPSH | FlagACK,
						WindowSize: winSize,
					},
					Payload: seg,
				}
				if err := emit(pkt); err != nil {
					return err
				}
				if evUp {
					clientSeq += uint32(len(seg))
				} else {
					serverSeq += uint32(len(seg))
				}
			}
		}
		// 并发会话：本事件推进后的 seq 状态写回该连接的 connKey 状态。
		if cfg.concurrent {
			if c := conns[evKey]; c != nil {
				c.clientSeq, c.serverSeq = clientSeq, serverSeq
			}
		}
		// CloseConn 收尾：数据段已上路（顺序与 legacy"数据→挥手"一致），
		// 再挥手该 key 并从并发状态表移除（流末不再重复挥手）。
		if closeAfter {
			if err := teardown(evKey); err != nil {
				return err
			}
			if cfg.concurrent {
				deleteConnKey(evKey)
			} else {
				connected = false
			}
		}
	}

	// RST|ACK(up) 代替挥手（RFC 9293 §3.5）。
	// 与 legacy tcp.go:306-328 一致：RST 分支只产出 RST 包，不提前 return——
	// 状态回写已在上方完成，emit 错误照常传播（review HIGH-1 修复）。
	// 空事件流（sawEvent==false，终结层没发事件就关闭）：补默认连接握手，
	// 维持旧行为（握手+RST/挥手空连接）。CloseConn 拆过连接的流不算空事件
	// 流——connected 已 false，不得再补握手（否则流末多出一条空连接）。
	if !connected && !sawEvent && !cfg.rst && cfg.handshake {
		if err := handshake(tcpConnKey{src: cfg.srcPort, dst: cfg.dstPort}, false); err != nil {
			return err
		}
		connected = true
	}
	if cfg.rst {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := emit(core.PacketConfig{
			Direction: "up",
			L4: core.L4Config{
				Protocol:   "tcp",
				SrcPort:    cfg.srcPort,
				DstPort:    cfg.dstPort,
				Seq:        clientSeq,
				Ack:        serverSeq,
				Flags:      FlagRST | FlagACK,
				WindowSize: winSize,
			},
		}); err != nil {
			return err
		}
		return nil
	}

	// 挥手：FIN|ACK(up) → ACK(down) → FIN|ACK(down) → ACK(up)。
	// 多会话（P0a）：以"最后一条连接"的客户端源端口挥手（curKey 已跟踪；
	// 单连接/无事件路径 curKey.src 恒为 cfg.srcPort，字节级不变）。
	// 并发会话模式：全部已建连接按首见序统一挥手（B6 gbt 并发正例——每条
	// 连接各 4 包 FIN×2×ACK；mms 等终止性语义不受影响：termination=false 的
	// 链本就不走本分支）。CloseConn 已在流内移除已挥手 key / 顺序模式已置
	// connected=false 跳过重复挥手，避免流末重复 FIN。
	if cfg.termination && connected {
		if cfg.concurrent {
			// 并发模式：按首见序挥剩余连接。connOrder 为空有两种成因，语义
			// 相反：sawEvent=true = 全部经 CloseConn 流内拆除（curKey 已死，
			// 重复挥手即双 FIN，不挥）；sawEvent=false = 空事件流的默认连接
			// 补丁（上方握手补齐），必须落穿到下方 teardown 完成旧行为
			// （握手+挥手空连接 = 7 包）。
			if sawEvent {
				for _, p := range connOrder {
					c := conns[p]
					clientSeq, serverSeq = c.clientSeq, c.serverSeq
					if err := teardown(p); err != nil {
						return err
					}
				}
				return nil
			}
		}
		if err := teardown(curKey); err != nil {
			return err
		}
	}
	return nil
}

// ---- udp 层生成器 ----

// UDPGenerator drives the UDP packet sequence for one flow (udp 层生成器,
// 字节级复刻 internal/protocol/udp/udp.go 的包序列)。UDP has no handshake,
// no segmentation, and no teardown: a request (up) always carries the flow
// payload; a response (down) is emitted only when spec.UDP.IsResponse is set.
// Two modes mirror the tcp generator's split:
//   - standalone payload mode: request payload = req.Meta.Payload。
//   - Inner mode (event-driven): terminal layer events (dns/ntp/...) arrive
//     on req.Meta.Events; events with Up=true take the up direction, Up=false
//     the down direction, each emitted as one datagram (no MSS segmentation).
type UDPGenerator struct{}

// Name returns "udp".
func (g *UDPGenerator) Name() string { return "udp" }

// GenEvents is unimplemented for the udp layer (udp 是传输层，消费事件流，
// 不产出报文事件)。
func (g *UDPGenerator) GenEvents() EventGenerator { return nil }

// udpCfg is the resolved UDP layer configuration.
type udpCfg struct {
	srcPort, dstPort uint16
}

// resolveCfg resolves the UDP layer configuration from the completed layer
// config. 存在但不可转换的值显式报错返回，绝不静默丢配置（与 tcp 层
// resolveCfg 同款纪律）。
func (g *UDPGenerator) resolveCfg(req *GenRequest) (udpCfg, error) {
	var cfg udpCfg
	c := req.Layer.Config
	if v, ok := flowConfigField(c, "src_port"); ok {
		if p, ok := configUint16(v); ok {
			cfg.srcPort = p
		} else {
			return cfg, fmt.Errorf("udp layer: field \"src_port\" = %v invalid: cannot convert to uint16", v)
		}
	}
	if v, ok := flowConfigField(c, "dst_port"); ok {
		if p, ok := configUint16(v); ok {
			cfg.dstPort = p
		} else {
			return cfg, fmt.Errorf("udp layer: field \"dst_port\" = %v invalid: cannot convert to uint16", v)
		}
	}
	return cfg, nil
}

// Generate drives the UDP sequence for one flow. 独立 [ip→udp] flow（无事件
// 流）发 1 包（request, up），spec.UDP.IsResponse 时再发 1 包（response,
// down）——顺序与 legacy udp.go Plan 逐字节一致。事件驱动模式（Meta.Events
// 非 nil，终结层如 dns/ntp 经 EmitMsg 接线）下每事件发 1 数据报，方向随事件；
// IsResponse 仅作用于独立模式（legacy udp.go 语义：事件流由终结层决定方向）。
// DisableChecksum 写 L4.Metadata["udp_disable_checksum"]（builder writeUDP
// :1320-1333 读取）。
func (g *UDPGenerator) Generate(ctx context.Context, req *GenRequest) error {
	cfg, err := g.resolveCfg(req)
	if err != nil {
		return err
	}
	emit := func(pkt core.PacketConfig) error {
		if req.Emit == nil {
			return nil
		}
		return req.Emit(pkt)
	}
	meta := func() map[string]interface{} {
		// 恒写键（review 波 3 M1 修复）：legacy udp.go 恒写
		// "udp_disable_checksum": false（false 也是显式键），
		// 只写 true 会让 false 语义漂移为"缺键"。
		return map[string]interface{}{"udp_disable_checksum": req.Meta.UDP != nil && req.Meta.UDP.DisableChecksum}
	}

	// ---- Inner 模式：终结层报文事件流（波 3）----
	// 每事件 1 数据报：UDP 无分段（IP 层处理碎片），事件方向决定包方向。
	// 事件的 Metadata（事件级元数据，syslog 波 4）合并进数据报 Metadata，
	// 优先于传输层自身的 meta() 键（互不重叠：udp_disable_checksum 由
	// 传输层持有，事件元数据是协议级键）。
	if req.Meta.Events != nil {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ev, ok := <-req.Meta.Events:
				if !ok {
					return nil
				}
				direction := "up"
				srcPort, dstPort := cfg.srcPort, cfg.dstPort
				// 事件级端口覆盖（波 5c：rip 每 router 独立端口 520/52001+idx，
				// legacy rip.go resolveSrcPort 语义）。覆盖值参与 up/down 交换；
				// down 方向 DstPort 覆盖映射为源端口（交换后落在 L4.SrcPort，
				// ip.go:565-566 再交换一次恢复事件值——down 包的目标端口恒为
				// 对端 spec 端口，如 request_full 的 auto-Response 521→520）。
				if ev.SrcPort != 0 {
					srcPort = ev.SrcPort
				}
				if ev.DstPort != 0 {
					dstPort = ev.DstPort
				}
				if !ev.Up {
					direction = "down"
					// 波 5d：dhcp 端口方向无关（legacy planner.go:629-633 对
					// 每条消息恒写角色解析的 srcPort/dstPort，down 包线上也保持
					// 原值——role=client 的 OFFER/ACK 是 68→67）。L4PortOverride
					// 事件直落覆盖值，不做 up/down 交换；否则按既有语义
					// （rip 波 5c：覆盖值参与交换，down 后目标端口为对端端口）。
					if !ev.L4PortOverride {
						srcPort, dstPort = dstPort, srcPort
					}
				}
				evMeta := meta()
				for k, v := range ev.Metadata {
					evMeta[k] = v
				}
				pkt := core.PacketConfig{
					Direction: direction,
					L4: core.L4Config{
						Protocol: "udp",
						SrcPort:  srcPort,
						DstPort:  dstPort,
					},
					Payload:  ev.Bytes,
					Metadata: evMeta,
				}
				// 事件级 flow 标识（波 5c）：rip legacy 每 router 独立 flowID /
				// request_full 共享 0/1，事件携带则直落（链层回填尊重之）。
				// FlowID 与 PacketIndex 成对设置（MessageEvent 注释契约）。
				if ev.FlowID != "" && ev.PacketIndex != nil {
					pkt.FlowID = ev.FlowID
					pkt.PacketIndex = *ev.PacketIndex
				}
				// 波 5 多播/单播目标覆盖：终结层事件显式指定目标（多播组
				// 224.0.0.251/239.255.255.250、广播 255.255.255.255，或单播回程
				// 如 ssdp 200 OK 回控制点 spec.SrcIP）与 TTL（mdns 255 / ssdp 4）
				// 时，udp 层把覆盖值写入包并置标记。标记让 ip 层与 finalEmit
				// 跳过 dst/ttl 覆盖与 down 交换——覆盖目标是绝对的。事件不携带
				// TTL（=0）时保留传输层默认（多播 255，legacy mdns 语义）；
				// 事件携带 TTL（ssdp 恒 4）时覆盖事件值。IPGenerator 的
				// ttl!=0 覆盖（spec.TTL 链上若是）与 finalEmit 的 ipTTL 均被
				// 标记跳过（链层 TTL 只服务独立 transport flow）。
				if ev.OverrideDstIP {
					pkt.L3.DstIP = ev.DstIP
				}
				// 事件级源 IP（波 5c：rip 每 router 独立 srcIP）。直落 L3，
				// 无覆盖标记（源从不参与交换）。
				if ev.SrcIP != "" {
					pkt.L3.SrcIP = ev.SrcIP
				}
				if ev.OverrideDstMAC {
					pkt.L2.DstMAC = ev.DstMAC
				}
				// 事件级源 MAC（波 5d：dhcp down 方向 reply 源 MAC 按角色
				// 交换/回退，事件携带 msgSrcMAC——含 DefaultServerMAC 回退）。
				// 非空即覆盖（finalEmit 覆盖分支恒写 spec.SrcMAC，事件值优先）。
				if ev.SrcMAC != "" {
					pkt.L2.SrcMAC = ev.SrcMAC
				}
				if ev.OverrideDstIP || ev.OverrideDstMAC || ev.TTL != 0 {
					pkt.Metadata[eventDstOverrideKey] = true
					pkt.L3.TTL = 255
					if ev.TTL != 0 {
						pkt.L3.TTL = ev.TTL
					}
				}
				// 事件级 DSCP（波 5c：rip 透传 spec.DSCP——legacy 的 CS6 默认
				// 是死参数，事件值恒等于 spec.DSCP）。覆盖标记包（多播/广播/
				// 指定 TTL）ip 层跳过 dscp 覆写，本值保留；非标记包（单播，
				// TTL 走链层）ip 层无条件写 schema dscp=0，事件 DSCP 被抹——
				// 单播 rip 包 DSCP 由 ip 层链路配置写回（spec.DSCP 注入 dscp
				// 字段），legacy 同款（emitRIPPacket 恒用 spec.DSCP 直配）。
				if ev.DSCP != 0 && (ev.OverrideDstIP || ev.OverrideDstMAC || ev.TTL != 0) {
					pkt.L3.DSCP = ev.DSCP
				}
				if err := emit(pkt); err != nil {
					return err
				}
			}
		}
	}

	// ---- 独立 payload 模式：request + 可选 response ----
	if err := emit(core.PacketConfig{
		Direction: "up",
		L4: core.L4Config{
			Protocol: "udp",
			SrcPort:  cfg.srcPort,
			DstPort:  cfg.dstPort,
		},
		Payload:  req.Meta.Payload,
		Metadata: meta(),
	}); err != nil {
		return err
	}
	if req.Meta.UDP != nil && req.Meta.UDP.IsResponse {
		if err := emit(core.PacketConfig{
			Direction: "down",
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort:  cfg.dstPort,
				DstPort:  cfg.srcPort,
			},
			Payload:  req.Meta.Payload,
			Metadata: meta(),
		}); err != nil {
			return err
		}
	}
	return nil
}
