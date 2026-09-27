package layers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// Package layers is part of the layer-chain architecture (v3) for
// the trafficgen core. This file is one of the five chain_planner*.go
// files split from the original monolithic chain_planner.go
// (T1.3 of docs/superpowers/plans/2026-09-03-layerchain-implementation.md).
//
// Original file: 2,893 lines (5 sections, 65 functions).
// This file: chain_planner_translate.go
//   - drive() and translateTerminalConfig() (per-protocol terminal config translation; biggest function in the package).
//
// Per-package conventions: type names (ChainPlanner, FlowMeta, etc.)
// are package-local; only file boundaries change.

// drive instantiates the generators inner→outer, wires the channels, and
// drives the outermost generator of the chain — which for a standalone tcp
// flow is the tcp generator itself (终结/传输层驱动整链)。Each packet flows
// inner → outer: the tcp generator emits L4-only packets into innerCh, the ip
// generator consumes them, fills the L3 config (src/dst/ttl/dscp/ecn/frag +
// IPID), and hands each wrapped packet to finalEmit, which assembles L2 (MACs
// swapped per direction), derives the direction-dependent src/dst IP swap,
// and backfills FlowID/PacketIndex/Timestamp.
//
// gens 由 Plan 同步预实例化并传入（review 波 3 修复：生成器实例化与事件
// 接线断言的结构性错误同步报错，drive 只承担运行时驱动）。
//
// 返回完整包序列（全量收集于内存，review CRITICAL-1 修复）：驱动失败/取消时
// 返回已收集的包 + 错误；ip 生成器退出后（genDone）drive 才返回，Plan 的
// goroutine 据此在**所有生产结束后**才 close(out)（消除 send-on-closed 竞态）。
// 取消路径（ctx.Done）经 select 在 finalEmit 传播，ip goroutine 正常退出，
// 不会产生泄漏。
func (p *ChainPlanner) drive(ctx context.Context, chain []Layer, gens []LayerGenerator, spec core.FlowSpec) ([]core.PacketConfig, error) {
	sess := &SessionState{IPID: uint16(rand.Uint32())}
	var meta = FlowMeta{
		FlowID:    flowID(spec),
		Payload:   spec.Payload,
		FlowIndex: spec.FlowIndex, // 多流会话级 dyn 解析（FTP sessions/banner/dyn 一族，flowMetaFor 同款字段；漏传时 dyn 恒按 index 0 解析）
		// HTTP/DstIP 注入给 http 层生成器（波 2 方案 A）：HTTPConfig 全量字段
		// 不落层 config（ValidateLayerConfig 拒绝未知字段），经 Meta 直传。
		// UDP 同款：UDPConfig 经 Meta.UDP 直传 udp 层生成器（波 3）。
		// DNS/NTP/SNMP/Syslog 同款（波 4）：协议配置经 Meta 直传终结层生成器。
		// MDNS 同款（波 5a）。SSDP 同款（波 5b）：配置 + 默认端口经 Meta 直传
		// ssdp 层生成器（端口 validateSpecBase 已默认化 1900）。
		HTTP:   spec.HTTP,
		UDP:    spec.UDP,
		DNS:    spec.DNS,
		NTP:    spec.NTP,
		SNMP:   spec.SNMP,
		Syslog: spec.Syslog,
		MDNS:   spec.MDNS,
		SSDP:   spec.SSDP,
		RIP:    spec.RIP,
		DHCP:   spec.DHCP,
		// DHCPv6 同款（波 5e）：配置经 Meta 直传 dhcpv6 层生成器（DUID/
		// scenario/relay 解析全部在生成器内，planner.go Plan 同款）。
		DHCPv6: spec.DHCPv6,
		// TFTP 同款（P4a）：配置经 Meta 直传 tftp 终结层生成器（Plan 内
		// 复刻——同一 Validate/默认化/emit 序列）。
		TFTP: spec.TFTP,
		// ENIP 同款（P4a）：配置经 Meta 直传 enip 终结层生成器（命令即
		// 数据段，事件按 buildENIPPacket 逐命令产出，字节级一致）。
		ENIP: spec.ENIP,
		// DNP3 同款（P4a）：配置经 Meta 直传 dnp3 终结层生成器（scenario
		// 展开逐帧事件，scenarioFrames 复用）。
		DNP3: spec.DNP3,
		// DoIP 同款（P4a）：配置经 Meta 直传 doip 终结层生成器（阶段逐
		// 报文事件，build* 纯函数复用）。
		DoIP: spec.DoIP,
		// GBT32960 同款（P4a）：配置经 Meta 直传 gbt32960 终结层生成器
		// （状态机逐消息事件，buildMessage 纯函数复用）。
		GBT32960: spec.GBT32960,
		// MCP 同款（P4a）：配置经 Meta 直传 mcp 终结层生成器（会话状态机
		// 逐消息事件，build* 纯函数复用）。
		MCP: spec.MCP,
		// MODBUS 同款（P4a）：配置经 Meta 直传 modbus 终结层生成器（事务
		// 循环逐帧事件，build* 纯函数复用）。
		MODBUS: spec.MODBUS,
		// MQTT 同款（P4a）：配置经 Meta 直传 mqtt 终结层生成器（会话序列
		// 逐帧事件，build* 纯函数复用）。
		MQTT: spec.MQTT,
		// NFS 同款（P4a）：配置经 Meta 直传 nfs 终结层生成器（RPC 调用/回复
		// 逐事件产出，buildCall/buildReply 纯函数复用）。interface{}——
		// core 无法 import protocol/nfs（protocol 包反向依赖 core），经
		// spec.Metadata["nfs"] 原样传递（mapToFlowSpec 存 JSON 解码子 map），
		// 生成器侧解析。
		NFS:  spec.Metadata["nfs"],
		FINS: spec.Metadata["fins"],
		// CoAP 同款（P4a）：配置经 Meta 直传 coap 终结层生成器（请求 + 可选
		// ACK 响应两事件，BuildMessage 纯函数复用）。缺这行时 req.Meta.CoAP
		// 恒 nil → 生成器回退默认 GET/无响应 → 所有 coap 链只发 1 包。
		CoAP: spec.CoAP,
		// D-SIP-2 WP-D：sip 事件面同款（dialog→MessageEvents 生成器读
		// Meta.SIP）。此前 sip 走 isRawIPChain 自驱分支（flowMetaFor 有
		// SIP 字段）——事件面分支在本 drive 内联 meta 清单补齐。
		SIP:        spec.SIP,
		S7:         spec.S7,
		IEC104:     spec.IEC104,
		GOOSE:      spec.GOOSE,
		SV:         spec.SV,
		OPCUA:      spec.OPCUA,
		MMS:        spec.MMS,
		BGP:        spec.BGP,
		STUN:       spec.STUN,
		HTTPFLV:    spec.HTTPFLV,
		HLS:        spec.HLS,
		HDS:        spec.HDS,
		MOXA:       spec.MOXA,
		SOMEIP:     spec.SOMEIP,
		DRDA:       spec.DRDA,
		Thrift:     spec.Thrift,
		OpenWire:   spec.OpenWire,
		AMS:        spec.AMS,
		Swarm:      spec.Swarm,
		Gnutella:   spec.Gnutella,
		TNS:        spec.TNS,
		MongoDB:    spec.MongoDB,
		Dameng:     spec.Dameng,
		PostgreSQL: spec.PostgreSQL,
		Megaco:     spec.Megaco,
		HL7:        spec.HL7,
		MMSE:       spec.MMSE,
		EDP:        spec.EDP,
		XMR:        spec.XMR,
		// D-BACNET-1：bacnet 终结层同款（sessions[]/events[] 配置经 Meta
		// 直传 bacnet 生成器；每事件一 UDP 数据报；自动应答按 respond 展开）。
		BACNET: spec.BACNET,
		// D-DCERPC-1：dcerpc 终结层同款（sessions[]/events[] 经 Meta 直传
		// 生成器；每事件按 PDU 渲染；应答按 respond 展开）。
		DCERPC: spec.DCERPC,
		// D-DTLS-1：dtls 终结层同款（sessions[]/events[] 经 Meta 直传
		// 生成器；每事件 = 一 record = 一 UDP 数据报）。
		DTLS: spec.DTLS,
		// D-KERBEROS-1：kerberos 终结层同款（sessions[]/events[] 经 Meta
		// 直传生成器；每事件 = 一消息 = 一 UDP datagram 或一 TCP record）。
		Kerberos: spec.Kerberos,
		// D-NTLM-1：ntlm 终结层同款（sessions[]/events[] 经 Meta 直传生成器；
		// 每事件 = 一 NTLMSSP 消息（按 profile 自封 SMB2/HTTP 帧）或一载体
		// 终态响应；固定检查点——Meta 字面量漏传即生成器收 nil 配置，
		// 链级红例逐项钉死（dcerpc/dtls/kerberos 三犯处教训）。
		NTLM: spec.NTLM,
		// D-SSTP-1：sstp 终结层同款（sessions[]/transactions[] 或 events[]
		// 经 Meta 直传生成器；每事务 = 一条 SSTP message，经 tls 层
		// application-data 透传——record/TCP segment 边界 ≠ SSTP Length
		// 边界，契约 §5/§8）。
		SSTP: spec.SSTP,
		// D-SPNEGO-1：spnego 终结层同款（sessions[]/events[] 经 Meta 直传
		// 生成器；固定检查点——Meta 字面量漏传即生成器收 nil 配置）。
		SPNEGO: spec.SPNEGO,
		CQL:    spec.CQL,
		// D-OCSP-1：ocsp 终结层同款（sessions[]/transactions[] 经 Meta 直传
		// 生成器；每事务 = request→response 两条消息 = HTTP 帧或整 DER）。
		OCSP:  spec.OCSP,
		LDP:   spec.LDP,
		PCEP:  spec.PCEP,
		CFlow: spec.CFlow,
		AMQP:  spec.AMQP,
		RTMFP: spec.RTMFP,
		IGMP:  spec.IGMP,
		OSPF:  spec.OSPF,
		PIM:   spec.PIM,
		ISIS:  spec.ISIS,
		// GBT 同款（B6）：sessions[]/events[] 配置经 Meta 直传 gbt 终结层
		// 生成器（每事件一笔事务一侧的完整 HTTP 帧字节；http 层透传转发）。
		GBT: spec.GBT,
		// GetWork 同款（B6）：sessions[]/events[] 配置经 Meta 直传 getwork
		// 终结层生成器（每事件一笔事务一侧的完整 HTTP 帧字节；http 层透传
		// 转发）。
		GetWork: spec.GetWork,
		// CWMP 同款（B6）：sessions[] 配置经 Meta 直传 cwmp 终结层生成器
		// （每事件一笔事务一侧的完整 HTTP 帧字节；http 层透传转发；flows[]
		// 流关联副连接在生成器内锚点发射）。
		CWMP: spec.CWMP,
		// DOH 同款（B6，66-doh）：sessions[]/events[] 配置经 Meta 直传 doh
		// 终结层生成器（每事件一笔查询事务：完整 HTTP 请求帧 + 自动应答
		// 响应帧；http 层透传转发）。
		DOH: spec.DOH,
		// ONVIF 同款（B6，67-onvif v2.1.1）：sessions[]/events[] 配置经
		// Meta 直传 onvif 终结层生成器（每事件一笔 SOAP 1.2 事务：完整
		// HTTP 请求帧 + 自动应答响应帧；http 层透传转发）。
		ONVIF: spec.ONVIF,
		// Stratum 同款（B6）：sessions[]/events[] 配置经 Meta 直传 stratum
		// 终结层生成器（每事件一条行/一对请求响应行；[tcp→stratum] 直连，
		// 无 http 层）。
		Stratum: spec.Stratum,
		// ETHMining 同款（73-ethmining v2.0.2：sessions[]/events[] 配置
		// 经 Meta 直传 ethmining 终结层生成器；每事件一条行/一对请求响应
		// 行；[tcp→ethmining] 直连，无 http 层）。
		ETHMining: spec.ETHMining,
		// NMEA 同款（69-nmea v2.0.0：sessions[]/events[] 配置经 Meta 直传
		// nmea 终结层生成器；每事件一句；[tcp→nmea]/[udp→nmea] 双载体）。
		NMEA: spec.NMEA,
		// SMB 同款（P4a）：配置经 Meta 直传 smb 终结层生成器（SMB2 会话
		// NEGOTIATE → SESSION_SETUP → TREE_CONNECT → CREATE → Operations →
		// CLOSE → TREE_DISCONNECT → LOGOFF 逐 PDU 事件，build* 纯函数复用）。
		SMB: spec.SMB,
		// SMTP 同款（P3）：配置经 Meta 直传 smtp 终结层生成器（banner + Dialog
		// 命令/响应对逐事件产出，buildSMTPEmailBody 纯函数复用）。
		SMTP: spec.SMTP,
		// Redis 同款（P3）：配置经 Meta 直传 redis 终结层生成器（RESP 会话
		// 逐帧事件，encodeRESP* 纯函数复用）。
		Redis: spec.Redis,
		// FTP 同款（FTP 链化）：配置经 Meta 直传 ftp 终结层生成器
		// （banner + 会话/命令/响应对/数据通道逐事件产出，resolveTx/
		// 端口推导复用 legacy planner）。
		FTP: spec.FTP,
		// POP3 同款（P3）：配置经 Meta 直传 pop3 终结层生成器（banner + 命令/
		// 响应对逐事件产出，buildMailDropResponse/buildTopResponse 纯函数复用）。
		POP3: spec.POP3,
		// IMAP 同款（P3）：配置经 Meta 直传 imap 终结层生成器（greeting +
		// 命令/literal/IDLE 逐事件产出，formatCommandLine 纯函数复用）。
		IMAP: spec.IMAP,
		// MySQL 同款（P3）：配置经 Meta 直传 mysql 终结层生成器（Greeting →
		// auth → 命令逐事件产出，encode*/buildReplyPackets 纯函数复用）。
		MySQL: spec.MySQL,
		// WireGuard 同款（P3）：配置经 Meta 直传 wireguard 终结层生成器
		// （UDP 数据报序列，build* 纯函数复用）。
		WireGuard: spec.WireGuard,
		// L2TP 同款（P3）：配置经 Meta 直传 l2tp 终结层生成器（UDP 隧道
		// 控制/PPP 数据报文列，build* 纯函数复用）。
		L2TP: spec.L2TP,
		// GTP 同款（P3）：配置经 Meta 直传 gtp 终结层生成器（GTP-U/C 隧道
		// 报文序列，buildGTPMessage/buildInnerIPv4Packet 纯函数复用）。
		GTP: spec.GTP,
		// IKE 同款（P3）：配置经 Meta 直传 ike 终结层生成器（IKE 消息序列 +
		// ESP 数据面，buildIKEMessageBytes 纯函数复用）。
		IKE: spec.IKE,
		// IKE-NAT-T 同款（P3）：配置经 Meta 直传 ike_nat_t 终结层生成器
		// （端口浮动 + Non-ESP Marker 的 NAT 穿透 IKE 消息序列，build*
		// 纯函数复用）。
		IKENATT: spec.IKENATT,
		// gRPC 同款（P3）：HTTP/2 preface + SETTINGS + 逐 call HEADERS/DATA/
		// trailers 逐帧事件，buildFrame/buildDataFrameStream 纯函数复用。
		GRPC: spec.GRPC,
		// SSH 同款（P3）：version exchange + KEXINIT/KEXDH + NEWKEYS + userauth
		// + channel 逐 BPP 帧事件，encode*/buildBPP 纯函数复用。
		SSH: spec.SSH,
		// RDP 同款（P3）：X.224/MCS/security PDU 序列逐帧事件，encode* 纯函数
		// 复用。Only set for rdp chains。
		RDP: spec.RDP,
		// OpenVPN 同款（P3）：UDP 数据报序列 P_CONTROL/P_DATA 事件，
		// build* 纯函数复用。Only set for openvpn chains。
		OpenVPN: spec.OpenVPN,
		// VMess 同款（P3）：TCP-mode request/response AEAD 帧序列事件，
		// build* 纯函数复用。Only set for vmess chains。
		Vmess: spec.Vmess,
		// Shadowsocks 同款（P3）：TCP-mode AEAD 帧序列 + 可选 SOCKS5/HTTP 混淆
		// 事件，build* 纯函数复用。Only set for shadowsocks chains。
		Shadowsocks: spec.Shadowsocks,
		// SOCKS 同款（J 组）：greeting/method/auth/request/reply 信令 + 隧道
		// 数据面事件，build* 纯函数复用。Only set for socks5 chains。
		Socks: spec.Socks,
		// VXLAN/Geneve/NVGRE 同款（B4 封装类）：配置经 Meta 直传终结层
		// 生成器（vxlan/geneve 逐数据报事件 + udp 载体；nvgre 自产完整包）。
		VXLAN:  spec.VXLAN,
		Geneve: spec.Geneve,
		NVGRE:  spec.NVGRE,
		// TCP 同款（P4a）：doip 0x36 分段读 spec.TCP.MSS。
		TCP:     spec.TCP,
		SrcPort: spec.SrcPort,
		DstPort: spec.DstPort,
		DstIP:   spec.DstIP,
		SrcIP:   spec.SrcIP,
		// DSCP/SrcMAC 直传终结层生成器（波 5c：rip 生成器透传 spec.DSCP——
		// legacy rip.go:494-498 的 CS6 默认是死参数——与 L2Base 的
		// spec.SrcMAC）。
		DSCP:   spec.DSCP,
		SrcMAC: spec.SrcMAC,
		// DstMAC 直传终结层生成器（波 5d：dhcp 生成器 resolveMACs 缺省回退
		// BroadcastMAC 前的 spec.DstMAC，与 role!=client 的 chaddr 回退）。
		DstMAC: spec.DstMAC,
		// TTL 直传终结层生成器（波 5b）：ssdp 生成器 honor spec.TTL 非零值
		// （legacy planner.go:282-285 同款），零值回退协议默认 4。
		TTL: spec.TTL,
	}
	// ClassID 由引擎回填（worker.go:317 config.ClassID = task.ClassID）。
	// Direction 由各层包序列自定（tcp 握手 up 发起）。

	// 1. 把 flow 级 spec 值映射进各层 config（手动值 > schema 默认值）。
	chain = p.applySpecToChain(chain, spec)

	// 2. 自内向外实例化生成器；相邻层用通道连接（内层产出 → 外层消费）。
	//    gens 已由 Plan 预实例化（instantiateGens），此处直接使用。
	innerCh := make(chan core.PacketConfig, 256)

	// 3. 驱动：最外层生成器（ip）包内层；最内层生成器（tcp 或 http）产出。
	//    通用模式：外层生成器消费内层通道；最内层生成器不消费 innerCh。
	var ipGen *IPGenerator
	var ipLayer Layer
	for i, l := range chain {
		if l.Name == "ip" {
			// 隧道链（gre）有两个 ip 层：外层（隧道端点）+ 内层（内层包）。
			// 外层生成器是链的出口，必须选**第一个**（outermost）ip 层——
			// 旧实现保留最后一个，对内层 ip 层生成器包帧后 finalEmit 再包
			// 一层，结构错乱。
			ipGen = gens[i].(*IPGenerator)
			ipLayer = chain[i]
			break
		}
	}
	if ipGen == nil {
		// 理论不可达：ip 是 transport 的 depends_on，补全必插入。
		return nil, fmt.Errorf("layers: chain for %q has no ip layer", p.name)
	}
	ipCfg := ipLayer.Config

	// 4. 出口：包齐 L2/L3 方向装配 + 元数据回填（全量收集于内存）。
	packets := make([]core.PacketConfig, 0, 64)
	finalEmit := func(pkt core.PacketConfig) error {
		// 波 5 多播覆盖：udp 层事件显式写入 L3.DstIP/L2.DstMAC（多播组/
		// 广播地址）时，同时写 Metadata[eventDstOverrideKey] 标记，该目标
		// 是绝对的——不参与 down 交换，MAC 也原样落（多播/广播 MAC 不可
		// 推导或须保持 legacy 显式值）。无覆盖事件（波 3/4 协议）无标记，
		// 走下方 legacy 语义。标记消费后移除，不泄漏到输出元数据。
		_, overrideDst := pkt.Metadata[eventDstOverrideKey]
		if overrideDst {
			delete(pkt.Metadata, eventDstOverrideKey)
			if pkt.L2.DstMAC == "" {
				pkt.L2.DstMAC = multicastDstMAC(pkt.L3.DstIP)
				if pkt.L2.DstMAC == "" {
					pkt.L2.DstMAC = l2For(pkt.Direction, spec).DstMAC
				}
			}
			// 事件级源 MAC（波 5d：dhcp down 方向 reply 源 MAC 按角色交换/
			// 回退，udp 层已写入事件值）；空（无覆盖事件）→ spec.SrcMAC。
			if pkt.L2.SrcMAC == "" {
				pkt.L2.SrcMAC = spec.SrcMAC
			}
			pkt.L2.EtherType = core.EtherTypeFor(pkt.L3.SrcIP)
		} else {
			// 隧道链（gre）：GREGenerator 已把 wire GRE 配置写进 L2.GRE，
			// l2For 全量重建会覆盖它——重建前先保留，装配后再恢复
			// （顺序必须如此：先取 gre 再 l2For，反了取到的是 nil）。
			gre := pkt.L2.GRE
			pkt.L2 = l2For(pkt.Direction, spec)
			if gre != nil {
				pkt.L2.GRE = gre
			}
			// 方向相关 src/dst 交换 + flow 级字段。IPID 已由 ip 层生成器写入
			// （每次 Emit 前写入并自增），这里只换 IP 不换 ID。
			if pkt.Direction == "down" {
				pkt.L3.SrcIP, pkt.L3.DstIP = pkt.L3.DstIP, pkt.L3.SrcIP
			}
			pkt.L3.TTL = ipTTL(ipCfg)
		}
		// L3 协议号随传输层（tcp=6 / udp=17；legacy L3Base 语义）。
		// 传输层是链上 ip 之下最后一层：独立 tcp/udp flow 的末层，
		// 或终结层链（http/dns...）的倒数第二层。隧道链（gre）由隧道层
		// 生成器已写入 47（IPPROTO_GRE）——只在 0 时填充，绝不覆盖。
		if p.name == "goose" || isGOOSEChain(chain) || p.name == "sv" || isSVChain(chain) {
			pkt.L2.EtherType = core.EtherTypeSV
			if p.name == "goose" || isGOOSEChain(chain) {
				pkt.L2.EtherType = core.EtherTypeGOOSE
			}
			pkt.L3 = core.L3Config{}
		} else if pkt.L3.Protocol == 0 {
			pkt.L3.Protocol = transportProtocol(chain)
		}
		// TTL 已按分支赋值（覆盖事件保留 udp 层写入的 255，普通包走
		// ipTTL）；TOS 整字节覆盖（review HIGH-2 修复，legacy L3Base
		// builder.go:158-161 语义）：spec.TOS != 0 时 DSCP=TOS>>2、
		// ECN=TOS&3，覆盖 DSCP/ECN 直配。
		if spec.TOS != 0 {
			pkt.L3.DSCP = spec.TOS >> 2
			pkt.L3.ECN = spec.TOS & 0x03
		} else {
			pkt.L3.DSCP = spec.DSCP
			pkt.L3.ECN = spec.ECN
		}
		pkt.L3.Flags = spec.IPFlags
		pkt.L3.FragOffset = spec.FragOffset
		pkt.L3.HopByHop = spec.HopByHop
		packets = append(packets, pkt)
		// 取消检测在驱动循环中处理（ip 生成器 select ctx.Done）：这里只收集。
		return nil
	}

	ipReq := &GenRequest{
		Chain: chain,
		Layer: ipLayer,
		Inner: innerCh,
		Emit:  finalEmit,
		Sess:  sess,
		Meta:  meta,
	}

	// 5. 驱动：先启动外层（消费 innerCh），再驱动内层（往 innerCh 里写）。
	//    逐层 goroutine 管线（隧道链 P2e T12 泛化）：外层 ip 生成器消费
	//    innerCh 并把包交给 finalEmit；其下每层（gre、tcp、udp...）各跑一个
	//    goroutine，从自己的内层通道消费、经 req.Emit 写入上一层通道。
	//    末层若是终结层生成器（http/dns/...），把其报文事件流接入传输层的
	//    Meta.Events，传输层在"单 payload 模式"后消费事件流（波 2 方案 A /
	//    波 3 泛化）。事件接线的 transport 断言已在 Plan 同步校验
	//    （assertEventWiring），此处断言必过，只做类型收窄。
	//    内层序列结束后关闭 innerCh：外层生成器排空后退出（否则 drive
	//    永远等不到 genDone，Plan 的 goroutine 不返回，worker 的 for-range 挂死）。
	//    与既有单 ip 层链的差异：泛化后 wrapper 层（gre）也占一个 goroutine
	//    并从自己的通道排空——ip 层不再"直接"消费传输层产出，而是消费
	//    wrapper 层的产出（包数、顺序不变，只多一跳通道）。
	genDone := make(chan error, 1)
	go func() { genDone <- ipGen.Generate(ctx, ipReq) }()

	lastGen := gens[len(chain)-1]
	var lastErr error

	// 6. 管线接线（隧道链 T12/T13 泛化）：每层一条通道，逐层 goroutine 级联。
	//    transportIdx 是传输层（tcp/udp）索引，按 Category 定位——不能再用
	//    len-2：tls 隧道链 [ip→tcp→tls→http] 里 len-2 是 tls（tls 在 tcp 之内，
	//    TLS record 是 TCP payload），传输层是 chain[1]。wrapper 层是链上 ip
	//    与 transport 之间的隧道层（gre/内层 ip），transport 之内到终结层之间
	//    的隧道层（tls）是**事件变换器**——它不产包，只变换终结层事件流。
	//    既有链（[ip→tcp]/[ip→udp]/[ip→tcp→http]）无 wrapper 层，通道形状与
	//    旧实现完全相同。
	//
	//    通道方向（包从内向外流）：层 i>0 读 pipeCh[i]、写 pipeCh[i-1]
	//    （更外层的输入）；pipeCh[0] = innerCh（外层 ip 读）；transport
	//    （i=transportIdx）只写 pipeCh[transportIdx-1]。关闭者 = 写者：
	//    每通道恰一个关闭者，wrapper goroutine 退出时关闭自己的输出，
	//    transport 结束后关闭 pipeCh[transportIdx-1]（无 wrapper 时即
	//    innerCh）。级联拆除：transport 关 → wrapper 排空退出逐层关 →
	//    最内层 wrapper 关 innerCh → 外层 ip 排空退出。
	transportIdx := transportIndex(gens)
	if transportIdx < 0 {
		return nil, fmt.Errorf("layers: chain %s has no transport layer", layerNames(chain))
	}
	// pipeCh 只在有 wrapper 层时存在（[ip→tcp]/[ip→tcp→http] 无 wrapper 不建
	// 数组）；pipeCh[0]=innerCh 是外层 ip 的输入（gre wrapper 的输出目标）。
	// transportIdx==0 的 [ip→tcp] 链直接走 transportOut==innerCh，无 pipeCh。
	pipeCh := make([]chan core.PacketConfig, transportIdx)
	if transportIdx > 0 {
		pipeCh[0] = innerCh
	}
	wrapperDone := make([]chan error, 0, max(transportIdx-1, 0))
	for i := 1; i < transportIdx; i++ {
		ch := make(chan core.PacketConfig, 256)
		pipeCh[i] = ch
		// 每层独立 Sess 副本：IPGenerator 写 Sess.IPID，外层 ip（ipGen，
		// Sess: sess）与内层 ip（本循环内 wrapper）若共享同一指针会并发
		// 双写（data race）；各层副本从同一基值起步、互不相干。
		sessLayer := *sess
		wrapperReq := &GenRequest{
			Chain: chain,
			Layer: chain[i],
			Inner: pipeCh[i],
			Emit: func(pkt core.PacketConfig) error {
				// 本层产出交给更外层：写 pipeCh[i-1]（下一层输入）。
				// 注意：不是 ch（= pipeCh[i] 本层输入）——写回自己的输入
				// 会把包裹循环化且无人消费（曾致 send on closed channel）。
				select {
				case pipeCh[i-1] <- pkt:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			Sess: &sessLayer,
			Meta: meta,
		}
		done := make(chan error, 1)
		wrapperDone = append(wrapperDone, done)
		go func(req *GenRequest, out chan core.PacketConfig, done chan error) {
			err := gens[i].Generate(ctx, req)
			// 级联拆除：本层退出即关闭**自己写入的**通道（pipeCh[i-1]），
			// 每通道单写者单关闭者——外层排空后退出。
			close(out)
			done <- err
		}(wrapperReq, pipeCh[i-1], done)
	}
	// transportOut 是传输层的输出通道（下一层输入）：无 wrapper
	// （[ip→tcp]/[ip→udp]/[ip→tcp→http]，transportIdx<=1）时即 innerCh——外层
	// ip 直接消费传输层产出，与旧实现同形状；有 wrapper 时是 wrapper 循环
	// 创建的最内层 wrapper 的输入通道（pipeCh[transportIdx-1]，如
	// [ip,gre,ip,tcp,http] 的 transport→内层 ip）。必须在循环后取——
	// 循环内 pipeCh[transportIdx-1] 尚未就位。
	transportOut := innerCh
	if transportIdx > 1 {
		transportOut = pipeCh[transportIdx-1]
	}
	// transportReq 是传输层生成器（tcp/udp）的驱动请求。Layer 按分支区分
	// （旧实现即如此）：事件分支（末层 http/dns）用 chain[transportIdx]——
	// tcp/udp 层读自己的层 config（窗口/MSS 等由层 config 携带）；非事件
	// 分支（独立 tcp/udp flow，[ip→tcp]）用 chain[len-1]——协议层即末层，
	// 其层 config 是协议参数（src_port/dst_port 等独立 flow 字段）。
	transportReq := &GenRequest{
		Chain: chain,
		Layer: chain[transportIdx],
		Emit: func(pkt core.PacketConfig) error {
			select {
			case transportOut <- pkt:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Sess: sess,
		Meta: meta,
	}
	// 事件生成器接线（http/dns/... 终结层）：事件流接入传输层 Meta.Events，
	// 传输层在"单 payload 模式"后消费事件流。T13 泛化（tls 变换器链）：
	// transport 之内的 CategoryTunnel 层（tls）不产包——它是**事件变换器**，
	// 经普通 Generate 驱动：从 req.Meta.Events 消费内层终结层事件流，变换
	// 后（tls 包成 ApplicationData record，握手 record 先注入）经 req.EmitMsg
	// 转发给更外层。事件流方向（内→外）：终结层 → 变换器链 → transport。
	// 关闭者 = 写者：终结层结束后关闭最内层变换器输入；变换器退出时关闭
	// 自己的输出；transport 消费到关闭退出。事件流关闭语义与单终结层一致：
	// tcp 把关闭视为数据段结束进入挥手。
	//
	// 每个变换器持自己的 FlowMeta 副本（Meta.Events = 自己的输入通道）——
	// 与 T12 的 sessLayer 副本同款：共享 meta 会让所有变换器读同一个输入流。
	if eg, ok := lastGen.(interface{ GenEvents() EventGenerator }); ok && eg.GenEvents() != nil {
		// 变换器链：transport 之内的层（i ∈ (transportIdx, len-1)）。终结层
		// 之前可能有多个变换器（[ip→tcp→tls→grpc→http] 式未来链）；当前
		// 只有 tls。transformers[0] = 最内层变换器（紧邻终结层）。
		var transformers []LayerGenerator
		for i := len(chain) - 2; i > transportIdx; i-- {
			transformers = append(transformers, gens[i])
		}
		n := len(transformers)
		// transformCh[k] = transformers[k] 的输入；transformCh[n] = transport
		// 的最终事件流。transformCh[0] 的写者 = 终结层（主线程驱动）。
		transformCh := make([]chan MessageEvent, n+1)
		for i := range transformCh {
			transformCh[i] = make(chan MessageEvent, 64)
		}
		meta.Events = transformCh[n]
		transportReq.Meta = meta
		// 变换器 goroutine（自最外层向最内层启动；各自阻塞读输入）。
		transformDone := make([]chan error, n)
		for k := 0; k < n; k++ {
			metaK := meta
			metaK.Events = transformCh[k]
			layerCfg := chain[transportIdx+1+k] // transformers[k] 的层 config
			out := transformCh[k+1]
			done := make(chan error, 1)
			transformDone[k] = done
			go func(gen LayerGenerator, layerCfg Layer, metaK FlowMeta, out chan MessageEvent, done chan error) {
				err := gen.Generate(ctx, &GenRequest{
					Layer: layerCfg,
					EmitMsg: func(ev MessageEvent) error {
						select {
						case out <- ev:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					},
					Sess: sess,
					Meta: metaK,
				})
				// 级联拆除：本变换器是 out 的唯一写者，退出即关闭。
				close(out)
				done <- err
			}(transformers[k], layerCfg, metaK, out, done)
		}
		// 终结层生成器的 EmitMsg 转发到最内层变换器输入（无变换器时即
		// transport 最终事件流，与旧实现同形状）。
		// Meta 契约（review T13 LOW-4）：终结层生成器经 Meta 读**配置值**
		// （Meta.HTTP/DNS/... 与 DstIP 等），绝不读 Meta.Events——Events 已被
		// 覆写为 transport 的最终事件流（transformCh[n]），终结层读它会把
		// 自己的输出当输入（自食）。事件流只经 req.EmitMsg 单向流出。
		reqForTerminal := &GenRequest{
			Chain: chain,
			Layer: chain[len(chain)-1],
			EmitMsg: func(ev MessageEvent) error {
				select {
				case transformCh[0] <- ev:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			Sess: sess,
			Meta: meta,
		}
		var transport interface {
			Generate(ctx context.Context, req *GenRequest) error
		}
		switch tg := gens[transportIdx].(type) {
		case *TCPGenerator:
			transport = tg
		case *UDPGenerator:
			transport = tg
		default:
			// assertEventWiring 已同步拦截，理论不可达。
			return nil, fmt.Errorf("layers: layer %q cannot consume terminal events (unsupported transport generator %T)",
				chain[transportIdx].Name, gens[transportIdx])
		}
		transportDone := make(chan error, 1)
		go func() {
			err := transport.Generate(ctx, transportReq)
			// transport 是唯一写者，退出即关闭输出（级联拆除起点）。
			close(transportOut)
			transportDone <- err
		}()
		lastErr = lastGen.Generate(ctx, reqForTerminal)
		close(transformCh[0])
		// 变换器层级联排空退出（各自关闭输出），全部等待，不泄漏。
		// ctx 取消逃生口（review T13 MED-1）：变换器在错误/取消路径可能
		// 长时间排空输入或阻塞——等待必须能被 ctx 打断，否则取消/超时
		// 时 Plan 永久挂死。
		for _, done := range transformDone {
			select {
			case err := <-done:
				if err != nil && lastErr == nil {
					lastErr = err
				}
			case <-ctx.Done():
				// 取消逃生口（review T13 MED-1）：变换器阻塞排空时不能挂死。
				// 返回前必须等 ip 生成器退出（review transform-wiring F2）：
				// ip goroutine 可能在 finalEmit 里 append(packets)，Plan 的
				// goroutine 随后遍历 packets——并发读写 slice 头是数据竞态。
				// 错误路径（err != nil）Plan 本就不发包，但防御性等待保持
				// "ip 退出后 drive 才返回"契约在所有分支成立（LOW-3 同款）。
				<-genDone
				return packets, ctx.Err()
			}
		}
		if lastErr != nil {
			// 终结层/变换器失败：传输层仍会排空事件流（事件流关闭视为
			// 数据段结束，tcp 进入挥手 / udp 直接结束）。等待其退出，不泄漏。
			<-transportDone
		} else if err := <-transportDone; err != nil {
			lastErr = err
		}
		// wrapper 层级联排空退出（各自关闭输出），全部等待，不泄漏。
		for _, done := range wrapperDone {
			<-done
		}
		if err := <-genDone; err != nil {
			return packets, err
		}
		return packets, lastErr
	}

	// 无事件生成器：末层直接产包（波 1 的 [ip → tcp] 独立 tcp flow 路径）。
	// 非事件分支的 Layer 是末层（协议层本身，旧实现 tcpReq.Layer =
	// chain[len-1] 语义）——[ip→tcp] 链 transportIdx=0 时 chain[0] 是 ip 层，
	// TCPGenerator 读它拿不到端口/MSS。
	transportReq.Layer = chain[len(chain)-1]
	lastErr = lastGen.Generate(ctx, transportReq)
	close(transportOut)
	// 先等 wrapper/ip 级联退出再返回（review T13 LOW-3 修复）：提前返回会
	// 与 ip goroutine 的 finalEmit append 竞态（drive 返回后 Plan goroutine
	// 遍历 packets 与仍在 append 的 ip goroutine 并发）——关闭协议要求
	// "ip 生成器退出后（genDone）drive 才返回"在**所有**分支成立。
	for _, done := range wrapperDone {
		<-done
	}
	if err := <-genDone; err != nil {
		if lastErr == nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return packets, lastErr
	}
	return packets, nil
}

// translateTerminalConfig translates the chain's terminal layer config into
// the flow spec's protocol config (终结层配置翻译)。The chain passed in via
// NewChainPlannerFromChain carries the user's completed layer configs; the
// terminal generators (http/dns) read req.Meta.HTTP / req.Meta.DNS (= spec
// values), NOT the layer config, so without translation
// {"http":{"method":"POST"}} silently falls back to GET / and {"dns":{}} fails
// validation with "DNS config is required" (validate_layers.go 的
// validated-but-not-yet-effective)。
//
// Semantics:
//   - Flat path is authoritative: when spec.HTTP/spec.DNS is already set
//     (mapToFlowSpec read cfg["http"]/cfg["dns"]), translation is skipped and
//     the layer config is ignored — flat and layer configs are two ways to
//     express the same terminal protocol, and a strategy may carry either
//     (flat wins when both present).
//   - Only layers with a schema Field 说明书 are translated (http/dns; ftp/
//     smtp have schema fields but no generators). Other terminal layers
//     (ntp/snmp/... 无字段) leave the spec untouched.
//   - Field values come from the layer config with schema defaults applied
//     (V9 已保证 config 类型合法), falling back to the registry default when
//     absent — for http, empty strings are left as zero so buildHTTPRequest's
//     build-time defaults (Method→GET, URI→/, Version→"HTTP/1.1") apply;
//     for dns, the "name" default "example.com" must be materialized because
//     buildDNSQuery would encode an empty domain as an empty label.
func (p *ChainPlanner) translateTerminalConfig(spec *core.FlowSpec) {
	if len(p.chain) == 0 {
		return
	}
	r := p.effectiveRegistry()
	term := p.chain[len(p.chain)-1]
	s, ok := r.Get(term.Name)
	if !ok {
		return
	}
	if term.Name == "bgp" && spec.BGP == nil {
		spec.BGP = &core.BGPConfig{}
	}
	if term.Name == "pcep" && spec.PCEP == nil {
		spec.PCEP = &core.PCEPConfig{}
	}
	if term.Name == "ldp" && spec.LDP == nil {
		spec.LDP = &core.LDPConfig{}
	}
	if term.Name == "isis" && spec.ISIS == nil {
		spec.ISIS = &core.ISISConfig{}
	}
	if term.Name == "cflow" && spec.CFlow == nil {
		spec.CFlow = &core.CFlowConfig{}
	}
	if term.Name == "http_flv" && spec.HTTPFLV == nil {
		spec.HTTPFLV = &core.HTTPFLVConfig{}
	}
	if term.Name == "http_flv" && spec.HTTPFLV != nil {
		// 默认模板：空 Flags → 0x05 (audio+video)，空 Tags → onMetaData + AAC + AVC
		if spec.HTTPFLV.Flags == 0 {
			spec.HTTPFLV.Flags = 0x05
		}
		if spec.HTTPFLV.Tags == nil {
			spec.HTTPFLV.Tags = []core.FLVTag{
				{Type: "script", Timestamp: 0},
				{Type: "audio", Timestamp: 0, Data: []byte{0x11, 0x90}},
				{Type: "video", Timestamp: 0, Data: []byte{0x01, 0x42, 0x00, 0x1e, 0xff, 0xe1, 0x00, 0x1c, 0x67, 0x42, 0x00, 0x1e, 0x99, 0xa0, 0x0b, 0xf0, 0xf1, 0x70, 0x11, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x32, 0x0f, 0x16, 0x32, 0x78, 0x80, 0x01, 0x00, 0x07, 0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0}},
			}
		}
		if spec.HTTPFLV.Rounds == 0 {
			spec.HTTPFLV.Rounds = 1
		}
	}
	if term.Name == "hls" && spec.HLS == nil {
		spec.HLS = &core.HLSConfig{}
	}
	if term.Name == "hls" && spec.HLS != nil {
		for i, s := range spec.HLS.Sessions {
			if s.Rounds == 0 {
				spec.HLS.Sessions[i].Rounds = 1
			}
		}
	}
	if term.Name == "hds" && spec.HDS == nil {
		spec.HDS = &core.HDSConfig{}
	}
	if term.Name == "hds" && spec.HDS != nil {
		for i, s := range spec.HDS.Sessions {
			if s.Rounds == 0 {
				spec.HDS.Sessions[i].Rounds = 1
			}
		}
	}
	if len(s.Fields) == 0 {
		return
	}
	switch term.Name {
	case "goose":
		// D-GOOSE-1：层 config 手工逐键映射进 spec.GOOSE（dns 手工映射
		// 同款——parseGOOSEConfig 在 strategy_convert 包未导出，layers 不可
		// 见；mcp JSON 往返/srv6 导出函数两条路皆无）。completedConfig 补全
		// 标量（本层 18 键零 Default，补全即原值）+ configUint*/configString/
		// configBool 逐键 + data/event_seq 槽位下钻（item["value"]
		// interface{} 透传，无 srv6 式 []byte 陷阱；parseGOOSEConfig:7590
		// 逐键对照为单源口径）。层优先（flat 判死后无双轨；goose 无 flat
		// 守卫历史故不设守卫——spec.GOOSE 缺席走翻译、已存在（引擎直调）
		// 则不覆盖，dns 同款）。空层 {} 翻译出零配置（非 nil）→ validator
		// 首命中 GOCBRef/DatSet=="" → "gocb_ref and dat_set are required"。
		// C 类排除：boolean 顶层键不映射（parse 有键、生成器零消费，
		// T-GOOSE C 类③）；delay_ms/data_idx 只解析（生成器零消费，
		// T-GOOSE C 类②，序列形状不断）。
		if spec.GOOSE == nil {
			cfg := completedConfig(s, term.Config)
			gc := &core.GOOSEConfig{}
			if v, ok := configUint16(cfg["appid"]); ok {
				gc.APPID = v
			}
			if v, ok := configString(cfg["gocb_ref"]); ok {
				gc.GOCBRef = v
			}
			if v, ok := configString(cfg["dat_set"]); ok {
				gc.DatSet = v
			}
			if v, ok := configString(cfg["go_id"]); ok {
				gc.GOID = v
			}
			if v, ok := configUint32(cfg["tal_ms"]); ok {
				gc.TALMs = v
			}
			if v, ok := configUint32(cfg["conf_rev"]); ok {
				gc.ConfRev = v
			}
			if v, ok := configUint32(cfg["start_stnum"]); ok {
				gc.StartSTNum = v
			}
			if v, ok := configUint32(cfg["start_sqnum"]); ok {
				gc.StartSQNum = v
			}
			if v, ok := configBool(cfg["test"]); ok {
				gc.Test = v
			}
			if v, ok := configBool(cfg["nds_com"]); ok {
				gc.NDSCom = v
			}
			// boolean 顶层键：parse 有键、生成器零消费（T-GOOSE C 类③）——
			// 此处故意不映射（字段事实：c.Boolean 全库零命中）。
			if v, ok := cfg["data"].([]interface{}); ok {
				for _, raw := range v {
					if item, ok := raw.(map[string]interface{}); ok {
						name, _ := configString(item["name"])
						typ, _ := configString(item["type"])
						var bitLen int
						if u, ok := configUint64(item["bit_length"]); ok {
							bitLen = int(u)
						}
						gc.Data = append(gc.Data, core.GOOSEData{Name: name, Type: typ, Value: item["value"], BitLength: bitLen})
					}
				}
			}
			if v, ok := cfg["event_seq"].([]interface{}); ok {
				for _, raw := range v {
					if item, ok := raw.(map[string]interface{}); ok {
						var ev core.GOOSEEventSeq
						if u, ok := configUint64(item["data_idx"]); ok {
							ev.DataIdx = int(u)
						}
						if u, ok := configUint64(item["delay_ms"]); ok {
							ev.DelayMs = int(u)
						}
						if u, ok := configUint64(item["retransmits"]); ok {
							ev.Retransmits = int(u)
						}
						if u, ok := configUint64(item["sqnum_step"]); ok {
							ev.SqNumStep = int(u)
						}
						gc.EventSeq = append(gc.EventSeq, ev)
					}
				}
			}
			if u, ok := configUint64(cfg["count"]); ok {
				gc.Count = int(u)
			}
			if v, ok := configString(cfg["dst_mac"]); ok {
				gc.DstMAC = v
			}
			if v, ok := configBool(cfg["vlan_enabled"]); ok {
				gc.VLANEnabled = v
			}
			if v, ok := configUint16(cfg["vlan_id"]); ok {
				gc.VLANID = v
			}
			if v, ok := configUint8(cfg["vlan_priority"]); ok {
				gc.VLANPriority = v
			}
			spec.GOOSE = gc
		}
		return
	case "sv":
		// D-SV-1：层 config 手工逐键映射进 spec.SV（goose case 同款——
		// parseSVConfig 在 strategy_convert 包未导出，layers 不可见）。
		// completedConfig 补全标量（本层 15 键零 Default，补全即原值）+
		// configUint*/configString/configBool 逐键 + data 槽位下钻。
		// inst_mag 有符号（int32 语义；负数字节是 T-24 场景）——
		// configUint64 拒负不可用，raw 数值 switch 双臂承接（JSON 源
		// float64、内部源 int）；typ=="float32" 同源 InstMagF（parse:
		// 7583 口径）；quality presence→HasQuality。层优先（spec.SV
		// 缺席走翻译、已存在（引擎直调）不覆盖，goose 同款）。空层 {}
		// 翻译出零配置（非 nil）→ validator 首命中 appid 0x0000 下界
		// （sv.go:26 双界既有执法；svID 必填分支由超长例单点钉）。
		if spec.SV == nil {
			cfg := completedConfig(s, term.Config)
			sc := &core.SVConfig{}
			if v, ok := configString(cfg["sv_id"]); ok {
				sc.SVID = v
			}
			if v, ok := configString(cfg["dat_set"]); ok {
				sc.DatSet = v
			}
			if v, ok := configUint16(cfg["appid"]); ok {
				sc.APPID = v
			}
			if v, ok := configUint32(cfg["conf_rev"]); ok {
				sc.ConfRev = v
			}
			if v, ok := configUint16(cfg["samples_per_cycle"]); ok {
				sc.SamplesPerCycle = v
			}
			if v, ok := configUint8(cfg["smp_synch"]); ok {
				sc.SMPSynch = v
			}
			if v, ok := configUint16(cfg["smp_rate"]); ok {
				sc.SMPRate = v
			}
			if u, ok := configUint64(cfg["period_us"]); ok {
				sc.PeriodUS = int(u)
			}
			if u, ok := configUint64(cfg["count"]); ok {
				sc.Count = int(u)
			}
			if v, ok := configString(cfg["dst_mac"]); ok {
				sc.DstMAC = v
			}
			if v, ok := configBool(cfg["double_send"]); ok {
				sc.DoubleSend = v
			}
			if v, ok := configBool(cfg["vlan_enabled"]); ok {
				sc.VLANEnabled = v
			}
			if v, ok := configUint16(cfg["vlan_id"]); ok {
				sc.VLANID = v
			}
			if v, ok := configUint8(cfg["vlan_priority"]); ok {
				sc.VLANPriority = v
			}
			if v, ok := cfg["data"].([]interface{}); ok {
				for _, raw := range v {
					if item, ok := raw.(map[string]interface{}); ok {
						name, _ := configString(item["name"])
						typ, _ := configString(item["type"])
						d := core.SVData{Name: name, Type: typ}
						switch n := item["inst_mag"].(type) {
						case float64:
							d.InstMag = int32(n)
							if typ == "float32" {
								d.InstMagF = float32(n)
							}
						case int:
							d.InstMag = int32(n)
							if typ == "float32" {
								d.InstMagF = float32(n)
							}
						}
						if _, ok := item["quality"]; ok {
							d.HasQuality = true
							if u, ok := configUint64(item["quality"]); ok {
								d.Quality = uint32(u)
							}
						}
						sc.Data = append(sc.Data, d)
					}
				}
			}
			spec.SV = sc
		}
		return
	case "arp":
		// D-ARP-1：层 config 手工逐键映射进 spec.ARP（goose/sv 手工映射
		// 同款——strategy_convert 的 case "arp" 在包外不可见）。completedConfig
		// 补全标量（本层 5 键零 Default，补全即原值）+ configUint16/
		// configString 逐键。空层 {} 翻译出零值配置（非 nil）→ 生成器缺省
		//（sender_ip=10.0.0.1/target_ip=10.0.0.2/MAC←eth 层，裁定2）。
		// 层优先（flat 判死后无双轨；spec.ARP 已存在=引擎直调，不覆盖）。
		if spec.ARP == nil {
			cfg := completedConfig(s, term.Config)
			ac := &core.ARPConfig{}
			if v, ok := configUint16(cfg["operation"]); ok {
				ac.Operation = v
			}
			if v, ok := configString(cfg["sender_mac"]); ok {
				ac.SenderMAC = v
			}
			if v, ok := configString(cfg["sender_ip"]); ok {
				ac.SenderIP = v
			}
			if v, ok := configString(cfg["target_mac"]); ok {
				ac.TargetMAC = v
			}
			if v, ok := configString(cfg["target_ip"]); ok {
				ac.TargetIP = v
			}
			spec.ARP = ac
		}
		return
	case "icmpv6":
		// D-ICMPV6-1：层 config 手工逐键映射进 spec.ICMPv6（parse 未导出
		// 不可跨包）。缺省镜像 parse（strategy_convert.go:732，决策 D1）：
		// type 128/code 0/sequence 1/data "ping"——空层=合法缺省 ping，
		// 存量例语义保持。data 字符串直转 []byte（getString 同口径，无
		// srv6 式 []byte 陷阱）；pattern 槽位下钻（step 缺省 sequence
		// 语义在生成器 index+1，translate 只透传显式值）。file_source 不
		// 映射（③ C 类）。层优先（spec.ICMPv6 缺席走翻译，goose 同款）。
		// 空层 {} 翻译出零值+缺省 → validator type/code 分支不触发（128/0
		// 合法）；v6 族检查由 layer validator 复用 legacy Validate。
		if spec.ICMPv6 == nil {
			cfg := completedConfig(s, term.Config)
			ic := &core.ICMPv6Config{Type: 128, Code: 0, Sequence: 1}
			if v, ok := configUint8(cfg["type"]); ok {
				ic.Type = v
			}
			if v, ok := configUint8(cfg["code"]); ok {
				ic.Code = v
			}
			if v, ok := configUint16(cfg["identifier"]); ok {
				ic.Identifier = v
			}
			if v, ok := configUint16(cfg["sequence"]); ok {
				ic.Sequence = v
			}
			if v, ok := cfg["data"].(string); ok {
				ic.Data = []byte(v)
			} else {
				ic.Data = []byte("ping")
			}
			if v, ok := cfg["pattern"].([]interface{}); ok {
				for _, raw := range v {
					if item, ok := raw.(map[string]interface{}); ok {
						// 缺省镜像 parseICMPv6Pattern（D1）：type 128/
						// code 0/sequence==0（含显式 0）自动补 index+1/
						// data "ping"。
						st := core.ICMPv6Step{Type: 128}
						if u, ok := configUint8(item["type"]); ok {
							st.Type = u
						}
						if u, ok := configUint8(item["code"]); ok {
							st.Code = u
						}
						if u, ok := configUint16(item["sequence"]); ok {
							st.Sequence = u
						}
						if st.Sequence == 0 {
							st.Sequence = uint16(len(ic.Pattern) + 1)
						}
						if d, ok := item["data"].(string); ok {
							st.Data = []byte(d)
						} else {
							st.Data = []byte("ping")
						}
						ic.Pattern = append(ic.Pattern, st)
					}
				}
			}
			spec.ICMPv6 = ic
		}
		return
	case "icmp":
		// D-ICMP-1：层 config 手工逐键映射进 spec.ICMP（parse 未导出
		// 不可跨包）。缺省镜像 parse（strategy_convert.go:507，决策 D1）：
		// type 8/code 0/sequence 1/data "ping"——空层=合法缺省 ping，
		// 存量例语义保持。data 字符串直转 []byte；pattern 槽位下钻
		//（step 缺省镜像 parseICMPPattern：type 8/code 0/sequence==0 自动
		// 补 index+1/data "ping"）。file_source 不映射（③ C 类）。层优先
		//（spec.ICMP 缺席走翻译，icmpv6 同款）。空层 {} 翻译出零值+缺省 →
		// validator type/code 分支不触发（8/0 合法）。
		if spec.ICMP == nil {
			cfg := completedConfig(s, term.Config)
			ic := &core.ICMPConfig{Type: 8, Code: 0, Sequence: 1}
			if v, ok := configUint8(cfg["type"]); ok {
				ic.Type = v
			}
			if v, ok := configUint8(cfg["code"]); ok {
				ic.Code = v
			}
			if v, ok := configUint16(cfg["identifier"]); ok {
				ic.Identifier = v
			}
			if v, ok := configUint16(cfg["sequence"]); ok {
				ic.Sequence = v
			}
			if v, ok := cfg["data"].(string); ok {
				ic.Data = []byte(v)
			} else {
				ic.Data = []byte("ping")
			}
			if v, ok := cfg["pattern"].([]interface{}); ok {
				for _, raw := range v {
					if item, ok := raw.(map[string]interface{}); ok {
						// 缺省镜像 parseICMPPattern（D1）：type 8/code 0/
						// sequence==0（含显式 0）自动补 index+1/data "ping"。
						st := core.ICMPStep{Type: 8}
						if u, ok := configUint8(item["type"]); ok {
							st.Type = u
						}
						if u, ok := configUint8(item["code"]); ok {
							st.Code = u
						}
						if u, ok := configUint16(item["sequence"]); ok {
							st.Sequence = u
						}
						if st.Sequence == 0 {
							st.Sequence = uint16(len(ic.Pattern) + 1)
						}
						if d, ok := item["data"].(string); ok {
							st.Data = []byte(d)
						} else {
							st.Data = []byte("ping")
						}
						ic.Pattern = append(ic.Pattern, st)
					}
				}
			}
			spec.ICMP = ic
		}
		return
	case "cwmp":
		if spec.CWMP != nil {
			return // flat 权优守卫（smtp 同款；新建路径顶层键已被判死，纯防御）
		}
		// D-CWMP-1：层 config（六键）经 JSON 往返解码为 core.CWMPConfig
		// （smtp `:2017` 同款；sessions/flows/auth 嵌套自动）。空层 config
		// 也翻译出非 nil 零值——isHTTPRPCInner 据此选透传模式 + 生成器/
		// validator 走 P0b 基线单会话（现状口径零改动）。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return
		}
		var sc core.CWMPConfig
		if err := json.Unmarshal(raw, &sc); err != nil {
			// parseSubconfigJSON 同款：unmarshal 失败（如 delay_seconds 超
			// uint32）必须报错拒任务，绝不静默吞错回退空层（否则
			// cwmp_neg_delay_out_of_range 类负例漏放成缺省流）。错误由
			// ValidateSpec 的翻译期统一拦截（chain_planner.go）转发。
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
			return
		}
		spec.CWMP = &sc
	case "h323":
		// D-H323-1：层 config 手工逐键映射进 spec.H323（parseH323Config
		// 未导出不可跨包，决策 C1）。缺省镜像 parse（strategy_convert.go
		// :3309，getIntPresence 语义=缺省补默认、显式 0 保留）：role caller/
		// scenario full/crv 0x2584/display "Administrator"/calls 1/media·ras
		// 子映射缺省见下钻。端口同键二态（D-FTP-2 v2）：标量→spec 端口
		// （层值赢），dst_port 缺席→1720（镜像 setDefaultDstPort :933）、
		// src_port 缺席→不动（worker 12345+i 保底）；对象→放行（worker
		// resolveLayerTuple 已把逐流解析值写进 spec 端口）。
		if spec.H323 == nil {
			cfg := completedConfig(s, term.Config)
			hc := &core.H323Config{
				Role:        "caller",
				Scenario:    "full",
				Crv:         0x2584,
				DisplayName: "Administrator",
				Calls:       1,
			}
			if v, ok := configString(cfg["role"]); ok {
				hc.Role = v
			}
			if v, ok := configString(cfg["scenario"]); ok {
				hc.Scenario = v
			}
			// getIntPresence：显式 0 保留（Plan 内 0→DefaultCRV 二次兜底）。
			if v, ok := cfg["crv"]; ok {
				if u, ok := configUint16(v); ok {
					hc.Crv = u
				}
			}
			if v, ok := configString(cfg["display_name"]); ok {
				hc.DisplayName = v
			}
			if v, ok := cfg["calls"]; ok {
				if u, ok := configUint16(v); ok {
					hc.Calls = int(u)
				}
			}
			if v, ok := configBool(cfg["rewrite_addr"]); ok {
				hc.RewriteAddr = v
			}
			if mm, ok := cfg["media"].(map[string]interface{}); ok {
				mc := &core.H323MediaConfig{
					SrcPort:   5062,
					DstPort:   5063,
					Frames:    10,
					FrameSize: 160,
				}
				if v, ok := configBool(mm["enabled"]); ok {
					mc.Enabled = v
				}
				if v, ok := mm["src_port"]; ok {
					if u, ok := configUint16(v); ok {
						mc.SrcPort = u
					}
				}
				if v, ok := mm["dst_port"]; ok {
					if u, ok := configUint16(v); ok {
						mc.DstPort = u
					}
				}
				if v, ok := mm["frames"]; ok {
					if u, ok := configUint16(v); ok {
						mc.Frames = int(u)
					}
				}
				if v, ok := mm["payload_type"]; ok {
					if u, ok := configUint8(v); ok {
						mc.PayloadType = u
					}
				}
				if v, ok := mm["frame_size"]; ok {
					if u, ok := configUint16(v); ok {
						mc.FrameSize = int(u)
					}
				}
				hc.Media = mc
			}
			if rm, ok := cfg["ras"].(map[string]interface{}); ok {
				rc := &core.H323RasConfig{
					GatekeeperIP: "10.12.184.53",
					Port:         1719,
					EndpointType: "terminal",
				}
				if v, ok := configBool(rm["enabled"]); ok {
					rc.Enabled = v
				}
				if v, ok := configString(rm["gatekeeper_ip"]); ok {
					rc.GatekeeperIP = v
				}
				if v, ok := rm["port"]; ok {
					if u, ok := configUint16(v); ok {
						rc.Port = u
					}
				}
				if v, ok := configString(rm["endpoint_type"]); ok {
					rc.EndpointType = v
				}
				hc.Ras = rc
			}
			spec.H323 = hc
		}
		// 端口同键二态（H323Config 之外，spec 框架端口）：见 case 头注。
		if cfg := completedConfig(s, term.Config); cfg != nil {
			if v, ok := cfg["src_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.SrcPort = u
				}
			}
			if v, ok := cfg["dst_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.DstPort = u
				}
			} else {
				spec.DstPort = 1720
			}
		}
		return
	case "mpls":
		// D-MPLS-1：层 config 手工逐键映射进 spec.MPLS（parseMPLSConfig
		// 未导出不可跨包，决策 C1）。parse 零缺省（strategy_convert.go
		// :3529——缺省全在 legacy Plan 内填：inner_proto 0→auto、frames 0
		// →1、direction ""→up、标签 TTL 0→64），translate 零缺省同口径。
		// 端口同键二态（h323 同款）：标量→spec 端口（层值赢）、对象→放行
		// （worker resolveLayerTuple 已把逐流解析值写进 spec 端口）。
		if spec.MPLS == nil {
			cfg := completedConfig(s, term.Config)
			mc := &core.MPLSConfig{}
			if v, ok := cfg["multicast"]; ok {
				if b, ok := configBool(v); ok {
					mc.Multicast = b
				}
			}
			if v, ok := cfg["inner_proto"]; ok {
				if u, ok := configUint8(v); ok {
					mc.InnerProto = u
				}
			}
			if v, ok := cfg["direction"]; ok {
				if sv, ok := configString(v); ok {
					mc.Direction = sv
				}
			}
			if v, ok := cfg["frames"]; ok {
				if u, ok := configUint16(v); ok {
					mc.Frames = int(u)
				}
			}
			if v, ok := configString(cfg["inner_payload"]); ok {
				mc.InnerPayload = []byte(v)
			}
			if arr, ok := cfg["labels"].([]interface{}); ok {
				for _, raw := range arr {
					item, ok := raw.(map[string]interface{})
					if !ok {
						continue
					}
					lb := core.MPLSLabel{}
					if v, ok := item["label"]; ok {
						if u, ok := configUint64(v); ok {
							lb.Label = uint32(u)
						}
					}
					if v, ok := item["tc"]; ok {
						if u, ok := configUint8(v); ok {
							lb.TC = u
						}
					}
					if v, ok := item["s"]; ok {
						if b, ok := configBool(v); ok {
							lb.S = b
						}
					}
					if v, ok := item["ttl"]; ok {
						if u, ok := configUint8(v); ok {
							lb.TTL = u
						}
					}
					mc.Labels = append(mc.Labels, lb)
				}
			}
			spec.MPLS = mc
		}
		if cfg := completedConfig(s, term.Config); cfg != nil {
			if v, ok := cfg["src_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.SrcPort = u
				}
			}
			if v, ok := cfg["dst_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.DstPort = u
				}
			}
		}
		return
	case "ngap":
		// D-NGAP-1：层 config 手工逐键映射进 spec.NGAP（parseNGAPConfig
		// 未导出不可跨包，决策 C1）。缺省镜像 parse（strategy_convert.go
		// :6589 parseNGAPConfig 零缺省——AMFName/DRX/UE ID 缺省在 legacy
		// Plan 内落，translate 缺省=不动）。端口同键二态（D-FTP-2 v2）：
		// 标量→spec 端口（层值赢），dst_port 缺席→38412（镜像
		// setDefaultDstPort，3GPP TS 38.413 规范端口）、src_port 缺席→
		// 不动（worker 12345+i 保底）；对象→放行（worker resolveLayerTuple
		// 已把逐流解析值写进 spec 端口）。NAS 三键 string→raw bytes
		// （镜像 getByteSlice：string 直转，非 hex）。
		if spec.NGAP == nil {
			cfg := completedConfig(s, term.Config)
			nc := &core.NGAPConfig{}
			if v, ok := configString(cfg["amf_name"]); ok {
				nc.AMFName = v
			}
			if v, ok := cfg["default_paging_drx"]; ok {
				if u, ok := configUint8(v); ok {
					nc.DefaultPagingDRX = int(u)
				}
			}
			if v, ok := cfg["ran_ue_ngap_id"]; ok {
				if u, ok := configUint32(v); ok {
					nc.RANUENGAPID = u
				}
			}
			if v, ok := cfg["amf_ue_ngap_id"]; ok {
				if u, ok := configUint32(v); ok {
					nc.AMFUENGAPID = u
				}
			}
			if v, ok := configBool(cfg["initial_ue_message"]); ok {
				nc.InitialUEMessage = v
			}
			if v, ok := configBool(cfg["ue_context_release"]); ok {
				nc.UEContextRelease = v
			}
			if v, ok := cfg["initial_nas"]; ok {
				nc.InitialNAS = ngapByteSlice(v)
			}
			if v, ok := cfg["downlink_nas"]; ok {
				nc.DownlinkNAS = ngapByteSlice(v)
			}
			if v, ok := cfg["uplink_nas"]; ok {
				nc.UplinkNAS = ngapByteSlice(v)
			}
			// 嵌套三件下钻（零缺省镜像 parseNGAPConfig）。
			if g, ok := cfg["global_ran_node_id"].(map[string]interface{}); ok && g != nil {
				gid := &core.NGAPGlobalRANNodeID{}
				if u, ok := configUint64(g["plmn_mcc"]); ok {
					gid.PLMNMCC = int(u)
				}
				if u, ok := configUint64(g["plmn_mnc"]); ok {
					gid.PLMNMNC = int(u)
				}
				if u, ok := configUint32(g["gnb_id"]); ok {
					gid.GNBID = u
				}
				nc.GlobalRANNodeID = gid
			}
			if tas, ok := cfg["supported_ta_list"].([]interface{}); ok {
				for _, item := range tas {
					taMap, ok := item.(map[string]interface{})
					if !ok {
						continue
					}
					ta := core.NGAPSupportedTA{}
					if u, ok := configUint64(taMap["plmn_mcc"]); ok {
						ta.PLMNMCC = int(u)
					}
					if u, ok := configUint64(taMap["plmn_mnc"]); ok {
						ta.PLMNMNC = int(u)
					}
					if tacs, ok := taMap["tacs"].([]interface{}); ok {
						for _, tc := range tacs {
							if u, ok := configUint32(tc); ok {
								ta.TACs = append(ta.TACs, u)
							}
						}
					}
					nc.SupportedTAList = append(nc.SupportedTAList, ta)
				}
			}
			if ps, ok := cfg["pdu_session_setup"].(map[string]interface{}); ok && ps != nil {
				pss := &core.NGAPPDUSessionSetup{}
				if u, ok := configUint64(ps["pdu_session_id"]); ok {
					pss.PDUSessionID = int(u)
				}
				if u, ok := configUint64(ps["sst"]); ok {
					pss.SST = int(u)
				}
				if u, ok := configUint32(ps["sd"]); ok {
					pss.SD = u
				}
				nc.PDUSessionSetup = pss
			}
			spec.NGAP = nc
			// 端口双态（h323 同款：标量层值赢，dst 缺省 38412，src 缺席
			// 不动，对象放行）。
			if v, ok := cfg["src_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.SrcPort = u
				}
			}
			if v, ok := cfg["dst_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.DstPort = u
				}
			} else {
				spec.DstPort = 38412
			}
		}
		return
	case "telnet":
		// D-TELNET-1：层 config 手工逐键映射进 spec.Telnet（parseTelnet
		// 内联于 strategy_convert.go:1085 不可跨包复用，决策 C1）。
		// 缺省镜像 parse（零缺省——banner/terminal_type/NAWS/xterm 等
		// 缺省在 legacy Plan 内落，translate 缺省=不动）。dialog 列表与
		// file_source object 经 JSON round-trip 直迁（TelnetEvent/
		// FileSource 形状由 struct 标签管，与扁平 parse 同形）。端口同键
		// 二态（D-FTP-2 v2）：标量→spec 端口（层值赢），dst_port 缺席→
		// 23（镜像 setDefaultDstPort，RFC 854 IANA）、src_port 缺席→
		// 不动（worker 12345+i 保底）；对象→放行（worker
		// resolveLayerTuple 已把逐流解析值写进 spec 端口）。
		if spec.Telnet == nil {
			cfg := completedConfig(s, term.Config)
			tc := &core.TelnetConfig{}
			if v, ok := configString(cfg["banner"]); ok {
				tc.Banner = v
			}
			if v, ok := configString(cfg["terminal_type"]); ok {
				tc.TerminalType = v
			}
			if v, ok := cfg["window_cols"]; ok {
				if u, ok := configUint16(v); ok {
					tc.WindowCols = u
				}
			}
			if v, ok := cfg["window_rows"]; ok {
				if u, ok := configUint16(v); ok {
					tc.WindowRows = u
				}
			}
			if v, ok := configString(cfg["scenario"]); ok {
				tc.Scenario = v
			}
			if v, ok := configString(cfg["username"]); ok {
				tc.Username = v
			}
			if v, ok := configString(cfg["password"]); ok {
				tc.Password = v
			}
			if cmds, ok := cfg["commands"]; ok {
				if b, err := json.Marshal(cmds); err == nil {
					var out []string
					if json.Unmarshal(b, &out) == nil {
						tc.Commands = out
					}
				}
			}
			if dlg, ok := cfg["dialog"]; ok {
				if b, err := json.Marshal(dlg); err == nil {
					var out []core.TelnetEvent
					if json.Unmarshal(b, &out) == nil {
						tc.Dialog = out
					}
				}
			}
			if fs, ok := cfg["file_source"]; ok {
				if b, err := json.Marshal(fs); err == nil {
					var out filesystem.FileSource
					if json.Unmarshal(b, &out) == nil {
						// 镜像 parseFileSource 零值→nil 契约
						// （strategy_convert.go:1545-1548）：全零
						// FileSource 视为缺省，不产生非 nil 空指针。
						if out.File != "" || out.Literal != "" || out.Fill != nil || out.Random != nil {
							tc.FileSource = &out
						}
					}
				}
			}
			spec.Telnet = tc
			// 端口双态（h323 同款：标量层值赢，dst 缺省 23，src 缺席
			// 不动，对象放行）。
			if v, ok := cfg["src_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.SrcPort = u
				}
			}
			if v, ok := cfg["dst_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.DstPort = u
				}
			} else {
				spec.DstPort = 23
			}
		}
		return
	case "sip":
		// D-SIP-1：层 config 手工逐键映射进 spec.SIP（parseSIPDialog/
		// parseSIPMedia 未导出不可跨包，决策 C1）。dialog/media 经 JSON
		// round-trip 直迁（SIPMessage/SIPMedia 形状由 struct 标签管，与
		// 扁平 parse 同形，零缺省镜像 :698）。端口同键二态（D-FTP-2 v2）：
		// 标量→spec 端口（层值赢），dst_port 缺席→5060（镜像
		// setDefaultDstPort，RFC 3261 §19.2）、src_port 缺席→不动
		// （worker 12345+i 保底）；对象→放行（worker resolveLayerTuple
		// 已把逐流解析值写进 spec 端口）。
		if spec.SIP == nil {
			cfg := completedConfig(s, term.Config)
			sc := &core.SIPConfig{}
			if dlg, ok := cfg["dialog"]; ok {
				if b, err := json.Marshal(dlg); err == nil {
					var out []core.SIPMessage
					if json.Unmarshal(b, &out) == nil {
						sc.Dialog = out
					}
				}
			}
			if md, ok := cfg["media"]; ok {
				if b, err := json.Marshal(md); err == nil {
					var out core.SIPMedia
					if json.Unmarshal(b, &out) == nil {
						sc.Media = &out
					}
				}
			}
			// D-SIP-2 WP-A：sessions[] 多会话（每 session 独立 TCP 连接/
			// Call-ID/生命周期）。与 dialog 互斥——schema create 门已判死
			// （checkSIPSessionsMutex），task-time 由协议 validator
			// （Planner.Validate 同锚词）背 door，translate 只负责解析。
			// 导出单一真相 ParseSIPSessions 承接 dyn 旁挂
			// （ParseFTPConfigFromMap 先例）。
			if ss, ok := cfg["sessions"]; ok {
				sc.Sessions = core.ParseSIPSessions(ss)
			}
			// D-SIP-2 WP-B：medias[] 多流媒体（与 media 互斥——schema 判死
			// +validator 背 door，translate 只解析）；interleave 交错调度。
			if md, ok := cfg["medias"]; ok {
				sc.Medias = core.ParseSIPMedias(md)
			}
			if iv, ok := cfg["interleave"]; ok {
				if b, ok := iv.(bool); ok {
					sc.Interleave = b
				}
			}
			// D-SIP-2 WP-C：RFC 3581 rport/received 合成开关（nil=透传）。
			if nv, ok := cfg["nat"]; ok {
				if nm, ok := nv.(map[string]interface{}); ok {
					sc.NAT = &core.SIPNAT{RPort: nm["rport"] == true}
				}
			}
			spec.SIP = sc
			// 端口双态（h323 同款：标量层值赢，dst 缺省 5060，src 缺席
			// 不动，对象放行）。
			if v, ok := cfg["src_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.SrcPort = u
				}
			}
			if v, ok := cfg["dst_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.DstPort = u
				}
			} else {
				spec.DstPort = 5060
			}
		}
		return
	case "radius":
		// D-RADIUS-1：层 config 手工逐键映射进 spec.Radius（parseRadiusConfig
		// 未导出不可跨包，决策 C1）。7 键逐映射零缺省镜像 :884；两属性
		// 列表经 JSON round-trip 直迁（RadiusAttribute 形状带 struct 标签）。
		// 端口双态与【核心顺序修正】：validateSpecBase:149 执行在 translate
		// 之前，其 :770 预写拿不到 spec.Radius（恒 nil）恒落 1812——此处
		// 依据层键显式性执行覆盖：当 dst_port 层键缺席时，依 code==4?1813:1812
		// 强制覆盖预写值；用户显式写 dst_port 层键时层值赢；src 缺席不动
		// （worker 12345+i 保底）；对象放行。
		if spec.Radius == nil {
			cfg := completedConfig(s, term.Config)
			rc := &core.RadiusConfig{}
			if v, ok := cfg["code"]; ok {
				if u, ok := configUint8(v); ok {
					rc.Code = int(u)
				}
			}
			if v, ok := cfg["identifier"]; ok {
				if u, ok := configUint8(v); ok {
					rc.Identifier = u
				}
			}
			if v, ok := configString(cfg["authenticator"]); ok {
				rc.Authenticator = v
			}
			if v, ok := cfg["response_code"]; ok {
				if u, ok := configUint8(v); ok {
					rc.ResponseCode = u
				}
			}
			if v, ok := cfg["rounds"]; ok {
				if u, ok := configUint16(v); ok {
					rc.Rounds = int(u)
				}
			}
			if attrs, ok := cfg["attributes"]; ok {
				if b, err := json.Marshal(attrs); err == nil {
					var out []core.RadiusAttribute
					if json.Unmarshal(b, &out) == nil {
						rc.Attributes = out
					}
				}
			}
			if rattrs, ok := cfg["response_attributes"]; ok {
				if b, err := json.Marshal(rattrs); err == nil {
					var out []core.RadiusAttribute
					if json.Unmarshal(b, &out) == nil {
						rc.ResponseAttributes = out
					}
				}
			}
			spec.Radius = rc
			// 端口双态+顺序修正：判断依据=层 config 是否显式含 "dst_port"
			if v, ok := cfg["src_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.SrcPort = u
				}
			}
			if v, ok := cfg["dst_port"]; ok {
				if u, ok := configUint16(v); ok {
					spec.DstPort = u
				}
			} else {
				if rc.Code == 4 {
					spec.DstPort = 1813
				} else {
					spec.DstPort = 1812
				}
			}
		}
		return
	case "opcua":
		if spec.OPCUA != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		cfg := completedConfig(s, term.Config)
		spec.OPCUA = &core.OPCUAConfig{}
		if v, ok := configString(cfg["security_mode"]); ok {
			spec.OPCUA.SecurityMode = v
		}
		if v, ok := cfg["read"].([]interface{}); ok {
			spec.OPCUA.Read = decodeNodeOps(v)
		}
		if v, ok := cfg["write"].([]interface{}); ok {
			spec.OPCUA.Write = decodeNodeOps(v)
		}
		if v, ok := cfg["browse"].([]interface{}); ok {
			spec.OPCUA.Browse = decodeNodeOps(v)
		}
		if v, ok := cfg["subscription"].(map[string]interface{}); ok {
			b, _ := json.Marshal(v)
			var sc core.OPCUASubConfig
			json.Unmarshal(b, &sc)
			spec.OPCUA.Subscription = &sc
		}
		if v, ok := cfg["error_inject"].(map[string]interface{}); ok {
			b, _ := json.Marshal(v)
			var ei core.OPCUAErrInject
			json.Unmarshal(b, &ei)
			spec.OPCUA.ErrorInject = &ei
		}
		if v, ok := cfg["sessions"].(float64); ok {
			spec.OPCUA.Sessions = int(v)
		}
		if v, ok := cfg["close"].(bool); ok {
			spec.OPCUA.Close = v
		}
		if v, ok := cfg["skip_channel"].(bool); ok {
			spec.OPCUA.SkipChannel = v
		}
		if v, ok := cfg["bad_message_size"].(bool); ok {
			spec.OPCUA.BadMessageSize = v
		}
		if v, ok := cfg["bad_length"].(bool); ok {
			spec.OPCUA.BadLength = v
		}
		return
	case "mms":
		if spec.MMS != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		cfg := completedConfig(s, term.Config)
		spec.MMS = &core.MMSConfig{}
		if v, ok := configString(cfg["iedName"]); ok {
			spec.MMS.IEDName = v
		}
		if v, ok := cfg["objects"].([]interface{}); ok {
			b, _ := json.Marshal(v)
			var objs []core.MMSObjectConfig
			if json.Unmarshal(b, &objs) == nil {
				spec.MMS.Objects = objs
			}
		}
		if v, ok := cfg["enableRead"].(bool); ok {
			spec.MMS.EnableRead = v
		}
		if v, ok := cfg["enableWrite"].(bool); ok {
			spec.MMS.EnableWrite = v
		}
		if v, ok := cfg["enableInformationReport"].(bool); ok {
			spec.MMS.EnableInformationReport = v
		}
		if v, ok := cfg["enableGetNameList"].(bool); ok {
			spec.MMS.EnableGetNameList = v
		}
		if v, ok := cfg["enableIdentify"].(bool); ok {
			spec.MMS.EnableIdentify = v
		}
		if v, ok := cfg["association"].(map[string]interface{}); ok {
			b, _ := json.Marshal(v)
			var a core.MMSAssociationConfig
			json.Unmarshal(b, &a)
			spec.MMS.Association = &a
		}
		if v, ok := cfg["multiSession"].([]interface{}); ok {
			b, _ := json.Marshal(v)
			var ms []core.MMSConfig
			if json.Unmarshal(b, &ms) == nil {
				spec.MMS.MultiSession = ms
			}
		}
		if v, ok := cfg["sequence"].(map[string]interface{}); ok {
			b, _ := json.Marshal(v)
			var sq core.MMSSequence
			json.Unmarshal(b, &sq)
			spec.MMS.Sequence = &sq
		}
		if v, ok := configString(cfg["errorClassName"]); ok {
			spec.MMS.ErrorClassName = v
		}
		if v, ok := cfg["errorValue"].(float64); ok {
			spec.MMS.ErrorValue = int(v)
		}
		return
	case "http":
		// D-HTTP-1 重走步骤 2+4：全 20 键经 ParseHTTPConfigFromMap 单一真相
		// （与顶层通用读同 parse、同缺省）。
		// flat 权威早返保留（TestBuildLayersPlanner_FlatSpecWinsOverLayerConfig
		// 锁定：直接构造 spec.HTTP 的调用方仍是 flat 优先，层 config 忽略；
		// 顶层 http 另由 CheckProtoFlat 判死，此处只做优先级）。
		// 例外：spec.HTTP 非 nil 但为空壳（Method/URI/Version 全空——worker
		// resolveLayerTuple 的防御性补建产物）时，层翻译继续（空壳无信息，
		// 层 config 才是真相；零值 Method 不代表用户写了 GET）。
		if spec.HTTP != nil && (spec.HTTP.Method != "" || spec.HTTP.URI != "" || spec.HTTP.Version != "") {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// 必须读 p.chain（用户原始链，含动态对象），不能读 term（补全链）：
		// completedConfig 只补标量缺省，动态对象在补全链上已被剥离，
		// 对象信息只在用户原始链上完整。
		// 动态对象直解：层内动态 6 键的对象值在此按 spec.FlowIndex 直接
		// 解析进翻译结果（与 worker resolveLayerTuple 同算法、同序号域；
		// FlowIndex 由 worker 每流置位，Plan 内 ValidateSpec→translate
		// 读到当流序号）。标量键走 Parse；对象键走 CheckLayerDynShape
		// 校验形状后按流序号解析（形状坏→返回错误，Plan 同步失败）。
		// version 裸值 prefix 归一是翻译侧专属（层 config 的 version 是
		// 裸版本号，schema 默认 "1.1"；HTTPConfig.Version 契约是完整
		// "HTTP/1.1"，builder 只默认空串）。
		rawCfg := term.Config
		for _, l := range p.chain {
			if l.Name == "http" {
				rawCfg = l.Config
				break
			}
		}
		cfg := completedConfig(s, rawCfg)
		if msg := translateHTTPDyn(cfg, rawCfg, spec.FlowIndex); msg != "" {
			// 形状坏（ValidateLayers 已在 create 期 400；此处覆盖引擎直调
			// 未走 ValidateLayers 路径）→ Plan 同步失败，不静默空流。
			return
		}
		hc := core.ParseHTTPConfigFromMap(cfg)
		if hc.Version != "" && !strings.HasPrefix(hc.Version, "HTTP/") {
			hc.Version = "HTTP/" + hc.Version
		}
		spec.HTTP = hc
		// D-TLS-1 步骤 2：tls 消费段（隧道层非末层，无独立 case 分支——挂在
		// http 末层分支内）。读 p.chain 上 tls 层 config 的 sni：标量直写
		// spec.TLS.SNI，动态对象按 spec.FlowIndex 直解写入（与 http :845 段
		// 同构：读 p.chain 原始链、不读 term 补全链）。spec.TLS 非 nil 空壳
		// （SNI/Version/Role/ALPN 全空——worker 防御性补建产物）不触发 flat
		// 权威早返，翻译继续（http :836 空壳例外同款）。形状坏→静默返回
		// （ValidateLayers 已在 create 期 400；此处覆盖引擎直调路径）。
		// 写入目标 spec.TLS.SNI：legacy 兜底分支（planner.go:389-398 读
		// spec.TLS，非 nil 优先）+ 生成器层 config 通道（applySpecToChain
		// 剥离对象后注入解析值）的双通道中的 spec 侧一环。
		translateTLSSNI(p, spec)
		// D-TLS-2：cert 消费段（sni 上段同构）。cert 标量（完整块/子键）
		// 不写 spec——生成器直接读层 config（零新增通道）；动态子键
		// （subject/san 对象）按 FlowIndex 直解写入
		// spec.TLS.ServerCertificate（只写解析键，其余留给 certgen 默认）。
		translateTLSCert(p, spec)
	case "dns":
		// D-DNS-1：层优先（flat 判死后无双轨——CheckProtoFlat 已拒顶层 dns
		// 子映射；`if spec.DNS != nil return` 删除）。层 14 键全量翻译进
		// spec.DNS（生成器读 spec.DNS 不变）；缺席键走 schema 默认（txid=0
		// /ttl=0/udp_payload_size=0 沿生成器回退语义）。
		// 动态对象直解（http :845 段同构）：读 p.chain 原始链（对象完整），
		// 不读 term 补全链（对象已剥离）。name 走 string 面直解；query_type/
		// txid 走 int 面直解（ResolvePortValue 是通用 uint16 解析器，非端口
		// 专属——status_code 先例同款）。
		rawDNS := term.Config
		for _, l := range p.chain {
			if l.Name == "dns" {
				rawDNS = l.Config
				break
			}
		}
		cfg := completedConfig(s, term.Config)
		if msg := translateDNSDyn(cfg, rawDNS, spec.FlowIndex); msg != "" {
			return
		}
		spec.DNS = &core.DNSConfig{
			Domain:    "example.com", // schema 默认；buildDNSQuery 不默认空域名
			QueryType: 1,             // schema 默认（A 记录）
		}
		if v, ok := configString(cfg["name"]); ok {
			spec.DNS.Domain = v
		}
		if v, ok := configUint16(cfg["query_type"]); ok {
			spec.DNS.QueryType = v
		}
		if v, ok := configUint16(cfg["txid"]); ok {
			spec.DNS.TxID = v
		}
		if v, ok := cfg["is_response"].(bool); ok {
			spec.DNS.IsResponse = v
		}
		if v, ok := configString(cfg["response_ip"]); ok {
			spec.DNS.ResponseIP = v
		}
		if v, ok := cfg["edns0_enabled"].(bool); ok {
			spec.DNS.EDNS0Enabled = v
		}
		if v, ok := configUint16(cfg["udp_payload_size"]); ok {
			spec.DNS.UDPPayloadSize = v
		}
		if v, ok := cfg["dnssec_ok"].(bool); ok {
			spec.DNS.DnssecOK = v
		}
		if v, ok := configString(cfg["transport"]); ok {
			spec.DNS.Transport = v
		}
		if v, ok := configUint8(cfg["response_code"]); ok {
			spec.DNS.RCode = v
		}
		if v, ok := configUint32(cfg["ttl"]); ok {
			spec.DNS.TTL = v
		}
		if v, ok := cfg["questions"].([]interface{}); ok && len(v) > 0 {
			out := make([]core.DNSQuestion, 0, len(v))
			for _, item := range v {
				m, isMap := item.(map[string]interface{})
				if !isMap {
					continue
				}
				q := core.DNSQuestion{}
				if s, ok := configString(m["name"]); ok {
					q.Name = s
				}
				if n, ok := configUint16(m["type"]); ok {
					q.Type = n
				}
				if n, ok := configUint16(m["class"]); ok {
					q.Class = n
				}
				out = append(out, q)
			}
			if len(out) > 0 {
				spec.DNS.Questions = out
			}
		}
		// answers/authority：RR 数组逐条翻译（字段映射与 flat
		// parseDNSRRs 同源——strategy_convert.go:3614 同表；此处是 layers
		// 侧镜像，不能 import core 的 unexported parse）。
		for _, key := range []string{"answers", "authority"} {
			v, ok := cfg[key].([]interface{})
			if !ok || len(v) == 0 {
				continue
			}
			rrs := make([]core.DNSRR, 0, len(v))
			for _, item := range v {
				m, isMap := item.(map[string]interface{})
				if !isMap {
					continue
				}
				rr := core.DNSRR{}
				if s, ok := configString(m["name"]); ok {
					rr.Name = s
				}
				if n, ok := configUint16(m["type"]); ok {
					rr.Type = n
				}
				if n, ok := configUint16(m["class"]); ok {
					rr.Class = n
				}
				if n, ok := configUint32(m["ttl"]); ok {
					rr.TTL = n
				}
				if s, ok := configString(m["ip"]); ok {
					rr.IP = s
				}
				if s, ok := configString(m["target"]); ok {
					rr.Target = s
				}
				if n, ok := configUint16(m["preference"]); ok {
					rr.Preference = n
				}
				if s, ok := configString(m["text"]); ok {
					rr.Text = s
				}
				if s, ok := configString(m["mname"]); ok {
					rr.MName = s
				}
				if s, ok := configString(m["rname"]); ok {
					rr.RName = s
				}
				if n, ok := configUint32(m["serial"]); ok {
					rr.Serial = n
				}
				if n, ok := configUint32(m["refresh"]); ok {
					rr.Refresh = n
				}
				if n, ok := configUint32(m["retry"]); ok {
					rr.Retry = n
				}
				if n, ok := configUint32(m["expire"]); ok {
					rr.Expire = n
				}
				if n, ok := configUint32(m["minimum"]); ok {
					rr.Minimum = n
				}
				if n, ok := configUint16(m["priority"]); ok {
					rr.Priority = n
				}
				if n, ok := configUint16(m["weight"]); ok {
					rr.Weight = n
				}
				if n, ok := configUint16(m["port"]); ok {
					rr.Port = n
				}
				if n, ok := configUint16(m["order"]); ok {
					rr.Order = n
				}
				if s, ok := configString(m["flags"]); ok {
					rr.Flags = s
				}
				if s, ok := configString(m["service"]); ok {
					rr.Service = s
				}
				if s, ok := configString(m["regexp"]); ok {
					rr.Regexp = s
				}
				if n, ok := configUint16(m["key_tag"]); ok {
					rr.KeyTag = n
				}
				if n, ok := configUint8(m["algorithm"]); ok {
					rr.Algorithm = n
				}
				if n, ok := configUint8(m["digest_type"]); ok {
					rr.DigestType = n
				}
				if s, ok := configString(m["digest"]); ok {
					rr.Digest = s
				}
				if n, ok := configUint16(m["key_flags"]); ok {
					rr.KeyFlags = n
				}
				if n, ok := configUint8(m["protocol"]); ok {
					rr.Protocol = n
				}
				if s, ok := configString(m["public_key"]); ok {
					rr.PublicKey = s
				}
				rrs = append(rrs, rr)
			}
			if len(rrs) > 0 {
				if key == "answers" {
					spec.DNS.Answers = rrs
				} else {
					spec.DNS.Authority = rrs
				}
			}
		}
	case "postgresql":
		if spec.PostgreSQL != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// 层 config（dialect/wire_profile/events/sessions/wire_fault）经 JSON
		// 往返解码为 core.PostgreSQLConfig：json tag 覆盖全部字段（含
		// events[].authtype *int32），比逐字段 map 取值更忠实。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return // 理论不可达（config 已是 JSON 可编码 map）
		}
		var pg core.PostgreSQLConfig
		if err := json.Unmarshal(raw, &pg); err == nil {
			// 默认值兜底：schema 默认已由 completedConfig 填充，这里再显式
			// 断言 dialect/wire_profile 非空（transcribe 防御）。
			if pg.Dialect == "" {
				pg.Dialect = "postgresql"
			}
			if pg.WireProfile == "" {
				pg.WireProfile = "postgresql_v3"
			}
			spec.PostgreSQL = &pg
		} else {
			// config 含非 JSON 可编码值（极端）→ 用一个最小默认，让后续
			// validator 报错而不是静默空流。
			spec.PostgreSQL = &core.PostgreSQLConfig{Dialect: "postgresql", WireProfile: "postgresql_v3"}
		}
	case "megaco":
		if spec.Megaco != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-MEGACO-1：层 config（profile/encoding/version/token_form/whitespace/
		// sessions/wire_fault）经 JSON 往返解码为 core.MegacoConfig——json tag
		// 覆盖全部字段（含 *int 定时器/指针 Services.Version），比逐字段 map
		// 取值忠实。未序列化错误（非 JSON 可编码值）时置最小默认让 validator
		// 报错，不静默空流。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			spec.Megaco = &core.MegacoConfig{}
			return
		}
		var mc core.MegacoConfig
		if err := json.Unmarshal(raw, &mc); err != nil {
			spec.Megaco = &core.MegacoConfig{}
			return
		}
		spec.Megaco = &mc
	case "hl7":
		if spec.HL7 != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-HL7-1：层 config 八键经 JSON 往返解码为 core.HL7Config（同
		// megaco 先例——json tag 忠实全字段）。解码失败（畸形值/类型不符，
		// 含 ack 对象形 coerce 失败）计入 ValidationErrors 走任务错误——
		// 置空配置会被 validator 直通成默认流（终审 F1 的假成功面）。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("hl7 layer config encode: %v", err))
			return
		}
		var hc core.HL7Config
		if err := json.Unmarshal(raw, &hc); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("hl7 layer config decode: %v", err))
			return
		}
		spec.HL7 = &hc
	case "mmse":
		if spec.MMSE != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-MMSE-1：层 config（profile/mms_version/concurrent/sessions/
		// wire_fault）经 JSON 往返解码为 core.MMSEConfig。裁定8：未知键严
		// 格拒（DisallowUnknownFields——config/session/event/content/part
		// 四级；reply_charging/previously_sent_by 等本版不产生键的自然面
		// 通道）。解码失败（畸形/类型不符/未知键）一律计 ValidationErrors
		// 走任务错误——置空配置会被 validator 直通成默认流假成功（hl7 修轮
		// d0d78f0 模式）。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("mmse layer config encode: %v", err))
			return
		}
		var mc core.MMSEConfig
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&mc); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("mmse layer config decode: %v", err))
			return
		}
		spec.MMSE = &mc
	case "edp":
		if spec.EDP != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-EDP-1：层 config（profile/sessions/wire_fault）经 JSON 往返
		// 解码为 core.EDPConfig。裁定8：未知键严格拒（DisallowUnknownFields
		//——config/session/event 三级；本版不产生键的自然面通道）。解码失败
		//（畸形/类型不符/未知键）一律计 ValidationErrors 走任务错误——
		// 置空配置会被 validator 直通成默认流假成功（hl7 修轮 d0d78f0 模式）。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("edp layer config encode: %v", err))
			return
		}
		var ec core.EDPConfig
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ec); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("edp layer config decode: %v", err))
			return
		}
		spec.EDP = &ec
	case "xmrmining":
		if spec.XMR != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-XMR-1：层 config（profile/concurrent/sessions/wire_fault）经 JSON
		// 往返解码为 core.XMRConfig。裁定8：未知键严格拒（DisallowUnknown
		// Fields——config/session/event 三级）。解码失败一律计 ValidationErrors
		// 走任务错误——置空配置会被 validator 直通成默认流假成功（edp 同款）。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("xmrmining layer config encode: %v", err))
			return
		}
		var xc core.XMRConfig
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&xc); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("xmrmining layer config decode: %v", err))
			return
		}
		spec.XMR = &xc
	case "bacnet":
		if spec.BACNET != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-BACNET-1：层 config（profile/concurrent/sessions/wire_fault）经
		// JSON 往返解码为 core.BACNETConfig。裁定：未知键严格拒（Disallow-
		// UnknownFields——config/session/event 三级，事件级由 BACNETEvent
		// UnmarshalJSON 自带严格性）。解码失败一律计 ValidationErrors 走
		// 任务错误——置空配置会被 validator 直通成默认流假成功（edp 同款）。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("bacnet layer config encode: %v", err))
			return
		}
		var bc core.BACNETConfig
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&bc); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("bacnet layer config decode: %v", err))
			return
		}
		spec.BACNET = &bc
	case "dcerpc":
		if spec.DCERPC != nil {
			return // flat 权威；二者并存时 flat 优先
		}
		// D-DCERPC-1：层 config 严格往返解码（DCERPCConfig UnmarshalJSON）。
		cfg2 := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg2)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("dcerpc layer config encode: %v", err))
			return
		}
		var dc core.DCERPCConfig
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&dc); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("dcerpc layer config decode: %v", err))
			return
		}
		spec.DCERPC = &dc
	case "dtls":
		if spec.DTLS != nil {
			return // flat 权威；二者并存时 flat 优先
		}
		// D-DTLS-1：层 config 严格往返解码（DTLSConfig UnmarshalJSON——
		// config/session/event/handshake 四级 DisallowUnknownFields）。
		cfg3 := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg3)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("dtls layer config encode: %v", err))
			return
		}
		var dcfg core.DTLSConfig
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&dcfg); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("dtls layer config decode: %v", err))
			return
		}
		spec.DTLS = &dcfg
	case "kerberos":
		if spec.Kerberos != nil {
			return // flat 权威；二者并存时 flat 优先（dtls 同款——扁平入口
			// 已由 CheckProtoFlat 判死，此处仅守 out-of-band 配置）
		}
		// D-KERBEROS-1：层 config 严格往返解码（KerberosConfig
		// UnmarshalJSON——config 一级 DisallowUnknownFields；sessions/
		// events 为值切片，未知键在 config 层即拒）。
		cfgK := completedConfig(s, term.Config)
		rawK, err := json.Marshal(cfgK)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("kerberos layer config encode: %v", err))
			return
		}
		var kcfg core.KerberosConfig
		decK := json.NewDecoder(bytes.NewReader(rawK))
		decK.DisallowUnknownFields()
		if err := decK.Decode(&kcfg); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("kerberos layer config decode: %v", err))
			return
		}
		spec.Kerberos = &kcfg
	case "ntlm":
		if spec.NTLM != nil {
			return // flat 权威；二者并存时 flat 优先（kerberos/dtls 同款）
		}
		// D-NTLM-1：层 config 严格往返解码（NTLMConfig UnmarshalJSON——
		// config/session/event/flags/target_info/ntlmv2_response 六级
		// DisallowUnknownFields；未知键在解码层即拒）。
		cfgN := completedConfig(s, term.Config)
		rawN, err := json.Marshal(cfgN)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("ntlm layer config encode: %v", err))
			return
		}
		var ncfg core.NTLMConfig
		decN := json.NewDecoder(bytes.NewReader(rawN))
		decN.DisallowUnknownFields()
		if err := decN.Decode(&ncfg); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("ntlm layer config decode: %v", err))
			return
		}
		spec.NTLM = &ncfg
	case "sstp":
		if spec.SSTP != nil {
			return // flat 权威；二者并存时 flat 优先（kerberos/dtls 同款——
			// 扁平入口已由 CheckProtoFlat 判死顶层 sstp 子映射，此处仅守
			// out-of-band 配置）
		}
		// D-SSTP-1：层 config 严格往返解码（SSTPConfig UnmarshalJSON——
		// DisallowUnknownFields 递归作用于 sessions[]/transactions[]/
		// attributes[]/ppp 嵌套结构；未知键在 config 层即拒）。
		cfgSSTP := completedConfig(s, term.Config)
		rawSSTP, err := json.Marshal(cfgSSTP)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("sstp layer config encode: %v", err))
			return
		}
		var scfgSSTP core.SSTPConfig
		decSSTP := json.NewDecoder(bytes.NewReader(rawSSTP))
		decSSTP.DisallowUnknownFields()
		if err := decSSTP.Decode(&scfgSSTP); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("sstp layer config decode: %v", err))
			return
		}
		spec.SSTP = &scfgSSTP
	case "spnego":
		if spec.SPNEGO != nil {
			return // flat 权威；二者并存时 flat 优先（kerberos/dtls/ntlm 同款）
		}
		// D-SPNEGO-1：层 config 严格往返解码（SPNEGOConfig UnmarshalJSON——
		// config/session/event/neg_hints/mech_token/mech_list_mic 六级
		// DisallowUnknownFields；未知键在解码层即拒）。
		cfgSPNEGO := completedConfig(s, term.Config)
		rawSPNEGO, err := json.Marshal(cfgSPNEGO)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("spnego layer config encode: %v", err))
			return
		}
		var scfgSPNEGO core.SPNEGOConfig
		decSPNEGO := json.NewDecoder(bytes.NewReader(rawSPNEGO))
		decSPNEGO.DisallowUnknownFields()
		if err := decSPNEGO.Decode(&scfgSPNEGO); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("spnego layer config decode: %v", err))
			return
		}
		spec.SPNEGO = &scfgSPNEGO
	case "ocsp":
		if spec.OCSP != nil {
			return // flat 权威；二者并存时 flat 优先（dtls 同款——扁平入口
			// 已由 CheckProtoFlat 判死，此处仅守 out-of-band 配置）
		}
		// D-OCSP-1：层 config 严格往返解码（OCSPConfig UnmarshalJSON——
		// config 一级 DisallowUnknownFields；sessions/transactions/certs
		// 为值切片，未知键在 config 层即拒）。
		cfgO := completedConfig(s, term.Config)
		rawO, err := json.Marshal(cfgO)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("ocsp layer config encode: %v", err))
			return
		}
		var ocfg core.OCSPConfig
		decO := json.NewDecoder(bytes.NewReader(rawO))
		decO.DisallowUnknownFields()
		if err := decO.Decode(&ocfg); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("ocsp layer config decode: %v", err))
			return
		}
		spec.OCSP = &ocfg
	case "amqp":
		if spec.AMQP != nil {
			return // flat 权威；二者并存时 flat 优先（ocsp 同款——扁平入口
			// 已由 CheckProtoFlat 判死，此处仅守 out-of-band 配置）
		}
		// D-AMQP-1：层 config 严格往返解码（ocsp 同款——json 往返 +
		// DisallowUnknownFields；未知键在 config 层即拒）。
		cfgA := completedConfig(s, term.Config)
		rawA, err := json.Marshal(cfgA)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("amqp layer config encode: %v", err))
			return
		}
		var acfg core.AMQPConfig
		decA := json.NewDecoder(bytes.NewReader(rawA))
		decA.DisallowUnknownFields()
		if err := decA.Decode(&acfg); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("amqp layer config decode: %v", err))
			return
		}
		spec.AMQP = &acfg
	case "enip":
		// D-ENIP-1（G-ENIP-3）：层优先（flat 判死后无双轨——CheckProtoFlat
		// 已拒顶层 enip 子映射）。ftp :2332 空壳例外同款：spec.ENIP 非 nil
		// 但为空壳（Scenario/Transport/Commands/IOData/SessionCount/
		// FlowCount 全空——mapToFlowSpec 只在 cfg["enip"] 存在时建 ENIP，
		// layer_gen_test 等直调构造的空壳无信息）时层翻译继续（空壳无信息，
		// 层 config 才是真相）；有内容的 spec.ENIP = 预 resolve 的
		// flat/直调值，翻译跳过（flat 权威——直接构造 spec 的调用方/单测
		// 仍是 flat 优先，顶层 enip 另由 CheckProtoFlat 判死）。空层 config
		// 翻译出空壳（非 nil）→ validator 报 "enip config is required"
		// 语义由 Planner.Validate 的 spec.ENIP 非空 + Commands 空检查承接
		// （层 config 未知键在 config 层即拒：ENIPConfig UnmarshalJSON
		// DisallowUnknownFields）。
		if spec.ENIP != nil && (spec.ENIP.Scenario != "" ||
			spec.ENIP.Transport != "" || len(spec.ENIP.Commands) > 0 ||
			spec.ENIP.IOData != nil || spec.ENIP.SessionCount != 0 ||
			spec.ENIP.FlowCount != 0) {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-ENIP-1（G-ENIP-3）：层 config 六键经 JSON 往返解码为
		// core.ENIPConfig（sstp/kerberos/ntlm 严格解码同款——struct 侧
		// 必须零未知键容忍；parseENIP* 在 strategy_convert 包未导出，
		// layers 不可见；generateFromLayer 复用同一解析器零语义分叉见
		// 设计 §15 8.2）。commands/io_data 嵌套值走 Planner.Validate
		// 全量校验（未知命令码/非法引用在协议级校验器拒，非翻译期）。
		cfgE := completedConfig(s, term.Config)
		rawE, err := json.Marshal(cfgE)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("enip layer config encode: %v", err))
			return
		}
		var ecfg core.ENIPConfig
		decE := json.NewDecoder(bytes.NewReader(rawE))
		decE.DisallowUnknownFields()
		if err := decE.Decode(&ecfg); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("enip layer config decode: %v", err))
			return
		}
		spec.ENIP = &ecfg
	case "ftp":
		// 只在扁平路径确实携带了业务内容（sessions/banner/commands/data_channel）
		// 时才跳过翻译。mapToFlowSpec 对协议 ftp 总会创建一个 FTPConfig
		//（cfg["ftp"] 缺省 → nil Sessions/Commands/Banner/DataChannel），此时
		// spec.FTP 恒非 nil 但内容全空——必须翻译层链内的 config 才能让生成器
		// 拿到 sessions。Task 5 扁平删除后，扁平路径入口已 400
		// （CheckFTPFlat），DB 旧 flat 行在 mapToFlowSpec 经 CheckFTPFlat →
		// ValidationErrors 阻断，不会到达此处。这里只需区分"空结构体"
		// 与"有内容的解析结果"。
		if spec.FTP != nil &&
			(len(spec.FTP.Sessions) > 0 || len(spec.FTP.Commands) > 0 ||
				spec.FTP.Banner != "" || spec.FTP.DataChannel != nil) {
			return
		}
		// 层 config（banner/commands/data_channel/sessions）经
		// core.ParseFTPConfigFromMap 解码（与扁平 cfg["ftp"] 同 parse
		// 函数、同缺省，零语义分叉）。空层 config → nil config，
		// 生成器走默认空会话（与 legacy Plan 对 nil Config 同款）。
		cfg := completedConfig(s, term.Config)
		spec.FTP = core.ParseFTPConfigFromMap(cfg)
	case "pop3":
		if spec.POP3 != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// 层 config（banner/commands/mailbox）经 JSON 往返解码为
		// core.POP3Config（J 组 POP3S：[tcp,tls,pop3] 链）。生成器对 nil
		// config 已走默认空会话，但 validator/单测要求翻译发生在校验前。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return
		}
		var pc core.POP3Config
		if err := json.Unmarshal(raw, &pc); err == nil {
			spec.POP3 = &pc
		}
	case "smtp":
		if spec.SMTP != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-SMTP-1：层 config（banner/dialog/email）经 JSON 往返解码为
		// core.SMTPConfig（pop3 `:1127` 同款；Email/Attachment 嵌套自动）。
		// 生成器对 nil config 已走默认会话（layer_gen.go:57），但 validator/
		// 单测要求翻译发生在校验前，故空层 config 也翻译出非 nil config。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return
		}
		var sc core.SMTPConfig
		if err := json.Unmarshal(raw, &sc); err == nil {
			spec.SMTP = &sc
		}
	case "imap":
		if spec.IMAP != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-IMAP-1：层 config 经 core.ParseIMAPConfigFromMap 解码为
		// core.IMAPConfig（与扁平 cfg["imap"] 同 parse 函数、同缺省，
		// 零语义分叉；ftp ParseFTPConfigFromMap / http
		// ParseHTTPConfigFromMap 同款）。旧 JSON 往返在此判死：
		// IMAPAttachment.Data 是 []byte，Go JSON 语义只认 base64 文本，
		// 附件 "data" 裸文本即整包解码失败、spec.IMAP 留 nil，mime_body
		// 经链恒空会话（T-051/52/80 实测 7 包空流），扁平同输入却正常。
		// 空层 config 也翻译出非 nil config（validator/单测要求翻译发生
		// 在校验前；生成器对 nil config 走默认空会话）。
		cfg := completedConfig(s, term.Config)
		spec.IMAP = core.ParseIMAPConfigFromMap(cfg)
	case "mcp":
		if spec.MCP != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// D-MCP-1：层 config（MCPConfig 同名 21 键）经 JSON 往返解码为
		// core.MCPConfig（pop3/smtp :1143 同款；imap 式 []byte 判死在 mcp
		// 不成立——MCPConfig 无 []byte 业务字段，caps 是 json.RawMessage，
		// JSON 文本往返无损且与扁平 parseMCPConfig 字节同路径零分叉）。
		// 空层 config 也翻译出非 nil config（mcp validator 要求 spec.MCP
		// 非 nil，"mcp config is required"），生成器走默认会话。
		// 端口：validateSpecBase 先于本函数跑（当时 spec.MCP 为 nil，stdio
		// 缺省 22 已写）；翻译后按 transport 修正 HTTP 形缺省 8081（legacy
		// plan.go:61-68 同款）。用户在 tcp 层显式写 dst_port 时，后续层值
		// 回填（ValidateSpec 末段，本函数之后执行）以用户值覆盖，不抢占。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return // 理论不可达（config 已是 JSON 可编码 map）
		}
		var mc core.MCPConfig
		if err := json.Unmarshal(raw, &mc); err == nil {
			spec.MCP = &mc
			if (mc.Transport == "http_sse" || mc.Transport == "streamable") &&
				(spec.DstPort == 0 || spec.DstPort == mcpStdioPort) {
				spec.DstPort = mcpHTTPPort
			}
		}
	case "mqtt":
		// D-MQTT-1：层优先（flat 判死后无双轨——CheckProtoFlat 已拒顶层
		// mqtt 子映射）。http :839 空壳例外同款：spec.MQTT 非 nil 但为空
		// 壳（ClientID/Messages/Will/Subscriptions/User/Properties 全空——
		// worker resolveLayerTuple 的防御性补建产物）时层翻译继续（空壳
		// 无信息，层 config 才是真相）；有内容的 spec.MQTT = 预 resolve
		// 的 flat/直调值，翻译跳过（flat 权威，http :839 同款——直接构造
		// spec 的调用方/单测仍是 flat 优先，顶层 mqtt 另由 CheckProtoFlat
		// 判死）。空层 config 也必须翻译出非 nil config（mqtt validator
		// 要求 spec.MQTT 非 nil，"MQTTConfig is required" 见 :112-115）。
		if spec.MQTT != nil && (spec.MQTT.ClientID != "" ||
			len(spec.MQTT.Messages) > 0 || spec.MQTT.Will != nil ||
			len(spec.MQTT.Subscriptions) > 0 || spec.MQTT.Username != "" ||
			len(spec.MQTT.Properties) > 0) {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// 层 17 键经 JSON 往返解码为 core.MQTTConfig（生成器读 spec.MQTT
		// 不变，J 组 MQTTS [tcp,tls,mqtt] 链同走此分支）。动态对象
		//（client_id 直键 / topic·payload 逐 messages[] 下钻）先按
		// spec.FlowIndex 直解写回 cfg 再走往返——对象值会让往返 unmarshal
		// 失败（Topic string 收 map），直解必须在前。
		// 读 p.chain 原始链取对象（补全链同引用，此读是将来多 mqtt 层
		// 时的明确语义锚）。形状坏 → 不翻译，spec.MQTT 保持 nil →
		// validator 报 "MQTTConfig is required"（同步失败）。
		rawMQTT := term.Config
		for _, l := range p.chain {
			if l.Name == "mqtt" {
				rawMQTT = l.Config
				break
			}
		}
		cfg := completedConfig(s, term.Config)
		if msg := translateMQTTDyn(cfg, rawMQTT, spec.FlowIndex); msg != "" {
			return
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			return // 理论不可达（config 已是 JSON 可编码 map）
		}
		var mc core.MQTTConfig
		if err := json.Unmarshal(raw, &mc); err == nil {
			spec.MQTT = &mc
		}
	case "srv6":
		// D-SRV6-1：层 config（SRv6Config 同名 16 用户键）经
		// core.ParseSRv6ConfigFromMap 复用扁平解析单一真相（非 JSON 往返：
		// inner_payload []byte 的字符串语义是原文字节，往返会 base64 误读；
		// segments_left/last_entry/reduced 指针三态也由扁平 parse 派生）。
		// 空层 config 也翻译出非 nil（srv6 validator VR-02 必拒"segment_list
		// must not be empty"，VR-01 链上不可达=mcp"config required 被翻译
		// 保底"同款 C 类）。无业务动态（allowlist 不加 srv6 行），raw 层
		// config 即 completedConfig（零 Default）。
		if spec.SRv6 == nil {
			spec.SRv6 = core.ParseSRv6ConfigFromMap(term.Config)
		}
	case "pppoe":
		// D-PPPOE-1：层 config 经 core.ParsePPPoEConfigFromMap 复用扁平
		// 解析单一真相（data_payload []byte 字符串语义=原文字节，JSON
		// 往返会 base64 误读——srv6 inner_payload 同陷阱；sessions[] 经
		// ParsePPPoESessions 承接 dyn 旁挂）。空层 config 也翻译出非 nil
		// （全默认冒烟形状合法：PADT 缺省 true、SessionID 缺省 1）。
		// sessions×顶层行为键互斥由 schema create 门判死 +
		// Planner.Validate 同锚词背 door，translate 只负责解析。
		if spec.PPPoE == nil {
			spec.PPPoE = core.ParsePPPoEConfigFromMap(completedConfig(s, term.Config))
		}
	case "ldap":
		// D-LDAP-1：层 config 经 core.ParseLDAPConfigFromMap 复用扁平
		// 解析单一真相（15 键全 string/int/[]string/bool，无 []byte
		// 陷阱）。空层 config 也翻译出非 nil（全默认=参考包 RootDSE
		// 形合法）。unbind 指针三态由扁平 parse 承接。
		if spec.LDAP == nil {
			spec.LDAP = core.ParseLDAPConfigFromMap(completedConfig(s, term.Config))
		}
	case "rtmp":
		// D-RTMP-1：层 config 经 core.ParseRTMPConfigFromMap 复用扁平
		// 解析单一真相（payload_b64 双形由扁平 parse 承接，JSON 往返会
		// 误读——data[].payload 字节数组/base64 双形同 inner_payload 陷阱）。
		// 空层 config 也翻译出非 nil（全默认=参考 pcap play 形合法）。
		if spec.RTMP == nil {
			spec.RTMP = core.ParseRTMPConfigFromMap(completedConfig(s, term.Config))
		}
	case "rtsp":
		// D-RTSP-1：层 config 经 core.ParseRTSPConfigFromMap 复用扁平
		// 解析单一真相（dialog/media 与 mapToFlowSpec case "rtsp" 同构）。
		// dialog 必需锚（空 dialog 拒）由 rtsp validator 背 door 承接。
		if spec.RTSP == nil {
			spec.RTSP = core.ParseRTSPConfigFromMap(completedConfig(s, term.Config))
		}
	case "pptp":
		// D-PPTP-1：层 config 经 core.ParsePPTPConfigFromMap 复用扁平
		// 解析单一真相（sub_address hex/inner_ip 嵌套 7 子键由扁平 parse
		// 承接，JSON 往返会误读 payload 字节面——srv6 inner_payload 同
		// 陷阱）。空层 config 也翻译出非 nil（全默认=参考 pcap full 形）。
		if spec.PPTP == nil {
			spec.PPTP = core.ParsePPTPConfigFromMap(completedConfig(s, term.Config))
		}
	case "vnc":
		// D-VNC-1：层 config 经 core.ParseVNCConfigFromMap 复用扁平解析
		// 单一真相（rect hextile_tile_data/xcursor_blob hex 原文由扁平
		// parse 承接；getIntPresence 显式 0 保留=缺省面与 flat 同构）。
		// 空层 config 也翻译出非 nil（全默认=参考 pcap Tight 形）。
		if spec.VNC == nil {
			spec.VNC = core.ParseVNCConfigFromMap(completedConfig(s, term.Config))
		}
	case "smb":
		// D-SMB-1：层 config 经 core.TranslateSMBConfigFromMap 复用扁平
		// parseSMBConfig 宽容口径为单一真相（hex 字符串数值/GUID hex 串/
		// data 原文字节/ops 级 file_id 由 flat parse 承接；未知键严格拒）。
		// 空层 config 也翻译出非 nil（全默认=默认单 read 会话）。
		if spec.SMB == nil {
			smbCfg, err := core.TranslateSMBConfigFromMap(completedConfig(s, term.Config))
			if err != nil {
				spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
				return
			}
			spec.SMB = smbCfg
		}
	case "dameng":
		// D-DAMENG-1 G-DM-2：层 config（wire_profile/events/sessions/
		// payload_size/wire_fault）经 JSON 往返解码为 core.DamengConfig
		//（postgresql :2009-2036 同款——json tag 覆盖全部字段）。层优先：
		// spec.Dameng 已存在（引擎直调/单测路径）则不覆盖；扁平入口已由
		// CheckProtoFlat 判死顶层 dameng 子映射（存量行经
		// strategy_convert 兼容块记 ValidationErrors）。空层 config 翻译出
		// 非 nil 空配置 → validator 按 P0b 缺省流承接（层 config 未知键在
		// config 层即拒：DamengConfig UnmarshalJSON
		// DisallowUnknownFields）。
		if spec.Dameng != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		cfgD := completedConfig(s, term.Config)
		rawD, err := json.Marshal(cfgD)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("dameng layer config encode: %v", err))
			return
		}
		var dcfg core.DamengConfig
		decD := json.NewDecoder(bytes.NewReader(rawD))
		decD.DisallowUnknownFields()
		if err := decD.Decode(&dcfg); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("dameng layer config decode: %v", err))
			return
		}
		spec.Dameng = &dcfg
	case "xmpp":
		// D-XMPP-1：层 config 经 core.ParseXmppConfigFromMap 复用扁平
		// 解析单一真相（messages 记录 direction/to/body 与 flat 同构）。
		// 空层 config 也翻译出非 nil（全默认=PLAIN 19 帧参考形）。
		if spec.Xmpp == nil {
			spec.Xmpp = core.ParseXmppConfigFromMap(completedConfig(s, term.Config))
		}
	case "sctp":
		// D-SCTP-1：层 config 经 core.ParseSCTPConfigFromMap 复用扁平
		// 解析单一真相（chunks[].data 双形 string/字节数组由扁平 parse
		// 承接——rtmp payload_b64 同陷阱面）。空层 config 也翻译出非 nil。
		if spec.SCTP == nil {
			spec.SCTP = core.ParseSCTPConfigFromMap(completedConfig(s, term.Config))
		}
		// 1.12 端口补位：sctp 层显式 src_port/dst_port 回填 spec（tcp/udp
		// 层回填循环 :181 只认 tcp/udp 层名，sctp 端口住本层）——非零显式
		// 才覆盖，dyn 对象/0 跳过（与 tcp 回填同语义）。
		if v, ok := term.Config["src_port"]; ok && v != nil {
			if _, isObj := v.(map[string]interface{}); !isObj {
				if up, ok2 := configUint16(v); ok2 && up != 0 {
					spec.SrcPort = up
				}
			}
		}
		if v, ok := term.Config["dst_port"]; ok && v != nil {
			if _, isObj := v.(map[string]interface{}); !isObj {
				if up, ok2 := configUint16(v); ok2 && up != 0 {
					spec.DstPort = up
				}
			}
		}
	case "jt808":
		// D-JT808-1：层 config 经 core.ParseJT808ConfigFromMap 复用扁平
		// 解析单一真相（procedures 嵌套全 parse 承接；extra/param value
		// 双形 getByteSlice——rtmp payload_b64 同陷阱面）。空层 config 也
		// 翻译出非 nil。端口=legacy 内部缺省 7611（vnc/pptp 变体），无
		// 端口回填分支（jt808 层无端口字段）。
		if spec.JT808 == nil {
			spec.JT808 = core.ParseJT808ConfigFromMap(completedConfig(s, term.Config))
		}
	case "jt809":
		// D-JT809-1：层 config 经 core.ParseJT809ConfigFromMap 复用扁平
		// 解析单一真相（procedures/slave_procedures 嵌套全 parse 承接）。
		// 空层 config 也翻译出非 nil。端口=legacy 内部缺省 8812（mapToFlowSpec
		// case 先补，jt808 同款），无端口回填分支（jt809 层无端口字段）。
		if spec.JT809 == nil {
			spec.JT809 = core.ParseJT809ConfigFromMap(completedConfig(s, term.Config))
		}
	case "jtt905":
		// D-JTT905-1：层 config 经 core.ParseJTT905ConfigFromMap 复用扁平
		// 解析单一真相（procedures 嵌套全 parse 承接；position 块对象键）。
		// 空层 config 也翻译出非 nil。端口=legacy 内部缺省 10700（mapToFlowSpec
		// case 先补，jt808 同款），无端口回填分支。
		if spec.JTT905 == nil {
			spec.JTT905 = core.ParseJTT905ConfigFromMap(completedConfig(s, term.Config))
		}
	case "tftp":
		// D-TFTP-1：层 config 经 core.ParseTFTPConfigFromMap 复用扁平
		// 解析单一真相（data_payload_pattern 原文字节/retransmit_blocks
		// 数字数组/auto_append_final_block 指针三态由扁平 parse 承接，
		// JSON 往返会误读——srv6 inner_payload 同陷阱）。
		// 空层 config 也翻译出非 nil（validator 首命中 filename 必需，
		// 不静默缺省流）。端口=validateSpecBase DstPort switch 69 缺省
		// （chain_planner.go:956），无端口回填分支（tftp 层无端口字段）。
		if spec.TFTP == nil {
			spec.TFTP = core.ParseTFTPConfigFromMap(completedConfig(s, term.Config))
		}
	case "fins":
		// D-FINS-1：层 config map 直存 Metadata（GetConfig map 分支既有
		// types.go:159-168；Data []byte 经 JSON 数字数组无双语义，无 srv6
		// inner_payload 陷阱）。carrier 门（chain_planner.go :369）在本翻译
		// （ValidateSpec :161）之后执行，层内 transport 值可达。空层 {} 也
		// 翻译出非 nil 空配置 → 生成器缺省化（P0b-2 默认 DM 读）。仅在
		// Metadata 缺席时落层值：既有 Metadata（引擎直调/存量行带类型配置）
		// 不被空层覆盖，carrier 门仍读原值（fins_test carrier mismatch 锁）。
		if spec.Metadata == nil {
			spec.Metadata = make(map[string]interface{})
		}
		if _, exists := spec.Metadata["fins"]; !exists {
			cfgMap := term.Config
			if cfgMap == nil {
				cfgMap = map[string]interface{}{}
			}
			spec.Metadata["fins"] = cfgMap
		}
	case "nfs":
		// D-NFS-1：层 config map 直存 Metadata（GetConfig map 分支经
		// nfsConfigFromJSONMap 往返；[12]byte 只认 JSON 数字数组——G-NFS-6
		// 裁定：文档回修，非法形态走反序列化失败）。仅在 Metadata 缺席时
		// 落层值：既有 Metadata（引擎直调/存量行带类型配置）不被空层覆盖，
		// carrier 门仍读原值（fins 同款锁）。空层 {} 也翻译出非 nil 空配置
		// → 生成器/validator 报 no config（与 legacy 无配置同款拒绝）。
		if spec.Metadata == nil {
			spec.Metadata = make(map[string]interface{})
		}
		if _, exists := spec.Metadata["nfs"]; !exists {
			cfgMap := term.Config
			if cfgMap == nil {
				cfgMap = map[string]interface{}{}
			}
			spec.Metadata["nfs"] = cfgMap
		}
	case "socks5":
		if spec.Socks != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// 层 config（version/auth_method/dst_addr/data/udp）经 JSON 往返
		// 解码为 core.SocksConfig（J 组 SOCKS5-over-TLS：[tcp,tls,socks5]
		// 链）。socks5 validator 要求 spec.Socks 非 nil，空层 config 也
		// 必须翻译出非 nil config（与 mqtt 分支同款）。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return
		}
		var sc core.SocksConfig
		if err := json.Unmarshal(raw, &sc); err == nil {
			spec.Socks = &sc
		}
	case "tds":
		// D-TDS-1：层条目 layers[].tds 经 JSON 搬进 spec.Payload（生成器经
		// FlowMeta.Payload 消费，drive :48 直传——无 Payload 字面量漏传位）。
		// 只搬用户显式键（term.Config 原样，不经 completedConfig）：补全后
		// 的 schema 默认（app_name:"" 等零值）会压住 configFromSpec 的
		// presence 默认（显式空串保留语义——T-026 password:"" 注记），导致
		// 缺省 LOGIN7 字段全空（login7_default 实证红）。层优先：
		// spec.Payload 已存在（引擎直调/单测路径）则不覆盖（goose/dns
		// 同款）；扁平入口已由 CheckProtoFlat 判死顶层 tds 子映射（存量行
		// 经 strategy_convert 兼容块记 ValidationErrors）。
		if len(spec.Payload) > 0 {
			return
		}
		if len(term.Config) == 0 {
			return
		}
		rawT, err := json.Marshal(term.Config)
		if err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors,
				fmt.Sprintf("tds layer config encode: %v", err))
			return
		}
		spec.Payload = rawT
	}
}

// decodeNodeOps converts a layer-config list of node operations into
// OPCUANodeRead values (read/write/browse share the shape).
func decodeNodeOps(v []interface{}) []core.OPCUANodeRead {
	ops := make([]core.OPCUANodeRead, 0, len(v))
	for _, item := range v {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		b, _ := json.Marshal(m)
		var op core.OPCUANodeRead
		json.Unmarshal(b, &op)
		ops = append(ops, op)
	}
	return ops
}

// translateDNSDyn resolves dns-layer dynamic objects (D-DNS-1 3 开字段：
// name string 面 / query_type·txid int 面) in the user raw config at flow
// index i, writing scalar resolutions into cfg (completed overlay).
// translateHTTPDyn 同构（读原始链、不读补全链；形状坏返回错误 Plan 同步
// 失败；空解析 no-op 保静态）。query_type/txid 走 ResolvePortValue（通用
// uint16 解析器，status_code 先例同款）。
func translateDNSDyn(cfg, raw map[string]interface{}, i int) string {
	if raw == nil {
		return ""
	}
	for _, key := range []string{"name", "query_type", "txid"} {
		m, isObj := raw[key].(map[string]interface{})
		if !isObj || m == nil {
			continue
		}
		if _, looksDyn := m["strategy"]; !looksDyn {
			continue
		}
		if msg := core.CheckLayerDynShape("dns", key, m); msg != "" {
			return msg
		}
		var sc core.StrategyConfig
		b, _ := json.Marshal(m)
		if err := json.Unmarshal(b, &sc); err != nil {
			return "dns." + key + ": invalid object"
		}
		if key == "name" {
			if v := core.ResolveStringValue(&sc, i); v != "" {
				cfg[key] = v
			} else {
				delete(cfg, key)
			}
			continue
		}
		if v := core.ResolvePortValue(&sc, i); v != 0 {
			cfg[key] = float64(v)
		} else {
			delete(cfg, key)
		}
	}
	return ""
}

// translateMQTTDyn resolves mqtt-layer dynamic objects (D-MQTT-1 §12 三开：
// client_id 直键 string 面 / topic·payload 逐 messages[] 槽位下钻 string 面)
// in the user raw config at flow index i, writing scalar resolutions into cfg
// (completed overlay). translateDNSDyn 同构：读原始链（对象完整）；形状坏
// 返回消息（caller 不翻译 → validator 同步拒绝）；空解析 no-op 保静态。
// messages[] 逐槽独立解析：静态槽不动，动态槽各自按 i 解析；item 浅拷贝
// 后替换——不写 p.chain 原对象（Plan 逐流复跑，对象必须保真）。
func translateMQTTDyn(cfg, raw map[string]interface{}, i int) string {
	if raw == nil {
		return ""
	}
	if m, isObj := raw["client_id"].(map[string]interface{}); isObj && m != nil {
		if _, looksDyn := m["strategy"]; looksDyn {
			if msg := core.CheckLayerDynShape("mqtt", "client_id", m); msg != "" {
				return msg
			}
			var sc core.StrategyConfig
			b, _ := json.Marshal(m)
			if err := json.Unmarshal(b, &sc); err != nil {
				return "mqtt.client_id: invalid object"
			}
			if v := core.ResolveStringValue(&sc, i); v != "" {
				cfg["client_id"] = v
			} else {
				delete(cfg, "client_id")
			}
		}
	}
	msgs, ok := raw["messages"].([]interface{})
	if !ok || len(msgs) == 0 {
		return ""
	}
	out := make([]interface{}, 0, len(msgs))
	for _, item := range msgs {
		im, isMap := item.(map[string]interface{})
		if !isMap {
			out = append(out, item)
			continue
		}
		copied := false
		for _, key := range []string{"topic", "payload"} {
			m, isObj := im[key].(map[string]interface{})
			if !isObj || m == nil {
				continue
			}
			if _, looksDyn := m["strategy"]; !looksDyn {
				continue
			}
			if msg := core.CheckLayerDynShape("mqtt", key, m); msg != "" {
				return msg
			}
			var sc core.StrategyConfig
			b, _ := json.Marshal(m)
			if err := json.Unmarshal(b, &sc); err != nil {
				return "mqtt." + key + ": invalid object"
			}
			if !copied {
				cp := make(map[string]interface{}, len(im))
				for k, v := range im {
					cp[k] = v
				}
				im = cp
				copied = true
			}
			if v := core.ResolveStringValue(&sc, i); v != "" {
				im[key] = v
			} else {
				delete(im, key)
			}
		}
		out = append(out, im)
	}
	cfg["messages"] = out
	return ""
}

// translateHTTPDyn resolves http-layer dynamic objects (D-HTTP-1 6 开字段)
// in the user raw config at flow index i, writing scalar resolutions into
// cfg (completed overlay). Scalar keys untouched. Shape errors return a
// message (caller fails Plan loudly); empty resolution is a no-op preserving
// the completed default (same "non-zero wins" as worker resolveLayerTuple).
// Only the 6 allowlisted keys are read; other keys (incl. closed-field
// objects rejected at ValidateLayers) are ignored here.
func translateHTTPDyn(cfg, raw map[string]interface{}, i int) string {
	if raw == nil {
		return ""
	}
	for _, key := range []string{"uri", "body", "body_b64", "response_body", "response_body_b64", "response_status_code"} {
		m, isObj := raw[key].(map[string]interface{})
		if !isObj || m == nil {
			continue
		}
		if _, looksDyn := m["strategy"]; !looksDyn {
			continue
		}
		if msg := core.CheckLayerDynShape("http", key, m); msg != "" {
			return msg
		}
		var sc core.StrategyConfig
		b, _ := json.Marshal(m)
		if err := json.Unmarshal(b, &sc); err != nil {
			return "http." + key + ": invalid object"
		}
		if key == "response_status_code" {
			if v := core.ResolvePortValue(&sc, i); v != 0 {
				cfg[key] = float64(v)
			} else {
				delete(cfg, key)
			}
			continue
		}
		if v := core.ResolveStringValue(&sc, i); v != "" {
			cfg[key] = v
		} else {
			delete(cfg, key)
		}
	}
	return ""
}

// translateTLSSNI resolves the tls-layer sni field (D-TLS-1 步骤 2，sni 开
// 1 关 3 中的唯一开键）from the user raw chain into spec.TLS.SNI. Scalar
// sni writes through; dynamic objects (strategy-bearing maps) resolve at
// spec.FlowIndex via CheckLayerDynShape + ResolveStringValue (same domain
// as worker resolveLayerTuple). Empty resolution is a no-op preserving the
// static/default. Only the allowlisted sni key is read; alpn/version/role
// objects are rejected at ValidateLayers and ignored here.
// Reads p.chain (user raw chain, dynamic objects intact), not the completed
// chain (objects stripped) — same rule as translateHTTPDyn's rawCfg.
func translateTLSSNI(p *ChainPlanner, spec *core.FlowSpec) {
	var rawCfg map[string]interface{}
	for _, l := range p.chain {
		if l.Name == "tls" {
			rawCfg = l.Config
			break
		}
	}
	if rawCfg == nil {
		return
	}
	// spec.TLS 非 nil 空壳（SNI/Version/Role/ALPN 全空）不算 flat 权威——
	// 层 config 才是真相（http :839 空壳例外同款；tls 链上 spec.TLS 恒 nil
	// 是合法态，有内容的 spec.TLS 才算 flat presence）。
	if spec.TLS != nil && (spec.TLS.SNI != "" || spec.TLS.Version != "" ||
		spec.TLS.Role != "" || len(spec.TLS.ALPN) > 0) {
		return // flat 权威；二者并存时 flat 优先，层 config 忽略
	}
	if m, isObj := rawCfg["sni"].(map[string]interface{}); isObj && m != nil {
		if _, looksDyn := m["strategy"]; looksDyn {
			if msg := core.CheckLayerDynShape("tls", "sni", m); msg != "" {
				return
			}
			var sc core.StrategyConfig
			b, _ := json.Marshal(m)
			if err := json.Unmarshal(b, &sc); err != nil {
				return
			}
			if v := core.ResolveStringValue(&sc, spec.FlowIndex); v != "" {
				if spec.TLS == nil {
					spec.TLS = &core.TLSConfig{}
				}
				spec.TLS.SNI = v
			}
			return
		}
	}
	if v, ok := rawCfg["sni"].(string); ok && v != "" {
		if spec.TLS == nil {
			spec.TLS = &core.TLSConfig{}
		}
		spec.TLS.SNI = v
	}
}

// translateTLSCert 直解 tls 层 cert 块内动态子键（D-TLS-2，translateTLSSNI
// 同构）：subject/san 的 strategy 对象按 spec.FlowIndex 解析，写入
// spec.TLS.ServerCertificate（只写解析键；标量 cert 不写 spec——生成器
// 直接读层 config）。读 p.chain 原始链。形状坏→静默返回（create 期已 400）。
func translateTLSCert(p *ChainPlanner, spec *core.FlowSpec) {
	var rawCfg map[string]interface{}
	for _, l := range p.chain {
		if l.Name == "tls" {
			rawCfg = l.Config
			break
		}
	}
	if rawCfg == nil {
		return
	}
	rawCert, ok := rawCfg["cert"].(map[string]interface{})
	if !ok || rawCert == nil {
		return
	}
	ensureServerCert := func() *core.X509Ref {
		if spec.TLS == nil {
			spec.TLS = &core.TLSConfig{}
		}
		if spec.TLS.ServerCertificate == nil {
			spec.TLS.ServerCertificate = &core.X509Ref{}
		}
		return spec.TLS.ServerCertificate
	}
	if m, isObj := rawCert["subject"].(map[string]interface{}); isObj && m != nil {
		if _, looksDyn := m["strategy"]; looksDyn {
			if msg := core.CheckLayerDynShape("tls", "cert.subject", m); msg != "" {
				return
			}
			var sc core.StrategyConfig
			b, _ := json.Marshal(m)
			if err := json.Unmarshal(b, &sc); err != nil {
				return
			}
			if v := core.ResolveStringValue(&sc, spec.FlowIndex); v != "" {
				ensureServerCert().Subject = v
			}
		}
	}
	if m, isObj := rawCert["san"].(map[string]interface{}); isObj && m != nil {
		if _, looksDyn := m["strategy"]; looksDyn {
			if msg := core.CheckLayerDynShape("tls", "cert.san", m); msg != "" {
				return
			}
			var sc core.StrategyConfig
			b, _ := json.Marshal(m)
			if err := json.Unmarshal(b, &sc); err != nil {
				return
			}
			if v := core.ResolveStringValue(&sc, spec.FlowIndex); v != "" {
				ensureServerCert().San = []string{v}
			}
		}
	}
}

// completedConfig overlays the user layer config onto the schema defaults
// (用户层 config > schema 默认值，applySpecToChain 同款语义)。
func completedConfig(s LayerSchema, user map[string]interface{}) map[string]interface{} {
	cfg := make(map[string]interface{}, len(s.Fields))
	for k, f := range s.Fields {
		if f.Default != nil {
			cfg[k] = f.Default
		}
	}
	for k, v := range user {
		cfg[k] = v
	}
	return cfg
}
