package layers

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
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
	meta := FlowMeta{
		FlowID:  flowID(spec),
		Payload: spec.Payload,
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
		NFS:        spec.Metadata["nfs"],
		FINS:       spec.Metadata["fins"],
		// CoAP 同款（P4a）：配置经 Meta 直传 coap 终结层生成器（请求 + 可选
		// ACK 响应两事件，BuildMessage 纯函数复用）。缺这行时 req.Meta.CoAP
		// 恒 nil → 生成器回退默认 GET/无响应 → 所有 coap 链只发 1 包。
		CoAP:       spec.CoAP,
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
		KingBase:   spec.KingBase,
		PostgreSQL: spec.PostgreSQL,
		CQL:        spec.CQL,
		LDP:        spec.LDP,
		PCEP:       spec.PCEP,
		CFlow:      spec.CFlow,
		AMQP:       spec.AMQP,
		RTMFP:      spec.RTMFP,
		IGMP:       spec.IGMP,
		OSPF:       spec.OSPF,
		PIM:        spec.PIM,
		ISIS:       spec.ISIS,
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
		GRPC:    spec.GRPC,
		// SSH 同款（P3）：version exchange + KEXINIT/KEXDH + NEWKEYS + userauth
		// + channel 逐 BPP 帧事件，encode*/buildBPP 纯函数复用。
		SSH:     spec.SSH,
		// RDP 同款（P3）：X.224/MCS/security PDU 序列逐帧事件，encode* 纯函数
		// 复用。Only set for rdp chains。
		RDP:     spec.RDP,
		// OpenVPN 同款（P3）：UDP 数据报序列 P_CONTROL/P_DATA 事件，
		// build* 纯函数复用。Only set for openvpn chains。
		OpenVPN: spec.OpenVPN,
		// VMess 同款（P3）：TCP-mode request/response AEAD 帧序列事件，
		// build* 纯函数复用。Only set for vmess chains。
		Vmess:   spec.Vmess,
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
		if spec.HTTP != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		cfg := completedConfig(s, term.Config)
		spec.HTTP = &core.HTTPConfig{}
		if v, ok := configString(cfg["method"]); ok {
			spec.HTTP.Method = v
		}
		if v, ok := configString(cfg["uri"]); ok {
			spec.HTTP.URI = v
		}
		if v, ok := configString(cfg["version"]); ok {
			// 层 config 的 version 是裸版本号（schema 默认 "1.1"），
			// HTTPConfig.Version 契约是完整 "HTTP/1.1"（types.go:487；
			// builder 只默认空串，见 http.go:563-565）——prefix 归一，
			// 与 flat 路径一致（mapToFlowSpec 从 cfg["http"]["version"] 取
			// 裸值也是经 builder 渲染成 "HTTP/1.1" 的隐含依赖）。
			if !strings.HasPrefix(v, "HTTP/") {
				spec.HTTP.Version = "HTTP/" + v
			} else {
				spec.HTTP.Version = v
			}
		}
		if h, ok := cfg["headers"]; ok {
			if m, ok := h.(map[string]interface{}); ok {
				spec.HTTP.RequestHeaders = make(map[string]string, len(m))
				for k, v := range m {
					spec.HTTP.RequestHeaders[k] = fmt.Sprint(v)
				}
			}
		}
		if v, ok := configString(cfg["body"]); ok {
			spec.HTTP.Body = v
		}
	case "dns":
		if spec.DNS != nil {
			return // flat 权威
		}
		cfg := completedConfig(s, term.Config)
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
	case "mqtt":
		if spec.MQTT != nil {
			return // flat 权威；二者并存时 flat 优先，层 config 忽略
		}
		// 层 config 经 JSON 往返解码为 core.MQTTConfig（J 组 MQTTS：
		// [tcp,tls,mqtt] 链）。mqtt validator 要求 spec.MQTT 非 nil，
		// 空层 config 也必须翻译出非 nil config（与 opcua 分支同款）。
		cfg := completedConfig(s, term.Config)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return
		}
		var mc core.MQTTConfig
		if err := json.Unmarshal(raw, &mc); err == nil {
			spec.MQTT = &mc
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
