package sstp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// 用例生成器（一次性，D-SSTP-1 P5）：按用例文档 §2 权威序产出 20 例
// （14 正 + 6 负），落 test/protocol_pcap/cases/sstp.json。
//
// 证据红线（契约 §1/§9/§16）：本 fixture 的 SSTP message 经 tls 层
// application-data 透传（合成 TLS record，无真实密钥协商），tshark 不会用
// sstp.*/ppp.* 解码器解析 record 体 —— 断言只用三通道：
//   ①载体字段 tls.record.content_type/version/length + tcp/ip 字段；
//   ②frames hex（record 体内的 SSTP header/attribute/PPP 字节逐位钉）；
//   ③方向（directional/same_as）+ 包数。
// 绝不写 sstp.* / ppp.* 字段断言（那是解密 fixture 才有的面）。
//
// 帧内偏移：Ethernet 14 + IPv4 20 + TCP 20 = 54 → TLS record 头 5 字节 →
// record 体（= SSTP message 起点 S）在帧内偏移 59；IPv6 外层为 14+40+20+5=79。
// 数据包序号：1-3 TCP 握手、4-10 TLS 握手 record×7、11 起 application-data。
const (
	sFrameOffV4 = 59
	sFrameOffV6 = 79
	sFirstData  = 11
)

type sfld struct {
	Packet   int
	Field    string
	Value    string
	Same     int
	Distinct []string
	Exclude  []string
	Nonzero  bool
}

func (f sfld) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "field": f.Field}
	if f.Value != "" {
		m["value"] = f.Value
	}
	if f.Same > 0 {
		m["same_as_packet"] = f.Same
	}
	if len(f.Distinct) > 0 {
		m["distinct_values"] = f.Distinct
	}
	if len(f.Exclude) > 0 {
		m["distinct_exclude"] = f.Exclude
	}
	if f.Nonzero {
		m["nonzero"] = true
	}
	return m
}

type sfr struct {
	Packet int
	Offset int
	Hex    string
}

func (f sfr) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "hex": f.Hex}
	if f.Offset != 0 {
		m["offset"] = f.Offset
	}
	return m
}

type sposCase struct {
	id      string
	summary string
	layers  []interface{}
	fc      *int
	fields  []sfld
	frames  []sfr
	notes   []string
	// min/max 包数期望（先跑后钉：P5 实测值）。
	packetCount int
	minPackets  int
	handshake   bool
	terminates  bool
	directional bool
}

type snegCase struct {
	id      string
	summary string
	layers  []interface{}
	anchor  string
	notes   []string
}

// fixture 端点/端口（契约 §16.1 样例同族）。
const (
	sCli   = "192.0.2.57"
	sSrv   = "198.51.100.57"
	sCli6  = "2001:db8::57"
	sSrv6  = "2001:db8:ffff::57"
	sSport = 45057
	sPort  = 443
	sSNI   = "sstp.example.test"
)

// ---- 层链快捷构造 ----

func ip4L(src, dst string) map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": src, "dst": dst}}
}
func tcpL(sp, dp int) map[string]interface{} {
	return map[string]interface{}{"tcp": map[string]interface{}{"src_port": sp, "dst_port": dp}}
}
func tcpDynL(dp int) map[string]interface{} {
	// flows>1 的用例：src_port 写 inc 动态对象（http_multiflow_dynamic_sport
	// 先例——静态四元组 + flows>1 被 checkLayerChainStaticCopy 判死，
	// CORE_MEMORY 12.9；动态对象即"逐流有别"证明）。
	return map[string]interface{}{"tcp": map[string]interface{}{
		"src_port": map[string]interface{}{"strategy": "inc", "range": []interface{}{41000, 41001}},
		"dst_port": dp,
	}}
}
func tlsL() map[string]interface{} {
	// 链上结构性门（P2e T13）：version 只 tls1.3、role 只 client。
	return map[string]interface{}{"tls": map[string]interface{}{
		"version": "tls1.3", "sni": sSNI, "role": "client",
	}}
}
func sstpL(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"sstp": cfg}
}

func sChain(cfg map[string]interface{}) []interface{} {
	return []interface{}{ip4L(sCli, sSrv), tcpL(sSport, sPort), tlsL(), sstpL(cfg)}
}
func sChain6(cfg map[string]interface{}) []interface{} {
	return []interface{}{ip4L(sCli6, sSrv6), tcpL(sSport, sPort), tlsL(), sstpL(cfg)}
}
func sChainMulti(cfg map[string]interface{}) []interface{} {
	return []interface{}{ip4L(sCli, sSrv), tcpDynL(sPort), tlsL(), sstpL(cfg)}
}

// ---- 事务/属性快捷构造（镜像 sstp 层 config 键） ----

func tx(kind string, extra map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"kind": kind}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func attrs(list ...map[string]interface{}) []interface{} {
	out := make([]interface{}, len(list))
	for i, a := range list {
		out[i] = a
	}
	return out
}

func attr(id int, extra ...map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"id": id}
	if len(extra) > 0 {
		for k, v := range extra[0] {
			m[k] = v
		}
	}
	return m
}

func eventsCfg(list ...map[string]interface{}) map[string]interface{} {
	evs := make([]interface{}, len(list))
	for i, e := range list {
		evs[i] = e
	}
	return map[string]interface{}{"events": evs}
}

// 常用事务序列片段。
func reqTx() map[string]interface{} {
	return tx("call_connect_request", map[string]interface{}{"direction": "c2s",
		"attributes": attrs(attr(1))})
}
func ackTx() map[string]interface{} {
	return tx("call_connect_ack", map[string]interface{}{"direction": "s2c",
		"attributes": attrs(attr(4))})
}
func connectedTx() map[string]interface{} {
	return tx("call_connected", map[string]interface{}{"direction": "c2s",
		"attributes": attrs(attr(3))})
}
func pppTx(proto string, payloadLen int, mppe bool) map[string]interface{} {
	ppp := map[string]interface{}{"protocol": proto}
	if payloadLen > 0 {
		ppp["payload_len"] = payloadLen
	}
	if mppe {
		ppp["mppe"] = true
	}
	return tx("ppp_data", map[string]interface{}{"direction": "c2s", "ppp": ppp})
}

// carrierFields 是每条正例共用的载体断言（TCP/443 + TLS record 面）。
func carrierFields(firstData int) []sfld {
	return []sfld{
		{Packet: 1, Field: "tcp.dstport", Value: "443"},
		{Packet: 4, Field: "tls.record.content_type", Value: "22"},       // TLS 握手起点
		{Packet: 10, Field: "tls.record.content_type", Value: "22"},      // 握手最后一条 record
		{Packet: firstData, Field: "tls.record.length", Nonzero: true},   // application-data record（tshark 不对 opaque application-data 解 content_type——canonical pop3s 同款，故不断 23；record 体由 frames hex 钉）
	}
}

// ---- 正例定义（契约 §10/testcase §2 权威序） ----

func sstpPosCases() []sposCase {
	two := 2
	return []sposCase{
		{
			id:      "sstp_https_tls_handshake",
			summary: "TCP/443 + TLS 握手 + application-data 载体（无密钥只断言 TLS）",
			layers:  sChain(eventsCfg(reqTx(), ackTx())),
			fields: append(carrierFields(sFirstData),
				sfld{Packet: 1, Field: "tcp.flags", Value: "0x0002"}),
			frames: []sfr{
				// 首条 application-data record 内：SSTP common header（Version
				// 0x10 | C=1 | Length 14）+ Type 0x0001 + Num 1。
				{Packet: sFirstData, Offset: sFrameOffV4, Hex: "10 01 00 0e 00 01 00 01"},
				// 第二条 record（server→client）：ACK 的 Type 0x0002 + 属性头 0x04。
				{Packet: sFirstData + 1, Offset: sFrameOffV4, Hex: "10 01 00 30 00 02 00 01 00 04 00 28"},
			},
			packetCount: 16,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"证据红线：无解密密钥，只断言 TCP/443 + tls.record.* + frames hex（record 体内字节），不使用 sstp.*/ppp.* 字段。",
				"packet_count 16 = 3 TCP 握手 + 7 TLS 握手 record + 2 application-data + 4 TCP 挥手。",
			},
		},
		{
			id:      "sstp_call_connect_request",
			summary: "CALL CONNECT REQUEST：Length 0x000e、Type 0x0001、Num 1、Encapsulated Protocol ID",
			layers:  sChain(eventsCfg(reqTx())),
			fields:  carrierFields(sFirstData),
			frames: []sfr{
				{Packet: sFirstData, Offset: sFrameOffV4, Hex: "10 01 00 0e 00 01 00 01 00 01 00 06 00 01"},
			},
			packetCount: 15,
			handshake:   true,
			terminates:  true,
			notes: []string{
				"REQUEST 全长 14B = 4B common header（Length 覆盖整包）+ 2B Message Type + 2B Num Attributes + 6B 属性（LengthPacket 含 4B 属性头）。",
			},
		},
		{
			id:      "sstp_call_connect_ack",
			summary: "CALL CONNECT ACK：Crypto Binding Request + Status Info、方向 s2c",
			layers: sChain(eventsCfg(
				reqTx(),
				tx("call_connect_ack", map[string]interface{}{"direction": "s2c", "attributes": attrs(
					attr(4), attr(2, map[string]interface{}{"attrib_id": 1, "status": 0})),
				}),
			)),
			fields: append(carrierFields(sFirstData),
				sfld{Packet: sFirstData + 1, Field: "tcp.srcport", Value: "443"}),
			frames: []sfr{
				// ACK：Length 0x0030+0x0c=0x003c（8 + 40 + 12）、Type 0x0002、
				// Num 2、首属性 0x04/LengthPacket 0x0028。
				{Packet: sFirstData + 1, Offset: sFrameOffV4, Hex: "10 01 00 3c 00 02 00 02 00 04 00 28"},
				// 末属性（Status Info）：Length 0x003c-40-8 = 12 → LengthPacket 0x000c。
				{Packet: sFirstData + 1, Offset: sFrameOffV4 + 8 + 40, Hex: "00 02 00 0c 00 00 00 01 00 00 00 00"},
			},
			packetCount: 16,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"ACK 不是 CONNECTED：Message Type 0x0002 与 0x0004 逐字节区别；Length 覆盖全部属性（40 + 12）。",
				"Status Info value = Reserved1(3) + AttribID(1) + Status(4) + AttribValue(0) = 8B（MS-SSTP §2.2.8）。",
			},
		},
		{
			id:      "sstp_call_connected",
			summary: "CONNECTED：Length 0x0070、Crypto Binding 0x0068（SHA-256 profile），其后才允许 PPP",
			layers: sChain(eventsCfg(
				reqTx(), ackTx(), connectedTx(), pppTx("ipv4", 24, false),
			)),
			fields: carrierFields(sFirstData),
			frames: []sfr{
				// CONNECTED：Length 112 = 8 + 104、Type 0x0004、Num 1、
				// 属性 0x03/LengthPacket 0x0068 + Reserved1(3)+hash(1)。
				{Packet: sFirstData + 2, Offset: sFrameOffV4, Hex: "10 01 00 70 00 04 00 01 00 03 00 68 00 00 00 02"},
				// 其后 PPP data：C=0、S+4 = ff 03 00 21（IPv4）。
				{Packet: sFirstData + 3, Offset: sFrameOffV4, Hex: "10 00 00 20 ff 03 00 21"},
			},
			packetCount: 18,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"PPP data 在 CONNECTED 之后（越序走负例 sstp_neg_state_transition）。",
			},
		},
		{
			id:      "sstp_call_abort",
			summary: "CALL ABORT：Type 0x0005 + Status Info，ABORT 后无任何后续消息且连接关闭",
			layers: sChain(eventsCfg(
				reqTx(), ackTx(), connectedTx(), pppTx("ipv4", 24, false),
				tx("call_abort", map[string]interface{}{"direction": "c2s", "attributes": attrs(
					attr(2, map[string]interface{}{"attrib_id": 1, "status": 6}))}),
			)),
			fields: carrierFields(sFirstData),
			frames: []sfr{
				// ABORT：Length 20 = 8 + 12、Type 0x0005、Num 1、
				// Status Info（LengthPacket 0x000c、AttribID 0x01、Status 0x00000006）。
				{Packet: sFirstData + 4, Offset: sFrameOffV4, Hex: "10 01 00 14 00 05 00 01 00 02 00 0c 00 00 00 01 00 00 00 06"},
			},
			packetCount: 19,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"Status 0x00000006 = ATTRIB_STATUS_RETRY_COUNT_EXCEEDED（MS-SSTP §2.2.8 枚举）。",
				"ABORT 是最后一条 application-data（其后为 TCP 挥手）；续发走负例 state。",
			},
		},
		{
			id:      "sstp_attribute_protocol_id",
			summary: "Encapsulated Protocol ID 属性：Attribute ID 0x01 / LengthPacket 0x0006 / Value 0x0001",
			layers:  sChain(eventsCfg(reqTx())),
			fields:  carrierFields(sFirstData),
			frames: []sfr{
				{Packet: sFirstData, Offset: sFrameOffV4 + 8, Hex: "00 01 00 06 00 01"},
			},
			packetCount: 15,
			handshake:   true,
			terminates:  true,
			notes: []string{
				"LengthPacket 含 4B 属性头（不是 value 长）：value 2B Protocol ID = 0x0001（PPP，RFC 1661）。",
				"属性头 Reserved 发送时为 0；Message Type 0x0005/0x0006 不能出现在属性 ID 位（负例 attribute_length）。",
			},
		},
		{
			id:      "sstp_attribute_status_crypto",
			summary: "Status Info（0x02）+ Crypto Binding（0x03）：总长 0x0068/变长，ACK 与 CONNECTED 的 nonce 同值",
			layers: sChain(eventsCfg(
				reqTx(),
				tx("call_connect_ack", map[string]interface{}{"direction": "s2c", "attributes": attrs(
					attr(4), attr(2, map[string]interface{}{"attrib_id": 2, "status": 0, "value_len": 4}))}),
				connectedTx(),
			)),
			fields: carrierFields(sFirstData),
			frames: []sfr{
				// ACK 尾属性：Status Info 变长（LengthPacket = 4 + 8 + 4 = 16）。
				{Packet: sFirstData + 1, Offset: sFrameOffV4 + 8 + 40, Hex: "00 02 00 10 00 00 00 02 00 00 00 00 00 00 00 00"},
				// CONNECTED 的 0x03 属性头 + Hash Protocol（SHA-256=0x02）+ nonce
				// 首 8B（确定性 0x5A 填充，与 ACK 的 Binding Request nonce 同值）。
				{Packet: sFirstData + 2, Offset: sFrameOffV4 + 8, Hex: "00 03 00 68 00 00 00 02 5a 5a 5a 5a 5a 5a 5a 5a"},
				// ACK 的 0x04 属性头 + bitmask 0x02 + 同值 nonce 首 8B。
				{Packet: sFirstData + 1, Offset: sFrameOffV4 + 8, Hex: "00 04 00 28 00 00 00 02 5a 5a 5a 5a 5a 5a 5a 5a"},
			},
			packetCount: 17,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"Crypto Binding 总长 104（0x0068）不得截断；Binding Request 总长 40（0x0028）。",
				"nonce/cert hash/compound MAC 是确定性 fixture（0x5A/0xC3/0xCA 填充），不伪造密码学语义；运行期可动态。",
			},
		},
		{
			id:      "sstp_ppp_ipv4",
			summary: "C=0 PPP IPv4：ff 03 00 21 + IPv4 头（version/length/checksum 实算）",
			layers: sChain(eventsCfg(
				reqTx(), ackTx(), connectedTx(), pppTx("ipv4", 40, false),
			)),
			fields: carrierFields(sFirstData),
			frames: []sfr{
				// data 包：Length 48 = 4 头 + 4 帧头 + 40 information；
				// ff 03 + 0021 + IPv4(45 00 0028 ... TTL 40 proto 01) + checksum。
				{Packet: sFirstData + 3, Offset: sFrameOffV4, Hex: "10 00 00 30 ff 03 00 21 45 00 00 28 00 00 00 00 40 01"},
				{Packet: sFirstData + 3, Offset: sFrameOffV4 + 20, Hex: "0a 00 00 01 0a 00 00 02"},
			},
			packetCount: 18,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"PPP protocol 由 sstp 层声明（ipv4→0x0021），不由 outer IP 地址族推导（契约 §7）。",
				"IPv4 头校验和按 RFC 1071 在合成载荷上实算（frame hex 钉前 20B）。",
			},
		},
		{
			id:      "sstp_ppp_ipv6",
			summary: "C=0 PPP IPv6：ff 03 00 57 + IPv6 头（version/payload length/Next Header 59）",
			layers: sChain(eventsCfg(
				reqTx(), ackTx(), connectedTx(), pppTx("ipv6", 60, false),
			)),
			fields: carrierFields(sFirstData),
			frames: []sfr{
				// Length 68 = 4 + 4 + 60；ff 03 + 0057 + IPv6(60 00 0000 0014 3b 40 …)。
				{Packet: sFirstData + 3, Offset: sFrameOffV4, Hex: "10 00 00 44 ff 03 00 57 60 00 00 00 00 14 3b 40"},
				{Packet: sFirstData + 3, Offset: sFrameOffV4 + 16, Hex: "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01"},
			},
			packetCount: 18,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"IPv6 独立 fixture：地址族与 IPv4 例互不改写（outer 仍为 IPv4/443 载体）。",
			},
		},
		{
			id:      "sstp_ppp_mppe_boundary",
			summary: "MPPE 边界：information 恰好 16B（block 对齐）与 20B（跨 boundary），密文 opaque",
			layers: sChain(eventsCfg(
				reqTx(), ackTx(), connectedTx(),
				pppTx("ipv4", 16, true), pppTx("ipv4", 20, true),
			)),
			fields: carrierFields(sFirstData),
			frames: []sfr{
				// MPPE 帧：protocol 0x00FD（RFC 3078 压缩加密数据报），
				// information 是 opaque 填充（不解释为 IPv4/IPv6 头）。
				{Packet: sFirstData + 3, Offset: sFrameOffV4, Hex: "10 00 00 18 ff 03 00 fd 5a 5a 5a 5a"},
				{Packet: sFirstData + 4, Offset: sFrameOffV4, Hex: "10 00 00 1c ff 03 00 fd 5a 5a 5a 5a"},
			},
			packetCount: 19,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"MPPE 只改 information 的加密表示，不改 SSTP Length 或 PPP protocol 语义边界（契约 §7）。",
				"无解密密钥：只断言 C=0 + SSTP Length + TLS application-data 长度，不把密文识别为 IPv4/IPv6。",
			},
		},
		{
			id:      "sstp_multi_connection",
			summary: "多连接隔离：flows=2 两条独立 TCP/443 + TLS session，各自完成控制序与 PPP",
			layers:  sChainMulti(eventsCfg(reqTx(), ackTx(), connectedTx(), pppTx("ipv4", 24, false))),
			fc:      &two,
			fields: []sfld{
				{Packet: 1, Field: "tcp.dstport", Value: "443"},
				{Packet: 4, Field: "tls.record.content_type", Value: "22"},
				// 两条流各自的 application-data record（每流第 11 包起）。
				{Packet: sFirstData, Field: "tls.record.length", Nonzero: true},
				{Packet: sFirstData + 18, Field: "tls.record.length", Nonzero: true},
			},
			packetCount: 36,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"flows=2：两条独立 TLS/TCP/SSTP connection（每流各自 REQUEST→ACK→CONNECTED→PPP），不跨连接串流（契约 §8）。",
				"src_port 未写 → worker 保底递增（12345+i），两条流四元组互异（CORE_MEMORY 9.39/2.8）。",
			},
		},
		{
			id:      "sstp_session_ordering",
			summary: "同连接严格顺序 + ECHO 保活 + 关闭后新 TLS/TCP 连接重连（flows=2）",
			layers: sChainMulti(eventsCfg(
				reqTx(), ackTx(), connectedTx(), pppTx("ipv4", 24, false),
				tx("echo_request", map[string]interface{}{"direction": "c2s"}),
				tx("echo_response", map[string]interface{}{"direction": "s2c"}),
			)),
			fc: &two,
			fields: []sfld{
				{Packet: sFirstData, Field: "tls.record.length", Nonzero: true},
				// 第二条连接重新走 REQUEST（第 2 流的首条 app record）。
				{Packet: sFirstData + 18, Field: "tls.record.length", Nonzero: true},
			},
			frames: []sfr{
				// 顺序钉：REQUEST→ACK→CONNECTED→PPP→ECHO REQ→ECHO RSP 的
				// Message Type 逐条（S+4 的 2B 网络序）。
				{Packet: sFirstData, Offset: sFrameOffV4 + 4, Hex: "00 01"},
				{Packet: sFirstData + 1, Offset: sFrameOffV4 + 4, Hex: "00 02"},
				{Packet: sFirstData + 2, Offset: sFrameOffV4 + 4, Hex: "00 04"},
				{Packet: sFirstData + 4, Offset: sFrameOffV4 + 4, Hex: "00 08"},
				{Packet: sFirstData + 5, Offset: sFrameOffV4 + 4, Hex: "00 09"},
			},
			packetCount: 40,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"ECHO REQ/RSP 只在 CONNECTED 之后（保活，MS-SSTP §3.4）；不假设并行到达的全局包序。",
				"重连 = 新 TLS/TCP connection（第 2 流整体重走），旧连接不再接收新状态。",
			},
		},
		{
			id:      "sstp_length_record_segmentation",
			summary: "SSTP Length 跨 TLS record/TCP segment：单 message 切多 record + 大帧跨 TCP 段",
			layers: sChain(eventsCfg(
				reqTx(), ackTx(), connectedTx(),
				tx("ppp_data", map[string]interface{}{"direction": "c2s", "chunk": 8,
					"ppp": map[string]interface{}{"protocol": "ipv4", "payload_len": 2000}}),
				pppTx("ipv6", 60, false),
			)),
			fields: []sfld{
				{Packet: 1, Field: "tcp.dstport", Value: "443"},
				{Packet: sFirstData, Field: "tls.record.length", Nonzero: true},
				// 首片 record 是 8 字节分片（不是完整 message 边界）。
				{Packet: sFirstData + 3, Field: "tls.record.length", Value: "8"},
			},
			frames: []sfr{
				// 首片 = common header 前 5B（Length 0x07d8 = 4 头 + 4 帧头 +
				// 2000 information）+ PPP 帧首字节 ff——S+4 `ff 03` 边界跨
				// record（契约 §5 点名形状）。
				{Packet: sFirstData + 3, Offset: sFrameOffV4, Hex: "10 00 07 d8 ff"},
				// 第 2 片已进 IPv4 头：45 00 07 d0（version 4 + total length 2000）。
				{Packet: sFirstData + 4, Offset: sFrameOffV4, Hex: "45 00 07 d0"},
			},
			packetCount: 269,
			minPackets:  269,
			handshake:   true,
			terminates:  true,
			notes: []string{
				"record/TCP segment 边界 ≠ SSTP message 边界：单条 message（Length 0x07d8 = 2008）切 251 条 8B record 后仍可按 Length 还原（契约 §5/§8）。",
				"实测 269 包 = 3 TCP 握手 + 7 TLS 握手 record + 3 控制消息 + 251 分片 + 1 IPv6 data + 4 TCP 挥手；跨 TCP segment 面由同数据形状的 MSS 切段覆盖。",
			},
		},
		{
			id:      "sstp_pcap_nic_consistency",
			summary: "PCAP/NIC 载体一致：TCP/443 + TLS 握手/应用数据 + 方向 + 握挥手数量",
			layers:  sChain(eventsCfg(reqTx(), ackTx())),
			fields: append(carrierFields(sFirstData),
				sfld{Packet: 1, Field: "tcp.flags", Value: "0x0002"},
				sfld{Packet: 15, Field: "tcp.flags", Value: "0x0011"}),
			packetCount: 16,
			handshake:   true,
			terminates:  true,
			directional: true,
			notes: []string{
				"NIinterface=netif:enp135s0f0np0；建议过滤器 tcp port 443；checksum offload 下 NIC 侧校验和可能显示为 0/非法（记录观察边界，不算失败）。",
				"未解密捕获不要求 SSTP/PPP 字段；PCAP 与 NIC 两侧断言同一载体口径（契约 §9/§14）。",
			},
		},
	}
}

func sstpNegCases() []snegCase {
	return []snegCase{
		{
			id:      "sstp_neg_header_length",
			summary: "common/control header 长度或 Length 不一致（wire_fault 注入）",
			layers:  sChain(map[string]interface{}{"wire_fault": "header_length"}),
			anchor:  "header",
		},
		{
			id:      "sstp_neg_attribute_length",
			summary: "属性头截断/LengthPacket 越界或把 Message Type 0x0005/0x0006 当属性（wire_fault 注入）",
			layers:  sChain(map[string]interface{}{"wire_fault": "attribute_length"}),
			anchor:  "attribute",
		},
		{
			id:      "sstp_neg_state_transition",
			summary: "越序：未 ACK 即 CONNECTED / 未 CONNECTED 即 PPP / ABORT 后续发",
			layers: sChain(eventsCfg(
				reqTx(), connectedTx(), pppTx("ipv4", 24, false),
			)),
			anchor: "state",
			notes:  []string{"自然配置通道（非注入）：状态机在 planner 同步面拒，任务 error 而非 0 包假成功。"},
		},
		{
			id:      "sstp_neg_transport_carrier",
			summary: "裸 TCP 载体缺 TLS（SSTP 只能经 TLS application-data 承载）",
			layers: []interface{}{ip4L(sCli, sSrv), tcpL(sSport, sPort),
				sstpL(eventsCfg(reqTx()))},
			anchor: "tls",
			notes:  []string{"预检在链补全前拦（DependsOn tls 会自动补 tls 层，不拦即被补全掩盖）。"},
		},
		{
			id:      "sstp_neg_ppp_framing",
			summary: "PPP framing 错：缺 address/control（ff 03）压缩形",
			layers: sChain(eventsCfg(
				reqTx(), ackTx(), connectedTx(),
				tx("ppp_data", map[string]interface{}{"direction": "c2s", "ppp": map[string]interface{}{
					"protocol": "ipv4", "framing": "none"}}),
			)),
			anchor: "framing",
			notes:  []string{"本版不产 address/control 压缩形 profile（契约 §7：显式声明才可用）。"},
		},
		{
			id:      "sstp_neg_tls_boundary",
			summary: "TLS record 截断/明文 SSTP 越过 TLS/跨连接拼接（wire_fault 注入）",
			layers:  sChain(map[string]interface{}{"wire_fault": "tls_boundary"}),
			anchor:  "tls",
		},
	}
}

// TestGenerateSSTPCases 生成 cases/sstp.json（一次性，P5；跑法：
//
//	go test ./internal/protocol/sstp/ -run TestGenerateSSTPCases -count=1
//
// 生成物入库（用例文件是测试产物，回指 TEST_CASES.md 编号）。
func TestGenerateSSTPCases(t *testing.T) {
	out := make([]map[string]interface{}, 0, 20)
	add := func(id, summary string, layers []interface{}, fc *int, expect map[string]interface{}) {
		c := map[string]interface{}{
			"id":        id,
			"proto":     "sstp",
			"summary":   summary,
			"spec_json": map[string]interface{}{"layers": layers},
		}
		if fc != nil {
			c["strategy_fc"] = map[string]interface{}{"type": "flows", "value": *fc}
		}
		c["expect"] = expect
		out = append(out, c)
	}

	for _, pc := range sstpPosCases() {
		expect := map[string]interface{}{}
		if pc.packetCount > 0 {
			expect["packet_count"] = pc.packetCount
		}
		if pc.minPackets > 0 {
			expect["min_packets"] = pc.minPackets
		}
		if pc.handshake {
			expect["has_handshake"] = true
		}
		if pc.terminates {
			expect["terminates"] = true
		}
		if pc.directional {
			expect["directional"] = true
		}
		if len(pc.fields) > 0 {
			fs := make([]map[string]interface{}, len(pc.fields))
			for i, f := range pc.fields {
				fs[i] = f.m()
			}
			expect["fields"] = fs
		}
		if len(pc.frames) > 0 {
			fs := make([]map[string]interface{}, len(pc.frames))
			for i, f := range pc.frames {
				fs[i] = f.m()
			}
			expect["frames"] = fs
		}
		if len(pc.notes) > 0 {
			expect["notes"] = pc.notes
		}
		add(pc.id, pc.summary, pc.layers, pc.fc, expect)
	}
	for _, nc := range sstpNegCases() {
		expect := map[string]interface{}{
			"expect_error":    true,
			"error_contains":  nc.anchor,
		}
		if len(nc.notes) > 0 {
			expect["notes"] = nc.notes
		}
		add(nc.id, nc.summary, nc.layers, nil, expect)
	}

	if len(out) != 20 {
		t.Fatalf("want 20 cases (14 pos + 6 neg), got %d", len(out))
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal cases: %v", err)
	}
	path := filepath.Join("..", "..", "..", "test", "protocol_pcap", "cases", "sstp.json")
	if _, err := os.Stat(path); err == nil {
		// 允许覆盖：生成器是权威（先跑后钉后重跑覆盖校准值）。
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s (%d cases)\n", path, len(out))
}
