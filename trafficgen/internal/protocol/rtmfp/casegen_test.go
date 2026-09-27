package rtmfp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// 用例生成器（一次性，D-RTMFP-1 P4/P5）：按契约 §9 权威序产出 29 例
// （16 正 + 9 负 + 4 链级红例），落 test/protocol_pcap/cases/rtmfp.json。
//
// 证据红线（契约 §1/§4/§9）：tshark 3.6.14 **无 RTMFP dissector**
//（`tshark -G fields | grep -ci rtmfp` = 0 实测），不存在 rtmfp.* 字段面。
// 断言只用三通道：
//  ①载体字段 udp.dstport/udp.srcport（方向交换）+ ipv6.nxt（IPv6 例）；
//  ②frames hex（UDP payload 内的 16B 自建头 + payload 逐字节，offset
//    42=IPv4 / 62=IPv6 起可复算）；
//  ③包数（事件数 = datagram 数，契约 §2）。
// 绝不写 rtmfp.* 字段断言。
//
// 帧内偏移：Ethernet 14 + IPv4 20 + UDP 8 = 42；IPv6 外层 14+40+8 = 62。
//
// 跑法：go test ./internal/protocol/rtmfp/ -run TestGenerateRTMFPCases -count=1
const (
	rOffV4 = 42
	rOffV6 = 62
)

type rfld struct {
	Packet int
	Field  string
	Value  string
}

func (f rfld) m() map[string]interface{} {
	return map[string]interface{}{"packet": f.Packet, "field": f.Field, "value": f.Value}
}

type rframe struct {
	Packet int
	Offset int
	Hex    string
}

func (f rframe) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "hex": f.Hex}
	if f.Offset != 0 {
		m["offset"] = f.Offset
	}
	return m
}

type rpos struct {
	id          string
	summary     string
	layers      []interface{}
	fields      []rfld
	frames      []rframe
	notes       []string
	packetCount int
}

type rneg struct {
	id      string
	summary string
	layers  []interface{}
	anchor  string
	notes   []string
	// top 是负例需要的额外顶层键（presence/游离键红例），键名与值原样落
	// spec_json（层链形状默认只有 layers）。
	top map[string]interface{}
}

// ---- 层链快捷构造（契约 §12.1 目标形状：地址只住 ip、端口只住 udp、
// 业务键住 rtmfp 层条目、数量走 flow_control）----

func ipL(src, dst string) map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": src, "dst": dst}}
}
func udpL(sp, dp int) map[string]interface{} {
	return map[string]interface{}{"udp": map[string]interface{}{"src_port": sp, "dst_port": dp}}
}
func rtmfpL(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"rtmfp": cfg}
}

// ---- 事件快捷构造 ----

func ev(kind, dir string) map[string]interface{} {
	return map[string]interface{}{"kind": kind, "direction": dir}
}
func evf(kind, dir string, extra map[string]interface{}) map[string]interface{} {
	m := ev(kind, dir)
	for k, v := range extra {
		m[k] = v
	}
	return m
}
func sess(sid int, events ...map[string]interface{}) map[string]interface{} {
	arr := make([]interface{}, len(events))
	for i, e := range events {
		arr[i] = e
	}
	return map[string]interface{}{"session_id": sid, "events": arr}
}
func sessPort(sid, sp int, events ...map[string]interface{}) map[string]interface{} {
	m := sess(sid, events...)
	m["src_port"] = sp
	return m
}
func sessions(list ...map[string]interface{}) map[string]interface{} {
	arr := make([]interface{}, len(list))
	for i, s := range list {
		arr[i] = s
	}
	return map[string]interface{}{"sessions": arr}
}
func frag(idx, count, total int, payload string) map[string]interface{} {
	return map[string]interface{}{"index": idx, "count": count, "total_length": total, "payload": payload}
}

// base 是每条正例共用的基线（profile/role 声明面）。
func base(sessCfg map[string]interface{}) map[string]interface{} {
	cfg := map[string]interface{}{"profile": "rtmfp_baseline", "role": "initiator"}
	for k, v := range sessCfg {
		cfg[k] = v
	}
	return cfg
}

// udpFields 由会话/事件序推导方向交换的 UDP 端口断言（c2s: dst=1935；
// s2c: src=1935），与 planner.go:106-116 的端口交换语义一一对应。
func udpFields(sport, dport int, sessionsCfg []interface{}) []rfld {
	var out []rfld
	pkt := 0
	for _, si := range sessionsCfg {
		s := si.(map[string]interface{})
		sp := sport
		if v, ok := s["src_port"].(int); ok {
			sp = v
		}
		for _, ei := range s["events"].([]interface{}) {
			e := ei.(map[string]interface{})
			pkt++
			if e["direction"] == "c2s" {
				out = append(out, rfld{pkt, "udp.dstport", fmt.Sprint(dport)})
				out = append(out, rfld{pkt, "udp.srcport", fmt.Sprint(sp)})
			} else {
				out = append(out, rfld{pkt, "udp.srcport", fmt.Sprint(dport)})
				out = append(out, rfld{pkt, "udp.dstport", fmt.Sprint(sp)})
			}
		}
	}
	return out
}

// hexFrame 拼装一帧的期望 hex（16B 头 + payload 字节，逐字节复算
// builder.go:89-103 的大端布局）。
func hexFrame(kind byte, sid, flow, seq uint32, payload ...byte) string {
	marker := byte(0x0e)
	switch kind {
	case 0x05, 0x06, 0x07, 0x0b, 0x0c:
		marker = 0x0c
	}
	total := 16 + len(payload)
	b := []byte{marker, kind, byte(total >> 8), byte(total), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b[4], b[5], b[6], b[7] = byte(sid>>24), byte(sid>>16), byte(sid>>8), byte(sid)
	b[8], b[9], b[10], b[11] = byte(flow>>24), byte(flow>>16), byte(flow>>8), byte(flow)
	b[12], b[13], b[14], b[15] = byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq)
	b = append(b, payload...)
	out := ""
	for i, v := range b {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%02x", v)
	}
	return out
}

// u32b / strb / cookie8 是 payload 片段构造器。
func u32b(v uint32) []byte  { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
func u16b(v uint16) []byte  { return []byte{byte(v >> 8), byte(v)} }
func strb(s string) []byte  { return []byte(s) }
func cookie8(sid uint32) []byte {
	return append(u32b(sid), u32b(sid^0xDEADBEEF)...)
}

// ---- 正例定义（契约 §9 权威序 #1–#15 + T-27 IPv6 对偶）----

func rtmfpPosCases() []rpos {
	const (
		cli   = "192.0.2.10"
		srv   = "198.51.100.20"
		cli6  = "2001:db8:48::10"
		srv6  = "2001:db8:48::20"
		sport = 40000
		dport = 1935
	)
	// 每条正例的层链：ip(地址) + udp(端口) + rtmfp(业务)。
	chain := func(cfg map[string]interface{}, sp int) []interface{} {
		return []interface{}{ipL(cli, srv), udpL(sp, dport), rtmfpL(cfg)}
	}
	chain6 := func(cfg map[string]interface{}, sp int) []interface{} {
		return []interface{}{ipL(cli6, srv6), udpL(sp, dport), rtmfpL(cfg)}
	}
	sessArr := func(s map[string]interface{}) []interface{} { return []interface{}{s} }

	// ①hello/hello_ack/cookie/session_confirm
	c1 := sess(1,
		ev("hello", "c2s"), ev("hello_ack", "s2c"), ev("cookie", "s2c"), ev("session_confirm", "c2s"))
	// ②IPv6 三事件握手
	c2 := sess(2, ev("hello", "c2s"), ev("hello_ack", "s2c"), ev("session_confirm", "c2s"))
	// ③reliable + ack
	c3 := sess(3, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "fixture"}),
		evf("ack", "s2c", map[string]interface{}{"flow_id": 1, "sequence": 1}))
	// ④unreliable
	c4 := sess(4, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("unreliable", "c2s", map[string]interface{}{"flow_id": 2, "message": "datagram"}))
	// ⑤retransmit 复用 seq=7
	c5 := sess(5, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 7, "message": "retry"}),
		evf("retransmit", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 7, "message": "retry"}),
		evf("ack", "s2c", map[string]interface{}{"flow_id": 1, "sequence": 7}))
	// ⑥三片分片
	c6 := sess(6, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("fragment", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 8, "fragment": frag(0, 3, 9, "abc")}),
		evf("fragment", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 8, "fragment": frag(1, 3, 9, "def")}),
		evf("fragment", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 8, "fragment": frag(2, 3, 9, "ghi")}))
	// ⑦ping/pong
	c7 := sess(7, ev("hello", "c2s"), ev("hello_ack", "s2c"), ev("ping", "c2s"), ev("pong", "s2c"))
	// ⑧close
	c8 := sess(8, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "last"}),
		ev("close", "c2s"))
	// ⑨多流 flow 1/2/3
	c9 := sess(9, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "audio"}),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 2, "sequence": 1, "message": "video"}),
		evf("unreliable", "c2s", map[string]interface{}{"flow_id": 3, "message": "metadata"}))
	// ⑩双会话（事件级 src_port 覆盖）
	c10a := sessPort(10, 40009, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "a"}))
	c10b := sessPort(11, 40010, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "b"}))
	// ⑪丢包 fixture + 双 range ACK + 重传
	c11 := sess(12, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "one"}),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 3, "message": "three"}),
		evf("ack", "s2c", map[string]interface{}{"flow_id": 1, "ranges": []interface{}{[]interface{}{1, 1}, []interface{}{3, 3}}}),
		evf("retransmit", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 2, "message": "two"}))
	// ⑫binary payload
	c12 := sess(13, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message_b64": "UkZN"}))
	// ⑬low_latency profile
	c13 := sess(14, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("unreliable", "c2s", map[string]interface{}{"flow_id": 1, "message": "low-latency"}))
	// ⑭IPv4 单 fixture（名义双地址族之 IPv4 半边）
	c14 := sess(15, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "same"}))
	// T-27：IPv6 对偶 fixture（同逻辑 payload "same"，独立 session/端口）
	c27 := sess(16, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "same"}))
	// ⑮有界保活（2 轮 ping/pong + close）
	c15 := sess(17, ev("hello", "c2s"), ev("hello_ack", "s2c"),
		ev("ping", "c2s"), ev("pong", "s2c"), ev("ping", "c2s"), ev("pong", "s2c"), ev("close", "c2s"))

	noFields := []string{"证据红线：tshark 3.6.14 无 RTMFP dissector（rtmfp.* 0 字段实测），不使用 rtmfp.* 字段断言；内层字节由 frames hex 钉。"}

	return []rpos{
		{
			id: "rtmfp_handshake_ipv4", summary: "RTMFP IPv4 UDP handshake and session establishment",
			layers: chain(base(sessions(c1)), sport),
			fields: udpFields(sport, dport, sessArr(c1)),
			frames: []rframe{
				{1, rOffV4, hexFrame(0x01, 1, 0, 0)},
				{2, rOffV4, hexFrame(0x02, 1, 0, 0)},
				// cookie 为确定性派生 8 字节：sessionID ‖ sessionID^0xDEADBEEF
				{3, rOffV4, hexFrame(0x03, 1, 0, 0, cookie8(1)...)},
				{4, rOffV4, hexFrame(0x04, 1, 0, 0)},
			},
			packetCount: 4,
			notes: append([]string{
				"cookie 派生可复算（builder.go:80-85）：sid=1 → 00 00 00 01 de ad be ee，无随机值。",
				"UDP 方向交换：c2s dst=1935 / s2c src=1935（planner.go:106-116）。",
			}, noFields...),
		},
		{
			id: "rtmfp_handshake_ipv6", summary: "RTMFP IPv6 UDP handshake",
			layers: chain6(base(sessions(c2)), 40001),
			fields: append(udpFields(40001, dport, sessArr(c2)),
				rfld{1, "ipv6.nxt", "17"}),
			frames: []rframe{
				{1, rOffV6, hexFrame(0x01, 2, 0, 0)},
				{2, rOffV6, hexFrame(0x02, 2, 0, 0)},
				{3, rOffV6, hexFrame(0x04, 2, 0, 0)},
			},
			packetCount: 3,
			notes: append([]string{
				"IPv6 外层：payload offset 62（14+40+8），ipv6.nxt=17（UDP）。",
				"IPv6 地址不写入应用 cookie（cookie 只含 sessionID 派生值）。",
			}, noFields...),
		},
		{
			id: "rtmfp_reliable_flow", summary: "RTMFP reliable flow with ACK",
			layers: chain(base(sessions(c3)), 40002),
			fields: udpFields(40002, dport, sessArr(c3)),
			frames: []rframe{
				{3, rOffV4, hexFrame(0x05, 3, 1, 1, strb("fixture")...)},
				// ack：ranges_count=0（本例不声明 ranges），marker 0x0E/kind 0x08
				{4, rOffV4, hexFrame(0x08, 3, 1, 1, u16b(0)...)},
			},
			packetCount: 4,
			notes: append([]string{
				"reliable marker=0x0C/kind=0x05/seq=1；ack marker=0x0E/kind=0x08，前缀 ranges_count(2B)。",
			}, noFields...),
		},
		{
			id: "rtmfp_unreliable_flow", summary: "RTMFP unreliable flow without implicit retransmission",
			layers: chain(base(sessions(c4)), 40003),
			fields: udpFields(40003, dport, sessArr(c4)),
			frames: []rframe{
				// unreliable：marker 0x0C/kind 0x06/sequence 恒 0（builder.go:145-149）
				{3, rOffV4, hexFrame(0x06, 4, 2, 0, strb("datagram")...)},
			},
			packetCount: 3,
			notes: append([]string{
				"unreliable sequence 恒 0（不占 reliable 序号）；未配置 retransmit 时不增包。",
			}, noFields...),
		},
		{
			id: "rtmfp_retransmission", summary: "RTMFP reliable retransmission keeps sequence",
			layers: chain(base(sessions(c5)), 40004),
			fields: udpFields(40004, dport, sessArr(c5)),
			frames: []rframe{
				{3, rOffV4, hexFrame(0x05, 5, 1, 7, strb("retry")...)},
				// 重传 = 既有 sequence 的重发：包 4 字节与包 3 完全相同
				{4, rOffV4, hexFrame(0x05, 5, 1, 7, strb("retry")...)},
			},
			packetCount: 5,
			notes: append([]string{
				"retransmit 是 kind 别名映射（planner.go:44-48）：线上字节与 reliable 原包逐字节相同，序号不递进。",
			}, noFields...),
		},
		{
			id: "rtmfp_fragment_reassembly", summary: "RTMFP three-fragment message reassembly",
			layers: chain(base(sessions(c6)), 40005),
			fields: udpFields(40005, dport, sessArr(c6)),
			frames: []rframe{
				// payload 前缀 idx(4)+count(4)+totalLen(4)+data（builder.go:153-162）
				{3, rOffV4, hexFrame(0x07, 6, 1, 8, append(append(append(u32b(0), u32b(3)...), u32b(9)...), strb("abc")...)...)},
				{4, rOffV4, hexFrame(0x07, 6, 1, 8, append(append(append(u32b(1), u32b(3)...), u32b(9)...), strb("def")...)...)},
				{5, rOffV4, hexFrame(0x07, 6, 1, 8, append(append(append(u32b(2), u32b(3)...), u32b(9)...), strb("ghi")...)...)},
			},
			packetCount: 5,
			notes: append([]string{
				"三片同 session/flow/sequence=8，index 0..2 递进、count=3、total_length=9。",
				"UDP packet index 不替代 fragment index（分片语义住 payload 前缀）。",
			}, noFields...),
		},
		{
			id: "rtmfp_ping_pong", summary: "RTMFP explicit ping pong keepalive",
			layers: chain(base(sessions(c7)), 40006),
			fields: udpFields(40006, dport, sessArr(c7)),
			frames: []rframe{
				{3, rOffV4, hexFrame(0x09, 7, 0, 0)},
				{4, rOffV4, hexFrame(0x0a, 7, 0, 0)},
			},
			packetCount: 4,
			notes: append([]string{
				"ping/pong 为显式事件（kind 0x09/0x0A，同 session 关联）；未配置 interval 不自动插周期 ping。",
			}, noFields...),
		},
		{
			id: "rtmfp_close", summary: "RTMFP close lifecycle",
			layers: chain(base(sessions(c8)), 40007),
			fields: udpFields(40007, dport, sessArr(c8)),
			frames: []rframe{
				{3, rOffV4, hexFrame(0x05, 8, 1, 1, strb("last")...)},
				{4, rOffV4, hexFrame(0x0b, 8, 0, 0)},
			},
			packetCount: 4,
			notes: append([]string{
				"close marker=0x0C/kind=0x0B；close 后残留事件由校验器拒（planner.go:204-206），本流止于 close。",
			}, noFields...),
		},
		{
			id: "rtmfp_multi_flow", summary: "RTMFP multiple isolated flows",
			layers: chain(base(sessions(c9)), 40008),
			fields: udpFields(40008, dport, sessArr(c9)),
			frames: []rframe{
				// flow_id 住头偏移 8..11，逐流独立
				{3, rOffV4, hexFrame(0x05, 9, 1, 1, strb("audio")...)},
				{4, rOffV4, hexFrame(0x05, 9, 2, 1, strb("video")...)},
				{5, rOffV4, hexFrame(0x06, 9, 3, 0, strb("metadata")...)},
			},
			packetCount: 5,
			notes: append([]string{
				"同会话 flow 1/2/3 交织（音/视/元数据），flow_id 独立且 sequence 互不影响。",
				"不按全局 packet index 假定跨流顺序（事件序顺序回放，断言逐包钉）。",
			}, noFields...),
		},
		{
			id: "rtmfp_multi_session", summary: "RTMFP isolated sessions on distinct ports",
			layers: chain(base(sessions(c10a, c10b)), 40009),
			fields: udpFields(40009, dport, []interface{}{c10a, c10b}),
			frames: []rframe{
				{1, rOffV4, hexFrame(0x01, 10, 0, 0)},
				{4, rOffV4, hexFrame(0x01, 11, 0, 0)},
				{6, rOffV4, hexFrame(0x05, 11, 1, 1, strb("b")...)},
			},
			packetCount: 6,
			notes: append([]string{
				"双会话 src_port 40009/40010（sessions[].src_port 事件级覆盖，planner.go:114-116）；session/flow/序号状态隔离。",
			}, noFields...),
		},
		{
			id: "rtmfp_loss_and_ack_ranges", summary: "RTMFP loss fixture and ACK range",
			layers: chain(base(sessions(c11)), 40011),
			fields: udpFields(40011, dport, sessArr(c11)),
			frames: []rframe{
				{3, rOffV4, hexFrame(0x05, 12, 1, 1, strb("one")...)},
				{4, rOffV4, hexFrame(0x05, 12, 1, 3, strb("three")...)},
				// ack：ranges_count=2 + [[1,1],[3,3]]（builder.go:166-176）
				{5, rOffV4, hexFrame(0x08, 12, 1, 0, append(append(append(append(u16b(2), u32b(1)...), u32b(1)...), u32b(3)...), u32b(3)...)...)},
				{6, rOffV4, hexFrame(0x05, 12, 1, 2, strb("two")...)},
			},
			packetCount: 6,
			notes: append([]string{
				"显式 fixture 丢 sequence=2：ACK ranges [[1,1],[3,3]] 只确认已接收序号；重传 2 复用原序号。",
				"合法丢包/重传是协议正例语义，不是 planner error。",
			}, noFields...),
		},
		{
			id: "rtmfp_binary_payload", summary: "RTMFP deterministic binary payload",
			layers: chain(base(sessions(c12)), 40012),
			fields: udpFields(40012, dport, sessArr(c12)),
			frames: []rframe{
				// message_b64 "UkZN" → bytes 52 46 4d（不把 base64 文本发上线）
				{3, rOffV4, hexFrame(0x05, 13, 1, 1, 0x52, 0x46, 0x4d)},
			},
			packetCount: 3,
			notes: append([]string{
				"message_b64 优先于 message（builder.go:66-77）：线上为解码字节，total_len=19（16+3）。",
			}, noFields...),
		},
		{
			id: "rtmfp_low_latency_profile", summary: "RTMFP explicit low latency profile",
			layers: chain(base(sessions(c13)), 40013),
			fields: udpFields(40013, dport, sessArr(c13)),
			frames: []rframe{
				{3, rOffV4, hexFrame(0x06, 14, 1, 0, strb("low-latency")...)},
			},
			packetCount: 3,
			notes: append([]string{
				"诚实注记（G-RTMFP-5）：profile 当前仅白名单校验、不消费线字节（两 profile 线上字节相同）——本例只断声明被接受，不冒充差异；负对照见 rtmfp_neg_profile_carrier。",
			}, noFields...),
		},
		{
			id: "rtmfp_ipv4_ipv6_same_payload", summary: "RTMFP same logical payload across address families",
			layers: chain(base(sessions(c14)), 40014),
			fields: udpFields(40014, dport, sessArr(c14)),
			frames: []rframe{
				{3, rOffV4, hexFrame(0x05, 15, 1, 1, strb("same")...)},
			},
			packetCount: 3,
			notes: append([]string{
				"本例为双地址族之 IPv4 半边；IPv6 对偶见 rtmfp_ipv6_same_payload（T-27，G-RTMFP-4 勘误补齐）。",
				"两 fixture 是两条独立策略/任务，session/flow 状态不互串（契约 §7）。",
			}, noFields...),
		},
		{
			id: "rtmfp_ipv6_same_payload", summary: "RTMFP same logical payload over IPv6 (dual of rtmfp_ipv4_ipv6_same_payload)",
			layers: chain6(base(sessions(c27)), 40016),
			fields: append(udpFields(40016, dport, sessArr(c27)),
				rfld{3, "ipv6.nxt", "17"}),
			frames: []rframe{
				{1, rOffV6, hexFrame(0x01, 16, 0, 0)},
				{3, rOffV6, hexFrame(0x05, 16, 1, 1, strb("same")...)},
			},
			packetCount: 3,
			notes: append([]string{
				"T-27（G-RTMFP-4）：#14 名义双地址族的 IPv6 对偶 fixture——同逻辑 payload \"same\" 在 IPv6 载体上逐字节可复算，地址族只换外层 ip 层。",
			}, noFields...),
		},
		{
			id: "rtmfp_keepalive_bounded", summary: "RTMFP bounded keepalive and close",
			layers: chain(func() map[string]interface{} {
				c := base(sessions(c15))
				// G-RTMFP-5 死配置注记：两键当前零消费（types 声明，planner/builder
				// 不读）——保留以证明声明面被接受，有界性由显式事件数保证。
				c["keepalive_interval"] = 5
				c["ping_count"] = 2
				return c
			}(), 40015),
			fields: udpFields(40015, dport, sessArr(c15)),
			frames: []rframe{
				{3, rOffV4, hexFrame(0x09, 17, 0, 0)},
				{4, rOffV4, hexFrame(0x0a, 17, 0, 0)},
				{7, rOffV4, hexFrame(0x0b, 17, 0, 0)},
			},
			packetCount: 7,
			notes: append([]string{
				"2 轮 ping/pong + close 共 7 包；保活数量=事件数（有界由显式事件保证，不依赖 wall-clock）。",
				"G-RTMFP-5 注记：keepalive_interval/ping_count 声明但零消费（周期自动保活明确不支持）。",
			}, noFields...),
		},
	}
}

// ---- 负例定义（契约 §9 #16–#24 + §12-P2 四链级红例）----

func rtmfpNegCases() []rneg {
	const (
		cli   = "192.0.2.10"
		srv   = "198.51.100.20"
		sport = 40016
		dport = 1935
	)
	// negChain 是负例的层链：地址/端口住层，业务键（wire_fault 等）住 rtmfp 层。
	negChain := func(cfg map[string]interface{}, sp int) []interface{} {
		return []interface{}{ipL(cli, srv), udpL(sp, dport), rtmfpL(cfg)}
	}
	fault := func(kind string, extra map[string]interface{}) map[string]interface{} {
		f := map[string]interface{}{"kind": kind}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	return []rneg{
		{
			id: "rtmfp_neg_short_header", summary: "Reject RTMFP short header",
			layers: negChain(map[string]interface{}{
				"profile": "rtmfp_baseline", "wire_fault": fault("short_header", nil),
				"sessions": []interface{}{sess(18, ev("hello", "c2s"))},
			}, sport),
			anchor: "header",
			notes:  []string{"锚词对 planner.go:287「header too short」。"},
		},
		{
			id: "rtmfp_neg_length_overrun", summary: "Reject RTMFP message length overrun",
			layers: negChain(map[string]interface{}{
				"profile": "rtmfp_baseline",
				"wire_fault": fault("bad_length", map[string]interface{}{"declared": 999, "actual": 2}),
				"sessions":   []interface{}{sess(19, ev("hello", "c2s"))},
			}, 40017),
			anchor: "length",
			notes:  []string{"锚词对 planner.go:289「length overruns payload」。"},
		},
		{
			id: "rtmfp_neg_cookie_session", summary: "Reject cookie and session mismatch",
			layers: negChain(map[string]interface{}{
				"profile": "rtmfp_baseline", "wire_fault": fault("session_mismatch", nil),
				"sessions": []interface{}{sess(20, ev("hello", "c2s"),
					evf("hello_ack", "s2c", map[string]interface{}{"session_id": 21}))},
			}, 40018),
			anchor: "session",
			notes:  []string{"锚词对 planner.go:291「session mismatch」；事件级 session_id override 面。"},
		},
		{
			id: "rtmfp_neg_sequence_regress", summary: "Reject reliable sequence regression",
			layers: negChain(map[string]interface{}{
				"profile": "rtmfp_baseline", "wire_fault": fault("sequence_regress", nil),
				"sessions": []interface{}{sess(21, ev("hello", "c2s"), ev("hello_ack", "s2c"),
					evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 2, "message": "two"}),
					evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "one"}))},
			}, 40019),
			anchor: "sequence",
			notes:  []string{"锚词对 planner.go:293 + 自然守卫 :223-225（序号回退）。"},
		},
		{
			id: "rtmfp_neg_fragment_gap", summary: "Reject missing RTMFP fragment",
			layers: negChain(map[string]interface{}{
				"profile": "rtmfp_baseline", "wire_fault": fault("fragment_gap", nil),
				"sessions": []interface{}{sess(22, ev("hello", "c2s"), ev("hello_ack", "s2c"),
					evf("fragment", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "fragment": frag(0, 3, 9, "abc")}),
					evf("fragment", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "fragment": frag(2, 3, 9, "ghi")}))},
			}, 40020),
			anchor: "fragment",
			notes:  []string{"锚词对 planner.go:295 + 自然守卫 :256-258（index ≥ count 拒）。"},
		},
		{
			id: "rtmfp_neg_ack_unknown", summary: "Reject ACK for unknown sequence",
			layers: negChain(map[string]interface{}{
				"profile": "rtmfp_baseline", "wire_fault": fault("ack_unknown", nil),
				"sessions": []interface{}{sess(23, ev("hello", "c2s"), ev("hello_ack", "s2c"),
					evf("ack", "s2c", map[string]interface{}{"flow_id": 1, "sequence": 99}))},
			}, 40021),
			anchor: "ack",
			notes:  []string{"锚词对 planner.go:297 + 自然守卫 :244-246（ACK 未发送序号）。"},
		},
		{
			id: "rtmfp_neg_state_order", summary: "Reject RTMFP state order violation",
			layers: negChain(map[string]interface{}{
				"profile": "rtmfp_baseline", "wire_fault": fault("state_order", nil),
				"sessions": []interface{}{sess(24,
					evf("reliable", "c2s", map[string]interface{}{"flow_id": 1, "sequence": 1, "message": "before hello"}),
					ev("close", "c2s"), ev("hello", "c2s"))},
			}, 40022),
			anchor: "state",
			notes:  []string{"锚词对 planner.go:299 + 自然守卫 :204-218（未握手先数据/close 后残留双保险）。"},
		},
		{
			id: "rtmfp_neg_profile_carrier", summary: "Reject invalid RTMFP profile or carrier",
			layers: negChain(map[string]interface{}{
				"profile": "unknown_profile", "role": "invalid",
				"sessions": []interface{}{sess(25, ev("hello", "c2s"))},
			}, 40023),
			anchor: "profile",
			notes:  []string{"自然守卫（非 wire_fault）：planner.go:150-157「unknown profile / unknown role」。"},
		},
		{
			id: "rtmfp_neg_session_leak", summary: "Reject cross-session flow state reference",
			layers: negChain(map[string]interface{}{
				"profile": "rtmfp_baseline", "wire_fault": fault("session_leak", nil),
				"sessions": []interface{}{
					sess(26, ev("hello", "c2s"), ev("hello_ack", "s2c")),
					sess(27, evf("reliable", "c2s", map[string]interface{}{
						"flow_id": 1, "session_id": 26, "sequence": 1, "message": "leaked"})),
				},
			}, 40024),
			anchor: "session",
			notes:  []string{"锚词对 planner.go:301 + 自然守卫 :264-275（跨 session 引用不存在 session）。"},
		},
		// ---- §12-P2 四链级红例 ----
		{
			id: "rtmfp_neg_top_rtmfp_presence_reject",
			summary: "§12-P2 presence 判死形状：层链 + 顶层空 rtmfp 子映射并存",
			layers: []interface{}{ipL(cli, srv), udpL(sport, dport), rtmfpL(map[string]interface{}{})},
			top:    map[string]interface{}{"rtmfp": map[string]interface{}{}},
			anchor: "no longer accepts a top-level rtmfp sub-config",
			notes:  []string{"判死形状（非残留）：层链与顶层空子映射并存即拒（CheckProtoFlat rtmfp 分支）。"},
		},
		{
			id: "rtmfp_neg_stray_src_ip", summary: "§12-P2 白名单外游离顶层键判死：layers + src_ip",
			layers: []interface{}{ipL(cli, srv), udpL(sport, dport), rtmfpL(map[string]interface{}{})},
			top:    map[string]interface{}{"src_ip": "192.0.2.99"},
			anchor: "no longer accepts flat config field src_ip",
			notes:  []string{"1.11–1.13 白名单制：非负例顶层键=0（仅 layers/flow_control/output）。"},
		},
		{
			id: "rtmfp_neg_carrier_tcp", summary: "§12-P2 tcp 载体判死：RTMFP 仅 UDP（carrier）",
			layers: []interface{}{ipL(cli, srv),
				map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40025, "dst_port": dport}},
				rtmfpL(map[string]interface{}{})},
			anchor: "carrier",
			notes:  []string{"registry TransportOn=[udp] → transport-dup 检查报 carrier 锚词（bacnet 同构）。"},
		},
		{
			id: "rtmfp_neg_carrier_missing_udp", summary: "§12-P2 缺 udp 载体判死：[ip,rtmfp] 直连",
			layers: []interface{}{ipL(cli, srv), rtmfpL(map[string]interface{}{})},
			anchor: "carrier",
			notes:  []string{"预检在链补全前拦（DependsOn udp 会自动补 udp 层，不拦即被补全掩盖）。"},
		},
	}
}

// TestGenerateRTMFPCases 生成 cases/rtmfp.json（一次性，P4/P5；跑法：
//
//	go test ./internal/protocol/rtmfp/ -run TestGenerateRTMFPCases -count=1
//
// 生成物入库（用例文件是测试产物，回指 48-rtmfp-testcase.md）。
func TestGenerateRTMFPCases(t *testing.T) {
	pos := rtmfpPosCases()
	neg := rtmfpNegCases()
	out := make([]map[string]interface{}, 0, len(pos)+len(neg))
	add := func(id, summary string, layers []interface{}, top map[string]interface{}, expect map[string]interface{}) {
		sj := map[string]interface{}{"layers": layers}
		for k, v := range top {
			sj[k] = v
		}
		out = append(out, map[string]interface{}{
			"id":        id,
			"proto":     "rtmfp",
			"summary":   summary,
			"spec_json": sj,
			"expect":    expect,
		})
	}
	for _, pc := range pos {
		expect := map[string]interface{}{}
		if pc.packetCount > 0 {
			expect["packet_count"] = pc.packetCount
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
		add(pc.id, pc.summary, pc.layers, nil, expect)
	}
	for _, nc := range neg {
		// 负例 expect 严格只有 expect_error/error_contains（testcase §1）；
		// nc.notes 只作文档留痕，不进机器契约。
		expect := map[string]interface{}{
			"expect_error":   true,
			"error_contains": nc.anchor,
		}
		add(nc.id, nc.summary, nc.layers, nc.top, expect)
	}

	if len(out) != 29 {
		t.Fatalf("want 29 cases (16 pos + 13 neg), got %d", len(out))
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal cases: %v", err)
	}
	path := filepath.Join("..", "..", "..", "test", "protocol_pcap", "cases", "rtmfp.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s (%d cases: %d pos + %d neg)\n", path, len(out), len(pos), len(neg))
}
