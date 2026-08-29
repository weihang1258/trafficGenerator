package pcaptest

import (
	"os"
	"strings"
	"testing"
)

// pcaptest 共享包的 spec 派生自测。这里的断言与 test/protocol_pcap（薄转发
// 层）共用同一套 tshark/hex 逻辑，但本文件直接在共享包内调用，保证 MCP 工具
// 与 go test 两侧共享的底层在搬家/重构后永久有回归锚点，不依赖对端封装。
//
// 依赖真实 pcap 的用例在缺文件时 Skip（/tmp/mcp-pcaps 为临时目录，清理后
// 由 TestProtocolPcapDrive 对新建 pcap 重跑）。

const pcapRoot = "/tmp/mcp-pcaps"

func requirePcap(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("pcap not present (ephemeral tree cleaned): %s", path)
	}
}

func TestPacketCount(t *testing.T) {
	cases := []struct {
		path string
		want int
	}{
		{pcapRoot + "/tftp/tftp-rrq-short-aa100.pcap", 3},
		{pcapRoot + "/tcp/tcp-handshake-basic.pcap", 7},
	}
	for _, c := range cases {
		requirePcap(t, c.path)
		n, err := PacketCount(c.path)
		if err != nil {
			t.Fatalf("PacketCount(%s): %v", c.path, err)
		}
		if n != c.want {
			t.Errorf("PacketCount(%s) = %d, want %d", c.path, n, c.want)
		}
	}
	// 缺文件必须报错而非静默 0。
	if n, err := PacketCount("/nonexistent.pcap"); err == nil {
		t.Errorf("PacketCount(missing) = %d, want error", n)
	}
}

func TestFieldValues_EmptyLinePreservation(t *testing.T) {
	// 不变量：FieldValues 每包一行，空包也必须返回占位空串——行索引 = 包索引。
	// VerifyPcap 的 packet 索引定位与同一字段的 SameAsPacket 持久性断言都
	// 依赖它；若用 strings.TrimSpace 剥掉首尾空行会移动全部索引。
	p := pcapRoot + "/tcp/tcp-handshake-basic.pcap"
	requirePcap(t, p)
	// 每包都有的字段：行数 == 包数。
	flags, err := FieldValues(p, "tcp.flags", nil)
	if err != nil {
		t.Fatalf("FieldValues: %v", err)
	}
	if len(flags) != 7 {
		t.Errorf("tcp.flags lines = %d, want 7 (== packet count)", len(flags))
	}
	// 全程缺失的字段（无重传）：每包一空行，行数仍 == 包数。
	rt, err := FieldValues(p, "tcp.analysis.retransmission", nil)
	if err != nil {
		t.Fatalf("FieldValues(absent): %v", err)
	}
	if len(rt) != 7 {
		t.Errorf("absent-field lines = %d, want 7 empty slots (line index must equal packet index)", len(rt))
	}
	for _, v := range rt {
		if v != "" {
			t.Errorf("absent-field line = %q, want empty", v)
		}
	}
	// 包 2 是 SYN+ACK（tshark 0x0012）：FLAG 子串与包索引一致。
	if !strings.Contains(flags[1], "0x0012") {
		t.Errorf("flags[1] = %q, want SYN+ACK (0x0012)", flags[1])
	}
}

func TestVerifyPcap_CleanPcapPasses(t *testing.T) {
	// 干净 tftp 流（3 包 RRQ/Data/ACK）在全检查下必须零问题：无 malformed、
	// 无 ILLEGAL checksum、计数与字段正确。
	p := pcapRoot + "/tftp/tftp-rrq-short-aa100.pcap"
	requirePcap(t, p)
	c := Case{
		ID:    "tftp-clean",
		Proto: "tftp",
		Expect: Expect{
			PacketCount: 3,
			Fields: []FieldAssert{
				{Packet: 1, Field: "udp.srcport", Value: "49152"},
				{Packet: 1, Field: "udp.dstport", Value: "69"},
				{Packet: 3, Field: "udp.srcport", Value: "49152"},
			},
			HasPayload: true, // data 包 frame.len > 80
		},
	}
	if probs := VerifyPcap(p, c); len(probs) != 0 {
		t.Fatalf("clean pcap failed: %v", probs)
	}
}

func TestVerifyPcap_TcpHandshakePaths(t *testing.T) {
	p := pcapRoot + "/tcp/tcp-handshake-basic.pcap"
	requirePcap(t, p)
	// 7 包握手：首包 SYN、包 2 SYN+ACK（negotiated）、末包 FIN（terminates）、
	// 双向 ip.src（directional）。全部打开必须通过。
	c := Case{
		ID: "tcp-handshake",
		Expect: Expect{
			PacketCount:  7,
			HasHandshake: true,
			Negotiated:   true,
			Terminates:   true,
			Directional:  true,
			Fields: []FieldAssert{
				{Packet: 2, Field: "tcp.flags", Value: "0x0012"}, // SYN+ACK
			},
		},
	}
	if probs := VerifyPcap(p, c); len(probs) != 0 {
		t.Fatalf("handshake paths failed: %v", probs)
	}
	// 负路径：该 pcap 无 frame.len > 80 的包，HasPayload 必须失败。
	c2 := Case{ID: "tcp-shortflow", Expect: Expect{HasPayload: true}}
	probs := VerifyPcap(p, c2)
	found := false
	for _, pr := range probs {
		if strings.Contains(pr, "has_payload") {
			found = true
		}
	}
	if !found {
		t.Errorf("HasPayload on short-flow pcap must fail, got %v", probs)
	}
	// 负路径：计数不匹配必须报告。
	c3 := Case{ID: "tcp-count", Expect: Expect{PacketCount: 99}}
	probs = VerifyPcap(p, c3)
	found = false
	for _, pr := range probs {
		if strings.Contains(pr, "count:") {
			found = true
		}
	}
	if !found {
		t.Errorf("wrong packet count must fail, got %v", probs)
	}
}

func TestCheckExpertInfo_CleanScan(t *testing.T) {
	// 独立深度审计：干净 pcap 无 malformed/ILLEGAL，任意 caseID 都不该报。
	p := pcapRoot + "/tftp/tftp-rrq-short-aa100.pcap"
	requirePcap(t, p)
	if probs := CheckExpertInfo(p, "tftp-clean", nil); len(probs) != 0 {
		t.Errorf("clean pcap expert scan flagged: %v", probs)
	}
}

func TestIsZeroValue(t *testing.T) {
	for _, v := range []string{"0", "0x0", "0x0000000000000000", "0000"} {
		if !IsZeroValue(v) {
			t.Errorf("IsZeroValue(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"1", "0x1", "0x0000000000000001", "", "0xdeadbeef"} {
		if IsZeroValue(v) {
			t.Errorf("IsZeroValue(%q) = true, want false", v)
		}
	}
}

func TestByteAtWantAt(t *testing.T) {
	b := []byte{0x10, 0x20, 0x30}
	if ByteAt(b, 0) != 0x10 || ByteAt(b, 2) != 0x30 {
		t.Error("ByteAt in-range access wrong")
	}
	for _, i := range []int{-1, 3, 100} {
		if ByteAt(b, i) != 0xff {
			t.Errorf("ByteAt(%d) out-of-range = %02x, want 0xff sentinel", i, ByteAt(b, i))
		}
	}
	if WantAt(b, 1) != 0x20 || WantAt(b, 9) != 0xff {
		t.Error("WantAt wrong")
	}
}

func TestTCPFlagBits_HasTCPFlag(t *testing.T) {
	// "0x0012"（SYN+ACK）必须同时置 SYN(0x002) 与 ACK(0x010) 位。
	bits, err := TCPFlagBits("0x0012")
	if err != nil {
		t.Fatalf("TCPFlagBits: %v", err)
	}
	want := uint16(0x002 | 0x010)
	if bits != want {
		t.Errorf("TCPFlagBits(0x0012) = 0x%04x, want 0x%04x", bits, want)
	}
	if !HasTCPFlag("0x0012", 0x002) || !HasTCPFlag("0x0012", 0x010) {
		t.Error("0x0012 must have SYN and ACK bits")
	}
	if HasTCPFlag("0x0012", 0x001) { // FIN 未置
		t.Error("0x0012 must not have FIN bit")
	}
	// 前后零对齐不改变语义："0x2" == "0x0002"。
	if n, _ := TCPFlagBits("0x2"); n&0x002 == 0 {
		t.Error("0x2 must parse as SYN")
	}
	// 非法值（非 hex）必须报错且 HasTCPFlag 返回 false。
	if _, err := TCPFlagBits("zz"); err == nil {
		t.Error("TCPFlagBits(zz) must error")
	}
	if HasTCPFlag("zz", 0x002) {
		t.Error("HasTCPFlag(zz) must be false")
	}
}

// TestHavePayload_ForCoAPChecksPayloadField: has_payload 的语义按 testcase
// 文档是"消息携带负载（由解码后负载长度驱动）"，而非"整帧超阈值"。CoAP 消息
// 负载小（如 14B），frame.len 常 < 80（63~67），旧实现用 frame.len>80 作代理
// 判断恒判"无负载"——这是误伤。CoAP 应检查 coap.payload_length 字段非零。
func TestHavePayload_ForCoAPChecksPayloadField(t *testing.T) {
	p := pcapRoot + "/coap/coap_con_get.pcap"
	requirePcap(t, p)
	c := Case{
		ID:     "coap_con_get",
		Proto:  "coap",
		Expect: Expect{HasPayload: true},
	}
	problems := VerifyPcap(p, c)
	for _, pr := range problems {
		if strings.Contains(pr, "has_payload") {
			t.Fatalf("coap has_payload false-failure (payload present but frame <80): %s", pr)
		}
	}
}

// TestHavePayload_ForIEC104ChecksAPDUPresence: IEC104 帧天然小（60~70B），
// frame.len 恒 < 80，旧实现用 frame.len>80 作代理判断恒判"无负载"。IEC104 的
// PDU（I/U/S 帧）由 iec60870_104.apdulen 标记：非空必有一个 IEC104 PDU 存在，
// 而纯 TCP 握手/挥手帧（apdulen 为空）不携带任何 IEC104 负载。设计 testcase
// 22-iec104-testcase.md 在 iec104_u_frames（纯 U 控制帧）也置 has_payload=true，
// 所以语义是"IEC104 PDU 存在"，非"ASDU 数据帧存在"。
func TestHavePayload_ForIEC104ChecksAPDUPresence(t *testing.T) {
	p := pcapRoot + "/iec104/iec104_u_frames.pcap"
	requirePcap(t, p)
	c := Case{
		ID:     "iec104_u_frames",
		Proto:  "iec104",
		Expect: Expect{HasPayload: true},
	}
	problems := VerifyPcap(p, c)
	for _, pr := range problems {
		if strings.Contains(pr, "has_payload") {
			t.Fatalf("iec104 has_payload false-failure (PDU present but frame <80): %s", pr)
		}
	}
	// 负路径：纯 TCP 握手（无任何 IEC104 PDU）必须失败。tcp-handshake-basic 只有
	// SYN/SYN-ACK/ACK/FIN，iec60870_104.apdulen 全程为空。
	p2 := pcapRoot + "/tcp/tcp-handshake-basic.pcap"
	requirePcap(t, p2)
	c2 := Case{ID: "iec104-nopdu", Proto: "iec104", Expect: Expect{HasPayload: true}}
	probs := VerifyPcap(p2, c2)
	found := false
	for _, pr := range probs {
		if strings.Contains(pr, "has_payload") {
			found = true
		}
	}
	if !found {
		t.Errorf("iec104 has_payload on pure-TCP pcap must fail, got %v", probs)
	}
}

// TestHavePayload_ForDamengAndCQLChecksTCPLen: dameng/cql/drda PDU 天然小（<80B），
// frame.len 恒 < 80，旧实现用 frame.len>80 作代理判断恒判"无负载"。应用层数据帧
// 的 tcp.len>0，纯 TCP 握手/挥手帧 tcp.len=0——用 tcp.len 判断，而非整帧长。
func TestHavePayload_ForDamengAndCQLChecksTCPLen(t *testing.T) {
	cases := []struct {
		proto string
		id    string
		pcap  string
	}{
		{"dameng", "dameng_auth_success", pcapRoot + "/dameng/dameng_auth_success.pcap"},
		{"cql", "cql_length_boundary", pcapRoot + "/cql/cql_length_boundary.pcap"},
		{"drda", "drda_database_connect", pcapRoot + "/drda/drda_database_connect.pcap"},
	}
	for _, tc := range cases {
		requirePcap(t, tc.pcap)
		c := Case{ID: tc.id, Proto: tc.proto, Expect: Expect{HasPayload: true}}
		problems := VerifyPcap(tc.pcap, c)
		for _, pr := range problems {
			if strings.Contains(pr, "has_payload") {
				t.Fatalf("%s has_payload false-failure (payload present but frame <80): %s", tc.proto, pr)
			}
		}
	}
	// 负路径：纯 TCP 握手（无任何应用载荷，tcp.len 全程 0）必须失败。
	p2 := pcapRoot + "/tcp/tcp-handshake-basic.pcap"
	requirePcap(t, p2)
	for _, proto := range []string{"dameng", "cql", "drda"} {
		c2 := Case{ID: proto + "-nopayload", Proto: proto, Expect: Expect{HasPayload: true}}
		probs := VerifyPcap(p2, c2)
		found := false
		for _, pr := range probs {
			if strings.Contains(pr, "has_payload") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s has_payload on pure-TCP pcap must fail, got %v", proto, probs)
		}
	}
}

// TestHavePayload_ForRoutingProtocolsChecksPdu: igmp/ospf/pim 是 raw-IP 链，
// 报文恒小（IGMP 8B+20B IP=28B，frame.len 恒 < 80），不能用整帧长作 has_payload
// 代理。存在性由协议自身的报文类型字段（igmp.type/ospf.msg/pim.type）标记：
// 非空 = 至少一个该协议 PDU。
func TestHavePayload_ForRoutingProtocolsChecksPdu(t *testing.T) {
	cases := []struct {
		proto string
		id    string
		pcap  string
	}{
		{"igmp", "igmp_v1_general_query", pcapRoot + "/igmp/igmp_v1_general_query.pcap"},
		{"ospf", "ospf_hello_dr_bdr", pcapRoot + "/ospf/ospf_hello_dr_bdr.pcap"},
		{"pim", "pim_sm_hello_options", pcapRoot + "/pim/pim_sm_hello_options.pcap"},
	}
	for _, tc := range cases {
		requirePcap(t, tc.pcap)
		c := Case{ID: tc.id, Proto: tc.proto, Expect: Expect{HasPayload: true}}
		problems := VerifyPcap(tc.pcap, c)
		for _, pr := range problems {
			if strings.Contains(pr, "has_payload") {
				t.Fatalf("%s has_payload false-failure (PDU present but frame <80): %s", tc.proto, pr)
			}
		}
	}
	// 负路径：纯 TCP 握手（无任何 raw-IP 路由报文，igmp.type/ospf.msg/pim.type 全空）
	// 必须失败。
	p2 := pcapRoot + "/tcp/tcp-handshake-basic.pcap"
	requirePcap(t, p2)
	for _, proto := range []string{"igmp", "ospf", "pim"} {
		c2 := Case{ID: proto + "-nopdu", Proto: proto, Expect: Expect{HasPayload: true}}
		probs := VerifyPcap(p2, c2)
		found := false
		for _, pr := range probs {
			if strings.Contains(pr, "has_payload") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s has_payload on pure-TCP pcap must fail, got %v", proto, probs)
		}
	}
}
