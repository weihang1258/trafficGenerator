package pcaptest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// VerifyPcap 依据用例期望对已生成 pcap 做 tshark 断言。返回问题列表
// （空 = 通过）。
func VerifyPcap(pcapPath string, c Case) []string {
	var problems []string
	if _, err := exec.LookPath("tshark"); err != nil {
		return []string{"tshark not found in PATH"}
	}
	if c.Expect.ExpectError {
		// 负向 / Validate 拒绝用例：任务按预期失败且未产出 pcap；无线数据可验证。
		return problems
	}
	problems = append(problems, CheckExpertInfo(pcapPath, c.ID, c.DecodeAs)...)
	if c.Expect.PacketCount > 0 || c.Expect.MinPackets > 0 {
		n, err := PacketCount(pcapPath)
		if err != nil {
			problems = append(problems, fmt.Sprintf("count: %v", err))
		} else {
			if c.Expect.PacketCount > 0 && n != c.Expect.PacketCount {
				problems = append(problems, fmt.Sprintf("count: got %d packets, want %d", n, c.Expect.PacketCount))
			}
			if c.Expect.MinPackets > 0 && n < c.Expect.MinPackets {
				problems = append(problems, fmt.Sprintf("count: got %d packets, want >= %d", n, c.Expect.MinPackets))
			}
		}
	}
	for _, fa := range c.Expect.Fields {
		vals, err := FieldValues(pcapPath, fa.Field, c.DecodeAs)
		if err != nil {
			problems = append(problems, fmt.Sprintf("field %s: %v", fa.Field, err))
			continue
		}
		// DistinctValues：多流聚合断言。字段跨全量包必须恰好取这些值（各
		// 至少一次）且无其他；包索引忽略，因为多流调度器非确定性交织。
		if len(fa.DistinctValues) > 0 {
			exclude := map[string]bool{}
			for _, e := range fa.DistinctExclude {
				exclude[e] = true
			}
			seen := map[string]int{}
			for _, v := range vals {
				if v != "" && !exclude[v] {
					seen[v]++
				}
			}
			want := map[string]bool{}
			for _, w := range fa.DistinctValues {
				want[w] = true
			}
			var unexpected []string
			for v := range seen {
				if !want[v] {
					unexpected = append(unexpected, fmt.Sprintf("%s(x%d)", v, seen[v]))
				}
			}
			var missing []string
			for _, w := range fa.DistinctValues {
				if seen[w] == 0 {
					missing = append(missing, w)
				}
			}
			if len(unexpected) > 0 || len(missing) > 0 {
				problems = append(problems, fmt.Sprintf("field %s: distinct values mismatch (want %v; missing %v; unexpected %v)",
					fa.Field, fa.DistinctValues, missing, unexpected))
			}
			continue
		}
		if fa.Packet < 1 || fa.Packet > len(vals) {
			problems = append(problems, fmt.Sprintf("field %s: packet %d out of range (file has %d packets)", fa.Field, fa.Packet, len(vals)))
			continue
		}
		got := vals[fa.Packet-1]
		if fa.Nonzero {
			if got == "" || IsZeroValue(got) {
				problems = append(problems, fmt.Sprintf("field %s on packet %d: got %q, want nonzero", fa.Field, fa.Packet, got))
			}
			continue
		}
		if fa.SameAsPacket > 0 {
			// 持久性断言：值必须等于另一包同字段值。处理无法固定六进制期望的
			// 运行期随机值（会话/文件 id）。
			if fa.SameAsPacket < 1 || fa.SameAsPacket > len(vals) {
				problems = append(problems, fmt.Sprintf("field %s: same_as_packet %d out of range (file has %d packets)", fa.Field, fa.SameAsPacket, len(vals)))
				continue
			}
			if got == "" {
				problems = append(problems, fmt.Sprintf("field %s on packet %d: absent, want value equal to packet %d", fa.Field, fa.Packet, fa.SameAsPacket))
				continue
			}
			if got != vals[fa.SameAsPacket-1] {
				problems = append(problems, fmt.Sprintf("field %s on packet %d: got %q, want equal to packet %d value %q", fa.Field, fa.Packet, got, fa.SameAsPacket, vals[fa.SameAsPacket-1]))
			}
			continue
		}
		if fa.Value == "" {
			if got == "" {
				problems = append(problems, fmt.Sprintf("field %s on packet %d: absent, want present", fa.Field, fa.Packet))
			}
			continue
		}
		// TCP flags：按位比较，"0x0002" 等于 "0x002"；期望位必须都置位。
		if fa.Field == "tcp.flags" {
			wantBits, werr := TCPFlagBits(fa.Value)
			if werr == nil && wantBits != 0 {
				if !HasTCPFlag(got, wantBits) {
					problems = append(problems, fmt.Sprintf("field %s on packet %d: got %q, want flags %s set", fa.Field, fa.Packet, got, fa.Value))
				}
				continue
			}
		}
		if got != fa.Value {
			problems = append(problems, fmt.Sprintf("field %s on packet %d: got %q, want %q", fa.Field, fa.Packet, got, fa.Value))
		}
	}
	if len(c.Expect.Frames) > 0 {
		frames, err := HexDumpAll(pcapPath, c.DecodeAs)
		if err != nil {
			problems = append(problems, fmt.Sprintf("frames: %v", err))
		} else {
			for _, fa := range c.Expect.Frames {
				if fa.Packet < 1 || fa.Packet > len(frames) {
					problems = append(problems, fmt.Sprintf("frame: packet %d out of range (file has %d packets)", fa.Packet, len(frames)))
					continue
				}
				want, err := ParseHexBytes(fa.Hex)
				if err != nil {
					problems = append(problems, fmt.Sprintf("frame packet %d: bad hex %q: %v", fa.Packet, fa.Hex, err))
					continue
				}
				fb := frames[fa.Packet-1].Bytes
				if fa.Offset > len(fb) {
					problems = append(problems, fmt.Sprintf("frame packet %d: offset %d beyond frame length %d", fa.Packet, fa.Offset, len(fb)))
					continue
				}
				matches, mismatchAt := MatchHexOffset(fb, fa.Offset, want)
				if !matches {
					problems = append(problems, fmt.Sprintf("frame packet %d offset %d: bytes mismatch at offset %d (got %02x, want %02x)",
						fa.Packet, fa.Offset, mismatchAt,
						ByteAt(fb, mismatchAt), WantAt(want, mismatchAt-fa.Offset)))
				}
			}
		}
	}
	if c.Expect.HasHandshake {
		if err := ExpectFirstFlag(pcapPath, "syn", c.DecodeAs); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if c.Expect.Terminates {
		has := false
		last, err := FieldValues(pcapPath, "tcp.flags", c.DecodeAs)
		if err != nil {
			problems = append(problems, fmt.Sprintf("terminates: %v", err))
		} else {
			for i := len(last) - 1; i >= 0 && i >= len(last)-3; i-- {
				if HasTCPFlag(last[i], 0x001) || HasTCPFlag(last[i], 0x004) { // FIN 或 RST
					has = true
					break
				}
			}
		}
		if err == nil && !has {
			problems = append(problems, "terminates: no FIN/RST in last 3 packets")
		}
	}
	if c.Expect.HasPayload {
		if err := checkHasPayload(pcapPath, c); err != nil {
			problems = append(problems, "has_payload: "+err.Error())
		}
	}
	if c.Expect.Directional {
		ipv4Srcs, err4 := FieldValues(pcapPath, "ip.src", c.DecodeAs)
		ipv6Srcs, err6 := FieldValues(pcapPath, "ipv6.src", c.DecodeAs)
		if err4 != nil && err6 != nil {
			problems = append(problems, fmt.Sprintf("directional: ip.src: %v; ipv6.src: %v", err4, err6))
		} else {
			seen := mergeDirectionalSources(ipv4Srcs, ipv6Srcs)
			if len(seen) < 2 {
				problems = append(problems, fmt.Sprintf("directional: only one IP source seen (%d distinct), want >= 2", len(seen)))
			}
		}
	}
	if c.Expect.Negotiated {
		// TCP 握手完成：至少一个 SYN+ACK 包。
		found := false
		flags, err := FieldValues(pcapPath, "tcp.flags", c.DecodeAs)
		if err != nil {
			problems = append(problems, fmt.Sprintf("negotiated: %v", err))
		} else {
			for _, f := range flags {
				if HasTCPFlag(f, 0x002) && HasTCPFlag(f, 0x010) {
					found = true
					break
				}
			}
		}
		if err == nil && !found {
			problems = append(problems, "negotiated: no SYN+ACK packet seen (handshake incomplete)")
		}
	}
	return problems
}

// checkHasPayload 断言用例标记 has_payload 的消息确实携带应用层负载。
// 语义来源：testcase 文档（如 20-coap-testcase.md §用例规范——"解码后的字节
// 长度才用于 … has_payload 判断"），即由"负载长度"驱动，而非"整帧长度"。
// 旧实现用 frame.len>80 作代理：对 TCP 大消息（STUN 82+）成立，但对负载
// 小的 UDP 协议（CoAP 63~79B，payload 14B）恒误报"无负载"。
// 协议感知：CoAP 有权威字段 coap.payload_length（空负载时 tshark 省略该
// 字段），用它判断最稳；其余协议回到 frame.len>80 启发式。
func checkHasPayload(pcapPath string, c Case) error {
	if c.Proto == "coap" {
		vals, err := FieldValues(pcapPath, "coap.payload_length", c.DecodeAs)
		if err != nil {
			return err
		}
		for _, v := range vals {
			if n, e := strconv.Atoi(v); e == nil && n > 0 {
				return nil
			}
		}
		return fmt.Errorf("no CoAP message with non-zero payload_length (payload field absent or 0)")
	}
	// IEC104 PDU 天然小（60~70B），frame.len 恒 < 80，不能用帧长作代理。PDU 是否
	// 存在由 iec60870_104.apdulen 标记：非空 = 至少一个 IEC104 PDU（I/U/S 帧），
	// 纯 TCP 握手/挥手帧该字段为空。设计 22-iec104-testcase.md 在纯 U 控制帧
	// （iec104_u_frames）也置 has_payload=true，故语义为"PDU 存在"。
	if c.Proto == "iec104" {
		vals, err := FieldValues(pcapPath, "iec60870_104.apdulen", c.DecodeAs)
		if err != nil {
			return err
		}
		for _, v := range vals {
			if v != "" {
				return nil
			}
		}
		return fmt.Errorf("no IEC104 PDU (iec60870_104.apdulen absent; only TCP handshake)")
	}
	// Dameng/CQL PDU 天然小（<80B），frame.len 恒 < 80，不能用帧长作代理。应用
	// 载荷存在性由 tcp.len（TCP payload 字节数）标记：真正的数据帧 tcp.len>0，
	// 纯握手/挥手帧 tcp.len=0。dameng 设计（30-dameng-testcase）与 cql 设计
	// （35-cql-testcase）都把 has_payload 语义定成"存在一个携带应用层数据的帧"。
	// OpenWire 命令帧同样天然小（ShutdownInfo 全帧 64B、WireFormatInfo 全帧
	// 恰 80B——通用 ">80" 判 false），不能用帧长作代理。tcp.len>0 判定与
	// dameng/cql/thrift 同款。AMS 管理帧同为小帧（最小 22B、典型 <80B），
	// 且 tshark 无该协议 dissector，不存在协议字段可查。Gnutella 23B 二进制
	// 消息帧更小（最小 PING 全帧 23B），握手 ASCII 帧才上百字节，同走 tcp.len。
	if c.Proto == "dameng" || c.Proto == "cql" || c.Proto == "drda" || c.Proto == "thrift" || c.Proto == "openwire" || c.Proto == "ams" || c.Proto == "gnutella" {
		vals, err := FieldValues(pcapPath, "tcp.len", c.DecodeAs)
		if err != nil {
			return err
		}
		for _, v := range vals {
			if n, e := strconv.Atoi(v); e == nil && n > 0 {
				return nil
			}
		}
		return fmt.Errorf("no %s payload (tcp.len 0 everywhere; only TCP handshake/teardown)", c.Proto)
	}
	// Swarm 双承载（B5）：TCP storage 帧用 tcp.len（同上）；UDP discovery
	// datagram 用 udp.length（含 8B UDP 头，>8 即有 SWD1 载荷）。
	// NMEA（69-nmea）：ASCII 句子 32~82B，UDP $PGRME 全帧 74B 落在通用
	// ">80" 启发式之下——TCP 侧 tcp.len>0、UDP 侧 udp.length>8 判定
	// （与 swarm 同款双承载分支）。
	if c.Proto == "nmea" {
		if vals, err := FieldValues(pcapPath, "tcp.len", c.DecodeAs); err == nil {
			for _, v := range vals {
				if n, e := strconv.Atoi(v); e == nil && n > 0 {
					return nil
				}
			}
		}
		vals, err := FieldValues(pcapPath, "udp.length", c.DecodeAs)
		if err != nil {
			return err
		}
		for _, v := range vals {
			if n, e := strconv.Atoi(v); e == nil && n > 8 {
				return nil
			}
		}
		return fmt.Errorf("no nmea payload (tcp.len 0 and udp.length<=8 everywhere)")
	}
	if c.Proto == "swarm" {
		if vals, err := FieldValues(pcapPath, "tcp.len", c.DecodeAs); err == nil {
			for _, v := range vals {
				if n, e := strconv.Atoi(v); e == nil && n > 0 {
					return nil
				}
			}
		}
		vals, err := FieldValues(pcapPath, "udp.length", c.DecodeAs)
		if err != nil {
			return err
		}
		for _, v := range vals {
			if n, e := strconv.Atoi(v); e == nil && n > 8 {
				return nil
			}
		}
		return fmt.Errorf("no swarm payload (tcp.len 0 and udp.length<=8 everywhere)")
	}
	// 路由协议（igmp/ospf/pim）是 raw-IP 链，报文恒小（IGMP 8B 报文+20B IP
	// = 28B，frame.len 恒 < 80），不能用帧长作代理。存在性由协议自身的报文
	// 类型字段标记：非空 = 至少一个协议 PDU（raw-IP 链每个发出的包都是该
	// 协议报文，无异帧污染）。
	if c.Proto == "igmp" || c.Proto == "ospf" || c.Proto == "pim" {
		field := map[string]string{"igmp": "igmp.type", "ospf": "ospf.msg", "pim": "pim.type"}[c.Proto]
		vals, err := FieldValues(pcapPath, field, c.DecodeAs)
		if err != nil {
			return err
		}
		for _, v := range vals {
			if v != "" {
				return nil
			}
		}
		return fmt.Errorf("no %s PDU (%s absent)", c.Proto, field)
	}
	lens, err := FieldValues(pcapPath, "frame.len", c.DecodeAs)
	if err != nil {
		return err
	}
	for _, l := range lens {
		if n, e := strconv.Atoi(l); e == nil {
			// ISIS/L2-only frames can be as short as 60 bytes (IEEE 802.3
			// minimum) so the generic "> 80" heuristic fails for them — the
			// isis branch is protocol-specific and must not relax the generic
			// threshold (a 66-byte TCP handshake with timestamps is NOT a
			// payload-bearing frame).
			if n > 80 || (c.Proto == "isis" && n > 0) {
				return nil
			}
		}
	}
	return fmt.Errorf("no packet with frame.len > 80")
}

func mergeDirectionalSources(groups ...[]string) map[string]bool {
	seen := map[string]bool{}
	for _, values := range groups {
		for _, value := range values {
			if value != "" {
				seen[value] = true
			}
		}
	}
	return seen
}

// ------ 深度 pcap 审计（Expert Info + checksum） ------

// CheckExpertInfo 扫描 pcap 的 Wireshark Expert Info malformed 标志
// （_ws.malformed / [Malformed Packet: X]）与 checksum 状态 ILLEGAL（=4，
// IPv6 UDP/TCP 校验和 0x0000 见 RFC 8200 §8.1）。状态 2（unverified）与
// 3（not present，IPv4 UDP 校验和 0x0000 见 RFC 768）合法、忽略——它们
// 曾在深度审计中产生误报。已知 tshark 对合法帧的 dissector 伪影按用例
// whitelist。
func CheckExpertInfo(pcapPath, caseID string, decodeAs []string) []string {
	var problems []string
	out, err := RunTshark(pcapPath, []string{
		"-T", "fields",
		"-e", "frame.number",
		"-e", "_ws.malformed",
		"-e", "_ws.expert.message",
		"-e", "tcp.checksum.status",
		"-e", "ip.checksum.status",
		"-e", "udp.checksum.status",
	}, decodeAs)
	if err != nil {
		return []string{fmt.Sprintf("expert: %v", err)}
	}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 6 {
			continue
		}
		fno, malf, expert, tcpck, ipck, udpck := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
		for _, v := range []string{tcpck, ipck, udpck} {
			if v == "4" {
				problems = append(problems, fmt.Sprintf("expert: frame %s checksum status ILLEGAL (RFC 8200 §8.1: 0x0000 over IPv6)", fno))
			}
		}
		if malf == "" {
			continue
		}
		if IsMalformedWhitelisted(caseID, malf, expert) {
			continue
		}
		problems = append(problems, fmt.Sprintf("expert: frame %s malformed: %s", fno, malf))
	}
	return problems
}

// IsMalformedWhitelisted 报告某用例上的 malformed 标志是否为已知 tshark
// dissector 对合法帧的伪影（2026-08 深度审计中字节级验证）——而非帧缺陷。
func IsMalformedWhitelisted(caseID string, flags ...string) bool {
	flag := ""
	expert := ""
	if len(flags) > 0 {
		flag = flags[0]
	}
	if len(flags) > 1 {
		expert = flags[1]
	}
	artifact := expert
	if artifact == "" {
		artifact = flag
	}
	artifactMatchesExact := func(want string) bool {
		for _, value := range strings.Split(artifact, ",") {
			if value == want {
				return true
			}
		}
		return false
	}
	artifactMatchesPrefix := func(prefix string) bool {
		// expert 消息可能是多条 Expert Info 逗号拼接（同一帧多个
		// "BER Error: ..."），按值逐个匹配前缀，多值不整体拒绝。
		for _, value := range strings.Split(artifact, ",") {
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
		return false
	}
	// flagMatchesExact 匹配 _ws.malformed 标志字段自身的值。expert 消息
	// （_ws.expert.message）对 TLS 报错可能是泛化的 "Malformed Packet
	// (Exception occurred)"，而 "Malformed Packet: TLS" 标志在 flag 字段里，
	// 因此 TLS 伪影按 flag 匹配，不依赖 expert 文案。
	flagMatchesExact := func(want string) bool {
		for _, value := range strings.Split(flag, ",") {
			if value == want {
				return true
			}
		}
		return false
	}

	// 1. NFSv3 自动会话 MOUNT 伪影：UMOUNT 应答复用 MNT 调用的 XID，tshark
	//    RPC 状态机用 MNT dissector 解析仅含状态的 UMOUNT 应答（RFC 1813
	//    §4.1）→ malformed。t111-t116/t128 除外（线上字节真实损坏，已修复）。
	// 2. SMB GSS-SPNEGO 伪影：T041 发送透传 security_blob，GSS 包裹长度
	//    （0x82 0x01 0x00 = 256）超过 7B 载荷 → BER 超界（blob 字节与
	//    SecurityBufferLength 恰为用例请求值）；probe_* 为套件外的诊断用例。
	// 3. 隧道/封装伪影：SRv6 内层 UDP 端口 53 携带 8B 载荷（"12345678"，
	//    设计 §6.1）触发 DNS 启发式 dissector；ENIP seq_wraparound 用例将
	//    原始透传字节经 CIP Message Router 路径。
	// 4. tshark 3.6 dissector 类型/FC 限制对合法帧：TDS 0xF4（JSON）与 0xF0
	//    （UDT）是合法 MS-TDS 类型码（TDS 7.4），packet-tds.c 不识别 → "Invalid
	//    data type" → 无法定长 → 错位 → malformed。字节级已验证：@x xml 0xF1 /
	//    @j json 0xF4 / @u udt 0xF0 均携带正确 LONGLEN_TYPE TYPE_INFO
	//    （0xFFFFFFFF）+ 完整 PLP_BODY。doip_userdata_empty 是显式线网负向
	//    用例（"Wireshark malformed(预期)"）：user_data=[] 只发裸 0x8001 头、
	//    无 UDS 服务，按设计不可解析。modbus-fc99-exemption 经豁免路径传
	//    FC 0x99（设计 V-103：0x99|0x80=0x99 幂等）——tshark FC 表外 → malformed；
	//    帧字节与期望完全一致。
	switch {
	case strings.HasPrefix(caseID, "nfs_t111"), strings.HasPrefix(caseID, "nfs_t112"),
		strings.HasPrefix(caseID, "nfs_t113"), strings.HasPrefix(caseID, "nfs_t114"),
		strings.HasPrefix(caseID, "nfs_t115"), strings.HasPrefix(caseID, "nfs_t116"),
		strings.HasPrefix(caseID, "nfs_t128"):
		return false
	case strings.HasPrefix(caseID, "nfs_") && strings.Contains(flag, "[Malformed Packet: MOUNT]"):
		return true
	case caseID == "smb_tpos41_custom_securityblob", strings.HasPrefix(caseID, "probe_"):
		return true
	case caseID == "srv6_tpos1_basic", caseID == "srv6_tpos6_nested_ipv6":
		return true
	case caseID == "enip_seq_wraparound_3_frames":
		return true
	case caseID == "tds_rpc_param_xml_json_udt", caseID == "doip_userdata_empty", caseID == "modbus-fc99-exemption":
		return true
	// Megaco 注释变体伪影（D-MEGACO-1，tshark 3.6 megaco dissector 未实现
	// ABNF COMMENT——RFC 3525 Annex B.2 `COMMENT = ";" ... EOL` 是合法线格
	// 式）：合法注释行报 malformed。帧字节由用例 frames 钉死（offset 65 起
	// 注释字节逐字节断言），仅 dissector 解析面受限。
	case caseID == "megaco_udp_ipv4_whitespace_comment_variants":
		return true
	// S7comm 错误头伪影：对"错误头+空数据"的 Ack_Data（parlg=1 参数为函数码、
	// datlg=0、errcls/errcod 非零），packet-s7comm.c 的 Write Var 分支读不存在的
	// 数据区 → "[Malformed Packet: S7COMM]"（设计 §9.3 S12 帧 15 已文档化）。
	// 字节级已对探针 pcap 验证：errcls=0x04/errcod=0x01/param=0x05，字段 tshark
	// 仍正确解析（errcls/errcod/func），仅 dissector 残留。属已知伪影非帧缺陷。
	case caseID == "s7_error_class_code":
		return true
	// FINS 0104 Multiple Memory Area Read 请求伪影：packet-omron-fins.c 的
	// 0104 分支按 count 循环读 4 字节/组（区码+地址2+bit），忽略每组的
	// NC——N 组请求剩余 N×2B NC 未消费 → malformed。线型合法（W342-E1：
	// count 1B + N×[区码+地址2+bit+NC2]，设计 §3.9 注记录该怪癖）；帧字节
	// 经 fins_multi_read 的 frames 原始断言校验。
	case caseID == "fins_multi_read":
		return true
	// H.323 ras_only RAS stub 伪影（2026-09-19，字节级已对
	// /tmp/mcp-pcaps/h323/h323_scenario_ras.pcap 验证）：legacy RAS 面发
	// 最小合成 stub（4B 头 [seqno 0x00+type] + [0x00 0x01 协议标识] +
	// 4B GK IP，h323.go:503-509），非完整 PER 编码——types.go:5471 注记
	// "RAS has no reference pcap"。packet-h225.c 按 H.225.0 §7 PER 解析
	// 8 字节载荷 → 每帧 "[Malformed Packet: H.225.0]"（判得对：确非完整
	// RAS 消息）。帧结构面正确（8×60B，五元组 12345↔1719、GK 10.12.184.53
	// 双向交替逐包验证），是 legacy 合成器字节合同，非帧缺陷。
	case caseID == "h323_scenario_ras":
		return true
	// 5. RTMP/XMPP/TLS dissector 对字节级合法帧的伪影（2026-08 冒烟用例，
	//    已对探针 pcap 验证）：RTMP dissector 的 AMF 递归守卫在嵌套 _result
	//    对象上触发（"Loop in AMF dissection"），但 AMF 编码合法（string
	//    0x02 0x00 <len16> <bytes> 已逐字节验证）；XMPP 的 "</stream:stream>"
	//    是合法 RFC 6120 §4.5 流结束，dissector 报 "Closing an unopened tag"；
	//    TLS Certificate 握手携带 261 字节证书（record len 0x010d = 9B record
	//    头 + 0x109 handshake 体，内部自洽）触发 packet-tls.c 尺寸启发。
	// 6. IPFIX enterprise IE + variable-length (length=65535) 组合：
	//    tshark 3.6.14 解析模板集正确但不注册数据集匹配（"Data (N bytes),
	//    no template found"）。字节已验证：template IE 0x8002=PEN424242,
	//    length=65535, data 0x0b+"short-value"=12B, pad=16B, 符合 RFC 7011
	//    §3.2 变长编码。是 tshark dissector 限制，非帧缺陷。
	case caseID == "cflow_ipfix_variable_length_ie":
		return true
	// 7. LDP FEC-only dissector 伪影（tshark 3.6.14 缺陷，字节级已对
	//    /tmp/mcp-pcaps/ldp/ 探针验证）：packet-ldp.c dissect_tlv_fec 在
	//    dispatch 前无条件读 op_length=tvb_get_bits16(offset+8)，对 IPv4
	//    Prefix FEC 该读取点永远在 FEC 元素（type+af+len+prefix, 7B /24）
	//    末端之外 2 字节。若 FEC TLV 是消息里最后一个 TLV（Label Request
	//    必须 FEC-only），offset+8 越过 tvb 终点 → BoundsError → malformed；
	//    若后面跟着 Label TLV（Label Mapping/Withdraw/Release）则读取点落在
	//    其后 TLV 头内 → 解码正常。编码正确（RFC 5036 §3.4.1.1 / §3.5.1），
	//    是 dissector 读越界，非帧缺陷。
	case caseID == "ldp_label_request_ipv4", caseID == "ldp_ordered_dod_allocation":
		return true
	case caseID == "rtmp-connect-play-basic" && artifactMatchesExact("Loop in AMF dissection"),
		// D-RTMP-1 P5 层链用例族同伪影（2026-09-20，字节级已对
		// /tmp/mcp-pcaps/rtmp/ldap 期探针验证：tshark 自身解析出
		// "connect()"/"_result()"/"Window Acknowledgement Size" 等消息名
		// ——AMF 编码合法可解析，仅 RTMP dissector 的 AMF 递归守卫对
		// 嵌套 _result 对象误报）：rtmp_ 前缀=层链 16 例族。
		strings.HasPrefix(caseID, "rtmp_") && artifactMatchesExact("Loop in AMF dissection"),
		// D-XMPP-1：'</stream:stream>' 流关闭（RFC 6120 §4.4）对 tshark
		// 是未打开标签的关闭——字节合法、语义合法，dissector 必报
		// "Closing an unopened tag"（每例双 FIN 前两帧恒现）；xmpp_ 前缀=
		// 层链 10 例族，"xmpp-stream-basic"=旧扁平例兼容。
		strings.HasPrefix(caseID, "xmpp_") && artifactMatchesExact("Closing an unopened tag"),
		caseID == "xmpp-stream-basic" && artifactMatchesExact("Closing an unopened tag"),
		// stun_binding_tls_session/pop3_over_tls/mqtt_over_tls/socks5_over_tls：
		// tshark 3.6.14 TLS dissector 对我们模板集 Certificate 的 BER 解析
		// 伪影（"Wrong field in SEQUENCE"/"SEQUENCE is N too many bytes long"）。
		// 字节级已对探针验证：记录层/handshake 布局与 RFC 8446 一致；同一
		// pcap 帧内后续 record（ServerHello/应用数据）解码全部正常。是
		// dissector 对非标准（但合法）会话模板的误报，非帧缺陷。
		// 注意：D-TLS-2 后 tls.json 6 例不再挂此白名单——Certificate 帧已换
		// 真 X.509 DER（certgen.go），tshark 干净解出，BER 伪影消失
		// （2026-09-14 落盘 /tmp/mcp-pcaps/tls/ 6 pcap 零 malformed 实证）。
		(caseID == "stun_binding_tls_session" ||
			caseID == "pop3_over_tls" || caseID == "mqtt_over_tls" ||
			caseID == "socks5_over_tls") &&
			(artifactMatchesPrefix("BER Error") || flagMatchesExact("[Malformed Packet: TLS]")):
		return true
	// 8. OpenWire dissector 对合法帧的伪影（tshark 3.6.14，字节级已对
	//    /tmp/ow-* 探针验证，2026-08）：openwire_exception_response 的
	//    ExceptionResponse 携带合法 THROWABLE（class=java.lang.
	//    IllegalStateException、message、depth）——packet-openwire.c 的
	//    THROWABLE 分支在自定义类型之上多读 1B 类型标记，class 之后即报
	//    BoundsError → "[Malformed Packet: OpenWire]"（throwable 字段仍正确
	//    解析，仅剩余字段对不齐）。openwire_message_body_segmentation 的
	//    4000B 消息跨 MSS 分 3 段，dissector 不做 TCP 重组，首段（携带
	//    length 前缀）在 length 结束前即被 tvb 切断 → 同样 malformed。两者
	//    均为 dissector 限制，非帧缺陷。
	case caseID == "openwire_exception_response" && strings.Contains(flag, "[Malformed Packet: OpenWire]"):
		return true
	case caseID == "openwire_message_body_segmentation" &&
		(strings.Contains(flag, "_ws.malformed") || strings.HasPrefix(expert, "Expected:")):
		return true
	// 9. Gnutella QueryHit dissector 缺陷（tshark 3.6.14，字节级已对
	//    /tmp/exp_qh_* 探针验证，2026-08）：packet-gnutella.c 把每个 Hit
	//    建模为 Index|Size|Name\0|Extra\0，Extra 的 NUL 扫描在规范正确的
	//    QueryHit（无 per-hit extra、结尾 16B ServentID）上扫不到终止符，
	//    hit_offset 越过 payload 末端后仍无条件再读 16B ServentID →
	//    BoundsError → "[Malformed Packet: GNUTELLA]"。Count/Port/IP/Speed/
	//    Hit 的 Index/Size/Name 仍全部正确解析；小端/大端探针均复现，与
	//    字节序无关（是 dissector 读越界，非帧缺陷）。规范布局（GDF 0.6，
	//    ServentID 收尾）不改帧迁就 dissector，按 openwire 先例白名单。
	case (caseID == "gnutella_query_queryhit" || caseID == "gnutella_push" ||
		caseID == "gnutella_multi_queryhit" || caseID == "gnutella_mss_message_reassembly" ||
		caseID == "gnutella_frame_boundary") &&
		strings.Contains(flag, "[Malformed Packet: GNUTELLA]"):
		return true
	// 10. MMSE send_conf Response-Status=0x84（error-sending-address-unresolved）
	//     dissector 伪影（D-MMSE-1，tshark 3.6，字节级已对
	//     /tmp/mcp-pcaps/mmse/mmse_response_status_error_values.pcap 帧 23
	//     验证）：PDU 为规范 WAP-209 §7.3 形（8C 81 | 98 TID | 8D 92 |
	//     8B Message-ID | 92 84，22B 与 Content-Length 自洽），dissector 正确
	//     解析全部字段（Message-Id / Response-Status: Sending address
	//     unresolved (0x84) 均在 -V 输出）后在 PDU 末端抛 Exception →
	//     "[Malformed Packet: MMSE]"。同形 send_conf 携带 0x81/0x83/0x85…
	//     0x88 值的帧全部干净，仅 0x84 触发——值特异的 dissector 缺陷，
	//     非帧缺陷。帧字节由 fields 断言钉死（response_status 0x84）。
	case caseID == "mmse_response_status_error_values" &&
		strings.Contains(flag, "[Malformed Packet: MMSE]"):
		return true
	}
	return false
}

// ------ 底层 tshark 封装 ------

// PacketCount 经 tshark 统计帧数。
func PacketCount(path string) (int, error) {
	out, err := RunTshark(path, []string{"-T", "fields", "-e", "frame.number"}, nil)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n, nil
}

// FieldValues 返回每包一个该字段的值。每包一行；空行表示该包字段缺失，
// 必须保留（行索引 = 包索引）。TrimSpace 会剥掉首尾空行（如无 SMB 载荷的
// TCP 握手包）并移动所有索引，因此仅移除尾部换行。
func FieldValues(path, field string, decodeAs []string) ([]string, error) {
	out, err := RunTshark(path, []string{"-T", "fields", "-e", field}, decodeAs)
	if err != nil {
		return nil, err
	}
	out = strings.TrimSuffix(out, "\n")
	lines := strings.Split(out, "\n")
	vals := make([]string, 0, len(lines))
	for _, l := range lines {
		vals = append(vals, strings.TrimSpace(l))
	}
	return vals, nil
}

// RunTsharkTimeout 是单次 tshark 调用的执行上限。tshark dissector 存在对
// 某些畸形/罕见帧的死循环问题（2026-08 回归实测：tshark 存活但无输出，
// cmd.Run() 永久阻塞，测试 22m 超时）。无超时则一个挂死的 tshark 会让整个
// 用例（及 MCP suite）卡死；超时后返回可读错误指明是哪种校验步骤。
const RunTsharkTimeout = 30 * time.Second

// tsharkTimeout 返回单次 tshark 调用的超时。PCAPTEST_TSHARK_TIMEOUT_MS 仅为
// 测试 seam：让测超时路径的用例用短值，不依赖真实挂死（真实 tshark 的死循环
// 无法在测试里确定性触发）。
func tsharkTimeout() time.Duration {
	if v := os.Getenv("PCAPTEST_TSHARK_TIMEOUT_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return RunTsharkTimeout
}

// RunTshark 执行 tshark -r path 加上 args 与 decodeAs 的 -d 规则。带超时：
// 挂死的 tshark（dissector 死循环）在超时内被杀死并返回错误，而不是让调用方
// 永久阻塞。
func RunTshark(path string, args []string, decodeAs []string) (string, error) {
	full := append([]string{"-r", path}, args...)
	// 端口 40000 在 Wireshark 服务表中注册为 "safetynetp"；SafetyNET P
	// dissector 认领该 TCP 流并遮蔽 RPC/NFS 解析。NFS 会话（设计 §7.7）
	// 刻意用 srcPort 40000/40010，故强制将该 NFS 端口按 RPC 解码。
	//
	// 启发式协议标签：Wireshark 启发式 dissector（RPC、X11 等）可能认领
	// 任意高端口并阻断被测流的协议字段提取。给 IANA 知名端口的已知启发式
	// 协议（NFS 2049、X11 6000、Sun RPC、IRC、MQTT 1883）打标签保持字段
	// 提取可用。
	full = append(full, "-d", "tcp.port==2049,rpc", "-d", "tcp.port==6000,x11",
		"-d", "tcp.port==1883,mqtt", "-d", "tcp.port==6667,irc")
	for _, d := range decodeAs {
		full = append(full, "-d", d)
	}
	timeout := tsharkTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tshark", full...)
	// WaitDelay：CommandContext 超时杀掉子进程后，exec 仍需等待 stdout/stderr
	// 管道读到 EOF 才从 Run() 返回。tshark 挂死时其 stdout/stderr 写端不随
	// SIGKILL 关闭（子进程/孙进程持有写端），io.Copy 与 Wait 会永久阻塞——
	// 这正是 2026-08 回归里 cmd.Run() 卡死整条链路的根因。WaitDelay 让 exec
	// 在超时后强制结束等待、关闭管道，Run() 立刻返回错误。
	cmd.WaitDelay = timeout
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		// CommandContext 超时杀进程返回 signal: killed；区分真实 dissector
		// 死循环（本次修复的挂死）与普通 tshark 报错，便于定位是哪种校验卡住。
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("tshark %v: timed out after %s (dissector hang; killed)", full, timeout)
		}
		return "", fmt.Errorf("tshark %v: %v: %s", full, err, errb.String())
	}
	return out.String(), nil
}

// tcpFlagBits 将 tshark tcp.flags 值（如 "0x0002"）映射为语义位。
func TCPFlagBits(s string) (uint16, error) {
	s = strings.TrimPrefix(s, "0x")
	n, err := strconv.ParseUint(s, 16, 16)
	return uint16(n), err
}

// HasTCPFlag 报告 s 的 flag 位是否置位。
func HasTCPFlag(s string, bit uint16) bool {
	n, err := TCPFlagBits(s)
	return err == nil && n&bit != 0
}

// ExpectFirstFlag 检查首 TCP 包是否置位给定 flag。
func ExpectFirstFlag(path, flag string, decodeAs []string) error {
	flags, err := FieldValues(path, "tcp.flags", decodeAs)
	if err != nil {
		return fmt.Errorf("handshake: %v", err)
	}
	if len(flags) == 0 {
		return fmt.Errorf("handshake: no TCP packets at all")
	}
	var bit uint16
	switch flag {
	case "syn":
		bit = 0x002
	case "fin":
		bit = 0x001
	case "rst":
		bit = 0x004
	default:
		return fmt.Errorf("handshake: unknown flag %q", flag)
	}
	if !HasTCPFlag(flags[0], bit) {
		return fmt.Errorf("handshake: first packet flags %q, want %s", flags[0], flag)
	}
	return nil
}

// IsZeroValue 报告 tshark 字段值是否为数字零（纯 "0"、六进制 "0x0"、
// "0x0000000000000000"，或未加 0x 前缀的定长全零六进制 token 如 "0000"）。
func IsZeroValue(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "0" {
		return true
	}
	t = strings.TrimPrefix(t, "0x")
	if t == "" {
		return false // 单独 "0x" 不是数字
	}
	for _, c := range t {
		if c != '0' {
			return false
		}
	}
	return true
}

// ByteAt 返回 i 处字节，越界为 0xff（哨兵）。
func ByteAt(b []byte, i int) byte {
	if i < 0 || i >= len(b) {
		return 0xff
	}
	return b[i]
}

// WantAt 返回期望字节 i 处值，越界为 0xff。
func WantAt(w []byte, i int) byte {
	if i < 0 || i >= len(w) {
		return 0xff
	}
	return w[i]
}
