// Command examplegen derives per-protocol LLM examples from the verified
// cases corpus (test/protocol_pcap/cases/*.json) into an embeddable JSON.
//
// 选择规则（每协议 ≤5 条，贪心字段多样性）：
//  1. simplest：事务例档优先（含响应语义的正常业务场景排前——一问一答
//     才是正常业务；语料只有单向例的协议维持单向），档内层最少、字段键
//     总数最少——LLM 拿来即用的最小可跑配置；
//  2. 多流例保底：示例集必含至少一个 flows>1 的已验证多流例（必然携带
//     动态 strategy 字段），LLM 照抄改 N，不从单流静态示例试错；
//  3. 逐轮挑"相对已收录带来最多新协议层键"的用例（headers/body/
//     transactions 等常用定制字段必须在示例里可见），直到无新键或达上限。
//
// 单条 config 超 6KB 跳过（控制内嵌体积与 LLM 上下文）。示例来自 cases
// 全量 sweep 验证过的真值——LLM 复制形状即可一次调用成功，无需试错。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type caseFile struct {
	ID       string          `json:"id"`
	Proto    string          `json:"proto"`
	Summary  string          `json:"summary"`
	SpecJSON json.RawMessage `json:"spec_json"`
	Expect   struct {
		ExpectError bool `json:"expect_error"`
		PacketCount int  `json:"packet_count"`
		MinPackets  int  `json:"min_packets"`
	} `json:"expect"`
}

type example struct {
	Protocol    string          `json:"protocol"`
	CaseID      string          `json:"case_id"`
	Summary     string          `json:"summary"`
	Config      json.RawMessage `json:"config"`
	FlowControl string          `json:"flow_control_note,omitempty"`
	Packets     int             `json:"packets"` // 事务档判定输入：缺省事务例（无 opt-out 键且 ≥2 包）
}

type envelope struct {
	Generated int               `json:"generated"`
	Protocols map[string][]exam `json:"protocols"`
}
type exam = example

// handExamples returns the curated D-FILE-1 file_id examples（每层至少 1 条
// file_id 形态——客户端第9轮复核 三.5）。config 形状与派生例同源（最小层
// 链 + file_source.file_id 占位符），真值经 8081 实跑验证。
func handExamples() []example {
	fid := "<上传回执 file_id，64 位 hex>"
	// Packets = 8081 实跑 pcap 的实测包数（2026-10-13 第9轮验证批次回填，
	// 展示口径：事务档判定与 LLM 预期包量）。
	pkts := map[string]int{
		"ftp_retr_file_id": 24, "http_body_file_id": 9, "tcp_raw_file_id": 9,
		"smtp_attachment_file_id": 20, "pop3_retr_file_id": 9, "smb_write_file_id": 31,
		"nfs_write_file_id": 13, "wireguard_payload_file_id": 3, "shadowsocks_file_id": 8,
		"vmess_payload_file_id": 11, "udp_raw_file_id": 1, "telnet_file_id": 14,
		// D-FILE-2 批（8081 实跑 2026-10-13 回填）
		"tftp_file_id": 3, "coap_file_id": 2, "socks5_data_file_id": 12,
		"openvpn_file_id": 12, "rdp_data_event_file_id": 28, "sip_media_file_id": 9,
		"sctp_chunk_file_id": 8,
	}
	mk := func(proto, id, summary, cfg string) example {
		return example{Protocol: proto, CaseID: id, Summary: summary,
			Config: json.RawMessage(cfg), Packets: pkts[id]}
	}
	return []example{
		// —— D-FILE-1 首批 3 条（此前手工追加进 layer_examples.json，收编
		// 入生成器防 examplegen 重生成丢失）——
		mk("ftp", "ftp_retr_file_id",
			"D-FILE-1：RETR 数据通道下发上传文件（data_channel.direction=down + file_source.file_id）",
			`{"layers": [{"tcp": {}}, {"ftp": {"sessions": [{"transactions": [{"commands": [{"cmd": "USER u", "response": "331"}, {"cmd": "PASS p", "response": "230"}, {"cmd": "RETR /f.bin", "response": "150", "emit_data_channel": true}, {"cmd": "", "response": "226"}, {"cmd": "QUIT", "response": "221"}], "data_channel": {"mode": "passive", "direction": "down", "file_source": {"file_id": "`+fid+`"}}}]}]}}]}`),
		mk("http", "http_body_file_id",
			"D-FILE-1：请求 body 来自上传文件（file_source.file_id=上传回执的 file_id，免重复上传）",
			`{"layers": [{"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}}, {"tcp": {"src_port": 40010, "dst_port": 80}}, {"http": {"method": "POST", "uri": "/upload", "version": "1.1", "file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("tcp", "tcp_raw_file_id",
			"D-FILE-1：tcp 裸流载荷来自上传文件（未适配协议传文件的万能兜底）",
			`{"layers": [{"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}}, {"tcp": {"src_port": 40012, "dst_port": 9000, "file_source": {"file_id": "`+fid+`"}}}]}`),
		// —— 第9轮补齐 9 条 ——
		mk("smtp", "smtp_attachment_file_id",
			"D-FILE-1：SMTP 附件内容来自上传文件（file_source 自动补单附件，RFC2045 base64）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"tcp": {"src_port": 12345, "dst_port": 25}}, {"smtp": {"file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("pop3", "pop3_retr_file_id",
			"D-FILE-1：POP3 RETR 邮件体来自上传文件（file_source 合成单消息信箱，命令须显式 RETR + emit_mail_drop）",
			`{"layers": [{"ip": {}}, {"tcp": {}}, {"pop3": {"commands": [{"cmd": "RETR 1", "emit_mail_drop": true, "msg_num": 1}], "file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("smb", "smb_write_file_id",
			"D-FILE-1：SMB WRITE 数据来自上传文件（file_source 自动补 write 操作）",
			`{"layers": [{"ip": {"src": "10.0.0.100", "dst": "10.0.0.1"}}, {"tcp": {}}, {"smb": {"file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("nfs", "nfs_write_file_id",
			"D-FILE-1：NFS WRITE 数据来自上传文件（v3 Proc=7 / v4 OP_WRITE=38，自动补 write op）",
			`{"layers": [{"tcp": {}}, {"nfs": {"version": 3, "file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("wireguard", "wireguard_payload_file_id",
			"D-FILE-1：WireGuard transport_payloads 内容来自上传文件",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"udp": {}}, {"wireguard": {"file_source": {"file_id": "`+fid+`"}}}], "flow_control": {"flows": 1}}`),
		mk("shadowsocks", "shadowsocks_file_id",
			"D-FILE-1：Shadowsocks 载荷来自上传文件（缺省自动分块；cipher=none 时线内容可校验）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"tcp": {}}, {"shadowsocks": {"cipher": "none", "file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("vmess", "vmess_payload_file_id",
			"D-FILE-1：VMess 载荷来自上传文件（AEAD 分块；uuid/address/port 必填）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"tcp": {}}, {"vmess": {"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "address": "203.0.113.10", "port": 443, "file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("udp", "udp_raw_file_id",
			"D-FILE-1：udp 裸流载荷来自上传文件（[ip→udp] 终结形态万能兜底）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"udp": {"dst_port": 9000, "file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("telnet", "telnet_file_id",
			"D-FILE-1：telnet 会话载荷来自上传文件（Dialog 前注入）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"telnet": {"src_port": 12345, "dst_port": 23, "file_source": {"file_id": "`+fid+`"}}}]}`),
		// —— D-FILE-2 第二批（2026-10-13）——
		mk("tftp", "tftp_file_id",
			"D-FILE-2：TFTP 文件模式——整文件按 blksize 分块传输（块数=ceil(size/blksize)，末块=余量）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"udp": {"src_port": 51000, "dst_port": 69}}, {"tftp": {"mode": "read", "filename": "firmware.bin", "file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("coap", "coap_file_id",
			"D-FILE-2：CoAP 请求 payload 来自上传文件（response_file_source 喂响应方向）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"udp": {"dst_port": 5683}}, {"coap": {"method": "POST", "path": ["upload"], "file_source": {"file_id": "`+fid+`"}, "response": true, "response_code": "2.01"}}]}`),
		mk("socks5", "socks5_data_file_id",
			"D-FILE-2：SOCKS5 隧道数据面来自上传文件（data[].file_source，[]byte 直上二进制安全）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"tcp": {"src_port": 40000, "dst_port": 1080}}, {"socks5": {"data": [{"direction": "up", "file_source": {"file_id": "`+fid+`"}}]}}]}`),
		mk("openvpn", "openvpn_file_id",
			"D-FILE-2：OpenVPN P_DATA 明文载荷来自上传文件（加密外层不校内容）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"udp": {"dst_port": 1194}}, {"openvpn": {"file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("rdp", "rdp_data_event_file_id",
			"D-FILE-2：RDP 虚拟通道数据来自上传文件（data_events[].file_source，优先级 FileSource > payload > payload_b64）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"tcp": {"src_port": 40001, "dst_port": 3389}}, {"rdp": {"data_events": [{"type": "cliprdr_format_list", "channel": "cliprdr", "file_source": {"file_id": "`+fid+`"}}]}}]}`),
		mk("sip", "sip_media_file_id",
			"D-FILE-2：SIP RTP 媒体帧载荷来自上传文件——须 dialog 消息 emit_media:true + media.enabled:true（媒体流锚在对话消息上，D-SIP-2）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"udp": {"dst_port": 5060}}, {"sip": {"dialog": [{"method": "INVITE", "direction": "up", "emit_media": true}], "media": {"enabled": true, "frames": 2, "file_source": {"file_id": "`+fid+`"}}}}]}`),
		mk("sctp", "sctp_chunk_file_id",
			"D-FILE-2：SCTP DATA 块载荷来自上传文件（chunks[].file_source）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"sctp": {"chunks": [{"tsn": 1, "sid": 0, "ssn": 0, "ppid": 1, "direction": "up", "file_source": {"file_id": "`+fid+`"}}]}}]}`),
		// —— D-FILE-2 P1 批（2026-10-13）——
		mk("mqtt", "mqtt_publish_file_id",
			"D-FILE-2 P1：MQTT PUBLISH 载荷来自上传文件（messages[].file_source，item 级）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"tcp": {"src_port": 40002, "dst_port": 1883}}, {"mqtt": {"messages": [{"topic": "sensor/data", "file_source": {"file_id": "`+fid+`"}}]}}]}`),
		mk("xmpp", "xmpp_body_file_id",
			"D-FILE-2 P1：XMPP <body> 来自上传文件（messages[].file_source，item 级，文本语义；xmpp 自建 TCP 载体，链不带 tcp 层）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"xmpp": {"messages": [{"direction": "up", "file_source": {"file_id": "`+fid+`"}}]}}]}`),
		mk("syslog", "syslog_msg_file_id",
			"D-FILE-2 P1：syslog 消息体来自上传文件（file_source，config 级，UTF-8）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"udp": {"dst_port": 514}}, {"syslog": {"file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("rtmp", "rtmp_data_file_id",
			"D-FILE-2 P1：RTMP 数据 chunk 来自上传文件（data[].file_source，item 级；rtmp 自建 TCP 载体，链不带 tcp 层）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"rtmp": {"command": "publish", "stream_name": "stream1", "data": [{"direction": "up", "file_source": {"file_id": "`+fid+`"}}]}}]}`),
		mk("someip", "someip_payload_file_id",
			"D-FILE-2 P1：SOME/IP payload 来自上传文件（file_source，config 级）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"udp": {"dst_port": 30490}}, {"someip": {"service_id": 1, "method_id": 1, "file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("icmp", "icmp_data_file_id",
			"D-FILE-2 P1：ICMP echo 载荷来自上传文件（file_source，config 级）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"icmp": {"file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("icmpv6", "icmpv6_data_file_id",
			"D-FILE-2 P1：ICMPv6 echo 载荷来自上传文件（file_source，config 级，icmp 对称）",
			`{"layers": [{"ip": {"src": "2001:db8::1", "dst": "2001:db8::2"}}, {"icmpv6": {"file_source": {"file_id": "`+fid+`"}}}]}`),
		mk("imap", "imap_append_file_id",
			"D-FILE-2 P1：IMAP APPEND literal 体来自上传文件（commands[].file_source，item 级）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"tcp": {"src_port": 40005, "dst_port": 143}}, {"imap": {"banner": "* OK ready\r\n", "commands": [{"cmd": "APPEND INGRID (\\Seen) {100}", "file_source": {"file_id": "`+fid+`"}}]}}]}`),
		mk("grpc", "grpc_request_file_id",
			"D-FILE-2 P1：gRPC 请求消息来自上传文件（file_source 覆盖 request_messages，既有接线）",
			`{"layers": [{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}}, {"tcp": {"src_port": 40006, "dst_port": 50051}}, {"grpc": {"service": "pkg.Svc", "method": "Put", "call_type": "unary", "file_source": {"file_id": "`+fid+`"}}}]}`),
	}
}

func complexity(spec json.RawMessage) (int, error) {
	var m struct {
		Layers []map[string]json.RawMessage `json:"layers"`
	}
	if err := json.Unmarshal(spec, &m); err != nil {
		return 0, err
	}
	score := len(m.Layers)
	for _, l := range m.Layers {
		score += len(l)
	}
	return score, nil
}

func flowNote(spec json.RawMessage) string {
	v := multiFlowValue(spec)
	if v > 1 {
		return fmt.Sprintf("flows=%d（%d 条流并发）", v, v)
	}
	return ""
}

// multiFlowValue returns the flow_control value (0 when absent).
func multiFlowValue(cfg json.RawMessage) int {
	var m struct {
		FlowControl *struct {
			Value int `json:"value"`
		} `json:"flow_control"`
	}
	json.Unmarshal(cfg, &m)
	if m.FlowControl != nil {
		return m.FlowControl.Value
	}
	return 0
}

// txTier：事务例档（排序用）。语料自证不逐协议硬编码——两路信号任一命中
// 即事务档：① config 携带响应/事务语义键（txSignal）；② **缺省事务例**：
// 正例 expect.packet_count ≥ 2 且 config 不带纯请求 opt-out 键（query_only/
// request_only）。②覆盖 D-DNS-2/D-SNMP-2/D-NTP-2 反转后的缺省一问一答例
// （如 snmp_get_default_transaction、ntp_client_default_transaction）——
// 它们不带任何显式响应键，靠包数自证；opt-out 键排除多流纯查询例
// （dns flows=2 查询例包数同为 2，但配置声明了 query_only）。
func txTier(e exam) bool {
	if txSignal(e.Config) {
		return true
	}
	return e.Packets >= 2 && !hasOptOutKey(e.Config)
}

// hasOptOutKey reports whether the config carries an explicit one-sided
// switch (query_only / request_only) in any layer config.
func hasOptOutKey(cfg json.RawMessage) bool {
	var m struct {
		Layers []map[string]json.RawMessage `json:"layers"`
	}
	if json.Unmarshal(cfg, &m) != nil {
		return false
	}
	for _, layer := range m.Layers {
		for _, raw := range layer {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				continue
			}
			if _, ok := fields["query_only"]; ok {
				return true
			}
			if _, ok := fields["request_only"]; ok {
				return true
			}
		}
	}
	return false
}

// txSignal：config 是否携带响应/事务语义（is_response、response_code、
// reply/replies、多步 procedures 含 response/reply/ack、transactions/
// sessions）。语料含事务例的协议，默认示例应选正常业务场景（请求+响应），
// 而不是纯请求的半边场景（提示词实测 P1-①：dns 默认示例只有 query 没有
// response——一问一答才是正常业务）。语料只有单向例的协议（路由通告/
// 日志上报/隧道封装）行为不变——单向即其正常场景，由语料自证，不逐协议
// 硬编码。
func txSignal(cfg json.RawMessage) bool {
	var m struct {
		Layers []map[string]json.RawMessage `json:"layers"`
	}
	if json.Unmarshal(cfg, &m) != nil {
		return false
	}
	for _, layer := range m.Layers {
		for _, raw := range layer {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				continue
			}
			for _, k := range []string{"is_response", "response_code", "responses", "reply", "replies", "transactions", "sessions"} {
				if _, ok := fields[k]; ok {
					return true
				}
			}
			if p, ok := fields["procedures"]; ok {
				var procs []map[string]interface{}
				if json.Unmarshal(p, &procs) == nil && len(procs) >= 2 {
					for _, pr := range procs {
						t := strings.ToLower(fmt.Sprint(pr["type"]))
						if strings.Contains(t, "response") || strings.Contains(t, "reply") || strings.Contains(t, "ack") {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func Generate(casesDir string) ([]byte, error) {
	files, err := filepath.Glob(filepath.Join(casesDir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no case files under %s", casesDir)
	}
	protos := map[string][]exam{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var cases []caseFile
		if err := json.Unmarshal(raw, &cases); err != nil {
			continue // 非用例数组文件（如元数据）跳过
		}
		for _, c := range cases {
			if c.Expect.ExpectError || len(c.SpecJSON) == 0 || len(c.SpecJSON) > 6<<10 {
				continue
			}
			pk := c.Expect.PacketCount
			if c.Expect.MinPackets > pk {
				// packet_count 与 min_packets 两断言口径取大者：min_packets 例
				// （如 openvpn 握手交换）此前落 0 丢事务档。
				pk = c.Expect.MinPackets
			}
			protos[c.Proto] = append(protos[c.Proto], exam{
				Protocol: c.Proto, CaseID: c.ID, Summary: c.Summary,
				Config: c.SpecJSON, FlowControl: flowNote(c.SpecJSON),
				Packets: pk,
			})
		}
	}
	out := map[string][]exam{}
	for proto, exs := range protos {
		// 示例面只教正常场景（用户裁定 2026-10-07：示例必须给正常场景例）。
		// 带 query_only/request_only 的例是显式单边形状——警示注记挡不住
		// "查询流量"字面匹配下的照抄（用户 100 条 DNS 查询实测），直接退出
		// 服务集；协议无干净例时才兜底保留（附警示注记）。opt-out 能力面由
		// schema 字段描述（registry Description）+ corpus 用例覆盖，不经示例。
		clean := make([]exam, 0, len(exs))
		optOut := make([]exam, 0)
		for _, e := range exs {
			if hasOptOutKey(e.Config) {
				optOut = append(optOut, e)
				continue
			}
			clean = append(clean, e)
		}
		if len(clean) > 0 {
			exs = clean
		} else {
			exs = optOut
		}
		// 排序：事务例档优先，同档内 complexity 升序。simplest 规则只在
		// 同档内生效——含响应语义的例永远排在纯请求例之前。
		sort.Slice(exs, func(i, j int) bool {
			if ti, tj := txTier(exs[i]), txTier(exs[j]); ti != tj {
				return ti
			}
			si, _ := complexity(exs[i].Config)
			sj, _ := complexity(exs[j].Config)
			return si < sj
		})
		// 每协议 ≤4 条，贪心补充多样性：每轮挑"相对已收录集合带来最多
		// 新协议层键"的用例，直到无新键或达上限。仅挑 simplest 会把
		// headers/body/transactions 等常用定制字段全部隐藏——LLM 写非
		// 默认配置被迫再查 schema（用户实测反馈）。多流例若带新键自然
		// 入选，flow_control 注记在收录时统一附加。
		var picked []exam
		seen := map[string]bool{}
		pick := func(e exam) {
			if seen[e.CaseID] {
				return
			}
			seen[e.CaseID] = true
			e.FlowControl = flowNote(e.Config)
			// opt-out 键警示（仅兜底路径可见——正常协议的 opt-out 例已退出
			// 服务集）：带 query_only/request_only 的例是**单边形状**。
			if hasOptOutKey(e.Config) {
				opt := "（⚠ 此例带 query_only/request_only = 显式单边单包；正常业务流量（请求+响应）请删除该键——缺省即一问一答）"
				e.FlowControl = e.FlowControl + opt
			}
			picked = append(picked, e)
		}
		protoKeys := func(cfg json.RawMessage) map[string]bool {
			keys := map[string]bool{}
			var m struct {
				Layers []map[string]json.RawMessage `json:"layers"`
			}
			if json.Unmarshal(cfg, &m) != nil {
				return keys
			}
			// 协议层 = 最内层（层链有序，外层为 ip/tcp 等脚手架）；
			// 多样性比较的是层内字段键，不是层名。
			if len(m.Layers) > 0 {
				var inner map[string]json.RawMessage
				for _, v := range m.Layers[len(m.Layers)-1] {
					if json.Unmarshal(v, &inner) == nil {
						for k := range inner {
							keys[k] = true
						}
					}
				}
			}
			return keys
		}
		covered := map[string]bool{}
		if len(exs) > 0 {
			pick(exs[0]) // simplest 的多流注记由 pick 统一附加
			for k := range protoKeys(exs[0].Config) {
				covered[k] = true
			}
		}
		// P1-②：示例集必须含至少一个多流正例——能通过 sweep 的多流例必然
		// 已把变化字段写成动态 strategy 对象（静态四元组 + flows>1 会被
		// 引擎拒绝），LLM 照抄它改 N 即可，不必从单流静态示例试错。
		hasMulti := false
		for _, e := range picked {
			if multiFlowValue(e.Config) > 1 {
				hasMulti = true
				break
			}
		}
		if !hasMulti {
			for _, e := range exs {
				if seen[e.CaseID] {
					continue
				}
				if multiFlowValue(e.Config) > 1 {
					pick(e)
					for k := range protoKeys(e.Config) {
						covered[k] = true
					}
					break
				}
			}
		}
		for len(picked) < 5 {
			best, bestNew := -1, 0
			for i, e := range exs[1:] {
				if seen[e.CaseID] {
					continue
				}
				newKeys := 0
				for k := range protoKeys(e.Config) {
					if !covered[k] {
						newKeys++
					}
				}
				if newKeys > bestNew {
					best, bestNew = i, newKeys
				}
			}
			if best < 0 {
				break
			}
			e := exs[1+best]
			pick(e)
			for k := range protoKeys(e.Config) {
				covered[k] = true
			}
		}
		out[proto] = picked
		// D-FILE-1 手工例（第9轮复核 三.5：派生例不含 file_id 形态——cases
		// 语料是内联 payload，file_id 形态是 MCP 工作流教面）。策展注入，
		// 去重后追加（不受 ≤5 派生上限约束）。加新协议手工例时在此追加。
		for _, he := range handExamples() {
			if he.Protocol != proto {
				continue
			}
			dup := false
			for _, e := range picked {
				if e.CaseID == he.CaseID {
					dup = true
					break
				}
			}
			if !dup {
				he.FlowControl = flowNote(he.Config)
				picked2 := append(picked, he)
				out[proto] = picked2
			}
		}
	}
	// hand-only 协议：派生集为空（无 cases 例）时手工例独立建条目
	// （第9轮 三.5：udp 无 examples 条目）。
	handByProto := map[string][]example{}
	for _, he := range handExamples() {
		handByProto[he.Protocol] = append(handByProto[he.Protocol], he)
	}
	for proto, hes := range handByProto {
		if _, ok := out[proto]; ok {
			continue
		}
		entry := make([]exam, 0, len(hes))
		for _, he := range hes {
			he.FlowControl = flowNote(he.Config)
			entry = append(entry, he)
		}
		out[proto] = entry
	}
	names := make([]string, 0, len(out))
	for k := range out {
		names = append(names, k)
	}
	sort.Strings(names)
	env := envelope{Generated: len(out), Protocols: out}
	b, err := json.MarshalIndent(env, "", " ")
	if err != nil {
		return nil, err
	}
	_ = names
	return b, nil
}

func main() {
	cases := flag.String("cases", "test/protocol_pcap/cases", "cases directory")
	out := flag.String("out", "internal/mcp/layer_examples.json", "output JSON path")
	flag.Parse()
	b, err := Generate(*cases)
	if err != nil {
		fmt.Fprintln(os.Stderr, "examplegen:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "examplegen write:", err)
		os.Exit(1)
	}
	var probe struct {
		Generated int `json:"generated"`
	}
	json.Unmarshal(b, &probe)
	fmt.Printf("examplegen: wrote %s (%d protocols)\n", *out, probe.Generated)
}
