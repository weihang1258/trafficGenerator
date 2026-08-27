// Package pcaptest 提供协议用例验证的共享底层：Case 结构、tshark 字段/
// hex 断言（VerifyPcap）、tshark -x 帧解析、NIC 抓包编排。
//
// 该包被两处使用：
//   - internal/mcp 的 flowb_run_protocol_case / flowb_run_protocol_suite
//     工具（校验在 server 进程内完成）；
//   - test/protocol_pcap 驱动测试（启用同一套校验，保证 go test 与任何
//     MCP 客户端跑的是同一套断言，见 CLAUDE.md "所有测试经 MCP 执行"）。
//
// 包本身不依赖 rest/engine/mcp，保持纯函数，供两侧无循环引用。
package pcaptest

import "encoding/json"

// Case 是一个测试用例，从协议用例文档 §7（或 cases/*.json）抽取。
type Case struct {
	ID       string          `json:"id"`
	Proto    string          `json:"proto"`
	Summary  string          `json:"summary"`
	SpecJSON json.RawMessage `json:"spec_json"`        // generate_traffic "config" 参数
	Output   string          `json:"output,omitempty"` // output_type 覆盖（默认 pcap）
	// StrategyFC，设置后作为 generate_traffic 的 strategy_flow_control 参数
	//（如 {"type":"flows","value":N} 多流用例）。缺省 = 无 strategy 级流控。
	StrategyFC *StrategyFC `json:"strategy_fc,omitempty"`
	// TaskFC 设置后作为 task create 的 task_flow_control 参数。
	TaskFC *StrategyFC `json:"task_fc,omitempty"`
	// DecodeAs：额外 tshark -d 解码提示（如 {"udp.port==80,isakmp"}，
	// 用于端口非 IANA 知名端口的探针用例）。追加在框架固定解码规则之后。
	DecodeAs []string `json:"decode_as,omitempty"`
	// Expect 携带验证提示，由 VerifyPcap 依据 pcap 核对。
	Expect Expect `json:"expect"`
}

// Expect 是 Case 的验证期望，对应 tshark 断言与用例级行为期望。
type Expect struct {
	PacketCount  int           `json:"packet_count,omitempty"` // 精确期望包数
	MinPackets   int           `json:"min_packets,omitempty"`
	Fields       []FieldAssert `json:"fields,omitempty"`
	Frames       []FrameAssert `json:"frames,omitempty"`        // 原始字节断言
	HasHandshake bool          `json:"has_handshake,omitempty"` // 首包 TCP SYN
	HasPayload   bool          `json:"has_payload,omitempty"`
	Negotiated   bool          `json:"negotiated,omitempty"`
	Terminates   bool          `json:"terminates,omitempty"`
	Directional  bool          `json:"directional,omitempty"` // 双向均出现
	Notes        []string      `json:"notes,omitempty"`
	// ExpectError：true 时该用例是 Validate 负向外——MCP generate_traffic
	// 调用或任务预期失败。失败判 PASS，成功判 FAIL。
	ExpectError bool `json:"expect_error,omitempty"`
	// ErrorContains：ExpectError 用例通过的可选子串断言（空 = 任何错误均可）。
	ErrorContains string `json:"error_contains,omitempty"`
}

// FieldAssert 断言某个 tshark 字段在某包偏移处的取值。
type FieldAssert struct {
	Packet int    `json:"packet"`          // 1-based 包索引
	Field  string `json:"field"`           // tshark 字段名，如 "tcp.dstport"
	Value  string `json:"value,omitempty"` // 精确字符串值；空串表示"字段存在"
	// SameAsPacket：>0 时断言本包字段值等于该包（1-based）同字段值。用于
	// 持久性断言（如 smb2.sesid / smb2.file_id）这类无法固定六进制期望的
	// 运行期随机值。
	SameAsPacket int `json:"same_as_packet,omitempty"`
	// Nonzero：true 时断言字段存在且非全零。
	Nonzero bool `json:"nonzero,omitempty"`
	// DistinctValues：多流用例的调度无关聚合断言。非空时断言全量包中该字段
	// 恰好取这些值（各至少一次）且无其他值。包索引被忽略——多流调度器
	// 非确定性地交织流，固定包位对逐流值无意义。
	DistinctValues []string `json:"distinct_values,omitempty"`
	// DistinctExclude：DistinctValues 聚合中跳过的值（如双向 tcp.srcport
	// 扫描中的服务端端口）。仅当 DistinctValues 非空时生效。
	DistinctExclude []string `json:"distinct_exclude,omitempty"`
}

// FrameAssert 断言一帧的原始字节（tshark -x 十六进制转储）。
type FrameAssert struct {
	Packet int    `json:"packet"`           // 1-based 包索引
	Offset int    `json:"offset,omitempty"` // 帧内字节偏移；默认 0
	Hex    string `json:"hex"`              // 期望字节，如 "00 01 63 6f 6e 66 69 67"（在 offset 处前缀匹配）
}

// StrategyFC 镜像 MCP flowControlInput 形态：{"type":"flows","value":N}。
type StrategyFC struct {
	Type  string  `json:"type"`
	Value float64 `json:"value"`
}
