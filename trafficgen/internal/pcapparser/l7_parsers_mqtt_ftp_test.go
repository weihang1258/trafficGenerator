package pcapparser

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// P1-4（2026-10-05 客户端复测）：L7 解析面只有 http/dns/tls 三个解析器，
// 生成面 123 协议——mqtt/ftp 生成正确但 L7Protocol/L7Metadata 全空。本组
// 测试钉定两个新解析器的字节级契约（对照 MQTT 3.1.1 / RFC 959 线格式）。

// mqttConnect 构造一条 MQTT 3.1.1 CONNECT 报文（fixed header + varint 剩余
// 长度 + "MQTT" 协议名 + level + flags + keepalive + payload client_id）。
func mqttConnect(t *testing.T, clientID string, keepalive uint16, cleanSession bool) []byte {
	t.Helper()
	payload := make([]byte, 0, 10+2+len(clientID))
	payload = append(payload, 0x00, 0x04)             // protocol name 长度
	payload = append(payload, 'M', 'Q', 'T', 'T')     // "MQTT"
	payload = append(payload, 0x04)                   // protocol level 4 (3.1.1)
	flags := byte(0)
	if cleanSession {
		flags |= 0x02
	}
	payload = append(payload, flags)
	payload = append(payload, byte(keepalive>>8), byte(keepalive))
	cid := []byte(clientID)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(cid)))
	payload = append(payload, l[:]...)
	payload = append(payload, cid...)
	// varint 剩余长度（LSB 组，高位 continuation）。
	rem := payload
	remLen := len(rem)
	// remLen < 128 走单字节（本测试全部满足）；>127 的多字节形态由
	// TestMqttParserVarint 覆盖。
	out := []byte{0x10, byte(remLen)}
	return append(out, rem...)
}

func mqttPublish(topic string, qos byte, msgID uint16, body []byte) []byte {
	head := []byte{0x30 | (qos << 1)}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(topic)))
	rest := append(l[:], topic...)
	if qos > 0 {
		var m [2]byte
		binary.BigEndian.PutUint16(m[:], msgID)
		rest = append(rest, m[:]...)
	}
	rest = append(rest, body...)
	rem := len(rest)
	var remBytes []byte
	for {
		b := byte(rem % 128)
		rem /= 128
		if rem > 0 {
			b |= 0x80
		}
		remBytes = append(remBytes, b)
		if rem == 0 {
			break
		}
	}
	return append(append(head, remBytes...), rest...)
}

func TestMqttParserConnect(t *testing.T) {
	stream := mqttConnect(t, "audit-c1", 60, true)
	res, err := (mqttParser{}).Parse(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Protocol != "mqtt" {
		t.Errorf("protocol = %q, want mqtt", res.Protocol)
	}
	if res.Metadata["client_id"] != "audit-c1" {
		t.Errorf("client_id = %v, want audit-c1", res.Metadata["client_id"])
	}
	if res.Metadata["keepalive"] != uint16(60) {
		t.Errorf("keepalive = %v, want 60", res.Metadata["keepalive"])
	}
	if res.Metadata["clean_session"] != true {
		t.Errorf("clean_session = %v, want true", res.Metadata["clean_session"])
	}
	if res.Metadata["proto_level"] != byte(4) {
		t.Errorf("proto_level = %v, want 4", res.Metadata["proto_level"])
	}
	if res.Metadata["method"] != "CONNECT" {
		t.Errorf("method (L7Method index) = %v, want CONNECT", res.Metadata["method"])
	}
}

func TestMqttParserPublish(t *testing.T) {
	stream := mqttPublish("sensors/temp", 1, 42, []byte{0x01, 0x02})
	res, err := (mqttParser{}).Parse(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Metadata["topic"] != "sensors/temp" {
		t.Errorf("topic = %v, want sensors/temp", res.Metadata["topic"])
	}
	if res.Metadata["qos"] != byte(1) {
		t.Errorf("qos = %v, want 1", res.Metadata["qos"])
	}
	if res.Metadata["msg_id"] != uint16(42) {
		t.Errorf("msg_id = %v, want 42", res.Metadata["msg_id"])
	}
}

func TestMqttParserMultiPacketStream(t *testing.T) {
	// CONNECT → CONNACK → PUBLISH → PINGREQ：类型序列 + 首个 CONNECT 的字段。
	var stream []byte
	stream = append(stream, mqttConnect(t, "multi", 30, false)...)
	stream = append(stream, 0x20, 0x02, 0x00, 0x00)              // CONNACK
	stream = append(stream, mqttPublish("t/1", 0, 0, []byte("x"))...)
	stream = append(stream, 0xC0, 0x00)                          // PINGREQ
	res, err := (mqttParser{}).Parse(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	types, _ := res.Metadata["msg_types"].([]string)
	if strings.Join(types, ",") != "CONNECT,CONNACK,PUBLISH,PINGREQ" {
		t.Errorf("msg_types = %v, want CONNECT,CONNACK,PUBLISH,PINGREQ", types)
	}
	if res.Metadata["client_id"] != "multi" {
		t.Errorf("client_id = %v (from first CONNECT), want multi", res.Metadata["client_id"])
	}
}

func TestMqttParserVarintRemainder(t *testing.T) {
	// 剩余长度 >127：双字节 varint（LSB 组）。PUBLISH 大载荷 300 字节。
	body := make([]byte, 300)
	stream := mqttPublish("big", 0, 0, body)
	res, err := (mqttParser{}).Parse(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Metadata["topic"] != "big" {
		t.Errorf("topic = %v (varint walk must stay aligned)", res.Metadata["topic"])
	}
}

func TestMqttParserCanParse(t *testing.T) {
	p := mqttParser{}
	conn := mqttConnect(t, "x", 10, false)
	if !p.CanParse(1883, conn) {
		t.Error("port 1883 must match")
	}
	if !p.CanParse(0, conn) {
		t.Error("CONNECT signature (0x10 ... MQTT) must match without port")
	}
	if !p.CanParse(0, []byte{0x20, 0x02, 0x00, 0x00}) {
		t.Error("CONNACK (0x20) leading byte must match on weak signal")
	}
	if p.CanParse(0, []byte("GET / HTTP/1.1\r\n")) {
		t.Error("HTTP text must not match mqtt")
	}
}

// ftp：控制流文本行协议。C2S "VERB arg\r\n"，S2C "NNN text\r\n"。
func TestFtpParserCommandsAndResponses(t *testing.T) {
	p := ftpParser{}
	c2s, err := p.Parse([]byte("USER test\r\nPASS pw\r\nRETR /x.bin\r\nQUIT\r\n"))
	if err != nil {
		t.Fatalf("parse c2s: %v", err)
	}
	if c2s.Protocol != "ftp" {
		t.Errorf("protocol = %q", c2s.Protocol)
	}
	if c2s.Metadata["method"] != "USER" {
		t.Errorf("method (first verb → L7Method index) = %v, want USER", c2s.Metadata["method"])
	}
	cmds, _ := c2s.Metadata["commands"].([]string)
	if strings.Join(cmds, ",") != "USER,PASS,RETR,QUIT" {
		t.Errorf("commands = %v", cmds)
	}

	s2c, err := p.Parse([]byte("220 ready\r\n331 need password\r\n150 opening\r\n226 done\r\n"))
	if err != nil {
		t.Fatalf("parse s2c: %v", err)
	}
	codes, _ := s2c.Metadata["response_codes"].([]string)
	if strings.Join(codes, ",") != "220,331,150,226" {
		t.Errorf("response_codes = %v", codes)
	}
	// 响应流不占 L7Method（与 mqtt 同语义）：保留 c2s 的命令动词不被覆盖。
	if s2c.Metadata["method"] != nil {
		t.Errorf("response-only stream must not set method, got %v", s2c.Metadata["method"])
	}
	if s2c.Metadata["banner"] != "ready" {
		t.Errorf("banner = %v, want ready", s2c.Metadata["banner"])
	}
}

func TestFtpParserCanParse(t *testing.T) {
	p := ftpParser{}
	if !p.CanParse(21, []byte("USER x\r\n")) {
		t.Error("port 21 must match")
	}
	if !p.CanParse(0, []byte("220 banner\r\n")) {
		t.Error("3-digit reply line must match without port")
	}
	if !p.CanParse(0, []byte("RETR /f\r\n")) {
		t.Error("bare command line must match without port")
	}
	if p.CanParse(0, []byte("GET / HTTP/1.1\r\n")) {
		t.Error("HTTP text must not match ftp")
	}
}

// setL7 双方向合并契约：c2s 先写、s2c 后写，第二次调用必须合并而非整体
// 覆盖（线上 e2e 抓到 MQTT 流 metadata 只剩 s2c 的 msg_types，c2s 的
// client_id/topic/qos 全丢）。列表键拼接成完整会话序，标量键新值胜。
func TestSetL7MergesBidirectionalMetadata(t *testing.T) {
	fs := &FlowState{}
	c2s, err := (mqttParser{}).Parse(mqttConnect(t, "audit-c1", 60, true))
	if err != nil {
		t.Fatalf("parse c2s: %v", err)
	}
	fs.setL7(c2s, "c2s")

	s2c, err := (mqttParser{}).Parse([]byte{0x20, 0x02, 0x00, 0x00})
	if err != nil {
		t.Fatalf("parse s2c: %v", err)
	}
	fs.setL7(s2c, "s2c")

	var md map[string]any
	if err := json.Unmarshal([]byte(fs.FlowModel.L7Metadata), &md); err != nil {
		t.Fatalf("L7Metadata not JSON: %q", fs.FlowModel.L7Metadata)
	}
	if md["client_id"] != "audit-c1" {
		t.Errorf("client_id lost after s2c parse, metadata = %v", md)
	}
	if md["keepalive"] != float64(60) {
		t.Errorf("keepalive lost after s2c parse, metadata = %v", md)
	}
	types, _ := md["msg_types"].([]any)
	if strings.Join(typesToStrings(types), ",") != "CONNECT,CONNACK" {
		t.Errorf("msg_types = %v, want c2s list followed by s2c list (CONNECT,CONNACK)", types)
	}
	if fs.FlowModel.L7Method != "CONNECT" {
		t.Errorf("L7Method = %q, want CONNECT (response stream must not clobber)", fs.FlowModel.L7Method)
	}
}

func typesToStrings(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// 复审 F1：MQTT 3.1 "MQIsdp"（协议名 6 字节）字段偏移随名长浮动，必须按
// 名长寻址——3.1.1 硬偏移读 3.1 包会把 'd'(0x64) 当 level、'p' 当 flags。
func TestMqttParser31MQIsdp(t *testing.T) {
	payload := []byte{0x00, 0x06, 'M', 'Q', 'I', 's', 'd', 'p', 0x03, 0x02, 0x00, 0x1e}
	payload = append(payload, 0x00, 0x05, '3', '.', '1', '.', '1')
	stream := append([]byte{0x10, byte(len(payload))}, payload...)
	res, err := (mqttParser{}).Parse(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Metadata["proto_level"] != byte(3) {
		t.Errorf("proto_level = %v, want 3 (MQTT 3.1)", res.Metadata["proto_level"])
	}
	if res.Metadata["clean_session"] != true {
		t.Errorf("clean_session = %v, want true (flags 0x02)", res.Metadata["clean_session"])
	}
	if res.Metadata["keepalive"] != uint16(30) {
		t.Errorf("keepalive = %v, want 30", res.Metadata["keepalive"])
	}
	if res.Metadata["client_id"] != "3.1.1" {
		t.Errorf("client_id = %v, want 3.1.1", res.Metadata["client_id"])
	}
}

// 复审 F5：CONNACK 弱探针收紧到 0x20 0x02（3.1.1 剩余长度恒 2），任意
// 0x20 开头的二进制不再误标 mqtt。
func TestMqttParserCanParseConnackFingerprint(t *testing.T) {
	p := mqttParser{}
	if !p.CanParse(0, []byte{0x20, 0x02, 0x00, 0x00}) {
		t.Error("real CONNACK (0x20 0x02) must match")
	}
	if p.CanParse(0, []byte{0x20, 0x99, 0xAB, 0xCD, 0x01}) {
		t.Error("random 0x20-leading binary must not match (only 0x20 0x02 is CONNACK)")
	}
}

// 复审 F7：PUBLISH 元数据一律 first-wins——topic/qos/msg_id 必须同出第一条，
// 不能 topic 取 #1 而 qos/msg_id 被 #N 覆盖成不成立的三元组。
func TestMqttParserPublishFirstWins(t *testing.T) {
	var stream []byte
	stream = append(stream, mqttPublish("first/topic", 1, 11, []byte("a"))...)
	stream = append(stream, mqttPublish("second/topic", 0, 0, []byte("b"))...)
	res, err := (mqttParser{}).Parse(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Metadata["topic"] != "first/topic" {
		t.Errorf("topic = %v, want first/topic", res.Metadata["topic"])
	}
	if res.Metadata["qos"] != byte(1) {
		t.Errorf("qos = %v, want 1 (from first PUBLISH)", res.Metadata["qos"])
	}
	if res.Metadata["msg_id"] != uint16(11) {
		t.Errorf("msg_id = %v, want 11 (from first PUBLISH)", res.Metadata["msg_id"])
	}
}

// 复审 F2：ftp 内容探针不得偷走邮件/消息协议端口——POP3 c2s 的 USER/PASS
// 与 SMTP s2c 的 220 都形似 ftp。错误标注比无标注差。
func TestFtpParserCanParseExcludesMailPorts(t *testing.T) {
	p := ftpParser{}
	if p.CanParse(110, []byte("USER bob\r\n")) {
		t.Error("POP3 USER on port 110 must not be labeled ftp")
	}
	if p.CanParse(25, []byte("220 mail.example ESMTP\r\n")) {
		t.Error("SMTP 220 on port 25 must not be labeled ftp")
	}
	if p.CanParse(143, []byte("220 ok\r\n")) {
		t.Error("IMAP port 143 must not be labeled ftp via digit probe")
	}
	if !p.CanParse(21, []byte("USER bob\r\n")) {
		t.Error("port 21 still matches")
	}
	if !p.CanParse(2222, []byte("220 ftp-on-weird-port\r\n")) {
		t.Error("nonstandard-port ftp content probes still work")
	}
}

// 复审 F3：varint 4 字节上限（含）——第 4 个 continuation 字节后必须止步，
// 不再多吞第 5 字节。
func TestMqttParserMalformedVarint(t *testing.T) {
	// PUBLISH 头 + 5 个连续 0xFF 长度字节 + 垃圾：不得 panic，安全返回。
	garbage := append([]byte{0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02}, make([]byte, 32)...)
	res, err := (mqttParser{}).Parse(garbage)
	if err != nil {
		t.Fatalf("malformed varint must not error: %v", err)
	}
	if res == nil || res.Protocol != "mqtt" {
		t.Errorf("malformed stream must return partial mqtt result, got %+v", res)
	}
	// 截断（长度声明超出实际）：同样安全返回。
	trunc := []byte{0x30, 0x40, 0x01}
	if _, err := (mqttParser{}).Parse(trunc); err != nil {
		t.Errorf("truncated packet must not error: %v", err)
	}
}

// 复审 F4：协议换判（c2s 解析成 A、s2c 换判成 B）必须清掉旧协议的索引列
// ——L7Host 不能残留 TLS SNI。
func TestSetL7ProtocolFlipResetsColumns(t *testing.T) {
	fs := &FlowState{}
	fs.setL7(&L7Result{Protocol: "tls", Metadata: map[string]any{"sni": "old.example"}}, "c2s")
	if fs.FlowModel.L7Host != "old.example" {
		t.Fatalf("setup: L7Host = %q", fs.FlowModel.L7Host)
	}
	fs.setL7(&L7Result{Protocol: "mqtt", Metadata: map[string]any{"msg_types": []string{"CONNACK"}}}, "s2c")
	if fs.FlowModel.L7Protocol != "mqtt" {
		t.Errorf("protocol must flip to mqtt, got %q", fs.FlowModel.L7Protocol)
	}
	if fs.FlowModel.L7Host != "" {
		t.Errorf("L7Host = %q, must be reset on protocol flip (stale TLS SNI)", fs.FlowModel.L7Host)
	}
	if fs.FlowModel.L7Method != "" {
		t.Errorf("L7Method = %q, must be reset on protocol flip", fs.FlowModel.L7Method)
	}
}

// 复审 F6 配套 + cap-16：超过 16 条的命令序列截断到 16。
func TestFtpParserCap16(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("NOOP\r\n")
	}
	res, err := (ftpParser{}).Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cmds, _ := res.Metadata["commands"].([]string)
	if len(cmds) != 16 {
		t.Errorf("commands len = %d, want capped at 16", len(cmds))
	}
}

// 响应型流（CONNACK 等）不占 L7Method 索引——按方向各解析一次、s2c 后写
// 覆盖 c2s，响应流不设 method 才能保留 c2s 的请求动词。
func TestMqttParserResponseStreamNoMethod(t *testing.T) {
	res, err := (mqttParser{}).Parse([]byte{0x20, 0x02, 0x00, 0x00})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Metadata["method"] != nil {
		t.Errorf("response-only stream must not set method, got %v", res.Metadata["method"])
	}
	if res.Protocol != "mqtt" {
		t.Errorf("protocol = %q, want mqtt (L7Protocol must still be tagged)", res.Protocol)
	}
}
