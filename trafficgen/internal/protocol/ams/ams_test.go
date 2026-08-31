package ams

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// mustFrame encodes an event or fails the test（用例辅助）。
func mustFrame(t *testing.T, e *core.AMSEvent, cfg *core.AMSConfig, sessionID uint32) []byte {
	t.Helper()
	f := BuildEventFrame(e, cfg, sessionID)
	if f == nil {
		t.Fatalf("BuildEventFrame(%s) returned nil", e.Kind)
	}
	return f
}

func cfg() *core.AMSConfig { return &core.AMSConfig{} }

// §3 帧头布局：Length=18+N（不含自身）、Version=1、FrameEnd ae 5a、最小帧。
func TestFrameHeaderLayout(t *testing.T) {
	// 空 payload PING：Length=18，总帧 22B。
	f := mustFrame(t, &core.AMSEvent{Kind: "ping", CorrelationID: 7}, cfg(), 3)
	want := "00000012" + "0130" + "0001" + "00000003" + "0000000000000007" + "ae5a"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("ping frame = %s, want %s", got, want)
	}
	if len(f) != 22 {
		t.Fatalf("empty-payload frame = %d bytes, want 22", len(f))
	}
}

// §4 HELLO：client_name + profile TLV；FieldLength 只计 Value。
func TestHelloFrame(t *testing.T) {
	f := mustFrame(t, &core.AMSEvent{Kind: "hello"}, cfg(), 0)
	// 53 = 18 + (4+10 client) + (4+17 profile)
	want := "00000035" + "0101" + "0001" + "00000000" + "0000000000000000" +
		"0001" + "000a" + hex.EncodeToString([]byte("ams-client")) +
		"0002" + "0011" + hex.EncodeToString([]byte("ams_management_v1")) + "ae5a"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("hello frame = %s, want %s", got, want)
	}
}

// §4 HELLO_OK：回显 profile + heartbeat + session_limit。
func TestHelloOKFrame(t *testing.T) {
	c := &core.AMSConfig{Heartbeat: 30, SessionLimit: 8}
	f := mustFrame(t, &core.AMSEvent{Kind: "hello_ok"}, c, 0)
	want := "00000033" + "0102" + "0002" + "00000000" + "0000000000000000" +
		"0002" + "0011" + hex.EncodeToString([]byte("ams_management_v1")) +
		"0012" + "0002" + "001e" +
		"0011" + "0002" + "0008" + "ae5a"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("hello_ok frame = %s, want %s", got, want)
	}
}

// §4 AUTH：只带 auth_method + credential_ref（无明文密码）。
func TestAuthFrame(t *testing.T) {
	f := mustFrame(t, &core.AMSEvent{Kind: "auth"}, cfg(), 0)
	want := "00000027" + "0103" + "0001" + "00000000" + "0000000000000000" +
		"0004" + "0003" + hex.EncodeToString([]byte("ref")) +
		"0005" + "000a" + hex.EncodeToString([]byte("cred-ref-1")) + "ae5a"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("auth frame = %s, want %s", got, want)
	}
}

// §4 COMMAND/RESPONSE：command/resource TLV + CorrelationID 头字段配对；
// status uint16；可选 body。
func TestCommandResponseFrames(t *testing.T) {
	cmd := mustFrame(t, &core.AMSEvent{Kind: "command", CorrelationID: 77,
		Command: "broker.info", Resource: "broker"}, cfg(), 1)
	wantCmd := "0000002b" + "0120" + "0001" + "00000001" + "000000000000004d" +
		"0020" + "000b" + hex.EncodeToString([]byte("broker.info")) +
		"0021" + "0006" + hex.EncodeToString([]byte("broker")) + "ae5a"
	if got := hex.EncodeToString(cmd); got != wantCmd {
		t.Fatalf("command frame = %s, want %s", got, wantCmd)
	}
	resp := mustFrame(t, &core.AMSEvent{Kind: "response", CorrelationID: 77, Status: 200}, cfg(), 1)
	wantResp := "00000018" + "0121" + "0002" + "00000001" + "000000000000004d" +
		"0023" + "0002" + "00c8" + "ae5a"
	if got := hex.EncodeToString(resp); got != wantResp {
		t.Fatalf("response frame = %s, want %s", got, wantResp)
	}
}

// §4 MESSAGE：message_id/message_kind/delivery_mode/sequence/payload；
// delivery_mode=1 → ack-required flag。
func TestMessageFrame(t *testing.T) {
	e := &core.AMSEvent{Kind: "message", MessageID: 500, Sequence: 1,
		MessageKind: "event", DeliveryMode: 1, Payload: []byte("hello-ams")}
	f := mustFrame(t, e, cfg(), 1)
	want := "00000045" + "0110" + "0005" + "00000001" + "0000000000000000" + // flags 0x0001|0x0004
		"0030" + "0008" + "00000000000001f4" +
		"0031" + "0005" + hex.EncodeToString([]byte("event")) +
		"0032" + "0001" + "01" +
		"0033" + "0008" + "0000000000000001" +
		"0034" + "0009" + hex.EncodeToString([]byte("hello-ams")) + "ae5a"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("message frame = %s, want %s", got, want)
	}
	// delivery_mode=0（缺省）→ 无 ack-required 位。
	f0 := mustFrame(t, &core.AMSEvent{Kind: "message", MessageID: 1, Sequence: 1, MessageKind: "e"}, cfg(), 1)
	if f0[6] != 0x00 || f0[7] != 0x01 {
		t.Fatalf("mode-0 flags = %x, want 0001", f0[6:8])
	}
}

// §4 MESSAGE_ACK：ack_for + ack_status（+ 可选 range_end）。
func TestMessageAckFrame(t *testing.T) {
	f := mustFrame(t, &core.AMSEvent{Kind: "message_ack", AckFor: 500, AckStatus: 0, AckRangeEnd: 502}, cfg(), 1)
	want := "00000030" + "0111" + "0002" + "00000001" + "0000000000000000" +
		"0040" + "0008" + "00000000000001f4" +
		"0041" + "0002" + "0000" +
		"0042" + "0008" + "00000000000001f6" + "ae5a"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("message_ack frame = %s, want %s", got, want)
	}
}

// §4 ERROR + OPEN_SESSION/OPEN_OK/CLOSE_SESSION/CLOSE_OK。
func TestLifecycleFrames(t *testing.T) {
	open := mustFrame(t, &core.AMSEvent{Kind: "open_session", SessionName: "mgmt"}, cfg(), 1)
	if got := hex.EncodeToString(open); got != "0000001a"+"0105"+"0001"+"00000001"+"0000000000000000"+"0010"+"0004"+hex.EncodeToString([]byte("mgmt"))+"ae5a" {
		t.Fatalf("open_session frame = %s", got)
	}
	ok := mustFrame(t, &core.AMSEvent{Kind: "open_ok", Status: 0}, cfg(), 1)
	if got := hex.EncodeToString(ok); got != "0000001e"+"0106"+"0002"+"00000001"+"0000000000000000"+"0023"+"0002"+"0000"+"0011"+"0002"+"0010"+"ae5a" {
		t.Fatalf("open_ok frame = %s", got)
	}
	closeS := mustFrame(t, &core.AMSEvent{Kind: "close_session"}, cfg(), 1)
	if got := hex.EncodeToString(closeS); got != "00000012"+"0107"+"0001"+"00000001"+"0000000000000000"+"ae5a" {
		t.Fatalf("close_session frame = %s", got)
	}
	err := mustFrame(t, &core.AMSEvent{Kind: "error", ErrorCode: 5, ErrorText: "denied"}, cfg(), 1)
	want := "00000022" + "017f" + "0002" + "00000001" + "0000000000000000" +
		"00f0" + "0002" + "0005" + "00f1" + "0006" + hex.EncodeToString([]byte("denied")) + "ae5a"
	if got := hex.EncodeToString(err); got != want {
		t.Fatalf("error frame = %s, want %s", got, want)
	}
}

// §3/§7 边界：显式 Type/Flags 覆盖、frame_max 守卫。
func TestOverridesAndFrameMax(t *testing.T) {
	f := mustFrame(t, &core.AMSEvent{Kind: "ping", Type: 0x7f, Flags: 0x0002}, cfg(), 1)
	if f[5] != 0x7f || f[6] != 0x00 || f[7] != 0x02 {
		t.Fatalf("override type/flags = %x, want 7f 0002", f[5:8])
	}
	big := &core.AMSConfig{FrameMax: 32}
	_, _, dir, _ := eventDefaults(&core.AMSEvent{Kind: "hello"})
	if dir != "c2s" {
		t.Fatalf("hello dir = %s", dir)
	}
	frame := BuildEventFrame(&core.AMSEvent{Kind: "hello"}, big, 0)
	if err := CheckFrameMax(frame, 32); err == nil {
		t.Fatalf("57-byte hello must exceed frame_max 32, got no error")
	}
	if err := CheckFrameMax(frame, 0); err != nil {
		t.Fatalf("default frame_max must accept: %v", err)
	}
}

// §5 状态机正例：完整握手 + 会话 + 业务帧合法。
func TestValidateHappyPath(t *testing.T) {
	c := &core.AMSConfig{Connections: []core.AMSConnection{{
		Events: []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{
			{Kind: "open_session"}, {Kind: "open_ok"},
			{Kind: "command", CorrelationID: 1, Command: "broker.info", Resource: "broker"},
			{Kind: "response", CorrelationID: 1, Status: 0},
			{Kind: "message", MessageID: 9, Sequence: 1, MessageKind: "e", DeliveryMode: 1},
			{Kind: "message_ack", AckFor: 9, AckStatus: 0},
			{Kind: "ping", CorrelationID: 3}, {Kind: "pong", CorrelationID: 3},
			{Kind: "close_session"}, {Kind: "close_ok"},
		}}},
	}}}
	if err := ValidateConfig(c); err != nil {
		t.Fatalf("happy path rejected: %v", err)
	}
}

func anchorErr(t *testing.T, cfg *core.AMSConfig, anchors ...string) error {
	t.Helper()
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatalf("expected rejection containing %v, got nil", anchors)
	}
	for _, a := range anchors {
		if !strings.Contains(err.Error(), a) {
			t.Fatalf("error %q missing anchor %q", err.Error(), a)
		}
	}
	return err
}

// §5/§9 负例矩阵：每条设计错误行至少一个校验测试（锚词 = 用例契约）。
func TestValidateNegatives(t *testing.T) {
	conn := func(ev ...core.AMSEvent) *core.AMSConfig {
		return &core.AMSConfig{Connections: []core.AMSConnection{{Events: ev}}}
	}
	// 非 hello 首帧 → hello。
	anchorErr(t, conn(core.AMSEvent{Kind: "auth"}), "hello")
	// hello_ok 前无 hello → handshake。
	anchorErr(t, conn(core.AMSEvent{Kind: "hello_ok"}), "handshake")
	// auth 未完成即 open_session → auth/session。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{{Kind: "open_session"}}}},
	}}}, "auth", "session")
	// session 未开先业务 → session。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{{Kind: "command", CorrelationID: 1, Command: "c", Resource: "r"}}}},
	}}}, "session")
	// response 无 pending command → correlation。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{{Kind: "open_session"}, {Kind: "open_ok"}, {Kind: "response", CorrelationID: 5}}}},
	}}}, "correlation")
	// ack 未发送 message → message/ack。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{{Kind: "open_session"}, {Kind: "open_ok"}, {Kind: "message_ack", AckFor: 9}}}},
	}}}, "message", "ack")
	// sequence 回退 → sequence。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{{Kind: "open_session"}, {Kind: "open_ok"},
			{Kind: "message", MessageID: 1, Sequence: 5, MessageKind: "e"},
			{Kind: "message", MessageID: 2, Sequence: 4, MessageKind: "e"}}}},
	}}}, "sequence")
	// 重传 sequence 不一致 → message/sequence。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{{Kind: "open_session"}, {Kind: "open_ok"},
			{Kind: "message", MessageID: 1, Sequence: 5, MessageKind: "e"},
			{Kind: "message", MessageID: 1, Sequence: 6, MessageKind: "e"}}}},
	}}}, "message", "sequence")
	// 关闭后新业务 → session。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{{Kind: "open_session"}, {Kind: "open_ok"}, {Kind: "close_session"}, {Kind: "command", CorrelationID: 1, Command: "c", Resource: "r"}}}},
	}}}, "session")
	// command correlation 重复 → correlation。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{{Kind: "open_session"}, {Kind: "open_ok"},
			{Kind: "command", CorrelationID: 1, Command: "c", Resource: "r"},
			{Kind: "response", CorrelationID: 1},
			{Kind: "command", CorrelationID: 1, Command: "c", Resource: "r"}}}},
	}}}, "correlation")
	// 空 session_id 的 open_session → session。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{Events: []core.AMSEvent{{Kind: "open_session"}}}},
	}}}, "session")
	// PING 在 session 外 → session。
	anchorErr(t, conn(core.AMSEvent{Kind: "hello"}, core.AMSEvent{Kind: "hello_ok"}, core.AMSEvent{Kind: "ping"}), "session")
	// 未知 profile → profile。
	anchorErr(t, &core.AMSConfig{Profile: "bogus"}, "profile")
	// 空事件连接 → hello。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{}}}, "hello")
	// 未知 kind → frame/type。
	anchorErr(t, conn(core.AMSEvent{Kind: "bogus"}), "frame")
}

// §8/§9 wire_fault 与端口/空配置校验。
func TestValidateWireFaultAndPort(t *testing.T) {
	for kind, anchor := range map[string]string{
		"bad_version":    "version",
		"unknown_type":   "frame",
		"reserved_flags": "frame",
		"length_overrun": "length",
		"bad_frame_end":  "frame",
		"tlv_overrun":    "tlv",
	} {
		c := &core.AMSConfig{WireFault: kind, Connections: []core.AMSConnection{{Events: []core.AMSEvent{{Kind: "hello"}}}}}
		anchorErr(t, c, anchor)
	}
	if err := ValidateConfig(&core.AMSConfig{WireFault: "nope"}); err == nil {
		t.Fatalf("unknown wire_fault must be rejected")
	}
	// 层校验：端口 61617 拒绝（port 锚词）、空 spec 通过。
	if err := ValidateSpec(&core.FlowSpec{AMS: &core.AMSConfig{}, DstPort: 61617}); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("port validation = %v", err)
	}
	if err := ValidateSpec(&core.FlowSpec{AMS: &core.AMSConfig{}}); err != nil {
		t.Fatalf("empty config must pass: %v", err)
	}
}

// 生成器冒烟：事件模式逐帧发射、SrcPort 会话边界、方向正确。
func TestGenerateEvents(t *testing.T) {
	c := &core.AMSConfig{Connections: []core.AMSConnection{{
		SrcPort: 42051,
		Events:  []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}},
	}}}
	g := &AMSGenerator{}
	var evs []layers.MessageEvent
	if err := g.generateEvents(t.Context(), func(e layers.MessageEvent) error {
		evs = append(evs, e)
		return nil
	}, c); err != nil {
		t.Fatalf("generateEvents: %v", err)
	}
	if len(evs) != 2 || !evs[0].Up || evs[1].Up || evs[0].SrcPort != 42051 {
		t.Fatalf("events = %+v", evs)
	}
}

// 生成器：frame_max 超限在生成期报错（防静默超帧）。
func TestGenerateFrameMaxRejected(t *testing.T) {
	c := &core.AMSConfig{FrameMax: 32, Connections: []core.AMSConnection{{
		Events: []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}},
	}}}
	g := &AMSGenerator{}
	err := g.generateEvents(t.Context(), func(layers.MessageEvent) error { return nil }, c)
	if err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("frame_max must reject at generation: %v", err)
	}
}

// §6 MUST：ack-required 消息必须收到 MESSAGE_ACK；PING/PONG 只能在
// session open 后（session 块内未 open 同样拒绝）。
func TestValidateAckRequiredAndSessionScopedPing(t *testing.T) {
	// mode=1 消息结束时仍未 ack → ack 锚词拒绝。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{
			{Kind: "open_session"}, {Kind: "open_ok"},
			{Kind: "message", MessageID: 5, Sequence: 1, MessageKind: "e", DeliveryMode: 1}}}},
	}}}, "ack")
	// session 块未 open 就发 ping → session 锚词拒绝。
	anchorErr(t, &core.AMSConfig{Connections: []core.AMSConnection{{
		Events:   []core.AMSEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.AMSSession{{SessionID: 1, Events: []core.AMSEvent{{Kind: "ping"}}}},
	}}}, "session")
}
